use super::reporter::{ConfirmOutcome, EntryGate, Reporter, ShellInbound};
use super::{AccountOp, FirewallOp, KeychainOp, Op, ProfileOp, tenants};
use crate::doctor::Severity;
use crate::{
    Cli, HelpTopic, InboundLevel, ModeLevel, Verb, allocation, allocation::TENANT_UID_FLOOR,
};

const EX_USAGE: u8 = 64;
const EX_IOERR: u8 = 74;
const EX_DOCTOR_WARNING: u8 = 1;
const EX_DOCTOR_CRITICAL: u8 = 2;

/// `Some(exit)` when the verb stops here instead of executing.
fn consent(reporter: &mut Reporter, default_yes: bool) -> Option<u8> {
    if reporter.refuse_sudo_without_terminal() {
        return Some(EX_USAGE);
    }
    match reporter.confirm(default_yes) {
        ConfirmOutcome::Proceed => None,
        ConfirmOutcome::Abort => {
            reporter.aborted();
            Some(0)
        }
    }
}

fn doctor_outcome_exit_code(outcome: &tenants::DoctorOutcome, strict: bool) -> u8 {
    if outcome.probe_failed {
        return EX_IOERR;
    }
    doctor_exit_code(outcome.max_severity(), strict)
}

fn doctor_exit_code(max_severity: Option<Severity>, strict: bool) -> u8 {
    if !strict {
        return 0;
    }
    match max_severity {
        Some(Severity::Critical) => EX_DOCTOR_CRITICAL,
        Some(Severity::Warning) => EX_DOCTOR_WARNING,
        Some(Severity::Info) | None => 0,
    }
}

pub(crate) fn dispatch(
    cli: Cli,
    directory: &dyn super::HostUserDirectory,
    tenants: &tenants::Tenants<'_>,
    host: &super::HostUserName,
    reporter: &mut Reporter,
) -> u8 {
    let show_summary = reporter.show_summary();
    match cli.verb {
        Verb::Create { name } => {
            if let Err(e) = tenants::validate_name(&name) {
                reporter.refuse_invalid_name(&name, &e);
                return EX_USAGE;
            }
            match tenants::check_conflict(directory, &name) {
                Ok(None) => {}
                Ok(Some(conflict)) => {
                    reporter.refuse_name_conflict(&name, &conflict);
                    return EX_USAGE;
                }
                Err(e) => {
                    reporter.create_conflict_probe_failed(&name, &e);
                    return EX_IOERR;
                }
            }
            let keep_profile = match tenants.existing_profile_loads(&name) {
                Ok(keep) => keep,
                Err(e) => {
                    reporter.refuse_create_profile_invalid(&name, &e);
                    return EX_USAGE;
                }
            };
            let uid = match allocation::UidAllocator::new(directory).lowest_free_uid() {
                Ok(uid) => uid,
                Err(e) => {
                    reporter.create_uid_allocation_failed(&e);
                    return EX_IOERR;
                }
            };
            let gid = match allocation::GidAllocator::new(directory).lowest_free_gid() {
                Ok(gid) => gid,
                Err(e) => {
                    reporter.create_gid_allocation_failed(&e);
                    return EX_IOERR;
                }
            };
            let create_plan_ops = build_create_plan_ops(&name, host, uid, gid, keep_profile);
            let create_plan = create_plan_entries(&create_plan_ops);
            if show_summary {
                reporter.create_summary(&name, host, uid, gid, Some(&create_plan));
                tenants.pre_exec_doctor_summary(None, host, tenants::DoctorScope::Create, reporter);
            }
            if let Some(code) = consent(reporter, true) {
                return code;
            }
            match tenants.create(&name, host, uid, gid, keep_profile, reporter) {
                Ok(()) => 0,
                Err(tenants::CreateError::Group(e)) => {
                    reporter.create_group_failed(&name, &e);
                    EX_IOERR
                }
                Err(tenants::CreateError::HostMembership(e)) => {
                    reporter.create_host_membership_failed(&name, host, &e);
                    EX_IOERR
                }
                Err(tenants::CreateError::User(e)) => {
                    reporter.create_failed(&name, &e);
                    EX_IOERR
                }
                Err(tenants::CreateError::UserWithRollback { user, rollback }) => {
                    // Original failure first, so greps for the single-failure shape still match.
                    reporter.create_failed(&name, &user);
                    reporter.create_rollback_failed(&name, &rollback);
                    EX_IOERR
                }
                Err(tenants::CreateError::CoworkDir(e)) => {
                    reporter.create_cowork_dir_failed(&name, &e);
                    EX_IOERR
                }
                Err(tenants::CreateError::KeychainProvision(e)) => {
                    reporter.create_keychain_provision_failed(&name, &e);
                    EX_IOERR
                }
                Err(tenants::CreateError::KeychainStash(e)) => {
                    reporter.create_keychain_stash_failed(&name, &e);
                    EX_IOERR
                }
                Err(tenants::CreateError::Profile(e)) => {
                    reporter.create_profile_failed(&name, &e);
                    EX_IOERR
                }
                Err(tenants::CreateError::Firewall(e)) => {
                    reporter.create_firewall_failed(&name, &e);
                    EX_IOERR
                }
                Err(tenants::CreateError::PostProvision(e)) => {
                    surface_create_post_provision_error(reporter, &name, &e);
                    EX_IOERR
                }
            }
        }
        Verb::Shell {
            name,
            mode,
            inbound,
            // TODO(smell): rename the `directory` port binding (e.g. `user_directory`) so this flag needn't be renamed at the bind
            directory: shell_directory,
            argv,
        } => {
            if let Err(e) = tenants::validate_name(&name) {
                reporter.refuse_invalid_name(&name, &e);
                return EX_USAGE;
            }
            // NotPresent + OrphanGroup collapse to one refusal: shell can't
            // run against a lingering group; convergence belongs to destroy.
            let eligibility = match tenants::destroy_eligibility(directory, &name) {
                Ok(e) => e,
                Err(e) => {
                    reporter.shell_eligibility_probe_failed(&name, &e);
                    return EX_IOERR;
                }
            };
            match eligibility {
                tenants::Eligibility::NotPresent | tenants::Eligibility::OrphanGroup => {
                    reporter.refuse_shell_absent(&name);
                    EX_USAGE
                }
                tenants::Eligibility::NotATenant { uid } => {
                    reporter.refuse_shell_not_a_tenant(&name, uid, TENANT_UID_FLOOR);
                    EX_USAGE
                }
                tenants::Eligibility::SystemAccount => {
                    reporter.refuse_shell_system_account(&name);
                    EX_USAGE
                }
                tenants::Eligibility::Destroyable => {
                    let resolved_mode = mode.unwrap_or(ModeLevel::Runtime);
                    if show_summary {
                        let posture_permissive = tenants.inbound_posture_is_permissive(&name);
                        if argv.is_empty() {
                            reporter.shell_summary(
                                &name,
                                host,
                                shell_directory.as_deref(),
                                posture_permissive,
                            );
                        } else {
                            let shell_inbound = match inbound {
                                Some(InboundLevel::Permissive) => ShellInbound::WidenedForCommand,
                                None if posture_permissive => ShellInbound::PermissiveByProfile,
                                _ => ShellInbound::Restricted,
                            };
                            reporter.shell_command_summary(
                                &name,
                                host,
                                resolved_mode,
                                shell_inbound,
                                &argv,
                                shell_directory.as_deref(),
                            );
                        }
                        tenants.pre_exec_doctor_summary(
                            Some(&name),
                            host,
                            tenants::DoctorScope::Shell,
                            reporter,
                        );
                    }
                    if reporter.refuse_sudo_without_terminal() {
                        return EX_USAGE;
                    }
                    let criticals = match tenants.shell_entry_criticals(&name, reporter) {
                        Ok(criticals) => criticals,
                        Err(e) => {
                            reporter.shell_narrow_probe_failed(&name, &e);
                            return EX_IOERR;
                        }
                    };
                    match reporter.gate_entry_on_criticals(&name, &criticals) {
                        EntryGate::Enter => {}
                        EntryGate::Declined => {
                            reporter.shell_entry_declined(&name);
                            return 0;
                        }
                        EntryGate::Refused => return EX_USAGE,
                    }
                    match tenants.shell(
                        &name,
                        host,
                        &argv,
                        resolved_mode,
                        inbound,
                        shell_directory.as_deref(),
                        reporter,
                    ) {
                        Ok(code) => {
                            // Command form only: an interactive session leaves nothing to close.
                            if !argv.is_empty() {
                                reporter.shell_command_done(code, resolved_mode);
                            }
                            code.clamp(0, 255) as u8
                        }
                        Err(tenants::ShellError::Account(e)) => {
                            reporter.shell_failed(&name, &e);
                            EX_IOERR
                        }
                        Err(tenants::ShellError::Mode(
                            tenants::ModeError::RestrictedOnPermissiveProfile,
                        )) => {
                            reporter.refuse_restricted_on_permissive_profile(&name);
                            EX_USAGE
                        }
                        Err(tenants::ShellError::Mode(e)) => {
                            surface_shell_mode_error(reporter, &name, &e);
                            EX_IOERR
                        }
                        Err(tenants::ShellError::NarrowFailed { child_exit }) => {
                            // TODO(smell): Runtime is passed only to suppress the "narrowed back" suffix — give shell_command_done an explicit flag
                            reporter.shell_narrow_failed(
                                &name,
                                resolved_mode == ModeLevel::Install,
                                inbound == Some(InboundLevel::Permissive),
                            );
                            reporter.shell_command_done(child_exit, ModeLevel::Runtime);
                            child_exit.clamp(0, 255) as u8
                        }
                        Err(tenants::ShellError::StashAbsent { name: refused }) => {
                            reporter.shell_refuse_stash_absent(&refused);
                            EX_USAGE
                        }
                        Err(tenants::ShellError::DirectoryInvalid { raw, reason }) => {
                            reporter.refuse_shell_directory_invalid(&raw, reason);
                            EX_USAGE
                        }
                        Err(tenants::ShellError::DirectoryUnavailable { path }) => {
                            reporter.refuse_shell_directory_unavailable(&name, &path);
                            EX_USAGE
                        }
                        Err(tenants::ShellError::DirectoryProbe { path, err }) => {
                            reporter.shell_directory_probe_failed(&path, &err);
                            EX_IOERR
                        }
                        Err(tenants::ShellError::UnlockFailed(err)) => {
                            reporter.keychain_unlock_failed(&name, &err);
                            EX_IOERR
                        }
                    }
                }
            }
        }
        Verb::Mode { name, level } => {
            if let Err(e) = tenants::validate_name(&name) {
                reporter.refuse_invalid_name(&name, &e);
                return EX_USAGE;
            }
            let eligibility = match tenants::destroy_eligibility(directory, &name) {
                Ok(e) => e,
                Err(e) => {
                    reporter.mode_eligibility_probe_failed(&name, &e);
                    return EX_IOERR;
                }
            };
            match eligibility {
                tenants::Eligibility::NotPresent | tenants::Eligibility::OrphanGroup => {
                    reporter.refuse_mode_absent(&name);
                    EX_USAGE
                }
                tenants::Eligibility::NotATenant { uid } => {
                    reporter.refuse_mode_not_a_tenant(&name, uid, TENANT_UID_FLOOR);
                    EX_USAGE
                }
                tenants::Eligibility::SystemAccount => {
                    reporter.refuse_mode_system_account(&name);
                    EX_USAGE
                }
                tenants::Eligibility::Destroyable => {
                    // Plan before summary, so pre-flight failures surface before the prompt.
                    if reporter.refuse_sudo_without_terminal() {
                        return EX_USAGE;
                    }
                    let plan = match tenants.build_reapply_plan(
                        &name,
                        host,
                        level,
                        None,
                        tenants::ReapplyScope::Light,
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            surface_mode_error(reporter, &name, &e);
                            return EX_IOERR;
                        }
                    };
                    let plan_entries = plan.as_plan_entries();
                    if show_summary {
                        reporter.mode_summary(&name, host, level, Some(&plan_entries));
                        tenants.pre_exec_doctor_summary(
                            Some(&name),
                            host,
                            tenants::DoctorScope::Mode,
                            reporter,
                        );
                    }
                    if let Some(code) = consent(reporter, true) {
                        return code;
                    }
                    match tenants.mode(&name, level, &plan, reporter) {
                        Ok(()) => 0,
                        Err(e) => {
                            surface_mode_error(reporter, &name, &e);
                            EX_IOERR
                        }
                    }
                }
            }
        }
        Verb::Inbound { name, level } => {
            if let Err(e) = tenants::validate_name(&name) {
                reporter.refuse_invalid_name(&name, &e);
                return EX_USAGE;
            }
            let eligibility = match tenants::destroy_eligibility(directory, &name) {
                Ok(e) => e,
                Err(e) => {
                    reporter.inbound_eligibility_probe_failed(&name, &e);
                    return EX_IOERR;
                }
            };
            match eligibility {
                tenants::Eligibility::NotPresent | tenants::Eligibility::OrphanGroup => {
                    reporter.refuse_inbound_absent(&name);
                    EX_USAGE
                }
                tenants::Eligibility::NotATenant { uid } => {
                    reporter.refuse_inbound_not_a_tenant(&name, uid, TENANT_UID_FLOOR);
                    EX_USAGE
                }
                tenants::Eligibility::SystemAccount => {
                    reporter.refuse_inbound_system_account(&name);
                    EX_USAGE
                }
                tenants::Eligibility::Destroyable => {
                    if reporter.refuse_sudo_without_terminal() {
                        return EX_USAGE;
                    }
                    let plan = match tenants.build_reapply_plan(
                        &name,
                        host,
                        ModeLevel::Runtime,
                        Some(level),
                        tenants::ReapplyScope::Light,
                    ) {
                        Ok(p) => p,
                        Err(tenants::ModeError::RestrictedOnPermissiveProfile) => {
                            reporter.refuse_restricted_on_permissive_profile(&name);
                            return EX_USAGE;
                        }
                        Err(e) => {
                            surface_inbound_error(reporter, &name, &e);
                            return EX_IOERR;
                        }
                    };
                    let plan_entries = plan.as_plan_entries();
                    if show_summary {
                        reporter.inbound_summary(&name, host, level, Some(&plan_entries));
                        tenants.pre_exec_doctor_summary(
                            Some(&name),
                            host,
                            tenants::DoctorScope::Mode,
                            reporter,
                        );
                    }
                    if let Some(code) = consent(reporter, true) {
                        return code;
                    }
                    match tenants.inbound(&name, level, &plan, reporter) {
                        Ok(()) => 0,
                        Err(e) => {
                            surface_inbound_error(reporter, &name, &e);
                            EX_IOERR
                        }
                    }
                }
            }
        }
        Verb::Doctor { name, strict } => match name {
            Some(n) => {
                if let Err(e) = tenants::validate_name(&n) {
                    reporter.refuse_invalid_name(&n, &e);
                    return EX_USAGE;
                }
                let eligibility = match tenants::destroy_eligibility(directory, &n) {
                    Ok(e) => e,
                    Err(e) => {
                        reporter.doctor_eligibility_probe_failed(&n, &e);
                        return EX_IOERR;
                    }
                };
                match eligibility {
                    tenants::Eligibility::NotPresent | tenants::Eligibility::OrphanGroup => {
                        reporter.refuse_doctor_absent(&n);
                        EX_USAGE
                    }
                    tenants::Eligibility::NotATenant { uid } => {
                        reporter.refuse_doctor_not_a_tenant(&n, uid, TENANT_UID_FLOOR);
                        EX_USAGE
                    }
                    tenants::Eligibility::SystemAccount => {
                        reporter.refuse_doctor_system_account(&n);
                        EX_USAGE
                    }
                    tenants::Eligibility::Destroyable => {
                        let (peers, enumerated) = match directory.tenant_names() {
                            Ok(names) => (names, true),
                            Err(e) => {
                                reporter.doctor_enumeration_failed(&e);
                                (Vec::new(), false)
                            }
                        };
                        let others: Vec<&super::TenantUserName> =
                            peers.iter().filter(|peer| **peer != n).collect();
                        let mut outcome = tenants.doctor(host, &n, &others, reporter);
                        outcome.probe_failed |= !enumerated;
                        doctor_outcome_exit_code(&outcome, strict)
                    }
                }
            }
            None => match tenants.doctor_all(host, directory, reporter) {
                Ok(outcome) => doctor_outcome_exit_code(&outcome, strict),
                Err(e) => {
                    reporter.doctor_error(&e);
                    EX_IOERR
                }
            },
        },
        Verb::Reload { name } => match name {
            Some(n) => {
                if let Err(e) = tenants::validate_name(&n) {
                    reporter.refuse_invalid_name(&n, &e);
                    return EX_USAGE;
                }
                let eligibility = match tenants::destroy_eligibility(directory, &n) {
                    Ok(e) => e,
                    Err(e) => {
                        reporter.reload_eligibility_probe_failed(&n, &e);
                        return EX_IOERR;
                    }
                };
                match eligibility {
                    tenants::Eligibility::NotPresent | tenants::Eligibility::OrphanGroup => {
                        reporter.refuse_reload_absent(&n);
                        EX_USAGE
                    }
                    tenants::Eligibility::NotATenant { uid } => {
                        reporter.refuse_reload_not_a_tenant(&n, uid, TENANT_UID_FLOOR);
                        EX_USAGE
                    }
                    tenants::Eligibility::SystemAccount => {
                        reporter.refuse_reload_system_account(&n);
                        EX_USAGE
                    }
                    tenants::Eligibility::Destroyable => {
                        if reporter.refuse_sudo_without_terminal() {
                            return EX_USAGE;
                        }
                        let plan = match tenants.build_reapply_plan(
                            &n,
                            host,
                            ModeLevel::Runtime,
                            None,
                            tenants::ReapplyScope::Full,
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                surface_reload_error(reporter, &n, &e);
                                return EX_IOERR;
                            }
                        };
                        let plan_entries = plan.as_plan_entries();
                        if show_summary {
                            reporter.reload_summary(&n, host, Some(&plan_entries));
                            tenants.pre_exec_doctor_summary(
                                Some(&n),
                                host,
                                tenants::DoctorScope::Reload,
                                reporter,
                            );
                        }
                        if let Some(code) = consent(reporter, true) {
                            return code;
                        }
                        match tenants.reload(&n, &plan, reporter) {
                            Ok(()) => 0,
                            Err(e) => {
                                surface_reload_error(reporter, &n, &e);
                                EX_IOERR
                            }
                        }
                    }
                }
            }
            None => {
                let names = match directory.tenant_names() {
                    Ok(n) => n,
                    Err(e) => {
                        reporter.reload_all_enumeration_failed(&e);
                        return EX_IOERR;
                    }
                };
                if names.is_empty() {
                    return match tenants.reload_all(directory, host, reporter) {
                        Ok(outcome) if outcome.failed == 0 => 0,
                        Ok(_) => EX_IOERR,
                        Err(e) => {
                            reporter.reload_all_enumeration_failed(&e);
                            EX_IOERR
                        }
                    };
                }
                if show_summary {
                    reporter.reload_all_summary(host, &names);
                }
                if let Some(code) = consent(reporter, true) {
                    return code;
                }
                match tenants.reload_all(directory, host, reporter) {
                    Ok(outcome) if outcome.failed == 0 => 0,
                    Ok(_) => EX_IOERR,
                    Err(e) => {
                        reporter.reload_all_enumeration_failed(&e);
                        EX_IOERR
                    }
                }
            }
        },
        Verb::Bootstrap { name } => match name {
            Some(n) => {
                if let Err(e) = tenants::validate_name(&n) {
                    reporter.refuse_invalid_name(&n, &e);
                    return EX_USAGE;
                }
                let eligibility = match tenants::destroy_eligibility(directory, &n) {
                    Ok(e) => e,
                    Err(e) => {
                        reporter.bootstrap_eligibility_probe_failed(&n, &e);
                        return EX_IOERR;
                    }
                };
                match eligibility {
                    tenants::Eligibility::NotPresent | tenants::Eligibility::OrphanGroup => {
                        reporter.refuse_bootstrap_absent(&n);
                        EX_USAGE
                    }
                    tenants::Eligibility::NotATenant { uid } => {
                        reporter.refuse_bootstrap_not_a_tenant(&n, uid, TENANT_UID_FLOOR);
                        EX_USAGE
                    }
                    tenants::Eligibility::SystemAccount => {
                        reporter.refuse_bootstrap_system_account(&n);
                        EX_USAGE
                    }
                    tenants::Eligibility::Destroyable => {
                        if reporter.refuse_sudo_without_terminal() {
                            return EX_USAGE;
                        }
                        let plan = match tenants.build_bootstrap_plan(&n, host) {
                            Ok(p) => p,
                            Err(e) => {
                                tenants::surface_bootstrap_error(
                                    reporter,
                                    &n,
                                    &tenants::BootstrapError::Mode(e),
                                );
                                return EX_IOERR;
                            }
                        };
                        if plan.commands.is_empty() {
                            reporter.bootstrap_nothing_declared(&n);
                            return 0;
                        }
                        let command_ops = build_bootstrap_command_ops(&n, &plan.commands);
                        let command_entries = bootstrap_command_entries(&command_ops);
                        let infra_entries = plan.widen.as_plan_entries();
                        if show_summary {
                            reporter.bootstrap_summary(&n, &command_entries, &infra_entries);
                            // TODO(smell): DoctorScope::Reload is reused for bootstrap — name the scope after the surfaces it audits, not a verb
                            tenants.pre_exec_doctor_summary(
                                Some(&n),
                                host,
                                tenants::DoctorScope::Reload,
                                reporter,
                            );
                        }
                        if let Some(code) = consent(reporter, true) {
                            return code;
                        }
                        match tenants.bootstrap(&n, host, &plan, reporter) {
                            Ok(()) => 0,
                            Err(e) => {
                                tenants::surface_bootstrap_error(reporter, &n, &e);
                                match e {
                                    tenants::BootstrapError::StashAbsent { .. } => EX_USAGE,
                                    _ => EX_IOERR,
                                }
                            }
                        }
                    }
                }
            }
            None => {
                let names = match directory.tenant_names() {
                    Ok(n) => n,
                    Err(e) => {
                        reporter.bootstrap_all_enumeration_failed(&e);
                        return EX_IOERR;
                    }
                };
                if names.is_empty() {
                    return match tenants.bootstrap_all(directory, host, reporter) {
                        Ok(outcome) if outcome.failed == 0 => 0,
                        Ok(_) => EX_IOERR,
                        Err(e) => {
                            reporter.bootstrap_all_enumeration_failed(&e);
                            EX_IOERR
                        }
                    };
                }
                if show_summary {
                    reporter.bootstrap_all_summary(host, &names);
                }
                if let Some(code) = consent(reporter, true) {
                    return code;
                }
                match tenants.bootstrap_all(directory, host, reporter) {
                    Ok(outcome) if outcome.failed == 0 => 0,
                    Ok(_) => EX_IOERR,
                    Err(e) => {
                        reporter.bootstrap_all_enumeration_failed(&e);
                        EX_IOERR
                    }
                }
            }
        },
        Verb::Setup => match tenants.setup(reporter) {
            Ok(()) => 0,
            Err(e) => {
                surface_setup_error(reporter, &e);
                EX_IOERR
            }
        },
        Verb::Help { topic } => {
            let body = match topic {
                Some(HelpTopic::Profile) => help_body_profile(),
                None => help_body_index(),
            };
            reporter.help_topic(body);
            0
        }
        Verb::Destroy { name } => {
            if let Err(e) = tenants::validate_name(&name) {
                reporter.refuse_invalid_name(&name, &e);
                return EX_USAGE;
            }
            let eligibility = match tenants::destroy_eligibility(directory, &name) {
                Ok(e) => e,
                Err(e) => {
                    reporter.destroy_eligibility_probe_failed(&name, &e);
                    return EX_IOERR;
                }
            };
            match eligibility {
                tenants::Eligibility::NotPresent => {
                    reporter.destroy_absent(&name);
                    0
                }
                tenants::Eligibility::OrphanGroup => {
                    let orphan_plan_ops = build_orphan_plan_ops(&name, host);
                    let orphan_plan = orphan_plan_entries(&orphan_plan_ops);
                    if show_summary {
                        reporter.destroy_orphan_summary(&name, host, Some(&orphan_plan));
                    }
                    if let Some(code) = consent(reporter, false) {
                        return code;
                    }
                    if let Err(e) = tenants.destroy_orphan_group(&name, host, reporter) {
                        surface_destroy_error(reporter, &name, &e);
                        return EX_IOERR;
                    }
                    0
                }
                tenants::Eligibility::NotATenant { uid } => {
                    reporter.refuse_not_a_tenant(&name, uid, TENANT_UID_FLOOR);
                    EX_USAGE
                }
                tenants::Eligibility::SystemAccount => {
                    reporter.refuse_system_account(&name);
                    EX_USAGE
                }
                tenants::Eligibility::Destroyable => {
                    let destroy_plan_ops = build_destroy_plan_ops(&name, host);
                    let destroy_plan = destroy_plan_entries(&destroy_plan_ops);
                    if show_summary {
                        let uid = match directory.uid_for(&name) {
                            Ok(opt) => opt.unwrap_or(super::UserId(0)),
                            Err(e) => {
                                reporter.destroy_uid_lookup_failed(&name, &e);
                                return EX_IOERR;
                            }
                        };
                        reporter.destroy_summary(&name, host, uid, Some(&destroy_plan));
                    }
                    if let Some(code) = consent(reporter, false) {
                        return code;
                    }
                    if let Err(e) = tenants.destroy(&name, host, reporter) {
                        surface_destroy_error(reporter, &name, &e);
                        return EX_IOERR;
                    }
                    0
                }
            }
        }
    }
}

fn surface_destroy_error(
    reporter: &mut Reporter,
    name: &super::TenantUserName,
    error: &tenants::DestroyError,
) {
    match error {
        tenants::DestroyError::Account(e) => reporter.destroy_failed(name, e),
        tenants::DestroyError::Profile(e) => reporter.destroy_profile_failed(name, e),
        tenants::DestroyError::Firewall(e) => reporter.destroy_firewall_failed(name, e),
    }
}

fn surface_setup_error(reporter: &mut Reporter, error: &tenants::SetupError) {
    match error {
        tenants::SetupError::Pam(e) => reporter.setup_pam_failed(e),
    }
}

fn surface_mode_error(
    reporter: &mut Reporter,
    name: &super::TenantUserName,
    error: &tenants::ModeError,
) {
    match error {
        tenants::ModeError::Profile(e) => reporter.mode_profile_failed(name, e),
        tenants::ModeError::Firewall(e) => reporter.mode_failed(name, e),
        tenants::ModeError::Acl(e) => reporter.mode_acl_failed(name, e),
        tenants::ModeError::Account(e) => reporter.mode_account_failed(name, e),
        tenants::ModeError::Probe(e) => reporter.mode_probe_failed(name, e),
        tenants::ModeError::Share(e) => reporter.refuse_mode_share(name, e),
        tenants::ModeError::RestrictedOnPermissiveProfile => {
            reporter.refuse_restricted_on_permissive_profile(name)
        }
    }
}

// TODO(smell): the surface_*_error fns repeat one ModeError match with per-verb Reporter methods — collapse
fn surface_shell_mode_error(
    reporter: &mut Reporter,
    name: &super::TenantUserName,
    error: &tenants::ModeError,
) {
    match error {
        tenants::ModeError::Profile(e) => reporter.shell_narrow_profile_failed(name, e),
        tenants::ModeError::Firewall(e) => reporter.shell_narrow_firewall_failed(name, e),
        tenants::ModeError::Acl(e) => reporter.shell_narrow_acl_failed(name, e),
        tenants::ModeError::Account(e) => reporter.shell_narrow_account_failed(name, e),
        tenants::ModeError::Probe(e) => reporter.shell_narrow_probe_failed(name, e),
        tenants::ModeError::Share(e) => reporter.refuse_shell_share(name, e),
        tenants::ModeError::RestrictedOnPermissiveProfile => {
            reporter.refuse_restricted_on_permissive_profile(name)
        }
    }
}

fn surface_inbound_error(
    reporter: &mut Reporter,
    name: &super::TenantUserName,
    error: &tenants::ModeError,
) {
    match error {
        tenants::ModeError::Profile(e) => reporter.mode_profile_failed(name, e),
        tenants::ModeError::Firewall(e) => reporter.inbound_failed(name, e),
        tenants::ModeError::Acl(e) => reporter.mode_acl_failed(name, e),
        tenants::ModeError::Account(e) => reporter.mode_account_failed(name, e),
        tenants::ModeError::Probe(e) => reporter.mode_probe_failed(name, e),
        tenants::ModeError::Share(e) => reporter.refuse_inbound_share(name, e),
        tenants::ModeError::RestrictedOnPermissiveProfile => {
            reporter.refuse_restricted_on_permissive_profile(name)
        }
    }
}

fn surface_reload_error(
    reporter: &mut Reporter,
    name: &super::TenantUserName,
    error: &tenants::ModeError,
) {
    match error {
        tenants::ModeError::Profile(e) => reporter.reload_profile_failed(name, e),
        tenants::ModeError::Firewall(e) => reporter.reload_firewall_failed(name, e),
        tenants::ModeError::Acl(e) => reporter.mode_acl_failed(name, e),
        tenants::ModeError::Account(e) => reporter.mode_account_failed(name, e),
        tenants::ModeError::Probe(e) => reporter.mode_probe_failed(name, e),
        tenants::ModeError::Share(e) => reporter.refuse_reload_share(name, e),
        tenants::ModeError::RestrictedOnPermissiveProfile => {
            reporter.refuse_restricted_on_permissive_profile(name)
        }
    }
}

/// Display-only ops for the pre-confirm command list; the real run goes through `exec_as_tenant`.
fn build_bootstrap_command_ops(
    name: &super::TenantUserName,
    commands: &[String],
) -> Vec<AccountOp> {
    commands
        .iter()
        .map(|command| AccountOp::ExecAsUser {
            name: name.into(),
            argv: vec!["/bin/sh".to_string(), "-c".to_string(), command.clone()],
            dir: None,
        })
        .collect()
}

fn bootstrap_command_entries(ops: &[AccountOp]) -> Vec<(Op<'_>, Option<&'static str>)> {
    ops.iter().map(|op| (Op::Account(op), None)).collect()
}

// Plan placeholder bodies are empty: `describe_*` ignores them, so plan lines match
// the real ops built after profile-read.

pub(crate) struct CreatePlanOps {
    pub(crate) create_group: AccountOp,
    pub(crate) add_host: AccountOp,
    pub(crate) add_user: AccountOp,
    pub(crate) rollback_group: AccountOp,
    pub(crate) ensure_cowork_dir: AccountOp,
    pub(crate) create_keychain: KeychainOp,
    pub(crate) set_default_keychain: KeychainOp,
    pub(crate) add_to_search_list: KeychainOp,
    pub(crate) disable_auto_lock: KeychainOp,
    pub(crate) stash_password: KeychainOp,
    pub(crate) create_profile: Option<ProfileOp>,
    pub(crate) backup: FirewallOp,
    pub(crate) install_anchor: FirewallOp,
    pub(crate) update_conf: FirewallOp,
    pub(crate) reload: FirewallOp,
    pub(crate) restore: FirewallOp,
    pub(crate) remove_anchor: FirewallOp,
    pub(crate) flush_anchor: FirewallOp,
    pub(crate) enable: FirewallOp,
}

fn build_create_plan_ops(
    name: &super::TenantUserName,
    host: &super::HostUserName,
    uid: super::UserId,
    gid: super::GroupId,
    keep_profile: bool,
) -> CreatePlanOps {
    let group = tenants::tenant_share_group_name(name.as_str());
    // describe_keychain renders `<password>` regardless; the real one is generated in `Tenants::create`.
    let plan_placeholder = super::KeychainPassword::for_plan_placeholder();
    CreatePlanOps {
        create_group: AccountOp::CreateShareGroup {
            group: group.clone(),
            gid,
        },
        add_host: AccountOp::AddHostToShareGroup {
            group: group.clone(),
            host: host.into(),
        },
        add_user: AccountOp::CreateTenantUser {
            name: name.into(),
            uid,
            gid,
        },
        rollback_group: AccountOp::DeleteShareGroup {
            group: group.clone(),
        },
        ensure_cowork_dir: AccountOp::EnsureCoworkDir {
            path: tenants::cowork_dir_path(name.as_str()),
            owner: host.into(),
            group,
            mode: 0o2770,
        },
        create_keychain: KeychainOp::CreateTenantKeychain {
            name: name.into(),
            password: plan_placeholder.clone(),
        },
        set_default_keychain: KeychainOp::SetDefaultKeychain { name: name.into() },
        add_to_search_list: KeychainOp::AddKeychainToSearchList { name: name.into() },
        disable_auto_lock: KeychainOp::DisableKeychainAutoLock { name: name.into() },
        stash_password: KeychainOp::StashPassword {
            name: name.into(),
            password: plan_placeholder,
        },
        create_profile: (!keep_profile).then(|| ProfileOp::Create { name: name.into() }),
        backup: FirewallOp::BackupConfig,
        install_anchor: FirewallOp::InstallAnchor {
            name: name.into(),
            body: String::new(),
        },
        update_conf: FirewallOp::UpdateConfig {
            content: String::new(),
        },
        reload: FirewallOp::Reload,
        restore: FirewallOp::RestoreConfigFromBackup,
        remove_anchor: FirewallOp::RemoveAnchor { name: name.into() },
        flush_anchor: FirewallOp::FlushAnchor { name: name.into() },
        enable: FirewallOp::Enable,
    }
}

fn create_plan_entries(ops: &CreatePlanOps) -> Vec<(Op<'_>, Option<&'static str>)> {
    let entries = vec![
        Some((Op::Account(&ops.create_group), None)),
        Some((Op::Account(&ops.add_host), None)),
        Some((Op::Account(&ops.add_user), None)),
        Some((Op::Account(&ops.rollback_group), Some("on rollback"))),
        Some((Op::Account(&ops.ensure_cowork_dir), None)),
        Some((Op::Keychain(&ops.create_keychain), None)),
        Some((Op::Keychain(&ops.set_default_keychain), None)),
        Some((Op::Keychain(&ops.add_to_search_list), None)),
        Some((Op::Keychain(&ops.disable_auto_lock), None)),
        Some((Op::Keychain(&ops.stash_password), None)),
        ops.create_profile
            .as_ref()
            .map(|op| (Op::Profile(op), None)),
        Some((Op::Firewall(&ops.backup), None)),
        Some((Op::Firewall(&ops.install_anchor), None)),
        Some((Op::Firewall(&ops.update_conf), None)),
        Some((Op::Firewall(&ops.reload), None)),
        Some((Op::Firewall(&ops.restore), Some("on reload failure"))),
        Some((Op::Firewall(&ops.remove_anchor), Some("on reload failure"))),
        Some((Op::Firewall(&ops.reload), Some("on reload failure"))),
        Some((Op::Firewall(&ops.flush_anchor), Some("on reload failure"))),
        Some((Op::Firewall(&ops.enable), None)),
    ];
    entries.into_iter().flatten().collect()
}

pub(crate) struct DestroyPlanOps {
    pub(crate) delete_user: AccountOp,
    pub(crate) probe: AccountOp,
    pub(crate) cleanup: AccountOp,
    pub(crate) delete_stashed_password: KeychainOp,
    pub(crate) remove_host: AccountOp,
    pub(crate) delete_group: AccountOp,
    pub(crate) delete_profile: ProfileOp,
    pub(crate) backup: FirewallOp,
    pub(crate) remove_anchor: FirewallOp,
    pub(crate) update_conf: FirewallOp,
    pub(crate) reload: FirewallOp,
    pub(crate) flush_anchor: FirewallOp,
}

fn build_destroy_plan_ops(
    name: &super::TenantUserName,
    host: &super::HostUserName,
) -> DestroyPlanOps {
    let group = tenants::tenant_share_group_name(name.as_str());
    DestroyPlanOps {
        delete_user: AccountOp::DeleteTenantUser { name: name.into() },
        probe: AccountOp::LookupUserRecord { name: name.into() },
        cleanup: AccountOp::DeleteUserRecord { name: name.into() },
        delete_stashed_password: KeychainOp::DeleteStashedPassword { name: name.into() },
        remove_host: AccountOp::RemoveHostFromShareGroup {
            group: group.clone(),
            host: host.into(),
        },
        delete_group: AccountOp::DeleteShareGroup { group },
        delete_profile: ProfileOp::Delete { name: name.into() },
        backup: FirewallOp::BackupConfig,
        remove_anchor: FirewallOp::RemoveAnchor { name: name.into() },
        update_conf: FirewallOp::UpdateConfig {
            content: String::new(),
        },
        reload: FirewallOp::Reload,
        flush_anchor: FirewallOp::FlushAnchor { name: name.into() },
    }
}

fn destroy_plan_entries(ops: &DestroyPlanOps) -> Vec<(Op<'_>, Option<&'static str>)> {
    vec![
        (Op::Account(&ops.delete_user), None),
        (Op::Account(&ops.probe), None),
        (Op::Account(&ops.cleanup), None),
        (Op::Keychain(&ops.delete_stashed_password), None),
        (Op::Account(&ops.remove_host), None),
        (Op::Account(&ops.delete_group), None),
        (Op::Profile(&ops.delete_profile), None),
        (Op::Firewall(&ops.backup), None),
        (Op::Firewall(&ops.remove_anchor), None),
        (Op::Firewall(&ops.update_conf), None),
        (Op::Firewall(&ops.reload), None),
        (Op::Firewall(&ops.flush_anchor), None),
    ]
}

pub(crate) struct OrphanGroupPlanOps {
    pub(crate) remove_host: AccountOp,
    pub(crate) delete_stashed_password: KeychainOp,
    pub(crate) delete_group: AccountOp,
    pub(crate) delete_profile: ProfileOp,
    pub(crate) backup: FirewallOp,
    pub(crate) remove_anchor: FirewallOp,
    pub(crate) update_conf: FirewallOp,
    pub(crate) reload: FirewallOp,
    pub(crate) flush_anchor: FirewallOp,
}

fn build_orphan_plan_ops(
    name: &super::TenantUserName,
    host: &super::HostUserName,
) -> OrphanGroupPlanOps {
    let group = tenants::tenant_share_group_name(name.as_str());
    OrphanGroupPlanOps {
        remove_host: AccountOp::RemoveHostFromShareGroup {
            group: group.clone(),
            host: host.into(),
        },
        delete_stashed_password: KeychainOp::DeleteStashedPassword { name: name.into() },
        delete_group: AccountOp::DeleteShareGroup { group },
        delete_profile: ProfileOp::Delete { name: name.into() },
        backup: FirewallOp::BackupConfig,
        remove_anchor: FirewallOp::RemoveAnchor { name: name.into() },
        update_conf: FirewallOp::UpdateConfig {
            content: String::new(),
        },
        reload: FirewallOp::Reload,
        flush_anchor: FirewallOp::FlushAnchor { name: name.into() },
    }
}

fn orphan_plan_entries(ops: &OrphanGroupPlanOps) -> Vec<(Op<'_>, Option<&'static str>)> {
    vec![
        (Op::Account(&ops.remove_host), None),
        (Op::Keychain(&ops.delete_stashed_password), None),
        (Op::Account(&ops.delete_group), None),
        (Op::Profile(&ops.delete_profile), None),
        (Op::Firewall(&ops.backup), None),
        (Op::Firewall(&ops.remove_anchor), None),
        (Op::Firewall(&ops.update_conf), None),
        (Op::Firewall(&ops.reload), None),
        (Op::Firewall(&ops.flush_anchor), None),
    ]
}

// TODO(smell): Profile/Firewall arms are unreachable here — narrow the error type
/// The tenant already exists, so the framing points recovery at `tenant reload`, not
/// `tenant create` (which would refuse on name-conflict).
fn surface_create_post_provision_error(
    reporter: &mut Reporter,
    name: &super::TenantUserName,
    error: &tenants::ModeError,
) {
    match error {
        tenants::ModeError::Profile(e) => reporter.mode_profile_failed(name, e),
        tenants::ModeError::Firewall(e) => reporter.mode_failed(name, e),
        tenants::ModeError::Acl(e) => reporter.create_post_provision_acl_failed(name, e),
        tenants::ModeError::Account(e) => reporter.create_post_provision_account_failed(name, e),
        tenants::ModeError::Probe(e) => reporter.create_post_provision_probe_failed(name, e),
        tenants::ModeError::Share(e) => reporter.refuse_create_post_provision_share(name, e),
        tenants::ModeError::RestrictedOnPermissiveProfile => {
            reporter.refuse_restricted_on_permissive_profile(name)
        }
    }
}

fn help_body_index() -> &'static str {
    include_str!("../resources/help_index.txt")
}

fn help_body_profile() -> &'static str {
    include_str!("../resources/help_profile.txt")
}
