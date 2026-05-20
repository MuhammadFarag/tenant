use super::reporter::{ConfirmOutcome, Reporter};
use super::{AccountOp, FirewallOp, KeychainOp, Op, ProfileOp, tenants};
use crate::doctor::Severity;
use crate::{Cli, HelpTopic, ModeLevel, Verb, allocation, allocation::TENANT_UID_FLOOR};

const EX_USAGE: u8 = 64;
const EX_IOERR: u8 = 74;
const EX_DOCTOR_WARNING: u8 = 1;
const EX_DOCTOR_CRITICAL: u8 = 2;

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
            let create_plan_ops = build_create_plan_ops(&name, host, uid, gid);
            let create_plan = create_plan_entries(&create_plan_ops);
            if show_summary {
                reporter.create_summary(&name, host, uid, gid, Some(&create_plan));
                tenants.pre_exec_doctor_summary(None, host, tenants::DoctorScope::Create, reporter);
            }
            if reporter.confirm(true) == ConfirmOutcome::Abort {
                reporter.aborted();
                return 0;
            }
            match tenants.create(&name, host, uid, gid, reporter) {
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
                    // Emit the original failure first so log-grep regexes
                    // matching the single-failure shape keep working; the
                    // rollback-failed line follows with its recovery hint.
                    reporter.create_failed(&name, &user);
                    reporter.create_rollback_failed(&name, &rollback);
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
        Verb::Shell { name, mode, argv } => {
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
                        if argv.is_empty() {
                            reporter.shell_summary(&name, host);
                        } else {
                            reporter.shell_command_summary(&name, host, resolved_mode, &argv);
                        }
                        tenants.pre_exec_doctor_summary(
                            Some(&name),
                            host,
                            tenants::DoctorScope::Shell,
                            reporter,
                        );
                    }
                    match tenants.shell(&name, host, &argv, resolved_mode, reporter) {
                        Ok(code) => {
                            // Closing surface is command-form-only; the
                            // interactive form has no terminal context
                            // left to render into after the session ends.
                            if !argv.is_empty() {
                                reporter.shell_command_done(code, resolved_mode);
                            }
                            code.clamp(0, 255) as u8
                        }
                        Err(tenants::ShellError::Account(e)) => {
                            reporter.shell_failed(&name, &e);
                            EX_IOERR
                        }
                        Err(tenants::ShellError::Mode(e)) => {
                            surface_shell_mode_error(reporter, &name, &e);
                            EX_IOERR
                        }
                        Err(tenants::ShellError::NarrowFailed {
                            child_exit,
                            narrow_err,
                        }) => {
                            // Child exit wins; the warning carries the
                            // narrow-failure signal. Pass Runtime to elide
                            // the "narrowed back" suffix — it would lie
                            // when the narrow just failed.
                            reporter.shell_narrow_failed(&name, &narrow_err);
                            reporter.shell_command_done(child_exit, ModeLevel::Runtime);
                            child_exit.clamp(0, 255) as u8
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
                    // Build the reapply plan BEFORE the summary so
                    // profile-read / share pre-flight failures surface
                    // pre-prompt — don't ask the operator to confirm
                    // something already doomed.
                    let plan = match tenants.build_reapply_plan(&name, host, level) {
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
                    if reporter.confirm(true) == ConfirmOutcome::Abort {
                        reporter.aborted();
                        return 0;
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
                        match tenants.doctor(host, &n, &[], reporter) {
                            Ok(outcome) => doctor_exit_code(outcome.max_severity(), strict),
                            Err(e) => {
                                surface_doctor_error(reporter, &e);
                                EX_IOERR
                            }
                        }
                    }
                }
            }
            None => match tenants.doctor_all(host, directory, reporter) {
                Ok(outcome) => doctor_exit_code(outcome.max_severity(), strict),
                Err(e) => {
                    surface_doctor_error(reporter, &e);
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
                        // Build plan pre-summary so profile-read / share
                        // pre-flight failures surface pre-prompt.
                        let plan = match tenants.build_reapply_plan(&n, host, ModeLevel::Runtime) {
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
                        if reporter.confirm(true) == ConfirmOutcome::Abort {
                            reporter.aborted();
                            return 0;
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
                // Show scope before the prompt; empty host has nothing
                // to confirm, so skip straight to the no-op summary.
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
                if reporter.confirm(true) == ConfirmOutcome::Abort {
                    reporter.aborted();
                    return 0;
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
                    // Convergence path: tenant user is gone but the
                    // suffixed group survived a prior partial failure.
                    let orphan_plan_ops = build_orphan_plan_ops(&name, host);
                    let orphan_plan = orphan_plan_entries(&orphan_plan_ops);
                    if show_summary {
                        reporter.destroy_orphan_summary(&name, host, Some(&orphan_plan));
                    }
                    if reporter.confirm(false) == ConfirmOutcome::Abort {
                        reporter.aborted();
                        return 0;
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
                    if reporter.confirm(false) == ConfirmOutcome::Abort {
                        reporter.aborted();
                        return 0;
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

fn surface_doctor_error(reporter: &mut Reporter, error: &tenants::DoctorError) {
    match error {
        tenants::DoctorError::Probe(e) => reporter.doctor_failed(e),
        tenants::DoctorError::HostFile(e) => reporter.doctor_host_file_failed(e),
        tenants::DoctorError::Firewall(e) => reporter.doctor_firewall_failed(e),
        tenants::DoctorError::UserDirectoryLookup(e) => reporter.doctor_enumeration_failed(e),
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
    }
}

/// Parallel to `surface_mode_error` with shell-entry phrasing: the
/// operator typed `tenant shell`, so the frame names the narrow as a
/// step within the shell verb, not a standalone mode switch.
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
    }
}

/// Parallel to `surface_mode_error` with reload-specific wording on
/// Firewall + Share arms; Acl / Account / Probe arms reuse the
/// mode-named methods whose wording is verb-agnostic.
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
    }
}

// Plan-slice construction for prompt-having verbs. `*_plan_ops` owns
// the ops; `*_plan_entries` flattens them into the borrowed-slice the
// Reporter expects. InstallAnchor / UpdateConfig placeholder bodies
// are empty strings; `describe_via` ignores those fields, so plan +
// echo lines match the real ops constructed later after profile-read.

pub(crate) struct CreatePlanOps {
    pub(crate) create_group: AccountOp,
    pub(crate) add_host: AccountOp,
    pub(crate) add_user: AccountOp,
    pub(crate) rollback_group: AccountOp,
    pub(crate) create_keychain: KeychainOp,
    pub(crate) set_default_keychain: KeychainOp,
    pub(crate) add_to_search_list: KeychainOp,
    pub(crate) disable_auto_lock: KeychainOp,
    pub(crate) stash_password: KeychainOp,
    pub(crate) create_profile: ProfileOp,
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
) -> CreatePlanOps {
    let group = tenants::tenant_share_group_name(name.as_str());
    // Plan-side placeholder password: describe_keychain always
    // renders `<password>` regardless of the actual bytes, so the
    // displayed plan never reveals secret material. The real
    // password is generated inside `Tenants::create`.
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
        rollback_group: AccountOp::DeleteShareGroup { group },
        create_keychain: KeychainOp::CreateLoginKeychain {
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
        create_profile: ProfileOp::Create { name: name.into() },
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
    vec![
        (Op::Account(&ops.create_group), None),
        (Op::Account(&ops.add_host), None),
        (Op::Account(&ops.add_user), None),
        (Op::Account(&ops.rollback_group), Some("on rollback")),
        (Op::Keychain(&ops.create_keychain), None),
        (Op::Keychain(&ops.set_default_keychain), None),
        (Op::Keychain(&ops.add_to_search_list), None),
        (Op::Keychain(&ops.disable_auto_lock), None),
        (Op::Keychain(&ops.stash_password), None),
        (Op::Profile(&ops.create_profile), None),
        (Op::Firewall(&ops.backup), None),
        (Op::Firewall(&ops.install_anchor), None),
        (Op::Firewall(&ops.update_conf), None),
        (Op::Firewall(&ops.reload), None),
        (Op::Firewall(&ops.restore), Some("on reload failure")),
        (Op::Firewall(&ops.remove_anchor), Some("on reload failure")),
        (Op::Firewall(&ops.reload), Some("on reload failure")),
        (Op::Firewall(&ops.flush_anchor), Some("on reload failure")),
        (Op::Firewall(&ops.enable), None),
    ]
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

/// Post-provision is the arm where the tenant is already provisioned
/// but share-reapply failed; the per-arm framing names the existing
/// state so the operator's recovery is `tenant reload`, not a fresh
/// `tenant create` (which would refuse on name-conflict). Profile /
/// Firewall arms are unreachable here but wired for completeness.
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
    }
}

/// Body for `tenant help` with no topic — lists available topics.
fn help_body_index() -> &'static str {
    r#"tenant help — long-form topic help

Available topics:

  profile    Per-tenant profile TOML schema and [[shares]] format

Run `tenant help <topic>` to view a topic.
"#
}

/// Body for `tenant help profile`. Plain text; raw string preserves the
/// two-space indent inside sections without backslash-continuation
/// stripping it. No ANSI styling — Reporter renders verbatim.
fn help_body_profile() -> &'static str {
    r#"tenant profile — per-tenant TOML configuration

Location

  ~/.config/tenant/profiles/<name>.toml

  Read on every `tenant create` (scaffolded), `tenant mode`,
  `tenant reload`, and `tenant shell`. Edits take effect on the
  next `tenant reload <name>` (or `tenant shell <name>` entry).

Schema

  schema_version = 1

  [allowlist.runtime]
  hosts = ["github.com", "api.anthropic.com"]

  [allowlist.install]
  hosts = ["registry.npmjs.org", "pypi.org"]

  Two allowlist tiers gate PF egress. Runtime is the baseline;
  install is the widened set used under `tenant mode <name> install`
  (persistent) or `tenant shell <name> --mode install -- <cmd>`
  (auto-narrows back to runtime on completion).

Shares

  [[shares]]
  host_path = "/Users/alice/projects/foo"
  mode = "ro"
  tenant_path = "$HOME/projects/foo"

  Each [[shares]] entry grants the tenant's share group access to a
  host path and (optionally) symlinks it under the tenant's home.

    host_path    Literal absolute path on the host.
    mode         "ro" (read-only) or "rw" (read-write). POSIX
                 bit-string forms (e.g. "r--") are rejected because
                 their file-vs-directory semantics diverge.
    tenant_path  $HOME-templated path inside the tenant's home.
                 $HOME resolves only as a path prefix: position 0
                 ($HOME alone or $HOME/...). Mid-string $HOME is
                 refused as a likely typo.

  File vs directory: ro on a directory grants list+read; rw grants
  full create/append/delete with inheritance to nested entries.
  Files mirror the same intent. The tenant_path is created as a
  symlink to host_path on reapply; an existing non-symlink at
  tenant_path is refused (the operator's data could be at risk).

  Removing a [[shares]] entry does NOT auto-revoke the ACL or
  symlink — `tenant doctor <name>` surfaces orphans. Manual cleanup
  is the operator's call.

Non-goal: filesystem contents

  tenant deliberately does not provision the tenant's filesystem
  contents (no `git clone`, no `mkdir`, no template files). There
  is no [provision] section. Bootstrap inside the tenant after
  creation:

    tenant shell <name> -- git clone https://github.com/you/repo

Applying changes

  Re-render the firewall anchor and re-apply shares after editing:

    tenant reload <name>

  Audit the result:

    tenant doctor <name>
"#
}
