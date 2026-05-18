use std::io::BufRead;

use super::reporter::{ConfirmOutcome, Reporter};
use super::{AccountOp, FirewallOp, Op, ProfileOp, accounts};
use crate::doctor::Severity;
use crate::{Cli, ModeLevel, Verb, allocation, allocation::TENANT_UID_FLOOR};

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

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch(
    cli: Cli,
    accounts: &dyn super::HostAccounts,
    writer: &accounts::Writer<'_>,
    host: &super::HostUserName,
    reporter: &mut Reporter,
    stdin: &mut dyn BufRead,
    stdin_is_tty: bool,
    yes_flag: bool,
) -> u8 {
    // `--yes` suppresses the prompt, not the summary: an operator on a
    // TTY still sees context; scripted (non-TTY real-mode) stays silent.
    let show_summary = cli.dry_run || stdin_is_tty;
    match cli.verb {
        Verb::Create { name } => {
            if let Err(e) = accounts::validate_name(&name) {
                reporter.refuse_invalid_name(&name, &e);
                return EX_USAGE;
            }
            if let Err(e) = accounts::check_conflict(accounts, &name) {
                reporter.refuse_name_conflict(&name, &e);
                return EX_USAGE;
            }
            let uid = allocation::UidAllocator::new(accounts).lowest_free_uid();
            let gid = allocation::GidAllocator::new(accounts).lowest_free_gid();
            let create_plan_ops = build_create_plan_ops(&name, host, uid, gid);
            let create_plan = create_plan_entries(&create_plan_ops);
            if show_summary {
                reporter.create_summary(&name, host, uid, gid, Some(&create_plan));
                writer.pre_exec_doctor_summary(None, host, accounts::DoctorScope::Create, reporter);
            }
            if reporter.confirm(true, stdin, stdin_is_tty, yes_flag) == ConfirmOutcome::Abort {
                reporter.aborted();
                return 0;
            }
            match writer.create_tenant(&name, host, uid, gid, reporter) {
                Ok(()) => 0,
                Err(accounts::CreateError::Group(e)) => {
                    reporter.create_group_failed(&name, &e);
                    EX_IOERR
                }
                Err(accounts::CreateError::HostMembership(e)) => {
                    reporter.create_host_membership_failed(&name, host, &e);
                    EX_IOERR
                }
                Err(accounts::CreateError::User(e)) => {
                    reporter.create_failed(&name, &e);
                    EX_IOERR
                }
                Err(accounts::CreateError::UserWithRollback { user, rollback }) => {
                    // Emit the original failure first so log-grep regexes
                    // matching the single-failure shape keep working; the
                    // rollback-failed line follows with its recovery hint.
                    reporter.create_failed(&name, &user);
                    reporter.create_rollback_failed(&name, &rollback);
                    EX_IOERR
                }
                Err(accounts::CreateError::Profile(e)) => {
                    reporter.create_profile_failed(&name, &e);
                    EX_IOERR
                }
                Err(accounts::CreateError::Firewall(e)) => {
                    reporter.create_firewall_failed(&name, &e);
                    EX_IOERR
                }
                Err(accounts::CreateError::PostProvision(e)) => {
                    surface_create_post_provision_error(reporter, &name, &e);
                    EX_IOERR
                }
            }
        }
        Verb::Shell { name, mode, argv } => {
            if let Err(e) = accounts::validate_name(&name) {
                reporter.refuse_invalid_name(&name, &e);
                return EX_USAGE;
            }
            // NotPresent + OrphanGroup collapse to one refusal: shell can't
            // run against a lingering group; convergence belongs to destroy.
            match accounts::destroy_eligibility(accounts, &name) {
                accounts::Eligibility::NotPresent | accounts::Eligibility::OrphanGroup => {
                    reporter.refuse_shell_absent(&name);
                    EX_USAGE
                }
                accounts::Eligibility::NotATenant { uid } => {
                    reporter.refuse_shell_not_a_tenant(&name, uid, TENANT_UID_FLOOR);
                    EX_USAGE
                }
                accounts::Eligibility::SystemAccount => {
                    reporter.refuse_shell_system_account(&name);
                    EX_USAGE
                }
                accounts::Eligibility::Destroyable => {
                    let resolved_mode = mode.unwrap_or(ModeLevel::Runtime);
                    if show_summary {
                        if argv.is_empty() {
                            reporter.shell_summary(&name, host);
                        } else {
                            reporter.shell_command_summary(&name, host, resolved_mode, &argv);
                        }
                        writer.pre_exec_doctor_summary(
                            Some(&name),
                            host,
                            accounts::DoctorScope::Shell,
                            reporter,
                        );
                    }
                    match writer.shell_into_tenant(&name, host, &argv, resolved_mode, reporter) {
                        Ok(code) => {
                            // Closing surface is command-form-only; the
                            // interactive form has no terminal context
                            // left to render into after the session ends.
                            if !argv.is_empty() {
                                reporter.shell_command_done(code, resolved_mode);
                            }
                            code.clamp(0, 255) as u8
                        }
                        Err(accounts::ShellError::Account(e)) => {
                            reporter.shell_failed(&name, &e);
                            EX_IOERR
                        }
                        Err(accounts::ShellError::Mode(e)) => {
                            surface_shell_mode_error(reporter, &name, &e);
                            EX_IOERR
                        }
                        Err(accounts::ShellError::NarrowFailed {
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
            if let Err(e) = accounts::validate_name(&name) {
                reporter.refuse_invalid_name(&name, &e);
                return EX_USAGE;
            }
            match accounts::destroy_eligibility(accounts, &name) {
                accounts::Eligibility::NotPresent | accounts::Eligibility::OrphanGroup => {
                    reporter.refuse_mode_absent(&name);
                    EX_USAGE
                }
                accounts::Eligibility::NotATenant { uid } => {
                    reporter.refuse_mode_not_a_tenant(&name, uid, TENANT_UID_FLOOR);
                    EX_USAGE
                }
                accounts::Eligibility::SystemAccount => {
                    reporter.refuse_mode_system_account(&name);
                    EX_USAGE
                }
                accounts::Eligibility::Destroyable => {
                    // Build the reapply plan BEFORE the summary so
                    // profile-read / share pre-flight failures surface
                    // pre-prompt — don't ask the operator to confirm
                    // something already doomed.
                    let plan = match writer.build_reapply_plan(&name, host, level) {
                        Ok(p) => p,
                        Err(e) => {
                            surface_mode_error(reporter, &name, &e);
                            return EX_IOERR;
                        }
                    };
                    let plan_entries = plan.as_plan_entries();
                    if show_summary {
                        reporter.mode_summary(&name, host, level, Some(&plan_entries));
                        writer.pre_exec_doctor_summary(
                            Some(&name),
                            host,
                            accounts::DoctorScope::Mode,
                            reporter,
                        );
                    }
                    if reporter.confirm(true, stdin, stdin_is_tty, yes_flag)
                        == ConfirmOutcome::Abort
                    {
                        reporter.aborted();
                        return 0;
                    }
                    match writer.apply_tenant_mode(&name, level, &plan, reporter) {
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
                if let Err(e) = accounts::validate_name(&n) {
                    reporter.refuse_invalid_name(&n, &e);
                    return EX_USAGE;
                }
                match accounts::destroy_eligibility(accounts, &n) {
                    accounts::Eligibility::NotPresent | accounts::Eligibility::OrphanGroup => {
                        reporter.refuse_doctor_absent(&n);
                        EX_USAGE
                    }
                    accounts::Eligibility::NotATenant { uid } => {
                        reporter.refuse_doctor_not_a_tenant(&n, uid, TENANT_UID_FLOOR);
                        EX_USAGE
                    }
                    accounts::Eligibility::SystemAccount => {
                        reporter.refuse_doctor_system_account(&n);
                        EX_USAGE
                    }
                    accounts::Eligibility::Destroyable => {
                        match writer.doctor_tenant(host, &n, &[], reporter) {
                            Ok(outcome) => doctor_exit_code(outcome.max_severity(), strict),
                            Err(e) => {
                                surface_doctor_error(reporter, &e);
                                EX_IOERR
                            }
                        }
                    }
                }
            }
            None => match writer.doctor_all_tenants(host, accounts, reporter) {
                Ok(outcome) => doctor_exit_code(outcome.max_severity(), strict),
                Err(e) => {
                    surface_doctor_error(reporter, &e);
                    EX_IOERR
                }
            },
        },
        Verb::Reload { name } => match name {
            Some(n) => {
                if let Err(e) = accounts::validate_name(&n) {
                    reporter.refuse_invalid_name(&n, &e);
                    return EX_USAGE;
                }
                match accounts::destroy_eligibility(accounts, &n) {
                    accounts::Eligibility::NotPresent | accounts::Eligibility::OrphanGroup => {
                        reporter.refuse_reload_absent(&n);
                        EX_USAGE
                    }
                    accounts::Eligibility::NotATenant { uid } => {
                        reporter.refuse_reload_not_a_tenant(&n, uid, TENANT_UID_FLOOR);
                        EX_USAGE
                    }
                    accounts::Eligibility::SystemAccount => {
                        reporter.refuse_reload_system_account(&n);
                        EX_USAGE
                    }
                    accounts::Eligibility::Destroyable => {
                        // Build plan pre-summary so profile-read / share
                        // pre-flight failures surface pre-prompt.
                        let plan = match writer.build_reapply_plan(&n, host, ModeLevel::Runtime) {
                            Ok(p) => p,
                            Err(e) => {
                                surface_reload_error(reporter, &n, &e);
                                return EX_IOERR;
                            }
                        };
                        let plan_entries = plan.as_plan_entries();
                        if show_summary {
                            reporter.reload_summary(&n, host, Some(&plan_entries));
                            writer.pre_exec_doctor_summary(
                                Some(&n),
                                host,
                                accounts::DoctorScope::Reload,
                                reporter,
                            );
                        }
                        if reporter.confirm(true, stdin, stdin_is_tty, yes_flag)
                            == ConfirmOutcome::Abort
                        {
                            reporter.aborted();
                            return 0;
                        }
                        match writer.reload_tenant(&n, &plan, reporter) {
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
                let names = accounts.tenant_names();
                if names.is_empty() {
                    let outcome = writer.reload_all_tenants(accounts, host, reporter);
                    return if outcome.failed == 0 { 0 } else { EX_IOERR };
                }
                if show_summary {
                    reporter.reload_all_summary(host, &names);
                }
                if reporter.confirm(true, stdin, stdin_is_tty, yes_flag) == ConfirmOutcome::Abort {
                    reporter.aborted();
                    return 0;
                }
                let outcome = writer.reload_all_tenants(accounts, host, reporter);
                if outcome.failed == 0 { 0 } else { EX_IOERR }
            }
        },
        Verb::Destroy { name } => {
            if let Err(e) = accounts::validate_name(&name) {
                reporter.refuse_invalid_name(&name, &e);
                return EX_USAGE;
            }
            match accounts::destroy_eligibility(accounts, &name) {
                accounts::Eligibility::NotPresent => {
                    reporter.destroy_absent(&name);
                    0
                }
                accounts::Eligibility::OrphanGroup => {
                    // Convergence path: tenant user is gone but the
                    // suffixed group survived a prior partial failure.
                    let orphan_plan_ops = build_orphan_plan_ops(&name, host);
                    let orphan_plan = orphan_plan_entries(&orphan_plan_ops);
                    if show_summary {
                        reporter.destroy_orphan_summary(&name, host, Some(&orphan_plan));
                    }
                    if reporter.confirm(false, stdin, stdin_is_tty, yes_flag)
                        == ConfirmOutcome::Abort
                    {
                        reporter.aborted();
                        return 0;
                    }
                    if let Err(e) = writer.destroy_orphan_group(&name, host, reporter) {
                        surface_destroy_error(reporter, &name, &e);
                        return EX_IOERR;
                    }
                    0
                }
                accounts::Eligibility::NotATenant { uid } => {
                    reporter.refuse_not_a_tenant(&name, uid, TENANT_UID_FLOOR);
                    EX_USAGE
                }
                accounts::Eligibility::SystemAccount => {
                    reporter.refuse_system_account(&name);
                    EX_USAGE
                }
                accounts::Eligibility::Destroyable => {
                    let destroy_plan_ops = build_destroy_plan_ops(&name, host);
                    let destroy_plan = destroy_plan_entries(&destroy_plan_ops);
                    if show_summary {
                        let uid = accounts.uid_for(&name).unwrap_or(super::UserId(0));
                        reporter.destroy_summary(&name, host, uid, Some(&destroy_plan));
                    }
                    if reporter.confirm(false, stdin, stdin_is_tty, yes_flag)
                        == ConfirmOutcome::Abort
                    {
                        reporter.aborted();
                        return 0;
                    }
                    if let Err(e) = writer.destroy_tenant(&name, host, reporter) {
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
    error: &accounts::DestroyError,
) {
    match error {
        accounts::DestroyError::Account(e) => reporter.destroy_failed(name, e),
        accounts::DestroyError::Profile(e) => reporter.destroy_profile_failed(name, e),
        accounts::DestroyError::Firewall(e) => reporter.destroy_firewall_failed(name, e),
    }
}

fn surface_doctor_error(reporter: &mut Reporter, error: &accounts::DoctorError) {
    match error {
        accounts::DoctorError::Probe(e) => reporter.doctor_failed(e),
        accounts::DoctorError::HostFile(e) => reporter.doctor_host_file_failed(e),
        accounts::DoctorError::Firewall(e) => reporter.doctor_firewall_failed(e),
    }
}

fn surface_mode_error(
    reporter: &mut Reporter,
    name: &super::TenantUserName,
    error: &accounts::ModeError,
) {
    match error {
        accounts::ModeError::Profile(e) => reporter.mode_profile_failed(name, e),
        accounts::ModeError::Firewall(e) => reporter.mode_failed(name, e),
        accounts::ModeError::Acl(e) => reporter.mode_acl_failed(name, e),
        accounts::ModeError::Account(e) => reporter.mode_account_failed(name, e),
        accounts::ModeError::Probe(e) => reporter.mode_probe_failed(name, e),
        accounts::ModeError::Share(e) => reporter.refuse_mode_share(name, e),
    }
}

/// Parallel to `surface_mode_error` with shell-entry phrasing: the
/// operator typed `tenant shell`, so the frame names the narrow as a
/// step within the shell verb, not a standalone mode switch.
fn surface_shell_mode_error(
    reporter: &mut Reporter,
    name: &super::TenantUserName,
    error: &accounts::ModeError,
) {
    match error {
        accounts::ModeError::Profile(e) => reporter.shell_narrow_profile_failed(name, e),
        accounts::ModeError::Firewall(e) => reporter.shell_narrow_firewall_failed(name, e),
        accounts::ModeError::Acl(e) => reporter.shell_narrow_acl_failed(name, e),
        accounts::ModeError::Account(e) => reporter.shell_narrow_account_failed(name, e),
        accounts::ModeError::Probe(e) => reporter.shell_narrow_probe_failed(name, e),
        accounts::ModeError::Share(e) => reporter.refuse_shell_share(name, e),
    }
}

/// Parallel to `surface_mode_error` with reload-specific wording on
/// Firewall + Share arms; Acl / Account / Probe arms reuse the
/// mode-named methods whose wording is verb-agnostic.
fn surface_reload_error(
    reporter: &mut Reporter,
    name: &super::TenantUserName,
    error: &accounts::ModeError,
) {
    match error {
        accounts::ModeError::Profile(e) => reporter.reload_profile_failed(name, e),
        accounts::ModeError::Firewall(e) => reporter.reload_firewall_failed(name, e),
        accounts::ModeError::Acl(e) => reporter.mode_acl_failed(name, e),
        accounts::ModeError::Account(e) => reporter.mode_account_failed(name, e),
        accounts::ModeError::Probe(e) => reporter.mode_probe_failed(name, e),
        accounts::ModeError::Share(e) => reporter.refuse_reload_share(name, e),
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
    let group = accounts::tenant_share_group_name(name.as_str());
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
    let group = accounts::tenant_share_group_name(name.as_str());
    DestroyPlanOps {
        delete_user: AccountOp::DeleteTenantUser { name: name.into() },
        probe: AccountOp::LookupUserRecord { name: name.into() },
        cleanup: AccountOp::DeleteUserRecord { name: name.into() },
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
    let group = accounts::tenant_share_group_name(name.as_str());
    OrphanGroupPlanOps {
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

fn orphan_plan_entries(ops: &OrphanGroupPlanOps) -> Vec<(Op<'_>, Option<&'static str>)> {
    vec![
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

/// Post-provision is the arm where the tenant is already provisioned
/// but share-reapply failed; the per-arm framing names the existing
/// state so the operator's recovery is `tenant reload`, not a fresh
/// `tenant create` (which would refuse on name-conflict). Profile /
/// Firewall arms are unreachable here but wired for completeness.
fn surface_create_post_provision_error(
    reporter: &mut Reporter,
    name: &super::TenantUserName,
    error: &accounts::ModeError,
) {
    match error {
        accounts::ModeError::Profile(e) => reporter.mode_profile_failed(name, e),
        accounts::ModeError::Firewall(e) => reporter.mode_failed(name, e),
        accounts::ModeError::Acl(e) => reporter.create_post_provision_acl_failed(name, e),
        accounts::ModeError::Account(e) => reporter.create_post_provision_account_failed(name, e),
        accounts::ModeError::Probe(e) => reporter.create_post_provision_probe_failed(name, e),
        accounts::ModeError::Share(e) => reporter.refuse_create_post_provision_share(name, e),
    }
}
