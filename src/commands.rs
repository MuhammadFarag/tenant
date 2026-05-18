use std::io::BufRead;

use crate::ModeLevel;
use crate::doctor::Severity;
use crate::executor::{AccountOp, FirewallOp, Op, ProfileOp};
use crate::reporter::ConfirmOutcome;
use crate::{
    Cli, Verb, accounts, allocation, allocation::TENANT_UID_FLOOR, domain, ids, reporter::Reporter,
};

const EX_USAGE: u8 = 64;
const EX_IOERR: u8 = 74;
const EX_DOCTOR_WARNING: u8 = 1;
const EX_DOCTOR_CRITICAL: u8 = 2;

/// Map `(max_severity, --strict)` to an exit code:
/// - Without strict: always exit 0 (findings are informational).
/// - With strict, no findings (max = None): exit 0.
/// - With strict, max = Info: exit 0 (info-tier doesn't trip --strict).
/// - With strict, max = Warning: exit 1.
/// - With strict, max = Critical: exit 2.
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

// Mirror of `tenant::run`'s param-count clippy allow — dispatch needs
// every capability `run` threaded through to make per-verb routing
// decisions. Bundling adds a layer without reducing real arguments.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch(
    cli: Cli,
    accounts: &dyn domain::HostAccounts,
    writer: &accounts::Writer<'_>,
    host: &ids::HostUserName,
    reporter: &mut Reporter,
    stdin: &mut dyn BufRead,
    stdin_is_tty: bool,
    yes_flag: bool,
) -> u8 {
    // The pre-execution summary emits ONLY when the operator is
    // interactive OR running dry-run. Non-TTY real-mode invocation
    // (scripted callers) stays silent before the substrate. `--yes`
    // doesn't suppress the summary on a TTY — the operator opted
    // out of the PROMPT, not the context.
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
            // Phase 3 allocates UID and GID independently — see the
            // `Decoupled UID/GID allocation` note in the project doctrine
            // for why these aren't fused. Both consult the same HostAccounts
            // but read disjoint maps, so the values may legitimately
            // diverge.
            let uid = allocation::UidAllocator::new(accounts).lowest_free_uid();
            let gid = allocation::GidAllocator::new(accounts).lowest_free_gid();
            // Pre-execution confirmation: summary + prompt
            // BEFORE any substrate fires. Default Y for create (the
            // operator typed the verb; abort is cheap; idempotent
            // on re-run).
            //
            // The plan slice the verbose summary renders is built
            // here in dispatch, mirroring the substrate flow the
            // verb fires. The placeholder InstallAnchor / UpdateConfig
            // bodies are empty strings — `describe_via` ignores those
            // fields, so plan + echo lines come out identical to the
            // real-bodied ops the verb constructs after profile-read.
            let create_plan_ops = build_create_plan_ops(&name, host, uid, gid);
            let create_plan = create_plan_entries(&create_plan_ops);
            if show_summary {
                reporter.create_summary(&name, host, uid, gid, Some(&create_plan));
                // Cycle-16 inline audit: surface verb-relevant doctor
                // findings BEFORE the operator confirms — critical
                // findings inline, warnings aggregated to a single
                // hint line pointing at `tenant doctor`. Same gating
                // as the summary itself; scripted callers stay silent.
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
                    // Two stderr lines — the original sysadminctl failure
                    // first (so log-grep regexes that match the
                    // single-failure shape keep working), then the
                    // rollback failure with its em-dash recovery hint
                    // pointing at `tenant destroy`.
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
            // Reuses `destroy_eligibility`'s 5-way classifier (per the
            // Option-A design lock). Shell collapses NotPresent and
            // OrphanGroup into the same `refuse_shell_absent` refusal —
            // Q3 ruled that operators wanting a shell don't care about
            // the lingering group; the destroy verb is the right tool
            // to converge that.
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
                    // Clap enforces `--mode` requires argv (parse-time
                    // refusal), so if mode is Some, argv is non-empty;
                    // dispatch still resolves to Runtime when mode is
                    // None for the interactive branch's symmetry.
                    let resolved_mode = mode.unwrap_or(ModeLevel::Runtime);
                    // Shell has no confirm prompt (interactive entry,
                    // auto-narrow is convergent + idempotent), but the
                    // pre-exec audit still wants visual context — the
                    // summary supplies it. Same `show_summary` gate as
                    // the other verbs; scripted callers stay silent.
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
                            // Closing surface only for the command
                            // form. Interactive form returns from
                            // `login` after the operator typed exit;
                            // there's no terminal context to render
                            // into (cycle-4 doctrine). Argv presence
                            // is the discriminator.
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
                            // Per option (a) lock: child exit wins. The
                            // yellow ⚠ stderr warning surfaces the
                            // narrow failure but does NOT override the
                            // child's outcome — operator's $? matches
                            // what the command itself returned. The
                            // closing line still fires (child ran),
                            // but with no "(firewall narrowed back ...)"
                            // suffix — that would be a lie when the
                            // narrow just failed. Pass Runtime to elide
                            // the suffix; the warning above carries the
                            // real signal about firewall state.
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
            // Mode reuses `destroy_eligibility`'s 5-way classifier.
            // Same collapse as shell: NotPresent + OrphanGroup both
            // refuse via `refuse_mode_absent` — the operator wants
            // to switch a tenant's mode; the lingering group alone
            // can't host one.
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
                    // something already doomed. The verbose summary
                    // renders the plan upfront; the verb then receives
                    // the same plan for execution.
                    let plan = match writer.build_reapply_plan(&name, host, level) {
                        Ok(p) => p,
                        Err(e) => {
                            surface_mode_error(reporter, &name, &e);
                            return EX_IOERR;
                        }
                    };
                    let plan_entries = plan.as_plan_entries();
                    // Confirm prompt; default Y (convergent reapply,
                    // reversible via the other mode).
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
        Verb::Doctor { name, strict } => {
            // Reuses `destroy_eligibility`'s 5-way classifier (same shape
            // as shell / mode). NotPresent + OrphanGroup collapse into
            // `refuse_doctor_absent` — a lingering `<name>-tenant-share`
            // group with no user behind it can't be audited as a tenant.
            // After the classifier clears, dispatch runs `doctor_tenant`
            // and consults the `DoctorOutcome.max_severity()` plus the
            // `--strict` flag to decide the exit code.
            match name {
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
            }
        }
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
                        // Build the reapply plan BEFORE the summary
                        // so profile-read / share pre-flight failures
                        // surface pre-prompt.
                        let plan = match writer.build_reapply_plan(&n, host, ModeLevel::Runtime) {
                            Ok(p) => p,
                            Err(e) => {
                                surface_reload_error(reporter, &n, &e);
                                return EX_IOERR;
                            }
                        };
                        let plan_entries = plan.as_plan_entries();
                        // Default Y (convergent, idempotent).
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
                // List the tenants up-front so the operator confirms
                // the scope before any substrate fires. Empty host
                // short-circuits via reload_all_done_summary (which
                // prints "No tenants…"), so we skip the prompt there.
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
                    // Convergence path: tenant user is already gone but
                    // the suffixed group survived a prior partial
                    // failure. Confirm; default N — same
                    // destructive-action posture as the full destroy.
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
                    // Routes through `surface_destroy_error` so a
                    // profile-rm failure on this arm gets the same
                    // operator-friendly framing as the Destroyable arm.
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
                    // Confirm; default N (destructive, muscle-memory
                    // ENTER must not delete).
                    let destroy_plan_ops = build_destroy_plan_ops(&name, host);
                    let destroy_plan = destroy_plan_entries(&destroy_plan_ops);
                    if show_summary {
                        let uid = accounts.uid_for(&name).unwrap_or(ids::UserId(0));
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

/// Route a `DestroyError` to the appropriate Reporter failure method.
/// Centralized so both destroy arms (`Destroyable` and `OrphanGroup`)
/// surface account-domain and profile-domain failures consistently.
fn surface_destroy_error(
    reporter: &mut Reporter,
    name: &ids::TenantUserName,
    error: &accounts::DestroyError,
) {
    match error {
        accounts::DestroyError::Account(e) => reporter.destroy_failed(name, e),
        accounts::DestroyError::Profile(e) => reporter.destroy_profile_failed(name, e),
        accounts::DestroyError::Firewall(e) => reporter.destroy_firewall_failed(name, e),
    }
}

/// Route a `DoctorError` to the right Reporter framing — Probe-side
/// failures (sudo prompt machinery) go to `doctor_failed`; host-config
/// file read failures (sudoers, pam.d/sudo) go to
/// `doctor_host_file_failed`; firewall-read failures (pfctl) go to
/// `doctor_firewall_failed`.
fn surface_doctor_error(reporter: &mut Reporter, error: &accounts::DoctorError) {
    match error {
        accounts::DoctorError::Probe(e) => reporter.doctor_failed(e),
        accounts::DoctorError::HostFile(e) => reporter.doctor_host_file_failed(e),
        accounts::DoctorError::Firewall(e) => reporter.doctor_firewall_failed(e),
    }
}

/// Route a `ModeError` (mode verb) to the right Reporter framing.
/// The share-reapply substrate adds four arms beyond the Profile +
/// Firewall pair; centralizing the dispatch keeps the verb arm in
/// `dispatch` thin.
fn surface_mode_error(
    reporter: &mut Reporter,
    name: &ids::TenantUserName,
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

/// Route a `ShellError::Mode(_)` to the right Reporter framing.
/// Parallel to `surface_mode_error` with shell-entry context phrasing
/// on each arm — operator typed `tenant shell`, not `tenant mode`, so
/// the failure frame names the narrow as a step within the shell verb.
fn surface_shell_mode_error(
    reporter: &mut Reporter,
    name: &ids::TenantUserName,
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

/// Route a `ModeError` to the right Reporter framing for the reload
/// verb. Parallel to `surface_mode_error` with reload-specific wording
/// on Firewall + Share arms ("reload firewall" / "cannot reload");
/// substrate arms (Acl / Account / Probe / Profile) reuse the
/// mode-named methods whose wording is verb-agnostic.
fn surface_reload_error(
    reporter: &mut Reporter,
    name: &ids::TenantUserName,
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

// ============================================================
// Plan-slice construction for prompt-having verbs
//
// Dispatch builds the plan-side op list BEFORE the summary so the
// verbose plan block can render before the confirm prompt.
// `*_plan_ops` owns the ops; `*_plan_entries` flattens them into the
// borrowed-slice shape the Reporter expects.
//
// The placeholder InstallAnchor / UpdateConfig bodies are empty
// strings — `describe_via` ignores those fields, so plan + echo lines
// come out identical to the real-bodied ops the verb constructs after
// profile-read.
// ============================================================

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
    name: &ids::TenantUserName,
    host: &ids::HostUserName,
    uid: ids::UserId,
    gid: ids::GroupId,
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

fn build_destroy_plan_ops(name: &ids::TenantUserName, host: &ids::HostUserName) -> DestroyPlanOps {
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
    name: &ids::TenantUserName,
    host: &ids::HostUserName,
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

/// Route a `CreateError::PostProvision(ModeError)` to the right
/// Reporter framing. Post-provision is the arm where the tenant has
/// already been provisioned (user + group + profile + PF + enable
/// all succeeded) but the share-reapply substrate failed — the
/// per-arm framing names the existing-tenant-state explicitly so the
/// operator's recovery is `tenant reload`, not `tenant create`
/// (which would refuse on name-conflict). Profile/Firewall arms are
/// unreachable on the create path because `reapply_shares_post_provision`
/// is called with a pre-parsed Profile and doesn't touch firewall
/// ops; the two arms are wired through the mode-failure family for
/// completeness.
fn surface_create_post_provision_error(
    reporter: &mut Reporter,
    name: &ids::TenantUserName,
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
