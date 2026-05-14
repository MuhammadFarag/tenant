use crate::doctor::Severity;
use crate::{Cli, Verb, accounts, allocation, allocation::TENANT_UID_FLOOR, reporter::Reporter};

const EX_USAGE: u8 = 64;
const EX_IOERR: u8 = 74;
const EX_DOCTOR_WARNING: u8 = 1;
const EX_DOCTOR_CRITICAL: u8 = 2;

/// Map `(max_severity, --strict)` to an exit code. Sub-cycle 4 wires
/// the `--strict` test cases:
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

pub(crate) fn dispatch(
    cli: Cli,
    accounts: &dyn accounts::Reader,
    writer: &accounts::Writer<'_>,
    host: &str,
    reporter: &mut Reporter,
) -> u8 {
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
            // for why these aren't fused. Both consult the same Reader
            // but read disjoint maps, so the values may legitimately
            // diverge.
            let uid = allocation::UidAllocator::new(accounts).lowest_free_uid();
            let gid = allocation::GidAllocator::new(accounts).lowest_free_gid();
            match writer.create_tenant(&name, uid, gid, reporter) {
                Ok(()) => 0,
                Err(accounts::CreateError::Group(e)) => {
                    reporter.create_group_failed(&name, &e);
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
        Verb::Shell { name } => {
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
                    match writer.shell_into_tenant(&name, reporter) {
                        Ok(code) => code.clamp(0, 255) as u8,
                        Err(accounts::ShellError::Account(e)) => {
                            reporter.shell_failed(&name, &e);
                            EX_IOERR
                        }
                        Err(accounts::ShellError::Mode(e)) => {
                            surface_shell_mode_error(reporter, &name, &e);
                            EX_IOERR
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
            // Mode reuses `destroy_eligibility`'s 5-way classifier (per
            // cycle-3's locked design). Same collapse as shell:
            // NotPresent + OrphanGroup both refuse via `refuse_mode_absent`
            // — the operator wants to switch a tenant's mode; the
            // lingering group alone can't host one.
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
                    match writer.apply_tenant_mode(&name, level, reporter) {
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
                        match writer.reload_tenant(&n, reporter) {
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
                let outcome = writer.reload_all_tenants(accounts, reporter);
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
                    // failure. Routes through `surface_destroy_error` so
                    // a profile-rm failure on this arm gets the same
                    // operator-friendly framing as the Destroyable arm.
                    if let Err(e) = writer.destroy_orphan_group(&name, reporter) {
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
                    if let Err(e) = writer.destroy_tenant(&name, reporter) {
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
fn surface_destroy_error(reporter: &mut Reporter, name: &str, error: &accounts::DestroyError) {
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
/// Cycle 10's share-reapply substrate adds four new arms beyond the
/// existing Profile + Firewall pair; centralizing the dispatch keeps
/// the verb arm in `dispatch` thin.
fn surface_mode_error(reporter: &mut Reporter, name: &str, error: &accounts::ModeError) {
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
fn surface_shell_mode_error(reporter: &mut Reporter, name: &str, error: &accounts::ModeError) {
    match error {
        accounts::ModeError::Profile(e) => reporter.shell_narrow_profile_failed(name, e),
        accounts::ModeError::Firewall(e) => reporter.shell_narrow_failed(name, e),
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
fn surface_reload_error(reporter: &mut Reporter, name: &str, error: &accounts::ModeError) {
    match error {
        accounts::ModeError::Profile(e) => reporter.reload_profile_failed(name, e),
        accounts::ModeError::Firewall(e) => reporter.reload_firewall_failed(name, e),
        accounts::ModeError::Acl(e) => reporter.mode_acl_failed(name, e),
        accounts::ModeError::Account(e) => reporter.mode_account_failed(name, e),
        accounts::ModeError::Probe(e) => reporter.mode_probe_failed(name, e),
        accounts::ModeError::Share(e) => reporter.refuse_reload_share(name, e),
    }
}

/// Route a `CreateError::PostProvision(ModeError)` to the right
/// Reporter framing. Post-provision is the cycle 10 arm where the
/// tenant has already been provisioned (user + group + profile + PF +
/// enable all succeeded) but the share-reapply substrate failed —
/// the per-arm framing names the existing-tenant-state explicitly so
/// the operator's recovery is `tenant reload`, not `tenant create`
/// (which would refuse on name-conflict). Profile/Firewall arms are
/// unreachable on the create path because `reapply_shares_post_provision`
/// is called with a pre-parsed Profile and doesn't touch firewall
/// ops; the two arms are wired through the mode-failure family for
/// completeness.
fn surface_create_post_provision_error(
    reporter: &mut Reporter,
    name: &str,
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
