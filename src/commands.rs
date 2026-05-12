use crate::{Cli, Verb, accounts, allocation, allocation::TENANT_UID_FLOOR, reporter::Reporter};

const EX_USAGE: u8 = 64;
const EX_IOERR: u8 = 74;

pub(crate) fn dispatch(
    cli: Cli,
    accounts: &dyn accounts::Reader,
    writer: &accounts::Writer<'_>,
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
                        Err(e) => {
                            reporter.shell_failed(&name, &e);
                            EX_IOERR
                        }
                    }
                }
            }
        }
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
