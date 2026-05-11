use crate::{
    Cli, Verb, accounts, allocation, allocation::TENANT_UID_FLOOR, messages, reporter::Reporter,
};

const EX_USAGE: u8 = 64;
const EX_IOERR: u8 = 74;

pub(crate) fn dispatch(
    cli: Cli,
    accounts: &dyn accounts::Reader,
    writer: &dyn accounts::Writer,
    reporter: &mut Reporter,
) -> u8 {
    match cli.verb {
        Verb::Create { name } => {
            if let Err(e) = accounts::validate_name(&name) {
                reporter.emit_err(messages::invalid_name(&name, &e));
                return EX_USAGE;
            }
            if let Err(e) = accounts::check_conflict(accounts, &name) {
                reporter.emit_err(messages::name_conflict(&name, &e));
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
                    reporter.emit_err(messages::create_group_failed(&name, &e));
                    EX_IOERR
                }
                Err(accounts::CreateError::User(e)) => {
                    reporter.emit_err(messages::create_failed(&name, &e));
                    EX_IOERR
                }
                Err(accounts::CreateError::UserWithRollback { user, rollback }) => {
                    // Two emit_err calls — the original sysadminctl failure
                    // first (so log-grep regexes that match the
                    // single-failure shape keep working), then the rollback
                    // failure with its em-dash recovery hint pointing at
                    // `tenant destroy`.
                    reporter.emit_err(messages::create_failed(&name, &user));
                    reporter.emit_err(messages::rollback_failed(&name, &rollback));
                    EX_IOERR
                }
            }
        }
        Verb::Destroy { name } => {
            if let Err(e) = accounts::validate_name(&name) {
                reporter.emit_err(messages::invalid_name(&name, &e));
                return EX_USAGE;
            }
            match accounts::destroy_eligibility(accounts, &name) {
                accounts::Eligibility::NotPresent => {
                    reporter.emit(messages::destroy_absent(&name));
                    0
                }
                accounts::Eligibility::OrphanGroup => {
                    // Convergence path: tenant user is already gone but the
                    // suffixed group survived a prior partial failure.
                    // Reuse `destroy_failed` for any exec failure — same
                    // surface contract as the full destroy path so the
                    // operator's recovery is unchanged.
                    if let Err(e) = writer.destroy_orphan_group(&name, reporter) {
                        reporter.emit_err(messages::destroy_failed(&name, &e));
                        return EX_IOERR;
                    }
                    0
                }
                accounts::Eligibility::NotATenant { uid } => {
                    reporter.emit_err(messages::not_a_tenant(&name, uid, TENANT_UID_FLOOR));
                    EX_USAGE
                }
                accounts::Eligibility::SystemAccount => {
                    reporter.emit_err(messages::system_account_refusal(&name));
                    EX_USAGE
                }
                accounts::Eligibility::Destroyable => {
                    if let Err(e) = writer.destroy_tenant(&name, reporter) {
                        reporter.emit_err(messages::destroy_failed(&name, &e));
                        return EX_IOERR;
                    }
                    0
                }
            }
        }
    }
}
