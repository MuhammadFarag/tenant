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
            let uid = allocation::UidAllocator::new(accounts).lowest_free_uid();
            if let Err(e) = writer.create_tenant(&name, uid, reporter) {
                reporter.emit_err(messages::create_failed(&name, &e));
                return EX_IOERR;
            }
            0
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
