use crate::{Cli, Command, accounts, allocation, messages, reporter::Reporter};

const EX_USAGE: u8 = 64;
const EX_IOERR: u8 = 74;

pub(crate) fn dispatch(
    cli: Cli,
    accounts: &dyn accounts::Reader,
    writer: &dyn accounts::Writer,
    reporter: &mut Reporter,
) -> u8 {
    match cli.command {
        Command::Create { name } => {
            if let Err(e) = accounts::validate_name(&name) {
                reporter.write_err(messages::invalid_name(&name, &e));
                return EX_USAGE;
            }
            if let Err(e) = accounts::check_conflict(accounts, &name) {
                reporter.write_err(messages::name_conflict(&name, &e));
                return EX_USAGE;
            }
            let uid = allocation::UidAllocator::new(accounts).lowest_free_uid();
            if let Err(e) = writer.create_tenant(&name, uid, reporter) {
                reporter.write_err(messages::create_failed(&name, &e));
                return EX_IOERR;
            }
            0
        }
    }
}
