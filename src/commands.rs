use crate::{Cli, Command, accounts, allocation, messages, reporter::Reporter};

const EX_USAGE: u8 = 64;

pub(crate) fn dispatch(cli: Cli, accounts: &dyn accounts::Reader, reporter: &mut Reporter) -> u8 {
    match cli.command {
        Command::Create { name, dry_run } => {
            if let Err(e) = accounts::validate_name(&name) {
                reporter.write_err(messages::invalid_name(&name, &e));
                return EX_USAGE;
            }
            if let Err(e) = accounts::check_conflict(accounts, &name) {
                reporter.write_err(messages::name_conflict(&name, &e));
                return EX_USAGE;
            }
            if !dry_run {
                return 0;
            }
            let uid = allocation::UidAllocator::new(accounts).lowest_free_uid();
            reporter.write(messages::would_create_tenant(&name, uid));
            0
        }
    }
}
