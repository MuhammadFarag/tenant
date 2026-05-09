use crate::{Cli, Command, accounts, allocation, messages, reporter::Reporter};

pub(crate) fn dispatch(cli: Cli, accounts: &dyn accounts::Reader, reporter: &mut Reporter) -> u8 {
    match cli.command {
        Command::Create { name, dry_run } => {
            if !dry_run {
                return 0;
            }
            let uid = allocation::UidAllocator::new(accounts).lowest_free_uid();
            reporter.write(messages::would_create_tenant(&name, uid));
            0
        }
    }
}
