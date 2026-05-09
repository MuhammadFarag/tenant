use std::io::Write;

use crate::{Cli, Command, accounts, allocation};

pub(crate) fn dispatch(cli: Cli, accounts: &dyn accounts::Reader, stdout: &mut dyn Write) -> u8 {
    match cli.command {
        Command::Create { name, dry_run } => {
            if dry_run {
                let _ = writeln!(stdout, "Would create tenant '{name}'.");
                if cli.verbose {
                    let uid = allocation::UidAllocator::new(accounts).lowest_free_uid();
                    let _ = writeln!(
                        stdout,
                        "Would run:\n  sudo sysadminctl -addUser {name} \
                         -fullName \"Tenant: {name}\" -shell /bin/zsh -UID {uid} -GID {uid}",
                    );
                }
            }
            0
        }
    }
}
