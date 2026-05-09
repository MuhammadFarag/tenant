use std::ffi::OsString;
use std::io::Write;

use clap::{Parser, Subcommand};

use crate::{accounts, allocation};

#[derive(Parser)]
#[command(name = "tenant")]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Create {
        name: String,
        #[arg(long)]
        dry_run: bool,
    },
}

pub fn run(
    args: &[String],
    accounts: &dyn accounts::Reader,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let cli = match parse(args, stdout, stderr) {
        Ok(cli) => cli,
        Err(code) => return code,
    };
    dispatch(cli, accounts, stdout)
}

fn parse(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> Result<Cli, u8> {
    let argv = std::iter::once(OsString::from("tenant")).chain(args.iter().map(OsString::from));
    Cli::try_parse_from(argv).map_err(|e| {
        let to_stderr = e.use_stderr();
        let target: &mut dyn Write = if to_stderr { stderr } else { stdout };
        let _ = write!(target, "{e}");
        if to_stderr { 1 } else { 0 }
    })
}

fn dispatch(cli: Cli, accounts: &dyn accounts::Reader, stdout: &mut dyn Write) -> u8 {
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
