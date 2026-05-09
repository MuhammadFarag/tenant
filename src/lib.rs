use std::ffi::OsString;
use std::io::Write;

use clap::{Parser, Subcommand};

pub mod accounts;
pub mod allocation;

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
    let cli = match parse_args(args, stdout, stderr) {
        Ok(cli) => cli,
        Err(code) => return code,
    };

    match cli.command {
        Command::Create { name, dry_run } => {
            cmd_create(&name, dry_run, cli.verbose, accounts, stdout)
        }
    }
}

fn parse_args(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> Result<Cli, u8> {
    let argv = std::iter::once(OsString::from("tenant")).chain(args.iter().map(OsString::from));
    Cli::try_parse_from(argv).map_err(|e| {
        let to_stderr = e.use_stderr();
        let target: &mut dyn Write = if to_stderr { stderr } else { stdout };
        let _ = write!(target, "{e}");
        if to_stderr { 1 } else { 0 }
    })
}

fn cmd_create(
    name: &str,
    dry_run: bool,
    verbose: bool,
    accounts: &dyn accounts::Reader,
    stdout: &mut dyn Write,
) -> u8 {
    if dry_run {
        let _ = writeln!(stdout, "Would create tenant '{name}'.");
        if verbose {
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
