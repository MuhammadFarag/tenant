use std::ffi::OsString;
use std::io::Write;

use clap::{Parser, Subcommand};

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

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let argv = std::iter::once(OsString::from("tenant")).chain(args.iter().map(OsString::from));
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(e) => {
            let target: &mut dyn Write = if e.use_stderr() { stderr } else { stdout };
            let _ = write!(target, "{e}");
            return if e.use_stderr() { 1 } else { 0 };
        }
    };

    match cli.command {
        Command::Create { name, dry_run } => {
            if dry_run {
                let _ = writeln!(stdout, "Would create tenant '{name}'.");
                if cli.verbose {
                    let _ = writeln!(
                        stdout,
                        "Would run:\n  sudo sysadminctl -addUser {name} \
                         -fullName \"Tenant: {name}\" -shell /bin/zsh -UID 600 -GID 600",
                    );
                }
            }
            0
        }
    }
}
