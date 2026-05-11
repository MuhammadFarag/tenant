use std::ffi::OsString;
use std::io::Write;

use clap::{Parser, Subcommand};

pub mod accounts;
pub mod allocation;
mod commands;
pub mod executor;
mod messages;
pub mod profile;
mod reporter;

use reporter::Reporter;

#[derive(Parser)]
#[command(name = "tenant")]
pub(crate) struct Cli {
    #[arg(short, long, global = true)]
    pub(crate) verbose: bool,

    #[arg(long, global = true)]
    pub(crate) dry_run: bool,

    #[command(subcommand)]
    pub(crate) verb: Verb,
}

#[derive(Subcommand)]
pub(crate) enum Verb {
    Create { name: String },
    Destroy { name: String },
    Shell { name: String },
}

pub fn run(
    args: &[String],
    accounts: &dyn accounts::Reader,
    executor: &dyn executor::Executor,
    profiles: &dyn profile::ProfileStore,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let cli = match parse(args, stdout, stderr) {
        Ok(cli) => cli,
        Err(code) => return code,
    };
    let dry_run_executor = executor::DryRunExecutor;
    let active_executor: &dyn executor::Executor = if cli.dry_run {
        &dry_run_executor
    } else {
        executor
    };
    // Same dry-run swap as the executor — domain writers stay
    // mode-agnostic; the composition root picks the right impl. Profile
    // is a 4th DI seam mirroring Reader/Executor; tests inject a
    // `StubProfileStore`, prod injects `XdgProfileStore`.
    let dry_run_profiles = profile::DryRunProfileStore;
    let active_profiles: &dyn profile::ProfileStore = if cli.dry_run {
        &dry_run_profiles
    } else {
        profiles
    };
    let writer = accounts::MacosWriter::new(active_executor, active_profiles);
    let mut reporter = Reporter::new(stdout, stderr, cli.verbose, cli.dry_run);
    commands::dispatch(cli, accounts, &writer, &mut reporter)
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
