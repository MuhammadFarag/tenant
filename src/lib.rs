use std::ffi::OsString;
use std::io::Write;

use clap::{Parser, Subcommand, ValueEnum};

pub mod accounts;
pub mod allocation;
mod commands;
pub mod doctor;
pub mod executor;
pub mod firewall;
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
    Create {
        name: String,
    },
    Destroy {
        name: String,
    },
    Shell {
        name: String,
    },
    /// Apply a PF widening level to the named tenant. Re-renders the
    /// anchor body from the profile's runtime or runtime+install host
    /// set, writes it, and reloads pf. Install widening is intentionally
    /// non-persistent — the contract for cycle 3 is "the operator
    /// narrows back manually with `tenant mode <name> runtime`."
    /// Auto-narrow on shell entry is deferred to cycle 4.
    Mode {
        name: String,
        #[arg(value_enum)]
        level: ModeLevel,
    },
    /// Audit filesystem-exposure boundaries between host and tenants
    /// by probing sensitive host paths as each tenant. Reports findings
    /// for paths that are unexpectedly readable or listable from a
    /// tenant account.
    ///
    /// Requires the operator to be a member of the `admin` group on
    /// macOS so `sudo -u <tenant>` is permitted. On invocation, doctor
    /// caches a sudo session up front (one Touch ID / password prompt);
    /// subsequent probes run silently within that session.
    ///
    /// Run against a single tenant with `tenant doctor <name>`; run
    /// against every tenant on the host with bare `tenant doctor`.
    /// Pass `--strict` to exit non-zero when findings are present (1
    /// for warnings only, 2 for any critical finding).
    Doctor {
        name: Option<String>,
        #[arg(long)]
        strict: bool,
    },
    /// Reapply the tenant's profile to host state: rewrite the PF
    /// anchor at runtime tier, then apply each declared share entry
    /// (host-side ACL grant + tenant-side parent dir + tenant-side
    /// symlink). The operator-facing "I edited the profile, apply
    /// it" verb. Idempotent at the substrate.
    ///
    /// Bare `tenant reload` walks every tenant on the host (parallel
    /// to `tenant doctor`'s no-arg shape). Per-tenant failures don't
    /// abort the walk; the verb continues and surfaces a summary at
    /// the end (Q15 lock). Exit code is 0 on full success or 74 if
    /// any tenant tripped.
    ///
    /// Always lands at runtime tier — install-tier widening stays the
    /// explicit `tenant mode <name> install` operator action.
    Reload {
        name: Option<String>,
    },
}

/// Which tier of the profile's allowlist the rendered PF anchor body
/// should include. Runtime is the baseline (only `allowlist.runtime.hosts`);
/// install is the widened set (`runtime + install`). Cycle 3 carves
/// the binary distinction; future tiers (e.g. provisioning, ci) would
/// extend the enum.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ModeLevel {
    Runtime,
    Install,
}

impl ModeLevel {
    /// Operator-facing label used in plan / echo / refusal / done
    /// messages. Matches the CLI literal so an operator who typed
    /// `tenant mode dev runtime` sees the same word back.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ModeLevel::Runtime => "runtime",
            ModeLevel::Install => "install",
        }
    }
}

pub fn run(
    args: &[String],
    accounts: &dyn accounts::Reader,
    executor: &dyn executor::Executor,
    host: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let cli = match parse(args, stdout, stderr) {
        Ok(cli) => cli,
        Err(code) => return code,
    };
    // Dry-run swap: the writer stays mode-agnostic; composition root
    // selects either the caller-supplied substrate (production / test)
    // or the no-op `DryRunExecutor` based on `--dry-run`.
    let dry_run_executor = executor::DryRunExecutor;
    let active_executor: &dyn executor::Executor = if cli.dry_run {
        &dry_run_executor
    } else {
        executor
    };
    let writer = accounts::Writer::new(active_executor);
    let mut reporter = Reporter::new(stdout, stderr, cli.verbose, cli.dry_run, active_executor);
    commands::dispatch(cli, accounts, &writer, host, &mut reporter)
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
