use std::ffi::OsString;
use std::io::{BufRead, Write};

use clap::{Parser, Subcommand, ValueEnum};

use crate::domain::{HostUserName, TenantUserName};

pub mod adapters;
pub mod allocation;
pub mod ansi;
pub mod doctor;
pub mod domain;
pub mod firewall;
pub mod profile;

use domain::reporter::Reporter;

#[derive(Parser)]
#[command(name = "tenant")]
pub(crate) struct Cli {
    #[arg(short, long, global = true)]
    pub(crate) verbose: bool,

    #[arg(long, global = true)]
    pub(crate) dry_run: bool,

    /// Skip the interactive confirmation prompt that mutating verbs
    /// (create / destroy / mode / reload) emit before executing.
    #[arg(short = 'y', long, global = true)]
    pub(crate) yes: bool,

    #[command(subcommand)]
    pub(crate) verb: Verb,
}

#[derive(Subcommand)]
pub(crate) enum Verb {
    Create {
        name: TenantUserName,
    },
    Destroy {
        name: TenantUserName,
    },
    /// Enter the tenant context. Two forms gated on argv presence:
    ///
    /// - `tenant shell <name>` — interactive: auto-narrows the firewall
    ///   to runtime tier, reapplies declared shares, then launches a
    ///   login shell as the tenant.
    ///
    /// - `tenant shell <name> [--mode install|runtime] -- <cmd...>` —
    ///   command form: same reapply (at the requested tier; runtime by
    ///   default), runs `<cmd...>` as the tenant, then always reapplies
    ///   at runtime tier on completion — guarantees on-disk state
    ///   returns to runtime even if `--mode install` widened it. Child
    ///   exit code propagates to the verb's exit. A narrow-on-completion
    ///   failure emits a ⚠ stderr warning naming `tenant mode <name>
    ///   runtime` for recovery, but does NOT override the child's exit
    ///   code.
    ///
    /// `--mode` is valid only with `-- <cmd>` — widening the interactive
    /// session would leave the operator at install tier silently.
    Shell {
        name: TenantUserName,
        /// Firewall tier for the command-form reapply. `install` widens
        /// for the call; runtime narrow always fires on completion.
        #[arg(long, value_enum, requires = "argv")]
        mode: Option<ModeLevel>,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Apply a firewall widening level to the named tenant. Install
    /// widening is intentionally non-persistent — `tenant shell <name>`
    /// auto-narrows to runtime tier on entry.
    Mode {
        name: TenantUserName,
        #[arg(value_enum)]
        level: ModeLevel,
    },
    /// Audit filesystem-exposure boundaries between host and tenants by
    /// probing sensitive host paths as each tenant. Bare `tenant doctor`
    /// walks every tenant. `--strict` exits 1 on warnings, 2 on any
    /// critical finding.
    ///
    /// Requires admin-group membership; doctor caches one sudo session
    /// up front so subsequent probes run silently.
    Doctor {
        name: Option<TenantUserName>,
        #[arg(long)]
        strict: bool,
    },
    /// Reapply the tenant's profile to host state. Always lands at
    /// runtime tier — install-tier widening stays the explicit
    /// `tenant mode <name> install` operator action. Bare `tenant
    /// reload` walks every tenant; per-tenant failures don't abort
    /// the walk.
    Reload {
        name: Option<TenantUserName>,
    },
}

/// Which tier of the profile's allowlist the rendered firewall anchor
/// includes. Runtime is the baseline; install is the widened set.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ModeLevel {
    Runtime,
    Install,
}

impl ModeLevel {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ModeLevel::Runtime => "runtime",
            ModeLevel::Install => "install",
        }
    }
}

// Composition root: each parameter is a discrete I/O capability the
// harness injects for testability. Bundling would add a layer without
// removing parameters.
#[allow(clippy::too_many_arguments)]
pub fn run(
    args: &[String],
    accounts: &dyn domain::HostAccounts,
    machine: &dyn domain::HostMachine,
    host: &HostUserName,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    stdin: &mut dyn BufRead,
    stdin_is_tty: bool,
    colors: ansi::Colors,
) -> u8 {
    let cli = match parse(args, stdout, stderr) {
        Ok(cli) => cli,
        Err(code) => return code,
    };
    let dry_run_machine = adapters::dry_run_host_machine::DryRunHostMachine;
    let active_machine: &dyn domain::HostMachine = if cli.dry_run {
        &dry_run_machine
    } else {
        machine
    };
    let tenants = domain::Tenants::new(active_machine);
    let yes = cli.yes;
    let mut reporter = Reporter::new(
        stdout,
        stderr,
        cli.verbose,
        cli.dry_run,
        active_machine,
        colors,
    );
    domain::commands::dispatch(
        cli,
        accounts,
        &tenants,
        host,
        &mut reporter,
        stdin,
        stdin_is_tty,
        yes,
    )
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
