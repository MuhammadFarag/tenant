use clap::{Parser, Subcommand, ValueEnum};

use crate::domain::TenantUserName;

pub mod adapters;
pub mod allocation;
pub mod ansi;
pub mod doctor;
pub mod domain;
pub mod firewall;
pub mod profile;
pub mod terminal;

pub use terminal::Terminal;

use domain::reporter::Reporter;

#[derive(Parser)]
#[command(name = "tenant")]
pub struct Cli {
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Skip the interactive confirmation prompt that mutating verbs
    /// (create / destroy / mode / reload) emit before executing.
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,

    #[command(subcommand)]
    pub verb: Verb,
}

#[derive(Subcommand)]
pub enum Verb {
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
pub enum ModeLevel {
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

// `run` takes a parsed `Cli` plus a `Terminal` bundle; argv-to-Cli
// parsing lives at the binary boundary (main / test helpers) so the
// core stays clap-error-routing free.
pub fn run(
    cli: Cli,
    directory: &dyn domain::HostUserDirectory,
    machine: &dyn domain::HostMachine,
    terminal: Terminal<'_>,
) -> u8 {
    // Resolve the operator identity from the real (non-dry-run) machine
    // BEFORE the dry-run swap, so dry-run preserves the env-var answer
    // rather than substituting a placeholder.
    let host = machine.current_host_user_name();
    let dry_run_machine = adapters::dry_run_host_machine::DryRunHostMachine { host: host.clone() };
    let active_machine: &dyn domain::HostMachine = if cli.dry_run {
        &dry_run_machine
    } else {
        machine
    };
    let tenants = domain::Tenants::new(active_machine);
    let mut reporter = Reporter::new(terminal, cli.verbose, cli.dry_run, cli.yes, active_machine);
    domain::commands::dispatch(cli, directory, &tenants, &host, &mut reporter)
}
