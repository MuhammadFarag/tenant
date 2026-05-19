pub mod adapters;
pub mod allocation;
pub mod ansi;
mod cli;
pub mod doctor;
pub mod domain;
pub mod firewall;
pub mod profile;
pub mod terminal;

pub use cli::{Cli, ModeLevel, Verb};
pub use terminal::Terminal;

use domain::reporter::Reporter;

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
