pub mod adapters;
pub mod allocation;
pub mod ansi;
mod cli;
pub mod doctor;
pub mod domain;
pub mod firewall;
pub mod profile;
pub mod terminal;

pub use cli::{Cli, HelpTopic, ModeLevel, Verb};
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
    let host = machine.current_host_user_name();
    with_active_machine(machine, cli.dry_run, &host, |active| {
        let tenants = domain::Tenants::new(active);
        let mut reporter = Reporter::new(terminal, cli.verbose, cli.dry_run, cli.yes, active);
        domain::commands::dispatch(cli, directory, &tenants, &host, &mut reporter)
    })
}

// Reads `host` from the passed-in machine before optionally wrapping —
// so the dry-run wrapper inherits the real env-var answer rather than a
// placeholder.
fn with_active_machine<R>(
    machine: &dyn domain::HostMachine,
    dry_run: bool,
    host: &domain::HostUserName,
    f: impl FnOnce(&dyn domain::HostMachine) -> R,
) -> R {
    if dry_run {
        let wrapper = adapters::dry_run_host_machine::DryRunHostMachine { host: host.clone() };
        f(&wrapper)
    } else {
        f(machine)
    }
}
