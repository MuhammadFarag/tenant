use std::process::ExitCode;

use clap::Parser;
use tenant::Cli;
use tenant::adapters::macos::{MacosHostMachine, MacosUserDirectory};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let directory = MacosUserDirectory;
    let machine = MacosHostMachine;
    let code =
        tenant::Terminal::with_stdio(|terminal| tenant::run(cli, &directory, &machine, terminal));
    ExitCode::from(code)
}
