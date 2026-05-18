use std::process::ExitCode;

use tenant::adapters::macos::{MacosHostMachine, MacosUserDirectory};

fn main() -> ExitCode {
    // Per-call dscl now lives inside each `HostUserDirectory` trait method,
    // so both adapters are ZSTs and construction is infallible.
    let directory = MacosUserDirectory;
    let machine = MacosHostMachine;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code =
        tenant::Terminal::with_stdio(|terminal| tenant::run(&args, &directory, &machine, terminal));
    ExitCode::from(code)
}
