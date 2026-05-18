use std::process::ExitCode;

use tenant::adapters::macos::{MacosHostMachine, MacosUserDirectory};
use tenant::domain::HostUserName;

fn main() -> ExitCode {
    // Per-call dscl now lives inside each `HostUserDirectory` trait method,
    // so both adapters are ZSTs and construction is infallible.
    let directory = MacosUserDirectory;
    let machine = MacosHostMachine;
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Under sudo, USER becomes `root` but SUDO_USER preserves the
    // real invoker — prefer it so `sudo tenant doctor` audits the
    // operator's home, not /Users/root/*. Fallback is a placeholder.
    let host = HostUserName(
        std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "operator".to_string()),
    );
    let code = tenant::Terminal::with_stdio(|terminal| {
        tenant::run(&args, &directory, &machine, &host, terminal)
    });
    ExitCode::from(code)
}
