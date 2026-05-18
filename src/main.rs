use std::io;
use std::process::ExitCode;

use tenant::adapters::macos::{MacosHostAccounts, MacosHostMachine};
use tenant::domain::HostUserName;

fn main() -> ExitCode {
    let accounts = match MacosHostAccounts::new() {
        Ok(accounts) => accounts,
        Err(e) => {
            eprintln!("tenant: failed to query account state: {e}");
            return ExitCode::from(74); // EX_IOERR
        }
    };
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
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let stdin_handle = io::stdin();
    let stdin_is_tty = std::io::IsTerminal::is_terminal(&stdin_handle);
    let mut stdin = stdin_handle.lock();
    let colors = tenant::ansi::Colors::detect();
    let terminal = tenant::Terminal {
        stdout: &mut stdout,
        stderr: &mut stderr,
        stdin: &mut stdin,
        stdin_is_tty,
        colors,
    };
    let code = tenant::run(&args, &accounts, &machine, &host, terminal);
    ExitCode::from(code)
}
