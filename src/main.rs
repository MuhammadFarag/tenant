use std::io;
use std::process::ExitCode;

use tenant::adapters::macos::MacosHostAccounts;
use tenant::domain::HostUserName;
use tenant::executor::MacosExecutor;

fn main() -> ExitCode {
    let accounts = match MacosHostAccounts::new() {
        Ok(reader) => reader,
        Err(e) => {
            eprintln!("tenant: failed to query account state: {e}");
            return ExitCode::from(74); // EX_IOERR
        }
    };
    let executor = MacosExecutor;
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Operator's login name is the `host` identity in doctor's curated
    // path expansion (`/Users/<host>/.ssh/...`). USER is set by the
    // login shell on macOS; under sudo, USER becomes `root` but
    // SUDO_USER preserves the original invoker — prefer SUDO_USER so
    // `sudo tenant doctor` still audits the real operator's home, not
    // `/Users/root/*`. Final fallback is a placeholder so a missing-
    // env edge case surfaces as "the path probes look weird" rather
    // than a hard crash.
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
    let code = tenant::run(
        &args,
        &accounts,
        &executor,
        &host,
        // (HostUserName) borrowed from the owned wrap above.
        &mut stdout,
        &mut stderr,
        &mut stdin,
        stdin_is_tty,
        colors,
    );
    ExitCode::from(code)
}
