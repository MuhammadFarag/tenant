use std::io;
use std::process::ExitCode;

use tenant::accounts::MacosReader;
use tenant::executor::SystemExecutor;

fn main() -> ExitCode {
    let accounts = match MacosReader::new() {
        Ok(reader) => reader,
        Err(e) => {
            eprintln!("tenant: failed to query account state: {e}");
            return ExitCode::from(74); // EX_IOERR
        }
    };
    let executor = SystemExecutor;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let code = tenant::run(&args, &accounts, &executor, &mut stdout, &mut stderr);
    ExitCode::from(code)
}
