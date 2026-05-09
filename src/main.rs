use std::io;
use std::process::ExitCode;

use tenant::accounts::StubReader;

fn main() -> ExitCode {
    // Placeholder accounts source — empty stub. A real macOS reader (dscl-backed)
    // will replace this when host-side wiring lands.
    let accounts = StubReader::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let code = tenant::run(&args, &accounts, &mut stdout, &mut stderr);
    ExitCode::from(code as u8)
}
