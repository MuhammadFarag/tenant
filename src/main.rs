use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let code = tenant::run(&args, &mut stdout, &mut stderr);
    ExitCode::from(code as u8)
}
