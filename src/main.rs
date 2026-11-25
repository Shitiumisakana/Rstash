use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = io::stdout();
    match rstash::cli::execute(&args, &mut stdout) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(message) => {
            let _ = writeln!(io::stderr(), "{message}");
            ExitCode::from(1)
        }
    }
}
