//! `verdict-tui` binary entry point.
//!
//! Parses arguments, then hands off to [`verdict_tui::run`]. Read-only by
//! construction: nothing here (or anywhere in the crate) opens evidence or
//! calls a forensic tool.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use verdict_tui::cli;

fn main() -> ExitCode {
    let args = match cli::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("verdict-tui: {message}\n\n{}", cli::help_text());
            return ExitCode::from(2);
        }
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut stdout = io::stdout();

    match verdict_tui::run(&args, &cwd, &mut stdout) {
        Ok(()) => {
            let _ = stdout.flush();
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("verdict-tui: {error}");
            ExitCode::FAILURE
        }
    }
}
