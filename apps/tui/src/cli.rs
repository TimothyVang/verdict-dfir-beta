//! Command-line argument parsing (hand-rolled — no clap dependency).
//!
//! `verdict-tui [OPTIONS] [CASE_DIR]`. With no `CASE_DIR`, the newest case
//! under the allow-listed roots is used. `--print` renders one frame to
//! stdout and exits (non-interactive, for smoke tests and piping).

use std::path::PathBuf;

/// Default headless render size for `--print`.
pub const DEFAULT_WIDTH: u16 = 100;
pub const DEFAULT_HEIGHT: u16 = 40;

/// Parsed invocation.
///
/// A CLI flag set is the natural home for several independent booleans, so
/// the `struct_excessive_bools` lint does not apply here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Explicit case directory; `None` selects the newest discovered case.
    pub case_dir: Option<PathBuf>,
    /// Render one frame to stdout and exit instead of going interactive.
    pub print: bool,
    /// Start on the Finding detail pane (first Finding) rather than the list.
    pub detail: bool,
    /// Drive mode: launch `scripts/verdict <EVIDENCE>` and live-tail its run.
    pub drive: Option<PathBuf>,
    /// Follow mode: live-tail the positional `CASE_DIR` as an in-progress run.
    pub follow: bool,
    /// Headless render width for `--print`.
    pub width: u16,
    /// Headless render height for `--print`.
    pub height: u16,
    pub help: bool,
    pub version: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            case_dir: None,
            print: false,
            detail: false,
            drive: None,
            follow: false,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            help: false,
            version: false,
        }
    }
}

/// Parse CLI arguments (excluding argv[0]).
///
/// # Errors
/// Returns a human-readable message for an unknown flag, a missing value,
/// an unparseable dimension, or a second positional argument.
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Args, String> {
    let mut parsed = Args::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => parsed.help = true,
            "-V" | "--version" => parsed.version = true,
            "--print" => parsed.print = true,
            "--detail" => parsed.detail = true,
            "--follow" => parsed.follow = true,
            "--drive" => parsed.drive = Some(take_value(&mut iter, "--drive")?),
            "--width" => parsed.width = take_dim(&mut iter, "--width")?,
            "--height" => parsed.height = take_dim(&mut iter, "--height")?,
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("unknown flag: {other}"));
            }
            _ => {
                if parsed.case_dir.is_some() {
                    return Err(format!("unexpected extra argument: {arg}"));
                }
                parsed.case_dir = Some(PathBuf::from(arg));
            }
        }
    }
    Ok(parsed)
}

fn take_dim<I: Iterator<Item = String>>(iter: &mut I, flag: &str) -> Result<u16, String> {
    let raw = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
    raw.parse::<u16>()
        .map_err(|_| format!("{flag} value must be a positive integer, got {raw}"))
}

fn take_value<I: Iterator<Item = String>>(iter: &mut I, flag: &str) -> Result<PathBuf, String> {
    iter.next()
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{flag} needs a value"))
}

/// Usage text for `--help`.
#[must_use]
pub fn help_text() -> String {
    format!(
        "verdict-tui {version} — read-only VERDICT case viewer + live monitor\n\
         \n\
         USAGE:\n\
         \x20   verdict-tui [OPTIONS] [CASE_DIR]\n\
         \n\
         ARGS:\n\
         \x20   CASE_DIR   Case directory (holds verdict.json when finished).\n\
         \x20              Omit to open the newest case under the\n\
         \x20              allow-listed roots.\n\
         \n\
         OPTIONS:\n\
         \x20   --drive <EVIDENCE>  Launch scripts/verdict on EVIDENCE and\n\
         \x20                       live-tail the run, then open the viewer\n\
         \x20   --follow            Live-tail CASE_DIR as an in-progress run\n\
         \x20   --print             Render one frame to stdout and exit\n\
         \x20   --detail            Open on the Finding detail pane\n\
         \x20   --width <N>         Headless render width for --print (default {w})\n\
         \x20   --height <N>        Headless render height for --print (default {h})\n\
         \x20   -h, --help          Show this help\n\
         \x20   -V, --version       Show the version\n\
         \n\
         Read-only by construction: it reads a case directory's JSON and,\n\
         in drive mode, launches the scripts/verdict launcher. It never\n\
         opens evidence itself, never calls a forensic tool, and never\n\
         emits a Finding.\n",
        version = env!("CARGO_PKG_VERSION"),
        w = DEFAULT_WIDTH,
        h = DEFAULT_HEIGHT,
    )
}

/// Version string for `--version`.
#[must_use]
pub fn version_text() -> String {
    format!("verdict-tui {}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> Args {
        parse(args.iter().map(ToString::to_string)).expect("parse succeeds")
    }

    #[test]
    fn defaults_are_interactive_newest_case() {
        let args = parse_ok(&[]);
        assert!(args.case_dir.is_none());
        assert!(!args.print);
        assert!(!args.detail);
        assert_eq!(args.width, DEFAULT_WIDTH);
        assert_eq!(args.height, DEFAULT_HEIGHT);
    }

    #[test]
    fn parses_positional_case_dir_and_flags() {
        let args = parse_ok(&["--print", "--detail", "/cases/x"]);
        assert_eq!(args.case_dir, Some(PathBuf::from("/cases/x")));
        assert!(args.print);
        assert!(args.detail);
    }

    #[test]
    fn parses_dimensions() {
        let args = parse_ok(&["--width", "80", "--height", "24"]);
        assert_eq!(args.width, 80);
        assert_eq!(args.height, 24);
    }

    #[test]
    fn parses_drive_and_follow() {
        let drive = parse_ok(&["--drive", "/evidence/case.evtx"]);
        assert_eq!(drive.drive, Some(PathBuf::from("/evidence/case.evtx")));
        assert!(!drive.follow);

        let follow = parse_ok(&["--follow", "/cases/tui-1"]);
        assert!(follow.follow);
        assert_eq!(follow.case_dir, Some(PathBuf::from("/cases/tui-1")));
    }

    #[test]
    fn drive_requires_a_value() {
        assert!(parse(["--drive".to_string()]).is_err());
    }

    #[test]
    fn rejects_unknown_flag() {
        assert!(parse(["--nope".to_string()]).is_err());
    }

    #[test]
    fn rejects_second_positional() {
        let err = parse(["a", "b"].iter().map(ToString::to_string));
        assert!(err.is_err());
    }

    #[test]
    fn rejects_bad_dimension() {
        assert!(parse(["--width".to_string(), "wide".to_string()]).is_err());
        assert!(parse(["--height".to_string()]).is_err());
    }

    #[test]
    fn recognizes_help_and_version() {
        assert!(parse_ok(&["--help"]).help);
        assert!(parse_ok(&["-V"]).version);
    }
}
