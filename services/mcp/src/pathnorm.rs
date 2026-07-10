//! Path canonicalization that is portable across the CI matrix.
//!
//! `std::fs::canonicalize` on Windows returns an extended-length "verbatim"
//! path with a `\\?\` prefix (e.g. `\\?\C:\evidence\case.dd`). The
//! evidence-authorization and tool path logic compares, joins, and re-opens
//! these paths, and the `\\?\` form does not round-trip through that logic
//! (it surfaces as broken paths such as `D:\?`). On Unix `canonicalize`
//! already returns a plain absolute path, so there is nothing to strip.
//!
//! [`canonicalize`] wraps [`dunce::canonicalize`], which is byte-identical to
//! `std::fs::canonicalize` on Unix and, on Windows, drops the `\\?\` prefix
//! whenever the resulting path is still valid without it (keeping it only for
//! the paths that genuinely require extended-length form). Every production
//! canonicalize call in this crate goes through here so the behavior is
//! uniform on every target.

use std::io;
use std::path::{Path, PathBuf};

/// Canonicalize `path`, normalizing the Windows `\\?\` verbatim prefix away.
///
/// Identical to `std::fs::canonicalize` on Unix. On Windows it returns the
/// most compatible absolute form, so downstream path comparison and re-opening
/// behave the same as on Unix.
pub fn canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    dunce::canonicalize(path)
}
