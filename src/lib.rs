//! slipcheck — audit package archives for path traversal, symlink escapes,
//! setuid bits and absolute paths *before* extraction.
//!
//! The crate is std-only. Formats are decoded by pure in-tree readers
//! ([`tar`], [`zip`], [`gzip`] on top of [`inflate`]); every entry is then
//! fed to the format-agnostic [`audit::Auditor`], which knows nothing about
//! bytes on disk — only entry names, kinds, modes and link targets.

pub mod audit;
pub mod cli;
pub mod entry;
pub mod findings;
pub mod format;
pub mod gzip;
pub mod inflate;
pub mod paths;
pub mod report;
pub mod scan;
pub mod tar;
pub mod zip;

#[cfg(test)]
pub mod testkit;

/// Crate version, single source of truth for `--version` and JSON output.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
