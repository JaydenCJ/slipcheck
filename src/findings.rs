//! The finding model: every check slipcheck can raise, with a stable
//! kebab-case id (used by `--allow` and JSON output), a default severity
//! and a one-line description surfaced by `slipcheck checks`.

use std::fmt;

/// How bad a finding is. `Critical` findings make extraction unsafe;
/// `Warning` findings are suspicious but not directly exploitable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Every check slipcheck knows about. Ids are stable API: scripts key on
/// them via `--allow <id>` and the JSON `check` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    AbsolutePath,
    Traversal,
    LinkEscape,
    LinkIndirection,
    Setuid,
    Setgid,
    WorldWritable,
    SpecialFile,
    DuplicatePath,
    CaseCollision,
    NameMismatch,
    UnpackLimit,
}

impl Check {
    pub const ALL: [Check; 12] = [
        Check::AbsolutePath,
        Check::Traversal,
        Check::LinkEscape,
        Check::LinkIndirection,
        Check::Setuid,
        Check::Setgid,
        Check::WorldWritable,
        Check::SpecialFile,
        Check::DuplicatePath,
        Check::CaseCollision,
        Check::NameMismatch,
        Check::UnpackLimit,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Check::AbsolutePath => "absolute-path",
            Check::Traversal => "traversal",
            Check::LinkEscape => "link-escape",
            Check::LinkIndirection => "link-indirection",
            Check::Setuid => "setuid",
            Check::Setgid => "setgid",
            Check::WorldWritable => "world-writable",
            Check::SpecialFile => "special-file",
            Check::DuplicatePath => "duplicate-path",
            Check::CaseCollision => "case-collision",
            Check::NameMismatch => "name-mismatch",
            Check::UnpackLimit => "unpack-limit",
        }
    }

    pub fn from_id(id: &str) -> Option<Check> {
        Check::ALL.iter().copied().find(|c| c.id() == id)
    }

    /// The severity this check *usually* carries — shown in the reference
    /// table. A few checks downgrade to warning in specific contexts
    /// (see `describe`).
    pub fn default_severity(self) -> Severity {
        match self {
            Check::AbsolutePath
            | Check::Traversal
            | Check::LinkEscape
            | Check::LinkIndirection
            | Check::Setuid
            | Check::Setgid
            | Check::SpecialFile
            | Check::UnpackLimit => Severity::Critical,
            Check::WorldWritable
            | Check::DuplicatePath
            | Check::CaseCollision
            | Check::NameMismatch => Severity::Warning,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Check::AbsolutePath => "entry name is absolute (leading '/', drive letter or UNC)",
            Check::Traversal => "entry name climbs out of the extraction root via '..'",
            Check::LinkEscape => "symlink or hard link target resolves outside the root",
            Check::LinkIndirection => {
                "entry is written through an earlier in-archive symlink (warning when the resolved location stays inside)"
            }
            Check::Setuid => "file mode carries the setuid bit",
            Check::Setgid => "file mode carries the setgid bit",
            Check::WorldWritable => "file or directory is world-writable",
            Check::SpecialFile => {
                "device node in the archive (fifos and unknown entry types downgrade to warning)"
            }
            Check::DuplicatePath => "the same path appears more than once; last entry wins",
            Check::CaseCollision => "two paths collide on a case-insensitive filesystem",
            Check::NameMismatch => "zip central directory and local header disagree on a name",
            Check::UnpackLimit => "compressed stream inflates past --max-unpacked (bomb guard)",
        }
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// One concrete problem found in one archive entry.
#[derive(Debug, Clone)]
pub struct Finding {
    pub check: Check,
    pub severity: Severity,
    /// The entry path as it appears in the archive (raw, un-normalized).
    pub path: String,
    /// Human-oriented explanation of why this specific entry was flagged.
    pub detail: String,
}

impl Finding {
    pub fn critical(check: Check, path: impl Into<String>, detail: impl Into<String>) -> Finding {
        Finding {
            check,
            severity: Severity::Critical,
            path: path.into(),
            detail: detail.into(),
        }
    }

    pub fn warning(check: Check, path: impl Into<String>, detail: impl Into<String>) -> Finding {
        Finding {
            check,
            severity: Severity::Warning,
            path: path.into(),
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_has_a_unique_stable_id() {
        let mut seen = std::collections::HashSet::new();
        for check in Check::ALL {
            assert!(seen.insert(check.id()), "duplicate id {}", check.id());
            // Ids are the CLI surface: kebab-case ASCII only.
            assert!(check
                .id()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '-'));
        }
    }

    #[test]
    fn from_id_round_trips_all_checks() {
        for check in Check::ALL {
            assert_eq!(Check::from_id(check.id()), Some(check));
        }
        assert_eq!(Check::from_id("no-such-check"), None);
        // Ids are case-sensitive by design; don't silently accept variants.
        assert_eq!(Check::from_id("Traversal"), None);
    }

    #[test]
    fn severity_orders_critical_above_warning() {
        assert!(Severity::Critical > Severity::Warning);
    }
}
