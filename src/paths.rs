//! Pure path arithmetic. Nothing in this module touches the filesystem:
//! it classifies raw archive entry names against a virtual extraction
//! root, exactly as a (naive) extractor would interpret them.
//!
//! Deliberately conservative choices:
//! - Both `/` and `\` are treated as separators. A name like `a\..\..\x`
//!   is harmless on Linux but escapes the root when extracted on Windows,
//!   so slipcheck flags it everywhere.
//! - Drive letters (`C:...`) and UNC prefixes count as absolute.

/// Result of interpreting a raw entry name relative to the extraction root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathCheck {
    /// Stays inside the root; the normalized components (no `.`/`..`,
    /// no empty parts). May be empty for names like `"."` or `"./"`.
    Inside(Vec<String>),
    /// Absolute in some interpretation; `kind` says which one.
    Absolute { kind: &'static str },
    /// Uses `..` to climb above the extraction root.
    Escapes,
    /// The name is empty.
    Empty,
}

/// Split a raw name on both separator conventions.
pub fn split(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(['/', '\\'])
}

/// Is the raw name absolute, and if so, in which convention?
pub fn absolute_kind(raw: &str) -> Option<&'static str> {
    let bytes = raw.as_bytes();
    if raw.starts_with("\\\\") || raw.starts_with("//") {
        return Some("UNC path");
    }
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Some("leading separator");
    }
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Some("Windows drive letter");
    }
    None
}

/// Classify a raw entry name against the extraction root.
pub fn classify(raw: &str) -> PathCheck {
    if raw.is_empty() {
        return PathCheck::Empty;
    }
    if let Some(kind) = absolute_kind(raw) {
        return PathCheck::Absolute { kind };
    }
    let mut out: Vec<String> = Vec::new();
    for comp in split(raw) {
        match comp {
            "" | "." => continue,
            ".." => {
                if out.pop().is_none() {
                    return PathCheck::Escapes;
                }
            }
            other => out.push(other.to_string()),
        }
    }
    PathCheck::Inside(out)
}

/// Resolve a link target the way extraction would: symlink targets are
/// relative to the directory containing the link (`base_dir`); pass an
/// empty base for hard links, whose targets are archive-root relative.
pub fn resolve_relative(base_dir: &[String], target: &str) -> PathCheck {
    if target.is_empty() {
        return PathCheck::Empty;
    }
    if let Some(kind) = absolute_kind(target) {
        return PathCheck::Absolute { kind };
    }
    let mut out: Vec<String> = base_dir.to_vec();
    for comp in split(target) {
        match comp {
            "" | "." => continue,
            ".." => {
                if out.pop().is_none() {
                    return PathCheck::Escapes;
                }
            }
            other => out.push(other.to_string()),
        }
    }
    PathCheck::Inside(out)
}

/// Join normalized components back into a display path.
pub fn join(comps: &[String]) -> String {
    comps.join("/")
}

/// Case-folded key used for collision detection on case-insensitive
/// filesystems (macOS default, Windows).
pub fn fold_case(comps: &[String]) -> String {
    comps
        .iter()
        .map(|c| c.to_lowercase())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inside(raw: &str) -> Vec<String> {
        match classify(raw) {
            PathCheck::Inside(c) => c,
            other => panic!("expected Inside for {raw:?}, got {other:?}"),
        }
    }

    #[test]
    fn plain_relative_paths_stay_inside() {
        assert_eq!(inside("bin/tool"), vec!["bin", "tool"]);
        assert_eq!(inside("a/b/c.txt"), vec!["a", "b", "c.txt"]);
    }

    #[test]
    fn dot_and_empty_components_are_dropped() {
        assert_eq!(inside("./a//./b/"), vec!["a", "b"]);
        // "." alone is the root itself — inside, zero components.
        assert_eq!(inside("."), Vec::<String>::new());
        assert_eq!(inside("./"), Vec::<String>::new());
    }

    #[test]
    fn interior_dotdot_that_stays_inside_is_allowed() {
        // "a/b/../c" normalizes to "a/c" without ever leaving the root.
        assert_eq!(inside("a/b/../c"), vec!["a", "c"]);
    }

    #[test]
    fn leading_dotdot_escapes() {
        assert_eq!(classify("../x"), PathCheck::Escapes);
        assert_eq!(classify("../../etc/passwd"), PathCheck::Escapes);
    }

    #[test]
    fn dotdot_that_dips_below_root_escapes_even_if_it_comes_back() {
        // The classic bypass for naive "count the ..s" checks: the walk
        // touches the parent directory before diving back down.
        assert_eq!(classify("a/../../b/deep/inside"), PathCheck::Escapes);
    }

    #[test]
    fn prefixed_dotdot_after_dot_escapes() {
        assert_eq!(classify("./../x"), PathCheck::Escapes);
    }

    #[test]
    fn absolute_unix_path_is_flagged() {
        assert_eq!(
            classify("/etc/cron.d/job"),
            PathCheck::Absolute {
                kind: "leading separator"
            }
        );
    }

    #[test]
    fn windows_drive_and_unc_are_absolute() {
        assert_eq!(
            classify("C:\\Windows\\System32\\evil.dll"),
            PathCheck::Absolute {
                kind: "Windows drive letter"
            }
        );
        assert_eq!(
            classify("c:boot.ini"),
            PathCheck::Absolute {
                kind: "Windows drive letter"
            }
        );
        assert_eq!(
            classify("\\\\server\\share\\x"),
            PathCheck::Absolute { kind: "UNC path" }
        );
        assert_eq!(
            classify("//host/share"),
            PathCheck::Absolute { kind: "UNC path" }
        );
    }

    #[test]
    fn backslashes_count_as_separators() {
        // Harmless on Linux, an escape on Windows — flagged everywhere.
        assert_eq!(classify("a\\..\\..\\x"), PathCheck::Escapes);
        assert_eq!(inside("dir\\file.txt"), vec!["dir", "file.txt"]);
    }

    #[test]
    fn empty_name_is_its_own_case() {
        assert_eq!(classify(""), PathCheck::Empty);
    }

    #[test]
    fn resolve_relative_walks_from_the_link_directory() {
        let base = vec!["lib".to_string(), "pkg".to_string()];
        assert_eq!(
            resolve_relative(&base, "../shared/libz.so"),
            PathCheck::Inside(vec!["lib".into(), "shared".into(), "libz.so".into()])
        );
    }

    #[test]
    fn resolve_relative_escape_and_absolute_targets() {
        let base = vec!["lib".to_string()];
        assert_eq!(resolve_relative(&base, "../../outside"), PathCheck::Escapes);
        assert_eq!(
            resolve_relative(&base, "/usr/lib/libz.so"),
            PathCheck::Absolute {
                kind: "leading separator"
            }
        );
        assert_eq!(resolve_relative(&base, ""), PathCheck::Empty);
    }

    #[test]
    fn resolve_relative_with_empty_base_is_root_relative() {
        // Hard-link semantics: targets resolve from the archive root.
        assert_eq!(
            resolve_relative(&[], "bin/tool"),
            PathCheck::Inside(vec!["bin".into(), "tool".into()])
        );
        assert_eq!(resolve_relative(&[], "../outside"), PathCheck::Escapes);
    }

    #[test]
    fn fold_case_lowers_every_component() {
        let a = vec!["Bin".to_string(), "Tool".to_string()];
        let b = vec!["bin".to_string(), "tool".to_string()];
        assert_eq!(fold_case(&a), fold_case(&b));
        assert_ne!(join(&a), join(&b));
    }
}
