//! The format-agnostic auditor. Entries are replayed in archive order —
//! the order an extractor would create them — against a virtual extraction
//! root, tracking every symlink the archive plants so that later entries
//! writing *through* those links are caught (the modern zip-slip variant
//! that pure name checks miss).

use std::collections::HashMap;

use crate::entry::{Entry, EntryKind};
use crate::findings::{Check, Finding};
use crate::paths::{self, PathCheck};

/// Where a recorded symlink ultimately points, with in-archive chains
/// already followed at the time the link was recorded.
#[derive(Debug, Clone)]
enum LinkState {
    Inside(Vec<String>),
    Escaped,
}

/// Outcome of resolving a normalized path through the recorded symlinks.
#[derive(Debug)]
enum Resolution {
    Inside {
        comps: Vec<String>,
        crossed: Vec<String>,
    },
    Escaped {
        via: String,
    },
}

/// Longest in-archive symlink chain the resolver will follow before it
/// gives up and treats the path as hostile (loops included).
const MAX_LINK_HOPS: usize = 40;

pub struct Auditor {
    /// Findings suppressed via `--allow`.
    allowed: Vec<Check>,
    findings: Vec<Finding>,
    entries: usize,
    /// Normalized symlink path -> resolved target state.
    links: HashMap<String, LinkState>,
    /// Normalized path -> (occurrences, any occurrence was a non-directory).
    seen: HashMap<String, (usize, bool)>,
    /// Case-folded path -> first original spelling.
    folded: HashMap<String, String>,
}

impl Auditor {
    pub fn new(allowed: &[Check]) -> Auditor {
        Auditor {
            allowed: allowed.to_vec(),
            findings: Vec::new(),
            entries: 0,
            links: HashMap::new(),
            seen: HashMap::new(),
            folded: HashMap::new(),
        }
    }

    /// Run the full pipeline over `entries` (plus any findings the format
    /// reader already produced, e.g. zip name mismatches).
    pub fn run(entries: &[Entry], pre: Vec<Finding>, allowed: &[Check]) -> (Vec<Finding>, usize) {
        let mut auditor = Auditor::new(allowed);
        for finding in pre {
            auditor.push(finding);
        }
        for entry in entries {
            auditor.record(entry);
        }
        (auditor.findings, auditor.entries)
    }

    fn push(&mut self, finding: Finding) {
        if !self.allowed.contains(&finding.check) {
            self.findings.push(finding);
        }
    }

    /// Feed one entry, in archive order.
    pub fn record(&mut self, entry: &Entry) {
        self.entries += 1;
        self.check_mode(entry);
        self.check_kind(entry);

        match paths::classify(&entry.path) {
            PathCheck::Empty => {
                self.push(Finding::warning(
                    Check::Traversal,
                    "(empty)",
                    "entry has an empty name; extractors disagree on what to do with it",
                ));
            }
            PathCheck::Absolute { kind } => {
                self.push(Finding::critical(
                    Check::AbsolutePath,
                    &entry.path,
                    format!("entry name is absolute ({kind}); extraction can write anywhere"),
                ));
            }
            PathCheck::Escapes => {
                self.push(Finding::critical(
                    Check::Traversal,
                    &entry.path,
                    "entry name climbs above the extraction root via '..'",
                ));
            }
            PathCheck::Inside(comps) => self.record_inside(entry, comps),
        }
    }

    fn record_inside(&mut self, entry: &Entry, comps: Vec<String>) {
        if comps.is_empty() {
            return; // the "." entry: the root itself, nothing to track
        }
        let joined = paths::join(&comps);
        self.check_duplicate(entry, &joined);
        self.check_case_collision(entry, &comps, &joined);

        // Where does the *parent directory* of this entry actually land,
        // once in-archive symlinks are honored?
        let parent = &comps[..comps.len() - 1];
        let resolved_parent = match self.resolve(parent) {
            Resolution::Escaped { via } => {
                self.push(Finding::critical(
                    Check::LinkIndirection,
                    &entry.path,
                    format!(
                        "written through symlink '{via}', which points outside the extraction root"
                    ),
                ));
                None
            }
            Resolution::Inside {
                comps: resolved,
                crossed,
            } => {
                if let Some(via) = crossed.last() {
                    let name = comps.last().map(String::as_str).unwrap_or("");
                    let lands = paths::join(&resolved);
                    self.push(Finding::warning(
                        Check::LinkIndirection,
                        &entry.path,
                        format!(
                            "written through in-archive symlink '{via}'; extraction lands at '{lands}/{name}'"
                        ),
                    ));
                }
                Some(resolved)
            }
        };

        // Does this entry overwrite a path that is already a symlink?
        // Extractors that do not unlink first will follow it.
        if entry.kind != EntryKind::Symlink {
            if let Some(state) = self.links.get(&joined).cloned() {
                match &state {
                    LinkState::Escaped => self.push(Finding::critical(
                        Check::LinkIndirection,
                        &entry.path,
                        format!(
                            "overwrites earlier symlink '{joined}' that points outside the root; extractors that follow existing links write outside"
                        ),
                    )),
                    LinkState::Inside(target) => {
                        let lands = paths::join(target);
                        self.push(Finding::warning(
                            Check::LinkIndirection,
                            &entry.path,
                            format!("overwrites earlier symlink '{joined}' (resolves to '{lands}')"),
                        ));
                    }
                }
            }
        }

        match entry.kind {
            EntryKind::Symlink => self.record_symlink(entry, &comps, &joined, resolved_parent),
            EntryKind::Hardlink => self.record_hardlink(entry),
            _ => {}
        }
    }

    fn record_symlink(
        &mut self,
        entry: &Entry,
        comps: &[String],
        joined: &str,
        resolved_parent: Option<Vec<String>>,
    ) {
        let target = entry.link_target.clone().unwrap_or_default();
        // Resolve the target relative to where the link *actually* lives
        // (the parent already resolved through earlier symlinks).
        let base_owned;
        let base: &[String] = match &resolved_parent {
            Some(resolved) => resolved,
            None => {
                base_owned = comps[..comps.len() - 1].to_vec();
                &base_owned
            }
        };
        let state = match paths::resolve_relative(base, &target) {
            PathCheck::Empty => {
                self.push(Finding::warning(
                    Check::LinkEscape,
                    &entry.path,
                    "symlink has an empty target",
                ));
                LinkState::Escaped
            }
            PathCheck::Absolute { kind } => {
                self.push(Finding::critical(
                    Check::LinkEscape,
                    &entry.path,
                    format!("symlink target '{target}' is absolute ({kind})"),
                ));
                LinkState::Escaped
            }
            PathCheck::Escapes => {
                self.push(Finding::critical(
                    Check::LinkEscape,
                    &entry.path,
                    format!("symlink target '{target}' escapes the extraction root"),
                ));
                LinkState::Escaped
            }
            PathCheck::Inside(target_comps) => match self.resolve(&target_comps) {
                Resolution::Escaped { via } => {
                    self.push(Finding::critical(
                        Check::LinkEscape,
                        &entry.path,
                        format!(
                            "symlink target '{target}' resolves through symlink '{via}' to outside the root"
                        ),
                    ));
                    LinkState::Escaped
                }
                Resolution::Inside {
                    comps: resolved, ..
                } => LinkState::Inside(resolved),
            },
        };
        self.links.insert(joined.to_string(), state);
    }

    fn record_hardlink(&mut self, entry: &Entry) {
        let target = entry.link_target.clone().unwrap_or_default();
        // Hard-link targets are archive-root relative (tar semantics).
        match paths::resolve_relative(&[], &target) {
            PathCheck::Empty => self.push(Finding::warning(
                Check::LinkEscape,
                &entry.path,
                "hard link has an empty target",
            )),
            PathCheck::Absolute { kind } => self.push(Finding::critical(
                Check::LinkEscape,
                &entry.path,
                format!("hard link target '{target}' is absolute ({kind}); links to a file outside the root"),
            )),
            PathCheck::Escapes => self.push(Finding::critical(
                Check::LinkEscape,
                &entry.path,
                format!("hard link target '{target}' escapes the extraction root"),
            )),
            PathCheck::Inside(target_comps) => {
                if let Resolution::Escaped { via } = self.resolve(&target_comps) {
                    self.push(Finding::critical(
                        Check::LinkEscape,
                        &entry.path,
                        format!("hard link target '{target}' resolves through symlink '{via}' to outside the root"),
                    ));
                }
            }
        }
    }

    /// Resolve normalized components through the recorded symlinks, the way
    /// the kernel would walk the extracted tree at this point in time.
    fn resolve(&self, comps: &[String]) -> Resolution {
        let mut out: Vec<String> = Vec::new();
        let mut crossed: Vec<String> = Vec::new();
        let mut hops = 0usize;
        for comp in comps {
            out.push(comp.clone());
            // Follow chains: the substituted prefix may itself be a link.
            loop {
                let key = paths::join(&out);
                match self.links.get(&key) {
                    None => break,
                    Some(LinkState::Escaped) => return Resolution::Escaped { via: key },
                    Some(LinkState::Inside(target)) => {
                        hops += 1;
                        if hops > MAX_LINK_HOPS {
                            // Loop or absurd chain: treat as hostile.
                            return Resolution::Escaped { via: key };
                        }
                        crossed.push(key);
                        out = target.clone();
                    }
                }
            }
        }
        Resolution::Inside {
            comps: out,
            crossed,
        }
    }

    fn check_duplicate(&mut self, entry: &Entry, joined: &str) {
        let non_dir = entry.kind != EntryKind::Dir;
        let slot = self.seen.entry(joined.to_string()).or_insert((0, false));
        slot.0 += 1;
        let previously_non_dir = slot.1;
        slot.1 |= non_dir;
        // Repeated directories are normal (zip writes them liberally);
        // flag only when a non-directory is involved on either side.
        if slot.0 >= 2 && (non_dir || previously_non_dir) {
            let count = slot.0;
            self.push(Finding::warning(
                Check::DuplicatePath,
                &entry.path,
                format!("path appears {count} times; the last entry silently wins on extraction"),
            ));
        }
    }

    fn check_case_collision(&mut self, entry: &Entry, comps: &[String], joined: &str) {
        let folded = paths::fold_case(comps);
        match self.folded.get(&folded).cloned() {
            None => {
                self.folded.insert(folded, joined.to_string());
            }
            Some(first) if first != joined => {
                self.push(Finding::warning(
                    Check::CaseCollision,
                    &entry.path,
                    format!("collides with '{first}' on case-insensitive filesystems"),
                ));
            }
            Some(_) => {} // exact same path: duplicate check covers it
        }
    }

    fn check_mode(&mut self, entry: &Entry) {
        let Some(mode) = entry.mode else { return };
        // Permission bits are only meaningful for files and directories.
        if !matches!(entry.kind, EntryKind::File | EntryKind::Dir) {
            return;
        }
        if mode & 0o4000 != 0 {
            self.push(Finding::critical(
                Check::Setuid,
                &entry.path,
                format!("mode {mode:04o} carries the setuid bit; runs as the owner after extraction by root"),
            ));
        }
        if mode & 0o2000 != 0 {
            self.push(Finding::critical(
                Check::Setgid,
                &entry.path,
                format!("mode {mode:04o} carries the setgid bit"),
            ));
        }
        if mode & 0o002 != 0 {
            self.push(Finding::warning(
                Check::WorldWritable,
                &entry.path,
                format!("mode {mode:04o} is world-writable"),
            ));
        }
    }

    fn check_kind(&mut self, entry: &Entry) {
        match entry.kind {
            EntryKind::CharDevice | EntryKind::BlockDevice => {
                self.push(Finding::critical(
                    Check::SpecialFile,
                    &entry.path,
                    format!(
                        "{} node in the archive; extraction as root creates a device",
                        entry.kind.label()
                    ),
                ));
            }
            EntryKind::Fifo => {
                self.push(Finding::warning(
                    Check::SpecialFile,
                    &entry.path,
                    "fifo (named pipe) in the archive",
                ));
            }
            EntryKind::Other(flag) => {
                self.push(Finding::warning(
                    Check::SpecialFile,
                    &entry.path,
                    format!("unrecognized entry type '{flag}'; slipcheck cannot vouch for it"),
                ));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    fn file(path: &str) -> Entry {
        Entry::new(path, EntryKind::File).with_mode(0o644)
    }

    fn dir(path: &str) -> Entry {
        Entry::new(path, EntryKind::Dir).with_mode(0o755)
    }

    fn symlink(path: &str, target: &str) -> Entry {
        Entry::new(path, EntryKind::Symlink).with_target(target)
    }

    fn audit(entries: &[Entry]) -> Vec<Finding> {
        Auditor::run(entries, Vec::new(), &[]).0
    }

    fn ids(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.check.id()).collect()
    }

    #[test]
    fn clean_package_produces_no_findings() {
        let entries = [
            dir("pkg"),
            file("pkg/README.md"),
            dir("pkg/bin"),
            file("pkg/bin/tool"),
            symlink("pkg/bin/alias", "tool"),
        ];
        assert!(audit(&entries).is_empty());
    }

    #[test]
    fn traversal_and_absolute_names_are_critical() {
        let findings = audit(&[file("../../etc/cron.d/job"), file("/etc/passwd")]);
        assert_eq!(ids(&findings), vec!["traversal", "absolute-path"]);
        assert!(findings.iter().all(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn symlink_with_absolute_target_is_link_escape() {
        let findings = audit(&[symlink("lib/libz.so", "/usr/lib/libz.so")]);
        assert_eq!(ids(&findings), vec!["link-escape"]);
        assert!(findings[0].detail.contains("absolute"));
    }

    #[test]
    fn symlink_climbing_out_relative_to_its_own_directory() {
        // "../.." from deep/nested/ is still inside; "../../.." is not.
        assert!(audit(&[symlink("deep/nested/ok", "../../fine")]).is_empty());
        let findings = audit(&[symlink("deep/nested/bad", "../../../outside")]);
        assert_eq!(ids(&findings), vec!["link-escape"]);
    }

    #[test]
    fn file_written_through_escaping_symlink_is_critical() {
        // The canonical two-step zip-slip: plant a link, then write through it.
        let findings = audit(&[symlink("build", "../../target"), file("build/injected.sh")]);
        assert_eq!(ids(&findings), vec!["link-escape", "link-indirection"]);
        assert_eq!(findings[1].severity, Severity::Critical);
        assert!(findings[1].detail.contains("build"));
    }

    #[test]
    fn file_written_through_internal_symlink_is_a_warning() {
        // The link stays inside the root, so the write cannot escape —
        // but it does not land where the name says, which merits a warning.
        let findings = audit(&[symlink("alias", "real"), file("alias/data.txt")]);
        assert_eq!(ids(&findings), vec!["link-indirection"]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].detail.contains("real/data.txt"));
    }

    #[test]
    fn symlink_chains_are_followed_to_their_end() {
        // a -> b, b -> ../../out: writing under a escapes via the chain.
        let findings = audit(&[
            symlink("stage/b", "../../out"),
            symlink("a", "stage/b"),
            file("a/payload"),
        ]);
        // stage/b escapes (link-escape), a resolves through it (link-escape),
        // and the write through a is critical indirection.
        assert_eq!(
            ids(&findings),
            vec!["link-escape", "link-escape", "link-indirection"]
        );
        assert!(findings.iter().all(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn symlink_loop_is_treated_as_hostile_not_an_infinite_loop() {
        let findings = audit(&[symlink("a", "b"), symlink("b", "a"), file("a/x")]);
        // Must terminate and flag the write; exact chain length is an
        // implementation detail, the guarantee is: no hang, critical result.
        assert!(ids(&findings).contains(&"link-indirection"));
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn file_overwriting_an_escaping_symlink_is_critical() {
        // Same path twice: first a hostile symlink, then a regular file.
        // Extractors that do not unlink first follow the link on write.
        let findings = audit(&[symlink("cfg", "/etc"), file("cfg")]);
        assert!(ids(&findings).contains(&"link-escape"));
        assert!(findings
            .iter()
            .any(|f| f.check == Check::LinkIndirection && f.severity == Severity::Critical));
    }

    #[test]
    fn hardlink_targets_resolve_from_the_archive_root() {
        // Unlike symlinks, "../x" in a hard link escapes even from deep dirs.
        let findings =
            audit(&[Entry::new("deep/dir/link", EntryKind::Hardlink).with_target("../x")]);
        assert_eq!(ids(&findings), vec!["link-escape"]);
        // Root-relative target inside the tree is fine.
        assert!(audit(&[
            file("bin/tool"),
            Entry::new("deep/dir/link", EntryKind::Hardlink).with_target("bin/tool"),
        ])
        .is_empty());
    }

    #[test]
    fn setuid_setgid_and_world_writable_bits() {
        let findings = audit(&[
            Entry::new("bin/su-like", EntryKind::File).with_mode(0o4755),
            Entry::new("bin/sg-like", EntryKind::File).with_mode(0o2755),
            Entry::new("share/loose", EntryKind::File).with_mode(0o666),
        ]);
        assert_eq!(ids(&findings), vec!["setuid", "setgid", "world-writable"]);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[2].severity, Severity::Warning);
    }

    #[test]
    fn symlink_modes_are_ignored() {
        // Symlinks commonly carry 0o777; that is meaningless, not a finding.
        let entry = Entry::new("ln", EntryKind::Symlink)
            .with_mode(0o777)
            .with_target("x");
        assert!(audit(&[entry]).is_empty());
    }

    #[test]
    fn device_nodes_are_critical_fifos_are_warnings() {
        let findings = audit(&[
            Entry::new("dev/sda", EntryKind::BlockDevice),
            Entry::new("dev/null", EntryKind::CharDevice),
            Entry::new("run/pipe", EntryKind::Fifo),
        ]);
        assert_eq!(
            ids(&findings),
            vec!["special-file", "special-file", "special-file"]
        );
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[2].severity, Severity::Warning);
    }

    #[test]
    fn duplicate_files_flagged_duplicate_dirs_tolerated() {
        // zip tools write the same directory entry freely; that is noise.
        assert!(audit(&[dir("a"), dir("a")]).is_empty());
        let findings = audit(&[file("a/x"), file("a/x")]);
        assert_eq!(ids(&findings), vec!["duplicate-path"]);
        // A dir and a file with the same normalized path do conflict.
        let findings = audit(&[dir("b"), file("b")]);
        assert_eq!(ids(&findings), vec!["duplicate-path"]);
    }

    #[test]
    fn equivalent_spellings_count_as_duplicates() {
        // "./a//x" and "a/x" normalize to the same write target.
        let findings = audit(&[file("./a//x"), file("a/x")]);
        assert_eq!(ids(&findings), vec!["duplicate-path"]);
    }

    #[test]
    fn case_collision_is_flagged_once_per_pair() {
        let findings = audit(&[file("README"), file("readme")]);
        assert_eq!(ids(&findings), vec!["case-collision"]);
        assert!(findings[0].detail.contains("README"));
    }

    #[test]
    fn allowed_checks_are_suppressed() {
        let entries = [
            file("bin/x"),
            Entry::new("bin/su", EntryKind::File).with_mode(0o4755),
        ];
        let (findings, entries_seen) = Auditor::run(&entries, Vec::new(), &[Check::Setuid]);
        assert!(findings.is_empty());
        assert_eq!(entries_seen, 2);
    }

    #[test]
    fn empty_entry_name_is_a_warning() {
        let findings = audit(&[file("")]);
        assert_eq!(ids(&findings), vec!["traversal"]);
        assert_eq!(findings[0].severity, Severity::Warning);
    }
}
