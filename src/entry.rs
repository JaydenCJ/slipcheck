//! The format-agnostic archive entry: what the tar and zip readers hand to
//! the auditor. Only metadata — slipcheck never materializes file contents
//! (the single exception is decoding a zip symlink's target).

/// What kind of filesystem object an entry would create on extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Hardlink,
    CharDevice,
    BlockDevice,
    Fifo,
    /// A type slipcheck does not model (e.g. GNU sparse maps, volume
    /// headers). Carried through so the auditor can warn instead of
    /// silently skipping.
    Other(char),
}

impl EntryKind {
    pub fn label(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Dir => "dir",
            EntryKind::Symlink => "symlink",
            EntryKind::Hardlink => "hardlink",
            EntryKind::CharDevice => "char-device",
            EntryKind::BlockDevice => "block-device",
            EntryKind::Fifo => "fifo",
            EntryKind::Other(_) => "other",
        }
    }
}

/// One archive member, normalized across formats.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The raw path exactly as stored in the archive.
    pub path: String,
    pub kind: EntryKind,
    /// Unix permission bits including setuid/setgid/sticky (`0o7777` mask),
    /// when the format records them. Zip entries made on non-unix hosts
    /// have `None`.
    pub mode: Option<u32>,
    /// Symlink or hard link target, raw as stored.
    pub link_target: Option<String>,
    /// Uncompressed payload size in bytes.
    pub size: u64,
}

impl Entry {
    pub fn new(path: impl Into<String>, kind: EntryKind) -> Entry {
        Entry {
            path: path.into(),
            kind,
            mode: None,
            link_target: None,
            size: 0,
        }
    }

    pub fn with_mode(mut self, mode: u32) -> Entry {
        self.mode = Some(mode);
        self
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Entry {
        self.link_target = Some(target.into());
        self
    }
}
