//! A metadata-only zip reader driven by the central directory (with
//! ZIP64 support for large archives). File payloads are never inflated;
//! the two exceptions are tiny and capped:
//!
//! - symlink entries: the target *is* the payload, so it is decoded
//!   (stored or deflate, capped at 4 KiB),
//! - every entry's local header is cross-checked against the central
//!   directory, because listers trust one and stream extractors trust
//!   the other — a classic smuggling seam.

use std::fmt;

use crate::entry::{Entry, EntryKind};
use crate::findings::{Check, Finding};
use crate::inflate;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipError {
    /// No end-of-central-directory record: not a zip file, or a broken one.
    NoEndOfCentralDirectory,
    /// A structure runs past the end of the input.
    Truncated(&'static str),
    /// A signature was not where a structure said it would be.
    BadSignature(&'static str),
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZipError::NoEndOfCentralDirectory => {
                write!(f, "no end-of-central-directory record (not a zip archive?)")
            }
            ZipError::Truncated(what) => write!(f, "zip archive truncated at {what}"),
            ZipError::BadSignature(what) => write!(f, "bad zip signature at {what}"),
        }
    }
}

/// Longest symlink target slipcheck will decode; anything larger is
/// treated as hostile rather than allocated.
const MAX_LINK_TARGET: usize = 4096;

const EOCD_SIG: u32 = 0x0605_4B50;
const EOCD64_SIG: u32 = 0x0606_4B50;
const EOCD64_LOCATOR_SIG: u32 = 0x0706_4B50;
const CENTRAL_SIG: u32 = 0x0201_4B50;
const LOCAL_SIG: u32 = 0x0403_4B50;

fn u16_at(data: &[u8], pos: usize) -> Option<u16> {
    data.get(pos..pos + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], pos: usize) -> Option<u32> {
    data.get(pos..pos + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(data: &[u8], pos: usize) -> Option<u64> {
    data.get(pos..pos + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Locate the EOCD record by scanning backwards through the zip comment
/// window (up to 64 KiB), requiring the comment length to be consistent
/// so a stray signature inside the comment is not mistaken for the record.
fn find_eocd(data: &[u8]) -> Option<usize> {
    let min = data.len().saturating_sub(22 + 0xFFFF);
    let mut pos = data.len().checked_sub(22)?;
    loop {
        if u32_at(data, pos) == Some(EOCD_SIG) {
            let comment_len = u16_at(data, pos + 20)? as usize;
            if pos + 22 + comment_len == data.len() {
                return Some(pos);
            }
        }
        if pos == min {
            return None;
        }
        pos -= 1;
    }
}

struct CentralDirectory {
    offset: u64,
    entries: u64,
}

fn locate_central_directory(data: &[u8]) -> Result<CentralDirectory, ZipError> {
    let eocd = find_eocd(data).ok_or(ZipError::NoEndOfCentralDirectory)?;
    let entries = u16_at(data, eocd + 10).unwrap() as u64;
    let offset = u32_at(data, eocd + 16).unwrap() as u64;
    if entries != 0xFFFF && offset != 0xFFFF_FFFF {
        return Ok(CentralDirectory { offset, entries });
    }
    // ZIP64: the locator sits directly before the EOCD.
    let locator = eocd
        .checked_sub(20)
        .ok_or(ZipError::Truncated("zip64 locator"))?;
    if u32_at(data, locator) != Some(EOCD64_LOCATOR_SIG) {
        return Err(ZipError::BadSignature("zip64 locator"));
    }
    let eocd64 = u64_at(data, locator + 8).ok_or(ZipError::Truncated("zip64 locator"))? as usize;
    if u32_at(data, eocd64) != Some(EOCD64_SIG) {
        return Err(ZipError::BadSignature("zip64 end of central directory"));
    }
    let entries = u64_at(data, eocd64 + 32).ok_or(ZipError::Truncated("zip64 EOCD"))?;
    let offset = u64_at(data, eocd64 + 48).ok_or(ZipError::Truncated("zip64 EOCD"))?;
    Ok(CentralDirectory { offset, entries })
}

struct CentralEntry {
    name: String,
    method: u16,
    csize: u64,
    external: u32,
    made_by_host: u8,
    local_offset: u64,
    /// Size of the whole central header (to advance the cursor).
    header_len: usize,
}

fn parse_central_entry(data: &[u8], pos: usize) -> Result<CentralEntry, ZipError> {
    if u32_at(data, pos) != Some(CENTRAL_SIG) {
        return Err(ZipError::BadSignature("central directory header"));
    }
    let made_by = u16_at(data, pos + 4).ok_or(ZipError::Truncated("central header"))?;
    let method = u16_at(data, pos + 10).ok_or(ZipError::Truncated("central header"))?;
    let mut csize = u32_at(data, pos + 20).ok_or(ZipError::Truncated("central header"))? as u64;
    let usize_ = u32_at(data, pos + 24).ok_or(ZipError::Truncated("central header"))? as u64;
    let name_len = u16_at(data, pos + 28).ok_or(ZipError::Truncated("central header"))? as usize;
    let extra_len = u16_at(data, pos + 30).ok_or(ZipError::Truncated("central header"))? as usize;
    let comment_len = u16_at(data, pos + 32).ok_or(ZipError::Truncated("central header"))? as usize;
    let external = u32_at(data, pos + 38).ok_or(ZipError::Truncated("central header"))?;
    let mut local_offset =
        u32_at(data, pos + 42).ok_or(ZipError::Truncated("central header"))? as u64;
    let name_bytes = data
        .get(pos + 46..pos + 46 + name_len)
        .ok_or(ZipError::Truncated("central header name"))?;
    let name = String::from_utf8_lossy(name_bytes).into_owned();

    // ZIP64 extra field: values that overflowed 32 bits appear here, in
    // a fixed order, only for the fields that are maxed out.
    let extra_start = pos + 46 + name_len;
    let extra = data
        .get(extra_start..extra_start + extra_len)
        .ok_or(ZipError::Truncated("central header extra"))?;
    let mut cursor = 0usize;
    while cursor + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[cursor], extra[cursor + 1]]);
        let len = u16::from_le_bytes([extra[cursor + 2], extra[cursor + 3]]) as usize;
        let body = extra
            .get(cursor + 4..cursor + 4 + len)
            .ok_or(ZipError::Truncated("central extra field"))?;
        if id == 0x0001 {
            let mut field = 0usize;
            let mut next = || {
                let v = u64_at(body, field);
                field += 8;
                v
            };
            if usize_ == 0xFFFF_FFFF {
                next().ok_or(ZipError::Truncated("zip64 extra"))?;
            }
            if csize == 0xFFFF_FFFF {
                csize = next().ok_or(ZipError::Truncated("zip64 extra"))?;
            }
            if local_offset == 0xFFFF_FFFF {
                local_offset = next().ok_or(ZipError::Truncated("zip64 extra"))?;
            }
        }
        cursor += 4 + len;
    }

    Ok(CentralEntry {
        name,
        method,
        csize,
        external,
        made_by_host: (made_by >> 8) as u8,
        local_offset,
        header_len: 46 + name_len + extra_len + comment_len,
    })
}

/// Unix host id in "version made by" — the only host whose external
/// attributes carry a full st_mode.
const HOST_UNIX: u8 = 3;

fn classify_kind(central: &CentralEntry) -> (EntryKind, Option<u32>) {
    if central.made_by_host == HOST_UNIX {
        let st_mode = central.external >> 16;
        let perms = Some(st_mode & 0o7777);
        return match st_mode & 0o170000 {
            0o120000 => (EntryKind::Symlink, perms),
            0o040000 => (EntryKind::Dir, perms),
            0o010000 => (EntryKind::Fifo, perms),
            0o020000 => (EntryKind::CharDevice, perms),
            0o060000 => (EntryKind::BlockDevice, perms),
            _ => {
                // Some tools set host=unix but leave the type bits empty.
                if central.name.ends_with('/') {
                    (EntryKind::Dir, perms)
                } else {
                    (EntryKind::File, perms)
                }
            }
        };
    }
    // DOS/Windows-made entries: directory bit or trailing slash, no mode.
    if central.name.ends_with('/') || central.external & 0x10 != 0 {
        (EntryKind::Dir, None)
    } else {
        (EntryKind::File, None)
    }
}

/// Read the name stored in an entry's local header, and the position of
/// its payload.
fn local_header(data: &[u8], offset: u64) -> Result<(String, usize), ZipError> {
    let pos = offset as usize;
    if u32_at(data, pos) != Some(LOCAL_SIG) {
        return Err(ZipError::BadSignature("local file header"));
    }
    let name_len = u16_at(data, pos + 26).ok_or(ZipError::Truncated("local header"))? as usize;
    let extra_len = u16_at(data, pos + 28).ok_or(ZipError::Truncated("local header"))? as usize;
    let name_bytes = data
        .get(pos + 30..pos + 30 + name_len)
        .ok_or(ZipError::Truncated("local header name"))?;
    let name = String::from_utf8_lossy(name_bytes).into_owned();
    Ok((name, pos + 30 + name_len + extra_len))
}

/// Decode a symlink entry's target from its payload.
fn read_link_target(data: &[u8], payload_at: usize, central: &CentralEntry) -> Option<String> {
    let csize = central.csize as usize;
    let raw = data.get(payload_at..payload_at + csize)?;
    let bytes = match central.method {
        0 => raw.to_vec(),
        8 => inflate::inflate(raw, MAX_LINK_TARGET).ok()?.0,
        _ => return None,
    };
    if bytes.len() > MAX_LINK_TARGET {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read all entries from a zip archive, plus any structural findings
/// (name mismatches between the central directory and local headers).
pub fn read_entries(data: &[u8]) -> Result<(Vec<Entry>, Vec<Finding>), ZipError> {
    let cd = locate_central_directory(data)?;
    let mut entries = Vec::new();
    let mut findings = Vec::new();
    let mut pos = cd.offset as usize;
    for _ in 0..cd.entries {
        let central = parse_central_entry(data, pos)?;
        let (kind, mode) = classify_kind(&central);

        let mut entry = Entry::new(central.name.clone(), kind);
        entry.mode = mode;
        entry.size = central.csize;

        match local_header(data, central.local_offset) {
            Ok((local_name, payload_at)) => {
                if local_name != central.name {
                    findings.push(Finding::warning(
                        Check::NameMismatch,
                        &central.name,
                        format!(
                            "central directory says '{}' but the local header says '{}'; stream extractors will use the latter",
                            central.name, local_name
                        ),
                    ));
                    // Audit the smuggled name too: it is what some
                    // extractors will actually write.
                    let mut smuggled = Entry::new(local_name, kind);
                    smuggled.mode = mode;
                    entries.push(smuggled);
                }
                if kind == EntryKind::Symlink {
                    match read_link_target(data, payload_at, &central) {
                        Some(target) => entry.link_target = Some(target),
                        None => findings.push(Finding::critical(
                            Check::LinkEscape,
                            &central.name,
                            "symlink target could not be decoded (encrypted, oversized or unsupported compression); treating as hostile",
                        )),
                    }
                }
            }
            Err(_) => findings.push(Finding::warning(
                Check::NameMismatch,
                &central.name,
                format!(
                    "local file header at offset {} is missing or corrupt",
                    central.local_offset
                ),
            )),
        }
        entries.push(entry);
        pos += central.header_len;
    }
    Ok((entries, findings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{ZipBuilder, ZipEntrySpec};

    #[test]
    fn plain_zip_files_and_dirs() {
        let zip = ZipBuilder::new()
            .dir("pkg/")
            .file("pkg/a.txt", b"alpha")
            .finish();
        let (entries, findings) = read_entries(&zip).unwrap();
        assert!(findings.is_empty());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, EntryKind::Dir);
        assert_eq!(entries[1].path, "pkg/a.txt");
        assert_eq!(entries[1].kind, EntryKind::File);
        assert_eq!(entries[1].mode, Some(0o644));
    }

    #[test]
    fn unix_mode_bits_are_extracted_from_external_attributes() {
        let zip = ZipBuilder::new()
            .file_mode("bin/su-like", 0o4755, b"x")
            .finish();
        let (entries, _) = read_entries(&zip).unwrap();
        assert_eq!(entries[0].mode, Some(0o4755));
    }

    #[test]
    fn dos_made_entries_have_no_mode_and_use_the_dir_bit() {
        let zip = ZipBuilder::new()
            .push_entry(ZipEntrySpec {
                name: "windows.txt",
                content: b"made on dos",
                unix_mode: None,
                local_name: None,
                deflate: false,
            })
            .push_entry(ZipEntrySpec {
                name: "folder/",
                content: b"",
                unix_mode: None,
                local_name: None,
                deflate: false,
            })
            .finish();
        let (entries, _) = read_entries(&zip).unwrap();
        assert_eq!(entries[0].kind, EntryKind::File);
        assert_eq!(entries[0].mode, None);
        assert_eq!(entries[1].kind, EntryKind::Dir);
    }

    #[test]
    fn stored_symlink_target_is_decoded() {
        let zip = ZipBuilder::new()
            .symlink("lib/link.so", "/usr/lib/real.so")
            .finish();
        let (entries, findings) = read_entries(&zip).unwrap();
        assert!(findings.is_empty());
        assert_eq!(entries[0].kind, EntryKind::Symlink);
        assert_eq!(entries[0].link_target.as_deref(), Some("/usr/lib/real.so"));
    }

    #[test]
    fn deflated_symlink_target_is_decoded() {
        let zip = ZipBuilder::new()
            .push_entry(ZipEntrySpec {
                name: "ln",
                content: b"../../outside",
                unix_mode: Some(0o120777),
                local_name: None,
                deflate: true,
            })
            .finish();
        let (entries, findings) = read_entries(&zip).unwrap();
        assert!(findings.is_empty());
        assert_eq!(entries[0].link_target.as_deref(), Some("../../outside"));
    }

    #[test]
    fn name_mismatch_surfaces_both_names() {
        // The lister shows "docs/readme.txt"; a stream extractor writes
        // "../../evil.sh". Both must reach the auditor.
        let zip = ZipBuilder::new()
            .push_entry(ZipEntrySpec {
                name: "docs/readme.txt",
                content: b"innocent",
                unix_mode: Some(0o100644),
                local_name: Some("../../evil.sh"),
                deflate: false,
            })
            .finish();
        let (entries, findings) = read_entries(&zip).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, Check::NameMismatch);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"docs/readme.txt"));
        assert!(paths.contains(&"../../evil.sh"));
    }

    #[test]
    fn eocd_is_found_despite_a_zip_comment_containing_the_signature() {
        let mut zip = ZipBuilder::new().file("a.txt", b"x").finish();
        // Append a comment that embeds the EOCD signature bytes.
        let comment = b"PK\x05\x06 fake signature in a comment";
        let len = zip.len();
        zip[len - 2..].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        zip.extend_from_slice(comment);
        let (entries, _) = read_entries(&zip).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "a.txt");
    }

    #[test]
    fn missing_eocd_is_a_typed_error() {
        assert_eq!(
            read_entries(b"this is not a zip file, just bytes").unwrap_err(),
            ZipError::NoEndOfCentralDirectory
        );
        assert_eq!(
            read_entries(&[]).unwrap_err(),
            ZipError::NoEndOfCentralDirectory
        );
    }

    #[test]
    fn truncated_central_directory_is_a_typed_error() {
        let zip = ZipBuilder::new().file("a.txt", b"payload").finish();
        // Slice off the front so the central directory offset dangles.
        let cut = &zip[zip.len() - 22..];
        assert!(read_entries(cut).is_err());
    }

    #[test]
    fn corrupt_local_header_downgrades_to_a_finding_not_an_error() {
        let mut zip = ZipBuilder::new().file("a.txt", b"payload").finish();
        zip[0] ^= 0xFF; // break the local header signature
        let (entries, findings) = read_entries(&zip).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, Check::NameMismatch);
        assert!(findings[0].detail.contains("missing or corrupt"));
    }

    #[test]
    fn zip64_end_of_central_directory_is_followed() {
        // Hand-build a minimal ZIP64 wrapper around one stored entry.
        let inner = ZipBuilder::new().file("big/one.bin", b"data").finish();
        let cd_offset = inner
            .windows(4)
            .position(|w| w == super::CENTRAL_SIG.to_le_bytes())
            .unwrap();
        let cd_size = inner.len() - cd_offset - 22;
        let mut zip = inner[..inner.len() - 22].to_vec();
        let eocd64_at = zip.len() as u64;
        // ZIP64 EOCD record.
        zip.extend_from_slice(&super::EOCD64_SIG.to_le_bytes());
        zip.extend_from_slice(&44u64.to_le_bytes()); // size of remainder
        zip.extend_from_slice(&[45, 0, 45, 0]); // made by / needed
        zip.extend_from_slice(&0u32.to_le_bytes()); // disk
        zip.extend_from_slice(&0u32.to_le_bytes()); // cd disk
        zip.extend_from_slice(&1u64.to_le_bytes()); // entries this disk
        zip.extend_from_slice(&1u64.to_le_bytes()); // entries total
        zip.extend_from_slice(&(cd_size as u64).to_le_bytes());
        zip.extend_from_slice(&(cd_offset as u64).to_le_bytes());
        // ZIP64 EOCD locator.
        zip.extend_from_slice(&super::EOCD64_LOCATOR_SIG.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&eocd64_at.to_le_bytes());
        zip.extend_from_slice(&1u32.to_le_bytes());
        // Classic EOCD with maxed-out fields.
        zip.extend_from_slice(&super::EOCD_SIG.to_le_bytes());
        zip.extend_from_slice(&[0, 0, 0, 0]);
        zip.extend_from_slice(&0xFFFFu16.to_le_bytes());
        zip.extend_from_slice(&0xFFFFu16.to_le_bytes());
        zip.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        zip.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        let (entries, _) = read_entries(&zip).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "big/one.bin");
    }
}
