//! A metadata-only tar reader: v7, ustar, GNU (long names/links, base-256
//! sizes) and PAX (`path`, `linkpath`, `size` records). Payloads are
//! skipped, never buffered — slipcheck only needs names, kinds, modes and
//! link targets. Header checksums are verified so corrupt input fails
//! loudly instead of yielding garbage entries.

use std::fmt;

use crate::entry::{Entry, EntryKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TarError {
    /// A header or a payload runs past the end of the input.
    Truncated { offset: usize },
    /// Header checksum mismatch: not a tar archive, or a corrupt one.
    BadChecksum { offset: usize },
    /// A numeric or PAX field could not be parsed.
    BadField { offset: usize, field: &'static str },
}

impl fmt::Display for TarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TarError::Truncated { offset } => {
                write!(f, "tar archive truncated at offset {offset}")
            }
            TarError::BadChecksum { offset } => {
                write!(f, "tar header checksum mismatch at offset {offset}")
            }
            TarError::BadField { offset, field } => {
                write!(f, "unparseable tar {field} field at offset {offset}")
            }
        }
    }
}

/// Parse a tar numeric field: octal with NUL/space padding, or GNU
/// base-256 (high bit of the first byte set) for sizes beyond 8 GiB.
fn parse_numeric(field: &[u8], offset: usize, name: &'static str) -> Result<u64, TarError> {
    if field.first().is_some_and(|&b| b & 0x80 != 0) {
        let mut value: u64 = (field[0] & 0x7F) as u64;
        for &byte in &field[1..] {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(byte as u64))
                .ok_or(TarError::BadField {
                    offset,
                    field: name,
                })?;
        }
        return Ok(value);
    }
    let text: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ' || b == 0)
        .take_while(|&b| b != b' ' && b != 0)
        .collect();
    if text.is_empty() {
        return Ok(0);
    }
    let mut value: u64 = 0;
    for byte in text {
        if !(b'0'..=b'7').contains(&byte) {
            return Err(TarError::BadField {
                offset,
                field: name,
            });
        }
        value = value
            .checked_mul(8)
            .and_then(|v| v.checked_add((byte - b'0') as u64))
            .ok_or(TarError::BadField {
                offset,
                field: name,
            })?;
    }
    Ok(value)
}

/// NUL-terminated string field, lossily decoded.
fn parse_str(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Verify the header checksum; both the unsigned (POSIX) and the signed
/// (historic Sun tar) sums are accepted, matching GNU tar's behavior.
fn checksum_ok(block: &[u8], offset: usize) -> Result<(), TarError> {
    let stored = parse_numeric(&block[148..156], offset, "checksum")?;
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &byte) in block.iter().enumerate() {
        let value = if (148..156).contains(&i) { b' ' } else { byte };
        unsigned += value as u64;
        signed += value as i8 as i64;
    }
    if stored == unsigned || stored as i64 == signed {
        Ok(())
    } else {
        Err(TarError::BadChecksum { offset })
    }
}

/// Parse PAX extended-header records: `"<len> <key>=<value>\n"` repeated,
/// where `<len>` counts the whole record including itself.
fn parse_pax(data: &[u8], offset: usize) -> Result<Vec<(String, String)>, TarError> {
    let bad = |field| TarError::BadField { offset, field };
    let mut records = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        // Tolerate NUL padding after the last record.
        if data[pos] == 0 {
            break;
        }
        let space = data[pos..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or(bad("pax record length"))?;
        let len: usize = std::str::from_utf8(&data[pos..pos + space])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(bad("pax record length"))?;
        if len < space + 2 || pos + len > data.len() {
            return Err(bad("pax record length"));
        }
        let body = &data[pos + space + 1..pos + len];
        let body = body
            .strip_suffix(b"\n")
            .ok_or(bad("pax record terminator"))?;
        let eq = body
            .iter()
            .position(|&b| b == b'=')
            .ok_or(bad("pax record"))?;
        records.push((
            String::from_utf8_lossy(&body[..eq]).into_owned(),
            String::from_utf8_lossy(&body[eq + 1..]).into_owned(),
        ));
        pos += len;
    }
    Ok(records)
}

fn kind_for(typeflag: u8, name: &str) -> EntryKind {
    match typeflag {
        b'0' | 0 | b'7' => {
            // Pre-ustar archives mark directories with a trailing slash.
            if name.ends_with('/') {
                EntryKind::Dir
            } else {
                EntryKind::File
            }
        }
        b'1' => EntryKind::Hardlink,
        b'2' => EntryKind::Symlink,
        b'3' => EntryKind::CharDevice,
        b'4' => EntryKind::BlockDevice,
        b'5' => EntryKind::Dir,
        b'6' => EntryKind::Fifo,
        other => EntryKind::Other(other as char),
    }
}

/// Read all entries from a tar archive held in memory.
pub fn read_entries(data: &[u8]) -> Result<Vec<Entry>, TarError> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    // GNU 'L'/'K' and PAX 'x' records override fields of the *next* entry.
    let mut long_name: Option<String> = None;
    let mut long_link: Option<String> = None;
    let mut pax_next: Vec<(String, String)> = Vec::new();

    while offset + 512 <= data.len() {
        let block = &data[offset..offset + 512];
        if block.iter().all(|&b| b == 0) {
            break; // end-of-archive marker
        }
        checksum_ok(block, offset)?;

        let mut size = parse_numeric(&block[124..136], offset, "size")?;
        let typeflag = block[156];
        let payload_start = offset + 512;

        // PAX may override the size used to locate the next header.
        if let Some(value) = pax_next.iter().rev().find(|(k, _)| k == "size") {
            if !matches!(typeflag, b'x' | b'g' | b'L' | b'K') {
                size = value.1.parse().map_err(|_| TarError::BadField {
                    offset,
                    field: "pax size",
                })?;
            }
        }
        let padded = size
            .checked_add(511)
            .map(|s| (s / 512) * 512)
            .ok_or(TarError::BadField {
                offset,
                field: "size",
            })? as usize;
        if payload_start + padded > data.len() {
            return Err(TarError::Truncated { offset });
        }
        let payload_end = (payload_start + size as usize).min(data.len());
        let payload = &data[payload_start.min(data.len())..payload_end];

        match typeflag {
            b'L' => {
                long_name = Some(parse_str(payload));
            }
            b'K' => {
                long_link = Some(parse_str(payload));
            }
            b'x' | b'g' => {
                // Global ('g') records are treated like per-entry ones;
                // real-world archives use them for the same keys.
                pax_next.extend(parse_pax(payload, offset)?);
            }
            _ => {
                let mut name = parse_str(&block[..100]);
                // ustar prefix field (POSIX magic only; GNU reuses the
                // space for other fields).
                if &block[257..263] == b"ustar\0" {
                    let prefix = parse_str(&block[345..500]);
                    if !prefix.is_empty() {
                        name = format!("{prefix}/{name}");
                    }
                }
                if let Some(long) = long_name.take() {
                    name = long;
                }
                let mut link = parse_str(&block[157..257]);
                if let Some(long) = long_link.take() {
                    link = long;
                }
                for (key, value) in pax_next.drain(..) {
                    match key.as_str() {
                        "path" => name = value,
                        "linkpath" => link = value,
                        _ => {}
                    }
                }
                let kind = kind_for(typeflag, &name);
                let mode = parse_numeric(&block[100..108], offset, "mode")? as u32 & 0o7777;
                let mut entry = Entry::new(name, kind).with_mode(mode);
                entry.size = size;
                if !link.is_empty() || matches!(kind, EntryKind::Symlink | EntryKind::Hardlink) {
                    entry.link_target = Some(link);
                }
                entries.push(entry);
            }
        }
        offset = payload_start + padded;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{tar_header, TarBuilder};

    #[test]
    fn plain_ustar_files_and_dirs() {
        let tar = TarBuilder::new()
            .dir("pkg/")
            .file("pkg/README.md", b"hello")
            .file_mode("pkg/bin/tool", 0o755, b"#!/bin/sh\n")
            .finish();
        let entries = read_entries(&tar).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].kind, EntryKind::Dir);
        assert_eq!(entries[1].path, "pkg/README.md");
        assert_eq!(entries[1].size, 5);
        assert_eq!(entries[2].mode, Some(0o755));
    }

    #[test]
    fn symlink_and_hardlink_targets_are_captured() {
        let tar = TarBuilder::new()
            .symlink("pkg/link", "../outside")
            .hardlink("pkg/hl", "pkg/README.md")
            .finish();
        let entries = read_entries(&tar).unwrap();
        assert_eq!(entries[0].kind, EntryKind::Symlink);
        assert_eq!(entries[0].link_target.as_deref(), Some("../outside"));
        assert_eq!(entries[1].kind, EntryKind::Hardlink);
        assert_eq!(entries[1].link_target.as_deref(), Some("pkg/README.md"));
    }

    #[test]
    fn setuid_mode_bits_survive_parsing() {
        let tar = TarBuilder::new()
            .file_mode("bin/su-like", 0o4755, b"x")
            .finish();
        let entries = read_entries(&tar).unwrap();
        assert_eq!(entries[0].mode, Some(0o4755));
    }

    #[test]
    fn gnu_long_name_record_overrides_the_header_name() {
        let long = format!("very/{}/file.txt", "deep/".repeat(30));
        assert!(long.len() > 100);
        let tar = TarBuilder::new().gnu_long_name(&long, b"content").finish();
        let entries = read_entries(&tar).unwrap();
        assert_eq!(entries.len(), 1, "the 'L' record itself must not surface");
        assert_eq!(entries[0].path, long);
    }

    #[test]
    fn pax_path_and_linkpath_records_override_header_fields() {
        let tar = TarBuilder::new()
            .pax(&[("path", "renamed/by/pax.txt")], "short-name", b"data")
            .finish();
        let entries = read_entries(&tar).unwrap();
        assert_eq!(entries.len(), 1, "the 'x' record itself must not surface");
        assert_eq!(entries[0].path, "renamed/by/pax.txt");
    }

    #[test]
    fn pax_hostile_path_override_is_visible_to_the_auditor() {
        // The header name is innocent; the PAX record smuggles the escape.
        let tar = TarBuilder::new()
            .pax(
                &[("path", "../../etc/cron.d/evil")],
                "innocent.txt",
                b"payload",
            )
            .finish();
        let entries = read_entries(&tar).unwrap();
        assert_eq!(entries[0].path, "../../etc/cron.d/evil");
    }

    #[test]
    fn ustar_prefix_field_is_joined() {
        let mut block = tar_header("tail.txt", b'0', 0o644, 0, "");
        // Re-checksum after planting a prefix.
        block[345..345 + 4].copy_from_slice(b"deep");
        block[148..156].copy_from_slice(b"        ");
        let sum: u64 = block.iter().map(|&b| b as u64).sum();
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut tar = block.to_vec();
        tar.extend_from_slice(&[0u8; 1024]);
        let entries = read_entries(&tar).unwrap();
        assert_eq!(entries[0].path, "deep/tail.txt");
    }

    #[test]
    fn base256_size_field_is_decoded() {
        // 8 GiB + 2 bytes cannot be expressed in 11 octal digits.
        let big = 8u64 * 1024 * 1024 * 1024 + 2;
        let mut block = tar_header("huge.bin", b'0', 0o644, 0, "");
        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[4..12].copy_from_slice(&big.to_be_bytes());
        block[124..136].copy_from_slice(&field);
        block[148..156].copy_from_slice(b"        ");
        let sum: u64 = block.iter().map(|&b| b as u64).sum();
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        // No payload follows: the archive must be reported truncated,
        // proving the parser believed the 8 GiB size.
        let err = read_entries(&block).unwrap_err();
        assert_eq!(err, TarError::Truncated { offset: 0 });
    }

    #[test]
    fn trailing_slash_marks_directories_in_v7_archives() {
        let tar = TarBuilder::new()
            .raw("olddir/", b'0', 0o755, "", &[])
            .finish();
        let entries = read_entries(&tar).unwrap();
        assert_eq!(entries[0].kind, EntryKind::Dir);
    }

    #[test]
    fn devices_and_fifos_map_to_their_kinds() {
        let tar = TarBuilder::new()
            .raw("dev/null", b'3', 0o666, "", &[])
            .raw("dev/sda", b'4', 0o660, "", &[])
            .raw("run/pipe", b'6', 0o644, "", &[])
            .finish();
        let kinds: Vec<EntryKind> = read_entries(&tar)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                EntryKind::CharDevice,
                EntryKind::BlockDevice,
                EntryKind::Fifo
            ]
        );
    }

    #[test]
    fn corrupt_checksum_is_rejected_with_its_offset() {
        let mut tar = TarBuilder::new()
            .file("ok.txt", b"fine")
            .file("bad.txt", b"broken")
            .finish();
        tar[1024] ^= 0xFF; // corrupt the second header's name byte
        let err = read_entries(&tar).unwrap_err();
        assert_eq!(err, TarError::BadChecksum { offset: 1024 });
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let tar = TarBuilder::new().file("cut.txt", b"0123456789").finish();
        let err = read_entries(&tar[..600]).unwrap_err();
        assert_eq!(err, TarError::Truncated { offset: 0 });
    }

    #[test]
    fn empty_archive_yields_no_entries() {
        assert!(read_entries(&[0u8; 1024]).unwrap().is_empty());
        assert!(read_entries(&[]).unwrap().is_empty());
    }
}
