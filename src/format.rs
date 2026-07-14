//! Archive format detection by magic bytes — never by file extension,
//! because attackers pick the extension.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Tar,
    TarGz,
    Zip,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::Tar => "tar",
            Format::TarGz => "tar.gz",
            Format::Zip => "zip",
        }
    }

    /// Parse a `--format` flag value.
    pub fn from_flag(flag: &str) -> Option<Format> {
        match flag {
            "tar" => Some(Format::Tar),
            "tar.gz" | "tgz" => Some(Format::TarGz),
            "zip" => Some(Format::Zip),
            _ => None,
        }
    }
}

/// Detect the archive format from content.
pub fn detect(data: &[u8]) -> Option<Format> {
    if data.starts_with(&[0x1F, 0x8B]) {
        return Some(Format::TarGz);
    }
    if data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"PK\x06\x06")
    {
        return Some(Format::Zip);
    }
    if looks_like_tar(data) {
        return Some(Format::Tar);
    }
    None
}

/// Tar has no leading magic; ustar archives carry "ustar" at offset 257,
/// and pre-POSIX archives are recognized by a valid first-header checksum.
fn looks_like_tar(data: &[u8]) -> bool {
    if data.len() < 512 {
        return false;
    }
    if &data[257..262] == b"ustar" {
        return true;
    }
    // Reject the all-zero block: an empty file of NULs is not an archive.
    if data[..512].iter().all(|&b| b == 0) {
        return false;
    }
    first_header_checksum_ok(data)
}

fn first_header_checksum_ok(data: &[u8]) -> bool {
    let block = &data[..512];
    let stored: u64 = {
        let field = &block[148..156];
        let text: Vec<u8> = field
            .iter()
            .copied()
            .skip_while(|&b| b == b' ' || b == 0)
            .take_while(|&b| (b'0'..=b'7').contains(&b))
            .collect();
        let mut v = 0u64;
        for b in text {
            v = v * 8 + (b - b'0') as u64;
        }
        v
    };
    let sum: u64 = block
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                b' ' as u64
            } else {
                b as u64
            }
        })
        .sum();
    stored != 0 && stored == sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{gzip_wrap, TarBuilder, ZipBuilder};

    #[test]
    fn gzip_magic_wins() {
        let gz = gzip_wrap(b"anything");
        assert_eq!(detect(&gz), Some(Format::TarGz));
    }

    #[test]
    fn zip_magic_including_empty_archives() {
        let zip = ZipBuilder::new().file("a", b"x").finish();
        assert_eq!(detect(&zip), Some(Format::Zip));
        let empty = ZipBuilder::new().finish();
        assert_eq!(detect(&empty), Some(Format::Zip));
    }

    #[test]
    fn ustar_magic_detects_tar() {
        let tar = TarBuilder::new().file("a.txt", b"x").finish();
        assert_eq!(detect(&tar), Some(Format::Tar));
    }

    #[test]
    fn pre_posix_tar_detected_by_checksum() {
        let mut tar = TarBuilder::new().file("a.txt", b"x").finish();
        // Wipe the ustar magic and re-checksum, simulating a v7 archive.
        for byte in &mut tar[257..265] {
            *byte = 0;
        }
        tar[148..156].copy_from_slice(b"        ");
        let sum: u64 = tar[..512].iter().map(|&b| b as u64).sum();
        tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert_eq!(detect(&tar), Some(Format::Tar));
    }

    #[test]
    fn junk_and_short_inputs_are_not_detected() {
        assert_eq!(detect(b"just some text"), None);
        assert_eq!(detect(&[]), None);
        assert_eq!(detect(&[0u8; 1024]), None);
        let mut noise = vec![0x42u8; 2048];
        noise[0] = 0x13;
        assert_eq!(detect(&noise), None);
    }

    #[test]
    fn format_flag_parsing() {
        assert_eq!(Format::from_flag("tar"), Some(Format::Tar));
        assert_eq!(Format::from_flag("tgz"), Some(Format::TarGz));
        assert_eq!(Format::from_flag("tar.gz"), Some(Format::TarGz));
        assert_eq!(Format::from_flag("zip"), Some(Format::Zip));
        assert_eq!(Format::from_flag("rar"), None);
    }
}
