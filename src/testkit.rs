//! Test-only builders for tar, zip and gzip bytes. Everything is built
//! from the wire format up, so tests are deterministic and offline —
//! no system `tar`/`zip` binaries involved.

use crate::gzip::crc32;

/// Wrap a payload in a valid single-member gzip stream using stored
/// (uncompressed) deflate blocks.
pub fn gzip_wrap(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 0xFF];
    out.extend_from_slice(&deflate_stored(payload));
    out.extend_from_slice(&crc32(payload).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out
}

/// Encode a payload as stored deflate blocks (no compression).
pub fn deflate_stored(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunks = payload.chunks(0xFFFF).peekable();
    if payload.is_empty() {
        out.extend_from_slice(&[0x01, 0, 0, 0xFF, 0xFF]);
        return out;
    }
    while let Some(chunk) = chunks.next() {
        let bfinal = if chunks.peek().is_none() { 1u8 } else { 0u8 };
        out.push(bfinal);
        out.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(chunk.len() as u16)).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

// ---------------------------------------------------------------- tar ---

#[derive(Default)]
pub struct TarBuilder {
    data: Vec<u8>,
}

fn write_octal(field: &mut [u8], value: u64) {
    let s = format!("{:0width$o}\0", value, width = field.len() - 1);
    field.copy_from_slice(s.as_bytes());
}

/// Build one 512-byte ustar header block.
pub fn tar_header(name: &str, typeflag: u8, mode: u32, size: u64, link: &str) -> [u8; 512] {
    let mut block = [0u8; 512];
    block[..name.len().min(100)].copy_from_slice(&name.as_bytes()[..name.len().min(100)]);
    write_octal(&mut block[100..108], mode as u64);
    write_octal(&mut block[108..116], 0); // uid
    write_octal(&mut block[116..124], 0); // gid
    write_octal(&mut block[124..136], size);
    write_octal(&mut block[136..148], 0); // mtime
    block[156] = typeflag;
    block[157..157 + link.len().min(100)].copy_from_slice(&link.as_bytes()[..link.len().min(100)]);
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    // Checksum: computed with the checksum field itself as spaces.
    block[148..156].copy_from_slice(b"        ");
    let sum: u64 = block.iter().map(|&b| b as u64).sum();
    let chk = format!("{sum:06o}\0 ");
    block[148..156].copy_from_slice(chk.as_bytes());
    block
}

impl TarBuilder {
    pub fn new() -> TarBuilder {
        TarBuilder { data: Vec::new() }
    }

    pub fn raw(mut self, name: &str, typeflag: u8, mode: u32, link: &str, content: &[u8]) -> Self {
        self.data.extend_from_slice(&tar_header(
            name,
            typeflag,
            mode,
            content.len() as u64,
            link,
        ));
        self.data.extend_from_slice(content);
        let pad = (512 - content.len() % 512) % 512;
        self.data.extend_from_slice(&vec![0u8; pad]);
        self
    }

    pub fn file(self, name: &str, content: &[u8]) -> Self {
        self.raw(name, b'0', 0o644, "", content)
    }

    pub fn file_mode(self, name: &str, mode: u32, content: &[u8]) -> Self {
        self.raw(name, b'0', mode, "", content)
    }

    pub fn dir(self, name: &str) -> Self {
        self.raw(name, b'5', 0o755, "", &[])
    }

    pub fn symlink(self, name: &str, target: &str) -> Self {
        self.raw(name, b'2', 0o777, target, &[])
    }

    pub fn hardlink(self, name: &str, target: &str) -> Self {
        self.raw(name, b'1', 0o644, target, &[])
    }

    /// GNU long-name record ('L') followed by the real entry with a
    /// truncated header name.
    pub fn gnu_long_name(self, long: &str, content: &[u8]) -> Self {
        let mut with_nul = long.as_bytes().to_vec();
        with_nul.push(0);
        self.raw("././@LongLink", b'L', 0o644, "", &with_nul).raw(
            &long[..long.len().min(100)],
            b'0',
            0o644,
            "",
            content,
        )
    }

    /// PAX extended header ('x') applying to the next entry.
    pub fn pax(self, records: &[(&str, &str)], name: &str, content: &[u8]) -> Self {
        let mut body = Vec::new();
        for (key, value) in records {
            // len includes the length digits themselves, per POSIX.
            let payload_len = 1 + key.len() + 1 + value.len() + 1; // " k=v\n"
            let mut len = payload_len;
            loop {
                let digits = len.to_string().len();
                if digits + payload_len == len {
                    break;
                }
                len = digits + payload_len;
            }
            body.extend_from_slice(format!("{len} {key}={value}\n").as_bytes());
        }
        self.raw("pax-header", b'x', 0o644, "", &body)
            .raw(name, b'0', 0o644, "", content)
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.data.extend_from_slice(&[0u8; 1024]);
        self.data
    }
}

// ---------------------------------------------------------------- zip ---

#[derive(Default)]
pub struct ZipBuilder {
    data: Vec<u8>,
    central: Vec<u8>,
    count: u16,
}

pub struct ZipEntrySpec<'a> {
    pub name: &'a str,
    pub content: &'a [u8],
    /// Full unix st_mode (type bits + permissions), or None for a
    /// DOS-made entry that carries no unix mode.
    pub unix_mode: Option<u32>,
    /// Name to store in the local header when it should differ from the
    /// central directory (the smuggling case).
    pub local_name: Option<&'a str>,
    /// Compress with deflate (stored-block encoding) instead of method 0.
    pub deflate: bool,
}

impl ZipBuilder {
    pub fn new() -> ZipBuilder {
        ZipBuilder {
            data: Vec::new(),
            central: Vec::new(),
            count: 0,
        }
    }

    pub fn push_entry(mut self, spec: ZipEntrySpec<'_>) -> Self {
        let offset = self.data.len() as u32;
        let local_name = spec.local_name.unwrap_or(spec.name);
        let crc = crc32(spec.content);
        let (method, stored): (u16, Vec<u8>) = if spec.deflate {
            (8, deflate_stored(spec.content))
        } else {
            (0, spec.content.to_vec())
        };
        // Local file header.
        self.data.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        self.data.extend_from_slice(&20u16.to_le_bytes()); // version needed
        self.data.extend_from_slice(&0u16.to_le_bytes()); // flags
        self.data.extend_from_slice(&method.to_le_bytes());
        self.data.extend_from_slice(&[0u8; 4]); // time + date
        self.data.extend_from_slice(&crc.to_le_bytes());
        self.data
            .extend_from_slice(&(stored.len() as u32).to_le_bytes());
        self.data
            .extend_from_slice(&(spec.content.len() as u32).to_le_bytes());
        self.data
            .extend_from_slice(&(local_name.len() as u16).to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes()); // extra len
        self.data.extend_from_slice(local_name.as_bytes());
        self.data.extend_from_slice(&stored);

        // Central directory header.
        let (made_by, external): (u16, u32) = match spec.unix_mode {
            Some(mode) => ((3 << 8) | 20, mode << 16),
            None => {
                let dos_dir = if spec.name.ends_with('/') { 0x10 } else { 0 };
                (20, dos_dir)
            }
        };
        self.central
            .extend_from_slice(&0x0201_4B50u32.to_le_bytes());
        self.central.extend_from_slice(&made_by.to_le_bytes());
        self.central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        self.central.extend_from_slice(&0u16.to_le_bytes()); // flags
        self.central.extend_from_slice(&method.to_le_bytes());
        self.central.extend_from_slice(&[0u8; 4]); // time + date
        self.central.extend_from_slice(&crc.to_le_bytes());
        self.central
            .extend_from_slice(&(stored.len() as u32).to_le_bytes());
        self.central
            .extend_from_slice(&(spec.content.len() as u32).to_le_bytes());
        self.central
            .extend_from_slice(&(spec.name.len() as u16).to_le_bytes());
        self.central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        self.central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        self.central.extend_from_slice(&0u16.to_le_bytes()); // disk start
        self.central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        self.central.extend_from_slice(&external.to_le_bytes());
        self.central.extend_from_slice(&offset.to_le_bytes());
        self.central.extend_from_slice(spec.name.as_bytes());
        self.count += 1;
        self
    }

    pub fn file(self, name: &str, content: &[u8]) -> Self {
        self.push_entry(ZipEntrySpec {
            name,
            content,
            unix_mode: Some(0o100644),
            local_name: None,
            deflate: false,
        })
    }

    pub fn file_mode(self, name: &str, mode: u32, content: &[u8]) -> Self {
        self.push_entry(ZipEntrySpec {
            name,
            content,
            unix_mode: Some(0o100000 | mode),
            local_name: None,
            deflate: false,
        })
    }

    pub fn dir(self, name: &str) -> Self {
        self.push_entry(ZipEntrySpec {
            name,
            content: &[],
            unix_mode: Some(0o040755),
            local_name: None,
            deflate: false,
        })
    }

    pub fn symlink(self, name: &str, target: &str) -> Self {
        self.push_entry(ZipEntrySpec {
            name,
            content: target.as_bytes(),
            unix_mode: Some(0o120777),
            local_name: None,
            deflate: false,
        })
    }

    pub fn finish(mut self) -> Vec<u8> {
        let cd_offset = self.data.len() as u32;
        let cd_size = self.central.len() as u32;
        self.data.extend_from_slice(&self.central);
        // End of central directory.
        self.data.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes()); // disk number
        self.data.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        self.data.extend_from_slice(&self.count.to_le_bytes()); // entries this disk
        self.data.extend_from_slice(&self.count.to_le_bytes()); // entries total
        self.data.extend_from_slice(&cd_size.to_le_bytes());
        self.data.extend_from_slice(&cd_offset.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes()); // comment len
        self.data
    }
}
