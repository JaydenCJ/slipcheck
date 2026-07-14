//! Minimal gzip (RFC 1952) container reader on top of [`crate::inflate`]:
//! header flags (FEXTRA/FNAME/FCOMMENT/FHCRC), CRC-32 and ISIZE trailer
//! verification, and multi-member streams (pigz and `cat a.gz b.gz`
//! both produce them).

use std::fmt;

use crate::inflate::{self, InflateError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GzipError {
    /// Missing the 0x1f 0x8b magic.
    BadMagic,
    /// Compression method other than deflate.
    UnsupportedMethod(u8),
    /// Header or trailer cut short; the field names what was expected.
    Truncated(&'static str),
    Inflate(InflateError),
    /// Trailer CRC-32 does not match the decompressed data.
    CrcMismatch,
    /// Trailer ISIZE does not match the decompressed length (mod 2^32).
    SizeMismatch,
}

impl fmt::Display for GzipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GzipError::BadMagic => write!(f, "not a gzip stream (bad magic)"),
            GzipError::UnsupportedMethod(m) => write!(f, "unsupported gzip method {m}"),
            GzipError::Truncated(what) => write!(f, "gzip stream truncated at {what}"),
            GzipError::Inflate(e) => write!(f, "deflate error: {e}"),
            GzipError::CrcMismatch => write!(f, "gzip CRC-32 mismatch (corrupt data)"),
            GzipError::SizeMismatch => write!(f, "gzip ISIZE mismatch (corrupt data)"),
        }
    }
}

const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;

const CRC_TABLE: [u32; 256] = build_crc_table();

const fn build_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

/// Standard CRC-32 (IEEE 802.3), as used by gzip and zip.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &byte in data {
        c = CRC_TABLE[((c ^ byte as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// Skip a NUL-terminated latin-1 field; returns the position after the NUL.
fn skip_cstr(data: &[u8], mut pos: usize, what: &'static str) -> Result<usize, GzipError> {
    loop {
        match data.get(pos) {
            None => return Err(GzipError::Truncated(what)),
            Some(0) => return Ok(pos + 1),
            Some(_) => pos += 1,
        }
    }
}

/// Parse one member starting at `pos`; returns (decompressed bytes,
/// position after the member's trailer). `budget` caps the output.
fn read_member(data: &[u8], pos: usize, budget: usize) -> Result<(Vec<u8>, usize), GzipError> {
    let header = data
        .get(pos..pos + 10)
        .ok_or(GzipError::Truncated("header"))?;
    if header[0] != 0x1F || header[1] != 0x8B {
        return Err(GzipError::BadMagic);
    }
    if header[2] != 8 {
        return Err(GzipError::UnsupportedMethod(header[2]));
    }
    let flags = header[3];
    let mut p = pos + 10;
    if flags & FEXTRA != 0 {
        let xlen = data
            .get(p..p + 2)
            .ok_or(GzipError::Truncated("FEXTRA length"))?;
        let xlen = u16::from_le_bytes([xlen[0], xlen[1]]) as usize;
        p += 2 + xlen;
        if p > data.len() {
            return Err(GzipError::Truncated("FEXTRA field"));
        }
    }
    if flags & FNAME != 0 {
        p = skip_cstr(data, p, "FNAME field")?;
    }
    if flags & FCOMMENT != 0 {
        p = skip_cstr(data, p, "FCOMMENT field")?;
    }
    if flags & FHCRC != 0 {
        p += 2;
        if p > data.len() {
            return Err(GzipError::Truncated("FHCRC field"));
        }
    }
    let (out, consumed) = inflate::inflate(&data[p..], budget).map_err(GzipError::Inflate)?;
    let trailer_at = p + consumed;
    let trailer = data
        .get(trailer_at..trailer_at + 8)
        .ok_or(GzipError::Truncated("CRC/ISIZE trailer"))?;
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    if crc32(&out) != crc {
        return Err(GzipError::CrcMismatch);
    }
    if out.len() as u32 != isize {
        return Err(GzipError::SizeMismatch);
    }
    Ok((out, trailer_at + 8))
}

/// Decompress an entire gzip file (all members). `limit` caps the total
/// decompressed size across members — the bomb guard.
pub fn decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, GzipError> {
    let (mut out, mut pos) = read_member(data, 0, limit)?;
    // Follow additional members; stop quietly at trailing non-gzip bytes
    // (some tools pad archives with zeros).
    while pos + 2 <= data.len() && data[pos] == 0x1F && data[pos + 1] == 0x8B {
        let budget = limit - out.len();
        let (more, next) = read_member(data, pos, budget)?;
        out.extend_from_slice(&more);
        pos = next;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::gzip_wrap;

    // `gzip.GzipFile(filename='notes.txt', mtime=0)` over
    // b"gzip payload for slipcheck tests\n" — exercises FNAME.
    const REFERENCE: [u8; 63] = [
        31, 139, 8, 8, 0, 0, 0, 0, 2, 255, 110, 111, 116, 101, 115, 46, 116, 120, 116, 0, 75, 175,
        202, 44, 80, 40, 72, 172, 204, 201, 79, 76, 81, 72, 203, 47, 82, 40, 206, 201, 44, 72, 206,
        72, 77, 206, 86, 40, 73, 45, 46, 41, 230, 2, 0, 79, 63, 210, 215, 33, 0, 0, 0,
    ];

    #[test]
    fn reference_gzip_with_fname_decompresses() {
        let out = decompress(&REFERENCE, 1 << 16).unwrap();
        assert_eq!(out, b"gzip payload for slipcheck tests\n");
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        // The canonical CRC-32 test vector.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn testkit_round_trip_covers_the_no_flags_path() {
        let gz = gzip_wrap(b"payload without optional header fields");
        assert_eq!(
            decompress(&gz, 1 << 16).unwrap(),
            b"payload without optional header fields"
        );
    }

    #[test]
    fn multi_member_streams_concatenate() {
        let mut gz = gzip_wrap(b"first ");
        gz.extend_from_slice(&gzip_wrap(b"second"));
        assert_eq!(decompress(&gz, 1 << 16).unwrap(), b"first second");
    }

    #[test]
    fn trailing_zero_padding_is_tolerated() {
        let mut gz = gzip_wrap(b"padded");
        gz.extend_from_slice(&[0u8; 512]);
        assert_eq!(decompress(&gz, 1 << 16).unwrap(), b"padded");
    }

    #[test]
    fn corrupt_crc_is_detected() {
        let mut gz = gzip_wrap(b"checksummed");
        let crc_at = gz.len() - 8;
        gz[crc_at] ^= 0xFF;
        assert_eq!(
            decompress(&gz, 1 << 16).unwrap_err(),
            GzipError::CrcMismatch
        );
    }

    #[test]
    fn bad_magic_and_bad_method_are_typed_errors() {
        assert_eq!(
            decompress(b"PK\x03\x04 not gzip", 64).unwrap_err(),
            GzipError::BadMagic
        );
        let mut gz = gzip_wrap(b"x");
        gz[2] = 7; // not deflate
        assert_eq!(
            decompress(&gz, 64).unwrap_err(),
            GzipError::UnsupportedMethod(7)
        );
    }

    #[test]
    fn output_limit_propagates_as_inflate_error() {
        let gz = gzip_wrap(&[b'a'; 1000]);
        assert_eq!(
            decompress(&gz, 100).unwrap_err(),
            GzipError::Inflate(InflateError::OutputLimit)
        );
    }

    #[test]
    fn truncation_anywhere_yields_an_error_never_a_panic() {
        let gz = gzip_wrap(b"truncate me at every byte");
        for cut in 0..gz.len() {
            assert!(decompress(&gz[..cut], 1 << 16).is_err(), "cut at {cut}");
        }
    }
}
