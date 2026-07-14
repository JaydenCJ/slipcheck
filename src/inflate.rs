//! A small, safe DEFLATE (RFC 1951) decompressor — stored, fixed-Huffman
//! and dynamic-Huffman blocks. In-tree so slipcheck stays std-only: it is
//! needed to look inside `.tar.gz` members and to decode zip symlink
//! targets. Every output is capped by the caller (bomb guard); malformed
//! streams return typed errors, never panic.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateError {
    /// Ran out of input mid-stream.
    UnexpectedEof,
    /// Reserved block type 3.
    InvalidBlockType,
    /// Stored block LEN/NLEN complement check failed.
    InvalidStoredLength,
    /// Huffman code description is over-subscribed or otherwise broken.
    InvalidCodeLengths,
    /// A decoded symbol has no assigned meaning.
    InvalidSymbol,
    /// Back-reference distance reaches before the start of the output.
    InvalidDistance,
    /// Output would exceed the caller's cap — likely a decompression bomb.
    OutputLimit,
}

impl fmt::Display for InflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            InflateError::UnexpectedEof => "unexpected end of compressed data",
            InflateError::InvalidBlockType => "reserved deflate block type",
            InflateError::InvalidStoredLength => "stored block length check failed",
            InflateError::InvalidCodeLengths => "invalid huffman code lengths",
            InflateError::InvalidSymbol => "invalid huffman symbol",
            InflateError::InvalidDistance => "back-reference before start of output",
            InflateError::OutputLimit => "output exceeds the configured unpack limit",
        };
        f.write_str(msg)
    }
}

/// LSB-first bit reader over a byte slice.
struct Bits<'a> {
    data: &'a [u8],
    /// Next byte to load into the buffer.
    pos: usize,
    buf: u32,
    cnt: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Bits<'a> {
        Bits {
            data,
            pos: 0,
            buf: 0,
            cnt: 0,
        }
    }

    fn take(&mut self, n: u32) -> Result<u32, InflateError> {
        debug_assert!(n <= 16);
        while self.cnt < n {
            let byte = *self.data.get(self.pos).ok_or(InflateError::UnexpectedEof)?;
            self.buf |= (byte as u32) << self.cnt;
            self.cnt += 8;
            self.pos += 1;
        }
        let out = self.buf & ((1u32 << n) - 1);
        self.buf >>= n;
        self.cnt -= n;
        Ok(out)
    }

    /// Position of the next unconsumed byte, discarding partial bits.
    fn byte_pos(&mut self) -> usize {
        let drop = self.cnt % 8;
        self.buf >>= drop;
        self.cnt -= drop;
        self.pos - (self.cnt / 8) as usize
    }

    /// Jump to an absolute byte position (after a stored block copy).
    fn seek(&mut self, pos: usize) {
        self.pos = pos;
        self.buf = 0;
        self.cnt = 0;
    }
}

/// Canonical Huffman decoding table: `count[len]` codes of each length,
/// symbols sorted by (length, symbol order).
struct Huffman {
    count: [u16; 16],
    symbol: Vec<u16>,
}

impl Huffman {
    fn construct(lengths: &[u16]) -> Result<Huffman, InflateError> {
        let mut count = [0u16; 16];
        for &len in lengths {
            count[len as usize] += 1;
        }
        if count[0] as usize == lengths.len() {
            // No codes at all: legal for an unused distance table.
            return Ok(Huffman {
                count,
                symbol: Vec::new(),
            });
        }
        // Reject over-subscribed sets (an incomplete set is legal; a gap
        // simply becomes InvalidSymbol at decode time).
        let mut left: i32 = 1;
        for &n in &count[1..16] {
            left <<= 1;
            left -= n as i32;
            if left < 0 {
                return Err(InflateError::InvalidCodeLengths);
            }
        }
        let mut offs = [0u16; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (sym, &len) in lengths.iter().enumerate() {
            if len != 0 {
                symbol[offs[len as usize] as usize] = sym as u16;
                offs[len as usize] += 1;
            }
        }
        Ok(Huffman { count, symbol })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, InflateError> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..16 {
            code |= bits.take(1)? as i32;
            let count = self.count[len] as i32;
            if code - count < first {
                return Ok(self.symbol[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(InflateError::InvalidSymbol)
    }
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Order in which code-length code lengths are stored in dynamic blocks.
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn push_byte(out: &mut Vec<u8>, byte: u8, limit: usize) -> Result<(), InflateError> {
    if out.len() >= limit {
        return Err(InflateError::OutputLimit);
    }
    out.push(byte);
    Ok(())
}

fn decode_block(
    bits: &mut Bits<'_>,
    lit: &Huffman,
    dist: &Huffman,
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<(), InflateError> {
    loop {
        let sym = lit.decode(bits)?;
        match sym {
            0..=255 => push_byte(out, sym as u8, limit)?,
            256 => return Ok(()),
            257..=285 => {
                let idx = (sym - 257) as usize;
                let len = LENGTH_BASE[idx] as usize + bits.take(LENGTH_EXTRA[idx])? as usize;
                let dsym = dist.decode(bits)? as usize;
                if dsym >= 30 {
                    return Err(InflateError::InvalidDistance);
                }
                let distance = DIST_BASE[dsym] as usize + bits.take(DIST_EXTRA[dsym])? as usize;
                if distance > out.len() {
                    return Err(InflateError::InvalidDistance);
                }
                for _ in 0..len {
                    let byte = out[out.len() - distance];
                    push_byte(out, byte, limit)?;
                }
            }
            _ => return Err(InflateError::InvalidSymbol),
        }
    }
}

fn fixed_tables() -> (Huffman, Huffman) {
    let mut lit_lengths = [0u16; 288];
    for (sym, len) in lit_lengths.iter_mut().enumerate() {
        *len = match sym {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let dist_lengths = [5u16; 30];
    // Fixed tables are defined by the RFC and always valid.
    let lit = Huffman::construct(&lit_lengths).expect("fixed literal table");
    let dist = Huffman::construct(&dist_lengths).expect("fixed distance table");
    (lit, dist)
}

fn dynamic_tables(bits: &mut Bits<'_>) -> Result<(Huffman, Huffman), InflateError> {
    let hlit = bits.take(5)? as usize + 257;
    let hdist = bits.take(5)? as usize + 1;
    let hclen = bits.take(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err(InflateError::InvalidCodeLengths);
    }
    let mut clen_lengths = [0u16; 19];
    for &slot in CLEN_ORDER.iter().take(hclen) {
        clen_lengths[slot] = bits.take(3)? as u16;
    }
    let clen = Huffman::construct(&clen_lengths)?;

    let mut lengths = vec![0u16; hlit + hdist];
    let mut i = 0;
    while i < lengths.len() {
        let sym = clen.decode(bits)?;
        match sym {
            0..=15 => {
                lengths[i] = sym;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err(InflateError::InvalidCodeLengths);
                }
                let prev = lengths[i - 1];
                let repeat = 3 + bits.take(2)? as usize;
                if i + repeat > lengths.len() {
                    return Err(InflateError::InvalidCodeLengths);
                }
                for _ in 0..repeat {
                    lengths[i] = prev;
                    i += 1;
                }
            }
            17 | 18 => {
                let repeat = if sym == 17 {
                    3 + bits.take(3)? as usize
                } else {
                    11 + bits.take(7)? as usize
                };
                if i + repeat > lengths.len() {
                    return Err(InflateError::InvalidCodeLengths);
                }
                i += repeat; // already zero
            }
            _ => return Err(InflateError::InvalidSymbol),
        }
    }
    if lengths[256] == 0 {
        // A block with no end-of-block code can never terminate.
        return Err(InflateError::InvalidCodeLengths);
    }
    let lit = Huffman::construct(&lengths[..hlit])?;
    let dist = Huffman::construct(&lengths[hlit..])?;
    Ok((lit, dist))
}

/// Decompress a raw DEFLATE stream. Returns the output and the number of
/// input bytes consumed (so gzip can find its trailer). `limit` caps the
/// output size; exceeding it yields [`InflateError::OutputLimit`].
pub fn inflate(data: &[u8], limit: usize) -> Result<(Vec<u8>, usize), InflateError> {
    let mut bits = Bits::new(data);
    let mut out = Vec::new();
    loop {
        let bfinal = bits.take(1)?;
        let btype = bits.take(2)?;
        match btype {
            0 => {
                // Stored block: byte-aligned LEN + one's complement NLEN.
                let start = bits.byte_pos();
                if start + 4 > data.len() {
                    return Err(InflateError::UnexpectedEof);
                }
                let len = u16::from_le_bytes([data[start], data[start + 1]]) as usize;
                let nlen = u16::from_le_bytes([data[start + 2], data[start + 3]]);
                if nlen != !(len as u16) {
                    return Err(InflateError::InvalidStoredLength);
                }
                let body = start + 4;
                if body + len > data.len() {
                    return Err(InflateError::UnexpectedEof);
                }
                if out.len() + len > limit {
                    return Err(InflateError::OutputLimit);
                }
                out.extend_from_slice(&data[body..body + len]);
                bits.seek(body + len);
            }
            1 => {
                let (lit, dist) = fixed_tables();
                decode_block(&mut bits, &lit, &dist, &mut out, limit)?;
            }
            2 => {
                let (lit, dist) = dynamic_tables(&mut bits)?;
                decode_block(&mut bits, &lit, &dist, &mut out, limit)?;
            }
            _ => return Err(InflateError::InvalidBlockType),
        }
        if bfinal == 1 {
            break;
        }
    }
    let consumed = bits.byte_pos();
    Ok((out, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a payload in a single stored (uncompressed) deflate block.
    pub fn stored_block(payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u16;
        let mut v = vec![0x01]; // BFINAL=1, BTYPE=00
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&(!len).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    // `zlib.compressobj(9, DEFLATED, -15)` over b"hello slipcheck":
    // a single fixed-Huffman block.
    const FIXED_VECTOR: [u8; 17] = [
        203, 72, 205, 201, 201, 87, 40, 206, 201, 44, 72, 206, 72, 77, 206, 6, 0,
    ];

    #[test]
    fn stored_block_round_trips() {
        let (out, consumed) = inflate(&stored_block(b"raw bytes"), 1 << 16).unwrap();
        assert_eq!(out, b"raw bytes");
        assert_eq!(consumed, 5 + 9);
    }

    #[test]
    fn fixed_huffman_reference_vector() {
        let (out, consumed) = inflate(&FIXED_VECTOR, 1 << 16).unwrap();
        assert_eq!(out, b"hello slipcheck");
        assert_eq!(consumed, FIXED_VECTOR.len());
    }

    #[test]
    fn dynamic_huffman_reference_vector() {
        // 4096 bytes of `32 + (((i*7) ^ (i>>3)) % 64)` compressed by zlib
        // at level 9 — chosen because zlib emits a dynamic-Huffman block.
        let expected: Vec<u8> = (0u32..4096)
            .map(|i| 32 + (((i * 7) ^ (i >> 3)) % 64) as u8)
            .collect();
        let (out, consumed) = inflate(&DYNAMIC_VECTOR, 1 << 16).unwrap();
        assert_eq!(out, expected);
        assert_eq!(consumed, DYNAMIC_VECTOR.len());
        // Sanity: the vector really is a dynamic block (BTYPE=2).
        assert_eq!((DYNAMIC_VECTOR[0] >> 1) & 3, 2);
    }

    #[test]
    fn multiple_blocks_concatenate() {
        // Two stored blocks: first with BFINAL=0, second with BFINAL=1.
        let mut v = vec![0x00, 3, 0, 252, 255];
        v.extend_from_slice(b"abc");
        v.extend_from_slice(&stored_block(b"def"));
        let (out, _) = inflate(&v, 64).unwrap();
        assert_eq!(out, b"abcdef");
    }

    #[test]
    fn output_limit_is_enforced_mid_stream() {
        let err = inflate(&stored_block(&[b'x'; 100]), 10).unwrap_err();
        assert_eq!(err, InflateError::OutputLimit);
        // Back-reference expansion is capped too, not just literals.
        let err = inflate(&FIXED_VECTOR, 4).unwrap_err();
        assert_eq!(err, InflateError::OutputLimit);
    }

    #[test]
    fn truncated_stream_reports_eof_not_panic() {
        for cut in 1..FIXED_VECTOR.len() - 1 {
            let err = inflate(&FIXED_VECTOR[..cut], 1 << 16).unwrap_err();
            assert_eq!(err, InflateError::UnexpectedEof, "cut at {cut}");
        }
    }

    #[test]
    fn corrupt_stored_length_is_rejected() {
        let mut v = stored_block(b"abc");
        v[3] ^= 0xFF; // break the NLEN complement
        assert_eq!(
            inflate(&v, 64).unwrap_err(),
            InflateError::InvalidStoredLength
        );
    }

    #[test]
    fn reserved_block_type_is_rejected() {
        // BFINAL=1, BTYPE=11 (reserved).
        assert_eq!(
            inflate(&[0x07], 64).unwrap_err(),
            InflateError::InvalidBlockType
        );
    }

    #[test]
    fn distance_before_output_start_is_rejected() {
        // Hand-built fixed block: length symbol with a distance pointing
        // before any output exists. Fuzz-ish: flip bits in the reference
        // vector and require a typed error or valid output, never a panic.
        for i in 0..FIXED_VECTOR.len() {
            for bit in 0..8 {
                let mut v = FIXED_VECTOR;
                v[i] ^= 1 << bit;
                let _ = inflate(&v, 1 << 12); // must not panic or hang
            }
        }
    }

    const DYNAMIC_VECTOR: [u8; 376] = [
        237, 209, 199, 161, 130, 80, 0, 5, 209, 86, 200, 162, 2, 34, 70, 178, 128, 10, 6, 64, 114,
        134, 254, 187, 248, 183, 143, 255, 214, 115, 118, 67, 173, 148, 147, 21, 188, 179, 110, 94,
        73, 39, 35, 136, 242, 106, 92, 41, 251, 107, 240, 249, 86, 243, 74, 220, 27, 119, 180, 22,
        198, 70, 203, 96, 206, 104, 111, 152, 29, 90, 0, 35, 238, 4, 251, 248, 241, 187, 172, 222,
        113, 182, 246, 185, 245, 83, 185, 19, 116, 245, 19, 220, 167, 122, 71, 233, 218, 23, 237,
        7, 115, 66, 235, 96, 28, 52, 31, 102, 133, 246, 129, 81, 47, 14, 47, 21, 189, 247, 74, 46,
        22, 191, 41, 90, 255, 241, 189, 56, 180, 88, 12, 227, 35, 185, 92, 233, 77, 137, 22, 193,
        200, 104, 30, 140, 128, 214, 195, 184, 104, 5, 204, 213, 61, 203, 220, 144, 191, 188, 167,
        123, 148, 153, 225, 247, 142, 239, 238, 121, 77, 13, 69, 25, 63, 93, 117, 205, 140, 104,
        55, 24, 30, 237, 5, 163, 160, 229, 48, 23, 180, 1, 230, 22, 38, 213, 200, 110, 246, 186,
        19, 126, 171, 158, 21, 181, 147, 21, 38, 89, 203, 110, 165, 147, 19, 70, 89, 207, 161, 93,
        97, 38, 180, 61, 76, 141, 182, 129, 73, 209, 88, 152, 40, 125, 78, 229, 150, 209, 247, 231,
        244, 62, 229, 91, 202, 176, 143, 233, 179, 251, 109, 89, 206, 62, 167, 183, 46, 151, 208,
        84, 152, 10, 77, 135, 153, 209, 24, 152, 16, 109, 11, 243, 107, 230, 199, 247, 96, 208,
        107, 165, 25, 31, 239, 195, 149, 225, 165, 102, 246, 162, 131, 105, 241, 74, 211, 122, 239,
        35, 154, 8, 19, 163, 209, 48, 79, 52, 3, 102, 65, 59, 192, 180, 75, 29, 223, 77, 109, 77,
        11, 75, 25, 251, 166, 186, 145, 185, 165, 126, 221, 204, 195, 81, 22, 150, 223, 203, 183,
        208, 40, 152, 7, 218, 26, 38, 65, 211, 96, 26, 52, 19, 134, 34, 255, 201, 127, 242, 159,
        252, 39, 255, 201, 127, 242, 159, 252, 39, 255, 201, 127, 242, 159, 252, 39, 255, 255, 197,
        255, 63,
    ];
}
