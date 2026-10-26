//! Minimal gzip / DEFLATE decoder (RFC 1952 / RFC 1951), used to unpack the
//! embedded proof-of-work seed text. Decoding follows the canonical-code
//! walk of zlib's `puff.c`: simple, dependency-free and fast enough for a
//! few megabytes. The gzip CRC is not checked; the stored size is.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateError {
    NotGzip,
    UnsupportedMethod(u8),
    UnexpectedEnd,
    InvalidBlockType,
    InvalidStoredLength,
    InvalidCode,
    InvalidDistance,
    InvalidLengths,
    SizeMismatch { expected: u32, actual: usize },
}

impl core::fmt::Display for InflateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InflateError::SizeMismatch { expected, actual } => {
                write!(f, "gzip size mismatch: header says {expected}, got {actual}")
            }
            other => write!(f, "inflate error: {other:?}"),
        }
    }
}

impl std::error::Error for InflateError {}

type Result<T> = core::result::Result<T, InflateError>;

const MAX_BITS: usize = 15;

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    cnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0, buf: 0, cnt: 0 }
    }

    fn bits(&mut self, n: u32) -> Result<u32> {
        while self.cnt < n {
            let b = *self.data.get(self.pos).ok_or(InflateError::UnexpectedEnd)?;
            self.pos += 1;
            self.buf |= (b as u32) << self.cnt;
            self.cnt += 8;
        }
        let v = self.buf & ((1u64 << n) - 1) as u32;
        self.buf >>= n;
        self.cnt -= n;
        Ok(v)
    }

    fn align_to_byte(&mut self) {
        self.buf = 0;
        self.cnt = 0;
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(InflateError::UnexpectedEnd)?;
        let s = self.data.get(self.pos..end).ok_or(InflateError::UnexpectedEnd)?;
        self.pos = end;
        Ok(s)
    }
}

/// Canonical Huffman code: number of codes per length and symbols ordered
/// by code.
struct Huffman {
    count: [u16; MAX_BITS + 1],
    symbol: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Huffman> {
        let mut count = [0u16; MAX_BITS + 1];
        for &l in lengths {
            count[l as usize] += 1;
        }
        count[0] = 0;
        // Over-subscribed code sets are invalid.
        let mut left: i32 = 1;
        for &c in &count[1..] {
            left = (left << 1) - c as i32;
            if left < 0 {
                return Err(InflateError::InvalidLengths);
            }
        }
        let mut offs = [0u16; MAX_BITS + 1];
        for len in 1..MAX_BITS {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbol[offs[l as usize] as usize] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Huffman { count, symbol })
    }

    fn decode(&self, r: &mut BitReader) -> Result<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=MAX_BITS {
            code |= r.bits(1)? as i32;
            let count = self.count[len] as i32;
            if code - count < first {
                return Ok(self.symbol[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(InflateError::InvalidCode)
    }
}

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CODE_LENGTH_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

fn codes(r: &mut BitReader, out: &mut Vec<u8>, lit: &Huffman, dist: &Huffman) -> Result<()> {
    loop {
        let sym = lit.decode(r)? as usize;
        if sym < 256 {
            out.push(sym as u8);
        } else if sym == 256 {
            return Ok(());
        } else {
            let li = sym - 257;
            if li >= LEN_BASE.len() {
                return Err(InflateError::InvalidCode);
            }
            let len = LEN_BASE[li] as usize + r.bits(LEN_EXTRA[li] as u32)? as usize;
            let di = dist.decode(r)? as usize;
            if di >= DIST_BASE.len() {
                return Err(InflateError::InvalidCode);
            }
            let d = DIST_BASE[di] as usize + r.bits(DIST_EXTRA[di] as u32)? as usize;
            if d > out.len() {
                return Err(InflateError::InvalidDistance);
            }
            let start = out.len() - d;
            for k in 0..len {
                let b = out[start + k];
                out.push(b);
            }
        }
    }
}

fn fixed_tables() -> (Huffman, Huffman) {
    let mut lengths = [0u8; 288];
    lengths[..144].fill(8);
    lengths[144..256].fill(9);
    lengths[256..280].fill(7);
    lengths[280..].fill(8);
    let lit = Huffman::new(&lengths).unwrap();
    let dist = Huffman::new(&[5u8; 30]).unwrap();
    (lit, dist)
}

fn dynamic_tables(r: &mut BitReader) -> Result<(Huffman, Huffman)> {
    let nlen = r.bits(5)? as usize + 257;
    let ndist = r.bits(5)? as usize + 1;
    let ncode = r.bits(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Err(InflateError::InvalidLengths);
    }
    let mut cl_lengths = [0u8; 19];
    for &i in CODE_LENGTH_ORDER.iter().take(ncode) {
        cl_lengths[i] = r.bits(3)? as u8;
    }
    let cl = Huffman::new(&cl_lengths)?;
    let mut lengths = vec![0u8; nlen + ndist];
    let mut i = 0;
    while i < nlen + ndist {
        let sym = cl.decode(r)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err(InflateError::InvalidLengths);
                }
                let prev = lengths[i - 1];
                let rep = 3 + r.bits(2)? as usize;
                if i + rep > lengths.len() {
                    return Err(InflateError::InvalidLengths);
                }
                lengths[i..i + rep].fill(prev);
                i += rep;
            }
            17 | 18 => {
                let rep = if sym == 17 { 3 + r.bits(3)? as usize } else { 11 + r.bits(7)? as usize };
                if i + rep > lengths.len() {
                    return Err(InflateError::InvalidLengths);
                }
                i += rep;
            }
            _ => return Err(InflateError::InvalidCode),
        }
    }
    if lengths[256] == 0 {
        return Err(InflateError::InvalidLengths);
    }
    let lit = Huffman::new(&lengths[..nlen])?;
    let dist = Huffman::new(&lengths[nlen..])?;
    Ok((lit, dist))
}

/// Decompresses a raw DEFLATE stream, appending to `out`. Returns the number
/// of input bytes consumed.
pub fn inflate(data: &[u8], out: &mut Vec<u8>) -> Result<usize> {
    let mut r = BitReader::new(data);
    loop {
        let last = r.bits(1)? == 1;
        match r.bits(2)? {
            0 => {
                r.align_to_byte();
                let hdr = r.take(4)?;
                let len = u16::from_le_bytes([hdr[0], hdr[1]]);
                let nlen = u16::from_le_bytes([hdr[2], hdr[3]]);
                if len != !nlen {
                    return Err(InflateError::InvalidStoredLength);
                }
                out.extend_from_slice(r.take(len as usize)?);
            }
            1 => {
                let (lit, dist) = fixed_tables();
                codes(&mut r, out, &lit, &dist)?;
            }
            2 => {
                let (lit, dist) = dynamic_tables(&mut r)?;
                codes(&mut r, out, &lit, &dist)?;
            }
            _ => return Err(InflateError::InvalidBlockType),
        }
        if last {
            return Ok(r.pos);
        }
    }
}

/// Decompresses a gzip member. The trailer's size field must match.
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b {
        return Err(InflateError::NotGzip);
    }
    if data[2] != 8 {
        return Err(InflateError::UnsupportedMethod(data[2]));
    }
    let flags = data[3];
    let mut pos = 10;
    let skip_zero_terminated = |pos: &mut usize| -> Result<()> {
        while *data.get(*pos).ok_or(InflateError::UnexpectedEnd)? != 0 {
            *pos += 1;
        }
        *pos += 1;
        Ok(())
    };
    if flags & 0x04 != 0 {
        let xlen = u16::from_le_bytes([
            *data.get(pos).ok_or(InflateError::UnexpectedEnd)?,
            *data.get(pos + 1).ok_or(InflateError::UnexpectedEnd)?,
        ]) as usize;
        pos += 2 + xlen;
    }
    if flags & 0x08 != 0 {
        skip_zero_terminated(&mut pos)?;
    }
    if flags & 0x10 != 0 {
        skip_zero_terminated(&mut pos)?;
    }
    if flags & 0x02 != 0 {
        pos += 2;
    }
    let body = data.get(pos..).ok_or(InflateError::UnexpectedEnd)?;
    let mut out = Vec::new();
    let used = inflate(body, &mut out)?;
    let trailer = body.get(used..used + 8).ok_or(InflateError::UnexpectedEnd)?;
    let isize = u32::from_le_bytes(trailer[4..8].try_into().unwrap());
    if isize as usize != out.len() & 0xffff_ffff {
        return Err(InflateError::SizeMismatch { expected: isize, actual: out.len() });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"hello hello hello hello, the quick brown fox jumps over the lazy dog. hello hello hello hello, the quick brown fox jumps over the lazy dog. hello hello hello hello, the quick brown fox jumps over the lazy dog. ";

    // gzip.compress(MSG, compresslevel=9, mtime=0): dynamic Huffman block.
    const DYN: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40,
        0x27, 0x75, 0x14, 0x4a, 0x32, 0x52, 0x15, 0x0a, 0x4b, 0x33, 0x93, 0xb3, 0x15, 0x92, 0x8a, 0xf2, 0xcb, 0xf3,
        0x14, 0xd2, 0xf2, 0x2b, 0x14, 0xb2, 0x4a, 0x73, 0x0b, 0x8a, 0x15, 0xf2, 0xcb, 0x52, 0x8b, 0xc0, 0xd2, 0x39,
        0x89, 0x55, 0x95, 0x0a, 0x29, 0xf9, 0xe9, 0x7a, 0x98, 0xfa, 0x07, 0xd0, 0x14, 0x00, 0xb6, 0x19, 0x84, 0x40,
        0xd2, 0x00, 0x00, 0x00,
    ];
    // gzip.compress(MSG, compresslevel=0, mtime=0): stored block.
    const STORED: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x03, 0x01, 0xd2, 0x00, 0x2d, 0xff, 0x68, 0x65, 0x6c,
        0x6c, 0x6f, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0x65, 0x6c,
        0x6c, 0x6f, 0x2c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
        0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
        0x2c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20,
        0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68,
        0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f,
        0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c,
        0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0xb6, 0x19, 0x84, 0x40, 0xd2, 0x00, 0x00, 0x00,
    ];
    // gzip.compress(b"abcabcabcabcabc", mtime=0): fixed Huffman block.
    const FIXED: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x4b, 0x4c, 0x4a, 0x4e, 0x44, 0x42, 0x00, 0xa3,
        0x8c, 0x27, 0xd3, 0x0f, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn decodes_all_block_types() {
        assert_eq!(MSG.len(), 210);
        assert_eq!(gunzip(DYN).unwrap(), MSG);
        assert_eq!(gunzip(STORED).unwrap(), MSG);
        assert_eq!(gunzip(FIXED).unwrap(), b"abcabcabcabcabc");
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(gunzip(&[0u8; 20]).unwrap_err(), InflateError::NotGzip);
        assert_eq!(gunzip(&DYN[..40]).unwrap_err(), InflateError::UnexpectedEnd);
        let mut bad = DYN.to_vec();
        let n = bad.len();
        bad[n - 1] ^= 1; // size trailer
        assert!(matches!(gunzip(&bad).unwrap_err(), InflateError::SizeMismatch { .. }));
        let mut bad = STORED.to_vec();
        bad[12] ^= 1; // LEN vs NLEN
        assert_eq!(gunzip(&bad).unwrap_err(), InflateError::InvalidStoredLength);
    }

    #[test]
    fn header_flags_are_skipped() {
        // Rebuild FIXED with FNAME and FEXTRA set.
        let mut g = vec![0x1f, 0x8b, 0x08, 0x04 | 0x08, 0, 0, 0, 0, 0, 3];
        g.extend_from_slice(&[2, 0, 0xaa, 0xbb]); // FEXTRA: xlen=2
        g.extend_from_slice(b"name.txt\0");
        g.extend_from_slice(&FIXED[10..]);
        assert_eq!(gunzip(&g).unwrap(), b"abcabcabcabcabc");
    }
}
