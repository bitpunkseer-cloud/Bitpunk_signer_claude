//! QR symbol decoding from a module matrix (ISO/IEC 18004): format and
//! version information (BCH, nearest valid codeword), data mask removal,
//! codeword extraction, block de-interleaving, Reed–Solomon correction
//! and segment parsing. Retries the transposed matrix for mirrored codes.
//! Allocation-free.

use crate::qr::{
    char_count_bits, mask_bit, num_raw_data_modules, Builder, Ecc, Mode, ALNUM, ECC_CODEWORDS_PER_BLOCK,
    MAX_CODEWORDS, MAX_SIZE, MODULE_BYTES, NUM_ECC_BLOCKS,
};
use crate::rs;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Matrix size is not 21..177 in steps of 4.
    BadSize,
    /// Format information unreadable.
    Format,
    /// Version information unreadable or inconsistent with the size.
    Version,
    /// A block has more errors than can be corrected.
    TooManyErrors,
    /// Segment data is malformed (bad length, value or mode).
    Malformed,
    /// Kanji or another mode Bitpunk does not use.
    UnsupportedMode,
    /// Output buffer too small.
    BufferTooSmall,
}

/// Square grid of modules; true = dark.
#[derive(Clone)]
pub struct BitMatrix {
    size: usize,
    bits: [u8; MODULE_BYTES],
}

impl BitMatrix {
    pub fn new(size: usize) -> Option<Self> {
        if !(21..=MAX_SIZE).contains(&size) || !(size - 17).is_multiple_of(4) {
            return None;
        }
        Some(Self {
            size,
            bits: [0; MODULE_BYTES],
        })
    }

    pub fn from_qr(q: &crate::QrCode) -> Self {
        let mut m = Self::new(q.size()).expect("valid symbol size");
        for y in 0..q.size() {
            for x in 0..q.size() {
                m.set(x, y, q.get(x, y));
            }
        }
        m
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn get(&self, x: usize, y: usize) -> bool {
        let i = y * self.size + x;
        self.bits[i / 8] >> (i % 8) & 1 == 1
    }

    pub fn set(&mut self, x: usize, y: usize, dark: bool) {
        let i = y * self.size + x;
        if dark {
            self.bits[i / 8] |= 1 << (i % 8);
        } else {
            self.bits[i / 8] &= !(1 << (i % 8));
        }
    }

    pub fn flip(&mut self, x: usize, y: usize) {
        let v = self.get(x, y);
        self.set(x, y, !v);
    }

    fn transpose(&mut self) {
        for y in 0..self.size {
            for x in y + 1..self.size {
                let (a, b) = (self.get(x, y), self.get(y, x));
                self.set(x, y, b);
                self.set(y, x, a);
            }
        }
    }
}

/// What was decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub len: usize,
    pub version: u8,
    pub ecc: Ecc,
    pub mask: u8,
    /// Codewords fixed by error correction.
    pub corrected: usize,
    /// The symbol was mirrored (read from the transposed matrix).
    pub mirrored: bool,
}

/// Decode `m` into `out` (the raw segment bytes: digits and alphanumeric
/// characters as ASCII, byte segments as-is).
pub fn decode(m: &BitMatrix, out: &mut [u8]) -> Result<Decoded, Error> {
    match decode_once(m, out) {
        Ok(d) => Ok(d),
        Err(Error::BufferTooSmall) => Err(Error::BufferTooSmall),
        Err(first) => {
            let mut t = m.clone();
            t.transpose();
            match decode_once(&t, out) {
                Ok(d) => Ok(Decoded { mirrored: true, ..d }),
                Err(_) => Err(first),
            }
        }
    }
}

// ---------- format and version information ----------

fn format_codeword(ecc: Ecc, mask: u8) -> u32 {
    let data = (ecc.format_bits() << 3) | mask as u32;
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | rem) ^ 0x5412
}

const ECCS: [Ecc; 4] = [Ecc::Low, Ecc::Medium, Ecc::Quartile, Ecc::High];

/// Both copies of the 15 format bits (bit 0 first), as the encoder lays
/// them out.
fn read_format(m: &BitMatrix) -> (u32, u32) {
    let s = m.size;
    let b = |x: usize, y: usize| m.get(x, y) as u32;
    let mut a = 0u32;
    for i in 0..6 {
        a |= b(8, i) << i;
    }
    a |= b(8, 7) << 6;
    a |= b(8, 8) << 7;
    a |= b(7, 8) << 8;
    for i in 9..15 {
        a |= b(14 - i, 8) << i;
    }
    let mut c = 0u32;
    for i in 0..8 {
        c |= b(s - 1 - i, 8) << i;
    }
    for i in 8..15 {
        c |= b(8, s - 15 + i) << i;
    }
    (a, c)
}

/// Nearest valid format codeword to either copy, within 3 bit errors.
fn decode_format(m: &BitMatrix) -> Option<(Ecc, u8)> {
    let (a, c) = read_format(m);
    let mut best = None;
    let mut best_dist = u32::MAX;
    for ecc in ECCS {
        for mask in 0..8u8 {
            let cw = format_codeword(ecc, mask);
            let d = (cw ^ a).count_ones().min((cw ^ c).count_ones());
            if d < best_dist {
                best_dist = d;
                best = Some((ecc, mask));
            }
        }
    }
    if best_dist <= 3 {
        best
    } else {
        None
    }
}

fn version_codeword(ver: u8) -> u32 {
    let mut rem = ver as u32;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    }
    ((ver as u32) << 12) | rem
}

/// Version from the size, checked against the version information
/// blocks (version 7 and up) within 3 bit errors.
fn decode_version(m: &BitMatrix) -> Option<u8> {
    let s = m.size;
    let from_size = ((s - 17) / 4) as u8;
    if from_size < 7 {
        return Some(from_size);
    }
    let (mut top_right, mut bottom_left) = (0u32, 0u32);
    for i in 0..18 {
        let a = s - 11 + i % 3;
        let b = i / 3;
        top_right |= (m.get(a, b) as u32) << i;
        bottom_left |= (m.get(b, a) as u32) << i;
    }
    let mut best = None;
    let mut best_dist = u32::MAX;
    for ver in 7..=40u8 {
        let cw = version_codeword(ver);
        let d = (cw ^ top_right).count_ones().min((cw ^ bottom_left).count_ones());
        if d < best_dist {
            best_dist = d;
            best = Some(ver);
        }
    }
    // the size is the stronger signal; the blocks must agree with it
    match best {
        Some(v) if best_dist <= 3 && v == from_size => Some(v),
        _ => None,
    }
}

/// ISO 18004 Table 9: misdecode-protection codewords for small symbols
/// (not used for correction).
fn misdecode_protection(ver: u8, ecc: Ecc) -> usize {
    match (ver, ecc) {
        (1, Ecc::Low) => 3,
        (1, Ecc::Medium) | (2, Ecc::Low) => 2,
        (1, _) | (3, Ecc::Low) => 1,
        _ => 0,
    }
}

// ---------- codewords ----------

fn decode_once(m: &BitMatrix, out: &mut [u8]) -> Result<Decoded, Error> {
    if BitMatrix::new(m.size).is_none() {
        return Err(Error::BadSize);
    }
    let (ecc, mask) = decode_format(m).ok_or(Error::Format)?;
    let ver = decode_version(m).ok_or(Error::Version)?;
    let func = Builder::function_map(ver);
    let size = m.size;

    // read codewords in the zigzag placement order, removing the mask
    let raw = num_raw_data_modules(ver) / 8;
    let mut cw = [0u8; MAX_CODEWORDS];
    let mut i = 0usize;
    let mut right = size as i32 - 1;
    while right >= 1 {
        if right == 6 {
            right = 5;
        }
        for vert in 0..size {
            for j in 0..2 {
                let x = (right - j) as usize;
                let upward = (right + 1) & 2 == 0;
                let y = if upward { size - 1 - vert } else { vert };
                if !func.is_function(x, y) && i < raw * 8 {
                    if m.get(x, y) ^ mask_bit(mask, x, y) {
                        cw[i >> 3] |= 0x80 >> (i & 7);
                    }
                    i += 1;
                }
            }
        }
        right -= 2;
    }

    // de-interleave and correct each block
    let e = ecc.ordinal();
    let nblocks = NUM_ECC_BLOCKS[e][ver as usize] as usize;
    let ecc_len = ECC_CODEWORDS_PER_BLOCK[e][ver as usize] as usize;
    let nshort = nblocks - raw % nblocks;
    let short_len = raw / nblocks;
    let max_errors = (ecc_len - misdecode_protection(ver, ecc)) / 2;
    let mut data = [0u8; MAX_CODEWORDS];
    let mut data_len = 0;
    let mut corrected = 0;
    let dlen_of = |b: usize| short_len - ecc_len + usize::from(b >= nshort);
    for b in 0..nblocks {
        let dlen = dlen_of(b);
        let mut block = [0u8; 255];
        // data byte k of block b sits at k * nblocks + b, except that the
        // last data byte of long blocks follows all short blocks' bytes
        for (k, byte) in block.iter_mut().enumerate().take(dlen) {
            let idx = if k < short_len - ecc_len {
                k * nblocks + b
            } else {
                (short_len - ecc_len) * nblocks + (b - nshort)
            };
            *byte = cw[idx];
        }
        let data_total = (short_len - ecc_len) * nblocks + (nblocks - nshort);
        for k in 0..ecc_len {
            block[dlen + k] = cw[data_total + k * nblocks + b];
        }
        corrected += rs::correct(&mut block[..dlen + ecc_len], ecc_len, max_errors)
            .map_err(|_| Error::TooManyErrors)?;
        data[data_len..data_len + dlen].copy_from_slice(&block[..dlen]);
        data_len += dlen;
    }

    let len = parse_segments(&data[..data_len], ver, out)?;
    Ok(Decoded {
        len,
        version: ver,
        ecc,
        mask,
        corrected,
        mirrored: false,
    })
}

// ---------- segments ----------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn left(&self) -> usize {
        self.data.len() * 8 - self.pos
    }
    fn read(&mut self, n: usize) -> Result<u32, Error> {
        if n > self.left() {
            return Err(Error::Malformed);
        }
        let mut v = 0u32;
        for _ in 0..n {
            let bit = (self.data[self.pos >> 3] >> (7 - (self.pos & 7))) & 1;
            v = (v << 1) | bit as u32;
            self.pos += 1;
        }
        Ok(v)
    }
}

fn parse_segments(data: &[u8], ver: u8, out: &mut [u8]) -> Result<usize, Error> {
    let mut r = Reader { data, pos: 0 };
    let mut n = 0usize;
    let mut put = |b: u8, n: &mut usize| -> Result<(), Error> {
        *out.get_mut(*n).ok_or(Error::BufferTooSmall)? = b;
        *n += 1;
        Ok(())
    };
    while r.left() >= 4 {
        match r.read(4)? {
            0 => break, // terminator
            1 => {
                let mut count = r.read(char_count_bits(Mode::Numeric, ver))? as usize;
                while count > 0 {
                    let digits = count.min(3);
                    let v = r.read(digits * 3 + 1)?;
                    if v >= [10, 100, 1000][digits - 1] {
                        return Err(Error::Malformed);
                    }
                    let mut buf = [0u8; 3];
                    let mut x = v;
                    for d in (0..digits).rev() {
                        buf[d] = b'0' + (x % 10) as u8;
                        x /= 10;
                    }
                    for &c in &buf[..digits] {
                        put(c, &mut n)?;
                    }
                    count -= digits;
                }
            }
            2 => {
                let mut count = r.read(char_count_bits(Mode::Alphanumeric, ver))? as usize;
                while count >= 2 {
                    let v = r.read(11)? as usize;
                    if v >= 45 * 45 {
                        return Err(Error::Malformed);
                    }
                    put(ALNUM[v / 45], &mut n)?;
                    put(ALNUM[v % 45], &mut n)?;
                    count -= 2;
                }
                if count == 1 {
                    let v = r.read(6)? as usize;
                    if v >= 45 {
                        return Err(Error::Malformed);
                    }
                    put(ALNUM[v], &mut n)?;
                }
            }
            4 => {
                let count = r.read(char_count_bits(Mode::Byte, ver))? as usize;
                for _ in 0..count {
                    put(r.read(8)? as u8, &mut n)?;
                }
            }
            7 => {
                // ECI designator: 1-3 bytes. The bytes that follow are kept
                // as-is (UTF-8, ECI 26, is what wallets use).
                let first = r.read(8)?;
                if first & 0x80 != 0 {
                    if first & 0x40 == 0 {
                        r.read(8)?;
                    } else if first & 0x20 == 0 {
                        r.read(16)?;
                    } else {
                        return Err(Error::Malformed);
                    }
                }
            }
            3 => {
                r.read(16)?; // structured append header: index, count, parity
            }
            5 => {} // FNC1, first position
            9 => {
                r.read(8)?; // FNC1, second position: application indicator
            }
            _ => return Err(Error::UnsupportedMode),
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::QrCode;

    #[test]
    fn format_codewords_are_distinct_enough() {
        // BCH(15,5) has minimum distance 7: 3 errors are correctable
        let mut all = [0u32; 32];
        let mut k = 0;
        for ecc in ECCS {
            for mask in 0..8 {
                all[k] = format_codeword(ecc, mask);
                k += 1;
            }
        }
        for i in 0..32 {
            for j in i + 1..32 {
                assert!((all[i] ^ all[j]).count_ones() >= 7);
            }
        }
    }

    #[test]
    fn version_codewords_are_distinct_enough() {
        for a in 7..=40u8 {
            for b in a + 1..=40 {
                assert!((version_codeword(a) ^ version_codeword(b)).count_ones() >= 8);
            }
        }
    }

    #[test]
    fn decodes_own_symbols() {
        let mut out = [0u8; 64];
        let q = QrCode::encode(b"HELLO WORLD", Ecc::Quartile, 1, 40, None).unwrap();
        let d = decode(&BitMatrix::from_qr(&q), &mut out).unwrap();
        assert_eq!(&out[..d.len], b"HELLO WORLD");
        assert_eq!(
            (d.version, d.ecc, d.mask, d.corrected),
            (1, Ecc::Quartile, q.mask(), 0)
        );
    }
}
