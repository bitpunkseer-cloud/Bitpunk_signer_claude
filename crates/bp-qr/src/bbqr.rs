//! BBQr (Coinkite "Better Bitcoin QR"): split a file across QR codes with an
//! 8-character header `B$` + encoding + file type + count + index (base 36).
//! Encodings: H = hex, 2 = Base32, Z = raw deflate (2^10 window) + Base32.
//! Splitting follows the reference `split_qrs` exactly; `Joiner` collects
//! scanned parts in any order and decodes the file. Allocation-free.

use crate::deflate;
use crate::qr::{capacity, Ecc, Mode};

pub const HEADER_LEN: usize = 8;
pub const MAX_PARTS: usize = 1295;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BufferTooSmall,
    CannotFit,
    TooManyParts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    Psbt,
    Transaction,
    Json,
    Cbor,
    Unicode,
    Binary,
}

impl FileType {
    pub const fn code(self) -> u8 {
        match self {
            FileType::Psbt => b'P',
            FileType::Transaction => b'T',
            FileType::Json => b'J',
            FileType::Cbor => b'C',
            FileType::Unicode => b'U',
            FileType::Binary => b'B',
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Hex,
    Base32,
    /// Compressed; falls back to Base32 when compression does not help.
    Zlib,
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 Base32 without padding; returns the character count.
pub fn base32(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let need = (data.len() * 8).div_ceil(5);
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut n = 0;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[n] = B32[((acc >> bits) & 31) as usize];
            n += 1;
        }
    }
    if bits > 0 {
        out[n] = B32[((acc << (5 - bits)) & 31) as usize];
        n += 1;
    }
    Ok(n)
}

fn hex_upper(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < data.len() * 2 {
        return Err(Error::BufferTooSmall);
    }
    const H: &[u8; 16] = b"0123456789ABCDEF";
    for (i, &b) in data.iter().enumerate() {
        out[2 * i] = H[(b >> 4) as usize];
        out[2 * i + 1] = H[(b & 15) as usize];
    }
    Ok(data.len() * 2)
}

fn base36(n: usize) -> [u8; 2] {
    let d = |x: usize| {
        if x < 10 {
            b'0' + x as u8
        } else {
            b'A' + (x - 10) as u8
        }
    };
    [d(n / 36), d(n % 36)]
}

/// (count, chars per part) at a QR version, as reference `num_qr_needed`.
fn num_qr_needed(ver: u8, len: usize, split_mod: usize) -> (usize, usize) {
    let cap = capacity(ver, Ecc::Low, Mode::Alphanumeric) - HEADER_LEN;
    let cap2 = cap - cap % split_mod;
    let need = len.div_ceil(cap2.max(1));
    if need <= 1 {
        return (1, len);
    }
    let actual = (need - 1) * cap2 + cap;
    (if actual >= len { need } else { need + 1 }, cap2)
}

/// Encoded payload ready to be cut into parts.
pub struct Bbqr<'a> {
    chars: &'a [u8],
    encoding: u8,
    file_type: u8,
    version: u8,
    count: usize,
    per_part: usize,
}

impl<'a> Bbqr<'a> {
    /// Encode `raw`, then pick the QR version in `min_ver..=max_ver` with the
    /// fewest parts (lowest version on ties). `work` receives compressed
    /// bytes, `chars` the encoded characters.
    pub fn new(
        raw: &[u8],
        file_type: FileType,
        encoding: Encoding,
        min_ver: u8,
        max_ver: u8,
        work: &mut [u8],
        chars: &'a mut [u8],
    ) -> Result<Self, Error> {
        let (code, n, split_mod) = match encoding {
            Encoding::Hex => (b'H', hex_upper(raw, chars)?, 2),
            Encoding::Base32 => (b'2', base32(raw, chars)?, 8),
            Encoding::Zlib => {
                let clen = deflate::compress(raw, work).map_err(|_| Error::BufferTooSmall)?;
                if clen >= raw.len() {
                    (b'2', base32(raw, chars)?, 8)
                } else {
                    (b'Z', base32(&work[..clen], chars)?, 8)
                }
            }
        };
        let min_ver = min_ver.min(max_ver).max(1);
        let mut best: Option<(u8, usize, usize)> = None;
        for ver in min_ver..=max_ver.min(40) {
            let (count, per) = num_qr_needed(ver, n, split_mod);
            if !(1..=MAX_PARTS).contains(&count) {
                continue;
            }
            if best.is_none_or(|(_, c, _)| count < c) {
                best = Some((ver, count, per));
            }
        }
        let (version, count, per_part) = best.ok_or(Error::CannotFit)?;
        Ok(Self {
            chars: &chars[..n],
            encoding: code,
            file_type: file_type.code(),
            version,
            count,
            per_part,
        })
    }

    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn count(&self) -> usize {
        self.count
    }
    /// 'H', '2' or 'Z' (Zlib may fall back to '2').
    pub fn encoding(&self) -> u8 {
        self.encoding
    }

    /// Write part `index` (0-based) into `out`; returns its length.
    pub fn part(&self, index: usize, out: &mut [u8]) -> Result<usize, Error> {
        let start = index * self.per_part;
        let end = (start + self.per_part).min(self.chars.len());
        let body = &self.chars[start.min(end)..end];
        let total = HEADER_LEN + body.len();
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        out[0] = b'B';
        out[1] = b'$';
        out[2] = self.encoding;
        out[3] = self.file_type;
        out[4..6].copy_from_slice(&base36(self.count));
        out[6..8].copy_from_slice(&base36(index));
        out[8..total].copy_from_slice(body);
        Ok(total)
    }
}

// ---------- joining scanned parts ----------

/// Parts a joiner can hold (the format allows up to 1295).
pub const MAX_JOIN_PARTS: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinError {
    /// Not a BBQr part (bad header).
    NotBbqr,
    /// The part belongs to a different file (encoding, type or count
    /// differ, or the same index arrived with other content).
    Mismatch,
    /// More parts than `MAX_JOIN_PARTS`, or the store is full.
    TooBig,
    /// The output buffer is too small.
    BufferTooSmall,
    /// Bad hex / Base32 characters or a corrupt compressed stream.
    Corrupt,
    /// `finish` before every part arrived.
    Incomplete,
}

/// Header of one part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub encoding: u8,
    pub file_type: u8,
    pub count: usize,
    pub index: usize,
}

fn from_base36(c: u8) -> Option<usize> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as usize),
        b'A'..=b'Z' => Some((c - b'A') as usize + 10),
        _ => None,
    }
}

/// Parse the 8-character header; `None` if `part` is not BBQr.
pub fn parse_header(part: &[u8]) -> Option<Header> {
    if part.len() < HEADER_LEN || &part[..2] != b"B$" {
        return None;
    }
    let encoding = part[2];
    if !matches!(encoding, b'H' | b'2' | b'Z') || !part[3].is_ascii_uppercase() {
        return None;
    }
    let count = from_base36(part[4])? * 36 + from_base36(part[5])?;
    let index = from_base36(part[6])? * 36 + from_base36(part[7])?;
    (count >= 1 && index < count).then_some(Header {
        encoding,
        file_type: part[3],
        count,
        index,
    })
}

/// Collects BBQr parts in any order (repeats are ignored) and decodes the
/// file once all have arrived. Part bodies are kept in `store`.
pub struct Joiner<'a> {
    store: &'a mut [u8],
    used: usize,
    /// (offset, length + 1) per index; 0 = not received
    slots: [(u32, u32); MAX_JOIN_PARTS],
    header: Option<Header>,
    received: usize,
}

impl<'a> Joiner<'a> {
    pub fn new(store: &'a mut [u8]) -> Self {
        Self {
            store,
            used: 0,
            slots: [(0, 0); MAX_JOIN_PARTS],
            header: None,
            received: 0,
        }
    }

    pub fn reset(&mut self) {
        self.store[..self.used].fill(0);
        self.used = 0;
        self.slots = [(0, 0); MAX_JOIN_PARTS];
        self.header = None;
        self.received = 0;
    }

    /// Wipe and give the storage back.
    pub fn into_store(mut self) -> &'a mut [u8] {
        self.store[..self.used].fill(0);
        self.used = 0;
        core::mem::take(&mut self.store)
    }

    /// (parts received, parts in the file); (0, 0) before the first part.
    pub fn progress(&self) -> (usize, usize) {
        (self.received, self.header.map_or(0, |h| h.count))
    }

    pub fn has_part(&self, index: usize) -> bool {
        self.slots.get(index).is_some_and(|s| s.1 != 0)
    }

    pub fn header(&self) -> Option<Header> {
        self.header
    }

    pub fn is_complete(&self) -> bool {
        self.header.is_some_and(|h| self.received == h.count)
    }

    /// Add one scanned part; returns true when the file is complete.
    pub fn add(&mut self, part: &[u8]) -> Result<bool, JoinError> {
        let h = parse_header(part).ok_or(JoinError::NotBbqr)?;
        if h.count > MAX_JOIN_PARTS {
            return Err(JoinError::TooBig);
        }
        match self.header {
            None => self.header = Some(h),
            Some(cur) => {
                if (cur.encoding, cur.file_type, cur.count) != (h.encoding, h.file_type, h.count) {
                    return Err(JoinError::Mismatch);
                }
            }
        }
        let body = &part[HEADER_LEN..];
        let (off, len1) = self.slots[h.index];
        if len1 != 0 {
            let old = &self.store[off as usize..off as usize + len1 as usize - 1];
            return if old == body {
                Ok(self.is_complete())
            } else {
                Err(JoinError::Mismatch)
            };
        }
        let end = self.used + body.len();
        if end > self.store.len() {
            return Err(JoinError::TooBig);
        }
        self.store[self.used..end].copy_from_slice(body);
        self.slots[h.index] = (self.used as u32, body.len() as u32 + 1);
        self.used = end;
        self.received += 1;
        Ok(self.is_complete())
    }

    fn body(&self, i: usize) -> &[u8] {
        let (off, len1) = self.slots[i];
        &self.store[off as usize..off as usize + len1 as usize - 1]
    }

    /// Decode the complete file into `out`; `work` holds the compressed
    /// bytes of Z-encoded files. Returns the file length.
    pub fn finish(&self, work: &mut [u8], out: &mut [u8]) -> Result<usize, JoinError> {
        let h = self.header.ok_or(JoinError::Incomplete)?;
        if !self.is_complete() {
            return Err(JoinError::Incomplete);
        }
        let chars = (0..h.count).flat_map(|i| self.body(i).iter().copied());
        match h.encoding {
            b'H' => decode_hex(chars, out),
            b'2' => decode_base32(chars, out),
            _ => {
                let n = decode_base32(chars, work)?;
                crate::inflate::inflate(&work[..n], out).map_err(|e| match e {
                    crate::inflate::Error::OutputFull => JoinError::BufferTooSmall,
                    _ => JoinError::Corrupt,
                })
            }
        }
    }
}

impl Drop for Joiner<'_> {
    fn drop(&mut self) {
        self.store[..self.used].fill(0);
    }
}

fn decode_hex(chars: impl Iterator<Item = u8>, out: &mut [u8]) -> Result<usize, JoinError> {
    let nib = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(JoinError::Corrupt),
    };
    let mut n = 0;
    let mut hi: Option<u8> = None;
    for c in chars {
        let v = nib(c)?;
        match hi.take() {
            None => hi = Some(v),
            Some(h) => {
                *out.get_mut(n).ok_or(JoinError::BufferTooSmall)? = h << 4 | v;
                n += 1;
            }
        }
    }
    if hi.is_some() {
        return Err(JoinError::Corrupt);
    }
    Ok(n)
}

fn decode_base32(chars: impl Iterator<Item = u8>, out: &mut [u8]) -> Result<usize, JoinError> {
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut n = 0;
    for c in chars {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(JoinError::Corrupt),
        };
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(n).ok_or(JoinError::BufferTooSmall)? = (acc >> bits) as u8;
            n += 1;
            acc &= (1 << bits) - 1;
        }
    }
    Ok(n)
}

/// Specter "pM/N" animated text: `p1of3 <chunk>`; one part is plain text.
pub mod specter {
    /// Number of parts for `len` characters with `chunk` characters each.
    pub fn count(len: usize, chunk: usize) -> usize {
        len.div_ceil(chunk.max(1)).max(1)
    }

    /// Write part `index` (0-based); returns its length.
    pub fn part(text: &[u8], chunk: usize, index: usize, out: &mut [u8]) -> Option<usize> {
        let n = count(text.len(), chunk);
        let start = index * chunk;
        let end = (start + chunk).min(text.len());
        let body = text.get(start..end)?;
        if n == 1 {
            out.get_mut(..body.len())?.copy_from_slice(body);
            return Some(body.len());
        }
        let mut w = 0;
        let mut put = |s: &[u8]| -> Option<()> {
            out.get_mut(w..w + s.len())?.copy_from_slice(s);
            w += s.len();
            Some(())
        };
        let mut num = [0u8; 10];
        put(b"p")?;
        put(fmt(index + 1, &mut num))?;
        put(b"of")?;
        put(fmt(n, &mut num))?;
        put(b" ")?;
        put(body)?;
        Some(w)
    }

    fn fmt(mut v: usize, buf: &mut [u8; 10]) -> &[u8] {
        let mut i = buf.len();
        loop {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        &buf[i..]
    }

    /// Parse `p<i>of<n> <body>` (1-based i); `None` if not a Specter part.
    pub fn parse(part: &[u8]) -> Option<(usize, usize, &[u8])> {
        let rest = part.strip_prefix(b"p")?;
        let num = |s: &[u8]| -> Option<(usize, usize)> {
            let digits = s.iter().take_while(|c| c.is_ascii_digit()).count();
            if digits == 0 || digits > 4 {
                return None;
            }
            let v = s[..digits]
                .iter()
                .fold(0usize, |a, &c| a * 10 + (c - b'0') as usize);
            Some((v, digits))
        };
        let (i, d1) = num(rest)?;
        let rest = rest[d1..].strip_prefix(b"of")?;
        let (n, d2) = num(rest)?;
        let body = rest[d2..].strip_prefix(b" ")?;
        (i >= 1 && i <= n).then_some((i, n, body))
    }

    /// Collects Specter parts in any order and joins them.
    pub struct Joiner<'a> {
        store: &'a mut [u8],
        used: usize,
        slots: [(u32, u32); super::MAX_JOIN_PARTS],
        count: usize,
        received: usize,
    }

    impl<'a> Joiner<'a> {
        pub fn new(store: &'a mut [u8]) -> Self {
            Self {
                store,
                used: 0,
                slots: [(0, 0); super::MAX_JOIN_PARTS],
                count: 0,
                received: 0,
            }
        }

        pub fn reset(&mut self) {
            self.store[..self.used].fill(0);
            self.used = 0;
            self.slots = [(0, 0); super::MAX_JOIN_PARTS];
            self.count = 0;
            self.received = 0;
        }

        /// Wipe and give the storage back.
        pub fn into_store(mut self) -> &'a mut [u8] {
            self.store[..self.used].fill(0);
            self.used = 0;
            core::mem::take(&mut self.store)
        }

        pub fn progress(&self) -> (usize, usize) {
            (self.received, self.count)
        }

        pub fn has_part(&self, index: usize) -> bool {
            self.slots.get(index).is_some_and(|s| s.1 != 0)
        }

        pub fn is_complete(&self) -> bool {
            self.count > 0 && self.received == self.count
        }

        /// Add one scanned part; returns true when all parts are present.
        pub fn add(&mut self, part: &[u8]) -> Result<bool, super::JoinError> {
            use super::JoinError;
            let (i, n, body) = parse(part).ok_or(JoinError::NotBbqr)?;
            if n > super::MAX_JOIN_PARTS {
                return Err(JoinError::TooBig);
            }
            if self.count == 0 {
                self.count = n;
            } else if self.count != n {
                return Err(JoinError::Mismatch);
            }
            let k = i - 1;
            let (off, len1) = self.slots[k];
            if len1 != 0 {
                let old = &self.store[off as usize..off as usize + len1 as usize - 1];
                return if old == body {
                    Ok(self.is_complete())
                } else {
                    Err(JoinError::Mismatch)
                };
            }
            let end = self.used + body.len();
            if end > self.store.len() {
                return Err(JoinError::TooBig);
            }
            self.store[self.used..end].copy_from_slice(body);
            self.slots[k] = (self.used as u32, body.len() as u32 + 1);
            self.used = end;
            self.received += 1;
            Ok(self.is_complete())
        }

        /// The joined text.
        pub fn finish(&self, out: &mut [u8]) -> Result<usize, super::JoinError> {
            if !self.is_complete() {
                return Err(super::JoinError::Incomplete);
            }
            let mut n = 0;
            for k in 0..self.count {
                let (off, len1) = self.slots[k];
                let body = &self.store[off as usize..off as usize + len1 as usize - 1];
                out.get_mut(n..n + body.len())
                    .ok_or(super::JoinError::BufferTooSmall)?
                    .copy_from_slice(body);
                n += body.len();
            }
            Ok(n)
        }
    }

    impl Drop for Joiner<'_> {
        fn drop(&mut self) {
            self.store[..self.used].fill(0);
        }
    }
}
