//! BBQr (Coinkite "Better Bitcoin QR"): split a file across QR codes with an
//! 8-character header `B$` + encoding + file type + count + index (base 36).
//! Encodings: H = hex, 2 = Base32, Z = raw deflate (2^10 window) + Base32.
//! Allocation-free; follows the reference `split_qrs` exactly.

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
}
