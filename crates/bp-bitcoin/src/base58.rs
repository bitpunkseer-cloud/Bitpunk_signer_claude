//! Base58 and Base58Check (Bitcoin alphabet). Allocation-free.

use bp_crypto::hashes::sha256d;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Largest payload we encode: an 82-byte extended key + 4-byte checksum.
pub const MAX_DATA: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BufferTooSmall,
    InvalidCharacter,
    BadChecksum,
    TooLong,
}

/// Encode `data` into `out`; returns the number of characters written.
pub fn encode(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if data.len() > MAX_DATA {
        return Err(Error::TooLong);
    }
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // base-58 digits, little-endian; size bound: len * log(256)/log(58) + 1
    let mut digits = [0u8; MAX_DATA * 138 / 100 + 2];
    let mut len = 0;
    for &byte in &data[zeros..] {
        let mut carry = byte as u32;
        for d in digits[..len].iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits[len] = (carry % 58) as u8;
            len += 1;
            carry /= 58;
        }
    }
    let total = zeros + len;
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    out[..zeros].fill(b'1');
    for i in 0..len {
        out[zeros + i] = ALPHABET[digits[len - 1 - i] as usize];
    }
    Ok(total)
}

/// Base58Check: payload followed by the first 4 bytes of SHA256d(payload).
pub fn encode_check(payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if payload.len() + 4 > MAX_DATA {
        return Err(Error::TooLong);
    }
    let mut buf = [0u8; MAX_DATA];
    buf[..payload.len()].copy_from_slice(payload);
    let ck = sha256d(payload);
    buf[payload.len()..payload.len() + 4].copy_from_slice(&ck[..4]);
    let r = encode(&buf[..payload.len() + 4], out);
    bp_crypto::secret::wipe(&mut buf); // extended private keys pass through here
    r
}

/// Decode into `out`; returns the number of bytes written.
pub fn decode(s: &str, out: &mut [u8]) -> Result<usize, Error> {
    let s = s.as_bytes();
    let zeros = s.iter().take_while(|&&c| c == b'1').count();
    let mut bytes = [0u8; MAX_DATA];
    let mut len = 0;
    for &c in &s[zeros..] {
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or(Error::InvalidCharacter)? as u32;
        let mut carry = v;
        for b in bytes[..len].iter_mut() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            if len >= MAX_DATA {
                return Err(Error::TooLong);
            }
            bytes[len] = carry as u8;
            len += 1;
            carry >>= 8;
        }
    }
    let total = zeros + len;
    if total > out.len() {
        return Err(Error::BufferTooSmall);
    }
    out[..zeros].fill(0);
    for i in 0..len {
        out[zeros + i] = bytes[len - 1 - i];
    }
    Ok(total)
}

/// Decode Base58Check; returns the payload length (checksum removed).
pub fn decode_check(s: &str, out: &mut [u8]) -> Result<usize, Error> {
    let mut buf = [0u8; MAX_DATA];
    let n = decode(s, &mut buf)?;
    if n < 4 {
        return Err(Error::BadChecksum);
    }
    let ck = sha256d(&buf[..n - 4]);
    if ck[..4] != buf[n - 4..n] {
        return Err(Error::BadChecksum);
    }
    if out.len() < n - 4 {
        return Err(Error::BufferTooSmall);
    }
    out[..n - 4].copy_from_slice(&buf[..n - 4]);
    bp_crypto::secret::wipe(&mut buf);
    Ok(n - 4)
}
