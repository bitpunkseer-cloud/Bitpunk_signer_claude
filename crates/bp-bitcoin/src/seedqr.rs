//! SeedQR (SeedSigner specification): Standard = 4-digit word indices in
//! QR numeric mode; Compact = the entropy bytes (checksum bits dropped) in
//! QR byte mode.

use crate::bip39::{Error, Mnemonic, MAX_WORDS};

/// Longest Standard SeedQR payload: 24 words x 4 digits.
pub const MAX_DIGITS: usize = MAX_WORDS * 4;

/// Standard SeedQR digit stream ("0000...0003"). Returns its length.
pub fn standard_digits(m: &Mnemonic, out: &mut [u8; MAX_DIGITS]) -> usize {
    for (i, &idx) in m.indices().iter().enumerate() {
        let mut v = idx;
        for d in (0..4).rev() {
            out[i * 4 + d] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    m.len() * 4
}

/// Compact SeedQR bytes: the entropy (16 or 32 bytes). Returns its length.
pub fn compact_bytes(m: &Mnemonic, out: &mut [u8; 32]) -> usize {
    m.entropy(out)
}

/// Parse a Standard SeedQR digit stream (48 or 96 digits ... any valid
/// BIP-39 length x 4).
pub fn from_standard(digits: &[u8]) -> Result<Mnemonic, Error> {
    if !digits.len().is_multiple_of(4) || digits.len() > MAX_DIGITS || !digits.iter().all(u8::is_ascii_digit)
    {
        return Err(Error::InvalidWordCount);
    }
    let mut idx = [0u16; MAX_WORDS];
    let n = digits.len() / 4;
    for (i, chunk) in digits.chunks(4).enumerate() {
        idx[i] = chunk.iter().fold(0u16, |a, &c| a * 10 + (c - b'0') as u16);
    }
    let r = Mnemonic::from_indices(&idx[..n]);
    bp_crypto::secret::wipe_u16(&mut idx);
    r
}

/// Parse Compact SeedQR bytes (16 or 32 bytes of entropy).
pub fn from_compact(bytes: &[u8]) -> Result<Mnemonic, Error> {
    match bytes.len() {
        16 | 32 => Mnemonic::from_entropy(bytes),
        _ => Err(Error::InvalidEntropyLength),
    }
}
