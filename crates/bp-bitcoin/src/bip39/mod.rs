//! BIP-39 mnemonics (English wordlist).
//!
//! Words are stored as 11-bit indices. The mnemonic is wiped on drop and its
//! `Debug` output never shows words.

mod wordlist_en;

use bp_crypto::secret::{wipe, Secret};
use bp_crypto::{pbkdf2_hmac_sha512, Sha256};
use core::fmt;
use core::ops::Range;

pub use wordlist_en::WORDS;

pub const MAX_WORDS: usize = 24;
/// Longest English word is 8 letters; words are joined by single spaces.
pub const MAX_PHRASE_LEN: usize = MAX_WORDS * 9 - 1;
/// Words of 4+ letters are uniquely identified by their first four letters;
/// 3-letter words are the first match of their own prefix.
pub const UNIQUE_PREFIX_LEN: usize = 4;
const PBKDF2_ROUNDS: u32 = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Word count must be 12, 15, 18, 21 or 24.
    InvalidWordCount,
    /// Entropy must be 16, 20, 24, 28 or 32 bytes.
    InvalidEntropyLength,
    /// Word index out of range (must be < 2048).
    InvalidWordIndex,
    InvalidChecksum,
    /// Passphrases are limited to printable ASCII (NFKD is then the identity).
    NonAsciiPassphrase,
}

/// Look up a word's index.
pub fn word_index(word: &str) -> Option<u16> {
    WORDS.binary_search(&word).ok().map(|i| i as u16)
}

/// Range of indices whose words start with `prefix` (the list is sorted).
pub fn prefix_range(prefix: &str) -> Range<usize> {
    let start = WORDS.partition_point(|w| *w < prefix);
    let end = start
        + WORDS[start..]
            .iter()
            .take_while(|w| w.starts_with(prefix))
            .count();
    start..end
}

/// Number of checksum bits for a mnemonic of `n` words.
pub const fn checksum_bits(n: usize) -> usize {
    n / 3
}

fn valid_word_count(n: usize) -> bool {
    matches!(n, 12 | 15 | 18 | 21 | 24)
}

/// Pack 11-bit indices (plus optional extra bits) into a big-endian bit string.
fn pack_indices(indices: &[u16], extra: Option<(u16, usize)>, out: &mut [u8; 33]) {
    out.fill(0);
    let mut bit = 0usize;
    let mut put = |value: u16, width: usize| {
        for i in (0..width).rev() {
            if (value >> i) & 1 == 1 {
                out[bit / 8] |= 0x80 >> (bit % 8);
            }
            bit += 1;
        }
    };
    for &idx in indices {
        put(idx, 11);
    }
    if let Some((value, width)) = extra {
        put(value, width);
    }
}

pub struct Mnemonic {
    idx: [u16; MAX_WORDS],
    len: u8,
}

impl Mnemonic {
    /// Encode entropy (16/20/24/28/32 bytes) as a mnemonic.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, Error> {
        let ent_bits = entropy.len() * 8;
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(Error::InvalidEntropyLength);
        }
        let cs_bits = ent_bits / 32;
        let n = (ent_bits + cs_bits) / 11;
        let mut bits = [0u8; 33];
        bits[..entropy.len()].copy_from_slice(entropy);
        let hash = Sha256::digest(entropy);
        bits[entropy.len()] = hash[0];
        let mut m = Mnemonic {
            idx: [0; MAX_WORDS],
            len: n as u8,
        };
        for (i, slot) in m.idx.iter_mut().enumerate().take(n) {
            let mut v = 0u16;
            for b in i * 11..i * 11 + 11 {
                v = (v << 1) | ((bits[b / 8] >> (7 - b % 8)) & 1) as u16;
            }
            *slot = v;
        }
        wipe(&mut bits);
        Ok(m)
    }

    /// Build from word indices, verifying the checksum.
    pub fn from_indices(indices: &[u16]) -> Result<Self, Error> {
        let n = indices.len();
        if !valid_word_count(n) {
            return Err(Error::InvalidWordCount);
        }
        if indices.iter().any(|&i| i >= 2048) {
            return Err(Error::InvalidWordIndex);
        }
        let mut m = Mnemonic {
            idx: [0; MAX_WORDS],
            len: n as u8,
        };
        m.idx[..n].copy_from_slice(indices);
        let mut ent = [0u8; 32];
        let ok = m.checksum_ok(&mut ent);
        wipe(&mut ent);
        if ok {
            Ok(m)
        } else {
            Err(Error::InvalidChecksum)
        }
    }

    fn checksum_ok(&self, ent_out: &mut [u8; 32]) -> bool {
        let n = self.len();
        let cs_bits = checksum_bits(n);
        let ent_bytes = (n * 11 - cs_bits) / 8;
        let mut bits = [0u8; 33];
        pack_indices(self.indices(), None, &mut bits);
        ent_out[..ent_bytes].copy_from_slice(&bits[..ent_bytes]);
        let expected = Sha256::digest(&bits[..ent_bytes])[0] >> (8 - cs_bits);
        let got = bits[ent_bytes] >> (8 - cs_bits);
        wipe(&mut bits);
        expected == got
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn indices(&self) -> &[u16] {
        &self.idx[..self.len()]
    }

    pub fn word(&self, i: usize) -> &'static str {
        WORDS[self.idx[i] as usize]
    }

    /// Copy the entropy into `out`, returning its length in bytes.
    pub fn entropy(&self, out: &mut [u8; 32]) -> usize {
        let n = self.len();
        self.checksum_ok(out);
        (n * 11 - checksum_bits(n)) / 8
    }

    /// Write the space-separated phrase into `out`, returning its length.
    pub fn write_phrase(&self, out: &mut [u8; MAX_PHRASE_LEN]) -> usize {
        let mut p = 0;
        for i in 0..self.len() {
            if i > 0 {
                out[p] = b' ';
                p += 1;
            }
            let w = self.word(i).as_bytes();
            out[p..p + w.len()].copy_from_slice(w);
            p += w.len();
        }
        p
    }

    /// BIP-39 seed: PBKDF2-HMAC-SHA512(phrase, "mnemonic" || passphrase, 2048).
    pub fn to_seed(&self, passphrase: &str) -> Result<Secret<64>, Error> {
        if !passphrase.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(Error::NonAsciiPassphrase);
        }
        let mut phrase = [0u8; MAX_PHRASE_LEN];
        let len = self.write_phrase(&mut phrase);
        let mut seed = Secret::new([0u8; 64]);
        pbkdf2_hmac_sha512(
            &phrase[..len],
            &[b"mnemonic", passphrase.as_bytes()],
            PBKDF2_ROUNDS,
            seed.expose_mut(),
        );
        wipe(&mut phrase);
        Ok(seed)
    }
}

impl Clone for Mnemonic {
    fn clone(&self) -> Self {
        Mnemonic {
            idx: self.idx,
            len: self.len,
        }
    }
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        for v in self.idx.iter_mut() {
            // SAFETY: valid exclusive reference.
            unsafe { core::ptr::write_volatile(v, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mnemonic({} words, ***)", self.len)
    }
}

/// Compute the final word for `first` (11, 14, 17, 20 or 23 words) when the
/// last word's non-checksum bits are `free_bits` (its top `11 - n/3` bits).
pub fn final_word(first: &[u16], free_bits: u16) -> Result<u16, Error> {
    let n = first.len() + 1;
    if !valid_word_count(n) {
        return Err(Error::InvalidWordCount);
    }
    if first.iter().any(|&i| i >= 2048) {
        return Err(Error::InvalidWordIndex);
    }
    let cs_bits = checksum_bits(n);
    let free_width = 11 - cs_bits;
    let free = free_bits & ((1 << free_width) - 1);
    let ent_bytes = (n * 11 - cs_bits) / 8;
    let mut bits = [0u8; 33];
    pack_indices(first, Some((free, free_width)), &mut bits);
    let cs = (Sha256::digest(&bits[..ent_bytes])[0] >> (8 - cs_bits)) as u16;
    wipe(&mut bits);
    Ok((free << cs_bits) | cs)
}

/// Number of free (non-checksum) bits in the last word of an `n`-word mnemonic.
pub const fn final_word_free_bits(n: usize) -> usize {
    11 - checksum_bits(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_are_unique_at_four_letters() {
        for w in WORDS.iter() {
            if w.len() >= UNIQUE_PREFIX_LEN {
                let p = &w[..UNIQUE_PREFIX_LEN];
                assert_eq!(prefix_range(p).len(), 1, "prefix {p} of {w}");
            } else {
                // 3-letter words (e.g. "act") prefix longer words; the exact
                // match always sorts first, so it is the default candidate.
                assert_eq!(WORDS[prefix_range(w).start], *w);
            }
        }
    }

    #[test]
    fn prefix_range_basic() {
        let r = prefix_range("aba");
        assert_eq!(&WORDS[r], &["abandon"]);
        assert_eq!(prefix_range("").len(), 2048);
        assert_eq!(prefix_range("zzz").len(), 0);
        assert!(prefix_range("ab").len() > 1);
    }

    #[test]
    fn debug_hides_words() {
        extern crate std;
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(std::format!("{m:?}"), "Mnemonic(12 words, ***)");
    }
}
