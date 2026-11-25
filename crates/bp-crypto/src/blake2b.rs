//! BLAKE2b (RFC 7693), the hash inside Argon2 (M10). Output 1-64 bytes,
//! optional key up to 64 bytes.

use crate::secret::wipe;
use core::sync::atomic::{compiler_fence, Ordering};

pub const BLOCK_LEN: usize = 128;
pub const MAX_OUT: usize = 64;

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Overwrite u64 words with zeros in a way the optimizer must not elide.
pub fn wipe_u64(words: &mut [u64]) {
    for w in words.iter_mut() {
        // SAFETY: `w` is a valid, aligned, exclusive reference to a u64.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_LEN], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *w = u64::from_le_bytes(b);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
    wipe_u64(&mut m);
    wipe_u64(&mut v);
}

/// Incremental BLAKE2b.
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    t: u128,
    buf: [u8; BLOCK_LEN],
    len: usize,
    out_len: usize,
}

impl Blake2b {
    /// Unkeyed hash with `out_len` bytes of output (1-64).
    pub fn new(out_len: usize) -> Self {
        Self::with_key(out_len, &[])
    }

    /// Keyed hash (key up to 64 bytes).
    pub fn with_key(out_len: usize, key: &[u8]) -> Self {
        assert!((1..=MAX_OUT).contains(&out_len), "BLAKE2b output is 1-64 bytes");
        assert!(key.len() <= MAX_OUT, "BLAKE2b key is at most 64 bytes");
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ ((key.len() as u64) << 8) ^ out_len as u64;
        let mut s = Self {
            h,
            t: 0,
            buf: [0; BLOCK_LEN],
            len: 0,
            out_len,
        };
        if !key.is_empty() {
            let mut block = [0u8; BLOCK_LEN];
            block[..key.len()].copy_from_slice(key);
            s.update(&block);
            wipe(&mut block);
        }
        s
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // a full buffer is compressed only once more data follows: the
            // last block must be compressed with the final flag
            if self.len == BLOCK_LEN {
                self.t += BLOCK_LEN as u128;
                compress(&mut self.h, &self.buf, self.t, false);
                self.len = 0;
            }
            let take = (BLOCK_LEN - self.len).min(data.len());
            self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
            data = &data[take..];
        }
    }

    /// Write the digest into `out` (exactly the output length chosen).
    pub fn finalize(mut self, out: &mut [u8]) {
        assert_eq!(out.len(), self.out_len, "BLAKE2b output length");
        self.t += self.len as u128;
        for b in self.buf[self.len..].iter_mut() {
            *b = 0;
        }
        compress(&mut self.h, &self.buf, self.t, true);
        let mut full = [0u8; MAX_OUT];
        for (i, w) in self.h.iter().enumerate() {
            full[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out.copy_from_slice(&full[..self.out_len]);
        wipe(&mut full);
        wipe(&mut self.buf);
        wipe_u64(&mut self.h);
    }

    /// One-shot unkeyed hash; the output length is `out.len()`.
    pub fn digest(out: &mut [u8], data: &[u8]) {
        let mut h = Self::new(out.len());
        h.update(data);
        h.finalize(out);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use blake2::digest::{Update, VariableOutput};
    use std::vec::Vec;

    #[test]
    fn rfc7693_abc() {
        let mut out = [0u8; 64];
        Blake2b::digest(&mut out, b"abc");
        let want = [
            0xBA, 0x80, 0xA5, 0x3F, 0x98, 0x1C, 0x4D, 0x0D, 0x6A, 0x27, 0x97, 0xB6, 0x9F, 0x12, 0xF6, 0xE9,
            0x4C, 0x21, 0x2F, 0x14, 0x68, 0x5A, 0xC4, 0xB7, 0x4B, 0x12, 0xBB, 0x6F, 0xDB, 0xFF, 0xA2, 0xD1,
            0x7D, 0x87, 0xC5, 0x39, 0x2A, 0xAB, 0x79, 0x2D, 0xC2, 0x52, 0xD5, 0xDE, 0x45, 0x33, 0xCC, 0x95,
            0x18, 0xD3, 0x8A, 0xA8, 0xDB, 0xF1, 0x92, 0x5A, 0xB9, 0x23, 0x86, 0xED, 0xD4, 0x00, 0x99, 0x23,
        ];
        assert_eq!(out, want);
    }

    #[test]
    fn matches_the_reference_crate() {
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..400 {
            let len = (next() % 700) as usize;
            let data: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let out_len = 1 + (next() % 64) as usize;
            // fed in random pieces
            let mut h = Blake2b::new(out_len);
            let mut rest = &data[..];
            while !rest.is_empty() {
                let n = 1 + (next() as usize % rest.len().max(1)).min(rest.len() - 1);
                h.update(&rest[..n]);
                rest = &rest[n..];
            }
            let mut ours = std::vec![0u8; out_len];
            h.finalize(&mut ours);
            let mut r = blake2::Blake2bVar::new(out_len).unwrap();
            r.update(&data);
            let mut want = std::vec![0u8; out_len];
            r.finalize_variable(&mut want).unwrap();
            assert_eq!(ours, want, "len {len} out {out_len}");
        }
    }

    #[test]
    fn keyed_matches_the_reference_crate() {
        use blake2::digest::Mac;
        for klen in [1usize, 16, 32, 64] {
            let key: Vec<u8> = (0..klen as u8).collect();
            for len in [0usize, 1, 127, 128, 129, 300] {
                let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
                let mut h = Blake2b::with_key(64, &key);
                h.update(&data);
                let mut ours = [0u8; 64];
                h.finalize(&mut ours);
                let mut r = blake2::Blake2bMac512::new_from_slice(&key).unwrap();
                Mac::update(&mut r, &data);
                assert_eq!(
                    ours.as_slice(),
                    r.finalize().into_bytes().as_slice(),
                    "key {klen} len {len}"
                );
            }
        }
    }
}
