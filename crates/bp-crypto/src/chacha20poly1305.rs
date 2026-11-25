//! ChaCha20-Poly1305 AEAD (RFC 8439), the vault cipher (M10). Plain
//! 32/64-bit arithmetic with no secret-dependent branches or table lookups,
//! so it runs in constant time on the device and in the simulator alike.
//! The tag is checked before anything is decrypted.

use crate::secret::wipe;
use core::sync::atomic::{compiler_fence, Ordering};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// The tag did not verify: the data was changed, or the key or nonce is
/// wrong. Nothing was decrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthError;

fn wipe_u32(words: &mut [u32]) {
    for w in words.iter_mut() {
        // SAFETY: `w` is a valid, aligned, exclusive reference to a u32.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline(always)]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// One ChaCha20 block (RFC 8439 2.3).
pub fn chacha20_block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN], out: &mut [u8; 64]) {
    let mut init = [0u32; 16];
    init[0] = 0x6170_7865;
    init[1] = 0x3320_646e;
    init[2] = 0x7962_2d32;
    init[3] = 0x6b20_6574;
    for i in 0..8 {
        init[4 + i] = le32(&key[i * 4..]);
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = le32(&nonce[i * 4..]);
    }
    let mut s = init;
    for _ in 0..10 {
        qr(&mut s, 0, 4, 8, 12);
        qr(&mut s, 1, 5, 9, 13);
        qr(&mut s, 2, 6, 10, 14);
        qr(&mut s, 3, 7, 11, 15);
        qr(&mut s, 0, 5, 10, 15);
        qr(&mut s, 1, 6, 11, 12);
        qr(&mut s, 2, 7, 8, 13);
        qr(&mut s, 3, 4, 9, 14);
    }
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    wipe_u32(&mut s);
    wipe_u32(&mut init);
}

/// XOR the ChaCha20 key stream from block `counter` onto `data` (RFC 8439 2.4).
pub fn chacha20_xor(key: &[u8; KEY_LEN], mut counter: u32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    let mut ks = [0u8; 64];
    for chunk in data.chunks_mut(64) {
        chacha20_block(key, counter, nonce, &mut ks);
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= k;
        }
        counter = counter.wrapping_add(1);
    }
    wipe(&mut ks);
}

/// Poly1305 one-time authenticator (RFC 8439 2.5), 26-bit limbs.
struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    buf: [u8; 16],
    len: usize,
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let r = [
            le32(&key[0..]) & 0x03ff_ffff,
            (le32(&key[3..]) >> 2) & 0x03ff_ff03,
            (le32(&key[6..]) >> 4) & 0x03ff_c0ff,
            (le32(&key[9..]) >> 6) & 0x03f0_3fff,
            (le32(&key[12..]) >> 8) & 0x000f_ffff,
        ];
        let s = [
            le32(&key[16..]),
            le32(&key[20..]),
            le32(&key[24..]),
            le32(&key[28..]),
        ];
        Self {
            r,
            s,
            h: [0; 5],
            buf: [0; 16],
            len: 0,
        }
    }

    fn block(&mut self, m: &[u8; 16], hibit: u32) {
        let [r0, r1, r2, r3, r4] = self.r.map(|v| v as u64);
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
        let mask = 0x03ff_ffffu32;
        let mut h0 = (self.h[0] + (le32(&m[0..]) & mask)) as u64;
        let mut h1 = (self.h[1] + ((le32(&m[3..]) >> 2) & mask)) as u64;
        let mut h2 = (self.h[2] + ((le32(&m[6..]) >> 4) & mask)) as u64;
        let mut h3 = (self.h[3] + ((le32(&m[9..]) >> 6) & mask)) as u64;
        let mut h4 = (self.h[4] + ((le32(&m[12..]) >> 8) | hibit)) as u64;
        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        let m64 = mask as u64;
        let mut c = d0 >> 26;
        h0 = d0 & m64;
        let d1 = d1 + c;
        c = d1 >> 26;
        h1 = d1 & m64;
        let d2 = d2 + c;
        c = d2 >> 26;
        h2 = d2 & m64;
        let d3 = d3 + c;
        c = d3 >> 26;
        h3 = d3 & m64;
        let d4 = d4 + c;
        c = d4 >> 26;
        h4 = d4 & m64;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= m64;
        h1 += c;
        self.h = [h0 as u32, h1 as u32, h2 as u32, h3 as u32, h4 as u32];
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.len > 0 {
            let take = (16 - self.len).min(data.len());
            self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
            data = &data[take..];
            if self.len == 16 {
                let b = self.buf;
                self.block(&b, 1 << 24);
                self.len = 0;
            }
        }
        while data.len() >= 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&data[..16]);
            self.block(&b, 1 << 24);
            data = &data[16..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; TAG_LEN] {
        if self.len > 0 {
            let mut b = [0u8; 16];
            b[..self.len].copy_from_slice(&self.buf[..self.len]);
            b[self.len] = 1;
            self.block(&b, 0);
        }
        let mask = 0x03ff_ffffu32;
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        // full carry
        let mut c = h1 >> 26;
        h1 &= mask;
        h2 += c;
        c = h2 >> 26;
        h2 &= mask;
        h3 += c;
        c = h3 >> 26;
        h3 &= mask;
        h4 += c;
        c = h4 >> 26;
        h4 &= mask;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= mask;
        h1 += c;
        // h - p, selected without branching
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= mask;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= mask;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= mask;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= mask;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
        let sel = (g4 >> 31).wrapping_sub(1); // all ones if h >= p
        h0 = (h0 & !sel) | (g0 & sel);
        h1 = (h1 & !sel) | (g1 & sel);
        h2 = (h2 & !sel) | (g2 & sel);
        h3 = (h3 & !sel) | (g3 & sel);
        h4 = (h4 & !sel) | (g4 & sel);
        // to 4 x 32 bits, then + s
        let w0 = h0 | (h1 << 26);
        let w1 = (h1 >> 6) | (h2 << 20);
        let w2 = (h2 >> 12) | (h3 << 14);
        let w3 = (h3 >> 18) | (h4 << 8);
        let mut f = w0 as u64 + self.s[0] as u64;
        let t0 = f as u32;
        f = w1 as u64 + self.s[1] as u64 + (f >> 32);
        let t1 = f as u32;
        f = w2 as u64 + self.s[2] as u64 + (f >> 32);
        let t2 = f as u32;
        f = w3 as u64 + self.s[3] as u64 + (f >> 32);
        let t3 = f as u32;
        let mut tag = [0u8; 16];
        for (i, t) in [t0, t1, t2, t3].iter().enumerate() {
            tag[i * 4..i * 4 + 4].copy_from_slice(&t.to_le_bytes());
        }
        wipe_u32(&mut self.r);
        wipe_u32(&mut self.s);
        wipe_u32(&mut self.h);
        wipe(&mut self.buf);
        tag
    }
}

/// Constant-time equality of two tags.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    // SAFETY: reading a valid local through a volatile pointer.
    let d = unsafe { core::ptr::read_volatile(&d) };
    d == 0
}

fn tag_of(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
    let mut otk = [0u8; 64];
    chacha20_block(key, 0, nonce, &mut otk);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&otk[..32]);
    let mut p = Poly1305::new(&pk);
    let zeros = [0u8; 16];
    p.update(aad);
    p.update(&zeros[..(16 - aad.len() % 16) % 16]);
    p.update(ct);
    p.update(&zeros[..(16 - ct.len() % 16) % 16]);
    p.update(&(aad.len() as u64).to_le_bytes());
    p.update(&(ct.len() as u64).to_le_bytes());
    wipe(&mut otk);
    wipe(&mut pk);
    p.finalize()
}

/// Encrypt `data` in place and return the tag (RFC 8439 2.8).
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
    chacha20_xor(key, 1, nonce, data);
    tag_of(key, nonce, aad, data)
}

/// Check the tag, then decrypt `data` in place. On a wrong tag nothing is
/// decrypted.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), AuthError> {
    let mut want = tag_of(key, nonce, aad, data);
    let ok = ct_eq(&want, tag);
    wipe(&mut want);
    if !ok {
        return Err(AuthError);
    }
    chacha20_xor(key, 1, nonce, data);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use std::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        let s: std::string::String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8439 2.3.2
    #[test]
    fn rfc8439_block() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut out = [0u8; 64];
        chacha20_block(&key, 1, &nonce, &mut out);
        let want = hex(
            "10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4 c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
             d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2 b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e",
        );
        assert_eq!(out.as_slice(), want.as_slice());
    }

    /// RFC 8439 2.5.2
    #[test]
    fn rfc8439_poly1305() {
        let key: [u8; 32] = hex(
            "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b",
        )
        .try_into()
        .unwrap();
        let mut p = Poly1305::new(&key);
        p.update(b"Cryptographic Forum Research Group");
        let want = hex("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9");
        assert_eq!(p.finalize().as_slice(), want.as_slice());
    }

    /// RFC 8439 2.8.2
    #[test]
    fn rfc8439_aead() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce = [0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
        let aad = hex("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut data = pt.to_vec();
        let tag = seal(&key, &nonce, &aad, &mut data);
        assert_eq!(
            tag.as_slice(),
            hex("1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91").as_slice()
        );
        assert_eq!(
            &data[..16],
            hex("d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2").as_slice()
        );
        open(&key, &nonce, &aad, &mut data, &tag).unwrap();
        assert_eq!(data.as_slice(), pt.as_slice());
    }

    #[test]
    fn tampering_is_refused_and_nothing_is_decrypted() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let mut data = b"seed entropy goes here".to_vec();
        let tag = seal(&key, &nonce, b"header", &mut data);
        let ct = data.clone();
        for i in 0..data.len() {
            let mut d = ct.clone();
            d[i] ^= 1;
            assert_eq!(open(&key, &nonce, b"header", &mut d, &tag), Err(AuthError));
            let mut want = ct.clone();
            want[i] ^= 1;
            assert_eq!(d, want, "nothing decrypted");
        }
        let mut d = ct.clone();
        assert_eq!(open(&key, &nonce, b"headeR", &mut d, &tag), Err(AuthError));
        let mut bad = tag;
        bad[15] ^= 0x80;
        assert_eq!(open(&key, &nonce, b"header", &mut d, &bad), Err(AuthError));
        assert_eq!(open(&[8u8; 32], &nonce, b"header", &mut d, &tag), Err(AuthError));
    }

    #[test]
    fn matches_the_reference_crate() {
        let mut x = 0x5eed_c0ff_ee00_1234u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..500 {
            let key: [u8; 32] = core::array::from_fn(|_| next() as u8);
            let nonce: [u8; 12] = core::array::from_fn(|_| next() as u8);
            let aad: Vec<u8> = (0..next() % 70).map(|_| next() as u8).collect();
            let pt: Vec<u8> = (0..next() % 300).map(|_| next() as u8).collect();
            let mut ours = pt.clone();
            let tag = seal(&key, &nonce, &aad, &mut ours);
            let c = chacha20poly1305::ChaCha20Poly1305::new((&key).into());
            let mut want = pt.clone();
            let rtag = c
                .encrypt_in_place_detached((&nonce).into(), &aad, &mut want)
                .unwrap();
            assert_eq!(ours, want);
            assert_eq!(tag.as_slice(), rtag.as_slice());
        }
    }
}
