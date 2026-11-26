//! SHA-1 (FIPS 180-4) and HMAC-SHA1 (RFC 2104), for HOTP/TOTP codes only
//! (M11-7, RFC 4226 / 6238: most authenticator keys use HMAC-SHA1).
//! SHA-1 is broken for collisions, which HMAC does not rely on; nothing
//! else on the device uses it. New file under the file-level freeze.

use crate::secret::wipe;

pub const BLOCK_LEN: usize = 64;
pub const DIGEST_LEN: usize = 20;

const H0: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];

#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sha1 {
    fn drop(&mut self) {
        wipe(&mut self.buf);
    }
}

fn compress(state: &mut [u32; 5], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u32; 80];
    for (i, c) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
        *s = s.wrapping_add(v);
    }
    for x in w.iter_mut() {
        *x = 0;
    }
}

impl Sha1 {
    pub const fn new() -> Self {
        Self {
            state: H0,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_LEN {
                let block = self.buf;
                compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        while data.len() >= BLOCK_LEN {
            let block: [u8; BLOCK_LEN] = data[..BLOCK_LEN].try_into().expect("block");
            compress(&mut self.state, &block);
            data = &data[BLOCK_LEN..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; DIGEST_LEN];
        for (o, s) in out.chunks_exact_mut(4).zip(self.state) {
            o.copy_from_slice(&s.to_be_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

/// HMAC-SHA1 (RFC 2104).
#[derive(Clone)]
pub struct HmacSha1 {
    inner: Sha1,
    outer: Sha1,
}

impl HmacSha1 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            k[..DIGEST_LEN].copy_from_slice(&Sha1::digest(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK_LEN];
        let mut opad = [0x5cu8; BLOCK_LEN];
        for i in 0..BLOCK_LEN {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha1::new();
        inner.update(&ipad);
        let mut outer = Sha1::new();
        outer.update(&opad);
        wipe(&mut k);
        wipe(&mut ipad);
        wipe(&mut opad);
        Self { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        let Self { inner, mut outer } = self;
        let mut ih = inner.finalize();
        outer.update(&ih);
        wipe(&mut ih);
        outer.finalize()
    }

    pub fn mac(key: &[u8], data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut h = Self::new(key);
        h.update(data);
        h.finalize()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn hex(s: &str) -> [u8; DIGEST_LEN] {
        let mut out = [0u8; DIGEST_LEN];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn fips_180_examples() {
        assert_eq!(
            Sha1::digest(b"abc"),
            hex("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            Sha1::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        );
        assert_eq!(Sha1::digest(b""), hex("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        let mut h = Sha1::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(h.finalize(), hex("34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
    }

    #[test]
    fn rfc_2202_hmac_vectors() {
        assert_eq!(
            HmacSha1::mac(&[0x0b; 20], b"Hi There"),
            hex("b617318655057264e28bc0b6fb378c8ef146be00")
        );
        assert_eq!(
            HmacSha1::mac(b"Jefe", b"what do ya want for nothing?"),
            hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
        );
        assert_eq!(
            HmacSha1::mac(&[0xaa; 20], &[0xdd; 50]),
            hex("125d7342b9ac11cd91a39af48aa17b4f63f175d3")
        );
        // a key longer than a block is hashed first
        assert_eq!(
            HmacSha1::mac(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            hex("aa4ae5e15272d00e95705637ce8a3b55ed402112")
        );
    }

    #[test]
    fn matches_the_reference_crates() {
        use hmac::Mac;
        use sha1_ref::Digest;
        let mut seed = 5u32;
        let mut next = || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (seed >> 16) as u8
        };
        for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 200, 1000] {
            let data: std::vec::Vec<u8> = (0..len).map(|_| next()).collect();
            let want: [u8; 20] = sha1_ref::Sha1::digest(&data).into();
            assert_eq!(Sha1::digest(&data), want, "{len}");
            // split updates
            let mut h = Sha1::new();
            let (a, b) = data.split_at(len / 3);
            h.update(a);
            h.update(b);
            assert_eq!(h.finalize(), want);
            let key: std::vec::Vec<u8> = (0..(len % 90)).map(|_| next()).collect();
            let mut m = hmac::Hmac::<sha1_ref::Sha1>::new_from_slice(&key).unwrap();
            m.update(&data);
            let want: [u8; 20] = m.finalize().into_bytes().into();
            assert_eq!(HmacSha1::mac(&key, &data), want);
        }
    }
}
