//! HMAC-SHA512 (RFC 2104 / RFC 4231).

use crate::secret::wipe;
use crate::sha512::{Sha512, BLOCK_LEN, DIGEST_LEN};

#[derive(Clone)]
pub struct HmacSha512 {
    inner: Sha512,
    outer: Sha512,
}

impl HmacSha512 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            let d = Sha512::digest(key);
            k[..DIGEST_LEN].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK_LEN];
        let mut opad = [0x5cu8; BLOCK_LEN];
        for i in 0..BLOCK_LEN {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha512::new();
        inner.update(&ipad);
        let mut outer = Sha512::new();
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
