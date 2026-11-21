//! HMAC-SHA512 and HMAC-SHA256 (RFC 2104 / RFC 4231).

use crate::secret::wipe;
use crate::sha256::Sha256;
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

/// HMAC-SHA256 (used by RFC 6979 nonce generation).
#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        use crate::sha256::{BLOCK_LEN as B, DIGEST_LEN as D};
        let mut k = [0u8; B];
        if key.len() > B {
            let d = Sha256::digest(key);
            k[..D].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; B];
        let mut opad = [0x5cu8; B];
        for i in 0..B {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        let mut outer = Sha256::new();
        outer.update(&opad);
        wipe(&mut k);
        wipe(&mut ipad);
        wipe(&mut opad);
        Self { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let Self { inner, mut outer } = self;
        let mut ih = inner.finalize();
        outer.update(&ih);
        wipe(&mut ih);
        outer.finalize()
    }

    pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut h = Self::new(key);
        h.update(data);
        h.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_case_2_sha256() {
        let mac = HmacSha256::mac(b"Jefe", b"what do ya want for nothing?");
        let want = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(mac, want);
    }
}
