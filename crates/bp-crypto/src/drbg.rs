//! Small deterministic random bit generator (SHA-256 in counter mode).
//!
//! **Not used for seed material.** Bitpunk seeds come only from dice and coin
//! flips. This generator only shuffles non-secret UI choices such as the order
//! of backup-quiz questions and decoy words.

use crate::sha256::Sha256;

pub struct Drbg {
    key: [u8; 32],
    counter: u64,
}

impl Drbg {
    pub fn new(seed: &[u8]) -> Self {
        Self {
            key: Sha256::digest(seed),
            counter: 0,
        }
    }

    /// Mix extra bytes into the state.
    pub fn reseed(&mut self, extra: &[u8]) {
        let mut h = Sha256::new();
        h.update(&self.key);
        h.update(extra);
        self.key = h.finalize();
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(&self.key);
            h.update(&self.counter.to_be_bytes());
            self.counter = self.counter.wrapping_add(1);
            let block = h.finalize();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        u32::from_le_bytes(b)
    }

    /// Uniform integer in `0..n` (rejection sampling, no modulo bias).
    pub fn below(&mut self, n: u32) -> u32 {
        assert!(n > 0);
        let zone = u32::MAX - (u32::MAX % n);
        loop {
            let v = self.next_u32();
            if v < zone {
                return v % n;
            }
        }
    }
}

impl Drop for Drbg {
    fn drop(&mut self) {
        crate::secret::wipe(&mut self.key);
    }
}
