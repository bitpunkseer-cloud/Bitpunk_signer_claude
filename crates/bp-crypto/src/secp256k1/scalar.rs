//! Scalars modulo the group order n. Constant-time add/negate; secret keys
//! are wrapped in `SecretKey`, which wipes itself on drop.

use super::ct::{add4, is_zero4, limbs_from_be, limbs_to_be, select4, sub4, Choice};
use core::fmt;

pub const N: [u64; 4] = [
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    u64::MAX,
];

#[derive(Clone, Copy)]
pub struct Scalar(pub(crate) [u64; 4]);

impl Scalar {
    pub const ZERO: Scalar = Scalar([0; 4]);
    pub const ONE: Scalar = Scalar([1, 0, 0, 0]);

    /// Parse big-endian bytes; `None` if the value is not below n.
    pub fn from_bytes(b: &[u8; 32]) -> Option<Scalar> {
        let x = limbs_from_be(b);
        let (_, borrow) = sub4(&x, &N);
        (borrow == 1).then_some(Scalar(x))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        limbs_to_be(&self.0)
    }

    pub fn add(&self, o: &Scalar) -> Scalar {
        let (s, c) = add4(&self.0, &o.0);
        let (d, borrow) = sub4(&s, &N);
        let use_d = Choice::from_bit(c).or(Choice::from_bit(borrow).not());
        Scalar(select4(&s, &d, use_d))
    }

    pub fn neg(&self) -> Scalar {
        let (d, _) = sub4(&N, &self.0);
        // -0 = 0
        Scalar(select4(&d, &[0; 4], self.is_zero()))
    }

    pub fn is_zero(&self) -> Choice {
        is_zero4(&self.0)
    }

    /// 4-bit window `i` (0 = least significant).
    pub(crate) fn nibble(&self, i: usize) -> u64 {
        (self.0[i / 16] >> ((i % 16) * 4)) & 0xF
    }

    pub fn select(a: &Scalar, b: &Scalar, c: Choice) -> Scalar {
        Scalar(select4(&a.0, &b.0, c))
    }

    pub(crate) fn wipe(&mut self) {
        for v in self.0.iter_mut() {
            // SAFETY: valid exclusive reference.
            unsafe { core::ptr::write_volatile(v, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// A valid private key (1 <= k < n). Wiped on drop, never printed.
pub struct SecretKey(Scalar);

impl SecretKey {
    pub fn from_bytes(b: &[u8; 32]) -> Option<SecretKey> {
        let s = Scalar::from_bytes(b)?;
        if s.is_zero().unwrap_public() {
            return None;
        }
        Some(SecretKey(s))
    }

    pub fn from_scalar(s: Scalar) -> Option<SecretKey> {
        if s.is_zero().unwrap_public() {
            None
        } else {
            Some(SecretKey(s))
        }
    }

    pub fn scalar(&self) -> &Scalar {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> super::point::PublicKey {
        super::point::PublicKey::from_secret(self)
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        SecretKey(self.0)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(***)")
    }
}
