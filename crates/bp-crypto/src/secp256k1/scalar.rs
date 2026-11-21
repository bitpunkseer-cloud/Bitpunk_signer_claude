//! Scalars modulo the group order n. Constant-time add, negate, multiply
//! and invert; secret keys are wrapped in `SecretKey`, which wipes itself
//! on drop.

use super::ct::{add4, is_zero4, limbs_from_be, limbs_to_be, select4, sub4, Choice};
use core::fmt;

pub const N: [u64; 4] = [
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    u64::MAX,
];

/// 2^256 - n (129 bits), so 2^256 = NC (mod n).
const NC: [u64; 3] = [0x402D_A173_2FC9_BEBF, 0x4551_2319_50B7_5FC4, 1];

/// n / 2 (floor), for the low-S rule.
const N_HALF: [u64; 4] = [
    0xDFE9_2F46_681B_20A0,
    0x5D57_6E73_57A4_501D,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

/// out += a * b over `out.len()` limbs (fixed loop bounds: constant time).
#[inline]
fn mul_add_into(out: &mut [u64], a: &[u64], b: &[u64]) {
    for (i, &ai) in a.iter().enumerate() {
        let mut carry: u128 = 0;
        for j in 0..out.len() - i {
            let bj = if j < b.len() { b[j] } else { 0 };
            let t = out[i + j] as u128 + (ai as u128) * (bj as u128) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
    }
}

/// Reduce a 512-bit value modulo n by folding the high half with
/// 2^256 = NC (four fixed rounds, then one conditional subtraction).
fn reduce512(x: &[u64; 8]) -> [u64; 4] {
    // round 1: < 2^256 + 2^385
    let mut a = [0u64; 7];
    a[..4].copy_from_slice(&x[..4]);
    mul_add_into(&mut a, &x[4..8], &NC);
    // round 2: < 2^256 + 2^(130 + 129)
    let mut b = [0u64; 5];
    b[..4].copy_from_slice(&a[..4]);
    mul_add_into(&mut b, &a[4..7], &NC);
    // round 3: < 2^256 + 2^131
    let mut c = [0u64; 5];
    c[..4].copy_from_slice(&b[..4]);
    mul_add_into(&mut c, &b[4..5], &NC);
    // round 4: c[4] is 0 or 1; if 1, the low part is below 2^131
    let mut d = [0u64; 5];
    d[..4].copy_from_slice(&c[..4]);
    mul_add_into(&mut d, &c[4..5], &NC);
    let r = [d[0], d[1], d[2], d[3]];
    let (s, borrow) = sub4(&r, &N);
    select4(&s, &r, Choice::from_bit(borrow))
}

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

    /// Big-endian bytes reduced modulo n (a 256-bit hash as a scalar).
    pub fn from_bytes_reduce(b: &[u8; 32]) -> Scalar {
        let x = limbs_from_be(b);
        let (d, borrow) = sub4(&x, &N);
        Scalar(select4(&d, &x, Choice::from_bit(borrow)))
    }

    pub fn mul(&self, o: &Scalar) -> Scalar {
        let mut w = [0u64; 8];
        mul_add_into(&mut w, &self.0, &o.0);
        let r = reduce512(&w);
        for v in w.iter_mut() {
            // SAFETY: valid exclusive reference.
            unsafe { core::ptr::write_volatile(v, 0) };
        }
        Scalar(r)
    }

    pub fn square(&self) -> Scalar {
        self.mul(self)
    }

    /// Multiplicative inverse (a^(n-2), fixed public exponent: constant
    /// time in `a`). The inverse of 0 is 0.
    pub fn invert(&self) -> Scalar {
        // n - 2
        let e: [u64; 4] = [N[0] - 2, N[1], N[2], N[3]];
        let mut acc = Scalar::ONE;
        for i in (0..256).rev() {
            acc = acc.square();
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                acc = acc.mul(self);
            }
        }
        acc
    }

    /// True when the scalar is above n / 2 (the high half; BIP-62 low-S).
    pub fn is_high(&self) -> Choice {
        let (_, borrow) = sub4(&N_HALF, &self.0);
        Choice::from_bit(borrow)
    }

    pub fn ct_eq(&self, o: &Scalar) -> Choice {
        let x = [
            self.0[0] ^ o.0[0],
            self.0[1] ^ o.0[1],
            self.0[2] ^ o.0[2],
            self.0[3] ^ o.0[3],
        ];
        is_zero4(&x)
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
