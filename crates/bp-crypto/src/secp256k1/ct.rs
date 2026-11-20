//! Constant-time helpers. A `Choice` is an all-ones or all-zeros mask, so
//! selections compile to bitwise operations instead of secret branches.

#[derive(Clone, Copy, Debug)]
pub struct Choice(pub(crate) u64);

/// Optimization barrier: the compiler cannot see the value through a
/// volatile read, so it cannot turn mask arithmetic back into a branch on a
/// secret (the same technique as the `subtle` crate).
#[inline(always)]
pub fn barrier(x: u64) -> u64 {
    // SAFETY: reading a local through a valid pointer.
    unsafe { core::ptr::read_volatile(&x) }
}

impl Choice {
    pub const TRUE: Choice = Choice(u64::MAX);
    pub const FALSE: Choice = Choice(0);

    /// From a 0/1 bit.
    #[inline]
    pub fn from_bit(b: u64) -> Choice {
        Choice(barrier((b & 1).wrapping_neg()))
    }

    #[inline]
    pub fn and(self, o: Choice) -> Choice {
        Choice(self.0 & o.0)
    }

    #[inline]
    pub fn or(self, o: Choice) -> Choice {
        Choice(self.0 | o.0)
    }

    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> Choice {
        Choice(!self.0)
    }

    /// Reveal the value. Only call on data that is public.
    #[inline]
    pub fn unwrap_public(self) -> bool {
        self.0 != 0
    }
}

/// `a` if `c` is false, `b` if true.
#[inline]
pub fn select4(a: &[u64; 4], b: &[u64; 4], c: Choice) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in 0..4 {
        r[i] = a[i] ^ (c.0 & (a[i] ^ b[i]));
    }
    r
}

/// Mask that is all ones when `x == 0`.
#[inline]
pub fn is_zero4(x: &[u64; 4]) -> Choice {
    let v = x[0] | x[1] | x[2] | x[3];
    // (v | -v) has the top bit set iff v != 0
    Choice::from_bit(((v | v.wrapping_neg()) >> 63) ^ 1)
}

/// Add with carry over 4 limbs; returns (sum, carry bit).
#[inline]
pub fn add4(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let t = a[i] as u128 + b[i] as u128 + carry;
        r[i] = t as u64;
        carry = t >> 64;
    }
    (r, carry as u64)
}

/// Subtract with borrow over 4 limbs; returns (difference, borrow bit).
#[inline]
pub fn sub4(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = (b1 | b2) as u64;
    }
    (r, borrow)
}

/// Big-endian 32 bytes -> little-endian limbs.
pub fn limbs_from_be(b: &[u8; 32]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in 0..4 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[24 - 8 * i..32 - 8 * i]);
        r[i] = u64::from_be_bytes(w);
    }
    r
}

pub fn limbs_to_be(x: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[24 - 8 * i..32 - 8 * i].copy_from_slice(&x[i].to_be_bytes());
    }
    out
}
