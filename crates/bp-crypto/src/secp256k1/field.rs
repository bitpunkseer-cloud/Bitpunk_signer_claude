//! Field arithmetic modulo p = 2^256 - 2^32 - 977. Values are kept fully
//! reduced (< p). All operations run in constant time.

use super::ct::{add4, is_zero4, limbs_from_be, limbs_to_be, select4, sub4, Choice};

pub const P: [u64; 4] = [0xFFFF_FFFE_FFFF_FC2F, u64::MAX, u64::MAX, u64::MAX];
/// 2^256 mod p
const C: u64 = 0x1_0000_03D1;

#[derive(Clone, Copy, Debug)]
pub struct Fe(pub(crate) [u64; 4]);

impl Fe {
    pub const ZERO: Fe = Fe([0; 4]);
    pub const ONE: Fe = Fe([1, 0, 0, 0]);

    pub const fn from_u64(v: u64) -> Fe {
        Fe([v, 0, 0, 0])
    }

    /// Parse big-endian bytes; `None` if the value is not below p.
    pub fn from_bytes(b: &[u8; 32]) -> Option<Fe> {
        let x = limbs_from_be(b);
        let (_, borrow) = sub4(&x, &P);
        (borrow == 1).then_some(Fe(x))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        limbs_to_be(&self.0)
    }

    /// Subtract p once if the value (with an extra carry bit) is >= p.
    fn reduce_once(x: [u64; 4], carry: u64) -> Fe {
        let (d, borrow) = sub4(&x, &P);
        // use the difference if there was a carry out, or no borrow
        let use_d = Choice::from_bit(carry).or(Choice::from_bit(borrow).not());
        Fe(select4(&x, &d, use_d))
    }

    pub fn add(&self, o: &Fe) -> Fe {
        let (s, c) = add4(&self.0, &o.0);
        Fe::reduce_once(s, c)
    }

    pub fn sub(&self, o: &Fe) -> Fe {
        let (d, borrow) = sub4(&self.0, &o.0);
        let mask = Choice::from_bit(borrow);
        let p = select4(&[0; 4], &P, mask);
        let (r, _) = add4(&d, &p);
        Fe(r)
    }

    pub fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    pub fn double(&self) -> Fe {
        self.add(self)
    }

    /// Multiply by a small constant.
    pub fn mul_small(&self, k: u64) -> Fe {
        self.mul(&Fe::from_u64(k))
    }

    pub fn mul(&self, o: &Fe) -> Fe {
        // 512-bit schoolbook product
        let a = &self.0;
        let b = &o.0;
        let mut r = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = a[i] as u128 * b[j] as u128 + r[i + j] as u128 + carry;
                r[i + j] = t as u64;
                carry = t >> 64;
            }
            r[i + 4] = carry as u64;
        }
        // fold the high half: hi * 2^256 = hi * C (mod p)
        let mut t = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let v = r[i] as u128 + r[i + 4] as u128 * C as u128 + carry;
            t[i] = v as u64;
            carry = v >> 64;
        }
        // fold the remaining carry (< 2^34)
        let mut v = t[0] as u128 + carry * C as u128;
        t[0] = v as u64;
        for limb in t.iter_mut().skip(1) {
            v = *limb as u128 + (v >> 64);
            *limb = v as u64;
        }
        let c2 = (v >> 64) as u64; // 0 or 1
                                   // a second overflow wraps again: add C * c2 (cannot overflow now)
        let mut v = t[0] as u128 + (C * c2) as u128;
        t[0] = v as u64;
        for limb in t.iter_mut().skip(1) {
            v = *limb as u128 + (v >> 64);
            *limb = v as u64;
        }
        Fe::reduce_once(t, 0)
    }

    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    /// self^e for a public exponent (bits are not secret).
    fn pow_public(&self, e: &[u64; 4]) -> Fe {
        let mut r = Fe::ONE;
        for i in (0..256).rev() {
            r = r.square();
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }

    /// Multiplicative inverse via Fermat (self^(p-2)); 0 maps to 0.
    pub fn invert(&self) -> Fe {
        let mut e = P;
        e[0] -= 2;
        self.pow_public(&e)
    }

    /// Square root if it exists (p ≡ 3 mod 4: self^((p+1)/4)).
    pub fn sqrt(&self) -> Option<Fe> {
        // (p+1)/4
        let e = [0xFFFF_FFFF_BFFF_FF0C, u64::MAX, u64::MAX, 0x3FFF_FFFF_FFFF_FFFF];
        let r = self.pow_public(&e);
        r.square().ct_eq(self).unwrap_public().then_some(r)
    }

    pub fn is_zero(&self) -> Choice {
        is_zero4(&self.0)
    }

    pub fn is_odd(&self) -> Choice {
        Choice::from_bit(self.0[0] & 1)
    }

    pub fn ct_eq(&self, o: &Fe) -> Choice {
        let x = [
            self.0[0] ^ o.0[0],
            self.0[1] ^ o.0[1],
            self.0[2] ^ o.0[2],
            self.0[3] ^ o.0[3],
        ];
        is_zero4(&x)
    }

    pub fn select(a: &Fe, b: &Fe, c: Choice) -> Fe {
        Fe(select4(&a.0, &b.0, c))
    }
}
