//! Group operations on secp256k1 (y^2 = x^3 + 7) in homogeneous projective
//! coordinates, using the complete addition formula of Renes, Costello and
//! Batina (2015, Algorithm 7, a = 0). "Complete" means the same formula is
//! correct for doubling and for the point at infinity, so there are no
//! secret-dependent branches.

use super::ct::Choice;
use super::field::Fe;
use super::scalar::{Scalar, SecretKey};

/// 3 * b, with b = 7.
const B3: u64 = 21;

pub const GX: [u8; 32] = [
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02,
    0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
];
pub const GY: [u8; 32] = [
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8, 0xFD,
    0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
];

#[derive(Clone, Copy, Debug)]
pub struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Point {
    pub const INFINITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ZERO,
    };

    pub fn generator() -> Point {
        Point {
            x: Fe::from_bytes(&GX).expect("valid Gx"),
            y: Fe::from_bytes(&GY).expect("valid Gy"),
            z: Fe::ONE,
        }
    }

    pub fn from_affine(x: Fe, y: Fe) -> Point {
        Point { x, y, z: Fe::ONE }
    }

    pub fn is_infinity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Complete addition (valid for P == Q and for infinity).
    pub fn add(&self, q: &Point) -> Point {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2, z2) = (&q.x, &q.y, &q.z);
        let mut t0 = x1.mul(x2);
        let mut t1 = y1.mul(y2);
        let mut t2 = z1.mul(z2);
        let mut t3 = x1.add(y1);
        let mut t4 = x2.add(y2);
        t3 = t3.mul(&t4);
        t4 = t0.add(&t1);
        t3 = t3.sub(&t4);
        t4 = y1.add(z1);
        let mut x3 = y2.add(z2);
        t4 = t4.mul(&x3);
        x3 = t1.add(&t2);
        t4 = t4.sub(&x3);
        x3 = x1.add(z1);
        let mut y3 = x2.add(z2);
        x3 = x3.mul(&y3);
        y3 = t0.add(&t2);
        y3 = x3.sub(&y3);
        x3 = t0.add(&t0);
        t0 = x3.add(&t0);
        t2 = t2.mul_small(B3);
        let mut z3 = t1.add(&t2);
        t1 = t1.sub(&t2);
        y3 = y3.mul_small(B3);
        x3 = t4.mul(&y3);
        t2 = t3.mul(&t1);
        x3 = t2.sub(&x3);
        y3 = y3.mul(&t0);
        t1 = t1.mul(&z3);
        y3 = t1.add(&y3);
        t0 = t0.mul(&t3);
        z3 = z3.mul(&t4);
        z3 = z3.add(&t0);
        Point { x: x3, y: y3, z: z3 }
    }

    pub fn double(&self) -> Point {
        self.add(self)
    }

    pub fn neg(&self) -> Point {
        Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    fn select(a: &Point, b: &Point, c: Choice) -> Point {
        Point {
            x: Fe::select(&a.x, &b.x, c),
            y: Fe::select(&a.y, &b.y, c),
            z: Fe::select(&a.z, &b.z, c),
        }
    }

    /// k * self with a 4-bit fixed window. Every window does four doublings
    /// and one addition, and the table lookup reads every entry, so timing
    /// and memory access do not depend on k.
    pub fn mul(&self, k: &Scalar) -> Point {
        let mut table = [Point::INFINITY; 16];
        for i in 1..16 {
            table[i] = table[i - 1].add(self);
        }
        let mut r = Point::INFINITY;
        for w in (0..64).rev() {
            r = r.double().double().double().double();
            let nib = k.nibble(w);
            let mut sel = Point::INFINITY;
            for (j, entry) in table.iter().enumerate() {
                let hit = Choice::from_bit(((nib ^ j as u64).wrapping_sub(1) >> 63) & 1);
                sel = Point::select(&sel, entry, hit);
            }
            r = r.add(&sel);
        }
        r
    }

    /// Affine coordinates, or `None` for the point at infinity.
    pub fn to_affine(&self) -> Option<(Fe, Fe)> {
        if self.is_infinity().unwrap_public() {
            return None;
        }
        let zi = self.z.invert();
        Some((self.x.mul(&zi), self.y.mul(&zi)))
    }
}

/// A public key (never the point at infinity), stored in affine form.
#[derive(Clone, Copy, Debug)]
pub struct PublicKey {
    x: Fe,
    y: Fe,
}

impl PartialEq for PublicKey {
    fn eq(&self, o: &Self) -> bool {
        self.x.ct_eq(&o.x).and(self.y.ct_eq(&o.y)).unwrap_public()
    }
}
impl Eq for PublicKey {}

impl PublicKey {
    pub fn from_secret(sk: &SecretKey) -> PublicKey {
        let p = Point::generator().mul(sk.scalar());
        let (x, y) = p.to_affine().expect("k in [1, n) never gives infinity");
        PublicKey { x, y }
    }

    pub fn from_point(p: &Point) -> Option<PublicKey> {
        p.to_affine().map(|(x, y)| PublicKey { x, y })
    }

    pub fn to_point(&self) -> Point {
        Point::from_affine(self.x, self.y)
    }

    /// 33-byte SEC1 compressed encoding.
    pub fn serialize(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = if self.y.is_odd().unwrap_public() {
            0x03
        } else {
            0x02
        };
        out[1..].copy_from_slice(&self.x.to_bytes());
        out
    }

    /// 65-byte SEC1 uncompressed encoding.
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x.to_bytes());
        out[33..].copy_from_slice(&self.y.to_bytes());
        out
    }

    /// BIP-340 x-only encoding.
    pub fn x_only(&self) -> [u8; 32] {
        self.x.to_bytes()
    }

    pub fn has_odd_y(&self) -> bool {
        self.y.is_odd().unwrap_public()
    }

    /// Parse a compressed (33-byte) or uncompressed (65-byte) key.
    pub fn parse(b: &[u8]) -> Option<PublicKey> {
        match (b.len(), b.first()) {
            (33, Some(&prefix @ (0x02 | 0x03))) => {
                let x = Fe::from_bytes(b[1..].try_into().ok()?)?;
                let rhs = x.square().mul(&x).add(&Fe::from_u64(7));
                let mut y = rhs.sqrt()?;
                if y.is_odd().unwrap_public() != (prefix == 0x03) {
                    y = y.neg();
                }
                Some(PublicKey { x, y })
            }
            (65, Some(0x04)) => {
                let x = Fe::from_bytes(b[1..33].try_into().ok()?)?;
                let y = Fe::from_bytes(b[33..].try_into().ok()?)?;
                let on_curve = y.square().ct_eq(&x.square().mul(&x).add(&Fe::from_u64(7)));
                on_curve.unwrap_public().then_some(PublicKey { x, y })
            }
            _ => None,
        }
    }

    /// self + t*G (BIP-32 public derivation, Taproot tweaks).
    pub fn add_tweak(&self, t: &Scalar) -> Option<PublicKey> {
        let p = self.to_point().add(&Point::generator().mul(t));
        PublicKey::from_point(&p)
    }
}
