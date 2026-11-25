//! Arithmetic in GF(256) with the polynomial x^8 + x^4 + x^3 + x + 1 (the
//! field of AES and SLIP-39), and Lagrange interpolation for Shamir's
//! secret sharing.
//!
//! Secret bytes go only through `mul`, which takes the same steps for every
//! value (no tables indexed by secret data). Share x-coordinates are public.

/// `a * b` in GF(256), in constant time.
pub fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & 0u8.wrapping_sub(b & 1);
        let hi = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1B & hi);
        b >>= 1;
    }
    p
}

/// `a^-1` (`a^254`); 0 maps to 0. Used on public x-coordinates only, but
/// constant time all the same.
pub fn inv(a: u8) -> u8 {
    // a^254 = a^(2+4+8+16+32+64+128)
    let mut result = 1u8;
    let mut sq = a;
    for _ in 0..7 {
        sq = mul(sq, sq);
        result = mul(result, sq);
    }
    result
}

/// The most points a polynomial is built from (SLIP-39 allows 16 shares).
pub const MAX_POINTS: usize = 16;
/// The longest value interpolated (a 256-bit secret).
pub const MAX_LEN: usize = 32;

/// A point (x, f(x)) of a polynomial evaluated bytewise.
#[derive(Clone)]
pub struct Point {
    pub x: u8,
    pub y: [u8; MAX_LEN],
}

impl Drop for Point {
    fn drop(&mut self) {
        bp_crypto::secret::wipe(&mut self.y);
    }
}

impl Point {
    pub fn new(x: u8, y: &[u8]) -> Point {
        let mut p = Point { x, y: [0; MAX_LEN] };
        p.y[..y.len()].copy_from_slice(y);
        p
    }
}

/// f(`x`) for the polynomial through `points` (distinct x-coordinates, all
/// `len` bytes long), written to `out[..len]`.
pub fn interpolate(points: &[Point], len: usize, x: u8, out: &mut [u8; MAX_LEN]) {
    debug_assert!(!points.is_empty() && points.len() <= MAX_POINTS && len <= MAX_LEN);
    out.iter_mut().for_each(|b| *b = 0);
    if let Some(p) = points.iter().find(|p| p.x == x) {
        out[..len].copy_from_slice(&p.y[..len]);
        return;
    }
    for (i, pi) in points.iter().enumerate() {
        // Lagrange basis polynomial i at x: prod (x - xj) / (xi - xj).
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, pj) in points.iter().enumerate() {
            if i != j {
                num = mul(num, x ^ pj.x);
                den = mul(den, pi.x ^ pj.x);
            }
        }
        let basis = mul(num, inv(den));
        for (o, y) in out[..len].iter_mut().zip(&pi.y[..len]) {
            *o ^= mul(basis, *y);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference implementation's log/exp tables (generator x + 1).
    fn slow_mul(a: u8, b: u8) -> u8 {
        let mut p = 0u16;
        for i in 0..8 {
            if (b >> i) & 1 == 1 {
                p ^= (a as u16) << i;
            }
        }
        for i in (8..16).rev() {
            if (p >> i) & 1 == 1 {
                p ^= 0x11B << (i - 8);
            }
        }
        p as u8
    }

    #[test]
    fn multiplication_and_inverse_are_the_field_of_aes() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), slow_mul(a, b));
            }
            if a != 0 {
                assert_eq!(mul(a, inv(a)), 1, "{a}");
            }
        }
        assert_eq!(inv(0), 0);
        assert_eq!(mul(0x57, 0x83), 0xC1); // FIPS-197 section 4.2
    }

    #[test]
    fn interpolation_recovers_any_point_from_enough_points() {
        // f(x) = s + a x + b x^2 bytewise; any three points give f(255).
        let eval = |x: u8, k: usize| -> u8 {
            let s = k as u8;
            let a = (k as u8).wrapping_mul(31) ^ 0x5A;
            let b = (k as u8).wrapping_mul(7) ^ 0xC3;
            s ^ mul(a, x) ^ mul(b, mul(x, x))
        };
        let pts: [Point; 5] = core::array::from_fn(|i| {
            let x = [0u8, 1, 7, 254, 100][i];
            let mut y = [0u8; 20];
            for (k, v) in y.iter_mut().enumerate() {
                *v = eval(x, k);
            }
            Point::new(x, &y)
        });
        for start in 0..3 {
            let mut out = [0u8; MAX_LEN];
            interpolate(&pts[start..start + 3], 20, 255, &mut out);
            for (k, v) in out[..20].iter().enumerate() {
                assert_eq!(*v, eval(255, k));
            }
        }
        let mut out = [0u8; MAX_LEN];
        interpolate(&pts[..3], 20, 7, &mut out);
        assert_eq!(out[..20], pts[2].y[..20]);
    }
}
