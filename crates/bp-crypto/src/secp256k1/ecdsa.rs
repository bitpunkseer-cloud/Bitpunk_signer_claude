//! ECDSA over secp256k1 for Bitcoin: deterministic nonces (RFC 6979 with
//! HMAC-SHA256), low-S normalisation (BIP-62/146) and low-R grinding (the
//! nonce is re-derived with an extra-entropy counter until r < 2^255, as
//! Bitcoin Core and libsecp256k1's `sign_ecdsa_low_r` do, so signatures are
//! 70-71 bytes in DER and look like everyone else's). DER encoding and
//! strict DER parsing (BIP-66). Signing is constant time in the key and the
//! nonce; verification works on public data only.

use super::point::{Point, PublicKey};
use super::scalar::{Scalar, SecretKey};
use crate::hmac::HmacSha256;
use crate::secret::wipe;

/// Longest DER signature (without the sighash byte).
pub const MAX_DER_LEN: usize = 72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// RFC 6979 HMAC-SHA256 DRBG, laid out as libsecp256k1 does: the seed is
/// key || message (mod n) || optional 32-byte extra data.
struct Rfc6979 {
    k: [u8; 32],
    v: [u8; 32],
    retry: bool,
}

impl Rfc6979 {
    fn new(seed: &[u8]) -> Self {
        let mut r = Rfc6979 {
            k: [0; 32],
            v: [1; 32],
            retry: false,
        };
        for sep in [0u8, 1] {
            let mut h = HmacSha256::new(&r.k);
            h.update(&r.v);
            h.update(&[sep]);
            h.update(seed);
            r.k = h.finalize();
            r.v = HmacSha256::mac(&r.k, &r.v);
        }
        r
    }

    fn generate(&mut self) -> [u8; 32] {
        if self.retry {
            let mut h = HmacSha256::new(&self.k);
            h.update(&self.v);
            h.update(&[0]);
            self.k = h.finalize();
            self.v = HmacSha256::mac(&self.k, &self.v);
        }
        self.v = HmacSha256::mac(&self.k, &self.v);
        self.retry = true;
        self.v
    }
}

impl Drop for Rfc6979 {
    fn drop(&mut self) {
        wipe(&mut self.k);
        wipe(&mut self.v);
    }
}

/// The x coordinate of a point reduced modulo n, or `None` at infinity.
fn x_mod_n(p: &Point) -> Option<Scalar> {
    let (x, _) = p.to_affine()?;
    Some(Scalar::from_bytes_reduce(&x.to_bytes()))
}

/// One signing attempt with optional extra entropy; `None` only in the
/// negligible cases (r or s zero after every nonce retry is impossible in
/// practice, but the loop is bounded).
fn sign_with(sk: &SecretKey, msg: &[u8; 32], extra: Option<&[u8; 32]>) -> Option<Signature> {
    let z = Scalar::from_bytes_reduce(msg);
    let mut seed = [0u8; 96];
    seed[..32].copy_from_slice(&sk.to_bytes());
    seed[32..64].copy_from_slice(&z.to_bytes());
    let seed_len = match extra {
        Some(e) => {
            seed[64..96].copy_from_slice(e);
            96
        }
        None => 64,
    };
    let mut drbg = Rfc6979::new(&seed[..seed_len]);
    wipe(&mut seed);
    for _ in 0..64 {
        let mut kb = drbg.generate();
        let k = Scalar::from_bytes(&kb);
        wipe(&mut kb);
        let Some(mut k) = k else { continue };
        if k.is_zero().unwrap_public() {
            continue;
        }
        let rp = Point::generator().mul(&k);
        let Some(r) = x_mod_n(&rp) else {
            k.wipe();
            continue;
        };
        if r.is_zero().unwrap_public() {
            k.wipe();
            continue;
        }
        // s = k^-1 (z + r d)
        let mut kinv = k.invert();
        let rd = r.mul(sk.scalar());
        let mut s = kinv.mul(&z.add(&rd));
        k.wipe();
        kinv.wipe();
        // low S
        s = Scalar::select(&s, &s.neg(), s.is_high());
        if s.is_zero().unwrap_public() {
            continue;
        }
        let sig = Signature {
            r: r.to_bytes(),
            s: s.to_bytes(),
        };
        s.wipe();
        return Some(sig);
    }
    None
}

/// Sign a 32-byte digest: RFC 6979 nonce, low S, and low R by grinding the
/// extra-entropy counter (little-endian u32 in a 32-byte buffer, as Bitcoin
/// Core). The result is byte-identical to libsecp256k1 `sign_ecdsa_low_r`.
pub fn sign(sk: &SecretKey, msg: &[u8; 32]) -> Signature {
    let mut extra = [0u8; 32];
    let mut counter: u32 = 0;
    loop {
        let e = (counter > 0).then_some(&extra);
        if let Some(sig) = sign_with(sk, msg, e) {
            if sig.r[0] < 0x80 {
                return sig;
            }
        }
        counter = counter.wrapping_add(1);
        extra[..4].copy_from_slice(&counter.to_le_bytes());
    }
}

/// Sign without grinding (plain RFC 6979 + low S), for vectors.
pub fn sign_no_grind(sk: &SecretKey, msg: &[u8; 32]) -> Option<Signature> {
    sign_with(sk, msg, None)
}

/// Verify a signature on public data. High-S signatures are rejected
/// (Bitcoin standardness), as are r or s outside [1, n-1].
pub fn verify(pk: &PublicKey, msg: &[u8; 32], sig: &Signature) -> bool {
    let (Some(r), Some(s)) = (Scalar::from_bytes(&sig.r), Scalar::from_bytes(&sig.s)) else {
        return false;
    };
    if r.is_zero().unwrap_public() || s.is_zero().unwrap_public() || s.is_high().unwrap_public() {
        return false;
    }
    let z = Scalar::from_bytes_reduce(msg);
    let w = s.invert();
    let u1 = z.mul(&w);
    let u2 = r.mul(&w);
    let p = Point::generator().mul(&u1).add(&pk.to_point().mul(&u2));
    match x_mod_n(&p) {
        Some(x) => x.ct_eq(&r).unwrap_public(),
        None => false,
    }
}

impl Signature {
    pub fn from_compact(b: &[u8; 64]) -> Signature {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&b[..32]);
        s.copy_from_slice(&b[32..]);
        Signature { r, s }
    }

    pub fn to_compact(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }

    /// DER encoding (strict, minimal); returns the length written.
    pub fn to_der(&self, out: &mut [u8; MAX_DER_LEN]) -> usize {
        fn int(v: &[u8; 32], out: &mut [u8], pos: &mut usize) {
            let start = v.iter().position(|&b| b != 0).unwrap_or(31);
            let pad = v[start] & 0x80 != 0;
            let len = 32 - start + pad as usize;
            out[*pos] = 0x02;
            out[*pos + 1] = len as u8;
            *pos += 2;
            if pad {
                out[*pos] = 0;
                *pos += 1;
            }
            out[*pos..*pos + 32 - start].copy_from_slice(&v[start..]);
            *pos += 32 - start;
        }
        let mut pos = 2;
        int(&self.r, out, &mut pos);
        int(&self.s, out, &mut pos);
        out[0] = 0x30;
        out[1] = (pos - 2) as u8;
        pos
    }

    /// Parse a strict DER signature (BIP-66 rules, no sighash byte).
    pub fn from_der(der: &[u8]) -> Option<Signature> {
        if der.len() < 8 || der.len() > MAX_DER_LEN || der[0] != 0x30 || der[1] as usize != der.len() - 2 {
            return None;
        }
        fn int(der: &[u8], pos: &mut usize) -> Option<[u8; 32]> {
            if *der.get(*pos)? != 0x02 {
                return None;
            }
            let len = *der.get(*pos + 1)? as usize;
            let body = der.get(*pos + 2..*pos + 2 + len)?;
            if len == 0 || body[0] & 0x80 != 0 {
                return None; // empty or negative
            }
            if len > 1 && body[0] == 0 && body[1] & 0x80 == 0 {
                return None; // non-minimal padding
            }
            let digits = if body[0] == 0 { &body[1..] } else { body };
            if digits.len() > 32 {
                return None;
            }
            let mut v = [0u8; 32];
            v[32 - digits.len()..].copy_from_slice(digits);
            *pos += 2 + len;
            Some(v)
        }
        let mut pos = 2;
        let r = int(der, &mut pos)?;
        let s = int(der, &mut pos)?;
        (pos == der.len()).then_some(Signature { r, s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_round_trip_and_strictness() {
        let sig = Signature {
            r: [0x7F; 32],
            s: {
                let mut s = [0u8; 32];
                s[31] = 1;
                s
            },
        };
        let mut der = [0u8; MAX_DER_LEN];
        let n = sig.to_der(&mut der);
        assert_eq!(Signature::from_der(&der[..n]), Some(sig));
        // high bit needs a zero pad
        let sig2 = Signature {
            r: [0x80; 32],
            s: [0x01; 32],
        };
        let n2 = sig2.to_der(&mut der);
        assert_eq!(n2, 2 + 2 + 33 + 2 + 32);
        assert_eq!(Signature::from_der(&der[..n2]), Some(sig2));
        // non-minimal padding is rejected
        let bad = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
        assert_eq!(Signature::from_der(&bad), None);
    }
}
