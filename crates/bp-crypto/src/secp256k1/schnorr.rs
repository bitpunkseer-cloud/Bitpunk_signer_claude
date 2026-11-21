//! BIP-340 Schnorr signatures and BIP-341 Taproot key tweaks.
//!
//! Signing follows the BIP-340 reference algorithm step by step: the key is
//! negated if its point has odd y, the nonce is derived from the key masked
//! with H_aux(aux_rand), the public key and the message, and the nonce is
//! negated if R has odd y. Both negations are constant-time selections.
//! Every signature is verified before it is returned, as BIP-340
//! recommends against fault attacks.
//!
//! Bitpunk signs with aux_rand = 32 zero bytes (deterministic, decision 4
//! of the M5 plan). That is identical to libsecp256k1 with a NULL aux
//! pointer.

use super::field::Fe;
use super::point::{Point, PublicKey};
use super::scalar::{Scalar, SecretKey};
use crate::hashes::tagged_hash;
use crate::secret::wipe;

pub type Signature = [u8; 64];

/// Even-y point with the given x coordinate (BIP-340 `lift_x`), or `None`
/// if x >= p or x is not on the curve.
pub fn lift_x(x: &[u8; 32]) -> Option<PublicKey> {
    let fx = Fe::from_bytes(x)?;
    let rhs = fx.square().mul(&fx).add(&Fe::from_u64(7));
    let y = rhs.sqrt()?;
    let even = if y.is_odd().unwrap_public() { y.neg() } else { y };
    PublicKey::from_point(&Point::from_affine(fx, even))
}

/// The secret key whose point has even y: d or n - d.
fn even_key(sk: &SecretKey) -> (Scalar, PublicKey) {
    let pk = sk.public_key();
    let d = *sk.scalar();
    // the parity of P is public (it is visible in the full public key)
    let d = Scalar::select(&d, &d.neg(), pk.y_is_odd());
    (d, pk)
}

fn challenge(r: &[u8; 32], px: &[u8; 32], msg: &[u8]) -> Scalar {
    Scalar::from_bytes_reduce(&tagged_hash(b"BIP0340/challenge", &[r, px, msg]))
}

/// Sign `msg` (32 bytes for Bitcoin; any length is allowed by BIP-340) with
/// auxiliary randomness `aux`. `None` only if the derived nonce is zero
/// (probability ~2^-256) or the self-check fails (a fault).
pub fn sign(sk: &SecretKey, msg: &[u8], aux: &[u8; 32]) -> Option<Signature> {
    let (mut d, pk) = even_key(sk);
    let px = pk.x_only();
    // t = bytes(d) xor H_aux(aux)
    let mut t = d.to_bytes();
    let mask = tagged_hash(b"BIP0340/aux", &[aux]);
    for (a, b) in t.iter_mut().zip(mask.iter()) {
        *a ^= b;
    }
    let mut rand = tagged_hash(b"BIP0340/nonce", &[&t, &px, msg]);
    wipe(&mut t);
    let mut k = Scalar::from_bytes_reduce(&rand);
    wipe(&mut rand);
    if k.is_zero().unwrap_public() {
        d.wipe();
        return None;
    }
    let rp = Point::generator().mul(&k);
    let (rx, ry) = rp.to_affine().expect("k in [1, n) never gives infinity");
    k = Scalar::select(&k, &k.neg(), ry.is_odd());
    let r = rx.to_bytes();
    let e = challenge(&r, &px, msg);
    let mut s = k.add(&e.mul(&d));
    k.wipe();
    d.wipe();
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    sig[32..].copy_from_slice(&s.to_bytes());
    s.wipe();
    verify(&px, msg, &sig).then_some(sig)
}

/// Verify a BIP-340 signature against an x-only public key.
pub fn verify(px: &[u8; 32], msg: &[u8], sig: &Signature) -> bool {
    let Some(pk) = lift_x(px) else {
        return false;
    };
    let r: [u8; 32] = sig[..32].try_into().expect("32 bytes");
    let sb: [u8; 32] = sig[32..].try_into().expect("32 bytes");
    let Some(rx) = Fe::from_bytes(&r) else {
        return false; // r >= p
    };
    let Some(s) = Scalar::from_bytes(&sb) else {
        return false; // s >= n
    };
    let e = challenge(&r, px, msg);
    // R = s*G - e*P
    let rp = Point::generator().mul(&s).add(&pk.to_point().mul(&e).neg());
    match rp.to_affine() {
        Some((x, y)) => !y.is_odd().unwrap_public() && x.ct_eq(&rx).unwrap_public(),
        None => false,
    }
}

/// BIP-341 tweak t = H_TapTweak(x(P) || merkle_root), or `None` if t >= n.
fn tap_tweak(px: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> Option<Scalar> {
    let h = match merkle_root {
        Some(m) => tagged_hash(b"TapTweak", &[px, m]),
        None => tagged_hash(b"TapTweak", &[px]),
    };
    Scalar::from_bytes(&h)
}

/// Taproot output key Q = lift_x(P) + t*G for an x-only internal key and
/// an optional script tree root. Returns x(Q) and whether Q has odd y (the
/// control block parity bit).
pub fn tweak_public_key(internal: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> Option<([u8; 32], bool)> {
    let p = lift_x(internal)?;
    let t = tap_tweak(internal, merkle_root)?;
    let q = p.add_tweak(&t)?;
    Some((q.x_only(), q.has_odd_y()))
}

/// The secret key for the Taproot output key: (d or n - d) + t, where d is
/// the internal key and t the BIP-341 tweak. Its point is Q (possibly with
/// odd y; `sign` handles that).
pub fn tweak_secret_key(sk: &SecretKey, merkle_root: Option<&[u8; 32]>) -> Option<SecretKey> {
    let (mut d, pk) = even_key(sk);
    let Some(t) = tap_tweak(&pk.x_only(), merkle_root) else {
        d.wipe();
        return None;
    };
    let mut sum = d.add(&t);
    d.wipe();
    let out = SecretKey::from_scalar(sum);
    sum.wipe();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lift_x_rejects_bad_x() {
        // x = p is out of range; x = 5 is not on the curve (5^3 + 7 = 132
        // is a non-residue mod p).
        let p = super::super::field::P;
        let mut b = [0u8; 32];
        for (i, limb) in p.iter().enumerate() {
            b[24 - 8 * i..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
        }
        assert!(lift_x(&b).is_none());
        let mut five = [0u8; 32];
        five[31] = 5;
        assert!(lift_x(&five).is_none());
        // the generator's x lifts to G (even y)
        let g = lift_x(&super::super::point::GX).unwrap();
        assert!(!g.has_odd_y());
    }
}
