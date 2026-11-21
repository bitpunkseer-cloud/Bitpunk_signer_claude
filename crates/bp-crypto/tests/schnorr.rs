//! BIP-340 Schnorr signatures and BIP-341 tweaks: the official vectors,
//! byte-for-byte equality with libsecp256k1 (test-only `secp256k1` crate)
//! for the same aux_rand, cross verification and tamper rejection.

#[path = "data/bip340_vectors.rs"]
mod bip340;
#[path = "data/bip341_tweak_vectors.rs"]
mod bip341;

use bp_crypto::hashes::tagged_hash;
use bp_crypto::secp256k1::schnorr::{self, lift_x};
use bp_crypto::secp256k1::SecretKey;
use secp256k1 as ref_secp;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        b
    }
}

fn key(rng: &mut Rng) -> ([u8; 32], SecretKey) {
    loop {
        let b = rng.bytes32();
        if let Some(k) = SecretKey::from_bytes(&b) {
            return (b, k);
        }
    }
}

#[test]
fn bip340_official_vectors() {
    for &(i, sk, pk, aux, msg, sig, ok, comment) in bip340::BIP340_VECTORS {
        let px = arr32(pk);
        let msg = unhex(msg);
        let sig: [u8; 64] = unhex(sig).try_into().unwrap();
        if !sk.is_empty() {
            let k = SecretKey::from_bytes(&arr32(sk)).unwrap();
            assert_eq!(k.public_key().x_only(), px, "vector {i}: public key");
            let ours = schnorr::sign(&k, &msg, &arr32(aux)).expect("signs");
            assert_eq!(ours, sig, "vector {i}: signature");
        }
        assert_eq!(
            schnorr::verify(&px, &msg, &sig),
            ok,
            "vector {i}: verify ({comment})"
        );
    }
}

#[test]
fn signatures_match_libsecp_byte_for_byte() {
    let secp = ref_secp::Secp256k1::new();
    let mut rng = Rng(340);
    for i in 0..1500 {
        let (b, k) = key(&mut rng);
        let msg = rng.bytes32();
        let aux = if i % 2 == 0 { [0u8; 32] } else { rng.bytes32() };
        let kp = ref_secp::Keypair::from_seckey_slice(&secp, &b).unwrap();
        let m = ref_secp::Message::from_digest(msg);
        let theirs = secp.sign_schnorr_with_aux_rand(&m, &kp, &aux);
        let ours = schnorr::sign(&k, &msg, &aux).unwrap();
        assert_eq!(ours, *theirs.as_ref(), "case {i}");
        if i % 2 == 0 {
            // a NULL aux pointer in libsecp256k1 equals 32 zero bytes
            assert_eq!(ours, *secp.sign_schnorr_no_aux_rand(&m, &kp).as_ref());
        }
    }
}

#[test]
fn cross_verification_and_tampering() {
    let secp = ref_secp::Secp256k1::new();
    let mut rng = Rng(7);
    for i in 0..300 {
        let (b, k) = key(&mut rng);
        let msg = rng.bytes32();
        let kp = ref_secp::Keypair::from_seckey_slice(&secp, &b).unwrap();
        let (xpk, _) = kp.x_only_public_key();
        let px = xpk.serialize();
        let m = ref_secp::Message::from_digest(msg);
        // theirs verifies with ours
        let theirs = secp.sign_schnorr_with_aux_rand(&m, &kp, &rng.bytes32());
        assert!(schnorr::verify(&px, &msg, theirs.as_ref()));
        // ours verifies with theirs
        let ours = schnorr::sign(&k, &msg, &[0; 32]).unwrap();
        let sig = ref_secp::schnorr::Signature::from_slice(&ours).unwrap();
        assert!(secp.verify_schnorr(&sig, &m, &xpk).is_ok());
        // any flipped bit in the signature, message or key is rejected
        let mut bad = ours;
        bad[i % 64] ^= 1 << (i % 8);
        assert!(!schnorr::verify(&px, &msg, &bad));
        let mut msg2 = msg;
        msg2[i % 32] ^= 0x80;
        assert!(!schnorr::verify(&px, &msg2, &ours));
        let mut px2 = px;
        px2[31] ^= 1;
        assert!(!schnorr::verify(&px2, &msg, &ours));
    }
}

#[test]
fn rejects_out_of_range_values() {
    let k = SecretKey::from_bytes(&[0x11; 32]).unwrap();
    let px = k.public_key().x_only();
    let msg = [0x22; 32];
    let sig = schnorr::sign(&k, &msg, &[0; 32]).unwrap();
    assert!(schnorr::verify(&px, &msg, &sig));
    // s + n (if it fits in 256 bits) must not verify
    let n = arr32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let mut s = [0u8; 32];
    let mut carry = 0u16;
    for j in (0..32).rev() {
        let v = sig[32 + j] as u16 + n[j] as u16 + carry;
        s[j] = v as u8;
        carry = v >> 8;
    }
    if carry == 0 {
        let mut bad = sig;
        bad[32..].copy_from_slice(&s);
        assert!(!schnorr::verify(&px, &msg, &bad));
    }
    // r = p is rejected
    let mut bad = sig;
    bad[..32].copy_from_slice(&arr32(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    ));
    assert!(!schnorr::verify(&px, &msg, &bad));
    // a key that is not on the curve
    let mut five = [0u8; 32];
    five[31] = 5;
    assert!(lift_x(&five).is_none());
    assert!(!schnorr::verify(&five, &msg, &sig));
}

#[test]
fn lift_x_matches_libsecp() {
    let mut rng = Rng(11);
    let mut found = 0;
    for _ in 0..500 {
        let x = rng.bytes32();
        let ours = lift_x(&x);
        let theirs = ref_secp::XOnlyPublicKey::from_slice(&x).ok();
        assert_eq!(ours.is_some(), theirs.is_some());
        if let (Some(a), Some(b)) = (ours, theirs) {
            let full = b.public_key(ref_secp::Parity::Even);
            assert_eq!(a.serialize(), full.serialize());
            found += 1;
        }
    }
    assert!(found > 200);
}

#[test]
fn bip341_tweak_vectors() {
    for &(internal, root, tweak, output, parity) in bip341::SCRIPT_PUBKEY {
        let root = (!root.is_empty()).then(|| arr32(root));
        let p = arr32(internal);
        let mut data = p.to_vec();
        data.extend_from_slice(root.as_ref().map_or(&[][..], |r| &r[..]));
        assert_eq!(tagged_hash(b"TapTweak", &[&data]), arr32(tweak));
        let (q, odd) = schnorr::tweak_public_key(&p, root.as_ref()).unwrap();
        assert_eq!(q, arr32(output));
        if parity >= 0 {
            assert_eq!(odd, parity == 1);
        }
    }
    for &(sk, root, internal, _tweak, tweaked, sighash, witness) in bip341::KEY_PATH_SPENDING {
        let root = (!root.is_empty()).then(|| arr32(root));
        let k = SecretKey::from_bytes(&arr32(sk)).unwrap();
        assert_eq!(k.public_key().x_only(), arr32(internal));
        let t = schnorr::tweak_secret_key(&k, root.as_ref()).unwrap();
        assert_eq!(t.to_bytes(), arr32(tweaked));
        // the tweaked key's point is the output key
        let (q, _) = schnorr::tweak_public_key(&arr32(internal), root.as_ref()).unwrap();
        assert_eq!(t.public_key().x_only(), q);
        // the published witness signatures were made with aux_rand = 0:
        // ours are identical and verify against Q
        let w = unhex(witness);
        let sig: [u8; 64] = w[..64].try_into().unwrap();
        let msg = arr32(sighash);
        assert!(schnorr::verify(&q, &msg, &sig));
        assert_eq!(schnorr::sign(&t, &msg, &[0; 32]).unwrap(), sig);
    }
}

#[test]
fn tweaks_match_libsecp() {
    let secp = ref_secp::Secp256k1::new();
    let mut rng = Rng(99);
    for i in 0..300 {
        let (b, k) = key(&mut rng);
        let root = (i % 2 == 1).then(|| rng.bytes32());
        let kp = ref_secp::Keypair::from_seckey_slice(&secp, &b).unwrap();
        let (xpk, _) = kp.x_only_public_key();
        let px = xpk.serialize();
        let mut data = px.to_vec();
        data.extend_from_slice(root.as_ref().map_or(&[][..], |r| &r[..]));
        let t = ref_secp::Scalar::from_be_bytes(tagged_hash(b"TapTweak", &[&data])).unwrap();
        let (q, parity) = xpk.add_tweak(&secp, &t).unwrap();
        let (ours_q, ours_odd) = schnorr::tweak_public_key(&px, root.as_ref()).unwrap();
        assert_eq!(ours_q, q.serialize());
        assert_eq!(ours_odd, parity == ref_secp::Parity::Odd);
        let tk = kp.add_xonly_tweak(&secp, &t).unwrap();
        let ours_k = schnorr::tweak_secret_key(&k, root.as_ref()).unwrap();
        assert_eq!(ours_k.to_bytes(), tk.secret_bytes());
        // key-path signature with the tweaked key equals libsecp256k1's
        let msg = rng.bytes32();
        let m = ref_secp::Message::from_digest(msg);
        let theirs = secp.sign_schnorr_no_aux_rand(&m, &tk);
        assert_eq!(schnorr::sign(&ours_k, &msg, &[0; 32]).unwrap(), *theirs.as_ref());
    }
}

/// dudect-style smoke test: one signature with a sparse key (d = 1) against
/// random keys, Welch's t-test on the fastest 90%. Host timing is only
/// indicative.
/// cargo test --release -p bp-crypto --test schnorr timing -- --ignored --nocapture
#[test]
#[ignore]
fn timing_smoke_test() {
    use std::time::Instant;
    let mut rng = Rng(77);
    let mut one = [0u8; 32];
    one[31] = 1;
    let sparse = SecretKey::from_bytes(&one).unwrap();
    let msg = rng.bytes32();
    let (mut a, mut b) = (Vec::new(), Vec::new());
    for i in 0..3000 {
        let sk = if i % 2 == 0 {
            sparse.clone()
        } else {
            key(&mut rng).1
        };
        let t = Instant::now();
        std::hint::black_box(schnorr::sign(&sk, &msg, &[0; 32]));
        let ns = t.elapsed().as_nanos() as f64;
        if i % 2 == 0 {
            a.push(ns)
        } else {
            b.push(ns)
        }
    }
    let stats = |v: &mut Vec<f64>| {
        v.sort_by(|x, y| x.partial_cmp(y).unwrap());
        v.truncate(v.len() * 9 / 10);
        let m = v.iter().sum::<f64>() / v.len() as f64;
        let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() - 1) as f64;
        (m, var, v.len() as f64)
    };
    let (ma, va, na) = stats(&mut a);
    let (mb, vb, nb) = stats(&mut b);
    let t = (ma - mb) / (va / na + vb / nb).sqrt();
    println!("schnorr sign: d=1 {ma:.0} ns, random {mb:.0} ns, t = {t:.2}");
    assert!(t.abs() < 10.0, "timing difference: t = {t}");
}
