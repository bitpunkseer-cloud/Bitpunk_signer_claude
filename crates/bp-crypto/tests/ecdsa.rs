//! ECDSA against libsecp256k1 (test-only `secp256k1` crate): byte-identical
//! signatures with and without low-R grinding, cross verification, and the
//! scalar arithmetic it relies on.

use bp_crypto::secp256k1::ecdsa::{self, Signature, MAX_DER_LEN};
use bp_crypto::secp256k1::{PublicKey, Scalar, SecretKey};
use secp256k1 as ref_secp;

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

fn key(rng: &mut Rng) -> ([u8; 32], SecretKey, ref_secp::SecretKey) {
    loop {
        let b = rng.bytes32();
        if let (Some(a), Ok(r)) = (SecretKey::from_bytes(&b), ref_secp::SecretKey::from_slice(&b)) {
            return (b, a, r);
        }
    }
}

#[test]
fn scalar_mul_matches_libsecp() {
    let mut rng = Rng(1);
    for i in 0..2000 {
        let (a, sa, ra) = key(&mut rng);
        let mut bb = rng.bytes32();
        if i % 7 == 0 {
            bb = [0xFF; 32]; // near-n values
            bb[0] = 0xFF;
        }
        let Some(b) = Scalar::from_bytes(&bb) else {
            continue;
        };
        let ours = sa.scalar().mul(&b).to_bytes();
        let tweak = ref_secp::Scalar::from_be_bytes(bb).unwrap();
        match ra.mul_tweak(&tweak) {
            Ok(t) => assert_eq!(ours, t.secret_bytes(), "#{i} {a:02x?}"),
            Err(_) => assert_eq!(ours, [0u8; 32]),
        }
    }
}

#[test]
fn scalar_invert() {
    let mut rng = Rng(2);
    for _ in 0..300 {
        let (_, sa, _) = key(&mut rng);
        let x = *sa.scalar();
        let one = x.mul(&x.invert()).to_bytes();
        let mut want = [0u8; 32];
        want[31] = 1;
        assert_eq!(one, want);
    }
    assert_eq!(Scalar::ZERO.invert().to_bytes(), [0u8; 32]);
}

#[test]
fn signatures_match_libsecp_byte_for_byte() {
    let ctx = ref_secp::Secp256k1::new();
    let mut rng = Rng(3);
    let mut ground = 0;
    for i in 0..1500 {
        let (_, sk, rsk) = key(&mut rng);
        let msg = if i == 0 {
            [0u8; 32]
        } else if i == 1 {
            [0xFF; 32]
        } else {
            rng.bytes32()
        };
        let m = ref_secp::Message::from_digest(msg);
        // plain RFC 6979
        let plain = ecdsa::sign_no_grind(&sk, &msg).unwrap();
        assert_eq!(
            plain.to_compact(),
            ctx.sign_ecdsa(&m, &rsk).serialize_compact(),
            "plain #{i}"
        );
        // low R
        let ours = ecdsa::sign(&sk, &msg);
        let theirs = ctx.sign_ecdsa_low_r(&m, &rsk);
        assert_eq!(ours.to_compact(), theirs.serialize_compact(), "low-r #{i}");
        assert!(ours.r[0] < 0x80);
        ground += (plain != ours) as u32;
        // DER is identical too, and at most 71 bytes with low R
        let mut der = [0u8; MAX_DER_LEN];
        let n = ours.to_der(&mut der);
        assert_eq!(&der[..n], &theirs.serialize_der()[..]);
        assert!(n <= 71);
        assert_eq!(Signature::from_der(&der[..n]), Some(ours));
    }
    assert!(ground > 500, "grinding happened {ground} times");
}

#[test]
fn recoverable_signatures_match_libsecp_and_recover() {
    use ref_secp::ecdsa::{RecoverableSignature, RecoveryId};
    let ctx = ref_secp::Secp256k1::new();
    let mut rng = Rng(9);
    let mut ids = [0u32; 4];
    for i in 0..600 {
        let (_, sk, rsk) = key(&mut rng);
        let msg = rng.bytes32();
        let m = ref_secp::Message::from_digest(msg);
        let (sig, recid) = ecdsa::sign_recoverable(&sk, &msg).unwrap();
        let theirs = ctx.sign_ecdsa_recoverable(&m, &rsk);
        let (tid, tbytes) = theirs.serialize_compact();
        assert_eq!((recid as i32, sig.to_compact()), (tid.to_i32(), tbytes), "#{i}");
        ids[recid as usize] += 1;
        let pk = sk.public_key();
        assert_eq!(ecdsa::recover(&msg, &sig, recid), Some(pk));
        // a wrong recovery id gives another key (or none)
        assert_ne!(ecdsa::recover(&msg, &sig, recid ^ 1), Some(pk));
        // high S still recovers the same key (Core accepts it)
        let high_s = Scalar::from_bytes(&sig.s).unwrap().neg().to_bytes();
        let hs = Signature { r: sig.r, s: high_s };
        assert_eq!(ecdsa::recover(&msg, &hs, recid ^ 1), Some(pk));
        // arbitrary (r, s, id), including R.x >= n: same answer as libsecp
        let mut r = rng.bytes32();
        if i % 4 == 0 {
            r[..16].fill(0); // small r, so r + n < p
        }
        let s2 = rng.bytes32();
        let id = (i % 4) as u8;
        let mut c = [0u8; 64];
        c[..32].copy_from_slice(&r);
        c[32..].copy_from_slice(&s2);
        let want = RecoverableSignature::from_compact(&c, RecoveryId::from_i32(id as i32).unwrap())
            .ok()
            .and_then(|rs| ctx.recover_ecdsa(&m, &rs).ok())
            .map(|k| k.serialize());
        let got = ecdsa::recover(&msg, &Signature::from_compact(&c), id).map(|k| k.serialize());
        assert_eq!(got, want, "arbitrary #{i} id {id}");
    }
    assert!(ids[0] > 200 && ids[1] > 200, "{ids:?}");
    assert_eq!(
        ecdsa::recover(
            &[1; 32],
            &Signature {
                r: [1; 32],
                s: [1; 32]
            },
            4
        ),
        None
    );
}

#[test]
fn cross_verification() {
    let ctx = ref_secp::Secp256k1::new();
    let mut rng = Rng(4);
    for i in 0..400 {
        let (_, sk, rsk) = key(&mut rng);
        let pk: PublicKey = sk.public_key();
        let rpk = ref_secp::PublicKey::from_secret_key(&ctx, &rsk);
        let msg = rng.bytes32();
        let m = ref_secp::Message::from_digest(msg);
        let ours = ecdsa::sign(&sk, &msg);
        let rsig = ref_secp::ecdsa::Signature::from_compact(&ours.to_compact()).unwrap();
        assert!(ctx.verify_ecdsa(&m, &rsig, &rpk).is_ok(), "#{i}");
        let theirs = ctx.sign_ecdsa(&m, &rsk);
        assert!(ecdsa::verify(
            &pk,
            &msg,
            &Signature::from_compact(&theirs.serialize_compact())
        ));
        // wrong message, wrong key, high S, corrupted r all fail
        let mut other = msg;
        other[0] ^= 1;
        assert!(!ecdsa::verify(&pk, &other, &ours));
        let (_, sk2, _) = key(&mut rng);
        assert!(!ecdsa::verify(&sk2.public_key(), &msg, &ours));
        let s = Scalar::from_bytes(&ours.s).unwrap();
        let high = Signature {
            r: ours.r,
            s: s.neg().to_bytes(),
        };
        assert!(!ecdsa::verify(&pk, &msg, &high));
        let mut bad = ours;
        bad.r[31] ^= 1;
        assert!(!ecdsa::verify(&pk, &msg, &bad));
    }
}

#[test]
fn rejects_out_of_range_values() {
    let mut rng = Rng(5);
    let (_, sk, _) = key(&mut rng);
    let pk = sk.public_key();
    let msg = rng.bytes32();
    let good = ecdsa::sign(&sk, &msg);
    for (r, s) in [
        ([0u8; 32], good.s),
        (good.r, [0u8; 32]),
        ([0xFF; 32], good.s),
        (good.r, [0xFF; 32]),
    ] {
        assert!(!ecdsa::verify(&pk, &msg, &Signature { r, s }));
    }
}

mod wycheproof {
    include!("data/wycheproof_ecdsa_bitcoin.rs");
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Wycheproof (Bitcoin variant): every valid signature verifies and every
/// invalid one (malleability, BER quirks, out-of-range values, edge-case
/// arithmetic) is rejected by strict DER parsing plus verification.
#[test]
fn wycheproof_bitcoin_vectors() {
    let mut count = 0;
    for (pk_hex, tests) in wycheproof::WYCHEPROOF_ECDSA_BITCOIN {
        let pk = PublicKey::parse(&unhex(pk_hex)).expect("valid test key");
        for (i, (msg, sig, valid)) in tests.iter().enumerate() {
            let digest = bp_crypto::sha256::Sha256::digest(&unhex(msg));
            let ok = match Signature::from_der(&unhex(sig)) {
                Some(s) => ecdsa::verify(&pk, &digest, &s),
                None => false,
            };
            assert_eq!(ok, *valid, "key {pk_hex} test {i} sig {sig}");
            count += 1;
        }
    }
    assert_eq!(count, 464);
}

/// dudect-style smoke test for signing: one RFC 6979 attempt with a sparse
/// key (d = 1) against random keys, and inversion of a sparse scalar
/// against random ones, compared with Welch's t-test. (Grinding repeats
/// whole attempts; the number of repeats follows from public data in the
/// same way as in Bitcoin Core.) Host timing is only indicative.
/// cargo test --release -p bp-crypto --test ecdsa timing -- --ignored --nocapture
#[test]
#[ignore]
fn timing_smoke_test() {
    use std::time::Instant;
    fn welch(mut a: Vec<f64>, mut b: Vec<f64>) -> (f64, f64, f64) {
        let stats = |v: &mut Vec<f64>| {
            v.sort_by(|x, y| x.partial_cmp(y).unwrap());
            v.truncate(v.len() * 9 / 10);
            let m = v.iter().sum::<f64>() / v.len() as f64;
            let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() - 1) as f64;
            (m, var, v.len() as f64)
        };
        let (ma, va, na) = stats(&mut a);
        let (mb, vb, nb) = stats(&mut b);
        (ma, mb, (ma - mb) / (va / na + vb / nb).sqrt())
    }
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
        std::hint::black_box(ecdsa::sign_no_grind(&sk, &msg));
        let ns = t.elapsed().as_nanos() as f64;
        if i % 2 == 0 {
            a.push(ns)
        } else {
            b.push(ns)
        }
    }
    let (ma, mb, t) = welch(a, b);
    println!("sign: d=1 {ma:.0} ns, random {mb:.0} ns, t = {t:.2}");
    let (mut a, mut b) = (Vec::new(), Vec::new());
    for i in 0..6000 {
        let s = if i % 2 == 0 {
            *sparse.scalar()
        } else {
            *key(&mut rng).1.scalar()
        };
        let t = Instant::now();
        std::hint::black_box(s.invert());
        let ns = t.elapsed().as_nanos() as f64;
        if i % 2 == 0 {
            a.push(ns)
        } else {
            b.push(ns)
        }
    }
    let (ma2, mb2, t2) = welch(a, b);
    println!("invert: 1 {ma2:.0} ns, random {mb2:.0} ns, t = {t2:.2}");
    assert!(t.abs() < 10.0 && t2.abs() < 10.0, "timing difference: {t} {t2}");
}
