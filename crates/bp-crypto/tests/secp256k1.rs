//! secp256k1: known multiples of G, edge cases, and differential tests
//! against libsecp256k1 (the `secp256k1` crate, dev-dependency only).

use bp_crypto::secp256k1::field::Fe;
use bp_crypto::secp256k1::{Point, PublicKey, Scalar, SecretKey};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

struct XorShift(u64);
impl XorShift {
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

const N_MINUS_1: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";

fn pk_hex(k: &str) -> String {
    hex(&SecretKey::from_bytes(&unhex32(k))
        .unwrap()
        .public_key()
        .serialize())
}

#[test]
fn small_multiples_of_g() {
    let one = "0000000000000000000000000000000000000000000000000000000000000001";
    let two = "0000000000000000000000000000000000000000000000000000000000000002";
    let three = "0000000000000000000000000000000000000000000000000000000000000003";
    assert_eq!(
        pk_hex(one),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    assert_eq!(
        pk_hex(two),
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    );
    assert_eq!(
        pk_hex(three),
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    );
    // (n-1)G = -G: same x, odd y
    assert_eq!(
        pk_hex(N_MINUS_1),
        "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
}

#[test]
fn rejects_invalid_secret_keys() {
    assert!(SecretKey::from_bytes(&[0u8; 32]).is_none());
    let n = unhex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    assert!(SecretKey::from_bytes(&n).is_none());
    assert!(SecretKey::from_bytes(&[0xff; 32]).is_none());
    assert!(SecretKey::from_bytes(&unhex32(N_MINUS_1)).is_some());
}

#[test]
fn group_laws() {
    let g = Point::generator();
    // G + (-G) = infinity, infinity + G = G, 2G = G + G
    assert!(g.add(&g.neg()).is_infinity().unwrap_public());
    let a = PublicKey::from_point(&Point::INFINITY.add(&g)).unwrap();
    assert_eq!(a, PublicKey::from_point(&g).unwrap());
    let two = PublicKey::from_point(&g.double()).unwrap();
    let two_b = PublicKey::from_point(&g.add(&g)).unwrap();
    assert_eq!(two, two_b);
    // n * G = infinity
    let n_minus_1 = Scalar::from_bytes(&unhex32(N_MINUS_1)).unwrap();
    assert!(g.mul(&n_minus_1).add(&g).is_infinity().unwrap_public());
}

#[test]
fn field_inverse_and_sqrt() {
    let mut rng = XorShift(5);
    for _ in 0..200 {
        let mut b = rng.bytes32();
        b[0] &= 0x7f;
        let a = Fe::from_bytes(&b).unwrap();
        if a.is_zero().unwrap_public() {
            continue;
        }
        assert!(a.mul(&a.invert()).ct_eq(&Fe::ONE).unwrap_public());
        let sq = a.square();
        let r = sq.sqrt().expect("squares have roots");
        assert!(r.square().ct_eq(&sq).unwrap_public());
    }
}

#[test]
fn parse_round_trip_and_rejects_off_curve() {
    let mut rng = XorShift(9);
    for _ in 0..100 {
        let Some(sk) = SecretKey::from_bytes(&rng.bytes32()) else {
            continue;
        };
        let pk = sk.public_key();
        assert_eq!(PublicKey::parse(&pk.serialize()).unwrap(), pk);
        assert_eq!(PublicKey::parse(&pk.serialize_uncompressed()).unwrap(), pk);
    }
    // x = 5 is not on the curve (5^3 + 7 = 132 is a non-residue mod p)
    let mut bad = [0u8; 33];
    bad[0] = 0x02;
    bad[32] = 5;
    assert!(PublicKey::parse(&bad).is_none());
}

#[test]
fn differential_public_keys_vs_libsecp256k1() {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = XorShift(0x5EC9_256B);
    let mut edge: Vec<[u8; 32]> = vec![unhex32(N_MINUS_1)];
    for i in 0..32 {
        let mut b = [0u8; 32];
        b[31 - i] = 1; // powers of 256
        edge.push(b);
        let mut f = [0u8; 32];
        f[..i + 1].fill(0x7f); // patterns with many equal nibbles
        edge.push(f);
    }
    let count = if cfg!(debug_assertions) { 2000 } else { 10000 };
    let randoms = (0..count).map(|_| rng.bytes32());
    let mut checked = 0;
    for b in edge.into_iter().chain(randoms) {
        let Some(ours) = SecretKey::from_bytes(&b) else {
            continue;
        };
        let theirs = secp256k1::SecretKey::from_slice(&b).unwrap();
        let theirs_pk = secp256k1::PublicKey::from_secret_key(&secp, &theirs);
        assert_eq!(
            ours.public_key().serialize(),
            theirs_pk.serialize(),
            "key {}",
            hex(&b)
        );
        checked += 1;
    }
    assert!(checked > 1900);
}

#[test]
fn differential_tweaks_vs_libsecp256k1() {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = XorShift(77);
    for _ in 0..300 {
        let (k, t) = (rng.bytes32(), rng.bytes32());
        let (Some(sk), Some(tw)) = (SecretKey::from_bytes(&k), Scalar::from_bytes(&t)) else {
            continue;
        };
        let their_sk = secp256k1::SecretKey::from_slice(&k).unwrap();
        let their_t = secp256k1::Scalar::from_be_bytes(t).unwrap();
        // scalar addition mod n
        let ours_add = sk.scalar().add(&tw).to_bytes();
        let theirs_add = their_sk.add_tweak(&their_t).unwrap().secret_bytes();
        assert_eq!(ours_add, theirs_add);
        // negation mod n
        assert_eq!(sk.scalar().neg().to_bytes(), their_sk.negate().secret_bytes());
        // point tweak: P + tG
        let their_pk = secp256k1::PublicKey::from_secret_key(&secp, &their_sk);
        let ours_pt = sk.public_key().add_tweak(&tw).unwrap().serialize();
        let theirs_pt = their_pk.add_exp_tweak(&secp, &their_t).unwrap().serialize();
        assert_eq!(ours_pt, theirs_pt);
    }
}

/// dudect-style smoke test: compare k*G timing for a sparse scalar (k = 1)
/// against random scalars with Welch's t-test. Host timing is noisy and
/// this is only indicative; real verification happens on the target chip.
/// Run with: cargo test --release -p bp-crypto --test secp256k1 -- --ignored --nocapture
#[test]
#[ignore]
fn timing_smoke_test() {
    use std::time::Instant;
    let mut rng = XorShift(1234);
    let g = Point::generator();
    let mut one = [0u8; 32];
    one[31] = 1;
    let fixed = Scalar::from_bytes(&one).unwrap();
    let (mut a, mut b) = (Vec::new(), Vec::new());
    for i in 0..4000 {
        let s = if i % 2 == 0 {
            fixed
        } else {
            loop {
                if let Some(s) = Scalar::from_bytes(&rng.bytes32()) {
                    break s;
                }
            }
        };
        let t = Instant::now();
        let p = g.mul(&s);
        std::hint::black_box(p);
        let ns = t.elapsed().as_nanos() as f64;
        if i % 2 == 0 {
            a.push(ns)
        } else {
            b.push(ns)
        }
    }
    let stats = |v: &mut Vec<f64>| {
        v.sort_by(|x, y| x.partial_cmp(y).unwrap());
        v.truncate(v.len() * 9 / 10); // drop the slowest 10% (scheduler noise)
        let m = v.iter().sum::<f64>() / v.len() as f64;
        let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() - 1) as f64;
        (m, var, v.len() as f64)
    };
    let (ma, va, na) = stats(&mut a);
    let (mb, vb, nb) = stats(&mut b);
    let t = (ma - mb) / (va / na + vb / nb).sqrt();
    println!("k=1: {ma:.0} ns, random: {mb:.0} ns, Welch t = {t:.2} (|t| < 4.5 suggests no leak)");
    assert!(t.abs() < 10.0, "large timing difference: t = {t}");
}
