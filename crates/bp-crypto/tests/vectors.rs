//! Known-answer tests (NIST FIPS 180-4 examples, RFC 4231) and differential
//! tests against the RustCrypto reference crates (dev-dependencies only).

use bp_crypto::drbg::Drbg;
use bp_crypto::{pbkdf2_hmac_sha512, HmacSha512, Sha256, Sha512};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Tiny deterministic generator for test inputs (not crypto).
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn sha256_nist() {
    assert_eq!(
        hex(&Sha256::digest(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&Sha256::digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&Sha256::digest(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    let mut h = Sha256::new();
    for _ in 0..1000 {
        h.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex(&h.finalize()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn sha512_nist() {
    assert_eq!(
        hex(&Sha512::digest(b"")),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
    assert_eq!(
        hex(&Sha512::digest(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(
        hex(&Sha512::digest(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    );
    let mut h = Sha512::new();
    for _ in 0..1000 {
        h.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex(&h.finalize()),
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    );
}

#[test]
fn hmac_sha512_rfc4231() {
    assert_eq!(
        hex(&HmacSha512::mac(&[0x0b; 20], b"Hi There")),
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    );
    assert_eq!(
        hex(&HmacSha512::mac(b"Jefe", b"what do ya want for nothing?")),
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    );
    assert_eq!(
        hex(&HmacSha512::mac(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
    );
}

#[test]
fn sha2_differential_random_lengths_and_split_points() {
    use sha2::Digest;
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    for len in (0..300).chain([511, 512, 513, 1023, 1024, 4096]) {
        let data = rng.bytes(len);
        let split = if len == 0 { 0 } else { (rng.next() as usize) % len };
        let mut a = Sha256::new();
        a.update(&data[..split]);
        a.update(&data[split..]);
        assert_eq!(
            a.finalize().as_slice(),
            sha2::Sha256::digest(&data).as_slice(),
            "sha256 len {len}"
        );
        let mut b = Sha512::new();
        b.update(&data[..split]);
        b.update(&data[split..]);
        assert_eq!(
            b.finalize().as_slice(),
            sha2::Sha512::digest(&data).as_slice(),
            "sha512 len {len}"
        );
    }
}

#[test]
fn hmac_differential() {
    use hmac::Mac;
    let mut rng = XorShift(42);
    for i in 0..200 {
        let key = rng.bytes((i * 7) % 300);
        let msg = rng.bytes((i * 13) % 500);
        let mut r = hmac::Hmac::<sha2::Sha512>::new_from_slice(&key).unwrap();
        r.update(&msg);
        assert_eq!(
            HmacSha512::mac(&key, &msg).as_slice(),
            r.finalize().into_bytes().as_slice()
        );
    }
}

#[test]
fn pbkdf2_differential() {
    let mut rng = XorShift(7);
    for (iters, out_len) in [(1u32, 64usize), (2, 64), (3, 100), (2048, 64), (17, 13)] {
        let pw = rng.bytes(40);
        let salt_a = rng.bytes(8);
        let salt_b = rng.bytes(5);
        let mut ours = vec![0u8; out_len];
        pbkdf2_hmac_sha512(&pw, &[&salt_a, &salt_b], iters, &mut ours);
        let mut salt = salt_a.clone();
        salt.extend_from_slice(&salt_b);
        let mut theirs = vec![0u8; out_len];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(&pw, &salt, iters, &mut theirs);
        assert_eq!(ours, theirs, "iters {iters} len {out_len}");
    }
}

#[test]
fn drbg_below_is_in_range_and_deterministic() {
    let mut a = Drbg::new(b"seed");
    let mut b = Drbg::new(b"seed");
    for n in 1..100 {
        let x = a.below(n);
        assert!(x < n);
        assert_eq!(x, b.below(n));
    }
}

#[test]
fn ripemd160_known_answers() {
    use bp_crypto::Ripemd160;
    // From the RIPEMD-160 reference page (Bosselaers).
    let cases: [(&[u8], &str); 5] = [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        ),
    ];
    for (m, d) in cases {
        assert_eq!(hex(&Ripemd160::digest(m)), d);
    }
    let mut h = Ripemd160::new();
    for _ in 0..1000 {
        h.update(&[b'a'; 1000]);
    }
    assert_eq!(hex(&h.finalize()), "52783243c1697bdbe16d37f97f68f08325dc1528");
}

#[test]
fn ripemd160_differential() {
    use ripemd::Digest;
    let mut rng = XorShift(0xABCDEF);
    for len in (0..300).chain([1000, 4096]) {
        let data = rng.bytes(len);
        assert_eq!(
            bp_crypto::Ripemd160::digest(&data).as_slice(),
            ripemd::Ripemd160::digest(&data).as_slice(),
            "len {len}"
        );
    }
}

#[test]
fn hash160_and_tagged_hash() {
    use bp_crypto::hashes::{hash160, tagged_hash};
    // HASH160 of the BIP-84 test vector public key (m/84'/0'/0'/0/0)
    let pk = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c";
    let pk: Vec<u8> = (0..pk.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&pk[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(hex(&hash160(&pk)), "c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2");
    // tagged hash = sha256(sha256(tag)||sha256(tag)||msg)
    let t = Sha256::digest(b"TapTweak");
    let mut h = Sha256::new();
    h.update(&t);
    h.update(&t);
    h.update(b"x");
    assert_eq!(tagged_hash(b"TapTweak", &[b"x"]), h.finalize());
}
