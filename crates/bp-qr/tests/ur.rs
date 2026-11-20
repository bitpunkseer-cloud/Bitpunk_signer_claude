//! UR: byte-exact comparison with the `ur` crate (a port of the reference
//! implementation), fountain recovery from a lossy subset, bytewords.

use bp_qr::ur::{bytewords_minimal, max_fragment_len_for_chars, UrEncoder};

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

fn part(enc: &mut UrEncoder) -> String {
    let mut buf = vec![0u8; 8192];
    let n = enc.next_part(&mut buf).unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

#[test]
fn bytewords_match_reference() {
    let mut rng = XorShift(1);
    for len in [0usize, 1, 2, 31, 100, 500] {
        let data = rng.bytes(len);
        let mut out = vec![0u8; (len + 4) * 2];
        let n = bytewords_minimal(&data, &mut out).unwrap();
        let ours = std::str::from_utf8(&out[..n]).unwrap();
        assert_eq!(ours, ur::bytewords::encode(&data, ur::bytewords::Style::Minimal));
    }
}

#[test]
fn single_part_matches_reference() {
    let mut rng = XorShift(2);
    for len in [1usize, 20, 150] {
        let data = rng.bytes(len);
        let mut enc = UrEncoder::new("bytes", &data, 1000).unwrap();
        assert!(enc.is_single_part());
        assert_eq!(part(&mut enc), ur::ur::encode(&data, &ur::Type::Bytes));
    }
}

#[test]
fn multipart_parts_match_reference_byte_for_byte() {
    let mut rng = XorShift(0xF00D);
    for (len, max_frag) in [
        (100usize, 30usize),
        (777, 100),
        (2500, 200),
        (4000, 64),
        (1234, 11),
    ] {
        let data = rng.bytes(len);
        let mut ours = UrEncoder::new("crypto-psbt", &data, max_frag).unwrap();
        let mut theirs = ur::Encoder::new(&data, max_frag, "crypto-psbt").unwrap();
        assert!(!ours.is_single_part());
        // pure parts first, then mixed (fountain) parts well past seq_len
        for i in 0..(ours.seq_len() * 3 + 20) {
            assert_eq!(
                part(&mut ours),
                theirs.next_part().unwrap(),
                "len {len} frag {max_frag} part {}",
                i + 1
            );
        }
    }
}

#[test]
fn tiny_max_fragment_follows_python_and_cpp_reference() {
    // The reference caps the fragment count at message_len / 10 (minimum
    // fragment length), so a 1234-byte message with max 10 uses 113 parts
    // of 11 bytes. (The `ur` crate ignores the minimum and uses 124 x 10.)
    let data = vec![7u8; 1234];
    let enc = UrEncoder::new("bytes", &data, 10).unwrap();
    assert_eq!((enc.seq_len(), enc.fragment_len()), (113, 11));
}

#[test]
fn reference_decoder_recovers_from_lossy_subset() {
    let mut rng = XorShift(99);
    let data = rng.bytes(3000);
    let mut enc = UrEncoder::new("bytes", &data, 150).unwrap();
    let mut dec = ur::Decoder::default();
    let mut sent = 0;
    while !dec.complete() {
        let p = part(&mut enc);
        sent += 1;
        // drop every third part, like a camera missing frames
        if sent % 3 != 0 {
            dec.receive(&p).unwrap();
        }
        assert!(sent < 500, "did not converge");
    }
    assert_eq!(dec.message().unwrap().unwrap(), data);
}

#[test]
fn uppercase_parts_are_qr_alphanumeric() {
    let mut rng = XorShift(5);
    let data = rng.bytes(400);
    let mut enc = UrEncoder::new("crypto-account", &data, 100).unwrap();
    let p = part(&mut enc).to_ascii_uppercase();
    assert_eq!(bp_qr::qr::best_mode(p.as_bytes()), bp_qr::Mode::Alphanumeric);
}

#[test]
fn fragment_sizing_fits_qr_capacity() {
    use bp_qr::qr::{capacity, Ecc, Mode};
    let mut rng = XorShift(6);
    let data = rng.bytes(5000);
    for ver in [6u8, 10, 15, 20, 25] {
        let cap = capacity(ver, Ecc::Low, Mode::Alphanumeric);
        let f = max_fragment_len_for_chars("crypto-psbt", data.len(), cap);
        let mut enc = UrEncoder::new("crypto-psbt", &data, f).unwrap();
        for _ in 0..enc.seq_len() + 5 {
            let p = part(&mut enc);
            assert!(p.len() <= cap, "v{ver}: part {} chars > capacity {cap}", p.len());
        }
    }
}
