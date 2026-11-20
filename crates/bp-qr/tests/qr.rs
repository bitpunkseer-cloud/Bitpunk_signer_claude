//! QR encoder: exact module-matrix comparison with Nayuki's qrcodegen and
//! round trips through two independent decoders, rqrr (quirc port) and
//! rxing (ZXing port). All are dev-dependencies only.

use bp_qr::qr::{best_mode, capacity, Ecc, Mode, QrCode};
use qrcodegen::{QrCodeEcc, QrSegment, Version};

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn their_ecc(e: Ecc) -> QrCodeEcc {
    match e {
        Ecc::Low => QrCodeEcc::Low,
        Ecc::Medium => QrCodeEcc::Medium,
        Ecc::Quartile => QrCodeEcc::Quartile,
        Ecc::High => QrCodeEcc::High,
    }
}

fn reference(data: &[u8], ecc: Ecc, mask: Option<u8>) -> qrcodegen::QrCode {
    let seg = match best_mode(data) {
        Mode::Numeric => QrSegment::make_numeric(std::str::from_utf8(data).unwrap()),
        Mode::Alphanumeric => QrSegment::make_alphanumeric(std::str::from_utf8(data).unwrap()),
        Mode::Byte => QrSegment::make_bytes(data),
    };
    qrcodegen::QrCode::encode_segments_advanced(
        &[seg],
        their_ecc(ecc),
        Version::MIN,
        Version::MAX,
        mask.map(qrcodegen::Mask::new),
        false,
    )
    .unwrap()
}

fn assert_same(ours: &QrCode, theirs: &qrcodegen::QrCode, what: &str) {
    assert_eq!(ours.size() as i32, theirs.size(), "{what}: size");
    for y in 0..ours.size() {
        for x in 0..ours.size() {
            assert_eq!(
                ours.get(x, y),
                theirs.get_module(x as i32, y as i32),
                "{what}: module ({x},{y})"
            );
        }
    }
}

fn decode(q: &QrCode) -> Vec<u8> {
    let scale = 4;
    let border = 4;
    let dim = (q.size() + 2 * border) * scale;
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(dim, dim, |x, y| {
        let mx = (x / scale) as isize - border as isize;
        let my = (y / scale) as isize - border as isize;
        if mx >= 0 && my >= 0 && q.get(mx as usize, my as usize) {
            0
        } else {
            255
        }
    });
    let grids = img.detect_grids();
    assert_eq!(grids.len(), 1, "one grid expected");
    let mut out = Vec::new();
    grids[0].decode_to(&mut out).expect("decodes");
    out
}

/// Decode with rxing; byte mode is read as ISO-8859-1 and mapped back.
fn decode_rxing(q: &QrCode) -> Vec<u8> {
    use rxing::{DecodeHintValue, DecodeHints, Reader};
    let scale = 3;
    let border = 4;
    let dim = (q.size() + 2 * border) * scale;
    let mut px = vec![255u8; dim * dim];
    for y in 0..dim {
        for x in 0..dim {
            let mx = (x / scale) as isize - border as isize;
            let my = (y / scale) as isize - border as isize;
            if mx >= 0 && my >= 0 && q.get(mx as usize, my as usize) {
                px[y * dim + x] = 0;
            }
        }
    }
    let src = rxing::Luma8Source::new(px, dim as u32, dim as u32).unwrap();
    let mut bmp = rxing::BinaryBitmap::new(rxing::common::HybridBinarizer::new(src));
    let hints = DecodeHints::default()
        .with(DecodeHintValue::PureBarcode(true))
        .with(DecodeHintValue::CharacterSet("ISO-8859-1".into()));
    let r = rxing::qrcode::QRCodeReader
        .decode_with_hints(&mut bmp, &hints)
        .expect("rxing decodes");
    r.getText().chars().map(|c| c as u32 as u8).collect()
}

fn random_payload(rng: &mut XorShift, mode: Mode, len: usize) -> Vec<u8> {
    const ALNUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    (0..len)
        .map(|_| {
            let r = rng.next() as usize;
            match mode {
                Mode::Numeric => b'0' + (r % 10) as u8,
                Mode::Alphanumeric => ALNUM[r % 45],
                Mode::Byte => r as u8,
            }
        })
        .collect()
}

#[test]
fn matches_reference_with_forced_masks() {
    let mut rng = XorShift(0xC0FFEE);
    for ecc in [Ecc::Low, Ecc::Medium, Ecc::Quartile, Ecc::High] {
        for mode in [Mode::Numeric, Mode::Alphanumeric, Mode::Byte] {
            for &len in &[1usize, 7, 25, 60, 150, 400, 1000] {
                if len > capacity(40, ecc, mode) {
                    continue;
                }
                let data = random_payload(&mut rng, mode, len);
                if best_mode(&data) != mode {
                    continue; // random bytes may happen to be digits
                }
                let mask = (rng.next() % 8) as u8;
                let ours = QrCode::encode(&data, ecc, 1, 40, Some(mask)).unwrap();
                assert_eq!(ours.mask(), mask);
                assert_same(
                    &ours,
                    &reference(&data, ecc, Some(mask)),
                    &format!("{ecc:?} {mode:?} len {len}"),
                );
            }
        }
    }
}

#[test]
fn automatic_mask_matches_reference() {
    let mut rng = XorShift(42);
    for i in 0..60 {
        let mode = [Mode::Numeric, Mode::Alphanumeric, Mode::Byte][i % 3];
        let ecc = [Ecc::Low, Ecc::Medium, Ecc::Quartile, Ecc::High][i % 4];
        let len = 1 + (rng.next() % 300) as usize;
        let data = random_payload(&mut rng, mode, len);
        let ours = QrCode::encode(&data, ecc, 1, 40, None).unwrap();
        let theirs = reference(&data, ecc, None);
        assert_eq!(ours.mask(), theirs.mask().value(), "mask choice #{i}");
        assert_same(&ours, &theirs, &format!("auto #{i}"));
    }
}

#[test]
fn every_version_round_trips_through_rqrr() {
    let mut rng = XorShift(7);
    for ver in 1..=40u8 {
        let ecc = [Ecc::Low, Ecc::Medium, Ecc::Quartile, Ecc::High][ver as usize % 4];
        // fill close to the capacity of this version so it is selected
        let len = capacity(ver, ecc, Mode::Byte);
        let data = random_payload(&mut rng, Mode::Byte, len);
        let q = QrCode::encode(&data, ecc, 1, 40, None).unwrap();
        assert_eq!(q.version(), ver);
        assert_eq!(decode(&q), data, "version {ver}");
    }
}

#[test]
fn every_version_and_mode_round_trips_through_rxing() {
    let mut rng = XorShift(11);
    for ver in 1..=40u8 {
        let ecc = [Ecc::Low, Ecc::Medium, Ecc::Quartile, Ecc::High][ver as usize % 4];
        for mode in [Mode::Numeric, Mode::Alphanumeric, Mode::Byte] {
            let len = capacity(ver, ecc, mode);
            let data = random_payload(&mut rng, mode, len);
            if best_mode(&data) != mode {
                continue;
            }
            let q = QrCode::encode(&data, ecc, 1, 40, None).unwrap();
            assert_eq!(q.version(), ver);
            assert_eq!(decode_rxing(&q), data, "version {ver} {mode:?}");
        }
    }
}

#[test]
fn uppercase_ur_text_uses_alphanumeric_mode() {
    let s = b"UR:BYTES/HDCXDWINVEZM";
    assert_eq!(best_mode(s), Mode::Alphanumeric);
    let q = QrCode::encode(s, Ecc::Low, 1, 40, None).unwrap();
    assert_eq!(decode(&q), s);
    assert_eq!(decode_rxing(&q), s);
}

#[test]
fn rejects_oversized_and_bad_arguments() {
    let big = vec![0xAAu8; 3000];
    assert!(QrCode::encode(&big, Ecc::Low, 1, 40, None).is_err());
    assert!(QrCode::encode(b"x", Ecc::Low, 0, 40, None).is_err());
    assert!(QrCode::encode(b"x", Ecc::Low, 1, 40, Some(8)).is_err());
    assert!(QrCode::encode(&[0u8; 100], Ecc::Low, 1, 3, None).is_err());
}
