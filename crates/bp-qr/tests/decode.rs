//! Matrix decoder: symbols from our encoder and from Nayuki's qrcodegen
//! (test-only), every version / ECC level / mode / mask, mixed and ECI
//! segments, mirrored symbols, and injected errors.

use bp_qr::decode::{decode, BitMatrix, Error};
use bp_qr::qr::{best_mode, capacity, Ecc, Mode, QrCode};
use qrcodegen::{Mask, QrCodeEcc, QrSegment, Version};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const ECCS: [Ecc; 4] = [Ecc::Low, Ecc::Medium, Ecc::Quartile, Ecc::High];

fn their_ecc(e: Ecc) -> QrCodeEcc {
    match e {
        Ecc::Low => QrCodeEcc::Low,
        Ecc::Medium => QrCodeEcc::Medium,
        Ecc::Quartile => QrCodeEcc::Quartile,
        Ecc::High => QrCodeEcc::High,
    }
}

fn payload(rng: &mut Rng, mode: Mode, len: usize) -> Vec<u8> {
    const ALNUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    (0..len)
        .map(|_| match mode {
            Mode::Numeric => b'0' + rng.below(10) as u8,
            Mode::Alphanumeric => ALNUM[rng.below(45)],
            Mode::Byte => rng.next() as u8,
        })
        .collect()
}

fn matrix_of(q: &qrcodegen::QrCode) -> BitMatrix {
    let n = q.size() as usize;
    let mut m = BitMatrix::new(n).unwrap();
    for y in 0..n {
        for x in 0..n {
            m.set(x, y, q.get_module(x as i32, y as i32));
        }
    }
    m
}

fn read(m: &BitMatrix) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; 8000];
    let d = decode(m, &mut out)?;
    out.truncate(d.len);
    Ok(out)
}

#[test]
fn every_version_ecc_and_mode_from_our_encoder() {
    let mut rng = Rng(1);
    for ver in 1..=40u8 {
        for ecc in ECCS {
            for mode in [Mode::Numeric, Mode::Alphanumeric, Mode::Byte] {
                let len = capacity(ver, ecc, mode);
                let data = payload(&mut rng, mode, len);
                if best_mode(&data) != mode {
                    continue;
                }
                // forced masks keep the test fast (mask choice is tested elsewhere)
                let mask = (ver as usize + mode as usize) as u8 % 8;
                let q = QrCode::encode(&data, ecc, 1, 40, Some(mask)).unwrap();
                assert_eq!(q.version(), ver);
                let mut out = vec![0u8; 8000];
                let d = decode(&BitMatrix::from_qr(&q), &mut out).unwrap();
                assert_eq!(&out[..d.len], &data[..], "v{ver} {ecc:?} {mode:?}");
                assert_eq!((d.version, d.ecc, d.mask), (ver, ecc, q.mask()));
                assert!(!d.mirrored);
            }
        }
    }
}

#[test]
fn qrcodegen_symbols_with_every_mask() {
    let mut rng = Rng(2);
    for i in 0..320 {
        let ver = 1 + (i % 40) as u8;
        let ecc = ECCS[i % 4];
        let mask = (i / 40) as u8;
        let mode = [Mode::Numeric, Mode::Alphanumeric, Mode::Byte][i % 3];
        let len = 1 + rng.below(capacity(ver, ecc, mode));
        let data = payload(&mut rng, mode, len);
        let seg = match mode {
            Mode::Numeric => QrSegment::make_numeric(std::str::from_utf8(&data).unwrap()),
            Mode::Alphanumeric => QrSegment::make_alphanumeric(std::str::from_utf8(&data).unwrap()),
            Mode::Byte => QrSegment::make_bytes(&data),
        };
        let q = qrcodegen::QrCode::encode_segments_advanced(
            &[seg],
            their_ecc(ecc),
            Version::new(ver),
            Version::new(40),
            Some(Mask::new(mask)),
            false,
        )
        .unwrap();
        assert_eq!(read(&matrix_of(&q)).unwrap(), data, "#{i}");
    }
}

#[test]
fn mixed_and_eci_segments() {
    let segs = [
        QrSegment::make_eci(26),
        QrSegment::make_bytes("Bitcoin ₿ ".as_bytes()),
        QrSegment::make_numeric("0123456789012"),
        QrSegment::make_alphanumeric("UR:CRYPTO-PSBT/"),
        QrSegment::make_bytes(&[0, 255, 10]),
    ];
    let q = qrcodegen::QrCode::encode_segments_advanced(
        &segs,
        QrCodeEcc::Medium,
        Version::new(1),
        Version::new(40),
        None,
        true,
    )
    .unwrap();
    let mut want = "Bitcoin ₿ ".as_bytes().to_vec();
    want.extend_from_slice(b"0123456789012UR:CRYPTO-PSBT/");
    want.extend_from_slice(&[0, 255, 10]);
    assert_eq!(read(&matrix_of(&q)).unwrap(), want);
}

#[test]
fn mirrored_symbol() {
    let q = QrCode::encode(
        b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        Ecc::Medium,
        1,
        40,
        None,
    )
    .unwrap();
    let m = BitMatrix::from_qr(&q);
    let n = m.size();
    let mut t = BitMatrix::new(n).unwrap();
    for y in 0..n {
        for x in 0..n {
            t.set(y, x, m.get(x, y));
        }
    }
    let mut out = [0u8; 100];
    let d = decode(&t, &mut out).unwrap();
    assert!(d.mirrored);
    assert_eq!(&out[..d.len], b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
}

/// Is (x, y) inside a finder, timing, format or version area? Those are
/// covered by their own tests; data errors go elsewhere.
fn is_reserved(n: usize, x: usize, y: usize) -> bool {
    let finder = |cx: usize, cy: usize| x.abs_diff(cx) <= 4 && y.abs_diff(cy) <= 4;
    finder(3, 3)
        || finder(n - 4, 3)
        || finder(3, n - 4)
        || x == 6
        || y == 6
        || (x <= 8 && y <= 8)
        || (y == 8 && x >= n - 8)
        || (x == 8 && y >= n - 8)
        || (n >= 45 && ((x >= n - 11 && y < 6) || (y >= n - 11 && x < 6)))
}

#[test]
fn corrects_data_errors_within_capacity() {
    // Each flipped module damages at most one codeword. Flipping no more
    // modules than the smallest per-block capacity can never exceed it.
    let mut rng = Rng(3);
    for i in 0..400 {
        let ver = 1 + (i % 40) as u8;
        let ecc = ECCS[(i / 40) % 4];
        let data = payload(&mut rng, Mode::Byte, capacity(ver, ecc, Mode::Byte));
        let q = QrCode::encode(&data, ecc, ver, ver, Some((i % 8) as u8)).unwrap();
        let mut m = BitMatrix::from_qr(&q);
        let n = m.size();
        // conservative per-block capacity (minus misdecode protection)
        let cap = match (ver, ecc) {
            (1, Ecc::Low) => 2,
            (1, Ecc::Medium) | (2, Ecc::Low) => 4,
            (1, Ecc::Quartile) => 6,
            (1, Ecc::High) => 8,
            (3, Ecc::Low) => 7,
            _ => 5,
        };
        let flips = 1 + rng.below(cap);
        let mut done = 0;
        while done < flips {
            let (x, y) = (rng.below(n), rng.below(n));
            if !is_reserved(n, x, y) {
                m.flip(x, y);
                done += 1;
            }
        }
        let mut out = vec![0u8; 3000];
        let d = decode(&m, &mut out).unwrap_or_else(|e| panic!("#{i} v{ver} {ecc:?}: {e:?}"));
        assert_eq!(&out[..d.len], &data[..], "#{i}");
        // flips in alignment patterns or remainder bits are not codeword errors
        assert!(d.corrected <= flips);
    }
}

#[test]
fn survives_damaged_format_and_version_information() {
    let mut rng = Rng(4);
    for ver in [1u8, 6, 7, 20, 40] {
        let data = payload(&mut rng, Mode::Alphanumeric, 8);
        let q = QrCode::encode(&data, Ecc::High, ver, ver, None).unwrap();
        let mut m = BitMatrix::from_qr(&q);
        let n = m.size();
        // 4 errors in the first format copy (beyond its own reach), 1 in
        // the second: the nearest codeword over both copies still wins
        for (x, y) in [(8, 0), (8, 3), (8, 7), (2, 8)] {
            m.flip(x, y);
        }
        m.flip(n - 2, 8);
        if ver >= 7 {
            // 3 errors in each version block
            for (x, y) in [(n - 11, 0), (n - 10, 2), (n - 9, 5)] {
                m.flip(x, y);
                m.flip(y, x);
            }
        }
        assert_eq!(read(&m).unwrap(), data, "v{ver}");
    }
}

#[test]
fn heavy_damage_fails_cleanly() {
    let mut rng = Rng(5);
    let mut wrong = 0;
    for i in 0..300 {
        let ver = 1 + (i % 40) as u8;
        let data = payload(&mut rng, Mode::Byte, capacity(ver, Ecc::Low, Mode::Byte));
        let q = QrCode::encode(&data, Ecc::Low, ver, ver, Some((i % 8) as u8)).unwrap();
        let mut m = BitMatrix::from_qr(&q);
        let n = m.size();
        for _ in 0..n * n / 4 {
            let (x, y) = (rng.below(n), rng.below(n));
            if !is_reserved(n, x, y) {
                m.flip(x, y);
            }
        }
        if let Ok(out) = read(&m) {
            if out != data {
                wrong += 1;
            }
        }
    }
    assert_eq!(wrong, 0);
}

#[test]
fn random_matrices_never_panic() {
    let mut rng = Rng(6);
    let mut out = [0u8; 4000];
    // one real symbol per size, damaged at random, plus pure noise
    let symbols: Vec<BitMatrix> = (1..=40u8)
        .map(|v| BitMatrix::from_qr(&QrCode::encode(b"TEST", Ecc::Low, v, v, Some(v % 8)).unwrap()))
        .collect();
    for i in 0..2000 {
        let k = rng.below(40);
        let mut m = if i % 2 == 0 {
            symbols[k].clone()
        } else {
            BitMatrix::new(21 + 4 * k).unwrap()
        };
        let n = m.size();
        for _ in 0..rng.below(n * n / 2 + 1) {
            let (x, y) = (rng.below(n), rng.below(n));
            m.flip(x, y);
        }
        let _ = decode(&m, &mut out);
    }
}

#[test]
fn small_output_buffer() {
    let q = QrCode::encode(b"0123456789", Ecc::Low, 1, 40, None).unwrap();
    let mut out = [0u8; 5];
    assert_eq!(
        decode(&BitMatrix::from_qr(&q), &mut out),
        Err(Error::BufferTooSmall)
    );
    assert!(BitMatrix::new(22).is_none());
    assert!(BitMatrix::new(181).is_none());
}

#[test]
fn kanji_segment_as_shift_jis() {
    use qrcodegen::QrSegmentMode;
    // ISO 18004 examples: 0x935F -> 0xD9F, 0xE4AA -> 0x1AAA (13 bits each)
    let mut bits = Vec::new();
    for v in [0xD9Fu32, 0x1AAA] {
        for i in (0..13).rev() {
            bits.push((v >> i) & 1 == 1);
        }
    }
    let seg = QrSegment::new(QrSegmentMode::Kanji, 2, bits);
    let q = qrcodegen::QrCode::encode_segments_advanced(
        &[seg],
        QrCodeEcc::Low,
        Version::new(1),
        Version::new(40),
        None,
        false,
    )
    .unwrap();
    assert_eq!(read(&matrix_of(&q)).unwrap(), vec![0x93, 0x5F, 0xE4, 0xAA]);
}
