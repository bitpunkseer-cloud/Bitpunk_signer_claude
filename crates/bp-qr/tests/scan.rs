//! Image scanner: synthetic frames of our own QR codes (every version,
//! all orientations, mirrored, inverted) and camera-like degradation,
//! compared with the test-only decoders rqrr and rxing.

use bp_qr::scan::{Image, Scanner};
use bp_qr::{Ecc, QrCode};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn unit(&mut self) -> f32 {
        (self.next() >> 40) as f32 / (1u64 << 24) as f32
    }
    fn signed(&mut self) -> f32 {
        self.unit() * 2.0 - 1.0
    }
    fn gauss(&mut self) -> f32 {
        let u = self.unit().max(1e-7);
        let v = self.unit();
        (-2.0 * u.ln()).sqrt() * (std::f32::consts::TAU * v).cos()
    }
}

#[derive(Clone, Copy)]
struct Shot {
    /// image pixels per module
    px: f32,
    angle_deg: f32,
    /// perspective tilt (fraction)
    tilt: f32,
    blur: f32,
    noise: f32,
    lo: f32,
    hi: f32,
    mirror: bool,
    invert: bool,
}

impl Shot {
    fn clean(px: f32) -> Self {
        Shot {
            px,
            angle_deg: 0.0,
            tilt: 0.0,
            blur: 0.0,
            noise: 0.0,
            lo: 0.0,
            hi: 255.0,
            mirror: false,
            invert: false,
        }
    }
}

/// Photograph `q` (with a 4-module light quiet zone on a dark surround).
fn photo(q: &QrCode, s: Shot, rng: &mut Rng) -> (Vec<u8>, usize, usize) {
    let n = q.size() as f32 + 8.0; // symbol + quiet zone, in modules
    let side = n * s.px;
    let dim = ((side * 1.5) as usize).clamp(64, 1024);
    let (w, h) = (dim, dim);
    let (sin, cos) = s.angle_deg.to_radians().sin_cos();
    let c = dim as f32 / 2.0;
    // module value at symbol coordinates (mx, my) in modules, origin at
    // the quiet-zone corner
    let module = |mx: f32, my: f32| -> f32 {
        if mx < 0.0 || my < 0.0 || mx >= n || my >= n {
            return 0.08; // dark surround (screen bezel / background)
        }
        let (x, y) = (mx as i32 - 4, my as i32 - 4);
        let dark = x >= 0 && y >= 0 && q.get(x as usize, y as usize);
        let light = if s.invert { dark } else { !dark };
        if light {
            1.0
        } else {
            0.0
        }
    };
    let mut img = vec![0f32; w * h];
    const SUB: [(f32, f32); 4] = [(0.25, 0.25), (0.75, 0.25), (0.25, 0.75), (0.75, 0.75)];
    for v in 0..h {
        for u in 0..w {
            let mut acc = 0.0;
            for (dx, dy) in SUB {
                let x = u as f32 + dx - c;
                let y = v as f32 + dy - c;
                let xr = x * cos + y * sin;
                let yr = -x * sin + y * cos;
                let wgt = 1.0 + s.tilt * (yr / (side / 2.0));
                let mut sx = xr / wgt / s.px + n / 2.0;
                let sy = yr / wgt / s.px + n / 2.0;
                if s.mirror {
                    sx = n - sx;
                }
                acc += module(sx, sy);
            }
            img[v * w + u] = s.lo + (s.hi - s.lo) * acc / 4.0;
        }
    }
    if s.blur > 0.0 {
        let r = (s.blur * 3.0).ceil() as i32;
        let k: Vec<f32> = (-r..=r)
            .map(|i| (-(i * i) as f32 / (2.0 * s.blur * s.blur)).exp())
            .collect();
        let sum: f32 = k.iter().sum();
        let mut tmp = vec![0f32; w * h];
        for y in 0..h {
            for x in 0..w {
                let mut a = 0.0;
                for (i, kv) in k.iter().enumerate() {
                    let xx = (x as i32 + i as i32 - r).clamp(0, w as i32 - 1) as usize;
                    a += img[y * w + xx] * kv;
                }
                tmp[y * w + x] = a / sum;
            }
        }
        for y in 0..h {
            for x in 0..w {
                let mut a = 0.0;
                for (i, kv) in k.iter().enumerate() {
                    let yy = (y as i32 + i as i32 - r).clamp(0, h as i32 - 1) as usize;
                    a += tmp[yy * w + x] * kv;
                }
                img[y * w + x] = a / sum;
            }
        }
    }
    let out = img
        .iter()
        .map(|&p| (p + rng.gauss() * s.noise).clamp(0.0, 255.0) as u8)
        .collect();
    (out, w, h)
}

fn ours(sc: &mut Scanner, img: &[u8], w: usize, h: usize, want: &[u8]) -> bool {
    let mut out = vec![0u8; 8000];
    match sc.scan(Image::new(img, w, h).unwrap(), &mut out) {
        Some(f) => &out[..f.decoded.len] == want,
        None => false,
    }
}

fn rqrr_reads(img: &[u8], w: usize, h: usize, want: &[u8]) -> bool {
    let mut p = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| img[y * w + x]);
    p.detect_grids().iter().any(|g| {
        let mut out = Vec::new();
        g.decode_to(&mut out).is_ok() && out == want
    })
}

fn rxing_reads(img: &[u8], w: usize, h: usize, want: &[u8]) -> bool {
    use rxing::Reader;
    let try_one = |data: Vec<u8>| -> bool {
        let Ok(src) = rxing::Luma8Source::new(data, w as u32, h as u32) else {
            return false;
        };
        let mut bmp = rxing::BinaryBitmap::new(rxing::common::HybridBinarizer::new(src));
        let hints =
            rxing::DecodeHints::default().with(rxing::DecodeHintValue::CharacterSet("ISO-8859-1".into()));
        match rxing::qrcode::QRCodeReader.decode_with_hints(&mut bmp, &hints) {
            Ok(r) => r.getText().chars().map(|c| c as u32 as u8).collect::<Vec<u8>>() == want,
            Err(_) => false,
        }
    };
    try_one(img.to_vec()) || try_one(img.iter().map(|v| 255 - v).collect())
}

fn payload(rng: &mut Rng, len: usize) -> Vec<u8> {
    const ALNUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    (0..len).map(|_| ALNUM[(rng.next() % 45) as usize]).collect()
}

#[test]
fn clean_frames_every_version() {
    let mut rng = Rng(1);
    let mut sc = Box::new(Scanner::new());
    for ver in 1..=40u8 {
        let len = bp_qr::qr::capacity(ver, Ecc::Low, bp_qr::Mode::Alphanumeric);
        let data = payload(&mut rng, len);
        let q = QrCode::encode(&data, Ecc::Low, ver, ver, Some(ver % 8)).unwrap();
        let px = if ver <= 10 { 4.0 } else { 3.0 };
        let (img, w, h) = photo(&q, Shot::clean(px), &mut rng);
        assert!(ours(&mut sc, &img, w, h, &data), "version {ver}");
    }
}

#[test]
fn every_orientation_mirror_and_inversion() {
    let mut rng = Rng(2);
    let mut sc = Box::new(Scanner::new());
    let data = b"UR:CRYPTO-ACCOUNT/OEADCYJKSKTNBKAOLYTAADMETAADDLOLAOWKAXHDCLAXNSRSIMBNYAJOBDA";
    let q = QrCode::encode(data, Ecc::Medium, 1, 40, None).unwrap();
    for a in (0..360).step_by(15) {
        for (mirror, invert) in [(false, false), (true, false), (false, true)] {
            let s = Shot {
                angle_deg: a as f32 + 3.0,
                mirror,
                invert,
                ..Shot::clean(4.0)
            };
            let (img, w, h) = photo(&q, s, &mut rng);
            assert!(
                ours(&mut sc, &img, w, h, data),
                "angle {a} mirror {mirror} invert {invert}"
            );
        }
    }
}

#[test]
fn perspective_frames() {
    let mut rng = Rng(3);
    let mut sc = Box::new(Scanner::new());
    let mut score = [0u32; 3];
    let mut trials = 0;
    for (i, ver) in [1u8, 2, 4, 7, 10, 15, 20, 25].into_iter().enumerate() {
        let data = payload(
            &mut rng,
            bp_qr::qr::capacity(ver, Ecc::Medium, bp_qr::Mode::Alphanumeric),
        );
        let q = QrCode::encode(&data, Ecc::Medium, ver, ver, None).unwrap();
        for k in 0..6 {
            let s = Shot {
                angle_deg: rng.signed() * 20.0,
                tilt: if k % 2 == 0 { 0.08 } else { -0.08 },
                ..Shot::clean(if ver > 10 { 4.0 } else { 5.0 })
            };
            let (img, w, h) = photo(&q, s, &mut rng);
            trials += 1;
            let o = ours(&mut sc, &img, w, h, &data);
            let a = rqrr_reads(&img, w, h, &data);
            let x = rxing_reads(&img, w, h, &data);
            if !o {
                println!("missed #{i} v{ver} k{k} (rqrr {a}, rxing {x})");
            }
            score[0] += o as u32;
            score[1] += a as u32;
            score[2] += x as u32;
        }
    }
    println!(
        "perspective: ours {} rqrr {} rxing {} of {trials}",
        score[0], score[1], score[2]
    );
    assert!(score[0] >= score[1].max(score[2]), "{score:?} of {trials}");
}

/// Degraded frames: our decoder against rqrr and rxing on identical images.
#[test]
fn degraded_frames_vs_reference_decoders() {
    let mut rng = Rng(4);
    let mut sc = Box::new(Scanner::new());
    let mut score = [0u32; 3];
    let mut trials = 0;
    for ver in [2u8, 4, 6, 8] {
        let data = payload(
            &mut rng,
            bp_qr::qr::capacity(ver, Ecc::Low, bp_qr::Mode::Alphanumeric),
        );
        let q = QrCode::encode(&data, Ecc::Low, ver, ver, None).unwrap();
        for px in [2.5f32, 3.0, 4.0, 5.0] {
            for _ in 0..6 {
                let s = Shot {
                    px,
                    angle_deg: rng.signed() * 15.0,
                    tilt: rng.signed() * 0.05,
                    blur: 1.0,
                    noise: 8.0,
                    lo: 35.0,
                    hi: 215.0,
                    mirror: false,
                    invert: false,
                };
                let (img, w, h) = photo(&q, s, &mut rng);
                trials += 1;
                score[0] += ours(&mut sc, &img, w, h, &data) as u32;
                score[1] += rqrr_reads(&img, w, h, &data) as u32;
                score[2] += rxing_reads(&img, w, h, &data) as u32;
            }
        }
    }
    println!(
        "ours {} rqrr {} rxing {} of {trials}",
        score[0], score[1], score[2]
    );
    assert!(score[0] + 3 >= score[1].max(score[2]), "{score:?} of {trials}");
}

#[test]
fn rejects_tiny_and_short_buffers() {
    assert!(Image::new(&[0u8; 100], 10, 10).is_none());
    assert!(Image::new(&[0u8; 100], 64, 64).is_none());
    let blank = vec![200u8; 320 * 240];
    let mut sc = Box::new(Scanner::new());
    let mut out = [0u8; 10];
    assert!(sc.scan(Image::new(&blank, 320, 240).unwrap(), &mut out).is_none());
}

/// Frame time on the desktop (release): `cargo test -p bp-qr --release
/// --test scan frame_time -- --ignored --nocapture`.
#[test]
#[ignore]
fn frame_time() {
    let mut rng = Rng(9);
    let mut sc = Box::new(Scanner::new());
    let data = payload(&mut rng, 150);
    let q = QrCode::encode(&data, Ecc::Low, 1, 40, None).unwrap();
    let s = Shot {
        angle_deg: 8.0,
        tilt: 0.04,
        blur: 1.0,
        noise: 8.0,
        lo: 35.0,
        hi: 215.0,
        ..Shot::clean(4.0)
    };
    let (img, w, h) = photo(&q, s, &mut rng);
    println!(
        "photo {w}x{h} v{} ours {} rqrr {} rxing {}",
        q.version(),
        ours(&mut sc, &img, w, h, &data),
        rqrr_reads(&img, w, h, &data),
        rxing_reads(&img, w, h, &data)
    );
    // crop/pad into a 640x480 frame
    let mut frame = vec![30u8; 640 * 480];
    for y in 0..480.min(h) {
        for x in 0..640.min(w) {
            frame[y * 640 + x] = img[y * w + x];
        }
    }
    let noise: Vec<u8> = (0..640 * 480).map(|_| (rng.next() >> 56) as u8).collect();
    let mut out = vec![0u8; 4000];
    for (name, f) in [("QR frame", &frame), ("noise frame", &noise)] {
        let t = std::time::Instant::now();
        let mut ok = 0;
        for _ in 0..20 {
            ok += sc.scan(Image::new(f, 640, 480).unwrap(), &mut out).is_some() as u32;
        }
        println!(
            "{name}: {:.2} ms/frame, decoded {ok}/20",
            t.elapsed().as_secs_f64() * 1000.0 / 20.0
        );
    }
}

/// Random block patterns (QR-like statistics) and noise never panic.
#[test]
fn random_frames_never_panic() {
    let mut rng = Rng(11);
    let mut sc = Box::new(Scanner::new());
    let mut out = vec![0u8; 512];
    for i in 0..40 {
        let (w, h) = (
            160 + (rng.next() % 200) as usize,
            120 + (rng.next() % 160) as usize,
        );
        let cell = 2 + (rng.next() % 6) as usize;
        let img: Vec<u8> = (0..w * h)
            .map(|k| {
                let (x, y) = (k % w / cell, k / w / cell);
                let v = ((x * 7919 + y * 104729 + i) as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 63;
                if i % 2 == 0 {
                    (v as u8) * 220 + 20
                } else {
                    (rng.next() >> 56) as u8
                }
            })
            .collect();
        let _ = sc.scan(Image::new(&img, w, h).unwrap(), &mut out);
    }
}
