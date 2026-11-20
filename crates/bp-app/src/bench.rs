//! Scan-performance bench. Real QR screens are rendered into a framebuffer,
//! degraded the way a phone camera sees a screen (scale, rotation, keystone,
//! contrast loss, blur, sensor noise) and decoded with two independent
//! test-only decoders: `rqrr` (quirc port) and `rxing` (ZXing port, with
//! the inverted retry of ZXing's ALSO_INVERTED option).
//!
//! `cargo test -p bp-app --release scan_bench_full -- --ignored --nocapture`
//! prints the full table recorded in docs/QR_SCAN_BENCH.md.

use super::*;
extern crate std;
use crate::qrview::{Density, Format, QrSession, Speed, TEXT_MAX};
use bp_hal::input::Key;
use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

const W: usize = 800;
const H: usize = 480;

/// Greyscale framebuffer.
struct Gray(Vec<u8>);

fn luma(c: bp_hal::Rgb) -> u8 {
    ((c.0 as u32 * 77 + c.1 as u32 * 150 + c.2 as u32 * 29) >> 8) as u8
}

impl bp_hal::Canvas for Gray {
    fn width(&self) -> u16 {
        W as u16
    }
    fn height(&self) -> u16 {
        H as u16
    }
    fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, c: bp_hal::Rgb) {
        let l = luma(c);
        for yy in y.max(0)..(y + h).min(H as i32) {
            for xx in x.max(0)..(x + w).min(W as i32) {
                self.0[yy as usize * W + xx as usize] = l;
            }
        }
    }
    fn blend_pixel(&mut self, x: i32, y: i32, c: bp_hal::Rgb, a: u8) {
        if x < 0 || y < 0 || x >= W as i32 || y >= H as i32 {
            return;
        }
        let p = &mut self.0[y as usize * W + x as usize];
        *p = ((*p as u32 * (255 - a as u32) + luma(c) as u32 * a as u32) / 255) as u8;
    }
}

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
        (-2.0 * u.ln()).sqrt() * (core::f32::consts::TAU * v).cos()
    }
}

/// Camera and viewing conditions.
#[derive(Clone, Copy)]
struct Conditions {
    name: &'static str,
    /// Gaussian blur sigma in camera pixels (focus, motion, optics).
    blur: f32,
    /// Sensor noise sigma (0-255 scale).
    noise: f32,
    /// What the camera records for screen black and screen white.
    lo: f32,
    hi: f32,
    /// Random rotation up to this many degrees either way.
    max_angle: f32,
    /// Random keystone (perspective) up to this fraction either way.
    max_keystone: f32,
}

const MEDIUM: Conditions = Conditions {
    name: "medium",
    blur: 1.0,
    noise: 8.0,
    lo: 35.0,
    hi: 215.0,
    max_angle: 15.0,
    max_keystone: 0.05,
};

const HARD: Conditions = Conditions {
    name: "hard",
    blur: 1.5,
    noise: 14.0,
    lo: 55.0,
    hi: 190.0,
    max_angle: 15.0,
    max_keystone: 0.10,
};

fn sample(fb: &Gray, x: f32, y: f32) -> f32 {
    if x < 0.0 || y < 0.0 || x >= (W - 1) as f32 || y >= (H - 1) as f32 {
        return 0.0; // device bezel
    }
    let (x0, y0) = (x as usize, y as usize);
    let (fx, fy) = (x - x0 as f32, y - y0 as f32);
    let p = |xx: usize, yy: usize| fb.0[yy * W + xx] as f32;
    let top = p(x0, y0) * (1.0 - fx) + p(x0 + 1, y0) * fx;
    let bot = p(x0, y0 + 1) * (1.0 - fx) + p(x0 + 1, y0 + 1) * fx;
    top * (1.0 - fy) + bot * fy
}

fn blur(img: &mut [f32], w: usize, h: usize, sigma: f32) {
    if sigma <= 0.0 {
        return;
    }
    let r = (sigma * 3.0).ceil() as i32;
    let k: Vec<f32> = (-r..=r)
        .map(|i| (-(i * i) as f32 / (2.0 * sigma * sigma)).exp())
        .collect();
    let sum: f32 = k.iter().sum();
    let k: Vec<f32> = k.iter().map(|v| v / sum).collect();
    let mut tmp = vec![0f32; w * h];
    for y in 0..h {
        for x in 0..w {
            let mut a = 0.0;
            for (i, kv) in k.iter().enumerate() {
                let xx = (x as i32 + i as i32 - r).clamp(0, w as i32 - 1) as usize;
                a += img[y * w + xx] * kv;
            }
            tmp[y * w + x] = a;
        }
    }
    for y in 0..h {
        for x in 0..w {
            let mut a = 0.0;
            for (i, kv) in k.iter().enumerate() {
                let yy = (y as i32 + i as i32 - r).clamp(0, h as i32 - 1) as usize;
                a += tmp[yy * w + x] * kv;
            }
            img[y * w + x] = a;
        }
    }
}

/// Photograph the screen. `scale` = camera pixels per screen pixel.
fn camera(fb: &Gray, scale: f32, cond: &Conditions, rng: &mut Rng) -> (Vec<u8>, usize, usize) {
    let angle = rng.signed() * cond.max_angle.to_radians();
    let ks = rng.signed() * cond.max_keystone;
    let ow = (900.0 * scale) as usize;
    let oh = (680.0 * scale) as usize;
    let (sin, cos) = angle.sin_cos();
    let cx = ow as f32 / 2.0 + rng.signed() * 3.0;
    let cy = oh as f32 / 2.0 + rng.signed() * 3.0;
    let mut img = vec![0f32; ow * oh];
    const SUB: [(f32, f32); 4] = [(0.25, 0.25), (0.75, 0.25), (0.25, 0.75), (0.75, 0.75)];
    for v in 0..oh {
        for u in 0..ow {
            let mut acc = 0.0;
            for (dx, dy) in SUB {
                let x = u as f32 + dx - cx;
                let y = v as f32 + dy - cy;
                let xr = x * cos + y * sin;
                let yr = -x * sin + y * cos;
                // perspective (a true homography, lines stay straight): the
                // screen is tilted about its horizontal axis
                let wgt = 1.0 + ks * (yr / (240.0 * scale));
                acc += sample(fb, xr / (scale * wgt) + 400.0, yr / (scale * wgt) + 240.0);
            }
            img[v * ow + u] = cond.lo + (cond.hi - cond.lo) * acc / (4.0 * 255.0);
        }
    }
    blur(&mut img, ow, oh, cond.blur);
    let out = img
        .iter()
        .map(|&p| (p + rng.gauss() * cond.noise).clamp(0.0, 255.0) as u8)
        .collect();
    (out, ow, oh)
}

fn decode_rqrr(img: &[u8], w: usize, h: usize, want: &[u8]) -> bool {
    let mut p = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| img[y * w + x]);
    p.detect_grids().iter().any(|g| {
        let mut out = Vec::new();
        g.decode_to(&mut out).is_ok() && out == want
    })
}

fn decode_rxing(img: Vec<u8>, w: usize, h: usize, want: &[u8]) -> bool {
    // ZXing's MultiFormatReader with ALSO_INVERTED retries on the inverted
    // image; QRCodeReader alone does not, so the retry is done here.
    let inverted: Vec<u8> = img.iter().map(|v| 255 - v).collect();
    rxing_once(img, w, h, want) || rxing_once(inverted, w, h, want)
}

fn rxing_once(img: Vec<u8>, w: usize, h: usize, want: &[u8]) -> bool {
    use rxing::Reader;
    let Ok(src) = rxing::Luma8Source::new(img, w as u32, h as u32) else {
        return false;
    };
    let mut bmp = rxing::BinaryBitmap::new(rxing::common::HybridBinarizer::new(src));
    let Ok(r) = rxing::qrcode::QRCodeReader.decode(&mut bmp) else {
        return false;
    };
    // byte mode decodes as ISO-8859-1: map chars back to bytes
    let text = r.getText();
    let bytes: Vec<u8> = if text.chars().all(|c| (c as u32) < 256) {
        text.chars().map(|c| c as u8).collect()
    } else {
        text.as_bytes().to_vec()
    };
    bytes == want
}

#[derive(Default, Clone, Copy)]
struct Score {
    trials: u32,
    rqrr: u32,
    rxing: u32,
    either: u32,
}

impl Score {
    fn add(&mut self, a: bool, b: bool) {
        self.trials += 1;
        self.rqrr += a as u32;
        self.rxing += b as u32;
        self.either += (a || b) as u32;
    }
    fn pct(n: u32, d: u32) -> f32 {
        100.0 * n as f32 / d.max(1) as f32
    }
    fn either_pct(&self) -> f32 {
        Self::pct(self.either, self.trials)
    }
    fn cells(&self) -> String {
        format!(
            "{:.0}% | {:.0}% | **{:.0}%**",
            Self::pct(self.rqrr, self.trials),
            Self::pct(self.rxing, self.trials),
            self.either_pct()
        )
    }
}

/// A QR screen to photograph: the app state and, per frame, the text the
/// decoder must return.
struct Case {
    name: String,
    app: App,
}

impl Case {
    fn frames(&self) -> usize {
        match self.app.current() {
            Screen::QrShow { .. } => {
                let q = self.app.qr.as_ref().unwrap();
                // UR keeps going with fountain parts: include two of them
                match q.format {
                    Format::Ur(_) if q.is_animated() => q.frames() + 2,
                    _ => q.frames(),
                }
            }
            _ => 1,
        }
    }

    /// Select frame `i`, render, return (screen, expected text).
    fn render(&mut self, i: usize) -> (Gray, Vec<u8>) {
        let want = match self.app.current() {
            Screen::QrShow { .. } => {
                let q = self.app.qr.as_mut().unwrap();
                q.frame = match q.format {
                    Format::Specter => i as u32,
                    _ => i as u32 + 1,
                };
                let mut buf = [0u8; TEXT_MAX];
                let n = q.text(&mut buf);
                buf[..n].to_vec()
            }
            Screen::AddressDetail {
                slot,
                st,
                change,
                index,
            } => {
                let seed = self.app.slot(slot as usize).unwrap();
                let mut out = [0u8; bp_bitcoin::address::MAX_ADDRESS_LEN];
                let n = seed
                    .address(st, self.app.settings.network, 0, change, index, &mut out)
                    .unwrap();
                let mut v = out[..n].to_vec();
                if matches!(st, ScriptType::NativeSegwit | ScriptType::Taproot) {
                    v.make_ascii_uppercase();
                }
                v
            }
            s => panic!("not a QR screen: {s:?}"),
        };
        let mut fb = Gray(vec![0; W * H]);
        self.app.render(&mut fb);
        (fb, want)
    }
}

fn abandon_app() -> App {
    let mut a = App::new(b"bench");
    a.tick(SPLASH_MS);
    let mut press = |k| a.on_key(KeyEvent::new(k));
    for c in "2211".chars() {
        press(Key::Char(c));
    }
    for _ in 0..11 {
        for c in "aban".chars() {
            press(Key::Char(c));
        }
    }
    for c in "abou".chars() {
        press(Key::Char(c));
    }
    press(Key::Enter);
    assert!(matches!(a.current(), Screen::SeedOptions { .. }));
    a
}

fn keys(a: &mut App, ks: &[Key]) {
    for &k in ks {
        a.on_key(KeyEvent::new(k));
    }
}

/// The QR screens a user reaches with default settings.
fn default_cases() -> Vec<Case> {
    let mut v = Vec::new();
    let xpub = [
        ('1', "xpub UR crypto-account"),
        ('2', "xpub UR crypto-output"),
        ('3', "xpub text [fp/path]zpub"),
        ('4', "xpub Specter pM/N"),
    ];
    for (k, name) in xpub {
        let mut a = abandon_app();
        keys(&mut a, &[Key::Char('2'), Key::Char('1'), Key::Char(k)]);
        v.push(Case {
            name: name.into(),
            app: a,
        });
    }
    let mut a = abandon_app();
    keys(&mut a, &[Key::Char('3'), Key::Char('2'), Key::Enter]);
    v.push(Case {
        name: "address (Taproot, upper-case)".into(),
        app: a,
    });
    for (k, name) in [('1', "SeedQR Standard"), ('2', "SeedQR Compact")] {
        let mut a = abandon_app();
        keys(&mut a, &[Key::Char('5'), Key::Char(k), Key::Enter]);
        v.push(Case {
            name: name.into(),
            app: a,
        });
    }
    v
}

/// Viewer options applied to the crypto-account QR.
fn option_cases() -> Vec<Case> {
    let opts: [(&str, &[Key]); 4] = [
        ("full screen", &[Key::Enter]),
        ("brightness level 3 of 5", &[Key::Down, Key::Down]),
        ("brightness level 5 of 5 (dimmest)", &[Key::Down; 4]),
        ("inverted (rqrr reads no inverted codes)", &[Key::Char('i')]),
    ];
    opts.iter()
        .map(|(name, ks)| {
            let mut a = abandon_app();
            keys(&mut a, &[Key::Char('2'), Key::Char('1'), Key::Char('1')]);
            keys(&mut a, ks);
            Case {
                name: format!("crypto-account, {name}"),
                app: a,
            }
        })
        .collect()
}

/// Random bytes the size of a PSBT, shown as an animated UR.
fn psbt_case(density: Density, len: usize) -> Case {
    let mut a = App::new(b"bench");
    a.tick(SPLASH_MS);
    let mut rng = Rng(0x5eed_0123_4567_89ab);
    let msg: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
    a.qr = QrSession::new(Format::Ur("crypto-psbt"), &msg, density, Speed::Normal);
    a.push(Screen::QrShow {
        kind: QrKind::Xpub {
            slot: 0,
            st: ScriptType::NativeSegwit,
            account: 0,
            format: XpubFormat::UrAccount,
        },
    });
    Case {
        name: format!("{len} B, {density:?}"),
        app: a,
    }
}

fn run(case: &mut Case, scale: f32, cond: &Conditions, trials: u32, seed: u64) -> Score {
    let mut rng = Rng(seed ^ 0x9e37_79b9_7f4a_7c15);
    let frames = case.frames();
    let mut s = Score::default();
    for t in 0..trials {
        let (fb, want) = case.render(t as usize % frames);
        let (img, w, h) = camera(&fb, scale, cond, &mut rng);
        let a = decode_rqrr(&img, w, h, &want);
        let b = decode_rxing(img, w, h, &want);
        s.add(a, b);
    }
    s
}

/// Reference distance: 0.55 camera px per screen px, about a 640x480
/// decode of a phone camera that has the device filling 70% of the frame.
const REFERENCE: f32 = 0.55;

/// CI check: every default QR screen at the reference distance in medium
/// conditions (target: at least 95% of frames decode).
#[test]
fn scan_bench_defaults() {
    let mut total = Score::default();
    for mut c in default_cases() {
        let s = run(&mut c, REFERENCE, &MEDIUM, 6, 1);
        assert!(s.either >= 5, "{}: {}", c.name, s.cells());
        total.trials += s.trials;
        total.either += s.either;
    }
    assert!(total.either_pct() >= 95.0, "{:.1}%", total.either_pct());
}

const SCALES: [f32; 5] = [0.35, 0.45, 0.55, 0.7, 0.9];

fn table(cases: Vec<Case>, cond: &Conditions, n: u32) -> Score {
    std::println!("| Screen | QR | scale | rqrr | rxing | either |");
    std::println!("|---|---|---|---|---|---|");
    let mut total = Score::default();
    for mut c in cases {
        let info = qr_info(&mut c);
        for (i, &sc) in SCALES.iter().enumerate() {
            let s = run(&mut c, sc, cond, n, i as u64 + 7);
            if sc == REFERENCE {
                total.trials += s.trials;
                total.either += s.either;
            }
            std::println!("| {} | {} | {} | {} |", c.name, info, sc, s.cells());
        }
    }
    total
}

#[test]
#[ignore]
fn scan_bench_full() {
    const N: u32 = 40;
    for cond in [&MEDIUM, &HARD] {
        std::println!(
            "\n### Default QR screens, {} conditions\n\nblur {} px, noise {}, contrast {}-{}, rotation up to {} deg, perspective up to {}%, {N} trials per row\n",
            cond.name,
            cond.blur,
            cond.noise,
            cond.lo,
            cond.hi,
            cond.max_angle,
            cond.max_keystone * 100.0
        );
        let total = table(default_cases(), cond, N);
        std::println!(
            "\nAt the reference scale {REFERENCE}: **{:.1}%** ({}/{})",
            total.either_pct(),
            total.either,
            total.trials
        );
    }

    std::println!("\n### Viewer options, medium conditions\n");
    table(option_cases(), &MEDIUM, N);

    std::println!("\n### Density (animated UR), medium conditions\n");
    std::println!("| Payload | QR | frames | scale | rqrr | rxing | either | est. time at Normal |");
    std::println!("|---|---|---|---|---|---|---|---|");
    for len in [700, 1000] {
        for d in [Density::Auto, Density::Low, Density::Medium, Density::High] {
            let mut c = psbt_case(d, len);
            let info = qr_info(&mut c);
            let frames = c.app.qr.as_ref().unwrap().frames();
            for (i, &sc) in SCALES.iter().enumerate() {
                let s = run(&mut c, sc, &MEDIUM, N, i as u64 + 101);
                // a fountain receiver needs about 1.1 x frames good parts
                let p = s.either as f32 / s.trials as f32;
                let t = if p > 0.0 {
                    format!("{:.1} s", frames as f32 * 1.1 / p * 0.45)
                } else {
                    "-".into()
                };
                std::println!("| {} | {info} | {frames} | {sc} | {} | {t} |", c.name, s.cells());
            }
        }
    }
}

fn qr_info(c: &mut Case) -> String {
    match c.app.current() {
        Screen::QrShow { .. } => {
            let q = c.app.qr.as_ref().unwrap();
            let sym = q.qr().unwrap();
            let bx = if q.fullscreen {
                H as i32
            } else {
                crate::qrview::QR_BOX_PX
            };
            format!("v{} {}px", sym.version(), bx / (sym.size() as i32 + 8))
        }
        Screen::AddressDetail { .. } => {
            let (_, want) = c.render(0);
            let sym = bp_qr::QrCode::encode(&want, bp_qr::Ecc::Medium, 1, 40, None).unwrap();
            format!("v{} {}px", sym.version(), 330 / (sym.size() as i32 + 8))
        }
        _ => "?".into(),
    }
}
