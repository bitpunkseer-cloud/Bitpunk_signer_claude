//! Real photographs: ZXing's blackbox QR sets (fetch with
//! tools/fetch_zxing_qr_photos.sh; not stored in this repository). Each
//! photo is turned to greyscale, scaled to fit the scanner's 1024 x 1024
//! limit, and read by our scanner, rqrr and rxing.

use bp_qr::scan::{Image, Scanner, MAX_HEIGHT, MAX_WIDTH};
use std::path::Path;

fn load_grey(path: &Path) -> Option<(Vec<u8>, usize, usize)> {
    let mut dec = png::Decoder::new(std::io::BufReader::new(std::fs::File::open(path).ok()?));
    dec.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = dec.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()?];
    let info = reader.next_frame(&mut buf).ok()?;
    let (w, h) = (info.width as usize, info.height as usize);
    let ch = match info.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return None,
    };
    let stride = info.line_size;
    let mut grey = vec![0u8; w * h];
    for y in 0..h {
        for x in 0..w {
            let p = &buf[y * stride + x * ch..];
            grey[y * w + x] = if ch >= 3 {
                ((p[0] as u32 * 77 + p[1] as u32 * 150 + p[2] as u32 * 29) >> 8) as u8
            } else {
                p[0]
            };
        }
    }
    // box-filter down by an integer factor to fit the scanner limits
    let f = w.div_ceil(MAX_WIDTH).max(h.div_ceil(MAX_HEIGHT));
    if f == 1 {
        return Some((grey, w, h));
    }
    let (nw, nh) = (w / f, h / f);
    let mut small = vec![0u8; nw * nh];
    for y in 0..nh {
        for x in 0..nw {
            let mut s = 0u32;
            for dy in 0..f {
                for dx in 0..f {
                    s += grey[(y * f + dy) * w + x * f + dx] as u32;
                }
            }
            small[y * nw + x] = (s / (f * f) as u32) as u8;
        }
    }
    Some((small, nw, nh))
}

fn rotate90(img: &[u8], w: usize, h: usize) -> (Vec<u8>, usize, usize) {
    let mut out = vec![0u8; w * h];
    for y in 0..h {
        for x in 0..w {
            out[x * h + (h - 1 - y)] = img[y * w + x];
        }
    }
    (out, h, w)
}

/// Raw bytes compared with the expected text as UTF-8, ISO-8859-1 or
/// Shift JIS (byte segments without an ECI, Kanji segments).
fn same_text(bytes: &[u8], want: &str) -> bool {
    bytes == want.as_bytes()
        || bytes.iter().map(|&b| b as char).collect::<String>() == want
        || encoding_rs::SHIFT_JIS.decode_without_bom_handling(bytes).0 == want
}

fn ours(sc: &mut Scanner, img: &[u8], w: usize, h: usize, want: &str) -> bool {
    let mut out = vec![0u8; 8000];
    match sc.scan(Image::new(img, w, h).unwrap(), &mut out) {
        Some(f) => same_text(&out[..f.decoded.len], want),
        None => false,
    }
}

fn rqrr_reads(img: &[u8], w: usize, h: usize, want: &str) -> bool {
    // rqrr 0.8 asserts on some photos; count that as a miss
    std::panic::catch_unwind(|| {
        let mut p = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| img[y * w + x]);
        p.detect_grids().iter().any(|g| {
            let mut out = Vec::new();
            g.decode_to(&mut out).is_ok() && same_text(&out, want)
        })
    })
    .unwrap_or(false)
}

fn rxing_reads(img: &[u8], w: usize, h: usize, want: &str) -> bool {
    use rxing::Reader;
    let try_one = |data: Vec<u8>| -> bool {
        let Ok(src) = rxing::Luma8Source::new(data, w as u32, h as u32) else {
            return false;
        };
        let mut bmp = rxing::BinaryBitmap::new(rxing::common::HybridBinarizer::new(src));
        match rxing::qrcode::QRCodeReader.decode(&mut bmp) {
            Ok(r) => r.getText() == want,
            Err(_) => false,
        }
    };
    try_one(img.to_vec()) || try_one(img.iter().map(|v| 255 - v).collect())
}

#[test]
#[ignore]
fn zxing_blackbox_photos() {
    let Ok(root) = std::env::var("ZXING_QR_PHOTOS") else {
        println!("set ZXING_QR_PHOTOS (see tools/fetch_zxing_qr_photos.sh)");
        return;
    };
    std::panic::set_hook(Box::new(|_| {})); // keep rqrr's panics quiet
    let mut sc = Box::new(Scanner::new());
    let mut total = [0u32; 4]; // photos, ours, rqrr, rxing
    println!("| Set | Photos x 2 rotations | Ours | rqrr | rxing |");
    println!("|---|---|---|---|---|");
    for set in 1..=6 {
        let dir = Path::new(&root).join(format!("qrcode-{set}"));
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        let mut s = [0u32; 4];
        for png in files.iter().filter(|p| p.extension().is_some_and(|e| e == "png")) {
            let Ok(want) = std::fs::read_to_string(png.with_extension("txt")) else {
                continue;
            };
            let Some((g, w, h)) = load_grey(png) else {
                println!("skipped {}", png.display());
                continue;
            };
            let (r, rw, rh) = rotate90(&g, w, h);
            for (img, iw, ih) in [(&g, w, h), (&r, rw, rh)] {
                if iw > MAX_WIDTH || ih > MAX_HEIGHT || iw < 40 || ih < 40 {
                    continue;
                }
                s[0] += 1;
                let o = ours(&mut sc, img, iw, ih, &want);
                let a = rqrr_reads(img, iw, ih, &want);
                let x = rxing_reads(img, iw, ih, &want);
                if std::env::var("VERBOSE").is_ok() && !o && (a || x) {
                    println!("  missed {} {}x{} (rqrr {a}, rxing {x})", png.display(), iw, ih);
                }
                s[1] += o as u32;
                s[2] += a as u32;
                s[3] += x as u32;
            }
        }
        println!("| qrcode-{set} | {} | {} | {} | {} |", s[0], s[1], s[2], s[3]);
        for k in 0..4 {
            total[k] += s[k];
        }
    }
    println!(
        "| **all** | {} | **{}** | {} | {} |",
        total[0], total[1], total[2], total[3]
    );
}
