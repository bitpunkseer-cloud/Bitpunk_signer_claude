//! BBQr against Coinkite's reference (H and Base32 parts must be identical);
//! our raw-deflate output must inflate (independent miniz_oxide) to the input.

include!("data/bbqr_vectors.rs");

use bp_qr::bbqr::{specter, Bbqr, Encoding, FileType};
use bp_qr::deflate;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn parts(b: &Bbqr) -> Vec<String> {
    (0..b.count())
        .map(|i| {
            let mut out = vec![0u8; 8192];
            let n = b.part(i, &mut out).unwrap();
            String::from_utf8(out[..n].to_vec()).unwrap()
        })
        .collect()
}

#[test]
fn hex_and_base32_parts_match_reference() {
    for (file, ftype, enc, lo, hi, ver, rawhex, expected) in BBQR_VECTORS {
        let raw = unhex(rawhex);
        let ft = if *ftype == 'P' {
            FileType::Psbt
        } else {
            FileType::Transaction
        };
        let e = if *enc == 'H' {
            Encoding::Hex
        } else {
            Encoding::Base32
        };
        let mut work = vec![0u8; raw.len() * 2 + 64];
        let mut chars = vec![0u8; raw.len() * 2 + 64];
        let b = Bbqr::new(&raw, ft, e, *lo, *hi, &mut work, &mut chars).unwrap();
        assert_eq!(b.version(), *ver, "{file} {enc} {lo}-{hi}: version");
        assert_eq!(parts(&b), *expected, "{file} {enc} {lo}-{hi}");
    }
}

fn inflate_raw(data: &[u8]) -> Vec<u8> {
    miniz_oxide::inflate::decompress_to_vec(data).expect("valid raw deflate")
}

#[test]
fn deflate_round_trips_through_miniz() {
    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        b"a".to_vec(),
        b"abcabcabcabcabcabc".to_vec(),
        vec![0u8; 5000],
    ];
    let mut x: u64 = 0x1234;
    let random: Vec<u8> = (0..3000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    cases.push(random);
    for (_, _, _, _, _, _, rawhex, _) in BBQR_VECTORS {
        cases.push(unhex(rawhex));
    }
    // repeated structure far apart (must not reference beyond 1024 bytes)
    let mut far = Vec::new();
    for i in 0..50u8 {
        far.extend_from_slice(b"psbt-input-derivation-path-m/84h/0h/0h/0/");
        far.extend(std::iter::repeat_n(i, 300));
    }
    cases.push(far);
    for c in cases {
        let mut out = vec![0u8; c.len() * 2 + 64];
        let n = deflate::compress(&c, &mut out).unwrap();
        assert_eq!(inflate_raw(&out[..n]), c, "len {}", c.len());
    }
}

#[test]
fn compression_shrinks_real_psbts() {
    for (file, _, _, _, _, _, rawhex, _) in BBQR_VECTORS.iter().step_by(6).filter(|v| v.0.ends_with(".psbt"))
    {
        let raw = unhex(rawhex);
        let mut out = vec![0u8; raw.len() * 2 + 64];
        let n = deflate::compress(&raw, &mut out).unwrap();
        println!(
            "{file}: {} -> {} bytes ({:.0}%)",
            raw.len(),
            n,
            n as f64 * 100.0 / raw.len() as f64
        );
        assert!(n < raw.len(), "{file} did not compress");
    }
}

#[test]
fn zlib_mode_parts_carry_compressed_payload() {
    let (_, _, _, _, _, _, rawhex, _) = BBQR_VECTORS[2];
    let raw = unhex(rawhex);
    let mut work = vec![0u8; raw.len() * 2 + 64];
    let mut chars = vec![0u8; raw.len() * 2 + 64];
    let b = Bbqr::new(&raw, FileType::Psbt, Encoding::Zlib, 5, 40, &mut work, &mut chars).unwrap();
    assert_eq!(b.encoding(), b'Z');
    // reassemble, Base32-decode and inflate
    let joined: String = parts(&b).iter().map(|p| p[8..].to_string()).collect();
    let mut acc = 0u32;
    let mut bits = 0;
    let mut bytes = Vec::new();
    for c in joined.bytes() {
        let v = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            .iter()
            .position(|&a| a == c)
            .unwrap() as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
        }
    }
    assert_eq!(inflate_raw(&bytes), raw);
}

#[test]
fn incompressible_data_falls_back_to_base32() {
    let mut x: u64 = 77;
    let raw: Vec<u8> = (0..500)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let mut work = vec![0u8; 2000];
    let mut chars = vec![0u8; 2000];
    let b = Bbqr::new(
        &raw,
        FileType::Binary,
        Encoding::Zlib,
        5,
        40,
        &mut work,
        &mut chars,
    )
    .unwrap();
    assert_eq!(b.encoding(), b'2');
}

#[test]
fn specter_format() {
    let text = b"[73c5da0a/84h/0h/0h]zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    assert_eq!(specter::count(text.len(), 65), 3);
    let mut out = [0u8; 128];
    let n = specter::part(text, 65, 0, &mut out).unwrap();
    assert!(out[..n].starts_with(b"p1of3 [73c5da0a/84h"));
    let n = specter::part(text, 65, 2, &mut out).unwrap();
    assert!(out[..n].starts_with(b"p3of3 "));
    let n = specter::part(text, 500, 0, &mut out[..]).map(|n| n.min(128));
    assert_eq!(n, None, "single part bigger than the buffer");
    let mut big = [0u8; 256];
    let n = specter::part(text, 500, 0, &mut big).unwrap();
    assert_eq!(&big[..n], &text[..], "one part = plain text");
}

/// Prints Z-mode parts for an external check with Coinkite's join.py:
/// cargo test -p bp-qr --test bbqr dump_z_parts -- --ignored --nocapture
#[test]
#[ignore]
fn dump_z_parts() {
    for (file, _, _, _, _, _, rawhex, _) in BBQR_VECTORS.iter().step_by(6) {
        let raw = unhex(rawhex);
        let mut work = vec![0u8; raw.len() * 2 + 64];
        let mut chars = vec![0u8; raw.len() * 2 + 64];
        let b = Bbqr::new(&raw, FileType::Psbt, Encoding::Zlib, 5, 15, &mut work, &mut chars).unwrap();
        println!("FILE {file} {rawhex}");
        for p in parts(&b) {
            println!("PART {p}");
        }
    }
}
