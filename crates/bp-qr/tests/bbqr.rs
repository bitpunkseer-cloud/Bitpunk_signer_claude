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

// ---------- joining ----------

use bp_qr::bbqr::{parse_header, JoinError, Joiner};

fn join(parts: &[String]) -> Result<Vec<u8>, JoinError> {
    let mut store = vec![0u8; 64 * 1024];
    let mut j = Joiner::new(&mut store);
    let mut done = false;
    for p in parts {
        done = j.add(p.as_bytes())?;
    }
    assert!(done);
    let mut work = vec![0u8; 64 * 1024];
    let mut out = vec![0u8; 64 * 1024];
    let n = j.finish(&mut work, &mut out)?;
    Ok(out[..n].to_vec())
}

#[test]
fn joins_reference_parts_in_any_order() {
    for (file, _, _, _, _, _, rawhex, expected) in BBQR_VECTORS {
        let raw = unhex(rawhex);
        let mut parts: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        parts.reverse();
        // repeats are ignored
        let again = parts[0].clone();
        parts.push(again);
        assert_eq!(join(&parts).unwrap(), raw, "{file}");
    }
}

#[test]
fn joins_our_compressed_parts() {
    let mut rng = 7u64;
    for len in [10usize, 300, 2000, 9000] {
        let raw: Vec<u8> = (0..len)
            .map(|i| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                if i % 3 == 0 {
                    rng as u8
                } else {
                    (i % 17) as u8
                }
            })
            .collect();
        let mut work = vec![0u8; 16384];
        let mut chars = vec![0u8; 32768];
        let b = Bbqr::new(&raw, FileType::Psbt, Encoding::Zlib, 5, 12, &mut work, &mut chars).unwrap();
        let mut list = parts(&b);
        let half = list.len() / 2;
        list.rotate_left(half);
        assert_eq!(join(&list).unwrap(), raw, "len {len}");
    }
}

#[test]
fn rejects_mixed_files_and_bad_headers() {
    let a: Vec<String> = BBQR_VECTORS
        .iter()
        .find(|v| v.7.len() >= 2)
        .unwrap()
        .7
        .iter()
        .map(|s| s.to_string())
        .collect();
    let b: Vec<String> = BBQR_VECTORS
        .iter()
        .find(|v| v.7.len() != a.len())
        .unwrap()
        .7
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut store = vec![0u8; 64 * 1024];
    let mut j = Joiner::new(&mut store);
    j.add(a[0].as_bytes()).unwrap();
    assert_eq!(j.add(b[0].as_bytes()), Err(JoinError::Mismatch));
    // same index, different content
    let mut forged = a[0].clone().into_bytes();
    let last = forged.len() - 1;
    forged[last] = if forged[last] == b'A' { b'B' } else { b'A' };
    assert_eq!(j.add(&forged), Err(JoinError::Mismatch));
    let mut work = vec![0u8; 1024];
    let mut out = vec![0u8; 1024];
    assert_eq!(j.finish(&mut work, &mut out), Err(JoinError::Incomplete));
    for bad in [
        "", "B$", "B$X01000", "B$HP0000", "B$HP0101", "X$HP0100", "B$Hp0100",
    ] {
        assert!(parse_header(bad.as_bytes()).is_none(), "{bad}");
    }
    assert_eq!(j.add(b"hello"), Err(JoinError::NotBbqr));
}

#[test]
fn specter_parts_join() {
    let text = b"[73c5da0a/84h/0h/0h]zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    let n = specter::count(text.len(), 40);
    let mut parts: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            let mut out = [0u8; 100];
            let k = specter::part(text, 40, i, &mut out).unwrap();
            out[..k].to_vec()
        })
        .collect();
    parts.reverse();
    let mut store = [0u8; 1024];
    let mut j = specter::Joiner::new(&mut store);
    for (k, p) in parts.iter().enumerate() {
        assert_eq!(j.add(p).unwrap(), k + 1 == n);
    }
    let mut out = [0u8; 300];
    let len = j.finish(&mut out).unwrap();
    assert_eq!(&out[..len], &text[..]);
    assert_eq!(specter::parse(b"p2of3 abc"), Some((2, 3, &b"abc"[..])));
    for bad in ["p0of3 x", "p4of3 x", "p1of3x", "q1of3 x", "pof3 x", "p1of x"] {
        assert!(specter::parse(bad.as_bytes()).is_none(), "{bad}");
    }
}

#[test]
fn parts_from_encoded_chars_join_back() {
    use bp_qr::bbqr::{Bbqr, Encoding, FileType, Joiner};
    let raw: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 13) as u8).collect();
    let mut work = vec![0u8; 4096];
    let mut chars = vec![0u8; 8192];
    let full = Bbqr::new(&raw, FileType::Psbt, Encoding::Zlib, 1, 12, &mut work, &mut chars).unwrap();
    let enc = full.encoding();
    let kept = full.chars().to_vec();
    for max_ver in [5u8, 9, 12, 20] {
        let b = Bbqr::from_encoded(&kept, enc, FileType::Psbt, 1, max_ver).unwrap();
        let mut store = vec![0u8; 16384];
        let mut j = Joiner::new(&mut store);
        let mut done = false;
        for i in 0..b.count() {
            let mut part = [0u8; 4096];
            let n = b.part(i, &mut part).unwrap();
            done = j.add(&part[..n]).unwrap();
        }
        assert!(done, "max version {max_ver}");
        let mut out = vec![0u8; 4096];
        let mut w2 = vec![0u8; 8192];
        let n = j.finish(&mut w2, &mut out).unwrap();
        assert_eq!(&out[..n], &raw[..], "max version {max_ver}");
    }
}
