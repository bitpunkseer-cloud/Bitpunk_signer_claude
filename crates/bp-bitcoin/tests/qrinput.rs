//! QR input: what each kind of scanned content is recognised as, and the
//! frame collector for UR, BBQr and Specter animations.

use bp_bitcoin::qrinput::{classify, AddressKind, Collector, Content, Feed, SeedSource, Source};
use bp_bitcoin::{base64, Network};
use bp_qr::bbqr::{specter, Bbqr, Encoding, FileType};
use bp_qr::ur::{cbor, UrEncoder};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Minimal valid v0 PSBT: 1 input, 2 outputs.
fn psbt() -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&2u32.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&[0x11; 32]);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.push(0);
    tx.extend_from_slice(&0xFFFF_FFFDu32.to_le_bytes());
    tx.push(2);
    for v in [50_000u64, 49_000] {
        tx.extend_from_slice(&v.to_le_bytes());
        tx.push(22);
        tx.extend_from_slice(&[0x00, 0x14]);
        tx.extend_from_slice(&[0x22; 20]);
    }
    tx.extend_from_slice(&0u32.to_le_bytes());
    let mut p = b"psbt\xff".to_vec();
    p.extend_from_slice(&[1, 0x00, tx.len() as u8]);
    p.extend_from_slice(&tx);
    p.extend_from_slice(&[0, 0, 0, 0]);
    p
}

fn big_psbt() -> Vec<u8> {
    // same transaction, plus a large unknown key in the input map
    let mut p = psbt();
    p.truncate(p.len() - 3); // drop the three empty maps
    p.extend_from_slice(&[2, 0xFC, 0x01]); // key: proprietary-ish
    p.extend_from_slice(&[0xFD, 0xE8, 0x03]); // value length 1000
    p.extend((0..1000).map(|i| (i * 7 % 256) as u8));
    p.extend_from_slice(&[0, 0, 0]); // end input map, 2 output maps
    p
}

fn seed_words(c: &Content) -> Option<(String, SeedSource)> {
    match c {
        Content::Seed { mnemonic, source } => {
            let words: Vec<&str> = (0..mnemonic.len()).map(|i| mnemonic.word(i)).collect();
            Some((words.join(" "), *source))
        }
        _ => None,
    }
}

fn cls(data: &[u8]) -> Content {
    let mut out = vec![0u8; 8192];
    classify(data, &mut out).unwrap()
}

#[test]
fn seeds_from_seedqr_and_words() {
    let digits = format!("{}0003", "0000".repeat(11));
    assert_eq!(
        seed_words(&cls(digits.as_bytes())),
        Some((ABANDON.into(), SeedSource::SeedQrStandard))
    );
    assert_eq!(
        seed_words(&cls(&[0u8; 16])),
        Some((ABANDON.into(), SeedSource::SeedQrCompact))
    );
    assert_eq!(
        seed_words(&cls(ABANDON.as_bytes())),
        Some((ABANDON.into(), SeedSource::Words))
    );
    let short = "aban aban aban aban aban aban aban aban aban aban aban abou";
    assert_eq!(
        seed_words(&cls(short.as_bytes())),
        Some((ABANDON.into(), SeedSource::Words))
    );
    assert_eq!(
        seed_words(&cls(ABANDON.to_uppercase().as_bytes())),
        Some((ABANDON.into(), SeedSource::Words))
    );
    // a bad checksum is not a seed
    let bad = ABANDON.replace("about", "abandon");
    assert!(matches!(cls(bad.as_bytes()), Content::Text { .. }));
}

#[test]
fn psbt_in_every_static_form() {
    let p = psbt();
    let mut b64 = vec![0u8; 400];
    let n = base64::encode(&p, &mut b64).unwrap();
    let hex: String = p.iter().map(|b| format!("{b:02x}")).collect();
    for data in [p.clone(), b64[..n].to_vec(), hex.into_bytes()] {
        let mut out = vec![0u8; 4096];
        match classify(&data, &mut out).unwrap() {
            Content::Psbt { len, summary } => {
                assert_eq!(&out[..len], &p[..]);
                assert_eq!((summary.inputs, summary.outputs), (1, 2));
            }
            _ => panic!("not a PSBT"),
        }
    }
}

#[test]
fn addresses_keys_descriptors_text() {
    let cases: [(&str, Network, AddressKind, &str); 7] = [
        (
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            Network::Mainnet,
            AddressKind::SegwitV0,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        ),
        (
            "BC1QCR8TE4KR609GCAWUTMRZA0J4XV80JY8Z306FYU",
            Network::Mainnet,
            AddressKind::SegwitV0,
            "BC1QCR8TE4KR609GCAWUTMRZA0J4XV80JY8Z306FYU",
        ),
        (
            "bitcoin:bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr?amount=0.001&label=x",
            Network::Mainnet,
            AddressKind::Taproot,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        ),
        (
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            Network::Mainnet,
            AddressKind::P2pkh,
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        ),
        (
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            Network::Mainnet,
            AddressKind::P2sh,
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        ),
        (
            "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
            Network::Testnet,
            AddressKind::SegwitV0,
            "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
        ),
        (
            "BITCOIN:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            Network::Mainnet,
            AddressKind::P2pkh,
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        ),
    ];
    for (text, net, kind, addr) in cases {
        let mut out = vec![0u8; 256];
        match classify(text.as_bytes(), &mut out).unwrap() {
            Content::Address {
                len,
                network,
                kind: k,
            } => {
                assert_eq!((network, k), (net, kind), "{text}");
                assert_eq!(&out[..len], addr.as_bytes());
            }
            _ => panic!("{text} is not an address"),
        }
    }
    let xpub = "[73c5da0a/84h/0h/0h]zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    assert!(matches!(
        cls(xpub.as_bytes()),
        Content::Xpub {
            network: Network::Mainnet,
            depth: 3,
            ..
        }
    ));
    let desc = "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#abcd";
    assert!(matches!(cls(desc.as_bytes()), Content::Descriptor { .. }));
    assert!(matches!(cls(b"  hello world  "), Content::Text { len: 11 }));
    assert!(matches!(cls(&[1, 2, 3, 200, 7]), Content::Binary { len: 5 }));
    // a broken address checksum is just text
    assert!(matches!(
        cls(b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv"),
        Content::Text { .. }
    ));
}

fn collect(frames: &[Vec<u8>]) -> (Content, Source, Vec<u8>) {
    let mut store = vec![0u8; 64 * 1024];
    let mut c = Collector::new(&mut store);
    let mut last = Feed::Ignored;
    for f in frames {
        last = c.feed(f);
        if last == Feed::Complete {
            break;
        }
    }
    assert_eq!(last, Feed::Complete);
    let mut work = vec![0u8; 32 * 1024];
    let mut out = vec![0u8; 32 * 1024];
    let (content, source) = c.finish(&mut work, &mut out).unwrap();
    (content, source, out)
}

fn assert_psbt(r: (Content, Source, Vec<u8>), want: &[u8], src: Source) {
    let (content, source, out) = r;
    assert_eq!(source, src);
    match content {
        Content::Psbt { len, summary } => {
            assert_eq!(&out[..len], want);
            assert_eq!((summary.inputs, summary.outputs), (1, 2));
        }
        _ => panic!("not a PSBT"),
    }
}

#[test]
fn animated_psbt_over_ur_bbqr_and_specter() {
    let p = big_psbt();
    // UR crypto-psbt: CBOR byte string around the PSBT
    let mut cb = vec![0u8; p.len() + 8];
    let mut w = cbor::Writer::new(&mut cb);
    w.bytes(&p).unwrap();
    let n = w.len();
    let enc = UrEncoder::new("crypto-psbt", &cb[..n], 120).unwrap();
    let frames: Vec<Vec<u8>> = (1..=enc.seq_len() as u32 * 3)
        .filter(|s| s % 4 != 0) // lost frames
        .map(|s| {
            let mut b = vec![0u8; 1024];
            let k = enc.part(s, &mut b).unwrap();
            b[..k].to_ascii_uppercase()
        })
        .collect();
    assert_psbt(collect(&frames), &p, Source::Ur);

    // BBQr Z, parts in reverse order
    let mut work = vec![0u8; 8192];
    let mut chars = vec![0u8; 16384];
    let b = Bbqr::new(&p, FileType::Psbt, Encoding::Zlib, 5, 8, &mut work, &mut chars).unwrap();
    let mut frames: Vec<Vec<u8>> = (0..b.count())
        .map(|i| {
            let mut out = vec![0u8; 1024];
            let k = b.part(i, &mut out).unwrap();
            out[..k].to_vec()
        })
        .collect();
    frames.reverse();
    assert!(frames.len() > 1);
    assert_psbt(collect(&frames), &p, Source::Bbqr);

    // Specter pM/N of the Base64 text
    let mut b64 = vec![0u8; 4096];
    let n = base64::encode(&p, &mut b64).unwrap();
    let count = specter::count(n, 200);
    let frames: Vec<Vec<u8>> = (0..count)
        .map(|i| {
            let mut out = vec![0u8; 512];
            let k = specter::part(&b64[..n], 200, i, &mut out).unwrap();
            out[..k].to_vec()
        })
        .collect();
    assert_psbt(collect(&frames), &p, Source::Specter);
}

#[test]
fn ur_bytes_and_static_frames() {
    let mut cb = vec![0u8; 200];
    let mut w = cbor::Writer::new(&mut cb);
    w.bytes(ABANDON.as_bytes()).unwrap();
    let n = w.len();
    let mut enc = UrEncoder::new("bytes", &cb[..n], 500).unwrap();
    let mut b = vec![0u8; 1024];
    let k = enc.next_part(&mut b).unwrap();
    let (content, source, _) = collect(&[b[..k].to_vec()]);
    assert_eq!(source, Source::Ur);
    assert_eq!(seed_words(&content).unwrap().0, ABANDON);

    let (content, source, out) = collect(&[b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".to_vec()]);
    assert_eq!(source, Source::Static);
    assert!(matches!(content, Content::Address { len: 42, .. }));
    assert_eq!(&out[..42], b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
}

#[test]
fn switching_codes_restarts_collection() {
    let p = big_psbt();
    let mut cb = vec![0u8; p.len() + 8];
    let mut w = cbor::Writer::new(&mut cb);
    w.bytes(&p).unwrap();
    let n = w.len();
    let enc = UrEncoder::new("crypto-psbt", &cb[..n], 150).unwrap();
    let mut store = vec![0u8; 64 * 1024];
    let mut c = Collector::new(&mut store);
    let mut b = vec![0u8; 1024];
    let k = enc.part(1, &mut b).unwrap();
    assert_eq!(c.feed(&b[..k]), Feed::Progress);
    assert_eq!(c.progress().source, Some(Source::Ur));
    // two stray frames are ignored, the third foreign one switches over
    assert_eq!(c.feed(b"hello"), Feed::Ignored);
    assert_eq!(c.feed(b"hello"), Feed::Ignored);
    assert_eq!(
        c.feed(b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
        Feed::Complete
    );
    assert_eq!(c.progress().source, Some(Source::Static));
    c.reset();
    assert_eq!(c.progress().source, None);
}
