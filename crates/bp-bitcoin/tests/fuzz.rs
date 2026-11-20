//! Deterministic fuzzing of everything a QR code can feed in: random bytes
//! and mutations of valid payloads must never panic, overrun a buffer or
//! hang. (QR content is untrusted input.)

use bp_bitcoin::qrinput::{classify, classify_ur, Collector, Feed};
use bp_bitcoin::{base64, psbt};
use bp_qr::bbqr::{specter, Bbqr, Encoding, FileType};
use bp_qr::ur::cbor::{Reader, Writer};
use bp_qr::ur::UrEncoder;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// Flip, insert, delete, replace or truncate a few bytes.
fn mutate(rng: &mut Rng, v: &[u8]) -> Vec<u8> {
    let mut m = v.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(5) {
            0 if !m.is_empty() => {
                let i = rng.below(m.len());
                m[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(m.len() + 1);
                m.insert(i, rng.next() as u8);
            }
            2 if !m.is_empty() => {
                let i = rng.below(m.len());
                m.remove(i);
            }
            3 if !m.is_empty() => {
                let i = rng.below(m.len());
                const CHARS: &[u8] = b"0123456789abcdefABCDEF :/?=[]()hpof-$\n";
                m[i] = CHARS[rng.below(CHARS.len())];
            }
            _ => {
                let n = rng.below(m.len() + 1);
                m.truncate(n);
            }
        }
    }
    m
}

fn sample_psbt() -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&2u32.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&[0x11; 36]);
    tx.push(0);
    tx.extend_from_slice(&[0xFF; 4]);
    tx.push(2);
    for _ in 0..2 {
        tx.extend_from_slice(&1000u64.to_le_bytes());
        tx.push(1);
        tx.push(0x51);
    }
    tx.extend_from_slice(&[0; 4]);
    let mut p = b"psbt\xff".to_vec();
    p.extend_from_slice(&[1, 0, tx.len() as u8]);
    p.extend_from_slice(&tx);
    p.extend_from_slice(&[0, 0, 0, 0]);
    p
}

fn seeds() -> Vec<Vec<u8>> {
    let p = sample_psbt();
    let mut b64 = vec![0u8; 400];
    let n = base64::encode(&p, &mut b64).unwrap();
    vec![
        format!("{}0003", "0000".repeat(11)).into_bytes(),
        vec![0u8; 16],
        b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_vec(),
        b"aban aban aban aban aban aban aban aban aban aban aban abou".to_vec(),
        p.clone(),
        b64[..n].to_vec(),
        p.iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes(),
        b"bitcoin:bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu?amount=0.1".to_vec(),
        b"bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr".to_vec(),
        b"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_vec(),
        b"[73c5da0a/84h/0h/0h]zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs".to_vec(),
        b"wsh(sortedmulti(2,[aa/48h/0h/0h/2h]xpub1,[bb]xpub2))".to_vec(),
    ]
}

#[test]
fn classify_never_panics() {
    let mut rng = Rng(1);
    let mut out = vec![0u8; 4096];
    let seeds = seeds();
    for i in 0..20_000 {
        let data = if i % 4 == 0 {
            let n = rng.below(200);
            rng.bytes(n)
        } else {
            mutate(&mut rng, &seeds[i % seeds.len()])
        };
        let _ = classify(&data, &mut out);
        // tiny output buffers must fail cleanly too
        let _ = classify(&data, &mut out[..rng.below(40)]);
    }
}

#[test]
fn psbt_base64_and_cbor_never_panic() {
    let mut rng = Rng(2);
    let p = sample_psbt();
    let mut out = vec![0u8; 1024];
    for _ in 0..20_000 {
        let m = mutate(&mut rng, &p);
        if let Ok(s) = psbt::summary(&m) {
            assert!(s.inputs <= 10_000 && s.outputs <= 10_000);
        }
        let _ = base64::decode(&m, &mut out);
        let mut r = Reader::new(&m);
        for _ in 0..8 {
            match r.peek_major() {
                Some(0) => drop(r.uint()),
                Some(2) => drop(r.bytes()),
                Some(3) => drop(r.text()),
                Some(4) => drop(r.array()),
                Some(5) => drop(r.map()),
                Some(6) => drop(r.tag()),
                _ => break,
            }
        }
        for ty in ["crypto-psbt", "bytes", "crypto-seed", "seed", "other"] {
            let _ = classify_ur(ty, &m, &mut out);
        }
    }
}

fn ur_frames(rng: &mut Rng) -> Vec<Vec<u8>> {
    let len = 300 + rng.below(700);
    let p = rng.bytes(len);
    let mut cb = vec![0u8; p.len() + 8];
    let mut w = Writer::new(&mut cb);
    w.bytes(&p).unwrap();
    let n = w.len();
    let enc = UrEncoder::new("crypto-psbt", &cb[..n], 40 + rng.below(100)).unwrap();
    (1..=enc.seq_len() as u32 + 5)
        .map(|s| {
            let mut b = vec![0u8; 1024];
            let k = enc.part(s, &mut b).unwrap();
            b[..k].to_vec()
        })
        .collect()
}

fn bbqr_frames(rng: &mut Rng) -> Vec<Vec<u8>> {
    let len = 200 + rng.below(1500);
    let raw = rng.bytes(len);
    let mut work = vec![0u8; 4096];
    let mut chars = vec![0u8; 8192];
    let enc = [Encoding::Hex, Encoding::Base32, Encoding::Zlib][rng.below(3)];
    let b = Bbqr::new(&raw, FileType::Psbt, enc, 3, 6, &mut work, &mut chars).unwrap();
    (0..b.count())
        .map(|i| {
            let mut out = vec![0u8; 1024];
            let k = b.part(i, &mut out).unwrap();
            out[..k].to_vec()
        })
        .collect()
}

fn specter_frames(rng: &mut Rng) -> Vec<Vec<u8>> {
    let text: Vec<u8> = (0..300).map(|_| b"abcdefghij"[rng.below(10)]).collect();
    (0..specter::count(text.len(), 60))
        .map(|i| {
            let mut out = vec![0u8; 200];
            let k = specter::part(&text, 60, i, &mut out).unwrap();
            out[..k].to_vec()
        })
        .collect()
}

#[test]
fn collector_never_panics_on_mutated_animations() {
    let mut rng = Rng(3);
    let mut c = Box::new(Collector::<{ 32 * 1024 }>::new());
    let mut work = vec![0u8; 32 * 1024];
    let mut out = vec![0u8; 32 * 1024];
    for round in 0..300 {
        let frames = match round % 3 {
            0 => ur_frames(&mut rng),
            1 => bbqr_frames(&mut rng),
            _ => specter_frames(&mut rng),
        };
        c.reset();
        for f in &frames {
            let f = if rng.below(3) == 0 {
                mutate(&mut rng, f)
            } else {
                f.clone()
            };
            if c.feed(&f) == Feed::Complete {
                let _ = c.finish(&mut work, &mut out);
                break;
            }
            let _ = c.progress();
        }
        // and pure garbage in between
        for _ in 0..5 {
            let n = rng.below(120);
            let g = rng.bytes(n);
            if c.feed(&g) == Feed::Complete {
                let _ = c.finish(&mut work, &mut out[..rng.below(64)]);
            }
        }
    }
}
