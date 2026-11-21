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

#[test]
fn transaction_parser_and_sighashes_never_panic() {
    use bp_bitcoin::sighash::{self, SegwitV0Hashes, TaprootHashes};
    use bp_bitcoin::tx::{Tx, TxOut};
    // a valid segwit transaction to mutate (BIP-143 native P2WPKH, signed)
    let signed: Vec<u8> = (0..BIP143_SIGNED.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&BIP143_SIGNED[i..i + 2], 16).unwrap())
        .collect();
    let mut rng = Rng(0x7478);
    let mut parsed = 0;
    for i in 0..30_000 {
        let data = if i % 10 == 0 {
            let n = rng.below(300);
            rng.bytes(n)
        } else {
            mutate(&mut rng, &signed)
        };
        let Ok(tx) = Tx::parse(&data) else { continue };
        parsed += 1;
        let _ = tx.txid();
        for j in 0..tx.n_inputs() + 1 {
            let _ = tx.input(j);
            let _ = tx.witness(j).count();
        }
        let _ = tx.outputs().count();
        let n = rng.below(40);
        let code = rng.bytes(n);
        let input = rng.below(tx.n_inputs() + 2);
        let _ = sighash::legacy(&tx, input, &code, rng.next() as u32);
        let v0 = SegwitV0Hashes::new(&tx);
        let _ = sighash::segwit_v0(&tx, &v0, input, &code, rng.next(), rng.next() as u32);
        let n = tx.n_inputs() + rng.below(2);
        let prev: Vec<TxOut> = (0..n).map(|_| TxOut::new(rng.next(), &code)).collect();
        if let Some(h) = TaprootHashes::new(&tx, &prev[..]) {
            let _ = sighash::taproot_key_spend(&tx, &h, &prev[..], input, rng.next() as u8);
        }
    }
    assert!(parsed > 1000, "too few mutations parsed: {parsed}");
}

const BIP143_SIGNED: &str = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";

#[test]
fn address_parser_never_panics() {
    use bp_bitcoin::addrcheck::Target;
    use bp_bitcoin::Network;
    let valid = [
        &b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"[..],
        b"bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        b"tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
        b"bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
        b"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        b"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        b"bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
    ];
    let mut rng = Rng(0xadd7);
    for i in 0..30_000 {
        let v = if i % 3 == 0 {
            let n = rng.below(100);
            rng.bytes(n)
        } else {
            let k = rng.below(valid.len());
            mutate(&mut rng, valid[k])
        };
        let Ok(s) = core::str::from_utf8(&v) else { continue };
        for net in Network::ALL {
            if let Ok(t) = Target::parse(s, net) {
                assert!(matches!(t.script().len(), 22 | 23 | 25 | 34));
            }
        }
    }
}

#[test]
fn armored_messages_never_panic() {
    use bp_bitcoin::message::{check_message, parse_armored, verify};
    use bp_bitcoin::Network;
    let valid = b"-----BEGIN BITCOIN SIGNED MESSAGE-----\naaaaaaaaaaaaaaaaaa\n-----BEGIN BITCOIN SIGNATURE-----\ntb1qkxgmh66fdthecudx042feulz3ymzkyuf7gma0x\nJ3jE1G2pv+6GG35Unak824xig8GzotLE8pFfvNwlgGU7KebANAxo7RuwybCNXrK9+RvjUEohtffM521N+phQNX0=\n-----END BITCOIN SIGNATURE-----\n";
    let a = parse_armored(valid).unwrap();
    assert!(verify(a.address, Network::Testnet, a.message, a.signature).is_ok());
    let mut rng = Rng(0x5167);
    let mut parsed = 0;
    for i in 0..4000 {
        let v = if i % 4 == 0 {
            let n = rng.below(300);
            rng.bytes(n)
        } else {
            mutate(&mut rng, valid)
        };
        let _ = check_message(&v);
        if let Some(a) = parse_armored(&v) {
            parsed += 1;
            let _ = verify(a.address, Network::Testnet, a.message, a.signature);
        }
    }
    assert!(parsed > 100);
}

#[test]
fn bip322_never_panics() {
    use bp_bitcoin::bip322::{classify_psbt, verify_simple};
    use bp_bitcoin::Network;
    let sigs = [
        &b"smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="[..],
        b"AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R",
    ];
    let addrs = [
        "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
        "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler",
    ];
    let mut rng = Rng(0xb322);
    for i in 0..3000 {
        let k = rng.below(2);
        let v = mutate(&mut rng, sigs[k]);
        if let Ok(s) = core::str::from_utf8(&v) {
            let _ = verify_simple(addrs[i % 2], Network::Mainnet, b"Hello World", s);
        }
    }
    // mutated message PSBTs
    let base = message_psbt_bytes();
    let mut msgs = 0;
    for _ in 0..3000 {
        let v = mutate(&mut rng, &base);
        if let Ok(p) = bp_bitcoin::psbt::Psbt::parse(&v) {
            if matches!(classify_psbt(&p), bp_bitcoin::bip322::PsbtKind::Message { .. }) {
                msgs += 1;
            }
        }
    }
    assert!(msgs > 0);
}

/// A minimal BIP-322 PSBT: global tx + 0x09, input 0 with witness UTXO.
fn message_psbt_bytes() -> Vec<u8> {
    use bp_bitcoin::bip322::{to_sign, to_spend_txid};
    let challenge = [&[0x00, 0x14][..], &[0x2b; 20]].concat();
    let msg = b"Hello World";
    let tx = to_sign(&to_spend_txid(&challenge, msg).unwrap());
    let mut p = b"psbt\xff".to_vec();
    p.extend_from_slice(&[1, 0x00, tx.len() as u8]);
    p.extend_from_slice(&tx);
    p.extend_from_slice(&[1, 0x09, msg.len() as u8]);
    p.extend_from_slice(msg);
    p.push(0);
    // input map: witness UTXO (value 0, challenge)
    let mut utxo = vec![0u8; 8];
    utxo.push(challenge.len() as u8);
    utxo.extend_from_slice(&challenge);
    p.extend_from_slice(&[1, 0x01, utxo.len() as u8]);
    p.extend_from_slice(&utxo);
    p.push(0);
    // output map
    p.push(0);
    p
}
