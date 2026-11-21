//! Coldcard's test PSBTs (Coldcard/firmware testing/data, MIT + Commons
//! Clause): not stored in this repository. `tools/fetch_coldcard_psbts.sh`
//! downloads them at a pinned commit into `target/coldcard-psbts`; without
//! them this test only reports that it was skipped.

use bp_bitcoin::psbt::{ParseError, Psbt};

fn load(raw: &[u8]) -> Vec<u8> {
    // binary, hex or base64
    if raw.starts_with(b"psbt\xff") {
        return raw.to_vec();
    }
    let text: Vec<u8> = raw.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    if text.starts_with(b"70736274ff") {
        return (0..text.len() / 2)
            .map(|i| u8::from_str_radix(std::str::from_utf8(&text[2 * i..2 * i + 2]).unwrap(), 16).unwrap())
            .collect();
    }
    let mut out = vec![0u8; text.len()];
    match bp_bitcoin::base64::decode(&text, &mut out) {
        Ok(n) => out[..n].to_vec(),
        Err(_) => raw.to_vec(),
    }
}

/// Files the strict parser refuses, and why; every other file parses.
const REFUSED: &[(&str, ParseError)] = &[
    ("dup_keys.psbt", ParseError::DuplicateKey),
    ("filled_scriptsig.psbt", ParseError::UnsignedTx),
    ("missing_ins.psbt", ParseError::MapCount),
    ("missing_txn.psbt", ParseError::NoUnsignedTx),
    ("truncated.psbt", ParseError::Truncated),
    // input keys 0x0e-0x12, unknown when the file was written, are PSBT v2
    // fields today: refused in v0 as Bitcoin Core does
    ("unknowns-ins.psbt", ParseError::V2Field),
    ("xpub-vector.psbt", ParseError::Value),
];

#[test]
fn coldcard_psbt_corpus() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/coldcard-psbts");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        println!("skipped: run tools/fetch_coldcard_psbts.sh first");
        return;
    };
    let mut names: Vec<_> = entries
        .flatten()
        .map(|e| e.file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 37);
    let master = bp_bitcoin::bip32::Xpriv::master(&[0x42; 32]).unwrap();
    for n in &names {
        let raw = load(&std::fs::read(dir.join(n)).unwrap());
        let want = REFUSED.iter().find(|(f, _)| f == n).map(|(_, e)| *e);
        match (Psbt::parse(&raw), want) {
            (Err(e), Some(w)) => assert_eq!(e, w, "{n}"),
            (Err(e), None) => panic!("{n}: refused with {e:?}"),
            (Ok(_), Some(w)) => panic!("{n}: accepted, expected {w:?}"),
            (Ok(p), None) => {
                // byte-identical re-serialization, and rust-bitcoin agrees
                struct V(Vec<u8>);
                impl bp_bitcoin::tx::Sink for V {
                    fn put(&mut self, b: &[u8]) {
                        self.0.extend_from_slice(b);
                    }
                }
                let mut out = V(Vec::new());
                p.write(&mut out);
                assert_eq!(out.0, raw, "{n}");
                let r = bitcoin::psbt::Psbt::deserialize(&raw).unwrap();
                use bitcoin::hashes::Hash;
                assert_eq!(p.tx.txid(), r.unsigned_tx.compute_txid().to_byte_array(), "{n}");
                // validation of a PSBT for another seed never panics; a
                // script that does not match its commitment is an attack
                // whoever owns the input
                let ctx = bp_bitcoin::validate::Context::new(&master, bp_bitcoin::Network::Testnet);
                let rep = bp_bitcoin::validate::validate(&raw, &ctx).1;
                if n == "wit-utxo-not-match-redeem-scr.psbt" {
                    assert!(
                        rep.worst() == Some(bp_bitcoin::validate::Class::Attack),
                        "{n}: {:?}",
                        rep.issues()
                    );
                }
                assert!(!rep.can_sign(true), "{n}: another seed must not sign");
            }
        }
    }
}
