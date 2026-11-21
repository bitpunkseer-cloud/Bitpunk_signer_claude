//! Strict PSBT v0 parser: Bitcoin Core's PSBT corpus, the BIP-174 and
//! BIP-371 vectors, byte-identical re-serialization, and every field
//! compared with rust-bitcoin's parser (test-only reference).

#[allow(dead_code)] // signer keys are used by the signing tests
#[path = "data/bip174_vectors.rs"]
mod bip174;
#[path = "data/bip371_vectors.rs"]
mod bip371;
#[path = "data/core_psbt.rs"]
mod core_psbt;

use bitcoin::hashes::Hash;
use bp_bitcoin::psbt::{ParseError, Psbt};
use bp_bitcoin::tx::Tx;
use bp_bitcoin::{base64, psbt};

fn try_b64(s: &str) -> Option<Vec<u8>> {
    let mut out = vec![0u8; s.len() * 3 / 4 + 3];
    let n = base64::decode(s.as_bytes(), &mut out).ok()?;
    out.truncate(n);
    Some(out)
}

fn b64(s: &str) -> Vec<u8> {
    try_b64(s).expect("base64")
}

/// Bitpunk refuses unsigned transactions without inputs or outputs
/// (nothing to sign; zero outputs is consensus-invalid).
fn empty_tx(raw: &[u8]) -> bool {
    bitcoin::psbt::Psbt::deserialize(raw)
        .map(|r| r.unsigned_tx.input.is_empty() || r.unsigned_tx.output.is_empty())
        .unwrap_or(false)
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Parse, re-serialize byte for byte, and compare every field with
/// rust-bitcoin.
fn accept(raw: &[u8], what: &str) {
    let p = Psbt::parse(raw).unwrap_or_else(|e| panic!("{what}: {e:?}"));
    let mut out = Vec::new();
    struct V<'a>(&'a mut Vec<u8>);
    impl bp_bitcoin::tx::Sink for V<'_> {
        fn put(&mut self, b: &[u8]) {
            self.0.extend_from_slice(b);
        }
    }
    p.write(&mut V(&mut out));
    assert_eq!(out, raw, "{what}: re-serialization");
    let r =
        bitcoin::psbt::Psbt::deserialize(raw).unwrap_or_else(|e| panic!("{what}: rust-bitcoin rejects: {e}"));
    compare(&p, &r, what);
}

fn compare(p: &Psbt, r: &bitcoin::psbt::Psbt, what: &str) {
    assert_eq!(
        p.tx.txid(),
        r.unsigned_tx.compute_txid().to_byte_array(),
        "{what}"
    );
    // global xpubs
    let ours: Vec<_> = p
        .xpubs()
        .map(|(x, s)| (x.to_vec(), s.fingerprint, s.steps().collect::<Vec<_>>()))
        .collect();
    assert_eq!(ours.len(), r.xpub.len(), "{what}: xpubs");
    for (x, fp, path) in &ours {
        let (rfp, rpath) = r
            .xpub
            .iter()
            .find(|(k, _)| k.encode().as_slice() == &x[4..] || k.encode()[4..] == x[4..])
            .map(|(_, v)| v)
            .unwrap();
        assert_eq!(fp, rfp.as_bytes(), "{what}");
        assert_eq!(
            path,
            &rpath.into_iter().map(|c| u32::from(*c)).collect::<Vec<_>>(),
            "{what}"
        );
    }
    assert_eq!(p.inputs().count(), r.inputs.len());
    for (i, (a, b)) in p.inputs().zip(&r.inputs).enumerate() {
        let w = format!("{what} input {i}");
        assert_eq!(
            a.witness_utxo().map(|o| (o.value, o.script_pubkey.to_vec())),
            b.witness_utxo
                .as_ref()
                .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes())),
            "{w}"
        );
        assert_eq!(
            a.non_witness_utxo().map(|t| t.txid()),
            b.non_witness_utxo
                .as_ref()
                .map(|t| t.compute_txid().to_byte_array()),
            "{w}"
        );
        assert_eq!(a.sighash_type(), b.sighash_type.map(|t| t.to_u32()), "{w}");
        assert_eq!(
            a.redeem_script(),
            b.redeem_script.as_ref().map(|s| s.as_bytes()),
            "{w}"
        );
        assert_eq!(
            a.witness_script(),
            b.witness_script.as_ref().map(|s| s.as_bytes()),
            "{w}"
        );
        assert_eq!(
            a.final_script_sig(),
            b.final_script_sig.as_ref().map(|s| s.as_bytes()),
            "{w}"
        );
        assert_eq!(
            a.final_script_witness().is_some(),
            b.final_script_witness.is_some(),
            "{w}"
        );
        let sigs: Vec<_> = a.partial_sigs().collect();
        assert_eq!(sigs.len(), b.partial_sigs.len(), "{w}");
        for (pk, sig) in sigs {
            let rpk = bitcoin::PublicKey::from_slice(pk).unwrap();
            assert_eq!(&b.partial_sigs[&rpk].to_vec()[..], sig, "{w}");
        }
        let ders: Vec<_> = a.bip32_derivations().collect();
        assert_eq!(ders.len(), b.bip32_derivation.len(), "{w}");
        for (pk, src) in ders {
            let rpk = bitcoin::secp256k1::PublicKey::from_slice(pk).unwrap();
            let (fp, path) = &b.bip32_derivation[&rpk];
            assert_eq!(&src.fingerprint, fp.as_bytes(), "{w}");
            assert_eq!(
                src.steps().collect::<Vec<_>>(),
                path.into_iter().map(|c| u32::from(*c)).collect::<Vec<_>>(),
                "{w}"
            );
        }
        assert_eq!(
            a.tap_key_sig().map(|s| s.to_vec()),
            b.tap_key_sig.map(|s| s.to_vec()),
            "{w}"
        );
        assert_eq!(
            a.tap_internal_key(),
            b.tap_internal_key.map(|k| k.serialize()),
            "{w}"
        );
        assert_eq!(
            a.tap_merkle_root(),
            b.tap_merkle_root.map(|h| h.to_byte_array()),
            "{w}"
        );
        let taps: Vec<_> = a.tap_bip32_derivations().collect();
        assert_eq!(taps.len(), b.tap_key_origins.len(), "{w}");
        for t in taps {
            let k = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&t.xonly).unwrap();
            let (leaves, (fp, path)) = &b.tap_key_origins[&k];
            assert_eq!(t.leaf_hashes.len() / 32, leaves.len(), "{w}");
            assert_eq!(&t.source.fingerprint, fp.as_bytes(), "{w}");
            assert_eq!(
                t.source.steps().collect::<Vec<_>>(),
                path.into_iter().map(|c| u32::from(*c)).collect::<Vec<_>>(),
                "{w}"
            );
        }
        assert_eq!(
            a.has_tap_scripts(),
            !b.tap_scripts.is_empty() || !b.tap_script_sigs.is_empty(),
            "{w}"
        );
    }
    assert_eq!(p.outputs().count(), r.outputs.len());
    for (i, (a, b)) in p.outputs().zip(&r.outputs).enumerate() {
        let w = format!("{what} output {i}");
        assert_eq!(
            a.redeem_script(),
            b.redeem_script.as_ref().map(|s| s.as_bytes()),
            "{w}"
        );
        assert_eq!(
            a.witness_script(),
            b.witness_script.as_ref().map(|s| s.as_bytes()),
            "{w}"
        );
        assert_eq!(a.bip32_derivations().count(), b.bip32_derivation.len(), "{w}");
        assert_eq!(
            a.tap_internal_key(),
            b.tap_internal_key.map(|k| k.serialize()),
            "{w}"
        );
        assert_eq!(a.tap_tree().is_some(), b.tap_tree.is_some(), "{w}");
        assert_eq!(a.tap_bip32_derivations().count(), b.tap_key_origins.len(), "{w}");
    }
}

/// The global version, read directly (v2 PSBTs are refused as unsupported).
fn declared_version(raw: &[u8]) -> u32 {
    let mut i = 5;
    while i < raw.len() && raw[i] != 0 {
        let kl = raw[i] as usize;
        let key = &raw[i + 1..i + 1 + kl];
        let vl = raw[i + 1 + kl] as usize;
        let val = &raw[i + 2 + kl..i + 2 + kl + vl];
        if key == [0xFB] && val.len() == 4 {
            return u32::from_le_bytes(val.try_into().unwrap());
        }
        i += 2 + kl + vl;
    }
    0
}

#[test]
fn core_invalid_corpus_is_rejected() {
    // (some are not even base64, which is a rejection as well)
    for (i, s) in core_psbt::INVALID.iter().enumerate() {
        if let Some(raw) = try_b64(s) {
            assert!(Psbt::parse(&raw).is_err(), "invalid {i} accepted");
        }
    }
    for (i, (s, msg)) in core_psbt::INVALID_WITH_MSG.iter().enumerate() {
        if let Some(raw) = try_b64(s) {
            assert!(
                Psbt::parse(&raw).is_err(),
                "invalid_with_msg {i} accepted ({msg})"
            );
        }
    }
}

#[test]
fn core_valid_corpus() {
    let mut v2 = 0;
    for (i, s) in core_psbt::VALID.iter().enumerate() {
        let raw = b64(s);
        if declared_version(&raw) == 2 {
            assert_eq!(
                Psbt::parse(&raw).err(),
                Some(ParseError::UnsupportedVersion),
                "valid {i}"
            );
            v2 += 1;
        } else if empty_tx(&raw) {
            assert_eq!(Psbt::parse(&raw).err(), Some(ParseError::UnsignedTx), "valid {i}");
        } else {
            accept(&raw, &format!("core valid {i}"));
        }
    }
    assert!(v2 > 0 && v2 < core_psbt::VALID.len());
    for (i, (_, input, result)) in core_psbt::SIGNER.iter().enumerate() {
        accept(&b64(input), &format!("core signer {i} input"));
        accept(&b64(result), &format!("core signer {i} result"));
    }
}

#[test]
fn bip174_vectors() {
    for (case, s) in bip174::INVALID {
        assert!(Psbt::parse(&b64(s)).is_err(), "accepted: {case}");
    }
    for (case, s) in bip174::VALID {
        let raw = b64(s);
        if empty_tx(&raw) {
            assert_eq!(Psbt::parse(&raw).err(), Some(ParseError::UnsignedTx), "{case}");
        } else {
            accept(&raw, case);
        }
    }
    // structurally valid; the validator must refuse to sign these
    for (case, s) in bip174::SIGNER_FAIL {
        accept(&b64(s), case);
    }
    for (name, h) in [
        ("created", bip174::CREATED),
        ("updated", bip174::UPDATED),
        ("sighash all", bip174::SIGHASH_ALL_ADDED),
        ("signed 1", bip174::SIGNED_1),
        ("signed 2", bip174::SIGNED_2),
        ("combined", bip174::COMBINED),
        ("finalized", bip174::FINALIZED),
        ("unknown a", bip174::UNKNOWN_A),
        ("unknown b", bip174::UNKNOWN_B),
        ("unknown combined", bip174::UNKNOWN_COMBINED),
        ("combine a", bip174::COMBINE_A),
        ("combine b", bip174::COMBINE_B),
        ("combine result", bip174::COMBINE_RESULT),
    ] {
        accept(&unhex(h), name);
    }
    // the extracted transaction spends the same outpoints to the same outputs
    let raw = unhex(bip174::EXTRACTED_TX);
    let tx = Tx::parse(&raw).unwrap();
    let p = unhex(bip174::FINALIZED);
    let p = Psbt::parse(&p).unwrap();
    assert_eq!(tx.outputs_bytes(), p.tx.outputs_bytes());
    assert!(tx
        .inputs()
        .zip(p.tx.inputs())
        .all(|(a, b)| a.outpoint == b.outpoint));
    for prev in [bip174::PREV_TX_1, bip174::PREV_TX_2] {
        Tx::parse(&unhex(prev)).unwrap();
    }
}

#[test]
fn bip371_vectors() {
    for (case, s) in bip371::INVALID {
        assert!(Psbt::parse(&b64(s)).is_err(), "accepted: {case}");
    }
    for (case, s) in bip371::VALID {
        accept(&b64(s), case);
    }
}

#[test]
fn specific_errors() {
    let raw = unhex(bip174::CREATED);
    assert!(Psbt::parse(&raw).is_ok());
    // magic, truncation, trailing data
    assert_eq!(Psbt::parse(b"psbt").err(), Some(ParseError::Magic));
    assert_eq!(
        Psbt::parse(&raw[..raw.len() - 1]).err(),
        Some(ParseError::MapCount)
    );
    assert_eq!(
        Psbt::parse(&raw[..raw.len() - 3]).err(),
        Some(ParseError::MapCount)
    );
    let mut t = raw.clone();
    t.push(0);
    assert_eq!(Psbt::parse(&t).err(), Some(ParseError::TrailingData));
    // a duplicate global key (the unsigned tx twice)
    let txlen = raw[7] as usize;
    let pair = raw[5..8 + txlen].to_vec();
    let mut d = raw[..8 + txlen].to_vec();
    d.extend_from_slice(&pair);
    d.extend_from_slice(&raw[8 + txlen..]);
    assert_eq!(Psbt::parse(&d).err(), Some(ParseError::DuplicateKey));
    // version 1 and 2
    for v in [1u8, 2] {
        let mut d = raw[..8 + txlen].to_vec();
        d.extend_from_slice(&[1, 0xFB, 4, v, 0, 0, 0]);
        d.extend_from_slice(&raw[8 + txlen..]);
        assert_eq!(Psbt::parse(&d).err(), Some(ParseError::UnsupportedVersion));
    }
    // a v2 field in a v0 PSBT
    let mut d = raw[..8 + txlen].to_vec();
    d.extend_from_slice(&[1, 0x04, 1, 2]);
    d.extend_from_slice(&raw[8 + txlen..]);
    assert_eq!(Psbt::parse(&d).err(), Some(ParseError::V2Field));
    // version 0 stated explicitly is fine
    let mut d = raw[..8 + txlen].to_vec();
    d.extend_from_slice(&[1, 0xFB, 4, 0, 0, 0, 0]);
    d.extend_from_slice(&raw[8 + txlen..]);
    assert!(Psbt::parse(&d).is_ok());
}

#[test]
fn summary_agrees_with_parser() {
    for s in core_psbt::VALID {
        let raw = b64(s);
        if let Ok(p) = Psbt::parse(&raw) {
            let sum = psbt::summary(&raw).unwrap();
            assert_eq!((sum.inputs, sum.outputs), (p.tx.n_inputs(), p.tx.n_outputs()));
        }
    }
}

/// Mutations of every valid vector: whatever is accepted re-serializes
/// identically, all accessors work, and rust-bitcoin accepts it too (we are
/// at least as strict).
#[test]
fn mutations() {
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
    }
    let mut seeds: Vec<Vec<u8>> = core_psbt::VALID
        .iter()
        .map(|s| b64(s))
        .filter(|r| Psbt::parse(r).is_ok())
        .collect();
    seeds.extend(bip371::VALID.iter().map(|(_, s)| b64(s)));
    let mut rng = Rng(0x9e37);
    let (mut accepted, mut disagree) = (0, Vec::new());
    for i in 0..25_000 {
        let mut m = seeds[i % seeds.len()].clone();
        for _ in 0..1 + rng.below(3) {
            match rng.below(4) {
                0 if !m.is_empty() => {
                    let j = rng.below(m.len());
                    m[j] ^= 1 << rng.below(8);
                }
                1 => {
                    let j = rng.below(m.len() + 1);
                    m.insert(j, rng.next() as u8);
                }
                2 if !m.is_empty() => {
                    let j = rng.below(m.len());
                    m.remove(j);
                }
                _ => {
                    let j = rng.below(m.len());
                    m[j] = [0, 1, 0xFC, 0xFD, 0xFF, 0x20, 0x21, 0x41][rng.below(8)];
                }
            }
        }
        let Ok(p) = Psbt::parse(&m) else { continue };
        accepted += 1;
        let mut out = Vec::new();
        struct V<'a>(&'a mut Vec<u8>);
        impl bp_bitcoin::tx::Sink for V<'_> {
            fn put(&mut self, b: &[u8]) {
                self.0.extend_from_slice(b);
            }
        }
        p.write(&mut V(&mut out));
        assert_eq!(out, m);
        match bitcoin::psbt::Psbt::deserialize(&m) {
            Ok(r) => compare(&p, &r, &format!("mutation {i}")),
            Err(e) => disagree.push(format!("{i}: {e}")),
        }
    }
    assert!(accepted > 1000, "accepted {accepted}");
    assert!(
        disagree.is_empty(),
        "{} accepted by us, rejected by rust-bitcoin: {:?}",
        disagree.len(),
        &disagree[..disagree.len().min(10)]
    );
}
