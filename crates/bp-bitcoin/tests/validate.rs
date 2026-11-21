//! Validator, part 1: input integrity, ownership by re-derivation, global
//! xpubs. PSBTs are built with rust-bitcoin (independent key derivation),
//! then altered the way an attacker or a broken wallet would.

mod common;

#[allow(dead_code)]
#[path = "data/bip174_vectors.rs"]
mod bip174;

use bitcoin::psbt::Psbt as RefPsbt;
use bitcoin::ScriptBuf;
use bp_bitcoin::bip32::Xpriv;
use bp_bitcoin::psbt::ParseError;
use bp_bitcoin::validate::{validate, AmountSource, At, Class, Context, Issue, Report, SpendKind};
use bp_bitcoin::Network;
use common::{build, In, Kind, Out, Wallet, SEED};

fn master() -> Xpriv {
    Xpriv::master(&SEED).unwrap()
}

fn check(p: &RefPsbt) -> Report {
    let raw = p.serialize();
    let m = master();
    validate(&raw, &Context::new(&m, Network::Signet)).1
}

fn simple(kind: Kind) -> RefPsbt {
    let w = Wallet::ours();
    build(
        &w,
        &[In::new(kind, 3, 100_000)],
        &[Out::pay(60_000), Out::change(&w, kind, 2, 39_000)],
    )
}

#[test]
fn four_script_types_are_verified() {
    for kind in Kind::ALL {
        let r = check(&simple(kind));
        assert_eq!(r.issues(), &[], "{kind:?}");
        assert!(r.can_sign(false));
        let o = r.inputs()[0].owned.expect("owned");
        let o = o.get();
        assert_eq!(o.amount, 100_000);
        assert_eq!(o.path.steps()[0], kind.purpose() | 0x8000_0000);
        assert_eq!(
            o.kind,
            match kind {
                Kind::Wpkh => SpendKind::P2wpkh,
                Kind::ShWpkh => SpendKind::P2shP2wpkh,
                Kind::Pkh => SpendKind::P2pkh,
                Kind::Tr => SpendKind::P2trKey,
            }
        );
        assert_eq!(o.source, AmountSource::PrevTx);
    }
}

#[test]
fn key_claims_must_derive_from_the_seed() {
    let w = Wallet::ours();
    for kind in Kind::ALL {
        let mut p = simple(kind);
        // our fingerprint, but the key of another path
        let path = kind.path(0, 3);
        let other = kind.path(0, 4);
        let inp = &mut p.inputs[0];
        if kind == Kind::Tr {
            let (_, (_, (fp, _))) = inp.tap_key_origins.pop_first().unwrap();
            inp.tap_key_origins.insert(
                w.xonly(&other),
                (
                    vec![],
                    (fp, path.parse::<bitcoin::bip32::DerivationPath>().unwrap()),
                ),
            );
        } else {
            let (_, v) = inp.bip32_derivation.pop_first().unwrap();
            inp.bip32_derivation.insert(w.key(&other).0, v);
        }
        let r = check(&p);
        assert!(
            r.has(Issue::KeyNotFromSeed(At::Input(0))),
            "{kind:?}: {:?}",
            r.issues()
        );
        assert_eq!(r.worst(), Some(Class::Attack));
        assert!(!r.can_sign(true));
    }
}

#[test]
fn script_must_be_built_from_our_key() {
    let w = Wallet::ours();
    for kind in Kind::ALL {
        // the claim is true, but the UTXO pays someone else
        let mut p = simple(kind);
        let foreign = Wallet::new(&[5; 32]).spk(kind, &kind.path(0, 3));
        let inp = &mut p.inputs[0];
        let mut prev = inp.non_witness_utxo.take().unwrap();
        prev.output[1].script_pubkey = foreign.clone();
        p.unsigned_tx.input[0].previous_output.txid = prev.compute_txid();
        let inp = &mut p.inputs[0];
        inp.non_witness_utxo = Some(prev.clone());
        if inp.witness_utxo.is_some() {
            inp.witness_utxo = Some(prev.output[1].clone());
        }
        if kind == Kind::ShWpkh {
            // redeem script that matches the foreign P2SH: someone else's key
            inp.redeem_script = Some(Wallet::new(&[5; 32]).redeem(&kind.path(0, 3)));
        }
        let r = check(&p);
        assert!(r.has(Issue::ScriptNotOurs(0)), "{kind:?}: {:?}", r.issues());
        assert_eq!(r.worst(), Some(Class::Attack));
    }
    let _ = w;
}

#[test]
fn redeem_script_must_match_commitment() {
    let w = Wallet::ours();
    let mut p = simple(Kind::ShWpkh);
    p.inputs[0].redeem_script = Some(w.redeem(&Kind::ShWpkh.path(0, 4)));
    assert!(check(&p).has(Issue::RedeemMismatch(0)));
    p.inputs[0].redeem_script = None;
    assert!(check(&p).has(Issue::MissingRedeemScript(0)));
}

#[test]
fn previous_transaction_integrity() {
    // witness UTXO contradicting the previous transaction
    for kind in [Kind::Wpkh, Kind::ShWpkh, Kind::Tr] {
        let mut p = simple(kind);
        p.inputs[0].witness_utxo.as_mut().unwrap().value = bitcoin::Amount::from_sat(1_000);
        let r = check(&p);
        assert!(r.has(Issue::PrevTxMismatch(0)), "{kind:?}");
        assert_eq!(r.worst(), Some(Class::Attack));
    }
    // a previous transaction that is not the outpoint's (parser, attack)
    let mut p = simple(Kind::Wpkh);
    p.inputs[0].non_witness_utxo.as_mut().unwrap().lock_time = bitcoin::absolute::LockTime::from_consensus(5);
    let r = check(&p);
    assert!(r.has(Issue::Parse(ParseError::UtxoMismatch)));
    assert_eq!(r.worst(), Some(Class::Attack));
    // legacy without the previous transaction
    let w = Wallet::ours();
    let p = build(
        &w,
        &[In::new(Kind::Pkh, 1, 5_000).without_prev_tx()],
        &[Out::pay(4_000)],
    );
    assert!(check(&p).has(Issue::MissingUtxo(0)));
    let mut spec = In::new(Kind::Pkh, 1, 5_000).without_prev_tx();
    spec.witness_utxo = true; // a witness UTXO for a non-witness input
    let p = build(&w, &[spec], &[Out::pay(4_000)]);
    assert!(check(&p).has(Issue::MissingPrevTx(0)));
}

#[test]
fn unneeded_scripts_are_refused() {
    let w = Wallet::ours();
    for kind in [Kind::Wpkh, Kind::Pkh, Kind::Tr] {
        let mut p = simple(kind);
        p.inputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x51]));
        assert!(check(&p).has(Issue::UnneededScript(0)), "{kind:?}");
    }
    let mut p = simple(Kind::Wpkh);
    p.inputs[0].redeem_script = Some(w.redeem(&Kind::Wpkh.path(0, 3)));
    assert!(check(&p).has(Issue::UnneededScript(0)));
}

#[test]
fn segwit_v0_amounts_without_previous_transactions() {
    let w = Wallet::ours();
    for kind in [Kind::Wpkh, Kind::ShWpkh] {
        // one input: BIP-143 commits to its amount
        let p = build(
            &w,
            &[In::new(kind, 1, 50_000).without_prev_tx()],
            &[Out::pay(40_000), Out::change(&w, kind, 1, 9_000)],
        );
        let r = check(&p);
        assert_eq!(r.issues(), &[], "{kind:?}");
        assert_eq!(
            r.inputs()[0].owned.unwrap().get().source,
            AmountSource::WitnessUtxo
        );
        // two inputs: blocked until overridden
        let ins = [
            In::new(kind, 1, 50_000).without_prev_tx(),
            In::new(kind, 2, 20_000),
        ];
        let r = check(&build(
            &w,
            &ins,
            &[Out::pay(60_000), Out::change(&w, kind, 1, 9_000)],
        ));
        assert_eq!(r.issues(), &[Issue::UnverifiedAmounts], "{kind:?}");
        assert!(!r.can_sign(false));
        assert!(r.can_sign(true));
    }
    // Taproot: BIP-341 commits to every amount
    let ins = [
        In::new(Kind::Tr, 1, 50_000).without_prev_tx(),
        In::new(Kind::Tr, 2, 20_000).without_prev_tx(),
    ];
    let r = check(&build(
        &w,
        &ins,
        &[Out::pay(60_000), Out::change(&w, Kind::Tr, 1, 9_000)],
    ));
    assert_eq!(r.issues(), &[]);
    assert_eq!(
        r.inputs()[0].owned.unwrap().get().source,
        AmountSource::TaprootCommitted
    );
}

#[test]
fn taproot_needs_every_utxo() {
    let w = Wallet::ours();
    let mut p = build(
        &w,
        &[In::new(Kind::Tr, 1, 50_000), In::new(Kind::Wpkh, 2, 20_000)],
        &[Out::pay(60_000)],
    );
    // the second input is someone else's and has no UTXO data
    p.inputs[1] = Default::default();
    let r = check(&p);
    assert!(r.has(Issue::MissingUtxo(1)), "{:?}", r.issues());
    assert!(r.has(Issue::ExternalInputs));
}

#[test]
fn inputs_of_another_seed() {
    let other = Wallet::new(&[3; 32]);
    let p = build(&other, &[In::new(Kind::Wpkh, 1, 50_000)], &[Out::pay(40_000)]);
    let r = check(&p);
    assert_eq!(r.issues(), &[Issue::NoInputsForSeed]);
    assert_eq!(r.fingerprints(), &[other.fp.to_bytes()]);
    // one of ours, one external (PayJoin)
    let w = Wallet::ours();
    let mut p = build(
        &w,
        &[In::new(Kind::Wpkh, 1, 50_000), In::new(Kind::Wpkh, 2, 20_000)],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 1, 9_000)],
    );
    let theirs = build(&other, &[In::new(Kind::Wpkh, 1, 20_000)], &[]);
    p.inputs[1] = theirs.inputs[0].clone();
    p.unsigned_tx.input[1] = theirs.unsigned_tx.input[0].clone();
    let r = check(&p);
    assert_eq!(r.issues(), &[Issue::ExternalInputs]);
    assert!(r.inputs()[1].owned.is_none());
    assert_eq!(r.inputs()[1].amount, Some(20_000));
}

#[test]
fn signed_and_finalized_inputs() {
    let w = Wallet::ours();
    let ins = [In::new(Kind::Wpkh, 1, 50_000), In::new(Kind::Wpkh, 2, 20_000)];
    let mut p = build(
        &w,
        &ins,
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 1, 9_000)],
    );
    p.inputs[0].final_script_witness = Some(bitcoin::Witness::from_slice(&[vec![1u8]]));
    let r = check(&p);
    assert_eq!(r.issues(), &[Issue::PartlySigned]);
    p.inputs[1].final_script_witness = Some(bitcoin::Witness::from_slice(&[vec![1u8]]));
    assert!(check(&p).has(Issue::NothingToSign));
    // a Taproot key-path signature already present
    let mut p = simple(Kind::Tr);
    p.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature::from_slice(&[1; 64]).unwrap());
    assert!(check(&p).has(Issue::NothingToSign));
}

#[test]
fn duplicate_inputs() {
    let w = Wallet::ours();
    let mut p = build(
        &w,
        &[In::new(Kind::Wpkh, 1, 50_000), In::new(Kind::Wpkh, 2, 20_000)],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 1, 9_000)],
    );
    p.unsigned_tx.input[1] = p.unsigned_tx.input[0].clone();
    p.inputs[1] = p.inputs[0].clone();
    assert!(check(&p).has(Issue::DuplicateInput(0)));
}

#[test]
fn unsupported_and_inconsistent_inputs() {
    let w = Wallet::ours();
    // our key claimed for a P2WSH output: without the witness script, then
    // with a script that is not multisig (M7 signs registered multisig only)
    let mut p = simple(Kind::Wpkh);
    let ws = ScriptBuf::from_bytes(vec![0x51]);
    let spk = ScriptBuf::new_p2wsh(&ws.wscript_hash());
    let mut prev = p.inputs[0].non_witness_utxo.take().unwrap();
    prev.output[1].script_pubkey = spk;
    p.unsigned_tx.input[0].previous_output.txid = prev.compute_txid();
    p.inputs[0].witness_utxo = Some(prev.output[1].clone());
    p.inputs[0].non_witness_utxo = Some(prev);
    assert!(check(&p).has(Issue::MissingWitnessScript(0)));
    p.inputs[0].witness_script = Some(ws);
    assert!(check(&p).has(Issue::UnsupportedInput(0)));
    // Taproot with a script tree, a script-leaf claim, a wrong internal key
    let mut p = simple(Kind::Tr);
    p.inputs[0].tap_merkle_root = Some(bitcoin::TapNodeHash::assume_hidden([1; 32]));
    assert!(check(&p).has(Issue::UnsupportedInput(0)));
    let mut p = simple(Kind::Tr);
    let x = *p.inputs[0].tap_key_origins.keys().next().unwrap();
    p.inputs[0].tap_key_origins.get_mut(&x).unwrap().0.push(
        <bitcoin::TapLeafHash as bitcoin::hashes::Hash>::from_byte_array([2; 32]),
    );
    assert!(check(&p).has(Issue::TaprootScriptPath(0)));
    let mut p = simple(Kind::Tr);
    p.inputs[0].tap_internal_key = Some(w.xonly(&Kind::Tr.path(0, 7)));
    assert!(check(&p).has(Issue::InconsistentInput(0)));
    // our key claimed in uncompressed form
    let p = simple(Kind::Pkh);
    let pk = *p.inputs[0].bip32_derivation.keys().next().unwrap();
    let mut raw = p.serialize();
    let comp = pk.serialize();
    let unc = pk.serialize_uncompressed();
    let at = raw
        .windows(34)
        .position(|win| win[0] == 0x06 && win[1..] == comp[..])
        .unwrap();
    raw.splice(at - 1..at + 34, [&[0x42u8, 0x06][..], &unc[..]].concat());
    let m = master();
    let r = validate(&raw, &Context::new(&m, Network::Signet)).1;
    assert!(r.has(Issue::UncompressedKey(0)), "{:?}", r.issues());
}

#[test]
fn global_xpubs() {
    let w = Wallet::ours();
    let account = "m/84'/1'/0'";
    let path: bitcoin::bip32::DerivationPath = account.parse().unwrap();
    let xpriv = w.master.derive_priv(&w.secp, &path).unwrap();
    let xpub = bitcoin::bip32::Xpub::from_priv(&w.secp, &xpriv);
    let mut p = simple(Kind::Wpkh);
    p.xpub.insert(xpub, (w.fp, path.clone()));
    assert_eq!(check(&p).issues(), &[]);
    // the same xpub claimed at another path of this seed
    let mut p = simple(Kind::Wpkh);
    p.xpub.insert(xpub, (w.fp, "m/84'/1'/1'".parse().unwrap()));
    assert!(check(&p).has(Issue::KeyNotFromSeed(At::Global)));
    // a different chain code
    let mut forged = xpub;
    forged.chain_code = bitcoin::bip32::ChainCode::from([9; 32]);
    let mut p = simple(Kind::Wpkh);
    p.xpub.insert(forged, (w.fp, path.clone()));
    assert!(check(&p).has(Issue::KeyNotFromSeed(At::Global)));
    // mainnet xpub on a test network
    let mut main = xpub;
    main.network = bitcoin::NetworkKind::Main;
    let mut p = simple(Kind::Wpkh);
    p.xpub.insert(main, (w.fp, path));
    assert!(check(&p).has(Issue::XpubNetwork));
    // another seed's xpub is ignored but listed
    let other = Wallet::new(&[3; 32]);
    let oxpub = bitcoin::bip32::Xpub::from_priv(&other.secp, &other.master);
    let mut p = simple(Kind::Wpkh);
    p.xpub
        .insert(oxpub, (other.fp, bitcoin::bip32::DerivationPath::master()));
    let r = check(&p);
    assert_eq!(r.issues(), &[]);
    assert_eq!(r.fingerprints(), &[other.fp.to_bytes()]);
}

#[test]
fn path_too_deep() {
    let mut p = simple(Kind::Wpkh);
    let w = Wallet::ours();
    let deep = "m/1/2/3/4/5/6/7/8/9/10/11";
    p.inputs[0].bip32_derivation.clear();
    p.inputs[0]
        .bip32_derivation
        .insert(w.key(deep).0, (w.fp, deep.parse().unwrap()));
    assert!(check(&p).has(Issue::PathTooDeep(At::Input(0))));
}

/// BIP-174 "Fails Signer checks": structurally valid, never signable.
#[test]
fn bip174_signer_check_vectors() {
    let (m, _, _) = Xpriv::decode(bip174::MASTER_TPRV).unwrap();
    let ctx = Context::new(&m, Network::Testnet);
    for (case, s) in bip174::SIGNER_FAIL {
        let mut raw = vec![0u8; s.len()];
        let n = bp_bitcoin::base64::decode(s.as_bytes(), &mut raw).unwrap();
        let r = validate(&raw[..n], &ctx).1;
        assert!(!r.can_sign(true), "{case}: {:?}", r.issues());
        let attack = r.issues().iter().any(|i| matches!(i, Issue::RedeemMismatch(_)));
        let wsh = r
            .issues()
            .iter()
            .any(|i| matches!(i, Issue::WitnessScriptMismatch(_)));
        if case.starts_with("redeemScript") {
            assert!(attack, "{case}: {:?}", r.issues());
        } else if case.starts_with("witnessScript") {
            assert!(wsh, "{case}: {:?}", r.issues());
        } else {
            // no derivation data for this seed at all
            assert_eq!(r.issues(), &[Issue::NoInputsForSeed], "{case}");
        }
    }
}
