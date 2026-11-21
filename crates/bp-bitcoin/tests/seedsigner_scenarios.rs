//! SeedSigner's PSBT parser scenarios (seedsigner/tests/test_psbt_parser.py,
//! MIT), re-created for the single-key cases Bitpunk signs in M5. Each test
//! names the SeedSigner tests whose situation it builds; the PSBTs are made
//! here with rust-bitcoin (no SeedSigner code or data is copied).
//!
//! Same verdicts as SeedSigner, with these deliberate differences:
//! - A payment to another wallet (account) of this seed is shown as a
//!   verified self-send rather than a spend; it is never counted as change.
//! - A Taproot key-path spend from an address with a script tree is refused
//!   until script trees arrive (M7); SeedSigner signs it.
//! - Multisig scenarios (cosigners, quorums, decoys in multisig scripts)
//!   belong to M7; here a multisig input is simply unsupported.

mod common;

use bitcoin::psbt::Psbt as RefPsbt;
use bitcoin::{Amount, ScriptBuf};
use bp_bitcoin::bip32::Xpriv;
use bp_bitcoin::psbt::ParseError;
use bp_bitcoin::validate::{validate, At, Class, Context, Issue, OutputKind, Report};
use bp_bitcoin::Network;
use common::{build, In, Kind, Out, Wallet, SEED};

fn check(p: &RefPsbt) -> Report {
    let m = Xpriv::master(&SEED).unwrap();
    validate(&p.serialize(), &Context::new(&m, Network::Signet)).1
}

fn ours() -> Wallet {
    Wallet::ours()
}

fn stranger() -> Wallet {
    Wallet::new(&[0x5A; 32])
}

fn with_change(kind: Kind) -> RefPsbt {
    let w = ours();
    build(
        &w,
        &[In::new(kind, 3, 100_000)],
        &[Out::pay(60_000), Out::change(&w, kind, 2, 39_000)],
    )
}

fn refused(r: &Report) -> bool {
    !r.can_sign(true)
}

/// Replace input `i`'s previous output script (and fix the outpoint).
fn set_prev_script(p: &mut RefPsbt, i: usize, script: ScriptBuf) {
    let inp = &mut p.inputs[i];
    let mut prev = inp.non_witness_utxo.take().unwrap();
    prev.output[1].script_pubkey = script;
    p.unsigned_tx.input[i].previous_output.txid = prev.compute_txid();
    if inp.witness_utxo.is_some() {
        inp.witness_utxo = Some(prev.output[1].clone());
    }
    inp.non_witness_utxo = Some(prev);
}

// test_singlesig_native_segwit, _nested_segwit, _taproot, _legacy_p2pkh,
// test_untampered_psbts_verify, test_p2tr_change_detection,
// test_p2sh_p2wpkh_nested_segwit, test_get_total_output_value
#[test]
fn single_sig_wallets_parse_with_change() {
    for kind in Kind::ALL {
        let r = check(&with_change(kind));
        assert_eq!(r.issues(), &[], "{kind:?}");
        assert!(matches!(r.outputs()[1].kind, OutputKind::Change(_)));
        assert_eq!(
            (r.totals.recipients, r.totals.change, r.totals.fee),
            (60_000, 39_000, Some(1_000))
        );
    }
}

// test__is_change_branch__distinguishes_the_change_branch_from_the_receive_branch,
// test__parse__counts_a_payment_to_another_wallet_of_this_seed_as_a_spend
#[test]
fn change_branch_versus_receive_branch() {
    let w = ours();
    let mut p = with_change(Kind::Wpkh);
    let path = Kind::Wpkh.path(0, 2);
    p.unsigned_tx.output[1].script_pubkey = w.spk(Kind::Wpkh, &path);
    p.outputs[1] = Default::default();
    w.claim_output(&mut p.outputs[1], Kind::Wpkh, &path);
    let r = check(&p);
    assert!(matches!(r.outputs()[1].kind, OutputKind::SelfSend(_)));
    assert_eq!(r.totals.change, 0);
    // another account of this seed
    let path = "m/84'/1'/5'/0/0";
    p.unsigned_tx.output[1].script_pubkey = w.spk(Kind::Wpkh, path);
    p.outputs[1] = Default::default();
    w.claim_output(&mut p.outputs[1], Kind::Wpkh, path);
    let r = check(&p);
    assert!(
        matches!(r.outputs()[1].kind, OutputKind::SelfSend(_)),
        "{:?}",
        r.issues()
    );
}

// test_has_matching_input_fingerprint, test_missing_fingerprint_handling,
// test__parse__rejects_a_seed_that_owns_no_input
#[test]
fn a_seed_that_owns_no_input() {
    let s = stranger();
    let p = build(&s, &[In::new(Kind::Wpkh, 1, 50_000)], &[Out::pay(49_000)]);
    let r = check(&p);
    assert_eq!(r.issues(), &[Issue::NoInputsForSeed]);
    assert_eq!(r.fingerprints(), &[s.fp.to_bytes()]);
    // no derivation data at all
    let mut p = p;
    p.inputs[0].bip32_derivation.clear();
    let r = check(&p);
    assert_eq!(r.issues(), &[Issue::NoInputsForSeed]);
    assert!(r.fingerprints().is_empty());
}

// test_tampered_non_witness_utxo_raises
#[test]
fn tampered_previous_transaction() {
    for kind in Kind::ALL {
        let mut p = with_change(kind);
        p.inputs[0].non_witness_utxo.as_mut().unwrap().output[0].value = Amount::from_sat(1);
        let r = check(&p);
        assert!(r.has(Issue::Parse(ParseError::UtxoMismatch)), "{kind:?}");
        assert_eq!(r.worst(), Some(Class::Attack));
    }
}

// test_witness_utxo_value_disagreeing_with_non_witness_utxo_raises,
// test_witness_utxo_script_pubkey_disagreeing_with_non_witness_utxo_raises
#[test]
fn witness_utxo_disagreeing_with_previous_transaction() {
    for kind in [Kind::Wpkh, Kind::ShWpkh, Kind::Tr] {
        let mut p = with_change(kind);
        p.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(99_999);
        assert!(check(&p).has(Issue::PrevTxMismatch(0)), "{kind:?} value");
        let mut p = with_change(kind);
        p.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = stranger().spk(kind, &kind.path(0, 3));
        assert!(check(&p).has(Issue::PrevTxMismatch(0)), "{kind:?} script");
    }
}

// test_legacy_input_without_non_witness_utxo_raises,
// test_segwit_input_without_non_witness_utxo_is_allowed,
// test_input_with_no_utxo_data_raises,
// test_a_psbt_with_no_utxos_is_rejected_rather_than_crashing
#[test]
fn utxo_data_requirements() {
    let w = ours();
    let mut legacy = In::new(Kind::Pkh, 3, 100_000).without_prev_tx();
    legacy.witness_utxo = true;
    let p = build(
        &w,
        &[legacy],
        &[Out::pay(60_000), Out::change(&w, Kind::Pkh, 2, 39_000)],
    );
    assert!(check(&p).has(Issue::MissingPrevTx(0)));
    for kind in [Kind::Wpkh, Kind::ShWpkh, Kind::Tr] {
        let p = build(
            &w,
            &[In::new(kind, 3, 100_000).without_prev_tx()],
            &[Out::pay(60_000), Out::change(&w, kind, 2, 39_000)],
        );
        assert_eq!(check(&p).issues(), &[], "{kind:?}");
    }
    let mut p = with_change(Kind::Wpkh);
    p.inputs[0].witness_utxo = None;
    p.inputs[0].non_witness_utxo = None;
    assert!(check(&p).has(Issue::MissingUtxo(0)));
}

// test_unrecognized_script_type_without_non_witness_utxo_raises,
// test__parse__refuses_an_unsupported_script_type
#[test]
fn unsupported_input_scripts() {
    let w = ours();
    let (pk, _) = w.key(&Kind::Wpkh.path(0, 3));
    // bare P2PK paying this seed's key
    let p2pk = bitcoin::script::Builder::new()
        .push_slice(pk.serialize())
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script();
    let mut p = with_change(Kind::Wpkh);
    set_prev_script(&mut p, 0, p2pk);
    let r = check(&p);
    assert!(r.has(Issue::UnsupportedInput(0)), "{:?}", r.issues());
    assert!(refused(&r));
}

// test_outpoint_index_past_end_of_non_witness_utxo_raises
#[test]
fn outpoint_index_past_the_previous_transaction() {
    let mut p = with_change(Kind::Wpkh);
    p.unsigned_tx.input[0].previous_output.vout = 7;
    assert!(check(&p).has(Issue::Parse(ParseError::UtxoIndex)));
}

// test_every_input_is_checked_not_just_the_first
#[test]
fn every_input_is_checked() {
    let w = ours();
    let mut p = build(
        &w,
        &[
            In::new(Kind::Wpkh, 1, 50_000),
            In::new(Kind::Wpkh, 2, 50_000),
            In::new(Kind::Wpkh, 3, 50_000),
        ],
        &[Out::pay(100_000), Out::change(&w, Kind::Wpkh, 1, 49_000)],
    );
    p.inputs[2].witness_utxo.as_mut().unwrap().value = Amount::from_sat(1);
    assert!(check(&p).has(Issue::PrevTxMismatch(2)));
}

// test__seed_owns_pubkey__*, test__parse__rejects_a_forged_claim_on_an_input,
// test__parse__rejects_a_forged_claim_on_an_output,
// test__parse__rejects_a_forged_taproot_claim,
// test__parse__rejects_a_forged_claim_behind_a_genuine_one,
// test_genuine_fingerprint_collision_is_rejected_like_a_forgery
#[test]
fn forged_claims() {
    let w = ours();
    for kind in Kind::ALL {
        // this seed's key at the wrong path
        let mut p = with_change(kind);
        let wrong = kind.path(0, 4);
        if kind == Kind::Tr {
            let (x, (l, (fp, _))) = p.inputs[0].tap_key_origins.pop_first().unwrap();
            p.inputs[0]
                .tap_key_origins
                .insert(x, (l, (fp, wrong.parse().unwrap())));
        } else {
            let (k, (fp, _)) = p.inputs[0].bip32_derivation.pop_first().unwrap();
            p.inputs[0]
                .bip32_derivation
                .insert(k, (fp, wrong.parse().unwrap()));
        }
        assert!(
            check(&p).has(Issue::KeyNotFromSeed(At::Input(0))),
            "{kind:?} input"
        );
        // the output's claim forged the same way
        let mut p = with_change(kind);
        if kind == Kind::Tr {
            let (x, (l, (fp, _))) = p.outputs[1].tap_key_origins.pop_first().unwrap();
            p.outputs[1]
                .tap_key_origins
                .insert(x, (l, (fp, kind.path(1, 3).parse().unwrap())));
        } else {
            let (k, (fp, _)) = p.outputs[1].bip32_derivation.pop_first().unwrap();
            p.outputs[1]
                .bip32_derivation
                .insert(k, (fp, kind.path(1, 3).parse().unwrap()));
        }
        assert!(
            check(&p).has(Issue::KeyNotFromSeed(At::Output(1))),
            "{kind:?} output"
        );
    }
    // a forged claim listed after a genuine one
    let mut p = with_change(Kind::Wpkh);
    let (k, _) = w.key(&Kind::Wpkh.path(0, 8));
    p.inputs[0]
        .bip32_derivation
        .insert(k, (w.fp, Kind::Wpkh.path(0, 9).parse().unwrap()));
    assert!(check(&p).has(Issue::KeyNotFromSeed(At::Input(0))));
    // our fingerprint on a stranger's key (a collision is treated alike)
    let s = stranger();
    let mut p = with_change(Kind::Wpkh);
    let (sk, _) = s.key(&Kind::Wpkh.path(0, 3));
    p.inputs[0]
        .bip32_derivation
        .insert(sk, (w.fp, Kind::Wpkh.path(0, 3).parse().unwrap()));
    assert!(check(&p).has(Issue::KeyNotFromSeed(At::Input(0))));
}

// test__parse__accepts_a_key_belonging_to_someone_else
#[test]
fn a_strangers_claim_on_a_recipient_is_fine() {
    let s = stranger();
    let mut p = with_change(Kind::Wpkh);
    let path = Kind::Wpkh.path(0, 1);
    p.unsigned_tx.output[0].script_pubkey = s.spk(Kind::Wpkh, &path);
    s.claim_output(&mut p.outputs[0], Kind::Wpkh, &path);
    let r = check(&p);
    assert_eq!(r.issues(), &[]);
    assert_eq!(r.outputs()[0].kind, OutputKind::External);
}

// test__parse__reports_a_bad_input_script_ahead_of_the_wrong_seed,
// test__parse__checks_input_scripts_whoever_the_input_belongs_to
#[test]
fn bad_scripts_on_other_inputs_are_attacks() {
    let s = stranger();
    let mut p = build(&s, &[In::new(Kind::ShWpkh, 1, 50_000)], &[Out::pay(49_000)]);
    p.inputs[0].redeem_script = Some(s.redeem(&Kind::ShWpkh.path(0, 2)));
    let r = check(&p);
    assert!(
        r.has(Issue::RedeemMismatch(0)) && !r.has(Issue::NoInputsForSeed),
        "{:?}",
        r.issues()
    );
    // a witness script that does not hash to a P2WSH input of anyone
    let w = ours();
    let mut p = build(
        &w,
        &[In::new(Kind::Wpkh, 1, 50_000), In::new(Kind::Wpkh, 2, 50_000)],
        &[Out::pay(99_000)],
    );
    let ws = ScriptBuf::from_bytes(vec![0x51]);
    set_prev_script(&mut p, 1, ScriptBuf::new_p2wsh(&ws.wscript_hash()));
    p.inputs[1].bip32_derivation.clear();
    p.inputs[1].witness_script = Some(ScriptBuf::from_bytes(vec![0x52]));
    assert!(check(&p).has(Issue::WitnessScriptMismatch(1)));
}

// test__parse__refuses_a_claim_at_a_derivation_path_too_short_for_a_wallet
#[test]
fn claims_on_paths_too_short() {
    let w = ours();
    for path in ["m", "m/7"] {
        let mut spec = In::new(Kind::Wpkh, 0, 100_000);
        spec.path = path.into();
        let p = build(
            &w,
            &[spec],
            &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 2, 39_000)],
        );
        assert!(check(&p).has(Issue::PathTooShort(At::Input(0))), "{path}");
    }
    // an output claiming the master key
    let mut p = with_change(Kind::Wpkh);
    p.unsigned_tx.output[1].script_pubkey = w.spk(Kind::Wpkh, "m");
    p.outputs[1] = Default::default();
    w.claim_output(&mut p.outputs[1], Kind::Wpkh, "m");
    assert!(check(&p).has(Issue::PathTooShort(At::Output(1))));
}

// test__parse__rejects_a_single_key_output_that_claims_more_than_one_path,
// test__parse__rejects_a_taproot_output_that_claims_more_than_one_internal_key,
// test__parse__rejects_an_output_with_entries_in_both_derivation_path_maps
#[test]
fn surplus_claims_on_single_key_outputs() {
    let w = ours();
    let mut p = with_change(Kind::Wpkh);
    let (k, path) = w.key(&Kind::Wpkh.path(1, 9));
    p.outputs[1].bip32_derivation.insert(k, (w.fp, path));
    assert!(check(&p).has(Issue::SurplusClaims(1)));
    let mut p = with_change(Kind::Tr);
    let path = Kind::Tr.path(1, 9);
    p.outputs[1]
        .tap_key_origins
        .insert(w.xonly(&path), (vec![], (w.fp, path.parse().unwrap())));
    assert!(check(&p).has(Issue::SurplusClaims(1)));
    let mut p = with_change(Kind::Tr);
    let (k, path) = w.key(&Kind::Tr.path(1, 2));
    p.outputs[1].bip32_derivation.insert(k, (w.fp, path));
    let r = check(&p);
    assert!(refused(&r), "{:?}", r.issues());
}

// test__parse__rejects_an_output_that_claims_this_seed_but_pays_someone_else,
// test__parse__rejects_an_output_that_pays_this_seed_but_claims_someone_else,
// test__parse__rejects_taproot_change_that_claims_someone_else,
// test__parse__rejects_a_bare_p2sh_output_that_claims_this_seed_but_pays_someone_else
#[test]
fn output_ownership_contradictions() {
    let s = stranger();
    for kind in Kind::ALL {
        let mut p = with_change(kind);
        p.unsigned_tx.output[1].script_pubkey = s.spk(kind, &kind.path(1, 2));
        assert!(
            check(&p).has(Issue::ChangeContradiction(1)),
            "{kind:?} pays someone else"
        );
        // our change, but the claim names a stranger's fingerprint
        let mut p = with_change(kind);
        if kind == Kind::Tr {
            let (x, (l, (_, path))) = p.outputs[1].tap_key_origins.pop_first().unwrap();
            p.outputs[1].tap_key_origins.insert(x, (l, (s.fp, path)));
        } else {
            let (k, (_, path)) = p.outputs[1].bip32_derivation.pop_first().unwrap();
            p.outputs[1].bip32_derivation.insert(k, (s.fp, path));
        }
        let r = check(&p);
        assert!(
            r.has(Issue::ChangeContradiction(1)),
            "{kind:?} claims someone else: {:?}",
            r.issues()
        );
    }
}

// test__parse__counts_nested_single_sig_change_without_its_redeem_script_as_change
#[test]
fn nested_change_without_redeem_script() {
    let mut p = with_change(Kind::ShWpkh);
    p.outputs[1].redeem_script = None;
    let r = check(&p);
    assert_eq!(r.issues(), &[]);
    assert!(matches!(r.outputs()[1].kind, OutputKind::Change(_)));
}

// test__parse__rejects_outputs_that_exceed_inputs, test__parse__accepts_a_zero_fee
#[test]
fn outputs_versus_inputs() {
    let w = ours();
    let p = build(
        &w,
        &[In::new(Kind::Wpkh, 3, 100_000)],
        &[Out::pay(60_001), Out::change(&w, Kind::Wpkh, 2, 40_000)],
    );
    assert!(check(&p).has(Issue::NegativeFee));
    let p = build(
        &w,
        &[In::new(Kind::Wpkh, 3, 100_000)],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 2, 40_000)],
    );
    let r = check(&p);
    assert_eq!(r.issues(), &[]);
    assert_eq!(r.totals.fee, Some(0));
}

// test__parse__refuses_an_input_that_omits_the_script_it_commits_to,
// test__parse__refuses_an_input_that_supplies_the_wrong_script,
// test__parse__refuses_an_input_that_supplies_an_extra_script
#[test]
fn input_scripts_missing_wrong_or_extra() {
    let w = ours();
    let mut p = with_change(Kind::ShWpkh);
    p.inputs[0].redeem_script = None;
    assert!(check(&p).has(Issue::MissingRedeemScript(0)));
    let mut p = with_change(Kind::ShWpkh);
    p.inputs[0].redeem_script = Some(w.redeem(&Kind::ShWpkh.path(0, 4)));
    assert!(check(&p).has(Issue::RedeemMismatch(0)));
    let mut p = with_change(Kind::Wpkh);
    p.inputs[0].redeem_script = Some(w.redeem(&Kind::Wpkh.path(0, 3)));
    assert!(check(&p).has(Issue::UnneededScript(0)));
}

// test__parse__refuses_a_true_claim_planted_on_another_partys_input,
// test__parse__refuses_a_taproot_map_claim_on_a_non_taproot_input
#[test]
fn true_claims_on_inputs_that_do_not_use_the_key() {
    let s = stranger();
    let w = ours();
    let mut p = build(
        &w,
        &[In::new(Kind::Wpkh, 3, 50_000), In::new(Kind::Wpkh, 4, 50_000)],
        &[Out::pay(99_000)],
    );
    set_prev_script(&mut p, 1, s.spk(Kind::Wpkh, &Kind::Wpkh.path(0, 4)));
    assert!(check(&p).has(Issue::ScriptNotOurs(1)));
    // a Taproot-map claim of this seed on its own P2WPKH input
    let mut p = with_change(Kind::Wpkh);
    let path = "m/86'/1'/0'/0/9";
    p.inputs[0]
        .tap_key_origins
        .insert(w.xonly(path), (vec![], (w.fp, path.parse().unwrap())));
    let r = check(&p);
    assert!(
        refused(&r) && r.worst() == Some(Class::Attack),
        "{:?}",
        r.issues()
    );
}

// test__parse__refuses_an_input_this_seed_can_sign_only_through_a_script_path,
// test__parse__refuses_an_internal_key_claim_that_its_merkle_root_contradicts,
// test__parse__keeps_a_key_path_spend_from_an_address_built_over_a_script_tree (differs)
#[test]
fn taproot_script_paths_and_trees() {
    let mut p = with_change(Kind::Tr);
    let x = *p.inputs[0].tap_key_origins.keys().next().unwrap();
    p.inputs[0].tap_key_origins.get_mut(&x).unwrap().0.push(
        <bitcoin::TapLeafHash as bitcoin::hashes::Hash>::from_byte_array([3; 32]),
    );
    assert!(check(&p).has(Issue::TaprootScriptPath(0)));
    let mut p = with_change(Kind::Tr);
    p.inputs[0].tap_merkle_root = Some(bitcoin::TapNodeHash::assume_hidden([4; 32]));
    assert!(refused(&check(&p)));
}

// test__parse__refuses_change_to_a_base_path_this_transaction_does_not_spend_from,
// test__parse__counts_a_non_hardened_wallet_level_as_part_of_the_base_path,
// test__parse__refuses_change_on_a_branch_no_coordinator_scans,
// test__parse__refuses_change_at_a_hardened_address_index,
// test__parse__refuses_change_at_a_derivation_path_too_short_for_a_wallet,
// test__parse__a_foreign_input_cannot_anchor_change_to_an_unspent_base_path
#[test]
fn change_path_rules() {
    let w = ours();
    for path in [
        "m/84'/1'/3'/1/2",
        "m/84'/1'/0'/5/1/2",
        "m/84'/1'/0'/2/2",
        "m/84'/1'/0'/1/2'",
        "m/84'/1'/0'/1",
    ] {
        let mut p = with_change(Kind::Wpkh);
        p.unsigned_tx.output[1].script_pubkey = w.spk(Kind::Wpkh, path);
        p.outputs[1] = Default::default();
        w.claim_output(&mut p.outputs[1], Kind::Wpkh, path);
        let r = check(&p);
        assert!(r.has(Issue::ChangePathViolation(1)), "{path}: {:?}", r.issues());
    }
    // a foreign input from account 3 does not make change into account 3 ours
    let s = stranger();
    let mut p = build(
        &w,
        &[In::new(Kind::Wpkh, 3, 50_000), In::new(Kind::Wpkh, 4, 50_000)],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 2, 39_000)],
    );
    let theirs = build(
        &s,
        &[{
            let mut i = In::new(Kind::Wpkh, 0, 50_000);
            i.path = "m/84'/1'/3'/0/0".into();
            i
        }],
        &[],
    );
    p.unsigned_tx.input[1] = theirs.unsigned_tx.input[0].clone();
    p.inputs[1] = theirs.inputs[0].clone();
    let path = "m/84'/1'/3'/1/0";
    p.unsigned_tx.output[1].script_pubkey = w.spk(Kind::Wpkh, path);
    p.outputs[1] = Default::default();
    w.claim_output(&mut p.outputs[1], Kind::Wpkh, path);
    assert!(check(&p).has(Issue::ChangePathViolation(1)));
}

// test__parse__flags_rather_than_refuses_change_far_past_the_inputs_address_indices,
// test__parse__flags_each_distant_change_output_and_warns_once,
// test__parse__measures_the_window_from_the_smallest_input_index_for_the_base_path,
// test__parse__leaves_hardened_input_indices_out_of_the_window,
// test__parse__measures_the_window_from_index_0_when_every_input_address_index_is_hardened,
// test__parse__measures_each_base_path_window_from_its_own_inputs,
// test__parse__a_foreign_input_cannot_affect_the_change_index_window
#[test]
fn change_index_window() {
    let w = ours();
    let at = |inputs: &[&str], change: u32| {
        let ins: Vec<In> = inputs
            .iter()
            .enumerate()
            .map(|(i, path)| {
                let mut s = In::new(Kind::Wpkh, i as u32, 50_000);
                s.path = path.to_string();
                s
            })
            .collect();
        let total = 50_000 * ins.len() as u64;
        build(
            &w,
            &ins,
            &[
                Out::pay(10_000),
                Out::change(&w, Kind::Wpkh, change, total - 11_000),
            ],
        )
    };
    // smallest input index 0 (inputs at 6 and 0), in either order
    for order in [
        ["m/84'/1'/0'/1/6", "m/84'/1'/0'/1/0"],
        ["m/84'/1'/0'/1/0", "m/84'/1'/0'/1/6"],
    ] {
        assert_eq!(check(&at(&order, 10_000)).issues(), &[]);
        let r = check(&at(&order, 10_001));
        assert_eq!(r.issues(), &[Issue::ChangeIndexFar(1)]);
        assert!(r.can_sign(false));
    }
    // hardened input indices are left out; all hardened: window from 0
    assert_eq!(
        check(&at(&["m/84'/1'/0'/0/20000'", "m/84'/1'/0'/0/5000"], 15_000)).issues(),
        &[]
    );
    assert_eq!(
        check(&at(&["m/84'/1'/0'/0/20000'"], 10_001)).issues(),
        &[Issue::ChangeIndexFar(1)]
    );
}

// test__parse__refuses_segwit_v0_single_sig_mixed_base_paths,
// test__parse__accepts_segwit_v0_single_sig_mixed_base_paths_with_non_witness_utxos,
// test__parse__accepts_mixed_base_paths_for_other_script_types
#[test]
fn mixed_base_paths() {
    let w = ours();
    for kind in [Kind::Wpkh, Kind::ShWpkh] {
        let mut second = In::new(kind, 0, 50_000).without_prev_tx();
        second.path = format!("m/{}'/1'/7'/0/0", kind.purpose());
        let p = build(
            &w,
            &[In::new(kind, 1, 50_000), second.clone()],
            &[Out::pay(60_000), Out::change(&w, kind, 1, 39_000)],
        );
        let r = check(&p);
        assert!(
            r.has(Issue::UnverifiedMixedBasePaths),
            "{kind:?}: {:?}",
            r.issues()
        );
        assert!(!r.can_sign(true), "no override for mixed base paths");
        // with every previous transaction: only the warning
        second.prev_tx = true;
        let p = build(
            &w,
            &[In::new(kind, 1, 50_000), second],
            &[Out::pay(60_000), Out::change(&w, kind, 1, 39_000)],
        );
        assert_eq!(check(&p).issues(), &[Issue::MultipleAccounts], "{kind:?}");
    }
    let mut second = In::new(Kind::Tr, 0, 50_000).without_prev_tx();
    second.path = "m/86'/1'/7'/0/0".into();
    let p = build(
        &w,
        &[In::new(Kind::Tr, 1, 50_000).without_prev_tx(), second],
        &[Out::pay(60_000), Out::change(&w, Kind::Tr, 1, 39_000)],
    );
    assert_eq!(check(&p).issues(), &[Issue::MultipleAccounts]);
}

// test__parse__payjoin_parses_and_anchors_only_on_our_own_input,
// test__parse__coinjoin_parses_with_many_foreign_inputs_and_outputs
#[test]
fn payjoin_and_coinjoin() {
    let w = ours();
    let s = stranger();
    let foreign: Vec<RefPsbt> = (0..4)
        .map(|i| build(&s, &[In::new(Kind::Wpkh, i, 50_000)], &[]))
        .collect();
    let mut ins = vec![In::new(Kind::Wpkh, 3, 50_000)];
    ins.extend((0..4).map(|i| In::new(Kind::Wpkh, 10 + i, 50_000)));
    let mut outs = vec![Out::change(&w, Kind::Wpkh, 2, 49_000)];
    outs.extend((0..4).map(|_| Out::pay(50_000)));
    let mut p = build(&w, &ins, &outs);
    for (i, f) in foreign.iter().enumerate() {
        p.unsigned_tx.input[i + 1] = f.unsigned_tx.input[0].clone();
        p.inputs[i + 1] = f.inputs[0].clone();
    }
    let r = check(&p);
    assert_eq!(r.issues(), &[Issue::ExternalInputs], "{:?}", r.issues());
    assert_eq!(r.inputs().iter().filter(|i| i.owned.is_some()).count(), 1);
    assert!(matches!(r.outputs()[0].kind, OutputKind::Change(_)));
    assert!(r.outputs()[1..].iter().all(|o| o.kind == OutputKind::External));
}

// test_parse_op_return_content, test_parse_op_return_payload_push_encodings
#[test]
fn op_return_outputs() {
    let w = ours();
    let mut p = build(
        &w,
        &[In::new(Kind::Wpkh, 3, 100_000)],
        &[Out::pay(0), Out::change(&w, Kind::Wpkh, 2, 99_000)],
    );
    p.unsigned_tx.output[0].script_pubkey = ScriptBuf::from_bytes(b"\x6a\x0bhello world".to_vec());
    let r = check(&p);
    assert_eq!(r.issues(), &[]);
    assert_eq!(r.outputs()[0].kind, OutputKind::OpReturn);
}
