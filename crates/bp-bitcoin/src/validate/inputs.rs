//! Inputs: previous-output integrity, ownership by re-derivation, the
//! script each owned input commits to, and how its amount is known.

use super::script::{self, classify, ScriptKind};
use super::{
    AmountSource, At, Context, DeriveError, Deriver, InputReport, Issue, OwnedInput, Report, SpendKind,
    Verified,
};
use crate::bip32::HARDENED;
use crate::psbt::{InputMap, KeySource, Psbt};
use crate::tx::{TxIn, TxOut};
use bp_crypto::hashes::hash160;
use bp_crypto::secp256k1::PublicKey;
use bp_crypto::sha256::Sha256;

enum Claim<'a> {
    /// A BIP-32 derivation for a 33- or 65-byte key.
    Ecdsa(&'a [u8]),
    /// A Taproot derivation: x-only key, listed for script leaves.
    Taproot([u8; 32], bool),
}

/// A key claim with this seed's fingerprint, confirmed by re-derivation.
struct OurKey<'a> {
    pubkey: PublicKey,
    /// Claimed in uncompressed (65-byte) form.
    uncompressed: bool,
    source: KeySource<'a>,
    /// A Taproot claim for script leaves.
    leaves_only: bool,
}

pub(super) fn check(psbt: &Psbt, ctx: &Context, d: &mut Deriver, report: &mut Report) {
    // the same outpoint twice
    for (i, a) in psbt.tx.inputs().enumerate() {
        if psbt.tx.inputs().skip(i + 1).any(|b| b.outpoint == a.outpoint) {
            report.push(Issue::DuplicateInput(i as u16));
        }
    }
    let mut any_owned = false;
    let mut any_taproot = false;
    let mut v0_unverified = false;
    for (i, (txin, map)) in psbt.tx.inputs().zip(psbt.inputs()).enumerate() {
        let idx = i as u16;
        let r = check_one(i, &txin, &map, d, report);
        // an outpoint signed since power-on must keep its amount
        if let (Some(mem), Some(a)) = (ctx.memory, r.amount) {
            if mem.amount(txin.outpoint).is_some_and(|m| m != a) {
                report.push(Issue::UtxoAmountChanged(idx));
            }
        }
        if let Some(o) = &r.owned {
            let o = o.get();
            any_owned = true;
            any_taproot |= o.kind == SpendKind::P2trKey;
            v0_unverified |= o.source == AmountSource::WitnessUtxo;
            // SIGHASH_ALL only (Taproot: DEFAULT or ALL)
            let ok = matches!(
                (o.kind, map.sighash_type()),
                (_, None) | (_, Some(1)) | (SpendKind::P2trKey, Some(0))
            );
            if !ok {
                report.push(Issue::NonStandardSighash(idx));
            }
            // m/purpose'/coin'/...: the coin type must be this network's
            let s = o.path.steps();
            if s.len() >= 2
                && s[0] & HARDENED != 0
                && s[1] & HARDENED != 0
                && s[1] & !HARDENED != ctx.network.coin_type()
            {
                report.push(Issue::NetworkMismatch(At::Input(idx)));
            }
        }
        report.inputs[i] = r;
    }
    // mixed script types or accounts
    let (mut mixed, mut accounts) = (false, false);
    let mut first: Option<OwnedInput> = None;
    for o in report
        .inputs()
        .iter()
        .filter_map(|r| r.owned.as_ref())
        .map(|o| *o.get())
    {
        let Some(f) = &first else {
            first = Some(o);
            continue;
        };
        // coin type and account (the purpose follows the script type,
        // which MixedScriptTypes covers)
        let account = |p: &crate::bip32::DerivationPath| {
            let mut a = [u32::MAX; 2];
            for (d, s) in a.iter_mut().zip(p.steps().iter().skip(1)) {
                *d = *s;
            }
            a
        };
        mixed |= f.kind != o.kind;
        accounts |= account(&f.path) != account(&o.path);
    }
    if mixed {
        report.push(Issue::MixedScriptTypes);
    }
    if accounts {
        report.push(Issue::MultipleAccounts);
    }
    let inputs = report.inputs();
    let owned = inputs.iter().filter(|r| r.owned.is_some());
    let pending = owned.clone().filter(|r| !r.finalized && !r.signed).count();
    let done = owned.count() - pending;
    let external = inputs.iter().any(|r| r.owned.is_none());
    let missing: Option<usize> = inputs.iter().position(|r| r.amount.is_none());
    if !any_owned {
        if report.worst() < Some(super::Class::Error) {
            report.push(Issue::NoInputsForSeed);
        }
        return;
    }
    if pending == 0 {
        report.push(Issue::NothingToSign);
    } else if done > 0 {
        report.push(Issue::PartlySigned);
    }
    if external {
        report.push(Issue::ExternalInputs);
    }
    // BIP-341 signatures commit to every input's amount and script
    if any_taproot {
        if let Some(j) = missing {
            report.push(Issue::MissingUtxo(j as u16));
        }
    }
    if v0_unverified && psbt.tx.n_inputs() > 1 {
        report.push(Issue::UnverifiedAmounts);
    }
}

/// A redeem or witness script that does not hash to the scriptPubKey's
/// commitment (checked for every input, ours or not).
fn script_commitments(idx: u16, spk: &[u8], map: &InputMap) -> Option<Issue> {
    let wsh = |program: &[u8; 32]| match map.witness_script() {
        Some(ws) if Sha256::digest(ws) != *program => Some(Issue::WitnessScriptMismatch(idx)),
        _ => None,
    };
    match classify(spk) {
        ScriptKind::P2sh(h) => {
            let redeem = map.redeem_script()?;
            if script::p2sh(redeem)[2..22] != h {
                return Some(Issue::RedeemMismatch(idx));
            }
            match classify(redeem) {
                ScriptKind::P2wsh(program) => wsh(&program),
                _ => None,
            }
        }
        ScriptKind::P2wsh(program) => wsh(&program),
        _ => None,
    }
}

fn check_one(i: usize, txin: &TxIn, map: &InputMap, d: &mut Deriver, report: &mut Report) -> InputReport {
    let idx = i as u16;
    let mut r = InputReport {
        finalized: map.is_finalized(),
        ..InputReport::EMPTY
    };
    // the previous output: the parser has checked that a non-witness UTXO
    // hashes to the outpoint and has the output index
    let from_tx = map.non_witness_utxo().and_then(|t| t.output(txin.vout as usize));
    let witness = map.witness_utxo();
    let prev: Option<(TxOut, AmountSource)> = match (from_tx, witness) {
        (Some(a), Some(b)) => {
            if a.value != b.value || a.script_pubkey != b.script_pubkey {
                report.push(Issue::PrevTxMismatch(idx));
                return r;
            }
            Some((a, AmountSource::PrevTx))
        }
        (Some(a), None) => Some((a, AmountSource::PrevTx)),
        (None, Some(b)) => Some((b, AmountSource::WitnessUtxo)),
        (None, None) => None,
    };
    if let Some((p, s)) = &prev {
        r.amount = Some(p.value);
        r.source = Some(*s);
    }

    // scripts supplied for any input must match what the UTXO commits to
    if let Some((p, _)) = &prev {
        if let Some(issue) = script_commitments(idx, p.script_pubkey, map) {
            report.push(issue);
            return r;
        }
    }

    // claims with this seed's fingerprint, each re-derived
    let mut ours: Option<OurKey> = None;
    let mut distinct = 0;
    let ecdsa = map.bip32_derivations().map(|(k, s)| (Claim::Ecdsa(k), s));
    let taproot = map
        .tap_bip32_derivations()
        .map(|t| (Claim::Taproot(t.xonly, !t.leaf_hashes.is_empty()), t.source));
    for (claim, src) in ecdsa.chain(taproot) {
        if src.fingerprint != d.fingerprint {
            report.note_fingerprint(src.fingerprint);
            continue;
        }
        let derived = match d.xpub(&src) {
            Ok(x) => x.key,
            Err(DeriveError::TooDeep) => {
                report.push(Issue::PathTooDeep(At::Input(idx)));
                return r;
            }
            Err(DeriveError::Failed) => {
                report.push(Issue::KeyNotFromSeed(At::Input(idx)));
                return r;
            }
        };
        // the claimed key must be the derived one
        let (matches, uncompressed, leaves_only) = match claim {
            Claim::Ecdsa(k) => (PublicKey::parse(k) == Some(derived), k.len() == 65, false),
            Claim::Taproot(x, leaves) => (derived.x_only() == x, false, leaves),
        };
        if !matches {
            report.push(Issue::KeyNotFromSeed(At::Input(idx)));
            return r;
        }
        if ours.as_ref().is_none_or(|o| o.pubkey != derived) {
            distinct += 1;
        }
        let prev_flags = ours
            .as_ref()
            .map_or((false, false), |o| (o.uncompressed, o.leaves_only));
        ours = Some(OurKey {
            pubkey: derived,
            uncompressed: uncompressed || prev_flags.0,
            source: src,
            leaves_only: leaves_only || prev_flags.1,
        });
    }
    let Some(key) = ours else {
        return r; // not this seed's input
    };
    if distinct > 1 {
        // several of this seed's keys: multisig (M7)
        report.push(Issue::UnsupportedInput(idx));
        return r;
    }
    let Some((prev, source)) = prev else {
        report.push(Issue::MissingUtxo(idx));
        return r;
    };

    // the script must be built from the derived key
    let pk = key.pubkey;
    let kind = match classify(prev.script_pubkey) {
        ScriptKind::P2wpkh(h) => {
            if h != hash160(&pk.serialize()) {
                report.push(Issue::ScriptNotOurs(idx));
                return r;
            }
            if map.redeem_script().is_some() || map.witness_script().is_some() {
                report.push(Issue::UnneededScript(idx));
                return r;
            }
            SpendKind::P2wpkh
        }
        ScriptKind::P2sh(h) => {
            let Some(redeem) = map.redeem_script() else {
                report.push(Issue::MissingRedeemScript(idx));
                return r;
            };
            if script::p2sh(redeem)[2..22] != h {
                report.push(Issue::RedeemMismatch(idx));
                return r;
            }
            match classify(redeem) {
                ScriptKind::P2wpkh(rh) if rh == hash160(&pk.serialize()) => {}
                ScriptKind::P2wpkh(_) => {
                    report.push(Issue::ScriptNotOurs(idx));
                    return r;
                }
                _ => {
                    report.push(Issue::UnsupportedInput(idx));
                    return r;
                }
            }
            if map.witness_script().is_some() {
                report.push(Issue::UnneededScript(idx));
                return r;
            }
            SpendKind::P2shP2wpkh
        }
        ScriptKind::P2pkh(h) => {
            if h != hash160(&pk.serialize()) {
                report.push(Issue::ScriptNotOurs(idx));
                return r;
            }
            if map.redeem_script().is_some() || map.witness_script().is_some() {
                report.push(Issue::UnneededScript(idx));
                return r;
            }
            if source != AmountSource::PrevTx {
                report.push(Issue::MissingPrevTx(idx));
                return r;
            }
            SpendKind::P2pkh
        }
        ScriptKind::P2tr(q) => {
            if key.leaves_only {
                report.push(Issue::TaprootScriptPath(idx));
                return r;
            }
            if map.tap_merkle_root().is_some() {
                report.push(Issue::UnsupportedInput(idx)); // script tree (M7)
                return r;
            }
            if q != script::p2tr(&pk)[2..] {
                report.push(Issue::ScriptNotOurs(idx));
                return r;
            }
            if map.tap_internal_key().is_some_and(|k| k != pk.x_only()) {
                report.push(Issue::InconsistentInput(idx));
                return r;
            }
            if map.redeem_script().is_some() || map.witness_script().is_some() {
                report.push(Issue::UnneededScript(idx));
                return r;
            }
            SpendKind::P2trKey
        }
        _ => {
            report.push(Issue::UnsupportedInput(idx));
            return r;
        }
    };
    if key.uncompressed {
        report.push(Issue::UncompressedKey(idx));
        return r;
    }
    let source = match (kind, source) {
        (SpendKind::P2trKey, AmountSource::WitnessUtxo) => AmountSource::TaprootCommitted,
        (_, s) => s,
    };
    r.source = Some(source);
    r.signed = match kind {
        SpendKind::P2trKey => map.tap_key_sig().is_some(),
        _ => map.partial_sigs().any(|(k, _)| PublicKey::parse(k) == Some(pk)),
    };
    let Some(path) = key.source.to_path() else {
        report.push(Issue::PathTooDeep(At::Input(idx)));
        return r;
    };
    r.owned = Some(Verified(OwnedInput {
        kind,
        path,
        pubkey: pk,
        amount: prev.value,
        source,
    }));
    r
}
