//! Outputs: which are this seed's (change or self-send), verified by
//! re-deriving the key and rebuilding the script, the change path rules,
//! and the output warnings.

use super::multisig::{self, Cache, OutputMatch};
use super::script::{self, classify, ScriptKind};
use super::{
    At, Context, DeriveError, Deriver, Issue, OutputKind, OutputReport, OwnedOutput, Report, SpendKind,
    Verified,
};
use crate::bip32::HARDENED;
use crate::psbt::{KeySource, OutputMap, Psbt};
use crate::tx::MAX_MONEY;
use bp_crypto::hashes::hash160;
use bp_crypto::secp256k1::PublicKey;

/// OP_RETURN with up to 80 bytes of data (Bitcoin Core's old default).
const MAX_OP_RETURN_SCRIPT: usize = 83;

pub(super) fn check(psbt: &Psbt, ctx: &Context, d: &mut Deriver, cache: &mut Cache, report: &mut Report) {
    let mut op_returns = 0;
    for (j, (out, map)) in psbt.tx.outputs().zip(psbt.outputs()).enumerate() {
        let idx = j as u16;
        let mut rep = OutputReport {
            kind: OutputKind::External,
            amount: out.value,
        };
        if out.value > MAX_MONEY {
            report.push(Issue::ValueOutOfRange);
        }
        let kind = classify(out.script_pubkey);
        match kind {
            ScriptKind::OpReturn => {
                rep.kind = OutputKind::OpReturn;
                op_returns += 1;
                if out.value > 0 {
                    report.push(Issue::BadOpReturn(idx)); // burns coins
                }
                if out.script_pubkey.len() > MAX_OP_RETURN_SCRIPT {
                    report.push(Issue::OpReturnNonStandard);
                }
            }
            ScriptKind::FutureWitness | ScriptKind::Other => report.push(Issue::UnknownScript(idx)),
            _ => {}
        }
        if out.value == 0 && kind != ScriptKind::OpReturn {
            report.push(Issue::ZeroValue(idx));
        }
        // a registered multisig wallet's address?
        if matches!(kind, ScriptKind::P2wsh(_) | ScriptKind::P2sh(_)) {
            match multisig_output(idx, out.script_pubkey, &map, ctx, d, cache, report) {
                Ok(Some(k)) => {
                    rep.kind = k;
                    report.outputs[j] = rep;
                    continue;
                }
                Ok(None) => {}
                Err(issue) => {
                    report.push(issue);
                    report.outputs[j] = rep;
                    continue;
                }
            }
        }
        if kind != ScriptKind::OpReturn {
            match ours(idx, kind, &map, d, report) {
                Ok(Some((spend, pubkey, src))) => {
                    if let Some(k) = owned_kind(idx, spend, pubkey, &src, ctx, report) {
                        rep.kind = k;
                    }
                }
                Ok(None) => {}
                Err(issue) => report.push(issue),
            }
        }
        report.outputs[j] = rep;
    }
    if op_returns > 1 {
        report.push(Issue::OpReturnNonStandard);
    }
}

/// The single-key script `kind` is, if it is built from `key`.
fn spend_for(
    key: &PublicKey,
    kind: ScriptKind,
    map: &OutputMap,
    idx: u16,
) -> Result<Option<SpendKind>, Issue> {
    let h = hash160(&key.serialize());
    Ok(match kind {
        ScriptKind::P2wpkh(sh) if sh == h => Some(SpendKind::P2wpkh),
        ScriptKind::P2pkh(sh) if sh == h => Some(SpendKind::P2pkh),
        ScriptKind::P2sh(sh) if sh[..] == script::p2sh(&script::p2wpkh(key))[2..22] => {
            match map.redeem_script() {
                Some(r) if r != script::p2wpkh(key) => return Err(Issue::ChangeContradiction(idx)),
                _ => Some(SpendKind::P2shP2wpkh),
            }
        }
        ScriptKind::P2tr(q) if q[..] == script::p2tr(key)[2..] && map.tap_tree().is_none() => {
            Some(SpendKind::P2trKey)
        }
        _ => None,
    })
}

/// This seed's key claimed for the output, re-derived, and the script it
/// must then be. `Ok(None)`: no claim, or a script the device does not
/// rebuild (multisig and the like: shown as an ordinary recipient).
///
/// Also refused, as SeedSigner does: claims on the master key or a
/// one-level path, a claim in the map of the other script family (Taproot
/// vs BIP-32), more than one derivation entry on a single-key output, and
/// an output that pays this seed's key at a path claimed for another
/// fingerprint.
#[allow(clippy::type_complexity)]
fn ours<'a>(
    idx: u16,
    kind: ScriptKind,
    map: &OutputMap<'a>,
    d: &mut Deriver,
    report: &mut Report,
) -> Result<Option<(SpendKind, PublicKey, KeySource<'a>)>, Issue> {
    let n_ecdsa = map.bip32_derivations().count();
    let n_tap = map.tap_bip32_derivations().count();
    let single_key = match kind {
        ScriptKind::P2wpkh(_) | ScriptKind::P2pkh(_) => true,
        ScriptKind::P2sh(_) => !matches!(map.redeem_script().map(classify), Some(ScriptKind::P2wsh(_))),
        ScriptKind::P2tr(_) => map.tap_tree().is_none(),
        _ => false,
    };
    let is_taproot = matches!(kind, ScriptKind::P2tr(_));
    let ecdsa = map.bip32_derivations().map(|(k, s)| (Some(k), None, s));
    let taproot = map
        .tap_bip32_derivations()
        .map(|t| (None, Some(t.xonly), t.source));
    let mut claimed = false;
    let mut found = None;
    for (k, x, src) in ecdsa.chain(taproot) {
        if src.fingerprint != d.fingerprint {
            report.note_fingerprint(src.fingerprint);
            // this seed's own key at that path, paid by the output?
            if single_key && src.depth() >= 2 {
                if let Ok(ours) = d.xpub(&src) {
                    if spend_for(&ours.key, kind, map, idx)?.is_some() {
                        return Err(Issue::ChangeContradiction(idx));
                    }
                }
            }
            continue;
        }
        let derived = match d.xpub(&src) {
            Ok(x) => x.key,
            Err(DeriveError::TooDeep) => return Err(Issue::PathTooDeep(At::Output(idx))),
            Err(DeriveError::Failed) => return Err(Issue::KeyNotFromSeed(At::Output(idx))),
        };
        let same = match (k, x) {
            (Some(k), _) => PublicKey::parse(k) == Some(derived),
            (_, Some(x)) => derived.x_only() == x,
            _ => false,
        };
        if !same {
            return Err(Issue::KeyNotFromSeed(At::Output(idx)));
        }
        if src.depth() < 2 {
            return Err(Issue::PathTooShort(At::Output(idx)));
        }
        claimed = true;
        if x.is_some() != is_taproot && single_key {
            return Err(Issue::ChangeContradiction(idx));
        }
        if found.is_none() {
            if let Some(s) = spend_for(&derived, kind, map, idx)? {
                found = Some((s, derived, src));
            }
        }
    }
    if claimed && single_key && n_ecdsa + n_tap > 1 {
        return Err(Issue::SurplusClaims(idx));
    }
    if found.is_some() || !claimed {
        return Ok(found);
    }
    // this seed's key is claimed, but the script is not built from it
    match kind {
        _ if single_key => Err(Issue::ChangeContradiction(idx)),
        _ => Ok(None),
    }
}

/// Change (branch 1 of an account that is spending) or self-send (branch 0
/// of any account), after the path rules: m/purpose'/coin'/account'/branch/
/// index with the purpose of the script type and this network's coin.
fn owned_kind(
    idx: u16,
    spend: SpendKind,
    pubkey: PublicKey,
    src: &KeySource,
    ctx: &Context,
    report: &mut Report,
) -> Option<OutputKind> {
    let violation = |report: &mut Report| {
        report.push(Issue::ChangePathViolation(idx));
        None
    };
    let Some(path) = src.to_path() else {
        report.push(Issue::PathTooDeep(At::Output(idx)));
        return None;
    };
    let s = path.steps();
    let hard = |v: u32| v & HARDENED != 0;
    if s.len() != 5 || !s[..3].iter().all(|&v| hard(v)) || s[3..].iter().any(|&v| hard(v)) {
        return violation(report);
    }
    if s[0] & !HARDENED != spend.script_type().purpose() {
        return violation(report);
    }
    if s[1] & !HARDENED != ctx.network.coin_type() {
        report.push(Issue::NetworkMismatch(At::Output(idx)));
        return None;
    }
    let owned = OwnedOutput {
        kind: spend,
        path,
        pubkey,
        ms: None,
    };
    match s[3] {
        0 => Some(OutputKind::SelfSend(Verified(owned))),
        1 => {
            let account = &s[..3];
            let mut spending = false;
            let mut base = None::<u32>;
            for p in report
                .inputs()
                .iter()
                .filter_map(|r| r.owned.as_ref())
                .map(|o| o.get().path)
            {
                let ps: &[u32] = p.steps();
                if ps.len() == 5 && &ps[..3] == account {
                    spending = true;
                    if !hard(ps[4]) {
                        base = Some(base.map_or(ps[4], |b| b.min(ps[4])));
                    }
                }
            }
            if !spending {
                // change into an account that is not spending
                return violation(report);
            }
            // the window starts at the smallest unhardened input index (0
            // if there is none), as SeedSigner measures it
            if s[4] > base.unwrap_or(0).saturating_add(ctx.policy.change_index_gap) {
                report.push(Issue::ChangeIndexFar(idx));
            }
            Some(OutputKind::Change(Verified(owned)))
        }
        _ => violation(report),
    }
}

/// A P2WSH / P2SH output with this seed's key claimed at a registered
/// wallet's path: that wallet's address (change, self-send, or another
/// registered wallet), or an attack if the script is not that wallet's.
/// `Ok(None)`: no such claim (handled as any other output).
fn multisig_output(
    idx: u16,
    spk: &[u8],
    map: &OutputMap,
    ctx: &Context,
    d: &mut Deriver,
    cache: &mut Cache,
    report: &mut Report,
) -> Result<Option<OutputKind>, Issue> {
    if ctx.multisig.iter().all(|w| w.is_none()) {
        return Ok(None);
    }
    for (k, src) in map.bip32_derivations() {
        if src.fingerprint != d.fingerprint {
            continue;
        }
        let derived = match d.xpub(&src) {
            Ok(x) => x.key,
            Err(DeriveError::TooDeep) => return Err(Issue::PathTooDeep(At::Output(idx))),
            Err(DeriveError::Failed) => return Err(Issue::KeyNotFromSeed(At::Output(idx))),
        };
        if PublicKey::parse(k) != Some(derived) {
            return Err(Issue::KeyNotFromSeed(At::Output(idx)));
        }
        let Some(path) = src.to_path() else {
            return Err(Issue::PathTooDeep(At::Output(idx)));
        };
        let m = multisig::output(ctx, cache, idx, &path, spk, map.witness_script(), &|| {
            map.bip32_derivations()
        })?;
        let OutputMatch::Registered(spend) = m else {
            continue;
        };
        let kind = if matches!(classify(spk), ScriptKind::P2sh(_)) {
            SpendKind::P2shP2wshMulti
        } else {
            SpendKind::P2wshMulti
        };
        let owned = OwnedOutput {
            kind,
            path,
            pubkey: derived,
            ms: Some(spend),
        };
        if report.wallet != Some(spend.wallet) {
            return Ok(Some(OutputKind::OtherWallet(Verified(owned))));
        }
        if spend.branch == 0 {
            return Ok(Some(OutputKind::SelfSend(Verified(owned))));
        }
        // change far beyond the indexes this wallet spends from
        let base = report
            .inputs()
            .iter()
            .filter_map(|r| r.owned.as_ref()?.get().ms)
            .filter(|m| m.wallet == spend.wallet)
            .map(|m| m.index)
            .min()
            .unwrap_or(0);
        if spend.index > base.saturating_add(ctx.policy.change_index_gap) {
            report.push(Issue::ChangeIndexFar(idx));
        }
        return Ok(Some(OutputKind::Change(Verified(owned))));
    }
    Ok(None)
}
