//! Outputs: which are this seed's (change or self-send), verified by
//! re-deriving the key and rebuilding the script, the change path rules,
//! and the output warnings.

use super::script::{self, classify, ScriptKind};
use super::{
    At, Context, DeriveError, Deriver, Issue, OutputKind, OutputReport, OwnedOutput, Report, SpendKind,
    Verified,
};
use crate::bip32::{DerivationPath, HARDENED};
use crate::psbt::{KeySource, OutputMap, Psbt};
use crate::tx::MAX_MONEY;
use bp_crypto::hashes::hash160;
use bp_crypto::secp256k1::PublicKey;

/// OP_RETURN with up to 80 bytes of data (Bitcoin Core's old default).
const MAX_OP_RETURN_SCRIPT: usize = 83;

pub(super) fn check(psbt: &Psbt, ctx: &Context, d: &mut Deriver, report: &mut Report) {
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

/// This seed's key claimed for the output, re-derived, and the script it
/// must then be. `Ok(None)`: no claim, or a script the device does not
/// rebuild (multisig and the like: shown as an ordinary recipient).
#[allow(clippy::type_complexity)]
fn ours<'a>(
    idx: u16,
    kind: ScriptKind,
    map: &OutputMap<'a>,
    d: &mut Deriver,
    report: &mut Report,
) -> Result<Option<(SpendKind, PublicKey, KeySource<'a>)>, Issue> {
    let ecdsa = map.bip32_derivations().map(|(k, s)| (Some(k), None, s));
    let taproot = map
        .tap_bip32_derivations()
        .map(|t| (None, Some(t.xonly), t.source));
    let mut claimed = false;
    for (k, x, src) in ecdsa.chain(taproot) {
        if src.fingerprint != d.fingerprint {
            report.note_fingerprint(src.fingerprint);
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
        claimed = true;
        let h = hash160(&derived.serialize());
        let spend = match kind {
            ScriptKind::P2wpkh(sh) if sh == h => Some(SpendKind::P2wpkh),
            ScriptKind::P2pkh(sh) if sh == h => Some(SpendKind::P2pkh),
            ScriptKind::P2sh(sh) if sh[..] == script::p2sh(&script::p2wpkh(&derived))[2..22] => {
                match map.redeem_script() {
                    Some(r) if r != script::p2wpkh(&derived) => return Err(Issue::ChangeContradiction(idx)),
                    _ => Some(SpendKind::P2shP2wpkh),
                }
            }
            ScriptKind::P2tr(q) if q[..] == script::p2tr(&derived)[2..] && map.tap_tree().is_none() => {
                Some(SpendKind::P2trKey)
            }
            _ => None,
        };
        if let Some(s) = spend {
            return Ok(Some((s, derived, src)));
        }
    }
    if !claimed {
        return Ok(None);
    }
    // this seed's key is claimed, but the script is not built from it
    match kind {
        ScriptKind::P2wpkh(_) | ScriptKind::P2pkh(_) | ScriptKind::P2tr(_) => {
            Err(Issue::ChangeContradiction(idx))
        }
        ScriptKind::P2sh(_) => match map.redeem_script().map(classify) {
            Some(ScriptKind::P2wsh(_)) => Ok(None), // P2SH-P2WSH multisig
            _ => Err(Issue::ChangeContradiction(idx)),
        },
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
    };
    match s[3] {
        0 => Some(OutputKind::SelfSend(Verified(owned))),
        1 => {
            let account = &s[..3];
            let max_index = report
                .inputs()
                .iter()
                .filter_map(|r| r.owned.as_ref())
                .map(|o| o.get().path)
                .filter(|p: &DerivationPath| p.steps().len() == 5 && &p.steps()[..3] == account)
                .map(|p| p.steps()[4])
                .max();
            let Some(max_index) = max_index else {
                // change into an account that is not spending
                return violation(report);
            };
            if s[4] > max_index.saturating_add(ctx.policy.change_index_gap) {
                report.push(Issue::ChangeIndexFar(idx));
            }
            Some(OutputKind::Change(Verified(owned)))
        }
        _ => violation(report),
    }
}
