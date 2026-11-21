//! Totals, the fee and its policy, and the size of the signed transaction.

use super::script::{classify, ScriptKind};
use super::{Context, Issue, OutputKind, Report, SpendKind, Totals};
use crate::psbt::Psbt;
use crate::tx::MAX_MONEY;

fn compact_len(n: usize) -> u64 {
    match n {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        _ => 5,
    }
}

/// Signed-input sizes (non-witness bytes, witness bytes). ECDSA signatures
/// are at most 71 bytes with low-R grinding, plus the sighash byte.
fn input_size(kind: Option<SpendKind>, ms: Option<super::MsSpend>) -> (u64, u64) {
    const OUTPOINT_SEQ: u64 = 36 + 4;
    const P2WPKH_WITNESS: u64 = 1 + (1 + 72) + (1 + 33);
    if let Some(m) = ms {
        // items, the empty CHECKMULTISIG dummy, m signatures, the script
        let ws = 3 + 34 * m.n as u64;
        let witness = 1 + 1 + m.m as u64 * (1 + 72) + compact_len(ws as usize) + ws;
        let base = match kind {
            Some(SpendKind::P2shP2wshMulti) => OUTPOINT_SEQ + 1 + 35,
            _ => OUTPOINT_SEQ + 1,
        };
        return (base, witness);
    }
    match kind {
        Some(SpendKind::P2pkh) => (OUTPOINT_SEQ + 1 + (1 + 72) + (1 + 33), 0),
        Some(SpendKind::P2shP2wpkh) => (OUTPOINT_SEQ + 1 + 23, P2WPKH_WITNESS),
        Some(SpendKind::P2trKey) => (OUTPOINT_SEQ + 1, 1 + 1 + 64),
        // P2WPKH, and the estimate for inputs of unknown kind
        _ => (OUTPOINT_SEQ + 1, P2WPKH_WITNESS),
    }
}

/// Virtual size of the transaction once every input is signed.
fn estimate_vsize(psbt: &Psbt, report: &Report) -> u64 {
    let tx = &psbt.tx;
    let mut base =
        8 + compact_len(tx.n_inputs()) + compact_len(tx.n_outputs()) + tx.outputs_bytes().len() as u64;
    let mut witness = 0u64;
    let mut witness_inputs = 0usize;
    for ((r, map), prev_kind) in report.inputs().iter().zip(psbt.inputs()).zip(
        psbt.inputs()
            .zip(psbt.tx.inputs())
            .map(|(m, i)| prev_kind(&m, i.vout)),
    ) {
        if r.finalized {
            let ss = map.final_script_sig().unwrap_or(&[]);
            base += 40 + compact_len(ss.len()) + ss.len() as u64;
            if let Some(w) = map.final_script_witness() {
                witness += w.len() as u64;
                witness_inputs += 1;
            }
            continue;
        }
        let kind = r.owned.map(|o| o.get().kind).or(prev_kind);
        let (b, w) = input_size(kind, r.owned.and_then(|o| o.get().ms));
        base += b;
        if w > 0 {
            witness += w;
            witness_inputs += 1;
        }
    }
    if witness_inputs > 0 {
        // marker, flag, and an empty stack for every non-witness input
        witness += 2 + (tx.n_inputs() - witness_inputs) as u64;
    }
    (base * 4 + witness).div_ceil(4)
}

/// The spend kind a previous output implies (for inputs of other seeds).
fn prev_kind(map: &crate::psbt::InputMap, vout: u32) -> Option<SpendKind> {
    let spk = match map.witness_utxo() {
        Some(o) => o.script_pubkey,
        None => map.non_witness_utxo()?.output(vout as usize)?.script_pubkey,
    };
    match classify(spk) {
        ScriptKind::P2pkh(_) => Some(SpendKind::P2pkh),
        ScriptKind::P2sh(_) => Some(SpendKind::P2shP2wpkh),
        ScriptKind::P2wpkh(_) => Some(SpendKind::P2wpkh),
        ScriptKind::P2tr(_) => Some(SpendKind::P2trKey),
        _ => None,
    }
}

pub(super) fn check(psbt: &Psbt, ctx: &Context, report: &mut Report) {
    let mut t = Totals {
        vsize: estimate_vsize(psbt, report),
        ..Totals::default()
    };
    let mut overflow = false;
    let mut add = |acc: &mut u64, v: u64| match acc.checked_add(v) {
        Some(s) if s <= MAX_MONEY && v <= MAX_MONEY => *acc = s,
        _ => overflow = true,
    };
    let mut all_known = true;
    let mut inputs_sum = 0u64;
    for r in report.inputs() {
        match r.amount {
            Some(a) => add(&mut inputs_sum, a),
            None => all_known = false,
        }
        if let Some(o) = &r.owned {
            add(&mut t.ours, o.get().amount);
        }
    }
    for o in report.outputs() {
        add(&mut t.outputs, o.amount);
        match o.kind {
            OutputKind::Change(_) => add(&mut t.change, o.amount),
            OutputKind::SelfSend(_) => add(&mut t.self_send, o.amount),
            OutputKind::External | OutputKind::OtherWallet(_) | OutputKind::OpReturn => {
                add(&mut t.recipients, o.amount)
            }
        }
    }
    if overflow {
        report.push(Issue::ValueOutOfRange);
        report.totals = t;
        return;
    }
    if ctx.policy.message {
        // never broadcast: no fee or change to judge
        t.inputs = all_known.then_some(inputs_sum);
        report.totals = t;
        return;
    }
    if all_known {
        t.inputs = Some(inputs_sum);
        match inputs_sum.checked_sub(t.outputs) {
            None => report.push(Issue::NegativeFee),
            Some(fee) => {
                t.fee = Some(fee);
                let p = &ctx.policy;
                let share = |pct: u64| fee as u128 * 100 >= pct as u128 * t.outputs as u128;
                if share(p.fee_block_percent) {
                    report.push(Issue::FeeTooHigh);
                } else if share(p.fee_warn_percent) {
                    report.push(Issue::HighFee);
                }
                if fee as u128 > p.fee_rate_warn as u128 * t.vsize as u128 {
                    report.push(Issue::HighFeeRate);
                }
            }
        }
    } else {
        report.push(Issue::FeeUnknown);
    }
    if t.change == 0 && t.self_send == 0 {
        report.push(Issue::NoChange);
    }
    report.totals = t;
}
