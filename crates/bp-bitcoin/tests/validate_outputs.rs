//! Validator, part 2: outputs and change rules, fees, sighash types,
//! network, mixed inputs, the session UTXO memory and the totals.

mod common;

use bitcoin::psbt::{Psbt as RefPsbt, PsbtSighashType};
use bitcoin::{Amount, ScriptBuf};
use bp_bitcoin::bip32::Xpriv;
use bp_bitcoin::validate::{validate, At, Class, Context, Issue, OutputKind, Policy, Report, UtxoMemory};
use bp_bitcoin::Network;
use common::{build, In, Kind, Out, Wallet, SEED};

fn master() -> Xpriv {
    Xpriv::master(&SEED).unwrap()
}

fn check_with(p: &RefPsbt, policy: Policy, memory: Option<&UtxoMemory>) -> Report {
    let raw = p.serialize();
    let m = master();
    let mut ctx = Context::new(&m, Network::Signet);
    ctx.policy = policy;
    ctx.memory = memory;
    validate(&raw, &ctx).1
}

fn check(p: &RefPsbt) -> Report {
    check_with(p, Policy::default(), None)
}

fn simple(kind: Kind) -> RefPsbt {
    let w = Wallet::ours();
    build(
        &w,
        &[In::new(kind, 3, 100_000)],
        &[Out::pay(60_000), Out::change(&w, kind, 2, 39_000)],
    )
}

/// An output paying `script`, claiming this wallet's key at `path`.
fn claimed_output(p: &mut RefPsbt, j: usize, script: ScriptBuf, kind: Kind, path: &str) {
    let w = Wallet::ours();
    p.unsigned_tx.output[j].script_pubkey = script;
    p.outputs[j] = Default::default();
    w.claim_output(&mut p.outputs[j], kind, path);
}

#[test]
fn change_is_verified_and_totals_add_up() {
    for kind in Kind::ALL {
        let r = check(&simple(kind));
        assert_eq!(r.issues(), &[], "{kind:?}");
        assert_eq!(r.outputs()[0].kind, OutputKind::External);
        let OutputKind::Change(c) = r.outputs()[1].kind else {
            panic!("{kind:?}: not change")
        };
        assert_eq!(c.get().path.steps()[3..], [1, 2]);
        let t = r.totals;
        assert_eq!((t.ours, t.inputs, t.outputs), (100_000, Some(100_000), 99_000));
        assert_eq!(
            (t.recipients, t.change, t.self_send, t.fee),
            (60_000, 39_000, 0, Some(1_000))
        );
        // vsize of a signed 1-in / 2-out transaction of this kind
        // overhead 10.5 + input + 31 (P2WPKH recipient) + change output
        let expect = match kind {
            Kind::Wpkh => 141,   // 68 + 31
            Kind::ShWpkh => 165, // 91 + 32
            Kind::Pkh => 223,    // 148 + 34 (no witness)
            Kind::Tr => 142,     // 57.5 + 43
        };
        assert!(t.vsize.abs_diff(expect) <= 2, "{kind:?}: vsize {}", t.vsize);
        assert!(!r.rbf || r.lock_time == 0);
    }
}

#[test]
fn self_send_to_a_receive_address() {
    let w = Wallet::ours();
    let p = build(
        &w,
        &[In::new(Kind::Wpkh, 3, 100_000)],
        &[Out::pay(60_000), {
            let mut o = Out::change(&w, Kind::Tr, 5, 39_000);
            o.script = w.spk(Kind::Tr, &Kind::Tr.path(0, 5));
            o.change = Some((Kind::Tr, Kind::Tr.path(0, 5)));
            o
        }],
    );
    let r = check(&p);
    assert_eq!(r.issues(), &[], "{:?}", r.issues());
    assert!(matches!(r.outputs()[1].kind, OutputKind::SelfSend(_)));
    assert_eq!(r.totals.self_send, 39_000);
}

#[test]
fn output_ownership_contradiction() {
    let other = Wallet::new(&[5; 32]);
    for kind in Kind::ALL {
        // claims this seed's change key, pays someone else
        let mut p = simple(kind);
        let path = kind.path(1, 2);
        claimed_output(&mut p, 1, other.spk(kind, &path), kind, &path);
        let r = check(&p);
        assert!(r.has(Issue::ChangeContradiction(1)), "{kind:?}: {:?}", r.issues());
        assert_eq!(r.worst(), Some(Class::Attack));
    }
    // P2SH-P2WPKH with a redeem script for another key
    let mut p = simple(Kind::ShWpkh);
    p.outputs[1].redeem_script = Some(other.redeem(&Kind::ShWpkh.path(1, 2)));
    assert!(check(&p).has(Issue::ChangeContradiction(1)));
}

#[test]
fn output_key_not_from_seed() {
    let w = Wallet::ours();
    let mut p = simple(Kind::Wpkh);
    let (_, v) = p.outputs[1].bip32_derivation.pop_first().unwrap();
    p.outputs[1]
        .bip32_derivation
        .insert(w.key(&Kind::Wpkh.path(1, 3)).0, v);
    let r = check(&p);
    assert!(r.has(Issue::KeyNotFromSeed(At::Output(1))));
    assert_eq!(r.worst(), Some(Class::Attack));
}

#[test]
fn change_path_rules() {
    let w = Wallet::ours();
    let cases: [(&str, Issue); 5] = [
        ("m/84'/1'/0'/2/2", Issue::ChangePathViolation(1)), // branch 2
        ("m/86'/1'/0'/1/2", Issue::ChangePathViolation(1)), // purpose of another script type
        ("m/84'/1'/1'/1/2", Issue::ChangePathViolation(1)), // an account that is not spending
        ("m/84'/1'/0'/1", Issue::ChangePathViolation(1)),   // too short
        ("m/84'/1'/0'/1'/2", Issue::ChangePathViolation(1)), // hardened branch
    ];
    for (path, issue) in cases {
        let mut p = simple(Kind::Wpkh);
        claimed_output(&mut p, 1, w.spk(Kind::Wpkh, path), Kind::Wpkh, path);
        let r = check(&p);
        assert!(r.has(issue), "{path}: {:?}", r.issues());
        assert_eq!(r.worst(), Some(Class::Attack), "{path}");
    }
    // coin type of another network
    let path = "m/84'/0'/0'/1/2";
    let mut p = simple(Kind::Wpkh);
    claimed_output(&mut p, 1, w.spk(Kind::Wpkh, path), Kind::Wpkh, path);
    assert!(check(&p).has(Issue::NetworkMismatch(At::Output(1))));
    // a change index far beyond the inputs'
    let path = "m/84'/1'/0'/1/20004";
    let mut p = simple(Kind::Wpkh);
    claimed_output(&mut p, 1, w.spk(Kind::Wpkh, path), Kind::Wpkh, path);
    let r = check(&p);
    assert_eq!(r.issues(), &[Issue::ChangeIndexFar(1)]);
    assert!(r.can_sign(false));
}

#[test]
fn fee_policy() {
    let w = Wallet::ours();
    let tx = |fee: u64| {
        build(
            &w,
            &[In::new(Kind::Wpkh, 1, 1_000_000)],
            &[Out::pay(500_000), Out::change(&w, Kind::Wpkh, 1, 500_000 - fee)],
        )
    };
    // < 5% of outputs: fine
    assert_eq!(check(&tx(40_000)).issues(), &[]);
    // >= 5%: warning
    let r = check(&tx(50_000));
    assert_eq!(r.issues(), &[Issue::HighFee]);
    assert!(r.can_sign(false));
    // >= 10%: refused by default
    let r = check(&tx(95_000));
    assert!(r.has(Issue::FeeTooHigh));
    assert!(!r.can_sign(true));
    // ... unless the policy allows it
    let policy = Policy {
        fee_block_percent: 20,
        ..Policy::default()
    };
    let r = check_with(&tx(95_000), policy, None);
    assert!(r.has(Issue::HighFee) && !r.has(Issue::FeeTooHigh));
    // outputs exceed inputs
    let p = build(
        &w,
        &[In::new(Kind::Wpkh, 1, 100_000)],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 1, 41_000)],
    );
    assert!(check(&p).has(Issue::NegativeFee));
    // a high fee rate with a small share
    let p = build(
        &w,
        &[In::new(Kind::Wpkh, 1, 2_000_000_000)],
        &[
            Out::pay(1_000_000_000),
            Out::change(&w, Kind::Wpkh, 1, 999_800_000),
        ],
    );
    assert_eq!(check(&p).issues(), &[Issue::HighFeeRate]);
}

#[test]
fn fee_unknown_and_no_change() {
    let w = Wallet::ours();
    let other = Wallet::new(&[3; 32]);
    let mut p = build(
        &w,
        &[In::new(Kind::Wpkh, 1, 50_000), In::new(Kind::Wpkh, 2, 20_000)],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 1, 9_000)],
    );
    let theirs = build(&other, &[In::new(Kind::Wpkh, 1, 20_000)], &[]);
    p.unsigned_tx.input[1] = theirs.unsigned_tx.input[0].clone();
    p.inputs[1] = Default::default(); // no UTXO data for the external input
    let r = check(&p);
    assert!(
        r.has(Issue::FeeUnknown) && r.has(Issue::ExternalInputs),
        "{:?}",
        r.issues()
    );
    assert_eq!(r.totals.fee, None);
    // everything to recipients
    let p = build(&w, &[In::new(Kind::Wpkh, 1, 100_000)], &[Out::pay(99_000)]);
    assert_eq!(check(&p).issues(), &[Issue::NoChange]);
}

#[test]
fn only_sighash_all() {
    for kind in Kind::ALL {
        for (ty, ok) in [(1u32, true), (2, false), (3, false), (0x81, false), (0x83, false)] {
            let mut p = simple(kind);
            p.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(ty));
            let r = check(&p);
            assert_eq!(!r.has(Issue::NonStandardSighash(0)), ok, "{kind:?} {ty:#x}");
        }
    }
    let mut p = simple(Kind::Tr);
    p.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0));
    assert_eq!(check(&p).issues(), &[]);
    let mut p = simple(Kind::Wpkh);
    p.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0));
    assert!(check(&p).has(Issue::NonStandardSighash(0)));
}

#[test]
fn input_paths_of_another_network() {
    let w = Wallet::ours();
    let mut spec = In::new(Kind::Wpkh, 3, 100_000);
    spec.path = "m/84'/0'/0'/0/3".into();
    let p = build(
        &w,
        &[spec],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 2, 39_000)],
    );
    let r = check(&p);
    assert!(r.has(Issue::NetworkMismatch(At::Input(0))), "{:?}", r.issues());
    assert!(!r.can_sign(true));
}

#[test]
fn utxo_memory() {
    let p = simple(Kind::Wpkh);
    let mut outpoint = p.unsigned_tx.input[0]
        .previous_output
        .txid
        .to_byte_array()
        .to_vec();
    outpoint.extend_from_slice(&1u32.to_le_bytes());
    let mut mem = UtxoMemory::new();
    mem.remember(&outpoint, 100_000);
    assert_eq!(check_with(&p, Policy::default(), Some(&mem)).issues(), &[]);
    let mut mem = UtxoMemory::new();
    mem.remember(&outpoint, 100_001);
    let r = check_with(&p, Policy::default(), Some(&mem));
    assert!(r.has(Issue::UtxoAmountChanged(0)));
    assert_eq!(r.worst(), Some(Class::Attack));
}

#[test]
fn unusual_outputs() {
    let w = Wallet::ours();
    let op_return = |data: usize| {
        let mut s = vec![0x6A, 0x4C, data as u8];
        s.extend(std::iter::repeat_n(0xAA, data));
        ScriptBuf::from_bytes(s)
    };
    let base = || {
        build(
            &w,
            &[In::new(Kind::Wpkh, 1, 100_000)],
            &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 1, 39_000)],
        )
    };
    // OP_RETURN with an amount burns it
    let mut p = base();
    p.unsigned_tx.output[0].script_pubkey = op_return(10);
    let r = check(&p);
    assert!(r.has(Issue::BadOpReturn(0)));
    assert_eq!(r.outputs()[0].kind, OutputKind::OpReturn);
    // two OP_RETURNs, or more than 80 bytes
    let mut p = base();
    p.unsigned_tx.output[0].value = Amount::from_sat(0);
    p.unsigned_tx.output[0].script_pubkey = op_return(81);
    p.unsigned_tx.output[1].value = Amount::from_sat(99_000);
    assert!(check(&p).has(Issue::OpReturnNonStandard));
    let mut p = base();
    p.unsigned_tx.output.push(bitcoin::TxOut {
        value: Amount::from_sat(0),
        script_pubkey: op_return(4),
    });
    p.unsigned_tx.output.push(bitcoin::TxOut {
        value: Amount::from_sat(0),
        script_pubkey: op_return(4),
    });
    p.outputs.push(Default::default());
    p.outputs.push(Default::default());
    let r = check(&p);
    assert!(r.has(Issue::OpReturnNonStandard), "{:?}", r.issues());
    // a script the device cannot show, a zero-value output
    let mut p = base();
    p.unsigned_tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x52, 0x02, 1, 2]);
    assert!(check(&p).has(Issue::UnknownScript(0)));
    let mut p = base();
    p.unsigned_tx.output[0].value = Amount::from_sat(0);
    p.unsigned_tx.output[1].value = Amount::from_sat(99_000);
    assert!(check(&p).has(Issue::ZeroValue(0)));
    // more than 21 million BTC
    let mut p = base();
    p.unsigned_tx.output[0].value = Amount::from_sat(2_100_000_000_000_001);
    assert!(check(&p).has(Issue::ValueOutOfRange));
}

#[test]
fn mixed_inputs() {
    let w = Wallet::ours();
    let p = build(
        &w,
        &[In::new(Kind::Wpkh, 1, 50_000), In::new(Kind::Tr, 2, 50_000)],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 1, 39_000)],
    );
    assert_eq!(check(&p).issues(), &[Issue::MixedScriptTypes]);
    let mut second = In::new(Kind::Wpkh, 2, 50_000);
    second.path = "m/84'/1'/1'/0/2".into();
    let p = build(
        &w,
        &[In::new(Kind::Wpkh, 1, 50_000), second],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 1, 39_000)],
    );
    assert_eq!(check(&p).issues(), &[Issue::MultipleAccounts]);
}

#[test]
fn lock_time_and_rbf_are_reported() {
    let mut p = simple(Kind::Wpkh);
    p.unsigned_tx.lock_time = bitcoin::absolute::LockTime::from_consensus(800_000);
    p.unsigned_tx.input[0].sequence = bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME;
    let r = check(&p);
    assert_eq!((r.lock_time, r.rbf), (800_000, true));
    p.unsigned_tx.input[0].sequence = bitcoin::Sequence::MAX;
    assert!(!check(&p).rbf);
}

use bitcoin::hashes::Hash;

/// Mutated PSBTs (all four script types, change, global xpub) never make
/// the validator panic, and a report that allows signing never contains an
/// attack or error.
#[test]
fn validator_never_panics_on_mutations() {
    let w = Wallet::ours();
    let mut seeds: Vec<Vec<u8>> = Kind::ALL.iter().map(|&k| simple(k).serialize()).collect();
    seeds.push(
        build(
            &w,
            &[
                In::new(Kind::Wpkh, 1, 50_000),
                In::new(Kind::Tr, 2, 50_000).without_prev_tx(),
            ],
            &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 1, 39_000)],
        )
        .serialize(),
    );
    let m = master();
    let mem = UtxoMemory::new();
    let mut ctx = Context::new(&m, Network::Signet);
    ctx.memory = Some(&mem);
    let mut x = 0x1234_5678_9abc_def0u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut parsed = 0;
    for i in 0..1_200 {
        let mut d = seeds[i % seeds.len()].clone();
        for _ in 0..1 + next() % 3 {
            let j = (next() as usize) % d.len();
            match next() % 3 {
                0 => d[j] ^= 1 << (next() % 8),
                1 => d[j] = next() as u8,
                _ => {
                    d.remove(j);
                }
            }
        }
        let (p, r) = validate(&d, &ctx);
        parsed += p.is_some() as usize;
        if r.can_sign(true) {
            assert!(r.worst() < Some(Class::Error));
            assert!(r.inputs().iter().any(|i| i.owned.is_some()));
        }
    }
    assert!(parsed > 100, "parsed {parsed}");
}
