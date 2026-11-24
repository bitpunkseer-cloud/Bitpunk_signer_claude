//! Multisig validation and signing (M7 plan 8, S1–S11). PSBTs, scripts,
//! keys and signature hashes are built with rust-bitcoin (independent of
//! our BIP-32, script and sighash code); the registered wallet goes through
//! our descriptor parser. Then they are altered the way the attacks in the
//! survey do (Coldcard, Passport, SeedSigner, Specter scenarios).

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv as RefXpriv, Xpub as RefXpub};
use bitcoin::blockdata::opcodes::all::OP_CHECKMULTISIG;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::psbt::Psbt as RefPsbt;
use bitcoin::secp256k1::{All, Message, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    absolute, transaction, Amount, CompressedPublicKey, NetworkKind, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use bp_bitcoin::bip32::Xpriv;
use bp_bitcoin::multisig::{descriptor, Wallet};
use bp_bitcoin::sign::{sign_psbt, Signer};
use bp_bitcoin::validate::{
    validate, Class, Context, Issue, OutputKind, Policy, Report, SpendKind, UtxoMemory,
};
use bp_bitcoin::Network;
use std::str::FromStr;

const OURS: [u8; 32] = [0x42; 32];
const COSIGNERS: [[u8; 32]; 2] = [[0x51; 32], [0x52; 32]];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wrap {
    Wsh,
    ShWsh,
}

impl Wrap {
    fn t(self) -> u32 {
        match self {
            Wrap::Wsh => 2,
            Wrap::ShWsh => 1,
        }
    }
}

struct Signer3 {
    secp: Secp256k1<All>,
    masters: Vec<RefXpriv>,
}

impl Signer3 {
    fn new() -> Self {
        let secp = Secp256k1::new();
        let masters = [OURS, COSIGNERS[0], COSIGNERS[1]]
            .iter()
            .map(|s| RefXpriv::new_master(NetworkKind::Test, s).unwrap())
            .collect();
        Signer3 { secp, masters }
    }

    fn fp(&self, k: usize) -> Fingerprint {
        self.masters[k].fingerprint(&self.secp)
    }

    fn origin(wrap: Wrap, account: u32) -> String {
        format!("m/48'/1'/{account}'/{}'", wrap.t())
    }

    fn account_xpub(&self, k: usize, wrap: Wrap, account: u32) -> RefXpub {
        let p = DerivationPath::from_str(&Self::origin(wrap, account)).unwrap();
        RefXpub::from_priv(&self.secp, &self.masters[k].derive_priv(&self.secp, &p).unwrap())
    }

    fn path(wrap: Wrap, account: u32, b: u32, i: u32) -> DerivationPath {
        DerivationPath::from_str(&format!("{}/{b}/{i}", Self::origin(wrap, account))).unwrap()
    }

    fn sk(&self, k: usize, path: &DerivationPath) -> SecretKey {
        self.masters[k].derive_priv(&self.secp, path).unwrap().private_key
    }

    fn pk(&self, k: usize, path: &DerivationPath) -> bitcoin::secp256k1::PublicKey {
        self.sk(k, path).public_key(&self.secp)
    }

    /// The wallet (keys `ks`, threshold `m`) as our record, from descriptor text.
    fn wallet(&self, wrap: Wrap, m: u8, ks: &[usize], account: u32) -> Wallet {
        let keys: Vec<String> = ks
            .iter()
            .map(|&k| {
                format!(
                    "[{}/48h/1h/{account}h/{}h]{}/<0;1>/*",
                    self.fp(k),
                    wrap.t(),
                    self.account_xpub(k, wrap, account)
                )
            })
            .collect();
        let inner = format!("sortedmulti({m},{})", keys.join(","));
        let text = match wrap {
            Wrap::Wsh => format!("wsh({inner})"),
            Wrap::ShWsh => format!("sh(wsh({inner}))"),
        };
        descriptor::parse(&text).unwrap().wallet
    }
}

/// `OP_m <sorted keys> OP_n OP_CHECKMULTISIG`, built with rust-bitcoin.
fn multisig_ws(m: i64, keys: &[bitcoin::secp256k1::PublicKey]) -> ScriptBuf {
    let mut ks: Vec<[u8; 33]> = keys.iter().map(|k| k.serialize()).collect();
    ks.sort();
    let mut b = Builder::new().push_int(m);
    for k in &ks {
        b = b.push_slice(k);
    }
    b.push_int(ks.len() as i64)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

fn spk_of(wrap: Wrap, ws: &ScriptBuf) -> (ScriptBuf, Option<ScriptBuf>) {
    let wsh = ScriptBuf::new_p2wsh(&ws.wscript_hash());
    match wrap {
        Wrap::Wsh => (wsh, None),
        Wrap::ShWsh => (ScriptBuf::new_p2sh(&wsh.script_hash()), Some(wsh)),
    }
}

/// One multisig address: keys `ks` at account/b/i, threshold m.
struct Addr {
    ws: ScriptBuf,
    spk: ScriptBuf,
    redeem: Option<ScriptBuf>,
    derivs: Vec<(bitcoin::secp256k1::PublicKey, (Fingerprint, DerivationPath))>,
}

fn addr(s: &Signer3, wrap: Wrap, m: i64, ks: &[usize], account: u32, b: u32, i: u32) -> Addr {
    let path = Signer3::path(wrap, account, b, i);
    let keys: Vec<_> = ks.iter().map(|&k| s.pk(k, &path)).collect();
    let ws = multisig_ws(m, &keys);
    let (spk, redeem) = spk_of(wrap, &ws);
    let derivs = ks
        .iter()
        .zip(&keys)
        .map(|(&k, pk)| (*pk, (s.fp(k), path.clone())))
        .collect();
    Addr {
        ws,
        spk,
        redeem,
        derivs,
    }
}

struct Spend {
    a: Addr,
    value: u64,
}

fn build(ins: &[Spend], outs: &[(Option<Addr>, u64)]) -> RefPsbt {
    let mut prevs = vec![];
    let mut txins = vec![];
    for (n, sp) in ins.iter().enumerate() {
        let prev = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([n as u8 + 7; 32]), 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(sp.value),
                script_pubkey: sp.a.spk.clone(),
            }],
        };
        txins.push(TxIn {
            previous_output: OutPoint::new(prev.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        prevs.push(prev);
    }
    let pay = ScriptBuf::new_p2wpkh(
        &CompressedPublicKey::from_slice(
            &Signer3::new()
                .pk(2, &DerivationPath::from_str("m/9'/9").unwrap())
                .serialize(),
        )
        .unwrap()
        .wpubkey_hash(),
    );
    let txouts = outs
        .iter()
        .map(|(a, v)| TxOut {
            value: Amount::from_sat(*v),
            script_pubkey: a.as_ref().map_or(pay.clone(), |a| a.spk.clone()),
        })
        .collect();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: txins,
        output: txouts,
    };
    let mut p = RefPsbt::from_unsigned_tx(tx).unwrap();
    for ((inp, sp), prev) in p.inputs.iter_mut().zip(ins).zip(prevs) {
        inp.witness_utxo = Some(prev.output[0].clone());
        inp.non_witness_utxo = Some(prev);
        inp.witness_script = Some(sp.a.ws.clone());
        inp.redeem_script = sp.a.redeem.clone();
        for (pk, d) in &sp.a.derivs {
            inp.bip32_derivation.insert(*pk, d.clone());
        }
    }
    for (o, (a, _)) in p.outputs.iter_mut().zip(outs) {
        if let Some(a) = a {
            o.witness_script = Some(a.ws.clone());
            o.redeem_script = a.redeem.clone();
            for (pk, d) in &a.derivs {
                o.bip32_derivation.insert(*pk, d.clone());
            }
        }
    }
    p
}

fn master() -> Xpriv {
    Xpriv::master(&OURS).unwrap()
}

fn check_with(p: &RefPsbt, wallets: &[Option<&Wallet>]) -> Report {
    let raw = p.serialize();
    let m = master();
    let mut ctx = Context::new(&m, Network::Signet);
    ctx.multisig = wallets;
    validate(&raw, &ctx).1
}

/// The honest 2-of-3: input at /0/5, change at /1/3, a payment.
fn honest(s: &Signer3, wrap: Wrap) -> RefPsbt {
    build(
        &[Spend {
            a: addr(s, wrap, 2, &[0, 1, 2], 0, 0, 5),
            value: 100_000,
        }],
        &[
            (None, 60_000),
            (Some(addr(s, wrap, 2, &[0, 1, 2], 0, 1, 3)), 39_000),
        ],
    )
}

#[test]
fn honest_two_of_three() {
    let s = Signer3::new();
    for wrap in [Wrap::Wsh, Wrap::ShWsh] {
        let w = s.wallet(wrap, 2, &[1, 0, 2], 0);
        let r = check_with(&honest(&s, wrap), &[Some(&w)]);
        assert_eq!(r.issues(), &[], "{wrap:?}");
        assert!(r.can_sign(false));
        assert_eq!(r.wallet, Some(0));
        let o = *r.inputs()[0].owned.unwrap().get();
        assert_eq!(
            o.kind,
            if wrap == Wrap::Wsh {
                SpendKind::P2wshMulti
            } else {
                SpendKind::P2shP2wshMulti
            }
        );
        let ms = o.ms.unwrap();
        assert_eq!((ms.wallet, ms.m, ms.n, ms.branch, ms.index), (0, 2, 3, 0, 5));
        assert!(matches!(r.outputs()[0].kind, OutputKind::External));
        match r.outputs()[1].kind {
            OutputKind::Change(c) => {
                let ms = c.get().ms.unwrap();
                assert_eq!((ms.branch, ms.index), (1, 3));
            }
            k => panic!("{k:?}"),
        }
        assert_eq!(r.totals.change, 39_000);
        assert_eq!(r.totals.recipients, 60_000);
        assert_eq!(r.totals.fee, Some(1_000));
        // 2-of-3 P2WSH input ~ 104 vB; the whole tx well above single-key
        assert!((150..=260).contains(&r.totals.vsize), "{}", r.totals.vsize);
    }
}

#[test]
fn unregistered_wallet_is_refused() {
    let s = Signer3::new();
    let p = honest(&s, Wrap::Wsh);
    let r = check_with(&p, &[]);
    assert!(r.has(Issue::UnregisteredMultisig(0)), "{:?}", r.issues());
    assert_eq!(r.worst(), Some(Class::Error));
    assert!(!r.can_sign(true));
    // a registered wallet of other keys does not help
    let other = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 1);
    assert!(check_with(&p, &[Some(&other)]).has(Issue::UnregisteredMultisig(0)));
    // nor the same keys with another threshold
    let one = s.wallet(Wrap::Wsh, 1, &[0, 1, 2], 0);
    assert!(check_with(&p, &[Some(&one)]).has(Issue::UnregisteredMultisig(0)));
}

#[test]
fn poisoned_input_is_refused() {
    // Passport: an attacker-funded 1-of-2 input with our key at the
    // registered path must not be signed (nor authorize change)
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let path = Signer3::path(Wrap::Wsh, 0, 0, 5);
    let attacker = Secp256k1::new();
    let evil = SecretKey::from_slice(&[0x66; 32]).unwrap().public_key(&attacker);
    let ws = multisig_ws(1, &[s.pk(0, &path), evil]);
    let (spk, _) = spk_of(Wrap::Wsh, &ws);
    let poisoned = Addr {
        ws,
        spk,
        redeem: None,
        derivs: vec![(s.pk(0, &path), (s.fp(0), path.clone()))],
    };
    let p = build(
        &[
            Spend {
                a: addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 0, 0, 5),
                value: 100_000,
            },
            Spend {
                a: poisoned,
                value: 50_000,
            },
        ],
        &[(None, 149_000)],
    );
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::UnregisteredMultisig(1)), "{:?}", r.issues());
    assert!(!r.can_sign(true));
}

#[test]
fn contradicting_claims_are_attacks() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    // a cosigner's path says another index (Passport "mismatched paths")
    let mut p = honest(&s, Wrap::Wsh);
    let cos = s.pk(1, &Signer3::path(Wrap::Wsh, 0, 0, 5));
    p.inputs[0]
        .bip32_derivation
        .insert(cos, (s.fp(1), Signer3::path(Wrap::Wsh, 0, 0, 6)));
    let r = check_with(&p, &[Some(&w)]);
    assert!(
        r.issues()
            .iter()
            .any(|i| matches!(i, Issue::MultisigClaimMismatch(_))),
        "{:?}",
        r.issues()
    );
    assert_eq!(r.worst(), Some(Class::Attack));
    // a claim for a key that is not in the wallet
    let mut p = honest(&s, Wrap::Wsh);
    let stranger = SecretKey::from_slice(&[0x77; 32]).unwrap().public_key(&s.secp);
    p.inputs[0].bip32_derivation.insert(
        stranger,
        (Fingerprint::from([1, 2, 3, 4]), Signer3::path(Wrap::Wsh, 0, 0, 5)),
    );
    let r = check_with(&p, &[Some(&w)]);
    assert!(r
        .issues()
        .iter()
        .any(|i| matches!(i, Issue::MultisigClaimMismatch(_))));
}

#[test]
fn our_key_claimed_but_not_in_the_script() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let mut p = honest(&s, Wrap::Wsh);
    // the script of three other keys, our claim kept
    let path = Signer3::path(Wrap::Wsh, 0, 0, 5);
    let k3 = SecretKey::from_slice(&[0x33; 32]).unwrap().public_key(&s.secp);
    let ws = multisig_ws(2, &[s.pk(1, &path), s.pk(2, &path), k3]);
    let (spk, _) = spk_of(Wrap::Wsh, &ws);
    p.inputs[0].witness_script = Some(ws);
    let mut prev = p.inputs[0].non_witness_utxo.clone().unwrap();
    prev.output[0].script_pubkey = spk.clone();
    p.unsigned_tx.input[0].previous_output = OutPoint::new(prev.compute_txid(), 0);
    p.inputs[0].witness_utxo = Some(prev.output[0].clone());
    p.inputs[0].non_witness_utxo = Some(prev);
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::ScriptNotOurs(0)), "{:?}", r.issues());
    assert_eq!(r.worst(), Some(Class::Attack));
}

#[test]
fn missing_witness_script() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let mut p = honest(&s, Wrap::Wsh);
    p.inputs[0].witness_script = None;
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::MissingWitnessScript(0)), "{:?}", r.issues());
    assert!(!r.can_sign(true));
}

fn with_change(s: &Signer3, change: Addr) -> RefPsbt {
    build(
        &[Spend {
            a: addr(s, Wrap::Wsh, 2, &[0, 1, 2], 0, 0, 5),
            value: 100_000,
        }],
        &[(None, 60_000), (Some(change), 39_000)],
    )
}

#[test]
fn change_attacks() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let path = Signer3::path(Wrap::Wsh, 0, 1, 3);
    // a cosigner replaced by the attacker's key (SFT-7394 / xpub swap)
    let evil = SecretKey::from_slice(&[0x66; 32]).unwrap().public_key(&s.secp);
    let ws = multisig_ws(2, &[s.pk(0, &path), s.pk(1, &path), evil]);
    let (spk, _) = spk_of(Wrap::Wsh, &ws);
    let swapped = Addr {
        ws,
        spk,
        redeem: None,
        derivs: vec![
            (s.pk(0, &path), (s.fp(0), path.clone())),
            (s.pk(1, &path), (s.fp(1), path.clone())),
            (evil, (Fingerprint::from([6, 6, 6, 6]), path.clone())),
        ],
    };
    let r = check_with(&with_change(&s, swapped), &[Some(&w)]);
    assert!(r.has(Issue::ChangeContradiction(1)), "{:?}", r.issues());
    assert!(!r.can_sign(true));
    // the threshold lowered with the registered keys (hostage)
    let one = addr(&s, Wrap::Wsh, 1, &[0, 1, 2], 0, 1, 3);
    let r = check_with(&with_change(&s, one), &[Some(&w)]);
    assert!(r.has(Issue::ChangeContradiction(1)), "{:?}", r.issues());
    // the right address, but another witness script in the output map
    let mut good = addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 0, 1, 3);
    good.ws = multisig_ws(1, &[s.pk(0, &path)]);
    let p = with_change(&s, good);
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::ChangeContradiction(1)), "{:?}", r.issues());
    // change on another account of the same signers: not ours, a recipient
    let cross = addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 1, 1, 3);
    let r = check_with(&with_change(&s, cross), &[Some(&w)]);
    assert!(!r.worst().is_some_and(|c| c >= Class::Error), "{:?}", r.issues());
    assert!(matches!(r.outputs()[1].kind, OutputKind::External));
    assert_eq!(r.totals.recipients, 99_000);
    assert!(r.has(Issue::NoChange));
    // honest change without derivations: a recipient too
    let mut bare = addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 0, 1, 3);
    bare.derivs.clear();
    let r = check_with(&with_change(&s, bare), &[Some(&w)]);
    assert!(matches!(r.outputs()[1].kind, OutputKind::External));
    // change far beyond the input index
    let far = addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 0, 1, 50_000);
    let r = check_with(&with_change(&s, far), &[Some(&w)]);
    assert!(r.has(Issue::ChangeIndexFar(1)), "{:?}", r.issues());
    assert!(matches!(r.outputs()[1].kind, OutputKind::Change(_)));
}

#[test]
fn output_to_another_registered_wallet() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let w2 = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 1);
    let to_w2 = addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 1, 0, 0);
    let r = check_with(&with_change(&s, to_w2), &[Some(&w), Some(&w2)]);
    match r.outputs()[1].kind {
        OutputKind::OtherWallet(o) => assert_eq!(o.get().ms.unwrap().wallet, 1),
        k => panic!("{k:?}"),
    }
    assert_eq!(r.totals.recipients, 99_000, "sent, not kept");
    assert!(r.can_sign(false), "{:?}", r.issues());
}

#[test]
fn mixed_wallets_are_refused() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let w2 = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 1);
    let p = build(
        &[
            Spend {
                a: addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 0, 0, 5),
                value: 100_000,
            },
            Spend {
                a: addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 1, 0, 2),
                value: 100_000,
            },
        ],
        &[(None, 199_000)],
    );
    let r = check_with(&p, &[Some(&w), Some(&w2)]);
    assert!(r.has(Issue::MixedWallets), "{:?}", r.issues());
    assert!(!r.can_sign(true));
}

#[test]
fn global_xpub_of_a_cosigner_must_match() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let mut p = honest(&s, Wrap::Wsh);
    let origin = DerivationPath::from_str(&Signer3::origin(Wrap::Wsh, 0)).unwrap();
    // the honest global xpubs are fine
    for k in 0..3 {
        p.xpub
            .insert(s.account_xpub(k, Wrap::Wsh, 0), (s.fp(k), origin.clone()));
    }
    assert_eq!(check_with(&p, &[Some(&w)]).issues(), &[]);
    // a cosigner's origin with the attacker's xpub
    let mut p = honest(&s, Wrap::Wsh);
    let evil = RefXpriv::new_master(NetworkKind::Test, &[0x66; 32]).unwrap();
    let evil = RefXpub::from_priv(&s.secp, &evil.derive_priv(&s.secp, &origin).unwrap());
    p.xpub.insert(evil, (s.fp(1), origin));
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::GlobalXpubMismatch), "{:?}", r.issues());
    assert_eq!(r.worst(), Some(Class::Attack));
}

fn cosign(s: &Signer3, p: &mut RefPsbt, k: usize, path: &DerivationPath, digest_override: Option<[u8; 32]>) {
    let ws = p.inputs[0].witness_script.clone().unwrap();
    let amount = p.inputs[0].witness_utxo.as_ref().unwrap().value;
    let h = SighashCache::new(&p.unsigned_tx)
        .p2wsh_signature_hash(0, &ws, amount, EcdsaSighashType::All)
        .unwrap();
    let msg = Message::from_digest(digest_override.unwrap_or(h.to_byte_array()));
    let sig = s.secp.sign_ecdsa(&msg, &s.sk(k, path));
    p.inputs[0].partial_sigs.insert(
        bitcoin::PublicKey::new(s.pk(k, path)),
        bitcoin::ecdsa::Signature {
            signature: sig,
            sighash_type: EcdsaSighashType::All,
        },
    );
}

#[test]
fn cosigner_signatures_are_checked() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let path = Signer3::path(Wrap::Wsh, 0, 0, 5);
    // a SeedSigner already signed: counted
    let mut p = honest(&s, Wrap::Wsh);
    cosign(&s, &mut p, 1, &path, None);
    let r = check_with(&p, &[Some(&w)]);
    assert_eq!(r.issues(), &[]);
    assert_eq!(r.inputs()[0].cosigs, 1);
    // a signature over something else: warned, not counted
    let mut p = honest(&s, Wrap::Wsh);
    cosign(&s, &mut p, 1, &path, Some([9; 32]));
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::BadCosignerSignature(0)), "{:?}", r.issues());
    assert_eq!(r.inputs()[0].cosigs, 0);
    assert!(r.can_sign(false), "a warning, not a block");
    // a key that is not in the script
    let mut p = honest(&s, Wrap::Wsh);
    cosign(&s, &mut p, 1, &DerivationPath::from_str("m/1/2").unwrap(), None);
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::BadCosignerSignature(0)));
}

#[test]
fn signing_uses_the_rebuilt_script() {
    let s = Signer3::new();
    for wrap in [Wrap::Wsh, Wrap::ShWsh] {
        let w = s.wallet(wrap, 2, &[0, 1, 2], 0);
        let p = honest(&s, wrap);
        let raw = p.serialize();
        let m = master();
        let wallets = [Some(&w)];
        let mut ctx = Context::new(&m, Network::Signet);
        ctx.multisig = &wallets;
        let report = validate(&raw, &ctx).1;
        let signer = Signer {
            master: &m,
            network: Network::Signet,
            policy: Policy::default(),
            multisig: &wallets,
            single_key: false,
        };
        let mut mem = UtxoMemory::new();
        let mut out = vec![0u8; 8192];
        let signed = sign_psbt(&raw, &signer, &mut mem, &report.digest(), false, &mut out).unwrap();
        assert_eq!(signed.signatures, 1);
        // rust-bitcoin: our partial signature verifies for the P2WSH sighash
        let result = RefPsbt::deserialize(&out[..signed.len]).unwrap();
        let path = Signer3::path(wrap, 0, 0, 5);
        let ours = bitcoin::PublicKey::new(s.pk(0, &path));
        let sig = result.inputs[0].partial_sigs.get(&ours).expect("our signature");
        let ws = p.inputs[0].witness_script.clone().unwrap();
        let h = SighashCache::new(&p.unsigned_tx)
            .p2wsh_signature_hash(0, &ws, Amount::from_sat(100_000), EcdsaSighashType::All)
            .unwrap();
        s.secp
            .verify_ecdsa(
                &Message::from_digest(h.to_byte_array()),
                &sig.signature,
                &ours.inner,
            )
            .unwrap();
        // without the wallet the signer refuses
        let none: [Option<&Wallet>; 0] = [];
        let signer = Signer {
            master: &m,
            network: Network::Signet,
            policy: Policy::default(),
            multisig: &none,
            single_key: false,
        };
        let mut out = vec![0u8; 8192];
        assert!(sign_psbt(&raw, &signer, &mut mem, &report.digest(), false, &mut out).is_err());
    }
}

#[test]
fn wallet_reconstructed_from_global_xpubs() {
    let s = Signer3::new();
    for wrap in [Wrap::Wsh, Wrap::ShWsh] {
        let w = s.wallet(wrap, 2, &[0, 1, 2], 0);
        let mut p = honest(&s, wrap);
        let raw = p.serialize();
        let parsed = bp_bitcoin::psbt::Psbt::parse(&raw).unwrap();
        let fp = master().fingerprint();
        // no global xpubs: nothing to rebuild from
        assert!(bp_bitcoin::multisig::reconstruct(&parsed, fp, true).is_none());
        let origin = DerivationPath::from_str(&Signer3::origin(wrap, 0)).unwrap();
        for k in [2, 0, 1] {
            p.xpub
                .insert(s.account_xpub(k, wrap, 0), (s.fp(k), origin.clone()));
        }
        let raw = p.serialize();
        let parsed = bp_bitcoin::psbt::Psbt::parse(&raw).unwrap();
        let got = bp_bitcoin::multisig::reconstruct(&parsed, fp, true).unwrap();
        assert_eq!(got.id(), w.id(), "{wrap:?}");
        // a swapped global xpub gives another wallet (and another code)
        let mut q = honest(&s, wrap);
        let evil = RefXpriv::new_master(NetworkKind::Test, &[0x66; 32]).unwrap();
        let evil = RefXpub::from_priv(&s.secp, &evil.derive_priv(&s.secp, &origin).unwrap());
        q.xpub
            .insert(s.account_xpub(0, wrap, 0), (s.fp(0), origin.clone()));
        q.xpub.insert(evil, (s.fp(1), origin.clone()));
        q.xpub
            .insert(s.account_xpub(2, wrap, 0), (s.fp(2), origin.clone()));
        let raw = q.serialize();
        let parsed = bp_bitcoin::psbt::Psbt::parse(&raw).unwrap();
        assert!(
            bp_bitcoin::multisig::reconstruct(&parsed, fp, true).is_none(),
            "keys must match the script"
        );
    }
}

#[test]
fn verify_only_with_a_seed_outside_the_wallet() {
    let s = Signer3::new();
    // a wallet of three keys, none of them this seed's
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let p = honest(&s, Wrap::Wsh);
    let raw = p.serialize();
    let outsider = Xpriv::master(&[0x99; 32]).unwrap();
    let wallets = [Some(&w)];
    let mut ctx = Context::new(&outsider, Network::Signet);
    ctx.multisig = &wallets;
    // without verify-only: nothing here for this seed
    assert!(validate(&raw, &ctx).1.has(Issue::NoInputsForSeed));
    ctx.watch = true;
    let r = validate(&raw, &ctx).1;
    assert!(r.watch_only);
    assert_eq!(r.issues(), &[], "{:?}", r.issues());
    assert!(!r.can_sign(true), "verify-only is never signable");
    assert_eq!(r.wallet, Some(0));
    assert!(matches!(r.outputs()[1].kind, OutputKind::Change(_)));
    assert_eq!(r.totals.fee, Some(1_000));
    // the attacks are still attacks
    let path = Signer3::path(Wrap::Wsh, 0, 1, 3);
    let evil = SecretKey::from_slice(&[0x66; 32]).unwrap().public_key(&s.secp);
    let ws = multisig_ws(2, &[s.pk(0, &path), s.pk(1, &path), evil]);
    let (spk, _) = spk_of(Wrap::Wsh, &ws);
    let swapped = Addr {
        ws,
        spk,
        redeem: None,
        derivs: vec![
            (s.pk(0, &path), (s.fp(0), path.clone())),
            (s.pk(1, &path), (s.fp(1), path.clone())),
        ],
    };
    let raw = with_change(&s, swapped).serialize();
    let r = validate(&raw, &ctx).1;
    assert!(r.has(Issue::ChangeContradiction(1)), "{:?}", r.issues());
    // an unregistered script is simply not verified
    let none: [Option<&Wallet>; 0] = [];
    ctx.multisig = &none;
    assert!(validate(&p.serialize(), &ctx).1.has(Issue::NoInputsForSeed));
}

// ---------- more attack scenarios (Coldcard / SeedSigner style) ----------

fn replace_input_script(p: &mut RefPsbt, ws: ScriptBuf, wrap: Wrap) {
    let (spk, redeem) = spk_of(wrap, &ws);
    let mut prev = p.inputs[0].non_witness_utxo.clone().unwrap();
    prev.output[0].script_pubkey = spk;
    p.unsigned_tx.input[0].previous_output = OutPoint::new(prev.compute_txid(), 0);
    p.inputs[0].witness_utxo = Some(prev.output[0].clone());
    p.inputs[0].non_witness_utxo = Some(prev);
    p.inputs[0].witness_script = Some(ws);
    p.inputs[0].redeem_script = redeem;
}

#[test]
fn script_type_confusion() {
    // the registered P2WSH keys, spent as P2SH-P2WSH: another wallet
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let mut p = honest(&s, Wrap::Wsh);
    let ws = p.inputs[0].witness_script.clone().unwrap();
    replace_input_script(&mut p, ws, Wrap::ShWsh);
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::UnregisteredMultisig(0)), "{:?}", r.issues());
}

#[test]
fn unsorted_and_odd_scripts() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let path = Signer3::path(Wrap::Wsh, 0, 0, 5);
    let mut keys: Vec<[u8; 33]> = (0..3).map(|k| s.pk(k, &path).serialize()).collect();
    keys.sort();
    keys.reverse(); // not BIP-67 order: `multi`, not `sortedmulti`
    let mut b = Builder::new().push_int(2);
    for k in &keys {
        b = b.push_slice(k);
    }
    let unsorted = b.push_int(3).push_opcode(OP_CHECKMULTISIG).into_script();
    let mut p = honest(&s, Wrap::Wsh);
    replace_input_script(&mut p, unsorted, Wrap::Wsh);
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::UnregisteredMultisig(0)), "{:?}", r.issues());
    // an uncompressed key in the script: not a script the signer signs
    let full = s.pk(1, &path).serialize_uncompressed();
    let odd = Builder::new()
        .push_int(1)
        .push_slice(s.pk(0, &path).serialize())
        .push_slice(full)
        .push_int(2)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    let mut p = honest(&s, Wrap::Wsh);
    replace_input_script(&mut p, odd, Wrap::Wsh);
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::UnsupportedInput(0)), "{:?}", r.issues());
}

#[test]
fn sighash_and_redeem_rules_apply_to_multisig() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::ShWsh, 2, &[0, 1, 2], 0);
    let mut p = honest(&s, Wrap::ShWsh);
    p.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from(EcdsaSighashType::None));
    assert!(check_with(&p, &[Some(&w)]).has(Issue::NonStandardSighash(0)));
    // a redeem script that is not the P2SH commitment
    let mut p = honest(&s, Wrap::ShWsh);
    p.inputs[0].redeem_script = Some(ScriptBuf::new_p2wsh(&multisig_ws(1, &[]).wscript_hash()));
    assert!(check_with(&p, &[Some(&w)]).has(Issue::RedeemMismatch(0)));
}

#[test]
fn change_on_an_unknown_branch_is_a_recipient() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let r = check_with(
        &with_change(&s, addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 0, 2, 3)),
        &[Some(&w)],
    );
    assert!(
        matches!(r.outputs()[1].kind, OutputKind::External),
        "{:?}",
        r.outputs()[1]
    );
    assert!(r.has(Issue::NoChange));
    assert!(r.can_sign(false), "{:?}", r.issues());
}

#[test]
fn two_inputs_must_agree_with_the_wallet() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let ins = || {
        [
            Spend {
                a: addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 0, 0, 5),
                value: 100_000,
            },
            Spend {
                a: addr(&s, Wrap::Wsh, 2, &[0, 1, 2], 0, 1, 9),
                value: 50_000,
            },
        ]
    };
    let p = build(&ins(), &[(None, 149_000)]);
    let r = check_with(&p, &[Some(&w)]);
    assert_eq!(r.issues(), &[Issue::NoChange]);
    assert_eq!(r.totals.ours, 150_000);
    // the second input's cosigner claims point at the first input's index
    let mut p = build(&ins(), &[(None, 149_000)]);
    let k1 = s.pk(1, &Signer3::path(Wrap::Wsh, 0, 1, 9));
    p.inputs[1]
        .bip32_derivation
        .insert(k1, (s.fp(1), Signer3::path(Wrap::Wsh, 0, 0, 5)));
    let r = check_with(&p, &[Some(&w)]);
    assert!(
        r.issues()
            .iter()
            .any(|i| matches!(i, Issue::MultisigClaimMismatch(_))),
        "{:?}",
        r.issues()
    );
}

#[test]
fn our_signature_already_there() {
    let s = Signer3::new();
    let w = s.wallet(Wrap::Wsh, 2, &[0, 1, 2], 0);
    let mut p = honest(&s, Wrap::Wsh);
    cosign(&s, &mut p, 0, &Signer3::path(Wrap::Wsh, 0, 0, 5), None);
    let r = check_with(&p, &[Some(&w)]);
    assert!(r.has(Issue::NothingToSign), "{:?}", r.issues());
    assert!(r.inputs()[0].signed);
}
