//! Signing: every signature checked with rust-bitcoin's independent
//! signature hashes and equal byte for byte to libsecp256k1 (test-only
//! references); re-validation before signing; trimmed output; the session
//! UTXO memory; and the BIP-174 and Bitcoin Core signer vectors reproduced.

mod common;

#[allow(dead_code)]
#[path = "data/bip174_vectors.rs"]
mod bip174;
#[allow(dead_code)]
#[path = "data/core_psbt.rs"]
mod core_psbt;

use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt as RefPsbt;
use bitcoin::secp256k1::{Message, SecretKey as RefSecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts as RefPrevouts, SighashCache, TapSighashType};
use bp_bitcoin::bip32::Xpriv;
use bp_bitcoin::psbt::Psbt;
use bp_bitcoin::sighash::{self, SegwitV0Hashes};
use bp_bitcoin::sign::{sign_psbt, sign_psbt_full, Error, Signer};
use bp_bitcoin::validate::script::{classify, p2pkh, ScriptKind};
use bp_bitcoin::validate::{validate, Context, Issue, Policy, UtxoMemory};
use bp_bitcoin::{base58, base64, Network};
use bp_crypto::secp256k1::{ecdsa, SecretKey};
use common::{build, In, Kind, Out, Wallet, SEED};

fn master() -> Xpriv {
    Xpriv::master(&SEED).unwrap()
}

/// Validate, approve, sign. Returns the trimmed PSBT.
fn approve_and_sign(raw: &[u8], memory: &mut UtxoMemory, overridden: bool) -> Result<Vec<u8>, Error> {
    let m = master();
    let mut ctx = Context::new(&m, Network::Signet);
    ctx.memory = Some(&*memory);
    let digest = validate(raw, &ctx).1.digest();
    let signer = Signer {
        master: &m,
        network: Network::Signet,
        policy: Policy::default(),
        multisig: &[],
    };
    let mut out = vec![0u8; 16 * 1024];
    let s = sign_psbt(raw, &signer, memory, &digest, overridden, &mut out)?;
    out.truncate(s.len);
    Ok(out)
}

/// Check every signature of `signed` against `original` with rust-bitcoin,
/// compare with libsecp256k1's own signature, and return the vsize of the
/// finalized transaction.
fn check_with_rust_bitcoin(w: &Wallet, original: &RefPsbt, specs: &[In], signed: &[u8]) -> usize {
    let r = RefPsbt::deserialize(signed).unwrap();
    assert_eq!(r.unsigned_tx, original.unsigned_tx);
    assert!(
        r.outputs.iter().all(|o| *o == Default::default()),
        "outputs are trimmed"
    );
    let prevouts: Vec<bitcoin::TxOut> = original
        .inputs
        .iter()
        .zip(&original.unsigned_tx.input)
        .map(|(i, txin)| {
            i.witness_utxo.clone().unwrap_or_else(|| {
                i.non_witness_utxo.as_ref().unwrap().output[txin.previous_output.vout as usize].clone()
            })
        })
        .collect();
    let mut cache = SighashCache::new(&original.unsigned_tx);
    let mut tx = original.unsigned_tx.clone();
    for (i, spec) in specs.iter().enumerate() {
        let inp = &r.inputs[i];
        let path: bitcoin::bip32::DerivationPath = spec.path.parse().unwrap();
        let sk = w.master.derive_priv(&w.secp, &path).unwrap().private_key;
        let pk = sk.public_key(&w.secp);
        let spk = &prevouts[i].script_pubkey;
        match spec.kind {
            Kind::Tr => {
                assert!(inp.partial_sigs.is_empty());
                let sig = inp.tap_key_sig.expect("taproot signature");
                assert_eq!(sig.sighash_type, TapSighashType::Default);
                let h = cache
                    .taproot_key_spend_signature_hash(
                        i,
                        &RefPrevouts::All(&prevouts),
                        TapSighashType::Default,
                    )
                    .unwrap();
                let msg = Message::from_digest(h.to_byte_array());
                let kp = bitcoin::key::Keypair::from_secret_key(&w.secp, &sk).tap_tweak(&w.secp, None);
                let q = kp.to_keypair().x_only_public_key().0;
                assert_eq!(spk.as_bytes()[2..], q.serialize());
                w.secp.verify_schnorr(&sig.signature, &msg, &q).unwrap();
                // aux_rand = 0: identical to libsecp256k1 without aux data
                assert_eq!(
                    sig.signature,
                    w.secp.sign_schnorr_no_aux_rand(&msg, &kp.to_keypair())
                );
                tx.input[i].witness = bitcoin::Witness::from_slice(&[sig.to_vec()]);
            }
            _ => {
                assert!(inp.tap_key_sig.is_none());
                assert_eq!(inp.partial_sigs.len(), 1);
                let (key, sig) = inp.partial_sigs.iter().next().unwrap();
                assert_eq!(key.inner, pk);
                assert_eq!(sig.sighash_type, EcdsaSighashType::All);
                let amount = prevouts[i].value;
                let h: [u8; 32] = match spec.kind {
                    Kind::Wpkh => cache
                        .p2wpkh_signature_hash(i, spk, amount, EcdsaSighashType::All)
                        .unwrap()
                        .to_byte_array(),
                    Kind::ShWpkh => {
                        let redeem = w.redeem(&spec.path);
                        cache
                            .p2wpkh_signature_hash(i, &redeem, amount, EcdsaSighashType::All)
                            .unwrap()
                            .to_byte_array()
                    }
                    _ => cache.legacy_signature_hash(i, spk, 1).unwrap().to_byte_array(),
                };
                let msg = Message::from_digest(h);
                w.secp.verify_ecdsa(&msg, &sig.signature, &pk).unwrap();
                // RFC 6979 + low R: identical to libsecp256k1 / Bitcoin Core
                assert_eq!(sig.signature, w.secp.sign_ecdsa_low_r(&msg, &sk));
                let pkb = pk.serialize().to_vec();
                match spec.kind {
                    Kind::Wpkh => tx.input[i].witness = bitcoin::Witness::from_slice(&[sig.to_vec(), pkb]),
                    Kind::ShWpkh => {
                        tx.input[i].witness = bitcoin::Witness::from_slice(&[sig.to_vec(), pkb]);
                        let redeem = w.redeem(&spec.path);
                        tx.input[i].script_sig = bitcoin::script::Builder::new()
                            .push_slice(<&bitcoin::script::PushBytes>::try_from(redeem.as_bytes()).unwrap())
                            .into_script();
                    }
                    _ => {
                        tx.input[i].script_sig = bitcoin::script::Builder::new()
                            .push_slice(
                                <&bitcoin::script::PushBytes>::try_from(sig.to_vec().as_slice()).unwrap(),
                            )
                            .push_slice(<&bitcoin::script::PushBytes>::try_from(pkb.as_slice()).unwrap())
                            .into_script();
                    }
                }
            }
        }
    }
    tx.vsize()
}

#[test]
fn four_script_types_sign_and_verify() {
    let w = Wallet::ours();
    let cases: Vec<Vec<In>> = vec![
        vec![In::new(Kind::Wpkh, 3, 100_000)],
        vec![In::new(Kind::ShWpkh, 3, 100_000)],
        vec![In::new(Kind::Pkh, 3, 100_000)],
        vec![In::new(Kind::Tr, 3, 100_000)],
        vec![In::new(Kind::Wpkh, 3, 60_000), In::new(Kind::Wpkh, 4, 40_000)],
        vec![
            In::new(Kind::Tr, 3, 60_000).without_prev_tx(),
            In::new(Kind::Tr, 9, 40_000).without_prev_tx(),
        ],
        vec![
            In::new(Kind::Wpkh, 1, 30_000),
            In::new(Kind::ShWpkh, 2, 30_000),
            In::new(Kind::Pkh, 3, 20_000),
            In::new(Kind::Tr, 4, 20_000),
        ],
    ];
    for specs in cases {
        let change = specs[0].kind;
        let p = build(
            &w,
            &specs,
            &[Out::pay(60_000), Out::change(&w, change, 2, 39_000)],
        );
        let raw = p.serialize();
        let mut mem = UtxoMemory::new();
        let signed = approve_and_sign(&raw, &mut mem, false).unwrap_or_else(|e| {
            panic!(
                "{specs:?}: {e:?}",
                specs = specs.iter().map(|s| s.kind).collect::<Vec<_>>()
            )
        });
        let vsize = check_with_rust_bitcoin(&w, &p, &specs, &signed);
        // the estimate shown on the fee screen is not below the real size
        // (ECDSA signatures may be a byte shorter than estimated)
        let m = master();
        let est = validate(&raw, &Context::new(&m, Network::Signet)).1.totals.vsize as usize;
        assert!(
            est >= vsize && est <= vsize + specs.len(),
            "estimate {est}, actual {vsize}"
        );
        // combining with the original works (it is the same transaction)
        let mut combined = p.clone();
        combined.combine(RefPsbt::deserialize(&signed).unwrap()).unwrap();
        // every signed outpoint is remembered with its amount
        for (txin, spec) in p.unsigned_tx.input.iter().zip(&specs) {
            let mut op = txin.previous_output.txid.to_byte_array().to_vec();
            op.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
            assert_eq!(mem.amount(&op), Some(spec.amount));
        }
    }
}

/// The full PSBT (for files) is the original with our signatures added:
/// rust-bitcoin sees exactly what combining the trimmed result gives, and
/// every original pair is kept byte for byte.
#[test]
fn full_psbt_is_the_original_plus_signatures() {
    let w = Wallet::ours();
    let m = master();
    let signer = Signer {
        master: &m,
        network: Network::Signet,
        policy: Policy::default(),
        multisig: &[],
    };
    for specs in [
        vec![In::new(Kind::Wpkh, 3, 100_000)],
        vec![
            In::new(Kind::Tr, 3, 60_000).without_prev_tx(),
            In::new(Kind::Pkh, 9, 40_000),
        ],
        vec![In::new(Kind::ShWpkh, 1, 50_000), In::new(Kind::Wpkh, 2, 50_000)],
    ] {
        let p = build(
            &w,
            &specs,
            &[Out::pay(60_000), Out::change(&w, specs[0].kind, 2, 39_000)],
        );
        let raw = p.serialize();
        let digest = validate(&raw, &Context::new(&m, Network::Signet)).1.digest();
        let mut out = vec![0u8; raw.len() + 4096];
        let s = sign_psbt_full(&raw, &signer, &mut UtxoMemory::new(), &digest, false, &mut out).unwrap();
        let full = &out[..s.len];
        assert_eq!(s.signatures, specs.len());
        let trimmed = approve_and_sign(&raw, &mut UtxoMemory::new(), false).unwrap();
        let mut combined = p.clone();
        combined.combine(RefPsbt::deserialize(&trimmed).unwrap()).unwrap();
        assert_eq!(RefPsbt::deserialize(full).unwrap(), combined);
        // original maps kept: global and outputs byte-identical, inputs grow
        let (a, b) = (Psbt::parse(&raw).unwrap(), Psbt::parse(full).unwrap());
        assert!(a.global_pairs().eq(b.global_pairs()));
        assert!(a.outputs().zip(b.outputs()).all(|(x, y)| x.pairs().eq(y.pairs())));
        for (x, y) in a.inputs().zip(b.inputs()) {
            assert_eq!(x.pairs().count() + 1, y.pairs().count());
            assert!(x.pairs().zip(y.pairs()).all(|(p, q)| p == q));
        }
        // signing the result again adds nothing (already signed)
        let d2 = validate(full, &Context::new(&m, Network::Signet)).1.digest();
        let mut again = vec![0u8; full.len() + 4096];
        assert_eq!(
            sign_psbt_full(full, &signer, &mut UtxoMemory::new(), &d2, false, &mut again).err(),
            Some(Error::NotSignable)
        );
        // too small a buffer: refused and wiped
        let mut small = vec![0xAAu8; raw.len()];
        assert_eq!(
            sign_psbt_full(&raw, &signer, &mut UtxoMemory::new(), &digest, false, &mut small).err(),
            Some(Error::OutputTooSmall)
        );
        assert!(small.iter().all(|&b| b == 0));
    }
}

#[test]
fn verdict_must_not_change_after_approval() {
    let w = Wallet::ours();
    let p = build(
        &w,
        &[In::new(Kind::Wpkh, 3, 100_000)],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 2, 39_000)],
    );
    let raw = p.serialize();
    let m = master();
    let digest = validate(&raw, &Context::new(&m, Network::Signet)).1.digest();
    let signer = |policy| Signer {
        master: &m,
        network: Network::Signet,
        policy,
        multisig: &[],
    };
    let mut out = vec![0u8; 8192];
    // another recipient amount after approval
    let mut q = p.clone();
    q.unsigned_tx.output[0].value = bitcoin::Amount::from_sat(60_500);
    q.unsigned_tx.output[1].value = bitcoin::Amount::from_sat(38_500);
    let e = sign_psbt(
        &q.serialize(),
        &signer(Policy::default()),
        &mut UtxoMemory::new(),
        &digest,
        false,
        &mut out,
    );
    assert_eq!(e, Err(Error::Changed));
    assert!(out.iter().all(|&b| b == 0), "output wiped");
    // a policy change between approval and signing
    let strict = Policy {
        fee_warn_percent: 1,
        ..Policy::default()
    };
    let e = sign_psbt(
        &raw,
        &signer(strict),
        &mut UtxoMemory::new(),
        &digest,
        false,
        &mut out,
    );
    assert_eq!(e, Err(Error::Changed));
    // the approved one signs
    assert!(sign_psbt(
        &raw,
        &signer(Policy::default()),
        &mut UtxoMemory::new(),
        &digest,
        false,
        &mut out
    )
    .is_ok());
}

#[test]
fn refused_reports_never_sign() {
    let w = Wallet::ours();
    // an attack, even with its own digest and the override
    let mut p = build(
        &w,
        &[In::new(Kind::Wpkh, 3, 100_000)],
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 2, 39_000)],
    );
    let other = Wallet::new(&[5; 32]);
    p.unsigned_tx.output[1].script_pubkey = other.spk(Kind::Wpkh, &Kind::Wpkh.path(1, 2));
    assert_eq!(
        approve_and_sign(&p.serialize(), &mut UtxoMemory::new(), true),
        Err(Error::NotSignable)
    );
    // blocking warning: only with the explicit override
    let ins = [
        In::new(Kind::Wpkh, 1, 50_000).without_prev_tx(),
        In::new(Kind::Wpkh, 2, 20_000),
    ];
    let p = build(
        &w,
        &ins,
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 1, 9_000)],
    );
    assert_eq!(
        approve_and_sign(&p.serialize(), &mut UtxoMemory::new(), false),
        Err(Error::NotSignable)
    );
    assert!(approve_and_sign(&p.serialize(), &mut UtxoMemory::new(), true).is_ok());
    // not a PSBT at all
    assert_eq!(
        approve_and_sign(b"psbt\xff", &mut UtxoMemory::new(), true),
        Err(Error::NotSignable)
    );
}

#[test]
fn partly_signed_and_memory() {
    let w = Wallet::ours();
    let specs = [In::new(Kind::Wpkh, 3, 60_000), In::new(Kind::Wpkh, 4, 40_000)];
    let p = build(
        &w,
        &specs,
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 2, 39_000)],
    );
    let mut mem = UtxoMemory::new();
    let signed = approve_and_sign(&p.serialize(), &mut mem, false).unwrap();
    // a PSBT where input 0 already carries our signature: only input 1 is signed
    let mut half = p.clone();
    let theirs = RefPsbt::deserialize(&signed).unwrap();
    half.inputs[0].partial_sigs = theirs.inputs[0].partial_sigs.clone();
    let again = approve_and_sign(&half.serialize(), &mut mem, false).unwrap();
    let r = Psbt::parse(&again).unwrap();
    let counts: Vec<usize> = r.inputs().map(|m| m.partial_sigs().count()).collect();
    assert_eq!(counts, [0, 1]);
    // the same UTXO with another amount is now an attack
    let mut specs2 = specs.clone();
    specs2[0].amount = 60_001;
    let mut q = build(
        &w,
        &specs2,
        &[Out::pay(60_000), Out::change(&w, Kind::Wpkh, 2, 39_001)],
    );
    // keep the original outpoint: a host lying about its amount
    q.unsigned_tx.input[0] = p.unsigned_tx.input[0].clone();
    q.inputs[0].non_witness_utxo = None;
    let m = master();
    let mut ctx = Context::new(&m, Network::Signet);
    ctx.memory = Some(&mem);
    let rep = validate(&q.serialize(), &ctx).1;
    assert!(rep.has(Issue::UtxoAmountChanged(0)), "{:?}", rep.issues());
}

#[test]
fn small_output_buffer_is_wiped() {
    let w = Wallet::ours();
    let p = build(
        &w,
        &[In::new(Kind::Tr, 3, 100_000)],
        &[Out::pay(60_000), Out::change(&w, Kind::Tr, 2, 39_000)],
    );
    let raw = p.serialize();
    let m = master();
    let digest = validate(&raw, &Context::new(&m, Network::Signet)).1.digest();
    let signer = Signer {
        master: &m,
        network: Network::Signet,
        policy: Policy::default(),
        multisig: &[],
    };
    let mut out = vec![0u8; 100];
    let mut mem = UtxoMemory::new();
    assert_eq!(
        sign_psbt(&raw, &signer, &mut mem, &digest, false, &mut out),
        Err(Error::OutputTooSmall)
    );
    assert!(out.iter().all(|&b| b == 0));
    // nothing was remembered either
    let txin = &p.unsigned_tx.input[0];
    let mut op = txin.previous_output.txid.to_byte_array().to_vec();
    op.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
    assert_eq!(mem.amount(&op), None);
}

// ---- reference signer vectors, reproduced with our hashes and ECDSA

fn wif(s: &str) -> SecretKey {
    let mut b = [0u8; 64];
    let n = base58::decode_check(s, &mut b).unwrap();
    assert!(n == 34 && b[33] == 1, "compressed WIF");
    SecretKey::from_bytes(b[1..33].try_into().unwrap()).unwrap()
}

/// Our signature for input `i` of `p` with `sk`, as a PSBT partial
/// signature value (ECDSA inputs only), with or without low-R grinding.
fn our_sig(p: &Psbt, i: usize, sk: &SecretKey, grind: bool) -> Option<Vec<u8>> {
    let m = p.input(i)?;
    let txin = p.tx.input(i)?;
    let prev = m
        .witness_utxo()
        .or_else(|| m.non_witness_utxo()?.output(txin.vout as usize))?;
    let pk = sk.public_key();
    let ht = m.sighash_type().unwrap_or(1);
    let v0 = SegwitV0Hashes::new(&p.tx);
    let digest = if let Some(ws) = m.witness_script() {
        sighash::segwit_v0(&p.tx, &v0, i, ws, prev.value, ht)?
    } else if let Some(redeem) = m.redeem_script() {
        match classify(redeem) {
            ScriptKind::P2wpkh(_) => sighash::segwit_v0(&p.tx, &v0, i, &p2pkh(&pk), prev.value, ht)?,
            _ => sighash::legacy(&p.tx, i, redeem, ht),
        }
    } else {
        match classify(prev.script_pubkey) {
            ScriptKind::P2wpkh(_) => sighash::segwit_v0(&p.tx, &v0, i, &p2pkh(&pk), prev.value, ht)?,
            ScriptKind::P2tr(_) => return None,
            _ => sighash::legacy(&p.tx, i, prev.script_pubkey, ht),
        }
    };
    let s = if grind {
        ecdsa::sign(sk, &digest)
    } else {
        ecdsa::sign_no_grind(sk, &digest)?
    };
    let mut der = [0u8; ecdsa::MAX_DER_LEN];
    let n = s.to_der(&mut der);
    let mut v = der[..n].to_vec();
    v.push(ht as u8);
    Some(v)
}

/// Every partial signature in `result` made by one of `keys` is the one we
/// produce for the same input of `input`: identical with low-R grinding,
/// or (for signatures made before Bitcoin Core ground R, high R) identical
/// to plain RFC 6979.
fn reproduce(input: &[u8], result: &[u8], keys: &[SecretKey]) -> usize {
    let p = Psbt::parse(input).unwrap();
    let r = Psbt::parse(result).unwrap();
    let mut compared = 0;
    for (i, m) in r.inputs().enumerate() {
        for (pk, sig) in m.partial_sigs() {
            let Some(sk) = keys.iter().find(|k| k.public_key().serialize()[..] == *pk) else {
                continue;
            };
            // signatures already in the input are kept as they were, not
            // made again (Core, and our signer, skip signed keys)
            if p.input(i).unwrap().partial_sigs().any(|(k, _)| k == pk) {
                continue;
            }
            let low_r = sig[3] == 0x20 && sig[4] < 0x80;
            assert_eq!(our_sig(&p, i, sk, low_r).as_deref(), Some(sig), "input {i}");
            compared += 1;
        }
    }
    compared
}

fn b64(s: &str) -> Vec<u8> {
    let mut out = vec![0u8; s.len()];
    let n = base64::decode(s.as_bytes(), &mut out).unwrap();
    out.truncate(n);
    out
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn bip174_signer_vectors() {
    let input = unhex(bip174::SIGHASH_ALL_ADDED);
    let k1: Vec<SecretKey> = bip174::SIGNER_1_KEYS.iter().map(|(w, _)| wif(w)).collect();
    let k2: Vec<SecretKey> = bip174::SIGNER_2_KEYS.iter().map(|(w, _)| wif(w)).collect();
    assert_eq!(reproduce(&input, &unhex(bip174::SIGNED_1), &k1), 2);
    assert_eq!(reproduce(&input, &unhex(bip174::SIGNED_2), &k2), 2);
    // the keys are the ones the tprv derives at the stated paths
    let (m, _, _) = Xpriv::decode(bip174::MASTER_TPRV).unwrap();
    for ((_, path), k) in bip174::SIGNER_1_KEYS.iter().zip(&k1) {
        let p = bp_bitcoin::bip32::DerivationPath::parse(path).unwrap();
        assert_eq!(m.derive_path(&p).unwrap().secret_key().to_bytes(), k.to_bytes());
    }
}

#[test]
fn core_signer_vectors() {
    let mut compared = 0;
    for (keys, input, result) in core_psbt::SIGNER {
        let keys: Vec<SecretKey> = keys.iter().map(|k| wif(k)).collect();
        compared += reproduce(&b64(input), &b64(result), &keys);
    }
    assert!(compared >= 4, "compared {compared}");
    let _ = RefSecretKey::from_slice(&[1; 32]);
}

/// Mutated PSBTs: signing either refuses or returns a trimmed PSBT for the
/// very same transaction whose every signature verifies; never a panic.
#[test]
fn signing_mutated_psbts() {
    let w = Wallet::ours();
    let seeds: Vec<Vec<u8>> = [Kind::Wpkh, Kind::ShWpkh, Kind::Pkh, Kind::Tr]
        .iter()
        .map(|&k| {
            build(
                &w,
                &[In::new(k, 3, 100_000)],
                &[Out::pay(60_000), Out::change(&w, k, 2, 39_000)],
            )
            .serialize()
        })
        .collect();
    let m = master();
    let signer = Signer {
        master: &m,
        network: Network::Signet,
        policy: Policy::default(),
        multisig: &[],
    };
    let mut x = 0x0dd5_eed5_u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let (mut signed, mut refused) = (0, 0);
    for i in 0..400 {
        let mut d = seeds[i % seeds.len()].clone();
        for _ in 0..1 + next() % 2 {
            let j = (next() as usize) % d.len();
            d[j] ^= 1 << (next() % 8);
        }
        let mut mem = UtxoMemory::new();
        let digest = validate(&d, &Context::new(&m, Network::Signet)).1.digest();
        let mut out = vec![0u8; 8192];
        match sign_psbt(&d, &signer, &mut mem, &digest, true, &mut out) {
            Ok(s) => {
                signed += 1;
                let orig = RefPsbt::deserialize(&d).unwrap();
                let r = RefPsbt::deserialize(&out[..s.len]).unwrap();
                assert_eq!(r.unsigned_tx, orig.unsigned_tx);
                assert_eq!(s.signatures, 1);
            }
            Err(_) => {
                refused += 1;
                assert!(out.iter().all(|&b| b == 0));
            }
        }
    }
    assert!(signed > 10 && refused > 100, "signed {signed}, refused {refused}");
}
