//! BIP-322 against the official test vectors (message hashes, to_spend and
//! to_sign txids, simple signatures, error cases, Proof of Funds PSBTs) and
//! against PSBTs built with rust-bitcoin the way Sparrow builds them.

#[path = "data/bip322_vectors.rs"]
mod vectors;

use bitcoin::psbt::{raw::Key, Psbt as RefPsbt};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bp_bitcoin::addrcheck::Target;
use bp_bitcoin::bip322::{
    classify_psbt, message_hash, sign_simple_taproot, simple_text, to_sign, to_spend, to_spend_txid,
    verify_simple, Forgery, PsbtKind, TO_SPEND_MAX,
};
use bp_bitcoin::psbt::Psbt;
use bp_bitcoin::tx::Tx;
use bp_bitcoin::{base64, Network};
use bp_crypto::secp256k1::SecretKey;
use vectors::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rev(mut b: [u8; 32]) -> [u8; 32] {
    b.reverse();
    b
}

fn challenge(addr: &str) -> Vec<u8> {
    Target::parse(addr, Network::Mainnet).unwrap().script().to_vec()
}

#[test]
fn message_hashes_and_virtual_transactions() {
    for (msg, addr, mh, spend, sign) in TX_HASHES {
        assert_eq!(hex(&message_hash(msg.as_bytes())), *mh, "{msg}");
        let c = challenge(addr);
        let txid = to_spend_txid(&c, msg.as_bytes()).unwrap();
        assert_eq!(hex(&rev(txid)), *spend, "to_spend {msg}");
        let raw = to_sign(&txid);
        assert_eq!(hex(&rev(Tx::parse(&raw).unwrap().txid())), *sign, "to_sign {msg}");
    }
}

#[test]
fn simple_signature_vectors_verify() {
    let mut checked = 0;
    for (msg, _keys, addr, kind, sigs) in SIMPLE {
        for sig in *sigs {
            let r = verify_simple(addr, Network::Mainnet, msg.as_bytes(), sig);
            match *kind {
                "p2wpkh" | "p2tr" => {
                    assert!(r.is_ok(), "{kind} {msg:?} {sig}: {r:?}");
                    checked += 1;
                }
                // P2WSH multisig arrives with descriptor wallets (M7)
                _ => assert!(r.is_err(), "{kind}"),
            }
        }
    }
    assert!(checked >= 7, "{checked}");
}

#[test]
fn error_vectors_are_rejected() {
    for (desc, msg, addr, sig) in ERRORS {
        assert!(
            verify_simple(addr, Network::Mainnet, msg.as_bytes(), sig).is_err(),
            "{desc}"
        );
    }
    // full signatures are never taken for simple ones
    for (msg, addr, _, sigs) in FULL {
        assert!(verify_simple(addr, Network::Mainnet, msg.as_bytes(), sigs[0]).is_err());
    }
}

#[test]
fn taproot_signing_round_trips() {
    for (msg, keys, addr, kind, sigs) in SIMPLE {
        if *kind != "p2tr" || sigs.is_empty() {
            continue;
        }
        let k = bitcoin::PrivateKey::from_wif(keys[0]).unwrap();
        let sk = SecretKey::from_bytes(&k.inner.secret_bytes()).unwrap();
        let w = sign_simple_taproot(&sk, msg.as_bytes()).unwrap();
        let mut text = [0u8; 100];
        let n = simple_text(&w, &mut text).unwrap();
        let ours = std::str::from_utf8(&text[..n]).unwrap();
        assert!(ours.starts_with("smp"));
        assert_eq!(
            verify_simple(addr, Network::Mainnet, msg.as_bytes(), ours),
            Ok(bp_bitcoin::address::ScriptType::Taproot)
        );
        // the vector used random auxiliary data, so the bytes differ from
        // ours (zero auxiliary data); both verify
        assert_ne!(ours, sigs[0]);
        assert!(verify_simple(addr, Network::Mainnet, b"another message", ours).is_err());
    }
}

/// A BIP-322 PSBT as Sparrow makes it: to_sign with the to_spend output as
/// witness UTXO, the message in global field 0x09.
fn message_psbt(addr: &str, msg: &str) -> RefPsbt {
    let c = challenge(addr);
    let txid = to_spend_txid(&c, msg.as_bytes()).unwrap();
    let tx = Transaction {
        version: transaction::Version(0),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(txid),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6A]),
        }],
    };
    let mut p = RefPsbt::from_unsigned_tx(tx).unwrap();
    p.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(c),
    });
    p.unknown.insert(
        Key {
            type_value: 0x09,
            key: vec![],
        },
        msg.as_bytes().to_vec(),
    );
    p
}

use bitcoin::hashes::Hash;

fn kind(p: &RefPsbt) -> PsbtKind<'static> {
    let raw: &'static [u8] = Box::leak(p.serialize().into_boxed_slice());
    classify_psbt(&Psbt::parse(raw).unwrap())
}

#[test]
fn message_psbts_are_recognised_and_forgeries_refused() {
    let addr = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
    let p = message_psbt(addr, "Hello World");
    assert!(matches!(
        kind(&p),
        PsbtKind::Message {
            message: b"Hello World",
            proof_of_reserves: false,
            ..
        }
    ));
    // the same with to_spend as the previous transaction
    let mut q = p.clone();
    let c = challenge(addr);
    let mut raw = [0u8; TO_SPEND_MAX];
    let n = to_spend(&c, b"Hello World", &mut raw).unwrap();
    let ts: Transaction = bitcoin::consensus::deserialize(&raw[..n]).unwrap();
    q.inputs[0].non_witness_utxo = Some(ts.clone());
    assert!(matches!(kind(&q), PsbtKind::Message { .. }));
    q.inputs[0].witness_utxo = None;
    assert!(matches!(kind(&q), PsbtKind::Message { .. }));
    // another message in field 0x09 than the one to_spend commits to
    let mut f = p.clone();
    f.unknown.insert(
        Key {
            type_value: 0x09,
            key: vec![],
        },
        b"Send me your coins".to_vec(),
    );
    assert_eq!(kind(&f), PsbtKind::Forged(Forgery::ToSpendMismatch));
    // a non-zero amount
    let mut f = p.clone();
    f.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(1000);
    assert_eq!(kind(&f), PsbtKind::Forged(Forgery::NonZeroAmount));
    // output 1 of to_spend
    let mut f = p.clone();
    f.unsigned_tx.input[0].previous_output.vout = 1;
    assert_eq!(kind(&f), PsbtKind::Forged(Forgery::PrevoutIndex));
    // version 1
    let mut f = p.clone();
    f.unsigned_tx.version = transaction::Version(1);
    assert_eq!(kind(&f), PsbtKind::Forged(Forgery::Version));
    // a previous transaction that is not to_spend (but has its txid claim)
    let mut f = p.clone();
    let mut other = ts.clone();
    other.lock_time = absolute::LockTime::from_consensus(1);
    f.inputs[0].non_witness_utxo = Some(other.clone());
    f.unsigned_tx.input[0].previous_output.txid = other.compute_txid();
    assert_eq!(kind(&f), PsbtKind::Forged(Forgery::ToSpendMismatch));
    // no previous output at all
    let mut f = p.clone();
    f.inputs[0].witness_utxo = None;
    assert_eq!(kind(&f), PsbtKind::Forged(Forgery::NoChallenge));
    // a real payment carrying a message field is reviewed as a payment
    let mut t = p.clone();
    t.unsigned_tx.output[0] = TxOut {
        value: Amount::from_sat(5000),
        script_pubkey: ScriptBuf::from_bytes(challenge(addr)),
    };
    t.outputs[0] = Default::default();
    assert_eq!(kind(&t), PsbtKind::Transaction);
    // no field 0x09: an ordinary transaction
    let mut t = p.clone();
    t.unknown.clear();
    assert_eq!(kind(&t), PsbtKind::Transaction);
    // more inputs: Proof of Reserves
    let mut r = p.clone();
    r.unsigned_tx.input.push(TxIn {
        previous_output: OutPoint {
            txid: bitcoin::Txid::from_byte_array([9; 32]),
            vout: 3,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ZERO,
        witness: Witness::new(),
    });
    r.inputs.push(Default::default());
    assert!(matches!(
        kind(&r),
        PsbtKind::Message {
            proof_of_reserves: true,
            ..
        }
    ));
}

#[test]
fn proof_of_funds_vectors_are_messages() {
    for (msg, _addr, kind_s, sigs) in PROOF_OF_FUNDS {
        let b64 = sigs[0].strip_prefix("pof").unwrap();
        let mut raw = vec![0u8; b64.len()];
        let n = base64::decode(b64.as_bytes(), &mut raw).unwrap();
        raw.truncate(n);
        // finalized: the finalizer dropped field 0x09, so it is no request
        assert_eq!(
            classify_psbt(&Psbt::parse(&raw).unwrap()),
            PsbtKind::Transaction,
            "{kind_s}"
        );
        // with the message field (as the signer received it): Proof of Reserves
        let mut with = raw[..5].to_vec();
        with.extend_from_slice(&[1, 0x09, msg.len() as u8]);
        with.extend_from_slice(msg.as_bytes());
        with.extend_from_slice(&raw[5..]);
        match classify_psbt(&Psbt::parse(&with).unwrap()) {
            PsbtKind::Message {
                message,
                proof_of_reserves,
                ..
            } => {
                assert_eq!(message, msg.as_bytes(), "{kind_s}");
                assert!(proof_of_reserves, "{kind_s}");
            }
            k => panic!("{kind_s}: {k:?}"),
        }
    }
}
