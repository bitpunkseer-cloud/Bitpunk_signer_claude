//! Single-key mode (an imported WIF): inputs and change are recognised by
//! the key's own scripts, signatures are checked with rust-bitcoin's
//! independent signature hashes, and other keys' inputs are not taken.

use bitcoin::hashes::Hash;
use bitcoin::key::{CompressedPublicKey, Secp256k1, TapTweak};
use bitcoin::psbt::Psbt as RefPsbt;
use bitcoin::secp256k1::{Message, SecretKey as RefSk};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bp_bitcoin::bip32::Xpriv;
use bp_bitcoin::sign::{sign_psbt, Signer};
use bp_bitcoin::validate::{validate, Context, Issue, OutputKind, Policy, UtxoMemory};
use bp_bitcoin::wif::{self, WifError};
use bp_bitcoin::Network;

const KEY: [u8; 32] = [0x42; 32];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Wpkh,
    ShWpkh,
    Pkh,
    Tr,
}

fn spk(kind: Kind, sk: &RefSk) -> ScriptBuf {
    let secp = Secp256k1::new();
    let pk = CompressedPublicKey(sk.public_key(&secp));
    match kind {
        Kind::Wpkh => ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()),
        Kind::ShWpkh => ScriptBuf::new_p2sh(&ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()).script_hash()),
        Kind::Pkh => ScriptBuf::new_p2pkh(&bitcoin::PublicKey::new(pk.0).pubkey_hash()),
        Kind::Tr => ScriptBuf::new_p2tr(&secp, pk.0.x_only_public_key().0, None),
    }
}

/// A PSBT spending one output of `kind` owned by `owner`, paying 60k out
/// and the rest (minus fee) back to `change` (if any).
fn build(kind: Kind, owner: &RefSk, change: Option<Kind>, with_redeem: bool) -> (RefPsbt, TxOut) {
    let secp = Secp256k1::new();
    let prev_out = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: spk(kind, owner),
    };
    let prev = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![prev_out.clone()],
    };
    let other = RefSk::from_slice(&[9; 32]).unwrap();
    let mut outs = vec![TxOut {
        value: Amount::from_sat(60_000),
        script_pubkey: spk(Kind::Wpkh, &other),
    }];
    if let Some(c) = change {
        outs.push(TxOut {
            value: Amount::from_sat(39_000),
            script_pubkey: spk(c, owner),
        });
    }
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outs,
    };
    let mut p = RefPsbt::from_unsigned_tx(tx).unwrap();
    p.inputs[0].non_witness_utxo = Some(prev);
    if kind != Kind::Pkh {
        p.inputs[0].witness_utxo = Some(prev_out.clone());
    }
    let pk = CompressedPublicKey(owner.public_key(&secp));
    if kind == Kind::ShWpkh && with_redeem {
        p.inputs[0].redeem_script = Some(ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()));
    }
    if kind == Kind::Tr {
        p.inputs[0].tap_internal_key = Some(pk.0.x_only_public_key().0);
    }
    (p, prev_out)
}

fn master() -> Xpriv {
    Xpriv::from_parts(&[0; 32], &KEY).unwrap()
}

fn ctx(m: &Xpriv) -> Context<'_> {
    let mut c = Context::new(m, Network::Mainnet);
    c.single_key = true;
    c
}

#[test]
fn every_script_type_signs_and_verifies() {
    let secp = Secp256k1::new();
    let sk = RefSk::from_slice(&KEY).unwrap();
    let pk = sk.public_key(&secp);
    let m = master();
    for kind in [Kind::Wpkh, Kind::ShWpkh, Kind::Pkh, Kind::Tr] {
        let (p, prev) = build(kind, &sk, Some(kind), true);
        let raw = p.serialize();
        let (_, report) = validate(&raw, &ctx(&m));
        assert!(
            !report.has(Issue::NoInputsForSeed),
            "{kind:?}: {:?}",
            report.issues()
        );
        assert!(report.can_sign(false), "{kind:?}: {:?}", report.issues());
        assert!(
            matches!(report.outputs()[1].kind, OutputKind::Change(_)),
            "{kind:?} change"
        );
        assert!(matches!(report.outputs()[0].kind, OutputKind::External));
        let signer = Signer {
            master: &m,
            network: Network::Mainnet,
            policy: Policy::default(),
            multisig: &[],
            single_key: true,
        };
        let mut out = vec![0u8; 8192];
        let s = sign_psbt(
            &raw,
            &signer,
            &mut UtxoMemory::new(),
            &report.digest(),
            false,
            &mut out,
        )
        .unwrap();
        let signed = RefPsbt::deserialize(&out[..s.len]).unwrap();
        let mut cache = SighashCache::new(&p.unsigned_tx);
        let wpkh = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash());
        match kind {
            Kind::Tr => {
                let sig = signed.inputs[0].tap_key_sig.unwrap();
                let h = cache
                    .taproot_key_spend_signature_hash(
                        0,
                        &Prevouts::All(std::slice::from_ref(&prev)),
                        TapSighashType::Default,
                    )
                    .unwrap();
                let kp = bitcoin::key::Keypair::from_secret_key(&secp, &sk).tap_tweak(&secp, None);
                secp.verify_schnorr(
                    &sig.signature,
                    &Message::from_digest(h.to_byte_array()),
                    &kp.to_keypair().x_only_public_key().0,
                )
                .unwrap();
            }
            _ => {
                let (key, sig) = signed.inputs[0].partial_sigs.iter().next().unwrap();
                assert_eq!(key.inner, pk);
                let h: [u8; 32] = match kind {
                    Kind::Pkh => cache
                        .legacy_signature_hash(0, &prev.script_pubkey, 1)
                        .unwrap()
                        .to_byte_array(),
                    _ => cache
                        .p2wpkh_signature_hash(0, &wpkh, prev.value, EcdsaSighashType::All)
                        .unwrap()
                        .to_byte_array(),
                };
                secp.verify_ecdsa(&Message::from_digest(h), &sig.signature, &pk)
                    .unwrap();
            }
        }
    }
}

#[test]
fn other_keys_and_missing_scripts() {
    let m = master();
    let other = RefSk::from_slice(&[7; 32]).unwrap();
    let (p, _) = build(Kind::Wpkh, &other, None, true);
    let (_, report) = validate(&p.serialize(), &ctx(&m));
    assert!(report.has(Issue::NoInputsForSeed));
    // a wrapped segwit input needs its redeem script
    let sk = RefSk::from_slice(&KEY).unwrap();
    let (p, _) = build(Kind::ShWpkh, &sk, None, false);
    let (_, report) = validate(&p.serialize(), &ctx(&m));
    assert!(report.has(Issue::MissingRedeemScript(0)));
    // a normal (HD) context does not take the single key's input
    let (p, _) = build(Kind::Wpkh, &sk, None, true);
    let (_, report) = validate(&p.serialize(), &Context::new(&m, Network::Mainnet));
    assert!(report.has(Issue::NoInputsForSeed));
}

#[test]
fn wif_decoding() {
    // Bitcoin Core / BIP-85 vector: compressed mainnet WIF
    let sk = wif::decode(
        "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp",
        Network::Mainnet,
    )
    .unwrap();
    let mut out = [0u8; wif::WIF_LEN];
    let n = wif::encode(&sk, Network::Mainnet, &mut out);
    assert_eq!(&out[..n], b"Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp");
    assert_eq!(
        wif::decode(
            "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp",
            Network::Signet
        )
        .err(),
        Some(WifError::Network)
    );
    // the same key, uncompressed form (5...)
    let k = bitcoin::PrivateKey {
        compressed: false,
        network: bitcoin::NetworkKind::Main,
        inner: RefSk::from_slice(&KEY).unwrap(),
    };
    assert_eq!(
        wif::decode(&k.to_wif(), Network::Mainnet).err(),
        Some(WifError::Uncompressed)
    );
    let t = bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Test,
        inner: RefSk::from_slice(&KEY).unwrap(),
    };
    assert_eq!(
        wif::decode(&t.to_wif(), Network::Testnet).unwrap().to_bytes(),
        KEY
    );
    for bad in [
        "",
        "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhq",
        "xprv9s21ZrQH143K",
    ] {
        assert_eq!(
            wif::decode(bad, Network::Mainnet).err(),
            Some(WifError::Invalid),
            "{bad}"
        );
    }
}
