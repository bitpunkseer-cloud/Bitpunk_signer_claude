//! Test PSBTs built with rust-bitcoin (test-only reference): keys are
//! derived independently of our BIP-32 code, so a validator that accepts
//! these is checked against another implementation.
#![allow(dead_code)]

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::{CompressedPublicKey, Secp256k1};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, PublicKey, XOnlyPublicKey};
use bitcoin::{
    absolute, transaction, Amount, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use std::str::FromStr;

pub const SEED: [u8; 32] = [0x42; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Wpkh,
    ShWpkh,
    Pkh,
    Tr,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Wpkh, Kind::ShWpkh, Kind::Pkh, Kind::Tr];

    pub fn purpose(self) -> u32 {
        match self {
            Kind::Wpkh => 84,
            Kind::ShWpkh => 49,
            Kind::Pkh => 44,
            Kind::Tr => 86,
        }
    }

    /// m/purpose'/1'/0'/change/index (test networks)
    pub fn path(self, change: u32, index: u32) -> String {
        format!("m/{}'/1'/0'/{change}/{index}", self.purpose())
    }
}

pub struct Wallet {
    pub secp: Secp256k1<All>,
    pub master: Xpriv,
    pub fp: Fingerprint,
}

impl Wallet {
    pub fn new(seed: &[u8]) -> Self {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(NetworkKind::Test, seed).unwrap();
        let fp = master.fingerprint(&secp);
        Wallet { secp, master, fp }
    }

    pub fn ours() -> Self {
        Self::new(&SEED)
    }

    pub fn key(&self, path: &str) -> (PublicKey, DerivationPath) {
        let p = DerivationPath::from_str(path).unwrap();
        let k = self.master.derive_priv(&self.secp, &p).unwrap();
        (k.private_key.public_key(&self.secp), p)
    }

    pub fn xonly(&self, path: &str) -> XOnlyPublicKey {
        self.key(path).0.x_only_public_key().0
    }

    pub fn redeem(&self, path: &str) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&CompressedPublicKey(self.key(path).0).wpubkey_hash())
    }

    pub fn spk(&self, kind: Kind, path: &str) -> ScriptBuf {
        let pk = CompressedPublicKey(self.key(path).0);
        match kind {
            Kind::Wpkh => ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()),
            Kind::ShWpkh => ScriptBuf::new_p2sh(&self.redeem(path).script_hash()),
            Kind::Pkh => ScriptBuf::new_p2pkh(&pk.pubkey_hash()),
            Kind::Tr => ScriptBuf::new_p2tr(&self.secp, self.xonly(path), None),
        }
    }

    /// Add this wallet's derivation claims for `path` to an input.
    pub fn claim_input(&self, inp: &mut bitcoin::psbt::Input, kind: Kind, path: &str) {
        let (pk, p) = self.key(path);
        match kind {
            Kind::Tr => {
                let x = pk.x_only_public_key().0;
                inp.tap_internal_key = Some(x);
                inp.tap_key_origins.insert(x, (vec![], (self.fp, p)));
            }
            _ => {
                inp.bip32_derivation.insert(pk, (self.fp, p));
            }
        }
        if kind == Kind::ShWpkh {
            inp.redeem_script = Some(self.redeem(path));
        }
    }

    pub fn claim_output(&self, out: &mut bitcoin::psbt::Output, kind: Kind, path: &str) {
        let (pk, p) = self.key(path);
        match kind {
            Kind::Tr => {
                let x = pk.x_only_public_key().0;
                out.tap_internal_key = Some(x);
                out.tap_key_origins.insert(x, (vec![], (self.fp, p)));
            }
            _ => {
                out.bip32_derivation.insert(pk, (self.fp, p));
            }
        }
        if kind == Kind::ShWpkh {
            out.redeem_script = Some(self.redeem(path));
        }
    }
}

#[derive(Clone)]
pub struct In {
    pub kind: Kind,
    pub path: String,
    pub amount: u64,
    /// Include the previous transaction.
    pub prev_tx: bool,
    /// Include the witness UTXO (segwit kinds).
    pub witness_utxo: bool,
}

impl In {
    pub fn new(kind: Kind, index: u32, amount: u64) -> Self {
        In {
            kind,
            path: kind.path(0, index),
            amount,
            prev_tx: true,
            witness_utxo: kind != Kind::Pkh,
        }
    }

    pub fn without_prev_tx(mut self) -> Self {
        self.prev_tx = false;
        self
    }
}

#[derive(Clone)]
pub struct Out {
    pub script: ScriptBuf,
    pub amount: u64,
    /// This wallet's change (kind, path) to claim.
    pub change: Option<(Kind, String)>,
}

impl Out {
    pub fn pay(amount: u64) -> Self {
        // someone else's P2WPKH
        let other = Wallet::new(&[7; 32]);
        Out {
            script: other.spk(Kind::Wpkh, &Kind::Wpkh.path(0, 9)),
            amount,
            change: None,
        }
    }

    pub fn change(w: &Wallet, kind: Kind, index: u32, amount: u64) -> Self {
        let path = kind.path(1, index);
        Out {
            script: w.spk(kind, &path),
            amount,
            change: Some((kind, path)),
        }
    }
}

/// A previous transaction paying `amount` to `script` at output 1.
pub fn prev_tx(script: ScriptBuf, amount: u64, salt: u8) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([salt; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1000 + salt as u64),
                script_pubkey: Wallet::new(&[9; 32]).spk(Kind::Wpkh, "m/0"),
            },
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: script,
            },
        ],
    }
}

pub fn build(w: &Wallet, ins: &[In], outs: &[Out]) -> Psbt {
    let prevs: Vec<Transaction> = ins
        .iter()
        .enumerate()
        .map(|(i, s)| prev_tx(w.spk(s.kind, &s.path), s.amount, i as u8))
        .collect();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: prevs
            .iter()
            .map(|p| TxIn {
                previous_output: OutPoint {
                    txid: p.compute_txid(),
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outs
            .iter()
            .map(|o| TxOut {
                value: Amount::from_sat(o.amount),
                script_pubkey: o.script.clone(),
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    for ((inp, spec), prev) in psbt.inputs.iter_mut().zip(ins).zip(&prevs) {
        if spec.prev_tx {
            inp.non_witness_utxo = Some(prev.clone());
        }
        if spec.witness_utxo {
            inp.witness_utxo = Some(prev.output[1].clone());
        }
        w.claim_input(inp, spec.kind, &spec.path);
    }
    for (out, spec) in psbt.outputs.iter_mut().zip(outs) {
        if let Some((kind, path)) = &spec.change {
            w.claim_output(out, *kind, path);
        }
    }
    psbt
}
