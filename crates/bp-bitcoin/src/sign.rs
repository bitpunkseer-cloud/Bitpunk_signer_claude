//! Signing (M5 plan §5). Called only after the user approved the review
//! screens for a report whose digest the caller kept.
//!
//! 1. Validate again and refuse unless the verdict is exactly the
//!    approved one (Coldcard, Trezor).
//! 2. For each input of this seed: derive the private key at the verified
//!    path and check that it gives the verified public key.
//! 3. Signature hash: BIP-143 (P2WPKH, P2SH-P2WPKH), legacy (P2PKH) or
//!    BIP-341 (Taproot key path; all amounts and scripts committed).
//! 4. Sign: ECDSA with RFC 6979, low S and low R; Schnorr with the BIP-341
//!    tweak and aux_rand = 0 (decision 4).
//! 5. Verify every signature against the key the UTXO commits to; any
//!    failure discards the whole result (faults, bugs).
//! 6. Private keys are wiped when they go out of scope.
//! 7. Output: a trimmed PSBT with the unsigned transaction and the new
//!    signatures only (decision 3), parsed again to check that every
//!    signature is there.
//! 8. The amounts of the signed UTXOs are remembered until power-off.

use crate::bip32::Xpriv;
use crate::psbt::{write, Psbt};
use crate::sighash::{self, Prevouts, SegwitV0Hashes, TaprootHashes};
use crate::tx::{Buf, TxOut};
use crate::validate::script;
use crate::validate::{validate, Context, Policy, SpendKind, UtxoMemory};
use crate::Network;
use bp_crypto::secp256k1::{ecdsa, schnorr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The verdict is not the approved one (the PSBT or the policy changed).
    Changed,
    /// The report does not allow signing.
    NotSignable,
    /// A key derived at a verified path does not give the verified key.
    Derive,
    /// A signature hash could not be computed.
    Sighash,
    /// A signature failed verification: nothing is returned.
    Verify,
    /// The output buffer is too small.
    OutputTooSmall,
    /// The result does not contain exactly the expected signatures.
    Output,
}

/// What the signer needs besides the PSBT.
pub struct Signer<'a> {
    pub master: &'a Xpriv,
    pub network: Network,
    pub policy: Policy,
}

/// Summary of a successful signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signed {
    /// Length of the trimmed PSBT in the output buffer.
    pub len: usize,
    pub signatures: usize,
}

/// Previous outputs read from the PSBT (validated: the non-witness UTXO
/// hashes to the outpoint, and the witness UTXO agrees with it).
struct PsbtPrevouts<'a, 'p>(&'p Psbt<'a>);

impl<'a> Prevouts<'a> for PsbtPrevouts<'a, '_> {
    fn prevout(&self, i: usize) -> Option<TxOut<'a>> {
        let m = self.0.input(i)?;
        m.witness_utxo().or_else(|| {
            let vout = self.0.tx.input(i)?.vout as usize;
            m.non_witness_utxo()?.output(vout)
        })
    }
}

/// One new signature: an ECDSA partial signature (key 0x02 || pubkey) or a
/// Taproot key-path signature (key 0x13).
enum Sig {
    Ecdsa {
        pubkey: [u8; 33],
        der: [u8; ecdsa::MAX_DER_LEN + 1],
        len: usize,
    },
    Taproot {
        sig: [u8; 65],
        len: usize,
    },
}

/// Sign every pending input of this seed. `approved` is the digest of the
/// report the user reviewed; `overridden` records an explicit override of
/// blocking warnings for this transaction.
pub fn sign_psbt(
    raw: &[u8],
    signer: &Signer,
    memory: &mut UtxoMemory,
    approved: &[u8; 32],
    overridden: bool,
    out: &mut [u8],
) -> Result<Signed, Error> {
    let r = sign_into(raw, signer, memory, approved, overridden, out);
    if r.is_err() {
        bp_crypto::secret::wipe(out);
    }
    r
}

fn sign_into(
    raw: &[u8],
    signer: &Signer,
    memory: &mut UtxoMemory,
    approved: &[u8; 32],
    overridden: bool,
    out: &mut [u8],
) -> Result<Signed, Error> {
    // 1. the same verdict as approved
    let ctx = Context {
        master: signer.master,
        network: signer.network,
        policy: signer.policy,
        memory: Some(&*memory),
    };
    let (psbt, report) = validate(raw, &ctx);
    if report.digest() != *approved {
        return Err(Error::Changed);
    }
    let psbt = psbt.ok_or(Error::NotSignable)?;
    if !report.can_sign(overridden) {
        return Err(Error::NotSignable);
    }
    let tx = &psbt.tx;
    let prevouts = PsbtPrevouts(&psbt);
    let v0 = SegwitV0Hashes::new(tx);
    let owned = |k: SpendKind| {
        report
            .inputs()
            .iter()
            .any(|i| i.owned.is_some_and(|o| o.get().kind == k))
    };
    let taproot = if owned(SpendKind::P2trKey) {
        Some(TaprootHashes::new(tx, &prevouts).ok_or(Error::Sighash)?)
    } else {
        None
    };

    // 7. the trimmed PSBT, written while signing
    let mut w = Buf::new(out);
    write::put_magic(&mut w);
    write::put_pair(&mut w, 0x00, &[], tx.raw());
    write::put_separator(&mut w);
    let mut expected = 0usize;
    for (i, (rep, map)) in report.inputs().iter().zip(psbt.inputs()).enumerate() {
        let Some(o) = rep.owned.filter(|_| !rep.finalized && !rep.signed) else {
            write::put_separator(&mut w);
            continue;
        };
        let o = o.get();
        let prev = prevouts.prevout(i).ok_or(Error::Sighash)?;
        // 2. the key at the verified path
        let xprv = signer.master.derive_path(&o.path).map_err(|_| Error::Derive)?;
        let sk = xprv.secret_key();
        if sk.public_key() != o.pubkey {
            return Err(Error::Derive);
        }
        // 3-5. hash, sign, verify
        let sig = match o.kind {
            SpendKind::P2wpkh | SpendKind::P2shP2wpkh | SpendKind::P2pkh => {
                let digest = if o.kind == SpendKind::P2pkh {
                    sighash::legacy(tx, i, prev.script_pubkey, sighash::ALL as u32)
                } else {
                    let code = script::p2wpkh_script_code(&o.pubkey);
                    sighash::segwit_v0(tx, &v0, i, &code, prev.value, sighash::ALL as u32)
                        .ok_or(Error::Sighash)?
                };
                let s = ecdsa::sign(sk, &digest);
                if !ecdsa::verify(&o.pubkey, &digest, &s) {
                    return Err(Error::Verify);
                }
                let mut der = [0u8; ecdsa::MAX_DER_LEN + 1];
                let mut d = [0u8; ecdsa::MAX_DER_LEN];
                let n = s.to_der(&mut d);
                der[..n].copy_from_slice(&d[..n]);
                der[n] = sighash::ALL;
                Sig::Ecdsa {
                    pubkey: o.pubkey.serialize(),
                    der,
                    len: n + 1,
                }
            }
            SpendKind::P2trKey => {
                let hashes = taproot.as_ref().ok_or(Error::Sighash)?;
                let ht = match map.sighash_type() {
                    Some(1) => sighash::ALL,
                    _ => sighash::DEFAULT,
                };
                let digest =
                    sighash::taproot_key_spend(tx, hashes, &prevouts, i, ht).ok_or(Error::Sighash)?;
                let tweaked = schnorr::tweak_secret_key(sk, None).ok_or(Error::Derive)?;
                let s = schnorr::sign(&tweaked, &digest, &[0; 32]).ok_or(Error::Verify)?;
                drop(tweaked);
                // against the output key in the UTXO itself
                let q: [u8; 32] = match prev.script_pubkey {
                    [0x51, 0x20, k @ ..] => k.try_into().map_err(|_| Error::Verify)?,
                    _ => return Err(Error::Verify),
                };
                if !schnorr::verify(&q, &digest, &s) {
                    return Err(Error::Verify);
                }
                let mut sig = [0u8; 65];
                sig[..64].copy_from_slice(&s);
                sig[64] = ht;
                Sig::Taproot {
                    sig,
                    len: if ht == sighash::DEFAULT { 64 } else { 65 },
                }
            }
        };
        drop(xprv); // 6. wiped
        match &sig {
            Sig::Ecdsa { pubkey, der, len } => write::put_pair(&mut w, 0x02, pubkey, &der[..*len]),
            Sig::Taproot { sig, len } => write::put_pair(&mut w, 0x13, &[], &sig[..*len]),
        }
        write::put_separator(&mut w);
        expected += 1;
    }
    for _ in 0..tx.n_outputs() {
        write::put_separator(&mut w);
    }
    let len = w.finish().ok_or(Error::OutputTooSmall)?;
    if expected == 0 {
        return Err(Error::Output);
    }

    // the result parses, is the same transaction, and carries exactly the
    // signatures made, for the verified keys
    let result = Psbt::parse(&out[..len]).map_err(|_| Error::Output)?;
    if result.tx.raw() != tx.raw() {
        return Err(Error::Output);
    }
    let mut found = 0;
    for (rep, m) in report.inputs().iter().zip(result.inputs()) {
        let sigs = m.partial_sigs().count() + m.tap_key_sig().is_some() as usize;
        let want = rep.owned.is_some() && !rep.finalized && !rep.signed;
        if sigs != want as usize {
            return Err(Error::Output);
        }
        if let Some(o) = rep.owned.filter(|_| want) {
            let ok = match o.get().kind {
                SpendKind::P2trKey => m.tap_key_sig().is_some(),
                _ => m.partial_sigs().all(|(k, _)| k == o.get().pubkey.serialize()),
            };
            if !ok {
                return Err(Error::Output);
            }
        }
        found += sigs;
    }
    if found != expected {
        return Err(Error::Output);
    }

    // 8. remember what was signed
    for (rep, txin) in report.inputs().iter().zip(tx.inputs()) {
        if let (Some(o), false) = (rep.owned, rep.finalized || rep.signed) {
            memory.remember(txin.outpoint, o.get().amount);
        }
    }
    Ok(Signed {
        len,
        signatures: expected,
    })
}
