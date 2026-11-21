//! BIP-322 generic signed messages.
//!
//! - `to_spend` / `to_sign`: the virtual transactions a BIP-322 signature
//!   spends and signs.
//! - simple signatures: signed here for Taproot (key path, BIP-340 with
//!   zero auxiliary randomness, SIGHASH_DEFAULT), verified for P2WPKH and
//!   P2TR. Written with the `smp` prefix (BIP-322 1.0); read with or
//!   without it.
//! - PSBTs that sign a `to_sign` transaction (Sparrow, Proof of Reserves):
//!   recognised by the rules of BIP-322 and Coldcard, and refused as forged
//!   when they claim to be a message but the transaction says otherwise.

use crate::addrcheck::{Target, TargetError};
use crate::address::{taproot_output_key, ScriptType};
use crate::psbt::Psbt;
use crate::sighash::{self, SegwitV0Hashes, TaprootHashes};
use crate::tx::{put_compact_size, Buf, Reader, Sink, Tx, TxOut};
use crate::{base64, Network};
use bp_crypto::hashes::{hash160, tagged_hash};
use bp_crypto::secp256k1::ecdsa;
use bp_crypto::secp256k1::{schnorr, PublicKey, SecretKey};

/// Prefix of simple signatures.
pub const SIMPLE_PREFIX: &str = "smp";
/// Longest challenge script (single-key and P2WSH/P2TR programs).
pub const MAX_CHALLENGE: usize = 42;
/// Serialized `to_spend` with the longest challenge.
pub const TO_SPEND_MAX: usize = 4 + 1 + 36 + 1 + 34 + 4 + 1 + 8 + 1 + MAX_CHALLENGE + 4;
/// Serialized `to_sign` (without witness).
pub const TO_SIGN_LEN: usize = 4 + 1 + 36 + 1 + 4 + 1 + 8 + 1 + 1 + 4;
/// A Taproot simple signature: [1 item][64 bytes][signature].
pub const TAPROOT_WITNESS_LEN: usize = 66;
/// "smp" + Base64 of a Taproot simple signature.
pub const TAPROOT_SIG_TEXT: usize = 3 + 88;

/// tagged_hash("BIP0322-signed-message", message)
pub fn message_hash(msg: &[u8]) -> [u8; 32] {
    tagged_hash(b"BIP0322-signed-message", &[msg])
}

/// Serialize `to_spend` for `challenge` (a scriptPubKey) and `msg`.
pub fn to_spend(challenge: &[u8], msg: &[u8], out: &mut [u8; TO_SPEND_MAX]) -> Option<usize> {
    if challenge.len() > MAX_CHALLENGE {
        return None;
    }
    let mut b = Buf::new(out);
    b.put(&0u32.to_le_bytes()); // version 0
    b.put(&[1]);
    b.put(&[0; 32]);
    b.put(&0xFFFF_FFFFu32.to_le_bytes());
    // scriptSig: OP_0 PUSH32 message_hash
    b.put(&[34, 0x00, 0x20]);
    b.put(&message_hash(msg));
    b.put(&0u32.to_le_bytes()); // sequence 0
    b.put(&[1]);
    b.put(&0u64.to_le_bytes());
    put_compact_size(&mut b, challenge.len() as u64);
    b.put(challenge);
    b.put(&0u32.to_le_bytes()); // lock time 0
    b.finish()
}

pub fn to_spend_txid(challenge: &[u8], msg: &[u8]) -> Option<[u8; 32]> {
    let mut raw = [0u8; TO_SPEND_MAX];
    let n = to_spend(challenge, msg, &mut raw)?;
    Some(Tx::parse(&raw[..n]).ok()?.txid())
}

/// Serialize the unsigned `to_sign` spending `to_spend_txid`:0.
pub fn to_sign(to_spend_txid: &[u8; 32]) -> [u8; TO_SIGN_LEN] {
    let mut out = [0u8; TO_SIGN_LEN];
    let mut b = Buf::new(&mut out);
    b.put(&0u32.to_le_bytes());
    b.put(&[1]);
    b.put(to_spend_txid);
    b.put(&0u32.to_le_bytes());
    b.put(&[0]); // empty scriptSig
    b.put(&0u32.to_le_bytes()); // sequence 0
    b.put(&[1]);
    b.put(&0u64.to_le_bytes());
    b.put(&[1, 0x6A]); // OP_RETURN
    b.put(&0u32.to_le_bytes());
    b.finish().expect("fits");
    out
}

/// The signature hash a single-input `to_sign` commits to for `challenge`.
fn taproot_sighash(challenge: &[u8], msg: &[u8], hash_type: u8) -> Option<[u8; 32]> {
    let txid = to_spend_txid(challenge, msg)?;
    let raw = to_sign(&txid);
    let tx = Tx::parse(&raw).ok()?;
    let prevouts = [TxOut::new(0, challenge)];
    let hashes = TaprootHashes::new(&tx, &prevouts[..])?;
    sighash::taproot_key_spend(&tx, &hashes, &prevouts[..], 0, hash_type)
}

fn segwit_v0_sighash(challenge: &[u8], msg: &[u8], script_code: &[u8], hash_type: u32) -> Option<[u8; 32]> {
    let txid = to_spend_txid(challenge, msg)?;
    let raw = to_sign(&txid);
    let tx = Tx::parse(&raw).ok()?;
    let hashes = SegwitV0Hashes::new(&tx);
    sighash::segwit_v0(&tx, &hashes, 0, script_code, 0, hash_type)
}

/// Taproot (BIP-86 key path) simple signature by `sk`, the internal key:
/// the witness [64-byte Schnorr signature], checked before it is returned.
pub fn sign_simple_taproot(sk: &SecretKey, msg: &[u8]) -> Option<[u8; TAPROOT_WITNESS_LEN]> {
    let q = taproot_output_key(&sk.public_key())?;
    let mut challenge = [0u8; 34];
    challenge[0] = 0x51;
    challenge[1] = 0x20;
    challenge[2..].copy_from_slice(&q);
    let digest = taproot_sighash(&challenge, msg, 0x00)?;
    let tweaked = schnorr::tweak_secret_key(sk, None)?;
    let sig = schnorr::sign(&tweaked, &digest, &[0; 32])?;
    if !schnorr::verify(&q, &digest, &sig) {
        return None;
    }
    let mut w = [0u8; TAPROOT_WITNESS_LEN];
    w[0] = 1;
    w[1] = 64;
    w[2..].copy_from_slice(&sig);
    Some(w)
}

/// "smp" + Base64 of a witness.
pub fn simple_text(witness: &[u8], out: &mut [u8]) -> Option<usize> {
    let p = SIMPLE_PREFIX.len();
    out.get_mut(..p)?.copy_from_slice(SIMPLE_PREFIX.as_bytes());
    let n = base64::encode(witness, out.get_mut(p..)?).ok()?;
    Some(p + n)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimpleError {
    Address(TargetError),
    /// Not (prefixed) Base64 of a witness stack.
    Encoding,
    /// A "full" or "proof of funds" signature (not supported here).
    OtherVariant,
    /// An address type simple signatures are not checked for here
    /// (P2PKH and P2SH use the legacy format).
    Unsupported,
    /// Not a valid signature by this address for this message.
    Invalid,
}

/// Up to two witness items of a simple signature.
fn witness_items(raw: &[u8]) -> Option<([&[u8]; 2], usize)> {
    let mut r = Reader::new(raw);
    let n = r.compact_size().ok()?;
    if n == 0 || n > 2 {
        return None;
    }
    let mut items: [&[u8]; 2] = [&[], &[]];
    for it in items.iter_mut().take(n as usize) {
        *it = r.var_bytes().ok()?;
    }
    (r.remaining() == 0).then_some((items, n as usize))
}

/// Verify a BIP-322 simple signature of `msg` by `address` (P2WPKH, P2TR).
pub fn verify_simple(address: &str, net: Network, msg: &[u8], sig: &str) -> Result<ScriptType, SimpleError> {
    let target = Target::parse(address.trim(), net).map_err(SimpleError::Address)?;
    let st = target.script_type();
    let s = sig.trim();
    if s.starts_with("ful") || s.starts_with("pof") {
        return Err(SimpleError::OtherVariant);
    }
    let body = s.strip_prefix(SIMPLE_PREFIX).unwrap_or(s);
    let mut raw = [0u8; 160];
    let n = base64::decode(body.as_bytes(), &mut raw).map_err(|_| SimpleError::Encoding)?;
    let (items, count) = witness_items(&raw[..n]).ok_or(SimpleError::Encoding)?;
    let challenge = target.script();
    match st {
        ScriptType::NativeSegwit => {
            if count != 2 {
                return Err(SimpleError::Invalid);
            }
            let (sig, pk) = (items[0], items[1]);
            let (&hash_type, der) = sig.split_last().ok_or(SimpleError::Invalid)?;
            // SIGHASH_ALL only (BIP-322 required rules)
            if hash_type != 0x01 || pk.len() != 33 || hash160(pk) != challenge[2..22] {
                return Err(SimpleError::Invalid);
            }
            let key = PublicKey::parse(pk).ok_or(SimpleError::Invalid)?;
            let sig = ecdsa::Signature::from_der(der).ok_or(SimpleError::Invalid)?;
            let mut code = [0u8; 25];
            code[..3].copy_from_slice(&[0x76, 0xA9, 0x14]);
            code[3..23].copy_from_slice(&challenge[2..22]);
            code[23..].copy_from_slice(&[0x88, 0xAC]);
            let digest = segwit_v0_sighash(challenge, msg, &code, 1).ok_or(SimpleError::Invalid)?;
            // verify() also rejects a high S (LOW_S rule)
            if !ecdsa::verify(&key, &digest, &sig) {
                return Err(SimpleError::Invalid);
            }
        }
        ScriptType::Taproot => {
            if count != 1 {
                return Err(SimpleError::Invalid);
            }
            let w = items[0];
            let (sig, hash_type) = match w.len() {
                64 => (w, 0x00),
                65 if w[64] == 0x01 => (&w[..64], 0x01),
                _ => return Err(SimpleError::Invalid),
            };
            let q: [u8; 32] = challenge[2..34].try_into().expect("32");
            let digest = taproot_sighash(challenge, msg, hash_type).ok_or(SimpleError::Invalid)?;
            if !schnorr::verify(&q, &digest, sig.try_into().expect("64")) {
                return Err(SimpleError::Invalid);
            }
        }
        ScriptType::Legacy | ScriptType::NestedSegwit => return Err(SimpleError::Unsupported),
    }
    Ok(st)
}

/// What a PSBT asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PsbtKind<'a> {
    /// An ordinary transaction (reviewed as one).
    Transaction,
    /// A BIP-322 message: sign `message` for the first input's
    /// `challenge`; with more inputs, a Proof of Reserves.
    Message {
        message: &'a [u8],
        challenge: &'a [u8],
        proof_of_reserves: bool,
    },
    /// It claims to be a message (field 0x09 and a lone zero OP_RETURN
    /// output) but the transaction does not sign that message.
    Forged(Forgery),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forgery {
    /// The first input carries no previous output to read the challenge.
    NoChallenge,
    /// The first input does not spend output 0.
    PrevoutIndex,
    /// The first input does not spend `to_spend` of this message.
    ToSpendMismatch,
    /// The first input's amount is not zero.
    NonZeroAmount,
    /// The previous transaction given is not `to_spend`.
    NonWitnessUtxo,
    /// Transaction version other than 0 or 2.
    Version,
}

const GLOBAL_GENERIC_SIGNED_MESSAGE: u64 = 0x09;

/// Classify `p` (rules of BIP-322 "PSBT signer", plus Coldcard's: the
/// amount, the previous transaction and the version must match too).
pub fn classify_psbt<'a>(p: &Psbt<'a>) -> PsbtKind<'a> {
    let message = p
        .global_pairs()
        .find(|g| g.key_type == GLOBAL_GENERIC_SIGNED_MESSAGE && g.key_data.is_empty())
        .map(|g| g.value);
    let Some(message) = message else {
        return PsbtKind::Transaction;
    };
    let lone_op_return = p.tx.n_outputs() == 1
        && p.tx
            .output(0)
            .is_some_and(|o| o.value == 0 && o.script_pubkey == [0x6A]);
    if !lone_op_return {
        // a message field on a real payment: reviewed as the payment
        return PsbtKind::Transaction;
    }
    match check_message_psbt(p, message) {
        Ok(challenge) => PsbtKind::Message {
            message,
            challenge,
            proof_of_reserves: p.tx.n_inputs() > 1,
        },
        Err(f) => PsbtKind::Forged(f),
    }
}

fn check_message_psbt<'a>(p: &Psbt<'a>, message: &[u8]) -> Result<&'a [u8], Forgery> {
    if !matches!(p.tx.version, 0 | 2) {
        return Err(Forgery::Version);
    }
    let txin = p.tx.input(0).ok_or(Forgery::NoChallenge)?;
    let map = p.input(0).ok_or(Forgery::NoChallenge)?;
    let wit = map.witness_utxo();
    let non_wit = map.non_witness_utxo();
    let prev = match (wit, non_wit) {
        (Some(w), _) => w,
        (None, Some(t)) => t.output(txin.vout as usize).ok_or(Forgery::NoChallenge)?,
        (None, None) => return Err(Forgery::NoChallenge),
    };
    let challenge = prev.script_pubkey;
    if txin.vout != 0 {
        return Err(Forgery::PrevoutIndex);
    }
    let mut raw = [0u8; TO_SPEND_MAX];
    let n = to_spend(challenge, message, &mut raw).ok_or(Forgery::ToSpendMismatch)?;
    let txid = Tx::parse(&raw[..n]).map_err(|_| Forgery::ToSpendMismatch)?.txid();
    if txin.txid != txid {
        return Err(Forgery::ToSpendMismatch);
    }
    if prev.value != 0 {
        return Err(Forgery::NonZeroAmount);
    }
    if let Some(t) = non_wit {
        if t.raw() != &raw[..n] {
            return Err(Forgery::NonWitnessUtxo);
        }
    }
    if let Some(w) = wit {
        // both given: they must agree
        if non_wit.is_some_and(|t| {
            t.output(0).map(|o| (o.value, o.script_pubkey)) != Some((w.value, w.script_pubkey))
        }) {
            return Err(Forgery::NonWitnessUtxo);
        }
    }
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_sign_layout() {
        let t = to_sign(&[7; 32]);
        let tx = Tx::parse(&t).unwrap();
        assert_eq!(
            (tx.version, tx.lock_time, tx.n_inputs(), tx.n_outputs()),
            (0, 0, 1, 1)
        );
        assert_eq!(tx.output(0).unwrap().script_pubkey, [0x6A]);
        assert_eq!(tx.input(0).unwrap().sequence, 0);
    }
}
