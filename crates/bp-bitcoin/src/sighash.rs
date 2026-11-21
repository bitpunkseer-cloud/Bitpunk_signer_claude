//! Signature hashes: legacy (pre-segwit), BIP-143 (segwit v0) and BIP-341
//! (Taproot key path).
//!
//! The signer only ever signs with SIGHASH_ALL (Taproot: DEFAULT); the
//! validator refuses anything else. All hash types are still implemented
//! exactly as Bitcoin Core does, so that this code can be checked against
//! the complete reference vectors. Preimages are streamed into a `Sink`, so
//! they can be hashed directly or written out for tests.

use crate::tx::{put_compact_size, Sink, Tx, TxOut};
use bp_crypto::hashes::sha256d;
use bp_crypto::sha256::Sha256;

pub const DEFAULT: u8 = 0x00;
pub const ALL: u8 = 0x01;
pub const NONE: u8 = 0x02;
pub const SINGLE: u8 = 0x03;
pub const ANYONECANPAY: u8 = 0x80;

/// Bitcoin Core's "one" result for an out-of-range input or SIGHASH_SINGLE
/// without a matching output (the historical SIGHASH_SINGLE bug).
pub const LEGACY_ONE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
};

/// Advance over one script operation as Bitcoin Core's `GetScriptOp`:
/// returns the opcode, or `None` with `pos` moved as far as Core moves it.
fn next_op(script: &[u8], pos: &mut usize) -> Option<u8> {
    let op = *script.get(*pos)?;
    *pos += 1;
    let size = match op {
        0x01..=0x4B => op as usize,
        0x4C => {
            let n = *script.get(*pos)? as usize;
            *pos += 1;
            n
        }
        0x4D => {
            let b = script.get(*pos..*pos + 2)?;
            *pos += 2;
            u16::from_le_bytes([b[0], b[1]]) as usize
        }
        0x4E => {
            let b = script.get(*pos..*pos + 4)?;
            *pos += 4;
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
        }
        _ => 0,
    };
    if script.len() - *pos < size {
        return None;
    }
    *pos += size;
    Some(op)
}

const OP_CODESEPARATOR: u8 = 0xAB;

/// Serialize a legacy script code with every OP_CODESEPARATOR removed,
/// byte for byte as Core's `CTransactionSignatureSerializer`.
fn put_script_code<S: Sink>(s: &mut S, script: &[u8]) {
    let mut pos = 0;
    let mut seps = 0;
    while let Some(op) = next_op(script, &mut pos) {
        seps += (op == OP_CODESEPARATOR) as usize;
    }
    put_compact_size(s, (script.len() - seps) as u64);
    let (mut begin, mut pos) = (0, 0);
    while let Some(op) = next_op(script, &mut pos) {
        if op == OP_CODESEPARATOR {
            s.put(&script[begin..pos - 1]);
            begin = pos;
        }
    }
    if begin != script.len() {
        s.put(&script[begin..pos]);
    }
}

/// Legacy signature hash of input `input` with `script_code` (for P2PKH,
/// the previous output's scriptPubKey). `hash_type` is the full 32-bit
/// value appended to the preimage.
pub fn legacy(tx: &Tx, input: usize, script_code: &[u8], hash_type: u32) -> [u8; 32] {
    let base = hash_type & 0x1F;
    let single = base == SINGLE as u32;
    let none = base == NONE as u32;
    let acp = hash_type & ANYONECANPAY as u32 != 0;
    if input >= tx.n_inputs() || (single && input >= tx.n_outputs()) {
        return LEGACY_ONE;
    }
    let mut h = Sha256::new();
    h.put(&tx.version.to_le_bytes());
    put_compact_size(&mut h, if acp { 1 } else { tx.n_inputs() as u64 });
    for (i, txin) in tx.inputs().enumerate() {
        if acp && i != input {
            continue;
        }
        h.put(txin.outpoint);
        if i == input {
            put_script_code(&mut h, script_code);
        } else {
            h.put(&[0]);
        }
        let seq = if i != input && (single || none) {
            0
        } else {
            txin.sequence
        };
        h.put(&seq.to_le_bytes());
    }
    let n_out = if none {
        0
    } else if single {
        input + 1
    } else {
        tx.n_outputs()
    };
    put_compact_size(&mut h, n_out as u64);
    for (i, out) in tx.outputs().take(n_out).enumerate() {
        if single && i != input {
            h.put(&u64::MAX.to_le_bytes()); // CTxOut(): value -1, empty script
            h.put(&[0]);
        } else {
            h.put(out.raw);
        }
    }
    h.put(&tx.lock_time.to_le_bytes());
    h.put(&hash_type.to_le_bytes());
    Sha256::digest(&h.finalize())
}

/// BIP-143 hashes shared by all inputs (double SHA-256).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegwitV0Hashes {
    pub prevouts: [u8; 32],
    pub sequences: [u8; 32],
    pub outputs: [u8; 32],
}

impl SegwitV0Hashes {
    pub fn new(tx: &Tx) -> Self {
        let t = TaprootTxHashes::new(tx);
        SegwitV0Hashes {
            prevouts: Sha256::digest(&t.prevouts),
            sequences: Sha256::digest(&t.sequences),
            outputs: Sha256::digest(&t.outputs),
        }
    }
}

/// Write the BIP-143 preimage; `None` if `input` is out of range.
pub fn segwit_v0_preimage<S: Sink>(
    s: &mut S,
    tx: &Tx,
    hashes: &SegwitV0Hashes,
    input: usize,
    script_code: &[u8],
    value: u64,
    hash_type: u32,
) -> Option<()> {
    let txin = tx.input(input)?;
    let base = (hash_type & 0x1F) as u8;
    let acp = hash_type & ANYONECANPAY as u32 != 0;
    let zero = [0u8; 32];
    s.put(&tx.version.to_le_bytes());
    s.put(if acp { &zero } else { &hashes.prevouts });
    s.put(if acp || base == SINGLE || base == NONE {
        &zero
    } else {
        &hashes.sequences
    });
    s.put(txin.outpoint);
    put_compact_size(s, script_code.len() as u64);
    s.put(script_code);
    s.put(&value.to_le_bytes());
    s.put(&txin.sequence.to_le_bytes());
    if base != SINGLE && base != NONE {
        s.put(&hashes.outputs);
    } else if base == SINGLE && input < tx.n_outputs() {
        s.put(&sha256d(tx.output(input)?.raw));
    } else {
        s.put(&zero);
    }
    s.put(&tx.lock_time.to_le_bytes());
    s.put(&hash_type.to_le_bytes());
    Some(())
}

/// BIP-143 signature hash. For P2WPKH and P2SH-P2WPKH the script code is
/// the P2PKH script of the key hash.
pub fn segwit_v0(
    tx: &Tx,
    hashes: &SegwitV0Hashes,
    input: usize,
    script_code: &[u8],
    value: u64,
    hash_type: u32,
) -> Option<[u8; 32]> {
    let mut h = Sha256::new();
    segwit_v0_preimage(&mut h, tx, hashes, input, script_code, value, hash_type)?;
    Some(Sha256::digest(&h.finalize()))
}

/// The previous outputs spent by a transaction, by input index.
pub trait Prevouts<'p> {
    fn prevout(&self, input: usize) -> Option<TxOut<'p>>;
}

impl<'p> Prevouts<'p> for [TxOut<'p>] {
    fn prevout(&self, input: usize) -> Option<TxOut<'p>> {
        self.get(input).copied()
    }
}

/// Single-SHA-256 hashes of the transaction's own data.
struct TaprootTxHashes {
    prevouts: [u8; 32],
    sequences: [u8; 32],
    outputs: [u8; 32],
}

impl TaprootTxHashes {
    fn new(tx: &Tx) -> Self {
        let (mut p, mut q) = (Sha256::new(), Sha256::new());
        for txin in tx.inputs() {
            p.put(txin.outpoint);
            q.put(&txin.sequence.to_le_bytes());
        }
        TaprootTxHashes {
            prevouts: p.finalize(),
            sequences: q.finalize(),
            outputs: Sha256::digest(tx.outputs_bytes()),
        }
    }
}

/// BIP-341 hashes shared by all inputs (single SHA-256).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaprootHashes {
    pub prevouts: [u8; 32],
    pub amounts: [u8; 32],
    pub script_pubkeys: [u8; 32],
    pub sequences: [u8; 32],
    pub outputs: [u8; 32],
}

impl TaprootHashes {
    /// `None` if any previous output is unknown (BIP-341 commits to all).
    pub fn new<'p, P: Prevouts<'p> + ?Sized>(tx: &Tx, prevouts: &P) -> Option<Self> {
        let t = TaprootTxHashes::new(tx);
        let (mut a, mut s) = (Sha256::new(), Sha256::new());
        for i in 0..tx.n_inputs() {
            let p = prevouts.prevout(i)?;
            a.put(&p.value.to_le_bytes());
            put_compact_size(&mut s, p.script_pubkey.len() as u64);
            s.put(p.script_pubkey);
        }
        Some(TaprootHashes {
            prevouts: t.prevouts,
            amounts: a.finalize(),
            script_pubkeys: s.finalize(),
            sequences: t.sequences,
            outputs: t.outputs,
        })
    }
}

/// Write the BIP-341 signature message for a key-path spend, including the
/// leading epoch byte 0x00 (no annex). `None` for an invalid hash type, an
/// input out of range, or SIGHASH_SINGLE without a matching output.
pub fn taproot_sigmsg<'p, S: Sink, P: Prevouts<'p> + ?Sized>(
    s: &mut S,
    tx: &Tx,
    hashes: &TaprootHashes,
    prevouts: &P,
    input: usize,
    hash_type: u8,
) -> Option<()> {
    if !matches!(hash_type, 0x00..=0x03 | 0x81..=0x83) {
        return None;
    }
    let base = hash_type & 0x03;
    let acp = hash_type & ANYONECANPAY != 0;
    let txin = tx.input(input)?;
    let single_out = if base == SINGLE {
        Some(tx.output(input)?)
    } else {
        None
    };
    s.put(&[0x00, hash_type]);
    s.put(&tx.version.to_le_bytes());
    s.put(&tx.lock_time.to_le_bytes());
    if !acp {
        s.put(&hashes.prevouts);
        s.put(&hashes.amounts);
        s.put(&hashes.script_pubkeys);
        s.put(&hashes.sequences);
    }
    if base != NONE && base != SINGLE {
        s.put(&hashes.outputs);
    }
    s.put(&[0x00]); // spend type: key path, no annex
    if acp {
        let p = prevouts.prevout(input)?;
        s.put(txin.outpoint);
        s.put(&p.value.to_le_bytes());
        put_compact_size(s, p.script_pubkey.len() as u64);
        s.put(p.script_pubkey);
        s.put(&txin.sequence.to_le_bytes());
    } else {
        s.put(&(input as u32).to_le_bytes());
    }
    if let Some(o) = single_out {
        let mut h = Sha256::new();
        o.write(&mut h);
        s.put(&h.finalize());
    }
    Some(())
}

/// BIP-341 key-path signature hash: H_TapSighash(0x00 || SigMsg).
pub fn taproot_key_spend<'p, P: Prevouts<'p> + ?Sized>(
    tx: &Tx,
    hashes: &TaprootHashes,
    prevouts: &P,
    input: usize,
    hash_type: u8,
) -> Option<[u8; 32]> {
    let tag = Sha256::digest(b"TapSighash");
    let mut h = Sha256::new();
    h.put(&tag);
    h.put(&tag);
    taproot_sigmsg(&mut h, tx, hashes, prevouts, input, hash_type)?;
    Some(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::Buf;

    fn code(script: &[u8]) -> ([u8; 64], usize) {
        let mut b = [0u8; 64];
        let mut w = Buf::new(&mut b);
        put_script_code(&mut w, script);
        let n = w.finish().unwrap();
        (b, n)
    }

    #[test]
    fn script_code_drops_only_real_codeseparators() {
        // OP_1 OP_CODESEPARATOR PUSH(1: 0xab) OP_CODESEPARATOR OP_2
        let (b, n) = code(&[0x51, 0xAB, 0x01, 0xAB, 0xAB, 0x52]);
        assert_eq!(&b[..n], &[4, 0x51, 0x01, 0xAB, 0x52]);
        // parsing stops at a truncated push as in Core; the declared length
        // counts everything but the separators found before it
        let (b, n) = code(&[0xAB, 0x4C]);
        assert_eq!(&b[..n], &[1, 0x4C]);
    }
}
