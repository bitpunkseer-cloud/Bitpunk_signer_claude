//! Strict PSBT v0 parser: BIP-174, Taproot fields (BIP-371), MuSig2 fields
//! (BIP-373, checked but not used).
//!
//! Every rule of Bitcoin Core's deserializer is applied: canonical compact
//! sizes, no duplicate keys, exact key sizes per type, exact value sizes,
//! valid public keys, strict DER signatures with a defined hash type, key
//! paths of 4-byte steps, well-formed Taproot trees, v2-only fields
//! rejected, an unsigned transaction without scriptSigs or witness, one map
//! per input and output, a non-witness UTXO whose hash and output count
//! match the outpoint, and no trailing bytes. On top of that come the
//! checks rust-bitcoin adds (x-only keys on the curve, hash preimages that
//! match, well-formed control blocks and leaf versions, xpub/tpub version
//! bytes) and two of our own: no hybrid public key encodings, and an
//! unsigned transaction with at least one input and one output.
//!
//! Nothing is copied: the parsed PSBT is a view of the original bytes, and
//! maps are walked again on access (they were all checked once).
//!
//! Everything here is a *claim* by the host. Which inputs and outputs
//! belong to the seed is decided only by re-deriving keys (validator).

use super::MAGIC;
use crate::bip32::DerivationPath;
use crate::tx::{self, Reader, Tx, TxOut};
use bp_crypto::hashes::{hash160, sha256d};
use bp_crypto::ripemd160::Ripemd160;
use bp_crypto::secp256k1::{schnorr, PublicKey};
use bp_crypto::sha256::Sha256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Missing `psbt\xff` magic.
    Magic,
    /// The data ends early (inside a map, or a map has no separator).
    Truncated,
    /// Bytes after the last output map.
    TrailingData,
    /// The same key twice in one map.
    DuplicateKey,
    /// A key has the wrong size or structure for its type.
    KeySize,
    /// A value has the wrong size or structure for its type.
    Value,
    /// No unsigned transaction in the global map.
    NoUnsignedTx,
    /// The unsigned transaction is invalid, has a witness or scriptSigs.
    UnsignedTx,
    /// PSBT version other than 0 (v2 arrives in M7).
    UnsupportedVersion,
    /// A PSBT v2 field in a v0 PSBT.
    V2Field,
    InvalidPubkey,
    /// A partial signature that is not strict DER with a defined hash type,
    /// or a Schnorr signature that is not 64 or 65 bytes.
    InvalidSignature,
    /// A key path that is empty or not a whole number of steps.
    InvalidKeyPath,
    InvalidTapTree,
    /// Fewer input or output maps than the transaction has.
    MapCount,
    /// A non-witness UTXO whose hash is not the outpoint's txid.
    UtxoMismatch,
    /// The outpoint's index is beyond the non-witness UTXO's outputs.
    UtxoIndex,
}

impl From<tx::Error> for Error {
    fn from(e: tx::Error) -> Error {
        match e {
            tx::Error::Truncated => Error::Truncated,
            tx::Error::Malformed => Error::Value,
        }
    }
}

// key types
const GLOBAL_UNSIGNED_TX: u64 = 0x00;
const GLOBAL_XPUB: u64 = 0x01;
const GLOBAL_VERSION: u64 = 0xFB;
const PROPRIETARY: u64 = 0xFC;

pub const IN_NON_WITNESS_UTXO: u64 = 0x00;
pub const IN_WITNESS_UTXO: u64 = 0x01;
pub const IN_PARTIAL_SIG: u64 = 0x02;
pub const IN_SIGHASH: u64 = 0x03;
pub const IN_REDEEM_SCRIPT: u64 = 0x04;
pub const IN_WITNESS_SCRIPT: u64 = 0x05;
pub const IN_BIP32_DERIVATION: u64 = 0x06;
pub const IN_FINAL_SCRIPTSIG: u64 = 0x07;
pub const IN_FINAL_SCRIPTWITNESS: u64 = 0x08;
pub const IN_TAP_KEY_SIG: u64 = 0x13;
pub const IN_TAP_SCRIPT_SIG: u64 = 0x14;
pub const IN_TAP_LEAF_SCRIPT: u64 = 0x15;
pub const IN_TAP_BIP32_DERIVATION: u64 = 0x16;
pub const IN_TAP_INTERNAL_KEY: u64 = 0x17;
pub const IN_TAP_MERKLE_ROOT: u64 = 0x18;

pub const OUT_REDEEM_SCRIPT: u64 = 0x00;
pub const OUT_WITNESS_SCRIPT: u64 = 0x01;
pub const OUT_BIP32_DERIVATION: u64 = 0x02;
pub const OUT_TAP_INTERNAL_KEY: u64 = 0x05;
pub const OUT_TAP_TREE: u64 = 0x06;
pub const OUT_TAP_BIP32_DERIVATION: u64 = 0x07;

/// One key-value pair. `key` is the whole key (type and data).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pair<'a> {
    pub key: &'a [u8],
    pub key_type: u64,
    pub key_data: &'a [u8],
    pub value: &'a [u8],
}

/// Read one pair; `None` at the separator.
fn read_pair<'a>(r: &mut Reader<'a>) -> Result<Option<Pair<'a>>, Error> {
    let key = r.var_bytes()?;
    if key.is_empty() {
        return Ok(None);
    }
    let mut kr = Reader::new(key);
    let key_type = kr.compact_size().map_err(|_| Error::KeySize)?;
    let key_data = &key[kr.pos()..];
    let value = r.var_bytes()?;
    Ok(Some(Pair {
        key,
        key_type,
        key_data,
        value,
    }))
}

/// Pairs of a map that has already been checked.
#[derive(Clone)]
pub struct Pairs<'a> {
    r: Reader<'a>,
}

impl<'a> Iterator for Pairs<'a> {
    type Item = Pair<'a>;
    fn next(&mut self) -> Option<Pair<'a>> {
        read_pair(&mut self.r).ok().flatten()
    }
}

/// Read a map up to its separator; returns its pairs region (without the
/// separator).
fn skip_map<'a>(r: &mut Reader<'a>, d: &'a [u8]) -> Result<&'a [u8], Error> {
    let start = r.pos();
    let mut end = start;
    while read_pair(r)?.is_some() {
        end = r.pos();
    }
    Ok(&d[start..end])
}

/// `skip_map` and a check for duplicate keys.
fn read_map<'a>(r: &mut Reader<'a>, d: &'a [u8]) -> Result<&'a [u8], Error> {
    let map = skip_map(r, d)?;
    let mut outer = Pairs { r: Reader::new(map) };
    while let Some(a) = outer.next() {
        if outer.clone().any(|b| b.key == a.key) {
            return Err(Error::DuplicateKey);
        }
    }
    Ok(map)
}

fn empty_key(p: &Pair) -> Result<(), Error> {
    if p.key_data.is_empty() {
        Ok(())
    } else {
        Err(Error::KeySize)
    }
}

fn key_len(p: &Pair, n: usize) -> Result<(), Error> {
    if p.key_data.len() == n {
        Ok(())
    } else {
        Err(Error::KeySize)
    }
}

/// A public key in a key: 33 or 65 bytes, valid.
fn pubkey_key(data: &[u8]) -> Result<(), Error> {
    if data.len() != 33 && data.len() != 65 {
        return Err(Error::KeySize);
    }
    PublicKey::parse(data).map(|_| ()).ok_or(Error::InvalidPubkey)
}

fn compressed_pubkey(data: &[u8]) -> Result<(), Error> {
    if data.len() == 33 {
        PublicKey::parse(data).map(|_| ()).ok_or(Error::InvalidPubkey)
    } else {
        Err(Error::InvalidPubkey)
    }
}

/// A valid x-only public key (a point on the curve).
fn xonly(data: &[u8]) -> Result<(), Error> {
    let x: [u8; 32] = data.try_into().map_err(|_| Error::Value)?;
    schnorr::lift_x(&x).map(|_| ()).ok_or(Error::InvalidPubkey)
}

/// A hash preimage whose hash is the key data.
fn preimage(p: &Pair) -> Result<(), Error> {
    let (n, ok) = match p.key_type {
        0x0A => (20, Ripemd160::digest(p.value)[..] == *p.key_data),
        0x0B => (32, Sha256::digest(p.value)[..] == *p.key_data),
        0x0C => (20, hash160(p.value)[..] == *p.key_data),
        _ => (32, sha256d(p.value)[..] == *p.key_data),
    };
    key_len(p, n)?;
    if ok {
        Ok(())
    } else {
        Err(Error::Value)
    }
}

fn key_path(v: &[u8]) -> Result<(), Error> {
    if v.is_empty() || !v.len().is_multiple_of(4) {
        Err(Error::InvalidKeyPath)
    } else {
        Ok(())
    }
}

/// The value fills exactly what `f` reads.
fn exact<'a, T>(v: &'a [u8], f: impl FnOnce(&mut Reader<'a>) -> Result<T, tx::Error>) -> Result<T, Error> {
    let mut r = Reader::new(v);
    let t = f(&mut r).map_err(|_| Error::Value)?;
    if r.remaining() != 0 {
        return Err(Error::Value);
    }
    Ok(t)
}

fn witness_utxo(v: &[u8]) -> Result<TxOut<'_>, Error> {
    exact(v, |r| {
        let value = r.u64()?;
        let script = r.var_bytes()?;
        Ok(TxOut {
            value,
            script_pubkey: script,
            raw: v,
        })
    })
}

/// Bitcoin Core's `IsValidSignatureEncoding` (BIP-66 strict DER with the
/// sighash byte) plus a defined hash type (ALL, NONE or SINGLE, optionally
/// with ANYONECANPAY), as `CheckSignatureEncoding` with DERSIG|STRICTENC.
pub fn is_valid_ecdsa_sig_encoding(sig: &[u8]) -> bool {
    let n = sig.len();
    if !(9..=73).contains(&n) || sig[0] != 0x30 || sig[1] as usize != n - 3 {
        return false;
    }
    let len_r = sig[3] as usize;
    if 5 + len_r >= n {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != n || sig[2] != 0x02 || len_r == 0 || sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0 && sig[5] & 0x80 == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 || len_s == 0 || sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }
    let ht = sig[n - 1] & !0x80;
    (1..=3).contains(&ht)
}

/// Leaf hashes then a key origin (Taproot BIP32 derivation value).
fn tap_derivation(v: &[u8]) -> Result<(&[u8], KeySource<'_>), Error> {
    let mut r = Reader::new(v);
    let n = r.compact_size().map_err(|_| Error::InvalidKeyPath)? as usize;
    let hashes = r
        .take(n.checked_mul(32).ok_or(Error::InvalidKeyPath)?)
        .map_err(|_| Error::InvalidKeyPath)?;
    let origin = &v[r.pos()..];
    key_path(origin)?;
    Ok((hashes, KeySource::new(origin)))
}

fn proprietary_key(data: &[u8]) -> Result<(), Error> {
    let mut r = Reader::new(data);
    r.var_bytes().map_err(|_| Error::KeySize)?;
    r.compact_size().map_err(|_| Error::KeySize)?;
    Ok(())
}

fn musig_participants(p: &Pair) -> Result<(), Error> {
    key_len(p, 33)?;
    compressed_pubkey(p.key_data)?;
    if !p.value.len().is_multiple_of(33) {
        return Err(Error::Value);
    }
    p.value.chunks(33).try_for_each(compressed_pubkey)
}

fn musig_identifier(p: &Pair) -> Result<(), Error> {
    if p.key_data.len() != 66 && p.key_data.len() != 98 {
        return Err(Error::KeySize);
    }
    compressed_pubkey(&p.key_data[..33])?;
    compressed_pubkey(&p.key_data[33..66])
}

/// A Taproot leaf version: even, and not the annex tag 0x50.
fn leaf_version_ok(v: u8) -> bool {
    v & 1 == 0 && v != 0x50
}

/// BIP-341 tree depths in DFS order must form a complete binary tree
/// (Bitcoin Core's `TaprootBuilder::ValidDepths`).
fn tap_tree(v: &[u8]) -> Result<(), Error> {
    const MAX_DEPTH: usize = 128;
    if v.is_empty() {
        return Err(Error::InvalidTapTree);
    }
    let mut branch = [false; MAX_DEPTH + 1];
    let mut len = 0usize;
    let mut r = Reader::new(v);
    while r.remaining() > 0 {
        let depth = r.u8().map_err(|_| Error::InvalidTapTree)? as usize;
        let leaf_ver = r.u8().map_err(|_| Error::InvalidTapTree)?;
        r.var_bytes().map_err(|_| Error::InvalidTapTree)?;
        if depth > MAX_DEPTH || !leaf_version_ok(leaf_ver) {
            return Err(Error::InvalidTapTree);
        }
        let mut d = depth;
        if d + 1 < len {
            return Err(Error::InvalidTapTree);
        }
        while len > d && branch[d] {
            len -= 1;
            branch[len] = false;
            if d == 0 {
                return Err(Error::InvalidTapTree);
            }
            d -= 1;
        }
        while len <= d {
            branch[len] = false;
            len += 1;
        }
        branch[d] = true;
    }
    if len == 0 || (len == 1 && branch[0]) {
        Ok(())
    } else {
        Err(Error::InvalidTapTree)
    }
}

fn check_input_pair(p: &Pair) -> Result<(), Error> {
    match p.key_type {
        IN_NON_WITNESS_UTXO => {
            empty_key(p)?;
            Tx::parse(p.value).map_err(|_| Error::Value)?;
        }
        IN_WITNESS_UTXO => {
            empty_key(p)?;
            witness_utxo(p.value)?;
        }
        IN_PARTIAL_SIG => {
            pubkey_key(p.key_data)?;
            if !is_valid_ecdsa_sig_encoding(p.value) {
                return Err(Error::InvalidSignature);
            }
        }
        IN_SIGHASH => {
            empty_key(p)?;
            if p.value.len() != 4 {
                return Err(Error::Value);
            }
        }
        IN_REDEEM_SCRIPT | IN_WITNESS_SCRIPT | IN_FINAL_SCRIPTSIG => empty_key(p)?,
        IN_BIP32_DERIVATION => {
            pubkey_key(p.key_data)?;
            key_path(p.value)?;
        }
        IN_FINAL_SCRIPTWITNESS => {
            empty_key(p)?;
            exact(p.value, |r| {
                for _ in 0..r.compact_size()? {
                    r.var_bytes()?;
                }
                Ok(())
            })?;
        }
        0x0A..=0x0D => preimage(p)?, // RIPEMD160, SHA256, HASH160, HASH256
        0x0E..=0x12 => return Err(Error::V2Field),
        IN_TAP_KEY_SIG => {
            empty_key(p)?;
            if !(64..=65).contains(&p.value.len()) {
                return Err(Error::InvalidSignature);
            }
        }
        IN_TAP_SCRIPT_SIG => {
            key_len(p, 64)?;
            xonly(&p.key_data[..32])?;
            if !(64..=65).contains(&p.value.len()) {
                return Err(Error::InvalidSignature);
            }
        }
        IN_TAP_LEAF_SCRIPT => {
            // control block: leaf version | parity, internal key, <= 128
            // 32-byte nodes
            let cb = p.key_data;
            if p.key.len() < 34 || !(p.key.len() - 2).is_multiple_of(32) || (cb.len() - 33) / 32 > 128 {
                return Err(Error::KeySize);
            }
            if !leaf_version_ok(cb[0] & 0xFE) {
                return Err(Error::KeySize);
            }
            xonly(&cb[1..33])?;
            match p.value.last() {
                Some(&v) if leaf_version_ok(v) => {}
                _ => return Err(Error::Value),
            }
        }
        IN_TAP_BIP32_DERIVATION => {
            key_len(p, 32)?;
            xonly(p.key_data)?;
            tap_derivation(p.value)?;
        }
        IN_TAP_INTERNAL_KEY => {
            empty_key(p)?;
            xonly(p.value)?;
        }
        IN_TAP_MERKLE_ROOT => {
            empty_key(p)?;
            if p.value.len() != 32 {
                return Err(Error::Value);
            }
        }
        0x1A => musig_participants(p)?,
        0x1B => {
            musig_identifier(p)?;
            if p.value.len() != 66 {
                return Err(Error::Value);
            }
        }
        0x1C => {
            musig_identifier(p)?;
            if p.value.len() != 32 {
                return Err(Error::Value);
            }
        }
        PROPRIETARY => proprietary_key(p.key_data)?,
        _ => {}
    }
    Ok(())
}

fn check_output_pair(p: &Pair) -> Result<(), Error> {
    match p.key_type {
        OUT_REDEEM_SCRIPT | OUT_WITNESS_SCRIPT => empty_key(p)?,
        OUT_BIP32_DERIVATION => {
            pubkey_key(p.key_data)?;
            key_path(p.value)?;
        }
        0x03 | 0x04 => return Err(Error::V2Field),
        OUT_TAP_INTERNAL_KEY => {
            empty_key(p)?;
            xonly(p.value)?;
        }
        OUT_TAP_TREE => {
            empty_key(p)?;
            tap_tree(p.value)?;
        }
        OUT_TAP_BIP32_DERIVATION => {
            key_len(p, 32)?;
            xonly(p.key_data)?;
            tap_derivation(p.value)?;
        }
        0x08 => musig_participants(p)?,
        PROPRIETARY => proprietary_key(p.key_data)?,
        _ => {}
    }
    Ok(())
}

/// A key origin: master fingerprint and derivation steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySource<'a> {
    pub fingerprint: [u8; 4],
    path: &'a [u8],
}

impl<'a> KeySource<'a> {
    /// From a checked value (fingerprint || steps).
    fn new(v: &'a [u8]) -> Self {
        KeySource {
            fingerprint: [v[0], v[1], v[2], v[3]],
            path: &v[4..],
        }
    }

    pub fn depth(&self) -> usize {
        self.path.len() / 4
    }

    pub fn steps(&self) -> impl Iterator<Item = u32> + 'a {
        self.path
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
    }

    /// As a derivation path, if it is not deeper than BIP-32 support.
    pub fn to_path(&self) -> Option<DerivationPath> {
        let mut steps = [0u32; crate::bip32::MAX_DEPTH];
        if self.depth() > steps.len() {
            return None;
        }
        for (s, v) in steps.iter_mut().zip(self.steps()) {
            *s = v;
        }
        DerivationPath::from_steps(&steps[..self.depth()]).ok()
    }
}

/// A Taproot BIP32 derivation: x-only key, leaf hashes, origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TapDerivation<'a> {
    pub xonly: [u8; 32],
    /// Concatenated 32-byte leaf hashes (empty for the key path only).
    pub leaf_hashes: &'a [u8],
    pub source: KeySource<'a>,
}

fn find<'a>(map: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    Pairs { r: Reader::new(map) }
        .find(|p| p.key == key)
        .map(|p| p.value)
}

fn arr32(v: &[u8]) -> Option<[u8; 32]> {
    v.try_into().ok()
}

fn derivations<'a>(map: &'a [u8], t: u64) -> impl Iterator<Item = (&'a [u8], KeySource<'a>)> {
    Pairs { r: Reader::new(map) }
        .filter(move |p| p.key_type == t)
        .map(|p| (p.key_data, KeySource::new(p.value)))
}

fn tap_derivations<'a>(map: &'a [u8], t: u64) -> impl Iterator<Item = TapDerivation<'a>> {
    Pairs { r: Reader::new(map) }
        .filter(move |p| p.key_type == t)
        .filter_map(|p| {
            let (leaf_hashes, source) = tap_derivation(p.value).ok()?;
            Some(TapDerivation {
                xonly: arr32(p.key_data)?,
                leaf_hashes,
                source,
            })
        })
}

/// An input map (checked).
#[derive(Clone, Copy, Debug)]
pub struct InputMap<'a> {
    map: &'a [u8],
}

impl<'a> InputMap<'a> {
    pub fn pairs(&self) -> Pairs<'a> {
        Pairs {
            r: Reader::new(self.map),
        }
    }

    pub fn non_witness_utxo(&self) -> Option<Tx<'a>> {
        Tx::parse(find(self.map, &[IN_NON_WITNESS_UTXO as u8])?).ok()
    }

    pub fn witness_utxo(&self) -> Option<TxOut<'a>> {
        witness_utxo(find(self.map, &[IN_WITNESS_UTXO as u8])?).ok()
    }

    pub fn sighash_type(&self) -> Option<u32> {
        let v = find(self.map, &[IN_SIGHASH as u8])?;
        Some(u32::from_le_bytes(v.try_into().ok()?))
    }

    pub fn redeem_script(&self) -> Option<&'a [u8]> {
        find(self.map, &[IN_REDEEM_SCRIPT as u8])
    }

    pub fn witness_script(&self) -> Option<&'a [u8]> {
        find(self.map, &[IN_WITNESS_SCRIPT as u8])
    }

    pub fn final_script_sig(&self) -> Option<&'a [u8]> {
        find(self.map, &[IN_FINAL_SCRIPTSIG as u8])
    }

    /// Raw value (item count and items).
    pub fn final_script_witness(&self) -> Option<&'a [u8]> {
        find(self.map, &[IN_FINAL_SCRIPTWITNESS as u8])
    }

    pub fn is_finalized(&self) -> bool {
        self.final_script_sig().is_some() || self.final_script_witness().is_some()
    }

    /// (public key, signature with sighash byte)
    pub fn partial_sigs(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        self.pairs()
            .filter(|p| p.key_type == IN_PARTIAL_SIG)
            .map(|p| (p.key_data, p.value))
    }

    /// (public key, origin)
    pub fn bip32_derivations(&self) -> impl Iterator<Item = (&'a [u8], KeySource<'a>)> {
        derivations(self.map, IN_BIP32_DERIVATION)
    }

    pub fn tap_key_sig(&self) -> Option<&'a [u8]> {
        find(self.map, &[IN_TAP_KEY_SIG as u8])
    }

    pub fn tap_internal_key(&self) -> Option<[u8; 32]> {
        arr32(find(self.map, &[IN_TAP_INTERNAL_KEY as u8])?)
    }

    pub fn tap_merkle_root(&self) -> Option<[u8; 32]> {
        arr32(find(self.map, &[IN_TAP_MERKLE_ROOT as u8])?)
    }

    pub fn tap_bip32_derivations(&self) -> impl Iterator<Item = TapDerivation<'a>> {
        tap_derivations(self.map, IN_TAP_BIP32_DERIVATION)
    }

    /// Any script-path data (leaf scripts or script signatures).
    pub fn has_tap_scripts(&self) -> bool {
        self.pairs()
            .any(|p| p.key_type == IN_TAP_LEAF_SCRIPT || p.key_type == IN_TAP_SCRIPT_SIG)
    }
}

/// An output map (checked).
#[derive(Clone, Copy, Debug)]
pub struct OutputMap<'a> {
    map: &'a [u8],
}

impl<'a> OutputMap<'a> {
    pub fn pairs(&self) -> Pairs<'a> {
        Pairs {
            r: Reader::new(self.map),
        }
    }

    pub fn redeem_script(&self) -> Option<&'a [u8]> {
        find(self.map, &[OUT_REDEEM_SCRIPT as u8])
    }

    pub fn witness_script(&self) -> Option<&'a [u8]> {
        find(self.map, &[OUT_WITNESS_SCRIPT as u8])
    }

    pub fn bip32_derivations(&self) -> impl Iterator<Item = (&'a [u8], KeySource<'a>)> {
        derivations(self.map, OUT_BIP32_DERIVATION)
    }

    pub fn tap_internal_key(&self) -> Option<[u8; 32]> {
        arr32(find(self.map, &[OUT_TAP_INTERNAL_KEY as u8])?)
    }

    pub fn tap_tree(&self) -> Option<&'a [u8]> {
        find(self.map, &[OUT_TAP_TREE as u8])
    }

    pub fn tap_bip32_derivations(&self) -> impl Iterator<Item = TapDerivation<'a>> {
        tap_derivations(self.map, OUT_TAP_BIP32_DERIVATION)
    }
}

/// A parsed PSBT v0 (a view of the original bytes).
#[derive(Clone, Copy, Debug)]
pub struct Psbt<'a> {
    raw: &'a [u8],
    pub tx: Tx<'a>,
    global: &'a [u8],
    inputs_at: usize,
    outputs_at: usize,
}

fn maps(raw: &[u8], at: usize, n: usize) -> impl Iterator<Item = &[u8]> {
    let mut r = Reader::new(raw);
    let ok = r.take(at).is_ok();
    (0..if ok { n } else { 0 }).map_while(move |_| skip_map(&mut r, raw).ok())
}

impl<'a> Psbt<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Psbt<'a>, Error> {
        if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
            return Err(Error::Magic);
        }
        let mut r = Reader::new(raw);
        r.take(MAGIC.len())?;
        // global map
        let global = read_map(&mut r, raw)?;
        let mut tx = None;
        let mut version = 0u32;
        let mut v2_fields = false;
        for p in (Pairs {
            r: Reader::new(global),
        }) {
            match p.key_type {
                GLOBAL_UNSIGNED_TX => {
                    empty_key(&p)?;
                    let t = Tx::parse(p.value).map_err(|_| Error::UnsignedTx)?;
                    if t.has_witness() || t.inputs().any(|i| !i.script_sig.is_empty()) {
                        return Err(Error::UnsignedTx);
                    }
                    tx = Some(t);
                }
                GLOBAL_XPUB => {
                    key_len(&p, 78)?;
                    // BIP-32 version bytes: xpub or tpub
                    if p.key_data[..4] != [0x04, 0x88, 0xB2, 0x1E]
                        && p.key_data[..4] != [0x04, 0x35, 0x87, 0xCF]
                    {
                        return Err(Error::KeySize);
                    }
                    compressed_pubkey(&p.key_data[45..])?;
                    key_path(p.value)?;
                }
                0x02..=0x06 => v2_fields = true,
                GLOBAL_VERSION => {
                    empty_key(&p)?;
                    let v: [u8; 4] = p.value.try_into().map_err(|_| Error::Value)?;
                    version = u32::from_le_bytes(v);
                }
                PROPRIETARY => proprietary_key(p.key_data)?,
                _ => {}
            }
        }
        if version != 0 {
            return Err(Error::UnsupportedVersion);
        }
        if v2_fields {
            return Err(Error::V2Field);
        }
        let tx = tx.ok_or(Error::NoUnsignedTx)?;
        // input maps
        let inputs_at = r.pos();
        for txin in tx.inputs() {
            if r.remaining() == 0 {
                return Err(Error::MapCount);
            }
            let map = read_map(&mut r, raw)?;
            for p in (Pairs { r: Reader::new(map) }) {
                check_input_pair(&p)?;
            }
            if let Some(utxo) = (InputMap { map }).non_witness_utxo() {
                if utxo.txid() != txin.txid {
                    return Err(Error::UtxoMismatch);
                }
                if txin.vout as usize >= utxo.n_outputs() {
                    return Err(Error::UtxoIndex);
                }
            }
        }
        // output maps
        let outputs_at = r.pos();
        for _ in 0..tx.n_outputs() {
            if r.remaining() == 0 {
                return Err(Error::MapCount);
            }
            let map = read_map(&mut r, raw)?;
            for p in (Pairs { r: Reader::new(map) }) {
                check_output_pair(&p)?;
            }
        }
        if r.remaining() != 0 {
            return Err(Error::TrailingData);
        }
        Ok(Psbt {
            raw,
            tx,
            global,
            inputs_at,
            outputs_at,
        })
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn global_pairs(&self) -> Pairs<'a> {
        Pairs {
            r: Reader::new(self.global),
        }
    }

    /// Global xpubs: (78-byte serialized xpub, origin).
    pub fn xpubs(&self) -> impl Iterator<Item = (&'a [u8], KeySource<'a>)> {
        derivations(self.global, GLOBAL_XPUB)
    }

    pub fn inputs(&self) -> impl Iterator<Item = InputMap<'a>> {
        maps(self.raw, self.inputs_at, self.tx.n_inputs()).map(|map| InputMap { map })
    }

    pub fn outputs(&self) -> impl Iterator<Item = OutputMap<'a>> {
        maps(self.raw, self.outputs_at, self.tx.n_outputs()).map(|map| OutputMap { map })
    }

    pub fn input(&self, i: usize) -> Option<InputMap<'a>> {
        self.inputs().nth(i)
    }

    pub fn output(&self, i: usize) -> Option<OutputMap<'a>> {
        self.outputs().nth(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn depths_ok(depths: &[u8]) -> bool {
        let mut v = [0u8; 64];
        let mut n = 0;
        for &d in depths {
            v[n] = d;
            v[n + 1] = 0xC0;
            v[n + 2] = 1;
            v[n + 3] = 0x51;
            n += 4;
        }
        tap_tree(&v[..n]).is_ok()
    }

    #[test]
    fn tap_tree_shapes() {
        assert!(depths_ok(&[0]));
        assert!(depths_ok(&[1, 1]));
        assert!(depths_ok(&[1, 2, 2]));
        assert!(depths_ok(&[2, 2, 1]));
        assert!(depths_ok(&[2, 2, 2, 2]));
        assert!(!depths_ok(&[1]));
        assert!(!depths_ok(&[0, 0]));
        assert!(!depths_ok(&[1, 1, 1]));
        assert!(!depths_ok(&[2, 1, 2]));
        assert!(!depths_ok(&[]));
    }

    #[test]
    fn signature_encoding() {
        // minimal valid: r = 1, s = 1, SIGHASH_ALL
        let ok = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01];
        assert!(is_valid_ecdsa_sig_encoding(&ok));
        let mut bad = ok;
        bad[8] = 0x04; // undefined hash type
        assert!(!is_valid_ecdsa_sig_encoding(&bad));
        let mut bad = ok;
        bad[4] = 0x80; // negative r
        assert!(!is_valid_ecdsa_sig_encoding(&bad));
        assert!(!is_valid_ecdsa_sig_encoding(&ok[..8]));
    }
}
