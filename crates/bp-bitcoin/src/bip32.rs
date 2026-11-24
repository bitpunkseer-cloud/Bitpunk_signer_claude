//! BIP-32 hierarchical deterministic keys, with SLIP-132 version bytes.

use crate::base58;
use crate::Network;
use bp_crypto::hashes::hash160;
use bp_crypto::secp256k1::{PublicKey, Scalar, SecretKey};
use bp_crypto::secret::wipe;
use bp_crypto::HmacSha512;
use core::fmt;

pub const HARDENED: u32 = 0x8000_0000;
pub const MAX_DEPTH: usize = 10;
/// Base58Check of a 78-byte extended key is 111 characters.
pub const XKEY_LEN: usize = 111;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Derived key outside [1, n) (probability ~2^-127); use the next index.
    InvalidChildKey,
    /// Master key outside [1, n): reject the seed.
    InvalidMasterKey,
    HardenedFromPublic,
    InvalidPath,
    InvalidEncoding,
    UnknownVersion,
    InvalidKey,
}

/// Version bytes. SLIP-132: y = P2SH-P2WPKH, z = P2WPKH, and for multisig
/// Y (testnet U) = P2SH-P2WSH, Z (testnet V) = P2WSH.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyVersion {
    X,
    Y,
    Z,
    MultiY,
    MultiZ,
}

impl KeyVersion {
    pub const fn public(self, net: Network) -> [u8; 4] {
        let main = matches!(net, Network::Mainnet);
        let v: u32 = match (self, main) {
            (KeyVersion::X, true) => 0x0488_B21E,
            (KeyVersion::Y, true) => 0x049D_7CB2,
            (KeyVersion::Z, true) => 0x04B2_4746,
            (KeyVersion::MultiY, true) => 0x0295_B43F,
            (KeyVersion::MultiZ, true) => 0x02AA_7ED3,
            (KeyVersion::X, false) => 0x0435_87CF,
            (KeyVersion::Y, false) => 0x044A_5262,
            (KeyVersion::Z, false) => 0x045F_1CF6,
            (KeyVersion::MultiY, false) => 0x0242_89EF,
            (KeyVersion::MultiZ, false) => 0x0257_5483,
        };
        v.to_be_bytes()
    }

    pub const fn private(self, net: Network) -> [u8; 4] {
        let main = matches!(net, Network::Mainnet);
        let v: u32 = match (self, main) {
            (KeyVersion::X, true) => 0x0488_ADE4,
            (KeyVersion::Y, true) => 0x049D_7878,
            (KeyVersion::Z, true) => 0x04B2_430C,
            (KeyVersion::MultiY, true) => 0x0295_B005,
            (KeyVersion::MultiZ, true) => 0x02AA_7A99,
            (KeyVersion::X, false) => 0x0435_8394,
            (KeyVersion::Y, false) => 0x044A_4E28,
            (KeyVersion::Z, false) => 0x045F_18BC,
            (KeyVersion::MultiY, false) => 0x0242_85B5,
            (KeyVersion::MultiZ, false) => 0x0257_5048,
        };
        v.to_be_bytes()
    }
}

/// A derivation path such as `m/84'/0'/0'`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DerivationPath {
    steps: [u32; MAX_DEPTH],
    len: usize,
}

impl DerivationPath {
    pub const fn new() -> Self {
        Self {
            steps: [0; MAX_DEPTH],
            len: 0,
        }
    }

    pub fn from_steps(steps: &[u32]) -> Result<Self, Error> {
        if steps.len() > MAX_DEPTH {
            return Err(Error::InvalidPath);
        }
        let mut p = Self::new();
        p.steps[..steps.len()].copy_from_slice(steps);
        p.len = steps.len();
        Ok(p)
    }

    /// Parse `m/84'/0'/0'/0/1` (apostrophe or `h` marks hardened).
    pub fn parse(s: &str) -> Result<Self, Error> {
        let mut parts = s.split('/');
        if parts.next() != Some("m") {
            return Err(Error::InvalidPath);
        }
        let mut p = Self::new();
        for part in parts {
            let (num, hard) = match part.strip_suffix('\'').or_else(|| part.strip_suffix('h')) {
                Some(n) => (n, true),
                None => (part, false),
            };
            let v: u32 = num.parse().map_err(|_| Error::InvalidPath)?;
            if v >= HARDENED || p.len >= MAX_DEPTH {
                return Err(Error::InvalidPath);
            }
            p.steps[p.len] = if hard { v | HARDENED } else { v };
            p.len += 1;
        }
        Ok(p)
    }

    pub fn steps(&self) -> &[u32] {
        &self.steps[..self.len]
    }

    pub fn child(&self, i: u32) -> Result<Self, Error> {
        let mut p = *self;
        if p.len >= MAX_DEPTH {
            return Err(Error::InvalidPath);
        }
        p.steps[p.len] = i;
        p.len += 1;
        Ok(p)
    }
}

impl Default for DerivationPath {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for &s in self.steps() {
            if s & HARDENED != 0 {
                write!(f, "/{}'", s & !HARDENED)?;
            } else {
                write!(f, "/{s}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub fn fingerprint(pk: &PublicKey) -> [u8; 4] {
    let h = hash160(&pk.serialize());
    [h[0], h[1], h[2], h[3]]
}

/// Extended private key. The key and chain code are wiped on drop.
#[derive(Clone)]
pub struct Xpriv {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    chain_code: [u8; 32],
    key: SecretKey,
}

impl Xpriv {
    /// Master key from a BIP-39 seed (16..=64 bytes).
    pub fn master(seed: &[u8]) -> Result<Self, Error> {
        let mut i = HmacSha512::mac(b"Bitcoin seed", seed);
        let r = Self::from_i(&i, 0, [0; 4], 0).map_err(|_| Error::InvalidMasterKey);
        wipe(&mut i);
        r
    }

    /// A root key (depth 0) from a chain code and a private key, as BIP-85
    /// XPRV builds it. Fails if the key is zero or not below the order.
    pub fn from_parts(chain_code: &[u8; 32], key: &[u8; 32]) -> Result<Self, Error> {
        let key = SecretKey::from_bytes(key).ok_or(Error::InvalidChildKey)?;
        Ok(Self {
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0,
            chain_code: *chain_code,
            key,
        })
    }

    fn from_i(i: &[u8; 64], depth: u8, parent: [u8; 4], child: u32) -> Result<Self, Error> {
        let key = SecretKey::from_bytes(i[..32].try_into().expect("32")).ok_or(Error::InvalidChildKey)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        Ok(Self {
            depth,
            parent_fingerprint: parent,
            child_number: child,
            chain_code,
            key,
        })
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.key
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        fingerprint(&self.public_key())
    }

    /// CKDpriv.
    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
        let mut mac = HmacSha512::new(&self.chain_code);
        let pk = self.public_key();
        if index & HARDENED != 0 {
            let mut k = self.key.to_bytes();
            mac.update(&[0]);
            mac.update(&k);
            wipe(&mut k);
        } else {
            mac.update(&pk.serialize());
        }
        mac.update(&index.to_be_bytes());
        let mut i = mac.finalize();
        let result = (|| {
            let il = Scalar::from_bytes(i[..32].try_into().expect("32")).ok_or(Error::InvalidChildKey)?;
            let child = SecretKey::from_scalar(il.add(self.key.scalar())).ok_or(Error::InvalidChildKey)?;
            let mut chain_code = [0u8; 32];
            chain_code.copy_from_slice(&i[32..]);
            Ok(Self {
                depth: self.depth.checked_add(1).ok_or(Error::InvalidPath)?,
                parent_fingerprint: fingerprint(&pk),
                child_number: index,
                chain_code,
                key: child,
            })
        })();
        wipe(&mut i);
        result
    }

    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Error> {
        let mut k = self.clone();
        for &step in path.steps() {
            k = k.derive_child(step)?;
        }
        Ok(k)
    }

    /// A 32-byte symmetric key bound to this key and `label` (domain
    /// separation): HMAC-SHA512(label, chain code ‖ private key), first half.
    /// Nothing about the key can be learned from it.
    pub fn symmetric_key(&self, label: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha512::new(label);
        let mut k = self.key.to_bytes();
        mac.update(&self.chain_code);
        mac.update(&k);
        wipe(&mut k);
        let mut full = mac.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&full[..32]);
        wipe(&mut full);
        out
    }

    pub fn to_xpub(&self) -> Xpub {
        Xpub {
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            chain_code: self.chain_code,
            key: self.public_key(),
        }
    }

    fn header(&self, version: [u8; 4], out: &mut [u8; 78]) {
        out[..4].copy_from_slice(&version);
        out[4] = self.depth;
        out[5..9].copy_from_slice(&self.parent_fingerprint);
        out[9..13].copy_from_slice(&self.child_number.to_be_bytes());
        out[13..45].copy_from_slice(&self.chain_code);
    }

    /// Base58Check serialization with the given version bytes.
    pub fn encode(&self, version: [u8; 4], out: &mut [u8; XKEY_LEN]) -> usize {
        let mut raw = [0u8; 78];
        self.header(version, &mut raw);
        raw[45] = 0;
        let mut k = self.key.to_bytes();
        raw[46..].copy_from_slice(&k);
        let n = base58::encode_check(&raw, out).expect("fits");
        wipe(&mut k);
        wipe(&mut raw);
        n
    }

    /// Parse an xprv/tprv/yprv/zprv (any known private version).
    pub fn decode(s: &str) -> Result<(Self, Network, KeyVersion), Error> {
        let mut raw = [0u8; 82];
        let n = base58::decode_check(s, &mut raw).map_err(|_| Error::InvalidEncoding)?;
        let r = (|| {
            if n != 78 {
                return Err(Error::InvalidEncoding);
            }
            let (net, kv) = lookup_version(&raw[..4], false)?;
            check_header(&raw)?;
            if raw[45] != 0 {
                return Err(Error::InvalidKey);
            }
            let key = SecretKey::from_bytes(raw[46..78].try_into().expect("32")).ok_or(Error::InvalidKey)?;
            let mut chain_code = [0u8; 32];
            chain_code.copy_from_slice(&raw[13..45]);
            let x = Xpriv {
                depth: raw[4],
                parent_fingerprint: raw[5..9].try_into().expect("4"),
                child_number: u32::from_be_bytes(raw[9..13].try_into().expect("4")),
                chain_code,
                key,
            };
            Ok((x, net, kv))
        })();
        wipe(&mut raw);
        r
    }
}

impl Drop for Xpriv {
    fn drop(&mut self) {
        wipe(&mut self.chain_code);
    }
}

impl fmt::Debug for Xpriv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Xpriv(depth {}, ***)", self.depth)
    }
}

/// Extended public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Xpub {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub key: PublicKey,
}

impl Xpub {
    pub fn fingerprint(&self) -> [u8; 4] {
        fingerprint(&self.key)
    }

    /// CKDpub (non-hardened only).
    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
        if index & HARDENED != 0 {
            return Err(Error::HardenedFromPublic);
        }
        let mut mac = HmacSha512::new(&self.chain_code);
        mac.update(&self.key.serialize());
        mac.update(&index.to_be_bytes());
        let i = mac.finalize();
        let il = Scalar::from_bytes(i[..32].try_into().expect("32")).ok_or(Error::InvalidChildKey)?;
        let key = self.key.add_tweak(&il).ok_or(Error::InvalidChildKey)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        Ok(Self {
            depth: self.depth.checked_add(1).ok_or(Error::InvalidPath)?,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code,
            key,
        })
    }

    pub fn encode(&self, version: [u8; 4], out: &mut [u8; XKEY_LEN]) -> usize {
        let mut raw = [0u8; 78];
        raw[..4].copy_from_slice(&version);
        raw[4] = self.depth;
        raw[5..9].copy_from_slice(&self.parent_fingerprint);
        raw[9..13].copy_from_slice(&self.child_number.to_be_bytes());
        raw[13..45].copy_from_slice(&self.chain_code);
        raw[45..].copy_from_slice(&self.key.serialize());
        base58::encode_check(&raw, out).expect("fits")
    }

    pub fn decode(s: &str) -> Result<(Self, Network, KeyVersion), Error> {
        let mut raw = [0u8; 82];
        let n = base58::decode_check(s, &mut raw).map_err(|_| Error::InvalidEncoding)?;
        if n != 78 {
            return Err(Error::InvalidEncoding);
        }
        let (net, kv) = lookup_version(&raw[..4], true)?;
        check_header(&raw)?;
        if raw[45] != 0x02 && raw[45] != 0x03 {
            return Err(Error::InvalidKey);
        }
        let key = PublicKey::parse(&raw[45..78]).ok_or(Error::InvalidKey)?;
        Ok((
            Xpub {
                depth: raw[4],
                parent_fingerprint: raw[5..9].try_into().expect("4"),
                child_number: u32::from_be_bytes(raw[9..13].try_into().expect("4")),
                chain_code: raw[13..45].try_into().expect("32"),
                key,
            },
            net,
            kv,
        ))
    }
}

fn lookup_version(v: &[u8], public: bool) -> Result<(Network, KeyVersion), Error> {
    for net in [Network::Mainnet, Network::Testnet] {
        for kv in [
            KeyVersion::X,
            KeyVersion::Y,
            KeyVersion::Z,
            KeyVersion::MultiY,
            KeyVersion::MultiZ,
        ] {
            let candidate = if public { kv.public(net) } else { kv.private(net) };
            if v == candidate {
                return Ok((net, kv));
            }
        }
    }
    Err(Error::UnknownVersion)
}

/// Depth 0 must have a zero parent fingerprint and child number.
fn check_header(raw: &[u8; 82]) -> Result<(), Error> {
    if raw[4] == 0 && (raw[5..9] != [0; 4] || raw[9..13] != [0; 4]) {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}
