//! Multisig wallets: `wsh(sortedmulti(...))` and `sh(wsh(sortedmulti(...)))`
//! with every key an origin-tagged xpub ranged over `<0;1>/*`.
//!
//! The wallet record is what the signer trusts. Scripts and addresses are
//! always rebuilt from it; nothing a PSBT says about keys is used except to
//! find the (branch, index) to rebuild at.

pub mod descriptor;

use crate::address::MAX_ADDRESS_LEN;
use crate::bip32::{self, DerivationPath, KeyVersion, Xpub, HARDENED};
use crate::validate::script::p2sh;
use crate::Network;
use bp_crypto::secp256k1::PublicKey;
use bp_crypto::Sha256;

/// Most keys in a wallet (P2SH redeem-script limit; Coldcard uses the same).
pub const MAX_KEYS: usize = 15;
/// `OP_m` + 15 × (push 33) + `OP_n` + `OP_CHECKMULTISIG`.
pub const MAX_WITNESS_SCRIPT: usize = 3 + MAX_KEYS * 34;
/// Longest wallet name kept.
pub const MAX_NAME: usize = 20;

/// How the multisig script is wrapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsScript {
    /// P2WSH (BIP-48 script type 2').
    Wsh,
    /// P2SH-P2WSH (BIP-48 script type 1').
    ShWsh,
}

impl MsScript {
    /// The last step of the BIP-48 account path.
    pub const fn bip48_type(self) -> u32 {
        match self {
            MsScript::Wsh => 2,
            MsScript::ShWsh => 1,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            MsScript::Wsh => "P2WSH",
            MsScript::ShWsh => "P2SH-P2WSH",
        }
    }

    /// The SLIP-132 version that names this script type.
    pub const fn key_version(self) -> KeyVersion {
        match self {
            MsScript::Wsh => KeyVersion::MultiZ,
            MsScript::ShWsh => KeyVersion::MultiY,
        }
    }

    /// `m/48'/coin'/account'/type'`
    pub fn account_path(self, net: Network, account: u32) -> DerivationPath {
        DerivationPath::from_steps(&[
            48 | HARDENED,
            net.coin_type() | HARDENED,
            (account & !HARDENED) | HARDENED,
            self.bip48_type() | HARDENED,
        ])
        .expect("depth 4")
    }
}

/// One cosigner: `[fingerprint/origin]xpub`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cosigner {
    pub fingerprint: [u8; 4],
    pub origin: DerivationPath,
    pub xpub: Xpub,
    /// The version the key was written with (SLIP-132 `Zpub` and the like).
    pub version: KeyVersion,
}

impl Cosigner {
    /// Bytes that identify the key regardless of how it was written.
    fn canonical_key(&self) -> [u8; 65] {
        let mut b = [0u8; 65];
        b[..33].copy_from_slice(&self.xpub.key.serialize());
        b[33..].copy_from_slice(&self.xpub.chain_code);
        b
    }
}

/// A multisig wallet record. Keys stay in the order they were given (so a
/// re-exported descriptor matches the coordinator's); everything that
/// depends on identity sorts them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wallet {
    /// `true` for tpub-family keys (testnet, signet, regtest).
    pub test: bool,
    pub script: MsScript,
    pub m: u8,
    n: u8,
    keys: [Cosigner; MAX_KEYS],
    name: [u8; MAX_NAME],
    name_len: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeriveError {
    /// Branch other than 0 (receive) or 1 (change), or a hardened index.
    Index,
    /// A child key outside the curve order (probability ~2^-127).
    Key,
}

/// Placeholder used to fill the unused key slots.
const NO_KEY: Cosigner = Cosigner {
    fingerprint: [0; 4],
    origin: DerivationPath::new(),
    xpub: Xpub {
        depth: 0,
        parent_fingerprint: [0; 4],
        child_number: 0,
        chain_code: [0; 32],
        key: PublicKey::GENERATOR,
    },
    version: KeyVersion::X,
};

impl Wallet {
    /// A wallet from parts; `None` if the counts are out of range. The rules
    /// that make a wallet acceptable (our key once, no duplicates, network)
    /// live in registration, not here.
    pub fn new(test: bool, script: MsScript, m: u8, keys: &[Cosigner]) -> Option<Wallet> {
        let n = keys.len();
        if n == 0 || n > MAX_KEYS || m == 0 || m as usize > n {
            return None;
        }
        let mut w = Wallet {
            test,
            script,
            m,
            n: n as u8,
            keys: [NO_KEY; MAX_KEYS],
            name: [0; MAX_NAME],
            name_len: 0,
        };
        w.keys[..n].copy_from_slice(keys);
        Some(w)
    }

    pub fn n(&self) -> u8 {
        self.n
    }

    pub fn keys(&self) -> &[Cosigner] {
        &self.keys[..self.n as usize]
    }

    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("")
    }

    /// Keep printable ASCII only, at most `MAX_NAME` characters.
    pub fn set_name(&mut self, name: &str) {
        let mut n = 0;
        for &b in name.trim().as_bytes() {
            if n == MAX_NAME {
                break;
            }
            if (0x20..0x7F).contains(&b) {
                self.name[n] = b;
                n += 1;
            }
        }
        self.name_len = n as u8;
    }

    /// Indexes into `keys()` sorted by (public key, chain code): the order
    /// identity uses.
    pub fn sorted_order(&self) -> [u8; MAX_KEYS] {
        let n = self.n as usize;
        let mut order = [0u8; MAX_KEYS];
        for (i, o) in order.iter_mut().enumerate().take(n) {
            *o = i as u8;
        }
        // insertion sort: n ≤ 15
        for i in 1..n {
            let mut j = i;
            while j > 0
                && self.keys[order[j - 1] as usize].canonical_key()
                    > self.keys[order[j] as usize].canonical_key()
            {
                order.swap(j - 1, j);
                j -= 1;
            }
        }
        order
    }

    /// Canonical bytes: everything that decides the scripts, nothing
    /// cosmetic (name, key order, how keys were written). Two records with
    /// the same bytes spend and receive identically.
    pub fn canonical(&self, out: &mut dyn FnMut(&[u8])) {
        out(b"BPMS1");
        out(&[self.test as u8, self.script.bip48_type() as u8, self.m, self.n]);
        let order = self.sorted_order();
        for &i in &order[..self.n as usize] {
            let k = &self.keys[i as usize];
            out(&k.fingerprint);
            let steps = k.origin.steps();
            out(&[steps.len() as u8]);
            for s in steps {
                out(&s.to_be_bytes());
            }
            out(&k.canonical_key());
        }
    }

    /// SHA-256 of the canonical bytes (for duplicate checks).
    pub fn id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        self.canonical(&mut |b| h.update(b));
        h.finalize()
    }

    /// The keys of one branch, ready to derive addresses from.
    pub fn branch(&self, branch: u32) -> Result<Branch, DeriveError> {
        if branch > 1 {
            return Err(DeriveError::Index);
        }
        let mut keys = [NO_KEY.xpub; MAX_KEYS];
        for (k, c) in keys.iter_mut().zip(self.keys()) {
            *k = c.xpub.derive_child(branch).map_err(|_| DeriveError::Key)?;
        }
        Ok(Branch {
            keys,
            n: self.n,
            m: self.m,
            script: self.script,
        })
    }

    /// The scripts at `branch/index`.
    pub fn derive(&self, branch: u32, index: u32) -> Result<Scripts, DeriveError> {
        self.branch(branch)?.derive(index)
    }
}

/// One branch's child xpubs (deriving them once makes address scans cheap).
#[derive(Clone)]
pub struct Branch {
    keys: [Xpub; MAX_KEYS],
    n: u8,
    m: u8,
    script: MsScript,
}

/// The scripts of one address.
#[derive(Clone)]
pub struct Scripts {
    ws: [u8; MAX_WITNESS_SCRIPT],
    ws_len: usize,
    /// The compressed keys, in script (BIP-67) order.
    pub pubkeys: [[u8; 33]; MAX_KEYS],
    pub n: u8,
    spk: [u8; 34],
    spk_len: usize,
}

impl Branch {
    pub fn derive(&self, index: u32) -> Result<Scripts, DeriveError> {
        if index & HARDENED != 0 {
            return Err(DeriveError::Index);
        }
        let n = self.n as usize;
        let mut pubkeys = [[0u8; 33]; MAX_KEYS];
        for (p, k) in pubkeys.iter_mut().zip(&self.keys[..n]) {
            *p = k
                .derive_child(index)
                .map_err(|_| DeriveError::Key)?
                .key
                .serialize();
        }
        pubkeys[..n].sort_unstable();
        let mut ws = [0u8; MAX_WITNESS_SCRIPT];
        let ws_len = multisig_script(self.m, &pubkeys[..n], &mut ws);
        let mut spk = [0u8; 34];
        let program = Sha256::digest(&ws[..ws_len]);
        spk[1] = 0x20;
        spk[2..].copy_from_slice(&program);
        let spk_len = match self.script {
            MsScript::Wsh => 34,
            MsScript::ShWsh => {
                let outer = p2sh(&spk);
                spk[..23].copy_from_slice(&outer);
                23
            }
        };
        Ok(Scripts {
            ws,
            ws_len,
            pubkeys,
            n: self.n,
            spk,
            spk_len,
        })
    }
}

impl Scripts {
    /// The witness script (`OP_m <keys> OP_n OP_CHECKMULTISIG`).
    pub fn witness_script(&self) -> &[u8] {
        &self.ws[..self.ws_len]
    }

    /// P2SH-P2WSH only: the redeem script `OP_0 <sha256(ws)>`.
    pub fn redeem_script(&self) -> [u8; 34] {
        let mut r = [0u8; 34];
        r[1] = 0x20;
        r[2..].copy_from_slice(&Sha256::digest(self.witness_script()));
        r
    }

    pub fn script_pubkey(&self) -> &[u8] {
        &self.spk[..self.spk_len]
    }

    pub fn pubkeys(&self) -> &[[u8; 33]] {
        &self.pubkeys[..self.n as usize]
    }

    pub fn address(&self, net: Network, out: &mut [u8; MAX_ADDRESS_LEN]) -> usize {
        crate::address::from_script(self.script_pubkey(), net, out).expect("P2SH or P2WSH")
    }
}

/// `OP_m <k1> … <kn> OP_n OP_CHECKMULTISIG`; returns its length.
pub fn multisig_script(m: u8, keys: &[[u8; 33]], out: &mut [u8; MAX_WITNESS_SCRIPT]) -> usize {
    let mut i = 0;
    out[i] = 0x50 + m;
    i += 1;
    for k in keys {
        out[i] = 33;
        out[i + 1..i + 34].copy_from_slice(k);
        i += 34;
    }
    out[i] = 0x50 + keys.len() as u8;
    out[i + 1] = 0xAE;
    i + 2
}

/// Parse an exact `OP_m <33-byte key>×n OP_n OP_CHECKMULTISIG` with
/// 1 ≤ m ≤ n ≤ 15; anything else (other pushes, uncompressed keys,
/// trailing bytes) is `None`. Returns (m, keys in script order).
pub fn parse_multisig_script(s: &[u8]) -> Option<(u8, [[u8; 33]; MAX_KEYS], u8)> {
    let (&first, rest) = s.split_first()?;
    if !(0x51..=0x5F).contains(&first) {
        return None;
    }
    let m = first - 0x50;
    let mut keys = [[0u8; 33]; MAX_KEYS];
    let mut n = 0usize;
    let mut r = rest;
    while let [33, body @ ..] = r {
        if n == MAX_KEYS || body.len() < 33 {
            return None;
        }
        let k = &body[..33];
        if k[0] != 0x02 && k[0] != 0x03 {
            return None;
        }
        keys[n].copy_from_slice(k);
        n += 1;
        r = &body[33..];
    }
    match r {
        [op_n, 0xAE] if *op_n == 0x50 + n as u8 && n >= m as usize && n >= 1 => Some((m, keys, n as u8)),
        _ => None,
    }
}

/// BIP-67: keys strictly increasing (also rules out duplicates).
pub fn is_sorted(keys: &[[u8; 33]]) -> bool {
    keys.windows(2).all(|w| w[0] < w[1])
}

/// The xpub version family name for messages.
pub fn version_name(v: KeyVersion, test: bool) -> &'static str {
    match (v, test) {
        (KeyVersion::X, false) => "xpub",
        (KeyVersion::X, true) => "tpub",
        (KeyVersion::Y, false) => "ypub",
        (KeyVersion::Y, true) => "upub",
        (KeyVersion::Z, false) => "zpub",
        (KeyVersion::Z, true) => "vpub",
        (KeyVersion::MultiY, false) => "Ypub",
        (KeyVersion::MultiY, true) => "Upub",
        (KeyVersion::MultiZ, false) => "Zpub",
        (KeyVersion::MultiZ, true) => "Vpub",
    }
}

/// Decode an extended public key in any supported version.
pub fn decode_xpub(s: &str) -> Result<(Xpub, bool, KeyVersion), bip32::Error> {
    let (x, net, v) = Xpub::decode(s)?;
    Ok((x, net != Network::Mainnet, v))
}
