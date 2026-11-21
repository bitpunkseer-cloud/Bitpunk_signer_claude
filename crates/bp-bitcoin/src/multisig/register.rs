//! Registration: the rules a wallet must pass before the signer will touch
//! it, the wallet code that ties a registration to the seed, and the
//! session registry.
//!
//! Rules (M7 plan R1–R11): our key exactly once and really ours; no key of
//! ours under another fingerprint; no duplicate keys or fingerprints; xpub
//! depth, child number and parent fingerprint consistent with the origin;
//! one network; SLIP-132 versions that agree with the script type; coin
//! type matching the network. Non-standard paths are warnings.
//!
//! The wallet code is HMAC-SHA256 over the wallet's canonical bytes with a
//! key only the seed can produce, cut to 40 bits. Without the seed nobody
//! can find a different wallet with the same code, so a short code typed by
//! the user is enough to re-register a wallet in a later session.

use super::{Cosigner, MsScript, Wallet};
use crate::bip32::{KeyVersion, Xpriv, HARDENED};
use crate::Network;
use bp_crypto::hmac::HmacSha256;
use bp_crypto::secret::wipe;
use bp_crypto::Sha256;

/// Wallets kept for this session.
pub const MAX_WALLETS: usize = 4;
/// Label for the code key (changing it changes every code).
const CODE_LABEL: &[u8] = b"Bitpunk wallet code v1";
/// Crockford base32.
const B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectKind {
    /// A key with our fingerprint that is not what our seed derives at its
    /// path (other passphrase, or a substituted key).
    OurKeyMismatch,
    /// Our fingerprint on more than one key.
    OurKeyTwice,
    /// Our key under another fingerprint (would let one seed count twice).
    OurKeyHidden,
    /// Two keys with the same public key.
    DuplicateKey,
    /// Two cosigners with the same fingerprint (one seed counted twice).
    DuplicateFingerprint,
    /// xpub depth differs from the origin length.
    Depth,
    /// xpub child number differs from the last origin step.
    ChildNumber,
    /// Depth-1 xpub whose parent fingerprint is not the master fingerprint.
    ParentFingerprint,
    /// Keys for another network than the device's.
    Network,
    /// A BIP-48 path whose coin type does not match the network.
    CoinType,
    /// A SLIP-132 version naming another script type (e.g. Zpub in a
    /// P2SH-P2WSH wallet, or a single-sig zpub).
    VersionScript,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reject {
    pub kind: RejectKind,
    /// Index into `Wallet::keys()` when one key is at fault.
    pub key: Option<u8>,
}

/// Things the user must see but may accept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Warnings {
    /// Our key is not at `m/48'/coin'/account'/type'` for this script type.
    pub our_path: bool,
    /// Cosigner keys not at a BIP-48 path for this script type.
    pub cosigner_paths: u8,
    /// No key of this seed: verify-only wallet.
    pub watch_only: bool,
    /// 1-of-N: any single key spends.
    pub one_of_n: bool,
    /// Registered wallet with the same keys but another threshold or script.
    pub similar: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checked {
    /// Index of our key in `Wallet::keys()` (`None`: verify-only).
    pub ours: Option<u8>,
    pub warnings: Warnings,
    /// Already registered as this entry.
    pub duplicate: Option<u8>,
}

fn reject(kind: RejectKind, key: Option<usize>) -> Reject {
    Reject {
        kind,
        key: key.map(|k| k as u8),
    }
}

/// Is `origin` the BIP-48 account path of `script` on `net` (any account)?
pub fn is_bip48(c: &Cosigner, script: MsScript, net: Network) -> bool {
    let s = c.origin.steps();
    s.len() == 4
        && s[0] == 48 | HARDENED
        && s[1] == net.coin_type() | HARDENED
        && s[2] & HARDENED != 0
        && s[3] == script.bip48_type() | HARDENED
}

/// Check `w` against the seed `master` (whose fingerprint marks our key),
/// the device network and the registry.
pub fn check(w: &Wallet, net: Network, master: &Xpriv, registry: &Registry) -> Result<Checked, Reject> {
    let keys = w.keys();
    let our_fp = master.fingerprint();
    if w.test != (net != Network::Mainnet) {
        return Err(reject(RejectKind::Network, None));
    }
    let mut ours = None;
    for (i, k) in keys.iter().enumerate() {
        // shape of each key
        let steps = k.origin.steps();
        if k.xpub.depth as usize != steps.len() {
            return Err(reject(RejectKind::Depth, Some(i)));
        }
        if let Some(&last) = steps.last() {
            if k.xpub.child_number != last {
                return Err(reject(RejectKind::ChildNumber, Some(i)));
            }
        }
        if steps.len() == 1 && k.xpub.parent_fingerprint != k.fingerprint {
            return Err(reject(RejectKind::ParentFingerprint, Some(i)));
        }
        if steps.len() >= 2 && steps[0] == 48 | HARDENED && steps[1] != net.coin_type() | HARDENED {
            return Err(reject(RejectKind::CoinType, Some(i)));
        }
        let version_ok = match k.version {
            KeyVersion::X => true,
            KeyVersion::MultiZ => w.script == MsScript::Wsh,
            KeyVersion::MultiY => w.script == MsScript::ShWsh,
            KeyVersion::Y | KeyVersion::Z => false,
        };
        if !version_ok {
            return Err(reject(RejectKind::VersionScript, Some(i)));
        }
        // ours, or another seed's
        let derived = master.derive_path(&k.origin).map(|x| x.to_xpub()).ok();
        let is_our_key = derived.is_some_and(|d| d.key == k.xpub.key && d.chain_code == k.xpub.chain_code);
        if k.fingerprint == our_fp {
            if !is_our_key {
                return Err(reject(RejectKind::OurKeyMismatch, Some(i)));
            }
            if ours.is_some() {
                return Err(reject(RejectKind::OurKeyTwice, Some(i)));
            }
            ours = Some(i);
        } else if is_our_key {
            return Err(reject(RejectKind::OurKeyHidden, Some(i)));
        }
    }
    for i in 0..keys.len() {
        for j in i + 1..keys.len() {
            if keys[i].xpub.key == keys[j].xpub.key {
                return Err(reject(RejectKind::DuplicateKey, Some(j)));
            }
            if keys[i].fingerprint == keys[j].fingerprint {
                let kind = if keys[i].fingerprint == our_fp {
                    RejectKind::OurKeyTwice
                } else {
                    RejectKind::DuplicateFingerprint
                };
                return Err(reject(kind, Some(j)));
            }
        }
    }
    let mut warnings = Warnings {
        our_path: ours.is_some_and(|i| !is_bip48(&keys[i], w.script, net)),
        watch_only: ours.is_none(),
        one_of_n: w.m == 1 && w.n() > 1,
        ..Warnings::default()
    };
    for (i, k) in keys.iter().enumerate() {
        if Some(i) != ours && !is_bip48(k, w.script, net) {
            warnings.cosigner_paths += 1;
        }
    }
    let id = w.id();
    let set = key_set_id(w);
    let mut duplicate = None;
    for (i, e) in registry.iter() {
        if e.wallet.id() == id {
            duplicate = Some(i as u8);
        } else if key_set_id(&e.wallet) == set {
            warnings.similar = Some(i as u8);
        }
    }
    Ok(Checked {
        ours: ours.map(|i| i as u8),
        warnings,
        duplicate,
    })
}

/// Hash of the sorted keys alone (threshold and script left out), to spot
/// a wallet that reuses another's keys with another policy.
pub fn key_set_id(w: &Wallet) -> [u8; 32] {
    let mut h = Sha256::new();
    let order = w.sorted_order();
    for &i in &order[..w.n() as usize] {
        let k = &w.keys()[i as usize];
        h.update(&k.fingerprint);
        for s in k.origin.steps() {
            h.update(&s.to_be_bytes());
        }
        h.update(&k.xpub.key.serialize());
        h.update(&k.xpub.chain_code);
    }
    h.finalize()
}

/// The code key of a seed; wiped on drop.
pub struct CodeKey([u8; 32]);

impl CodeKey {
    pub fn new(master: &Xpriv) -> Self {
        CodeKey(master.symmetric_key(CODE_LABEL))
    }

    /// The full 256-bit registration tag (kept for later storage on SD).
    pub fn tag(&self, w: &Wallet) -> [u8; 32] {
        let mut mac = HmacSha256::new(&self.0);
        w.canonical(&mut |b| mac.update(b));
        mac.finalize()
    }

    /// The 8-character code: the tag's first 40 bits in Crockford base32.
    pub fn code(&self, w: &Wallet) -> Code {
        Code::from_tag(&self.tag(w))
    }
}

impl Drop for CodeKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// A wallet code: 8 Crockford base32 characters (40 bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code(pub [u8; 8]);

impl Code {
    pub fn from_tag(tag: &[u8; 32]) -> Code {
        let v = tag[..5].iter().fold(0u64, |a, &b| (a << 8) | b as u64);
        let mut c = [0u8; 8];
        for (i, ch) in c.iter_mut().enumerate() {
            *ch = B32[((v >> (35 - 5 * i)) & 31) as usize];
        }
        Code(c)
    }

    /// Typed input: case-insensitive, `-` and spaces ignored, O→0 and
    /// I/L→1 as in Crockford's alphabet. `None` unless exactly 8 symbols.
    pub fn parse(input: &str) -> Option<Code> {
        let mut c = [0u8; 8];
        let mut n = 0;
        for b in input.bytes() {
            let u = match b.to_ascii_uppercase() {
                b'-' | b' ' => continue,
                b'O' => b'0',
                b'I' | b'L' => b'1',
                x => x,
            };
            if !B32.contains(&u) || n == 8 {
                return None;
            }
            c[n] = u;
            n += 1;
        }
        (n == 8).then_some(Code(c))
    }

    /// `XXXX-XXXX`
    pub fn display(&self) -> [u8; 9] {
        let mut d = [b'-'; 9];
        d[..4].copy_from_slice(&self.0[..4]);
        d[5..].copy_from_slice(&self.0[4..]);
        d
    }
}

/// One registered wallet.
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub wallet: Wallet,
    /// Seed slot whose key made the code (and is our key, unless verify-only).
    pub slot: u8,
    pub ours: Option<u8>,
    pub code: Code,
    /// Full tag (for the M8 wallet file).
    pub tag: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddError {
    Full,
    Duplicate(u8),
}

/// Wallets registered this session (RAM only until M8/M9).
pub struct Registry {
    entries: [Option<Entry>; MAX_WALLETS],
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub const fn new() -> Self {
        Registry {
            entries: [None; MAX_WALLETS],
        }
    }

    pub fn add(&mut self, e: Entry) -> Result<u8, AddError> {
        let id = e.wallet.id();
        if let Some((i, _)) = self.iter().find(|(_, x)| x.wallet.id() == id) {
            return Err(AddError::Duplicate(i as u8));
        }
        let free = self
            .entries
            .iter()
            .position(|x| x.is_none())
            .ok_or(AddError::Full)?;
        self.entries[free] = Some(e);
        Ok(free as u8)
    }

    pub fn get(&self, i: u8) -> Option<&Entry> {
        self.entries.get(i as usize)?.as_ref()
    }

    pub fn remove(&mut self, i: u8) {
        if let Some(e) = self.entries.get_mut(i as usize) {
            *e = None;
        }
    }

    /// Forget wallets whose code came from `slot` (that seed was unloaded:
    /// its key and its code key are gone).
    pub fn forget_slot(&mut self, slot: u8) {
        for e in self.entries.iter_mut() {
            if e.is_some_and(|x| x.slot == slot) {
                *e = None;
            }
        }
    }

    pub fn clear(&mut self) {
        self.entries = [None; MAX_WALLETS];
    }

    pub fn iter(&self) -> impl Iterator<Item = (usize, &Entry)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|e| (i, e)))
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_full(&self) -> bool {
        self.len() == MAX_WALLETS
    }
}

/// Our key's index for a wallet registered with `master`, if any key
/// carries our fingerprint (used when re-checking at signing time).
pub fn our_index(w: &Wallet, master: &Xpriv) -> Option<usize> {
    let fp = master.fingerprint();
    w.keys().iter().position(|k| k.fingerprint == fp)
}
