//! What the vault keeps (M10-5, decision 7): seeds, registered multisig
//! wallets and the settings. Passphrases, BIP-85 results, signed
//! transactions, remembered amounts and the session log are never kept.
//!
//! The body (encrypted by `vault.rs`) is `BPVB 01 00` then records of
//! `kind u8 | len u16 LE | data`:
//!
//! | kind | data |
//! |---|---|
//! | 1 seed | `type u8` (0 words, 1 XPRV, 2 WIF), fingerprint (4), secret: the words' entropy, the XPRV in Base58, or the WIF's 32-byte key |
//! | 2 wallet | the `.bpw` text (name, wallet code, 256-bit tag, descriptor) |
//! | 3 settings | 12 bytes, one per setting |
//!
//! A seed is checked when it is loaded (its fingerprint must come out the
//! same); a wallet only registers again when a loaded seed recomputes its
//! tag and the registration rules pass again.

use crate::seeds::{SeedSlot, SlotKind};
use crate::settings::{Lang, QrDensity, Settings, Units};
use bp_bitcoin::bip32::{KeyVersion, Xpriv, XKEY_LEN};
use bp_bitcoin::bip39::Mnemonic;
use bp_bitcoin::multisig::{formats, register::MAX_WALLETS};
use bp_bitcoin::Network;
use bp_crypto::chacha20poly1305::ct_eq;
use bp_crypto::secp256k1::SecretKey;
use bp_crypto::secret::wipe;
use bp_crypto::sha256::Sha256;

/// Seeds the vault holds (decision 7).
pub const MAX_STORED: usize = 8;
/// Largest wallet record (a 15-key wallet is about 2.4 KB).
pub const WALLET_MAX: usize = 4096;
/// Largest body this firmware writes (a platform's slot holds more).
pub const BODY_MAX: usize = 24 * 1024;

const HEAD: &[u8; 6] = b"BPVB\x01\x00";
const R_SEED: u8 = 1;
const R_WALLET: u8 = 2;
const R_SETTINGS: u8 = 3;
const SETTINGS_LEN: usize = 12;

/// A seed in the vault.
pub struct StoredSeed {
    pub kind: SlotKind,
    /// Without a passphrase (the one shown in the vault's list).
    pub fp: [u8; 4],
    len: u8,
    secret: [u8; XKEY_LEN],
}

impl Drop for StoredSeed {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

/// The secret a slot is stored as: entropy, Base58 XPRV or the WIF key.
fn slot_secret(s: &SeedSlot, out: &mut [u8; XKEY_LEN]) -> Option<usize> {
    match s.kind {
        SlotKind::Mnemonic => {
            let mut e = [0u8; 32];
            let n = s.mnemonic.as_ref()?.entropy(&mut e);
            out[..n].copy_from_slice(&e[..n]);
            wipe(&mut e);
            Some(n)
        }
        SlotKind::Xprv => Some(s.master().encode(KeyVersion::X.private(Network::Mainnet), out)),
        SlotKind::Wif => {
            let mut k = s.master().secret_key().to_bytes();
            out[..32].copy_from_slice(&k);
            wipe(&mut k);
            Some(32)
        }
    }
}

impl StoredSeed {
    /// The vault form of a loaded seed: the words only (never the
    /// passphrase), an XPRV or a WIF key.
    pub fn from_slot(s: &SeedSlot) -> Option<StoredSeed> {
        let mut secret = [0u8; XKEY_LEN];
        let len = slot_secret(s, &mut secret)?;
        let mut st = StoredSeed {
            kind: s.kind,
            fp: s.fingerprint,
            len: len as u8,
            secret,
        };
        if s.has_passphrase() {
            // the fingerprint of the words alone
            st.fp = st.to_slot_unchecked()?.fingerprint;
        }
        Some(st)
    }

    fn secret(&self) -> &[u8] {
        &self.secret[..self.len as usize]
    }

    /// Whether a loaded slot holds this seed (with or without a passphrase).
    pub fn matches(&self, s: &SeedSlot) -> bool {
        if s.kind != self.kind {
            return false;
        }
        let mut b = [0u8; XKEY_LEN];
        let same = slot_secret(s, &mut b).is_some_and(|n| ct_eq(&b[..n], self.secret()));
        wipe(&mut b);
        same
    }

    fn to_slot_unchecked(&self) -> Option<SeedSlot> {
        match self.kind {
            SlotKind::Mnemonic => SeedSlot::new(Mnemonic::from_entropy(self.secret()).ok()?, b""),
            SlotKind::Xprv => {
                let text = core::str::from_utf8(self.secret()).ok()?;
                Some(SeedSlot::from_xprv(Xpriv::decode(text).ok()?.0))
            }
            SlotKind::Wif => SeedSlot::from_wif(&SecretKey::from_bytes(self.secret().try_into().ok()?)?),
        }
    }

    /// The seed, ready for a slot; `None` if it does not come out with the
    /// fingerprint it was stored with.
    pub fn to_slot(&self) -> Option<SeedSlot> {
        self.to_slot_unchecked().filter(|s| s.fingerprint == self.fp)
    }

    /// Words of a stored mnemonic.
    pub fn words(&self) -> usize {
        self.len as usize * 3 / 4
    }

    fn parse(d: &[u8]) -> Option<StoredSeed> {
        let (&t, rest) = d.split_first()?;
        let kind = [SlotKind::Mnemonic, SlotKind::Xprv, SlotKind::Wif]
            .get(t as usize)
            .copied()?;
        let fp: [u8; 4] = rest.get(..4)?.try_into().ok()?;
        let sec = &rest[4..];
        let ok = match kind {
            SlotKind::Mnemonic => matches!(sec.len(), 16 | 20 | 24 | 28 | 32),
            SlotKind::Xprv => (100..=XKEY_LEN).contains(&sec.len()),
            SlotKind::Wif => sec.len() == 32,
        };
        if !ok {
            return None;
        }
        let mut secret = [0u8; XKEY_LEN];
        secret[..sec.len()].copy_from_slice(sec);
        Some(StoredSeed {
            kind,
            fp,
            len: sec.len() as u8,
            secret,
        })
    }
}

/// A wallet's `.bpw` text.
pub struct WalletRec {
    buf: [u8; WALLET_MAX],
    len: usize,
}

impl WalletRec {
    const fn new() -> Self {
        Self {
            buf: [0; WALLET_MAX],
            len: 0,
        }
    }
    pub fn text(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    /// The registration tag in the text.
    pub fn tag(&self) -> Option<[u8; 32]> {
        formats::parse_bpw(self.text()).ok().map(|b| b.tag)
    }
    fn set(&mut self, text: &[u8]) -> bool {
        if text.len() > WALLET_MAX {
            return false;
        }
        self.buf[..text.len()].copy_from_slice(text);
        self.buf[text.len()..self.len.max(text.len())].fill(0);
        self.len = text.len();
        true
    }
}

fn settings_bytes(s: &Settings) -> [u8; SETTINGS_LEN] {
    let net = [
        Network::Mainnet,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ]
    .iter()
    .position(|n| *n == s.network)
    .unwrap_or(0) as u8;
    let fx = [bp_ui::fx::Fx::Full, bp_ui::fx::Fx::Reduced, bp_ui::fx::Fx::Off]
        .iter()
        .position(|f| *f == s.fx)
        .unwrap_or(1) as u8;
    [
        net,
        (s.units == Units::Btc) as u8,
        s.qr_density as u8,
        s.advanced as u8,
        s.lang as u8,
        s.msg_signing as u8,
        s.fee_warn,
        s.fee_block,
        s.fee_rate,
        s.sd_wipe_original as u8,
        fx,
        s.saver,
    ]
}

fn settings_from(b: &[u8]) -> Option<Settings> {
    if b.len() != SETTINGS_LEN {
        return None;
    }
    let flag = |v: u8| (v <= 1).then_some(v == 1);
    let small = |v: u8, n: u8| (v < n).then_some(v);
    Some(Settings {
        network: *[
            Network::Mainnet,
            Network::Testnet,
            Network::Signet,
            Network::Regtest,
        ]
        .get(b[0] as usize)?,
        units: if flag(b[1])? { Units::Btc } else { Units::Sats },
        qr_density: *[QrDensity::Low, QrDensity::Medium, QrDensity::High].get(b[2] as usize)?,
        advanced: flag(b[3])?,
        lang: *Lang::ALL.get(b[4] as usize)?,
        msg_signing: flag(b[5])?,
        fee_warn: small(b[6], 3)?,
        fee_block: small(b[7], 3)?,
        fee_rate: small(b[8], 3)?,
        sd_wipe_original: flag(b[9])?,
        fx: *[bp_ui::fx::Fx::Full, bp_ui::fx::Fx::Reduced, bp_ui::fx::Fx::Off].get(b[10] as usize)?,
        saver: small(b[11], 3)?,
    })
}

/// The vault's contents while it is open (wiped when it locks).
pub struct VaultData {
    pub seeds: [Option<StoredSeed>; MAX_STORED],
    wallets: [WalletRec; MAX_WALLETS],
    pub settings: Option<Settings>,
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

/// The body could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadBody;

impl VaultData {
    pub const fn new() -> Self {
        Self {
            seeds: [const { None }; MAX_STORED],
            wallets: [const { WalletRec::new() }; MAX_WALLETS],
            settings: None,
        }
    }

    /// Forget everything (the seeds wipe themselves).
    pub fn clear(&mut self) {
        self.seeds = [const { None }; MAX_STORED];
        for w in self.wallets.iter_mut() {
            w.set(&[]);
        }
        self.settings = None;
    }

    pub fn seed_count(&self) -> usize {
        self.seeds.iter().flatten().count()
    }

    /// The `i`-th stored seed, in list order.
    pub fn seed(&self, i: usize) -> Option<&StoredSeed> {
        self.seeds.iter().flatten().nth(i)
    }

    /// Store a seed at the end of the list; false when the vault is full.
    pub fn add_seed(&mut self, s: StoredSeed) -> bool {
        match self.seeds.iter_mut().find(|x| x.is_none()) {
            Some(x) => {
                *x = Some(s);
                true
            }
            None => false,
        }
    }

    /// Remove the `i`-th stored seed (the rest keep their order).
    pub fn remove_seed(&mut self, i: usize) {
        if let Some(pos) = self
            .seeds
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .nth(i)
            .map(|(p, _)| p)
        {
            self.seeds[pos] = None;
            self.seeds[pos..].rotate_left(1);
        }
    }

    /// The stored seed a loaded slot holds, if any (its list index).
    pub fn find(&self, s: &SeedSlot) -> Option<usize> {
        self.seeds.iter().flatten().position(|x| x.matches(s))
    }

    pub fn wallets(&self) -> impl Iterator<Item = &WalletRec> {
        self.wallets.iter().filter(|w| w.len > 0)
    }

    /// Replace the wallet records; false if one did not fit (it is left out).
    pub fn set_wallets<'a>(&mut self, texts: impl Iterator<Item = &'a [u8]>) -> bool {
        let mut all = true;
        let mut i = 0;
        for t in texts {
            if i < MAX_WALLETS && self.wallets[i].set(t) {
                i += 1;
            } else {
                all = false;
            }
        }
        for w in self.wallets[i..].iter_mut() {
            w.set(&[]);
        }
        all
    }

    /// Write the body through `out`, piece by piece.
    pub fn write(&self, out: &mut dyn FnMut(&[u8])) {
        let mut rec = |kind: u8, parts: &[&[u8]]| {
            let n: usize = parts.iter().map(|p| p.len()).sum();
            out(&[kind]);
            out(&(n as u16).to_le_bytes());
            for p in parts {
                out(p);
            }
        };
        for s in self.seeds.iter().flatten() {
            let t = [match s.kind {
                SlotKind::Mnemonic => 0,
                SlotKind::Xprv => 1,
                SlotKind::Wif => 2,
            }];
            rec(R_SEED, &[&t, &s.fp, s.secret()]);
        }
        for w in self.wallets() {
            rec(R_WALLET, &[w.text()]);
        }
        if let Some(st) = &self.settings {
            rec(R_SETTINGS, &[&settings_bytes(st)]);
        }
    }

    /// The body length.
    pub fn body_len(&self) -> usize {
        let mut n = HEAD.len();
        self.write(&mut |b| n += b.len());
        n
    }

    /// The body into `out`; `None` if it does not fit.
    pub fn to_body(&self, out: &mut [u8]) -> Option<usize> {
        let n = self.body_len();
        if n > out.len() || n > BODY_MAX {
            return None;
        }
        out[..HEAD.len()].copy_from_slice(HEAD);
        let mut at = HEAD.len();
        self.write(&mut |b| {
            out[at..at + b.len()].copy_from_slice(b);
            at += b.len();
        });
        Some(n)
    }

    /// SHA-256 of the body (to see whether it changed).
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(HEAD);
        self.write(&mut |b| h.update(b));
        h.finalize()
    }

    /// Read a body. Every record must be whole; unknown kinds are skipped.
    pub fn read(&mut self, body: &[u8]) -> Result<(), BadBody> {
        self.clear();
        let mut rest = body.strip_prefix(HEAD.as_slice()).ok_or(BadBody)?;
        let (mut seeds, mut wallets) = (0, 0);
        while !rest.is_empty() {
            if rest.len() < 3 {
                self.clear();
                return Err(BadBody);
            }
            let kind = rest[0];
            let n = u16::from_le_bytes([rest[1], rest[2]]) as usize;
            let Some(d) = rest.get(3..3 + n) else {
                self.clear();
                return Err(BadBody);
            };
            let ok = match kind {
                R_SEED if seeds < MAX_STORED => StoredSeed::parse(d).map(|s| {
                    self.seeds[seeds] = Some(s);
                    seeds += 1;
                }),
                R_WALLET if wallets < MAX_WALLETS => self.wallets[wallets].set(d).then(|| wallets += 1),
                R_SETTINGS if self.settings.is_none() => settings_from(d).map(|s| self.settings = Some(s)),
                R_SEED | R_WALLET | R_SETTINGS => None,
                _ => Some(()),
            };
            if ok.is_none() {
                self.clear();
                return Err(BadBody);
            }
            rest = &rest[3 + n..];
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abandon() -> SeedSlot {
        SeedSlot::new(Mnemonic::from_entropy(&[0u8; 16]).unwrap(), b"").unwrap()
    }

    #[test]
    fn seeds_settings_and_wallets_round_trip() {
        let mut d = VaultData::new();
        assert_eq!(d.body_len(), HEAD.len());
        let a = abandon();
        let s = StoredSeed::from_slot(&a).unwrap();
        assert_eq!(s.fp, a.fingerprint);
        assert_eq!(s.words(), 12);
        assert!(d.add_seed(s));
        let x = SeedSlot::from_xprv(Xpriv::master(&[7u8; 32]).unwrap());
        assert!(d.add_seed(StoredSeed::from_slot(&x).unwrap()));
        let w = SeedSlot::from_wif(&SecretKey::from_bytes(&[9u8; 32]).unwrap()).unwrap();
        assert!(d.add_seed(StoredSeed::from_slot(&w).unwrap()));
        let st = Settings {
            network: Network::Testnet,
            lang: Lang::Ko,
            saver: 2,
            fx: bp_ui::fx::Fx::Off,
            ..Settings::default()
        };
        d.settings = Some(st);
        assert!(d.set_wallets([&b"# Bitpunk wallet v1\nx"[..]].into_iter()));
        let mut body = [0u8; BODY_MAX];
        let n = d.to_body(&mut body).unwrap();
        assert_eq!(n, d.body_len());
        let mut back = VaultData::new();
        back.read(&body[..n]).unwrap();
        assert_eq!(back.digest(), d.digest());
        assert_eq!(back.settings, Some(st));
        for (slot, i) in [(&a, 0), (&x, 1), (&w, 2)] {
            let got = back.seed(i).unwrap().to_slot().unwrap();
            assert_eq!(got.fingerprint, slot.fingerprint);
            assert_eq!(back.find(slot), Some(i));
        }
        assert_eq!(back.wallets().count(), 1);
        // removing keeps the order of the rest
        back.remove_seed(0);
        assert_eq!(back.seed(0).unwrap().kind, SlotKind::Xprv);
        assert_eq!(back.seed_count(), 2);
    }

    #[test]
    fn a_passphrase_is_never_stored() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let with = SeedSlot::new(m, b"secret words").unwrap();
        let s = StoredSeed::from_slot(&with).unwrap();
        assert_eq!(s.fp, abandon().fingerprint, "the fingerprint of the words alone");
        assert!(s.matches(&with) && s.matches(&abandon()));
        let back = s.to_slot().unwrap();
        assert!(!back.has_passphrase());
    }

    #[test]
    fn full_vault_and_wrong_fingerprint() {
        let mut d = VaultData::new();
        for i in 0..MAX_STORED {
            let x = SeedSlot::from_xprv(Xpriv::master(&[i as u8 + 1; 32]).unwrap());
            assert!(d.add_seed(StoredSeed::from_slot(&x).unwrap()));
        }
        let x = SeedSlot::from_xprv(Xpriv::master(&[99; 32]).unwrap());
        assert!(!d.add_seed(StoredSeed::from_slot(&x).unwrap()));
        let mut s = StoredSeed::from_slot(&abandon()).unwrap();
        s.fp[0] ^= 1;
        assert!(
            s.to_slot().is_none(),
            "a seed that comes out different is refused"
        );
    }

    #[test]
    fn bad_bodies_are_refused_without_panicking() {
        let mut d = VaultData::new();
        d.add_seed(StoredSeed::from_slot(&abandon()).unwrap());
        d.settings = Some(Settings::default());
        let mut body = [0u8; 512];
        let n = d.to_body(&mut body).unwrap();
        let mut r = VaultData::new();
        // every truncation inside a record (record boundaries are whole bodies)
        let seed_end = HEAD.len() + 3 + 1 + 4 + 16;
        for cut in 0..n {
            let whole = cut == HEAD.len() || cut == seed_end;
            assert_eq!(r.read(&body[..cut]).is_ok(), whole, "cut {cut}");
        }
        // out-of-range values
        let mut bad = body;
        bad[n - 1] = 9; // saver
        assert!(r.read(&bad[..n]).is_err());
        // random bytes after the head
        let mut x = 0x1234_5678_u32;
        for _ in 0..2000 {
            let mut b = [0u8; 64];
            b[..6].copy_from_slice(HEAD);
            for v in b[6..].iter_mut() {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                *v = x as u8;
            }
            let _ = r.read(&b[..6 + (x as usize % 58)]);
        }
    }
}
