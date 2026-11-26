//! What the vault keeps (M10-5, decision 7): seeds, registered multisig
//! wallets and the settings. Passphrases, BIP-85 results, signed
//! transactions, remembered amounts and the session log are never kept.
//!
//! The body (encrypted by `vault.rs`) is `BPVB 01 00` then records of
//! `kind u8 | len u16 LE | data`:
//!
//! | kind | data |
//! |---|---|
//! | 1 seed | `type u8` (0 words, 1 XPRV, 2 WIF, 3 SLIP-39), fingerprint (4), secret: the words' entropy, the XPRV in Base58, the WIF's 32-byte key, or a SLIP-39 wallet's identifier (2, big-endian), extendable flag, iteration exponent and encrypted master secret (16–32) |
//! | 2 wallet | the `.bpw` text (name, wallet code, 256-bit tag, descriptor) |
//! | 3 settings | 12 bytes, one per setting |
//! | 5 OTP key | (M11-7) `bp_backup::otp::OtpKey::encode`: kind, algorithm, digits, period or counter (8, big-endian), label, secret |
//! | 4 note | (M11-6) `kind u8` (0 note, 1 password), then title, user, password, site and text, each `len u16 LE` + printable ASCII |
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
const R_NOTE: u8 = 4;
const R_OTP: u8 = 5;

/// One-time password keys kept (M11-7).
pub const MAX_OTP: usize = 16;
type OtpBuf = [u8; 2 + 1 + 8 + 1 + bp_backup::otp::MAX_LABEL + 1 + bp_backup::otp::MAX_SECRET];

/// Notes and passwords kept (M11-6, decision 9).
pub const MAX_NOTES: usize = 16;

/// A note's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteKind {
    Text,
    Password,
}

/// A note's fields, in record order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Title,
    User,
    Secret,
    Site,
    Text,
}

impl Field {
    pub const ALL: [Field; 5] = [Field::Title, Field::User, Field::Secret, Field::Site, Field::Text];

    /// Longest value (printable ASCII).
    pub const fn max(self) -> usize {
        match self {
            Field::Title => 32,
            Field::User | Field::Secret | Field::Site => 64,
            Field::Text => 400,
        }
    }
}

/// A secure note or password (printable ASCII only: the keyboard types it).
#[derive(Clone)]
pub struct Note {
    pub kind: NoteKind,
    title: [u8; 32],
    user: [u8; 64],
    secret: [u8; 64],
    site: [u8; 64],
    text: [u8; 400],
    lens: [u16; 5],
}

impl Drop for Note {
    fn drop(&mut self) {
        wipe(&mut self.user);
        wipe(&mut self.secret);
        wipe(&mut self.text);
        wipe(&mut self.site);
        wipe(&mut self.title);
    }
}

impl PartialEq for Note {
    fn eq(&self, o: &Note) -> bool {
        self.kind == o.kind && Field::ALL.iter().all(|&f| self.get(f) == o.get(f))
    }
}

impl Note {
    pub const fn new(kind: NoteKind) -> Note {
        Note {
            kind,
            title: [0; 32],
            user: [0; 64],
            secret: [0; 64],
            site: [0; 64],
            text: [0; 400],
            lens: [0; 5],
        }
    }

    fn buf(&self, f: Field) -> &[u8] {
        match f {
            Field::Title => &self.title,
            Field::User => &self.user,
            Field::Secret => &self.secret,
            Field::Site => &self.site,
            Field::Text => &self.text,
        }
    }

    pub fn get(&self, f: Field) -> &[u8] {
        &self.buf(f)[..self.lens[f as usize] as usize]
    }

    /// The field as text (always ASCII).
    pub fn text_of(&self, f: Field) -> &str {
        core::str::from_utf8(self.get(f)).unwrap_or("")
    }

    /// Set a field; false if too long or not printable ASCII.
    pub fn set(&mut self, f: Field, v: &[u8]) -> bool {
        if v.len() > f.max() || v.iter().any(|&c| !(32..=126).contains(&c)) {
            return false;
        }
        let b: &mut [u8] = match f {
            Field::Title => &mut self.title,
            Field::User => &mut self.user,
            Field::Secret => &mut self.secret,
            Field::Site => &mut self.site,
            Field::Text => &mut self.text,
        };
        b.fill(0);
        b[..v.len()].copy_from_slice(v);
        self.lens[f as usize] = v.len() as u16;
        true
    }

    /// The fields this kind of note has.
    pub fn fields(&self) -> &'static [Field] {
        match self.kind {
            NoteKind::Text => &[Field::Title, Field::Text],
            NoteKind::Password => &Field::ALL,
        }
    }

    fn record_len(&self) -> usize {
        1 + Field::ALL.iter().map(|&f| 2 + self.get(f).len()).sum::<usize>()
    }

    fn parse(d: &[u8]) -> Option<Note> {
        let (&k, mut rest) = d.split_first()?;
        let kind = match k {
            0 => NoteKind::Text,
            1 => NoteKind::Password,
            _ => return None,
        };
        let mut n = Note::new(kind);
        for f in Field::ALL {
            let len = u16::from_le_bytes([*rest.first()?, *rest.get(1)?]) as usize;
            let v = rest.get(2..2 + len)?;
            if !n.set(f, v) {
                return None;
            }
            rest = &rest[2 + len..];
        }
        (rest.is_empty() && !n.get(Field::Title).is_empty()).then_some(n)
    }
}
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
        SlotKind::Slip39 => {
            let e = s.ems.as_ref()?;
            out[..2].copy_from_slice(&e.identifier.to_be_bytes());
            out[2] = e.extendable as u8;
            out[3] = e.iteration_exponent;
            out[4..4 + e.len()].copy_from_slice(e.value());
            Some(4 + e.len())
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
            SlotKind::Slip39 => {
                let d = self.secret();
                let ems = bp_backup::slip39::Ems::from_parts(
                    u16::from_be_bytes([d[0], d[1]]),
                    d[2] == 1,
                    d[3],
                    &d[4..],
                )
                .ok()?;
                SeedSlot::from_slip39(ems, b"")
            }
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
        let kind = [
            SlotKind::Mnemonic,
            SlotKind::Xprv,
            SlotKind::Wif,
            SlotKind::Slip39,
        ]
        .get(t as usize)
        .copied()?;
        let fp: [u8; 4] = rest.get(..4)?.try_into().ok()?;
        let sec = &rest[4..];
        let ok = match kind {
            SlotKind::Mnemonic => matches!(sec.len(), 16 | 20 | 24 | 28 | 32),
            SlotKind::Xprv => (100..=XKEY_LEN).contains(&sec.len()),
            SlotKind::Wif => sec.len() == 32,
            SlotKind::Slip39 => {
                (20..=36).contains(&sec.len())
                    && sec.len() % 2 == 0
                    && sec[0] < 0x80
                    && sec[2] <= 1
                    && sec[3] <= 15
            }
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
    /// Notes and passwords (M11-6): kept with the vault when it is open,
    /// for the session otherwise.
    notes: [Option<Note>; MAX_NOTES],
    /// One-time password keys (M11-7), kept as the notes are.
    otp: [Option<bp_backup::otp::OtpKey>; MAX_OTP],
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
            notes: [const { None }; MAX_NOTES],
            otp: [const { None }; MAX_OTP],
        }
    }

    /// Forget everything (the seeds wipe themselves).
    pub fn clear(&mut self) {
        self.seeds = [const { None }; MAX_STORED];
        for w in self.wallets.iter_mut() {
            w.set(&[]);
        }
        self.settings = None;
        self.notes = [const { None }; MAX_NOTES];
        self.otp = [const { None }; MAX_OTP];
    }

    pub fn otp_count(&self) -> usize {
        self.otp.iter().flatten().count()
    }

    pub fn otp_key(&self, i: usize) -> Option<&bp_backup::otp::OtpKey> {
        self.otp.iter().flatten().nth(i)
    }

    /// Add a key at the end; `false` if there are 16, the same key is
    /// there, or the body would not fit.
    pub fn add_otp(&mut self, k: bp_backup::otp::OtpKey) -> bool {
        if self.has_otp(&k) {
            return false;
        }
        let Some(pos) = self.otp.iter().position(|x| x.is_none()) else {
            return false;
        };
        let mut b: OtpBuf = [0; core::mem::size_of::<OtpBuf>()];
        let room = self.body_len() + 3 + k.encode(&mut b) <= BODY_MAX;
        wipe(&mut b);
        if room {
            self.otp[pos] = Some(k);
        }
        room
    }

    /// Move an HOTP key's counter (each code shown uses one).
    pub fn set_otp_counter(&mut self, i: usize, counter: u64) {
        if let Some(k) = self.otp.iter_mut().flatten().nth(i) {
            if let bp_backup::otp::OtpKind::Hotp { .. } = k.kind {
                k.kind = bp_backup::otp::OtpKind::Hotp { counter };
            }
        }
    }

    pub fn remove_otp(&mut self, i: usize) {
        if let Some(pos) = self
            .otp
            .iter()
            .enumerate()
            .filter(|(_, k)| k.is_some())
            .nth(i)
            .map(|(p, _)| p)
        {
            self.otp[pos] = None;
            self.otp[pos..].rotate_left(1);
        }
    }

    pub fn has_otp(&self, k: &bp_backup::otp::OtpKey) -> bool {
        self.otp.iter().flatten().any(|x| x == k)
    }

    /// Take the keys out (as `take_notes`).
    pub fn take_otp(&mut self) -> [Option<bp_backup::otp::OtpKey>; MAX_OTP] {
        core::mem::replace(&mut self.otp, [const { None }; MAX_OTP])
    }

    pub fn note_count(&self) -> usize {
        self.notes.iter().flatten().count()
    }

    /// The `i`-th note, in list order.
    pub fn note(&self, i: usize) -> Option<&Note> {
        self.notes.iter().flatten().nth(i)
    }

    /// Add a note at the end; `false` if there are 16 or the body would
    /// not fit the vault.
    pub fn add_note(&mut self, n: Note) -> bool {
        let Some(pos) = self.notes.iter().position(|x| x.is_none()) else {
            return false;
        };
        let room = self.body_len() + 3 + n.record_len() <= BODY_MAX;
        if room {
            self.notes[pos] = Some(n);
        }
        room
    }

    /// Replace the `i`-th note; `false` (nothing changed) if it would not fit.
    pub fn set_note(&mut self, i: usize, n: Note) -> bool {
        let Some(pos) = self.note_pos(i) else { return false };
        let old = self.notes[pos].as_ref().map_or(0, |o| o.record_len());
        if self.body_len() - old + n.record_len() > BODY_MAX {
            return false;
        }
        self.notes[pos] = Some(n);
        true
    }

    /// Remove the `i`-th note (the rest keep their order).
    pub fn remove_note(&mut self, i: usize) {
        if let Some(pos) = self.note_pos(i) {
            self.notes[pos] = None;
            self.notes[pos..].rotate_left(1);
        }
    }

    fn note_pos(&self, i: usize) -> Option<usize> {
        self.notes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.is_some())
            .nth(i)
            .map(|(p, _)| p)
    }

    /// Take the notes out (the vault's body replaces the session's when it
    /// opens; the session's are added back after).
    pub fn take_notes(&mut self) -> [Option<Note>; MAX_NOTES] {
        core::mem::replace(&mut self.notes, [const { None }; MAX_NOTES])
    }

    /// Whether this exact note is kept.
    pub fn has_note(&self, n: &Note) -> bool {
        self.notes.iter().flatten().any(|x| x == n)
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
                SlotKind::Slip39 => 3,
            }];
            rec(R_SEED, &[&t, &s.fp, s.secret()]);
        }
        for w in self.wallets() {
            rec(R_WALLET, &[w.text()]);
        }
        for n in self.notes.iter().flatten() {
            let k = [(n.kind == NoteKind::Password) as u8];
            let l = Field::ALL.map(|f| (n.get(f).len() as u16).to_le_bytes());
            let v = Field::ALL.map(|f| n.get(f));
            rec(
                R_NOTE,
                &[
                    &k, &l[0], v[0], &l[1], v[1], &l[2], v[2], &l[3], v[3], &l[4], v[4],
                ],
            );
        }
        for k in self.otp.iter().flatten() {
            let mut b: OtpBuf = [0; core::mem::size_of::<OtpBuf>()];
            let n = k.encode(&mut b);
            rec(R_OTP, &[&b[..n]]);
            wipe(&mut b);
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
        let (mut seeds, mut wallets, mut notes, mut otp) = (0, 0, 0, 0);
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
                R_NOTE if notes < MAX_NOTES => Note::parse(d).map(|n| {
                    self.notes[notes] = Some(n);
                    notes += 1;
                }),
                R_OTP if otp < MAX_OTP => bp_backup::otp::OtpKey::decode(d).map(|k| {
                    self.otp[otp] = Some(k);
                    otp += 1;
                }),
                R_SEED | R_WALLET | R_SETTINGS | R_NOTE | R_OTP => None,
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
    fn a_slip39_wallet_is_kept_without_its_passphrase() {
        use bp_backup::slip39::{Ems, MasterSecret};
        for len in [16usize, 32] {
            let ms = MasterSecret::new(&[0x5a; 32][..len]).unwrap();
            let ems = Ems::encrypt(&ms, b"", 0x1234, true, 1).unwrap();
            let plain = SeedSlot::from_slip39(ems.clone(), b"").unwrap();
            assert_eq!(
                plain.fingerprint,
                Xpriv::master(ms.expose()).unwrap().fingerprint()
            );
            let with = SeedSlot::from_slip39(ems, b"hidden").unwrap();
            let s = StoredSeed::from_slot(&with).unwrap();
            assert_eq!(s.kind, SlotKind::Slip39);
            assert_eq!(s.fp, plain.fingerprint, "the fingerprint without the passphrase");
            assert!(s.matches(&with) && s.matches(&plain));
            let mut d = VaultData::new();
            assert!(d.add_seed(s));
            let mut body = [0u8; BODY_MAX];
            let n = d.to_body(&mut body).unwrap();
            let mut back = VaultData::new();
            back.read(&body[..n]).unwrap();
            let got = back.seed(0).unwrap().to_slot().unwrap();
            assert_eq!(got.kind, SlotKind::Slip39);
            assert_eq!(got.fingerprint, plain.fingerprint);
            assert!(!got.has_passphrase());
            let e = got.ems.as_ref().unwrap();
            assert_eq!(
                (e.identifier, e.extendable, e.iteration_exponent),
                (0x1234, true, 1)
            );
            // with the passphrase again: the hidden wallet comes back
            assert_eq!(
                got.with_passphrase(b"hidden").unwrap().fingerprint,
                with.fingerprint
            );
        }
        // malformed records are refused
        for bad in [
            &[3u8, 0, 0, 0, 0, 0x80, 0, 1, 1][..], // identifier above 15 bits
            &[3, 0, 0, 0, 0, 0, 1, 2, 1],          // flag not 0/1
            &[3, 0, 0, 0, 0, 0, 1, 1, 16],         // exponent above 15
        ] {
            let mut rec = [7u8; 25];
            rec[..9].copy_from_slice(bad);
            assert!(StoredSeed::parse(&rec).is_none());
        }
        let mut odd = [7u8; 26];
        odd[..9].copy_from_slice(&[3u8, 0, 0, 0, 0, 0, 1, 1, 1]);
        assert!(StoredSeed::parse(&odd).is_none());
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
