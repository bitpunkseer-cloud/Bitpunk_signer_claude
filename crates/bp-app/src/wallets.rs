//! Tools > Multisig wallets: import (scan), registration, the session list,
//! cosigner pages and export.
//!
//! Registration (M7 plan 4-7): the wallet must pass `register::check`; the
//! user then either pages through every cosigner, sees the first addresses
//! and writes down the wallet code (typing it back to catch copying
//! mistakes), or, for a wallet registered in an earlier session, types the
//! code they wrote down. A wallet never gets registered from a PSBT.

use crate::seeds::fingerprint_hex;
use crate::{scan, App, Pick, QrKind, Screen};
use bp_bitcoin::address::MAX_ADDRESS_LEN;
use bp_bitcoin::bip32::XKEY_LEN;
use bp_bitcoin::multisig::descriptor::Error as DError;
use bp_bitcoin::multisig::formats::{self, Format};
use bp_bitcoin::multisig::register::{self, Checked, Code, CodeKey, Entry, Reject, RejectKind};
use bp_bitcoin::multisig::{version_name, Cosigner, MsScript, Wallet, MAX_KEYS};
use bp_bitcoin::qrinput::UrKey;
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, HUGE, SMALL, TITLE};
use bp_ui::theme;
use bp_ui::widgets::{self, MenuItem, MARGIN, STATUS_H};

const CODE_INPUT: usize = 16;
const W: i32 = 800 - 2 * MARGIN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WlStep {
    List {
        sel: u8,
    },
    NeedSeed,
    /// The scanned wallet was refused (format or rule).
    Refused,
    Summary {
        sel: u8,
    },
    Cosigner {
        i: u8,
    },
    Addresses,
    CodeShow,
    /// Typing the code: to confirm it was written down, or (`rereg`) to
    /// register a wallet seen in an earlier session.
    CodeEntry {
        rereg: bool,
    },
    Registered {
        idx: u8,
        sel: u8,
    },
    Wallet {
        idx: u8,
        sel: u8,
    },
    Keys {
        idx: u8,
        i: u8,
    },
    Export {
        idx: u8,
        sel: u8,
    },
    Remove {
        idx: u8,
        sel: u8,
    },
    /// Which loaded seed creates the wallet (`export`: exports its key).
    PickSeed {
        sel: u8,
        export: bool,
    },
    /// New wallet: script type, M, N, account.
    CreateSize {
        field: u8,
    },
    /// Keys collected so far; Enter scans the next cosigner.
    CreateKeys,
    /// A scanned cosigner, shown in full before it is added.
    CreateConfirm {
        sel: u8,
    },
    CreateRefused,
    /// Export this device's BIP-48 key: script type (and account).
    KeyScript {
        slot: u8,
        sel: u8,
    },
    KeyFormat {
        slot: u8,
        script: u8,
        sel: u8,
    },
    /// A registered wallet's address, with its QR.
    Address {
        idx: u8,
        change: bool,
        index: u32,
    },
    /// Is a scanned address one of the registered wallets'?
    AddrSearch,
    AddrPaused {
        sel: u8,
    },
    AddrFound,
}

/// Formats for exporting this device's multisig key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyFormat {
    Text,
    UrAccount,
    ColdcardJson,
}

impl KeyFormat {
    pub const ALL: [KeyFormat; 3] = [KeyFormat::Text, KeyFormat::UrAccount, KeyFormat::ColdcardJson];
}

/// A wallet being created on the device (M7 plan 6.1).
pub struct Creating {
    pub slot: u8,
    pub script: MsScript,
    pub m: u8,
    pub n: u8,
    pub account: u32,
    pub test: bool,
    keys: [Option<Cosigner>; MAX_KEYS],
    pub count: u8,
    pub candidate: Option<Cosigner>,
}

impl Creating {
    pub fn keys(&self) -> impl Iterator<Item = &Cosigner> {
        self.keys[..self.count as usize].iter().flatten()
    }

    /// The keys so far plus the candidate, as a wallet (threshold 1), for
    /// the registration rules and the cosigner page.
    fn with_candidate(&self) -> Option<Wallet> {
        let mut list = [self.keys[0]?; MAX_KEYS];
        let mut n = 0;
        for k in self.keys() {
            list[n] = *k;
            n += 1;
        }
        if let Some(c) = self.candidate {
            list[n] = c;
            n += 1;
        }
        Wallet::new(self.test, self.script, 1, &list[..n])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletFormat {
    Descriptor,
    Specter,
    ColdcardUr,
    Bbqr,
}

impl WalletFormat {
    pub const ALL: [WalletFormat; 4] = [
        WalletFormat::Descriptor,
        WalletFormat::Specter,
        WalletFormat::ColdcardUr,
        WalletFormat::Bbqr,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    Format(formats::Error),
    Reject(Reject),
}

/// A scanned wallet waiting for the user.
pub struct Pending {
    pub wallet: Wallet,
    /// `None` for a wallet created on the device.
    pub format: Option<Format>,
    pub slot: u8,
    pub checked: Checked,
    pub code: Code,
    tag: [u8; 32],
    pub two_seeds: bool,
    addr: [[u8; MAX_ADDRESS_LEN]; 2],
    addr_len: [usize; 2],
}

impl Pending {
    pub fn address(&self, change: usize) -> &str {
        core::str::from_utf8(&self.addr[change][..self.addr_len[change]]).unwrap_or("")
    }
}

pub struct WlState {
    pub pending: Option<Pending>,
    pub problem: Option<Problem>,
    pub creating: Option<Creating>,
    /// Account for "Export my multisig key".
    pub key_account: u32,
    /// Address search over the registered wallets, and the address.
    pub search: Option<bp_bitcoin::multisig::Search>,
    search_addr: [u8; MAX_ADDRESS_LEN],
    search_len: usize,
    input: [u8; CODE_INPUT],
    len: usize,
    /// 0 none, 1 mismatch, 2 not a code.
    pub bad: u8,
}

impl Default for WlState {
    fn default() -> Self {
        WlState {
            pending: None,
            problem: None,
            creating: None,
            key_account: 0,
            search: None,
            search_addr: [0; MAX_ADDRESS_LEN],
            search_len: 0,
            input: [0; CODE_INPUT],
            len: 0,
            bad: 0,
        }
    }
}

impl WlState {
    fn search_addr(&self) -> &str {
        core::str::from_utf8(&self.search_addr[..self.search_len]).unwrap_or("")
    }

    fn clear_input(&mut self) {
        self.input = [0; CODE_INPUT];
        self.len = 0;
        self.bad = 0;
    }
}

/// Index into `WalletStrings::format_errors`.
pub fn format_error_index(e: formats::Error) -> usize {
    use formats::Error as F;
    match e {
        F::Unknown => 0,
        F::Descriptor(d) => match d {
            DError::Syntax => 1,
            DError::Checksum => 2,
            DError::Unsorted => 3,
            DError::UnsupportedScript => 4,
            DError::Threshold => 5,
            DError::TooManyKeys => 6,
            DError::MissingOrigin => 7,
            DError::Key => 8,
            DError::PrivateKey => 9,
            DError::Hardened => 10,
            DError::Suffix => 11,
            DError::MixedSuffix => 12,
            DError::MixedNetwork => 13,
            DError::PathTooDeep => 14,
        },
        F::ChangeOnly => 15,
        F::LinesDiffer => 16,
        F::Policy => 17,
        F::Derivation => 18,
        F::ScriptFormat => 19,
        F::KeyCount => 20,
        F::Key => 8,
        F::PrivateKey => 9,
        F::MissingOrigin => 7,
        F::MixedNetwork => 13,
        F::Cbor => 21,
    }
}

/// Index into `WalletStrings::rejects`.
pub fn reject_index(k: RejectKind) -> usize {
    match k {
        RejectKind::OurKeyMismatch => 0,
        RejectKind::OurKeyTwice => 1,
        RejectKind::OurKeyHidden => 2,
        RejectKind::DuplicateKey => 3,
        RejectKind::DuplicateFingerprint => 4,
        RejectKind::Depth => 5,
        RejectKind::ChildNumber => 6,
        RejectKind::ParentFingerprint => 7,
        RejectKind::Network => 8,
        RejectKind::CoinType => 9,
        RejectKind::VersionScript => 10,
    }
}

fn format_index(f: Format) -> usize {
    match f {
        Format::Descriptor => 0,
        Format::Json => 1,
        Format::Coldcard => 2,
        Format::UrOutput => 3,
    }
}

/// A file name stem from a wallet name: FAT-safe characters only.
fn file_stem(name: &str, out: &mut bp_fat::Name) {
    for c in name.chars() {
        let ok = c.is_ascii_alphanumeric() || "-_ ()".contains(c);
        let mut b = [0u8; 4];
        let part: &str = if ok { c.encode_utf8(&mut b) } else { "_" };
        out.push_str(part);
    }
    if out.is_empty() {
        out.push_str("wallet");
    }
}

/// `xpub…` in its own version, as 4-character groups.
fn xpub_text(k: &Cosigner, test: bool, out: &mut [u8; XKEY_LEN]) -> usize {
    let net = if test {
        bp_bitcoin::Network::Testnet
    } else {
        bp_bitcoin::Network::Mainnet
    };
    k.xpub.encode(k.version.public(net), out)
}

impl App {
    pub(crate) fn open_wallets(&mut self) {
        let step = if self.seed_count() == 0 {
            WlStep::NeedSeed
        } else {
            WlStep::List { sel: 0 }
        };
        self.push(Screen::Wallets { step });
    }

    /// A wallet arrived from the scanner (text, or UR crypto-output CBOR).
    /// Replaces the scanner screen.
    pub(crate) fn wallet_import(&mut self, data: &[u8], ur: bool) {
        self.wl.pending = None;
        self.wl.problem = None;
        self.wl.clear_input();
        if self.seed_count() == 0 {
            self.set_current(Screen::Wallets {
                step: WlStep::NeedSeed,
            });
            return;
        }
        let parsed = if ur {
            formats::parse_output_ur(data)
        } else {
            formats::parse_wallet(data)
        };
        let imported = match parsed {
            Ok(i) => i,
            Err(e) => {
                self.wl.problem = Some(Problem::Format(e));
                self.set_current(Screen::Wallets {
                    step: WlStep::Refused,
                });
                return;
            }
        };
        let w = imported.wallet;
        // the seed whose key is in the wallet; else the first seed (verify-only)
        let mut slot = None;
        let mut two = false;
        for (i, s) in self.seeds.iter().enumerate() {
            let Some(s) = s else { continue };
            if w.keys().iter().any(|k| k.fingerprint == s.fingerprint) {
                if slot.is_some() {
                    two = true;
                } else {
                    slot = Some(i);
                }
            }
        }
        // verify-only falls back to a seed with extended keys (never a WIF)
        let Some(slot) = slot.or_else(|| {
            self.seeds
                .iter()
                .position(|s| s.as_ref().is_some_and(|s| !s.single_key()))
        }) else {
            self.set_current(Screen::Wallets {
                step: WlStep::NeedSeed,
            });
            return;
        };
        if self.make_pending(w, Some(imported.format), slot, two) {
            self.set_current(Screen::Wallets {
                step: WlStep::Summary { sel: 0 },
            });
        }
    }

    /// Check `w` with the seed in `slot` and hold it for registration
    /// (false: refused, the Refused screen is up).
    fn make_pending(&mut self, w: Wallet, format: Option<Format>, slot: usize, two: bool) -> bool {
        let Some(seed) = self.slot(slot) else { return false };
        let net = self.settings.network;
        let checked = match register::check(&w, net, seed.master(), &self.wallets) {
            Ok(c) => c,
            Err(r) => {
                self.wl.problem = Some(Problem::Reject(r));
                self.set_current(Screen::Wallets {
                    step: WlStep::Refused,
                });
                return false;
            }
        };
        let ck = CodeKey::new(seed.master());
        let mut addr = [[0u8; MAX_ADDRESS_LEN]; 2];
        let mut addr_len = [0usize; 2];
        for (b, (a, l)) in addr.iter_mut().zip(addr_len.iter_mut()).enumerate() {
            if let Ok(sc) = w.derive(b as u32, 0) {
                *l = sc.address(net, a);
            }
        }
        self.wl.pending = Some(Pending {
            wallet: w,
            format,
            slot: slot as u8,
            checked,
            code: ck.code(&w),
            tag: ck.tag(&w),
            two_seeds: two,
            addr,
            addr_len,
        });
        true
    }

    /// Tools > Multisig wallets > Create: with `slot`'s seed.
    fn create_start(&mut self, slot: u8) {
        self.wl.creating = Some(Creating {
            slot,
            script: MsScript::Wsh,
            m: 2,
            n: 3,
            account: 0,
            test: self.settings.network != bp_bitcoin::Network::Mainnet,
            keys: [None; MAX_KEYS],
            count: 0,
            candidate: None,
        });
        self.push(Screen::Wallets {
            step: WlStep::CreateSize { field: 0 },
        });
    }

    /// Size chosen: this device's key goes first.
    fn create_begin(&mut self) {
        let net = self.settings.network;
        let Some(cr) = self.wl.creating.as_ref() else {
            return;
        };
        let Some(seed) = self.slot(cr.slot as usize) else {
            return;
        };
        let path = cr.script.account_path(net, cr.account);
        let Ok(k) = seed.master().derive_path(&path) else {
            return;
        };
        let ours = Cosigner {
            fingerprint: seed.fingerprint,
            origin: path,
            xpub: k.to_xpub(),
            version: bp_bitcoin::bip32::KeyVersion::X,
        };
        let cr = self.wl.creating.as_mut().expect("checked");
        cr.keys = [None; MAX_KEYS];
        cr.keys[0] = Some(ours);
        cr.count = 1;
        cr.candidate = None;
        self.set_current(Screen::Wallets {
            step: WlStep::CreateKeys,
        });
    }

    /// A cosigner key arrived from the scanner (text, or a UR key). Replaces
    /// the scanner with the cosigner page or the refusal.
    pub(crate) fn wallet_cosigner_scanned(&mut self, data: &[u8], ur: Option<UrKey>) {
        let net = self.settings.network;
        let Some(cr) = self.wl.creating.as_mut() else {
            return;
        };
        let parsed = match ur {
            None => formats::parse_cosigner(data, cr.script),
            Some(UrKey::Account) => formats::parse_cosigner_ur("crypto-account", data, cr.script),
            Some(UrKey::HdKey) => formats::parse_cosigner_ur("crypto-hdkey", data, cr.script),
            Some(UrKey::Output) => Err(formats::Error::Unknown),
        };
        let fail = |app: &mut App, p: Problem| {
            app.wl.problem = Some(p);
            if let Some(cr) = app.wl.creating.as_mut() {
                cr.candidate = None;
            }
            app.set_current(Screen::Wallets {
                step: WlStep::CreateRefused,
            });
        };
        let (key, test) = match parsed {
            Ok(v) => v,
            Err(e) => return fail(self, Problem::Format(e)),
        };
        if test != cr.test {
            return fail(
                self,
                Problem::Reject(Reject {
                    kind: RejectKind::Network,
                    key: None,
                }),
            );
        }
        cr.candidate = Some(key);
        let slot = cr.slot as usize;
        let Some(w) = cr.with_candidate() else { return };
        let Some(seed) = self.slot(slot) else { return };
        if let Err(r) = register::check(&w, net, seed.master(), &register::Registry::new()) {
            return fail(self, Problem::Reject(r));
        }
        self.set_current(Screen::Wallets {
            step: WlStep::CreateConfirm { sel: 0 },
        });
    }

    /// All keys in: the wallet goes on to the first addresses and the code.
    fn create_finish(&mut self) {
        let Some(cr) = self.wl.creating.take() else { return };
        let mut list = [cr.keys[0].expect("our key"); MAX_KEYS];
        for (l, k) in list.iter_mut().zip(cr.keys()) {
            *l = *k;
        }
        let Some(w) = Wallet::new(cr.test, cr.script, cr.m, &list[..cr.count as usize]) else {
            return;
        };
        if self.make_pending(w, None, cr.slot as usize, false) {
            self.wl.clear_input();
            self.set_current(Screen::Wallets {
                step: WlStep::Addresses,
            });
        }
    }

    /// The QR for this device's BIP-48 key.
    pub(crate) fn key_qr(
        &self,
        slot: u8,
        script: MsScript,
        account: u32,
        format: KeyFormat,
    ) -> Option<crate::qrview::QrSession> {
        use crate::qrview::{Density, Format as QF, QrSession, Speed, PAYLOAD_MAX};
        let net = self.settings.network;
        let test = net != bp_bitcoin::Network::Mainnet;
        let seed = self.slot(slot as usize)?;
        let key = |sc: MsScript| -> Option<Cosigner> {
            let path = sc.account_path(net, account);
            Some(Cosigner {
                fingerprint: seed.fingerprint,
                origin: path,
                xpub: seed.master().derive_path(&path).ok()?.to_xpub(),
                version: bp_bitcoin::bip32::KeyVersion::X,
            })
        };
        let c = key(script)?;
        let mut buf = [0u8; PAYLOAD_MAX];
        let (fmt, n) = match format {
            KeyFormat::Text => (QF::Static, formats::write_key_text(&c, test, &mut buf)?),
            KeyFormat::ColdcardJson => {
                let wsh = key(MsScript::Wsh)?;
                let sh = key(MsScript::ShWsh)?;
                (
                    QF::Static,
                    formats::write_coldcard_xpub_json(&wsh, &sh, account, test, &mut buf)?,
                )
            }
            KeyFormat::UrAccount => {
                use bp_bitcoin::urtypes::{crypto_account_tags, AccountKey, TAG_SH, TAG_WSH};
                let ak = AccountKey {
                    xpub: &c.xpub,
                    master_fingerprint: c.fingerprint,
                    path: &c.origin,
                    script: bp_bitcoin::address::ScriptType::NativeSegwit,
                    network: net,
                };
                let tags: &[u64] = match script {
                    MsScript::Wsh => &[TAG_WSH],
                    MsScript::ShWsh => &[TAG_SH, TAG_WSH],
                };
                (
                    QF::Ur(bp_bitcoin::urtypes::UR_ACCOUNT),
                    crypto_account_tags(&ak, tags, &mut buf).ok()?,
                )
            }
        };
        // xpub exports start at low density and slow speed (as for single-sig)
        QrSession::new(fmt, &buf[..n], Density::Low, Speed::Slow)
    }

    /// Add the pending wallet to the session registry.
    fn wallet_register(&mut self) -> Option<u8> {
        let p = self.wl.pending.as_ref()?;
        let e = Entry {
            wallet: p.wallet,
            slot: p.slot,
            ours: p.checked.ours,
            code: p.code,
            tag: p.tag,
        };
        match self.wallets.add(e) {
            Ok(i) => Some(i),
            Err(register::AddError::Duplicate(i)) => Some(i),
            Err(register::AddError::Full) => {
                self.notice = Some(self.text().wl.full);
                None
            }
        }
    }

    fn wallet_end(&mut self) {
        self.wl.pending = None;
        self.wl.problem = None;
        self.wl.clear_input();
        self.pop();
    }

    fn wallet_indices(&self) -> ([u8; register::MAX_WALLETS], usize) {
        let mut v = [0u8; register::MAX_WALLETS];
        let mut n = 0;
        for (i, _) in self.wallets.iter() {
            v[n] = i as u8;
            n += 1;
        }
        (v, n)
    }

    fn loaded_slots(&self) -> ([u8; 3], usize) {
        let mut v = [0u8; 3];
        let mut n = 0;
        for (i, s) in self.seeds.iter().enumerate() {
            if s.is_some() && n < 3 {
                v[n] = i as u8;
                n += 1;
            }
        }
        (v, n)
    }

    /// Create (or export a key) with the only seed, or ask which one.
    fn pick_seed_then(&mut self, export: bool) {
        let (v, n) = self.loaded_slots();
        if n == 1 {
            self.seed_chosen(v[0], export);
        } else {
            self.push(Screen::Wallets {
                step: WlStep::PickSeed { sel: 0, export },
            });
        }
    }

    fn seed_chosen(&mut self, slot: u8, export: bool) {
        if self.slot(slot as usize).is_some_and(|s| s.single_key()) {
            self.notice = Some(self.text().key.not_for_wif);
            return;
        }
        if export {
            self.wl.key_account = 0;
            self.push(Screen::Wallets {
                step: WlStep::KeyScript { slot, sel: 0 },
            });
        } else {
            self.create_start(slot);
        }
    }

    pub(crate) fn wallets_key(&mut self, step: WlStep, ev: KeyEvent) {
        let set = |app: &mut App, step: WlStep| app.set_current(Screen::Wallets { step });
        match step {
            WlStep::NeedSeed | WlStep::Refused => {
                if matches!(ev.key, Key::Enter | Key::Esc | Key::Backspace | Key::Left) {
                    self.wallet_end();
                }
            }
            WlStep::List { sel } => {
                let (idx, n) = self.wallet_indices();
                match crate::pick(ev.key, sel, n as u8 + 3) {
                    Pick::Move(s) => set(self, WlStep::List { sel: s }),
                    Pick::Choose(s) if (s as usize) < n => self.push(Screen::Wallets {
                        step: WlStep::Wallet {
                            idx: idx[s as usize],
                            sel: 0,
                        },
                    }),
                    Pick::Choose(s) if s as usize == n + 2 => self.pick_seed_then(true),
                    Pick::Choose(_) if self.wallets.is_full() => self.notice = Some(self.text().wl.full),
                    Pick::Choose(s) if s as usize == n + 1 => self.pick_seed_then(false),
                    Pick::Choose(_) => self.start_scan(scan::Purpose::Wallet),
                    Pick::Back => self.pop(),
                    Pick::None => {}
                }
            }
            WlStep::Summary { sel } => {
                let Some(p) = self.wl.pending.as_ref() else {
                    return self.wallet_end();
                };
                let duplicate = p.checked.duplicate;
                let n = if duplicate.is_some() { 1 } else { 3 };
                match crate::pick(ev.key, sel, n) {
                    Pick::Move(s) => set(self, WlStep::Summary { sel: s }),
                    Pick::Choose(_) if duplicate.is_some() => self.wallet_end(),
                    Pick::Choose(0) => set(self, WlStep::Cosigner { i: 0 }),
                    Pick::Choose(1) => {
                        self.wl.clear_input();
                        set(self, WlStep::CodeEntry { rereg: true });
                    }
                    Pick::Choose(_) | Pick::Back => self.wallet_end(),
                    Pick::None => {}
                }
            }
            WlStep::Cosigner { i } => {
                let n = self.wl.pending.as_ref().map_or(0, |p| p.wallet.n());
                match ev.key {
                    Key::Right | Key::Enter | Key::Down => {
                        if i + 1 < n {
                            set(self, WlStep::Cosigner { i: i + 1 });
                        } else {
                            set(self, WlStep::Addresses);
                        }
                    }
                    Key::Left | Key::Up => {
                        if i > 0 {
                            set(self, WlStep::Cosigner { i: i - 1 });
                        }
                    }
                    Key::Esc | Key::Backspace => set(self, WlStep::Summary { sel: 0 }),
                    _ => {}
                }
            }
            WlStep::Addresses => match ev.key {
                Key::Enter | Key::Right => set(self, WlStep::CodeShow),
                Key::Left | Key::Esc | Key::Backspace => {
                    let n = self.wl.pending.as_ref().map_or(1, |p| p.wallet.n());
                    set(self, WlStep::Cosigner { i: n - 1 });
                }
                _ => {}
            },
            WlStep::CodeShow => match ev.key {
                Key::Enter | Key::Right => {
                    self.wl.clear_input();
                    set(self, WlStep::CodeEntry { rereg: false });
                }
                Key::Left | Key::Esc | Key::Backspace => set(self, WlStep::Addresses),
                _ => {}
            },
            WlStep::CodeEntry { rereg } => match ev.key {
                Key::Char(c) if c.is_ascii_alphanumeric() || c == '-' || c == ' ' => {
                    if self.wl.len < CODE_INPUT {
                        self.wl.input[self.wl.len] = c.to_ascii_uppercase() as u8;
                        self.wl.len += 1;
                    }
                    self.wl.bad = 0;
                }
                Key::Backspace if self.wl.len > 0 => {
                    self.wl.len -= 1;
                    self.wl.input[self.wl.len] = 0;
                    self.wl.bad = 0;
                }
                Key::Enter => {
                    let typed = core::str::from_utf8(&self.wl.input[..self.wl.len]).unwrap_or("");
                    let want = self.wl.pending.as_ref().map(|p| p.code);
                    match Code::parse(typed) {
                        None => self.wl.bad = 2,
                        Some(c) if Some(c) == want => {
                            if let Some(idx) = self.wallet_register() {
                                self.wl.clear_input();
                                set(self, WlStep::Registered { idx, sel: 0 });
                            }
                        }
                        Some(_) => self.wl.bad = 1,
                    }
                }
                Key::Esc | Key::Backspace => {
                    self.wl.clear_input();
                    set(
                        self,
                        if rereg {
                            WlStep::Summary { sel: 1 }
                        } else {
                            WlStep::CodeShow
                        },
                    );
                }
                _ => {}
            },
            WlStep::Registered { idx, sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => set(self, WlStep::Registered { idx, sel: s }),
                Pick::Choose(0) => self.push(Screen::Wallets {
                    step: WlStep::Export { idx, sel: 0 },
                }),
                Pick::Choose(_) | Pick::Back => {
                    self.wl.pending = None;
                    self.pop();
                }
                Pick::None => {}
            },
            WlStep::Wallet { idx, sel } => match crate::pick(ev.key, sel, 4) {
                Pick::Move(s) => set(self, WlStep::Wallet { idx, sel: s }),
                Pick::Choose(0) => self.push(Screen::Wallets {
                    step: WlStep::Address {
                        idx,
                        change: false,
                        index: 0,
                    },
                }),
                Pick::Choose(1) => self.push(Screen::Wallets {
                    step: WlStep::Keys { idx, i: 0 },
                }),
                Pick::Choose(2) => self.push(Screen::Wallets {
                    step: WlStep::Export { idx, sel: 0 },
                }),
                Pick::Choose(_) => self.push(Screen::Wallets {
                    step: WlStep::Remove { idx, sel: 0 },
                }),
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            WlStep::Keys { idx, i } => {
                let n = self.wallets.get(idx).map_or(0, |e| e.wallet.n());
                match ev.key {
                    Key::Right | Key::Down | Key::Enter if i + 1 < n => {
                        set(self, WlStep::Keys { idx, i: i + 1 })
                    }
                    Key::Left | Key::Up if i > 0 => set(self, WlStep::Keys { idx, i: i - 1 }),
                    Key::Esc | Key::Backspace => self.pop(),
                    Key::Enter => self.pop(),
                    _ => {}
                }
            }
            WlStep::Export { idx, sel } => match crate::pick(ev.key, sel, 5) {
                Pick::Move(s) => set(self, WlStep::Export { idx, sel: s }),
                Pick::Choose(4) => {
                    set(self, WlStep::Export { idx, sel: 4 });
                    if self.sd.present {
                        self.start_save(crate::sd::Job::SaveWalletFile(idx));
                    } else {
                        self.notice = Some(self.text().sd.problems[0][0]);
                    }
                }
                Pick::Choose(s) => self.open_qr(QrKind::Wallet {
                    idx,
                    format: WalletFormat::ALL[s as usize],
                }),
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            WlStep::Remove { idx, sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => set(self, WlStep::Remove { idx, sel: s }),
                Pick::Choose(1) => {
                    self.wallets.remove(idx);
                    self.pop(); // this question
                    self.pop(); // the wallet's menu: back to the list
                    self.set_current(Screen::Wallets {
                        step: WlStep::List { sel: 0 },
                    });
                }
                Pick::Choose(_) | Pick::Back => self.pop(),
                Pick::None => {}
            },
            WlStep::Address { idx, change, index } => match ev.key {
                Key::Right => set(
                    self,
                    WlStep::Address {
                        idx,
                        change,
                        index: (index + 1).min(0x7FFF_FFFF),
                    },
                ),
                Key::Left => set(
                    self,
                    WlStep::Address {
                        idx,
                        change,
                        index: index.saturating_sub(1),
                    },
                ),
                Key::Tab | Key::Up | Key::Down => set(
                    self,
                    WlStep::Address {
                        idx,
                        change: !change,
                        index,
                    },
                ),
                Key::Esc | Key::Backspace | Key::Enter => self.pop(),
                _ => {}
            },
            WlStep::AddrSearch => {
                if matches!(ev.key, Key::Esc | Key::Backspace) {
                    set(self, WlStep::AddrPaused { sel: 0 });
                }
            }
            WlStep::AddrPaused { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => set(self, WlStep::AddrPaused { sel: s }),
                Pick::Choose(0) => {
                    if let Some(sr) = self.wl.search.as_mut() {
                        sr.more();
                    }
                    set(self, WlStep::AddrSearch);
                }
                Pick::Choose(_) | Pick::Back => {
                    self.wl.search = None;
                    self.pop();
                }
                Pick::None => {}
            },
            WlStep::AddrFound => {
                if matches!(ev.key, Key::Enter | Key::Esc | Key::Backspace) {
                    self.wl.search = None;
                    self.pop();
                }
            }
            WlStep::PickSeed { sel, export } => {
                let slots = self.loaded_slots();
                match crate::pick(ev.key, sel, slots.1 as u8) {
                    Pick::Move(s) => set(self, WlStep::PickSeed { sel: s, export }),
                    Pick::Choose(s) => {
                        let slot = slots.0[s as usize];
                        self.pop();
                        self.seed_chosen(slot, export);
                    }
                    Pick::Back => self.pop(),
                    Pick::None => {}
                }
            }
            WlStep::CreateSize { field } => {
                let Some(cr) = self.wl.creating.as_mut() else {
                    return self.pop();
                };
                let d: i32 = match ev.key {
                    Key::Right => 1,
                    Key::Left => -1,
                    _ => 0,
                };
                match ev.key {
                    Key::Up => set(
                        self,
                        WlStep::CreateSize {
                            field: (field + 3) % 4,
                        },
                    ),
                    Key::Down | Key::Tab => set(
                        self,
                        WlStep::CreateSize {
                            field: (field + 1) % 4,
                        },
                    ),
                    Key::Left | Key::Right => {
                        match field {
                            0 => {
                                cr.script = match cr.script {
                                    MsScript::Wsh => MsScript::ShWsh,
                                    MsScript::ShWsh => MsScript::Wsh,
                                }
                            }
                            1 => cr.m = (cr.m as i32 + d).clamp(1, cr.n as i32) as u8,
                            2 => {
                                cr.n = (cr.n as i32 + d).clamp(2, MAX_KEYS as i32) as u8;
                                cr.m = cr.m.min(cr.n);
                            }
                            _ => cr.account = (cr.account as i32 + d).clamp(0, 999) as u32,
                        }
                        self.dirty = true;
                    }
                    Key::Enter => self.create_begin(),
                    Key::Esc | Key::Backspace => {
                        self.wl.creating = None;
                        self.pop();
                    }
                    _ => {}
                }
            }
            WlStep::CreateKeys => match ev.key {
                Key::Enter | Key::Right => self.start_scan(scan::Purpose::Cosigner),
                Key::Esc | Key::Backspace => set(self, WlStep::CreateSize { field: 0 }),
                _ => {}
            },
            WlStep::CreateConfirm { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => set(self, WlStep::CreateConfirm { sel: s }),
                Pick::Choose(0) => {
                    let Some(cr) = self.wl.creating.as_mut() else {
                        return;
                    };
                    if let Some(c) = cr.candidate.take() {
                        cr.keys[cr.count as usize] = Some(c);
                        cr.count += 1;
                    }
                    if cr.count == cr.n {
                        self.create_finish();
                    } else {
                        set(self, WlStep::CreateKeys);
                    }
                }
                Pick::Choose(_) | Pick::Back => {
                    if let Some(cr) = self.wl.creating.as_mut() {
                        cr.candidate = None;
                    }
                    set(self, WlStep::CreateKeys);
                }
                Pick::None => {}
            },
            WlStep::CreateRefused => {
                if matches!(ev.key, Key::Enter | Key::Esc | Key::Backspace | Key::Left) {
                    self.wl.problem = None;
                    set(self, WlStep::CreateKeys);
                }
            }
            WlStep::KeyScript { slot, sel } => match ev.key {
                Key::Left | Key::Right => {
                    let d: i32 = if ev.key == Key::Right { 1 } else { -1 };
                    self.wl.key_account = (self.wl.key_account as i32 + d).clamp(0, 999) as u32;
                    self.dirty = true;
                }
                k => match crate::pick(k, sel, 2) {
                    Pick::Move(s) => set(self, WlStep::KeyScript { slot, sel: s }),
                    Pick::Choose(s) => self.push(Screen::Wallets {
                        step: WlStep::KeyFormat {
                            slot,
                            script: s,
                            sel: 0,
                        },
                    }),
                    Pick::Back => self.pop(),
                    Pick::None => {}
                },
            },
            WlStep::KeyFormat { slot, script, sel } => match crate::pick(ev.key, sel, 3) {
                Pick::Move(s) => set(self, WlStep::KeyFormat { slot, script, sel: s }),
                Pick::Choose(s) => self.open_qr(QrKind::MsKey {
                    slot,
                    script: if script == 0 {
                        MsScript::Wsh
                    } else {
                        MsScript::ShWsh
                    },
                    account: self.wl.key_account,
                    format: KeyFormat::ALL[s as usize],
                }),
                Pick::Back => self.pop(),
                Pick::None => {}
            },
        }
    }

    /// The QR payload for exporting registered wallet `idx`.
    pub(crate) fn wallet_qr(&self, idx: u8, format: WalletFormat) -> Option<crate::qrview::QrSession> {
        use crate::qrview::{Density, Format as QF, QrSession, Speed, PAYLOAD_MAX, TEXT_MAX};
        let e = self.wallets.get(idx)?;
        let w = &e.wallet;
        let mut text = [0u8; bp_bitcoin::multisig::descriptor::MAX_DESCRIPTOR];
        let mut buf = [0u8; PAYLOAD_MAX];
        let (fmt, n) = match format {
            WalletFormat::Descriptor | WalletFormat::Specter | WalletFormat::Bbqr => {
                let n = bp_bitcoin::multisig::descriptor::write(
                    w,
                    bp_bitcoin::multisig::descriptor::Form::Multipath,
                    &mut text,
                )?;
                match format {
                    WalletFormat::Descriptor => {
                        if n > TEXT_MAX {
                            return None;
                        }
                        buf[..n].copy_from_slice(&text[..n]);
                        (QF::Static, n)
                    }
                    WalletFormat::Specter => {
                        buf[..n].copy_from_slice(&text[..n]);
                        (QF::Specter, n)
                    }
                    _ => {
                        let mut work = [0u8; PAYLOAD_MAX];
                        let b = bp_qr::bbqr::Bbqr::new(
                            &text[..n],
                            bp_qr::bbqr::FileType::Unicode,
                            bp_qr::bbqr::Encoding::Zlib,
                            1,
                            40,
                            &mut work,
                            &mut buf,
                        )
                        .ok()?;
                        let enc = b.encoding();
                        let len = b.chars().len();
                        (
                            QF::Bbqr {
                                encoding: enc,
                                file_type: bp_qr::bbqr::FileType::Unicode,
                            },
                            len,
                        )
                    }
                }
            }
            WalletFormat::ColdcardUr => {
                let name = self.wallet_name(e);
                let n = formats::write_coldcard(w, name.as_str(), &mut text)?;
                let mut wr = bp_qr::ur::cbor::Writer::new(&mut buf);
                wr.bytes(&text[..n]).ok()?;
                (QF::Ur("bytes"), wr.len())
            }
        };
        QrSession::new(fmt, &buf[..n], Density::Auto, Speed::Normal)
    }

    /// The wallet's name, or "Bitpunk-<code>" when it has none.
    /// A wallet export as a file: the descriptor, or the Coldcard file.
    /// Returns the file stem and the length written.
    pub(crate) fn wallet_export_file(
        &self,
        idx: u8,
        format: WalletFormat,
        out: &mut [u8],
    ) -> Option<(bp_fat::Name, usize)> {
        let e = self.wallets.get(idx)?;
        let name = self.wallet_name(e);
        let mut stem = bp_fat::Name::empty();
        file_stem(name.as_str(), &mut stem);
        let n = match format {
            WalletFormat::ColdcardUr => {
                stem.push_str("-coldcard");
                formats::write_coldcard(&e.wallet, name.as_str(), out)?
            }
            _ => {
                stem.push_str("-descriptor");
                let n = bp_bitcoin::multisig::descriptor::write(
                    &e.wallet,
                    bp_bitcoin::multisig::descriptor::Form::Multipath,
                    out,
                )?;
                *out.get_mut(n)? = b'\n';
                n + 1
            }
        };
        Some((stem, n))
    }

    /// The Bitpunk wallet file (`.bpw`) of a registered wallet.
    pub(crate) fn wallet_bpw(&self, idx: u8, out: &mut [u8]) -> Option<(bp_fat::Name, usize)> {
        let e = self.wallets.get(idx)?;
        let name = self.wallet_name(e);
        let d = e.code.display();
        let code = core::str::from_utf8(&d).ok()?;
        let n = formats::write_bpw(&e.wallet, name.as_str(), code, &e.tag, out)?;
        let mut stem = bp_fat::Name::empty();
        file_stem(name.as_str(), &mut stem);
        Some((stem, n))
    }

    /// This device's BIP-48 keys as Coldcard's multisig JSON (`ccxp-…`).
    pub(crate) fn ms_key_json(&self, slot: u8, account: u32, out: &mut [u8]) -> Option<usize> {
        let net = self.settings.network;
        let seed = self.slot(slot as usize)?;
        let key = |sc: MsScript| -> Option<Cosigner> {
            let path = sc.account_path(net, account);
            Some(Cosigner {
                fingerprint: seed.fingerprint,
                origin: path,
                xpub: seed.master().derive_path(&path).ok()?.to_xpub(),
                version: bp_bitcoin::bip32::KeyVersion::X,
            })
        };
        let test = net != bp_bitcoin::Network::Mainnet;
        formats::write_coldcard_xpub_json(&key(MsScript::Wsh)?, &key(MsScript::ShWsh)?, account, test, out)
    }

    /// A wallet file from the card. A `.bpw` whose tag one of the loaded
    /// seeds recomputes is registered without the code (the registration
    /// rules are checked again); anything else goes through the normal
    /// import (every cosigner checked, or the code typed). Pushes the
    /// wallet screens.
    pub(crate) fn wallet_import_file(&mut self, text: &[u8]) {
        self.push(Screen::Wallets {
            step: WlStep::List { sel: 0 },
        });
        if !text.starts_with(formats::BPW_HEADER.as_bytes()) && !text.starts_with(b"\xEF\xBB\xBF# Bitpunk") {
            self.wallet_import(text, false);
            return;
        }
        let bpw = match formats::parse_bpw(text) {
            Ok(b) => b,
            Err(e) => {
                self.wl.pending = None;
                self.wl.problem = Some(Problem::Format(e));
                self.set_current(Screen::Wallets {
                    step: WlStep::Refused,
                });
                return;
            }
        };
        let mut desc = [0u8; bp_bitcoin::multisig::descriptor::MAX_DESCRIPTOR];
        let n = bpw.descriptor.len().min(desc.len());
        desc[..n].copy_from_slice(&bpw.descriptor[..n]);
        let (tag, name) = (bpw.tag, {
            let mut b = [0u8; 64];
            let k = bpw.name.len().min(64);
            b[..k].copy_from_slice(&bpw.name.as_bytes()[..k]);
            (b, k)
        });
        let code_ok = |c: &Code| core::str::from_utf8(&c.display()).ok() == Some(bpw.code);
        let matched = formats::parse_wallet(&desc[..n]).ok().and_then(|imp| {
            let code = Code::from_tag(&tag);
            if !code_ok(&code) {
                return None;
            }
            self.seeds.iter().enumerate().find_map(|(i, s)| {
                let s = s.as_ref()?;
                (CodeKey::new(s.master()).tag(&imp.wallet) == tag).then_some((i, imp))
            })
        });
        let name = core::str::from_utf8(&name.0[..name.1]).unwrap_or("");
        match matched {
            Some((slot, mut imp)) => {
                imp.wallet.set_name(name);
                self.wl.pending = None;
                self.wl.problem = None;
                self.wl.clear_input();
                if self.make_pending(imp.wallet, Some(imp.format), slot, false) {
                    if let Some(idx) = self.wallet_register() {
                        self.notice = Some(self.text().sd.registered_from_file);
                        self.set_current(Screen::Wallets {
                            step: WlStep::Registered { idx, sel: 0 },
                        });
                    }
                }
            }
            None => {
                self.wallet_import(&desc[..n], false);
                if let Some(p) = self.wl.pending.as_mut() {
                    p.wallet.set_name(name);
                }
            }
        }
        bp_crypto::secret::wipe(&mut desc);
    }

    pub(crate) fn wallet_name(&self, e: &Entry) -> Buf<24> {
        if e.wallet.name().is_empty() {
            let c = core::str::from_utf8(&e.code.0[..4]).unwrap_or("");
            fill("Bitpunk-{}", &[&c])
        } else {
            fill("{}", &[&e.wallet.name()])
        }
    }

    /// Can `addr` (scanned) be one of the registered wallets' addresses?
    pub(crate) fn ms_search_possible(&self, addr: &str) -> bool {
        let Some((spk, n)) = bp_bitcoin::address::script_of(addr, self.settings.network) else {
            return false;
        };
        bp_bitcoin::multisig::Search::new(&spk[..n], &self.multisig_wallets()).is_some()
    }

    /// Search the registered wallets for `addr` (replaces the current screen).
    pub(crate) fn start_ms_search(&mut self, addr: &str) {
        let Some((spk, n)) = bp_bitcoin::address::script_of(addr, self.settings.network) else {
            return;
        };
        self.wl.search = bp_bitcoin::multisig::Search::new(&spk[..n], &self.multisig_wallets());
        let len = addr.len().min(MAX_ADDRESS_LEN);
        self.wl.search_addr[..len].copy_from_slice(&addr.as_bytes()[..len]);
        self.wl.search_len = len;
        self.set_current(Screen::Wallets {
            step: WlStep::AddrSearch,
        });
    }

    /// Run the address search while its screen is shown. True to redraw.
    pub(crate) fn wallets_tick(&mut self) -> bool {
        if self.current()
            != (Screen::Wallets {
                step: WlStep::AddrSearch,
            })
        {
            return false;
        }
        let wallets: [Option<Wallet>; register::MAX_WALLETS] =
            core::array::from_fn(|i| self.wallets.get(i as u8).map(|e| e.wallet));
        let refs: [Option<&Wallet>; register::MAX_WALLETS] = core::array::from_fn(|i| wallets[i].as_ref());
        let Some(sr) = self.wl.search.as_mut() else {
            return false;
        };
        use bp_bitcoin::multisig::SearchState;
        match sr.step(&refs, 8) {
            SearchState::Searching => {}
            SearchState::Paused => self.set_current(Screen::Wallets {
                step: WlStep::AddrPaused { sel: 0 },
            }),
            SearchState::Found { .. } => self.set_current(Screen::Wallets {
                step: WlStep::AddrFound,
            }),
        }
        true
    }

    /// Why the last wallet or key was refused.
    fn problem_line(&self) -> Buf<256> {
        let t = self.text().wl;
        match self.wl.problem {
            Some(Problem::Format(e)) => fill(t.format_errors[format_error_index(e)], &[]),
            Some(Problem::Reject(r)) => {
                let arg: Buf<16> = match r.kind {
                    RejectKind::Network => fill("{}", &[&self.settings.network.name()]),
                    _ => fill("{}", &[&(r.key.unwrap_or(0) as usize + 1)]),
                };
                fill(t.rejects[reject_index(r.kind)], &[&arg.as_str()])
            }
            None => Buf::new(),
        }
    }

    /// The registered wallets by registry slot (for the validator).
    pub(crate) fn multisig_wallets(&self) -> [Option<&Wallet>; register::MAX_WALLETS] {
        core::array::from_fn(|i| self.wallets.get(i as u8).map(|e| &e.wallet))
    }

    pub(crate) fn render_wallets(&self, c: &mut dyn Canvas, step: WlStep) {
        let s = self.text();
        let t = s.wl;
        self.status(c, t.menu);
        let top = STATUS_H + 16;
        match step {
            WlStep::NeedSeed => {
                widgets::message_at(c, STATUS_H + 90, t.need_seed, theme::WARN, &[t.need_seed_1]);
                widgets::hint_bar(c, &[("Esc", s.h_back)]);
            }
            WlStep::Refused => {
                let line = self.problem_line();
                widgets::message_at(c, STATUS_H + 90, t.refused, theme::DANGER, &[line.as_str()]);
                widgets::hint_bar(c, &[("Esc", s.h_back)]);
            }
            WlStep::List { sel } => {
                let (idx, n) = self.wallet_indices();
                let mut labels: [Buf<40>; register::MAX_WALLETS] = Default::default();
                let mut details: [Buf<40>; register::MAX_WALLETS] = Default::default();
                for k in 0..n {
                    let e = self.wallets.get(idx[k]).expect("listed");
                    labels[k] = fill("{}", &[&self.wallet_name(e).as_str()]);
                    details[k] = fill(t.policy, &[&e.wallet.m, &e.wallet.n(), &e.wallet.script.name()]);
                }
                let items: [MenuItem; register::MAX_WALLETS + 3] = core::array::from_fn(|k| {
                    if k < n {
                        MenuItem {
                            label: labels[k].as_str(),
                            detail: details[k].as_str(),
                        }
                    } else {
                        let (label, detail) = match k - n {
                            0 => (t.import, t.import_detail),
                            1 => (t.create, t.create_detail),
                            _ => (t.export_key, t.export_key_detail),
                        };
                        MenuItem { label, detail }
                    }
                });
                widgets::list(c, MARGIN, top, W, 364, &items[..n + 3], sel as usize, true);
                if n == 0 {
                    BODY.draw(c, MARGIN, top + 176, t.empty, theme::TEXT_DIM);
                }
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            WlStep::Summary { sel } => self.render_wallet_summary(c, sel),
            WlStep::Cosigner { i } => {
                if let Some(p) = self.wl.pending.as_ref() {
                    render_cosigner(s, c, &p.wallet, i, p.checked.ours, p.wallet.n());
                }
                widgets::hint_bar(c, &[("<>", s.h_prev_next), ("Esc", s.h_back)]);
            }
            WlStep::Keys { idx, i } => {
                if let Some(e) = self.wallets.get(idx) {
                    render_cosigner(s, c, &e.wallet, i, e.ours, e.wallet.n());
                }
                widgets::hint_bar(c, &[("<>", s.h_prev_next), ("Esc", s.h_back)]);
            }
            WlStep::Addresses => {
                let Some(p) = self.wl.pending.as_ref() else { return };
                TITLE.draw(c, MARGIN, top, t.addr_title, theme::TEXT);
                let mut y = top + 50;
                for (b, label) in [(0usize, t.receive_n), (1, t.change_n)] {
                    let l: Buf<32> = fill(label, &[&0]);
                    widgets::label(c, MARGIN, y, l.as_str());
                    y = BODY.draw_wrapped(c, MARGIN, y + 22, W, 28, 3, p.address(b), theme::TEXT) + 14;
                }
                SMALL.draw_wrapped(c, MARGIN, y + 6, W, 22, 3, t.addr_note, theme::TEXT_DIM);
                widgets::hint_bar(c, &[("Enter", t.h_next), ("Esc", s.h_back)]);
            }
            WlStep::CodeShow => {
                let Some(p) = self.wl.pending.as_ref() else { return };
                TITLE.draw(c, MARGIN, top, t.code_title, theme::TEXT);
                let d = p.code.display();
                let code = core::str::from_utf8(&d).unwrap_or("");
                HUGE.draw_centered(c, 0, 800, top + 70, code, theme::ACCENT);
                let mut y = top + 150;
                for l in t.code_lines {
                    y = BODY.draw_wrapped(c, MARGIN, y, W, 28, 3, l, theme::TEXT) + 8;
                }
                widgets::hint_bar(c, &[("Enter", t.h_next), ("Esc", s.h_back)]);
            }
            WlStep::CodeEntry { rereg } => {
                TITLE.draw(c, MARGIN, top, t.entry_title, theme::TEXT);
                widgets::label(c, MARGIN, top + 56, t.entry_label);
                let typed = core::str::from_utf8(&self.wl.input[..self.wl.len]).unwrap_or("");
                // the placeholder shrinks as characters are typed
                const PLACEHOLDER: &str = "XXXX-XXXX";
                let ghost = PLACEHOLDER.get(typed.len()..).unwrap_or("");
                widgets::text_field(c, MARGIN, top + 80, 360, typed, ghost, &TITLE);
                let msg = match self.wl.bad {
                    1 if rereg => Some(t.entry_bad_rereg),
                    1 => Some(t.entry_bad_confirm),
                    2 => Some(t.entry_invalid),
                    _ => None,
                };
                if let Some(m) = msg {
                    BODY.draw_wrapped(c, MARGIN, top + 160, W, 28, 3, m, theme::DANGER);
                }
                widgets::hint_bar(c, &[("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            WlStep::Registered { idx, sel } => {
                let Some(e) = self.wallets.get(idx) else { return };
                TITLE.draw(c, MARGIN, top, t.done_title, theme::OK);
                let name = self.wallet_name(e);
                BODY.draw(c, MARGIN, top + 50, name.as_str(), theme::TEXT);
                let d = e.code.display();
                let pol: Buf<64> = fill(t.policy, &[&e.wallet.m, &e.wallet.n(), &e.wallet.script.name()]);
                let line: Buf<96> = fill(
                    "{}  {}",
                    &[&pol.as_str(), &core::str::from_utf8(&d).unwrap_or("")],
                );
                BODY.draw(c, MARGIN, top + 82, line.as_str(), theme::TEXT_DIM);
                SMALL.draw(c, MARGIN, top + 116, t.done_line, theme::TEXT_DIM);
                if let Some(n) = self.notice {
                    SMALL.draw(c, MARGIN, top + 140, n, theme::OK);
                }
                let items = t.done_options.map(|l| MenuItem { label: l, detail: "" });
                widgets::list(c, MARGIN, top + 176, W, 110, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select)]);
            }
            WlStep::Wallet { idx, sel } => {
                let Some(e) = self.wallets.get(idx) else { return };
                let name = self.wallet_name(e);
                TITLE.draw(c, MARGIN, top, name.as_str(), theme::TEXT);
                let d = e.code.display();
                let pol: Buf<64> = fill(t.policy, &[&e.wallet.m, &e.wallet.n(), &e.wallet.script.name()]);
                let line: Buf<96> = fill(
                    "{}  {}",
                    &[&pol.as_str(), &core::str::from_utf8(&d).unwrap_or("")],
                );
                BODY.draw(c, MARGIN, top + 46, line.as_str(), theme::TEXT_DIM);
                let items = t.wallet_options.map(|l| MenuItem { label: l, detail: "" });
                widgets::list(c, MARGIN, top + 90, W, 220, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            WlStep::Export { idx, sel } => {
                TITLE.draw(c, MARGIN, top, t.export_title, theme::TEXT);
                let f = t.export_formats;
                let b = s.sd.bpw_export;
                let items = [f[0], f[1], f[2], f[3], b].map(|(l, d)| MenuItem { label: l, detail: d });
                widgets::list(c, MARGIN, top + 44, W, 5 * 52, &items, sel as usize, false);
                if let Some(n) = self.notice {
                    SMALL.draw(c, MARGIN, top + 44 + 5 * 52 + 4, n, theme::WARN);
                }
                let shared = self.wallets.get(idx).is_some_and(|e| {
                    e.wallet
                        .keys()
                        .iter()
                        .all(|k| k.origin == e.wallet.keys()[0].origin)
                });
                if !shared && sel == 2 {
                    SMALL.draw_wrapped(c, MARGIN, top + 276, W, 22, 2, t.export_paths_note, theme::WARN);
                }
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            WlStep::Address { idx, change, index } => {
                let Some(e) = self.wallets.get(idx) else { return };
                let name = self.wallet_name(e);
                let pos: Buf<32> = fill(if change { t.change_n } else { t.receive_n }, &[&index]);
                let title: Buf<96> = fill(t.addr_view_title, &[&name.as_str(), &pos.as_str()]);
                TITLE.draw(c, MARGIN, top, title.as_str(), theme::TEXT);
                let mut a = [0u8; MAX_ADDRESS_LEN];
                let n = e
                    .wallet
                    .derive(change as u32, index)
                    .map(|sc| sc.address(self.settings.network, &mut a))
                    .unwrap_or(0);
                let addr = core::str::from_utf8(&a[..n]).unwrap_or("");
                // the QR on the right (bech32 upper-cased: alphanumeric mode)
                let mut q = a;
                if addr.starts_with(self.settings.network.hrp()) {
                    q[..n].make_ascii_uppercase();
                }
                if let Ok(code) = bp_qr::QrCode::encode(&q[..n], bp_qr::qr::Ecc::Medium, 1, 40, None) {
                    self.draw_qr(
                        c,
                        &code,
                        800 - MARGIN - 300,
                        top + 50,
                        300,
                        300,
                        widgets::QrStyle {
                            light: 255,
                            invert: false,
                        },
                    );
                }
                // 4 groups of 4 per line: room for the QR on the right
                let mut y = top + 60;
                for chunk in addr.as_bytes().chunks(16) {
                    let mut line = Buf::<24>::new();
                    for (i, g) in chunk.chunks(4).enumerate() {
                        if i > 0 {
                            line.push_str(" ");
                        }
                        line.push_str(core::str::from_utf8(g).unwrap_or(""));
                    }
                    TITLE.draw(c, MARGIN, y, line.as_str(), theme::TEXT);
                    y += TITLE.height as i32 + 8;
                }
                let pol: Buf<64> = fill(t.policy, &[&e.wallet.m, &e.wallet.n(), &e.wallet.script.name()]);
                SMALL.draw(c, MARGIN, top + 330, pol.as_str(), theme::TEXT_DIM);
                widgets::hint_bar(c, &[("<>", t.h_index), ("Tab", t.h_branch), ("Esc", s.h_back)]);
            }
            WlStep::AddrSearch | WlStep::AddrPaused { .. } => {
                let Some(sr) = self.wl.search.as_ref() else { return };
                SMALL.draw(c, MARGIN, top - 4, self.wl.search_addr(), theme::TEXT_DIM);
                let paused = matches!(step, WlStep::AddrPaused { .. });
                let (head, col) = if paused {
                    (s.va_not_found, theme::WARN)
                } else {
                    (t.va_ms_searching, theme::TEXT)
                };
                TITLE.draw(c, MARGIN, top + 18, head, col);
                let mut names: Buf<128> = Buf::new();
                for (i, (_, e)) in self.wallets.iter().enumerate() {
                    if i > 0 {
                        names.push_str(", ");
                    }
                    names.push_str(self.wallet_name(e).as_str());
                }
                let l: Buf<160> = fill(t.va_ms_wallets, &[&names.as_str()]);
                let mut y = BODY.draw_wrapped(c, MARGIN, top + 64, W, 28, 2, l.as_str(), theme::TEXT) + 8;
                let limit = sr.limit();
                let frac = sr.scanned() as f64 / limit.max(1) as f64;
                widgets::progress_bar(c, MARGIN, y, W, 10, frac, theme::ACCENT);
                y += 24;
                if let WlStep::AddrPaused { sel } = step {
                    if sr.state() == bp_bitcoin::multisig::SearchState::Paused {
                        let l: Buf<192> = fill(t.va_ms_not_found_1, &[&limit.saturating_sub(1)]);
                        y = SMALL.draw_wrapped(c, MARGIN, y, W, 22, 2, l.as_str(), theme::TEXT_DIM) + 6;
                    }
                    let items = t.va_ms_more.map(|l| MenuItem { label: l, detail: "" });
                    widgets::list(c, MARGIN, y, W, 110, &items, sel as usize, false);
                    widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
                } else {
                    widgets::hint_bar(c, &[("Esc", s.h_stop)]);
                }
            }
            WlStep::AddrFound => {
                let Some(sr) = self.wl.search.as_ref() else { return };
                let bp_bitcoin::multisig::SearchState::Found {
                    wallet,
                    branch,
                    index,
                } = sr.state()
                else {
                    return;
                };
                TITLE.draw(c, MARGIN, top, s.va_found, theme::OK);
                let name = self
                    .wallets
                    .get(wallet)
                    .map(|e| self.wallet_name(e))
                    .unwrap_or_default();
                let pos: Buf<32> = fill(if branch == 1 { t.change_n } else { t.receive_n }, &[&index]);
                let l: Buf<192> = fill(t.va_ms_found_1, &[&pos.as_str(), &name.as_str()]);
                let y = BODY.draw_wrapped(c, MARGIN, top + 50, W, 28, 2, l.as_str(), theme::TEXT) + 12;
                crate::review_view::address_lines(c, MARGIN, y, self.wl.search_addr());
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
            WlStep::PickSeed { sel, .. } => {
                TITLE.draw(c, MARGIN, top, t.pick_seed, theme::TEXT);
                let (v, n) = self.loaded_slots();
                let labels: [Buf<40>; 3] = core::array::from_fn(|k| {
                    self.slot(v[k] as usize)
                        .map(crate::view::seed_label)
                        .unwrap_or_default()
                });
                let items: [MenuItem; 3] = core::array::from_fn(|k| MenuItem {
                    label: labels[k].as_str(),
                    detail: "",
                });
                widgets::list(c, MARGIN, top + 44, W, 170, &items[..n], sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            WlStep::CreateSize { field } => {
                let Some(cr) = self.wl.creating.as_ref() else {
                    return;
                };
                TITLE.draw(c, MARGIN, top, t.create_title, theme::TEXT);
                let values: [Buf<24>; 4] = [
                    fill("{}", &[&cr.script.name()]),
                    fill("{}", &[&cr.m]),
                    fill("{}", &[&cr.n]),
                    fill("{}", &[&cr.account]),
                ];
                for (i, (label, value)) in t.create_fields.iter().zip(values.iter()).enumerate() {
                    let y = top + 50 + i as i32 * 44;
                    let on = i == field as usize;
                    if on {
                        bp_ui::draw::round_rect(c, MARGIN, y - 6, W, 38, 8, theme::SURFACE_HI);
                    }
                    BODY.draw(
                        c,
                        MARGIN + 14,
                        y,
                        label,
                        if on { theme::TEXT } else { theme::TEXT_DIM },
                    );
                    let v: Buf<32> = fill("< {} >", &[&value.as_str()]);
                    let vw = BODY.text_width(v.as_str());
                    BODY.draw(
                        c,
                        800 - MARGIN - 14 - vw,
                        y,
                        v.as_str(),
                        if on { theme::ACCENT } else { theme::TEXT },
                    );
                }
                let pol: Buf<64> = fill(t.policy, &[&cr.m, &cr.n, &cr.script.name()]);
                BODY.draw(c, MARGIN, top + 234, pol.as_str(), theme::ACCENT);
                SMALL.draw_wrapped(c, MARGIN, top + 270, W, 22, 3, t.create_note, theme::TEXT_DIM);
                widgets::hint_bar(
                    c,
                    &[
                        ("^v", s.h_move),
                        ("<>", t.h_change),
                        ("Enter", t.h_next),
                        ("Esc", s.h_back),
                    ],
                );
            }
            WlStep::CreateKeys => {
                let Some(cr) = self.wl.creating.as_ref() else {
                    return;
                };
                let title: Buf<48> = fill(t.keys_title, &[&cr.count, &cr.n]);
                TITLE.draw(c, MARGIN, top, title.as_str(), theme::TEXT);
                // two columns of up to 8 rows (N ≤ 15)
                for (i, k) in cr.keys().enumerate() {
                    let (col, row) = (i / 8, i % 8);
                    let x = MARGIN + col as i32 * 410;
                    let y = top + 44 + row as i32 * 20;
                    let fp = fingerprint_hex(&k.fingerprint);
                    let num: Buf<4> = fill(if i < 9 { " {}" } else { "{}" }, &[&(i + 1)]);
                    let l: Buf<96> = fill("{}  {}  {}", &[&num.as_str(), &fp.as_str(), &k.origin]);
                    let end = SMALL.draw(c, x, y, l.as_str(), theme::TEXT);
                    if i == 0 {
                        widgets::badge(
                            c,
                            end + 10,
                            y - 2,
                            t.this_badge,
                            theme::ACCENT,
                            theme::ACCENT_TEXT,
                        );
                    }
                }
                let next: Buf<48> = fill(t.scan_next, &[&(cr.count + 1)]);
                options(c, 446 - 6 - OPTION_H, &[next.as_str()], 0);
                SMALL.draw_wrapped(
                    c,
                    MARGIN,
                    446 - 6 - OPTION_H - 50,
                    W,
                    22,
                    2,
                    t.keys_note,
                    theme::TEXT_DIM,
                );
                widgets::hint_bar(c, &[("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            WlStep::CreateConfirm { sel } => {
                let Some(cr) = self.wl.creating.as_ref() else {
                    return;
                };
                if let Some(w) = cr.with_candidate() {
                    render_cosigner(s, c, &w, cr.count, Some(0), cr.n);
                }
                options(c, 446 - 6 - 2 * OPTION_H, &t.confirm_options, sel);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select)]);
            }
            WlStep::CreateRefused => {
                let line = self.problem_line();
                widgets::message_at(c, STATUS_H + 90, t.key_refused, theme::DANGER, &[line.as_str()]);
                widgets::hint_bar(c, &[("Esc", s.h_back)]);
            }
            WlStep::KeyScript { slot, sel } => {
                TITLE.draw(c, MARGIN, top, t.key_title, theme::TEXT);
                let label = self
                    .slot(slot as usize)
                    .map(crate::view::seed_label)
                    .unwrap_or_default();
                BODY.draw(c, MARGIN, top + 44, label.as_str(), theme::TEXT_DIM);
                let items = [MsScript::Wsh, MsScript::ShWsh].map(|sc| MenuItem {
                    label: sc.name(),
                    detail: "",
                });
                widgets::list(c, MARGIN, top + 84, W, 110, &items, sel as usize, false);
                let acct: Buf<48> = fill(t.account_line, &[&self.wl.key_account]);
                let path = [MsScript::Wsh, MsScript::ShWsh][sel as usize & 1]
                    .account_path(self.settings.network, self.wl.key_account);
                let l: Buf<96> = fill("< {} >   {}", &[&acct.as_str(), &path]);
                BODY.draw(c, MARGIN, top + 206, l.as_str(), theme::ACCENT);
                widgets::hint_bar(
                    c,
                    &[
                        ("^v", s.h_move),
                        ("<>", t.h_change),
                        ("Enter", s.h_select),
                        ("Esc", s.h_back),
                    ],
                );
            }
            WlStep::KeyFormat { sel, .. } => {
                TITLE.draw(c, MARGIN, top, t.key_title, theme::TEXT);
                let items = t.key_formats.map(|(l, d)| MenuItem { label: l, detail: d });
                widgets::list(c, MARGIN, top + 44, W, 170, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            WlStep::Remove { idx, sel } => {
                let Some(e) = self.wallets.get(idx) else { return };
                let name = self.wallet_name(e);
                let q: Buf<96> = fill(t.remove_q, &[&name.as_str()]);
                BODY.draw_wrapped(c, MARGIN, top + 10, W, 28, 2, q.as_str(), theme::TEXT);
                let items = t.remove_options.map(|l| MenuItem { label: l, detail: "" });
                widgets::list(c, MARGIN, top + 90, W, 110, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select)]);
            }
        }
    }

    fn render_wallet_summary(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        let t = s.wl;
        let Some(p) = self.wl.pending.as_ref() else { return };
        let w = &p.wallet;
        let top = STATUS_H + 12;
        TITLE.draw(c, MARGIN, top, t.summary_title, theme::TEXT);
        let name = if w.name().is_empty() { t.unnamed } else { w.name() };
        BODY.draw(c, MARGIN, top + 42, name, theme::ACCENT);
        if let Some(f) = p.format {
            let from: Buf<64> = fill(t.read_from, &[&t.formats[format_index(f)]]);
            let fw = SMALL.text_width(from.as_str());
            SMALL.draw(c, 800 - MARGIN - fw, top + 46, from.as_str(), theme::TEXT_DIM);
        }
        let pol: Buf<96> = fill(
            t.policy_line,
            &[&w.m, &w.n(), &w.script.name(), &self.settings.network.name()],
        );
        BODY.draw(c, MARGIN, top + 72, pol.as_str(), theme::TEXT);
        let mut y = top + 102;
        let fp = self
            .slot(p.slot as usize)
            .map(|x| fingerprint_hex(&x.fingerprint))
            .unwrap_or_default();
        match p.checked.ours {
            Some(i) => {
                let l: Buf<96> = fill(t.this_device, &[&(i as usize + 1), &w.n(), &fp.as_str()]);
                BODY.draw(c, MARGIN, y, l.as_str(), theme::TEXT);
                y += 32;
            }
            None => {
                let l: Buf<128> = fill(t.watch_only, &[&fp.as_str()]);
                y = BODY.draw_wrapped(c, MARGIN, y, W, 26, 2, l.as_str(), theme::WARN) + 4;
            }
        }
        // the options sit at the bottom; warnings fill the space above them
        let items: &[&str] = if p.checked.duplicate.is_some() {
            &t.duplicate_options
        } else {
            &t.summary_options
        };
        let list_top = 446 - 6 - items.len() as i32 * OPTION_H;
        let wn = &p.checked.warnings;
        let mut warns: [Buf<160>; 6] = Default::default();
        let mut nw = 0;
        if let Some(d) = p.checked.duplicate {
            let name = self
                .wallets
                .get(d)
                .map(|e| self.wallet_name(e))
                .unwrap_or_default();
            warns[nw] = fill(t.duplicate, &[&name.as_str()]);
            nw += 1;
        }
        if p.two_seeds {
            warns[nw] = fill(t.w_two_seeds, &[]);
            nw += 1;
        }
        if let Some(i) = wn.similar {
            let name = self
                .wallets
                .get(i)
                .map(|e| self.wallet_name(e))
                .unwrap_or_default();
            warns[nw] = fill(t.w_similar, &[&name.as_str()]);
            nw += 1;
        }
        if wn.one_of_n {
            warns[nw] = fill(t.w_one_of_n, &[]);
            nw += 1;
        }
        if wn.our_path {
            warns[nw] = fill(t.w_our_path, &[]);
            nw += 1;
        }
        if wn.cosigner_paths > 0 {
            warns[nw] = fill(t.w_cosigner_paths, &[&wn.cosigner_paths]);
            nw += 1;
        }
        for wline in &warns[..nw] {
            // a warning that would not fit whole is not drawn half
            let lines = if SMALL.text_width(wline.as_str()) > W {
                2
            } else {
                1
            };
            if y + lines * 20 > list_top - 4 {
                break;
            }
            y = SMALL.draw_wrapped(c, MARGIN, y, W, 20, 2, wline.as_str(), theme::WARN);
        }
        options(c, list_top, items, sel);
        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
    }
}

/// Height of one row of `options`.
const OPTION_H: i32 = 36;

/// A compact numbered option list (for screens that need the room).
fn options(c: &mut dyn Canvas, top: i32, items: &[&str], sel: u8) {
    for (i, label) in items.iter().enumerate() {
        let y = top + i as i32 * OPTION_H;
        let on = i == sel as usize;
        if on {
            bp_ui::draw::round_rect(c, MARGIN, y, W, OPTION_H - 4, 8, theme::ACCENT);
        }
        let fg = if on { theme::ACCENT_TEXT } else { theme::TEXT };
        let ty = y + (OPTION_H - 4 - BODY.height as i32) / 2;
        let n = [b'1' + i as u8];
        BODY.draw(
            c,
            MARGIN + 14,
            ty,
            core::str::from_utf8(&n).unwrap_or(""),
            if on { fg } else { theme::TEXT_DIM },
        );
        BODY.draw(c, MARGIN + 44, ty, label, fg);
    }
}

/// One cosigner page: number, fingerprint, path, xpub in groups.
fn render_cosigner(s: &crate::Strings, c: &mut dyn Canvas, w: &Wallet, i: u8, ours: Option<u8>, total: u8) {
    let t = s.wl;
    let Some(k) = w.keys().get(i as usize) else { return };
    let top = STATUS_H + 14;
    let title: Buf<48> = fill(t.cosigner_title, &[&(i as usize + 1), &total]);
    TITLE.draw(c, MARGIN, top, title.as_str(), theme::TEXT);
    if ours == Some(i) {
        let bw = widgets::badge_width(t.this_badge);
        widgets::badge(
            c,
            800 - MARGIN - bw,
            top + 4,
            t.this_badge,
            theme::ACCENT,
            theme::ACCENT_TEXT,
        );
    }
    let mut y = top + 48;
    widgets::label(c, MARGIN, y, t.fingerprint);
    let fp = fingerprint_hex(&k.fingerprint);
    TITLE.draw(c, MARGIN, y + 20, fp.as_str(), theme::ACCENT);
    widgets::label(c, MARGIN + 260, y, t.path);
    let path: Buf<96> = fill("{}", &[&k.origin]);
    BODY.draw(c, MARGIN + 260, y + 26, path.as_str(), theme::TEXT);
    y += 70;
    let mut x = [0u8; XKEY_LEN];
    let n = xpub_text(k, w.test, &mut x);
    let label: Buf<64> = fill("{} ({})", &[&t.xpub, &version_name(k.version, w.test)]);
    widgets::label(c, MARGIN, y, label.as_str());
    y += 24;
    // 4-character groups, 12 per line
    let text = core::str::from_utf8(&x[..n]).unwrap_or("");
    let mut line: Buf<64> = Buf::new();
    let mut groups = 0;
    for (gi, chunk) in text.as_bytes().chunks(4).enumerate() {
        if groups == 12 {
            BODY.draw(c, MARGIN, y, line.as_str(), theme::TEXT);
            y += 30;
            line = Buf::new();
            groups = 0;
        }
        if groups > 0 {
            line.push_str(" ");
        }
        line.push_str(core::str::from_utf8(chunk).unwrap_or(""));
        groups += 1;
        let _ = gi;
    }
    if groups > 0 {
        BODY.draw(c, MARGIN, y, line.as_str(), theme::TEXT);
        y += 30;
    }
    SMALL.draw_wrapped(c, MARGIN, y + 10, W, 22, 2, t.compare, theme::TEXT_DIM);
}
