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
use bp_bitcoin::multisig::{version_name, Cosigner, Wallet};
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
    pub format: Format,
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

#[derive(Default)]
pub struct WlState {
    pub pending: Option<Pending>,
    pub problem: Option<Problem>,
    input: [u8; CODE_INPUT],
    len: usize,
    /// 0 none, 1 mismatch, 2 not a code.
    pub bad: u8,
}

impl WlState {
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
        let slot = slot.unwrap_or_else(|| self.seeds.iter().position(|s| s.is_some()).unwrap_or(0));
        let Some(seed) = self.slot(slot) else { return };
        let net = self.settings.network;
        let checked = match register::check(&w, net, seed.master(), &self.wallets) {
            Ok(c) => c,
            Err(r) => {
                self.wl.problem = Some(Problem::Reject(r));
                self.set_current(Screen::Wallets {
                    step: WlStep::Refused,
                });
                return;
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
            format: imported.format,
            slot: slot as u8,
            checked,
            code: ck.code(&w),
            tag: ck.tag(&w),
            two_seeds: two,
            addr,
            addr_len,
        });
        self.set_current(Screen::Wallets {
            step: WlStep::Summary { sel: 0 },
        });
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
                match crate::pick(ev.key, sel, n as u8 + 1) {
                    Pick::Move(s) => set(self, WlStep::List { sel: s }),
                    Pick::Choose(s) if (s as usize) < n => self.push(Screen::Wallets {
                        step: WlStep::Wallet {
                            idx: idx[s as usize],
                            sel: 0,
                        },
                    }),
                    Pick::Choose(_) => {
                        if self.wallets.is_full() {
                            self.notice = Some(self.text().wl.full);
                        } else {
                            self.start_scan(scan::Purpose::Wallet);
                        }
                    }
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
                    set(self, WlStep::List { sel: 0 });
                }
                Pick::None => {}
            },
            WlStep::Wallet { idx, sel } => match crate::pick(ev.key, sel, 3) {
                Pick::Move(s) => set(self, WlStep::Wallet { idx, sel: s }),
                Pick::Choose(0) => self.push(Screen::Wallets {
                    step: WlStep::Keys { idx, i: 0 },
                }),
                Pick::Choose(1) => self.push(Screen::Wallets {
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
            WlStep::Export { idx, sel } => match crate::pick(ev.key, sel, 4) {
                Pick::Move(s) => set(self, WlStep::Export { idx, sel: s }),
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
                    self.pop(); // the wallet menu
                    self.set_current(Screen::Wallets {
                        step: WlStep::List { sel: 0 },
                    });
                }
                Pick::Choose(_) | Pick::Back => self.pop(),
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
    pub(crate) fn wallet_name(&self, e: &Entry) -> Buf<24> {
        if e.wallet.name().is_empty() {
            let c = core::str::from_utf8(&e.code.0[..4]).unwrap_or("");
            fill("Bitpunk-{}", &[&c])
        } else {
            fill("{}", &[&e.wallet.name()])
        }
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
                let mut line: Buf<256> = Buf::new();
                match self.wl.problem {
                    Some(Problem::Format(e)) => line = fill(t.format_errors[format_error_index(e)], &[]),
                    Some(Problem::Reject(r)) => {
                        let arg: Buf<16> = match r.kind {
                            RejectKind::Network => fill("{}", &[&self.settings.network.name()]),
                            _ => fill("{}", &[&(r.key.unwrap_or(0) as usize + 1)]),
                        };
                        line = fill(t.rejects[reject_index(r.kind)], &[&arg.as_str()]);
                    }
                    None => {}
                }
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
                let items: [MenuItem; register::MAX_WALLETS + 1] = core::array::from_fn(|k| {
                    if k < n {
                        MenuItem {
                            label: labels[k].as_str(),
                            detail: details[k].as_str(),
                        }
                    } else {
                        MenuItem {
                            label: t.import,
                            detail: t.import_detail,
                        }
                    }
                });
                widgets::list(c, MARGIN, top, W, 300, &items[..n + 1], sel as usize, false);
                if n == 0 {
                    BODY.draw(c, MARGIN, top + 80, t.empty, theme::TEXT_DIM);
                }
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            WlStep::Summary { sel } => self.render_wallet_summary(c, sel),
            WlStep::Cosigner { i } => {
                if let Some(p) = self.wl.pending.as_ref() {
                    render_cosigner(s, c, &p.wallet, i, p.checked.ours);
                }
                widgets::hint_bar(c, &[("<>", s.h_prev_next), ("Esc", s.h_back)]);
            }
            WlStep::Keys { idx, i } => {
                if let Some(e) = self.wallets.get(idx) {
                    render_cosigner(s, c, &e.wallet, i, e.ours);
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
                let items = t.done_options.map(|l| MenuItem { label: l, detail: "" });
                widgets::list(c, MARGIN, top + 160, W, 110, &items, sel as usize, false);
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
                widgets::list(c, MARGIN, top + 90, W, 170, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            WlStep::Export { idx, sel } => {
                TITLE.draw(c, MARGIN, top, t.export_title, theme::TEXT);
                let items = t.export_formats.map(|(l, d)| MenuItem { label: l, detail: d });
                widgets::list(c, MARGIN, top + 44, W, 220, &items, sel as usize, false);
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
        let from: Buf<64> = fill(t.read_from, &[&t.formats[format_index(p.format)]]);
        let fw = SMALL.text_width(from.as_str());
        SMALL.draw(c, 800 - MARGIN - fw, top + 46, from.as_str(), theme::TEXT_DIM);
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
fn render_cosigner(s: &crate::Strings, c: &mut dyn Canvas, w: &Wallet, i: u8, ours: Option<u8>) {
    let t = s.wl;
    let Some(k) = w.keys().get(i as usize) else { return };
    let top = STATUS_H + 14;
    let title: Buf<48> = fill(t.cosigner_title, &[&(i as usize + 1), &w.n()]);
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
