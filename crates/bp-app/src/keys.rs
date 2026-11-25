//! Seeds > Load > Import private key (M8 plan §8): a WIF or an extended
//! private key, scanned or typed (never read from the SD card, decision
//! 7). An XPRV becomes the root of a slot; a WIF a single-key slot.

use crate::seeds::{SeedSlot, SlotKind};
use crate::{App, Pick, Screen};
use bp_bitcoin::address::{self, ScriptType};
use bp_bitcoin::bip32::Xpriv;
use bp_bitcoin::wif::{self, WifError};
use bp_bitcoin::Network;
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, DOUBLE, SMALL, TITLE};
use bp_ui::theme;
use bp_ui::widgets::{self, MenuItem, MARGIN, STATUS_H};

const W: i32 = 800 - 2 * MARGIN;
/// Longest key typed (an extended key is 111 characters).
pub const KEY_INPUT: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStep {
    Method {
        sel: u8,
    },
    Type,
    Confirm {
        sel: u8,
    },
    Refused,
    /// A single key's four addresses.
    Addresses {
        slot: u8,
        sel: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProblem {
    Invalid,
    Network,
    Uncompressed,
    OutOfRange,
    Full,
    Duplicate,
}

/// The typed key (wiped when cleared and on drop).
pub struct KeyInput {
    buf: [u8; KEY_INPUT],
    len: usize,
}

impl KeyInput {
    pub const fn new() -> Self {
        KeyInput {
            buf: [0; KEY_INPUT],
            len: 0,
        }
    }
    pub fn text(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
    pub fn clear(&mut self) {
        bp_crypto::secret::wipe(&mut self.buf);
        self.len = 0;
    }
}

impl Drop for KeyInput {
    fn drop(&mut self) {
        self.clear();
    }
}

/// The key types a single-key slot shows addresses for.
pub const KEY_SCRIPTS: [ScriptType; 4] = [
    ScriptType::NativeSegwit,
    ScriptType::NestedSegwit,
    ScriptType::Legacy,
    ScriptType::Taproot,
];

/// Rows of a slot's options screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotOpt {
    Words,
    Xpub,
    Explorer,
    Passphrase,
    SeedQr,
    Discard,
    Addresses,
    /// Another set of SLIP-39 shares of this wallet (M11-2).
    Slip39Shares,
    /// Split the seed into Seed XOR parts (M11-3).
    SeedXor,
    /// The seed's dots for a metal plate (M11-4).
    Metal,
}

/// The options a slot of this kind offers.
pub fn slot_opts(kind: SlotKind) -> &'static [SlotOpt] {
    use SlotOpt::*;
    match kind {
        SlotKind::Mnemonic => &[Words, Xpub, Explorer, Passphrase, SeedQr, SeedXor, Metal, Discard],
        SlotKind::Xprv => &[Xpub, Explorer, Discard],
        SlotKind::Wif => &[Addresses, Discard],
        SlotKind::Slip39 => &[Xpub, Explorer, Passphrase, Slip39Shares, Discard],
    }
}

/// Parse a typed or scanned key for the device's network.
pub fn parse_key(text: &str, net: Network) -> Result<SeedSlot, KeyProblem> {
    let t = text.trim();
    let extended = [
        "xprv", "tprv", "yprv", "zprv", "uprv", "vprv", "Yprv", "Zprv", "Uprv", "Vprv",
    ];
    if extended.iter().any(|p| t.starts_with(p)) {
        let (x, xnet, _) = Xpriv::decode(t).map_err(|_| KeyProblem::Invalid)?;
        if (xnet == Network::Mainnet) != (net == Network::Mainnet) {
            return Err(KeyProblem::Network);
        }
        return Ok(SeedSlot::from_xprv(x));
    }
    match wif::decode(t, net) {
        Ok(sk) => SeedSlot::from_wif(&sk).ok_or(KeyProblem::OutOfRange),
        Err(WifError::Network) => Err(KeyProblem::Network),
        Err(WifError::Uncompressed) => Err(KeyProblem::Uncompressed),
        Err(WifError::OutOfRange) => Err(KeyProblem::OutOfRange),
        Err(WifError::Invalid) => Err(KeyProblem::Invalid),
    }
}

impl App {
    /// Seeds > Import private key.
    pub(crate) fn open_key_import(&mut self) {
        self.key_in.clear();
        self.key_pending = None;
        self.push(Screen::Key {
            step: KeyStep::Method { sel: 0 },
        });
    }

    /// Text from the scanner or the keyboard: check it and ask.
    pub(crate) fn key_text(&mut self, text: &str) {
        let r = parse_key(text, self.settings.network).and_then(|slot| {
            if self
                .seeds
                .iter()
                .flatten()
                .any(|s| s.fingerprint == slot.fingerprint)
            {
                Err(KeyProblem::Duplicate)
            } else if self.free_slot().is_none() {
                Err(KeyProblem::Full)
            } else {
                Ok(slot)
            }
        });
        self.key_in.clear();
        // typed: the answer goes on top (back returns to typing); scanned:
        // it replaces the scanner
        let typed = self.current() == Screen::Key { step: KeyStep::Type };
        let show = |a: &mut App, step: KeyStep| {
            if typed {
                a.push(Screen::Key { step });
            } else {
                a.set_current(Screen::Key { step });
            }
        };
        match r {
            Ok(slot) => {
                self.key_pending = Some(slot);
                self.key_problem = None;
                show(self, KeyStep::Confirm { sel: 0 });
            }
            Err(p) => {
                self.key_pending = None;
                self.key_problem = Some(p);
                show(self, KeyStep::Refused);
            }
        }
    }

    pub(crate) fn key_key(&mut self, step: KeyStep, ev: KeyEvent) {
        let set = |a: &mut App, s: KeyStep| a.set_current(Screen::Key { step: s });
        match step {
            KeyStep::Method { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => set(self, KeyStep::Method { sel: s }),
                Pick::Choose(0) => {
                    set(self, KeyStep::Method { sel: 0 });
                    self.start_scan(crate::scan::Purpose::PrivKey);
                }
                Pick::Choose(_) => {
                    self.key_in.clear();
                    self.push(Screen::Key { step: KeyStep::Type });
                }
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            KeyStep::Type => match ev.key {
                Key::Char(c) if c.is_ascii_alphanumeric() => {
                    let k = &mut self.key_in;
                    if k.len < KEY_INPUT {
                        k.buf[k.len] = c as u8;
                        k.len += 1;
                    }
                }
                Key::Backspace if self.key_in.len > 0 => {
                    let k = &mut self.key_in;
                    k.len -= 1;
                    k.buf[k.len] = 0;
                }
                Key::Enter if self.key_in.len > 0 => {
                    let mut t = [0u8; KEY_INPUT];
                    let n = self.key_in.len;
                    t[..n].copy_from_slice(&self.key_in.buf[..n]);
                    self.key_text(core::str::from_utf8(&t[..n]).unwrap_or(""));
                    bp_crypto::secret::wipe(&mut t);
                }
                Key::Esc | Key::Backspace => {
                    self.key_in.clear();
                    self.pop();
                }
                _ => {}
            },
            KeyStep::Confirm { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => set(self, KeyStep::Confirm { sel: s }),
                Pick::Choose(0) => {
                    let (Some(slot), Some(i)) = (self.key_pending.take(), self.free_slot()) else {
                        return;
                    };
                    self.seeds[i] = Some(slot);
                    self.go_seeds(Some(Screen::SeedReady {
                        slot: i as u8,
                        created: false,
                    }));
                }
                Pick::Choose(_) | Pick::Back => {
                    self.key_pending = None;
                    self.pop();
                }
                Pick::None => {}
            },
            KeyStep::Refused => {
                if matches!(ev.key, Key::Enter | Key::Esc | Key::Backspace) {
                    self.key_problem = None;
                    self.pop();
                }
            }
            KeyStep::Addresses { slot, sel } => match ev.key {
                Key::Up => set(
                    self,
                    KeyStep::Addresses {
                        slot,
                        sel: sel.saturating_sub(1),
                    },
                ),
                Key::Down => set(
                    self,
                    KeyStep::Addresses {
                        slot,
                        sel: (sel + 1).min(3),
                    },
                ),
                Key::Esc | Key::Backspace | Key::Enter | Key::Left => self.pop(),
                _ => {}
            },
        }
    }

    /// Address of a single-key slot for `st`.
    pub(crate) fn key_address(
        &self,
        slot: u8,
        st: ScriptType,
        out: &mut [u8; address::MAX_ADDRESS_LEN],
    ) -> usize {
        let Some(s) = self.slot(slot as usize) else {
            return 0;
        };
        address::encode(&s.master().public_key(), st, self.settings.network, out)
    }

    pub(crate) fn render_key(&self, c: &mut dyn Canvas, step: KeyStep) {
        let s = self.text();
        let t = s.key;
        let top = STATUS_H + 20;
        match step {
            KeyStep::Method { sel } => {
                self.status(c, t.title);
                let items = t.methods.map(|(l, d)| MenuItem { label: l, detail: d });
                widgets::list(c, MARGIN, top, W, 2 * 52, &items, sel as usize, false);
                SMALL.draw(c, MARGIN, top + 130, t.not_new[0], theme::TEXT_DIM);
                SMALL.draw(c, MARGIN, top + 156, t.not_new[1], theme::TEXT_DIM);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            KeyStep::Type => {
                self.status(c, t.title);
                TITLE.draw(c, MARGIN, top, t.type_title, theme::TEXT);
                SMALL.draw(c, MARGIN, top + 44, t.type_help, theme::TEXT_DIM);
                // the key wrapped at 37 characters, in groups the eye can check
                let text = self.key_in.text();
                let mut y = top + 90;
                let mut rest = text;
                while !rest.is_empty() {
                    let n = rest.len().min(37);
                    BODY.draw(c, MARGIN, y, &rest[..n], theme::ACCENT);
                    rest = &rest[n..];
                    y += 36;
                }
                let count: Buf<16> = fill("{}", &[&text.len()]);
                SMALL.draw(
                    c,
                    MARGIN,
                    480 - widgets::HINT_H - 26,
                    count.as_str(),
                    theme::TEXT_DIM,
                );
                widgets::hint_bar(c, &[("Enter", t.load), ("Del", s.h_back), ("Esc", s.h_back)]);
            }
            KeyStep::Confirm { sel } => {
                self.status(c, t.title);
                let Some(k) = self.key_pending.as_ref() else {
                    return;
                };
                TITLE.draw(c, MARGIN, top, t.confirm_title, theme::TEXT);
                let (kind, can) = match k.kind {
                    SlotKind::Xprv => (t.kind_xprv, t.can_xprv),
                    _ => (t.kind_wif, t.can_wif),
                };
                let fp = crate::seeds::fingerprint_hex(&k.fingerprint);
                BODY.draw(c, MARGIN, top + 46, kind, theme::ACCENT);
                // the fingerprint: data to compare, double size (M9-7)
                let x1 = BODY.draw(c, MARGIN, top + 100, t.fingerprint, theme::TEXT_DIM);
                let dy = top + 100 + BODY.baseline as i32 - DOUBLE.baseline as i32;
                DOUBLE.draw(c, x1 + 16, dy, fp.as_str(), theme::BRIGHT);
                SMALL.draw(c, MARGIN, top + 140, can, theme::TEXT_DIM);
                SMALL.draw(c, MARGIN, top + 164, t.not_new[1], theme::TEXT_DIM);
                let items = [
                    MenuItem {
                        label: t.load,
                        detail: "",
                    },
                    MenuItem {
                        label: t.cancel,
                        detail: "",
                    },
                ];
                widgets::list(c, MARGIN, top + 196, W, 2 * 52, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            KeyStep::Refused => {
                self.status(c, t.title);
                TITLE.draw(c, MARGIN, top + 20, t.refused, theme::DANGER);
                let p = self.key_problem.map_or(0, |p| p as usize);
                BODY.draw(c, MARGIN, top + 76, t.problems[p], theme::TEXT);
                self.show_error(crate::errors::Area::Key, p);
                widgets::hint_bar(c, &[("Enter", s.h_back)]);
            }
            KeyStep::Addresses { slot, sel } => {
                let label = self
                    .slot(slot as usize)
                    .map(crate::view::seed_label)
                    .unwrap_or_default();
                self.status(c, label.as_str());
                TITLE.draw(c, MARGIN, top, t.addresses, theme::TEXT);
                let mut bufs = [[0u8; address::MAX_ADDRESS_LEN]; 4];
                let mut lens = [0usize; 4];
                for (i, st) in KEY_SCRIPTS.iter().enumerate() {
                    lens[i] = self.key_address(slot, *st, &mut bufs[i]);
                }
                let names: [MenuItem; 4] = KEY_SCRIPTS.map(|st| MenuItem {
                    label: st.name(),
                    detail: "",
                });
                widgets::list(c, MARGIN, top + 44, 400, 4 * 52, &names, sel as usize, false);
                let i = sel.min(3) as usize;
                let a = core::str::from_utf8(&bufs[i][..lens[i]]).unwrap_or("");
                SMALL.draw_wrapped(c, MARGIN, top + 270, 420, 24, 3, a, theme::TEXT);
                // the selected address as a QR on the right
                let mut q = bufs[i];
                let n = lens[i];
                if a.starts_with(self.settings.network.hrp()) {
                    q[..n].make_ascii_uppercase();
                }
                if let Ok(code) = bp_qr::QrCode::encode(&q[..n], bp_qr::qr::Ecc::Medium, 1, 40, None) {
                    self.draw_qr(
                        c,
                        &code,
                        800 - MARGIN - 300,
                        top + 30,
                        300,
                        300,
                        widgets::QrStyle {
                            light: 255,
                            invert: false,
                        },
                    );
                }
                widgets::hint_bar(c, &[("^v", s.h_move), ("Esc", s.h_back)]);
            }
        }
    }
}
