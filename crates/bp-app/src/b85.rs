//! Tools > BIP-85 child keys (M8 plan §7): an application, an index, a
//! warning, then the secret on screen and as a QR. A derived mnemonic can
//! be loaded into an empty slot. Nothing is ever written to the SD card
//! (decision 6). The state is wiped when the screens close.

use crate::{App, Pick, Screen};
use bp_bitcoin::bip85::{self, App as B85App, Derived, MAX_TEXT};
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, SMALL, TITLE};
use bp_ui::theme;
use bp_ui::widgets::{self, MenuItem, MARGIN, STATUS_H};

const W: i32 = 800 - 2 * MARGIN;
const MAX_INDEX: u32 = (1 << 31) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B85Step {
    PickSeed { sel: u8 },
    App { sel: u8 },
    Params,
    Warning,
    Result { sel: u8 },
}

pub struct B85State {
    pub slot: u8,
    pub app: B85App,
    pub index: u32,
    /// Index digits typed (empty means 0).
    pub typed: bool,
    pub derived: Option<Derived>,
    pub error: Option<bip85::Error>,
}

/// The application of a row, with its default length.
fn app_of(row: u8) -> B85App {
    match row {
        0 => B85App::Bip39 { words: 12 },
        1 => B85App::Bip39 { words: 18 },
        2 => B85App::Bip39 { words: 24 },
        3 => B85App::Wif,
        4 => B85App::Xprv,
        5 => B85App::Hex { bytes: 32 },
        6 => B85App::PwdBase64 { len: 20 },
        _ => B85App::PwdBase85 { len: 20 },
    }
}

fn row_of(app: B85App) -> usize {
    match app {
        B85App::Bip39 { words: 12 } => 0,
        B85App::Bip39 { words: 18 } => 1,
        B85App::Bip39 { .. } => 2,
        B85App::Wif => 3,
        B85App::Xprv => 4,
        B85App::Hex { .. } => 5,
        B85App::PwdBase64 { .. } => 6,
        B85App::PwdBase85 { .. } => 7,
    }
}

/// Change the length of `app` by `d`, within its range.
fn adjust(app: B85App, d: i32) -> B85App {
    let step = |v: u8, lo: i32, hi: i32| (v as i32 + d).clamp(lo, hi) as u8;
    match app {
        B85App::Hex { bytes } => B85App::Hex {
            bytes: step(bytes, 16, 64),
        },
        B85App::PwdBase64 { len } => B85App::PwdBase64 {
            len: step(len, 20, 86),
        },
        B85App::PwdBase85 { len } => B85App::PwdBase85 {
            len: step(len, 10, 80),
        },
        other => other,
    }
}

impl App {
    /// Tools > BIP-85.
    pub(crate) fn open_b85(&mut self) {
        match self.seed_count() {
            0 => self.push(Screen::NoSeed),
            1 => {
                let slot = self.seed_row_slot(0).unwrap_or(0) as u8;
                self.b85_start(slot);
                if self.b85.is_some() {
                    self.push(Screen::Bip85 {
                        step: B85Step::App { sel: 0 },
                    });
                }
            }
            _ => self.push(Screen::Bip85 {
                step: B85Step::PickSeed { sel: 0 },
            }),
        }
    }

    fn b85_start(&mut self, slot: u8) {
        if self.slot(slot as usize).is_some_and(|s| s.single_key()) {
            self.b85 = None;
            self.notice = Some(self.text().key.not_for_wif);
            return;
        }
        self.b85 = Some(B85State {
            slot,
            app: B85App::Bip39 { words: 12 },
            index: 0,
            typed: false,
            derived: None,
            error: None,
        });
    }

    fn b85_set(&mut self, step: B85Step) {
        self.set_current(Screen::Bip85 { step });
    }

    pub(crate) fn b85_key(&mut self, step: B85Step, ev: KeyEvent) {
        match step {
            B85Step::PickSeed { sel } => match crate::pick(ev.key, sel, self.seed_count().max(1) as u8) {
                Pick::Move(s) => self.b85_set(B85Step::PickSeed { sel: s }),
                Pick::Choose(s) => {
                    if let Some(slot) = self.seed_row_slot(s as usize) {
                        self.b85_start(slot as u8);
                        if self.b85.is_some() {
                            self.push(Screen::Bip85 {
                                step: B85Step::App { sel: 0 },
                            });
                        }
                    }
                }
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            B85Step::App { sel } => match crate::pick(ev.key, sel, 8) {
                Pick::Move(s) => self.b85_set(B85Step::App { sel: s }),
                Pick::Choose(s) => {
                    self.b85_set(B85Step::App { sel: s });
                    if let Some(b) = self.b85.as_mut() {
                        b.app = app_of(s);
                        b.index = 0;
                        b.typed = false;
                        b.error = None;
                    }
                    self.push(Screen::Bip85 {
                        step: B85Step::Params,
                    });
                }
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            B85Step::Params => {
                let Some(b) = self.b85.as_mut() else { return };
                match ev.key {
                    Key::Char(c @ '0'..='9') => {
                        let d = c as u32 - '0' as u32;
                        let v = if b.typed {
                            b.index as u64 * 10 + d as u64
                        } else {
                            d as u64
                        };
                        if v <= MAX_INDEX as u64 {
                            b.index = v as u32;
                            b.typed = true;
                        }
                    }
                    Key::Backspace if b.typed && b.index > 0 => b.index /= 10,
                    Key::Left => b.app = adjust(b.app, -1),
                    Key::Right => b.app = adjust(b.app, 1),
                    Key::Up => b.app = adjust(b.app, 10),
                    Key::Down => b.app = adjust(b.app, -10),
                    Key::Enter => self.push(Screen::Bip85 {
                        step: B85Step::Warning,
                    }),
                    Key::Esc | Key::Backspace => self.pop(),
                    _ => {}
                }
            }
            B85Step::Warning => match ev.key {
                Key::Enter => {
                    self.b85_derive();
                    self.b85_set(B85Step::Result { sel: 0 });
                }
                Key::Esc | Key::Backspace => self.pop(),
                _ => {}
            },
            B85Step::Result { sel } => {
                let words = matches!(
                    self.b85.as_ref().and_then(|b| b.derived.as_ref()),
                    Some(Derived::Mnemonic(_))
                );
                let failed = self.b85.as_ref().is_none_or(|b| b.derived.is_none());
                let n = if failed {
                    1
                } else if words {
                    4
                } else {
                    2
                };
                match crate::pick(ev.key, sel, n) {
                    Pick::Move(s) => self.b85_set(B85Step::Result { sel: s }),
                    Pick::Choose(s) if failed || s + 1 == n => self.b85_done(),
                    Pick::Choose(s) => {
                        self.b85_set(B85Step::Result { sel: s });
                        match (words, s) {
                            (true, 2) => self.b85_load(),
                            (true, c) => self.open_qr(crate::QrKind::Bip85 { compact: c == 1 }),
                            (false, _) => self.open_qr(crate::QrKind::Bip85 { compact: false }),
                        }
                    }
                    Pick::Back => {
                        // the secret goes; back to the parameters
                        if let Some(b) = self.b85.as_mut() {
                            b.derived = None;
                        }
                        self.pop();
                    }
                    Pick::None => {}
                }
            }
        }
    }

    fn b85_derive(&mut self) {
        let net = self.settings.network;
        let Some(b) = self.b85.as_mut() else { return };
        let Some(seed) = self.seeds[b.slot as usize].as_ref() else {
            return;
        };
        match bip85::derive(seed.master(), b.app, b.index, net) {
            Ok(d) => {
                b.derived = Some(d);
                b.error = None;
            }
            Err(e) => {
                b.derived = None;
                b.error = Some(e);
            }
        }
    }

    /// Done: every BIP-85 screen closes and the state is wiped.
    fn b85_done(&mut self) {
        self.b85 = None;
        while matches!(self.current(), Screen::Bip85 { .. }) && self.depth > 1 {
            self.pop();
        }
    }

    /// Load the derived mnemonic into an empty slot.
    fn b85_load(&mut self) {
        let Some(slot) = self.free_slot() else {
            self.push(Screen::SlotsFull);
            return;
        };
        let m = match self.b85.as_ref().and_then(|b| b.derived.as_ref()) {
            Some(Derived::Mnemonic(m)) => m.clone(),
            _ => return,
        };
        let Some(seed) = crate::seeds::SeedSlot::new(m, b"") else {
            return;
        };
        self.seeds[slot] = Some(seed);
        self.b85 = None;
        self.go_seeds(Some(Screen::SeedReady {
            slot: slot as u8,
            created: false,
        }));
    }

    /// The QR session for the derived secret.
    pub(crate) fn b85_qr(&self, compact: bool) -> Option<crate::qrview::QrSession> {
        use crate::qrview::{Density, Format, QrSession, Speed};
        let d = self.b85.as_ref()?.derived.as_ref()?;
        match d {
            Derived::Mnemonic(m) => {
                let mut digits = [0u8; bp_bitcoin::seedqr::MAX_DIGITS];
                let mut ent = [0u8; 32];
                let s = if compact {
                    let n = bp_bitcoin::seedqr::compact_bytes(m, &mut ent);
                    QrSession::new(Format::SeedCompact, &ent[..n], Density::Auto, Speed::Slow)
                } else {
                    let n = bp_bitcoin::seedqr::standard_digits(m, &mut digits);
                    QrSession::new(Format::SeedStandard, &digits[..n], Density::Auto, Speed::Slow)
                };
                bp_crypto::secret::wipe(&mut digits);
                bp_crypto::secret::wipe(&mut ent);
                s
            }
            Derived::Text { .. } => {
                let mut t = [0u8; MAX_TEXT];
                let n = d.write_text(&mut t);
                let s = QrSession::new(Format::Static, &t[..n], Density::Auto, Speed::Slow);
                bp_crypto::secret::wipe(&mut t);
                s
            }
        }
    }

    /// Title for the QR screen and the result.
    pub(crate) fn b85_title(&self) -> &'static str {
        let t = self.text().b85;
        self.b85.as_ref().map_or(t.title, |b| t.apps[row_of(b.app)].0)
    }

    pub(crate) fn render_b85(&self, c: &mut dyn Canvas, step: B85Step) {
        let s = self.text();
        let t = s.b85;
        let top = STATUS_H + 20;
        match step {
            B85Step::PickSeed { sel } => {
                self.status(c, t.title);
                TITLE.draw(c, MARGIN, top, t.pick_seed, theme::TEXT);
                let labels: [Buf<40>; 3] = core::array::from_fn(|i| {
                    self.seed_row_slot(i)
                        .and_then(|sl| self.slot(sl))
                        .map(crate::view::seed_label)
                        .unwrap_or_default()
                });
                let n = self.seed_count();
                let items: [MenuItem; 3] = core::array::from_fn(|i| MenuItem {
                    label: labels[i].as_str(),
                    detail: ">",
                });
                widgets::list(c, MARGIN, top + 50, W, 3 * 52, &items[..n], sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            B85Step::App { sel } => {
                self.status(c, t.title);
                let items = t.apps.map(|(l, d)| MenuItem { label: l, detail: d });
                widgets::list(c, MARGIN, STATUS_H + 8, W, 7 * 52, &items, sel as usize, true);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            B85Step::Params => {
                let Some(b) = self.b85.as_ref() else { return };
                self.status(c, t.apps[row_of(b.app)].0);
                let idx: Buf<16> = fill("{}", &[&b.index]);
                let path = b
                    .app
                    .path(b.index)
                    .map(|p| fill::<64>("{}", &[&p]))
                    .unwrap_or_default();
                let len: Buf<24> = match b.app {
                    B85App::Hex { bytes } => fill(t.bytes_unit, &[&bytes]),
                    B85App::PwdBase64 { len } | B85App::PwdBase85 { len } => fill(t.chars_unit, &[&len]),
                    _ => Buf::new(),
                };
                let mut rows: [(&str, &str); 3] =
                    [(t.index, idx.as_str()), (t.path, path.as_str()), ("", "")];
                let n = if len.as_str().is_empty() {
                    2
                } else {
                    rows[2] = (t.length, len.as_str());
                    3
                };
                widgets::info_rows(c, &rows[..n]);
                SMALL.draw(c, MARGIN, STATUS_H + 200, t.params_help[0], theme::TEXT_DIM);
                if n == 3 {
                    SMALL.draw(c, MARGIN, STATUS_H + 226, t.params_help[1], theme::TEXT_DIM);
                }
                let hints: &[(&str, &str)] = if n == 3 {
                    &[
                        ("0-9", t.index),
                        ("<>", t.h_length),
                        ("Enter", t.h_show),
                        ("Esc", s.h_back),
                    ]
                } else {
                    &[("0-9", t.index), ("Enter", t.h_show), ("Esc", s.h_back)]
                };
                widgets::hint_bar(c, hints);
            }
            B85Step::Warning => {
                self.status(c, t.title);
                TITLE.draw(c, MARGIN, top + 20, t.warn_title, theme::WARN);
                let mut y = top + 80;
                for l in t.warn_lines {
                    BODY.draw(c, MARGIN, y, l, theme::TEXT);
                    y += 36;
                }
                widgets::hint_bar(c, &[("Enter", t.h_show), ("Esc", s.h_back)]);
            }
            B85Step::Result { sel } => self.render_b85_result(c, sel),
        }
    }

    fn render_b85_result(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        let t = s.b85;
        let Some(b) = self.b85.as_ref() else { return };
        self.status(c, t.apps[row_of(b.app)].0);
        let Some(seed) = self.slot(b.slot as usize) else {
            return;
        };
        let path = b
            .app
            .path(b.index)
            .map(|p| fill::<64>("{}", &[&p]))
            .unwrap_or_default();
        let fp = crate::seeds::fingerprint_hex(&seed.fingerprint);
        let head: Buf<128> = fill("{} {}  {} {}", &[&t.seed, &fp.as_str(), &t.path, &path.as_str()]);
        SMALL.draw(c, MARGIN, STATUS_H + 8, head.as_str(), theme::TEXT_DIM);
        let mut y = STATUS_H + 32;
        if seed.has_passphrase() {
            SMALL.draw(c, MARGIN, y, t.passphrase_note, theme::WARN);
            y += 24;
        }
        let items_words = t.options_words.map(|l| MenuItem { label: l, detail: "" });
        let items_text = t.options_text.map(|l| MenuItem { label: l, detail: "" });
        let done = [MenuItem {
            label: t.options_text[1],
            detail: "",
        }];
        match (&b.derived, b.error) {
            (Some(Derived::Mnemonic(m)), _) => {
                let words: [&str; 24] = core::array::from_fn(|i| if i < m.len() { m.word(i) } else { "" });
                let row_h = match m.len() {
                    12 => 34,
                    18 => 30,
                    _ => 25,
                };
                widgets::word_grid(c, MARGIN, y, W, &words[..m.len()], 4, row_h, None, &BODY);
                let rows = m.len().div_ceil(4) as i32;
                let ly = y + rows * row_h + 8;
                // as many option rows as fit above the hint bar (the rest scroll)
                let room = ((480 - widgets::HINT_H - ly) / 52).clamp(2, 4);
                widgets::list(c, MARGIN, ly, W, room * 52, &items_words, sel as usize, room < 4);
            }
            (Some(d @ Derived::Text { .. }), _) => {
                let mut text = [0u8; MAX_TEXT];
                let n = d.write_text(&mut text);
                let shown = core::str::from_utf8(&text[..n]).unwrap_or("");
                let y2 = BODY.draw_wrapped(c, MARGIN, y + 8, W, 34, 5, shown, theme::ACCENT);
                bp_crypto::secret::wipe(&mut text);
                widgets::list(c, MARGIN, y2 + 16, W, 2 * 52, &items_text, sel as usize, false);
            }
            (None, _) => {
                BODY.draw(c, MARGIN, y + 8, t.invalid_key, theme::DANGER);
                widgets::list(c, MARGIN, y + 60, W, 52, &done, 0, false);
            }
        }
        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
    }
}
