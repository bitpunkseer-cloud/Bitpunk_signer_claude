//! Message signing: a `signmessage` QR, a message typed on the device
//! (Tools > Sign message, then an address from the explorer), or "sign a
//! message with this address" after Verify address. Off by default: only
//! the device's own Settings turn it on.
//!
//! Screens: every page of the message (line breaks shown as a mark, the
//! message hash on the last page), the address derived from the seed, then
//! Sign / Cancel with Cancel selected. m/44', 49', 84' sign the Electrum /
//! Bitcoin Core format; m/86' signs BIP-322 simple. The signature is
//! verified against the address before it is shown, and the key wiped.

use crate::review_view::address_lines;
use crate::seeds::fingerprint_hex;
use crate::{App, Pick, QrKind, Screen};
use bp_bitcoin::address::{self, ScriptType};
use bp_bitcoin::bip32::{DerivationPath, HARDENED};
use bp_bitcoin::bip322;
use bp_bitcoin::message::{self, MessageError, RequestError, MAX_MESSAGE};
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::bformat;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{split_line, BODY, SMALL, TITLE};
use bp_ui::theme;
use bp_ui::widgets::{self, MenuItem, MARGIN, STATUS_H};

/// Message lines per page.
const PAGE_LINES: usize = 9;
const LINE_H: i32 = 30;
/// Longest signature text: "smp" + Base64 of a Taproot witness.
const SIG_MAX: usize = 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsStep {
    /// Message signing is off in Settings.
    Off,
    /// The request cannot be signed (reason in the state).
    Problem,
    /// A QR request without fingerprint while several seeds are loaded.
    PickSeed {
        sel: u8,
    },
    /// Typing the message on the device.
    Type,
    Message {
        page: u8,
    },
    Address,
    Confirm {
        sel: u8,
    },
    Done {
        sel: u8,
    },
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    Request(RequestError),
    /// The request names a seed that is not loaded.
    SeedMissing([u8; 4]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub slot: u8,
    pub st: ScriptType,
    pub account: u32,
    pub change: bool,
    pub index: u32,
}

pub struct MsgState {
    msg: [u8; MAX_MESSAGE],
    len: usize,
    problem: Option<Problem>,
    /// The address to sign with, once chosen.
    target: Option<Target>,
    /// Waiting for an address picked in the explorer.
    pub picking: bool,
    addr: [u8; address::MAX_ADDRESS_LEN],
    addr_len: usize,
    /// Furthest page shown: signing needs every page seen.
    seen: u8,
    sig: [u8; SIG_MAX],
    sig_len: usize,
    /// Rule broken by the typed message (shown under the editor).
    rule: Option<MessageError>,
    /// Typed on the device (Esc on the message returns to the editor).
    typed: bool,
}

impl MsgState {
    fn new() -> MsgState {
        MsgState {
            msg: [0; MAX_MESSAGE],
            len: 0,
            problem: None,
            target: None,
            picking: false,
            addr: [0; address::MAX_ADDRESS_LEN],
            addr_len: 0,
            seen: 0,
            sig: [0; SIG_MAX],
            sig_len: 0,
            rule: None,
            typed: false,
        }
    }

    pub fn message(&self) -> &[u8] {
        &self.msg[..self.len]
    }

    fn addr(&self) -> &str {
        core::str::from_utf8(&self.addr[..self.addr_len]).unwrap_or("")
    }

    pub fn signature(&self) -> Option<&[u8]> {
        (self.sig_len > 0).then(|| &self.sig[..self.sig_len])
    }

    /// The armored signed message (message, address, signature) for a
    /// `.sig` file. Returns its length.
    pub fn armored(&self, out: &mut [u8]) -> Option<usize> {
        let sig = core::str::from_utf8(self.signature()?).ok()?;
        bp_bitcoin::message::write_armored(self.message(), self.addr(), sig, out)
    }
}

impl Drop for MsgState {
    fn drop(&mut self) {
        bp_crypto::secret::wipe(&mut self.msg);
        bp_crypto::secret::wipe(&mut self.addr);
        bp_crypto::secret::wipe(&mut self.sig);
    }
}

/// The message's display lines: (start, end, ends with a line break),
/// wrapped to `cols` columns (two kept free for the break mark).
fn lines(msg: &[u8], cols: usize, mut f: impl FnMut(usize, usize, bool)) {
    let text = core::str::from_utf8(msg).unwrap_or("");
    let offset = |sub: &str| sub.as_ptr() as usize - text.as_ptr() as usize;
    let mut raws = text.split('\n').peekable();
    while let Some(raw) = raws.next() {
        let brk = raws.peek().is_some();
        let mut rest = raw;
        loop {
            let (line, tail) = split_line(rest, cols - 2);
            let start = offset(line);
            f(start, start + line.len(), brk && tail.is_empty());
            if tail.is_empty() {
                break;
            }
            rest = tail;
        }
    }
}

fn page_count(msg: &[u8]) -> u8 {
    let mut n: usize = 0;
    lines(msg, cols(), |_, _, _| n += 1);
    n.div_ceil(PAGE_LINES).clamp(1, 255) as u8
}

fn cols() -> usize {
    ((800 - 2 * MARGIN) / BODY.width as i32) as usize
}

fn rule_index(e: MessageError) -> usize {
    match e {
        MessageError::TooShort => 0,
        MessageError::TooLong => 1,
        MessageError::NotPrintable => 2,
        MessageError::LeadingOrTrailingSpace => 3,
        MessageError::TooManySpaces => 4,
    }
}

impl App {
    fn msg_state(&mut self) -> &mut MsgState {
        self.msg.get_or_insert_with(MsgState::new)
    }

    fn msg_show(&mut self, step: MsStep) {
        if matches!(self.current(), Screen::MsgSign { .. }) {
            self.set_current(Screen::MsgSign { step });
        } else {
            self.push(Screen::MsgSign { step });
        }
    }

    /// A scanned `signmessage` request (the scanner is replaced).
    pub(crate) fn start_msg_request(&mut self, text: &[u8]) {
        self.msg = None;
        if !self.settings.msg_signing {
            self.msg_state();
            self.set_current(Screen::MsgSign { step: MsStep::Off });
            return;
        }
        let net = self.settings.network;
        let req = match message::parse_request(text, net) {
            Ok(r) => r,
            Err(e) => {
                self.msg_state().problem = Some(Problem::Request(e));
                self.set_current(Screen::MsgSign {
                    step: MsStep::Problem,
                });
                return;
            }
        };
        let st = self.msg_state();
        st.msg[..req.message.len()].copy_from_slice(req.message);
        st.len = req.message.len();
        let mut target = Target {
            slot: 0,
            st: req.script_type,
            account: req.account,
            change: req.change,
            index: req.index,
        };
        let slot = match req.fingerprint {
            Some(fp) => match self
                .seeds
                .iter()
                .position(|s| s.as_ref().is_some_and(|s| s.fingerprint == fp))
            {
                Some(i) => i,
                None => {
                    self.msg_state().problem = Some(Problem::SeedMissing(fp));
                    self.set_current(Screen::MsgSign {
                        step: MsStep::Problem,
                    });
                    return;
                }
            },
            None if self.seed_count() == 1 => self.seed_row_slot(0).unwrap_or(0),
            None if self.seed_count() == 0 => {
                self.msg = None;
                self.set_current(Screen::NoSeed);
                return;
            }
            None => {
                self.msg_state().target = Some(target);
                self.set_current(Screen::MsgSign {
                    step: MsStep::PickSeed { sel: 0 },
                });
                return;
            }
        };
        target.slot = slot as u8;
        if self.slot(slot).is_some_and(|s| s.single_key()) {
            // a request names a derivation path; a single key has none
            self.msg_state().problem = Some(Problem::Request(message::RequestError::Path));
            self.set_current(Screen::MsgSign {
                step: MsStep::Problem,
            });
            return;
        }
        self.msg_set_target(target);
        self.set_current(Screen::MsgSign {
            step: MsStep::Message { page: 0 },
        });
    }

    /// Tools > Sign message (or Verify address's shortcut with `preset`).
    pub(crate) fn start_msg_typing(&mut self, preset: Option<Target>) {
        self.msg = None;
        if !self.settings.msg_signing {
            self.msg_state();
            self.msg_show(MsStep::Off);
            return;
        }
        if self.seed_count() == 0 {
            self.push(Screen::NoSeed);
            return;
        }
        self.msg_state().typed = true;
        if let Some(t) = preset {
            self.msg_set_target(t);
        }
        self.msg_show(MsStep::Type);
    }

    fn msg_set_target(&mut self, t: Target) {
        let net = self.settings.network;
        let mut out = [0u8; address::MAX_ADDRESS_LEN];
        let n = self
            .slot(t.slot as usize)
            .and_then(|s| s.address(t.st, net, t.account, t.change, t.index, &mut out));
        let st = self.msg_state();
        st.target = Some(t);
        st.addr = out;
        st.addr_len = n.unwrap_or(0);
        st.seen = 0;
    }

    /// The explorer picked an address while a typed message waits for one.
    pub(crate) fn msg_pick(&mut self, t: Target) -> bool {
        if !self.msg.as_ref().is_some_and(|m| m.picking) {
            return false;
        }
        self.msg_set_target(t);
        self.msg_state().picking = false;
        while !matches!(self.current(), Screen::MsgSign { .. }) && self.depth > 1 {
            self.pop();
        }
        self.set_current(Screen::MsgSign {
            step: MsStep::Message { page: 0 },
        });
        true
    }

    fn msg_sign(&mut self) -> bool {
        let net = self.settings.network;
        let Some(m) = self.msg.as_ref() else { return false };
        let Some(t) = m.target else { return false };
        let Some(seed) = self.slot(t.slot as usize) else {
            return false;
        };
        let steps = [
            t.st.purpose() | HARDENED,
            net.coin_type() | HARDENED,
            t.account | HARDENED,
            t.change as u32,
            t.index,
        ];
        let Ok(path) = DerivationPath::from_steps(&steps) else {
            return false;
        };
        let Ok(key) = seed.master().derive_path(&path) else {
            return false;
        };
        let mut sig = [0u8; SIG_MAX];
        let n = match t.st {
            ScriptType::Taproot => {
                let Some(w) = bip322::sign_simple_taproot(key.secret_key(), m.message()) else {
                    return false;
                };
                let Some(n) = bip322::simple_text(&w, &mut sig) else {
                    return false;
                };
                let text = core::str::from_utf8(&sig[..n]).unwrap_or("");
                if bip322::verify_simple(m.addr(), net, m.message(), text) != Ok(ScriptType::Taproot) {
                    return false;
                }
                n
            }
            _ => {
                let Some(raw) = message::sign(key.secret_key(), m.message()) else {
                    return false;
                };
                let mut b = [0u8; message::SIG_B64_LEN];
                let n = message::to_base64(&raw, &mut b);
                let text = core::str::from_utf8(&b[..n]).unwrap_or("");
                match message::verify(m.addr(), net, m.message(), text) {
                    Ok(v) if v.header_matches && v.script_type == t.st => {}
                    _ => return false,
                }
                sig[..n].copy_from_slice(&b[..n]);
                n
            }
        };
        drop(key);
        let m = self.msg_state();
        m.sig = sig;
        m.sig_len = n;
        true
    }

    pub(crate) fn msg_key(&mut self, step: MsStep, ev: KeyEvent) {
        let back = matches!(ev.key, Key::Esc);
        match step {
            MsStep::Off | MsStep::Problem | MsStep::Failed => {
                if back || matches!(ev.key, Key::Enter | Key::Backspace) {
                    self.msg_end();
                }
            }
            MsStep::PickSeed { sel } => {
                let n = self.seed_count() as u8;
                match crate::pick(ev.key, sel, n) {
                    Pick::Move(s) => self.set_current(Screen::MsgSign {
                        step: MsStep::PickSeed { sel: s },
                    }),
                    Pick::Choose(s) => {
                        let slot = self.seed_row_slot(s as usize).unwrap_or(0) as u8;
                        if let Some(mut t) = self.msg.as_ref().and_then(|m| m.target) {
                            t.slot = slot;
                            self.msg_set_target(t);
                            self.set_current(Screen::MsgSign {
                                step: MsStep::Message { page: 0 },
                            });
                        }
                    }
                    Pick::Back => self.msg_end(),
                    Pick::None => {}
                }
            }
            MsStep::Type => self.msg_type_key(ev),
            MsStep::Message { page } => {
                let pages = self.msg.as_ref().map_or(1, |m| page_count(m.message()));
                let go = |a: &mut App, p: u8| {
                    if let Some(m) = a.msg.as_mut() {
                        m.seen = m.seen.max(p);
                    }
                    a.set_current(Screen::MsgSign {
                        step: MsStep::Message { page: p },
                    });
                };
                match ev.key {
                    Key::Right | Key::Down if page + 1 < pages => go(self, page + 1),
                    Key::Left | Key::Up if page > 0 => go(self, page - 1),
                    Key::Enter if page + 1 < pages => go(self, page + 1),
                    Key::Enter => self.set_current(Screen::MsgSign {
                        step: MsStep::Address,
                    }),
                    Key::Esc | Key::Backspace => self.msg_back_from_message(),
                    _ => {}
                }
            }
            MsStep::Address => match ev.key {
                Key::Enter => self.set_current(Screen::MsgSign {
                    step: MsStep::Confirm { sel: 0 },
                }),
                Key::Esc | Key::Backspace => {
                    let last = self.msg.as_ref().map_or(1, |m| page_count(m.message())) - 1;
                    self.set_current(Screen::MsgSign {
                        step: MsStep::Message { page: last },
                    });
                }
                _ => {}
            },
            MsStep::Confirm { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.set_current(Screen::MsgSign {
                    step: MsStep::Confirm { sel: s },
                }),
                Pick::Choose(1) => {
                    // every page must have been shown
                    let all = self
                        .msg
                        .as_ref()
                        .is_some_and(|m| m.seen + 1 >= page_count(m.message()));
                    let step = if all && self.msg_sign() {
                        MsStep::Done { sel: 0 }
                    } else {
                        MsStep::Failed
                    };
                    self.set_current(Screen::MsgSign { step });
                }
                Pick::Choose(_) | Pick::Back => self.msg_end(),
                Pick::None => {}
            },
            MsStep::Done { sel } if self.msg_from_sd() => match crate::pick(ev.key, sel, 3) {
                Pick::Move(s) => self.set_current(Screen::MsgSign {
                    step: MsStep::Done { sel: s },
                }),
                Pick::Choose(0) => self.start_save(crate::sd::Job::SaveSig),
                Pick::Choose(1) => self.open_qr(QrKind::MessageSig),
                Pick::Choose(_) | Pick::Back => self.msg_end(),
                Pick::None => {}
            },
            MsStep::Done { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.set_current(Screen::MsgSign {
                    step: MsStep::Done { sel: s },
                }),
                Pick::Choose(0) => self.open_qr(QrKind::MessageSig),
                Pick::Choose(_) | Pick::Back => self.msg_end(),
                Pick::None => {}
            },
        }
    }

    fn msg_back_from_message(&mut self) {
        // a typed message goes back to the editor; a scanned one ends
        if self.msg.as_ref().is_some_and(|m| m.typed) {
            self.set_current(Screen::MsgSign { step: MsStep::Type });
        } else {
            self.msg_end();
        }
    }

    /// The message came from a file on the card (saving is offered).
    pub(crate) fn msg_from_sd(&self) -> bool {
        self.sd
            .origin
            .is_some_and(|o| o.kind == crate::sdfile::OriginKind::Message)
    }

    fn msg_end(&mut self) {
        self.msg = None;
        self.pop();
    }

    fn msg_type_key(&mut self, ev: KeyEvent) {
        let Some(m) = self.msg.as_mut() else { return };
        if edit_key(&mut m.msg, &mut m.len, ev) {
            m.rule = None;
            return;
        }
        match ev.key {
            Key::Enter => {
                if let Err(e) = message::check_message(m.message()) {
                    m.rule = Some(e);
                    return;
                }
                if m.target.is_some() {
                    self.set_current(Screen::MsgSign {
                        step: MsStep::Message { page: 0 },
                    });
                } else {
                    m.picking = true;
                    self.open_explorer();
                }
            }
            Key::Esc => self.msg_end(),
            _ => {}
        }
    }

    pub(crate) fn render_msg(&self, c: &mut dyn Canvas, step: MsStep) {
        let s = self.text();
        let Some(m) = self.msg.as_ref() else { return };
        self.status(c, s.sign_message);
        let net = self.settings.network;
        match step {
            MsStep::Off => {
                widgets::message_at(
                    c,
                    STATUS_H + 70,
                    s.ms_off_title,
                    theme::WARN,
                    &[s.ms_off_1, "", s.ms_off_2],
                );
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
            MsStep::Problem => {
                let reason: Buf<256> = match m.problem {
                    Some(Problem::Request(RequestError::Format)) => fill(s.ms_problems[0], &[]),
                    Some(Problem::Request(RequestError::Path)) => fill(s.ms_problems[1], &[]),
                    Some(Problem::Request(RequestError::Network)) => fill(s.ms_problems[2], &[&net.name()]),
                    Some(Problem::Request(RequestError::Message(e))) => {
                        fill(s.ms_problems[3], &[&s.ms_rules[rule_index(e)]])
                    }
                    Some(Problem::SeedMissing(fp)) => {
                        fill(s.ms_problems[4], &[&fingerprint_hex(&fp).as_str()])
                    }
                    None => Buf::new(),
                };
                let code = match m.problem {
                    Some(Problem::Request(RequestError::Format)) => Some(0),
                    Some(Problem::Request(RequestError::Path)) => Some(1),
                    Some(Problem::Request(RequestError::Network)) => Some(2),
                    Some(Problem::Request(RequestError::Message(_))) => Some(3),
                    Some(Problem::SeedMissing(_)) => Some(4),
                    None => None,
                };
                if let Some(i) = code {
                    self.show_error(crate::errors::Area::Msg, i);
                }
                widgets::message_at(
                    c,
                    STATUS_H + 70,
                    s.rv.cannot_sign,
                    theme::DANGER,
                    &[reason.as_str()],
                );
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
            MsStep::PickSeed { sel } => {
                TITLE.draw(c, MARGIN, STATUS_H + 16, s.pick_seed, theme::TEXT);
                let mut labels: [Buf<40>; crate::SEED_SLOTS] = Default::default();
                let mut n = 0;
                for seed in self.seeds.iter().flatten() {
                    labels[n] = crate::view::seed_label(seed);
                    n += 1;
                }
                let items: [MenuItem; crate::SEED_SLOTS] = core::array::from_fn(|i| MenuItem {
                    label: labels[i].as_str(),
                    detail: "",
                });
                widgets::list(
                    c,
                    MARGIN,
                    STATUS_H + 70,
                    800 - 2 * MARGIN,
                    300,
                    &items[..n],
                    sel as usize,
                    false,
                );
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_cancel)]);
            }
            MsStep::Type => {
                let warn: Option<Buf<192>> = m
                    .rule
                    .map(|e| fill(s.ms_problems[3], &[&s.ms_rules[rule_index(e)]]));
                draw_editor(
                    s,
                    c,
                    s.ms_type_label,
                    m.message(),
                    warn.as_ref().map(|w| w.as_str()),
                );
            }
            MsStep::Message { page } => self.render_msg_page(c, m, page),
            MsStep::Address => {
                let Some(t) = m.target else { return };
                widgets::label(c, MARGIN, STATUS_H + 12, s.ms_sign_with);
                let y = address_lines(c, MARGIN, STATUS_H + 36, m.addr()) + 8;
                let path = bformat!(
                    64,
                    "{}/{}/{}",
                    t.st.account_path(net, t.account),
                    t.change as u8,
                    t.index
                );
                BODY.draw(c, MARGIN, y, path.as_str(), theme::ACCENT);
                let fp = self
                    .slot(t.slot as usize)
                    .map(|x| fingerprint_hex(&x.fingerprint))
                    .unwrap_or_default();
                let l: Buf<128> = fill(s.ms_verified, &[&fp.as_str()]);
                BODY.draw(c, MARGIN, y + 36, l.as_str(), theme::OK);
                let fmt = s.ms_formats[(t.st == ScriptType::Taproot) as usize];
                let l: Buf<128> = fill(s.ms_format, &[&fmt]);
                SMALL.draw(c, MARGIN, y + 76, l.as_str(), theme::TEXT_DIM);
                widgets::hint_bar(c, &[("Enter", s.rv.h_next), ("Esc", s.h_back)]);
            }
            MsStep::Confirm { sel } => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, s.ms_confirm, theme::ACCENT);
                let preview = core::str::from_utf8(m.message()).unwrap_or("");
                let mut y = STATUS_H + 70;
                let (first, rest) = split_line(preview, cols() - 4);
                let shown: Buf<80> = if rest.is_empty() {
                    bformat!(80, "\"{}\"", first)
                } else {
                    bformat!(80, "\"{}...\"", split_line(first, cols() - 7).0)
                };
                BODY.draw(c, MARGIN, y, shown.as_str(), theme::TEXT);
                y += 36;
                SMALL.draw(c, MARGIN, y, m.addr(), theme::TEXT_DIM);
                y += 40;
                let items = s.rv.options.map(|label| MenuItem { label, detail: "" });
                widgets::list(c, MARGIN, y, 400, 110, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_cancel)]);
            }
            MsStep::Done { sel } => {
                let y = widgets::message_at(c, STATUS_H + 16, s.ms_signed, theme::OK, &[s.ms_signed_1]);
                let sig = core::str::from_utf8(m.signature().unwrap_or(&[])).unwrap_or("");
                let y = SMALL.draw_wrapped(c, MARGIN, y + 8, 800 - 2 * MARGIN, 22, 3, sig, theme::TEXT) + 8;
                let [qr, done] = s.ms_done_options;
                let all = [s.sd.save_sd, qr, done].map(|label| MenuItem { label, detail: "" });
                let items: &[MenuItem] = if self.msg_from_sd() { &all } else { &all[1..] };
                widgets::list(c, MARGIN, y, 800 - 2 * MARGIN, 160, items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select)]);
            }
            MsStep::Failed => {
                widgets::message_at(c, STATUS_H + 90, s.rv.failed, theme::DANGER, &[s.ms_failed_1]);
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
        }
    }

    fn render_msg_page(&self, c: &mut dyn Canvas, m: &MsgState, page: u8) {
        let bip322 = m.target.map(|t| t.st) == Some(ScriptType::Taproot);
        draw_message_page(self.text(), c, m.message(), page, bip322);
    }
}

/// Pages of `msg` on the message screens.
pub(crate) fn message_pages(msg: &[u8]) -> u8 {
    page_count(msg)
}

/// One page of a message being signed: the lines (breaks marked), and on
/// the last page the message hash (BIP-322 tagged hash or SHA-256d).
pub(crate) fn draw_message_page(s: &crate::Strings, c: &mut dyn Canvas, msg: &[u8], page: u8, bip322: bool) {
    let pages = page_count(msg);
    let head: Buf<96> = fill(s.ms_page, &[&(page + 1), &pages]);
    widgets::label(c, MARGIN, STATUS_H + 12, head.as_str());
    let text = core::str::from_utf8(msg).unwrap_or("");
    let first = page as usize * PAGE_LINES;
    let mut n = 0;
    let mut y = STATUS_H + 40;
    lines(msg, cols(), |a, b, brk| {
        if (first..first + PAGE_LINES).contains(&n) {
            let end = BODY.draw(c, MARGIN, y, &text[a..b], theme::TEXT);
            if brk {
                BODY.draw(c, end, y, s.newline_mark, theme::ACCENT);
            }
            y += LINE_H;
        }
        n += 1;
    });
    if page + 1 == pages {
        let (label, hash) = if bip322 {
            (s.ms_hash_bip322, bip322::message_hash(msg))
        } else {
            (s.ms_hash, message::message_hash(msg))
        };
        widgets::label(c, MARGIN, 360, label);
        let mut hex = Buf::<64>::new();
        for b in hash {
            let _ = core::fmt::Write::write_fmt(&mut hex, format_args!("{b:02x}"));
        }
        SMALL.draw(c, MARGIN, 382, hex.as_str(), theme::TEXT_DIM);
        widgets::hint_bar(c, &[("<>", s.h_page), ("Enter", s.rv.h_next), ("Esc", s.h_back)]);
    } else {
        SMALL.draw(c, MARGIN, 382, s.ms_read_all, theme::WARN);
        widgets::hint_bar(c, &[("<>", s.h_page), ("Enter", s.h_page), ("Esc", s.h_back)]);
    }
}

/// Typing into a message buffer: printable ASCII appends, Del deletes.
/// Returns true when the key edited the text.
pub(crate) fn edit_key(buf: &mut [u8], len: &mut usize, ev: KeyEvent) -> bool {
    match ev.key {
        Key::Char(c) if (' '..='~').contains(&c) => {
            if *len < buf.len() {
                buf[*len] = c as u8;
                *len += 1;
            }
            true
        }
        Key::Backspace => {
            if *len > 0 {
                *len -= 1;
                buf[*len] = 0;
            }
            true
        }
        _ => false,
    }
}

/// The message editor: a box with the tail of the text, a cursor, the
/// character count and an optional warning below.
pub(crate) fn draw_editor(
    s: &crate::Strings,
    c: &mut dyn Canvas,
    label: &str,
    msg: &[u8],
    warn: Option<&str>,
) {
    widgets::label(c, MARGIN, STATUS_H + 12, label);
    bp_ui::draw::round_rect(
        c,
        MARGIN,
        STATUS_H + 34,
        800 - 2 * MARGIN,
        9 * LINE_H + 16,
        10,
        theme::SURFACE,
    );
    let text = core::str::from_utf8(msg).unwrap_or("");
    let cols = cols() - 2;
    let mut starts = [0usize; 64];
    let mut count = 0;
    let mut rest = text;
    loop {
        let (line, tail) = split_line(rest, cols);
        if count < starts.len() {
            starts[count] = line.as_ptr() as usize - text.as_ptr() as usize;
            count += 1;
        }
        if tail.is_empty() {
            break;
        }
        rest = tail;
    }
    let first = count.saturating_sub(9);
    let mut end_x = MARGIN + 16;
    let mut y = STATUS_H + 42;
    for i in first..count {
        let a = starts[i];
        let b = if i + 1 < count { starts[i + 1] } else { text.len() };
        // the last line keeps its trailing spaces: the cursor follows them
        let line = if i + 1 < count {
            text[a..b].trim_end()
        } else {
            &text[a..b]
        };
        end_x = BODY.draw(c, MARGIN + 16, y, line, theme::TEXT);
        if i + 1 < count {
            y += LINE_H;
        }
    }
    c.fill_rect(end_x, y + 4, 3, BODY.height as i32 - 8, theme::ACCENT);
    let count_s: Buf<48> = fill(s.progress, &[&msg.len(), &MAX_MESSAGE]);
    SMALL.draw(
        c,
        800 - MARGIN - SMALL.text_width(count_s.as_str()),
        STATUS_H + 12,
        count_s.as_str(),
        theme::TEXT_DIM,
    );
    if let Some(w) = warn {
        BODY.draw_wrapped(c, MARGIN, 368, 800 - 2 * MARGIN, 28, 2, w, theme::WARN);
    }
    widgets::hint_bar(
        c,
        &[("Del", s.h_delete), ("Enter", s.h_continue), ("Esc", s.h_cancel)],
    );
}
