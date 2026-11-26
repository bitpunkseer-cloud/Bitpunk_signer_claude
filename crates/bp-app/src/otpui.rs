//! One-time password codes (M11-7, decision 8): Backup & tools > OTP codes.
//! Keys come from an `otpauth://` QR or are typed in Base32; they are kept
//! as the notes are (in the vault when it is open). TOTP needs the time:
//! the board has no clock battery, so it is typed once per power-on (UTC)
//! and forgotten at power off. HOTP needs no clock: each code shown moves
//! its counter.

use crate::{typed, App, Pick, Screen};
use bp_backup::otp::{self, Algorithm, KeyError, OtpKey, OtpKind};
use bp_crypto::secret::wipe;
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, DOUBLE, SMALL, TITLE};
use bp_ui::widgets::{self, MenuItem, Tag, MARGIN, STATUS_H};
use bp_ui::{grid, theme};

const INPUT_MAX: usize = 120;

/// Steps of the OTP screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpStep {
    /// The keys, then "Scan", "Type a key", "Set the time".
    List { sel: u8 },
    /// One key's code.
    Code { idx: u8 },
    /// Typing a key (Base32), then its name.
    Type { name: bool },
    /// A key read or typed: add it?
    Add { sel: u8 },
    /// Typing the date and time (UTC).
    Time,
    /// Delete a key (type WIPE).
    Delete { idx: u8 },
}

/// State of the OTP screens; wiped when they close.
pub struct OtpState {
    /// A key waiting for "Add".
    pub pending: Option<OtpKey>,
    input: [u8; INPUT_MAX],
    pub input_len: usize,
    /// The key typed, while its name is typed.
    secret: [u8; otp::MAX_SECRET],
    secret_len: usize,
    /// Digits of the date and time being typed.
    pub time: [u8; 12],
    pub time_len: usize,
}

impl Drop for OtpState {
    fn drop(&mut self) {
        wipe(&mut self.input);
        wipe(&mut self.secret);
    }
}

impl OtpState {
    fn new() -> OtpState {
        OtpState {
            pending: None,
            input: [0; INPUT_MAX],
            input_len: 0,
            secret: [0; otp::MAX_SECRET],
            secret_len: 0,
            time: [0; 12],
            time_len: 0,
        }
    }

    pub fn input(&self) -> &[u8] {
        &self.input[..self.input_len]
    }

    fn clear_input(&mut self) {
        wipe(&mut self.input);
        self.input_len = 0;
    }
}

fn error_index(e: KeyError) -> usize {
    match e {
        KeyError::NotOtpauth => 0,
        KeyError::Secret => 1,
        KeyError::SecretLength => 2,
        KeyError::Parameter => 3,
    }
}

/// "2026-11-26 10:31:05"
pub fn clock_text(t: u64) -> Buf<24> {
    let (y, mo, d, h, mi, s) = otp::utc(t);
    bp_ui::bformat!(24, "{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// "123 456" / "1234 5678"
fn grouped(code: u32, digits: u8) -> Buf<12> {
    let s: Buf<10> = bp_ui::bformat!(10, "{:0width$}", code, width = digits as usize);
    let half = s.as_str().len() / 2;
    let mut out = Buf::new();
    out.push_str(&s.as_str()[..half]);
    out.push_str(" ");
    out.push_str(&s.as_str()[half..]);
    out
}

impl App {
    fn otp_step(&mut self, step: OtpStep) {
        self.set_current(Screen::Otp { step });
    }

    /// The time now (UTC seconds), when it was set this power-on.
    pub(crate) fn now(&self) -> Option<u64> {
        self.clock.map(|(t, _)| t)
    }

    /// Advance the clock; redraw a TOTP code each second.
    pub(crate) fn clock_tick(&mut self, dt_ms: u32) {
        if let Some((t, ms)) = self.clock.as_mut() {
            *ms += dt_ms;
            let secs = *ms / 1000;
            if secs > 0 {
                *t += secs as u64;
                *ms %= 1000;
                if matches!(self.current(), Screen::Otp { .. }) {
                    self.dirty = true;
                }
            }
        }
    }

    /// Backup & tools > OTP codes.
    pub(crate) fn otp_action(&mut self) {
        self.otp = Some(OtpState::new());
        self.push(Screen::Otp {
            step: OtpStep::List { sel: 0 },
        });
    }

    /// The scanner read some text: an `otpauth://` key, or a refusal.
    pub(crate) fn otp_scanned(&mut self, text: &str) {
        let t = self.text().bk;
        if self.otp.is_none() {
            self.otp = Some(OtpState::new());
        }
        match OtpKey::from_uri(text) {
            Ok(k) => {
                if let Some(st) = self.otp.as_mut() {
                    st.pending = Some(k);
                }
                self.set_current(Screen::Otp {
                    step: OtpStep::Add { sel: 0 },
                });
            }
            Err(e) => {
                self.notice = Some(t.otp_errors[error_index(e)]);
                self.set_current(Screen::Otp {
                    step: OtpStep::List { sel: 0 },
                });
            }
        }
    }

    pub(crate) fn otp_key(&mut self, step: OtpStep, ev: KeyEvent) {
        let t = self.text().bk;
        self.notice = None;
        if self.otp.is_none() {
            self.pop();
            return;
        }
        let count = self.vault.data.otp_count();
        match step {
            OtpStep::List { sel } => match crate::pick(ev.key, sel, count as u8 + 3) {
                Pick::Move(s) => self.otp_step(OtpStep::List { sel: s }),
                Pick::Choose(i) if (i as usize) < count => self.otp_step(OtpStep::Code { idx: i }),
                Pick::Choose(i) => match i as usize - count {
                    0 => self.start_scan(crate::scan::Purpose::Otp),
                    1 => {
                        if let Some(st) = self.otp.as_mut() {
                            st.clear_input();
                        }
                        self.otp_step(OtpStep::Type { name: false });
                    }
                    _ => {
                        if let Some(st) = self.otp.as_mut() {
                            st.time_len = 0;
                        }
                        self.otp_step(OtpStep::Time);
                    }
                },
                Pick::Back => {
                    self.otp = None;
                    self.pop();
                }
                Pick::None => {}
            },
            OtpStep::Code { idx } => {
                let Some(kind) = self.vault.data.otp_key(idx as usize).map(|k| k.kind) else {
                    self.otp_step(OtpStep::List { sel: 0 });
                    return;
                };
                match ev.key {
                    Key::Enter => match kind {
                        OtpKind::Hotp { counter } => {
                            self.vault.data.set_otp_counter(idx as usize, counter + 1)
                        }
                        OtpKind::Totp { .. } if self.clock.is_none() => {
                            if let Some(st) = self.otp.as_mut() {
                                st.time_len = 0;
                            }
                            self.otp_step(OtpStep::Time);
                        }
                        OtpKind::Totp { .. } => {}
                    },
                    Key::Backspace => {
                        self.typed.clear();
                        self.otp_step(OtpStep::Delete { idx });
                    }
                    Key::Esc => self.otp_step(OtpStep::List { sel: idx }),
                    _ => {}
                }
            }
            OtpStep::Type { name } => {
                let Some(st) = self.otp.as_mut() else { return };
                match ev.key {
                    Key::Char(c) if (' '..='~').contains(&c) && st.input_len < INPUT_MAX => {
                        let c = if name { c } else { c.to_ascii_uppercase() };
                        st.input[st.input_len] = c as u8;
                        st.input_len += 1;
                    }
                    Key::Backspace if st.input_len > 0 => {
                        st.input_len -= 1;
                        st.input[st.input_len] = 0;
                    }
                    Key::Enter if !name => {
                        let text = core::str::from_utf8(&st.input[..st.input_len]).unwrap_or("");
                        match otp::base32_decode(text, &mut st.secret) {
                            Some(n) if (10..=otp::MAX_SECRET).contains(&n) => {
                                st.secret_len = n;
                                st.clear_input();
                                self.otp_step(OtpStep::Type { name: true });
                            }
                            Some(_) => self.notice = Some(t.otp_errors[2]),
                            None => self.notice = Some(t.otp_errors[1]),
                        }
                    }
                    Key::Enter => {
                        let key = OtpKey::new(
                            OtpKind::Totp { period: 30 },
                            Algorithm::Sha1,
                            6,
                            &st.secret[..st.secret_len],
                            st.input(),
                        );
                        wipe(&mut st.secret);
                        st.secret_len = 0;
                        st.clear_input();
                        match key {
                            Ok(k) => {
                                st.pending = Some(k);
                                self.otp_step(OtpStep::Add { sel: 0 });
                            }
                            Err(e) => self.notice = Some(t.otp_errors[error_index(e)]),
                        }
                    }
                    Key::Esc => {
                        wipe(&mut st.secret);
                        st.secret_len = 0;
                        st.clear_input();
                        self.otp_step(OtpStep::List { sel: 0 });
                    }
                    _ => {}
                }
            }
            OtpStep::Add { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.otp_step(OtpStep::Add { sel: s }),
                Pick::Choose(0) => {
                    let Some(k) = self.otp.as_mut().and_then(|s| s.pending.take()) else {
                        return;
                    };
                    if self.vault.data.has_otp(&k) {
                        self.notice = Some(t.otp_dup);
                        self.otp_step(OtpStep::List { sel: 0 });
                    } else if self.vault.data.add_otp(k) {
                        self.notice = Some(t.otp_added);
                        let idx = self.vault.data.otp_count() as u8 - 1;
                        self.otp_step(OtpStep::Code { idx });
                    } else {
                        self.notice = Some(t.otp_full);
                        self.otp_step(OtpStep::List { sel: 0 });
                    }
                }
                Pick::Choose(_) | Pick::Back => {
                    if let Some(st) = self.otp.as_mut() {
                        st.pending = None;
                    }
                    self.otp_step(OtpStep::List { sel: 0 });
                }
                Pick::None => {}
            },
            OtpStep::Time => {
                let Some(st) = self.otp.as_mut() else { return };
                match ev.key {
                    Key::Char(c @ '0'..='9') if st.time_len < 12 => {
                        st.time[st.time_len] = c as u8 - b'0';
                        st.time_len += 1;
                    }
                    Key::Backspace if st.time_len > 0 => st.time_len -= 1,
                    Key::Enter => {
                        let d = st.time;
                        let num =
                            |a: usize, b: usize| d[a..b].iter().fold(0u32, |acc, &x| acc * 10 + x as u32);
                        let when = (st.time_len == 12)
                            .then(|| otp::unix_time(num(0, 4), num(4, 6), num(6, 8), num(8, 10), num(10, 12)))
                            .flatten();
                        match when {
                            Some(t0) => {
                                self.clock = Some((t0, 0));
                                self.notice = Some(t.otp_time_set);
                                self.otp_step(OtpStep::List { sel: 0 });
                            }
                            None => self.notice = Some(t.otp_time_bad),
                        }
                    }
                    Key::Esc => self.otp_step(OtpStep::List { sel: 0 }),
                    _ => {}
                }
            }
            OtpStep::Delete { idx } => match self.typed.key(ev.key, typed::WIPE) {
                typed::Typed::Confirmed => {
                    self.vault.data.remove_otp(idx as usize);
                    self.notice = Some(t.otp_deleted);
                    self.otp_step(OtpStep::List { sel: 0 });
                }
                typed::Typed::Cancelled => self.otp_step(OtpStep::Code { idx }),
                typed::Typed::Pending => {}
            },
        }
    }

    // ---------- drawing ----------

    pub(crate) fn render_otp(&self, c: &mut dyn Canvas, step: OtpStep) {
        let s = self.text();
        let t = s.bk;
        let Some(st) = self.otp.as_ref() else { return };
        let w = grid::COLS * grid::CELL_W;
        let g = |row| grid::text_y(&BODY, row, 1);
        let bottom = c.height() as i32 - widgets::HINT_H - 8;
        let notice = |c: &mut dyn Canvas, row: i32| {
            if let Some(n) = self.notice {
                widgets::log_line(c, MARGIN, g(row), w, Tag::Info, n, "");
            }
        };
        self.status(c, t.otp_menu);
        match step {
            OtpStep::List { sel } => {
                match self.now() {
                    Some(now) => {
                        let line: Buf<64> = fill(t.otp_time, &[&clock_text(now).as_str()]);
                        widgets::log_line(c, MARGIN, g(2), w, Tag::Ok, line.as_str(), "");
                    }
                    None => widgets::log_line(c, MARGIN, g(2), w, Tag::Warn, t.otp_no_time, ""),
                }
                let (tag, kept) = if self.vault.is_open() {
                    (Tag::Ok, t.nt_kept)
                } else {
                    (Tag::Warn, t.nt_session)
                };
                widgets::log_line(c, MARGIN, g(3), w, tag, kept, "");
                let count = self.vault.data.otp_count();
                let items: [MenuItem; crate::vaultdata::MAX_OTP + 3] = core::array::from_fn(|i| {
                    if i < count {
                        let k = self.vault.data.otp_key(i);
                        MenuItem {
                            label: k.map_or("", |k| k.label()),
                            detail: match k.map(|k| k.kind) {
                                Some(OtpKind::Hotp { .. }) => "HOTP",
                                _ => "TOTP",
                            },
                        }
                    } else {
                        MenuItem {
                            label: [t.otp_scan, t.otp_type, t.otp_set_time][(i - count).min(2)],
                            detail: ">",
                        }
                    }
                });
                let top = g(5) - 6;
                widgets::list(
                    c,
                    MARGIN,
                    top,
                    w,
                    bottom - top - 30,
                    &items[..count + 3],
                    sel as usize,
                    true,
                );
                notice(c, 17);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            OtpStep::Code { idx } => {
                let Some(k) = self.vault.data.otp_key(idx as usize) else {
                    return;
                };
                TITLE.draw(c, MARGIN, STATUS_H + 12, k.label(), theme::TEXT);
                let info: Buf<64> = fill(
                    t.otp_info,
                    &[
                        &match k.kind {
                            OtpKind::Totp { .. } => "TOTP",
                            OtpKind::Hotp { .. } => "HOTP",
                        },
                        &k.alg.name(),
                        &k.digits,
                    ],
                );
                SMALL.draw(c, MARGIN, g(4), info.as_str(), theme::TEXT_DIM);
                let code_y = grid::text_y(&DOUBLE, 6, 2);
                match (k.kind, self.now()) {
                    (OtpKind::Totp { period }, Some(now)) => {
                        let code = grouped(k.code(now), k.digits);
                        DOUBLE.draw(c, MARGIN, code_y, code.as_str(), theme::BRIGHT);
                        let left = period as u64 - now % period as u64;
                        let line: Buf<32> = fill(t.otp_valid, &[&left]);
                        widgets::log_line(c, MARGIN, g(10), w, Tag::Info, line.as_str(), "");
                        widgets::progress_bar(
                            c,
                            MARGIN,
                            g(11) + 4,
                            w,
                            8,
                            left as f64 / period as f64,
                            theme::ACCENT,
                        );
                        let when: Buf<64> = fill(t.otp_time, &[&clock_text(now).as_str()]);
                        SMALL.draw(c, MARGIN, g(13), when.as_str(), theme::TEXT_DIM);
                        widgets::hint_bar(c, &[("Del", t.nt_delete), ("Esc", s.h_back)]);
                    }
                    (OtpKind::Totp { .. }, None) => {
                        widgets::log_line(c, MARGIN, g(6), w, Tag::Warn, t.otp_set_first, "");
                        widgets::hint_bar(
                            c,
                            &[("Enter", t.otp_set_time), ("Del", t.nt_delete), ("Esc", s.h_back)],
                        );
                    }
                    (OtpKind::Hotp { counter }, _) => {
                        let code = grouped(k.code(0), k.digits);
                        DOUBLE.draw(c, MARGIN, code_y, code.as_str(), theme::BRIGHT);
                        let line: Buf<32> = fill(t.otp_counter, &[&counter]);
                        widgets::log_line(c, MARGIN, g(10), w, Tag::Info, line.as_str(), "");
                        widgets::hint_bar(
                            c,
                            &[("Enter", t.h_next_code), ("Del", t.nt_delete), ("Esc", s.h_back)],
                        );
                    }
                }
                notice(c, 15);
            }
            OtpStep::Type { name } => {
                widgets::label(
                    c,
                    MARGIN,
                    STATUS_H + 12,
                    if name { t.otp_label_q } else { t.otp_key_q },
                );
                let text = core::str::from_utf8(st.input()).unwrap_or("");
                let max = ((w - 40) / BODY.width as i32) as usize;
                let start = text.len().saturating_sub(max);
                widgets::text_field(c, MARGIN, STATUS_H + 34, w, &text[start..], "", &BODY);
                notice(c, 8);
                widgets::hint_bar(
                    c,
                    &[
                        ("A-Z", s.h_type),
                        ("Del", s.h_delete),
                        ("Enter", s.h_accept),
                        ("Esc", s.h_cancel),
                    ],
                );
            }
            OtpStep::Add { sel } => {
                let Some(k) = st.pending.as_ref() else { return };
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.otp_add_title, theme::TEXT);
                BODY.draw(c, MARGIN, g(5), k.label(), theme::BRIGHT);
                let info: Buf<64> = fill(
                    t.otp_info,
                    &[
                        &match k.kind {
                            OtpKind::Totp { .. } => "TOTP",
                            OtpKind::Hotp { .. } => "HOTP",
                        },
                        &k.alg.name(),
                        &k.digits,
                    ],
                );
                widgets::log_line(c, MARGIN, g(7), w, Tag::Info, info.as_str(), "");
                let period: Buf<32> = match k.kind {
                    OtpKind::Totp { period } => fill(t.otp_period, &[&period]),
                    OtpKind::Hotp { counter } => fill(t.otp_counter, &[&counter]),
                };
                widgets::log_line(c, MARGIN, g(8), w, Tag::Info, period.as_str(), "");
                let items = [
                    MenuItem {
                        label: t.otp_add,
                        detail: "",
                    },
                    MenuItem {
                        label: s.h_cancel,
                        detail: "",
                    },
                ];
                widgets::list(c, MARGIN, g(10), w, 2 * 48, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select)]);
            }
            OtpStep::Time => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.otp_time_title, theme::TEXT);
                let mut shown = Buf::<24>::new();
                for i in 0..12 {
                    if matches!(i, 4 | 6) {
                        shown.push_str("-");
                    } else if i == 8 {
                        shown.push_str(" ");
                    } else if i == 10 {
                        shown.push_str(":");
                    }
                    let ch: Buf<2> = if i < st.time_len {
                        fill("{}", &[&st.time[i]])
                    } else {
                        fill("_", &[])
                    };
                    shown.push_str(ch.as_str());
                }
                DOUBLE.draw(
                    c,
                    MARGIN,
                    grid::text_y(&DOUBLE, 5, 2),
                    shown.as_str(),
                    theme::BRIGHT,
                );
                for (i, n) in t.otp_time_notes.iter().enumerate() {
                    widgets::log_line(c, MARGIN, g(9 + i as i32), w, Tag::Info, n, "");
                }
                notice(c, 12);
                widgets::hint_bar(
                    c,
                    &[
                        ("0-9", s.h_number),
                        ("Del", s.h_delete),
                        ("Enter", s.h_accept),
                        ("Esc", s.h_back),
                    ],
                );
            }
            OtpStep::Delete { idx } => {
                let label = self.vault.data.otp_key(idx as usize).map_or("", |k| k.label());
                let y = widgets::message_at(
                    c,
                    STATUS_H + 40,
                    t.otp_delete_title,
                    theme::DANGER,
                    &[label, t.nt_delete_line],
                );
                let prompt: Buf<96> = fill(s.typed_prompt, &[&typed::WIPE]);
                let wrong = self.typed.wrong.then_some(s.typed_wrong);
                widgets::typed_field(c, y + 40, prompt.as_str(), self.typed.text(), wrong);
                widgets::hint_bar(c, &[("A-Z", s.h_type), ("Enter", t.nt_delete), ("Esc", s.keep)]);
            }
        }
    }
}
