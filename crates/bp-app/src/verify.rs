//! Address verification screens: Tools > Verify address, or any address
//! scanned from the main menu. The search itself is
//! `bp_bitcoin::addrcheck`; it runs a few candidates per tick.

use crate::review_view::{address_lines, fps};
use crate::seeds::fingerprint_hex;
use crate::{App, Screen};
use bp_bitcoin::addrcheck::{Account, Found, Search, State, Target, TargetError, MAX_ACCOUNTS};
use bp_bitcoin::address::{self, ScriptType};
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::bformat;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, SMALL, TITLE};
use bp_ui::theme;
use bp_ui::widgets::{self, MenuItem, MARGIN, STATUS_H};

/// Candidates checked per tick (about 60 ticks a second in the simulator).
const STEPS_PER_TICK: usize = 16;
/// Accounts remembered from this session (account 0 is always searched).
pub const SESSION_ACCOUNTS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaStep {
    /// The address, large, with Verify / Done (or why it cannot be checked).
    Confirm {
        sel: u8,
    },
    Searching,
    /// A batch ended (or Esc): continue, next batch, other account, stop.
    Paused {
        sel: u8,
    },
    Found,
}

pub struct VerifyState {
    addr: [u8; address::MAX_ADDRESS_LEN],
    len: usize,
    target: Result<Target, TargetError>,
    hint: Option<u32>,
    search: Option<Search>,
}

impl VerifyState {
    fn addr(&self) -> &str {
        core::str::from_utf8(&self.addr[..self.len]).unwrap_or("")
    }
}

#[cfg(test)]
impl VerifyState {
    pub fn search_state(&self) -> Option<State> {
        self.search.as_ref().map(|s| s.state())
    }
    pub fn scanned(&self) -> Option<u32> {
        self.search.as_ref().map(|s| s.scanned())
    }
    pub fn target_error(&self) -> Option<TargetError> {
        self.target.err()
    }
}

impl Drop for VerifyState {
    fn drop(&mut self) {
        bp_crypto::secret::wipe(&mut self.addr);
    }
}

impl App {
    /// Show `addr` (scanned) and offer to verify it. Replaces the scanner.
    pub(crate) fn start_verify(&mut self, addr: &[u8], hint: Option<u32>) {
        let mut a = [0u8; address::MAX_ADDRESS_LEN];
        let len = addr.len().min(a.len());
        a[..len].copy_from_slice(&addr[..len]);
        let text = core::str::from_utf8(&a[..len]).unwrap_or("");
        let target = Target::parse(text, self.settings.network);
        self.verify = Some(VerifyState {
            addr: a,
            len,
            target,
            hint,
            search: None,
        });
        self.set_current(Screen::VerifyAddr {
            step: VaStep::Confirm { sel: 0 },
        });
    }

    fn can_verify(&self) -> bool {
        self.seed_count() > 0 && self.verify.as_ref().is_some_and(|v| v.target.is_ok())
    }

    /// Every loaded seed at the session's accounts, or at `only`.
    fn verify_accounts(
        &self,
        st: ScriptType,
        only: Option<u32>,
        out: &mut [Option<Account>; MAX_ACCOUNTS],
    ) -> usize {
        let net = self.settings.network;
        let session = &self.session_accounts[..self.n_session_accounts];
        let list: &[u32] = match &only {
            Some(a) => core::slice::from_ref(a),
            None => session,
        };
        let mut n = 0;
        for (slot, seed) in self.seeds.iter().enumerate() {
            let Some(seed) = seed else { continue };
            for &acct in list {
                if n == MAX_ACCOUNTS {
                    return n;
                }
                if let Some(x) = seed.account_xpub(st, net, acct) {
                    out[n] = Account::new(slot as u8, seed.fingerprint, acct, &x);
                    n += out[n].is_some() as usize;
                }
            }
        }
        n
    }

    fn begin_search(&mut self, only: Option<u32>) {
        let Some(v) = self.verify.as_ref() else { return };
        let Ok(target) = v.target else { return };
        let mut acc = [None; MAX_ACCOUNTS];
        let n = self.verify_accounts(target.script_type(), only, &mut acc);
        let (hint, near) = if only.is_some() {
            (None, None)
        } else {
            (v.hint, self.last_found)
        };
        let search = Search::new(target, acc[..n].iter().flatten().copied(), hint, near);
        if let Some(v) = self.verify.as_mut() {
            v.search = Some(search);
        }
        self.set_current(Screen::VerifyAddr {
            step: VaStep::Searching,
        });
    }

    /// Remember an account used this session (searched by default).
    pub(crate) fn note_account(&mut self, account: u32) {
        let n = self.n_session_accounts;
        if self.session_accounts[..n].contains(&account) {
            return;
        }
        if n < SESSION_ACCOUNTS {
            self.session_accounts[n] = account;
            self.n_session_accounts += 1;
        } else {
            // keep account 0, replace the oldest of the others
            self.session_accounts.copy_within(2.., 1);
            self.session_accounts[SESSION_ACCOUNTS - 1] = account;
        }
    }

    /// Run the search while its screen is shown. Returns true to redraw.
    pub(crate) fn verify_tick(&mut self) -> bool {
        if self.current()
            != (Screen::VerifyAddr {
                step: VaStep::Searching,
            })
        {
            return false;
        }
        let Some(s) = self.verify.as_mut().and_then(|v| v.search.as_mut()) else {
            return false;
        };
        match s.step(STEPS_PER_TICK) {
            State::Searching => {}
            State::Paused => self.set_current(Screen::VerifyAddr {
                step: VaStep::Paused { sel: 0 },
            }),
            State::Found(f) => {
                self.last_found = Some(f.index);
                self.note_account(f.account);
                self.set_current(Screen::VerifyAddr { step: VaStep::Found });
            }
        }
        true
    }

    fn next_account(&self) -> u32 {
        let s = self.verify.as_ref().and_then(|v| v.search.as_ref());
        s.and_then(|s| s.accounts().map(|a| a.account).max())
            .unwrap_or(0)
            .saturating_add(1)
            .min(1 << 30)
    }

    pub(crate) fn verify_key(&mut self, step: VaStep, ev: KeyEvent) {
        let back = matches!(ev.key, Key::Esc | Key::Backspace);
        match step {
            VaStep::Confirm { sel } => {
                if !self.can_verify() {
                    if back || ev.key == Key::Enter {
                        self.pop();
                    }
                    return;
                }
                match crate::pick(ev.key, sel, 2) {
                    crate::Pick::Move(s) => self.set_current(Screen::VerifyAddr {
                        step: VaStep::Confirm { sel: s },
                    }),
                    crate::Pick::Choose(0) => self.begin_search(None),
                    crate::Pick::Choose(_) | crate::Pick::Back => self.pop(),
                    crate::Pick::None => {}
                }
            }
            VaStep::Searching => {
                if back {
                    self.set_current(Screen::VerifyAddr {
                        step: VaStep::Paused { sel: 0 },
                    });
                }
            }
            VaStep::Paused { sel } => match crate::pick(ev.key, sel, 3) {
                crate::Pick::Move(s) => self.set_current(Screen::VerifyAddr {
                    step: VaStep::Paused { sel: s },
                }),
                crate::Pick::Choose(0) => {
                    if let Some(s) = self.verify.as_mut().and_then(|v| v.search.as_mut()) {
                        s.more();
                    }
                    self.set_current(Screen::VerifyAddr {
                        step: VaStep::Searching,
                    });
                }
                crate::Pick::Choose(1) => {
                    let next = self.next_account();
                    self.begin_search(Some(next));
                }
                crate::Pick::Choose(_) | crate::Pick::Back => self.pop(),
                crate::Pick::None => {}
            },
            VaStep::Found => match ev.key {
                Key::Char('s' | 'S') => {
                    let v = self.verify.as_ref();
                    let found = v.and_then(|v| match (v.search.as_ref().map(|s| s.state()), v.target) {
                        (Some(State::Found(f)), Ok(t)) => Some((f, t.script_type())),
                        _ => None,
                    });
                    if let Some((f, st)) = found {
                        self.start_msg_typing(Some(crate::msgsign::Target {
                            slot: f.slot,
                            st,
                            account: f.account,
                            change: f.change,
                            index: f.index,
                        }));
                    }
                }
                _ if back || ev.key == Key::Enter => self.pop(),
                _ => {}
            },
        }
    }

    pub(crate) fn render_verify(&self, c: &mut dyn Canvas, step: VaStep) {
        let s = self.text();
        let Some(v) = self.verify.as_ref() else { return };
        self.status(c, s.verify_address);
        let net = self.settings.network;
        match step {
            VaStep::Confirm { sel } => {
                widgets::label(c, MARGIN, STATUS_H + 12, s.res_address);
                let mut y = STATUS_H + 34;
                if let Ok(t) = v.target {
                    let kind: Buf<96> = fill(s.words_count, &[&t.script_type().name(), &net.name()]);
                    BODY.draw(c, MARGIN, y, kind.as_str(), theme::TEXT_DIM);
                    y += 40;
                }
                let y = address_lines(c, MARGIN, y, v.addr()) + 12;
                match v.target {
                    Err(e) => {
                        let i = match e {
                            TargetError::Invalid => 0,
                            TargetError::WrongNetwork => 1,
                            TargetError::Multisig => 2,
                            TargetError::Unsupported => 3,
                        };
                        let msg: Buf<256> = fill(s.va_errors[i], &[&net.name()]);
                        let col = if i == 1 { theme::DANGER } else { theme::WARN };
                        BODY.draw_wrapped(c, MARGIN, y, 800 - 2 * MARGIN, 30, 3, msg.as_str(), col);
                        widgets::hint_bar(c, &[("Enter", s.h_done)]);
                    }
                    Ok(_) if self.seed_count() == 0 => {
                        BODY.draw_wrapped(c, MARGIN, y, 800 - 2 * MARGIN, 30, 2, s.va_no_seed, theme::WARN);
                        widgets::hint_bar(c, &[("Enter", s.h_done)]);
                    }
                    Ok(_) => {
                        let items = s.va_options.map(|label| MenuItem { label, detail: "" });
                        widgets::list(c, MARGIN, y, 800 - 2 * MARGIN, 110, &items, sel as usize, false);
                        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
                    }
                }
            }
            VaStep::Searching | VaStep::Paused { .. } => {
                let Some(search) = v.search.as_ref() else { return };
                SMALL.draw(c, MARGIN, STATUS_H + 12, v.addr(), theme::TEXT_DIM);
                let paused = matches!(step, VaStep::Paused { .. });
                let (head, col) = if paused {
                    (s.va_not_found, theme::WARN)
                } else {
                    (s.va_searching, theme::TEXT)
                };
                TITLE.draw(c, MARGIN, STATUS_H + 34, head, col);
                let mut y = STATUS_H + 80;
                let seeds = self.verify_seed_list(search);
                let l: Buf<160> = fill(s.va_seeds, &[&seeds.as_str()]);
                BODY.draw(c, MARGIN, y, l.as_str(), theme::TEXT);
                y += 30;
                let accts = account_list(search);
                let st = search.target().script_type().name();
                let l: Buf<160> = fill(s.va_accounts, &[&st, &accts.as_str()]);
                BODY.draw(c, MARGIN, y, l.as_str(), theme::TEXT);
                y += 36;
                let (done, limit) = (search.scanned(), search.limit());
                let frac = if limit == 0 {
                    0.0
                } else {
                    done as f64 / limit as f64
                };
                widgets::progress_bar(c, MARGIN, y, 800 - 2 * MARGIN, 10, frac, theme::ACCENT);
                y += 18;
                let p: Buf<160> = fill(s.va_progress, &[&done, &limit]);
                SMALL.draw(c, MARGIN, y, p.as_str(), theme::TEXT_DIM);
                let ck: Buf<96> = fill(s.va_checked, &[&search.checked()]);
                SMALL.draw(
                    c,
                    800 - MARGIN - SMALL.text_width(ck.as_str()),
                    y,
                    ck.as_str(),
                    theme::TEXT_DIM,
                );
                y += 28;
                if let VaStep::Paused { sel } = step {
                    let finished = search.state() == State::Paused;
                    if finished {
                        let last = limit.saturating_sub(1);
                        let l: Buf<256> = fill(s.va_not_found_1, &[&last]);
                        y = SMALL.draw_wrapped(
                            c,
                            MARGIN,
                            y,
                            800 - 2 * MARGIN,
                            22,
                            2,
                            l.as_str(),
                            theme::TEXT_DIM,
                        ) + 4;
                    }
                    let next = self.next_account();
                    let acct: Buf<96> = fill(s.va_more[2], &[&next]);
                    let first = if finished { s.va_more[1] } else { s.va_more[0] };
                    let items = [
                        MenuItem {
                            label: first,
                            detail: "",
                        },
                        MenuItem {
                            label: acct.as_str(),
                            detail: "",
                        },
                        MenuItem {
                            label: s.va_more[3],
                            detail: "",
                        },
                    ];
                    widgets::list(
                        c,
                        MARGIN,
                        y,
                        800 - 2 * MARGIN,
                        446 - 8 - y,
                        &items,
                        sel as usize,
                        false,
                    );
                    widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
                } else {
                    widgets::hint_bar(c, &[("Esc", s.h_stop)]);
                }
            }
            VaStep::Found => {
                let Some(State::Found(f)) = v.search.as_ref().map(|s| s.state()) else {
                    return;
                };
                self.render_found(c, v, f);
            }
        }
    }

    fn verify_seed_list(&self, search: &Search) -> Buf<48> {
        let mut list = [[0u8; 4]; crate::SEED_SLOTS];
        let mut n = 0;
        for a in search.accounts() {
            if n < list.len() && !list[..n].contains(&a.fingerprint) {
                list[n] = a.fingerprint;
                n += 1;
            }
        }
        fps(&list[..n])
    }

    fn render_found(&self, c: &mut dyn Canvas, v: &VerifyState, f: Found) {
        let s = self.text();
        let Ok(t) = v.target else { return };
        let st = t.script_type();
        let net = self.settings.network;
        let addr = v.addr();
        // the address QR on the left (bech32 upper-cased: alphanumeric mode)
        let mut qr_text = [0u8; address::MAX_ADDRESS_LEN];
        let n = addr.len();
        qr_text[..n].copy_from_slice(addr.as_bytes());
        if matches!(st, ScriptType::NativeSegwit | ScriptType::Taproot) {
            qr_text[..n].make_ascii_uppercase();
        }
        if let Ok(q) = bp_qr::QrCode::encode(&qr_text[..n], bp_qr::qr::Ecc::Medium, 1, 40, None) {
            let style = widgets::QrStyle {
                light: 255,
                invert: false,
            };
            widgets::qr_code(c, &q, MARGIN - 8, STATUS_H + 30, 300, 300, style);
        }
        let x = MARGIN + 310;
        TITLE.draw(c, x, STATUS_H + 24, s.va_found, theme::OK);
        let fp = fingerprint_hex(&f.fingerprint);
        let l: Buf<128> = fill(s.va_found_1, &[&fp.as_str()]);
        BODY.draw_wrapped(
            c,
            x,
            STATUS_H + 72,
            800 - MARGIN - x,
            28,
            2,
            l.as_str(),
            theme::TEXT,
        );
        let path = bformat!(
            64,
            "{}/{}/{}",
            st.account_path(net, f.account),
            f.change as u8,
            f.index
        );
        BODY.draw(c, x, STATUS_H + 136, path.as_str(), theme::ACCENT);
        let kind = if f.change { s.change } else { s.receive };
        let head: Buf<96> = fill(s.addr_head, &[&kind, &f.index]);
        widgets::label(c, x, STATUS_H + 170, head.as_str());
        // the address in groups of four, five groups per line
        let mut y = STATUS_H + 200;
        for chunk in addr.as_bytes().chunks(20) {
            let mut line = Buf::<32>::new();
            for (i, g) in chunk.chunks(4).enumerate() {
                if i > 0 {
                    line.push_str(" ");
                }
                line.push_str(core::str::from_utf8(g).unwrap_or(""));
            }
            BODY.draw(c, x, y, line.as_str(), theme::TEXT);
            y += 30;
        }
        widgets::hint_bar(c, &[("Enter", s.h_done), ("S", s.ms_shortcut)]);
    }
}

/// "0, 1" (the accounts searched).
fn account_list(search: &Search) -> Buf<48> {
    let mut seen = [0u32; MAX_ACCOUNTS];
    let mut n = 0;
    let mut out = Buf::<48>::new();
    for a in search.accounts() {
        if !seen[..n].contains(&a.account) {
            if n > 0 {
                out.push_str(", ");
            }
            let _ = core::fmt::Write::write_fmt(&mut out, format_args!("{}", a.account));
            seen[n] = a.account;
            n += 1;
        }
    }
    out
}
