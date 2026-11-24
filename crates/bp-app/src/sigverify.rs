//! Verifying a signed message: one armored QR ("BEGIN BITCOIN SIGNED
//! MESSAGE"), or Tools > Verify signature: the signer's address, the
//! message typed on the device, then the signature. Electrum, BIP-137 and
//! BIP-322 simple signatures are checked; a header naming another address
//! type is reported. "Is this address mine?" continues with Verify
//! address.

use crate::msgsign::{draw_editor, edit_key};
use crate::{scan, App, Pick, Screen};
use bp_bitcoin::addrcheck::TargetError;
use bp_bitcoin::address::{self, ScriptType};
use bp_bitcoin::message::{self, CheckError, SigKind, MAX_MESSAGE};
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, SMALL, TITLE};
use bp_ui::theme;
use bp_ui::widgets::{self, MenuItem, MARGIN, STATUS_H};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvStep {
    /// Typing the message that was signed (after scanning the address).
    Type,
    Result {
        sel: u8,
    },
}

pub type Verdict = Result<(ScriptType, SigKind), CheckError>;

pub struct SigState {
    addr: [u8; address::MAX_ADDRESS_LEN],
    addr_len: usize,
    msg: [u8; MAX_MESSAGE],
    len: usize,
    pub verdict: Option<Verdict>,
}

impl SigState {
    fn new() -> SigState {
        SigState {
            addr: [0; address::MAX_ADDRESS_LEN],
            addr_len: 0,
            msg: [0; MAX_MESSAGE],
            len: 0,
            verdict: None,
        }
    }

    fn addr(&self) -> &str {
        core::str::from_utf8(&self.addr[..self.addr_len]).unwrap_or("")
    }

    fn message(&self) -> &[u8] {
        &self.msg[..self.len]
    }

    fn set_addr(&mut self, a: &[u8]) {
        let n = a.len().min(self.addr.len());
        self.addr[..n].copy_from_slice(&a[..n]);
        self.addr_len = n;
    }

    fn set_message(&mut self, m: &[u8]) {
        let n = m.len().min(self.msg.len());
        self.msg[..n].copy_from_slice(&m[..n]);
        self.len = n;
    }
}

impl Drop for SigState {
    fn drop(&mut self) {
        bp_crypto::secret::wipe(&mut self.msg);
    }
}

impl App {
    /// An armored signed message was scanned: verify it at once.
    pub(crate) fn verify_armored(&mut self, text: &[u8]) {
        let mut st = SigState::new();
        let net = self.settings.network;
        st.verdict = Some(match message::parse_armored(text) {
            Some(a) => {
                st.set_addr(a.address.as_bytes());
                st.set_message(a.message);
                message::verify_any(a.address, net, a.message, a.signature)
            }
            None => Err(CheckError::Encoding),
        });
        self.sig = Some(st);
        self.set_current(Screen::SigVerify {
            step: SvStep::Result { sel: 0 },
        });
    }

    /// Tools > Verify signature scanned the signer's address.
    pub(crate) fn sig_address(&mut self, addr: &[u8]) {
        let mut st = SigState::new();
        st.set_addr(addr);
        self.sig = Some(st);
        self.set_current(Screen::SigVerify { step: SvStep::Type });
    }

    /// The signature was scanned (text): verify.
    pub(crate) fn sig_signature(&mut self, text: &[u8]) {
        let net = self.settings.network;
        if let Some(st) = self.sig.as_mut() {
            let sig = core::str::from_utf8(text).unwrap_or("");
            let addr = core::str::from_utf8(&st.addr[..st.addr_len]).unwrap_or("");
            st.verdict = Some(message::verify_any(addr, net, st.message(), sig));
        }
        // the scanner was pushed on top of the editor: back to it, as result
        self.pop();
        self.set_current(Screen::SigVerify {
            step: SvStep::Result { sel: 0 },
        });
    }

    pub(crate) fn sig_key(&mut self, step: SvStep, ev: KeyEvent) {
        match step {
            SvStep::Type => {
                let Some(st) = self.sig.as_mut() else { return };
                if edit_key(&mut st.msg, &mut st.len, ev) {
                    return;
                }
                match ev.key {
                    Key::Enter => self.start_scan(scan::Purpose::SigText),
                    Key::Esc => self.sig_end(),
                    _ => {}
                }
            }
            SvStep::Result { sel } => {
                let mine = self.sig_can_check_address();
                let n = if mine { 2 } else { 1 };
                match crate::pick(ev.key, sel, n) {
                    Pick::Move(s) => self.set_current(Screen::SigVerify {
                        step: SvStep::Result { sel: s },
                    }),
                    Pick::Choose(0) if mine => {
                        let mut a = [0u8; address::MAX_ADDRESS_LEN];
                        let st = self.sig.as_ref().map(|s| (s.addr, s.addr_len));
                        if let Some((addr, len)) = st {
                            a[..len].copy_from_slice(&addr[..len]);
                            self.sig = None;
                            // Verify address takes this screen's place
                            self.start_verify(&a[..len], None);
                        }
                    }
                    Pick::Choose(_) | Pick::Back => self.sig_end(),
                    Pick::None => {}
                }
            }
        }
    }

    /// Valid and a seed is loaded: offer Verify address.
    fn sig_can_check_address(&self) -> bool {
        self.seed_count() > 0 && matches!(self.sig.as_ref().and_then(|s| s.verdict), Some(Ok(_)))
    }

    fn sig_end(&mut self) {
        self.sig = None;
        self.pop();
    }

    pub(crate) fn render_sig(&self, c: &mut dyn Canvas, step: SvStep) {
        let s = self.text();
        self.status(c, s.verify_sig);
        let Some(st) = self.sig.as_ref() else { return };
        let net = self.settings.network;
        match step {
            SvStep::Type => {
                draw_editor(s, c, s.sv_type_label, st.message(), None);
                SMALL.draw(c, MARGIN, 400, st.addr(), theme::TEXT_DIM);
            }
            SvStep::Result { sel } => {
                let mut y = STATUS_H + 20;
                match st.verdict {
                    Some(Ok((_, kind))) => {
                        TITLE.draw(c, MARGIN, y, s.sv_valid, theme::OK);
                        y += 48;
                        widgets::label(c, MARGIN, y, s.res_address);
                        SMALL.draw(
                            c,
                            MARGIN,
                            y + 20,
                            crate::review_view::groups4(st.addr()).as_str(),
                            theme::BRIGHT,
                        );
                        y += 50;
                        let k = match kind {
                            SigKind::Legacy { bip137: false, .. } => s.sv_kinds[0],
                            SigKind::Legacy { bip137: true, .. } => s.sv_kinds[1],
                            SigKind::Bip322 => s.sv_kinds[2],
                        };
                        let l: Buf<128> = fill(s.ms_format, &[&k]);
                        BODY.draw(c, MARGIN, y, l.as_str(), theme::TEXT_DIM);
                        y += 34;
                        if let SigKind::Legacy {
                            header_matches: false,
                            ..
                        } = kind
                        {
                            y = BODY.draw_wrapped(
                                c,
                                MARGIN,
                                y,
                                800 - 2 * MARGIN,
                                28,
                                2,
                                s.sv_header_warn,
                                theme::WARN,
                            );
                        }
                    }
                    Some(Err(e)) => {
                        TITLE.draw(c, MARGIN, y, s.sv_invalid, theme::DANGER);
                        y += 48;
                        let i = match e {
                            CheckError::Address(TargetError::Invalid) => 0,
                            CheckError::Address(TargetError::WrongNetwork) => 1,
                            CheckError::Address(TargetError::Multisig) => 2,
                            CheckError::Address(TargetError::Unsupported) | CheckError::Unsupported => 3,
                            CheckError::Encoding => 4,
                            CheckError::Invalid => 5,
                        };
                        let l: Buf<256> = fill(s.sv_reasons[i], &[&net.name()]);
                        self.show_error(crate::errors::Area::Sig, i);
                        y = BODY.draw_wrapped(c, MARGIN, y, 800 - 2 * MARGIN, 28, 3, l.as_str(), theme::TEXT);
                        if st.addr_len > 0 {
                            SMALL.draw(c, MARGIN, y + 4, st.addr(), theme::TEXT_DIM);
                            y += 30;
                        }
                    }
                    None => {}
                }
                // the message, first lines
                let msg = core::str::from_utf8(st.message()).unwrap_or("");
                widgets::label(c, MARGIN, y + 4, s.sv_type_label);
                y = SMALL.draw_wrapped(c, MARGIN, y + 26, 800 - 2 * MARGIN, 22, 2, msg, theme::TEXT) + 8;
                let items = [
                    MenuItem {
                        label: s.sv_options[0],
                        detail: "",
                    },
                    MenuItem {
                        label: s.sv_options[1],
                        detail: "",
                    },
                ];
                let shown = if self.sig_can_check_address() {
                    &items[..]
                } else {
                    &items[1..]
                };
                widgets::list(
                    c,
                    MARGIN,
                    y.min(330),
                    800 - 2 * MARGIN,
                    110,
                    shown,
                    sel as usize,
                    false,
                );
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select)]);
            }
        }
    }
}
