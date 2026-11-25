//! Tamper check (M10-7, decision 12): before typing the PIN, type a check
//! code and compare two words with the ones written down when the code was
//! first used. The words come from the code (stretched like a PIN), the
//! firmware's SHA-256, the device key and the secure element: another
//! firmware image or another device shows other words.
//!
//! The code is never stored and the attempt counter is not touched. Tab on
//! the lock screen (or its wait) opens it; so does Settings > Security >
//! Tamper check. What it proves is limited until signed boot (M12): a
//! malicious firmware that can reach the device key and the secure element
//! could still compute the genuine words, so the words chiefly catch a
//! swapped device and firmware that was changed without that care.

use crate::vault::{self, VaultHw};
use crate::vaultui::Mode;
use crate::{App, Screen};
use bp_crypto::hmac::HmacSha256;
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, DOUBLE, TITLE};
use bp_ui::widgets::{self, Tag, MARGIN};
use bp_ui::{grid, theme};

pub const CODE_MIN: usize = 6;
pub const CODE_MAX: usize = 16;

/// Steps of the tamper check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TamperStep {
    /// Type the check code.
    Code,
    /// The code is stretched, the secure element asked.
    Working,
    /// The two words.
    Words,
}

impl App {
    /// The platform gives the firmware image's SHA-256 at start-up.
    pub fn set_firmware_hash(&mut self, hash: [u8; 32]) {
        self.vault.firmware = Some(hash);
    }

    fn tc_step(&mut self, step: TamperStep) {
        self.set_current(Screen::Tamper { step });
    }

    /// Open the tamper check (lock screen Tab, or Settings > Security).
    pub(crate) fn vault_tamper_action(&mut self) {
        let t = self.text().vault;
        if self.vault.firmware.is_none() {
            self.notice = Some(t.tc_no_fw);
            return;
        }
        match self.vault.exists {
            None => self.notice = Some(t.no_hw),
            Some(false) => self.notice = Some(t.no_vault),
            Some(true) => {
                self.vault.tamper.clear();
                self.vault.tamper_words = None;
                self.push(Screen::Tamper {
                    step: TamperStep::Code,
                });
            }
        }
    }

    /// The tamper check job: the words for the code typed.
    pub(crate) fn vault_tamper_job(&mut self, hw: &mut VaultHw, body: &mut [u8]) {
        let fw = self.vault.firmware.unwrap_or([0; 32]);
        let words = if self.vault.mode == Mode::Fake {
            // after a silent erase the element is gone: words that look real
            Some(self.fake_tamper_words(&fw))
        } else {
            vault::scan(hw.flash, body)
                .ok()
                .flatten()
                .and_then(|found| vault::tamper_words(hw, &found, self.vault.tamper.text(), &fw).ok())
        };
        self.vault.tamper.clear();
        match words {
            Some(w) => {
                self.vault.tamper_words = Some(w);
                self.tc_step(TamperStep::Words);
            }
            None => {
                self.notice = Some(self.text().vault.problems[2]);
                self.pop();
            }
        }
    }

    fn fake_tamper_words(&self, fw: &[u8; 32]) -> [u16; 2] {
        let key = self.vault_fake_key().unwrap_or([0; 32]);
        let mut h = HmacSha256::new(&key);
        h.update(b"bitpunk tamper");
        h.update(self.vault.tamper.text());
        h.update(fw);
        let m = h.finalize();
        [
            u16::from_be_bytes([m[0], m[1]]) >> 5,
            u16::from_be_bytes([m[2], m[3]]) >> 5,
        ]
    }

    // ---------- keys ----------

    pub(crate) fn tamper_key(&mut self, step: TamperStep, ev: KeyEvent) {
        let t = self.text().vault;
        self.notice = None;
        match step {
            TamperStep::Code => match ev.key {
                Key::Enter if self.vault.tamper.len() >= CODE_MIN => {
                    self.tc_step(TamperStep::Working);
                    self.vault_queue_tamper();
                }
                Key::Enter => self.notice = Some(t.tc_short),
                Key::Esc => {
                    self.vault.tamper.clear();
                    self.pop();
                }
                k => {
                    self.vault.tamper.key(k, CODE_MAX);
                }
            },
            TamperStep::Working => {}
            TamperStep::Words => {
                if matches!(ev.key, Key::Enter | Key::Esc) {
                    self.vault.tamper_words = None;
                    self.pop();
                }
            }
        }
    }

    // ---------- drawing ----------

    pub(crate) fn render_tamper(&self, c: &mut dyn Canvas, step: TamperStep) {
        let s = self.text();
        let t = s.vault;
        self.status(c, t.tc_title);
        let w = grid::COLS * grid::CELL_W;
        let g = |row| grid::text_y(&BODY, row, 1);
        TITLE.draw(c, MARGIN, grid::text_y(&TITLE, 2, 2), t.tc_title, theme::BRIGHT);
        match step {
            TamperStep::Code => {
                BODY.draw(c, MARGIN, g(5), t.tc_label, theme::TEXT_DIM);
                let mut stars = Buf::<32>::new();
                for _ in 0..self.vault.tamper.len() {
                    stars.push_str("*");
                }
                widgets::text_field(
                    c,
                    MARGIN,
                    grid::y(6) + 4,
                    800 - 2 * MARGIN,
                    stars.as_str(),
                    "",
                    &TITLE,
                );
                for (i, l) in t.tc_lines.iter().enumerate() {
                    widgets::log_line(c, MARGIN, g(10 + i as i32), w, Tag::Info, l, "");
                }
                if let Some(n) = self.notice {
                    widgets::log_line(c, MARGIN, g(13), w, Tag::Warn, n, "");
                }
                widgets::hint_bar(
                    c,
                    &[("Enter", t.h_tamper), ("Del", s.h_delete), ("Esc", s.h_back)],
                );
            }
            TamperStep::Working => {
                BODY.draw(c, MARGIN, g(5), t.tc_working, theme::TEXT);
                for (i, l) in t.tc_working_lines.iter().enumerate() {
                    widgets::log_line(c, MARGIN, g(7 + i as i32), w, Tag::Pending, l, "");
                }
            }
            TamperStep::Words => {
                BODY.draw(c, MARGIN, g(5), t.tc_words, theme::TEXT_DIM);
                if let Some([a, b]) = self.vault.tamper_words {
                    let ws = bp_bitcoin::bip39::WORDS;
                    let l: Buf<32> = fill("{}  {}", &[&ws[a as usize & 2047], &ws[b as usize & 2047]]);
                    DOUBLE.draw(c, MARGIN, grid::text_y(&DOUBLE, 6, 2), l.as_str(), theme::BRIGHT);
                }
                let fw = self.vault.firmware.unwrap_or([0; 32]);
                let short = crate::seeds::fingerprint_hex(&[fw[0], fw[1], fw[2], fw[3]]);
                let line: Buf<64> = fill(t.tc_firmware, &[&short.as_str()]);
                BODY.draw(c, MARGIN, g(9), line.as_str(), theme::TEXT_DIM);
                widgets::log_line(c, MARGIN, g(11), w, Tag::Info, t.tc_same, "");
                widgets::log_line(c, MARGIN, g(12), w, Tag::Warn, t.tc_differ, "");
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
        }
    }
}
