//! Seed XOR screens (M11-3, decision 5): splitting a loaded seed into two
//! to four parts that are seeds of their own, and loading a seed from its
//! parts (typed with the usual word entry, one part after another).
//!
//! Parts take no device randomness: Coldcard's deterministic formula, or
//! the formula with dice (`bp_backup::seedxor`). Every part is shown, then
//! three of its words are checked; the seed's last word is shown to write
//! with them (Coldcard's advice: it confirms a restore).

use crate::menus::Start;
use crate::{App, Pick, Screen};
use bp_backup::seedxor::{self, MAX_COMBINE, MAX_PARTS};
use bp_bitcoin::bip39::{Mnemonic, MAX_WORDS, WORDS};
use bp_crypto::secret::wipe;
use bp_crypto::sha256::Sha256;
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, SMALL, TITLE};
use bp_ui::widgets::{self, MenuItem, Tag, MARGIN, STATUS_H};
use bp_ui::{grid, theme};

/// Dice rolls asked for when they are mixed in (129 bits).
pub const MIN_DICE: usize = 50;
const MAX_DICE: usize = 200;
/// Words checked of every part.
pub const CHECKS: usize = 3;
const LIST_TOP: i32 = STATUS_H + 80;

/// Steps of the Seed XOR screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XorStep {
    /// Split: two, three or four parts.
    Parts { sel: u8 },
    /// Split: the formula alone, or with dice.
    Mode { sel: u8 },
    /// Split: typing the dice.
    Dice,
    /// Split: one part's words.
    Show { part: u8 },
    /// The screen saver hid a part.
    Covered { part: u8 },
    /// Split: checking a word of the part just shown.
    Check { part: u8, q: u8, sel: u8 },
    /// Split: all parts written; the seed's last word.
    Done,
    /// Restore: the parts so far and the seed they make.
    Combined { sel: u8 },
}

/// What the screens are doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XrMode {
    /// Split the seed in this slot.
    Split(u8),
    Restore,
}

#[derive(Clone, Copy, Default)]
struct Check {
    pos: u8,
    options: [u16; 4],
    answer: u8,
}

/// State of the Seed XOR screens; wiped when they close.
pub struct XorState {
    pub mode: XrMode,
    /// Entropy bytes of the seed (and of every part).
    pub len: usize,
    // split
    pub n: u8,
    parts: [[u8; 32]; MAX_PARTS],
    /// The seed's last word (written with the parts).
    pub last_word: u16,
    dice: [u8; MAX_DICE],
    pub dice_len: usize,
    checks: [Check; CHECKS],
    // restore
    acc: [u8; 32],
    pub count: u8,
    seen: [[u8; 32]; MAX_COMBINE],
    /// The seed the parts make so far: fingerprint and last word.
    pub result: Option<([u8; 4], u16)>,
    /// The last part was typed before.
    pub again: bool,
}

impl Drop for XorState {
    fn drop(&mut self) {
        for p in self.parts.iter_mut() {
            wipe(p);
        }
        wipe(&mut self.acc);
        wipe(&mut self.dice);
        for h in self.seen.iter_mut() {
            wipe(h);
        }
    }
}

impl XorState {
    fn new(mode: XrMode) -> XorState {
        XorState {
            mode,
            len: 0,
            n: 2,
            parts: [[0; 32]; MAX_PARTS],
            last_word: 0,
            dice: [0; MAX_DICE],
            dice_len: 0,
            checks: [Check::default(); CHECKS],
            acc: [0; 32],
            count: 0,
            seen: [[0; 32]; MAX_COMBINE],
            result: None,
            again: false,
        }
    }

    /// Word values of part `p` (split), in `out`; returns how many.
    pub fn part_words(&self, p: u8, out: &mut [u16; MAX_WORDS]) -> usize {
        let Ok(m) = Mnemonic::from_entropy(&self.parts[p as usize % MAX_PARTS][..self.len]) else {
            return 0;
        };
        out[..m.len()].copy_from_slice(m.indices());
        m.len()
    }

    /// Position asked and the four choices of check `q` (tests).
    #[cfg(test)]
    pub fn check_for_test(&self, q: usize) -> (usize, [u16; 4]) {
        (self.checks[q].pos as usize, self.checks[q].options)
    }
}

/// Part letters, as Coldcard names them.
pub fn letter(p: u8) -> char {
    (b'A' + p) as char
}

impl App {
    fn xr_step(&mut self, step: XorStep) {
        self.set_current(Screen::SeedXor { step });
    }

    /// Seed options > Split (Seed XOR).
    pub(crate) fn seed_xor_split_action(&mut self, slot: u8) {
        let Some(m) = self.seed(slot as usize) else { return };
        let mut st = XorState::new(XrMode::Split(slot));
        let mut e = [0u8; 32];
        st.len = m.entropy(&mut e);
        st.last_word = m.indices()[m.len() - 1];
        wipe(&mut e);
        self.xor = Some(st);
        self.push(Screen::SeedXor {
            step: XorStep::Parts { sel: 1 },
        });
    }

    /// A part was typed (word entry with `Start::XorParts`): add it.
    pub(crate) fn seed_xor_part_typed(&mut self, m: Mnemonic) {
        let words = m.len();
        self.flow = None;
        let st = self.xor.get_or_insert_with(|| XorState::new(XrMode::Restore));
        let mut e = [0u8; 32];
        let len = m.entropy(&mut e);
        drop(m);
        let h = Sha256::digest(&e[..len]);
        st.again = st.seen[..st.count as usize].contains(&h);
        if !st.again {
            if st.count == 0 {
                st.len = len;
            }
            seedxor::xor_into(&mut st.acc[..len], &e[..len]);
            st.seen[st.count as usize] = h;
            st.count += 1;
            st.result = Mnemonic::from_entropy(&st.acc[..len]).ok().and_then(|r| {
                let last = r.indices()[words - 1];
                crate::seeds::SeedSlot::new(r, b"").map(|s| (s.fingerprint, last))
            });
        }
        wipe(&mut e);
        self.xr_step(XorStep::Combined { sel: 0 });
    }

    fn xr_cancel(&mut self) {
        match self.xor.as_ref().map(|s| s.mode) {
            Some(XrMode::Split(slot)) => {
                self.xor = None;
                self.go_seeds(Some(Screen::SeedOptions { slot, sel: 0 }));
            }
            _ => self.confirm_cancel(),
        }
    }

    pub(crate) fn seed_xor_key(&mut self, step: XorStep, ev: KeyEvent) {
        self.notice = None;
        let t = self.text().bk;
        let Some(st) = self.xor.as_mut() else {
            self.go_seeds(None);
            return;
        };
        match step {
            XorStep::Parts { sel } => match crate::pick(ev.key, sel, 3) {
                Pick::Move(s) => self.xr_step(XorStep::Parts { sel: s }),
                Pick::Choose(s) => {
                    st.n = s + 2;
                    self.xr_step(XorStep::Mode { sel: 0 });
                }
                Pick::Back => self.xr_cancel(),
                Pick::None => {}
            },
            XorStep::Mode { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.xr_step(XorStep::Mode { sel: s }),
                Pick::Choose(0) => {
                    st.dice_len = 0;
                    self.xr_make();
                }
                Pick::Choose(_) => {
                    wipe(&mut st.dice);
                    st.dice_len = 0;
                    self.xr_step(XorStep::Dice);
                }
                Pick::Back => {
                    let sel = st.n - 2;
                    self.xr_step(XorStep::Parts { sel });
                }
                Pick::None => {}
            },
            XorStep::Dice => match ev.key {
                Key::Char(c @ '1'..='6') if st.dice_len < MAX_DICE => {
                    st.dice[st.dice_len] = c as u8;
                    st.dice_len += 1;
                }
                Key::Backspace if st.dice_len > 0 => {
                    st.dice_len -= 1;
                    st.dice[st.dice_len] = 0;
                }
                Key::Enter if st.dice_len >= MIN_DICE => self.xr_make(),
                Key::Enter => self.notice = Some(t.sl_dice_short),
                Key::Esc => self.xr_step(XorStep::Mode { sel: 1 }),
                _ => {}
            },
            XorStep::Show { part } | XorStep::Covered { part } => match ev.key {
                Key::Enter => self.xr_start_checks(part),
                Key::Esc => self.xr_cancel(),
                _ => {}
            },
            XorStep::Check { part, q, sel } => match crate::pick(ev.key, sel, 4) {
                Pick::Move(s) => self.xr_step(XorStep::Check { part, q, sel: s }),
                Pick::Choose(s) => {
                    if st.checks[q as usize].answer != s {
                        self.notice = Some(t.sl_check_wrong);
                        self.xr_step(XorStep::Show { part });
                    } else if (q as usize) + 1 < CHECKS {
                        self.xr_step(XorStep::Check {
                            part,
                            q: q + 1,
                            sel: 0,
                        });
                    } else if part + 1 < st.n {
                        self.xr_step(XorStep::Show { part: part + 1 });
                    } else {
                        self.xr_step(XorStep::Done);
                    }
                }
                Pick::Back => self.xr_step(XorStep::Show { part }),
                Pick::None => {}
            },
            XorStep::Done => {
                if matches!(ev.key, Key::Enter | Key::Esc) {
                    self.xr_cancel();
                }
            }
            XorStep::Combined { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.xr_step(XorStep::Combined { sel: s }),
                Pick::Choose(0) => {
                    if st.count as usize >= MAX_COMBINE {
                        self.notice = Some(t.xr_full);
                        return;
                    }
                    // the entry replaces this screen (the stack stays put)
                    let words = st.len * 3 / 4;
                    self.flow = Some(crate::flow::Flow::new(Start::XorParts, words));
                    self.set_current(Screen::WordEntry);
                }
                Pick::Choose(_) => {
                    if st.count < 2 {
                        self.notice = Some(t.xr_two);
                        return;
                    }
                    let m = Mnemonic::from_entropy(&st.acc[..st.len]).ok();
                    self.xor = None;
                    self.store_seed(m, false);
                }
                Pick::Back => self.xr_cancel(),
                Pick::None => {}
            },
        }
    }

    /// The parts of the seed (formula, optionally with dice); the first
    /// is shown.
    fn xr_make(&mut self) {
        let Some(st) = self.xor.as_mut() else { return };
        let XrMode::Split(slot) = st.mode else { return };
        let Some(m) = self.seeds[slot as usize]
            .as_ref()
            .and_then(|s| s.mnemonic.as_ref())
        else {
            return;
        };
        let mut e = [0u8; 32];
        let len = m.entropy(&mut e);
        let ok = seedxor::split(&e[..len], st.n as usize, &st.dice[..st.dice_len], &mut st.parts).is_ok();
        wipe(&mut e);
        if ok {
            self.xr_step(XorStep::Show { part: 0 });
        }
    }

    fn xr_start_checks(&mut self, part: u8) {
        let Some(st) = self.xor.as_mut() else { return };
        let mut w = [0u16; MAX_WORDS];
        let n = st.part_words(part, &mut w);
        if n == 0 {
            return;
        }
        let mut picked = [usize::MAX; CHECKS];
        for q in 0..CHECKS {
            let mut pos = self.quiz_rng.below(n as u32) as usize;
            while picked[..q].contains(&pos) {
                pos = (pos + 1) % n;
            }
            picked[q] = pos;
            let mut opts = [w[pos]; 4];
            let mut k = 1;
            while k < 4 {
                let cand = self.quiz_rng.below(2048) as u16;
                if !opts[..k].contains(&cand) {
                    opts[k] = cand;
                    k += 1;
                }
            }
            let at = self.quiz_rng.below(4) as usize;
            opts.swap(0, at);
            st.checks[q] = Check {
                pos: pos as u8,
                options: opts,
                answer: at as u8,
            };
        }
        bp_crypto::secret::wipe_u16(&mut w);
        self.xr_step(XorStep::Check { part, q: 0, sel: 0 });
    }

    // ---------- drawing ----------

    pub(crate) fn render_seed_xor(&self, c: &mut dyn Canvas, step: XorStep) {
        let s = self.text();
        let t = s.bk;
        let Some(st) = self.xor.as_ref() else { return };
        let w = grid::COLS * grid::CELL_W;
        let g = |row| grid::text_y(&BODY, row, 1);
        let notice = |c: &mut dyn Canvas, row: i32| {
            if let Some(n) = self.notice {
                widgets::log_line(c, MARGIN, g(row), w, Tag::Warn, n, "");
            }
        };
        self.status(c, t.xr_title);
        match step {
            XorStep::Parts { sel } => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.xr_parts_q, theme::TEXT);
                let labels: [Buf<16>; 3] = core::array::from_fn(|i| fill(t.xr_n_parts, &[&(i + 2)]));
                let items: [MenuItem; 3] = core::array::from_fn(|i| MenuItem {
                    label: labels[i].as_str(),
                    detail: "",
                });
                widgets::list(c, MARGIN, LIST_TOP, w, 3 * 48, &items, sel as usize, false);
                widgets::log_line(c, MARGIN, g(12), w, Tag::Info, t.xr_parts_note, "");
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            XorStep::Mode { sel } => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.xr_mode_q, theme::TEXT);
                let items = t.xr_modes.map(|l| MenuItem { label: l, detail: "" });
                widgets::list(c, MARGIN, LIST_TOP, w, 2 * 48, &items, sel as usize, false);
                widgets::log_line(
                    c,
                    MARGIN,
                    g(10),
                    w,
                    Tag::Info,
                    t.xr_mode_notes[sel as usize % 2],
                    "",
                );
                let n: Buf<24> = fill(t.xr_parts_line, &[&st.n]);
                widgets::log_line(c, MARGIN, g(11), w, Tag::Info, n.as_str(), "");
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            XorStep::Dice => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.sl_dice_title, theme::TEXT);
                let count: Buf<48> = fill(t.sl_dice_count, &[&st.dice_len]);
                let tag = if st.dice_len >= MIN_DICE {
                    Tag::Ok
                } else {
                    Tag::Pending
                };
                widgets::log_line(c, MARGIN, g(5), w, tag, count.as_str(), "");
                let rec = &st.dice[..st.dice_len];
                for (row, chunk) in rec.chunks(60).take(4).enumerate() {
                    let line = core::str::from_utf8(chunk).unwrap_or("");
                    BODY.draw(c, MARGIN, g(7 + row as i32), line, theme::TEXT);
                }
                notice(c, 13);
                widgets::hint_bar(
                    c,
                    &[
                        ("1-6", s.h_type),
                        ("Del", s.h_delete),
                        ("Enter", s.h_continue),
                        ("Esc", s.h_back),
                    ],
                );
            }
            XorStep::Show { part } => {
                let head: Buf<48> = fill(t.xr_show_title, &[&letter(part), &st.n]);
                TITLE.draw(c, MARGIN, STATUS_H + 12, head.as_str(), theme::TEXT);
                let mut wv = [0u16; MAX_WORDS];
                let n = st.part_words(part, &mut wv);
                let words: [&str; MAX_WORDS] =
                    core::array::from_fn(|i| if i < n { WORDS[wv[i] as usize] } else { "" });
                let row_h = if n <= 12 { 40 } else { 34 };
                widgets::word_grid(
                    c,
                    MARGIN + 6,
                    STATUS_H + 60,
                    w,
                    &words[..n],
                    4,
                    row_h,
                    None,
                    &BODY,
                );
                bp_crypto::secret::wipe_u16(&mut wv);
                match self.notice {
                    Some(m) => BODY.draw(c, MARGIN, 410, m, theme::WARN),
                    None => SMALL.draw(c, MARGIN, 414, t.xr_show_note, theme::TEXT_DIM),
                };
                widgets::hint_bar(c, &[("Enter", t.h_check), ("Esc", s.h_cancel)]);
            }
            XorStep::Covered { part } => {
                let head: Buf<48> = fill(t.xr_show_title, &[&letter(part), &st.n]);
                TITLE.draw(c, MARGIN, STATUS_H + 12, head.as_str(), theme::TEXT);
                widgets::log_line(c, MARGIN, g(4), w, Tag::Info, t.sl_covered, "");
                widgets::hint_bar(c, &[("Enter", t.h_check), ("Esc", s.h_cancel)]);
            }
            XorStep::Check { part, q, sel } => {
                let ck = &st.checks[q as usize % CHECKS];
                let line: Buf<96> = fill(t.xr_check_q, &[&letter(part), &st.n, &(ck.pos + 1)]);
                TITLE.draw(c, MARGIN, STATUS_H + 20, line.as_str(), theme::TEXT);
                let items = ck.options.map(|o| MenuItem {
                    label: WORDS[o as usize],
                    detail: "",
                });
                widgets::list(c, MARGIN, LIST_TOP, w, 4 * 48, &items, sel as usize, false);
                let prog: Buf<16> = fill("{}/{}", &[&(q + 1), &CHECKS]);
                SMALL.draw(c, MARGIN, 414, prog.as_str(), theme::TEXT_DIM);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            XorStep::Done => {
                TITLE.draw(c, MARGIN, grid::text_y(&TITLE, 2, 2), t.xr_done_title, theme::OK);
                let parts: Buf<64> = fill(t.xr_done_parts, &[&st.n]);
                widgets::log_line(c, MARGIN, g(5), w, Tag::Ok, parts.as_str(), "");
                let word: Buf<96> = fill(t.xr_done_word, &[&WORDS[st.last_word as usize]]);
                widgets::log_line(c, MARGIN, g(6), w, Tag::Info, word.as_str(), "");
                for (i, n) in t.xr_done_notes.iter().enumerate() {
                    widgets::log_line(c, MARGIN, g(8 + i as i32), w, Tag::Info, n, "");
                }
                widgets::hint_bar(c, &[("Enter", s.h_continue)]);
            }
            XorStep::Combined { sel } => {
                let (tag, line): (Tag, Buf<64>) = if st.again {
                    (Tag::Warn, fill("{}", &[&t.xr_again]))
                } else {
                    (
                        Tag::Ok,
                        fill(t.xr_added, &[&letter(st.count.saturating_sub(1)), &st.count]),
                    )
                };
                TITLE.draw(c, MARGIN, grid::text_y(&TITLE, 2, 2), t.xr_title, theme::TEXT);
                widgets::log_line(c, MARGIN, g(5), w, tag, line.as_str(), "");
                if let Some((fp, last)) = st.result {
                    let fp = crate::seeds::fingerprint_hex(&fp);
                    let r: Buf<96> = fill(t.xr_result, &[&fp.as_str(), &WORDS[last as usize]]);
                    widgets::log_line(c, MARGIN, g(6), w, Tag::Info, r.as_str(), "");
                    widgets::log_line(c, MARGIN, g(7), w, Tag::Info, t.xr_result_note, "");
                }
                let items = [
                    MenuItem {
                        label: t.xr_more,
                        detail: ">",
                    },
                    MenuItem {
                        label: t.xr_load,
                        detail: "",
                    },
                ];
                widgets::list(c, MARGIN, g(9), w, 2 * 48, &items, sel as usize, false);
                notice(c, 14);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_cancel)]);
            }
        }
    }
}
