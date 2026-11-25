//! SLIP-39 screens (M11-2, decisions 4 and 5): typing shares to open a
//! SLIP-39 wallet, making a new one from dice or coins, and making another
//! set of shares of a loaded one.
//!
//! A new wallet's secret is the entropy the dice give (the same conversion
//! as for seed words); its shares take no device randomness: they come from
//! the secret, the groups and optional dice (`bp_backup::slip39::make_set`).
//! Every share is shown, then three of its words are checked.

use crate::menus::Start;
use crate::seeds::{SeedSlot, SlotKind};
use crate::{App, Pick, Screen};
use bp_backup::slip39::{
    self, Added, Ems, Error, Group, MasterSecret, Recovery, Share, MAX_SHARES, MAX_SHARE_WORDS, WORDS,
};
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, DOUBLE, SMALL, TITLE};
use bp_ui::widgets::{self, MenuItem, Tag, MARGIN, STATUS_H};
use bp_ui::{grid, theme};

/// Highest iteration exponent opened here (640 000 PBKDF2 rounds).
pub const MAX_EXPONENT: u8 = 6;
/// Dice rolls asked for when they are mixed into the shares (129 bits).
pub const MIN_DICE: usize = 50;
const MAX_DICE: usize = 200;
/// Words checked of every share made.
pub const CHECKS: usize = 3;
const MAX_INPUT: usize = 8;
/// Top of a choice list under a title (as the "how many words" screen).
const LIST_TOP: i32 = STATUS_H + 80;

/// Steps of the SLIP-39 screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlStep {
    /// Opening: how many words each share has (first share only).
    Length { sel: u8 },
    /// Typing a share's words.
    Words,
    /// The share's checksum failed: pick the wrong word.
    Fix { sel: u8 },
    /// What the share did, and how far the set is.
    Status,
    /// The SLIP-39 passphrase (may be empty).
    Passphrase,
    /// The wallet's fingerprint: load it.
    Ready { sel: u8 },
    /// New wallet: dice, coins or a D20.
    Source { sel: u8 },
    /// New wallet: 20 or 33 words per share.
    Strength { kind: Start, sel: u8 },
    /// How to split: presets.
    Groups { sel: u8 },
    /// Groups set one by one.
    Custom { sel: u8 },
    /// The shares' random values: from the secret, or with dice.
    Mix { sel: u8 },
    /// Typing the dice mixed into the shares.
    Dice,
    /// One share's words.
    Show { idx: u16 },
    /// The screen saver hid a share.
    Covered { idx: u16 },
    /// Checking a word of a share just shown.
    Check { idx: u16, q: u8, sel: u8 },
}

/// What the screens are doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlMode {
    Recover,
    Create,
    /// Another set of the wallet in this slot.
    Reshare(u8),
}

/// Typing a share's words (the SLIP-39 list: four letters tell each apart).
pub struct ShareEntry {
    pub n: usize,
    pub idx: [u16; MAX_SHARE_WORDS],
    pub filled: [bool; MAX_SHARE_WORDS],
    pub pos: usize,
    input: [u8; MAX_INPUT],
    input_len: usize,
    pub cand: usize,
    pub fixing: Option<usize>,
    tail: Option<(u16, usize)>,
}

impl Drop for ShareEntry {
    fn drop(&mut self) {
        bp_crypto::secret::wipe_u16(&mut self.idx);
        bp_crypto::secret::wipe(&mut self.input);
    }
}

impl ShareEntry {
    pub fn new(n: usize) -> ShareEntry {
        ShareEntry {
            n,
            idx: [0; MAX_SHARE_WORDS],
            filled: [false; MAX_SHARE_WORDS],
            pos: 0,
            input: [0; MAX_INPUT],
            input_len: 0,
            cand: 0,
            fixing: None,
            tail: None,
        }
    }

    pub fn input(&self) -> &str {
        core::str::from_utf8(&self.input[..self.input_len]).unwrap_or("")
    }

    fn clear_input(&mut self) {
        self.input = [0; MAX_INPUT];
        self.input_len = 0;
        self.cand = 0;
    }

    pub fn complete(&self) -> bool {
        self.filled[..self.n].iter().all(|f| *f)
    }

    pub fn candidates(&self) -> core::ops::Range<usize> {
        slip39::prefix_range(self.input())
    }

    /// Append a letter; `false` if no word starts so.
    fn push_char(&mut self, ch: char) -> bool {
        if let Some((w, typed)) = self.tail {
            let word = WORDS[w as usize].as_bytes();
            if typed < word.len() && ch.to_ascii_lowercase() as u8 == word[typed] {
                self.tail = (typed + 1 < word.len()).then_some((w, typed + 1));
                return true;
            }
            self.tail = None;
        }
        if self.input_len >= MAX_INPUT || !ch.is_ascii_alphabetic() {
            return false;
        }
        self.input[self.input_len] = ch.to_ascii_lowercase() as u8;
        self.input_len += 1;
        if self.candidates().is_empty() {
            self.input_len -= 1;
            self.input[self.input_len] = 0;
            return false;
        }
        self.cand = 0;
        true
    }

    fn backspace_char(&mut self) -> bool {
        if self.input_len == 0 {
            return false;
        }
        self.input_len -= 1;
        self.input[self.input_len] = 0;
        self.cand = 0;
        true
    }

    fn auto_accept_ready(&self) -> bool {
        let r = self.candidates();
        r.len() == 1
            && (self.input_len >= slip39::UNIQUE_PREFIX_LEN || WORDS[r.start].len() == self.input_len)
    }

    fn auto_accept(&mut self) {
        let w = self.candidates().start as u16;
        let typed = self.input_len;
        self.accept(w);
        let len = WORDS[w as usize].len();
        self.tail = (typed < len).then_some((w, typed));
    }

    fn accept(&mut self, word: u16) {
        self.tail = None;
        self.idx[self.pos] = word;
        self.filled[self.pos] = true;
        self.clear_input();
        if self.fixing.take().is_some() {
            self.pos = (0..self.n).find(|&i| !self.filled[i]).unwrap_or(self.n - 1);
        } else if self.pos + 1 < self.n {
            self.pos += 1;
        }
    }

    fn step_back(&mut self) {
        let target = if self.filled[self.pos] {
            self.pos
        } else {
            self.pos.saturating_sub(1)
        };
        if self.filled[target] {
            self.filled[target] = false;
            self.idx[target] = 0;
            self.pos = target;
        }
    }

    fn start_fix(&mut self, i: usize) {
        self.fixing = Some(i);
        self.pos = i;
        self.clear_input();
    }

    pub fn word_at(&self, i: usize) -> &'static str {
        if self.filled[i] {
            WORDS[self.idx[i] as usize]
        } else {
            ""
        }
    }
}

/// One word check: the position asked, four choices, the right one.
#[derive(Clone, Copy, Default)]
struct Check {
    pos: u8,
    options: [u16; 4],
    answer: u8,
}

/// State of the SLIP-39 screens; wiped when they close.
pub struct SlipState {
    pub mode: SlMode,
    // opening
    pub rec: Recovery,
    pub words: usize,
    pub entry: ShareEntry,
    /// Shares typed so far (for "Share {}").
    pub typed: u8,
    /// What the last share did.
    pub last: Option<Result<Added, Error>>,
    /// The last share asked for more PBKDF2 rounds than allowed here.
    pub slow: bool,
    /// The first two words of the set (its identifier).
    pub set_words: [u16; 2],
    /// The opened wallet, waiting for "Load".
    pub pending: Option<SeedSlot>,
    // making
    pub ems: Option<Ems>,
    pub ms: Option<MasterSecret>,
    pub gt: u8,
    pub groups: [Group; MAX_SHARES],
    pub ngroups: u8,
    dice: [u8; MAX_DICE],
    pub dice_len: usize,
    checks: [Check; CHECKS],
}

impl Drop for SlipState {
    fn drop(&mut self) {
        bp_crypto::secret::wipe(&mut self.dice);
    }
}

impl SlipState {
    pub fn new(mode: SlMode) -> SlipState {
        SlipState {
            mode,
            rec: Recovery::new(),
            words: slip39::MIN_SHARE_WORDS,
            entry: ShareEntry::new(slip39::MIN_SHARE_WORDS),
            typed: 0,
            last: None,
            slow: false,
            set_words: [0; 2],
            pending: None,
            ems: None,
            ms: None,
            gt: 1,
            groups: [Group {
                threshold: 2,
                count: 3,
            }; MAX_SHARES],
            ngroups: 1,
            dice: [0; MAX_DICE],
            dice_len: 0,
            checks: [Check::default(); CHECKS],
        }
    }

    /// Position asked and the four choices of check `q` (tests).
    #[cfg(test)]
    pub fn check_for_test(&self, q: usize) -> (usize, [u16; 4]) {
        (self.checks[q].pos as usize, self.checks[q].options)
    }

    /// The right choice of check `q` (tests).
    #[cfg(test)]
    pub fn answer_for_test(&self, q: usize) -> u8 {
        self.checks[q].answer
    }

    pub fn dice(&self) -> &[u8] {
        &self.dice[..self.dice_len]
    }

    fn groups(&self) -> &[Group] {
        &self.groups[..self.ngroups as usize]
    }

    /// Shares the set has in all.
    pub fn total(&self) -> u16 {
        self.groups().iter().map(|g| g.count as u16).sum()
    }

    /// Group and member of share `idx` (group by group).
    pub fn place(&self, idx: u16) -> (u8, u8) {
        let mut left = idx;
        for (g, spec) in self.groups().iter().enumerate() {
            if left < spec.count as u16 {
                return (g as u8, left as u8);
            }
            left -= spec.count as u16;
        }
        (0, 0)
    }

    /// The words of share `idx` of the set being made, in `out`.
    pub fn share_words(&self, idx: u16, out: &mut [u16; MAX_SHARE_WORDS]) -> usize {
        let Some(ems) = self.ems.as_ref() else { return 0 };
        let mut n = 0;
        let mut k = 0u16;
        let _ = slip39::reshare(ems, self.gt, self.groups(), self.dice(), |s: &Share| {
            if k == idx {
                n = s.to_indices(out);
            }
            k += 1;
        });
        n
    }

    /// Custom groups: rows are "needed", "groups", then needs and shares
    /// for each group, then "make".
    pub fn custom_rows(&self) -> u8 {
        3 + 2 * self.ngroups
    }

    /// Change custom row `row` by `d` (-1 or +1), keeping the set valid.
    fn adjust(&mut self, row: u8, d: i8) {
        let step = |v: u8, lo: u8, hi: u8| -> u8 { (v as i16 + d as i16).clamp(lo as i16, hi as i16) as u8 };
        match row {
            0 => self.gt = step(self.gt, 1, self.ngroups),
            1 => {
                let n = step(self.ngroups, 1, MAX_SHARES as u8);
                if n > self.ngroups {
                    self.groups[n as usize - 1] = Group {
                        threshold: 1,
                        count: 1,
                    };
                }
                self.ngroups = n;
                self.gt = self.gt.min(n);
            }
            r if r < self.custom_rows() - 1 => {
                let g = &mut self.groups[(r as usize - 2) / 2];
                if r % 2 == 0 {
                    // needs: 1 only for a group of one share, else 2..=count
                    let lo = if g.count == 1 { 1 } else { 2 };
                    g.threshold = step(g.threshold, lo, g.count);
                } else {
                    g.count = step(g.count, 1, MAX_SHARES as u8);
                    g.threshold = if g.count == 1 {
                        1
                    } else {
                        g.threshold.clamp(2, g.count)
                    };
                }
            }
            _ => {}
        }
    }
}

/// `sl_errors` index for a refused share.
pub fn error_index(e: Error) -> usize {
    match e {
        Error::OtherSet => 0,
        Error::MemberThreshold => 1,
        Error::SameIndex => 2,
        Error::Digest => 3,
        Error::GroupThreshold => 4,
        Error::Padding => 5,
        _ => 6,
    }
}

impl App {
    fn sl_step(&mut self, step: SlStep) {
        self.set_current(Screen::Slip39 { step });
    }

    /// Seeds & keys > Load a seed > SLIP-39 shares.
    pub(crate) fn slip39_load_action(&mut self) {
        self.slip = Some(SlipState::new(SlMode::Recover));
        self.push(Screen::Slip39 {
            step: SlStep::Length { sel: 0 },
        });
    }

    /// Seeds & keys > New seed > SLIP-39 wallet.
    pub(crate) fn slip39_new_action(&mut self) {
        self.slip = Some(SlipState::new(SlMode::Create));
        self.push(Screen::Slip39 {
            step: SlStep::Source { sel: 0 },
        });
    }

    /// Seed options > SLIP-39 shares: another set of this wallet.
    pub(crate) fn slip39_reshare_action(&mut self, slot: u8) {
        let Some(ems) = self.slot(slot as usize).and_then(|s| s.ems.clone()) else {
            return;
        };
        let mut st = SlipState::new(SlMode::Reshare(slot));
        st.ems = Some(ems);
        self.slip = Some(st);
        self.push(Screen::Slip39 {
            step: SlStep::Groups { sel: 1 },
        });
    }

    /// The entropy summary of a SLIP-39 flow: its entropy is the master
    /// secret; the flow's state is wiped.
    pub(crate) fn slip39_from_entropy(&mut self) {
        let ms = self
            .flow
            .as_ref()
            .and_then(|f| f.mnemonic.as_ref())
            .and_then(|m| {
                let mut e = [0u8; 32];
                let n = m.entropy(&mut e);
                let ms = MasterSecret::new(&e[..n]).ok();
                bp_crypto::secret::wipe(&mut e);
                ms
            });
        self.flow = None;
        match (ms, self.slip.as_mut()) {
            (Some(ms), Some(st)) => {
                st.ms = Some(ms);
                self.sl_step(SlStep::Groups { sel: 1 });
            }
            _ => self.go_seeds(None),
        }
    }

    /// Leave the SLIP-39 screens: back to the seeds (a set being made is
    /// confirmed first, as any flow).
    fn sl_cancel(&mut self) {
        match self.slip.as_ref().map(|s| s.mode) {
            Some(SlMode::Reshare(slot)) => {
                self.slip = None;
                self.go_seeds(Some(Screen::SeedOptions { slot, sel: 0 }));
            }
            _ => self.confirm_cancel(),
        }
    }

    pub(crate) fn slip39_key(&mut self, step: SlStep, ev: KeyEvent) {
        self.notice = None;
        if self.slip.is_none() {
            self.go_seeds(None);
            return;
        }
        match step {
            SlStep::Length { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.sl_step(SlStep::Length { sel: s }),
                Pick::Choose(s) => {
                    let n = [slip39::MIN_SHARE_WORDS, slip39::MAX_SHARE_WORDS][s as usize];
                    if let Some(st) = self.slip.as_mut() {
                        st.words = n;
                        st.entry = ShareEntry::new(n);
                    }
                    self.sl_step(SlStep::Words);
                }
                Pick::Back => {
                    self.slip = None;
                    self.pop();
                }
                Pick::None => {}
            },
            SlStep::Words => self.sl_words_key(ev),
            SlStep::Fix { sel } => {
                let Some(st) = self.slip.as_mut() else { return };
                let n = st.words as u8;
                let rows = n.div_ceil(sl_cols(st.words) as u8);
                let sel = match ev.key {
                    Key::Up => (sel + n - 1) % n,
                    Key::Down => (sel + 1) % n,
                    Key::Left => (sel + n - rows) % n,
                    Key::Right => (sel + rows) % n,
                    Key::Enter => {
                        st.entry.start_fix(sel as usize);
                        self.sl_step(SlStep::Words);
                        return;
                    }
                    Key::Esc => {
                        self.sl_cancel();
                        return;
                    }
                    _ => sel,
                };
                self.sl_step(SlStep::Fix { sel });
            }
            SlStep::Status => match ev.key {
                Key::Enter => {
                    let Some(st) = self.slip.as_mut() else { return };
                    if st.rec.is_complete() {
                        self.pass_in.clear();
                        self.sl_step(SlStep::Passphrase);
                    } else {
                        st.entry = ShareEntry::new(st.words);
                        self.sl_step(SlStep::Words);
                    }
                }
                Key::Esc => self.sl_cancel(),
                _ => {}
            },
            SlStep::Passphrase => match ev.key {
                Key::Char(c) if (' '..='~').contains(&c) => self.pass_in.push(c as u8),
                Key::Backspace => self.pass_in.backspace(),
                Key::Tab => self.pass_in.show = !self.pass_in.show,
                Key::Enter => self.sl_open(),
                Key::Esc => {
                    self.pass_in.clear();
                    self.sl_step(SlStep::Status);
                }
                _ => {}
            },
            SlStep::Ready { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.sl_step(SlStep::Ready { sel: s }),
                Pick::Choose(0) => {
                    let Some(slot) = self.slip.as_mut().and_then(|s| s.pending.take()) else {
                        return;
                    };
                    self.slip = None;
                    match self.free_slot() {
                        Some(i) => {
                            self.seeds[i] = Some(slot);
                            self.go_seeds(Some(Screen::SeedReady {
                                slot: i as u8,
                                created: false,
                            }));
                        }
                        None => self.go_seeds(Some(Screen::SlotsFull)),
                    }
                }
                Pick::Choose(_) | Pick::Back => {
                    if let Some(st) = self.slip.as_mut() {
                        st.pending = None;
                    }
                    self.sl_step(SlStep::Passphrase);
                }
                Pick::None => {}
            },
            SlStep::Source { sel } => match crate::pick(ev.key, sel, 3) {
                Pick::Move(s) => self.sl_step(SlStep::Source { sel: s }),
                Pick::Choose(s) => {
                    let kind = [Start::Dice, Start::Coin, Start::D20][s as usize];
                    self.push(Screen::Slip39 {
                        step: SlStep::Strength { kind, sel: 0 },
                    });
                }
                Pick::Back => {
                    self.slip = None;
                    self.pop();
                }
                Pick::None => {}
            },
            SlStep::Strength { kind, sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.sl_step(SlStep::Strength { kind, sel: s }),
                Pick::Choose(s) => {
                    // the entropy flow as for 12 or 24 words: 128 or 256 bits
                    self.start_flow(kind, [12, 24][s as usize]);
                    if let Some(f) = self.flow.as_mut() {
                        f.slip39 = true;
                    }
                }
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            SlStep::Groups { sel } => match crate::pick(ev.key, sel, 4) {
                Pick::Move(s) => self.sl_step(SlStep::Groups { sel: s }),
                Pick::Choose(s) => {
                    let Some(st) = self.slip.as_mut() else { return };
                    let presets = [(1, 1), (2, 3), (3, 5)];
                    if let Some(&(t, c)) = presets.get(s as usize) {
                        st.gt = 1;
                        st.ngroups = 1;
                        st.groups[0] = Group {
                            threshold: t,
                            count: c,
                        };
                        self.sl_step(SlStep::Mix { sel: 0 });
                    } else {
                        st.gt = 2;
                        st.ngroups = 3;
                        st.groups[0] = Group {
                            threshold: 1,
                            count: 1,
                        };
                        st.groups[1] = Group {
                            threshold: 1,
                            count: 1,
                        };
                        st.groups[2] = Group {
                            threshold: 2,
                            count: 3,
                        };
                        self.sl_step(SlStep::Custom { sel: 0 });
                    }
                }
                Pick::Back => self.sl_cancel(),
                Pick::None => {}
            },
            SlStep::Custom { sel } => {
                let Some(st) = self.slip.as_mut() else { return };
                let n = st.custom_rows();
                match ev.key {
                    Key::Up => self.sl_step(SlStep::Custom {
                        sel: (sel + n - 1) % n,
                    }),
                    Key::Down | Key::Tab => self.sl_step(SlStep::Custom { sel: (sel + 1) % n }),
                    Key::Left => {
                        st.adjust(sel, -1);
                        let sel = sel.min(st.custom_rows() - 1);
                        self.sl_step(SlStep::Custom { sel });
                    }
                    Key::Right => {
                        st.adjust(sel, 1);
                        self.sl_step(SlStep::Custom { sel });
                    }
                    Key::Enter => {
                        if slip39::check_config(st.gt, st.groups()).is_ok() {
                            self.sl_step(SlStep::Mix { sel: 0 });
                        } else {
                            self.notice = Some(self.text().bk.sl_rule);
                        }
                    }
                    Key::Esc | Key::Backspace => self.sl_step(SlStep::Groups { sel: 3 }),
                    _ => {}
                }
            }
            SlStep::Mix { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.sl_step(SlStep::Mix { sel: s }),
                Pick::Choose(0) => {
                    if let Some(st) = self.slip.as_mut() {
                        st.dice_len = 0;
                    }
                    self.sl_make();
                }
                Pick::Choose(_) => {
                    if let Some(st) = self.slip.as_mut() {
                        bp_crypto::secret::wipe(&mut st.dice);
                        st.dice_len = 0;
                    }
                    self.sl_step(SlStep::Dice);
                }
                Pick::Back => self.sl_step(SlStep::Groups { sel: 0 }),
                Pick::None => {}
            },
            SlStep::Dice => {
                let Some(st) = self.slip.as_mut() else { return };
                match ev.key {
                    Key::Char(c @ '1'..='6') if st.dice_len < MAX_DICE => {
                        st.dice[st.dice_len] = c as u8;
                        st.dice_len += 1;
                    }
                    Key::Backspace if st.dice_len > 0 => {
                        st.dice_len -= 1;
                        st.dice[st.dice_len] = 0;
                    }
                    Key::Enter if st.dice_len >= MIN_DICE => self.sl_make(),
                    Key::Enter => self.notice = Some(self.text().bk.sl_dice_short),
                    Key::Esc => self.sl_step(SlStep::Mix { sel: 1 }),
                    _ => {}
                }
            }
            SlStep::Show { idx } | SlStep::Covered { idx } => match ev.key {
                Key::Enter => self.sl_start_checks(idx),
                Key::Esc => self.sl_cancel(),
                _ => {}
            },
            SlStep::Check { idx, q, sel } => match crate::pick(ev.key, sel, 4) {
                Pick::Move(s) => self.sl_step(SlStep::Check { idx, q, sel: s }),
                Pick::Choose(s) => self.sl_answer(idx, q, s),
                Pick::Back => self.sl_step(SlStep::Show { idx }),
                Pick::None => {}
            },
        }
    }

    fn sl_words_key(&mut self, ev: KeyEvent) {
        let s = self.text();
        let Some(st) = self.slip.as_mut() else { return };
        let e = &mut st.entry;
        let mut done = false;
        match ev.key {
            Key::Char(' ') | Key::Enter | Key::Tab if e.input().is_empty() => e.tail = None,
            Key::Char(' ') | Key::Enter | Key::Tab => {
                let r = e.candidates();
                if !r.is_empty() {
                    e.accept((r.start + e.cand.min(r.len() - 1)) as u16);
                    done = e.complete();
                }
            }
            Key::Char(c) => {
                let before = e.input_len;
                if !e.push_char(c) {
                    self.notice = Some(s.no_match);
                } else if e.input_len > before && e.auto_accept_ready() {
                    e.auto_accept();
                    done = e.complete();
                }
            }
            Key::Up => e.cand = e.cand.saturating_sub(1),
            Key::Down => {
                if e.cand + 1 < e.candidates().len() {
                    e.cand += 1;
                }
            }
            Key::Backspace => {
                e.tail = None;
                if !e.backspace_char() && e.fixing.is_none() {
                    e.step_back();
                }
            }
            Key::Esc if e.fixing.is_some() => {
                e.fixing = None;
                done = true;
            }
            Key::Esc => {
                self.sl_cancel();
                return;
            }
            _ => {}
        }
        if done {
            self.sl_share_typed();
        }
    }

    /// A whole share is typed: read it and add it to the set.
    fn sl_share_typed(&mut self) {
        let Some(st) = self.slip.as_mut() else { return };
        let share = match Share::from_indices(&st.entry.idx[..st.entry.n]) {
            Err(Error::Checksum) => {
                self.sl_step(SlStep::Fix { sel: 0 });
                return;
            }
            r => r,
        };
        st.typed = st.typed.saturating_add(1);
        st.slow = false;
        st.last = Some(match share {
            Ok(s) if s.iteration_exponent > MAX_EXPONENT => {
                st.slow = true;
                Err(Error::Length)
            }
            Ok(s) => {
                let r = st.rec.add(&s);
                if r.is_ok() && st.rec.shares() == 1 {
                    st.set_words = [st.entry.idx[0], st.entry.idx[1]];
                }
                r
            }
            Err(e) => Err(e),
        });
        st.entry = ShareEntry::new(st.words);
        self.sl_step(SlStep::Status);
    }

    /// Enough shares and the passphrase: decrypt the wallet.
    fn sl_open(&mut self) {
        let Some(st) = self.slip.as_mut() else { return };
        match st.rec.ems() {
            Ok(ems) => {
                st.pending = SeedSlot::from_slip39(ems, self.pass_in.text());
                self.pass_in.clear();
                if st.pending.is_some() {
                    self.sl_step(SlStep::Ready { sel: 0 });
                }
            }
            Err(e) => {
                // groups that do not fit together: start the set again
                st.last = Some(Err(e));
                st.rec = Recovery::new();
                self.pass_in.clear();
                self.sl_step(SlStep::Status);
            }
        }
    }

    /// The groups are chosen: make the set (a new wallet's encryption runs
    /// once here) and show its first share.
    fn sl_make(&mut self) {
        let Some(st) = self.slip.as_mut() else { return };
        if st.mode == SlMode::Create {
            let Some(ms) = st.ms.as_ref() else { return };
            match slip39::make_set(
                ms,
                b"",
                st.gt,
                &st.groups[..st.ngroups as usize],
                &st.dice[..st.dice_len],
                |_| {},
            ) {
                Ok(ems) => st.ems = Some(ems),
                Err(_) => {
                    self.notice = Some(self.text().bk.sl_rule);
                    return;
                }
            }
        }
        self.sl_step(SlStep::Show { idx: 0 });
    }

    fn sl_start_checks(&mut self, idx: u16) {
        let Some(st) = self.slip.as_mut() else { return };
        let mut w = [0u16; MAX_SHARE_WORDS];
        let n = st.share_words(idx, &mut w);
        if n == 0 {
            return;
        }
        // three different positions, each with three other words
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
                let cand = self.quiz_rng.below(1024) as u16;
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
        self.sl_step(SlStep::Check { idx, q: 0, sel: 0 });
    }

    fn sl_answer(&mut self, idx: u16, q: u8, choice: u8) {
        let Some(st) = self.slip.as_mut() else { return };
        if st.checks[q as usize].answer != choice {
            self.notice = Some(self.text().bk.sl_check_wrong);
            self.sl_step(SlStep::Show { idx });
            return;
        }
        if (q as usize) + 1 < CHECKS {
            self.sl_step(SlStep::Check {
                idx,
                q: q + 1,
                sel: 0,
            });
        } else if idx + 1 < st.total() {
            self.sl_step(SlStep::Show { idx: idx + 1 });
        } else {
            self.sl_finish();
        }
    }

    /// Every share shown and checked: a new wallet loads; another set of a
    /// loaded one returns to its options.
    fn sl_finish(&mut self) {
        let Some(st) = self.slip.take() else { return };
        match st.mode {
            SlMode::Create => {
                let slot = st.ems.clone().and_then(|e| SeedSlot::from_slip39(e, b""));
                drop(st);
                let Some(slot) = slot else {
                    self.go_seeds(None);
                    return;
                };
                match self.free_slot() {
                    Some(i) => {
                        self.seeds[i] = Some(slot);
                        self.go_seeds(Some(Screen::SeedReady {
                            slot: i as u8,
                            created: true,
                        }));
                    }
                    None => self.go_seeds(Some(Screen::SlotsFull)),
                }
            }
            SlMode::Reshare(slot) => {
                drop(st);
                let sel = crate::keys::slot_opts(SlotKind::Slip39)
                    .iter()
                    .position(|o| *o == crate::keys::SlotOpt::Slip39Shares)
                    .unwrap_or(0) as u8;
                self.go_seeds(Some(Screen::SeedOptions { slot, sel }));
                self.notice = Some(self.text().bk.sl_done);
            }
            SlMode::Recover => self.go_seeds(None),
        }
    }

    // ---------- drawing ----------

    pub(crate) fn render_slip39(&self, c: &mut dyn Canvas, step: SlStep) {
        let s = self.text();
        let t = s.bk;
        let Some(st) = self.slip.as_ref() else { return };
        let w = grid::COLS * grid::CELL_W;
        let g = |row| grid::text_y(&BODY, row, 1);
        let notice = |c: &mut dyn Canvas, row: i32| {
            if let Some(n) = self.notice {
                widgets::log_line(c, MARGIN, g(row), w, Tag::Warn, n, "");
            }
        };
        let title = match st.mode {
            SlMode::Create => t.sl_new_menu,
            _ => t.sl_title,
        };
        self.status(c, title);
        match step {
            SlStep::Length { sel } => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.sl_length_q, theme::TEXT);
                let items = t.sl_lengths.map(|l| MenuItem { label: l, detail: "" });
                widgets::list(c, MARGIN, LIST_TOP, w, 2 * 48, &items, sel as usize, false);
                widgets::log_line(c, MARGIN, g(10), w, Tag::Info, t.sl_length_note, "");
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            SlStep::Words => self.render_share_entry(c, st),
            SlStep::Fix { sel } => {
                BODY.draw(c, MARGIN, STATUS_H + 16, t.sl_checksum[0], theme::DANGER);
                BODY.draw(c, MARGIN, STATUS_H + 44, t.sl_checksum[1], theme::TEXT_DIM);
                let words: [&str; MAX_SHARE_WORDS] = core::array::from_fn(|i| st.entry.word_at(i));
                let (cols, row_h) = sl_grid(st.words);
                widgets::word_grid(
                    c,
                    MARGIN + 6,
                    130,
                    w,
                    &words[..st.words],
                    cols,
                    row_h,
                    Some(sel as usize),
                    &BODY,
                );
                widgets::hint_bar(
                    c,
                    &[("Arrows", s.h_move), ("Enter", s.h_fix), ("Esc", s.h_cancel)],
                );
            }
            SlStep::Status => {
                let (tag, line) = match (st.slow, st.last) {
                    (true, _) => (Tag::Fail, t.sl_slow),
                    (_, Some(Ok(Added::Accepted))) => (Tag::Ok, t.sl_added[0]),
                    (_, Some(Ok(Added::Again))) => (Tag::Warn, t.sl_added[1]),
                    (_, Some(Ok(Added::NotNeeded))) => (Tag::Info, t.sl_added[2]),
                    (_, Some(Err(e))) => (Tag::Fail, t.sl_errors[error_index(e)]),
                    (_, None) => (Tag::Info, ""),
                };
                let head: Buf<48> = fill(t.sl_share_word, &[&st.typed, &st.words, &st.words]);
                let head = head.as_str().split(':').next().unwrap_or("");
                TITLE.draw(c, MARGIN, grid::text_y(&TITLE, 2, 2), head, theme::TEXT);
                widgets::log_line(c, MARGIN, g(5), w, tag, line, "");
                let mut row = 7;
                if let (Some(gt), Some(gc)) = (st.rec.group_threshold(), st.rec.group_count()) {
                    let set_name: Buf<24> = fill(
                        "{} {}",
                        &[&WORDS[st.set_words[0] as usize], &WORDS[st.set_words[1] as usize]],
                    );
                    let set: Buf<96> = fill(t.sl_set, &[&set_name.as_str(), &gt, &gc]);
                    widgets::log_line(c, MARGIN, g(row), w, Tag::Info, set.as_str(), "");
                    row += 1;
                    for gi in 0..gc as usize {
                        let p = st.rec.group(gi);
                        if p.have == 0 && !p.done {
                            continue;
                        }
                        let line: Buf<64> = fill(t.sl_group, &[&(gi + 1), &p.have, &p.need]);
                        let tag = if p.done { Tag::Ok } else { Tag::Pending };
                        widgets::log_line(c, MARGIN, g(row), w, tag, line.as_str(), "");
                        row += 1;
                        if row > 15 {
                            break;
                        }
                    }
                    let done = st.rec.groups_done();
                    if st.rec.is_complete() {
                        widgets::log_line(c, MARGIN, g(row + 1), w, Tag::Ok, t.sl_enough, "");
                    } else {
                        let more: Buf<64> = if gc == 1 {
                            let p = st.rec.group(0);
                            fill(t.sl_more_shares, &[&p.need.saturating_sub(p.have)])
                        } else {
                            fill(t.sl_more_groups, &[&(gt - done.min(gt))])
                        };
                        widgets::log_line(c, MARGIN, g(row + 1), w, Tag::Info, more.as_str(), "");
                    }
                }
                let next = if st.rec.is_complete() {
                    t.sl_open
                } else {
                    t.sl_next
                };
                widgets::hint_bar(c, &[("Enter", next), ("Esc", s.h_cancel)]);
            }
            SlStep::Passphrase => {
                widgets::label(c, MARGIN, STATUS_H + 12, t.sl_pass_title);
                let text = self.pass_in.text();
                let max = ((w - 40) / BODY.width as i32) as usize;
                let start = text.len().saturating_sub(max);
                let mut shown = Buf::<128>::new();
                for &b in &text[start..] {
                    let ch = if self.pass_in.show { b as char } else { '*' };
                    let mut tmp = [0u8; 4];
                    shown.push_str(ch.encode_utf8(&mut tmp));
                }
                widgets::text_field(c, MARGIN, STATUS_H + 34, w, shown.as_str(), "", &BODY);
                let mut y = STATUS_H + 120;
                for line in t.sl_pass_notes {
                    y = BODY.draw_wrapped(c, MARGIN, y, w, 28, 2, line, theme::TEXT_DIM);
                }
                widgets::hint_bar(
                    c,
                    &[
                        ("Sym", "!@#"),
                        ("Tab", s.h_display),
                        ("Enter", t.sl_open),
                        ("Esc", s.h_back),
                    ],
                );
            }
            SlStep::Ready { sel } => {
                let Some(p) = st.pending.as_ref() else { return };
                TITLE.draw(c, MARGIN, grid::text_y(&TITLE, 2, 2), t.sl_ready_title, theme::OK);
                widgets::label(c, MARGIN, g(5), s.fp_label);
                let fp = crate::seeds::fingerprint_hex(&p.fingerprint);
                DOUBLE.draw(c, MARGIN, grid::text_y(&DOUBLE, 6, 2), fp.as_str(), theme::BRIGHT);
                let info: Buf<64> = fill(
                    t.sl_ready_info,
                    &[
                        &st.words,
                        &st.rec.group_threshold().unwrap_or(1),
                        &st.rec.group_count().unwrap_or(1),
                    ],
                );
                let tag = if p.has_passphrase() { s.pp_tag } else { "" };
                widgets::log_line(c, MARGIN, g(9), w, Tag::Info, info.as_str(), tag);
                let items = [
                    MenuItem {
                        label: t.sl_load,
                        detail: "",
                    },
                    MenuItem {
                        label: s.h_back,
                        detail: "",
                    },
                ];
                widgets::list(c, MARGIN, g(11), w, 2 * 48, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select)]);
            }
            SlStep::Source { sel } => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.sl_source_q, theme::TEXT);
                let items = [s.dice_rolls, s.coin_flips, s.d20_rolls].map(|l| MenuItem {
                    label: l,
                    detail: ">",
                });
                widgets::list(c, MARGIN, LIST_TOP, w, 3 * 48, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            SlStep::Strength { kind, sel } => {
                use bp_bitcoin::entropy::Source;
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.sl_strength_q, theme::TEXT);
                let (src, unit) = match kind {
                    Start::Coin => (Source::Coin, s.flips),
                    Start::D20 => (Source::D20, s.rolls),
                    _ => (Source::Dice, s.rolls),
                };
                let d: [Buf<32>; 2] = [12, 24].map(|n| fill(s.count_plus, &[&src.min_count(n), &unit]));
                let items: [MenuItem; 2] = core::array::from_fn(|i| MenuItem {
                    label: t.sl_lengths[i],
                    detail: d[i].as_str(),
                });
                widgets::list(c, MARGIN, LIST_TOP, w, 2 * 48, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            SlStep::Groups { sel } => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.sl_groups_q, theme::TEXT);
                let items = t.sl_presets.map(|l| MenuItem { label: l, detail: "" });
                widgets::list(c, MARGIN, LIST_TOP, w, 4 * 48, &items, sel as usize, false);
                widgets::log_line(
                    c,
                    MARGIN,
                    g(14),
                    w,
                    Tag::Info,
                    t.sl_preset_notes[sel as usize % 4],
                    "",
                );
                notice(c, 16);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            SlStep::Custom { sel } => {
                let n = st.ngroups as usize;
                let mut labels: [Buf<32>; 2 * MAX_SHARES] = core::array::from_fn(|_| Buf::new());
                let mut values: [Buf<12>; 2 * MAX_SHARES + 2] = core::array::from_fn(|_| Buf::new());
                values[0] = fill("< {} >", &[&st.gt]);
                values[1] = fill("< {} >", &[&st.ngroups]);
                for gi in 0..n {
                    labels[2 * gi] = fill(t.sl_g_needs, &[&(gi + 1)]);
                    labels[2 * gi + 1] = fill(t.sl_g_shares, &[&(gi + 1)]);
                    values[2 + 2 * gi] = fill("< {} >", &[&st.groups[gi].threshold]);
                    values[3 + 2 * gi] = fill("< {} >", &[&st.groups[gi].count]);
                }
                let rows = st.custom_rows() as usize;
                let items: [MenuItem; 2 * MAX_SHARES + 3] = core::array::from_fn(|i| match i {
                    0 => MenuItem {
                        label: t.sl_needed,
                        detail: values[0].as_str(),
                    },
                    1 => MenuItem {
                        label: t.sl_n_groups,
                        detail: values[1].as_str(),
                    },
                    i if i + 1 < rows => MenuItem {
                        label: labels[i - 2].as_str(),
                        detail: values[i].as_str(),
                    },
                    _ => MenuItem {
                        label: t.sl_make,
                        detail: ">",
                    },
                });
                let top = STATUS_H + 8;
                widgets::list(c, MARGIN, top, w, g(15) - top, &items[..rows], sel as usize, true);
                let total: Buf<48> = fill(t.sl_total, &[&st.total()]);
                widgets::log_line(c, MARGIN, g(16), w, Tag::Info, total.as_str(), "");
                notice(c, 17);
                widgets::hint_bar(
                    c,
                    &[
                        ("^v", s.h_move),
                        ("<>", s.h_change),
                        ("Enter", t.sl_make),
                        ("Esc", s.h_back),
                    ],
                );
            }
            SlStep::Mix { sel } => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.sl_mix_q, theme::TEXT);
                let items = t.sl_mix.map(|l| MenuItem { label: l, detail: "" });
                widgets::list(c, MARGIN, LIST_TOP, w, 2 * 48, &items, sel as usize, false);
                widgets::log_line(
                    c,
                    MARGIN,
                    g(10),
                    w,
                    Tag::Info,
                    t.sl_mix_notes[sel as usize % 2],
                    "",
                );
                let total: Buf<48> = fill(t.sl_total, &[&st.total()]);
                widgets::log_line(c, MARGIN, g(11), w, Tag::Info, total.as_str(), "");
                notice(c, 13);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            SlStep::Dice => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.sl_dice_title, theme::TEXT);
                let count: Buf<48> = fill(t.sl_dice_count, &[&st.dice_len]);
                let tag = if st.dice_len >= MIN_DICE {
                    Tag::Ok
                } else {
                    Tag::Pending
                };
                widgets::log_line(c, MARGIN, g(5), w, tag, count.as_str(), "");
                let rec = core::str::from_utf8(st.dice()).unwrap_or("");
                for (row, chunk) in rec.as_bytes().chunks(60).take(4).enumerate() {
                    let line = core::str::from_utf8(chunk).unwrap_or("");
                    BODY.draw(c, MARGIN, g(7 + row as i32), line, theme::TEXT);
                }
                notice(c, 13);
                widgets::hint_bar(
                    c,
                    &[
                        ("1-6", s.h_type),
                        ("Del", s.h_delete),
                        ("Enter", t.sl_make),
                        ("Esc", s.h_back),
                    ],
                );
            }
            SlStep::Show { idx } => {
                let (gi, m) = st.place(idx);
                let count = st.groups.get(gi as usize).map_or(1, |g| g.count);
                let head: Buf<64> = fill(t.sl_show_title, &[&(gi + 1), &(m + 1), &count]);
                TITLE.draw(c, MARGIN, STATUS_H + 12, head.as_str(), theme::TEXT);
                let mut wv = [0u16; MAX_SHARE_WORDS];
                let n = st.share_words(idx, &mut wv);
                let words: [&str; MAX_SHARE_WORDS] =
                    core::array::from_fn(|i| if i < n { WORDS[wv[i] as usize] } else { "" });
                let (cols, row_h) = sl_grid(n);
                widgets::word_grid(
                    c,
                    MARGIN + 6,
                    STATUS_H + 60,
                    w,
                    &words[..n],
                    cols,
                    row_h,
                    None,
                    &BODY,
                );
                bp_crypto::secret::wipe_u16(&mut wv);
                match self.notice {
                    Some(m) => BODY.draw(c, MARGIN, 410, m, theme::WARN),
                    None => SMALL.draw(c, MARGIN, 414, t.sl_show_note, theme::TEXT_DIM),
                };
                widgets::hint_bar(c, &[("Enter", t.h_check), ("Esc", s.h_cancel)]);
            }
            SlStep::Covered { idx } => {
                let (gi, m) = st.place(idx);
                let count = st.groups.get(gi as usize).map_or(1, |g| g.count);
                let head: Buf<64> = fill(t.sl_show_title, &[&(gi + 1), &(m + 1), &count]);
                TITLE.draw(c, MARGIN, STATUS_H + 12, head.as_str(), theme::TEXT);
                widgets::log_line(c, MARGIN, g(4), w, Tag::Info, t.sl_covered, "");
                widgets::hint_bar(c, &[("Enter", t.h_check), ("Esc", s.h_cancel)]);
            }
            SlStep::Check { idx, q, sel } => {
                let ck = &st.checks[q as usize % CHECKS];
                let k = idx + 1;
                let qline: Buf<96> = fill(t.sl_check_q, &[&k, &st.total(), &(ck.pos + 1)]);
                TITLE.draw(c, MARGIN, STATUS_H + 20, qline.as_str(), theme::TEXT);
                let items = ck.options.map(|o| MenuItem {
                    label: WORDS[o as usize],
                    detail: "",
                });
                widgets::list(c, MARGIN, LIST_TOP, w, 4 * 48, &items, sel as usize, false);
                let prog: Buf<16> = fill("{}/{}", &[&(q + 1), &CHECKS]);
                SMALL.draw(c, MARGIN, 414, prog.as_str(), theme::TEXT_DIM);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
        }
    }

    fn render_share_entry(&self, c: &mut dyn Canvas, st: &SlipState) {
        let s = self.text();
        let t = s.bk;
        let e = &st.entry;
        let k = st.typed + 1;
        let head: Buf<96> = match e.fixing {
            Some(i) => fill(t.sl_fix_word, &[&k, &(i + 1)]),
            None => fill(t.sl_share_word, &[&k, &(e.pos + 1), &e.n]),
        };
        widgets::label(c, MARGIN, STATUS_H + 12, head.as_str());
        let input = e.input();
        let mut ghost = Buf::<24>::new();
        let r = e.candidates();
        if !input.is_empty() && !r.is_empty() {
            let wd = WORDS[r.start + e.cand.min(r.len() - 1)];
            ghost.push_str(&wd[input.len().min(wd.len())..]);
        }
        widgets::text_field(
            c,
            MARGIN,
            STATUS_H + 34,
            800 - 2 * MARGIN,
            input,
            ghost.as_str(),
            &TITLE,
        );
        if !input.is_empty() {
            let first = e.cand.saturating_sub(5);
            let list: [&str; 8] = core::array::from_fn(|i| {
                if r.start + first + i < r.end {
                    WORDS[r.start + first + i]
                } else {
                    ""
                }
            });
            let count = (r.len() - first).min(8);
            widgets::chips(
                c,
                MARGIN,
                STATUS_H + 102,
                800 - 2 * MARGIN - 60,
                &list[..count],
                e.cand - first,
            );
        }
        let words: [&str; MAX_SHARE_WORDS] =
            core::array::from_fn(|i| if i < e.n { e.word_at(i) } else { "" });
        let (cols, row_h) = sl_grid(e.n);
        widgets::word_grid(
            c,
            MARGIN + 6,
            200,
            800 - 2 * MARGIN,
            &words[..e.n],
            cols,
            row_h,
            Some(e.pos),
            &BODY,
        );
        if let Some(n) = self.notice {
            BODY.draw(c, MARGIN, 410, n, theme::WARN);
        }
        widgets::hint_bar(
            c,
            &[
                ("a-z", s.h_type),
                ("^v", s.h_pick),
                ("Enter", s.h_accept),
                ("Del", s.h_delete),
                ("Esc", s.h_cancel),
            ],
        );
    }
}

/// Columns of a share's word grid.
fn sl_cols(n: usize) -> usize {
    if n > 24 {
        5
    } else {
        4
    }
}

/// Columns and row height of a share's word grid (fits 20 or 33 words).
fn sl_grid(n: usize) -> (usize, i32) {
    if n > 24 {
        (5, 29)
    } else {
        (4, 40)
    }
}
