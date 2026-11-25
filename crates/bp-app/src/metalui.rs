//! Metal plate screens (M11-4, decision 6): a words seed shown as the dots
//! to punch on a Tinyseed or a Stackbit 1248, and a plate's dots entered
//! cell by cell to load its seed.
//!
//! Entering keeps the checksum: the last word is never filled in, so a dot
//! copied wrong ends on the usual checksum screen (pick the word, type it).

use crate::menus::Start;
use crate::{App, Pick, Screen};
use bp_backup::metal::{self, STACKBIT_DOTS, TINYSEED_DOTS};
use bp_bitcoin::bip39::{Mnemonic, MAX_WORDS, WORDS};
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, SMALL, TITLE};
use bp_ui::widgets::{self, MenuItem, Tag, MARGIN, STATUS_H};
use bp_ui::{grid, theme};

/// Words on one page of a plate.
pub const ROWS: usize = 12;
const LIST_TOP: i32 = STATUS_H + 80;

/// The plate format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plate {
    Tinyseed,
    Stackbit,
}

impl Plate {
    pub fn dots(self) -> usize {
        match self {
            Plate::Tinyseed => TINYSEED_DOTS,
            Plate::Stackbit => STACKBIT_DOTS,
        }
    }

    pub fn encode(self, index: u16) -> u16 {
        match self {
            Plate::Tinyseed => metal::tinyseed_dots(index),
            Plate::Stackbit => metal::stackbit_dots(index),
        }
    }

    pub fn decode(self, dots: u16) -> Option<u16> {
        match self {
            Plate::Tinyseed => metal::tinyseed_index(dots),
            Plate::Stackbit => metal::stackbit_index(dots),
        }
    }

    /// Which bit of a word's dots column `col` is (left to right as on
    /// the plate).
    fn bit(self, col: usize) -> u16 {
        match self {
            // 2048 on the left, 1 on the right
            Plate::Tinyseed => 1 << (TINYSEED_DOTS - 1 - col),
            // thousands first; in each group 1, 2, 4, 8
            Plate::Stackbit => 1 << (4 * (col / 4) + col % 4),
        }
    }
}

/// Steps of the metal plate screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetalStep {
    /// Tinyseed or Stackbit 1248.
    Format { sel: u8 },
    /// The dots to punch, twelve words a page.
    View { page: u8 },
    /// The screen saver hid the dots.
    Covered { page: u8 },
    /// Entering a plate's dots.
    Grid { page: u8 },
}

/// What the screens are doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtMode {
    /// Show the seed in this slot.
    View(u8),
    Enter,
}

/// State of the metal plate screens; wiped when they close.
pub struct MetalState {
    pub mode: MtMode,
    pub plate: Plate,
    pub words: usize,
    pub dots: [u16; MAX_WORDS],
    pub row: u8,
    pub col: u8,
}

impl Drop for MetalState {
    fn drop(&mut self) {
        bp_crypto::secret::wipe_u16(&mut self.dots);
    }
}

impl MetalState {
    pub fn pages(&self) -> u8 {
        self.words.div_ceil(ROWS) as u8
    }

    /// Re-encode the seed for the chosen plate (view).
    fn encode(&mut self, indices: &[u16]) {
        for (d, &i) in self.dots.iter_mut().zip(indices) {
            *d = self.plate.encode(i);
        }
    }
}

impl App {
    fn mt_step(&mut self, step: MetalStep) {
        self.set_current(Screen::Metal { step });
    }

    /// Seed options > Metal plate.
    pub(crate) fn metal_view_action(&mut self, slot: u8) {
        let Some(m) = self.seed(slot as usize) else { return };
        let words = m.len();
        self.metal = Some(MetalState {
            mode: MtMode::View(slot),
            plate: Plate::Tinyseed,
            words,
            dots: [0; MAX_WORDS],
            row: 0,
            col: 0,
        });
        self.push(Screen::Metal {
            step: MetalStep::Format { sel: 0 },
        });
    }

    /// Load a seed > Metal plate grid (after "how many words").
    pub(crate) fn metal_enter_start(&mut self, words: usize) {
        self.flow = None;
        self.metal = Some(MetalState {
            mode: MtMode::Enter,
            plate: Plate::Tinyseed,
            words,
            dots: [0; MAX_WORDS],
            row: 0,
            col: 0,
        });
        self.push(Screen::Metal {
            step: MetalStep::Format { sel: 0 },
        });
    }

    fn mt_cancel(&mut self) {
        match self.metal.as_ref().map(|m| m.mode) {
            Some(MtMode::View(slot)) => {
                self.metal = None;
                self.go_seeds(Some(Screen::SeedOptions { slot, sel: 0 }));
            }
            _ => self.confirm_cancel(),
        }
    }

    pub(crate) fn metal_key(&mut self, step: MetalStep, ev: KeyEvent) {
        self.notice = None;
        let mode = self.metal.as_ref().map(|m| m.mode);
        let Some(mode) = mode else {
            self.go_seeds(None);
            return;
        };
        match step {
            MetalStep::Format { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.mt_step(MetalStep::Format { sel: s }),
                Pick::Choose(s) => {
                    let plate = [Plate::Tinyseed, Plate::Stackbit][s as usize];
                    let indices = match mode {
                        MtMode::View(slot) => self.seed(slot as usize).map(|m| {
                            let mut v = [0u16; MAX_WORDS];
                            v[..m.len()].copy_from_slice(m.indices());
                            v
                        }),
                        MtMode::Enter => None,
                    };
                    let Some(st) = self.metal.as_mut() else { return };
                    st.plate = plate;
                    if let Some(mut v) = indices {
                        st.encode(&v[..st.words]);
                        bp_crypto::secret::wipe_u16(&mut v);
                        self.mt_step(MetalStep::View { page: 0 });
                    } else {
                        st.dots = [0; MAX_WORDS];
                        st.row = 0;
                        st.col = 0;
                        self.mt_step(MetalStep::Grid { page: 0 });
                    }
                }
                Pick::Back => match mode {
                    MtMode::View(_) => self.mt_cancel(),
                    MtMode::Enter => {
                        self.metal = None;
                        self.pop();
                    }
                },
                Pick::None => {}
            },
            MetalStep::View { page } | MetalStep::Covered { page } => {
                let pages = self.metal.as_ref().map_or(1, |m| m.pages());
                match ev.key {
                    Key::Right | Key::Down | Key::Tab | Key::Enter if page + 1 < pages => {
                        self.mt_step(MetalStep::View { page: page + 1 })
                    }
                    Key::Left | Key::Up if page > 0 => self.mt_step(MetalStep::View { page: page - 1 }),
                    Key::Enter | Key::Esc => self.mt_cancel(),
                    _ => {}
                }
            }
            MetalStep::Grid { page } => self.mt_grid_key(page, ev),
        }
    }

    fn mt_grid_key(&mut self, page: u8, ev: KeyEvent) {
        let Some(st) = self.metal.as_mut() else { return };
        let cols = st.plate.dots() as u8;
        let rows = (st.words - page as usize * ROWS).min(ROWS) as u8;
        let word = page as usize * ROWS + st.row as usize;
        match ev.key {
            Key::Up => st.row = (st.row + rows - 1) % rows,
            Key::Down => st.row = (st.row + 1) % rows,
            Key::Left => st.col = (st.col + cols - 1) % cols,
            Key::Right => st.col = (st.col + 1) % cols,
            Key::Char(' ') => st.dots[word] ^= st.plate.bit(st.col as usize),
            Key::Backspace => st.dots[word] = 0,
            Key::Tab if st.pages() > 1 => {
                let next = (page + 1) % st.pages();
                st.row = st.row.min((st.words - next as usize * ROWS).min(ROWS) as u8 - 1);
                self.mt_step(MetalStep::Grid { page: next });
            }
            Key::Enter => self.mt_done(),
            Key::Esc => self.mt_cancel(),
            _ => {}
        }
    }

    /// Every row read: load the seed, or show the checksum screen.
    fn mt_done(&mut self) {
        let t = self.text().bk;
        let Some(st) = self.metal.as_mut() else { return };
        let mut idx = [0u16; MAX_WORDS];
        for (w, slot) in idx.iter_mut().enumerate().take(st.words) {
            match st.plate.decode(st.dots[w]) {
                Some(i) => *slot = i,
                None => {
                    let page = (w / ROWS) as u8;
                    st.row = (w % ROWS) as u8;
                    self.notice = Some(t.mt_not_word);
                    self.mt_step(MetalStep::Grid { page });
                    return;
                }
            }
        }
        let words = st.words;
        self.metal = None;
        match Mnemonic::from_indices(&idx[..words]) {
            Ok(m) => self.store_seed(Some(m), false),
            Err(_) => {
                // the usual checksum screen: pick the word, type it
                let mut f = crate::flow::Flow::new(Start::TypeWords, words);
                for (i, &v) in idx[..words].iter().enumerate() {
                    f.entry.idx[i] = v;
                    f.entry.filled[i] = true;
                }
                self.flow = Some(f);
                self.set_current(Screen::ChecksumError { sel: 0 });
            }
        }
        bp_crypto::secret::wipe_u16(&mut idx);
    }

    // ---------- drawing ----------

    pub(crate) fn render_metal(&self, c: &mut dyn Canvas, step: MetalStep) {
        let s = self.text();
        let t = s.bk;
        let Some(st) = self.metal.as_ref() else { return };
        let w = grid::COLS * grid::CELL_W;
        let g = |row| grid::text_y(&BODY, row, 1);
        let name = match st.plate {
            Plate::Tinyseed => t.mt_formats[0],
            Plate::Stackbit => t.mt_formats[1],
        };
        match step {
            MetalStep::Format { sel } => {
                self.status(c, t.mt_title);
                let q = match st.mode {
                    MtMode::View(_) => t.mt_view_q,
                    MtMode::Enter => t.mt_enter_q,
                };
                TITLE.draw(c, MARGIN, STATUS_H + 20, q, theme::TEXT);
                let items = t.mt_formats.map(|l| MenuItem { label: l, detail: "" });
                widgets::list(c, MARGIN, LIST_TOP, w, 2 * 48, &items, sel as usize, false);
                widgets::log_line(
                    c,
                    MARGIN,
                    g(10),
                    w,
                    Tag::Info,
                    t.mt_format_notes[sel as usize % 2],
                    "",
                );
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            MetalStep::View { page } => {
                self.status(c, name);
                self.draw_plate(c, st, page, None);
                let line: Buf<64> = fill(t.mt_page, &[&(page + 1), &st.pages()]);
                SMALL.draw(c, MARGIN, 446 - widgets::HINT_H, line.as_str(), theme::TEXT_DIM);
                if page + 1 < st.pages() {
                    widgets::hint_bar(
                        c,
                        &[
                            ("Enter", t.mt_next_page),
                            ("<", t.mt_prev_page),
                            ("Esc", s.h_back),
                        ],
                    );
                } else {
                    widgets::hint_bar(
                        c,
                        &[("<", t.mt_prev_page), ("Enter", s.h_done), ("Esc", s.h_back)],
                    );
                }
            }
            MetalStep::Covered { page } => {
                self.status(c, name);
                let line: Buf<64> = fill(t.mt_page, &[&(page + 1), &st.pages()]);
                TITLE.draw(c, MARGIN, STATUS_H + 12, line.as_str(), theme::TEXT);
                widgets::log_line(c, MARGIN, g(4), w, Tag::Info, t.mt_covered, "");
                widgets::hint_bar(c, &[("Enter", t.mt_show), ("Esc", s.h_back)]);
            }
            MetalStep::Grid { page } => {
                self.status(c, name);
                self.draw_plate(c, st, page, Some((st.row as usize, st.col as usize)));
                match self.notice {
                    Some(n) => {
                        BODY.draw(c, MARGIN, 446 - widgets::HINT_H, n, theme::WARN);
                    }
                    None => {
                        let line: Buf<96> = fill(t.mt_grid_line, &[&(page + 1), &st.pages()]);
                        SMALL.draw(c, MARGIN, 446 - widgets::HINT_H, line.as_str(), theme::TEXT_DIM);
                    }
                }
                let mut hints: [(&str, &str); 5] = [
                    ("Arrows", s.h_move),
                    ("Space", t.mt_punch),
                    ("Del", t.mt_clear),
                    ("Enter", s.h_done),
                    ("Esc", s.h_cancel),
                ];
                if st.pages() > 1 {
                    hints[2] = ("Tab", t.mt_next_page);
                }
                widgets::hint_bar(c, &hints);
            }
        }
    }

    /// Twelve rows of dots: column weights on top, the row's word number
    /// on the left, its word on the right; `cursor` while entering.
    fn draw_plate(&self, c: &mut dyn Canvas, st: &MetalState, page: u8, cursor: Option<(usize, usize)>) {
        let dots = st.plate.dots();
        let left = MARGIN + 40;
        let right = 800 - MARGIN - 112;
        let gap = if st.plate == Plate::Stackbit { 10 } else { 0 };
        let groups = if st.plate == Plate::Stackbit { 3 } else { 0 };
        let pitch = (right - left - groups * gap) / dots as i32;
        let top = STATUS_H + 34;
        let row_h = 26;
        let col_x =
            |col: usize| left + col as i32 * pitch + (col / 4) as i32 * if groups > 0 { gap } else { 0 };
        // column weights
        for col in 0..dots {
            let label: Buf<6> = match st.plate {
                Plate::Tinyseed => fill("{}", &[&(1u32 << (TINYSEED_DOTS - 1 - col))]),
                Plate::Stackbit => fill("{}", &[&(1u32 << (col % 4))]),
            };
            let lw = SMALL.text_width(label.as_str());
            SMALL.draw(
                c,
                col_x(col) + (pitch - lw) / 2,
                top - 22,
                label.as_str(),
                theme::TEXT_DIM,
            );
        }
        let first = page as usize * ROWS;
        for r in 0..ROWS.min(st.words - first) {
            let word = first + r;
            let y = top + r as i32 * row_h;
            let nb: Buf<4> = fill("{}", &[&(word + 1)]);
            SMALL.draw(c, MARGIN, y + 3, nb.as_str(), theme::TEXT_FAINT);
            for col in 0..dots {
                let x = col_x(col) + 4;
                let (cw, ch) = (pitch - 8, row_h - 8);
                let on = st.dots[word] & st.plate.bit(col) != 0;
                if on {
                    c.fill_rect(x, y + 2, cw, ch, theme::BRIGHT);
                } else {
                    c.fill_rect(x, y + 2 + ch / 2 - 1, cw, 2, theme::LINE);
                }
                if cursor == Some((r, col)) {
                    let a = theme::ACCENT;
                    c.fill_rect(x - 3, y - 1, cw + 6, 2, a);
                    c.fill_rect(x - 3, y + ch + 3, cw + 6, 2, a);
                    c.fill_rect(x - 3, y - 1, 2, ch + 6, a);
                    c.fill_rect(x + cw + 1, y - 1, 2, ch + 6, a);
                }
            }
            let (text, color) = match st.plate.decode(st.dots[word]) {
                Some(i) => (WORDS[i as usize], theme::TEXT),
                None => ("----", theme::WARN),
            };
            BODY.draw(c, right + 12, y, text, color);
        }
    }
}
