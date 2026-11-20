//! Rendering for every screen. Layout targets 800 x 480.

use crate::flow::Flow;
use crate::menus::{self, Start};
use crate::{App, Confirm, MenuId, Screen, GIT_HASH, VERSION};
use bp_bitcoin::bip39::{Mnemonic, WORDS};
use bp_bitcoin::entropy::{Analysis, Source, Status};
use bp_hal::Canvas;
use bp_ui::bformat;
use bp_ui::fmt::Buf;
use bp_ui::font::{BODY, HUGE, SMALL, TITLE};
use bp_ui::theme;
use bp_ui::widgets::{self, CheckState, MenuItem, MARGIN, STATUS_H};

/// "crew ... unique (12)"
pub fn seed_label(m: &Mnemonic) -> Buf<40> {
    bformat!(40, "{} ... {} ({})", m.word(0), m.word(m.len() - 1), m.len())
}

impl App {
    fn status(&self, c: &mut dyn Canvas, title: &str) {
        let net = self.settings.network;
        widgets::status_bar(
            c,
            &widgets::Status {
                title,
                network_badge: net.badge(),
                mainnet: net == bp_bitcoin::Network::Mainnet,
                test_only: self.test_only,
            },
        );
    }

    pub fn render(&self, c: &mut dyn Canvas) {
        let (w, h) = (c.width() as i32, c.height() as i32);
        c.fill_rect(0, 0, w, h, theme::BG);
        let s = self.text();
        match self.current() {
            Screen::Splash => render_splash(c),
            Screen::PoweredOff => {
                widgets::message_panel(c, s.powered_off, &[s.powered_off_1, "", s.powered_off_2]);
            }
            Screen::Menu { id, sel } => self.render_menu(c, id, sel),
            Screen::Placeholder { title, phase } => {
                self.status(c, title);
                widgets::message_panel(c, title, &[s.not_built, "", phase, s.see_roadmap]);
                widgets::hint_bar(c, &[("Esc", s.h_back)]);
            }
            Screen::About => {
                self.status(c, s.about);
                let mut rows = s.about_rows;
                rows[0].1 = VERSION;
                rows[1].1 = GIT_HASH;
                widgets::info_rows(c, &rows);
                widgets::hint_bar(c, &[("Esc", s.h_back)]);
            }
            Screen::ChooseWords { kind, sel } => {
                self.status(c, start_title(self, kind));
                TITLE.draw(c, MARGIN, STATUS_H + 20, s.how_many_words, theme::TEXT);
                let (d12, d24) = match kind {
                    Start::Dice => ("50+ rolls", "100+ rolls"),
                    Start::Coin => ("128+ flips", "256+ flips"),
                    _ => ("", ""),
                };
                let items = [
                    MenuItem {
                        label: s.words_12,
                        detail: d12,
                    },
                    MenuItem {
                        label: s.words_24,
                        detail: d24,
                    },
                ];
                widgets::list(
                    c,
                    MARGIN,
                    STATUS_H + 80,
                    w - 2 * MARGIN,
                    120,
                    &items,
                    sel as usize,
                    false,
                );
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            Screen::EntropyIntro => {
                let dice = self.flow_kind() == Some(Start::Dice);
                let (title, lines) = if dice {
                    (s.dice_intro_title, &s.dice_intro)
                } else {
                    (s.coin_intro_title, &s.coin_intro)
                };
                self.status(c, title);
                widgets::message_at(c, STATUS_H + 36, title, theme::TEXT, lines);
                if let Some(f) = self.flow.as_ref() {
                    let src = if dice { Source::Dice } else { Source::Coin };
                    let unit = if dice { s.rolls } else { s.flips };
                    let line = bformat!(
                        48,
                        "{} words: at least {} {}",
                        f.words,
                        src.min_count(f.words),
                        unit
                    );
                    BODY.draw_centered(c, 0, w, 360, line.as_str(), theme::ACCENT);
                }
                widgets::hint_bar(c, &[("Enter", s.h_continue), ("Esc", s.h_back)]);
            }
            Screen::EntropyEntry => self.render_entropy(c),
            Screen::EntropySummary => self.render_summary(c),
            Screen::WordsWarning { view } => {
                self.status(c, s.words_title);
                let lines: &[&str] = if view.is_some() {
                    &s.warn_lines[..3]
                } else {
                    &s.warn_lines
                };
                widgets::message_at(c, STATUS_H + 60, s.warn_title, theme::WARN, lines);
                widgets::hint_bar(c, &[("Enter", s.show_words), ("Esc", s.h_back)]);
            }
            Screen::ShowWords { view } => self.render_words(c, view),
            Screen::QuizIntro => {
                self.status(c, s.quiz_title);
                widgets::message_at(c, STATUS_H + 60, s.quiz_intro_title, theme::TEXT, &s.quiz_intro);
                widgets::hint_bar(c, &[("Enter", s.h_continue), ("Esc", s.h_back)]);
            }
            Screen::Quiz { sel } => self.render_quiz(c, sel),
            Screen::QuizFailed { sel } => {
                self.status(c, s.quiz_title);
                widgets::message_at(
                    c,
                    STATUS_H + 40,
                    s.quiz_failed_title,
                    theme::DANGER,
                    &[s.quiz_failed_1, s.quiz_failed_2],
                );
                let items = [
                    MenuItem {
                        label: s.quiz_retry,
                        detail: "",
                    },
                    MenuItem {
                        label: s.quiz_discard,
                        detail: "",
                    },
                ];
                widgets::list(c, 120, 240, w - 240, 110, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select)]);
            }
            Screen::SeedReady { slot, created } => {
                self.status(c, s.seeds);
                let label = self.seed(slot as usize).map(seed_label).unwrap_or_default();
                let head = if created { s.seed_created } else { s.seed_loaded };
                widgets::message_at(
                    c,
                    STATUS_H + 80,
                    head,
                    theme::OK,
                    &[label.as_str(), "", s.seed_ready_1],
                );
                widgets::hint_bar(c, &[("Enter", s.h_continue)]);
            }
            Screen::SlotsFull => {
                self.status(c, s.seeds);
                widgets::message_at(
                    c,
                    STATUS_H + 80,
                    s.slots_full_title,
                    theme::WARN,
                    &[s.slots_full_1],
                );
                widgets::hint_bar(c, &[("Esc", s.h_back)]);
            }
            Screen::WordEntry => self.render_word_entry(c),
            Screen::ChecksumError { sel } => self.render_checksum(c, sel),
            Screen::SeedOptions { slot, sel } => {
                let label = self.seed(slot as usize).map(seed_label).unwrap_or_default();
                self.status(c, label.as_str());
                let items = [
                    MenuItem {
                        label: s.show_words,
                        detail: ">",
                    },
                    MenuItem {
                        label: s.discard_seed,
                        detail: "",
                    },
                ];
                widgets::menu_list(c, &items, sel as usize);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            Screen::Confirm { what, sel } => {
                self.status(c, s.seeds);
                let (t, l) = match what {
                    Confirm::CancelFlow => (s.confirm_cancel_title, s.confirm_cancel_1),
                    Confirm::DiscardSeed(_) => (s.confirm_discard_title, s.confirm_discard_1),
                };
                widgets::message_at(c, STATUS_H + 60, t, theme::WARN, &[l]);
                let items = [
                    MenuItem {
                        label: s.keep,
                        detail: "",
                    },
                    MenuItem {
                        label: s.discard,
                        detail: "",
                    },
                ];
                widgets::list(c, 200, 220, w - 400, 110, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.keep)]);
            }
        }
    }

    fn flow_kind(&self) -> Option<Start> {
        self.flow.as_ref().map(|f| f.kind)
    }

    fn render_menu(&self, c: &mut dyn Canvas, id: MenuId, sel: u8) {
        let s = self.text();
        self.status(c, menus::title(id, s));
        // Loaded seeds are listed first in the Seeds menu.
        let labels: [Buf<40>; 3] = core::array::from_fn(|i| {
            self.seeds
                .iter()
                .flatten()
                .nth(i)
                .map(seed_label)
                .unwrap_or_default()
        });
        let mut items: [MenuItem; menus::MAX_ITEMS + crate::SEED_SLOTS] =
            core::array::from_fn(|_| MenuItem {
                label: "",
                detail: "",
            });
        let mut n = 0;
        if id == MenuId::Seeds {
            for l in labels.iter().take(self.seed_count()) {
                items[n] = MenuItem {
                    label: l.as_str(),
                    detail: "SEED",
                };
                n += 1;
            }
        }
        for (i, e) in menus::table(id).iter().enumerate() {
            let detail = self.settings.value_label(id, i as u8).unwrap_or(e.detail);
            items[n] = MenuItem {
                label: (e.label)(s),
                detail,
            };
            n += 1;
        }
        widgets::menu_list(c, &items[..n], sel as usize);
        if menus::is_settings(id) {
            widgets::hint_bar(c, &[("^v", s.h_move), ("<>", s.h_change), ("Esc", s.h_back)]);
        } else if id == MenuId::Main {
            widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("1-9", s.h_jump)]);
        } else {
            widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
        }
    }

    fn render_entropy(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let Some(f) = self.flow.as_ref() else { return };
        let Some(pe) = f.entropy.as_ref() else { return };
        let dice = f.kind == Start::Dice;
        let a = pe.analyze();
        self.status(
            c,
            if dice {
                s.dice_intro_title
            } else {
                s.coin_intro_title
            },
        );

        // Left: count and recent values
        let lx = MARGIN;
        let unit = if dice { s.rolls } else { s.flips };
        let head = bformat!(
            40,
            "{} - {} WORDS",
            if dice { "DICE ROLLS" } else { "COIN FLIPS" },
            f.words
        );
        widgets::label(c, lx, STATUS_H + 14, head.as_str());
        let count = bformat!(8, "{}", a.count);
        let x = HUGE.draw(c, lx - 4, STATUS_H + 30, count.as_str(), theme::TEXT);
        let min = bformat!(24, "/ {} {}", a.min_count, unit);
        BODY.draw(
            c,
            x + 10,
            STATUS_H + 30 + HUGE.baseline as i32 - BODY.baseline as i32,
            min.as_str(),
            theme::TEXT_DIM,
        );

        widgets::label(c, lx, 168, s.recent);
        let rec = pe.record();
        let per_row = 14;
        let rows = 4;
        let shown = rec.len().min(per_row * rows);
        let start = rec.len() - shown;
        bp_ui::draw::round_rect(c, lx, 190, 360, rows as i32 * 28 + 14, 8, theme::SURFACE);
        for (i, &v) in rec[start..].iter().enumerate() {
            let ch = match (dice, v) {
                (true, _) => v as char,
                (false, b'1') => 'H',
                (false, _) => 'T',
            };
            let mut b = [0u8; 4];
            let cs = ch.encode_utf8(&mut b);
            let col = (i % per_row) as i32;
            let row = (i / per_row) as i32;
            let last = start + i + 1 == rec.len();
            BODY.draw(
                c,
                lx + 14 + col * 24,
                197 + row * 28,
                cs,
                if last { theme::ACCENT } else { theme::TEXT },
            );
        }
        let keys = if dice { s.dice_keys } else { s.coin_keys };
        SMALL.draw(c, lx, 330, keys, theme::TEXT_DIM);
        SMALL.draw(
            c,
            lx,
            352,
            "Back undo   Enter finish   Esc cancel",
            theme::TEXT_FAINT,
        );

        // Right: frequency, entropy, checks
        let rx = 412;
        let rw = 800 - MARGIN - rx;
        widgets::label(c, rx, STATUS_H + 14, s.frequency);
        let src = pe.source();
        let expected = a.count as f64 / src.sides() as f64;
        if dice {
            widgets::bar_chart(
                c,
                rx,
                76,
                rw,
                112,
                &a.counts[..6],
                &["1", "2", "3", "4", "5", "6"],
                expected,
            );
        } else {
            // show heads first
            widgets::bar_chart(
                c,
                rx,
                76,
                rw,
                112,
                &[a.counts[1], a.counts[0]],
                &["Heads", "Tails"],
                expected,
            );
        }
        widgets::label(c, rx, 196, s.entropy_label);
        let eb = bformat!(32, "{:.0} / {} bits", a.est_bits, a.target_bits);
        let ok = a.entropy_status == Status::Pass;
        SMALL.draw(
            c,
            rx + rw - SMALL.text_width(eb.as_str()),
            196,
            eb.as_str(),
            if ok { theme::OK } else { theme::TEXT },
        );
        widgets::progress_bar(
            c,
            rx,
            222,
            rw,
            12,
            a.est_bits / a.target_bits as f64,
            if ok { theme::OK } else { theme::ACCENT },
        );
        widgets::label(c, rx, 244, s.checks);
        for (i, (name, st, detail)) in check_rows(s, &a, src).iter().enumerate() {
            widgets::check_row(c, rx, 266 + i as i32 * 27, rw, *st, name, detail.as_str());
        }

        // Status line across the bottom
        let (msg, color) = if let Some(n) = self.notice {
            (n, theme::WARN)
        } else if a.any_fail() {
            (s.st_failed, theme::DANGER)
        } else if a.all_pass() {
            (s.st_ready, theme::OK)
        } else {
            (s.st_keep_going, theme::TEXT_DIM)
        };
        BODY.draw(c, lx, 392, msg, color);
        if a.any_fail() && self.notice.is_none() {
            SMALL.draw(c, lx, 421, s.st_failed_2, theme::TEXT_DIM);
        }
        let hints: &[(&str, &str)] = if dice {
            &[
                ("1-6", "Roll"),
                ("Back", s.h_undo),
                ("Enter", s.h_finish),
                ("Esc", s.h_cancel),
            ]
        } else {
            &[
                ("H/T", "Flip"),
                ("Back", s.h_undo),
                ("Enter", s.h_finish),
                ("Esc", s.h_cancel),
            ]
        };
        widgets::hint_bar(c, hints);
    }

    fn render_summary(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let Some(f) = self.flow.as_ref() else { return };
        let Some(pe) = f.entropy.as_ref() else { return };
        let dice = f.kind == Start::Dice;
        self.status(
            c,
            if dice {
                s.dice_intro_title
            } else {
                s.coin_intro_title
            },
        );
        let a = pe.analyze();
        let w = 800;
        TITLE.draw_centered(c, 0, w, STATUS_H + 14, s.summary_title, theme::OK);
        let info = bformat!(
            64,
            "{} {}  -  ~{:.0} bits estimated  -  {} words",
            a.count,
            if dice { s.rolls } else { s.flips },
            a.est_bits,
            f.words
        );
        BODY.draw_centered(c, 0, w, STATUS_H + 58, info.as_str(), theme::TEXT_DIM);

        widgets::label(c, MARGIN, 146, s.summary_sha);
        let hash = pe.sha256();
        let mut hex = Buf::<64>::new();
        for b in hash {
            let _ = core::fmt::Write::write_fmt(&mut hex, format_args!("{b:02x}"));
        }
        let hs = hex.as_str();
        BODY.draw(c, MARGIN, 168, &hs[..32], theme::ACCENT);
        BODY.draw(c, MARGIN, 194, &hs[32..], theme::ACCENT);

        widgets::label(c, MARGIN, 232, s.summary_record);
        let rec = pe.record();
        let per_row = 80;
        for (row, chunk) in rec.chunks(per_row).take(7).enumerate() {
            let line = core::str::from_utf8(chunk).unwrap_or("");
            SMALL.draw(c, MARGIN, 254 + row as i32 * 20, line, theme::TEXT);
        }
        SMALL.draw(c, MARGIN, 404, s.summary_verify, theme::TEXT_FAINT);
        widgets::hint_bar(c, &[("Enter", s.h_continue), ("Esc", s.h_back)]);
    }

    fn render_words(&self, c: &mut dyn Canvas, view: Option<u8>) {
        let s = self.text();
        let m = match view {
            Some(slot) => self.seed(slot as usize),
            None => self.flow.as_ref().and_then(|f| f.mnemonic.as_ref()),
        };
        let Some(m) = m else { return };
        let title = bformat!(32, "{} ({})", s.words_title, m.len());
        self.status(c, title.as_str());
        let words: [&str; 24] = core::array::from_fn(|i| if i < m.len() { m.word(i) } else { "" });
        if m.len() <= 12 {
            widgets::word_grid(
                c,
                64,
                STATUS_H + 30,
                800 - 128,
                &words[..m.len()],
                3,
                72,
                None,
                &TITLE,
            );
        } else {
            widgets::word_grid(
                c,
                40,
                STATUS_H + 20,
                800 - 80,
                &words[..m.len()],
                4,
                58,
                None,
                &BODY,
            );
        }
        if view.is_none() {
            widgets::hint_bar(c, &[("Enter", "Start backup check"), ("Esc", s.h_cancel)]);
        } else {
            widgets::hint_bar(c, &[("Esc", s.h_back)]);
        }
    }

    fn render_quiz(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        let Some(f) = self.flow.as_ref() else { return };
        let q = &f.quiz;
        if q.done() {
            return;
        }
        self.status(c, s.quiz_title);
        let prog = bformat!(32, "{} / {}", q.q + 1, q.n);
        widgets::label(c, MARGIN, STATUS_H + 14, prog.as_str());
        widgets::progress_bar(
            c,
            MARGIN + 90,
            STATUS_H + 18,
            800 - 2 * MARGIN - 90,
            10,
            q.q as f64 / q.n as f64,
            theme::ACCENT,
        );
        let ask = bformat!(24, "{}{}", s.quiz_question, q.word_pos() + 1);
        TITLE.draw_centered(c, 0, 800, STATUS_H + 50, ask.as_str(), theme::TEXT);
        let opts = q.options[q.q];
        let items: [MenuItem; 4] = core::array::from_fn(|i| MenuItem {
            label: WORDS[opts[i] as usize],
            detail: "",
        });
        widgets::list(c, 220, STATUS_H + 110, 360, 210, &items, sel as usize, false);
        widgets::hint_bar(
            c,
            &[
                ("1-4", s.h_choose),
                ("^v", s.h_move),
                ("Enter", s.h_select),
                ("Esc", s.h_cancel),
            ],
        );
    }

    fn render_word_entry(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let Some(f) = self.flow.as_ref() else { return };
        let e = &f.entry;
        let numbers = f.numbers_mode();
        self.status(
            c,
            if numbers {
                s.entry_title_numbers
            } else {
                s.entry_title_words
            },
        );

        let head = match e.fixing {
            Some(i) => bformat!(32, "{} {}", s.fixing_word, i + 1),
            None => bformat!(32, "{} {} OF {}", s.word_n_of, e.pos + 1, e.n),
        };
        widgets::label(c, MARGIN, STATUS_H + 12, head.as_str());

        let input = e.input();
        let mut ghost = Buf::<24>::new();
        if numbers {
            if let Some(wi) = e.number_value() {
                ghost.push_str("  = ");
                ghost.push_str(WORDS[wi as usize]);
            }
        } else if !input.is_empty() {
            let r = e.candidates();
            if !r.is_empty() {
                let wd = WORDS[r.start + e.cand.min(r.len() - 1)];
                ghost.push_str(&wd[input.len().min(wd.len())..]);
            }
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

        // candidate chips (word mode)
        if !numbers && !input.is_empty() {
            let r = e.candidates();
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
            if r.len() > first + count {
                let more = bformat!(8, "+{}", r.len() - first - count);
                SMALL.draw(
                    c,
                    800 - MARGIN - 50,
                    STATUS_H + 110,
                    more.as_str(),
                    theme::TEXT_DIM,
                );
            }
        }

        let words: [&str; 24] = core::array::from_fn(|i| if i < e.n { e.word_at(i) } else { "" });
        let rows_h = if e.n <= 12 { 40 } else { 34 };
        widgets::word_grid(
            c,
            MARGIN + 6,
            200,
            800 - 2 * MARGIN,
            &words[..e.n],
            4,
            rows_h,
            Some(e.pos),
            &BODY,
        );

        if let Some(n) = self.notice {
            BODY.draw(c, MARGIN, 410, n, theme::WARN);
        }
        if numbers {
            widgets::hint_bar(
                c,
                &[
                    ("0-9", "Number"),
                    ("Enter", s.h_accept),
                    ("Back", s.h_delete),
                    ("Esc", s.h_cancel),
                ],
            );
        } else {
            widgets::hint_bar(
                c,
                &[
                    ("a-z", "Type"),
                    ("^v", "Pick"),
                    ("Enter", s.h_accept),
                    ("Back", s.h_delete),
                    ("Esc", s.h_cancel),
                ],
            );
        }
    }

    fn render_checksum(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        let Some(f): Option<&Flow> = self.flow.as_ref() else {
            return;
        };
        let e = &f.entry;
        self.status(c, s.checksum_title);
        BODY.draw(c, MARGIN, STATUS_H + 16, s.checksum_1, theme::DANGER);
        BODY.draw(c, MARGIN, STATUS_H + 44, s.checksum_2, theme::TEXT_DIM);
        let words: [&str; 24] = core::array::from_fn(|i| if i < e.n { e.word_at(i) } else { "" });
        let rows_h = if e.n <= 12 { 44 } else { 36 };
        widgets::word_grid(
            c,
            MARGIN + 6,
            140,
            800 - 2 * MARGIN,
            &words[..e.n],
            4,
            rows_h,
            Some(sel as usize),
            &BODY,
        );
        widgets::hint_bar(
            c,
            &[("Arrows", s.h_move), ("Enter", s.h_fix), ("Esc", s.h_cancel)],
        );
    }
}

fn start_title(app: &App, kind: Start) -> &'static str {
    let s = app.text();
    match kind {
        Start::Dice => s.dice_intro_title,
        Start::Coin => s.coin_intro_title,
        Start::TypeWords => s.entry_title_words,
        Start::WordNumbers => s.entry_title_numbers,
    }
}

fn state(st: Status) -> CheckState {
    match st {
        Status::Pending => CheckState::Wait,
        Status::Pass => CheckState::Pass,
        Status::Fail => CheckState::Fail,
    }
}

fn check_rows(s: &crate::Strings, a: &Analysis, src: Source) -> [(&'static str, CheckState, Buf<32>); 5] {
    let tested = a.count >= a.min_count;
    let after = bformat!(32, "after {}", a.min_count);
    [
        (
            s.chk_count,
            state(a.count_status),
            bformat!(32, "{} / {}", a.count, a.min_count),
        ),
        (
            s.chk_entropy,
            state(a.entropy_status),
            bformat!(32, "{:.0} / {} bits", a.est_bits, a.target_bits),
        ),
        (
            s.chk_bias,
            state(a.bias_status),
            if tested {
                bformat!(32, "chi2 {:.1} (max {:.1})", a.chi2, src.chi2_limit())
            } else {
                after
            },
        ),
        (
            s.chk_pattern,
            state(a.pattern_status),
            if tested {
                bformat!(32, "|z| {:.1} (max 4.0)", a.autocorr_z)
            } else {
                bformat!(32, "after {}", a.min_count)
            },
        ),
        (
            s.chk_repeat,
            state(a.repeat_status),
            bformat!(32, "longest {} (max {})", a.longest_run, src.run_limit() - 1),
        ),
    ]
}

fn render_splash(c: &mut dyn Canvas) {
    let (w, h) = (c.width() as i32, c.height() as i32);
    let y = h / 2 - HUGE.height as i32 + 10;
    let bw = HUGE.text_width("BITPUNK");
    let x = (w - bw) / 2;
    HUGE.draw(c, x, y, "BIT", theme::ACCENT);
    HUGE.draw(c, x + HUGE.text_width("BIT"), y, "PUNK", theme::TEXT);
    let sy = y + HUGE.height as i32;
    BODY.draw_centered(c, 0, w, sy, "S I G N E R", theme::TEXT_DIM);
    c.fill_rect(w / 2 - 40, sy + BODY.height as i32 + 18, 80, 2, theme::ACCENT);
    SMALL.draw_centered(c, 0, w, h - 60, "Air-gapped Bitcoin signer", theme::TEXT_FAINT);
    let ver = bformat!(48, "v{} / {}", VERSION, GIT_HASH);
    SMALL.draw_centered(c, 0, w, h - 36, ver.as_str(), theme::TEXT_FAINT);
}
