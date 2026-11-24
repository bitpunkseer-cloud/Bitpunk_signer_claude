//! Rendering of the PSBT review and signing screens (800 x 480).

use crate::review::{issue_at, issue_index, Step};
use crate::seeds::fingerprint_hex;
use crate::settings::Units;
use crate::App;
use bp_bitcoin::address;
use bp_bitcoin::bip322::Forgery;
use bp_bitcoin::psbt::Psbt;
use bp_bitcoin::sign;
use bp_bitcoin::validate::{At, Class, Issue, OutputKind};
use bp_hal::Canvas;
use bp_hal::Rgb;
use bp_ui::bformat;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{Font, BODY, DOUBLE, SMALL, TITLE};
use bp_ui::grid;
use bp_ui::theme;
use bp_ui::widgets::{self, Align, MenuItem, Tag, MARGIN, STATUS_H};

const W: i32 = 800;

/// Digits with a separator every three from the right: `1,234,567`.
fn grouped(out: &mut Buf<40>, v: u64, sep: &str) {
    let digits = bformat!(24, "{}", v);
    let d = digits.as_str().as_bytes();
    for (i, ch) in d.iter().enumerate() {
        if i > 0 && (d.len() - i) % 3 == 0 {
            out.push_str(sep);
        }
        out.push_str(core::str::from_utf8(core::slice::from_ref(ch)).unwrap_or(""));
    }
}

/// `1,234,567 sats` or `0.01 234 567 BTC` (M9 C10: the eight decimals in
/// groups so the sats can be read off the BTC amount).
pub fn amount(v: u64, units: Units) -> Buf<40> {
    let mut out = Buf::<40>::new();
    match units {
        Units::Sats => {
            grouped(&mut out, v, ",");
            out.push_str(" sats");
        }
        Units::Btc => {
            grouped(&mut out, v / 100_000_000, ",");
            let f = bformat!(8, "{:08}", v % 100_000_000);
            let f = f.as_str();
            out.push_str(".");
            out.push_str(&f[..2]);
            out.push_str(" ");
            out.push_str(&f[2..5]);
            out.push_str(" ");
            out.push_str(&f[5..]);
            out.push_str(" BTC");
        }
    }
    out
}

/// The same amount in the other unit, for the headline (C10).
pub fn other_unit(v: u64, units: Units) -> Buf<40> {
    let other = match units {
        Units::Sats => Units::Btc,
        Units::Btc => Units::Sats,
    };
    let mut out = Buf::<40>::new();
    out.push_str("= ");
    out.push_str(amount(v, other).as_str());
    out
}

/// A label on `row`, the other unit at its right end, and the value in the
/// double-size font on the two rows below (UX language: amounts are the
/// brightest data). Values with Korean fall back to the title font.
fn headline(c: &mut dyn Canvas, row: i32, label: &str, other: &str, value: &str, color: Rgb) {
    BODY.draw(c, grid::x(0), grid::text_y(&BODY, row, 1), label, theme::TEXT_DIM);
    let w = BODY.text_width(other);
    BODY.draw(
        c,
        grid::x(grid::COLS) - w,
        grid::text_y(&BODY, row, 1),
        other,
        theme::TEXT_DIM,
    );
    if value.is_ascii() {
        DOUBLE.draw(c, grid::x(0), grid::text_y(&DOUBLE, row + 1, 2), value, color);
    } else {
        TITLE.draw(c, grid::x(0), grid::text_y(&TITLE, row + 1, 2), value, color);
    }
}

/// One ledger row: label left, value right.
fn ledger(c: &mut dyn Canvas, row: i32, label: &str, value: &str, color: Rgb) {
    widgets::table_row(
        c,
        0,
        row,
        &[
            (label, 36, Align::Left, theme::TEXT_DIM),
            (value, 28, Align::Right, color),
        ],
    );
}

/// A rule through the middle of an empty row (spacing between blocks).
fn mid_rule(c: &mut dyn Canvas, row: i32) {
    c.fill_rect(
        grid::x(0) - 4,
        grid::y(row) + grid::CELL_H / 2,
        grid::COLS * grid::CELL_W + 8,
        1,
        theme::LINE,
    );
}

/// One verification log line on a grid row.
fn log(c: &mut dyn Canvas, row: i32, tag: Tag, text: &str, detail: &str) {
    widgets::log_line(
        c,
        grid::x(0),
        grid::text_y(&BODY, row, 1),
        grid::COLS * grid::CELL_W,
        tag,
        text,
        detail,
    );
}

/// `7.0 sat/vB`
fn fee_rate(t: &bp_bitcoin::validate::Totals) -> Option<Buf<24>> {
    t.fee_rate_msat_vb()
        .map(|m| bformat!(24, "{}.{} sat/vB", m / 1000, m % 1000 / 100))
}

/// The fee as a share of the outputs: `1.0%`
fn fee_share(t: &bp_bitcoin::validate::Totals) -> Option<Buf<16>> {
    t.fee
        .map(|f| (f as u128 * 1000 / (t.outputs as u128).max(1)) as u64)
        .map(|p| bformat!(16, "{}.{}%", p / 10, p % 10))
}

/// Last content row (the key bar is row 19).
const LAST_ROW: i32 = grid::ROWS - 2;

/// Words wrapped to the screen width (inside the margins); returns the y
/// below the last line.
fn prose(c: &mut dyn Canvas, y: i32, text: &str, font: &Font, color: bp_hal::Rgb, max_lines: usize) -> i32 {
    font.draw_wrapped(
        c,
        MARGIN,
        y,
        W - 2 * MARGIN,
        font.height as i32 + 4,
        max_lines,
        text,
        color,
    )
}

/// An address in groups of four characters, eight groups per line, all
/// equally bright (UX language rule 9), one line per two grid rows.
pub(crate) fn address_lines(c: &mut dyn Canvas, x: i32, y: i32, addr: &str) -> i32 {
    let mut y = y;
    for chunk in addr.as_bytes().chunks(32) {
        let mut line = Buf::<48>::new();
        for (i, g) in chunk.chunks(4).enumerate() {
            if i > 0 {
                line.push_str(" ");
            }
            line.push_str(core::str::from_utf8(g).unwrap_or(""));
        }
        TITLE.draw(c, x, y, line.as_str(), theme::BRIGHT);
        y += 2 * grid::CELL_H;
    }
    y
}

pub(crate) fn fps(list: &[[u8; 4]]) -> Buf<48> {
    let mut b = Buf::<48>::new();
    for (i, fp) in list.iter().enumerate() {
        if i > 0 {
            b.push_str(", ");
        }
        b.push_str(fingerprint_hex(fp).as_str());
    }
    b
}

impl App {
    fn issue_where(&self, i: &Issue) -> Buf<24> {
        let rv = self.text().rv;
        match issue_at(i) {
            Some(At::Input(n)) => fill(rv.at_input, &[&n]),
            Some(At::Output(n)) => fill(rv.at_output, &[&n]),
            Some(At::Global) => fill(rv.at_global, &[]),
            None => Buf::new(),
        }
    }

    fn psbt(&self) -> Option<Psbt<'_>> {
        let r = self.review.as_ref()?;
        Psbt::parse(&self.scan.out[..r.psbt_len.min(self.scan.out.len())]).ok()
    }

    /// Input 0 of a BIP-322 PSBT: the address, its verified path, and for
    /// Proof of Reserves the coins and their total.
    fn message_input(&self) -> Option<(Buf<96>, Buf<64>)> {
        let r = self.review.as_ref()?;
        let rep = r.report.as_ref()?;
        let first = rep.inputs().first()?;
        let owned = first.owned.as_ref()?.get();
        let psbt = self.psbt()?;
        let map = psbt.input(0)?;
        let spk = match (map.witness_utxo(), map.non_witness_utxo()) {
            (Some(w), _) => w.script_pubkey,
            (None, Some(t)) => t.output(0)?.script_pubkey,
            _ => return None,
        };
        let mut a = [0u8; address::MAX_ADDRESS_LEN];
        let n = address::from_script(spk, self.settings.network, &mut a)?;
        let mut addr = Buf::<96>::new();
        addr.push_str(core::str::from_utf8(&a[..n]).ok()?);
        Some((addr, bformat!(64, "{}", owned.path)))
    }

    fn render_message_address(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let rv = s.rv;
        let Some(r) = self.review.as_ref() else { return };
        let por = r.message.is_some_and(|m| m.proof_of_reserves);
        self.status(c, if por { rv.por_title } else { rv.msg_title });
        let Some((addr, path)) = self.message_input() else {
            return;
        };
        widgets::label(c, MARGIN, STATUS_H + 12, s.ms_sign_with);
        let y = address_lines(c, MARGIN, STATUS_H + 36, addr.as_str()) + 8;
        BODY.draw(c, MARGIN, y, path.as_str(), theme::ACCENT);
        let fp = r
            .report
            .as_ref()
            .map(|x| fingerprint_hex(&x.master_fingerprint))
            .unwrap_or_default();
        let l: Buf<128> = fill(s.ms_verified, &[&fp.as_str()]);
        BODY.draw(c, MARGIN, y + 36, l.as_str(), theme::OK);
        if por {
            if let Some(rep) = r.report.as_ref() {
                let coins = rep.inputs().len().saturating_sub(1);
                let total = amount(rep.totals.ours, self.settings.units);
                let l: Buf<160> = fill(rv.por_line, &[&coins, &total.as_str()]);
                BODY.draw(c, MARGIN, y + 80, l.as_str(), theme::TEXT);
                SMALL.draw(c, MARGIN, y + 114, rv.por_all_ours, theme::TEXT_DIM);
            }
        }
        widgets::hint_bar(c, &[("Enter", rv.h_next), ("Esc", s.h_back)]);
    }

    fn render_message_approve(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        let rv = s.rv;
        let Some(r) = self.review.as_ref() else { return };
        let por = r.message.is_some_and(|m| m.proof_of_reserves);
        self.status(c, if por { rv.por_title } else { rv.msg_title });
        TITLE.draw(
            c,
            MARGIN,
            STATUS_H + 20,
            if por { rv.por_confirm } else { s.ms_confirm },
            theme::ACCENT,
        );
        let msg = core::str::from_utf8(self.review_message().unwrap_or(&[])).unwrap_or("");
        let cols = ((W - 2 * MARGIN) / BODY.width as i32) as usize;
        let (first, rest) = bp_ui::font::split_line(msg, cols - 4);
        let shown: Buf<80> = if rest.is_empty() {
            bformat!(80, "\"{}\"", first)
        } else {
            bformat!(80, "\"{}...\"", bp_ui::font::split_line(first, cols - 7).0)
        };
        let mut y = STATUS_H + 70;
        BODY.draw(c, MARGIN, y, shown.as_str(), theme::TEXT);
        y += 36;
        if let Some((addr, _)) = self.message_input() {
            SMALL.draw(c, MARGIN, y, addr.as_str(), theme::TEXT_DIM);
        }
        y += 40;
        let items = rv.options.map(|label| MenuItem { label, detail: "" });
        widgets::list(c, MARGIN, y, 400, 110, &items, sel as usize, false);
        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
    }

    pub(crate) fn render_review(&self, c: &mut dyn Canvas, step: Step) {
        let s = self.text();
        let rv = s.rv;
        let Some(r) = self.review.as_ref() else { return };
        let units = self.settings.units;
        let top = STATUS_H + 20;
        match step {
            Step::WrongSeed => {
                self.status(c, rv.title);
                let need: Buf<160> = fill(rv.needs, &[&fps(&r.need[..r.n_need]).as_str()]);
                let mut loaded = [[0u8; 4]; crate::SEED_SLOTS];
                let mut n = 0;
                for seed in self.seeds.iter().flatten() {
                    loaded[n] = seed.fingerprint;
                    n += 1;
                }
                let have: Buf<160> = if n == 0 {
                    fill(rv.none_loaded, &[])
                } else {
                    fill(rv.loaded, &[&fps(&loaded[..n]).as_str()])
                };
                widgets::message_at(
                    c,
                    STATUS_H + 70,
                    rv.wrong_seed,
                    theme::DANGER,
                    &[need.as_str(), have.as_str(), "", rv.load_hint],
                );
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
            Step::Problem => {
                self.status(c, rv.title);
                let Some(rep) = r.report.as_ref() else { return };
                let attack = rep.worst() == Some(Class::Attack);
                let (head, color) = if attack {
                    (rv.attack, theme::DANGER)
                } else {
                    (rv.cannot_sign, theme::WARN)
                };
                TITLE.draw(c, MARGIN, top, head, color);
                let mut y = top + TITLE.height as i32 + 16;
                let worst = rep.worst();
                let mut first: Option<Issue> = None;
                let mut shown = 0;
                for want in [Class::Attack, Class::Error] {
                    for i in rep.issues().iter().filter(|i| i.class() == want) {
                        if shown == 4 {
                            break;
                        }
                        first.get_or_insert(*i);
                        let (title, _) = rv.issues[issue_index(i)];
                        let at = self.issue_where(i);
                        let line: Buf<256> = if at.as_str().is_empty() {
                            fill("- {}", &[&title])
                        } else {
                            fill("- {} ({})", &[&title, &at.as_str()])
                        };
                        let col = if i.class() == Class::Attack {
                            theme::DANGER
                        } else {
                            theme::TEXT
                        };
                        BODY.draw(c, MARGIN, y, line.as_str(), col);
                        y += BODY.height as i32 + 6;
                        shown += 1;
                    }
                }
                if let Some(i) = first {
                    self.show_error(crate::errors::Area::Tx, issue_index(&i));
                    y += 8;
                    let p = self.settings.policy();
                    let text: Buf<512> = fill(
                        rv.issues[issue_index(&i)].1,
                        &[&p.fee_warn_percent, &p.fee_block_percent, &p.fee_rate_warn],
                    );
                    y = prose(c, y, text.as_str(), &SMALL, theme::TEXT_DIM, 3);
                }
                let tail = if worst == Some(Class::Attack) {
                    rv.attack_1
                } else {
                    rv.problem_1
                };
                prose(c, y + 10, tail, &SMALL, color, 2);
                widgets::hint_bar(c, &[("Enter", rv.h_discard)]);
            }
            Step::Warning { idx, sel } => {
                self.status(c, rv.title);
                let Some(w) = r.warning(idx) else { return };
                let n = r.warnings().count();
                let head: Buf<64> = fill(rv.check_n, &[&(idx as usize + 1), &n]);
                widgets::label(c, MARGIN, top, head.as_str());
                let (title, text) = rv.issues[issue_index(&w)];
                self.show_error(crate::errors::Area::Tx, issue_index(&w));
                TITLE.draw(c, MARGIN, top + 24, title, theme::WARN);
                let at = self.issue_where(&w);
                let mut y = top + 24 + TITLE.height as i32 + 8;
                if !at.as_str().is_empty() {
                    BODY.draw(c, MARGIN, y, at.as_str(), theme::TEXT_DIM);
                    y += BODY.height as i32 + 8;
                }
                let p = self.settings.policy();
                let text: Buf<512> = fill(
                    text,
                    &[&p.fee_warn_percent, &p.fee_block_percent, &p.fee_rate_warn],
                );
                y = prose(c, y + 4, text.as_str(), &BODY, theme::TEXT, 4);
                if w.needs_override() {
                    let items = rv.override_options.map(|label| MenuItem { label, detail: "" });
                    widgets::list(
                        c,
                        MARGIN,
                        y + 12,
                        W - 2 * MARGIN,
                        2 * 52,
                        &items,
                        sel as usize,
                        false,
                    );
                    widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
                } else {
                    widgets::hint_bar(c, &[("Enter", rv.h_next), ("Esc", s.h_back)]);
                }
            }
            Step::Overview => self.render_overview(c),
            Step::Output { idx } => self.render_output(c, idx),
            Step::Fee => self.render_fee(c),
            Step::Approve { sel } if r.message.is_some() => self.render_message_approve(c, sel),
            Step::Forged => {
                self.status(c, rv.title);
                let i = match r.forgery {
                    Some(Forgery::NoChallenge) => 0,
                    Some(Forgery::PrevoutIndex) => 1,
                    Some(Forgery::ToSpendMismatch) | None => 2,
                    Some(Forgery::NonZeroAmount) => 3,
                    Some(Forgery::NonWitnessUtxo) => 4,
                    Some(Forgery::Version) => 5,
                };
                let y = widgets::message_at(c, STATUS_H + 50, rv.attack, theme::DANGER, &[rv.forged_1]);
                BODY.draw_wrapped(
                    c,
                    MARGIN,
                    y + 16,
                    W - 2 * MARGIN,
                    30,
                    3,
                    rv.forgeries[i],
                    theme::TEXT,
                );
                widgets::hint_bar(c, &[("Enter", rv.h_discard)]);
            }
            Step::MsgOff => {
                self.status(c, rv.msg_title);
                widgets::message_at(
                    c,
                    STATUS_H + 70,
                    s.ms_off_title,
                    theme::WARN,
                    &[s.ms_off_1, "", s.ms_off_2],
                );
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
            Step::MsgRule => {
                self.status(c, rv.msg_title);
                let i = match r.rule {
                    Some(bp_bitcoin::message::MessageError::TooShort) => 0,
                    Some(bp_bitcoin::message::MessageError::TooLong) => 1,
                    Some(bp_bitcoin::message::MessageError::NotPrintable) | None => 2,
                    Some(bp_bitcoin::message::MessageError::LeadingOrTrailingSpace) => 3,
                    Some(bp_bitcoin::message::MessageError::TooManySpaces) => 4,
                };
                let l: Buf<256> = fill(s.ms_problems[3], &[&s.ms_rules[i]]);
                self.show_error(crate::errors::Area::Msg, 3);
                widgets::message_at(c, STATUS_H + 70, rv.cannot_sign, theme::DANGER, &[l.as_str()]);
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
            Step::MsgPage { page } => {
                let por = r.message.is_some_and(|m| m.proof_of_reserves);
                self.status(c, if por { rv.por_title } else { rv.msg_title });
                let msg = self.review_message().unwrap_or(&[]);
                crate::msgsign::draw_message_page(s, c, msg, page, true);
            }
            Step::MsgAddress => self.render_message_address(c),
            Step::Approve { sel } => {
                self.status(c, rv.title);
                let Some(rep) = r.report.as_ref() else { return };
                let t = rep.totals;
                TITLE.draw(c, MARGIN, top, rv.approve, theme::ACCENT);
                let n_rec = rep
                    .outputs()
                    .iter()
                    .filter(|o| matches!(o.kind, OutputKind::External | OutputKind::OpReturn))
                    .count();
                let l1: Buf<80> = fill(
                    rv.approve_lines[0],
                    &[&amount(t.recipients, units).as_str(), &n_rec],
                );
                let fee = t.fee.map(|f| amount(f, units));
                let l2: Buf<160> = fill(
                    rv.approve_lines[1],
                    &[&fee.as_ref().map_or(rv.unknown, |f| f.as_str())],
                );
                let l3: Buf<160> = fill(
                    rv.approve_lines[2],
                    &[&amount(t.change + t.self_send, units).as_str()],
                );
                let mut y = top + TITLE.height as i32 + 16;
                for l in [l1.as_str(), l2.as_str(), l3.as_str()] {
                    BODY.draw(c, MARGIN, y, l, theme::TEXT);
                    y += BODY.height as i32 + 8;
                }
                let items = rv.options.map(|label| MenuItem { label, detail: "" });
                widgets::list(c, MARGIN, y + 16, 400, 2 * 52, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            Step::Signed { sel } => {
                self.status(c, rv.title);
                let n = r.signed.map_or(0, |x| x.signatures);
                let l1: Buf<80> = fill(rv.signed_1, &[&n]);
                // multisig: whether the signatures are now enough
                let more: Buf<160> = match r.report.as_ref().and_then(|rep| self.multisig_progress(rep)) {
                    Some((_, after, m)) if after >= m => fill(s.wl.rv_complete, &[]),
                    Some((_, after, m)) => fill(s.wl.rv_more, &[&(m - after)]),
                    None if r.from_sd => fill(s.sd.signed_sd, &[]),
                    None => fill(rv.signed_2, &[]),
                };
                let y = widgets::message_at(
                    c,
                    STATUS_H + 30,
                    rv.signed,
                    theme::OK,
                    &[l1.as_str(), more.as_str()],
                );
                let mut items = rv.show_qr.map(|label| MenuItem { label, detail: "" });
                let items: &[MenuItem] = if r.from_sd {
                    items[0].label = s.sd.save_sd;
                    items[1].label = s.sd.done;
                    &items[..2]
                } else {
                    &items
                };
                widgets::list(
                    c,
                    MARGIN,
                    y + 16,
                    W - 2 * MARGIN,
                    4 * 52,
                    items,
                    sel as usize,
                    false,
                );
                if let Some(msg) = self.notice {
                    SMALL.draw(c, MARGIN, y + 16 + 4 * 52 + 6, msg, theme::WARN);
                }
                widgets::hint_bar(
                    c,
                    &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", rv.h_discard)],
                );
            }
            Step::MsRegister { sel } => {
                self.status(c, rv.title);
                let t = s.wl;
                let Some(w) = r.candidate.as_ref() else { return };
                TITLE.draw(c, MARGIN, top, t.unreg_title, theme::WARN);
                let pol: Buf<64> = fill(t.policy, &[&w.m, &w.n(), &w.script.name()]);
                BODY.draw(c, MARGIN, top + 44, pol.as_str(), theme::TEXT);
                let mut fpl: Buf<160> = Buf::new();
                for (i, k) in w.keys().iter().enumerate() {
                    if i > 0 {
                        fpl.push_str(", ");
                    }
                    fpl.push_str(crate::seeds::fingerprint_hex(&k.fingerprint).as_str());
                }
                let keys: Buf<192> = fill(t.unreg_keys, &[&fpl.as_str()]);
                let mut y = SMALL.draw_wrapped(
                    c,
                    MARGIN,
                    top + 76,
                    W - 2 * MARGIN,
                    20,
                    2,
                    keys.as_str(),
                    theme::TEXT_DIM,
                ) + 8;
                for l in t.unreg_lines {
                    y = BODY.draw_wrapped(c, MARGIN, y, W - 2 * MARGIN, 26, 3, l, theme::TEXT) + 6;
                }
                let items = t.unreg_options.map(|label| MenuItem { label, detail: "" });
                widgets::list(
                    c,
                    MARGIN,
                    y.max(300) + 4,
                    W - 2 * MARGIN,
                    104,
                    &items,
                    sel as usize,
                    false,
                );
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            Step::VerifiedOnly => {
                self.status(c, rv.title);
                let t = s.wl;
                widgets::message_at(c, STATUS_H + 70, t.verified_title, theme::OK, &t.verified_lines);
                widgets::hint_bar(c, &[("Enter", s.h_done), ("Esc", s.h_back)]);
            }
            Step::MsCode => {
                self.status(c, rv.title);
                let t = s.wl;
                TITLE.draw(c, MARGIN, top, t.entry_title, theme::TEXT);
                widgets::label(c, MARGIN, top + 56, t.entry_label);
                let typed = core::str::from_utf8(&r.code_in[..r.code_len]).unwrap_or("");
                const PLACEHOLDER: &str = "XXXX-XXXX";
                let ghost = PLACEHOLDER.get(typed.len()..).unwrap_or("");
                widgets::text_field(c, MARGIN, top + 80, 360, typed, ghost, &TITLE);
                let msg = match r.code_bad {
                    1 => Some(t.entry_bad_rereg),
                    2 => Some(t.entry_invalid),
                    3 => Some(t.unreg_rule),
                    4 => Some(t.full),
                    _ => None,
                };
                if let Some(m) = msg {
                    BODY.draw_wrapped(c, MARGIN, top + 160, W - 2 * MARGIN, 28, 3, m, theme::DANGER);
                }
                widgets::hint_bar(c, &[("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            Step::Failed => {
                self.status(c, rv.title);
                let i = match r.error {
                    Some(sign::Error::Changed) => 0,
                    Some(sign::Error::NotSignable) | None => 1,
                    Some(sign::Error::Derive) => 2,
                    Some(sign::Error::Sighash) => 3,
                    Some(sign::Error::Verify) => 4,
                    Some(sign::Error::OutputTooSmall) => 5,
                    Some(sign::Error::Output) => 6,
                };
                widgets::message_at(c, STATUS_H + 90, rv.failed, theme::DANGER, &[rv.sign_errors[i]]);
                self.show_error(crate::errors::Area::Sign, i);
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
        }
    }
}

impl App {
    /// Overview (M9-6): what leaves, in the double-size font, and the fee;
    /// the ledger; then the verification log.
    fn render_overview(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let rv = s.rv;
        self.status(c, rv.overview);
        let Some(r) = self.review.as_ref() else { return };
        let Some(rep) = r.report.as_ref() else { return };
        let t = rep.totals;
        let units = self.settings.units;
        let n_rec = rep
            .outputs()
            .iter()
            .filter(|o| matches!(o.kind, OutputKind::External | OutputKind::OpReturn))
            .count();
        let (head, value): (Buf<112>, u64) = if n_rec > 0 {
            (fill(rv.head_send, &[&n_rec]), t.recipients)
        } else {
            (fill(rv.head_self, &[]), t.change + t.self_send)
        };
        headline(
            c,
            2,
            head.as_str(),
            other_unit(value, units).as_str(),
            amount(value, units).as_str(),
            theme::BRIGHT,
        );
        let high = rep
            .issues()
            .iter()
            .any(|i| matches!(i, Issue::HighFee | Issue::HighFeeRate));
        let fee_color = if high { theme::WARN } else { theme::BRIGHT };
        let mut line = Buf::<96>::new();
        match t.fee {
            Some(f) => {
                line.push_str(amount(f, units).as_str());
                if let Some(x) = fee_rate(&t) {
                    line.push_str(" | ");
                    line.push_str(x.as_str());
                }
                if let Some(x) = fee_share(&t) {
                    line.push_str(" | ");
                    line.push_str(x.as_str());
                }
            }
            None => line.push_str(rv.unknown),
        }
        let y5 = grid::text_y(&BODY, 5, 1);
        let x1 = BODY.draw(c, grid::x(0), y5, rv.fee, theme::TEXT_DIM);
        BODY.draw(c, x1 + 2 * BODY.width as i32, y5, line.as_str(), fee_color);

        // rows needed: a spacer row before and after the ledger when they fit
        let other = t.inputs.is_some_and(|a| a > t.ours);
        let back = rep
            .outputs()
            .iter()
            .filter(|o| matches!(o.kind, OutputKind::Change(_) | OutputKind::SelfSend(_)))
            .count();
        let warns = r.warnings().count();
        let ledger_rows = 3 + other as i32 + (t.change > 0) as i32 + (t.self_send > 0) as i32;
        let log_rows = 2 * rep.wallet.is_some() as i32
            + 1
            + (back > 0) as i32
            + !rep.watch_only as i32
            + warns.max(1) as i32;
        let roomy = 6 + ledger_rows + 1 + log_rows <= LAST_ROW + 1;

        // the ledger: in = out + fee
        let mut row = 6;
        if roomy {
            mid_rule(c, row);
            row += 1;
        }
        let spending = if rep.watch_only {
            s.wl.rv_spending_watch
        } else {
            rv.spending
        };
        ledger(c, row, spending, amount(t.ours, units).as_str(), theme::BRIGHT);
        row += 1;
        if let Some(all) = t.inputs.filter(|_| other) {
            ledger(
                c,
                row,
                rv.other_inputs,
                amount(all - t.ours, units).as_str(),
                theme::TEXT,
            );
            row += 1;
        }
        let label: Buf<112> = fill(rv.to_recipients, &[&n_rec]);
        ledger(
            c,
            row,
            label.as_str(),
            amount(t.recipients, units).as_str(),
            theme::BRIGHT,
        );
        row += 1;
        if t.change > 0 {
            ledger(
                c,
                row,
                rv.to_change,
                amount(t.change, units).as_str(),
                theme::BRIGHT,
            );
            row += 1;
        }
        if t.self_send > 0 {
            ledger(
                c,
                row,
                rv.to_self,
                amount(t.self_send, units).as_str(),
                theme::BRIGHT,
            );
            row += 1;
        }
        let fee = t.fee.map(|f| amount(f, units));
        ledger(
            c,
            row,
            rv.fee,
            fee.as_ref().map_or(rv.unknown, |f| f.as_str()),
            fee_color,
        );
        if roomy {
            mid_rule(c, row + 1);
            row += 2;
        } else {
            grid::rule(c, row);
            row += 1;
        }

        // the verification log: what the device established
        if let Some((wallet, sigs)) = self.multisig_lines(rep) {
            log(c, row, Tag::Ok, wallet.as_str(), "");
            let done = self
                .multisig_progress(rep)
                .is_some_and(|(_, after, m)| after >= m);
            log(
                c,
                row + 1,
                if done { Tag::Ok } else { Tag::Info },
                sigs.as_str(),
                "",
            );
            row += 2;
        }
        let total = rep.inputs().len();
        let ours = rep.inputs().iter().filter(|i| i.owned.is_some()).count();
        let fp = fingerprint_hex(&rep.master_fingerprint);
        if rep.watch_only {
            let l: Buf<128> = fill(rv.log_inputs_watch, &[&ours, &total]);
            log(c, row, Tag::Ok, l.as_str(), "");
        } else {
            let l: Buf<128> = fill(rv.log_inputs, &[&ours, &total]);
            log(c, row, Tag::Ok, l.as_str(), fp.as_str());
        }
        row += 1;
        if back > 0 {
            let l: Buf<128> = fill(rv.log_back, &[&back]);
            log(c, row, Tag::Ok, l.as_str(), "");
            row += 1;
        }
        if !rep.watch_only {
            log(c, row, Tag::Ok, rv.log_sighash, "");
            row += 1;
        }
        // warnings (each was confirmed before this screen)
        if warns == 0 {
            log(c, row, Tag::Ok, rv.log_no_warnings, "");
        } else {
            let room = (LAST_ROW - row + 1).max(0) as usize;
            let show = if warns <= room {
                warns
            } else {
                room.saturating_sub(1)
            };
            for w in r.warnings().take(show) {
                let at = self.issue_where(w);
                log(c, row, Tag::Warn, rv.issues[issue_index(w)].0, at.as_str());
                row += 1;
            }
            if show < warns && row <= LAST_ROW {
                let l: Buf<128> = fill(rv.log_more, &[&(warns - show)]);
                log(c, row, Tag::Warn, l.as_str(), "");
            }
        }
        widgets::hint_bar(c, &[("Enter", rv.h_next), ("Esc", s.h_back)]);
    }

    /// One output (M9-6): kind and amount, the address in groups of four,
    /// and for this seed's outputs the verified path.
    fn render_output(&self, c: &mut dyn Canvas, idx: u8) {
        let s = self.text();
        let rv = s.rv;
        self.status(c, rv.title);
        let Some(r) = self.review.as_ref() else { return };
        let (Some(rep), Some(p)) = (r.report.as_ref(), self.psbt()) else {
            return;
        };
        let (Some(o), Some(out)) = (rep.outputs().get(idx as usize), p.tx.output(idx as usize)) else {
            return;
        };
        let units = self.settings.units;
        let (kind, color, owned) = match &o.kind {
            OutputKind::External => (rv.kinds[0], theme::ACCENT, None),
            OutputKind::Change(v) => (rv.kinds[1], theme::OK, Some(v.get().path)),
            OutputKind::SelfSend(v) => (rv.kinds[2], theme::OK, Some(v.get().path)),
            OutputKind::OpReturn => (rv.kinds[3], theme::WARN, None),
            OutputKind::OtherWallet(v) => (rv.kinds[4], theme::ACCENT, Some(v.get().path)),
        };
        let head: Buf<64> = fill(rv.output_n, &[&(idx as usize + 1), &rep.outputs().len()]);
        headline(
            c,
            2,
            head.as_str(),
            other_unit(o.amount, units).as_str(),
            amount(o.amount, units).as_str(),
            theme::BRIGHT,
        );
        let kx = grid::x(grid::cells(head.as_str()) + 2);
        BODY.draw(c, kx, grid::text_y(&BODY, 2, 1), kind, color);
        let mut buf = [0u8; address::MAX_ADDRESS_LEN];
        let y = match address::from_script(out.script_pubkey, self.settings.network, &mut buf) {
            Some(n) => address_lines(
                c,
                grid::x(0),
                grid::text_y(&TITLE, 6, 2),
                core::str::from_utf8(&buf[..n]).unwrap_or(""),
            ),
            None => {
                BODY.draw(
                    c,
                    grid::x(0),
                    grid::text_y(&BODY, 6, 1),
                    rv.no_address,
                    theme::TEXT_DIM,
                );
                let mut hex = Buf::<128>::new();
                for b in out.script_pubkey.iter().take(60) {
                    hex.push_str(bformat!(2, "{:02x}", b).as_str());
                }
                prose(c, grid::y(7), hex.as_str(), &SMALL, theme::BRIGHT, 2)
            }
        };
        let row = (y + grid::CELL_H - 1) / grid::CELL_H;
        match owned {
            Some(path) => {
                let p: Buf<48> = bformat!(48, "{}", path);
                BODY.draw(
                    c,
                    grid::x(0),
                    grid::text_y(&BODY, row, 1),
                    p.as_str(),
                    theme::TEXT_DIM,
                );
                let ms = match &o.kind {
                    OutputKind::Change(v) | OutputKind::SelfSend(v) | OutputKind::OtherWallet(v) => {
                        v.get().ms
                    }
                    _ => None,
                };
                match ms {
                    Some(m) => {
                        let t = s.wl;
                        let name = self
                            .wallets
                            .get(m.wallet)
                            .map(|e| self.wallet_name(e))
                            .unwrap_or_default();
                        let pos: Buf<32> =
                            fill(if m.branch == 1 { t.change_n } else { t.receive_n }, &[&m.index]);
                        let l: Buf<96> = fill(t.rv_in_wallet, &[&name.as_str(), &pos.as_str()]);
                        log(c, row + 1, Tag::Ok, l.as_str(), "");
                    }
                    None => log(c, row + 1, Tag::Ok, rv.verified, ""),
                }
            }
            None if matches!(o.kind, OutputKind::External) => {
                log(c, row, Tag::Info, rv.log_recipient, "");
            }
            None => {}
        }
        widgets::hint_bar(
            c,
            &[("<>", s.h_prev_next), ("Enter", rv.h_next), ("Esc", s.h_back)],
        );
    }

    /// Fee (M9-6): the fee in the double-size font, rate, share and size,
    /// then the fee checks against the user's limits.
    fn render_fee(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let rv = s.rv;
        self.status(c, rv.fee_title);
        let Some(r) = self.review.as_ref() else { return };
        let Some(rep) = r.report.as_ref() else { return };
        let t = rep.totals;
        let units = self.settings.units;
        let has = |want: Issue| rep.issues().contains(&want);
        let (high_fee, high_rate) = (has(Issue::HighFee), has(Issue::HighFeeRate));
        let fee = t.fee.map(|f| amount(f, units));
        let other = t.fee.map(|f| other_unit(f, units)).unwrap_or_default();
        let warn = |w: bool| if w { theme::WARN } else { theme::BRIGHT };
        headline(
            c,
            2,
            rv.fee_rows[0],
            other.as_str(),
            fee.as_ref().map_or(rv.unknown, |f| f.as_str()),
            warn(high_fee || high_rate),
        );
        mid_rule(c, 6);
        let rate = fee_rate(&t);
        ledger(
            c,
            7,
            rv.fee_rows[1],
            rate.as_ref().map_or(rv.unknown, |b| b.as_str()),
            warn(high_rate),
        );
        let share = fee_share(&t);
        ledger(
            c,
            8,
            rv.fee_rows[2],
            share.as_ref().map_or(rv.unknown, |b| b.as_str()),
            warn(high_fee),
        );
        let size: Buf<16> = bformat!(16, "{} vB", t.vsize);
        ledger(c, 9, rv.fee_rows[3], size.as_str(), theme::TEXT);
        mid_rule(c, 10);
        let mut row = 11;
        for i in rep
            .issues()
            .iter()
            .filter(|i| matches!(i, Issue::HighFee | Issue::HighFeeRate | Issue::FeeUnknown))
        {
            log(c, row, Tag::Warn, rv.issues[issue_index(i)].0, "");
            row += 1;
        }
        if t.fee.is_some() && !high_fee && !high_rate {
            let p = self.settings.policy();
            let l: Buf<128> = fill(rv.log_fee_ok, &[&p.fee_warn_percent, &p.fee_rate_warn]);
            log(c, row, Tag::Ok, l.as_str(), "");
            row += 1;
        }
        if rep.lock_time != 0 {
            let lt: Buf<96> = fill(rv.lock_time, &[&rep.lock_time]);
            log(c, row, Tag::Info, lt.as_str(), "");
            row += 1;
        }
        if rep.rbf {
            log(c, row, Tag::Info, rv.rbf, "");
        }
        widgets::hint_bar(c, &[("Enter", rv.h_next), ("Esc", s.h_back)]);
    }
}

impl App {
    /// Signatures on this seed's multisig inputs: (now, after signing, m),
    /// the fewest over the inputs.
    pub(crate) fn multisig_progress(&self, rep: &bp_bitcoin::validate::Report) -> Option<(u8, u8, u8)> {
        rep.wallet?;
        let mut best: Option<(u8, u8, u8)> = None;
        for i in rep.inputs() {
            let Some(o) = i.owned.as_ref() else { continue };
            let Some(ms) = o.get().ms else { continue };
            let now = i.cosigs + i.signed as u8;
            let after = if rep.watch_only {
                now
            } else {
                now + (!i.signed && !i.finalized) as u8
            };
            best = Some(match best {
                None => (now, after, ms.m),
                Some((n, a, m)) => (n.min(now), a.min(after), m),
            });
        }
        best
    }

    /// Overview lines for a multisig spend: the wallet, and the signatures.
    fn multisig_lines(&self, rep: &bp_bitcoin::validate::Report) -> Option<(Buf<96>, Buf<128>)> {
        let t = self.text().wl;
        let e = self.wallets.get(rep.wallet?)?;
        let name = self.wallet_name(e);
        let pol: Buf<48> = fill(t.policy, &[&e.wallet.m, &e.wallet.n(), &e.wallet.script.name()]);
        let d = e.code.display();
        let head: Buf<96> = fill(
            t.rv_wallet,
            &[
                &name.as_str(),
                &pol.as_str(),
                &core::str::from_utf8(&d).unwrap_or(""),
            ],
        );
        let (now, after, m) = self.multisig_progress(rep)?;
        let sigs: Buf<128> = if rep.watch_only {
            fill(t.rv_sigs_watch, &[&now, &m])
        } else {
            fill(t.rv_sigs, &[&now, &m, &after])
        };
        Some((head, sigs))
    }
}
