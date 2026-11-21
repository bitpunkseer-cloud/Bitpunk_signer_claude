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
use bp_ui::bformat;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{Font, BODY, HUGE, SMALL, TITLE};
use bp_ui::theme;
use bp_ui::widgets::{self, MenuItem, MARGIN, STATUS_H};

const W: i32 = 800;

/// `1,234,567 sats` or `0.01234567 BTC`.
pub fn amount(v: u64, units: Units) -> Buf<40> {
    match units {
        Units::Sats => {
            let digits = bformat!(24, "{}", v);
            let d = digits.as_str().as_bytes();
            let mut out = Buf::<40>::new();
            for (i, ch) in d.iter().enumerate() {
                if i > 0 && (d.len() - i) % 3 == 0 {
                    out.push_str(",");
                }
                out.push_str(core::str::from_utf8(core::slice::from_ref(ch)).unwrap_or(""));
            }
            out.push_str(" sats");
            out
        }
        Units::Btc => bformat!(40, "{}.{:08} BTC", v / 100_000_000, v % 100_000_000),
    }
}

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

/// An address in groups of four characters, eight groups per line.
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
        TITLE.draw(c, x, y, line.as_str(), theme::TEXT);
        y += TITLE.height as i32 + 8;
    }
    y
}

/// A label on the left and an amount on the right.
fn row(c: &mut dyn Canvas, y: i32, label: &str, value: &str, color: bp_hal::Rgb) {
    BODY.draw(c, MARGIN, y, label, theme::TEXT_DIM);
    let w = BODY.text_width(value);
    BODY.draw(c, W - MARGIN - w, y, value, color);
    c.fill_rect(MARGIN, y + BODY.height as i32 + 8, W - 2 * MARGIN, 1, theme::LINE);
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
            Step::Overview => {
                self.status(c, rv.overview);
                let Some(rep) = r.report.as_ref() else { return };
                let t = rep.totals;
                let mut y = top + 10;
                let gap = BODY.height as i32 + 24;
                row(c, y, rv.spending, amount(t.ours, units).as_str(), theme::TEXT);
                y += gap;
                if let Some(all) = t.inputs.filter(|&a| a > t.ours) {
                    row(
                        c,
                        y,
                        rv.other_inputs,
                        amount(all - t.ours, units).as_str(),
                        theme::TEXT_DIM,
                    );
                    y += gap;
                }
                let n_rec = rep
                    .outputs()
                    .iter()
                    .filter(|o| matches!(o.kind, OutputKind::External | OutputKind::OpReturn))
                    .count();
                let label: Buf<112> = fill(rv.to_recipients, &[&n_rec]);
                row(
                    c,
                    y,
                    label.as_str(),
                    amount(t.recipients, units).as_str(),
                    theme::ACCENT,
                );
                y += gap;
                if t.change > 0 {
                    row(c, y, rv.to_change, amount(t.change, units).as_str(), theme::OK);
                    y += gap;
                }
                if t.self_send > 0 {
                    row(c, y, rv.to_self, amount(t.self_send, units).as_str(), theme::OK);
                    y += gap;
                }
                let fee = t.fee.map(|f| amount(f, units));
                row(
                    c,
                    y,
                    rv.fee,
                    fee.as_ref().map_or(rv.unknown, |f| f.as_str()),
                    theme::WARN,
                );
                widgets::hint_bar(c, &[("Enter", rv.h_next), ("Esc", s.h_back)]);
            }
            Step::Output { idx } => {
                self.status(c, rv.title);
                let (Some(rep), Some(p)) = (r.report.as_ref(), self.psbt()) else {
                    return;
                };
                let (Some(o), Some(out)) = (rep.outputs().get(idx as usize), p.tx.output(idx as usize))
                else {
                    return;
                };
                let head: Buf<64> = fill(rv.output_n, &[&(idx as usize + 1), &rep.outputs().len()]);
                widgets::label(c, MARGIN, top, head.as_str());
                let (kind, color, owned) = match &o.kind {
                    OutputKind::External => (rv.kinds[0], theme::ACCENT, None),
                    OutputKind::Change(v) => (rv.kinds[1], theme::OK, Some(v.get().path)),
                    OutputKind::SelfSend(v) => (rv.kinds[2], theme::OK, Some(v.get().path)),
                    OutputKind::OpReturn => (rv.kinds[3], theme::WARN, None),
                    OutputKind::OtherWallet(v) => (rv.kinds[4], theme::ACCENT, Some(v.get().path)),
                };
                TITLE.draw(c, MARGIN, top + 24, kind, color);
                HUGE.draw(c, MARGIN, top + 62, amount(o.amount, units).as_str(), theme::TEXT);
                let mut y = top + 62 + HUGE.height as i32 + 18;
                let mut buf = [0u8; address::MAX_ADDRESS_LEN];
                match address::from_script(out.script_pubkey, self.settings.network, &mut buf) {
                    Some(n) => {
                        y = address_lines(c, MARGIN, y, core::str::from_utf8(&buf[..n]).unwrap_or(""));
                    }
                    None => {
                        BODY.draw(c, MARGIN, y, rv.no_address, theme::TEXT_DIM);
                        y += BODY.height as i32 + 6;
                        let mut hex = Buf::<128>::new();
                        for b in out.script_pubkey.iter().take(60) {
                            hex.push_str(bformat!(2, "{:02x}", b).as_str());
                        }
                        y = prose(c, y, hex.as_str(), &SMALL, theme::TEXT, 2);
                    }
                }
                if let Some(path) = owned {
                    let p: Buf<48> = bformat!(48, "{}", path);
                    BODY.draw(c, MARGIN, y + 4, p.as_str(), theme::TEXT_DIM);
                    SMALL.draw(c, MARGIN, y + 4 + BODY.height as i32 + 6, rv.verified, theme::OK);
                }
                widgets::hint_bar(
                    c,
                    &[("<>", s.h_prev_next), ("Enter", rv.h_next), ("Esc", s.h_back)],
                );
            }
            Step::Fee => {
                self.status(c, rv.fee_title);
                let Some(rep) = r.report.as_ref() else { return };
                let t = rep.totals;
                let gap = BODY.height as i32 + 24;
                let mut y = top + 10;
                let fee = t.fee.map(|f| amount(f, units));
                row(
                    c,
                    y,
                    rv.fee_rows[0],
                    fee.as_ref().map_or(rv.unknown, |f| f.as_str()),
                    theme::WARN,
                );
                y += gap;
                let rate: Option<Buf<24>> = t
                    .fee_rate_msat_vb()
                    .map(|m| bformat!(24, "{}.{} sat/vB", m / 1000, m % 1000 / 100));
                row(
                    c,
                    y,
                    rv.fee_rows[1],
                    rate.as_ref().map_or(rv.unknown, |b| b.as_str()),
                    theme::TEXT,
                );
                y += gap;
                let share: Option<Buf<16>> = t
                    .fee
                    .map(|f| (f as u128 * 1000 / (t.outputs as u128).max(1)) as u64)
                    .map(|p| bformat!(16, "{}.{}%", p / 10, p % 10));
                row(
                    c,
                    y,
                    rv.fee_rows[2],
                    share.as_ref().map_or(rv.unknown, |b| b.as_str()),
                    theme::TEXT,
                );
                y += gap;
                let size: Buf<16> = bformat!(16, "{} vB", t.vsize);
                row(c, y, rv.fee_rows[3], size.as_str(), theme::TEXT);
                y += gap;
                if rep.lock_time != 0 {
                    let lt: Buf<96> = fill(rv.lock_time, &[&rep.lock_time]);
                    SMALL.draw(c, MARGIN, y, lt.as_str(), theme::TEXT_DIM);
                    y += SMALL.height as i32 + 8;
                }
                if rep.rbf {
                    SMALL.draw(c, MARGIN, y, rv.rbf, theme::TEXT_DIM);
                }
                widgets::hint_bar(c, &[("Enter", rv.h_next), ("Esc", s.h_back)]);
            }
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
                let y = widgets::message_at(
                    c,
                    STATUS_H + 30,
                    rv.signed,
                    theme::OK,
                    &[l1.as_str(), rv.signed_2],
                );
                let items = rv.show_qr.map(|label| MenuItem { label, detail: "" });
                widgets::list(
                    c,
                    MARGIN,
                    y + 16,
                    W - 2 * MARGIN,
                    4 * 52,
                    &items,
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
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
        }
    }
}
