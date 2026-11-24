//! Rendering for every screen. Layout targets 800 x 480.

use crate::flow::Flow;
use crate::menus::{self, Start};
use crate::qrview::{Format, QrSession};
use crate::{App, Confirm, MenuId, QrKind, Screen, GIT_HASH, VERSION};
use bp_bitcoin::address::{self, ScriptType};
use bp_bitcoin::bip32::XKEY_LEN;
use bp_bitcoin::bip39::WORDS;
use bp_bitcoin::entropy::{Analysis, Source, Status};
use bp_hal::Canvas;
use bp_ui::bformat;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, HUGE, SMALL, TITLE};
use bp_ui::theme;
use bp_ui::widgets::{self, CheckState, MenuItem, MARGIN, STATUS_H};

/// `[73c5da0a/84h/0h/0h]zpub...`: the account key with its origin, in the
/// SLIP-132 form (xpub/tpub for taproot). Returns the length written.
pub fn xpub_origin_text(
    fp: [u8; 4],
    xpub: &bp_bitcoin::bip32::Xpub,
    st: ScriptType,
    net: bp_bitcoin::Network,
    account: u32,
    out: &mut [u8],
) -> usize {
    let fp = crate::seeds::fingerprint_hex(&fp);
    let origin = bformat!(48, "[{}/{}h/{}h/{}h]", fp, st.purpose(), net.coin_type(), account);
    let mut key = [0u8; XKEY_LEN];
    let n = xpub.encode(st.key_version().public(net), &mut key);
    let o = origin.as_str().as_bytes();
    let total = o.len() + n;
    if out.len() < total {
        return 0;
    }
    out[..o.len()].copy_from_slice(o);
    out[o.len()..total].copy_from_slice(&key[..n]);
    total
}

/// e.g. "73c5da0a (12)" or "73c5da0a (12) +PP" with a passphrase.
pub fn seed_label(slot: &crate::seeds::SeedSlot) -> Buf<40> {
    let fp = crate::seeds::fingerprint_hex(&slot.fingerprint);
    let pp = if slot.has_passphrase() {
        crate::text::EN.pp_tag
    } else {
        ""
    };
    let what: Buf<8> = match (slot.kind, slot.mnemonic.as_ref()) {
        (crate::seeds::SlotKind::Xprv, _) => fill("XPRV", &[]),
        (crate::seeds::SlotKind::Wif, _) => fill("WIF", &[]),
        (_, m) => fill("{}", &[&m.map_or(0, |m| m.len())]),
    };
    fill(crate::text::EN.seed_label, &[&fp, &what.as_str(), &pp])
}

impl App {
    /// The status line's path: the menus below this screen, then its title,
    /// e.g. `BITPUNK:~/Tools/BIP-85>` (UX language: where you are).
    pub(crate) fn status_path(&self, title: &str) -> Buf<192> {
        let mut path = Buf::<192>::new();
        path.push_str("BITPUNK:~");
        for i in 0..self.depth.saturating_sub(1) {
            if let Screen::Menu { id, .. } = self.stack[i] {
                if id != MenuId::Main {
                    path.push_str("/");
                    path.push_str(menus::title(id, self.text()));
                }
            }
        }
        if !matches!(self.current(), Screen::Menu { id: MenuId::Main, .. }) {
            path.push_str("/");
            path.push_str(title);
        }
        path.push_str(">");
        path
    }

    pub(crate) fn status(&self, c: &mut dyn Canvas, title: &str) {
        let net = self.settings.network;
        let path = self.status_path(title);
        widgets::status_bar(
            c,
            &widgets::Status {
                title: path.as_str(),
                network_badge: net.badge(),
                mainnet: net == bp_bitcoin::Network::Mainnet,
                air_gapped: match self.comm {
                    bp_hal::CommCheck::Detected(_) => self.text().key.comm_badge,
                    _ => self.text().air_gapped,
                },
                air_gap_ok: !matches!(self.comm, bp_hal::CommCheck::Detected(_)),
                test_only: self.test_only.then_some(self.text().test_only),
                sd: self.sd.present.then_some(self.text().sd.badge),
            },
        );
    }

    /// The QR code drawn by the last `render`, quiet zone included, for
    /// `bp_ui::fx::FxCanvas::finish`.
    pub fn qr_area(&self) -> Option<[i32; 4]> {
        self.qr_area.get()
    }

    /// Draw a QR code and remember where (screen effects skip it).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn draw_qr(
        &self,
        c: &mut dyn Canvas,
        q: &bp_qr::QrCode,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        style: widgets::QrStyle,
    ) -> i32 {
        self.qr_area.set(Some(widgets::qr_box(q, x, y, w, h)));
        widgets::qr_code(c, q, x, y, w, h, style)
    }

    /// Show the code of the error this screen explains (drawn at the
    /// right of the key bar once the screen is done).
    pub(crate) fn show_error(&self, area: crate::errors::Area, index: usize) {
        self.err_code.set(Some((area, index as u8)));
    }

    /// The error code of the last render, for tests.
    #[cfg(test)]
    pub(crate) fn shown_error(&self) -> Option<Buf<16>> {
        self.err_code
            .get()
            .map(|(a, i)| crate::errors::code(a, i as usize))
    }

    pub fn render(&self, c: &mut dyn Canvas) {
        self.qr_area.set(None);
        self.err_code.set(None);
        #[cfg(test)]
        crate::coverage::note(&self.current());
        if self.saver {
            self.render_saver(c);
            return;
        }
        self.render_screen(c);
        // a band of rain while a long search runs (no information there)
        if matches!(
            self.current(),
            Screen::VerifyAddr {
                step: crate::verify::VaStep::Searching
            } | Screen::Wallets {
                step: crate::wallets::WlStep::AddrSearch
            }
        ) {
            self.rain.draw(c, 15, 3);
        }
        if let Some((a, i)) = self.err_code.get() {
            widgets::error_code(c, crate::errors::code(a, i as usize).as_str());
        }
    }

    /// The screen saver: rain over the whole screen, nothing of what was
    /// on it (M9-5, C6).
    fn render_saver(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let (w, h) = (c.width() as i32, c.height() as i32);
        c.fill_rect(0, 0, w, h, theme::BG);
        self.rain.draw(c, 0, bp_ui::grid::ROWS - 1);
        let (bw, bh) = (456, 144);
        let (bx, by) = ((w - bw) / 2, (h - bh) / 2);
        c.fill_rect(bx, by, bw, bh, theme::BG);
        bp_ui::draw::outline(c, bx, by, bw, bh, theme::TEXT_DIM);
        TITLE.draw_centered(c, bx, bw, by + 22, s.saver_title, theme::BRIGHT);
        BODY.draw_centered(c, bx, bw, by + 72, s.saver_lines[0], theme::TEXT_DIM);
        BODY.draw_centered(c, bx, bw, by + 102, s.saver_lines[1], theme::TEXT_DIM);
    }

    /// Boot: the self-test log (M9-5, C7) under a band of rain with the
    /// name. Only checks the device really makes are listed.
    fn render_boot(&self, c: &mut dyn Canvas) {
        use widgets::Tag;
        let s = self.text();
        let w = c.width() as i32;
        self.rain.draw(c, 0, 5);
        let name_w = bp_ui::font::DOUBLE.text_width("BITPUNK") + 32;
        c.fill_rect((w - name_w) / 2, 40, name_w, 60, theme::BG);
        bp_ui::font::DOUBLE.draw(c, (w - name_w) / 2 + 16, 44, "BITPUNK", theme::BRIGHT);
        let ver = bformat!(64, "SIGNER v{} · build {}", VERSION, GIT_HASH);
        SMALL.draw_centered(c, 0, w, 128, ver.as_str(), theme::TEXT_DIM);
        c.fill_rect(MARGIN, 156, w - 2 * MARGIN, 1, theme::LINE);
        SMALL.draw(c, MARGIN, 164, s.boot_title, theme::TEXT_DIM);
        let net = match self.comm {
            bp_hal::CommCheck::NotRun => (Tag::Pending, s.boot_net[0]),
            bp_hal::CommCheck::Clean => (Tag::Ok, s.boot_net[1]),
            bp_hal::CommCheck::Detected(_) => (Tag::Fail, s.boot_net[2]),
        };
        let sd = if self.sd.present {
            (Tag::Ok, s.boot_sd[1])
        } else {
            (Tag::Pending, s.boot_sd[0])
        };
        let mut lines = [(Tag::Info, ""); 5];
        lines[0] = net;
        lines[1] = (Tag::Warn, s.boot_fw);
        lines[2] = sd;
        lines[3] = (Tag::Info, s.boot_seed);
        let n = if self.test_only {
            lines[4] = (Tag::Warn, s.boot_sim);
            5
        } else {
            4
        };
        let shown = ((self.splash_ms / 150) as usize + 1).min(n);
        for (i, (tag, text)) in lines[..shown].iter().enumerate() {
            widgets::log_line(c, MARGIN, 192 + i as i32 * 32, w - 2 * MARGIN, *tag, text, "");
        }
        SMALL.draw(c, MARGIN, 420, s.boot_any_key, theme::TEXT_FAINT);
    }

    fn render_screen(&self, c: &mut dyn Canvas) {
        let (w, h) = (c.width() as i32, c.height() as i32);
        c.fill_rect(0, 0, w, h, theme::BG);
        let s = self.text();
        match self.current() {
            Screen::Splash => self.render_boot(c),
            Screen::PoweredOff => {
                widgets::message_panel(c, s.powered_off, &[s.powered_off_1, "", s.powered_off_2]);
            }
            Screen::Menu { id, sel } => self.render_menu(c, id, sel),
            Screen::Welcome { sel } => {
                self.status(c, s.start);
                bp_ui::font::DOUBLE.draw(c, MARGIN, STATUS_H + 10, "BITPUNK", theme::BRIGHT);
                SMALL.draw(c, MARGIN + 200, STATUS_H + 36, s.tagline, theme::TEXT_DIM);
                let mut y = STATUS_H + 76;
                for l in s.welcome {
                    widgets::log_line(c, MARGIN, y, w - 2 * MARGIN, widgets::Tag::Info, l, "");
                    y += BODY.height as i32 + 4;
                }
                let value = |row| self.settings.value_label(MenuId::Settings, row, s).unwrap_or("");
                let items = [
                    MenuItem {
                        label: s.start,
                        detail: ">",
                    },
                    MenuItem {
                        label: s.language,
                        detail: value(crate::settings::ROW_LANG),
                    },
                    MenuItem {
                        label: s.network,
                        detail: value(crate::settings::ROW_NETWORK),
                    },
                ];
                widgets::list(
                    c,
                    MARGIN,
                    y + 12,
                    w - 2 * MARGIN,
                    3 * 48,
                    &items,
                    sel as usize,
                    false,
                );
                widgets::hint_bar(c, &[("^v", s.h_move), ("<>", s.h_change), ("Enter", s.h_select)]);
            }
            Screen::About => {
                self.status(c, s.about);
                let mut rows = s.about_rows;
                rows[0].1 = VERSION;
                rows[1].1 = GIT_HASH;
                widgets::info_rows(c, &rows);
                // M9-4 (C2): features not built yet live here, not in the menus
                let y = STATUS_H + 20 + rows.len() as i32 * (BODY.height as i32 + 8) + 10;
                SMALL.draw(c, MARGIN, y, s.planned, theme::TEXT_DIM);
                let m10: Buf<96> = fill("M10 · {}", &[&s.seed_vault]);
                let m11: Buf<320> = fill(
                    "M11 · {} · {} · {} · {} · {} · {}",
                    &[
                        &s.slip39,
                        &s.tinyseed,
                        &s.seed_xor,
                        &s.encrypted_backup,
                        &s.secure_notes,
                        &s.totp,
                    ],
                );
                SMALL.draw(c, MARGIN, y + 22, m10.as_str(), theme::TEXT);
                SMALL.draw_wrapped(
                    c,
                    MARGIN,
                    y + 44,
                    w - 2 * MARGIN,
                    22,
                    2,
                    m11.as_str(),
                    theme::TEXT,
                );
                widgets::hint_bar(c, &[("Esc", s.h_back)]);
            }
            Screen::ChooseWords { kind, sel } => {
                self.status(c, start_title(self, kind));
                TITLE.draw(c, MARGIN, STATUS_H + 20, s.how_many_words, theme::TEXT);
                let detail = |words: usize| -> Buf<32> {
                    match kind {
                        Start::Dice => fill(s.count_plus, &[&Source::Dice.min_count(words), &s.rolls]),
                        Start::Coin => fill(s.count_plus, &[&Source::Coin.min_count(words), &s.flips]),
                        Start::D20 => fill(s.count_plus, &[&Source::D20.min_count(words), &s.rolls]),
                        Start::FinalWord => fill(
                            s.final_detail,
                            &[&(words - 1), &bp_bitcoin::bip39::final_word_free_bits(words)],
                        ),
                        _ => Buf::new(),
                    }
                };
                let (b12, b24) = (detail(12), detail(24));
                let (d12, d24) = (b12.as_str(), b24.as_str());
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
                let kind = self.flow_kind();
                let (title, lines, src, unit) = match kind {
                    Some(Start::Dice) => (s.dice_intro_title, &s.dice_intro, Source::Dice, s.rolls),
                    Some(Start::D20) => (s.d20_intro_title, &s.d20_intro, Source::D20, s.rolls),
                    _ => (s.coin_intro_title, &s.coin_intro, Source::Coin, s.flips),
                };
                self.status(c, title);
                widgets::message_at(c, STATUS_H + 36, title, theme::TEXT, lines);
                if let Some(f) = self.flow.as_ref() {
                    let line: Buf<128> = fill(s.intro_min, &[&f.words, &src.min_count(f.words), &unit]);
                    BODY.draw_centered(c, 0, w, 360, line.as_str(), theme::ACCENT);
                }
                widgets::hint_bar(c, &[("Enter", s.h_continue), ("Esc", s.h_back)]);
            }
            Screen::FinalIntro => {
                self.status(c, s.final_title);
                widgets::message_at(c, STATUS_H + 36, s.final_title, theme::TEXT, &s.final_intro);
                widgets::hint_bar(c, &[("Enter", s.h_continue), ("Esc", s.h_back)]);
            }
            Screen::FinalCoins => self.render_final_coins(c),
            Screen::FinalResult => self.render_final_result(c),
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
                let label = self.slot(slot as usize).map(seed_label).unwrap_or_default();
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
                let label = self.slot(slot as usize).map(seed_label).unwrap_or_default();
                self.status(c, label.as_str());
                let kind = self
                    .slot(slot as usize)
                    .map_or(crate::seeds::SlotKind::Mnemonic, |s| s.kind);
                let opts = crate::keys::slot_opts(kind);
                let mut items: [MenuItem; 6] = core::array::from_fn(|_| MenuItem {
                    label: "",
                    detail: ">",
                });
                for (it, o) in items.iter_mut().zip(opts) {
                    use crate::keys::SlotOpt::*;
                    it.label = match o {
                        Words => s.show_words,
                        Xpub => s.export_xpub,
                        Explorer => s.address_explorer,
                        Passphrase => s.passphrase,
                        SeedQr => s.backup_seedqr,
                        Addresses => s.key.addresses,
                        Discard => s.discard_seed,
                    };
                    if *o == Discard {
                        it.detail = "";
                    }
                }
                widgets::menu_list(c, &items[..opts.len()], sel as usize);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            Screen::PassphraseEntry { slot } => self.render_passphrase(c, slot),
            Screen::PassphraseReview { slot, sel } => self.render_pp_review(c, slot, sel),
            Screen::ScriptSelect { slot, explorer, sel } => {
                let label = self.slot(slot as usize).map(seed_label).unwrap_or_default();
                self.status(c, label.as_str());
                TITLE.draw(
                    c,
                    MARGIN,
                    STATUS_H + 16,
                    if explorer {
                        s.address_explorer
                    } else {
                        s.export_xpub
                    },
                    theme::TEXT,
                );
                let scripts = self.visible_scripts();
                let bips: [Buf<16>; 4] = core::array::from_fn(|i| {
                    scripts
                        .get(i)
                        .map(|st| fill(s.bip_n, &[&st.purpose()]))
                        .unwrap_or_default()
                });
                let items: [MenuItem; 4] = core::array::from_fn(|i| MenuItem {
                    label: scripts.get(i).map(|st| st.name()).unwrap_or(""),
                    detail: bips[i].as_str(),
                });
                widgets::list(
                    c,
                    MARGIN,
                    STATUS_H + 70,
                    w - 2 * MARGIN,
                    4 * 52,
                    &items[..scripts.len()],
                    sel as usize,
                    false,
                );
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            Screen::XpubView { slot, st, account } => self.render_xpub(c, slot, st, account),
            Screen::AddressList {
                slot,
                st,
                change,
                page,
                sel,
            } => self.render_addr_list(c, slot, st, change, page, sel),
            Screen::AddressDetail {
                slot,
                st,
                change,
                index,
            } => self.render_addr_detail(c, slot, st, change, index),
            Screen::PickSeed { sel } => {
                self.status(c, s.address_explorer);
                TITLE.draw(c, MARGIN, STATUS_H + 16, s.pick_seed, theme::TEXT);
                let labels: [Buf<40>; 3] = core::array::from_fn(|i| {
                    self.seeds
                        .iter()
                        .flatten()
                        .nth(i)
                        .map(seed_label)
                        .unwrap_or_default()
                });
                let items: [MenuItem; 3] = core::array::from_fn(|i| MenuItem {
                    label: labels[i].as_str(),
                    detail: s.seed_tag,
                });
                widgets::list(
                    c,
                    MARGIN,
                    STATUS_H + 70,
                    w - 2 * MARGIN,
                    3 * 52,
                    &items[..self.seed_count()],
                    sel as usize,
                    false,
                );
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            Screen::XpubFormat { slot, st, sel } => {
                let label = self.slot(slot as usize).map(seed_label).unwrap_or_default();
                self.status(c, label.as_str());
                let head: Buf<128> = fill(s.words_count, &[&s.xpub_as, &st.name()]);
                TITLE.draw(c, MARGIN, STATUS_H + 16, head.as_str(), theme::TEXT);
                let items: [MenuItem; 4] = core::array::from_fn(|i| MenuItem {
                    label: s.xpub_formats[i].0,
                    detail: s.xpub_formats[i].1,
                });
                widgets::list(
                    c,
                    MARGIN,
                    STATUS_H + 70,
                    w - 2 * MARGIN,
                    4 * 52,
                    &items,
                    sel as usize,
                    false,
                );
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_display), ("Esc", s.h_back)]);
            }
            Screen::QrShow { kind } => self.render_qr(c, kind),
            Screen::SeedQrSelect { slot, sel } => {
                let label = self.slot(slot as usize).map(seed_label).unwrap_or_default();
                self.status(c, label.as_str());
                TITLE.draw(c, MARGIN, STATUS_H + 16, s.backup_seedqr, theme::TEXT);
                let items: [MenuItem; 2] = core::array::from_fn(|i| MenuItem {
                    label: s.seedqr_kinds[i].0,
                    detail: s.seedqr_kinds[i].1,
                });
                widgets::list(
                    c,
                    MARGIN,
                    STATUS_H + 70,
                    w - 2 * MARGIN,
                    2 * 52,
                    &items,
                    sel as usize,
                    false,
                );
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            Screen::SeedQrWarning { .. } => {
                self.status(c, s.backup_seedqr);
                widgets::message_at(c, STATUS_H + 70, s.seedqr_warn_title, theme::WARN, &s.seedqr_warn);
                widgets::hint_bar(c, &[("Enter", s.h_display), ("Esc", s.h_back)]);
            }
            Screen::Transcribe { line, x, y, .. } => self.render_transcribe(c, line, x, y),
            Screen::Scan { purpose } => self.render_scan(c, purpose),
            Screen::ScanSeed { sel } => self.render_scan_seed(c, sel),
            Screen::ScanVerify { slot } => self.render_scan_verify(c, slot),
            Screen::ScanResult => self.render_scan_result(c),
            Screen::Review { step } => self.render_review(c, step),
            Screen::VerifyAddr { step } => self.render_verify(c, step),
            Screen::MsgSign { step } => self.render_msg(c, step),
            Screen::SigVerify { step } => self.render_sig(c, step),
            Screen::SettingsImport { sel } => self.render_settings_import(c, sel),
            Screen::Wallets { step } => self.render_wallets(c, step),
            Screen::Sd { step } => self.render_sd(c, step),
            Screen::Bip85 { step } => self.render_b85(c, step),
            Screen::Key { step } => self.render_key(c, step),
            Screen::CommDetected => {
                self.status(c, s.key.comm_title);
                let (addr, id) = match self.comm {
                    bp_hal::CommCheck::Detected(p) => (p.addr, p.id),
                    _ => (0, 0),
                };
                let found: Buf<96> = fill(
                    s.key.comm_found,
                    &[&addr, &bp_ui::bformat!(8, "{:08X}", id).as_str()],
                );
                TITLE.draw(c, MARGIN, STATUS_H + 30, s.key.comm_title, theme::DANGER);
                self.show_error(crate::errors::Area::Hw, 0);
                BODY.draw(c, MARGIN, STATUS_H + 90, found.as_str(), theme::TEXT);
                let mut y = STATUS_H + 136;
                for l in s.key.comm_lines {
                    SMALL.draw(c, MARGIN, y, l, theme::TEXT_DIM);
                    y += 28;
                }
            }
            Screen::NoSeed => {
                self.status(c, s.address_explorer);
                widgets::message_at(c, STATUS_H + 80, s.no_seed_title, theme::WARN, &[s.no_seed_1]);
                widgets::hint_bar(c, &[("Esc", s.h_back)]);
            }
            Screen::Confirm {
                what: Confirm::DiscardSeed(_),
                ..
            } => {
                self.status(c, s.seeds);
                let y = widgets::message_at(
                    c,
                    STATUS_H + 40,
                    s.confirm_discard_title,
                    theme::DANGER,
                    &[s.confirm_discard_1],
                );
                let prompt: Buf<96> = fill(s.typed_prompt, &[&crate::typed::WIPE]);
                let wrong = self.typed.wrong.then_some(s.typed_wrong);
                widgets::typed_field(c, y + 40, prompt.as_str(), self.typed.text(), wrong);
                widgets::hint_bar(c, &[("A-Z", s.h_type), ("Enter", s.discard), ("Esc", s.keep)]);
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
                    detail: s.seed_tag,
                };
                n += 1;
            }
        }
        for (i, e) in menus::table(id).iter().enumerate() {
            let detail = self.settings.value_label(id, i as u8, s).unwrap_or(e.detail);
            items[n] = MenuItem {
                label: (e.label)(s),
                detail,
            };
            n += 1;
        }
        if id == MenuId::Main {
            self.render_main_menu(c, &items[..n], sel);
        } else {
            widgets::menu_list(c, &items[..n], sel as usize);
        }
        if menus::is_settings(id) {
            widgets::hint_bar(c, &[("^v", s.h_move), ("<>", s.h_change), ("Esc", s.h_back)]);
        } else if id == MenuId::Main {
            widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("1-9", s.h_jump)]);
        } else {
            widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
        }
    }

    /// The main menu in compact rows, and under it the session log (M9-4,
    /// C4): what happened since power on, newest first.
    fn render_main_menu(&self, c: &mut dyn Canvas, items: &[MenuItem], sel: u8) {
        let s = self.text();
        let w = c.width() as i32;
        let row_h = 36;
        let top = STATUS_H + 8;
        widgets::list_rows(
            c,
            MARGIN,
            top,
            w - 2 * MARGIN,
            items.len() as i32 * row_h,
            items,
            sel as usize,
            false,
            row_h,
        );
        let mut y = top + items.len() as i32 * row_h + 8;
        c.fill_rect(MARGIN, y, w - 2 * MARGIN, 1, theme::LINE);
        y += 6;
        SMALL.draw(c, MARGIN, y, s.log_title, theme::TEXT_DIM);
        y += SMALL.height as i32 + 2;
        if self.log.is_empty() {
            BODY.draw(c, MARGIN, y, s.log_empty, theme::TEXT_DIM);
            return;
        }
        for e in self.log.latest() {
            let t = crate::session::clock(e.secs);
            let what = s.log_events[e.event as usize];
            let line: Buf<96> = match e.fingerprint {
                Some(fp) => fill(
                    "[{}] {} · {}",
                    &[&t.as_str(), &what, &crate::seeds::fingerprint_hex(&fp).as_str()],
                ),
                None => fill("[{}] {}", &[&t.as_str(), &what]),
            };
            BODY.draw(c, MARGIN, y, line.as_str(), theme::TEXT);
            y += BODY.height as i32 - 1;
        }
    }

    fn render_entropy(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let Some(f) = self.flow.as_ref() else { return };
        let Some(pe) = f.entropy.as_ref() else { return };
        let dice = f.kind == Start::Dice;
        let d20 = f.kind == Start::D20;
        let a = pe.analyze();
        self.status(c, start_title(self, f.kind));

        // Left: count and recent values
        let lx = MARGIN;
        let unit = if dice || d20 { s.rolls } else { s.flips };
        let head_name = match f.kind {
            Start::Dice => s.dice_head,
            Start::D20 => s.d20_head,
            _ => s.coin_head,
        };
        let head: Buf<112> = fill(s.entry_head, &[&head_name, &f.words]);
        widgets::label(c, lx, STATUS_H + 14, head.as_str());
        let count = bformat!(8, "{}", a.count);
        let x = HUGE.draw(c, lx - 4, STATUS_H + 30, count.as_str(), theme::TEXT);
        let min: Buf<96> = fill(s.count_of, &[&a.min_count, &unit]);
        BODY.draw(
            c,
            x + 10,
            STATUS_H + 30 + HUGE.baseline as i32 - BODY.baseline as i32,
            min.as_str(),
            theme::TEXT_DIM,
        );

        widgets::label(c, lx, 168, s.recent);
        let rec = pe.record();
        if d20 {
            // two-digit values, ten per row
            let shown = rec.len().min(40);
            let start = rec.len() - shown;
            bp_ui::draw::round_rect(c, lx, 190, 360, 4 * 28 + 14, 8, theme::SURFACE);
            for (i, &v) in rec[start..].iter().enumerate() {
                let t = bformat!(4, "{:>2}", v);
                let last = start + i + 1 == rec.len();
                let (col, row) = ((i % 10) as i32, (i / 10) as i32);
                BODY.draw(
                    c,
                    lx + 14 + col * 34,
                    197 + row * 28,
                    t.as_str(),
                    if last { theme::ACCENT } else { theme::TEXT },
                );
            }
        }
        let per_row = if d20 { 0 } else { 14 };
        let rows = 4;
        let shown = rec.len().min(per_row * rows);
        let start = rec.len() - shown;
        if !d20 {
            bp_ui::draw::round_rect(c, lx, 190, 360, rows as i32 * 28 + 14, 8, theme::SURFACE);
        }
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
        let keys = match f.kind {
            Start::Dice => s.dice_keys,
            Start::D20 => s.d20_keys,
            _ => s.coin_keys,
        };
        if d20 && f.d20_digits > 0 {
            let t: Buf<64> = fill(s.d20_typing, &[&f.d20]);
            SMALL.draw(c, lx, 330, t.as_str(), theme::ACCENT);
        } else {
            SMALL.draw(c, lx, 330, keys, theme::TEXT_DIM);
        }
        SMALL.draw(c, lx, 352, s.entry_keys2, theme::TEXT_FAINT);

        // Right: frequency, entropy, checks
        let rx = 412;
        let rw = 800 - MARGIN - rx;
        widgets::label(c, rx, STATUS_H + 14, s.frequency);
        let src = pe.source();
        let expected = a.count as f64 / src.sides() as f64;
        if d20 {
            const L: [&str; 20] = [
                "1", "", "", "", "5", "", "", "", "", "10", "", "", "", "", "15", "", "", "", "", "20",
            ];
            widgets::bar_chart(c, rx, 76, rw, 112, &a.counts[..20], &L, expected);
        } else if dice {
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
                &[s.heads, s.tails],
                expected,
            );
        }
        widgets::label(c, rx, 196, s.entropy_label);
        let est = bformat!(16, "{:.0}", a.est_bits);
        let eb: Buf<96> = fill(s.bits_of, &[&est, &a.target_bits]);
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
            widgets::check_row(
                c,
                rx,
                264 + i as i32 * 26,
                rw,
                *st,
                &s.pills,
                name,
                detail.as_str(),
            );
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
        BODY.draw(c, lx, 398, msg, color);
        if a.any_fail() && self.notice.is_none() {
            SMALL.draw(c, lx, 424, s.st_failed_2, theme::TEXT_DIM);
        }
        let hints: &[(&str, &str)] = if d20 {
            &[
                ("1-20", s.h_roll),
                ("Space", s.h_accept),
                ("Del", s.h_undo),
                ("Enter", s.h_finish),
                ("Esc", s.h_cancel),
            ]
        } else if dice {
            &[
                ("1-6", s.h_roll),
                ("Del", s.h_undo),
                ("Enter", s.h_finish),
                ("Esc", s.h_cancel),
            ]
        } else {
            &[
                ("H/T", s.h_flip),
                ("Del", s.h_undo),
                ("Enter", s.h_finish),
                ("Esc", s.h_cancel),
            ]
        };
        widgets::hint_bar(c, hints);
    }

    fn render_final_coins(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let Some(f) = self.flow.as_ref() else { return };
        self.status(c, s.final_title);
        let free = f.free_bits();
        let cs = 11 - free;
        widgets::label(c, MARGIN, STATUS_H + 14, s.final_coins_label);
        let l1: Buf<160> = fill(s.final_coins_1, &[&free]);
        let l2: Buf<160> = fill(s.final_coins_2, &[&cs]);
        BODY.draw(c, MARGIN, STATUS_H + 40, l1.as_str(), theme::TEXT_DIM);
        BODY.draw(c, MARGIN, STATUS_H + 68, l2.as_str(), theme::TEXT_DIM);

        // one box per flip
        let bw = 76;
        let gap = 14;
        let total = free as i32 * bw + (free as i32 - 1) * gap;
        let x0 = (800 - total) / 2;
        let y = 180;
        for i in 0..free {
            let x = x0 + i as i32 * (bw + gap);
            let filled = i < f.coin_len;
            let next = i == f.coin_len;
            bp_ui::draw::round_rect(
                c,
                x,
                y,
                bw,
                96,
                12,
                if filled { theme::SURFACE_HI } else { theme::SURFACE },
            );
            if next {
                bp_ui::draw::outline(c, x, y, bw, 96, theme::ACCENT);
            }
            if filled {
                let (face, bit) = if f.coins[i] == 1 { ("H", "1") } else { ("T", "0") };
                TITLE.draw_centered(c, x, bw, y + 14, face, theme::TEXT);
                SMALL.draw_centered(c, x, bw, y + 62, bit, theme::ACCENT);
            }
        }
        let prog: Buf<48> = fill(s.progress, &[&f.coin_len, &free]);
        BODY.draw_centered(c, 0, 800, 300, prog.as_str(), theme::TEXT);
        if let Some(n) = self.notice {
            BODY.draw(c, MARGIN, 404, n, theme::WARN);
        }
        widgets::hint_bar(
            c,
            &[
                ("H/T", s.h_flip),
                ("Del", s.h_undo),
                ("Enter", s.h_finish),
                ("Esc", s.h_cancel),
            ],
        );
    }

    fn render_final_result(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let Some(f) = self.flow.as_ref() else { return };
        let Some(m) = f.mnemonic.as_ref() else { return };
        self.status(c, s.final_title);
        let n = m.len();
        let last = m.indices()[n - 1];
        let free = f.free_bits();
        let cs = 11 - free;
        let head: Buf<96> = fill(s.words_count, &[&s.final_result_title, &n]);
        widgets::label(c, MARGIN, STATUS_H + 14, head.as_str());
        HUGE.draw_centered(c, 0, 800, STATUS_H + 50, m.word(n - 1), theme::ACCENT);
        let mut bits = Buf::<16>::new();
        for i in (0..11).rev() {
            bits.push_str(if (last >> i) & 1 == 1 { "1" } else { "0" });
        }
        let b = bits.as_str();
        let l1 = bformat!(128, "{}: {}", s.final_bits, &b[..free]);
        let l2 = bformat!(128, "{}: {}", s.final_checksum, &b[free..free + cs]);
        BODY.draw_centered(c, 0, 800, 230, l1.as_str(), theme::TEXT);
        BODY.draw_centered(c, 0, 800, 262, l2.as_str(), theme::TEXT_DIM);
        let num: Buf<64> = fill(s.word_number, &[&(last + 1)]);
        SMALL.draw_centered(c, 0, 800, 300, num.as_str(), theme::TEXT_FAINT);
        BODY.draw_centered(c, 0, 800, 360, s.final_next, theme::TEXT_DIM);
        widgets::hint_bar(c, &[("Enter", s.h_continue), ("Esc", s.h_back)]);
    }

    fn render_passphrase(&self, c: &mut dyn Canvas, slot: u8) {
        let s = self.text();
        let label = self.slot(slot as usize).map(seed_label).unwrap_or_default();
        self.status(c, label.as_str());
        widgets::label(c, MARGIN, STATUS_H + 12, s.pp_label);
        let text = self.pass_in.text();
        // show the tail that fits; mask when hidden
        let max = ((800 - 2 * MARGIN - 40) / BODY.width as i32) as usize;
        let start = text.len().saturating_sub(max);
        let mut shown = Buf::<128>::new();
        for &b in &text[start..] {
            let ch = if self.pass_in.show { b as char } else { '*' };
            let mut t = [0u8; 4];
            shown.push_str(ch.encode_utf8(&mut t));
        }
        widgets::text_field(
            c,
            MARGIN,
            STATUS_H + 34,
            800 - 2 * MARGIN,
            shown.as_str(),
            "",
            &BODY,
        );
        let count: Buf<48> = fill(s.progress, &[&text.len(), &crate::seeds::MAX_PASSPHRASE]);
        SMALL.draw(
            c,
            800 - MARGIN - SMALL.text_width(count.as_str()),
            STATUS_H + 84,
            count.as_str(),
            theme::TEXT_DIM,
        );
        let mut y = STATUS_H + 120;
        for line in s.pp_info {
            y = BODY.draw_wrapped(c, MARGIN, y, 800 - 2 * MARGIN, 28, 2, line, theme::TEXT_DIM);
        }
        widgets::hint_bar(
            c,
            &[
                ("Sym", "!@#"),
                ("Tab", s.h_display),
                ("Enter", s.h_review),
                ("Esc", s.h_back),
            ],
        );
    }

    fn render_pp_review(&self, c: &mut dyn Canvas, slot: u8, sel: u8) {
        let s = self.text();
        self.status(c, s.pp_review_title);
        let text = self.pass_in.text();
        let mut y = STATUS_H + 16;
        if text.is_empty() {
            BODY.draw(c, MARGIN, y, s.pp_none, theme::TEXT_DIM);
            y += 30;
        } else {
            for chunk in text.chunks(58).take(2) {
                let line = core::str::from_utf8(chunk).unwrap_or("");
                let quoted = bformat!(64, "\"{}\"", line);
                BODY.draw(c, MARGIN, y, quoted.as_str(), theme::TEXT);
                y += 30;
            }
            let spaces = text.iter().filter(|&&b| b == b' ').count();
            let info: Buf<128> = fill(s.pp_len, &[&text.len(), &spaces]);
            SMALL.draw(c, MARGIN, y, info.as_str(), theme::TEXT_DIM);
            y += 26;
        }
        let cur = self
            .slot(slot as usize)
            .map(|x| crate::seeds::fingerprint_hex(&x.fingerprint))
            .unwrap_or_default();
        let new = self
            .pending
            .as_ref()
            .map(|x| crate::seeds::fingerprint_hex(&x.fingerprint))
            .unwrap_or_default();
        widgets::label(c, MARGIN, y + 6, s.fp_current);
        BODY.draw(c, MARGIN + 220, y, cur.as_str(), theme::TEXT_DIM);
        widgets::label(c, MARGIN, y + 46, s.fp_new);
        TITLE.draw(c, MARGIN + 220, y + 34, new.as_str(), theme::ACCENT);
        SMALL.draw(c, MARGIN, y + 84, s.pp_check, theme::TEXT_DIM);
        let items = [
            MenuItem {
                label: s.apply,
                detail: "",
            },
            MenuItem {
                label: s.edit,
                detail: "",
            },
        ];
        widgets::list(c, 200, 336, 400, 104, &items, sel as usize, false);
        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.edit)]);
    }

    fn render_xpub(&self, c: &mut dyn Canvas, slot: u8, st: ScriptType, account: u32) {
        let s = self.text();
        let Some(seed) = self.slot(slot as usize) else {
            return;
        };
        let net = self.settings.network;
        let head: Buf<128> = fill(
            s.words_count,
            &[&st.name(), &fill::<48>(s.account_n, &[&account])],
        );
        self.status(c, head.as_str());
        let Some(x) = seed.account_xpub(st, net, account) else {
            return;
        };
        let fp = crate::seeds::fingerprint_hex(&seed.fingerprint);
        let path = st.account_path(net, account);
        let path_s = bformat!(32, "{}", path);
        widgets::label(c, MARGIN, STATUS_H + 12, s.fp_label);
        BODY.draw(c, MARGIN + 110, STATUS_H + 6, fp.as_str(), theme::ACCENT);
        widgets::label(c, MARGIN + 260, STATUS_H + 12, s.path_label);
        BODY.draw(c, MARGIN + 320, STATUS_H + 6, path_s.as_str(), theme::TEXT);

        // SLIP-132 form (zpub/ypub/xpub), grouped by 4 for reading
        let kv = st.key_version();
        let mut out = [0u8; XKEY_LEN];
        let n = x.encode(kv.public(net), &mut out);
        let key = core::str::from_utf8(&out[..n]).unwrap_or("");
        let prefix = &key[..4];
        // ypub/zpub/upub/vpub are SLIP-132; xpub/tpub are plain BIP-32
        let tmpl = if kv == bp_bitcoin::bip32::KeyVersion::X {
            s.bip32_label
        } else {
            s.slip132_label
        };
        let lab: Buf<96> = fill(tmpl, &[&prefix, &st.purpose()]);
        widgets::label(c, MARGIN, STATUS_H + 50, lab.as_str());
        for (row, chunk) in key.as_bytes().chunks(40).enumerate() {
            let mut line = Buf::<64>::new();
            for (i, g) in chunk.chunks(4).enumerate() {
                if i > 0 {
                    line.push_str(" ");
                }
                line.push_str(core::str::from_utf8(g).unwrap_or(""));
            }
            BODY.draw(
                c,
                MARGIN,
                STATUS_H + 72 + row as i32 * 28,
                line.as_str(),
                theme::TEXT,
            );
        }

        // descriptor-style key with origin, always in xpub/tpub form
        widgets::label(c, MARGIN, STATUS_H + 168, s.descriptor_label);
        let mut out2 = [0u8; XKEY_LEN];
        let n2 = x.encode(bp_bitcoin::bip32::KeyVersion::X.public(net), &mut out2);
        let xk = core::str::from_utf8(&out2[..n2]).unwrap_or("");
        let origin = bformat!(48, "[{}/{}'/{}'/{}']", fp, st.purpose(), net.coin_type(), account);
        let mut desc = Buf::<200>::new();
        desc.push_str(st.descriptor_prefix());
        desc.push_str(origin.as_str());
        desc.push_str(xk);
        desc.push_str("/<0;1>/*");
        desc.push_str(st.descriptor_suffix());
        for (row, chunk) in desc.as_str().as_bytes().chunks(80).enumerate() {
            SMALL.draw(
                c,
                MARGIN,
                STATUS_H + 190 + row as i32 * 20,
                core::str::from_utf8(chunk).unwrap_or(""),
                theme::TEXT_DIM,
            );
        }
        widgets::hint_bar(c, &[("<>", s.h_account), ("Esc", s.h_back)]);
    }

    #[allow(clippy::too_many_arguments)]
    fn render_addr_list(
        &self,
        c: &mut dyn Canvas,
        slot: u8,
        st: ScriptType,
        change: bool,
        page: u32,
        sel: u8,
    ) {
        let s = self.text();
        let Some(seed) = self.slot(slot as usize) else {
            return;
        };
        let net = self.settings.network;
        self.status(c, st.name());
        let path = st.account_path(net, 0);
        let kind = if change { s.change } else { s.receive };
        let head = bformat!(64, "{}  {}/{}/*", kind, path, change as u8);
        widgets::label(c, MARGIN, STATUS_H + 12, head.as_str());
        let pg: Buf<48> = fill(s.page_n, &[&(page + 1)]);
        SMALL.draw(
            c,
            800 - MARGIN - SMALL.text_width(pg.as_str()),
            STATUS_H + 12,
            pg.as_str(),
            theme::TEXT_DIM,
        );
        // derive the chain key once for the page
        let Some(acct) = seed.account_xpub(st, net, 0) else {
            return;
        };
        let Ok(chain) = acct.derive_child(change as u32) else {
            return;
        };
        for row in 0..10u32 {
            let idx = page * 10 + row;
            let y = STATUS_H + 40 + row as i32 * 33;
            let selected = row == sel as u32;
            if selected {
                bp_ui::draw::round_rect(
                    c,
                    MARGIN - 8,
                    y - 2,
                    800 - 2 * MARGIN + 16,
                    30,
                    6,
                    theme::SURFACE_HI,
                );
            }
            let num = bformat!(8, "{:>4}", idx);
            SMALL.draw(c, MARGIN, y + 3, num.as_str(), theme::TEXT_FAINT);
            let mut out = [0u8; address::MAX_ADDRESS_LEN];
            if let Ok(k) = chain.derive_child(idx) {
                let n = address::encode(&k.key, st, net, &mut out);
                let a = core::str::from_utf8(&out[..n]).unwrap_or("");
                SMALL.draw(
                    c,
                    MARGIN + 52,
                    y + 3,
                    a,
                    if selected { theme::ACCENT } else { theme::TEXT },
                );
            }
        }
        widgets::hint_bar(
            c,
            &[
                ("^v", s.h_move),
                ("<>", s.h_page),
                ("Tab", s.h_switch),
                ("Enter", s.h_open),
                ("Esc", s.h_back),
            ],
        );
    }

    fn render_addr_detail(&self, c: &mut dyn Canvas, slot: u8, st: ScriptType, change: bool, index: u32) {
        let s = self.text();
        let Some(seed) = self.slot(slot as usize) else {
            return;
        };
        let net = self.settings.network;
        self.status(c, st.name());
        let kind = if change { s.change } else { s.receive };
        let head: Buf<96> = fill(s.addr_head, &[&kind, &index]);
        widgets::label(c, MARGIN, STATUS_H + 12, head.as_str());
        let path = bformat!(48, "{}/{}/{}", st.account_path(net, 0), change as u8, index);
        SMALL.draw(
            c,
            800 - MARGIN - SMALL.text_width(path.as_str()),
            STATUS_H + 12,
            path.as_str(),
            theme::TEXT_DIM,
        );
        let mut out = [0u8; address::MAX_ADDRESS_LEN];
        let Some(n) = seed.address(st, net, 0, change, index, &mut out) else {
            return;
        };
        // QR on the left: bech32 is upper-cased so it fits alphanumeric mode
        let mut qr_text = out;
        if address_is_bech32(st) {
            qr_text[..n].make_ascii_uppercase();
        }
        if let Ok(q) = bp_qr::QrCode::encode(&qr_text[..n], bp_qr::qr::Ecc::Medium, 1, 40, None) {
            let style = widgets::QrStyle {
                light: 255,
                invert: false,
            };
            self.draw_qr(c, &q, MARGIN - 8, STATUS_H + 40, 330, 330, style);
        }
        // groups of four, four groups per line (Coldcard-style readability)
        let tx = MARGIN + 340;
        for (row, chunk) in out[..n].chunks(16).enumerate() {
            let mut line = Buf::<24>::new();
            for (i, g) in chunk.chunks(4).enumerate() {
                if i > 0 {
                    line.push_str(" ");
                }
                line.push_str(core::str::from_utf8(g).unwrap_or(""));
            }
            TITLE.draw(c, tx, STATUS_H + 70 + row as i32 * 50, line.as_str(), theme::TEXT);
        }
        let fp = crate::seeds::fingerprint_hex(&seed.fingerprint);
        let info = bformat!(64, "{}  -  {}  -  {}", st.name(), net.name(), fp);
        SMALL.draw(c, tx, 380, info.as_str(), theme::TEXT_DIM);
        widgets::hint_bar(c, &[("<>", s.h_prev_next), ("Esc", s.h_back)]);
    }

    fn qr_title(&self, kind: QrKind) -> Buf<128> {
        let s = self.text();
        match kind {
            QrKind::Xpub { st, account, .. } => fill(
                s.words_count,
                &[&st.name(), &fill::<48>(s.account_n, &[&account])],
            ),
            QrKind::SeedQr { slot, compact } => {
                let label = self.slot(slot as usize).map(seed_label).unwrap_or_default();
                fill(
                    s.words_count,
                    &[&s.seedqr_kinds[compact as usize].0, &label.as_str()],
                )
            }
            QrKind::SignedPsbt { format } => fill(s.rv.qr_title, &[&s.rv.formats[format as usize]]),
            QrKind::MessageSig => fill(s.ms_sig_qr, &[]),
            QrKind::Settings => fill(s.settings_qr, &[]),
            QrKind::Wallet { idx, .. } => {
                let name = self
                    .wallets
                    .get(idx)
                    .map(|e| self.wallet_name(e))
                    .unwrap_or_default();
                fill(s.wl.qr_title, &[&name.as_str()])
            }
            QrKind::MsKey { script, account, .. } => fill(s.wl.key_qr_title, &[&script.name(), &account]),
            QrKind::Bip85 { compact } => {
                let what = if compact {
                    s.seedqr_kinds[1].0
                } else {
                    self.b85_title()
                };
                fill("{}", &[&what])
            }
        }
    }

    fn render_qr(&self, c: &mut dyn Canvas, kind: QrKind) {
        let s = self.text();
        let Some(q) = self.qr.as_ref() else { return };
        let Some(sym) = q.qr() else { return };
        let style = widgets::QrStyle {
            light: q.light(),
            invert: q.invert,
        };
        let (w, h) = (c.width() as i32, c.height() as i32);
        if q.fullscreen {
            c.fill_rect(0, 0, w, h, theme::QR_DARK);
            self.draw_qr(c, &sym, 0, 0, w, h, style);
            return;
        }
        let title = self.qr_title(kind);
        self.status(c, title.as_str());
        // No hint bar here: the keys are listed in the side panel so the
        // symbol gets every pixel of height (bigger modules scan better).
        let bx = crate::qrview::QR_BOX_PX;
        let px = self.draw_qr(c, &sym, 8, STATUS_H + 4, bx, bx, style);

        // information panel
        let x = 8 + bx + 20;
        let right = w - 16;
        let mut y = STATUS_H + 10;
        const ROW: i32 = 50;
        let row = |c: &mut dyn Canvas, y: &mut i32, label: &str, value: &str, color| {
            widgets::label(c, x, *y, label);
            BODY.draw(c, x, *y + 18, value, color);
            *y += ROW;
        };
        let fmt_name = match q.format {
            Format::Ur(t) => bformat!(112, "UR {}", t),
            Format::Specter => bformat!(112, "{}", s.fmt_specter),
            Format::SeedStandard | Format::SeedCompact => {
                let i = matches!(q.format, Format::SeedCompact) as usize;
                bformat!(112, "{}", s.seedqr_kinds[i].0)
            }
            Format::Static => bformat!(112, "{}", s.fmt_text),
            Format::Bbqr { encoding, .. } => bformat!(112, "BBQr ({})", encoding as char),
        };
        row(c, &mut y, s.qr_format, fmt_name.as_str(), theme::TEXT);

        let frames = q.frames();
        let frame_s: Buf<112> = match q.format {
            _ if frames <= 1 => fill(s.single_qr, &[]),
            Format::Specter | Format::Bbqr { .. } => fill(s.part_n, &[&(q.frame + 1), &frames]),
            _ if q.frame as usize <= frames => fill(s.part_n, &[&q.frame, &frames]),
            _ => fill(s.part_fountain, &[&q.frame, &frames]),
        };
        widgets::label(c, x, y, s.qr_frame);
        if q.paused {
            let pw = widgets::badge_width(s.paused);
            widgets::badge(c, right - pw, y - 2, s.paused, theme::WARN, theme::ACCENT_TEXT);
        }
        BODY.draw(c, x, y + 18, frame_s.as_str(), theme::TEXT);
        if frames > 1 {
            // one segment per pure part; fountain parts light the whole bar
            let bw = right - x;
            let n = frames.min(bw as usize / 3).max(1) as i32;
            let seg = bw / n;
            let cur = match q.format {
                Format::Specter => q.frame as i32,
                _ => q.frame as i32 - 1,
            };
            for i in 0..n {
                let on = cur >= frames as i32 || i == cur * n / frames as i32;
                let col = if on { theme::ACCENT } else { theme::SURFACE_HI };
                c.fill_rect(x + i * seg, y + 48, (seg - 2).max(1), 4, col);
            }
        }
        y += ROW + 10;

        let animatable = matches!(q.format, Format::Ur(_) | Format::Specter);
        widgets::label(c, x, y, s.qr_density_lbl);
        let di = q.density.index();
        for i in 0..4 {
            let col = match (animatable, i == di) {
                (false, _) => theme::SURFACE_HI,
                (true, true) => theme::ACCENT,
                (true, false) => theme::TEXT_FAINT,
            };
            bp_ui::draw::round_rect(c, x + i as i32 * 18, y + 24, 12, 12, 6, col);
        }
        let dname: Buf<64> = if q.density == crate::qrview::Density::Auto && animatable {
            let eff = s.densities[q.effective_density().index()];
            fill(s.words_count, &[&s.densities[di], &eff])
        } else {
            fill(s.densities[di], &[])
        };
        let dcol = if animatable {
            theme::TEXT
        } else {
            theme::TEXT_FAINT
        };
        BODY.draw(c, x + 84, y + 18, dname.as_str(), dcol);
        y += ROW;

        let scol = if frames > 1 {
            theme::TEXT
        } else {
            theme::TEXT_FAINT
        };
        row(c, &mut y, s.qr_speed, s.speeds[q.speed as usize], scol);

        widgets::label(c, x, y, s.qr_brightness);
        let levels = QrSession::brightness_levels();
        for i in 0..levels {
            let on = i < levels - q.brightness;
            let col = if on { theme::TEXT } else { theme::SURFACE_HI };
            c.fill_rect(x + i as i32 * 26, y + 24, 22, 14, col);
        }
        if q.invert {
            let iw = widgets::badge_width(s.inverted);
            widgets::badge(c, right - iw, y + 18, s.inverted, theme::SURFACE_HI, theme::TEXT);
        }
        y += ROW;

        let info: Buf<128> = fill(s.qr_info, &[&sym.version(), &sym.size(), &sym.size(), &px]);
        row(c, &mut y, s.qr_symbol, info.as_str(), theme::TEXT_DIM);

        let extra = match kind {
            QrKind::Xpub { .. } => s.qr_keys_xpub,
            QrKind::SeedQr { .. } => s.qr_keys_seed,
            QrKind::SignedPsbt { .. } | QrKind::MessageSig => s.rv.qr_keys,
            QrKind::Settings => s.si_note_short,
            QrKind::Wallet { .. } | QrKind::MsKey { .. } => s.wl.qr_keys,
            QrKind::Bip85 { .. } => s.b85.qr_keys,
        };
        let y0 = h - 4 * 21 - 6;
        for (i, k) in s.qr_keys.iter().chain(core::iter::once(&extra)).enumerate() {
            SMALL.draw(c, x, y0 + i as i32 * 21, k, theme::TEXT_DIM);
        }
        if self.export_allowed(kind) {
            let (text, col) = match self.notice {
                Some(n) => (n, theme::WARN),
                None => (s.sd.qr_save, theme::TEXT_DIM),
            };
            SMALL.draw(c, x, y0 - 21, text, col);
        }
    }

    fn render_transcribe(&self, c: &mut dyn Canvas, line: bool, bx: u8, by: u8) {
        let s = self.text();
        let Some(sym) = self.qr.as_ref().and_then(|q| q.qr()) else {
            return;
        };
        self.status(c, s.transcribe);
        let n = sym.size() as i32;
        let w = c.width() as i32;
        let white = theme::QR_LIGHT;
        let black = theme::QR_DARK;

        // overview with the current block / row outlined
        // smaller overview in row mode to leave room for the big strip
        let mpx = (if line { 150 } else { 232 } / n).max(2);
        let (ox, oy) = (MARGIN, STATUS_H + 40);
        c.fill_rect(ox - 2 * mpx, oy - 2 * mpx, (n + 4) * mpx, (n + 4) * mpx, white);
        for my in 0..n {
            for mx in 0..n {
                if sym.get(mx as usize, my as usize) {
                    c.fill_rect(ox + mx * mpx, oy + my * mpx, mpx, mpx, black);
                }
            }
        }
        let (sx, sy, sw, sh) = if line {
            (0, by as i32, n, 1)
        } else {
            let x0 = bx as i32 * 5;
            let y0 = by as i32 * 5;
            (x0, y0, (n - x0).min(5), (n - y0).min(5))
        };
        let hl = theme::ACCENT;
        let (hx, hy, hw, hh) = (ox + sx * mpx, oy + sy * mpx, sw * mpx, sh * mpx);
        for t in 1..3 {
            bp_ui::draw::outline(c, hx - t, hy - t, hw + 2 * t, hh + 2 * t, hl);
        }

        let tx = ox + (n + 4) * mpx + 24;
        if line {
            let head: Buf<96> = fill(s.row_n, &[&(by + 1), &n]);
            TITLE.draw(c, tx, STATUS_H + 30, head.as_str(), theme::TEXT);
            // the row, big, with column numbers every 5 cells
            let cell = ((w - 2 * MARGIN) / n).min(30);
            let rx = (w - cell * n) / 2;
            let ry = 320;
            // grey grid behind the cells so dark cells stay visible
            c.fill_rect(rx - 1, ry - 1, cell * n + 1, cell + 1, theme::TEXT_FAINT);
            for mx in 0..n {
                let dark = sym.get(mx as usize, by as usize);
                c.fill_rect(
                    rx + mx * cell,
                    ry,
                    cell - 1,
                    cell - 1,
                    if dark { black } else { white },
                );
                if mx % 5 == 0 {
                    let num = bformat!(4, "{}", mx + 1);
                    SMALL.draw(c, rx + mx * cell, ry - 24, num.as_str(), theme::TEXT_DIM);
                }
            }
        } else {
            let col = (b'A' + bx) as char;
            let head: Buf<96> = fill(s.block_n, &[&col, &(by + 1)]);
            TITLE.draw(c, tx, STATUS_H + 30, head.as_str(), theme::TEXT);
            let cr: Buf<112> = fill(s.block_cols_rows, &[&(sx + 1), &(sx + sw), &(sy + 1), &(sy + sh)]);
            SMALL.draw(c, tx, STATUS_H + 76, cr.as_str(), theme::TEXT_DIM);
            // 5x5 zoom with a grid; cells outside the symbol stay empty
            let cell = 48;
            let (zx, zy) = (tx, STATUS_H + 110);
            c.fill_rect(zx - 1, zy - 1, cell * 5 + 1, cell * 5 + 1, theme::TEXT_FAINT);
            for dy in 0..5 {
                for dx in 0..5 {
                    let (mx, my) = (sx + dx, sy + dy);
                    let color = if mx >= n || my >= n {
                        theme::SURFACE
                    } else if sym.get(mx as usize, my as usize) {
                        black
                    } else {
                        white
                    };
                    c.fill_rect(zx + dx * cell, zy + dy * cell, cell - 1, cell - 1, color);
                }
            }
        }
        SMALL.draw(c, MARGIN, 410, s.transcribe_tip, theme::TEXT_FAINT);
        widgets::hint_bar(
            c,
            &[
                ("<>^v", s.h_move),
                ("Tab", s.h_mode),
                ("V", s.h_verify),
                ("Esc", s.h_back),
            ],
        );
    }

    fn render_scan(&self, c: &mut dyn Canvas, purpose: crate::scan::Purpose) {
        use crate::scan::{Purpose, PREVIEW_H, PREVIEW_W};
        let s = self.text();
        let title = match purpose {
            Purpose::Any => s.scan_qr,
            Purpose::Seed => s.scan_seedqr,
            Purpose::Verify { .. } => s.verify_seedqr,
            Purpose::Address => s.verify_address,
            Purpose::Signed => s.verify_sig,
            Purpose::SigText => s.sv_scan_sig,
            Purpose::Wallet => s.wl.scan_title,
            Purpose::Cosigner => s.wl.key_scan_title,
            Purpose::PrivKey => s.key.scan_title,
        };
        self.status(c, title);
        let (bx, by) = (MARGIN, STATUS_H + 20);
        let (bw, bh) = (PREVIEW_W as i32 * 2, PREVIEW_H as i32 * 2);
        let sc = &self.scan;
        if sc.has_preview {
            for py in 0..PREVIEW_H {
                let row = &sc.preview[py * PREVIEW_W..(py + 1) * PREVIEW_W];
                let mut px = 0;
                while px < PREVIEW_W {
                    // merge runs of similar grey for speed
                    let v = row[px] & 0xF8;
                    let start = px;
                    while px < PREVIEW_W && row[px] & 0xF8 == v {
                        px += 1;
                    }
                    let g = row[start];
                    c.fill_rect(
                        bx + start as i32 * 2,
                        by + py as i32 * 2,
                        (px - start) as i32 * 2,
                        2,
                        bp_hal::Rgb(g, g, g), // palette: camera image
                    );
                }
            }
            if let Some(q) = sc.found {
                for k in 0..4 {
                    let (a, b) = (q[k], q[(k + 1) % 4]);
                    draw_line(
                        c,
                        bx + a.0 * 2,
                        by + a.1 * 2,
                        bx + b.0 * 2,
                        by + b.1 * 2,
                        theme::OK,
                        (bx, by, bw, bh),
                    );
                }
            }
        } else {
            bp_ui::draw::round_rect(c, bx, by, bw, bh, 8, theme::SURFACE);
            BODY.draw_centered(c, bx, bw, by + bh / 2 - 30, s.scan_waiting, theme::TEXT_DIM);
            if self.test_only {
                SMALL.draw_centered(c, bx, bw, by + bh / 2 + 10, s.scan_sim_hint, theme::TEXT_FAINT);
            }
        }
        bp_ui::draw::outline(c, bx - 1, by - 1, bw + 2, bh + 2, theme::LINE);

        let x = bx + bw + 24;
        let right = 800 - MARGIN;
        let p = sc.progress();
        widgets::label(c, x, by, s.scan_status);
        let name: Buf<112> = match (p.source, sc.ur_type()) {
            (None, _) => fill(s.scan_point, &[]),
            (Some(bp_bitcoin::qrinput::Source::Ur), Some(t)) => bformat!(112, "UR {}", t),
            (Some(src), _) => fill(s.res_via[src as usize], &[]),
        };
        // long status text wraps onto two lines
        BODY.draw_wrapped(c, x, by + 20, right - x, 28, 2, name.as_str(), theme::TEXT);
        if p.total > 1 {
            let parts: Buf<96> = fill(s.scan_parts, &[&p.received, &p.total]);
            BODY.draw(c, x, by + 92, parts.as_str(), theme::ACCENT);
            let w = right - x;
            let done = (w as usize * p.received / p.total) as i32;
            c.fill_rect(x, by + 126, w, 6, theme::SURFACE_HI);
            c.fill_rect(x, by + 126, done, 6, theme::ACCENT);
            if p.total <= 100 {
                let cols = 10;
                for i in 0..p.total {
                    let (cx, cy) = ((i % cols) as i32, (i / cols) as i32);
                    let col = if sc.has_part(i) {
                        theme::OK
                    } else {
                        theme::SURFACE_HI
                    };
                    c.fill_rect(x + cx * 18, by + 146 + cy * 18, 14, 14, col);
                }
            }
        }
        for (i, tip) in s.scan_tips.iter().enumerate() {
            SMALL.draw(c, bx, by + bh + 14 + i as i32 * 20, tip, theme::TEXT_FAINT);
        }
        widgets::hint_bar(c, &[("Esc", s.h_cancel)]);
    }

    fn render_scan_seed(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        self.status(c, s.scan_seed_title);
        let Some(seed) = self.scanned.as_ref() else { return };
        let fp = crate::seeds::fingerprint_hex(&seed.fingerprint);
        widgets::label(c, MARGIN, STATUS_H + 20, s.fp_label);
        HUGE.draw(c, MARGIN, STATUS_H + 42, fp.as_str(), theme::ACCENT);
        let src = match self.scan.seed_source {
            Some(bp_bitcoin::qrinput::SeedSource::SeedQrStandard) => s.scan_seed_sources[0],
            Some(bp_bitcoin::qrinput::SeedSource::SeedQrCompact) => s.scan_seed_sources[1],
            Some(bp_bitcoin::qrinput::SeedSource::Words) => s.scan_seed_sources[2],
            _ => s.scan_seed_sources[3],
        };
        let info: Buf<128> = fill(
            s.words_count,
            &[
                &src,
                &fill::<48>(s.n_words, &[&seed.mnemonic.as_ref().map_or(0, |m| m.len())]),
            ],
        );
        BODY.draw(c, MARGIN, STATUS_H + 130, info.as_str(), theme::TEXT);
        SMALL.draw(c, MARGIN, STATUS_H + 166, s.scan_seed_check, theme::WARN);
        let items = [
            MenuItem {
                label: s.scan_load,
                detail: "",
            },
            MenuItem {
                label: s.discard,
                detail: "",
            },
        ];
        widgets::list(
            c,
            MARGIN,
            STATUS_H + 210,
            400,
            2 * 52,
            &items,
            sel as usize,
            false,
        );
        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.discard)]);
    }

    fn render_scan_verify(&self, c: &mut dyn Canvas, slot: u8) {
        let s = self.text();
        self.status(c, s.verify_seedqr);
        let (Some(copy), Some(orig)) = (
            self.scan.seed.as_ref(),
            self.slot(slot as usize).and_then(|s| s.mnemonic.as_ref()),
        ) else {
            return;
        };
        let (a, b) = (copy.indices(), orig.indices());
        if a == b {
            widgets::message_at(c, STATUS_H + 90, s.verify_ok, theme::OK, &[s.verify_ok_1]);
        } else if a.len() != b.len() {
            widgets::message_at(c, STATUS_H + 90, s.verify_bad, theme::DANGER, &[s.verify_len]);
        } else {
            let mut list = Buf::<64>::new();
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                if x != y {
                    if !list.as_str().is_empty() {
                        list.push_str(", ");
                    }
                    list.push_str(bformat!(4, "{}", i + 1).as_str());
                }
            }
            let line: Buf<192> = fill(s.verify_words, &[&list.as_str()]);
            widgets::message_at(c, STATUS_H + 90, s.verify_bad, theme::DANGER, &[line.as_str()]);
        }
        widgets::hint_bar(c, &[("Enter", s.h_done)]);
    }

    fn render_scan_result(&self, c: &mut dyn Canvas) {
        use crate::scan::Outcome;
        let s = self.text();
        let Some(o) = self.scan.outcome else { return };
        let out = &self.scan.out;
        let text = |len: usize| core::str::from_utf8(&out[..len.min(out.len())]).unwrap_or("");
        let y0 = STATUS_H + 24;
        match o {
            Outcome::Psbt { len, summary, source } => {
                self.status(c, s.res_psbt);
                TITLE.draw(c, MARGIN, y0, s.res_psbt, theme::ACCENT);
                let l1: Buf<96> = fill(s.res_psbt_lines[0], &[&summary.version]);
                let l2: Buf<128> = fill(s.res_psbt_lines[1], &[&summary.inputs, &summary.outputs]);
                let l3: Buf<128> = fill(s.res_psbt_lines[2], &[&len, &s.res_via[source as usize]]);
                for (i, l) in [l1.as_str(), l2.as_str(), l3.as_str()].iter().enumerate() {
                    BODY.draw(c, MARGIN, y0 + 60 + i as i32 * 36, l, theme::TEXT);
                }
                SMALL.draw(c, MARGIN, y0 + 190, s.res_m5, theme::TEXT_DIM);
            }
            Outcome::Xpub { len, network, depth } => {
                self.status(c, s.res_xpub);
                TITLE.draw(c, MARGIN, y0, s.res_xpub, theme::ACCENT);
                let l: Buf<128> = fill(s.res_xpub_line, &[&network.name(), &depth]);
                BODY.draw(c, MARGIN, y0 + 56, l.as_str(), theme::TEXT);
                wrap(c, MARGIN, y0 + 96, text(len), 8);
            }
            // addresses and messages open their own screens
            Outcome::Address { .. }
            | Outcome::SignMessage { .. }
            | Outcome::SignedMessage { .. }
            | Outcome::Settings { .. } => {}
            Outcome::NotSigned => {
                self.status(c, s.verify_sig);
                widgets::message_at(
                    c,
                    STATUS_H + 90,
                    s.sv_not_signed,
                    theme::WARN,
                    &[s.sv_not_signed_1],
                );
            }
            Outcome::Descriptor { len } => {
                self.status(c, s.res_descriptor);
                TITLE.draw(c, MARGIN, y0, s.res_descriptor, theme::ACCENT);
                wrap(c, MARGIN, y0 + 56, text(len), 10);
                SMALL.draw(c, MARGIN, y0 + 290, s.res_m7, theme::TEXT_DIM);
            }
            Outcome::KeyUr { kind, .. } => {
                self.status(c, s.res_xpub);
                let name = match kind {
                    bp_bitcoin::qrinput::UrKey::Output => "UR crypto-output",
                    bp_bitcoin::qrinput::UrKey::Account => "UR crypto-account",
                    bp_bitcoin::qrinput::UrKey::HdKey => "UR crypto-hdkey",
                };
                widgets::message_at(c, STATUS_H + 90, s.res_xpub, theme::ACCENT, &[name]);
            }
            Outcome::NotAKey => {
                self.status(c, s.wl.key_scan_title);
                widgets::message_at(c, STATUS_H + 90, s.wl.not_key, theme::WARN, &[s.wl.not_key_1]);
            }
            Outcome::NotAWallet => {
                self.status(c, s.wl.scan_title);
                widgets::message_at(
                    c,
                    STATUS_H + 90,
                    s.wl.not_wallet,
                    theme::WARN,
                    &[s.wl.not_wallet_1],
                );
            }
            Outcome::UnknownUr { len } => {
                self.status(c, s.res_unknown_ur);
                widgets::message_at(c, STATUS_H + 90, s.res_unknown_ur, theme::WARN, &[text(len)]);
            }
            Outcome::Text { len } => {
                self.status(c, s.res_text);
                TITLE.draw(c, MARGIN, y0, s.res_text, theme::ACCENT);
                wrap(c, MARGIN, y0 + 56, text(len), 13);
            }
            Outcome::Binary { len } => {
                self.status(c, s.res_binary);
                let l: Buf<96> = fill(s.res_bytes, &[&len]);
                widgets::message_at(c, STATUS_H + 90, s.res_binary, theme::TEXT, &[l.as_str()]);
            }
            Outcome::NotASeed => {
                self.status(c, s.res_not_seed);
                widgets::message_at(c, STATUS_H + 90, s.res_not_seed, theme::WARN, &[s.res_not_seed_1]);
            }
            Outcome::NotAnAddress => {
                self.status(c, s.verify_address);
                widgets::message_at(
                    c,
                    STATUS_H + 90,
                    s.va_not_address,
                    theme::WARN,
                    &[s.va_not_address_1],
                );
            }
            Outcome::Failed => {
                self.status(c, s.res_failed);
                widgets::message_at(c, STATUS_H + 90, s.res_failed, theme::DANGER, &[s.res_failed_1]);
            }
        }
        widgets::hint_bar(c, &[("Enter", s.h_done)]);
    }

    fn render_settings_import(&self, c: &mut dyn Canvas, sel: u8) {
        use crate::settings::VALUE_ROWS;
        let s = self.text();
        self.status(c, s.si_title);
        let mut y = STATUS_H + 16;
        match &self.import {
            Some(Ok(imp)) => {
                widgets::label(c, MARGIN, y, s.si_changes);
                y += 26;
                let mut changed = 0;
                for row in 0..VALUE_ROWS {
                    let id = MenuId::Settings;
                    let old = self.settings.value_label(id, row, s).unwrap_or("");
                    let new = imp.settings.value_label(id, row, s).unwrap_or("");
                    if old == new {
                        continue;
                    }
                    let label = (crate::menus::table(id)[row as usize].label)(s);
                    let l: Buf<160> = bformat!(160, "{}: {} -> {}", label, old, new);
                    BODY.draw(c, MARGIN, y, l.as_str(), theme::TEXT);
                    y += 30;
                    changed += 1;
                }
                if changed == 0 {
                    BODY.draw(c, MARGIN, y, s.si_none, theme::TEXT_DIM);
                    y += 30;
                }
                if imp.blocked.any() {
                    y = BODY.draw_wrapped(
                        c,
                        MARGIN,
                        y + 6,
                        800 - 2 * MARGIN,
                        28,
                        2,
                        s.si_blocked,
                        theme::WARN,
                    );
                    let mut names = Buf::<160>::new();
                    for (i, row) in imp.blocked.rows().enumerate() {
                        if i > 0 {
                            names.push_str(", ");
                        }
                        names.push_str((crate::menus::table(MenuId::Settings)[row as usize].label)(s));
                    }
                    BODY.draw(c, MARGIN, y, names.as_str(), theme::WARN);
                    y += 34;
                }
                let items = if changed > 0 {
                    [s.si_options[0], s.si_options[1]]
                } else {
                    [s.h_done, ""]
                };
                let n = if changed > 0 { 2 } else { 1 };
                let menu = items.map(|label| MenuItem { label, detail: "" });
                widgets::list(c, MARGIN, y.min(330), 400, 110, &menu[..n], sel as usize, false);
            }
            Some(Err(e)) => {
                let i = *e as usize;
                widgets::message_at(c, STATUS_H + 70, s.si_invalid, theme::DANGER, &[s.si_errors[i]]);
                self.show_error(crate::errors::Area::Settings, i);
            }
            None => {}
        }
        SMALL.draw(c, MARGIN, 420, s.si_note, theme::TEXT_DIM);
        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_cancel)]);
    }

    fn render_summary(&self, c: &mut dyn Canvas) {
        let s = self.text();
        let Some(f) = self.flow.as_ref() else { return };
        let Some(pe) = f.entropy.as_ref() else { return };
        let dice = f.kind != Start::Coin;
        self.status(c, start_title(self, f.kind));
        let a = pe.analyze();
        let w = 800;
        TITLE.draw_centered(c, 0, w, STATUS_H + 14, s.summary_title, theme::OK);
        let est = bformat!(16, "{:.0}", a.est_bits);
        let info: Buf<160> = fill(
            s.summary_info,
            &[&a.count, &if dice { s.rolls } else { s.flips }, &est, &f.words],
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
        let mut text = [0u8; bp_bitcoin::entropy::MAX_TEXT];
        let n = pe.text(&mut text);
        let rec = &text[..n];
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
        let title: Buf<96> = fill(s.words_count, &[&s.words_title, &m.len()]);
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
            widgets::hint_bar(c, &[("Enter", s.h_start_check), ("Esc", s.h_cancel)]);
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
        let prog: Buf<96> = fill(s.progress, &[&(q.q + 1), &q.n]);
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
        let ask = bformat!(64, "{}{}", s.quiz_question, q.word_pos() + 1);
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
            Some(i) => fill::<96>(s.fixing_word, &[&(i + 1)]),
            None => fill::<96>(s.word_of, &[&(e.pos + 1), &e.n]),
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
                    ("0-9", s.h_number),
                    ("Enter", s.h_accept),
                    ("Del", s.h_delete),
                    ("Esc", s.h_cancel),
                ],
            );
        } else {
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

/// Thick line clipped to `clip` (x, y, w, h).
fn draw_line(
    c: &mut dyn Canvas,
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
    color: bp_hal::Rgb,
    clip: (i32, i32, i32, i32),
) {
    let steps = (x1 - x0).abs().max((y1 - y0).abs()).max(1);
    for k in 0..=steps {
        let x = x0 + (x1 - x0) * k / steps;
        let y = y0 + (y1 - y0) * k / steps;
        if x >= clip.0 && y >= clip.1 && x < clip.0 + clip.2 - 2 && y < clip.1 + clip.3 - 2 {
            c.fill_rect(x, y, 3, 3, color);
        }
    }
}

/// Printable text wrapped at the screen width, at most `max_lines`.
fn wrap(c: &mut dyn Canvas, x: i32, y: i32, text: &str, max_lines: usize) {
    let per = ((800 - 2 * x) / SMALL.width as i32) as usize;
    let mut line = 0;
    for raw in text.split('\n') {
        let b = raw.as_bytes();
        for chunk in b.chunks(per.max(1)) {
            if line == max_lines {
                SMALL.draw(c, x, y + line as i32 * 22, "...", theme::TEXT_DIM);
                return;
            }
            let shown: Buf<128> = {
                let mut s = Buf::<128>::new();
                for &ch in chunk {
                    let ch = if (0x20..0x7F).contains(&ch) { ch } else { b'.' };
                    s.push_str(core::str::from_utf8(&[ch]).unwrap_or("."));
                }
                s
            };
            SMALL.draw(c, x, y + line as i32 * 22, shown.as_str(), theme::TEXT);
            line += 1;
        }
    }
}

fn address_is_bech32(st: ScriptType) -> bool {
    matches!(st, ScriptType::NativeSegwit | ScriptType::Taproot)
}

fn start_title(app: &App, kind: Start) -> &'static str {
    let s = app.text();
    match kind {
        Start::Dice => s.dice_intro_title,
        Start::Coin => s.coin_intro_title,
        Start::D20 => s.d20_intro_title,
        Start::TypeWords => s.entry_title_words,
        Start::WordNumbers => s.entry_title_numbers,
        Start::FinalWord => s.final_title,
    }
}

fn state(st: Status) -> CheckState {
    match st {
        Status::Pending => CheckState::Wait,
        Status::Pass => CheckState::Pass,
        Status::Fail => CheckState::Fail,
    }
}

fn check_rows(s: &crate::Strings, a: &Analysis, src: Source) -> [(&'static str, CheckState, Buf<96>); 5] {
    let tested = a.count >= a.min_count;
    let after = || -> Buf<96> { fill(s.after_n, &[&a.min_count]) };
    let est = bformat!(16, "{:.0}", a.est_bits);
    let chi2 = bformat!(16, "{:.1}", a.chi2);
    let chi2_max = bformat!(16, "{:.1}", src.chi2_limit());
    let z = bformat!(16, "{:.1}", a.autocorr_z);
    [
        (
            s.chk_count,
            state(a.count_status),
            fill(s.progress, &[&a.count, &a.min_count]),
        ),
        (
            s.chk_entropy,
            state(a.entropy_status),
            fill(s.bits_of, &[&est, &a.target_bits]),
        ),
        (
            s.chk_bias,
            state(a.bias_status),
            if tested {
                fill(s.chi2_detail, &[&chi2, &chi2_max])
            } else {
                after()
            },
        ),
        (
            s.chk_pattern,
            state(a.pattern_status),
            if tested { fill(s.z_detail, &[&z]) } else { after() },
        ),
        (
            s.chk_repeat,
            state(a.repeat_status),
            fill(s.longest_detail, &[&a.longest_run, &(src.run_limit() - 1)]),
        ),
    ]
}
