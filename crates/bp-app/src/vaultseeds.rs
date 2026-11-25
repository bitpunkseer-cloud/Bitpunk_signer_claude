//! What the open vault keeps (M10-5): the seed vault screens (Seeds & keys,
//! then Seed vault), and keeping the registered wallets and the settings in
//! the vault as they change.
//!
//! Seeds go in only when the user stores them; wallets and settings follow
//! the session by themselves (settings when the Settings menu is left).
//! When the vault opens, its settings apply, its first seeds load into the
//! free slots, and its wallets register again for the loaded seeds whose
//! tag they carry (the registration rules are checked again).

use crate::menus::MenuId;
use crate::vaultdata::{StoredSeed, MAX_STORED, WALLET_MAX};
use crate::{typed, App, Pick, Screen};
use bp_bitcoin::multisig::formats;
use bp_bitcoin::multisig::register::{self, Code, CodeKey, Entry, MAX_WALLETS};
use bp_hal::input::KeyEvent;
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, DOUBLE};
use bp_ui::widgets::{self, MenuItem, Tag, MARGIN, STATUS_H};
use bp_ui::{grid, theme};

/// Steps of the seed vault screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedVaultStep {
    /// The stored seeds, then "Store a loaded seed".
    List { sel: u8 },
    /// One stored seed: load it, or remove it.
    Seed { idx: u8, sel: u8 },
    /// Which loaded seed to store.
    Pick { sel: u8 },
    /// Remove a stored seed (type WIPE).
    Remove { idx: u8 },
}

/// The fingerprints in the RAM slots (to notice seeds coming and going).
pub(crate) type SlotsSeen = [Option<[u8; 4]>; crate::SEED_SLOTS];

/// The registry's tags (to notice wallets coming and going).
pub(crate) type WalletsSeen = ([[u8; 32]; MAX_WALLETS], usize);

fn stored_label(s: &StoredSeed) -> Buf<40> {
    let fp = crate::seeds::fingerprint_hex(&s.fp);
    let what: Buf<8> = match s.kind {
        crate::seeds::SlotKind::Xprv => fill("XPRV", &[]),
        crate::seeds::SlotKind::Wif => fill("WIF", &[]),
        crate::seeds::SlotKind::Mnemonic => fill("{}", &[&s.words()]),
    };
    fill(crate::text::EN.seed_label, &[&fp, &what.as_str(), &""])
}

impl App {
    fn sv_step(&mut self, step: SeedVaultStep) {
        self.set_current(Screen::SeedVault { step });
    }

    /// Seeds & keys > Seed vault: the lock screen first if the vault is locked.
    pub(crate) fn seed_vault_action(&mut self) {
        let t = self.text().vault;
        match (self.vault.exists, self.vault.is_open()) {
            (None, _) => self.notice = Some(t.no_hw),
            (Some(false), _) => self.notice = Some(t.sv_no_vault),
            (Some(true), false) => self.push(self.lock_screen()),
            (Some(true), true) => self.push(Screen::SeedVault {
                step: SeedVaultStep::List { sel: 0 },
            }),
        }
    }

    /// Loaded slots whose seed is not in the vault.
    fn storable(&self) -> ([u8; crate::SEED_SLOTS], usize) {
        let mut v = [0u8; crate::SEED_SLOTS];
        let mut n = 0;
        for (i, s) in self.seeds.iter().enumerate() {
            if let Some(s) = s {
                if self.vault.data.find(s).is_none() {
                    v[n] = i as u8;
                    n += 1;
                }
            }
        }
        (v, n)
    }

    /// Whether a stored seed is in one of the RAM slots.
    fn stored_loaded(&self, s: &StoredSeed) -> bool {
        self.seeds.iter().flatten().any(|x| s.matches(x))
    }

    /// Store the seed of `slot` in the vault (saved by `vault_after_event`).
    fn sv_store(&mut self, slot: usize) {
        let t = self.text().vault;
        let Some(seed) = self.slot(slot) else { return };
        let pass = seed.has_passphrase();
        let Some(st) = StoredSeed::from_slot(seed) else {
            return;
        };
        if self.vault.data.add_seed(st) {
            self.notice = Some(if pass { t.sv_stored_pass } else { t.sv_stored });
            let sel = self.vault.data.seed_count().saturating_sub(1) as u8;
            self.sv_step(SeedVaultStep::List { sel });
        } else {
            self.notice = Some(t.sv_full);
        }
    }

    /// Load stored seed `idx` into a free slot. `false` if it did not load.
    fn sv_load(&mut self, idx: usize, quiet: bool) -> Option<usize> {
        let t = self.text().vault;
        let st = self.vault.data.seed(idx)?;
        if self.stored_loaded(st) {
            if !quiet {
                self.notice = Some(t.sv_already);
            }
            return None;
        }
        let Some(free) = self.free_slot() else {
            if !quiet {
                self.push(Screen::SlotsFull);
            }
            return None;
        };
        match st.to_slot() {
            Some(slot) => {
                self.seeds[free] = Some(slot);
                Some(free)
            }
            None => {
                self.notice = Some(t.sv_bad);
                None
            }
        }
    }

    // ---------- the vault opens, the session changes ----------

    /// The vault opened with `body` (plaintext): apply its settings, load
    /// its first seeds into the free slots. `false` if the body is unreadable.
    pub(crate) fn vault_opened(&mut self, body: &[u8]) -> bool {
        if self.vault.data.read(body).is_err() {
            return false;
        }
        if let Some(st) = self.vault.data.settings {
            self.settings = st;
        }
        for i in 0..self.vault.data.seed_count() {
            if self.free_slot().is_none() {
                break;
            }
            let _ = self.sv_load(i, true);
        }
        self.vault.saved = self.vault.data.digest();
        self.vault.failed = None;
        self.vault.seen_slots = [None; crate::SEED_SLOTS];
        self.vault.seen_wallets = ([[0; 32]; MAX_WALLETS], usize::MAX);
        self.vault_restore_wallets();
        true
    }

    /// Register the stored wallets whose tag a loaded seed recomputes (the
    /// registration rules are checked again, as for a `.bpw` file).
    fn vault_restore_wallets(&mut self) {
        let net = self.settings.network;
        let mut text = [0u8; WALLET_MAX];
        for w in 0..MAX_WALLETS {
            let Some(rec) = self.vault.data.wallets().nth(w) else {
                break;
            };
            let n = rec.text().len();
            text[..n].copy_from_slice(rec.text());
            let Ok(bpw) = formats::parse_bpw(&text[..n]) else {
                continue;
            };
            if self.wallets.iter().any(|(_, e)| e.tag == bpw.tag) || self.wallets.is_full() {
                continue;
            }
            if core::str::from_utf8(&Code::from_tag(&bpw.tag).display()).ok() != Some(bpw.code) {
                continue;
            }
            let Ok(mut imp) = formats::parse_wallet(bpw.descriptor) else {
                continue;
            };
            imp.wallet.set_name(bpw.name);
            for (i, s) in self.seeds.iter().enumerate() {
                let Some(s) = s else { continue };
                let ck = CodeKey::new(s.master());
                if ck.tag(&imp.wallet) != bpw.tag {
                    continue;
                }
                if let Ok(checked) = register::check(&imp.wallet, net, s.master(), &self.wallets) {
                    let _ = self.wallets.add(Entry {
                        wallet: imp.wallet,
                        slot: i as u8,
                        ours: checked.ours,
                        code: ck.code(&imp.wallet),
                        tag: bpw.tag,
                    });
                }
                break;
            }
        }
        bp_crypto::secret::wipe(&mut text);
    }

    /// Bring the vault's wallet records up to date: every registered wallet,
    /// plus stored ones whose seed is not loaded (a wallet removed while its
    /// seed is loaded leaves the vault).
    fn vault_sync_wallets(&mut self) {
        let in_registry = |a: &App, tag: &[u8; 32]| a.wallets.iter().any(|(_, e)| e.tag == *tag);
        let recomputed = |a: &App, text: &[u8]| -> bool {
            let Ok(bpw) = formats::parse_bpw(text) else {
                return false;
            };
            let Ok(imp) = formats::parse_wallet(bpw.descriptor) else {
                return false;
            };
            a.seeds
                .iter()
                .flatten()
                .any(|s| CodeKey::new(s.master()).tag(&imp.wallet) == bpw.tag)
        };
        // the texts to keep, then the registered wallets not yet stored
        let mut keep = [false; MAX_WALLETS];
        for (k, rec) in self.vault.data.wallets().enumerate() {
            keep[k] = match rec.tag() {
                Some(tag) => {
                    in_registry(self, &tag) || self.wallets.is_full() || !recomputed(self, rec.text())
                }
                None => false,
            };
        }
        let mut bufs = [[0u8; WALLET_MAX]; MAX_WALLETS];
        let mut lens = [0usize; MAX_WALLETS];
        let mut n = 0;
        for (k, rec) in self.vault.data.wallets().enumerate() {
            if keep[k] && n < MAX_WALLETS {
                bufs[n][..rec.text().len()].copy_from_slice(rec.text());
                lens[n] = rec.text().len();
                n += 1;
            }
        }
        let mut fits = true;
        for (_, e) in self.wallets.iter() {
            let stored = bufs[..n]
                .iter()
                .zip(&lens[..n])
                .any(|(b, l)| formats::parse_bpw(&b[..*l]).is_ok_and(|x| x.tag == e.tag));
            if stored {
                continue;
            }
            let d = e.code.display();
            let code = core::str::from_utf8(&d).unwrap_or("");
            let mut out = [0u8; WALLET_MAX];
            match formats::write_bpw(&e.wallet, e.wallet.name(), code, &e.tag, &mut out) {
                Some(len) if n < MAX_WALLETS => {
                    bufs[n][..len].copy_from_slice(&out[..len]);
                    lens[n] = len;
                    n += 1;
                }
                _ => fits = false,
            }
        }
        if !self
            .vault
            .data
            .set_wallets(bufs[..n].iter().zip(&lens[..n]).map(|(b, l)| &b[..*l]))
            || !fits
        {
            self.notice = Some(self.text().vault.wallet_full);
        }
    }

    /// Update the wallet records now (also before a new vault is written).
    pub(crate) fn vault_sync_now(&mut self) {
        let mut tags = [[0u8; 32]; MAX_WALLETS];
        let mut n = 0;
        for (_, e) in self.wallets.iter() {
            tags[n] = e.tag;
            n += 1;
        }
        self.vault.seen_wallets = (tags, n);
        self.vault_sync_wallets();
    }

    /// After every key and vault job: wallets register again for seeds that
    /// came in, the vault's copy follows the session, and a save is queued
    /// when it changed (settings once the Settings menu is left).
    pub(crate) fn vault_after_event(&mut self) {
        if !self.vault.is_open() || self.vault.pending_job() {
            return;
        }
        let slots: SlotsSeen = core::array::from_fn(|i| self.seeds[i].as_ref().map(|s| s.fingerprint));
        if slots != self.vault.seen_slots {
            self.vault.seen_slots = slots;
            self.vault_restore_wallets();
        }
        let mut tags = [[0u8; 32]; MAX_WALLETS];
        let mut n = 0;
        for (_, e) in self.wallets.iter() {
            tags[n] = e.tag;
            n += 1;
        }
        if (tags, n) != self.vault.seen_wallets {
            self.vault_sync_now();
        }
        let in_settings = matches!(
            self.current(),
            Screen::Menu {
                id: MenuId::Settings,
                ..
            }
        );
        if !in_settings {
            self.vault.data.settings = Some(self.settings);
        }
        let d = self.vault.data.digest();
        if d != self.vault.saved && Some(d) != self.vault.failed {
            if self.vault.mode == crate::vaultui::Mode::Decoy {
                // behind a decoy PIN nothing is written; it only looks saved
                self.vault.saved = d;
                self.log.push(crate::session::Event::VaultSaved, None);
            } else {
                self.vault_queue_save();
            }
        }
    }

    // ---------- keys ----------

    pub(crate) fn seed_vault_key(&mut self, step: SeedVaultStep, ev: KeyEvent) {
        let t = self.text().vault;
        self.notice = None;
        let count = self.vault.data.seed_count();
        match step {
            SeedVaultStep::List { sel } => match crate::pick(ev.key, sel, count as u8 + 1) {
                Pick::Move(s) => self.sv_step(SeedVaultStep::List { sel: s }),
                Pick::Choose(i) if (i as usize) < count => {
                    self.sv_step(SeedVaultStep::Seed { idx: i, sel: 0 })
                }
                Pick::Choose(_) => {
                    if count >= MAX_STORED {
                        self.notice = Some(t.sv_full);
                    } else if self.storable().1 == 0 {
                        self.notice = Some(t.sv_nothing);
                    } else {
                        self.sv_step(SeedVaultStep::Pick { sel: 0 });
                    }
                }
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            SeedVaultStep::Seed { idx, sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.sv_step(SeedVaultStep::Seed { idx, sel: s }),
                Pick::Choose(0) => {
                    if let Some(slot) = self.sv_load(idx as usize, false) {
                        self.go_seeds(Some(Screen::SeedReady {
                            slot: slot as u8,
                            created: false,
                        }));
                    }
                }
                Pick::Choose(_) => {
                    self.typed.clear();
                    self.sv_step(SeedVaultStep::Remove { idx });
                }
                Pick::Back => self.sv_step(SeedVaultStep::List { sel: idx }),
                Pick::None => {}
            },
            SeedVaultStep::Pick { sel } => {
                let (slots, n) = self.storable();
                if n == 0 {
                    self.sv_step(SeedVaultStep::List { sel: 0 });
                    return;
                }
                match crate::pick(ev.key, sel.min(n as u8 - 1), n as u8) {
                    Pick::Move(s) => self.sv_step(SeedVaultStep::Pick { sel: s }),
                    Pick::Choose(i) => self.sv_store(slots[i as usize] as usize),
                    Pick::Back => self.sv_step(SeedVaultStep::List { sel: count as u8 }),
                    Pick::None => {}
                }
            }
            SeedVaultStep::Remove { idx } => match self.typed.key(ev.key, typed::WIPE) {
                typed::Typed::Confirmed => {
                    self.vault.data.remove_seed(idx as usize);
                    self.notice = Some(t.sv_removed);
                    self.sv_step(SeedVaultStep::List { sel: 0 });
                }
                typed::Typed::Cancelled => self.sv_step(SeedVaultStep::Seed { idx, sel: 1 }),
                typed::Typed::Pending => {}
            },
        }
    }

    // ---------- drawing ----------

    pub(crate) fn render_seed_vault(&self, c: &mut dyn Canvas, step: SeedVaultStep) {
        let s = self.text();
        let t = s.vault;
        self.status(c, t.sv_menu);
        let w = grid::COLS * grid::CELL_W;
        let g = |row| grid::text_y(&BODY, row, 1);
        let bottom = c.height() as i32 - widgets::HINT_H - 8;
        let notice = |c: &mut dyn Canvas, row: i32| {
            if let Some(n) = self.notice {
                widgets::log_line(c, MARGIN, g(row), w, Tag::Info, n, "");
            }
        };
        match step {
            SeedVaultStep::List { sel } => {
                let count = self.vault.data.seed_count();
                let head: Buf<64> = fill(t.sv_count, &[&count, &MAX_STORED]);
                widgets::log_line(c, MARGIN, g(2), w, Tag::Info, head.as_str(), "");
                let labels: [Buf<40>; MAX_STORED] =
                    core::array::from_fn(|i| self.vault.data.seed(i).map(stored_label).unwrap_or_default());
                let items: [MenuItem; MAX_STORED + 1] = core::array::from_fn(|i| {
                    if i < count {
                        let st = self.vault.data.seed(i);
                        MenuItem {
                            label: labels[i].as_str(),
                            detail: if st.is_some_and(|x| self.stored_loaded(x)) {
                                t.sv_loaded
                            } else {
                                ""
                            },
                        }
                    } else {
                        MenuItem {
                            label: t.sv_store,
                            detail: ">",
                        }
                    }
                });
                let top = g(4) - 6;
                widgets::list(
                    c,
                    MARGIN,
                    top,
                    w,
                    bottom - top - 40,
                    &items[..count + 1],
                    sel as usize,
                    true,
                );
                notice(c, 16);
                widgets::log_line(c, MARGIN, g(17), w, Tag::Info, t.sv_never, "");
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            SeedVaultStep::Seed { idx, sel } => {
                let Some(st) = self.vault.data.seed(idx as usize) else {
                    return;
                };
                let fp = crate::seeds::fingerprint_hex(&st.fp);
                DOUBLE.draw(c, MARGIN, grid::text_y(&DOUBLE, 2, 2), fp.as_str(), theme::BRIGHT);
                let label = stored_label(st);
                BODY.draw(c, MARGIN, g(5), label.as_str(), theme::TEXT_DIM);
                let items = [
                    MenuItem {
                        label: t.sv_load,
                        detail: if self.stored_loaded(st) { t.sv_loaded } else { "" },
                    },
                    MenuItem {
                        label: t.sv_remove,
                        detail: ">",
                    },
                ];
                widgets::list(c, MARGIN, g(7), w, 2 * 52, &items, sel as usize, false);
                notice(c, 12);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            SeedVaultStep::Pick { sel } => {
                let (slots, n) = self.storable();
                BODY.draw(c, MARGIN, g(2), t.sv_pick, theme::TEXT);
                let labels: [Buf<40>; crate::SEED_SLOTS] = core::array::from_fn(|i| {
                    self.slot(slots[i] as usize)
                        .filter(|_| i < n)
                        .map(crate::view::seed_label)
                        .unwrap_or_default()
                });
                let items: [MenuItem; crate::SEED_SLOTS] = core::array::from_fn(|i| MenuItem {
                    label: labels[i].as_str(),
                    detail: s.seed_tag,
                });
                widgets::list(c, MARGIN, g(4), w, 3 * 52, &items[..n], sel as usize, false);
                let pass = slots[..n]
                    .iter()
                    .any(|&i| self.slot(i as usize).is_some_and(|x| x.has_passphrase()));
                let tag = if pass { Tag::Warn } else { Tag::Info };
                widgets::log_line(c, MARGIN, g(10), w, tag, t.sv_never, "");
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", t.sv_put), ("Esc", s.h_back)]);
            }
            SeedVaultStep::Remove { idx } => {
                let label = self
                    .vault
                    .data
                    .seed(idx as usize)
                    .map(stored_label)
                    .unwrap_or_default();
                let y = widgets::message_at(
                    c,
                    STATUS_H + 40,
                    t.sv_remove_title,
                    theme::DANGER,
                    &[label.as_str(), t.sv_remove_line],
                );
                let prompt: Buf<96> = fill(s.typed_prompt, &[&typed::WIPE]);
                let wrong = self.typed.wrong.then_some(s.typed_wrong);
                widgets::typed_field(c, y + 40, prompt.as_str(), self.typed.text(), wrong);
                widgets::hint_bar(c, &[("A-Z", s.h_type), ("Enter", t.sv_remove), ("Esc", s.keep)]);
            }
        }
    }
}
