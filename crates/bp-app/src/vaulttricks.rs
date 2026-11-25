//! Trick PINs (M10-6, decision 6): what each one does when typed on the
//! lock screen, and Settings > Security > Trick PINs.
//!
//! | kind | on the lock screen |
//! |---|---|
//! | decoy wallet | opens like the vault, with a decoy seed (a BIP-85 child, 1001-1003, of a real seed); nothing is ever written |
//! | erase, then "wrong PIN" | the vault is erased for good; the lock screen goes on counting wrong PINs |
//! | erase, then decoy | the vault is erased for good; the decoy opens |
//! | look blank | the session starts like a device without a vault; nothing is erased |
//!
//! None of them uses an attempt of the secure element, and the screens
//! show nothing that tells a trick PIN from the vault's own.

use crate::menus::MenuId;
use crate::seeds::{SeedSlot, SlotKind};
use crate::vault::{self, TrickInfo, TrickKind, VaultError, VaultHw, MAX_ATTEMPTS, TRICKS};
use crate::vaultdata::StoredSeed;
use crate::vaultui::{Mode, TrickDraft, VStep};
use crate::{session, App, Pick, Screen};
use bp_bitcoin::bip85;
use bp_crypto::hmac::HmacSha256;
use bp_crypto::secret::{wipe, Secret};
use bp_hal::input::KeyEvent;
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::BODY;
use bp_ui::grid;
use bp_ui::widgets::{self, MenuItem, Tag, MARGIN};

/// Steps of Settings > Security > Trick PINs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrickStep {
    /// The trick PINs set, then "Add a trick PIN".
    List { sel: u8 },
    /// What the new trick PIN does.
    Kind { sel: u8 },
    /// The seed a decoy comes from.
    Seed { kind: TrickKind, sel: u8 },
    /// Keep or remove trick `idx`.
    Remove { idx: u8, sel: u8 },
}

/// BIP-85 index of the decoy in trick entry `i` (M10 plan: 1001-1003).
pub fn decoy_index(i: usize) -> u16 {
    1001 + i as u16
}

impl App {
    fn tr_step(&mut self, step: TrickStep) {
        self.set_current(Screen::Tricks { step });
    }

    /// The trick PINs as the list shows them (none behind a decoy PIN).
    fn trick_list(&self) -> [Option<TrickInfo>; TRICKS] {
        match &self.vault.unlocked {
            Some(u) => vault::tricks(u),
            None => [None; TRICKS],
        }
    }

    /// Loaded slots a decoy can come from (words or an XPRV, not a WIF).
    fn decoy_sources(&self) -> ([u8; crate::SEED_SLOTS], usize) {
        let mut v = [0u8; crate::SEED_SLOTS];
        let mut n = 0;
        for (i, s) in self.seeds.iter().enumerate() {
            if s.as_ref().is_some_and(|s| s.kind != SlotKind::Wif) {
                v[n] = i as u8;
                n += 1;
            }
        }
        (v, n)
    }

    /// Settings > Security > Trick PINs (the vault must be open).
    pub(crate) fn vault_tricks_action(&mut self) {
        let t = self.text().vault;
        match self.vault.exists {
            None => self.notice = Some(t.no_hw),
            Some(true) if !self.vault.is_open() => self.push(self.lock_screen()),
            Some(true) => self.push(Screen::Tricks {
                step: TrickStep::List { sel: 0 },
            }),
            Some(false) => self.notice = Some(t.no_vault),
        }
    }

    /// Start typing the new trick PIN.
    fn tr_pin(&mut self, kind: TrickKind, slot: u8) {
        self.vault.trick = Some(TrickDraft { kind, slot });
        self.vault_clear_pins();
        self.push(Screen::Vault {
            step: VStep::NewPrefix,
        });
    }

    // ---------- the lock screen ----------

    /// A trick PIN was typed (`decoy`: the decoy seed's entropy).
    pub(crate) fn vault_trick(&mut self, hw: &mut VaultHw, kind: TrickKind, decoy: Option<Secret<16>>) {
        match kind {
            TrickKind::Decoy => self.open_decoy(decoy),
            TrickKind::Blank => {
                self.vault.mode = Mode::Blank;
                self.vault.exists = Some(false);
                self.reset_to(Screen::Welcome { sel: 0 });
            }
            TrickKind::WipeWrong | TrickKind::WipeDecoy => {
                // erased for good before anything shows
                let _ = vault::wipe_all(hw);
                let mut key = [0u8; 32];
                hw.rng.fill_bytes(&mut key);
                self.vault_set_fake_key(key);
                if kind == TrickKind::WipeDecoy {
                    self.open_decoy(decoy);
                } else {
                    self.vault.mode = Mode::Fake;
                    self.fake_wrong();
                }
            }
        }
    }

    /// Open the decoy: it looks like the vault holding one seed.
    fn open_decoy(&mut self, decoy: Option<Secret<16>>) {
        self.vault.mode = Mode::Decoy;
        self.vault.left = MAX_ATTEMPTS;
        self.vault.wrong_left = None;
        self.vault.data.clear();
        let slot = decoy
            .and_then(|e| bp_bitcoin::bip39::Mnemonic::from_entropy(e.expose()).ok())
            .and_then(|m| SeedSlot::new(m, b""));
        if let Some(slot) = slot {
            if let Some(st) = StoredSeed::from_slot(&slot) {
                self.vault.data.add_seed(st);
            }
            if let Some(free) = self.free_slot() {
                self.seeds[free] = Some(slot);
            }
        }
        self.vault.data.settings = Some(self.settings);
        self.vault.saved = self.vault.data.digest();
        self.vault.failed = None;
        self.log.push(session::Event::VaultOpened, None);
        self.reset_to(Screen::Menu {
            id: MenuId::Main,
            sel: 0,
        });
    }

    /// After a silent wipe: two words for the typed prefix, the same for
    /// the same prefix (the real ones are gone with the secure element).
    pub(crate) fn fake_words(&self) -> [u16; 2] {
        let key = self.vault_fake_key().unwrap_or([0; 32]);
        let mut h = HmacSha256::new(&key);
        h.update(b"bitpunk words");
        h.update(self.vault_prefix());
        let m = h.finalize();
        [
            u16::from_be_bytes([m[0], m[1]]) & 2047,
            u16::from_be_bytes([m[2], m[3]]) & 2047,
        ]
    }

    /// After a silent wipe every PIN is "wrong", counting down as before.
    pub(crate) fn fake_wrong(&mut self) {
        let left = self.vault.left.saturating_sub(1);
        self.vault.left = left;
        if left == 0 {
            self.vault.exists = Some(false);
            self.vault.mode = Mode::Normal;
            self.vault.left = MAX_ATTEMPTS;
            self.set_current(Screen::Vault { step: VStep::Wiped });
        } else {
            self.vault.wrong_left = Some(left);
            self.vault_start_delay();
        }
    }

    // ---------- adding and removing ----------

    /// The add-trick job: stretch the trick PIN, add it, write the vault.
    pub(crate) fn vault_add_trick(&mut self, hw: &mut VaultHw, body: &mut [u8]) {
        let t = self.text().vault;
        let Some(draft) = self.vault.trick else { return };
        let mut pin = [0u8; crate::vaultui::PREFIX_MAX + 1 + crate::vaultui::SUFFIX_MAX];
        let n = self.vault_joined_pin(&mut pin);
        self.vault_clear_pins();
        let done = |a: &mut App, msg: &'static str| {
            a.vault.trick = None;
            a.notice = Some(msg);
            a.pop();
            if matches!(a.current(), Screen::Tricks { .. }) {
                a.tr_step(TrickStep::List { sel: 0 });
            }
        };
        if self.vault.mode == Mode::Decoy {
            // behind a decoy nothing is written; it only looks done
            wipe(&mut pin);
            done(self, t.tr_added);
            return;
        }
        let net = self.settings.network;
        let Some(u) = self.vault.unlocked.as_ref() else {
            wipe(&mut pin);
            done(self, t.save_failed);
            return;
        };
        let Some(i) = vault::next_trick(u) else {
            wipe(&mut pin);
            done(self, t.tr_full);
            return;
        };
        let index = decoy_index(i);
        let mut ent = [0u8; 16];
        let mut src_fp = [0u8; 4];
        let mut decoy = false;
        if draft.kind.has_decoy() {
            let seed = self.slot(draft.slot as usize);
            let m = seed.and_then(|s| {
                bip85::derive(s.master(), bip85::App::Bip39 { words: 12 }, index as u32, net).ok()
            });
            if let (Some(s), Some(bip85::Derived::Mnemonic(m))) = (seed, m.as_ref()) {
                let mut e = [0u8; 32];
                let k = m.entropy(&mut e);
                ent.copy_from_slice(&e[..k.min(16)]);
                wipe(&mut e);
                src_fp = s.fingerprint;
                decoy = true;
            }
            if !decoy {
                wipe(&mut pin);
                done(self, t.tr_need_seed);
                return;
            }
        }
        let u = self.vault.unlocked.as_mut().expect("open");
        let r = vault::add_trick(
            hw,
            u,
            &pin[..n],
            draft.kind,
            src_fp,
            if decoy { index } else { 0 },
            decoy.then_some(&ent),
        );
        wipe(&mut pin);
        wipe(&mut ent);
        match r {
            Ok(()) => {
                self.vault_save_now(hw, body);
                let msg = if self.notice.is_some() {
                    t.save_failed
                } else {
                    t.tr_added
                };
                done(self, msg);
            }
            Err(VaultError::PinClash) => {
                self.notice = Some(t.tr_clash);
                self.set_current(Screen::Vault {
                    step: VStep::NewPrefix,
                });
            }
            Err(VaultError::TricksFull) => done(self, t.tr_full),
            Err(_) => done(self, t.save_failed),
        }
    }

    // ---------- keys ----------

    pub(crate) fn tricks_key(&mut self, step: TrickStep, ev: KeyEvent) {
        let t = self.text().vault;
        self.notice = None;
        let list = self.trick_list();
        let count = list.iter().flatten().count();
        match step {
            TrickStep::List { sel } => match crate::pick(ev.key, sel, count as u8 + 1) {
                Pick::Move(s) => self.tr_step(TrickStep::List { sel: s }),
                Pick::Choose(i) if (i as usize) < count => self.tr_step(TrickStep::Remove { idx: i, sel: 0 }),
                Pick::Choose(_) if count >= TRICKS => self.notice = Some(t.tr_full),
                Pick::Choose(_) => self.tr_step(TrickStep::Kind { sel: 0 }),
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            TrickStep::Kind { sel } => match crate::pick(ev.key, sel, 4) {
                Pick::Move(s) => self.tr_step(TrickStep::Kind { sel: s }),
                Pick::Choose(i) => {
                    let kind = TrickKind::ALL[i as usize];
                    if !kind.has_decoy() {
                        self.tr_pin(kind, 0);
                    } else if self.decoy_sources().1 == 0 {
                        self.notice = Some(t.tr_need_seed);
                    } else {
                        self.tr_step(TrickStep::Seed { kind, sel: 0 });
                    }
                }
                Pick::Back => self.tr_step(TrickStep::List { sel: count as u8 }),
                Pick::None => {}
            },
            TrickStep::Seed { kind, sel } => {
                let (slots, n) = self.decoy_sources();
                if n == 0 {
                    self.tr_step(TrickStep::Kind { sel: 0 });
                    return;
                }
                match crate::pick(ev.key, sel.min(n as u8 - 1), n as u8) {
                    Pick::Move(s) => self.tr_step(TrickStep::Seed { kind, sel: s }),
                    Pick::Choose(i) => self.tr_pin(kind, slots[i as usize]),
                    Pick::Back => self.tr_step(TrickStep::Kind {
                        sel: TrickKind::ALL.iter().position(|k| *k == kind).unwrap_or(0) as u8,
                    }),
                    Pick::None => {}
                }
            }
            TrickStep::Remove { idx, sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.tr_step(TrickStep::Remove { idx, sel: s }),
                Pick::Choose(1) => {
                    self.tr_step(TrickStep::List { sel: 0 });
                    self.vault_queue_remove_trick(idx);
                }
                Pick::Choose(_) | Pick::Back => self.tr_step(TrickStep::List { sel: idx }),
                Pick::None => {}
            },
        }
    }

    // ---------- drawing ----------

    fn trick_label(&self, info: &TrickInfo) -> (Buf<48>, Buf<24>) {
        let t = self.text().vault;
        let label = fill("{}", &[&t.tr_kinds[info.kind as usize]]);
        let detail = if info.kind.has_decoy() {
            let fp = crate::seeds::fingerprint_hex(&info.src_fp);
            fill("{} #{}", &[&fp.as_str(), &info.index])
        } else {
            Buf::new()
        };
        (label, detail)
    }

    pub(crate) fn render_tricks(&self, c: &mut dyn Canvas, step: TrickStep) {
        let s = self.text();
        let t = s.vault;
        self.status(c, t.row_tricks);
        let w = grid::COLS * grid::CELL_W;
        let g = |row| grid::text_y(&BODY, row, 1);
        let notice = |c: &mut dyn Canvas, row: i32| {
            if let Some(n) = self.notice {
                widgets::log_line(c, MARGIN, g(row), w, Tag::Info, n, "");
            }
        };
        let hints = [("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)];
        match step {
            TrickStep::List { sel } => {
                widgets::log_line(c, MARGIN, g(2), w, Tag::Info, t.tr_note, "");
                let list = self.trick_list();
                let count = list.iter().flatten().count();
                let labels: [(Buf<48>, Buf<24>); TRICKS] = core::array::from_fn(|i| match &list[i] {
                    Some(info) => self.trick_label(info),
                    None => (Buf::new(), Buf::new()),
                });
                let items: [MenuItem; TRICKS + 1] = core::array::from_fn(|i| {
                    if i < count {
                        MenuItem {
                            label: labels[i].0.as_str(),
                            detail: labels[i].1.as_str(),
                        }
                    } else {
                        MenuItem {
                            label: t.tr_add,
                            detail: ">",
                        }
                    }
                });
                widgets::list(
                    c,
                    MARGIN,
                    g(4) - 6,
                    w,
                    4 * 52,
                    &items[..count + 1],
                    sel as usize,
                    false,
                );
                notice(c, 15);
                widgets::log_line(c, MARGIN, g(16), w, Tag::Warn, t.tr_warn, "");
                widgets::hint_bar(c, &hints);
            }
            TrickStep::Kind { sel } => {
                BODY.draw(c, MARGIN, g(2), t.tr_add, grid_text());
                let items: [MenuItem; 4] = core::array::from_fn(|i| MenuItem {
                    label: t.tr_kinds[i],
                    detail: "",
                });
                widgets::list(c, MARGIN, g(4) - 6, w, 4 * 52, &items, sel as usize, false);
                for (i, l) in t.tr_explain[sel as usize % 4].iter().enumerate() {
                    widgets::log_line(c, MARGIN, g(13 + i as i32), w, Tag::Info, l, "");
                }
                notice(c, 16);
                widgets::hint_bar(c, &hints);
            }
            TrickStep::Seed { sel, .. } => {
                BODY.draw(c, MARGIN, g(2), t.tr_pick_seed, grid_text());
                let (slots, n) = self.decoy_sources();
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
                widgets::list(c, MARGIN, g(4) - 6, w, 3 * 52, &items[..n], sel as usize, false);
                widgets::log_line(c, MARGIN, g(12), w, Tag::Info, t.tr_explain[0][1], "");
                widgets::hint_bar(c, &hints);
            }
            TrickStep::Remove { idx, sel } => {
                let list = self.trick_list();
                if let Some(info) = &list[idx as usize % TRICKS] {
                    let (label, detail) = self.trick_label(info);
                    widgets::log_line(c, MARGIN, g(2), w, Tag::Info, label.as_str(), detail.as_str());
                }
                let items = [
                    MenuItem {
                        label: t.tr_keep,
                        detail: "",
                    },
                    MenuItem {
                        label: t.tr_remove,
                        detail: "",
                    },
                ];
                widgets::list(c, MARGIN, g(4) - 6, w, 2 * 52, &items, sel as usize, false);
                widgets::hint_bar(c, &hints);
            }
        }
    }
}

fn grid_text() -> bp_hal::Rgb {
    bp_ui::theme::TEXT
}
