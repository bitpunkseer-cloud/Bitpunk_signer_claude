//! The vault on screen (M10-4): the lock screen, setting or changing the
//! PIN, locking and erasing. The work itself (`vault.rs`) runs when the
//! platform services a queued job, like microSD jobs — after the screen
//! that says what is happening has been drawn.

use crate::menus::MenuId;
use crate::vault::{self, Opened, TrickKind, VaultError, VaultHw, MAX_ATTEMPTS};
use crate::{session, typed, App, Screen};
use bp_crypto::argon2::Params;
use bp_crypto::chacha20poly1305::ct_eq;
use bp_crypto::secret::wipe;
use bp_hal::input::{Key, KeyEvent};
use bp_hal::secure::SeState;
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, DOUBLE, TITLE};
use bp_ui::widgets::{self, Tag, MARGIN, STATUS_H};
use bp_ui::{grid, theme};
use core::cell::Cell;

pub const PREFIX_MIN: usize = 4;
pub const PREFIX_MAX: usize = 8;
pub const SUFFIX_MIN: usize = 4;
pub const SUFFIX_MAX: usize = 48;

/// Steps of the vault screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VStep {
    // the lock screen
    Prefix,
    Words,
    Suffix,
    /// A vault job runs (Argon2id, the secure element, the flash).
    Working,
    /// Wrong PINs: wait before the next attempt.
    Delay,
    /// Ten wrong PINs: erased.
    Wiped,
    /// The vault cannot be opened (damaged, rolled back, hardware).
    Problem,
    // setting or changing the PIN
    Intro,
    NewPrefix,
    NewSuffix,
    AgainPrefix,
    AgainSuffix,
    Remember,
    // erasing (type WIPE)
    Wipe,
}

/// Seconds to wait before the next attempt when `used` wrong PINs are
/// counted by the secure element (decision 5: from the fourth attempt).
/// The secure element keeps the count, so a power cycle does not help.
pub fn delay_secs(used: u8) -> u32 {
    match used {
        0..=2 => 0,
        3 => 60,
        4 => 5 * 60,
        5 => 15 * 60,
        _ => 60 * 60,
    }
}

/// PIN characters, wiped when cleared or dropped.
pub struct PinBuf {
    buf: [u8; SUFFIX_MAX],
    len: usize,
}

impl PinBuf {
    const fn new() -> Self {
        Self {
            buf: [0; SUFFIX_MAX],
            len: 0,
        }
    }
    pub(crate) fn text(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }
    pub(crate) fn clear(&mut self) {
        wipe(&mut self.buf);
        self.len = 0;
    }
    /// Edit with a key; true if the key was used.
    pub(crate) fn key(&mut self, k: Key, max: usize) -> bool {
        match k {
            Key::Char(c) if (' '..='~').contains(&c) && self.len < max => {
                self.buf[self.len] = c as u8;
                self.len += 1;
                true
            }
            Key::Backspace if self.len > 0 => {
                self.len -= 1;
                self.buf[self.len] = 0;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
impl PinBuf {
    /// Nothing typed is left in it.
    pub(crate) fn is_wiped(&self) -> bool {
        self.len == 0 && self.buf.iter().all(|&b| b == 0)
    }
}

impl Drop for PinBuf {
    fn drop(&mut self) {
        wipe(&mut self.buf);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Job {
    Probe,
    Words,
    Unlock,
    Create,
    Change,
    Erase,
    /// Write the vault's records again (M10-5).
    Save,
    /// Add the trick PIN being set, or remove trick `n` (M10-6).
    AddTrick,
    RemoveTrick(u8),
    /// The tamper check words for the code typed (M10-7).
    Tamper,
}

/// What the last PIN opened (M10-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The vault itself, or nothing yet.
    Normal,
    /// A decoy trick PIN: looks open, nothing is ever written.
    Decoy,
    /// The look-blank trick PIN: a device without a vault, for this session.
    Blank,
    /// After a silent wipe: the lock screen goes on as if nothing happened.
    Fake,
}

/// A trick PIN being set: its kind, and the slot its decoy comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrickDraft {
    pub kind: TrickKind,
    pub slot: u8,
}

pub struct VaultState {
    /// Whether a vault exists; `None` until the platform answered (and on
    /// a platform without secure storage).
    pub(crate) exists: Option<bool>,
    /// Attempts left, as the secure element counts them.
    pub(crate) left: u8,
    pub(crate) unlocked: Option<vault::Unlocked>,
    job: Option<Job>,
    drawn: Cell<bool>,
    pub(crate) words: Option<[u16; 2]>,
    prefix: PinBuf,
    suffix: PinBuf,
    again_prefix: PinBuf,
    again_suffix: PinBuf,
    /// The PIN flow changes an existing PIN.
    change: bool,
    pub(crate) wrong_left: Option<u8>,
    pub(crate) problem: Option<VaultError>,
    delay_ms: u32,
    /// The KDF cost for new vaults (tests use a small one).
    pub kdf: Params,
    /// The vault's contents while it is open (M10-5).
    pub(crate) data: crate::vaultdata::VaultData,
    /// Digest of the body last read or written.
    pub(crate) saved: [u8; 32],
    /// Digest of a body that failed to save (not retried until it changes).
    pub(crate) failed: Option<[u8; 32]>,
    pub(crate) seen_slots: crate::vaultseeds::SlotsSeen,
    pub(crate) seen_wallets: crate::vaultseeds::WalletsSeen,
    /// What the last PIN opened (M10-6).
    pub(crate) mode: Mode,
    /// After a silent wipe: the key for words that look like the real ones.
    fake_key: Option<[u8; 32]>,
    /// The trick PIN being set.
    pub(crate) trick: Option<TrickDraft>,
    /// The tamper check code typed, and its words (M10-7).
    pub(crate) tamper: PinBuf,
    pub(crate) tamper_words: Option<[u16; 2]>,
    /// SHA-256 of the firmware image, from the platform (M10-7).
    pub(crate) firmware: Option<[u8; 32]>,
}

impl VaultState {
    pub const fn new() -> Self {
        Self {
            exists: None,
            left: MAX_ATTEMPTS,
            unlocked: None,
            job: Some(Job::Probe),
            drawn: Cell::new(false),
            words: None,
            prefix: PinBuf::new(),
            suffix: PinBuf::new(),
            again_prefix: PinBuf::new(),
            again_suffix: PinBuf::new(),
            change: false,
            wrong_left: None,
            problem: None,
            delay_ms: 0,
            kdf: vault::DEFAULT_KDF,
            data: crate::vaultdata::VaultData::new(),
            saved: [0; 32],
            failed: None,
            seen_slots: [None; crate::SEED_SLOTS],
            seen_wallets: ([[0; 32]; bp_bitcoin::multisig::register::MAX_WALLETS], 0),
            mode: Mode::Normal,
            fake_key: None,
            trick: None,
            tamper: PinBuf::new(),
            tamper_words: None,
            firmware: None,
        }
    }

    /// No PIN, trick PIN or check code typed is left in RAM (M10-9).
    #[cfg(test)]
    pub(crate) fn pins_wiped(&self) -> bool {
        [
            &self.prefix,
            &self.suffix,
            &self.again_prefix,
            &self.again_suffix,
            &self.tamper,
        ]
        .iter()
        .all(|b| b.is_wiped())
    }

    /// The vault is open (or a decoy PIN made it look open).
    pub(crate) fn is_open(&self) -> bool {
        self.unlocked.is_some() || self.mode == Mode::Decoy
    }

    /// A job other than the power-on probe is queued.
    pub(crate) fn pending_job(&self) -> bool {
        self.job.is_some()
    }

    fn clear_pins(&mut self) {
        self.prefix.clear();
        self.suffix.clear();
        self.again_prefix.clear();
        self.again_suffix.clear();
    }

    /// Lock: forget the keys and every PIN typed.
    pub(crate) fn lock(&mut self) {
        self.unlocked = None;
        self.clear_pins();
        self.words = None;
        self.data.clear();
        self.saved = [0; 32];
        self.failed = None;
        self.trick = None;
        self.tamper.clear();
        self.tamper_words = None;
        if self.mode == Mode::Decoy {
            self.mode = Mode::Normal;
        }
        if self.job == Some(Job::Save) {
            self.job = None;
        }
    }

    /// Power on: RAM starts empty, the parts are asked again.
    pub(crate) fn power_on(&mut self) {
        let (kdf, firmware) = (self.kdf, self.firmware);
        self.lock();
        *self = VaultState::new();
        self.kdf = kdf;
        self.firmware = firmware;
    }
}

impl Default for VaultState {
    fn default() -> Self {
        Self::new()
    }
}

/// `prefix || 0 || suffix`: the split is part of the PIN.
fn joined(prefix: &[u8], suffix: &[u8], out: &mut [u8; PREFIX_MAX + 1 + SUFFIX_MAX]) -> usize {
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()] = 0;
    out[prefix.len() + 1..prefix.len() + 1 + suffix.len()].copy_from_slice(suffix);
    prefix.len() + 1 + suffix.len()
}

/// Index of a vault problem in the message table (error codes E-VLT-nn).
pub fn problem_index(e: VaultError) -> usize {
    match e {
        VaultError::Rollback => 1,
        VaultError::Hardware => 2,
        _ => 0,
    }
}

impl App {
    fn vstep(&mut self, step: VStep) {
        self.set_current(Screen::Vault { step });
    }

    fn queue(&mut self, job: Job) {
        self.vault.job = Some(job);
        self.vault.drawn.set(false);
    }

    /// Queue writing the vault's records (after the next frame).
    pub(crate) fn vault_queue_save(&mut self) {
        self.queue(Job::Save);
    }

    /// Queue the tamper check (M10-7).
    pub(crate) fn vault_queue_tamper(&mut self) {
        self.queue(Job::Tamper);
    }

    /// Queue removing trick PIN `i` (M10-6).
    pub(crate) fn vault_queue_remove_trick(&mut self, i: u8) {
        self.queue(Job::RemoveTrick(i));
    }

    pub(crate) fn vault_clear_pins(&mut self) {
        self.vault.clear_pins();
    }

    /// The PIN typed (`prefix || 0 || suffix`) into `out`; its length.
    pub(crate) fn vault_joined_pin(&self, out: &mut [u8; PREFIX_MAX + 1 + SUFFIX_MAX]) -> usize {
        joined(self.vault.prefix.text(), self.vault.suffix.text(), out)
    }

    pub(crate) fn vault_prefix(&self) -> &[u8] {
        self.vault.prefix.text()
    }

    pub(crate) fn vault_fake_key(&self) -> Option<[u8; 32]> {
        self.vault.fake_key
    }

    pub(crate) fn vault_set_fake_key(&mut self, key: [u8; 32]) {
        self.vault.fake_key = Some(key);
    }

    pub(crate) fn vault_start_delay(&mut self) {
        self.start_delay_if_needed();
    }

    /// Called by `render`: a queued job may run once its screen is shown.
    pub(crate) fn vault_drawn(&self) {
        self.vault.drawn.set(true);
    }

    /// For the simulator page: 0 no vault, 1 locked, 2 open.
    pub fn vault_state(&self) -> u32 {
        match (self.vault.exists, self.vault.is_open()) {
            (_, true) => 2,
            (Some(true), false) => 1,
            _ => 0,
        }
    }

    /// A vault job waits for the platform.
    pub fn vault_pending(&self) -> bool {
        match self.vault.job {
            None => false,
            Some(Job::Probe) => true,
            Some(_) => self.vault.drawn.get(),
        }
    }

    /// The lock screen (or its wait) — after power on, or after Lock now.
    pub(crate) fn lock_screen(&self) -> Screen {
        let used = MAX_ATTEMPTS.saturating_sub(self.vault.left);
        if delay_secs(used) > 0 {
            Screen::Vault { step: VStep::Delay }
        } else {
            Screen::Vault { step: VStep::Prefix }
        }
    }

    fn start_delay_if_needed(&mut self) {
        let used = MAX_ATTEMPTS.saturating_sub(self.vault.left);
        self.vault.delay_ms = delay_secs(used) * 1000;
        if self.vault.delay_ms > 0 {
            self.vstep(VStep::Delay);
        } else {
            self.vstep(VStep::Prefix);
        }
    }

    /// Where the device goes after the start screen: the lock screen if a
    /// vault exists (decision 2: otherwise the stateless first-run screen).
    pub(crate) fn after_boot(&mut self) {
        if self.vault.exists == Some(true) {
            let s = self.lock_screen();
            self.vault.delay_ms = if matches!(s, Screen::Vault { step: VStep::Delay }) {
                delay_secs(MAX_ATTEMPTS.saturating_sub(self.vault.left)) * 1000
            } else {
                0
            };
            self.reset_to(s);
        } else {
            self.reset_to(Screen::Welcome { sel: 0 });
        }
    }

    /// Count down the wait between attempts.
    pub(crate) fn vault_tick(&mut self, dt_ms: u32) {
        if matches!(self.current(), Screen::Vault { step: VStep::Delay }) && self.vault.delay_ms > 0 {
            let before = self.vault.delay_ms / 1000;
            self.vault.delay_ms = self.vault.delay_ms.saturating_sub(dt_ms.min(5_000));
            if self.vault.delay_ms / 1000 != before {
                self.dirty = true;
            }
            if self.vault.delay_ms == 0 {
                self.vstep(VStep::Prefix);
            }
        }
    }

    /// Run the queued vault job with the platform's parts; `body` is the
    /// platform's buffer for the vault contents.
    pub fn vault_service(&mut self, hw: &mut VaultHw, body: &mut [u8]) {
        let Some(job) = self.vault.job.take() else { return };
        self.dirty = true;
        self.vault_run(job, hw, body);
        self.vault_after_event();
    }

    fn vault_run(&mut self, job: Job, hw: &mut VaultHw, body: &mut [u8]) {
        match job {
            Job::Probe => {
                let state = hw.se.state();
                let found = vault::scan(hw.flash, body);
                if let Ok(Some(f)) = &found {
                    // the lock screen speaks the vault's language
                    if let Some(&l) = crate::settings::Lang::ALL.get(f.header.lang as usize) {
                        self.settings.lang = l;
                    }
                }
                match (state, found) {
                    (Ok(SeState::Ready { left }), Ok(Some(_))) => {
                        self.vault.exists = Some(true);
                        self.vault.left = left;
                    }
                    (Ok(SeState::Locked), Ok(Some(_))) => {
                        self.vault.exists = Some(true);
                        self.vault.left = 0;
                    }
                    (Ok(_), Ok(_)) => self.vault.exists = Some(false),
                    _ => self.vault.exists = None,
                }
            }
            Job::Words if self.vault.mode == Mode::Fake => {
                self.vault.words = Some(self.fake_words());
                self.vstep(VStep::Words);
            }
            Job::Unlock if self.vault.mode == Mode::Fake => {
                let mut pin = [0u8; PREFIX_MAX + 1 + SUFFIX_MAX];
                let n = joined(self.vault.prefix.text(), self.vault.suffix.text(), &mut pin);
                vault::spend_an_attempt(hw, &pin[..n], self.vault.kdf);
                wipe(&mut pin);
                self.vault.clear_pins();
                self.fake_wrong();
            }
            Job::Words => {
                let words = vault::scan(hw.flash, body)
                    .ok()
                    .flatten()
                    .and_then(|found| vault::phishing_words(hw, &found, self.vault.prefix.text()).ok());
                match words {
                    Some(w) => {
                        self.vault.words = Some(w);
                        self.vstep(VStep::Words);
                    }
                    None => {
                        self.vault.problem = Some(VaultError::Hardware);
                        self.vstep(VStep::Problem);
                    }
                }
            }
            Job::Unlock => {
                let mut pin = [0u8; PREFIX_MAX + 1 + SUFFIX_MAX];
                let n = joined(self.vault.prefix.text(), self.vault.suffix.text(), &mut pin);
                let r = vault::open(hw, &pin[..n], body);
                wipe(&mut pin);
                self.vault.clear_pins();
                match r {
                    Ok(Opened::Trick { kind, decoy }) => self.vault_trick(hw, kind, decoy),
                    Ok(Opened::Vault(u, len)) => {
                        self.vault.unlocked = Some(u);
                        self.vault.left = MAX_ATTEMPTS;
                        self.vault.wrong_left = None;
                        let ok = self.vault_opened(&body[..len]);
                        wipe(&mut body[..len]);
                        if ok {
                            self.log.push(session::Event::VaultOpened, None);
                            self.reset_to(Screen::Menu {
                                id: MenuId::Main,
                                sel: 0,
                            });
                        } else {
                            self.vault.lock();
                            self.vault.problem = Some(VaultError::Corrupt);
                            self.vstep(VStep::Problem);
                        }
                    }
                    Err(VaultError::WrongPin { left }) => {
                        self.vault.left = left;
                        self.vault.wrong_left = Some(left);
                        self.start_delay_if_needed();
                    }
                    Err(VaultError::Wiped) => {
                        self.vault.exists = Some(false);
                        self.vault.left = MAX_ATTEMPTS;
                        self.vstep(VStep::Wiped);
                    }
                    Err(VaultError::NoVault) => {
                        self.vault.exists = Some(false);
                        self.reset_to(Screen::Welcome { sel: 0 });
                    }
                    Err(e) => {
                        self.vault.problem = Some(e);
                        self.vstep(VStep::Problem);
                    }
                }
            }
            Job::Create | Job::Change => {
                let mut pin = [0u8; PREFIX_MAX + 1 + SUFFIX_MAX];
                let n = joined(self.vault.prefix.text(), self.vault.suffix.text(), &mut pin);
                if job == Job::Create {
                    // a new vault keeps the settings, the registered
                    // wallets and the notes written this session (M11-6);
                    // seeds go in through the seed vault
                    let notes = self.vault.data.take_notes();
                    self.vault.data.clear();
                    for n in notes.into_iter().flatten() {
                        let _ = self.vault.data.add_note(n);
                    }
                    self.vault.seen_wallets.1 = usize::MAX;
                }
                self.vault_records();
                let len = self.vault.data.to_body(body).unwrap_or(0);
                let lang = self.settings.lang as u8;
                let r = match (job, self.vault.unlocked.as_mut()) {
                    _ if len == 0 => Err(VaultError::TooLarge),
                    // nothing real is ever written behind a trick PIN
                    (Job::Change, _) if self.vault.mode == Mode::Decoy => Ok(()),
                    (Job::Create, _) if self.vault.mode == Mode::Blank => Err(VaultError::Hardware),
                    (Job::Change, Some(u)) => {
                        u.set_lang(lang);
                        vault::change_pin(hw, u, &pin[..n], body, len)
                    }
                    _ => vault::create(hw, &pin[..n], self.vault.kdf, lang, body, len).map(|u| {
                        self.vault.unlocked = Some(u);
                    }),
                };
                wipe(&mut pin);
                wipe(&mut body[..len]);
                match r {
                    Ok(()) => {
                        self.vault.saved = self.vault.data.digest();
                        self.vault.failed = None;
                        self.vault.exists = Some(true);
                        self.vault.left = MAX_ATTEMPTS;
                        self.vault.words = vault::scan(hw.flash, body)
                            .ok()
                            .flatten()
                            .and_then(|found| {
                                vault::phishing_words(hw, &found, self.vault.prefix.text()).ok()
                            })
                            .or_else(|| Some(self.fake_words()));
                        self.vault.clear_pins();
                        self.log.push(session::Event::VaultSaved, None);
                        self.vstep(VStep::Remember);
                    }
                    Err(VaultError::PinClash) => {
                        self.vault.clear_pins();
                        self.notice = Some(self.text().vault.tr_clash);
                        self.vstep(VStep::NewPrefix);
                    }
                    Err(e) => {
                        self.vault.clear_pins();
                        self.vault.problem = Some(e);
                        self.vstep(VStep::Problem);
                    }
                }
            }
            Job::AddTrick => self.vault_add_trick(hw, body),
            Job::Tamper => self.vault_tamper_job(hw, body),
            Job::RemoveTrick(i) => {
                if let Some(u) = self.vault.unlocked.as_mut() {
                    vault::remove_trick(hw.rng, u, i as usize);
                    self.vault_save_now(hw, body);
                }
                if self.notice.is_none() {
                    self.notice = Some(self.text().vault.tr_removed);
                }
            }
            Job::Save => self.vault_save_now(hw, body),
            Job::Erase => {
                let r = vault::wipe_all(hw);
                self.vault.lock();
                match r {
                    Ok(()) => {
                        self.vault.exists = Some(false);
                        self.vault.left = MAX_ATTEMPTS;
                        self.notice = Some(self.text().vault.wiped_done);
                        self.pop();
                    }
                    Err(e) => {
                        self.vault.problem = Some(e);
                        self.vstep(VStep::Problem);
                    }
                }
            }
        }
    }

    /// Write the vault's records now (the save job, and after trick changes).
    pub(crate) fn vault_save_now(&mut self, hw: &mut VaultHw, body: &mut [u8]) {
        let digest = self.vault.data.digest();
        let Some(u) = self.vault.unlocked.as_mut() else {
            return;
        };
        u.set_lang(self.settings.lang as u8);
        let r = match self.vault.data.to_body(body) {
            Some(n) => {
                let r = vault::save(hw, u, body, n);
                wipe(&mut body[..n]);
                r
            }
            None => Err(VaultError::TooLarge),
        };
        match r {
            Ok(()) => {
                self.vault.saved = digest;
                self.vault.failed = None;
                self.log.push(session::Event::VaultSaved, None);
            }
            Err(_) => {
                self.vault.failed = Some(digest);
                self.notice = Some(self.text().vault.save_failed);
            }
        }
    }

    /// Bring the vault's records up to date with the session (wallets and
    /// settings; seeds change only through the seed vault).
    fn vault_records(&mut self) {
        self.vault.data.settings = Some(self.settings);
        self.vault_sync_now();
    }

    // ---------- menu actions (Settings > Security) ----------

    pub(crate) fn vault_pin_action(&mut self) {
        let t = self.text().vault;
        match self.vault.exists {
            None => self.notice = Some(t.no_hw),
            Some(true) if !self.vault.is_open() => self.push(self.lock_screen()),
            Some(exists) => {
                self.vault.change = exists;
                self.vault.clear_pins();
                self.push(Screen::Vault { step: VStep::Intro });
            }
        }
    }

    pub(crate) fn vault_lock_action(&mut self) {
        if self.vault.is_open() {
            self.wipe_ram();
            self.vault.lock();
            let s = self.lock_screen();
            self.reset_to(s);
        } else {
            self.notice = Some(self.text().vault.no_vault);
        }
    }

    pub(crate) fn vault_wipe_action(&mut self) {
        if self.vault.exists == Some(true) {
            self.typed.clear();
            self.push(Screen::Vault { step: VStep::Wipe });
        } else {
            self.notice = Some(self.text().vault.no_vault);
        }
    }

    // ---------- keys ----------

    pub(crate) fn vault_key(&mut self, step: VStep, ev: KeyEvent) {
        let t = self.text().vault;
        self.notice = None;
        match step {
            VStep::Prefix => match ev.key {
                Key::Enter if self.vault.prefix.len >= PREFIX_MIN => self.queue(Job::Words),
                Key::Enter => self.notice = Some(t.too_short),
                Key::Esc => self.use_without_vault(),
                // check the device before typing the PIN (M10-7)
                Key::Tab => self.vault_tamper_action(),
                k => {
                    self.vault.prefix.key(k, PREFIX_MAX);
                }
            },
            VStep::Words => match ev.key {
                Key::Enter => self.vstep(VStep::Suffix),
                Key::Esc | Key::Backspace => {
                    self.vault.clear_pins();
                    self.vault.words = None;
                    self.vstep(VStep::Prefix);
                }
                _ => {}
            },
            VStep::Suffix => match ev.key {
                Key::Enter if self.vault.suffix.len >= SUFFIX_MIN => {
                    self.vault.wrong_left = None;
                    self.vstep(VStep::Working);
                    self.queue(Job::Unlock);
                }
                Key::Enter => self.notice = Some(t.too_short),
                Key::Esc => {
                    self.vault.clear_pins();
                    self.vault.words = None;
                    self.vstep(VStep::Prefix);
                }
                k => {
                    self.vault.suffix.key(k, SUFFIX_MAX);
                }
            },
            VStep::Working => {}
            VStep::Delay => match ev.key {
                Key::Esc => self.use_without_vault(),
                Key::Tab => self.vault_tamper_action(),
                _ => {}
            },
            VStep::Wiped | VStep::Problem => {
                if matches!(ev.key, Key::Enter | Key::Esc) {
                    self.use_without_vault();
                }
            }
            VStep::Intro => match ev.key {
                Key::Enter => self.vstep(VStep::NewPrefix),
                Key::Esc | Key::Backspace => self.pop(),
                _ => {}
            },
            VStep::NewPrefix | VStep::AgainPrefix => {
                let again = step == VStep::AgainPrefix;
                match ev.key {
                    Key::Enter => {
                        let n = if again {
                            self.vault.again_prefix.len
                        } else {
                            self.vault.prefix.len
                        };
                        if n < PREFIX_MIN {
                            self.notice = Some(t.too_short);
                        } else {
                            self.vstep(if again {
                                VStep::AgainSuffix
                            } else {
                                VStep::NewSuffix
                            });
                        }
                    }
                    Key::Esc => {
                        self.vault.clear_pins();
                        self.vault.trick = None;
                        self.pop();
                    }
                    k => {
                        let b = if again {
                            &mut self.vault.again_prefix
                        } else {
                            &mut self.vault.prefix
                        };
                        b.key(k, PREFIX_MAX);
                    }
                }
            }
            VStep::NewSuffix => match ev.key {
                Key::Enter if self.vault.suffix.len >= SUFFIX_MIN => self.vstep(VStep::AgainPrefix),
                Key::Enter => self.notice = Some(t.too_short),
                Key::Esc => {
                    self.vault.suffix.clear();
                    self.vstep(VStep::NewPrefix);
                }
                k => {
                    self.vault.suffix.key(k, SUFFIX_MAX);
                }
            },
            VStep::AgainSuffix => match ev.key {
                Key::Enter if self.vault.again_suffix.len >= SUFFIX_MIN => {
                    let v = &self.vault;
                    let same = ct_eq(v.prefix.text(), v.again_prefix.text())
                        & ct_eq(v.suffix.text(), v.again_suffix.text());
                    if same {
                        self.vstep(VStep::Working);
                        self.queue(if self.vault.trick.is_some() {
                            Job::AddTrick
                        } else if self.vault.change {
                            Job::Change
                        } else {
                            Job::Create
                        });
                    } else {
                        self.vault.clear_pins();
                        self.notice = Some(t.mismatch);
                        self.vstep(VStep::NewPrefix);
                    }
                }
                Key::Enter => self.notice = Some(t.too_short),
                Key::Esc => {
                    self.vault.again_suffix.clear();
                    self.vstep(VStep::AgainPrefix);
                }
                k => {
                    self.vault.again_suffix.key(k, SUFFIX_MAX);
                }
            },
            VStep::Remember => {
                if matches!(ev.key, Key::Enter | Key::Esc) {
                    self.vault.words = None;
                    self.pop();
                }
            }
            VStep::Wipe => match self.typed.key(ev.key, typed::WIPE) {
                typed::Typed::Confirmed => {
                    self.vstep(VStep::Working);
                    self.queue(Job::Erase);
                }
                typed::Typed::Cancelled => self.pop(),
                typed::Typed::Pending => {}
            },
        }
    }

    /// Leave the lock screen for a stateless session (the vault stays locked).
    fn use_without_vault(&mut self) {
        self.vault.clear_pins();
        self.vault.words = None;
        self.reset_to(Screen::Welcome { sel: 0 });
    }

    // ---------- drawing ----------

    pub(crate) fn render_vault(&self, c: &mut dyn Canvas, step: VStep) {
        let s = self.text();
        let t = s.vault;
        let lock = matches!(
            step,
            VStep::Prefix | VStep::Words | VStep::Suffix | VStep::Delay | VStep::Wiped | VStep::Problem
        ) || (step == VStep::Working && !self.vault.is_open() && self.vault.exists == Some(true));
        let title = if lock {
            t.locked_title
        } else if self.vault.trick.is_some() {
            t.tr_title
        } else if self.vault.change {
            t.change_title
        } else {
            t.setup_title
        };
        self.status(c, if lock { t.path } else { title });
        let g = |row| grid::text_y(&BODY, row, 1);
        let w = grid::COLS * grid::CELL_W;
        let field = |c: &mut dyn Canvas, label: &str, b: &PinBuf| {
            BODY.draw(c, MARGIN, g(5), label, theme::TEXT_DIM);
            let mut stars = Buf::<64>::new();
            for _ in 0..b.len {
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
        };
        let notice = |c: &mut dyn Canvas, row: i32| {
            if let Some(left) = self.vault.wrong_left {
                let l: Buf<128> = fill(t.wrong, &[&left]);
                widgets::log_line(c, MARGIN, g(row), w, Tag::Warn, l.as_str(), "");
            }
            if let Some(n) = self.notice {
                widgets::log_line(c, MARGIN, g(row + 1), w, Tag::Warn, n, "");
            }
        };
        let words = |c: &mut dyn Canvas, row: i32| {
            if let Some([a, b]) = self.vault.words {
                let ws = bp_bitcoin::bip39::WORDS;
                let l: Buf<32> = fill("{}  {}", &[&ws[a as usize & 2047], &ws[b as usize & 2047]]);
                DOUBLE.draw(
                    c,
                    MARGIN,
                    grid::text_y(&DOUBLE, row, 2),
                    l.as_str(),
                    theme::BRIGHT,
                );
            }
        };
        if !matches!(step, VStep::Wiped | VStep::Problem | VStep::Wipe) {
            TITLE.draw(c, MARGIN, grid::text_y(&TITLE, 2, 2), title, theme::BRIGHT);
        }
        match step {
            VStep::Prefix => {
                field(c, t.prefix_label, &self.vault.prefix);
                widgets::log_line(c, MARGIN, g(10), w, Tag::Info, t.prefix_note, "");
                notice(c, 12);
                widgets::hint_bar(
                    c,
                    &[
                        ("Enter", s.rv.h_next),
                        ("Del", s.h_delete),
                        ("Tab", t.h_tamper),
                        ("Esc", t.h_without),
                    ],
                );
            }
            VStep::Words => {
                BODY.draw(c, MARGIN, g(5), t.words_title, theme::TEXT_DIM);
                words(c, 6);
                widgets::log_line(c, MARGIN, g(10), w, Tag::Info, t.words_same, "");
                widgets::log_line(c, MARGIN, g(11), w, Tag::Warn, t.words_different, "");
                widgets::hint_bar(c, &[("Enter", s.rv.h_next), ("Esc", t.h_retype)]);
            }
            VStep::Suffix => {
                field(c, t.suffix_label, &self.vault.suffix);
                words(c, 10);
                notice(c, 13);
                widgets::hint_bar(
                    c,
                    &[("Enter", t.h_unlock), ("Del", s.h_delete), ("Esc", t.h_retype)],
                );
            }
            VStep::Working => {
                BODY.draw(c, MARGIN, g(5), t.working, theme::TEXT);
                for (i, l) in t.working_lines.iter().enumerate() {
                    widgets::log_line(c, MARGIN, g(7 + i as i32), w, Tag::Pending, l, "");
                }
            }
            VStep::Delay => {
                let used = MAX_ATTEMPTS.saturating_sub(self.vault.left);
                let secs = self.vault.delay_ms.div_ceil(1000);
                let clock: Buf<8> = fill("{}:{}{}", &[&(secs / 60), &(secs % 60 / 10), &(secs % 10)]);
                let l: Buf<96> = fill(t.delay, &[&used, &clock.as_str()]);
                widgets::log_line(c, MARGIN, g(5), w, Tag::Warn, l.as_str(), "");
                DOUBLE.draw(
                    c,
                    MARGIN,
                    grid::text_y(&DOUBLE, 7, 2),
                    clock.as_str(),
                    theme::WARN,
                );
                widgets::log_line(c, MARGIN, g(10), w, Tag::Info, t.delay_note, "");
                let left: Buf<128> = fill(t.wrong, &[&self.vault.left]);
                widgets::log_line(c, MARGIN, g(11), w, Tag::Info, left.as_str(), "");
                widgets::hint_bar(c, &[("Tab", t.h_tamper), ("Esc", t.h_without)]);
            }
            VStep::Wiped => {
                widgets::message_at(c, STATUS_H + 70, t.wiped_title, theme::DANGER, &t.wiped_lines);
                widgets::hint_bar(c, &[("Enter", s.h_continue)]);
            }
            VStep::Problem => {
                let i = problem_index(self.vault.problem.unwrap_or(VaultError::Corrupt));
                self.show_error(crate::errors::Area::Vault, i);
                widgets::message_at(
                    c,
                    STATUS_H + 70,
                    t.without,
                    theme::WARN,
                    &[t.problems[i], "", t.problem_next],
                );
                widgets::hint_bar(c, &[("Enter", s.h_continue)]);
            }
            VStep::Intro => {
                for (i, l) in t.rules.iter().enumerate() {
                    widgets::log_line(c, MARGIN, g(5 + i as i32), w, Tag::Info, l, "");
                }
                widgets::hint_bar(c, &[("Enter", s.rv.h_next), ("Esc", s.h_back)]);
            }
            VStep::NewPrefix | VStep::AgainPrefix => {
                let (label, b) = if step == VStep::NewPrefix {
                    (t.new_prefix, &self.vault.prefix)
                } else {
                    (t.again_prefix, &self.vault.again_prefix)
                };
                field(c, label, b);
                notice(c, 10);
                widgets::hint_bar(
                    c,
                    &[("Enter", s.rv.h_next), ("Del", s.h_delete), ("Esc", s.h_back)],
                );
            }
            VStep::NewSuffix | VStep::AgainSuffix => {
                let (label, b) = if step == VStep::NewSuffix {
                    (t.new_suffix, &self.vault.suffix)
                } else {
                    (t.again_suffix, &self.vault.again_suffix)
                };
                field(c, label, b);
                notice(c, 10);
                widgets::hint_bar(
                    c,
                    &[("Enter", s.rv.h_next), ("Del", s.h_delete), ("Esc", s.h_back)],
                );
            }
            VStep::Remember => {
                BODY.draw(c, MARGIN, g(5), t.remember_title, theme::TEXT_DIM);
                words(c, 6);
                for (i, l) in t.remember_lines.iter().enumerate() {
                    widgets::log_line(c, MARGIN, g(10 + i as i32), w, Tag::Info, l, "");
                }
                widgets::hint_bar(c, &[("Enter", s.h_done)]);
            }
            VStep::Wipe => {
                let y = widgets::message_at(c, STATUS_H + 40, t.wipe_title, theme::DANGER, &t.wipe_lines);
                let prompt: Buf<96> = fill(s.typed_prompt, &[&typed::WIPE]);
                let wrong = self.typed.wrong.then_some(s.typed_wrong);
                widgets::typed_field(c, y + 40, prompt.as_str(), self.typed.text(), wrong);
                widgets::hint_bar(c, &[("A-Z", s.h_type), ("Enter", t.row_wipe), ("Esc", s.keep)]);
            }
        }
    }
}
