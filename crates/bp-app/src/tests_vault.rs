//! M10-4: the vault on screen — setting a PIN, the lock screen, wrong PINs,
//! the wait, erasing after ten, locking, changing and erasing (D1, D2).
//! M10-5: what it keeps — seeds stored by the user, the registered wallets
//! and the settings, back after power on.
//! M10-6: trick PINs — decoy, erase then "wrong PIN", erase then decoy,
//! look blank; none uses an attempt.

use super::*;
use crate::menus::MenuId;
use crate::nav::{self, To};
use crate::seeds::{SeedSlot, SlotKind};
use crate::sim_hw::{SimDeviceKey, SimFlash, SimSecureElement, SLOT_LEN};
use crate::vault::TrickKind;
use crate::vault::{VaultHw, MAX_ATTEMPTS};
use crate::vaultdata::StoredSeed;
use crate::vaultseeds::SeedVaultStep;
use crate::vaulttricks::TrickStep;
use crate::vaultui::VStep;
use bp_crypto::argon2::{Block, Params};
use std::vec;
use std::vec::Vec;

struct NullCanvas;
impl bp_hal::Canvas for NullCanvas {
    fn width(&self) -> u16 {
        800
    }
    fn height(&self) -> u16 {
        480
    }
    fn fill_rect(&mut self, _: i32, _: i32, _: i32, _: i32, _: bp_hal::Rgb) {}
    fn blend_pixel(&mut self, _: i32, _: i32, _: bp_hal::Rgb, _: u8) {}
}

struct TestRng(u64);
impl bp_hal::Rng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *b = self.0 as u8;
        }
    }
}

/// The device's secure storage parts, served like the firmware does.
pub(super) struct Bench {
    se: SimSecureElement,
    key: SimDeviceKey,
    flash: SimFlash,
    rng: TestRng,
    mem: Vec<Block>,
    body: Vec<u8>,
}

impl Bench {
    pub(super) fn new(chip: u64) -> Bench {
        Bench {
            se: SimSecureElement::new(chip),
            key: SimDeviceKey::new(chip),
            flash: SimFlash::new(),
            rng: TestRng(chip | 1),
            mem: vec![[0u64; 128]; 64],
            body: vec![0u8; SLOT_LEN],
        }
    }

    /// Draw, then run the queued vault jobs (the screen first, as on the device).
    pub(super) fn serve(&mut self, a: &mut App) {
        for _ in 0..8 {
            a.render(&mut NullCanvas);
            if !a.vault_pending() {
                return;
            }
            let mut hw = VaultHw {
                se: &mut self.se,
                key: &mut self.key,
                flash: &mut self.flash,
                rng: &mut self.rng,
                mem: &mut self.mem,
            };
            a.vault_service(&mut hw, &mut self.body);
        }
    }
}

const KDF: Params = Params {
    m_kib: 16,
    t: 1,
    p: 1,
};

/// A device with these parts, past the start screen.
pub(super) fn boot(b: &mut Bench) -> App {
    let mut a = App::new(b"vault tests");
    a.vault.kdf = KDF;
    b.serve(&mut a); // the probe
    a.tick(SPLASH_MS);
    a
}

fn step(a: &App) -> VStep {
    match a.current() {
        Screen::Vault { step } => step,
        s => panic!("not a vault screen: {s:?}"),
    }
}

/// Settings > Security > PIN, typed twice.
pub(super) fn set_pin(a: &mut App, b: &mut Bench, prefix: &str, suffix: &str) {
    nav::go(a, To::Menu(MenuId::Security));
    press(a, Key::Char('1'));
    assert_eq!(step(a), VStep::Intro);
    press(a, Key::Enter);
    for (p, s) in [(prefix, suffix), (prefix, suffix)] {
        type_str(a, p);
        press(a, Key::Enter);
        type_str(a, s);
        press(a, Key::Enter);
    }
    assert_eq!(step(a), VStep::Working);
    b.serve(a);
    assert_eq!(step(a), VStep::Remember);
}

/// Power off and on again: the same parts, a fresh RAM.
fn power_cycle(a: &mut App, b: &mut Bench) -> App {
    nav::go(a, To::PowerOff);
    let _ = a;
    boot(b)
}

/// Type the PIN on the lock screen.
fn unlock(a: &mut App, b: &mut Bench, prefix: &str, suffix: &str) {
    assert_eq!(step(a), VStep::Prefix);
    type_str(a, prefix);
    press(a, Key::Enter);
    b.serve(a);
    assert_eq!(step(a), VStep::Words);
    press(a, Key::Enter);
    type_str(a, suffix);
    press(a, Key::Enter);
    b.serve(a);
}

#[test]
fn without_a_vault_the_device_starts_as_before() {
    let mut b = Bench::new(1);
    let a = boot(&mut b);
    assert_eq!(a.vault.exists, Some(false));
    assert!(matches!(a.current(), Screen::Welcome { .. }));
    // no parts at all (a platform without secure storage)
    let mut a = App::new(b"x");
    a.tick(SPLASH_MS);
    assert_eq!(a.vault.exists, None);
    assert!(matches!(a.current(), Screen::Welcome { .. }));
}

#[test]
fn set_a_pin_then_unlock_after_power_on() {
    let mut b = Bench::new(2);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh12");
    let words = a.vault.words.expect("words to remember");
    press(&mut a, Key::Enter);
    assert!(matches!(
        a.current(),
        Screen::Menu {
            id: MenuId::Security,
            ..
        }
    ));
    assert_eq!(a.vault.exists, Some(true));
    assert!(a.vault.unlocked.is_some());
    // power off and on: the lock screen (D1), the same words for the prefix
    let mut a = power_cycle(&mut a, &mut b);
    assert_eq!(step(&a), VStep::Prefix);
    assert!(a.vault.unlocked.is_none());
    type_str(&mut a, "abcd");
    press(&mut a, Key::Enter);
    b.serve(&mut a);
    assert_eq!(a.vault.words, Some(words), "the words seen at setup");
    press(&mut a, Key::Enter);
    type_str(&mut a, "efgh12");
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), VStep::Working, "the work is shown before it runs");
    b.serve(&mut a);
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
    assert!(a.vault.unlocked.is_some());
    assert_eq!(
        a.log.latest().next().unwrap().event,
        crate::session::Event::VaultOpened
    );
    // another prefix gives other words
    let mut a = power_cycle(&mut a, &mut b);
    type_str(&mut a, "abce");
    press(&mut a, Key::Enter);
    b.serve(&mut a);
    assert_ne!(a.vault.words, Some(words));
}

#[test]
fn wrong_pins_count_wait_and_erase_on_the_tenth() {
    let mut b = Bench::new(3);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    let mut a = power_cycle(&mut a, &mut b);
    // three wrong: no wait yet
    for left in [9u8, 8, 7] {
        unlock(&mut a, &mut b, "abcd", "wrong");
        assert_eq!(a.vault.wrong_left, Some(left));
        if left > 7 {
            assert_eq!(step(&a), VStep::Prefix);
        }
    }
    // the fourth attempt waits a minute; keys do nothing but Esc
    assert_eq!(step(&a), VStep::Delay);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), VStep::Delay);
    for _ in 0..59 {
        a.tick(1000);
    }
    assert_eq!(step(&a), VStep::Delay);
    a.tick(1000);
    assert_eq!(step(&a), VStep::Prefix);
    // turning the power off does not skip the wait
    let mut a = power_cycle(&mut a, &mut b);
    assert_eq!(step(&a), VStep::Delay);
    // the right PIN after the wait opens, and the count starts over
    for _ in 0..60 {
        a.tick(1000);
    }
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert!(a.vault.unlocked.is_some());
    assert_eq!(a.vault.left, MAX_ATTEMPTS);
    // ten wrong in a row (waiting each time): erased for good
    let mut a = power_cycle(&mut a, &mut b);
    for _ in 0..MAX_ATTEMPTS {
        for _ in 0..3600 {
            if step(&a) != VStep::Delay {
                break;
            }
            a.tick(1000);
        }
        unlock(&mut a, &mut b, "abcd", "wrong");
    }
    assert_eq!(step(&a), VStep::Wiped);
    assert_eq!(a.vault.exists, Some(false));
    press(&mut a, Key::Enter);
    assert!(matches!(a.current(), Screen::Welcome { .. }));
    let a = power_cycle(&mut a, &mut b);
    assert!(matches!(a.current(), Screen::Welcome { .. }), "no vault any more");
}

#[test]
fn pin_rules_and_mismatch() {
    let mut b = Bench::new(4);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    nav::go(&mut a, To::Menu(MenuId::Security));
    press(&mut a, Key::Char('1'));
    press(&mut a, Key::Enter);
    type_str(&mut a, "abc");
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), VStep::NewPrefix, "too short");
    assert_eq!(a.notice, Some(a.text().vault.too_short));
    type_str(&mut a, "d123456789");
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), VStep::NewSuffix, "kept to 8 characters");
    type_str(&mut a, "wxyz");
    press(&mut a, Key::Enter);
    type_str(&mut a, "abcd1234");
    press(&mut a, Key::Enter);
    type_str(&mut a, "wxyZ");
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), VStep::NewPrefix, "different: start again");
    assert_eq!(a.notice, Some(a.text().vault.mismatch));
    assert_eq!(a.vault.exists, Some(false), "nothing was made");
}

#[test]
fn lock_now_change_pin_and_erase() {
    let mut b = Bench::new(5);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    // Lock now: RAM is wiped, the lock screen comes
    nav::go(&mut a, To::VaultLock);
    assert_eq!(step(&a), VStep::Prefix);
    assert_eq!(a.seed_count(), 0);
    unlock(&mut a, &mut b, "abcd", "efgh");
    // change the PIN
    nav::go(&mut a, To::Menu(MenuId::Security));
    set_pin(&mut a, &mut b, "wxyz", "9876");
    press(&mut a, Key::Enter);
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.wrong_left, Some(9), "the old PIN no longer opens");
    unlock(&mut a, &mut b, "wxyz", "9876");
    assert!(a.vault.unlocked.is_some());
    // erase: type WIPE
    nav::go(&mut a, To::VaultWipe);
    assert_eq!(step(&a), VStep::Wipe);
    type_str(&mut a, "WIPE");
    press(&mut a, Key::Enter);
    b.serve(&mut a);
    assert_eq!(a.vault.exists, Some(false));
    assert!(a.vault.unlocked.is_none());
    assert!(matches!(
        a.current(),
        Screen::Menu {
            id: MenuId::Security,
            ..
        }
    ));
    let a = power_cycle(&mut a, &mut b);
    assert!(matches!(a.current(), Screen::Welcome { .. }));
}

#[test]
fn esc_on_the_lock_screen_is_a_session_without_the_vault() {
    let mut b = Bench::new(6);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    let mut a = power_cycle(&mut a, &mut b);
    press(&mut a, Key::Esc);
    assert!(matches!(a.current(), Screen::Welcome { .. }));
    assert_eq!(a.vault.exists, Some(true), "the vault stays");
    assert!(a.vault.unlocked.is_none());
    // Security > PIN while locked: the lock screen first
    nav::home(&mut a);
    nav::go(&mut a, To::Menu(MenuId::Security));
    press(&mut a, Key::Char('1'));
    assert_eq!(step(&a), VStep::Prefix);
}

#[test]
fn a_broken_secure_element_is_a_problem_with_a_code() {
    let mut b = Bench::new(7);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    let mut a = power_cycle(&mut a, &mut b);
    type_str(&mut a, "abcd");
    press(&mut a, Key::Enter);
    b.se.broken = true;
    b.serve(&mut a);
    assert_eq!(step(&a), VStep::Problem);
    a.render(&mut NullCanvas);
    assert_eq!(a.err_code.get(), Some((crate::errors::Area::Vault, 2)));
    press(&mut a, Key::Enter);
    assert!(matches!(a.current(), Screen::Welcome { .. }));
}

/// Every vault step drawn in both languages (screen tour, M9 coverage).
#[test]
pub(crate) fn vault_screens_fit() {
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(format!("vault-{l}-{name}.ppm")));
            }
        };
        let mut b = Bench::new(40 + lang as u64);
        let mut a = boot(&mut b);
        a.settings.lang = lang;
        a.set_test_only(true);
        nav::home(&mut a);
        nav::go(&mut a, To::Menu(MenuId::Security));
        shot(&a, "menu");
        press(&mut a, Key::Char('1'));
        shot(&a, "intro");
        press(&mut a, Key::Enter);
        type_str(&mut a, "ab");
        press(&mut a, Key::Enter);
        shot(&a, "new-prefix-short");
        type_str(&mut a, "cd");
        press(&mut a, Key::Enter);
        type_str(&mut a, "efgh");
        shot(&a, "new-suffix");
        press(&mut a, Key::Enter);
        type_str(&mut a, "abcd");
        shot(&a, "again-prefix");
        press(&mut a, Key::Enter);
        type_str(&mut a, "efgh");
        shot(&a, "again-suffix");
        press(&mut a, Key::Enter);
        shot(&a, "working");
        b.serve(&mut a);
        shot(&a, "remember");
        press(&mut a, Key::Enter);
        nav::go(&mut a, To::VaultWipe);
        type_str(&mut a, "WI");
        shot(&a, "wipe");
        press(&mut a, Key::Esc);
        // the seed vault (M10-5)
        load_abandon(&mut a);
        nav::go(&mut a, To::SeedVault);
        shot(&a, "sv-list-empty");
        press(&mut a, Key::Enter);
        assert_eq!(sv(&a), SeedVaultStep::Pick { sel: 0 });
        shot(&a, "sv-pick");
        press(&mut a, Key::Enter);
        shot(&a, "sv-list");
        b.serve(&mut a);
        press(&mut a, Key::Char('1'));
        shot(&a, "sv-seed");
        press(&mut a, Key::Char('2'));
        type_str(&mut a, "WI");
        shot(&a, "sv-remove");
        press(&mut a, Key::Esc);
        // trick PINs (M10-6)
        nav::go(&mut a, To::VaultTricks);
        shot(&a, "tr-list-empty");
        press(&mut a, Key::Char('1'));
        shot(&a, "tr-kind");
        press(&mut a, Key::Char('1'));
        shot(&a, "tr-seed");
        press(&mut a, Key::Char('1'));
        type_str(&mut a, "zz");
        shot(&a, "tr-pin");
        press(&mut a, Key::Esc);
        add_trick(&mut a, &mut b, '4', None, "zzzz", "4444");
        add_trick(&mut a, &mut b, '1', Some('1'), "yyyy", "1111");
        shot(&a, "tr-list");
        press(&mut a, Key::Char('2'));
        shot(&a, "tr-remove");
        press(&mut a, Key::Esc);
        // the lock screen
        nav::go(&mut a, To::PowerOff);
        let mut a = boot(&mut b);
        a.settings.lang = lang;
        a.set_test_only(true);
        type_str(&mut a, "abcd");
        shot(&a, "prefix");
        press(&mut a, Key::Enter);
        b.serve(&mut a);
        shot(&a, "words");
        press(&mut a, Key::Enter);
        type_str(&mut a, "wro");
        shot(&a, "suffix");
        for _ in 0..3 {
            type_str(&mut a, "ng");
            press(&mut a, Key::Enter);
            b.serve(&mut a);
            if step(&a) == VStep::Prefix {
                shot(&a, "prefix-wrong");
                type_str(&mut a, "abcd");
                press(&mut a, Key::Enter);
                b.serve(&mut a);
                press(&mut a, Key::Enter);
                type_str(&mut a, "wro");
            }
        }
        a.tick(1500);
        shot(&a, "delay");
        b.se.broken = true;
        nav::go(&mut a, To::PowerOff);
        let mut a = boot(&mut b);
        a.settings.lang = lang;
        b.se.broken = false;
        // the probe failed: no vault known, the first-run screen
        assert!(matches!(a.current(), Screen::Welcome { .. }));
        // a problem screen and the erased screen
        a.vault.problem = Some(crate::vault::VaultError::Corrupt);
        a.push(Screen::Vault { step: VStep::Problem });
        shot(&a, "problem");
        a.set_current(Screen::Vault { step: VStep::Wiped });
        shot(&a, "wiped");
    }
}

// ---------- M10-5: what the vault keeps ----------

fn sv(a: &App) -> SeedVaultStep {
    match a.current() {
        Screen::SeedVault { step } => step,
        s => panic!("not the seed vault: {s:?}"),
    }
}

/// Seed vault > Store a loaded seed > the first one offered.
fn store_first(a: &mut App, b: &mut Bench) {
    nav::go(a, To::SeedVault);
    let n = a.vault.data.seed_count();
    press(a, Key::Char((b'1' + n as u8) as char));
    assert_eq!(sv(a), SeedVaultStep::Pick { sel: 0 });
    press(a, Key::Enter);
    b.serve(a);
}

fn xprv_slot(i: u8) -> SeedSlot {
    SeedSlot::from_xprv(bp_bitcoin::bip32::Xpriv::master(&[i; 32]).unwrap())
}

#[test]
fn stored_seeds_come_back_after_power_on() {
    let mut b = Bench::new(11);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    // no vault yet
    nav::go(&mut a, To::SeedVault);
    assert_eq!(a.notice, Some(a.text().vault.sv_no_vault));
    load_abandon(&mut a);
    let fp = a.slot(0).unwrap().fingerprint;
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    assert_eq!(a.vault.data.seed_count(), 0, "seeds go in only when stored");
    store_first(&mut a, &mut b);
    assert_eq!(sv(&a), SeedVaultStep::List { sel: 0 });
    assert_eq!(a.vault.data.seed_count(), 1);
    assert_eq!(
        a.log.latest().next().unwrap().event,
        crate::session::Event::VaultSaved
    );
    // nothing more to store
    press(&mut a, Key::Char('2'));
    assert_eq!(a.notice, Some(a.text().vault.sv_nothing));
    // power off and on: the seed is loaded again once the vault opens
    let mut a = power_cycle(&mut a, &mut b);
    assert_eq!(a.seed_count(), 0);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.seed_count(), 1);
    assert_eq!(a.slot(0).unwrap().fingerprint, fp);
    // locked again: the seed vault asks for the PIN first
    nav::go(&mut a, To::VaultLock);
    assert_eq!(a.seed_count(), 0);
    nav::go(&mut a, To::SeedVault);
    assert_eq!(step(&a), VStep::Prefix);
}

#[test]
fn keys_and_passphrase_seeds_keep_their_fingerprint() {
    let mut b = Bench::new(12);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    let m = bp_bitcoin::bip39::Mnemonic::from_entropy(&[0u8; 16]).unwrap();
    a.seeds[0] = SeedSlot::new(m, b"my passphrase");
    a.seeds[1] = Some(xprv_slot(7));
    a.seeds[2] = SeedSlot::from_wif(&bp_crypto::secp256k1::SecretKey::from_bytes(&[9u8; 32]).unwrap());
    let fps: Vec<[u8; 4]> = a.seeds.iter().flatten().map(|s| s.fingerprint).collect();
    store_first(&mut a, &mut b);
    assert_eq!(
        a.notice,
        Some(a.text().vault.sv_stored_pass),
        "the passphrase is not stored"
    );
    store_first(&mut a, &mut b);
    store_first(&mut a, &mut b);
    assert_eq!(a.vault.data.seed_count(), 3);
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    let m = bp_bitcoin::bip39::Mnemonic::from_entropy(&[0u8; 16]).unwrap();
    let words_only = SeedSlot::new(m, b"").unwrap().fingerprint;
    let back: Vec<([u8; 4], SlotKind, bool)> = a
        .seeds
        .iter()
        .flatten()
        .map(|s| (s.fingerprint, s.kind, s.has_passphrase()))
        .collect();
    assert_eq!(
        back,
        vec![
            (words_only, SlotKind::Mnemonic, false),
            (fps[1], SlotKind::Xprv, false),
            (fps[2], SlotKind::Wif, false),
        ]
    );
    assert_ne!(words_only, fps[0]);
}

#[test]
fn the_list_loads_removes_and_counts_eight() {
    let mut b = Bench::new(13);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    for i in 0..8 {
        assert!(a
            .vault
            .data
            .add_seed(StoredSeed::from_slot(&xprv_slot(i + 1)).unwrap()));
    }
    nav::home(&mut a); // any key: the change is saved
    b.serve(&mut a);
    // full: nothing more goes in
    a.seeds[0] = Some(xprv_slot(50));
    nav::go(&mut a, To::SeedVault);
    press(&mut a, Key::Char('9'));
    assert_eq!(a.notice, Some(a.text().vault.sv_full));
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.seed_count(), 3, "the first three fill the slots");
    nav::go(&mut a, To::SeedVault);
    // the fourth: no free slot
    press(&mut a, Key::Char('4'));
    press(&mut a, Key::Char('1'));
    assert_eq!(a.current(), Screen::SlotsFull);
    // the first: already loaded
    nav::go(&mut a, To::SeedVault);
    press(&mut a, Key::Char('1'));
    press(&mut a, Key::Char('1'));
    assert_eq!(a.notice, Some(a.text().vault.sv_already));
    // remove the fourth (type WIPE); the others keep their order
    press(&mut a, Key::Esc);
    press(&mut a, Key::Char('4'));
    press(&mut a, Key::Char('2'));
    assert_eq!(sv(&a), SeedVaultStep::Remove { idx: 3 });
    type_str(&mut a, "WIPE");
    press(&mut a, Key::Enter);
    b.serve(&mut a);
    assert_eq!(a.vault.data.seed_count(), 7);
    let want = xprv_slot(5).fingerprint;
    assert_eq!(a.vault.data.seed(3).unwrap().fp, want);
    // a free slot: the list loads a stored seed
    a.seeds[2] = None;
    nav::go(&mut a, To::SeedVault);
    press(&mut a, Key::Char('4'));
    press(&mut a, Key::Char('1'));
    assert!(matches!(a.current(), Screen::SeedReady { .. }));
    assert_eq!(a.slot(2).unwrap().fingerprint, want);
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.data.seed_count(), 7, "the removal was saved");
}

#[test]
fn settings_are_kept_and_the_lock_screen_speaks_their_language() {
    let mut b = Bench::new(14);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    let units = a.settings.units;
    nav::go(&mut a, To::Setting(|s| s.units));
    assert_ne!(a.settings.units, units);
    a.settings.lang = crate::settings::Lang::Ko;
    a.render(&mut NullCanvas);
    assert!(
        !a.vault_pending(),
        "nothing is written while in the Settings menu"
    );
    press(&mut a, Key::Esc);
    a.render(&mut NullCanvas);
    assert!(a.vault_pending(), "leaving the Settings menu saves them");
    b.serve(&mut a);
    let mut a = power_cycle(&mut a, &mut b);
    assert_eq!(
        a.settings.lang,
        crate::settings::Lang::Ko,
        "the lock screen in Korean"
    );
    assert_eq!(a.settings.units, units, "the rest waits for the PIN");
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_ne!(a.settings.units, units);
}

#[test]
fn wallets_register_again_for_their_seed() {
    use super::wallets_flow::{register_quick, wallet_of};
    use bp_bitcoin::multisig::MsScript;
    let mut b = Bench::new(15);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    store_first(&mut a, &mut b);
    let w = wallet_of(&a, MsScript::Wsh, 2, 3);
    register_quick(&mut a, &w);
    b.serve(&mut a);
    assert_eq!(a.vault.data.wallets().count(), 1);
    let (tag, code) = {
        let e = a.wallets.get(0).unwrap();
        (e.tag, e.code)
    };
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.wallets.len(), 1, "registered again without the code");
    let e = a.wallets.iter().next().unwrap().1;
    assert_eq!((e.tag, e.code, e.slot), (tag, code, 0));
    // the seed leaves RAM: its wallet stays in the vault
    a.push(Screen::Confirm {
        what: Confirm::DiscardSeed(0),
        sel: 1,
    });
    type_str(&mut a, "wipe");
    press(&mut a, Key::Enter);
    b.serve(&mut a);
    assert!(a.wallets.is_empty());
    assert_eq!(a.vault.data.wallets().count(), 1);
    // loading the seed from the vault brings the wallet back
    nav::go(&mut a, To::SeedVault);
    press(&mut a, Key::Char('1'));
    press(&mut a, Key::Char('1'));
    b.serve(&mut a);
    assert_eq!(a.wallets.len(), 1);
    // removed while its seed is loaded: it leaves the vault
    let idx = a.wallets.iter().next().unwrap().0 as u8;
    a.wallets.remove(idx);
    nav::home(&mut a);
    b.serve(&mut a);
    assert_eq!(a.vault.data.wallets().count(), 0);
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert!(a.wallets.is_empty());
}

#[test]
fn a_failed_save_is_reported_once_and_retried_on_the_next_change() {
    let mut b = Bench::new(16);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    b.se.broken = true;
    store_first(&mut a, &mut b);
    assert_eq!(a.notice, Some(a.text().vault.save_failed));
    nav::home(&mut a);
    a.render(&mut NullCanvas);
    assert!(!a.vault_pending(), "not retried until something changes");
    b.se.broken = false;
    a.seeds[1] = Some(xprv_slot(3));
    store_first(&mut a, &mut b);
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.data.seed_count(), 2);
}

// ---------- M10-6: trick PINs ----------

fn tricks_set(a: &App) -> usize {
    a.vault
        .unlocked
        .as_ref()
        .map_or(0, |u| crate::vault::tricks(u).iter().flatten().count())
}

/// Security > Trick PINs > Add: kind row (1-4), the decoy's seed row, the PIN twice.
fn add_trick(a: &mut App, b: &mut Bench, kind: char, seed: Option<char>, prefix: &str, suffix: &str) {
    nav::go(a, To::VaultTricks);
    let n = tricks_set(a);
    press(a, Key::Char((b'1' + n as u8) as char));
    assert!(matches!(
        a.current(),
        Screen::Tricks {
            step: TrickStep::Kind { .. }
        }
    ));
    press(a, Key::Char(kind));
    if let Some(s) = seed {
        assert!(matches!(
            a.current(),
            Screen::Tricks {
                step: TrickStep::Seed { .. }
            }
        ));
        press(a, Key::Char(s));
    }
    assert_eq!(step(a), VStep::NewPrefix);
    for _ in 0..2 {
        type_str(a, prefix);
        press(a, Key::Enter);
        type_str(a, suffix);
        press(a, Key::Enter);
    }
    assert_eq!(step(a), VStep::Working);
    b.serve(a);
}

fn decoy_fp(a: &App, index: u32) -> [u8; 4] {
    let d = bp_bitcoin::bip85::derive(
        a.slot(0).unwrap().master(),
        bp_bitcoin::bip85::App::Bip39 { words: 12 },
        index,
        a.settings.network,
    )
    .unwrap();
    let bp_bitcoin::bip85::Derived::Mnemonic(m) = &d else {
        unreachable!()
    };
    let mut e = [0u8; 32];
    let n = m.entropy(&mut e);
    let m = bp_bitcoin::bip39::Mnemonic::from_entropy(&e[..n]).unwrap();
    SeedSlot::new(m, b"").unwrap().fingerprint
}

fn se_left(b: &mut Bench) -> Option<u8> {
    use bp_hal::secure::{SeState, SecureElement};
    match b.se.state().unwrap() {
        SeState::Ready { left } => Some(left),
        _ => None,
    }
}

#[test]
fn a_decoy_pin_opens_a_decoy_seed_and_uses_no_attempt() {
    use bp_hal::secure::SecureElement;
    let mut b = Bench::new(21);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    let real = a.slot(0).unwrap().fingerprint;
    let decoy = decoy_fp(&a, 1001);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    store_first(&mut a, &mut b);
    add_trick(&mut a, &mut b, '1', Some('1'), "zzzz", "1111");
    assert_eq!(a.notice, Some(a.text().vault.tr_added));
    let t = crate::vault::tricks(a.vault.unlocked.as_ref().unwrap());
    assert_eq!(
        t[0].map(|t| (t.kind, t.src_fp, t.index)),
        Some((TrickKind::Decoy, real, 1001))
    );
    // the trick PIN on the lock screen: the decoy seed, no attempt used
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "zzzz", "1111");
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
    assert_eq!(a.vault_state(), 2, "looks open");
    assert_eq!(a.seed_count(), 1);
    assert_eq!(a.slot(0).unwrap().fingerprint, decoy);
    assert_eq!(se_left(&mut b), Some(MAX_ATTEMPTS));
    // nothing behind it is written, though it looks saved
    let counter = b.se.counter().unwrap();
    nav::go(&mut a, To::Setting(|s| s.units));
    nav::home(&mut a);
    b.serve(&mut a);
    assert_eq!(b.se.counter().unwrap(), counter);
    assert_eq!(
        a.log.latest().next().unwrap().event,
        crate::session::Event::VaultSaved
    );
    nav::go(&mut a, To::VaultTricks);
    assert_eq!(tricks_set(&a), 0, "no trick PINs to see");
    // the vault's own PIN still opens the real seed
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.slot(0).unwrap().fingerprint, real);
    assert_eq!(tricks_set(&a), 1);
    // the trick survives a PIN change
    nav::go(&mut a, To::Menu(MenuId::Security));
    set_pin(&mut a, &mut b, "wxyz", "9876");
    press(&mut a, Key::Enter);
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "zzzz", "1111");
    assert_eq!(a.slot(0).unwrap().fingerprint, decoy);
}

#[test]
fn an_erase_trick_erases_then_looks_like_a_wrong_pin() {
    let mut b = Bench::new(22);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    add_trick(&mut a, &mut b, '2', None, "zzzz", "2222");
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "zzzz", "2222");
    assert_eq!(step(&a), VStep::Prefix);
    assert_eq!(a.vault.wrong_left, Some(9), "looks like a wrong PIN");
    assert_eq!(se_left(&mut b), None, "the secure element's secret is gone");
    assert!(crate::vault::scan(&mut b.flash, &mut b.body).unwrap().is_none());
    // the lock screen goes on: words still come, every PIN is "wrong"
    let words = {
        type_str(&mut a, "abcd");
        press(&mut a, Key::Enter);
        b.serve(&mut a);
        assert_eq!(step(&a), VStep::Words);
        a.vault.words
    };
    press(&mut a, Key::Esc);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.wrong_left, Some(8));
    assert!(words.is_some());
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(step(&a), VStep::Delay, "the waits come as before");
    let a = power_cycle(&mut a, &mut b);
    assert!(matches!(a.current(), Screen::Welcome { .. }), "no vault any more");
}

#[test]
fn an_erase_then_decoy_trick_opens_the_decoy() {
    let mut b = Bench::new(23);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    let decoy = decoy_fp(&a, 1001);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    add_trick(&mut a, &mut b, '3', Some('1'), "zzzz", "3333");
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "zzzz", "3333");
    assert_eq!(a.vault_state(), 2);
    assert_eq!(a.slot(0).unwrap().fingerprint, decoy);
    assert_eq!(se_left(&mut b), None, "erased first");
    let a = power_cycle(&mut a, &mut b);
    assert!(matches!(a.current(), Screen::Welcome { .. }));
}

#[test]
fn a_blank_trick_starts_like_a_device_without_a_vault() {
    let mut b = Bench::new(24);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    store_first(&mut a, &mut b);
    add_trick(&mut a, &mut b, '4', None, "zzzz", "4444");
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "zzzz", "4444");
    assert!(matches!(a.current(), Screen::Welcome { .. }));
    assert_eq!(a.vault_state(), 0);
    assert_eq!(a.seed_count(), 0);
    nav::home(&mut a);
    nav::go(&mut a, To::SeedVault);
    assert_eq!(a.notice, Some(a.text().vault.sv_no_vault));
    // setting a PIN here never touches the real vault
    nav::go(&mut a, To::Menu(MenuId::Security));
    press(&mut a, Key::Char('1'));
    press(&mut a, Key::Enter);
    for _ in 0..2 {
        type_str(&mut a, "qqqq");
        press(&mut a, Key::Enter);
        type_str(&mut a, "rrrr");
        press(&mut a, Key::Enter);
    }
    b.serve(&mut a);
    assert_eq!(step(&a), VStep::Problem);
    assert_eq!(
        se_left(&mut b),
        Some(MAX_ATTEMPTS),
        "nothing erased, no attempt used"
    );
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.seed_count(), 1, "the vault was there all along");
}

#[test]
fn trick_pins_must_differ_and_are_three_at_most() {
    let mut b = Bench::new(25);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    // the vault's own PIN cannot be a trick PIN
    add_trick(&mut a, &mut b, '4', None, "abcd", "efgh");
    assert_eq!(step(&a), VStep::NewPrefix);
    assert_eq!(a.notice, Some(a.text().vault.tr_clash));
    press(&mut a, Key::Esc);
    add_trick(&mut a, &mut b, '2', None, "zzzz", "2222");
    assert_eq!(tricks_set(&a), 1);
    // nor two tricks the same PIN
    add_trick(&mut a, &mut b, '4', None, "zzzz", "2222");
    assert_eq!(a.notice, Some(a.text().vault.tr_clash));
    press(&mut a, Key::Esc);
    add_trick(&mut a, &mut b, '4', None, "yyyy", "4444");
    add_trick(&mut a, &mut b, '4', None, "xxxx", "4444");
    assert_eq!(tricks_set(&a), 3);
    nav::go(&mut a, To::VaultTricks);
    press(&mut a, Key::Char('4'));
    assert_eq!(a.notice, Some(a.text().vault.tr_full));
    // the vault's PIN cannot become a trick PIN either
    nav::go(&mut a, To::Menu(MenuId::Security));
    press(&mut a, Key::Char('1'));
    press(&mut a, Key::Enter);
    for _ in 0..2 {
        type_str(&mut a, "zzzz");
        press(&mut a, Key::Enter);
        type_str(&mut a, "2222");
        press(&mut a, Key::Enter);
    }
    b.serve(&mut a);
    assert_eq!(step(&a), VStep::NewPrefix);
    assert_eq!(a.notice, Some(a.text().vault.tr_clash));
    press(&mut a, Key::Esc);
    // remove the first (the erase trick): it is an ordinary wrong PIN again
    nav::go(&mut a, To::VaultTricks);
    press(&mut a, Key::Char('1'));
    assert!(matches!(
        a.current(),
        Screen::Tricks {
            step: TrickStep::Remove { idx: 0, .. }
        }
    ));
    press(&mut a, Key::Char('2'));
    b.serve(&mut a);
    assert_eq!(a.notice, Some(a.text().vault.tr_removed));
    assert_eq!(tricks_set(&a), 2);
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "zzzz", "2222");
    assert_eq!(a.vault.wrong_left, Some(9));
    assert_eq!(se_left(&mut b), Some(9), "a real attempt");
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(tricks_set(&a), 2);
}
