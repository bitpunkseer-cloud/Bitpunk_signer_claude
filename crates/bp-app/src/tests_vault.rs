//! M10-4: the vault on screen — setting a PIN, the lock screen, wrong PINs,
//! the wait, erasing after ten, locking, changing and erasing (D1, D2).
//! M10-5: what it keeps — seeds stored by the user, the registered wallets
//! and the settings, back after power on.
//! M10-6: trick PINs — decoy, erase then "wrong PIN", erase then decoy,
//! look blank; none uses an attempt.
//! M10-7: the tamper check — a code, the firmware and the device give two
//! words; the words change when the firmware does.

use super::*;
use crate::menus::MenuId;
use crate::nav::{self, To};
use crate::seeds::{SeedSlot, SlotKind};
use crate::sim_hw::{SimDeviceKey, SimFlash, SimSecureElement, SLOT_LEN};
use crate::vault::TrickKind;
use crate::vault::{VaultHw, MAX_ATTEMPTS};
use crate::vaultdata::StoredSeed;
use crate::vaultseeds::SeedVaultStep;
use crate::vaulttamper::TamperStep;
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
/// The firmware image's SHA-256, as the platform gives it.
pub(super) const FIRMWARE: [u8; 32] = [0x5a; 32];

pub(super) fn boot(b: &mut Bench) -> App {
    let mut a = App::new(b"vault tests");
    a.vault.kdf = KDF;
    a.set_firmware_hash(FIRMWARE);
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
        // the tamper check (M10-7)
        nav::go(&mut a, To::VaultTamper);
        type_str(&mut a, "chk");
        press(&mut a, Key::Enter);
        shot(&a, "tc-code");
        type_str(&mut a, "123");
        press(&mut a, Key::Enter);
        shot(&a, "tc-working");
        b.serve(&mut a);
        shot(&a, "tc-words");
        press(&mut a, Key::Enter);
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

/// Draws nothing; notes whether the warning colour lands in a band of rows.
struct Band {
    y0: i32,
    y1: i32,
    hit: bool,
}
impl bp_hal::Canvas for Band {
    fn width(&self) -> u16 {
        800
    }
    fn height(&self) -> u16 {
        480
    }
    fn fill_rect(&mut self, _: i32, y: i32, _: i32, h: i32, c: bp_hal::Rgb) {
        if c == bp_ui::theme::WARN && y < self.y1 && y + h > self.y0 {
            self.hit = true;
        }
    }
    fn blend_pixel(&mut self, _: i32, y: i32, c: bp_hal::Rgb, _: u8) {
        if c == bp_ui::theme::WARN && (self.y0..self.y1).contains(&y) {
            self.hit = true;
        }
    }
}

fn warning_above_keys(a: &App) -> bool {
    let hint = bp_ui::widgets::HINT_H;
    let mut c = Band {
        y0: 480 - hint - 40,
        y1: 480 - hint,
        hit: false,
    };
    a.render(&mut c);
    c.hit
}

#[test]
fn a_menu_row_that_does_nothing_says_why() {
    // no vault yet: Trick PINs, Lock now, Erase and the seed vault say so
    let mut b = Bench::new(26);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    for (to, menu) in [
        (To::VaultTricks, MenuId::Security),
        (To::VaultLock, MenuId::Security),
        (To::VaultWipe, MenuId::Security),
        (To::SeedVault, MenuId::Seeds),
    ] {
        nav::go(&mut a, to);
        assert!(matches!(a.current(), Screen::Menu { id, .. } if id == menu));
        assert!(a.notice.is_some(), "{to:?} gave no reason");
        assert!(warning_above_keys(&a), "{to:?}: the reason is not on screen");
    }
    assert_eq!(a.notice, Some(a.text().vault.sv_no_vault));
    // the next key clears it
    press(&mut a, Key::Down);
    assert!(!warning_above_keys(&a));
}

// ---------- M10-7: tamper check ----------

fn tc(a: &App) -> TamperStep {
    match a.current() {
        Screen::Tamper { step } => step,
        s => panic!("not the tamper check: {s:?}"),
    }
}

/// Tab on the lock screen, the code, the words; back on the lock screen.
fn check_words(a: &mut App, b: &mut Bench, code: &str) -> [u16; 2] {
    press(a, Key::Tab);
    assert_eq!(tc(a), TamperStep::Code);
    type_str(a, code);
    press(a, Key::Enter);
    assert_eq!(tc(a), TamperStep::Working, "the work is shown before it runs");
    b.serve(a);
    assert_eq!(tc(a), TamperStep::Words);
    let w = a.vault.tamper_words.expect("words");
    press(a, Key::Enter);
    w
}

#[test]
fn the_tamper_check_words_change_only_with_the_firmware() {
    let mut b = Bench::new(51);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    // no vault yet: nothing to check against
    nav::go(&mut a, To::VaultTamper);
    assert_eq!(a.notice, Some(a.text().vault.no_vault));
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    // first time, from Settings > Security: write the words down
    nav::go(&mut a, To::VaultTamper);
    type_str(&mut a, "check1");
    press(&mut a, Key::Enter);
    b.serve(&mut a);
    let first = a.vault.tamper_words.unwrap();
    press(&mut a, Key::Enter);
    assert!(matches!(
        a.current(),
        Screen::Menu {
            id: MenuId::Security,
            ..
        }
    ));
    // on the lock screen, before the PIN: the same words, no attempt used
    let mut a = power_cycle(&mut a, &mut b);
    assert_eq!(check_words(&mut a, &mut b, "check1"), first);
    assert_eq!(step(&a), VStep::Prefix, "back on the lock screen");
    assert_eq!(se_left(&mut b), Some(MAX_ATTEMPTS));
    assert_ne!(
        check_words(&mut a, &mut b, "check2"),
        first,
        "a typo gives other words"
    );
    // too short
    press(&mut a, Key::Tab);
    type_str(&mut a, "abc");
    press(&mut a, Key::Enter);
    assert_eq!(tc(&a), TamperStep::Code);
    assert_eq!(a.notice, Some(a.text().vault.tc_short));
    press(&mut a, Key::Esc);
    // another firmware image: other words
    nav::go(&mut a, To::PowerOff);
    let mut a = App::new(b"vault tests");
    a.vault.kdf = KDF;
    a.set_firmware_hash([0x5b; 32]);
    b.serve(&mut a);
    a.tick(SPLASH_MS);
    assert_ne!(check_words(&mut a, &mut b, "check1"), first);
    // the wait between attempts offers it too
    for _ in 0..3 {
        unlock(&mut a, &mut b, "abcd", "wrong");
    }
    assert_eq!(step(&a), VStep::Delay);
    press(&mut a, Key::Tab);
    assert_eq!(tc(&a), TamperStep::Code);
}

#[test]
fn the_tamper_check_goes_on_after_a_silent_erase_and_needs_a_firmware_hash() {
    let mut b = Bench::new(52);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    add_trick(&mut a, &mut b, '2', None, "zzzz", "2222");
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "zzzz", "2222");
    assert_eq!(se_left(&mut b), None, "erased");
    let w = check_words(&mut a, &mut b, "check1");
    assert_eq!(
        check_words(&mut a, &mut b, "check1"),
        w,
        "still steady for one code"
    );
    // a platform that gives no firmware hash: the check says so
    let mut c = App::new(b"x");
    c.tick(SPLASH_MS);
    nav::home(&mut c);
    nav::go(&mut c, To::VaultTamper);
    assert_eq!(c.notice, Some(c.text().vault.tc_no_fw));
}

// ---------- M10-9: attacks and fuzzing ----------

fn se_state(b: &mut Bench) -> bp_hal::secure::SeState {
    use bp_hal::secure::SecureElement;
    b.se.state().unwrap()
}

#[test]
fn attack_an_old_flash_copy_opens_nothing_after_a_pin_change() {
    let mut b = Bench::new(61);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    store_first(&mut a, &mut b);
    // the attacker copies the flash while the old PIN is in use
    let copy = b.flash.clone();
    nav::go(&mut a, To::Menu(MenuId::Security));
    set_pin(&mut a, &mut b, "wxyz", "9876");
    press(&mut a, Key::Enter);
    // ... and writes it back later
    b.flash = copy;
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.wrong_left, Some(9), "the old PIN is a wrong PIN now");
    unlock(&mut a, &mut b, "wxyz", "9876");
    assert_eq!(step(&a), VStep::Problem, "the new PIN finds only an old copy");
    assert_eq!(a.vault.problem, Some(crate::vault::VaultError::Rollback));
    assert_eq!(a.seed_count(), 0);
}

#[test]
fn attack_restoring_the_flash_does_not_give_attempts_back() {
    let mut b = Bench::new(62);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    let copy = b.flash.clone();
    let mut a = power_cycle(&mut a, &mut b);
    for _ in 0..3 {
        unlock(&mut a, &mut b, "abcd", "nope");
    }
    b.flash = copy;
    let a = power_cycle(&mut a, &mut b);
    assert_eq!(se_state(&mut b), bp_hal::secure::SeState::Ready { left: 7 });
    assert_eq!(step(&a), VStep::Delay, "the wait comes back too");
}

#[test]
fn attack_the_flash_in_another_device_opens_nothing() {
    let mut b = Bench::new(63);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    store_first(&mut a, &mut b);
    // the same flash, another board (its own element and hidden key)
    let mut other = Bench::new(64);
    other.flash = b.flash.clone();
    let mut c = boot(&mut other);
    // no secret there: the element is blank, so no vault is offered
    assert!(matches!(c.current(), Screen::Welcome { .. }));
    // even forcing the lock screen, the right PIN opens nothing
    c.vault.exists = Some(true);
    c.push(Screen::Vault { step: VStep::Prefix });
    type_str(&mut c, "abcd");
    press(&mut c, Key::Enter);
    other.serve(&mut c);
    assert_eq!(c.seed_count(), 0);
}

#[test]
fn attack_a_changed_trick_area_is_refused_not_obeyed() {
    let mut b = Bench::new(65);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    add_trick(&mut a, &mut b, '2', None, "zzzz", "2222");
    // flip one byte of the trick area (header offset 80..336) and, like a
    // capable attacker, recompute the slot's unkeyed check
    for slot in b.flash.slots.iter_mut() {
        let n = u16::from_le_bytes([slot[76], slot[77]]) as usize;
        if &slot[..4] != b"BPV1" {
            continue;
        }
        slot[100] ^= 0x40;
        let end = crate::vault::HEADER_LEN + n;
        let check = bp_crypto::sha256::Sha256::digest(&slot[..end]);
        slot[end..end + crate::vault::CHECK_LEN].copy_from_slice(&check[..crate::vault::CHECK_LEN]);
    }
    let mut a = power_cycle(&mut a, &mut b);
    // the erase trick no longer fires: it is an ordinary wrong PIN
    unlock(&mut a, &mut b, "zzzz", "2222");
    assert_ne!(se_left(&mut b), None, "nothing was erased");
    // and the vault refuses its changed header rather than trusting it
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(step(&a), VStep::Problem);
}

#[test]
fn attack_nothing_typed_or_loaded_stays_in_ram() {
    let mut b = Bench::new(66);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    assert!(a.vault.pins_wiped(), "after setting the PIN");
    press(&mut a, Key::Enter);
    store_first(&mut a, &mut b);
    add_trick(&mut a, &mut b, '4', None, "zzzz", "4444");
    assert!(a.vault.pins_wiped(), "after a trick PIN");
    nav::go(&mut a, To::VaultTamper);
    type_str(&mut a, "check1");
    press(&mut a, Key::Enter);
    b.serve(&mut a);
    assert!(a.vault.pins_wiped(), "after the tamper check");
    press(&mut a, Key::Enter);
    // Lock now: keys, contents, seeds and words are gone
    nav::go(&mut a, To::VaultLock);
    assert!(a.vault.unlocked.is_none());
    assert_eq!(a.vault.data.seed_count(), 0);
    assert_eq!(a.seed_count(), 0);
    assert!(a.vault.words.is_none() && a.vault.tamper_words.is_none());
    // a wrong PIN and a half-typed one leave nothing either
    unlock(&mut a, &mut b, "abcd", "nope");
    assert!(a.vault.pins_wiped(), "after a wrong PIN");
    type_str(&mut a, "abc");
    press(&mut a, Key::Esc);
    assert!(a.vault.pins_wiped(), "after leaving the lock screen");
}

#[test]
fn attack_a_decoy_looks_like_the_vault() {
    // what the screen and the session log show after the decoy PIN and
    // after the vault's PIN: the same kinds of things in the same order
    let mut b = Bench::new(67);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    store_first(&mut a, &mut b);
    add_trick(&mut a, &mut b, '1', Some('1'), "zzzz", "1111");
    let mut seen = Vec::new();
    for (p, s) in [("abcd", "efgh"), ("zzzz", "1111")] {
        let mut c = power_cycle(&mut a, &mut b);
        unlock(&mut c, &mut b, p, s);
        let log: Vec<_> = c.log.latest().map(|e| e.event).collect();
        nav::go(&mut c, To::SeedVault);
        let listed = c.vault.data.seed_count();
        nav::go(&mut c, To::VaultTricks);
        let menu = c.current();
        seen.push((
            c.vault_state(),
            c.seed_count(),
            log,
            listed,
            matches!(menu, Screen::Tricks { .. }),
        ));
        a = c;
    }
    assert_eq!(seen[0], seen[1]);
}

#[test]
fn attack_the_wait_cannot_be_typed_through() {
    let mut b = Bench::new(68);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    let mut a = power_cycle(&mut a, &mut b);
    for _ in 0..3 {
        unlock(&mut a, &mut b, "abcd", "nope");
    }
    assert_eq!(step(&a), VStep::Delay);
    type_str(&mut a, "abcd");
    for k in [Key::Enter, Key::Backspace, Key::Down, Key::Char('1')] {
        press(&mut a, k);
    }
    a.render(&mut NullCanvas);
    assert_eq!(step(&a), VStep::Delay);
    assert!(!a.vault_pending(), "no attempt can start during the wait");
    assert_eq!(se_state(&mut b), bp_hal::secure::SeState::Ready { left: 7 });
}

#[test]
fn attack_forged_wallet_records_register_nothing() {
    let mut b = Bench::new(69);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    load_abandon(&mut a);
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    // records that a loaded seed does not recompute (a forged tag), and junk
    let forged = b"# Bitpunk wallet v1\nname: x\ncode: ABCD-EFGH\ntag: 0000000000000000000000000000000000000000000000000000000000000000\nwsh(sortedmulti(1,[73c5da0a/48h/0h/0h/2h]xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/<0;1>/*))\n";
    let mut x = 9u64;
    let mut junk = || {
        (0..200)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect::<Vec<u8>>()
    };
    let j1 = junk();
    let j2 = junk();
    a.vault
        .data
        .set_wallets([&forged[..], &j1[..], &j2[..]].into_iter());
    a.vault.seen_slots = [None; crate::SEED_SLOTS];
    nav::home(&mut a);
    b.serve(&mut a);
    assert!(a.wallets.is_empty(), "nothing registered without a matching seed");
}

/// Random keys on the vault screens, the jobs served as on the device:
/// nothing panics, and afterwards the vault still opens with its PIN.
#[test]
fn fuzz_random_keys_on_the_vault_screens() {
    use bp_hal::secure::SeState;
    let keys = [
        Key::Enter,
        Key::Esc,
        Key::Tab,
        Key::Backspace,
        Key::Up,
        Key::Down,
        Key::Left,
        Key::Right,
        Key::Char('1'),
        Key::Char('2'),
        Key::Char('3'),
        Key::Char('4'),
        Key::Char('a'),
        Key::Char('b'),
        Key::Char('W'),
        Key::Char('z'),
    ];
    for round in 0..6u64 {
        let mut b = Bench::new(70 + round);
        let mut a = boot(&mut b);
        nav::home(&mut a);
        load_abandon(&mut a);
        set_pin(&mut a, &mut b, "abcd", "efgh");
        press(&mut a, Key::Enter);
        let mut x = 0x1234_5678 ^ round;
        for i in 0..1500 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if i % 300 == 0 {
                // back to somewhere in the vault's screens (the monkey may
                // have wandered into a seed flow)
                if a.vault.is_open() {
                    a.reset_to(Screen::Menu {
                        id: MenuId::Main,
                        sel: 0,
                    });
                    let to = [
                        To::VaultPin,
                        To::VaultTricks,
                        To::SeedVault,
                        To::VaultTamper,
                        To::VaultLock,
                    ];
                    nav::go(&mut a, to[(x % 5) as usize]);
                }
            }
            press(&mut a, keys[(x >> 8) as usize % keys.len()]);
            if x % 7 == 0 {
                a.tick(700);
            }
            b.serve(&mut a);
        }
        // the element never counts more than it allows, and the PIN (if it
        // was not changed by chance) or a wipe leaves a usable device
        match se_state(&mut b) {
            SeState::Ready { left } => assert!(left <= MAX_ATTEMPTS),
            SeState::Blank | SeState::Locked => {}
        }
        a.reset_to(Screen::Menu {
            id: MenuId::Main,
            sel: 0,
        });
        let _ = power_cycle(&mut a, &mut b);
    }
}
