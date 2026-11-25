//! M10-4: the vault on screen — setting a PIN, the lock screen, wrong PINs,
//! the wait, erasing after ten, locking, changing and erasing (D1, D2).

use super::*;
use crate::menus::MenuId;
use crate::nav::{self, To};
use crate::sim_hw::{SimDeviceKey, SimFlash, SimSecureElement, SLOT_LEN};
use crate::vault::{VaultHw, MAX_ATTEMPTS};
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
    press(&mut a, Key::Char('2'));
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
    nav::go(&mut a, To::Menu(MenuId::Security));
    press(&mut a, Key::Char('3'));
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
        press(&mut a, Key::Char('3'));
        type_str(&mut a, "WI");
        shot(&a, "wipe");
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
