//! OTP codes (M11-7): a typed key, an otpauth QR, the time typed by hand,
//! HOTP counters, refusals, kept by the vault, and every step drawn in both
//! languages.

extern crate std;

use super::vault_flow::{boot, power_cycle, set_pin, unlock, Bench};
use super::*;
use crate::menus::MenuId;
use crate::nav::{self, To};
use crate::otpui::OtpStep;
use bp_backup::otp::{self, Algorithm, OtpKind};
use bp_hal::input::Key;

/// RFC 4226 / 6238's SHA-1 key "12345678901234567890" in Base32.
const RFC_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn app() -> App {
    let mut a = App::new(b"test quiz seed");
    a.tick(SPLASH_MS);
    nav::home(&mut a);
    a
}

fn press(a: &mut App, k: Key) {
    a.on_key(KeyEvent::new(k));
}

fn type_str(a: &mut App, s: &str) {
    for ch in s.chars() {
        press(a, Key::Char(ch));
    }
}

fn step(a: &App) -> OtpStep {
    match a.current() {
        Screen::Otp { step } => step,
        s => panic!("not an OTP screen: {s:?}"),
    }
}

/// The list's fixed rows after the keys: scan, type, time.
fn row(a: &mut App, k: usize) {
    let n = a.vault.data.otp_count();
    for _ in 0..n + k {
        press(a, Key::Down);
    }
    press(a, Key::Enter);
}

/// Type a key and its name, then Add.
fn type_key(a: &mut App, key: &str, name: &str) {
    nav::go(a, To::Otp);
    row(a, 1);
    assert_eq!(step(a), OtpStep::Type { name: false });
    type_str(a, key);
    press(a, Key::Enter);
    assert_eq!(step(a), OtpStep::Type { name: true });
    type_str(a, name);
    press(a, Key::Enter);
    assert_eq!(step(a), OtpStep::Add { sel: 0 });
    press(a, Key::Enter);
}

/// Set the clock from the list ("YYYYMMDDHHMM").
fn set_time(a: &mut App, digits: &str) {
    nav::go(a, To::Otp);
    row(a, 2);
    assert_eq!(step(a), OtpStep::Time);
    type_str(a, digits);
    press(a, Key::Enter);
}

#[test]
fn a_typed_key_gives_the_rfc_codes_once_the_time_is_set() {
    let mut a = app();
    type_key(&mut a, &RFC_KEY.to_lowercase(), "RFC test");
    assert_eq!(step(&a), OtpStep::Code { idx: 0 });
    let k = a.vault.data.otp_key(0).unwrap();
    assert_eq!(k.secret(), b"12345678901234567890");
    assert_eq!(
        (k.kind, k.alg, k.digits),
        (OtpKind::Totp { period: 30 }, Algorithm::Sha1, 6)
    );
    assert_eq!(k.label(), "RFC test");
    // no clock yet: Enter goes to setting it
    assert!(a.now().is_none());
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), OtpStep::Time);
    type_str(&mut a, "203305180333");
    press(&mut a, Key::Enter);
    assert_eq!(a.now(), Some(2_000_000_000 - 20));
    assert_eq!(a.notice, Some(a.text().bk.otp_time_set));
    // the clock runs with the ticks: at 2 000 000 000, RFC 6238's code
    a.tick(5_000);
    a.tick(5_000);
    a.tick(5_000);
    a.tick(5_000);
    assert_eq!(a.now(), Some(2_000_000_000));
    let k = a.vault.data.otp_key(0).unwrap();
    assert_eq!(k.code(a.now().unwrap()), 69279037 % 1_000_000);
    // power off forgets the time (no clock battery)
    nav::go(&mut a, To::PowerOff);
    assert!(a.now().is_none());
}

#[test]
fn an_otpauth_qr_adds_a_hotp_key_whose_counter_moves() {
    let mut a = app();
    nav::go(&mut a, To::Otp);
    row(&mut a, 0);
    assert_eq!(
        a.current(),
        Screen::Scan {
            purpose: scan::Purpose::Otp
        }
    );
    a.on_qr_text(std::format!("otpauth://hotp/Bank:bob?secret={RFC_KEY}&counter=3&issuer=Bank").as_bytes());
    assert_eq!(step(&a), OtpStep::Add { sel: 0 });
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), OtpStep::Code { idx: 0 });
    let code = |a: &App| a.vault.data.otp_key(0).unwrap().code(0);
    assert_eq!(code(&a), 969429); // RFC 4226, counter 3
    press(&mut a, Key::Enter);
    assert_eq!(code(&a), 338314); // counter 4
    assert_eq!(
        a.vault.data.otp_key(0).unwrap().kind,
        OtpKind::Hotp { counter: 4 }
    );
    // the same key again is refused
    press(&mut a, Key::Esc);
    row(&mut a, 0);
    a.on_qr_text(std::format!("otpauth://hotp/Bank:bob?secret={RFC_KEY}&counter=3").as_bytes());
    press(&mut a, Key::Enter);
    assert_eq!(a.notice, Some(a.text().bk.otp_dup));
    assert_eq!(a.vault.data.otp_count(), 1);
    // something that is not an otpauth key: said, nothing added
    row(&mut a, 0);
    a.on_qr_text(b"https://example.com/2fa");
    assert_eq!(step(&a), OtpStep::List { sel: 0 });
    assert_eq!(a.notice, Some(a.text().bk.otp_errors[0]));
    // delete: Del, then WIPE
    press(&mut a, Key::Enter);
    press(&mut a, Key::Backspace);
    assert_eq!(step(&a), OtpStep::Delete { idx: 0 });
    type_str(&mut a, "WIPE");
    press(&mut a, Key::Enter);
    assert_eq!(a.vault.data.otp_count(), 0);
}

#[test]
fn bad_keys_and_times_are_refused() {
    let mut a = app();
    nav::go(&mut a, To::Otp);
    row(&mut a, 1);
    type_str(&mut a, "GEZD1");
    press(&mut a, Key::Enter);
    assert_eq!(a.notice, Some(a.text().bk.otp_errors[1]));
    for _ in 0..5 {
        press(&mut a, Key::Backspace);
    }
    type_str(&mut a, "GEZDGNBV");
    press(&mut a, Key::Enter);
    assert_eq!(a.notice, Some(a.text().bk.otp_errors[2]), "5 bytes: too short");
    assert_eq!(step(&a), OtpStep::Type { name: false });
    press(&mut a, Key::Esc);
    // times: not a date, too early, not finished
    for bad in ["202502290000", "202301010000", "2026112612", "202613010000"] {
        set_time(&mut a, bad);
        assert_eq!(step(&a), OtpStep::Time, "{bad}");
        assert_eq!(a.notice, Some(a.text().bk.otp_time_bad));
        assert!(a.now().is_none());
        press(&mut a, Key::Esc);
    }
    set_time(&mut a, "202611261200");
    assert_eq!(a.now(), otp::unix_time(2026, 11, 26, 12, 0));
}

#[test]
fn keys_are_kept_by_the_vault() {
    let mut b = Bench::new(71);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    type_key(&mut a, RFC_KEY, "before");
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    b.serve(&mut a);
    let mut a = power_cycle(&mut a, &mut b);
    assert_eq!(a.vault.data.otp_count(), 0);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.data.otp_count(), 1);
    // an HOTP counter that moved is saved
    nav::home(&mut a);
    nav::go(&mut a, To::Otp);
    row(&mut a, 0);
    a.on_qr_text(std::format!("otpauth://hotp/h?secret={RFC_KEY}&counter=0").as_bytes());
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter);
    b.serve(&mut a);
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.data.otp_count(), 2);
    assert_eq!(
        a.vault.data.otp_key(1).unwrap().kind,
        OtpKind::Hotp { counter: 2 }
    );
    let _ = MenuId::Main;
}

/// Every OTP step drawn in both languages (screen tour).
#[test]
pub(crate) fn otp_screens_fit() {
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(std::format!("otp-{l}-{name}.ppm")));
            }
        };
        let mut a = app();
        a.settings.lang = lang;
        a.set_test_only(true);
        nav::go(&mut a, To::Otp);
        shot(&a, "list-empty");
        row(&mut a, 1);
        type_str(&mut a, RFC_KEY);
        shot(&a, "type-key");
        press(&mut a, Key::Enter);
        type_str(&mut a, "Exchange:alice@example.com");
        shot(&a, "type-name");
        press(&mut a, Key::Enter);
        shot(&a, "add");
        press(&mut a, Key::Enter);
        shot(&a, "code-no-time");
        press(&mut a, Key::Enter);
        type_str(&mut a, "2026112");
        shot(&a, "time");
        type_str(&mut a, "61200");
        press(&mut a, Key::Enter);
        shot(&a, "list");
        press(&mut a, Key::Enter);
        shot(&a, "code-totp");
        press(&mut a, Key::Esc);
        row(&mut a, 0);
        shot(&a, "scan");
        a.on_qr_text(std::format!("otpauth://hotp/Bank:bob?secret={RFC_KEY}&counter=3&digits=8").as_bytes());
        shot(&a, "add-hotp");
        press(&mut a, Key::Enter);
        shot(&a, "code-hotp");
        press(&mut a, Key::Backspace);
        type_str(&mut a, "WI");
        shot(&a, "delete");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('?'));
        shot(&a, "help");
    }
}
