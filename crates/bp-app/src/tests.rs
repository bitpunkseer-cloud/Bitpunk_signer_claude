//! Flow tests: drive the app with key events like a user would.

use super::*;
extern crate std;
use crate::menus::Start;
use crate::nav::{self, To};
use bp_bitcoin::bip39::WORDS;
use bp_hal::input::Key;
use std::string::String;

fn app() -> App {
    let mut a = App::new(b"test quiz seed");
    a.tick(SPLASH_MS);
    nav::home(&mut a); // past the first-run screen (M9-4)
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

/// Main > Seeds > Create new seed > (Dice|Coin) > 12 words > intro
fn open_create(a: &mut App, coin: bool, words24: bool) {
    nav::go(a, To::Start(if coin { Start::Coin } else { Start::Dice }));
    nav::words(a, if words24 { 24 } else { 12 });
    assert_eq!(a.current(), Screen::EntropyIntro);
    press(a, Key::Enter);
    assert_eq!(a.current(), Screen::EntropyEntry);
}

/// Main > Scan QR.
fn scan_any(a: &mut App) {
    nav::go(a, To::Scan(scan::Purpose::Any));
}

/// Seeds > Load seed > Type words > `n` words.
fn open_typed(a: &mut App, n: usize) {
    nav::go(a, To::Start(Start::TypeWords));
    nav::words(a, n);
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Enter fair dice rolls until every check passes.
fn roll_until_ready(a: &mut App, seed: u64) {
    let mut rng = XorShift(seed);
    for _ in 0..400 {
        let pe = a.flow.as_ref().unwrap().entropy.as_ref().unwrap();
        if pe.analyze().all_pass() {
            return;
        }
        press(a, Key::Char((b'1' + (rng.next() % 6) as u8) as char));
    }
    panic!("never became ready");
}

fn answer_all(a: &mut App, wrong_at: Option<usize>) {
    loop {
        let Screen::Quiz { .. } = a.current() else { return };
        let q = &a.flow.as_ref().unwrap().quiz;
        let right = q.answer[q.q];
        let choice = if Some(q.q) == wrong_at {
            (right + 1) % 4
        } else {
            right
        };
        press(a, Key::Char((b'1' + choice) as char));
    }
}

#[test]
fn splash_times_out_to_the_first_run_screen_then_main() {
    let mut a = App::new(b"x");
    assert_eq!(a.current(), Screen::Splash);
    a.tick(SPLASH_MS);
    // M9-4 (C3): principles, language and network first
    assert_eq!(a.current(), Screen::Welcome { sel: 0 });
    press(&mut a, Key::Enter); // Start
    assert_eq!(
        a.current(),
        Screen::Menu {
            id: MenuId::Main,
            sel: 0
        }
    );
}

#[test]
fn first_run_screen_sets_language_and_network() {
    let mut a = App::new(b"x");
    a.tick(SPLASH_MS);
    press(&mut a, Key::Char('2')); // language
    assert_eq!(a.settings.lang, settings::Lang::Ko);
    press(&mut a, Key::Left);
    assert_eq!(a.settings.lang, settings::Lang::En);
    press(&mut a, Key::Down); // network
    let before = a.settings.network;
    press(&mut a, Key::Right);
    assert_ne!(a.settings.network, before);
    press(&mut a, Key::Esc); // Esc also starts
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
    // power off, power on: the first-run screen again (nothing is stored)
    nav::go(&mut a, To::PowerOff);
    press(&mut a, Key::Enter);
    a.tick(SPLASH_MS);
    assert_eq!(a.current(), Screen::Welcome { sel: 0 });
}

#[test]
fn session_log_records_what_happened_and_power_off_wipes_it() {
    use crate::session::Event;
    let mut a = app();
    a.settings.saver = 2; // no screen saver while the clock runs
    assert!(a.log.is_empty());
    for _ in 0..65 {
        a.tick(1000);
    }
    load_abandon(&mut a);
    nav::seed_opt(&mut a, keys::SlotOpt::Xpub);
    nav::script(&mut a, ScriptType::NativeSegwit);
    press(&mut a, Key::Char('1'));
    let events: std::vec::Vec<_> = a.log.latest().map(|e| (e.event, e.fingerprint)).collect();
    assert_eq!(
        events,
        [
            (Event::XpubShown, Some([0x73, 0xc5, 0xda, 0x0a])),
            (Event::SeedLoaded, Some([0x73, 0xc5, 0xda, 0x0a])),
        ]
    );
    assert!(a.log.latest().last().unwrap().secs >= 65, "time since power on");
    // shown under the main menu
    nav::home(&mut a);
    a.render(&mut layout_free::Null);
    nav::go(&mut a, To::PowerOff);
    assert!(a.log.is_empty());
}

mod layout_free {
    pub struct Null;
    impl bp_hal::Canvas for Null {
        fn width(&self) -> u16 {
            800
        }
        fn height(&self) -> u16 {
            480
        }
        fn fill_rect(&mut self, _: i32, _: i32, _: i32, _: i32, _: bp_hal::Rgb) {}
        fn blend_pixel(&mut self, _: i32, _: i32, _: bp_hal::Rgb, _: u8) {}
    }
}

#[test]
fn enter_is_blocked_until_checks_pass() {
    let mut a = app();
    open_create(&mut a, false, false);
    type_str(&mut a, "3615243"); // far too few
    press(&mut a, Key::Enter);
    assert_eq!(a.current(), Screen::EntropyEntry);
    assert!(a.notice.is_some());
}

#[test]
fn patterned_dice_cannot_create_a_seed() {
    let mut a = app();
    open_create(&mut a, false, false);
    type_str(&mut a, &"123456".repeat(12));
    let an = a.flow.as_ref().unwrap().entropy.as_ref().unwrap().analyze();
    assert!(an.any_fail());
    press(&mut a, Key::Enter);
    assert_eq!(a.current(), Screen::EntropyEntry);
    assert_eq!(a.seed_count(), 0);
}

#[test]
fn alternating_coins_cannot_create_a_seed() {
    let mut a = app();
    open_create(&mut a, true, false);
    type_str(&mut a, &"HT".repeat(70));
    press(&mut a, Key::Enter);
    assert_eq!(a.current(), Screen::EntropyEntry);
    assert_eq!(a.seed_count(), 0);
}

#[test]
fn dice_flow_creates_seed_only_after_full_quiz() {
    let mut a = app();
    open_create(&mut a, false, false);
    roll_until_ready(&mut a, 7);
    press(&mut a, Key::Enter);
    assert_eq!(a.current(), Screen::EntropySummary);
    press(&mut a, Key::Enter); // warning
    press(&mut a, Key::Enter); // words
    assert_eq!(a.current(), Screen::ShowWords { view: None });
    press(&mut a, Key::Enter); // quiz intro
    press(&mut a, Key::Enter); // quiz
    assert_eq!(a.seed_count(), 0, "no seed before the quiz is passed");
    let n = a.flow.as_ref().unwrap().quiz.n;
    assert_eq!(n, 12, "every word is asked");
    answer_all(&mut a, None);
    assert_eq!(a.seed_count(), 1);
    assert!(matches!(a.current(), Screen::SeedReady { created: true, .. }));
}

#[test]
fn one_wrong_answer_fails_the_quiz_and_creates_nothing() {
    let mut a = app();
    open_create(&mut a, false, false);
    roll_until_ready(&mut a, 11);
    for _ in 0..4 {
        press(&mut a, Key::Enter); // summary, warning, words, quiz intro
    }
    press(&mut a, Key::Enter);
    answer_all(&mut a, Some(5));
    assert!(matches!(a.current(), Screen::QuizFailed { .. }));
    assert_eq!(a.seed_count(), 0);
    // retry path: review words, retake and pass
    press(&mut a, Key::Char('1'));
    assert_eq!(a.current(), Screen::ShowWords { view: None });
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter);
    answer_all(&mut a, None);
    assert_eq!(a.seed_count(), 1);
}

#[test]
fn discard_after_failed_quiz_wipes_flow() {
    let mut a = app();
    open_create(&mut a, false, false);
    roll_until_ready(&mut a, 13);
    for _ in 0..5 {
        press(&mut a, Key::Enter);
    }
    answer_all(&mut a, Some(0));
    press(&mut a, Key::Char('2'));
    assert!(a.flow.is_none());
    assert_eq!(a.seed_count(), 0);
    assert!(matches!(
        a.current(),
        Screen::Menu {
            id: MenuId::Seeds,
            ..
        }
    ));
}

#[test]
fn typed_words_load_with_autocomplete() {
    let mut a = app();
    open_typed(&mut a, 12);
    assert_eq!(a.current(), Screen::WordEntry);
    // "aban" auto-completes to "abandon" (unique 4-letter prefix)
    for _ in 0..11 {
        type_str(&mut a, "aban");
    }
    type_str(&mut a, "abou"); // about
                              // every word once more before loading (M11-5, E3)
    assert_eq!(a.current(), Screen::WordReview { sel: 0 });
    assert_eq!(a.seed_count(), 0);
    press(&mut a, Key::Enter);
    assert_eq!(a.seed_count(), 1);
    assert!(matches!(a.current(), Screen::SeedReady { created: false, .. }));
}

#[test]
fn full_words_and_prefixes_both_work() {
    let mut a = app();
    open_typed(&mut a, 12);
    // mix of full words (with spaces) and 4-letter prefixes
    for i in 0..11 {
        if i % 2 == 0 {
            type_str(&mut a, "abandon ");
        } else {
            type_str(&mut a, "aban");
        }
    }
    type_str(&mut a, "about");
    press(&mut a, Key::Enter);
    assert_eq!(a.seed_count(), 1);
}

#[test]
fn checksum_error_lets_user_fix_a_word() {
    let mut a = app();
    open_typed(&mut a, 12);
    for _ in 0..12 {
        type_str(&mut a, "aban");
    }
    assert_eq!(a.current(), Screen::ChecksumError { sel: 0 });
    // select the 12th word: column-major grid, 3 rows -> Left wraps
    for _ in 0..11 {
        press(&mut a, Key::Down);
    }
    press(&mut a, Key::Enter);
    assert_eq!(a.current(), Screen::WordEntry);
    type_str(&mut a, "abou");
    press(&mut a, Key::Enter);
    assert_eq!(a.seed_count(), 1);
}

#[test]
fn three_letter_word_needs_enter() {
    let mut a = app();
    open_typed(&mut a, 12);
    type_str(&mut a, "act");
    let e = &a.flow.as_ref().unwrap().entry;
    assert!(!e.filled[0], "act is a prefix of action/actor: wait for Enter");
    press(&mut a, Key::Enter);
    let e = &a.flow.as_ref().unwrap().entry;
    assert_eq!(WORDS[e.idx[0] as usize], "act");
}

#[test]
fn word_numbers_entry() {
    let mut a = app();
    nav::go(&mut a, To::Start(Start::WordNumbers));
    nav::words(&mut a, 12);
    for _ in 0..11 {
        type_str(&mut a, "1");
        press(&mut a, Key::Enter);
    }
    type_str(&mut a, "4"); // "about" is word #4
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter);
    assert_eq!(a.seed_count(), 1);
}

#[test]
fn escape_from_entry_asks_before_wiping() {
    let mut a = app();
    open_create(&mut a, false, false);
    type_str(&mut a, "1234");
    press(&mut a, Key::Esc);
    assert!(matches!(
        a.current(),
        Screen::Confirm {
            what: Confirm::CancelFlow,
            ..
        }
    ));
    press(&mut a, Key::Char('1')); // keep
    assert_eq!(a.current(), Screen::EntropyEntry);
    assert_eq!(a.flow.as_ref().unwrap().entropy.as_ref().unwrap().len(), 4);
    press(&mut a, Key::Esc);
    press(&mut a, Key::Char('2')); // discard
    assert!(a.flow.is_none());
}

#[test]
fn power_off_wipes_seeds() {
    let mut a = app();
    open_typed(&mut a, 12);
    for _ in 0..11 {
        type_str(&mut a, "aban");
    }
    type_str(&mut a, "abou");
    press(&mut a, Key::Enter);
    assert_eq!(a.seed_count(), 1);
    press(&mut a, Key::Esc);
    a.reset_to(Screen::Menu {
        id: MenuId::Main,
        sel: 0,
    });
    nav::go(&mut a, To::PowerOff);
    assert_eq!(a.current(), Screen::PoweredOff);
    assert_eq!(a.seed_count(), 0);
}

#[test]
fn network_setting_cycles() {
    let mut a = app();
    nav::select_setting(&mut a, |s| s.network);
    let before = a.settings.network;
    press(&mut a, Key::Right);
    assert_ne!(a.settings.network, before);
}

#[test]
fn language_setting_switches_every_string() {
    let mut a = app();
    nav::select_setting(&mut a, |s| s.language);
    assert_eq!(a.text().settings, "Settings");
    press(&mut a, Key::Right);
    assert_eq!(a.settings.lang, settings::Lang::Ko);
    assert_eq!(a.text().settings, "설정");
    assert_eq!(a.text().rv.issues.len(), text::ISSUE_KINDS);
    press(&mut a, Key::Left);
    assert_eq!(a.settings.lang, settings::Lang::En);
}

#[test]
pub(crate) fn every_screen_renders_without_panicking() {
    struct Null;
    impl bp_hal::Canvas for Null {
        fn width(&self) -> u16 {
            800
        }
        fn height(&self) -> u16 {
            480
        }
        fn fill_rect(&mut self, _: i32, _: i32, _: i32, _: i32, _: bp_hal::Rgb) {}
        fn blend_pixel(&mut self, _: i32, _: i32, _: bp_hal::Rgb, _: u8) {}
    }
    let mut a = app();
    a.set_test_only(true);
    let mut c = Null;
    a.render(&mut c);
    open_create(&mut a, false, true);
    a.render(&mut c);
    roll_until_ready(&mut a, 5);
    a.render(&mut c);
    for _ in 0..5 {
        press(&mut a, Key::Enter);
        a.render(&mut c);
    }
    answer_all(&mut a, None);
    a.render(&mut c);
    press(&mut a, Key::Enter);
    a.render(&mut c);
}

/// Tools > Final word calculator > 12 words
fn open_final_word(a: &mut App) {
    nav::go(a, To::Start(Start::FinalWord));
    nav::words(a, 12);
    assert_eq!(a.current(), Screen::FinalIntro);
    press(a, Key::Enter);
    assert_eq!(a.current(), Screen::WordEntry);
}

#[test]
fn final_word_from_drawn_words_and_coins() {
    let mut a = app();
    open_final_word(&mut a);
    assert_eq!(
        a.flow.as_ref().unwrap().entry.n,
        11,
        "one word fewer than the seed"
    );
    for _ in 0..11 {
        type_str(&mut a, "aban");
    }
    assert_eq!(a.current(), Screen::FinalCoins);
    press(&mut a, Key::Enter); // no flips yet
    assert_eq!(a.current(), Screen::FinalCoins);
    // 7 tails -> free bits 0 -> checksum of all-zero entropy -> "about"
    type_str(&mut a, "TTTTTTT");
    type_str(&mut a, "H"); // an 8th flip is ignored
    assert_eq!(a.flow.as_ref().unwrap().coin_len, 7);
    press(&mut a, Key::Enter);
    assert_eq!(a.current(), Screen::FinalResult);
    let m = a.flow.as_ref().unwrap().mnemonic.as_ref().unwrap();
    assert_eq!(m.word(11), "about");
    // the backup check is still required
    press(&mut a, Key::Enter); // warning
    press(&mut a, Key::Enter); // words
    press(&mut a, Key::Enter); // quiz intro
    press(&mut a, Key::Enter); // quiz
    assert_eq!(a.seed_count(), 0);
    answer_all(&mut a, None);
    assert_eq!(a.seed_count(), 1);
}

#[test]
fn final_word_matches_bip39_for_random_flips() {
    let mut a = app();
    open_final_word(&mut a);
    let words = [
        "zoo", "abil", "wris", "cact", "lege", "noi", "orbi", "pupp", "quiz", "rhyt", "tube",
    ];
    for w in words {
        type_str(&mut a, w);
        if a.flow.as_ref().unwrap().entry.input_len > 0 {
            press(&mut a, Key::Enter);
        }
    }
    assert_eq!(a.current(), Screen::FinalCoins);
    type_str(&mut a, "HTHHTTH");
    press(&mut a, Key::Enter);
    let f = a.flow.as_ref().unwrap();
    let expected = bp_bitcoin::bip39::final_word(&f.entry.idx[..11], 0b1011001).unwrap();
    assert_eq!(f.mnemonic.as_ref().unwrap().indices()[11], expected);
}

#[test]
fn backspace_on_empty_coins_returns_to_words() {
    let mut a = app();
    open_final_word(&mut a);
    for _ in 0..11 {
        type_str(&mut a, "aban");
    }
    press(&mut a, Key::Backspace);
    assert_eq!(a.current(), Screen::WordEntry);
}

#[test]
fn qr_key_opens_scanner_from_menus_only() {
    let mut a = app();
    press(&mut a, Key::Qr);
    assert!(matches!(a.current(), Screen::Scan { .. }));
    press(&mut a, Key::Esc);
    open_create(&mut a, false, false);
    press(&mut a, Key::Qr); // ignored while entering dice
    assert_eq!(a.current(), Screen::EntropyEntry);
}

// ---------- M2: keys, passphrase, xpub, addresses ----------

/// Seeds > Load seed > Type words > 12: "abandon x11 about", then open its options.
fn load_abandon(a: &mut App) {
    open_typed(a, 12);
    for _ in 0..11 {
        type_str(a, "aban");
    }
    type_str(a, "abou");
    assert!(matches!(a.current(), Screen::WordReview { .. }));
    press(a, Key::Enter); // the words reviewed (M11-5)
    assert!(matches!(a.current(), Screen::SeedReady { .. }));
    press(a, Key::Enter);
    assert!(matches!(a.current(), Screen::SeedOptions { .. }));
}

fn xpub_string(a: &App, st: ScriptType, account: u32) -> String {
    let net = a.settings.network;
    let x = a.slot(0).unwrap().account_xpub(st, net, account).unwrap();
    let mut o = [0u8; bp_bitcoin::bip32::XKEY_LEN];
    let n = x.encode(st.key_version().public(net), &mut o);
    String::from_utf8(o[..n].to_vec()).unwrap()
}

fn address_string(a: &App, st: ScriptType, change: bool, index: u32) -> String {
    let mut o = [0u8; bp_bitcoin::address::MAX_ADDRESS_LEN];
    let n = a
        .slot(0)
        .unwrap()
        .address(st, a.settings.network, 0, change, index, &mut o)
        .unwrap();
    String::from_utf8(o[..n].to_vec()).unwrap()
}

#[test]
fn loaded_seed_matches_bip84_and_bip86_vectors() {
    let mut a = app();
    load_abandon(&mut a);
    assert_eq!(a.slot(0).unwrap().fingerprint, [0x73, 0xc5, 0xda, 0x0a]);
    assert_eq!(
        xpub_string(&a, ScriptType::NativeSegwit, 0),
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
    );
    assert_eq!(
        address_string(&a, ScriptType::NativeSegwit, false, 0),
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );
    assert_eq!(
        address_string(&a, ScriptType::Taproot, false, 0),
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    );
    assert_eq!(
        address_string(&a, ScriptType::NativeSegwit, true, 0),
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
    );
}

#[test]
fn testnet_setting_changes_prefixes() {
    let mut a = app();
    load_abandon(&mut a);
    a.settings.network = bp_bitcoin::Network::Testnet;
    assert!(xpub_string(&a, ScriptType::NativeSegwit, 0).starts_with("vpub"));
    assert!(address_string(&a, ScriptType::NativeSegwit, false, 0).starts_with("tb1q"));
    a.settings.network = bp_bitcoin::Network::Regtest;
    assert!(address_string(&a, ScriptType::Taproot, false, 0).starts_with("bcrt1p"));
}

#[test]
fn passphrase_review_shows_new_fingerprint_and_applies() {
    let mut a = app();
    load_abandon(&mut a);
    nav::seed_opt(&mut a, keys::SlotOpt::Passphrase);
    assert!(matches!(a.current(), Screen::PassphraseEntry { .. }));
    type_str(&mut a, "TREZOR");
    press(&mut a, Key::Enter);
    assert!(matches!(a.current(), Screen::PassphraseReview { .. }));
    // expected: fingerprint of the Trezor vector root key (passphrase "TREZOR")
    let (root, _, _) = bp_bitcoin::bip32::Xpriv::decode(
        "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF",
    )
    .unwrap();
    assert_eq!(a.pending.as_ref().unwrap().fingerprint, root.fingerprint());
    assert_eq!(
        a.slot(0).unwrap().fingerprint,
        [0x73, 0xc5, 0xda, 0x0a],
        "not applied yet"
    );
    press(&mut a, Key::Char('1')); // Apply
    assert_eq!(a.slot(0).unwrap().fingerprint, root.fingerprint());
    assert!(a.slot(0).unwrap().has_passphrase());
    assert_eq!(a.pass_in.len, 0, "input wiped after apply");
}

#[test]
fn passphrase_edit_and_cancel_keep_old_wallet() {
    let mut a = app();
    load_abandon(&mut a);
    nav::seed_opt(&mut a, keys::SlotOpt::Passphrase);
    type_str(&mut a, "x y");
    press(&mut a, Key::Tab); // hide
    assert!(!a.pass_in.show);
    press(&mut a, Key::Enter);
    press(&mut a, Key::Char('2')); // Edit -> back to entry
    assert!(matches!(a.current(), Screen::PassphraseEntry { .. }));
    press(&mut a, Key::Esc);
    assert_eq!(a.slot(0).unwrap().fingerprint, [0x73, 0xc5, 0xda, 0x0a]);
    assert_eq!(a.pass_in.len, 0);
}

#[test]
fn script_types_follow_advanced_setting() {
    let mut a = app();
    assert_eq!(a.visible_scripts().len(), 2);
    a.settings.advanced = true;
    assert_eq!(a.visible_scripts().len(), 4);
}

#[test]
fn xpub_and_explorer_navigation() {
    let mut a = app();
    load_abandon(&mut a);
    nav::seed_opt(&mut a, keys::SlotOpt::Xpub);
    nav::script(&mut a, ScriptType::NativeSegwit);
    assert!(matches!(a.current(), Screen::XpubFormat { sel: 0, .. }));
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    nav::seed_opt(&mut a, keys::SlotOpt::Explorer);
    nav::script(&mut a, ScriptType::Taproot);
    assert!(matches!(
        a.current(),
        Screen::AddressList {
            change: false,
            page: 0,
            sel: 0,
            ..
        }
    ));
    press(&mut a, Key::Tab);
    assert!(matches!(a.current(), Screen::AddressList { change: true, .. }));
    press(&mut a, Key::Right);
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    assert!(matches!(
        a.current(),
        Screen::AddressDetail {
            change: true,
            index: 11,
            ..
        }
    ));
}

#[test]
fn tools_explorer_needs_a_seed() {
    let mut a = app();
    nav::go(&mut a, To::Explorer);
    // (Tools > Address explorer)
    assert_eq!(a.current(), Screen::NoSeed);
}

#[test]
fn seeds_menu_shows_fingerprint_not_words() {
    let mut a = app();
    load_abandon(&mut a);
    let label = view::seed_label(a.slot(0).unwrap());
    assert_eq!(label.as_str(), "73c5da0a (12)");
}

#[test]
pub(crate) fn m2_screens_render() {
    struct Null;
    impl bp_hal::Canvas for Null {
        fn width(&self) -> u16 {
            800
        }
        fn height(&self) -> u16 {
            480
        }
        fn fill_rect(&mut self, _: i32, _: i32, _: i32, _: i32, _: bp_hal::Rgb) {}
        fn blend_pixel(&mut self, _: i32, _: i32, _: bp_hal::Rgb, _: u8) {}
    }
    let mut a = app();
    a.settings.advanced = true;
    load_abandon(&mut a);
    let mut c = Null;
    for st in ScriptType::ALL {
        a.push(Screen::XpubView {
            slot: 0,
            st,
            account: 0,
        });
        a.render(&mut c);
        a.push(Screen::AddressList {
            slot: 0,
            st,
            change: false,
            page: 0,
            sel: 0,
        });
        a.render(&mut c);
        a.push(Screen::AddressDetail {
            slot: 0,
            st,
            change: false,
            index: 0,
        });
        a.render(&mut c);
    }
    a.push(Screen::PassphraseEntry { slot: 0 });
    a.render(&mut c);
}

const ABANDON_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

fn qr_text(a: &App) -> String {
    let mut buf = [0u8; qrview::TEXT_MAX];
    let n = a.qr.as_ref().unwrap().text(&mut buf);
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

/// Seed options > Export xpub > Native SegWit > format `n` (1-4).
fn open_xpub_qr(a: &mut App, n: char) {
    nav::seed_opt(a, keys::SlotOpt::Xpub);
    nav::script(a, ScriptType::NativeSegwit);
    press(a, Key::Char(n));
    assert!(matches!(
        a.current(),
        Screen::QrShow {
            kind: QrKind::Xpub { .. }
        }
    ));
}

#[test]
fn xpub_qr_formats() {
    let mut a = app();
    load_abandon(&mut a);
    open_xpub_qr(&mut a, '3'); // text with key origin
    assert_eq!(qr_text(&a), std::format!("[73c5da0a/84h/0h/0h]{ABANDON_ZPUB}"));
    let q = a.qr.as_ref().unwrap();
    assert_eq!(q.density, qrview::Density::Low);
    assert_eq!(q.speed, qrview::Speed::Slow);
    assert!(!q.is_animated());
    press(&mut a, Key::Esc);
    assert!(a.qr.is_none(), "closing the QR drops the session");

    // UR crypto-account: payload is the registry encoding of the account
    press(&mut a, Key::Char('1'));
    assert!(matches!(a.current(), Screen::QrShow { .. }));
    let t = qr_text(&a);
    assert!(t.starts_with("UR:CRYPTO-ACCOUNT/"), "{t}");
    let seed = a.slot(0).unwrap();
    let net = a.settings.network;
    let st = ScriptType::NativeSegwit;
    let xpub = seed.account_xpub(st, net, 0).unwrap();
    let path = st.account_path(net, 0);
    let key = bp_bitcoin::urtypes::AccountKey {
        xpub: &xpub,
        master_fingerprint: seed.fingerprint,
        path: &path,
        script: st,
        network: net,
    };
    let mut want = [0u8; 512];
    let n = bp_bitcoin::urtypes::crypto_account(&key, &mut want).unwrap();
    assert_eq!(a.qr.as_ref().unwrap().payload(), &want[..n]);
    press(&mut a, Key::Esc);

    press(&mut a, Key::Char('2')); // UR crypto-output
    assert!(qr_text(&a).starts_with("UR:CRYPTO-OUTPUT/"));
    press(&mut a, Key::Esc);

    press(&mut a, Key::Char('4')); // Specter pM/N, 40 chars per part at Low
    let q = a.qr.as_ref().unwrap();
    assert_eq!(q.frames(), 4);
    assert!(qr_text(&a).starts_with("p1of4 [73c5da0a/84h/0h/0h]"));
}

#[test]
fn qr_display_controls() {
    let mut a = app();
    load_abandon(&mut a);
    open_xpub_qr(&mut a, '4');
    // animation follows the speed setting and pauses
    a.tick(0); // clear the redraw flag from the key presses
    assert!(!a.tick(799));
    assert!(a.tick(1));
    assert_eq!(a.qr.as_ref().unwrap().frame, 1);
    assert!(qr_text(&a).starts_with("p2of4 "));
    press(&mut a, Key::Char(' '));
    a.tick(0);
    assert!(!a.tick(5000));
    press(&mut a, Key::Char(' '));
    press(&mut a, Key::Tab);
    assert_eq!(a.qr.as_ref().unwrap().speed, qrview::Speed::Normal);
    // density: Low -> Medium (65 chars per part) restarts from the first part
    press(&mut a, Key::Right);
    let q = a.qr.as_ref().unwrap();
    assert_eq!(q.density, qrview::Density::Medium);
    assert_eq!((q.frames(), q.frame), (3, 0));
    press(&mut a, Key::Down);
    press(&mut a, Key::Down);
    assert_eq!(a.qr.as_ref().unwrap().light(), 175);
    for _ in 0..10 {
        press(&mut a, Key::Down);
    }
    assert_eq!(a.qr.as_ref().unwrap().light(), 95);
    press(&mut a, Key::Char('i'));
    assert!(a.qr.as_ref().unwrap().invert);
    press(&mut a, Key::Enter);
    assert!(a.qr.as_ref().unwrap().fullscreen);
    press(&mut a, Key::Esc); // leaves full screen only
    assert!(matches!(a.current(), Screen::QrShow { .. }));
    assert!(!a.qr.as_ref().unwrap().fullscreen);

    // account via digits keeps the viewer settings
    press(&mut a, Key::Char('3'));
    assert!(matches!(
        a.current(),
        Screen::QrShow {
            kind: QrKind::Xpub { account: 3, .. }
        }
    ));
    let q = a.qr.as_ref().unwrap();
    assert!(q.invert && q.light() == 95);
    assert!(qr_text(&a).contains("/84h/0h/3h]"));

    // details screen, account change there follows back to the QR
    press(&mut a, Key::Char('d'));
    assert!(matches!(a.current(), Screen::XpubView { account: 3, .. }));
    press(&mut a, Key::Right);
    press(&mut a, Key::Esc);
    assert!(matches!(
        a.current(),
        Screen::QrShow {
            kind: QrKind::Xpub { account: 4, .. }
        }
    ));
    press(&mut a, Key::Esc);
    assert!(matches!(a.current(), Screen::XpubFormat { .. }));
    assert!(a.qr.is_none());
}

#[test]
fn seedqr_backup_and_transcribe() {
    let mut a = app();
    load_abandon(&mut a);
    nav::seed_opt(&mut a, keys::SlotOpt::SeedQr);
    assert!(matches!(a.current(), Screen::SeedQrSelect { .. }));
    press(&mut a, Key::Char('1')); // Standard
    assert!(matches!(
        a.current(),
        Screen::SeedQrWarning { compact: false, .. }
    ));
    assert!(a.qr.is_none(), "nothing is shown before the warning is accepted");
    press(&mut a, Key::Enter);
    assert!(matches!(
        a.current(),
        Screen::QrShow {
            kind: QrKind::SeedQr { compact: false, .. }
        }
    ));
    assert_eq!(qr_text(&a), std::format!("{}0003", "0000".repeat(11)));
    let sym = a.qr.as_ref().unwrap().qr().unwrap();
    assert_eq!(sym.size(), 25);
    // density keys do nothing on a static SeedQR
    press(&mut a, Key::Right);
    assert_eq!(a.qr.as_ref().unwrap().density, qrview::Density::Auto);

    press(&mut a, Key::Char('t'));
    assert_eq!(
        a.current(),
        Screen::Transcribe {
            slot: 0,
            line: false,
            x: 0,
            y: 0
        }
    );
    for _ in 0..10 {
        press(&mut a, Key::Right);
        press(&mut a, Key::Down);
    }
    // 25 modules = 5 x 5 blocks
    assert_eq!(
        a.current(),
        Screen::Transcribe {
            slot: 0,
            line: false,
            x: 4,
            y: 4
        }
    );
    press(&mut a, Key::Tab);
    for _ in 0..30 {
        press(&mut a, Key::Down);
    }
    assert_eq!(
        a.current(),
        Screen::Transcribe {
            slot: 0,
            line: true,
            x: 0,
            y: 24
        }
    );
    press(&mut a, Key::Esc);
    assert!(matches!(a.current(), Screen::QrShow { .. }));
    press(&mut a, Key::Esc);
    assert!(matches!(a.current(), Screen::SeedQrSelect { .. }));
    assert!(a.qr.is_none());

    press(&mut a, Key::Char('2')); // Compact
    press(&mut a, Key::Enter);
    let q = a.qr.as_ref().unwrap();
    assert_eq!(q.payload(), &[0u8; 16]);
    assert_eq!(q.qr().unwrap().size(), 21);
    // leaving to the main menu from anywhere wipes the session
    a.reset_to(Screen::Menu {
        id: MenuId::Main,
        sel: 0,
    });
    press(&mut a, Key::Down);
    assert!(a.qr.is_none());
}

#[test]
pub(crate) fn qr_screens_render() {
    struct Count(usize);
    impl bp_hal::Canvas for Count {
        fn width(&self) -> u16 {
            800
        }
        fn height(&self) -> u16 {
            480
        }
        fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, _: bp_hal::Rgb) {
            assert!(
                x >= -8 && y >= -8 && x + w <= 808 && y + h <= 488,
                "{x},{y} {w}x{h}"
            );
            self.0 += 1;
        }
        fn blend_pixel(&mut self, _: i32, _: i32, _: bp_hal::Rgb, _: u8) {}
    }
    let mut a = app();
    load_abandon(&mut a);
    let mut c = Count(0);
    for f in ['1', '2', '3', '4'] {
        open_xpub_qr(&mut a, f);
        for _ in 0..4 {
            a.render(&mut c);
            press(&mut a, Key::Right);
        }
        press(&mut a, Key::Enter);
        a.render(&mut c);
        press(&mut a, Key::Esc);
        press(&mut a, Key::Esc);
        press(&mut a, Key::Esc);
        press(&mut a, Key::Esc);
    }
    nav::seed_opt(&mut a, keys::SlotOpt::SeedQr);
    a.render(&mut c);
    press(&mut a, Key::Char('2'));
    a.render(&mut c);
    press(&mut a, Key::Enter);
    a.render(&mut c);
    press(&mut a, Key::Char('t'));
    for _ in 0..6 {
        a.render(&mut c);
        press(&mut a, Key::Right);
        press(&mut a, Key::Down);
    }
    press(&mut a, Key::Tab);
    for _ in 0..25 {
        a.render(&mut c);
        press(&mut a, Key::Down);
    }
    assert!(c.0 > 1000);
}

// ---------- M4: scanning ----------

/// Render `q` as a camera-like greyscale frame (4 px modules, quiet zone).
fn qr_frame(q: &bp_qr::QrCode) -> (std::vec::Vec<u8>, usize, usize) {
    let (w, h) = (320usize, 240usize);
    let px = 4usize;
    let side = (q.size() + 8) * px;
    let (ox, oy) = ((w - side) / 2, (h - side) / 2);
    let mut img = std::vec![40u8; w * h];
    for y in 0..side {
        for x in 0..side {
            let (mx, my) = (x / px, y / px);
            let dark = mx >= 4 && my >= 4 && q.get(mx - 4, my - 4);
            img[(oy + y) * w + ox + x] = if dark { 20 } else { 230 };
        }
    }
    (img, w, h)
}

#[test]
fn scan_opens_from_menu_and_qr_key() {
    let mut a = app();
    scan_any(&mut a);
    assert_eq!(
        a.current(),
        Screen::Scan {
            purpose: scan::Purpose::Any
        }
    );
    assert!(a.wants_camera());
    press(&mut a, Key::Esc);
    assert!(back_where_scans_start(&a));
    assert!(!a.wants_camera());
    press(&mut a, Key::Qr);
    assert!(matches!(a.current(), Screen::Scan { .. }));
}

#[test]
fn scanned_address_shows_and_state_is_wiped() {
    let mut a = app();
    scan_any(&mut a);
    a.on_qr_text(b"bitcoin:bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu?amount=1");
    assert_eq!(
        a.current(),
        Screen::VerifyAddr {
            step: verify::VaStep::Confirm { sel: 0 }
        }
    );
    assert!(!a.scan_live);
    assert!(a.scan.out.iter().all(|&b| b == 0), "scan buffer wiped");
    // no seed loaded: Enter only closes it
    press(&mut a, Key::Enter);
    assert!(back_where_scans_start(&a));
    assert!(a.verify.is_none());
}

#[test]
fn scan_seedqr_from_camera_and_load_it() {
    let mut a = app();
    nav::go(&mut a, To::Scan(scan::Purpose::Seed));
    // (Seeds > Load seed > Scan SeedQR)

    assert_eq!(
        a.current(),
        Screen::Scan {
            purpose: scan::Purpose::Seed
        }
    );
    // Compact SeedQR of "abandon x11 about": 16 zero bytes, byte mode
    let q = bp_qr::QrCode::encode_mode(&[0u8; 16], bp_qr::Mode::Byte, bp_qr::Ecc::Low, 1, 40, None).unwrap();
    let (img, w, h) = qr_frame(&q);
    a.on_frame(&img, w, h);
    assert_eq!(a.current(), Screen::ScanSeed { sel: 0 });
    assert_eq!(a.scanned.as_ref().unwrap().fingerprint, [0x73, 0xc5, 0xda, 0x0a]);
    press(&mut a, Key::Enter); // Load
    assert!(matches!(a.current(), Screen::SeedReady { created: false, .. }));
    assert_eq!(a.slot(0).unwrap().fingerprint, [0x73, 0xc5, 0xda, 0x0a]);
    assert!(a.scanned.is_none());
    assert!(!a.scan_live);
}

#[test]
fn scan_seed_discard_and_not_a_seed() {
    let mut a = app();
    scan_any(&mut a);
    a.on_qr_text(ABANDON_WORDS.as_bytes());
    assert_eq!(a.current(), Screen::ScanSeed { sel: 0 });
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter); // Discard
    assert!(matches!(a.current(), Screen::Menu { .. }));
    assert_eq!(a.seed_count(), 0);
    // Load seed > Scan SeedQR with an address: not a seed
    nav::go(&mut a, To::Scan(scan::Purpose::Seed));

    a.on_qr_text(b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(a.scan.outcome, Some(scan::Outcome::NotASeed));
}

const ABANDON_WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn verify_copied_seedqr() {
    let mut a = app();
    load_abandon(&mut a);
    nav::seed_opt(&mut a, keys::SlotOpt::SeedQr);
    press(&mut a, Key::Char('1')); // Standard
    press(&mut a, Key::Enter);
    press(&mut a, Key::Char('t'));
    assert!(matches!(a.current(), Screen::Transcribe { slot: 0, .. }));
    press(&mut a, Key::Char('v'));
    assert_eq!(
        a.current(),
        Screen::Scan {
            purpose: scan::Purpose::Verify { slot: 0 }
        }
    );
    let digits = std::format!("{}0003", "0000".repeat(11));
    a.on_qr_text(digits.as_bytes());
    assert_eq!(a.current(), Screen::ScanVerify { slot: 0 });
    let (copy, orig) = (a.scan.seed.as_ref().unwrap(), a.slot(0).unwrap());
    assert_eq!(copy.indices(), orig.mnemonic.as_ref().unwrap().indices());
    press(&mut a, Key::Enter);
    assert!(matches!(a.current(), Screen::Transcribe { .. }));
    // a copy with one wrong word
    press(&mut a, Key::Char('v'));
    let bad = std::format!("{}0001{}0003", "0000".repeat(2), "0000".repeat(8));
    a.on_qr_text(bad.as_bytes());
    if a.current() == (Screen::ScanVerify { slot: 0 }) {
        let copy = a.scan.seed.as_ref().unwrap();
        assert_ne!(
            copy.indices(),
            a.slot(0).unwrap().mnemonic.as_ref().unwrap().indices()
        );
    } else {
        // the BIP-39 checksum rejected the copy: not a seed
        assert_eq!(a.scan.outcome, Some(scan::Outcome::NotASeed));
    }
}

#[test]
fn animated_psbt_over_ur_text_frames() {
    let mut a = app();
    scan_any(&mut a);
    // a valid PSBT (1 input, 2 outputs) padded with a large unknown field
    let mut tx = std::vec::Vec::new();
    tx.extend_from_slice(&2u32.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&[0x11; 36]);
    tx.push(0);
    tx.extend_from_slice(&[0xFF; 4]);
    tx.push(2);
    for _ in 0..2 {
        tx.extend_from_slice(&1000u64.to_le_bytes());
        tx.push(1);
        tx.push(0x51);
    }
    tx.extend_from_slice(&[0; 4]);
    let mut p = b"psbt\xff".to_vec();
    p.extend_from_slice(&[1, 0, tx.len() as u8]);
    p.extend_from_slice(&tx);
    p.push(0);
    p.extend_from_slice(&[2, 0xFC, 0x01, 0xFD, 0x20, 0x03]);
    p.extend(std::iter::repeat_n(7u8, 800));
    p.extend_from_slice(&[0, 0, 0]);
    let mut cb = std::vec![0u8; p.len() + 8];
    let mut w = bp_qr::ur::cbor::Writer::new(&mut cb);
    w.bytes(&p).unwrap();
    let n = w.len();
    let enc = bp_qr::ur::UrEncoder::new("crypto-psbt", &cb[..n], 100).unwrap();
    let mut seq = 1;
    while matches!(a.current(), Screen::Scan { .. }) {
        let mut buf = [0u8; 600];
        let k = enc.part(seq, &mut buf).unwrap();
        if seq % 3 != 0 {
            a.on_qr_text(&buf[..k]);
        }
        if a.current()
            == (Screen::Scan {
                purpose: scan::Purpose::Any,
            })
        {
            let pr = a.scan.progress();
            assert_eq!(pr.source, Some(bp_bitcoin::qrinput::Source::Ur));
        }
        seq += 1;
        assert!(seq < 200);
    }
    // a PSBT goes to the review (no seed loaded here)
    assert_eq!(
        a.current(),
        Screen::Review {
            step: review::Step::WrongSeed
        }
    );
    match a.scan.outcome {
        Some(scan::Outcome::Psbt { len, summary, source }) => {
            assert_eq!(&a.scan.out[..len], &p[..]);
            assert_eq!((summary.inputs, summary.outputs), (1, 2));
            assert_eq!(source, bp_bitcoin::qrinput::Source::Ur);
        }
        o => panic!("{o:?}"),
    }
}

#[test]
pub(crate) fn scan_screens_render() {
    struct Count;
    impl bp_hal::Canvas for Count {
        fn width(&self) -> u16 {
            800
        }
        fn height(&self) -> u16 {
            480
        }
        fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, _: bp_hal::Rgb) {
            assert!(
                x >= 0 && y >= 0 && x + w <= 800 && y + h <= 480,
                "{x},{y} {w}x{h}"
            );
        }
        fn blend_pixel(&mut self, _: i32, _: i32, _: bp_hal::Rgb, _: u8) {}
    }
    let mut c = Count;
    let mut a = app();
    a.set_test_only(true);
    scan_any(&mut a);
    a.render(&mut c); // waiting for camera
    let q = bp_qr::QrCode::encode(b"HELLO WORLD", bp_qr::Ecc::Low, 1, 40, None).unwrap();
    let (img, w, h) = qr_frame(&q);
    a.on_frame(&img, w, h);
    a.render(&mut c); // text result
    for text in [
        &b"bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"[..],
        b"[73c5da0a/84h/0h/0h]zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        b"wsh(sortedmulti(2,[aa/48h/0h/0h/2h]xpub1,[bb]xpub2))",
        b"ur:crypto-account/aeaeae",
        &[0xFF, 0x00, 0x12][..],
    ] {
        press(&mut a, Key::Enter);
        scan_any(&mut a);
        a.on_qr_text(text);
        a.render(&mut c);
    }
    press(&mut a, Key::Enter);
    scan_any(&mut a);
    a.on_qr_text(ABANDON_WORDS.as_bytes());
    a.render(&mut c); // seed found
                      // a partial animated code: progress grid
    press(&mut a, Key::Esc);
    scan_any(&mut a);
    let data = [5u8; 600];
    let enc = bp_qr::ur::UrEncoder::new("bytes", &data, 50).unwrap();
    let mut buf = [0u8; 400];
    let k = enc.part(2, &mut buf).unwrap();
    a.on_qr_text(&buf[..k]);
    a.on_frame(&img, w, h); // also a camera frame with a foreign code
    a.render(&mut c);
}

// ---------- M6: D20 ----------

#[test]
fn d20_rolls_are_typed_then_recorded_with_space() {
    let mut a = app();
    nav::go(&mut a, To::Start(Start::D20));
    nav::words(&mut a, 12);

    assert_eq!(a.current(), Screen::EntropyIntro);
    press(&mut a, Key::Enter);
    assert_eq!(a.current(), Screen::EntropyEntry);
    let rec = |a: &App| {
        a.flow
            .as_ref()
            .unwrap()
            .entropy
            .as_ref()
            .unwrap()
            .record()
            .to_vec()
    };
    type_str(&mut a, "21 ");
    assert!(rec(&a).is_empty(), "21 is not a face");
    assert!(a.notice.is_some());
    type_str(&mut a, "7 ");
    type_str(&mut a, "19");
    press(&mut a, Key::Backspace); // "1"
    type_str(&mut a, "2 ");
    type_str(&mut a, "20");
    press(&mut a, Key::Enter); // Enter records a typed number too
    assert_eq!(rec(&a), [7, 12, 20]);
    press(&mut a, Key::Backspace); // nothing typed: removes the last roll
    assert_eq!(rec(&a), [7, 12]);
    press(&mut a, Key::Enter); // not ready
    assert_eq!(a.current(), Screen::EntropyEntry);
    // fair rolls until every check passes, then the seed is SHA-256 of
    // "7-12-..." as Krux computes it
    let mut x = 0x1234_5678_9abc_def1u64;
    for _ in 0..200 {
        if a.flow
            .as_ref()
            .unwrap()
            .entropy
            .as_ref()
            .unwrap()
            .analyze()
            .all_pass()
        {
            break;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        type_str(&mut a, &std::format!("{} ", x % 20 + 1));
    }
    let r = rec(&a);
    press(&mut a, Key::Enter);
    assert_eq!(a.current(), Screen::EntropySummary);
    let text = r
        .iter()
        .map(|v| std::format!("{v}"))
        .collect::<std::vec::Vec<_>>()
        .join("-");
    let want = bp_bitcoin::entropy::mnemonic_from_record(text.as_bytes(), 12);
    assert_eq!(
        a.flow.as_ref().unwrap().mnemonic.as_ref().unwrap().indices(),
        want.indices()
    );
}

// ---------- M9: typed-word confirmation (intended change C5) ----------

#[test]
fn discarding_a_seed_needs_the_word_wipe() {
    let mut a = app();
    load_abandon(&mut a);
    nav::seed_opt(&mut a, keys::SlotOpt::Discard);
    assert!(matches!(
        a.current(),
        Screen::Confirm {
            what: Confirm::DiscardSeed(0),
            ..
        }
    ));
    // the old "2 = discard" no longer discards; a wrong word changes nothing
    press(&mut a, Key::Char('2'));
    type_str(&mut a, "wip");
    press(&mut a, Key::Enter);
    assert_eq!(a.seed_count(), 1);
    assert!(a.typed.wrong);
    // Esc keeps the seed
    press(&mut a, Key::Esc);
    assert!(matches!(a.current(), Screen::SeedOptions { .. }));
    assert_eq!(a.seed_count(), 1);
    // the word discards it
    nav::seed_opt(&mut a, keys::SlotOpt::Discard);
    assert_eq!(a.typed.text(), "", "the field starts empty");
    type_str(&mut a, "WIPE");
    press(&mut a, Key::Enter);
    assert_eq!(a.seed_count(), 0);
    assert!(matches!(
        a.current(),
        Screen::Menu {
            id: MenuId::Seeds,
            ..
        }
    ));
}

/// Flows started from the scanner or message signing end back on the menu
/// that holds them (M9-4: Sign; it was the main menu before).
fn back_where_scans_start(a: &App) -> bool {
    matches!(a.current(), Screen::Menu { id, .. } if id == nav::menu_of(To::Scan(scan::Purpose::Any)))
}

// ---------- M9-5: screen saver (intended change C6) ----------

fn idle(a: &mut App, secs: u32) {
    for _ in 0..secs {
        a.tick(1000);
    }
}

#[test]
fn screen_saver_closes_secret_screens_and_keeps_typing_flows() {
    // a seed's words on screen: the saver comes after a minute, the key
    // that wakes it does nothing else, and the words are closed
    let mut a = app();
    load_abandon(&mut a);
    nav::seed_opt(&mut a, keys::SlotOpt::Words);
    while !matches!(a.current(), Screen::ShowWords { .. }) {
        press(&mut a, Key::Enter);
    }
    idle(&mut a, 59);
    assert!(!a.saver);
    idle(&mut a, 2);
    assert!(a.saver);
    a.render(&mut layout_free::Null);
    press(&mut a, Key::Char('1'));
    assert!(!a.saver);
    assert!(!matches!(a.current(), Screen::ShowWords { .. }), "words closed");
    assert_eq!(a.seed_count(), 1, "nothing else happened");
    // typing words: the saver hides them, and they are all still there after
    nav::go(&mut a, To::Start(Start::TypeWords));
    nav::words(&mut a, 12);
    for _ in 0..5 {
        type_str(&mut a, "aban");
    }
    let before = a.current();
    idle(&mut a, 61);
    assert!(a.saver);
    press(&mut a, Key::Enter);
    assert_eq!(a.current(), before);
    for _ in 0..6 {
        type_str(&mut a, "aban");
    }
    type_str(&mut a, "abou");
    assert!(
        matches!(a.current(), Screen::WordReview { .. }),
        "the five words were kept"
    );
}

/// M9-7: the words screen says when the saver will hide the words, and is
/// redrawn as the seconds count down; nothing is shown when the saver is off.
#[test]
fn words_screen_counts_down_to_the_screen_saver() {
    let mut a = app();
    load_abandon(&mut a);
    nav::seed_opt(&mut a, keys::SlotOpt::Words);
    while !matches!(a.current(), Screen::ShowWords { .. }) {
        press(&mut a, Key::Enter);
    }
    assert_eq!(a.hides_in(), Some(60));
    a.render(&mut layout_free::Null);
    a.tick(1); // settle any pending redraw
    assert!(!a.tick(400), "no redraw inside the same second");
    assert_eq!(a.hides_in(), Some(60), "rounded up to the whole second");
    assert!(a.tick(700), "redrawn when the second changes");
    assert_eq!(a.hides_in(), Some(59));
    idle(&mut a, 50);
    assert!(a.hides_in().unwrap() <= 10);
    idle(&mut a, 10);
    assert!(a.saver);
    assert_eq!(a.hides_in(), None, "covered");
    // a key wakes the device and closes the words; open them again
    press(&mut a, Key::Esc);
    while !matches!(a.current(), Screen::ShowWords { .. }) {
        press(&mut a, Key::Enter);
    }
    assert_eq!(a.hides_in(), Some(60), "a key press restarts the count");
    // other screens and a saver turned off show nothing
    press(&mut a, Key::Esc);
    assert_eq!(a.hides_in(), None);
    a.settings.saver = 2;
    while !matches!(a.current(), Screen::ShowWords { .. }) {
        press(&mut a, Key::Enter);
    }
    assert_eq!(a.hides_in(), None);
}

#[test]
fn screen_saver_waits_for_qr_scanning_and_can_be_turned_off() {
    let mut a = app();
    load_abandon(&mut a);
    // an xpub QR may stay up while a wallet scans it
    nav::seed_opt(&mut a, keys::SlotOpt::Xpub);
    nav::script(&mut a, ScriptType::NativeSegwit);
    press(&mut a, Key::Char('1'));
    idle(&mut a, 300);
    assert!(!a.saver);
    // the camera too
    nav::go(&mut a, To::Scan(scan::Purpose::Any));
    idle(&mut a, 300);
    assert!(!a.saver);
    // a SeedQR is a secret: covered, and closed after
    nav::home(&mut a);
    nav::seed(&mut a, 0);
    nav::seed_opt(&mut a, keys::SlotOpt::SeedQr);
    press(&mut a, Key::Char('1'));
    press(&mut a, Key::Enter);
    assert!(matches!(
        a.current(),
        Screen::QrShow {
            kind: QrKind::SeedQr { .. }
        }
    ));
    idle(&mut a, 61);
    assert!(a.saver);
    press(&mut a, Key::Esc);
    assert!(!matches!(a.current(), Screen::QrShow { .. }));
    assert!(a.qr.is_none(), "the SeedQR payload is dropped");
    // 5 minutes, then off
    nav::select_setting(&mut a, |s| s.saver_label);
    press(&mut a, Key::Right);
    assert_eq!(a.settings.saver, 1);
    nav::home(&mut a);
    idle(&mut a, 120);
    assert!(!a.saver);
    idle(&mut a, 200);
    assert!(a.saver);
    press(&mut a, Key::Esc);
    nav::select_setting(&mut a, |s| s.saver_label);
    press(&mut a, Key::Right);
    assert_eq!(a.settings.saver, 2);
    idle(&mut a, 3600);
    assert!(!a.saver);
}

// ---------- M9-9 task efficiency (see taskcount.rs, docs/M9_TASKS.md) ----------

/// Stop counting and compare with the M8 build.
pub(crate) fn task_done(name: &str, a: &App) {
    let (keys, screens) = crate::taskcount::finish(&a.current());
    crate::taskcount::check(name, keys, screens);
}

#[test]
fn task_seed_from_dice() {
    let mut a = app();
    crate::taskcount::start(&a.current());
    open_create(&mut a, false, false);
    roll_until_ready(&mut a, 7);
    for _ in 0..5 {
        press(&mut a, Key::Enter); // finish, summary, warning, words, quiz intro
    }
    answer_all(&mut a, None);
    press(&mut a, Key::Enter); // seed ready
    task_done("seed-dice-12", &a);
}

#[test]
fn task_seed_typed() {
    let mut a = app();
    crate::taskcount::start(&a.current());
    load_abandon(&mut a);
    task_done("seed-typed-12", &a);
}

#[test]
fn task_xpub_qr() {
    let mut a = app();
    load_abandon(&mut a);
    nav::home(&mut a);
    crate::taskcount::start(&a.current());
    nav::seed(&mut a, 0);
    open_xpub_qr(&mut a, '1');
    task_done("xpub-qr", &a);
}

#[test]
fn task_power_on() {
    // first-run screen (C3): once per power on
    let mut a = App::new(b"test quiz seed");
    a.tick(SPLASH_MS);
    crate::taskcount::start(&a.current());
    nav::home(&mut a);
    task_done("power-on", &a);
}

/// M9-9 (C11): `?` opens the screen's help and any key closes it without
/// doing anything else; where text is typed `?` is a character (F1 still
/// opens the help); the screen saver closes it.
#[test]
fn help_opens_with_question_mark_and_the_next_key_only_closes_it() {
    let mut a = app();
    let menu = a.current();
    press(&mut a, Key::Char('?'));
    assert!(a.help.get());
    assert_eq!(a.help_topic(), Some(crate::help::Topic::Menus));
    assert_eq!(a.current(), menu);
    press(&mut a, Key::Char('1')); // would open the first row
    assert!(!a.help.get());
    assert_eq!(a.current(), menu, "the closing key did nothing else");
    press(&mut a, Key::F(1));
    assert!(a.help.get());
    press(&mut a, Key::Esc);
    assert!(!a.help.get());
    assert_eq!(a.current(), menu);
    // typing words: `?` opens the help and the letters typed are kept
    open_typed(&mut a, 12);
    type_str(&mut a, "ab");
    press(&mut a, Key::Char('?'));
    assert_eq!(a.help_topic(), Some(crate::help::Topic::TypeWords));
    press(&mut a, Key::Enter);
    assert!(!a.help.get());
    assert_eq!(a.flow.as_ref().unwrap().entry.pos, 0);
    type_str(&mut a, "an");
    assert_eq!(a.flow.as_ref().unwrap().entry.pos, 1, "aban completes abandon");
    // a passphrase may contain `?`: it is typed, F1 opens the help
    let mut a = app();
    load_abandon(&mut a);
    nav::seed_opt(&mut a, keys::SlotOpt::Passphrase);
    assert!(matches!(a.current(), Screen::PassphraseEntry { .. }));
    type_str(&mut a, "a?b");
    assert!(!a.help.get());
    assert_eq!(a.pass_in.text(), b"a?b");
    press(&mut a, Key::F(1));
    assert_eq!(a.help_topic(), Some(crate::help::Topic::Passphrase));
    press(&mut a, Key::Char('x'));
    assert_eq!(a.pass_in.text(), b"a?b", "the closing key was not typed");
    // the screen saver closes the help
    press(&mut a, Key::F(1));
    idle(&mut a, 61);
    assert!(a.saver && !a.help.get());
}

/// M11-5 (E3): a word typed wrong but still a valid seed is caught on the
/// review — Del retypes the selected word, then the review shows again.
#[test]
fn a_typed_word_can_be_fixed_on_the_review() {
    let mut a = app();
    open_typed(&mut a, 12);
    // "legal winner thank year wave sausage worth useful legal winner
    // thank yellow"
    for w in [
        "lega", "winn", "than", "year", "wave", "saus", "wort", "usef", "lega", "winn", "than", "yell",
    ] {
        type_str(&mut a, w);
    }
    assert_eq!(a.current(), Screen::WordReview { sel: 0 });
    let fp = a.flow.as_ref().unwrap().review_fp.unwrap();
    // move to word 5 and retype it as the same word: back on the review
    for _ in 0..4 {
        press(&mut a, Key::Down);
    }
    assert_eq!(a.current(), Screen::WordReview { sel: 4 });
    press(&mut a, Key::Backspace);
    assert_eq!(a.current(), Screen::WordEntry);
    assert_eq!(a.flow.as_ref().unwrap().entry.fixing, Some(4));
    type_str(&mut a, "wave");
    assert_eq!(a.current(), Screen::WordReview { sel: 0 });
    assert_eq!(a.flow.as_ref().unwrap().review_fp, Some(fp));
    assert_eq!(a.seed_count(), 0, "nothing loads before Enter");
    // Esc asks before throwing the words away
    press(&mut a, Key::Esc);
    assert!(matches!(a.current(), Screen::Confirm { .. }));
    press(&mut a, Key::Char('1')); // keep
    assert_eq!(a.current(), Screen::WordReview { sel: 0 });
    press(&mut a, Key::Enter);
    assert_eq!(a.slot(0).unwrap().fingerprint, fp);
}
