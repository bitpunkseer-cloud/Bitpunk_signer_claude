//! Flow tests: drive the app with key events like a user would.

use super::*;
use bp_bitcoin::bip39::WORDS;
use bp_hal::input::Key;

fn app() -> App {
    let mut a = App::new(b"test quiz seed");
    a.tick(SPLASH_MS);
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
    press(a, Key::Char('2')); // Seeds
    press(a, Key::Char('1')); // Create new seed
    press(a, Key::Char(if coin { '2' } else { '1' }));
    press(a, Key::Char(if words24 { '2' } else { '1' }));
    assert_eq!(a.current(), Screen::EntropyIntro);
    press(a, Key::Enter);
    assert_eq!(a.current(), Screen::EntropyEntry);
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
fn splash_times_out_to_main_menu() {
    let mut a = App::new(b"x");
    assert_eq!(a.current(), Screen::Splash);
    a.tick(SPLASH_MS);
    assert_eq!(
        a.current(),
        Screen::Menu {
            id: MenuId::Main,
            sel: 0
        }
    );
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
    press(&mut a, Key::Char('2')); // Seeds
    press(&mut a, Key::Char('2')); // Load seed
    press(&mut a, Key::Char('1')); // Type words
    press(&mut a, Key::Char('1')); // 12 words
    assert_eq!(a.current(), Screen::WordEntry);
    // "aban" auto-completes to "abandon" (unique 4-letter prefix)
    for _ in 0..11 {
        type_str(&mut a, "aban");
    }
    type_str(&mut a, "abou"); // about
    assert_eq!(a.seed_count(), 1);
    assert!(matches!(a.current(), Screen::SeedReady { created: false, .. }));
}

#[test]
fn full_words_and_prefixes_both_work() {
    let mut a = app();
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('1'));
    press(&mut a, Key::Char('1'));
    // mix of full words (with spaces) and 4-letter prefixes
    for i in 0..11 {
        if i % 2 == 0 {
            type_str(&mut a, "abandon ");
        } else {
            type_str(&mut a, "aban");
        }
    }
    type_str(&mut a, "about");
    assert_eq!(a.seed_count(), 1);
}

#[test]
fn checksum_error_lets_user_fix_a_word() {
    let mut a = app();
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('1'));
    press(&mut a, Key::Char('1'));
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
    assert_eq!(a.seed_count(), 1);
}

#[test]
fn three_letter_word_needs_enter() {
    let mut a = app();
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('1'));
    press(&mut a, Key::Char('1'));
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
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('2')); // word numbers
    press(&mut a, Key::Char('1'));
    for _ in 0..11 {
        type_str(&mut a, "1");
        press(&mut a, Key::Enter);
    }
    type_str(&mut a, "4"); // "about" is word #4
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
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('1'));
    press(&mut a, Key::Char('1'));
    for _ in 0..11 {
        type_str(&mut a, "aban");
    }
    type_str(&mut a, "abou");
    assert_eq!(a.seed_count(), 1);
    press(&mut a, Key::Esc);
    a.reset_to(Screen::Menu {
        id: MenuId::Main,
        sel: 0,
    });
    press(&mut a, Key::Char('5'));
    press(&mut a, Key::Char('1'));
    assert_eq!(a.current(), Screen::PoweredOff);
    assert_eq!(a.seed_count(), 0);
}

#[test]
fn network_setting_cycles() {
    let mut a = app();
    press(&mut a, Key::Char('4'));
    let before = a.settings.network;
    press(&mut a, Key::Right);
    assert_ne!(a.settings.network, before);
}

#[test]
fn every_screen_renders_without_panicking() {
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
    press(a, Key::Char('3')); // Tools
    press(a, Key::Char('1')); // Final word calculator
    press(a, Key::Char('1')); // 12 words
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
fn qr_key_opens_scanner_placeholder_from_menus_only() {
    let mut a = app();
    press(&mut a, Key::Qr);
    assert!(matches!(a.current(), Screen::Placeholder { .. }));
    press(&mut a, Key::Esc);
    open_create(&mut a, false, false);
    press(&mut a, Key::Qr); // ignored while entering dice
    assert_eq!(a.current(), Screen::EntropyEntry);
}
