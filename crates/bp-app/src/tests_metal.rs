//! Metal plate screens (M11-4): a seed's Tinyseed and Stackbit dots, a
//! plate copied dot by dot, and every step drawn in both languages.

extern crate std;

use super::*;
use crate::keys::SlotOpt;
use crate::menus::Start;
use crate::metalui::{MetalStep, Plate, ROWS};
use crate::nav::{self, To};
use bp_backup::metal;
use bp_bitcoin::bip39::{word_index, Mnemonic};
use bp_hal::input::Key;
use std::vec::Vec;

const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const LEGAL24: &str = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless";

fn app() -> App {
    let mut a = App::new(b"test quiz seed");
    a.tick(SPLASH_MS);
    nav::home(&mut a);
    a
}

fn press(a: &mut App, k: Key) {
    a.on_key(KeyEvent::new(k));
}

fn type_words(a: &mut App, words: &str) {
    for w in words.split(' ') {
        for ch in w.chars() {
            press(a, Key::Char(ch));
        }
        press(a, Key::Char(' '));
    }
}

fn indices(words: &str) -> Vec<u16> {
    words.split(' ').map(|w| word_index(w).unwrap()).collect()
}

fn fp_of(words: &str) -> [u8; 4] {
    crate::seeds::SeedSlot::new(Mnemonic::from_indices(&indices(words)).unwrap(), b"")
        .unwrap()
        .fingerprint
}

fn step(a: &App) -> MetalStep {
    match a.current() {
        Screen::Metal { step } => step,
        s => panic!("not a metal plate screen: {s:?}"),
    }
}

fn load(a: &mut App, words: &str) {
    nav::go(a, To::Start(Start::TypeWords));
    nav::words(a, words.split(' ').count());
    type_words(a, words);
    press(a, Key::Enter); // the words reviewed
    press(a, Key::Enter); // SeedReady -> options
}

#[test]
fn a_seed_shows_its_dots_for_both_plates() {
    for (words, pages) in [(LEGAL, 1u8), (LEGAL24, 2)] {
        for (sel, plate) in [('1', Plate::Tinyseed), ('2', Plate::Stackbit)] {
            let mut a = app();
            load(&mut a, words);
            nav::seed_opt(&mut a, SlotOpt::Metal);
            assert_eq!(step(&a), MetalStep::Format { sel: 0 });
            press(&mut a, Key::Char(sel));
            assert_eq!(step(&a), MetalStep::View { page: 0 });
            let st = a.metal.as_ref().unwrap();
            assert_eq!(st.plate, plate);
            for (i, &w) in indices(words).iter().enumerate() {
                assert_eq!(st.dots[i], plate.encode(w));
                assert_eq!(plate.decode(st.dots[i]), Some(w));
            }
            if pages == 2 {
                press(&mut a, Key::Enter);
                assert_eq!(step(&a), MetalStep::View { page: 1 });
                press(&mut a, Key::Left);
                assert_eq!(step(&a), MetalStep::View { page: 0 });
                press(&mut a, Key::Tab);
            }
            press(&mut a, Key::Enter);
            assert!(matches!(a.current(), Screen::SeedOptions { .. }));
            assert!(a.metal.is_none());
        }
    }
}

/// Punch `dots` into the row under the cursor's page row `row`.
fn punch_row(a: &mut App, row: usize, dots: u16) {
    let cols = a.metal.as_ref().unwrap().plate.dots();
    let plate = a.metal.as_ref().unwrap().plate;
    for col in 0..cols {
        let bit = match plate {
            Plate::Tinyseed => 1u16 << (cols - 1 - col),
            Plate::Stackbit => 1u16 << (4 * (col / 4) + col % 4),
        };
        if dots & bit == 0 {
            continue;
        }
        // move the cursor to (row, col)
        loop {
            let st = a.metal.as_ref().unwrap();
            if st.row as usize == row {
                break;
            }
            press(a, Key::Down);
        }
        loop {
            let st = a.metal.as_ref().unwrap();
            if st.col as usize == col {
                break;
            }
            press(a, Key::Right);
        }
        press(a, Key::Char(' '));
    }
}

/// Load > Metal plate dots, `plate` ('1' Tinyseed, '2' Stackbit), copy
/// `words`; `change` flips one dot of one word first.
fn copy_plate(a: &mut App, words: &str, plate: char, change: Option<(usize, u16)>) {
    nav::go(a, To::Start(Start::MetalGrid));
    let n = words.split(' ').count();
    nav::words(a, n);
    assert_eq!(step(a), MetalStep::Format { sel: 0 });
    press(a, Key::Char(plate));
    assert_eq!(step(a), MetalStep::Grid { page: 0 });
    let p = a.metal.as_ref().unwrap().plate;
    for (i, &w) in indices(words).iter().enumerate() {
        if i == ROWS {
            press(a, Key::Tab);
            assert_eq!(step(a), MetalStep::Grid { page: 1 });
        }
        let mut dots = p.encode(w);
        if let Some((at, bit)) = change {
            if at == i {
                dots ^= bit;
            }
        }
        punch_row(a, i % ROWS, dots);
    }
    press(a, Key::Enter);
}

#[test]
fn a_copied_plate_loads_its_seed() {
    for (words, plate) in [(LEGAL, '1'), (LEGAL, '2'), (LEGAL24, '1'), (LEGAL24, '2')] {
        let mut a = app();
        copy_plate(&mut a, words, plate, None);
        // the plate's words go through the review, as typed words
        assert_eq!(a.current(), Screen::WordReview { sel: 0 });
        press(&mut a, Key::Enter);
        let Screen::SeedReady { slot, created: false } = a.current() else {
            panic!("{:?}", a.current())
        };
        assert_eq!(a.slot(slot as usize).unwrap().fingerprint, fp_of(words));
        assert!(a.metal.is_none(), "the dots are wiped");
    }
}

#[test]
fn a_wrong_dot_ends_on_the_checksum_screen() {
    // "legal" (1018 = 0b01111111010) with the 1 dot added is "lemon"... a
    // valid word, so only the checksum catches it
    let mut a = app();
    copy_plate(&mut a, LEGAL, '1', Some((4, 0b1)));
    assert_eq!(a.current(), Screen::ChecksumError { sel: 0 });
    for _ in 0..4 {
        press(&mut a, Key::Down);
    }
    press(&mut a, Key::Enter);
    type_words(&mut a, "wave");
    press(&mut a, Key::Enter);
    let Screen::SeedReady { slot, .. } = a.current() else {
        panic!("{:?}", a.current())
    };
    assert_eq!(a.slot(slot as usize).unwrap().fingerprint, fp_of(LEGAL));
}

#[test]
fn a_row_that_is_no_word_is_pointed_at() {
    let mut a = app();
    nav::go(&mut a, To::Start(Start::MetalGrid));
    nav::words(&mut a, 12);
    press(&mut a, Key::Char('2')); // Stackbit
    for (i, &w) in indices(LEGAL).iter().enumerate() {
        if i == 6 {
            continue; // row 7 left empty
        }
        punch_row(&mut a, i, metal::stackbit_dots(w));
    }
    // and row 3 ("thank", 1791) gets a tens digit of 15: 9 = 1001, plus 0110
    punch_row(&mut a, 2, 0b0110 << 8);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), MetalStep::Grid { page: 0 });
    assert_eq!(a.metal.as_ref().unwrap().row, 2);
    assert_eq!(a.notice, Some(a.text().bk.mt_not_word));
    // Del clears the row; copy it again
    press(&mut a, Key::Backspace);
    punch_row(&mut a, 2, metal::stackbit_dots(indices(LEGAL)[2]));
    press(&mut a, Key::Enter);
    assert_eq!(a.metal.as_ref().unwrap().row, 6);
    punch_row(&mut a, 6, metal::stackbit_dots(indices(LEGAL)[6]));
    press(&mut a, Key::Enter);
    assert!(matches!(a.current(), Screen::WordReview { .. }));
}

#[test]
fn the_saver_covers_the_dots_and_menus_wipe_them() {
    let mut a = app();
    load(&mut a, LEGAL);
    nav::seed_opt(&mut a, SlotOpt::Metal);
    press(&mut a, Key::Enter);
    for _ in 0..13 {
        a.tick(5_000);
    }
    press(&mut a, Key::Char('x'));
    assert_eq!(step(&a), MetalStep::Covered { page: 0 });
    press(&mut a, Key::Esc);
    assert!(a.metal.is_none());
    // entering: power off wipes the dots typed
    nav::go(&mut a, To::Start(Start::MetalGrid));
    nav::words(&mut a, 12);
    press(&mut a, Key::Enter);
    press(&mut a, Key::Char(' '));
    assert!(a.metal.is_some());
    a.wipe_ram();
    assert!(a.metal.is_none());
}

/// Every metal plate step drawn in both languages (screen tour).
#[test]
pub(crate) fn metal_screens_fit() {
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(std::format!("metal-{l}-{name}.ppm")));
            }
        };
        let mut a = app();
        a.settings.lang = lang;
        a.set_test_only(true);
        load(&mut a, LEGAL24);
        nav::seed_opt(&mut a, SlotOpt::Metal);
        shot(&a, "format");
        press(&mut a, Key::Char('1'));
        shot(&a, "tinyseed");
        press(&mut a, Key::Enter);
        shot(&a, "tinyseed-2");
        press(&mut a, Key::Esc);
        nav::seed(&mut a, 0);
        nav::seed_opt(&mut a, SlotOpt::Metal);
        press(&mut a, Key::Char('2'));
        shot(&a, "stackbit");
        for _ in 0..13 {
            a.tick(5_000);
        }
        press(&mut a, Key::Char('x'));
        shot(&a, "covered");
        press(&mut a, Key::Esc);
        nav::go(&mut a, To::Start(Start::MetalGrid));
        nav::words(&mut a, 24);
        shot(&a, "enter-format");
        press(&mut a, Key::Char('1'));
        punch_row(&mut a, 0, metal::tinyseed_dots(1018));
        punch_row(&mut a, 1, 0b1);
        shot(&a, "grid-tinyseed");
        press(&mut a, Key::Enter);
        shot(&a, "grid-not-word");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('2'));
        nav::go(&mut a, To::Start(Start::MetalGrid));
        nav::words(&mut a, 12);
        press(&mut a, Key::Char('2'));
        punch_row(&mut a, 0, metal::stackbit_dots(1018));
        shot(&a, "grid-stackbit");
        press(&mut a, Key::Char('?'));
        shot(&a, "help");
    }
}
