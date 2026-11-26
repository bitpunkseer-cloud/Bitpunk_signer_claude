//! Seed XOR screens (M11-3): loading a seed from its parts (Coldcard's
//! documented example), splitting a loaded seed (Coldcard's formula, or
//! with dice), and every step drawn in both languages.

extern crate std;

use super::*;
use crate::keys::SlotOpt;
use crate::menus::Start;
use crate::nav::{self, To};
use crate::seedxorui::{XorStep, CHECKS, MIN_DICE};
use bp_backup::seedxor;
use bp_bitcoin::bip39::{word_index, Mnemonic, WORDS};
use bp_hal::input::Key;
use std::format;
use std::string::String;
use std::vec::Vec;

/// Coldcard's docs/seed-xor.md: three 24-word parts and their seed.
const DOC24: [&str; 3] = [
    "romance wink lottery autumn shop bring dawn tongue range crater truth ability miss spice fitness easy legal release recall obey exchange recycle dragon room",
    "lion misery divide hurry latin fluid camp advance illegal lab pyramid unaware eager fringe sick camera series noodle toy crowd jeans select depth lounge",
    "vault nominee cradle silk own frown throw leg cactus recall talent worry gadget surface shy planet purpose coffee drip few seven term squeeze educate",
];
const DOC24_SEED: &str = "silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary indoor";
const DOC12: [&str; 3] = [
    "romance wink lottery autumn shop bring dawn tongue range crater truth ability",
    "boat unfair shell violin tree robust open ride visual forest vintage approve",
    "lion misery divide hurry latin fluid camp advance illegal lab pyramid unhappy",
];
const DOC12_SEED: &str = "cannon opinion leader nephew found yard metal galaxy crouch between real trade";

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

fn type_words(a: &mut App, words: &str) {
    for w in words.split(' ') {
        type_str(a, w);
        press(a, Key::Char(' '));
    }
}

fn fp_of(words: &str) -> [u8; 4] {
    let idx: Vec<u16> = words.split(' ').map(|w| word_index(w).unwrap()).collect();
    crate::seeds::SeedSlot::new(Mnemonic::from_indices(&idx).unwrap(), b"")
        .unwrap()
        .fingerprint
}

fn step(a: &App) -> XorStep {
    match a.current() {
        Screen::SeedXor { step } => step,
        s => panic!("not a Seed XOR screen: {s:?}"),
    }
}

fn saver(a: &mut App) {
    for _ in 0..13 {
        a.tick(5_000);
    }
}

/// Load > Seed XOR parts, `words` long, then the parts one by one.
fn type_parts(a: &mut App, parts: &[&str]) {
    nav::go(a, To::Start(Start::XorParts));
    nav::words(a, parts[0].split(' ').count());
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            press(a, Key::Char('1')); // add another part
            assert_eq!(a.current(), Screen::WordEntry);
        }
        type_words(a, p);
        assert_eq!(step(a), XorStep::Combined { sel: 0 }, "part {i}");
    }
}

#[test]
fn coldcard_documented_parts_load_their_seed() {
    for (parts, seed) in [(DOC24, DOC24_SEED), (DOC12, DOC12_SEED)] {
        let mut a = app();
        type_parts(&mut a, &parts[..1]);
        // one part is not enough to load
        press(&mut a, Key::Char('2'));
        assert_eq!(a.notice, Some(a.text().bk.xr_two));
        assert_eq!(step(&a), XorStep::Combined { sel: 0 });
        // the same part again changes nothing
        press(&mut a, Key::Char('1'));
        type_words(&mut a, parts[0]);
        let st = a.xor.as_ref().unwrap();
        assert!(st.again);
        assert_eq!(st.count, 1);
        for p in &parts[1..] {
            press(&mut a, Key::Char('1'));
            type_words(&mut a, p);
        }
        let st = a.xor.as_ref().unwrap();
        assert_eq!(st.count, 3);
        let (fp, last) = st.result.unwrap();
        assert_eq!(fp, fp_of(seed));
        assert_eq!(WORDS[last as usize], seed.split(' ').next_back().unwrap());
        press(&mut a, Key::Char('2'));
        let Screen::SeedReady { slot, created: false } = a.current() else {
            panic!("{:?}", a.current())
        };
        assert_eq!(a.slot(slot as usize).unwrap().fingerprint, fp_of(seed));
        assert!(a.xor.is_none(), "the parts are wiped");
    }
}

#[test]
fn a_wrong_word_in_a_part_is_fixed_before_it_counts() {
    let mut a = app();
    nav::go(&mut a, To::Start(Start::XorParts));
    nav::words(&mut a, 12);
    let mut w: Vec<&str> = DOC12[0].split(' ').collect();
    w[2] = "abandon";
    type_words(&mut a, &w.join(" "));
    assert_eq!(a.current(), Screen::ChecksumError { sel: 0 });
    assert!(a.xor.is_none() || a.xor.as_ref().unwrap().count == 0);
    press(&mut a, Key::Down);
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    type_words(&mut a, "lottery");
    assert_eq!(step(&a), XorStep::Combined { sel: 0 });
    assert_eq!(a.xor.as_ref().unwrap().count, 1);
}

/// Entropy 7f7f..7f (BIP-39 test vector).
const LEGAL: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// Load the LEGAL seed and open its options. (The all-zero seed splits
/// into two equal parts, which loading refuses as a repeat.)
fn load_legal(a: &mut App) -> u8 {
    nav::go(a, To::Start(Start::TypeWords));
    nav::words(a, 12);
    type_words(a, LEGAL);
    press(a, Key::Enter); // the words reviewed
    let Screen::SeedReady { slot, .. } = a.current() else {
        panic!()
    };
    press(a, Key::Enter);
    slot
}

/// Show and check every part; returns their words.
fn write_and_check_all(a: &mut App) -> Vec<String> {
    let mut out = Vec::new();
    while let Screen::SeedXor {
        step: XorStep::Show { part },
    } = a.current()
    {
        let st = a.xor.as_ref().unwrap();
        let mut w = [0u16; 24];
        let n = st.part_words(part, &mut w);
        out.push(
            w[..n]
                .iter()
                .map(|&i| WORDS[i as usize])
                .collect::<Vec<_>>()
                .join(" "),
        );
        press(a, Key::Enter);
        for q in 0..CHECKS {
            let st = a.xor.as_ref().unwrap();
            let (pos, options) = st.check_for_test(q);
            let words: Vec<&str> = out.last().unwrap().split(' ').collect();
            let pick = (0..4u8)
                .find(|&i| WORDS[options[i as usize] as usize] == words[pos])
                .unwrap();
            press(a, Key::Char((b'1' + pick) as char));
        }
    }
    out
}

#[test]
fn a_split_makes_coldcard_parts_that_load_back() {
    for n in [2u8, 3, 4] {
        let mut a = app();
        let slot = load_legal(&mut a);
        let fp = a.slot(slot as usize).unwrap().fingerprint;
        nav::seed_opt(&mut a, SlotOpt::SeedXor);
        assert_eq!(step(&a), XorStep::Parts { sel: 1 });
        press(&mut a, Key::Char((b'0' + n - 1) as char));
        assert_eq!(step(&a), XorStep::Mode { sel: 0 });
        press(&mut a, Key::Enter);
        let parts = write_and_check_all(&mut a);
        assert_eq!(parts.len(), n as usize);
        assert_eq!(step(&a), XorStep::Done);
        assert_eq!(WORDS[a.xor.as_ref().unwrap().last_word as usize], "yellow");
        press(&mut a, Key::Enter);
        assert!(matches!(a.current(), Screen::SeedOptions { .. }));
        assert!(a.xor.is_none());
        // Coldcard's formula, byte for byte
        let mut want = [[0u8; 32]; seedxor::MAX_PARTS];
        seedxor::split(&[0x7f; 16], n as usize, b"", &mut want).unwrap();
        for (i, p) in parts.iter().enumerate() {
            let idx: Vec<u16> = p.split(' ').map(|w| word_index(w).unwrap()).collect();
            let mut e = [0u8; 32];
            Mnemonic::from_indices(&idx).unwrap().entropy(&mut e);
            assert_eq!(e[..16], want[i][..16], "part {i} of {n}");
        }
        // the parts, in another order, load the seed
        let mut b = app();
        let mut order: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
        order.reverse();
        type_parts(&mut b, &order);
        assert_eq!(b.xor.as_ref().unwrap().result.unwrap().0, fp);
    }
}

#[test]
fn dice_mixed_parts_differ_and_still_make_the_seed() {
    let mut a = app();
    let slot = load_legal(&mut a);
    let fp = a.slot(slot as usize).unwrap().fingerprint;
    nav::seed_opt(&mut a, SlotOpt::SeedXor);
    press(&mut a, Key::Char('1')); // 2 parts
    press(&mut a, Key::Char('2')); // with dice
    assert_eq!(step(&a), XorStep::Dice);
    type_str(&mut a, "12345");
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), XorStep::Dice, "50 rolls needed");
    for i in 0..MIN_DICE {
        press(&mut a, Key::Char((b'1' + (i % 6) as u8) as char));
    }
    press(&mut a, Key::Enter);
    let parts = write_and_check_all(&mut a);
    let mut want = [[0u8; 32]; seedxor::MAX_PARTS];
    seedxor::split(&[0x7f; 16], 2, b"", &mut want).unwrap();
    let first: Vec<u16> = parts[0].split(' ').map(|w| word_index(w).unwrap()).collect();
    let mut e = [0u8; 32];
    Mnemonic::from_indices(&first).unwrap().entropy(&mut e);
    assert_ne!(e[..16], want[0][..16], "not the plain formula");
    let mut b = app();
    let order: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
    type_parts(&mut b, &order);
    assert_eq!(b.xor.as_ref().unwrap().result.unwrap().0, fp);
}

#[test]
fn a_wrong_check_shows_the_part_again_and_the_saver_covers_it() {
    let mut a = app();
    load_legal(&mut a);
    nav::seed_opt(&mut a, SlotOpt::SeedXor);
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), XorStep::Show { part: 0 });
    press(&mut a, Key::Enter);
    let st = a.xor.as_ref().unwrap();
    let (pos, options) = st.check_for_test(0);
    let mut w = [0u16; 24];
    st.part_words(0, &mut w);
    let wrong = (0..4u8).find(|&i| options[i as usize] != w[pos]).unwrap();
    press(&mut a, Key::Char((b'1' + wrong) as char));
    assert_eq!(step(&a), XorStep::Show { part: 0 });
    assert_eq!(a.notice, Some(a.text().bk.sl_check_wrong));
    saver(&mut a);
    press(&mut a, Key::Char('x'));
    assert_eq!(step(&a), XorStep::Covered { part: 0 });
    // Esc leaves for the seed's options without a question
    press(&mut a, Key::Esc);
    assert!(matches!(a.current(), Screen::SeedOptions { .. }));
    assert!(a.xor.is_none());
}

#[test]
fn only_word_seeds_offer_a_split() {
    use crate::seeds::SlotKind;
    assert!(crate::keys::slot_opts(SlotKind::Mnemonic).contains(&SlotOpt::SeedXor));
    for k in [SlotKind::Xprv, SlotKind::Wif, SlotKind::Slip39] {
        assert!(!crate::keys::slot_opts(k).contains(&SlotOpt::SeedXor), "{k:?}");
    }
}

/// Every Seed XOR step drawn in both languages (screen tour, M9 coverage).
#[test]
pub(crate) fn seedxor_screens_fit() {
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(format!("seedxor-{l}-{name}.ppm")));
            }
        };
        let mut a = app();
        a.settings.lang = lang;
        a.set_test_only(true);
        // loading from parts
        nav::go(&mut a, To::Start(Start::XorParts));
        shot(&a, "length");
        nav::words(&mut a, 24);
        type_words(&mut a, &DOC24[0].split(' ').take(5).collect::<Vec<_>>().join(" "));
        shot(&a, "entry");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('2'));
        type_parts(&mut a, &DOC24[..2]);
        shot(&a, "combined");
        press(&mut a, Key::Char('1'));
        type_words(&mut a, DOC24[1]);
        shot(&a, "combined-again");
        press(&mut a, Key::Char('1'));
        shot(&a, "entry-c");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('2'));
        // splitting
        load_legal(&mut a);
        nav::seed_opt(&mut a, SlotOpt::SeedXor);
        shot(&a, "parts");
        press(&mut a, Key::Enter);
        shot(&a, "mode");
        press(&mut a, Key::Char('2'));
        type_str(&mut a, "1234");
        press(&mut a, Key::Enter);
        shot(&a, "dice");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('1'));
        shot(&a, "show");
        press(&mut a, Key::Enter);
        shot(&a, "check");
        press(&mut a, Key::Esc);
        saver(&mut a);
        press(&mut a, Key::Char('x'));
        shot(&a, "covered");
        press(&mut a, Key::Esc);
        nav::seed(&mut a, 0);
        nav::seed_opt(&mut a, SlotOpt::SeedXor);
        press(&mut a, Key::Char('1'));
        press(&mut a, Key::Enter);
        let _ = write_and_check_all(&mut a);
        shot(&a, "done");
        press(&mut a, Key::Char('?'));
        shot(&a, "help");
        let _ = format!("{lang:?}");
    }
}
