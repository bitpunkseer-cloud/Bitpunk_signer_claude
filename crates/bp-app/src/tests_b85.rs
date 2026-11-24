//! Tools > BIP-85 child keys: results agree with embit's vectors, a child
//! mnemonic loads into a slot, the state is wiped, nothing goes to the SD
//! card, and every screen fits in both languages.

use super::*;
use crate::b85::B85Step;
use std::string::String;

fn open(a: &mut App) {
    press(a, Key::Char('3')); // Tools
    press(a, Key::Char('7')); // BIP-85
}

fn step(a: &App) -> B85Step {
    match a.current() {
        Screen::Bip85 { step } => step,
        s => panic!("not BIP-85: {s:?}"),
    }
}

fn result_text(a: &App) -> String {
    let mut t = [0u8; bp_bitcoin::bip85::MAX_TEXT];
    let n = a
        .b85
        .as_ref()
        .unwrap()
        .derived
        .as_ref()
        .unwrap()
        .write_text(&mut t);
    String::from_utf8(t[..n].to_vec()).unwrap()
}

/// From the application list: row, index, then the result.
fn derive(a: &mut App, row: char, index: &str) {
    press(a, Key::Char(row));
    assert_eq!(step(a), B85Step::Params);
    type_str(a, index);
    press(a, Key::Enter);
    assert_eq!(step(a), B85Step::Warning);
    render(a);
    press(a, Key::Enter);
    assert!(matches!(step(a), B85Step::Result { .. }));
    render(a);
}

#[test]
fn child_keys_match_embit() {
    let mut a = app();
    load_abandon(&mut a);
    open(&mut a);
    assert_eq!(step(&a), B85Step::App { sel: 0 });
    derive(&mut a, '1', "7");
    assert_eq!(
        result_text(&a),
        "witness sibling furnace fall indoor virus net island torch avoid talk drum"
    );
    // Esc drops the secret and goes back to the parameters
    press(&mut a, Key::Esc);
    assert_eq!(step(&a), B85Step::Params);
    assert!(a.b85.as_ref().unwrap().derived.is_none());
    press(&mut a, Key::Esc);
    derive(&mut a, '4', "3"); // WIF
    let want = crate::tests_review::b85_embit("Wif", 3);
    assert_eq!(result_text(&a), want);
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    derive(&mut a, '5', "1000"); // XPRV
    assert_eq!(result_text(&a), crate::tests_review::b85_embit("Xprv", 1000));
    // Done closes everything and wipes the state
    press(&mut a, Key::Char('2'));
    assert!(matches!(
        a.current(),
        Screen::Menu {
            id: MenuId::Tools,
            ..
        }
    ));
    assert!(a.b85.is_none());
}

#[test]
fn lengths_stay_in_range() {
    let mut a = app();
    load_abandon(&mut a);
    open(&mut a);
    press(&mut a, Key::Char('8')); // Base85 password, 20 characters
    for _ in 0..30 {
        press(&mut a, Key::Left);
    }
    assert_eq!(
        a.b85.as_ref().unwrap().app,
        bp_bitcoin::bip85::App::PwdBase85 { len: 10 }
    );
    for _ in 0..10 {
        press(&mut a, Key::Up);
    }
    assert_eq!(
        a.b85.as_ref().unwrap().app,
        bp_bitcoin::bip85::App::PwdBase85 { len: 80 }
    );
    // the index stops at 2^31 - 1
    type_str(&mut a, "99999999999");
    assert!(a.b85.as_ref().unwrap().index < (1 << 31));
    press(&mut a, Key::Backspace);
    render(&a);
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter);
    assert_eq!(result_text(&a).len(), 80);
}

#[test]
fn child_mnemonic_loads_into_a_free_slot() {
    let mut a = app();
    load_abandon(&mut a);
    open(&mut a);
    derive(&mut a, '1', "0");
    let words = result_text(&a);
    assert_eq!(
        words,
        "prosper short ramp prepare exchange stove life snack client enough purpose fold"
    );
    press(&mut a, Key::Char('3')); // Load into an empty slot
    assert!(matches!(a.current(), Screen::SeedReady { .. }));
    assert_eq!(a.seed_count(), 2);
    assert!(a.b85.is_none());
    let loaded = a
        .seeds
        .iter()
        .flatten()
        .find(|s| s.fingerprint != a.slot(0).unwrap().fingerprint)
        .unwrap();
    let got: std::vec::Vec<&str> = (0..12)
        .map(|i| loaded.mnemonic.as_ref().unwrap().word(i))
        .collect();
    assert_eq!(got.join(" "), words);
    // with two seeds the first screen asks which one
    for _ in 0..6 {
        press(&mut a, Key::Esc);
    }
    a.reset_to(Screen::Menu {
        id: MenuId::Main,
        sel: 0,
    });
    open(&mut a);
    assert_eq!(step(&a), B85Step::PickSeed { sel: 0 });
    render(&a);
}

#[test]
fn qr_shows_the_secret_but_never_saves_it() {
    let mut a = app();
    load_abandon(&mut a);
    a.set_card_present(true);
    open(&mut a);
    derive(&mut a, '1', "0");
    press(&mut a, Key::Char('2')); // Compact SeedQR
    assert_eq!(
        a.current(),
        Screen::QrShow {
            kind: QrKind::Bip85 { compact: true }
        }
    );
    render(&a);
    let m = match a.b85.as_ref().unwrap().derived.as_ref().unwrap() {
        bp_bitcoin::bip85::Derived::Mnemonic(m) => m.clone(),
        _ => panic!(),
    };
    let mut ent = [0u8; 32];
    let n = bp_bitcoin::seedqr::compact_bytes(&m, &mut ent);
    assert_eq!(a.qr.as_ref().unwrap().payload(), &ent[..n]);
    assert!(!a.export_allowed(QrKind::Bip85 { compact: true }));
    press(&mut a, Key::Char('s'));
    assert!(
        matches!(a.current(), Screen::QrShow { .. }),
        "no save from a secret"
    );
    press(&mut a, Key::Esc);
    assert!(matches!(step(&a), B85Step::Result { .. }));
    assert!(a.qr.is_none(), "QR payload wiped");
    // a text result as QR
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    derive(&mut a, '6', "0"); // HEX
    press(&mut a, Key::Char('1'));
    assert_eq!(a.qr.as_ref().unwrap().payload(), result_text(&a).as_bytes());
}

#[test]
fn needs_a_seed() {
    let mut a = app();
    open(&mut a);
    assert_eq!(a.current(), Screen::NoSeed);
}

#[test]
fn b85_screens_fit() {
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(format!("b85-{l}-{name}.ppm")));
            }
        };
        let mut a = app();
        load_abandon(&mut a);
        a.settings.lang = lang;
        a.set_test_only(true);
        open(&mut a);
        shot(&a, "apps");
        a.set_current(Screen::Bip85 {
            step: B85Step::App { sel: 7 },
        });
        shot(&a, "apps-last");
        press(&mut a, Key::Char('3'));
        type_str(&mut a, "2147483647");
        shot(&a, "params-words");
        press(&mut a, Key::Enter);
        shot(&a, "warning");
        press(&mut a, Key::Enter);
        shot(&a, "result-24");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('1'));
        press(&mut a, Key::Enter);
        press(&mut a, Key::Enter);
        shot(&a, "result-12");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Esc);
        for (row, name) in [('5', "xprv"), ('6', "hex"), ('7', "pwd64")] {
            press(&mut a, Key::Char(row));
            if row == '6' {
                for _ in 0..4 {
                    press(&mut a, Key::Up);
                }
                shot(&a, "params-length");
            }
            press(&mut a, Key::Enter);
            press(&mut a, Key::Enter);
            shot(&a, &format!("result-{name}"));
            press(&mut a, Key::Esc);
            press(&mut a, Key::Esc);
        }
        // a passphrase on the seed is noted
        let mut b = app();
        load_abandon(&mut b);
        b.settings.lang = lang;
        let m = b.slot(0).unwrap().mnemonic.clone().unwrap();
        b.seeds[0] = crate::seeds::SeedSlot::new(m, b"secret");
        open(&mut b);
        press(&mut b, Key::Char('4'));
        press(&mut b, Key::Enter);
        press(&mut b, Key::Enter);
        shot(&b, "result-passphrase");
    }
}
