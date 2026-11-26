//! Secure notes (M11-6): writing, showing, QR, editing, deleting, a
//! password from dice, kept by the vault across power off, and every step
//! drawn in both languages.

extern crate std;

use super::vault_flow::{boot, power_cycle, set_pin, unlock, Bench};
use super::*;
use crate::menus::MenuId;
use crate::nav::{self, To};
use crate::notesui::{password_from_dice, NoteStep, MIN_DICE, PASSWORD_LEN};
use crate::vaultdata::{Field, Note, NoteKind};
use bp_hal::input::Key;
use std::string::String;

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

fn step(a: &App) -> NoteStep {
    match a.current() {
        Screen::Notes { step } => step,
        s => panic!("not a notes screen: {s:?}"),
    }
}

/// On the edit screen: open row `row`, type `text` over what is there.
fn set_field(a: &mut App, row: char, text: &str) {
    press(a, Key::Char(row));
    assert!(matches!(step(a), NoteStep::Field { .. }));
    for _ in 0..500 {
        press(a, Key::Backspace);
    }
    type_str(a, text);
    press(a, Key::Enter);
    assert!(matches!(step(a), NoteStep::Edit { .. }));
}

/// Backup & tools > Secure notes > New password, filled in and saved.
fn new_password(a: &mut App, title: &str, secret: &str) {
    nav::go(a, To::Notes);
    let count = a.vault.data.note_count();
    assert_eq!(step(a), NoteStep::List { sel: 0 });
    // the rows after the notes: New note, New password
    for _ in 0..count + 1 {
        press(a, Key::Down);
    }
    press(a, Key::Enter);
    assert_eq!(step(a), NoteStep::Edit { sel: 0 });
    // rows: title, user, password, generate, site, text, save
    set_field(a, '1', title);
    set_field(a, '2', "alice");
    set_field(a, '3', secret);
    set_field(a, '5', "bank.example");
    set_field(a, '6', "PIN for the card: 1234");
    press(a, Key::Char('7'));
}

#[test]
fn a_password_is_written_shown_edited_and_deleted() {
    let mut a = app();
    nav::go(&mut a, To::Notes);
    assert_eq!(a.vault.data.note_count(), 0);
    press(&mut a, Key::Esc);
    new_password(&mut a, "Bank", "s3cret! pass");
    assert_eq!(step(&a), NoteStep::View { idx: 0, sel: 0 });
    assert_eq!(a.notice, Some(a.text().bk.nt_saved));
    let n = a.vault.data.note(0).unwrap();
    assert_eq!(n.kind, NoteKind::Password);
    assert_eq!(n.get(Field::Title), b"Bank");
    assert_eq!(n.get(Field::User), b"alice");
    assert_eq!(n.get(Field::Secret), b"s3cret! pass");
    assert_eq!(n.get(Field::Site), b"bank.example");
    assert_eq!(n.get(Field::Text), b"PIN for the card: 1234");
    // the password is hidden until asked for
    assert!(!a.notes.as_ref().unwrap().show);
    press(&mut a, Key::Char('1'));
    assert!(a.notes.as_ref().unwrap().show);
    // as a QR: the password itself; the screen saver closes it
    press(&mut a, Key::Char('2'));
    assert_eq!(
        a.current(),
        Screen::QrShow {
            kind: QrKind::Note { idx: 0 }
        }
    );
    assert_eq!(a.qr.as_ref().unwrap().payload(), b"s3cret! pass");
    for _ in 0..13 {
        a.tick(5_000);
    }
    assert!(a.saver);
    press(&mut a, Key::Char('x'));
    assert!(matches!(step(&a), NoteStep::View { .. }));
    // edit the title
    press(&mut a, Key::Char('3'));
    set_field(&mut a, '1', "Bank (old)");
    press(&mut a, Key::Char('7'));
    assert_eq!(a.vault.data.note(0).unwrap().get(Field::Title), b"Bank (old)");
    assert_eq!(a.vault.data.note_count(), 1, "edited, not added");
    // delete: WIPE
    press(&mut a, Key::Char('4'));
    assert_eq!(step(&a), NoteStep::Delete { idx: 0 });
    type_str(&mut a, "WIPE");
    press(&mut a, Key::Enter);
    assert_eq!(a.vault.data.note_count(), 0);
    assert_eq!(step(&a), NoteStep::List { sel: 0 });
}

#[test]
fn a_text_note_and_its_rules() {
    let mut a = app();
    nav::go(&mut a, To::Notes);
    press(&mut a, Key::Enter); // New note
    assert_eq!(step(&a), NoteStep::Edit { sel: 0 });
    // no title: not saved
    press(&mut a, Key::Char('3'));
    assert_eq!(a.notice, Some(a.text().bk.nt_no_title));
    set_field(&mut a, '1', "Recovery plan");
    // a field stops at its length
    press(&mut a, Key::Char('2'));
    type_str(&mut a, &"x".repeat(450));
    assert_eq!(a.notes.as_ref().unwrap().input_len, Field::Text.max());
    press(&mut a, Key::Enter);
    press(&mut a, Key::Char('3'));
    let n = a.vault.data.note(0).unwrap();
    assert_eq!(n.kind, NoteKind::Text);
    assert_eq!(n.get(Field::Text).len(), 400);
    // a text note's QR is its text; it has no password row
    press(&mut a, Key::Char('1'));
    assert_eq!(
        a.current(),
        Screen::QrShow {
            kind: QrKind::Note { idx: 0 }
        }
    );
    press(&mut a, Key::Esc);
    // Esc while editing throws the draft away
    nav::go(&mut a, To::Notes);
    press(&mut a, Key::Char('2')); // New note (after one note)
    set_field(&mut a, '1', "draft");
    press(&mut a, Key::Esc);
    assert_eq!(step(&a), NoteStep::List { sel: 0 });
    assert_eq!(a.vault.data.note_count(), 1);
}

#[test]
fn a_password_from_dice() {
    let mut a = app();
    nav::go(&mut a, To::Notes);
    press(&mut a, Key::Char('2')); // New password
    press(&mut a, Key::Char('4')); // make one from dice
    assert_eq!(step(&a), NoteStep::Generate);
    type_str(&mut a, "123456");
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), NoteStep::Generate, "50 rolls needed");
    let mut rolls = String::from("123456");
    for i in 0..MIN_DICE {
        let c = (b'1' + (i * 7 % 6) as u8) as char;
        rolls.push(c);
        press(&mut a, Key::Char(c));
    }
    press(&mut a, Key::Enter);
    assert!(matches!(step(&a), NoteStep::Edit { sel: 3 }));
    let mut want = [0u8; PASSWORD_LEN];
    password_from_dice(rolls.as_bytes(), &mut want);
    let got = a.notes.as_ref().unwrap().draft.get(Field::Secret).to_vec();
    assert_eq!(got, want);
    // Base58: no 0, O, I or l
    assert!(got
        .iter()
        .all(|c| c.is_ascii_alphanumeric() && !b"0OIl".contains(c)));
    // other rolls, another password
    let mut other = [0u8; PASSWORD_LEN];
    password_from_dice(
        b"6543216543216543216543216543216543216543216543216543",
        &mut other,
    );
    assert_ne!(other, want);
}

#[test]
fn notes_are_kept_by_the_vault_and_written_ones_join_it() {
    let mut b = Bench::new(61);
    let mut a = boot(&mut b);
    nav::home(&mut a);
    // without a vault: kept for the session only
    new_password(&mut a, "Before", "one");
    assert!(!a.vault.is_open());
    set_pin(&mut a, &mut b, "abcd", "efgh");
    press(&mut a, Key::Enter);
    b.serve(&mut a);
    // the note written before the vault existed is in it now
    let mut a = power_cycle(&mut a, &mut b);
    assert_eq!(a.vault.data.note_count(), 0, "power off wiped RAM");
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.data.note_count(), 1);
    assert_eq!(a.vault.data.note(0).unwrap().get(Field::Secret), b"one");
    // a note written with the vault open is saved at once
    nav::home(&mut a);
    new_password(&mut a, "After", "two");
    b.serve(&mut a);
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.data.note_count(), 2);
    // written while "without the vault", it joins when the vault opens
    let mut a = power_cycle(&mut a, &mut b);
    press(&mut a, Key::Esc); // use without the vault
    nav::home(&mut a);
    new_password(&mut a, "Session", "three");
    assert_eq!(a.vault.data.note_count(), 1);
    nav::go(&mut a, To::VaultPin); // the lock screen first
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.data.note_count(), 3);
    b.serve(&mut a);
    let mut a = power_cycle(&mut a, &mut b);
    unlock(&mut a, &mut b, "abcd", "efgh");
    assert_eq!(a.vault.data.note_count(), 3);
    assert_eq!(a.vault.data.note(2).unwrap().get(Field::Title), b"Session");
}

#[test]
fn sixteen_notes_at_most_and_the_vault_body_limit() {
    let mut d = crate::vaultdata::VaultData::new();
    for i in 0..crate::vaultdata::MAX_NOTES {
        let mut n = Note::new(NoteKind::Text);
        assert!(n.set(Field::Title, std::format!("note {i}").as_bytes()));
        assert!(n.set(Field::Text, &[b'x'; 400]));
        assert!(d.add_note(n), "{i}");
    }
    let mut n = Note::new(NoteKind::Text);
    n.set(Field::Title, b"seventeen");
    assert!(!d.add_note(n));
    // fields: printable ASCII and within their length
    let mut n = Note::new(NoteKind::Password);
    assert!(!n.set(Field::Title, "é".as_bytes()));
    assert!(!n.set(Field::Secret, &[b'a'; 65]));
    assert!(!n.set(Field::Text, b"line\nbreak"));
    assert!(n.set(Field::Secret, &[b'a'; 64]));
}

/// Every notes step drawn in both languages (screen tour).
#[test]
pub(crate) fn notes_screens_fit() {
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(std::format!("notes-{l}-{name}.ppm")));
            }
        };
        let mut a = app();
        a.settings.lang = lang;
        a.set_test_only(true);
        nav::go(&mut a, To::Menu(MenuId::Tools));
        shot(&a, "menu");
        nav::home(&mut a);
        shot(&a, "main");
        nav::go(&mut a, To::Notes);
        shot(&a, "list-empty");
        press(&mut a, Key::Esc);
        new_password(
            &mut a,
            "Exchange account with a long title",
            "correct horse battery",
        );
        shot(&a, "view");
        press(&mut a, Key::Char('1'));
        shot(&a, "view-shown");
        press(&mut a, Key::Char('2'));
        shot(&a, "qr");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('3'));
        shot(&a, "edit");
        press(&mut a, Key::Char('3'));
        shot(&a, "field");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('4'));
        type_str(&mut a, "12345");
        press(&mut a, Key::Enter);
        shot(&a, "generate");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('4'));
        type_str(&mut a, "WI");
        shot(&a, "delete");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Esc);
        shot(&a, "list");
        press(&mut a, Key::Char('?'));
        shot(&a, "help");
    }
}
