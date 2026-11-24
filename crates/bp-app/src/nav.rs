//! Test navigation by feature, not by key number (M9-0).
//!
//! Menu paths are found by searching the menu tables from the main menu, so
//! reorganising the menus (M9-4) changes no test: a feature that is no longer
//! reachable fails `go` (and the reachability test) instead of silently
//! testing something else. Choices inside flows go through the named helpers
//! below — the one place that knows their key positions.

extern crate std;

use super::*;
use crate::menus::{Action, MenuId, Start};
use bp_hal::input::Key;
use std::collections::VecDeque;
use std::vec::Vec;

/// A menu row, named by what it does.
#[derive(Clone, Copy, Debug)]
pub enum To {
    Menu(MenuId),
    Scan(scan::Purpose),
    Start(Start),
    Explorer,
    VerifyAddress,
    SignMessage,
    VerifySignature,
    Multisig,
    SdCard,
    Bip85,
    ImportKey,
    SettingsQr,
    About,
    PowerOff,
    /// A settings row, by its English label.
    Setting(fn(&crate::text::Strings) -> &'static str),
}

/// Every menu row kind except settings rows and placeholders: the features
/// the menus must keep reaching (the reachability test walks this list).
pub const FEATURES: &[To] = &[
    To::Menu(MenuId::Seeds),
    To::Menu(MenuId::NewSeed),
    To::Menu(MenuId::LoadSeed),
    To::Menu(MenuId::Tools),
    To::Menu(MenuId::Settings),
    To::Menu(MenuId::Power),
    To::Scan(scan::Purpose::Any),
    To::Scan(scan::Purpose::Seed),
    To::Start(Start::Dice),
    To::Start(Start::Coin),
    To::Start(Start::D20),
    To::Start(Start::TypeWords),
    To::Start(Start::WordNumbers),
    To::Start(Start::FinalWord),
    To::Explorer,
    To::VerifyAddress,
    To::SignMessage,
    To::VerifySignature,
    To::Multisig,
    To::SdCard,
    To::Bip85,
    To::ImportKey,
    To::SettingsQr,
    To::About,
    To::PowerOff,
];

fn is(t: To, action: &Action, label: &str) -> bool {
    match (t, action) {
        (To::Menu(a), Action::Open(b)) => a == *b,
        (To::Scan(a), Action::Scan(b)) => a == *b,
        (To::Start(a), Action::Start(b)) => a == *b,
        (To::Explorer, Action::Explorer)
        | (To::VerifyAddress, Action::VerifyAddress)
        | (To::SignMessage, Action::SignMessage)
        | (To::VerifySignature, Action::VerifySignature)
        | (To::Multisig, Action::Multisig)
        | (To::SdCard, Action::SdCard)
        | (To::Bip85, Action::Bip85)
        | (To::ImportKey, Action::ImportKey)
        | (To::SettingsQr, Action::SettingsQr)
        | (To::About, Action::About)
        | (To::PowerOff, Action::PowerOff) => true,
        (To::Setting(f), Action::CycleSetting) => f(&crate::text::EN) == label,
        _ => false,
    }
}

/// The rows to activate from the main menu to reach `t` (static rows only:
/// loaded seeds above the Seeds menu are added when pressing).
pub fn path(t: To) -> Option<Vec<(MenuId, usize)>> {
    let mut queue = VecDeque::new();
    queue.push_back((MenuId::Main, Vec::new()));
    let mut seen = Vec::new();
    while let Some((id, route)) = queue.pop_front() {
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        for (row, e) in menus::table(id).iter().enumerate() {
            let mut next: Vec<(MenuId, usize)> = route.clone();
            next.push((id, row));
            if is(t, &e.action, (e.label)(&crate::text::EN)) {
                return Some(next);
            }
            if let Action::Open(sub) = e.action {
                queue.push_back((sub, next));
            }
        }
    }
    None
}

fn press(a: &mut App, k: Key) {
    a.on_key(KeyEvent::new(k));
}

/// Back to the main menu with Esc, as a user would.
pub fn home(a: &mut App) {
    for _ in 0..16 {
        if matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }) {
            return;
        }
        press(a, Key::Esc);
    }
    panic!("could not get back to the main menu from {:?}", a.current());
}

/// Activate row `row` of the static rows of the menu on screen.
fn activate_row(a: &mut App, id: MenuId, row: usize) {
    let Screen::Menu { id: now, sel } = a.current() else {
        panic!("expected menu {id:?}, got {:?}", a.current());
    };
    assert_eq!(now, id, "navigation left the expected menu");
    let row = row + if id == MenuId::Seeds { a.seed_count() } else { 0 };
    if row < 9 {
        press(a, Key::Char((b'1' + row as u8) as char));
    } else {
        let n = a.menu_rows(id);
        for _ in 0..(row + n - sel as usize) % n {
            press(a, Key::Down);
        }
        press(a, Key::Enter);
    }
}

/// Open the feature `t` from wherever the app is (via the main menu).
pub fn go(a: &mut App, t: To) {
    home(a);
    let route = path(t).unwrap_or_else(|| panic!("{t:?} is not reachable from the main menu"));
    for (id, row) in route {
        activate_row(a, id, row);
    }
}

/// Open a menu and stay on it.
pub fn menu(a: &mut App, id: MenuId) {
    go(a, To::Menu(id));
}

// ---------- choices inside flows ----------

/// Seeds menu: open the options of loaded seed number `n` (0-based, as listed).
pub fn seed(a: &mut App, n: usize) {
    menu(a, MenuId::Seeds);
    assert!(n < a.seed_count());
    press(a, Key::Char((b'1' + n as u8) as char));
    assert!(matches!(a.current(), Screen::SeedOptions { .. }));
}

/// Seed options: pick an option by meaning.
pub fn seed_opt(a: &mut App, o: keys::SlotOpt) {
    let Screen::SeedOptions { slot, .. } = a.current() else {
        panic!("expected seed options, got {:?}", a.current());
    };
    let kind = a.slot(slot as usize).expect("slot").kind;
    let i = keys::slot_opts(kind)
        .iter()
        .position(|x| *x == o)
        .unwrap_or_else(|| panic!("{o:?} not offered for {kind:?}"));
    press(a, Key::Char((b'1' + i as u8) as char));
}

/// Number of words chosen on the "how many words" screen.
pub fn words(a: &mut App, n: usize) {
    assert!(matches!(a.current(), Screen::ChooseWords { .. }));
    let key = match n {
        12 => '1',
        24 => '2',
        _ => panic!("12 or 24 words"),
    };
    press(a, Key::Char(key));
}

/// Script type list (xpub export or explorer): pick a script type.
pub fn script(a: &mut App, st: ScriptType) {
    assert!(matches!(a.current(), Screen::ScriptSelect { .. }));
    let i = a
        .visible_scripts()
        .iter()
        .position(|x| *x == st)
        .unwrap_or_else(|| panic!("{st:?} is not offered"));
    press(a, Key::Char((b'1' + i as u8) as char));
}

/// Settings: move the selection to a row (by its English label) without
/// changing it; Left/Right then change the value.
pub fn select_setting(a: &mut App, label: fn(&crate::text::Strings) -> &'static str) {
    menu(a, MenuId::Settings);
    let row = menus::table(MenuId::Settings)
        .iter()
        .position(|e| (e.label)(&crate::text::EN) == label(&crate::text::EN))
        .expect("settings row");
    let n = a.menu_rows(MenuId::Settings);
    let Screen::Menu { sel, .. } = a.current() else {
        unreachable!()
    };
    for _ in 0..(row + n - sel as usize) % n {
        press(a, Key::Down);
    }
    assert_eq!(
        a.current(),
        Screen::Menu {
            id: MenuId::Settings,
            sel: row as u8
        }
    );
}

/// Rows of the SD card status screen.
#[derive(Clone, Copy, Debug)]
pub enum SdRow {
    SignPsbt,
    Browse,
    Format,
    ReadAgain,
}

/// The key that picks an SD status row.
pub fn sd_row(r: SdRow) -> Key {
    let i = match r {
        SdRow::SignPsbt => 0,
        SdRow::Browse => 1,
        SdRow::Format => 2,
        SdRow::ReadAgain => 3,
    };
    Key::Char((b'1' + i) as char)
}

/// The key for an action on the open file (by meaning).
pub fn file_action(a: &App, f: sd::FileAction) -> Key {
    let i = sd::file_actions(a.sd.kind)
        .iter()
        .position(|x| *x == f)
        .unwrap_or_else(|| panic!("{f:?} not offered for {:?}", a.sd.kind));
    Key::Char((b'1' + i as u8) as char)
}

/// The key for the open file's main action (sign, import, or view).
pub fn file_main(a: &App) -> Key {
    let _ = sd::file_actions(a.sd.kind).first().expect("file actions");
    Key::Char('1')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every feature row is reachable from the main menu, by real keys.
    #[test]
    fn every_feature_is_reachable() {
        for &t in FEATURES {
            let mut a = App::new(b"nav");
            a.tick(SPLASH_MS);
            assert!(path(t).is_some(), "{t:?} has no path from the main menu");
            go(&mut a, t);
            assert!(
                !matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }),
                "{t:?} did not leave the main menu"
            );
        }
    }
}
