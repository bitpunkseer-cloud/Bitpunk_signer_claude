//! Static menu tree. Features not built yet show the milestone that builds them.

use crate::text::Strings;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuId {
    Main,
    /// Loaded seeds are listed above the static rows (see `App`).
    Seeds,
    NewSeed,
    LoadSeed,
    Tools,
    Settings,
    Power,
}

pub const MAX_ITEMS: usize = 12;

type Label = fn(&Strings) -> &'static str;

pub struct Entry {
    pub label: Label,
    pub detail: &'static str,
    pub action: Action,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    Dice,
    Coin,
    TypeWords,
    WordNumbers,
}

#[derive(Clone, Copy)]
pub enum Action {
    Open(MenuId),
    /// Not built yet: label + milestone description.
    Todo(Label, &'static str),
    Start(Start),
    CycleSetting,
    About,
    PowerOff,
}

macro_rules! todo_entry {
    ($f:expr, $tag:literal, $desc:literal) => {
        Entry {
            label: $f,
            detail: $tag,
            action: Action::Todo($f, $desc),
        }
    };
}

const fn open(label: Label, id: MenuId) -> Entry {
    Entry {
        label,
        detail: ">",
        action: Action::Open(id),
    }
}

const fn start(label: Label, s: Start) -> Entry {
    Entry {
        label,
        detail: ">",
        action: Action::Start(s),
    }
}

const fn setting(label: Label) -> Entry {
    Entry {
        label,
        detail: "",
        action: Action::CycleSetting,
    }
}

static MAIN: [Entry; 5] = [
    todo_entry!(|s| s.scan_qr, "M4", "Milestone M4 (QR input)"),
    open(|s| s.seeds, MenuId::Seeds),
    open(|s| s.tools, MenuId::Tools),
    open(|s| s.settings, MenuId::Settings),
    open(|s| s.power, MenuId::Power),
];

static SEEDS: [Entry; 4] = [
    open(|s| s.create_seed, MenuId::NewSeed),
    open(|s| s.load_seed, MenuId::LoadSeed),
    todo_entry!(|s| s.import_key, "M8", "Milestone M8 (microSD, keys)"),
    todo_entry!(|s| s.seed_vault, "M9", "Milestone M9 (secure storage)"),
];

static NEW_SEED: [Entry; 3] = [
    start(|s| s.dice_rolls, Start::Dice),
    start(|s| s.coin_flips, Start::Coin),
    todo_entry!(|s| s.slip39, "M10", "Milestone M10 (advanced backup)"),
];

static LOAD_SEED: [Entry; 6] = [
    start(|s| s.type_words, Start::TypeWords),
    start(|s| s.word_numbers, Start::WordNumbers),
    todo_entry!(|s| s.scan_seedqr, "M4", "Milestone M4 (QR input)"),
    todo_entry!(|s| s.tinyseed, "M10", "Milestone M10 (advanced backup)"),
    todo_entry!(|s| s.seed_xor, "M10", "Milestone M10 (advanced backup)"),
    todo_entry!(|s| s.encrypted_backup, "M10", "Milestone M10 (advanced backup)"),
];

static TOOLS: [Entry; 6] = [
    todo_entry!(|s| s.address_explorer, "M2", "Milestone M2 (keys & addresses)"),
    todo_entry!(|s| s.verify_address, "M6", "Milestone M6 (signing extras)"),
    todo_entry!(|s| s.sign_message, "M6", "Milestone M6 (signing extras)"),
    todo_entry!(|s| s.bip85, "M8", "Milestone M8 (microSD, keys)"),
    todo_entry!(|s| s.secure_notes, "M10", "Milestone M10 (advanced tools)"),
    todo_entry!(|s| s.totp, "M10", "Milestone M10 (advanced tools)"),
];

static SETTINGS: [Entry; 5] = [
    setting(|s| s.network),
    setting(|s| s.units),
    setting(|s| s.qr_density),
    setting(|s| s.advanced),
    Entry {
        label: |s| s.about,
        detail: ">",
        action: Action::About,
    },
];

static POWER: [Entry; 1] = [Entry {
    label: |s| s.power_off,
    detail: "",
    action: Action::PowerOff,
}];

pub fn table(id: MenuId) -> &'static [Entry] {
    match id {
        MenuId::Main => &MAIN,
        MenuId::Seeds => &SEEDS,
        MenuId::NewSeed => &NEW_SEED,
        MenuId::LoadSeed => &LOAD_SEED,
        MenuId::Tools => &TOOLS,
        MenuId::Settings => &SETTINGS,
        MenuId::Power => &POWER,
    }
}

pub fn title(id: MenuId, s: &Strings) -> &'static str {
    match id {
        MenuId::Main => s.app_title,
        MenuId::Seeds => s.seeds,
        MenuId::NewSeed => s.create_seed,
        MenuId::LoadSeed => s.load_seed,
        MenuId::Tools => s.tools,
        MenuId::Settings => s.settings,
        MenuId::Power => s.power,
    }
}

pub fn is_settings(id: MenuId) -> bool {
    id == MenuId::Settings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menus_fit_max_items() {
        for id in [
            MenuId::Main,
            MenuId::Seeds,
            MenuId::NewSeed,
            MenuId::LoadSeed,
            MenuId::Tools,
            MenuId::Settings,
            MenuId::Power,
        ] {
            assert!(!table(id).is_empty() && table(id).len() <= MAX_ITEMS);
        }
    }
}
