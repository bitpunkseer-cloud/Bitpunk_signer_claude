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
    /// Twenty-sided die.
    D20,
    TypeWords,
    WordNumbers,
    /// Words drawn by the user + coin flips for the last word's free bits.
    FinalWord,
}

#[derive(Clone, Copy)]
pub enum Action {
    Open(MenuId),
    /// Not built yet: label + milestone description.
    Todo(Label, Label),
    /// Tools > Address explorer (picks a seed first if several are loaded).
    Explorer,
    /// Tools > Verify address (scans an address, needs a loaded seed).
    VerifyAddress,
    /// Tools > Sign message (needs message signing turned on).
    SignMessage,
    /// Tools > Verify signature.
    VerifySignature,
    /// Tools > Multisig wallets.
    Multisig,
    /// Main > SD card.
    SdCard,
    /// Tools > BIP-85 child keys.
    Bip85,
    /// Settings > Settings as QR.
    SettingsQr,
    Start(Start),
    CycleSetting,
    About,
    PowerOff,
    /// Open the camera scanner.
    Scan(crate::scan::Purpose),
}

macro_rules! todo_entry {
    ($f:expr, $tag:literal, $desc:expr) => {
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

static MAIN: [Entry; 6] = [
    Entry {
        label: |s| s.scan_qr,
        detail: ">",
        action: Action::Scan(crate::scan::Purpose::Any),
    },
    open(|s| s.seeds, MenuId::Seeds),
    open(|s| s.tools, MenuId::Tools),
    open(|s| s.settings, MenuId::Settings),
    Entry {
        label: |s| s.sd.menu,
        detail: ">",
        action: Action::SdCard,
    },
    open(|s| s.power, MenuId::Power),
];

static SEEDS: [Entry; 4] = [
    open(|s| s.create_seed, MenuId::NewSeed),
    open(|s| s.load_seed, MenuId::LoadSeed),
    todo_entry!(|s| s.import_key, "M8", |s| s.ms_keys),
    todo_entry!(|s| s.seed_vault, "M9", |s| s.ms_storage),
];

static NEW_SEED: [Entry; 4] = [
    start(|s| s.dice_rolls, Start::Dice),
    start(|s| s.coin_flips, Start::Coin),
    start(|s| s.d20_rolls, Start::D20),
    todo_entry!(|s| s.slip39, "M10", |s| s.ms_backup),
];

static LOAD_SEED: [Entry; 6] = [
    start(|s| s.type_words, Start::TypeWords),
    start(|s| s.word_numbers, Start::WordNumbers),
    Entry {
        label: |s| s.scan_seedqr,
        detail: ">",
        action: Action::Scan(crate::scan::Purpose::Seed),
    },
    todo_entry!(|s| s.tinyseed, "M10", |s| s.ms_backup),
    todo_entry!(|s| s.seed_xor, "M10", |s| s.ms_backup),
    todo_entry!(|s| s.encrypted_backup, "M10", |s| s.ms_backup),
];

static TOOLS: [Entry; 9] = [
    start(|s| s.final_word, Start::FinalWord),
    Entry {
        label: |s| s.address_explorer,
        detail: ">",
        action: Action::Explorer,
    },
    Entry {
        label: |s| s.verify_address,
        detail: ">",
        action: Action::VerifyAddress,
    },
    Entry {
        label: |s| s.sign_message,
        detail: ">",
        action: Action::SignMessage,
    },
    Entry {
        label: |s| s.verify_sig,
        detail: ">",
        action: Action::VerifySignature,
    },
    Entry {
        label: |s| s.wl.menu,
        detail: ">",
        action: Action::Multisig,
    },
    Entry {
        label: |s| s.bip85,
        detail: ">",
        action: Action::Bip85,
    },
    todo_entry!(|s| s.secure_notes, "M10", |s| s.ms_tools),
    todo_entry!(|s| s.totp, "M10", |s| s.ms_tools),
];

static SETTINGS: [Entry; 12] = [
    setting(|s| s.network),
    setting(|s| s.units),
    setting(|s| s.qr_density),
    setting(|s| s.advanced),
    setting(|s| s.language),
    setting(|s| s.msg_signing),
    setting(|s| s.fee_warn_label),
    setting(|s| s.fee_block_label),
    setting(|s| s.fee_rate_label),
    setting(|s| s.sd.wipe_setting),
    Entry {
        label: |s| s.settings_qr,
        detail: ">",
        action: Action::SettingsQr,
    },
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
