//! Static menu tree (M9-4: grouped by task). Features not built yet are
//! listed under Settings > About, not in the menus.

use crate::text::Strings;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuId {
    Main,
    /// Sign: scan a PSBT or message QR, type a message.
    Sign,
    /// Receive and verify: addresses, address and signature checks.
    Verify,
    /// Seeds and keys. Loaded seeds are listed above the static rows (see `App`).
    Seeds,
    NewSeed,
    LoadSeed,
    Settings,
    Power,
}

pub const MAX_ITEMS: usize = 13;

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
    /// Seeds > Import private key.
    ImportKey,
    /// Settings > Settings as QR.
    SettingsQr,
    Start(Start),
    CycleSetting,
    About,
    PowerOff,
    /// Open the camera scanner.
    Scan(crate::scan::Purpose),
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

const fn action(label: Label, action: Action) -> Entry {
    Entry {
        label,
        detail: ">",
        action,
    }
}

static MAIN: [Entry; 7] = [
    open(|s| s.m_sign, MenuId::Sign),
    open(|s| s.m_verify, MenuId::Verify),
    open(|s| s.m_seeds, MenuId::Seeds),
    action(|s| s.wl.menu, Action::Multisig),
    action(|s| s.sd.menu, Action::SdCard),
    open(|s| s.settings, MenuId::Settings),
    open(|s| s.power, MenuId::Power),
];

static SIGN: [Entry; 2] = [
    action(|s| s.scan_qr, Action::Scan(crate::scan::Purpose::Any)),
    action(|s| s.sign_message, Action::SignMessage),
];

static VERIFY: [Entry; 3] = [
    action(|s| s.address_explorer, Action::Explorer),
    action(|s| s.verify_address, Action::VerifyAddress),
    action(|s| s.verify_sig, Action::VerifySignature),
];

static SEEDS: [Entry; 4] = [
    open(|s| s.create_seed, MenuId::NewSeed),
    open(|s| s.load_seed, MenuId::LoadSeed),
    action(|s| s.import_key, Action::ImportKey),
    action(|s| s.bip85, Action::Bip85),
];

static NEW_SEED: [Entry; 4] = [
    start(|s| s.dice_rolls, Start::Dice),
    start(|s| s.coin_flips, Start::Coin),
    start(|s| s.d20_rolls, Start::D20),
    start(|s| s.final_word, Start::FinalWord),
];

static LOAD_SEED: [Entry; 3] = [
    start(|s| s.type_words, Start::TypeWords),
    start(|s| s.word_numbers, Start::WordNumbers),
    action(|s| s.scan_seedqr, Action::Scan(crate::scan::Purpose::Seed)),
];

static SETTINGS: [Entry; 13] = [
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
    setting(|s| s.fx_label),
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
        MenuId::Sign => &SIGN,
        MenuId::Verify => &VERIFY,
        MenuId::Seeds => &SEEDS,
        MenuId::NewSeed => &NEW_SEED,
        MenuId::LoadSeed => &LOAD_SEED,
        MenuId::Settings => &SETTINGS,
        MenuId::Power => &POWER,
    }
}

pub fn title(id: MenuId, s: &Strings) -> &'static str {
    match id {
        MenuId::Main => s.app_title,
        MenuId::Sign => s.m_sign,
        MenuId::Verify => s.m_verify,
        MenuId::Seeds => s.m_seeds,
        MenuId::NewSeed => s.create_seed,
        MenuId::LoadSeed => s.load_seed,
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
            MenuId::Sign,
            MenuId::Verify,
            MenuId::Seeds,
            MenuId::NewSeed,
            MenuId::LoadSeed,
            MenuId::Settings,
            MenuId::Power,
        ] {
            assert!(!table(id).is_empty() && table(id).len() <= MAX_ITEMS);
        }
    }
}
