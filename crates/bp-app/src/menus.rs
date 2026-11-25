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
    /// Settings > Security: the vault's PIN, locking, erasing (M10).
    Security,
    Power,
}

pub const MAX_ITEMS: usize = 15;

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
    /// Seed XOR parts, typed one after another (M11-3).
    XorParts,
    /// A metal plate's dots, entered cell by cell (M11-4).
    MetalGrid,
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
    /// Settings > Security > PIN (set up, change; unlock first if locked).
    VaultPin,
    /// Seeds & keys > Seed vault (unlock first if locked).
    SeedVault,
    /// Settings > Security > Trick PINs (M10-6).
    VaultTricks,
    /// Settings > Security > Tamper check (M10-7).
    VaultTamper,
    /// Settings > Security > Lock now.
    VaultLock,
    /// Settings > Security > Erase the vault.
    VaultWipe,
    /// Seeds & keys > New seed > SLIP-39 wallet (M11-2).
    Slip39New,
    /// Seeds & keys > Load a seed > SLIP-39 shares (M11-2).
    Slip39Load,
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

static SEEDS: [Entry; 5] = [
    open(|s| s.create_seed, MenuId::NewSeed),
    open(|s| s.load_seed, MenuId::LoadSeed),
    action(|s| s.import_key, Action::ImportKey),
    action(|s| s.bip85, Action::Bip85),
    action(|s| s.vault.sv_menu, Action::SeedVault),
];

static NEW_SEED: [Entry; 5] = [
    start(|s| s.dice_rolls, Start::Dice),
    start(|s| s.coin_flips, Start::Coin),
    start(|s| s.d20_rolls, Start::D20),
    start(|s| s.final_word, Start::FinalWord),
    action(|s| s.bk.sl_new_menu, Action::Slip39New),
];

static LOAD_SEED: [Entry; 6] = [
    start(|s| s.type_words, Start::TypeWords),
    start(|s| s.word_numbers, Start::WordNumbers),
    action(|s| s.scan_seedqr, Action::Scan(crate::scan::Purpose::Seed)),
    action(|s| s.bk.sl_load_menu, Action::Slip39Load),
    start(|s| s.bk.xr_load_menu, Start::XorParts),
    start(|s| s.bk.mt_load_menu, Start::MetalGrid),
];

static SETTINGS: [Entry; 15] = [
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
    setting(|s| s.saver_label),
    open(|s| s.vault.menu, MenuId::Security),
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

static SECURITY: [Entry; 5] = [
    Entry {
        label: |s| s.vault.row_pin,
        detail: ">",
        action: Action::VaultPin,
    },
    Entry {
        label: |s| s.vault.row_tricks,
        detail: ">",
        action: Action::VaultTricks,
    },
    Entry {
        label: |s| s.vault.row_tamper,
        detail: ">",
        action: Action::VaultTamper,
    },
    Entry {
        label: |s| s.vault.row_lock,
        detail: "",
        action: Action::VaultLock,
    },
    Entry {
        label: |s| s.vault.row_wipe,
        detail: ">",
        action: Action::VaultWipe,
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
        MenuId::Security => &SECURITY,
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
        MenuId::Security => s.vault.menu,
        MenuId::Power => s.power,
    }
}

/// The row of `parent` that opens `child` (for returning with the
/// selection where the user left it).
pub fn row_opening(parent: MenuId, child: MenuId) -> u8 {
    table(parent)
        .iter()
        .position(|e| matches!(e.action, Action::Open(id) if id == child))
        .unwrap_or(0) as u8
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
            MenuId::Security,
            MenuId::Power,
        ] {
            assert!(!table(id).is_empty() && table(id).len() <= MAX_ITEMS);
        }
    }
}
