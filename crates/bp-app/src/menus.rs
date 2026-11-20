//! Static menu tree. Features not built yet point at their roadmap phase.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuId {
    Main,
    Seeds,
    NewSeed,
    LoadSeed,
    Tools,
    Settings,
    Power,
}

pub const MAX_ITEMS: usize = 12;

pub struct Entry {
    pub label: &'static str,
    pub detail: &'static str,
    pub action: Action,
}

#[derive(Clone, Copy)]
pub enum Action {
    Open(MenuId),
    Todo {
        title: &'static str,
        phase: &'static str,
    },
    CycleSetting,
    About,
    PowerOff,
}

const fn todo(label: &'static str, phase: &'static str) -> Entry {
    Entry {
        label,
        detail: phase_short(phase),
        action: Action::Todo { title: label, phase },
    }
}

const fn phase_short(phase: &'static str) -> &'static str {
    // detail column shows a compact phase tag
    match phase.as_bytes()[6] {
        b'1' => "P1",
        b'2' => "P2",
        b'3' => "P3",
        b'4' => "P4",
        _ => "P5",
    }
}

const fn open(label: &'static str, id: MenuId) -> Entry {
    Entry {
        label,
        detail: ">",
        action: Action::Open(id),
    }
}

const fn setting(label: &'static str) -> Entry {
    Entry {
        label,
        detail: "",
        action: Action::CycleSetting,
    }
}

const P1: &str = "Phase 1 (MVP single-sig signer)";
const P2: &str = "Phase 2 (wallets & microSD)";
const P3: &str = "Phase 3 (secure storage & advanced)";

static MAIN: [Entry; 5] = [
    todo("Scan QR", P1),
    open("Seeds", MenuId::Seeds),
    open("Tools", MenuId::Tools),
    open("Settings", MenuId::Settings),
    open("Power", MenuId::Power),
];

static SEEDS: [Entry; 4] = [
    open("Create new seed", MenuId::NewSeed),
    open("Load seed", MenuId::LoadSeed),
    todo("Import private key (WIF / xprv)", P2),
    todo("Seed vault", P3),
];

static NEW_SEED: [Entry; 5] = [
    todo("12 words (hardware TRNG)", P1),
    todo("24 words (hardware TRNG)", P1),
    todo("Dice rolls (D6 / D20)", P1),
    todo("Camera image entropy", P1),
    todo("SLIP-39 Shamir shares", P3),
];

static LOAD_SEED: [Entry; 6] = [
    todo("Type words (QWERTY)", P1),
    todo("Scan SeedQR", P1),
    todo("Enter word numbers", P1),
    todo("Tinyseed / Stackbit", P3),
    todo("Seed XOR restore", P3),
    todo("Encrypted backup (microSD)", P3),
];

static TOOLS: [Entry; 7] = [
    todo("Final word calculator", P1),
    todo("Address explorer", P1),
    todo("Verify address", P1),
    todo("Sign message", P2),
    todo("BIP-85 child seeds", P2),
    todo("Secure notes", P3),
    todo("TOTP authenticator", P3),
];

static SETTINGS: [Entry; 5] = [
    setting("Network"),
    setting("Units"),
    setting("QR density"),
    setting("Advanced features"),
    Entry {
        label: "About",
        detail: ">",
        action: Action::About,
    },
];

static POWER: [Entry; 1] = [Entry {
    label: "Wipe memory and power off",
    detail: "",
    action: Action::PowerOff,
}];

fn table(id: MenuId) -> &'static [Entry] {
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

pub fn title(id: MenuId) -> &'static str {
    match id {
        MenuId::Main => "Bitpunk Signer",
        MenuId::Seeds => "Seeds",
        MenuId::NewSeed => "Create new seed",
        MenuId::LoadSeed => "Load seed",
        MenuId::Tools => "Tools",
        MenuId::Settings => "Settings",
        MenuId::Power => "Power",
    }
}

pub fn len(id: MenuId) -> usize {
    table(id).len()
}

pub fn entry(id: MenuId, i: u8) -> &'static Entry {
    &table(id)[i as usize]
}

pub fn action(id: MenuId, i: u8) -> Action {
    entry(id, i).action
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
            assert!(len(id) > 0 && len(id) <= MAX_ITEMS);
        }
    }
}
