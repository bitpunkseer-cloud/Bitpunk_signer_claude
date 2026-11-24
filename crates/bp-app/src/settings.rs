//! User settings (in RAM; persistence arrives with secure storage in M10,
//! until then a SettingsQR carries them across power cycles).
//!
//! SettingsQR: `bitpunk-settings::v1 key=value ...` (SeedSigner's form).
//! A scanned one never weakens safety: turning message signing on or
//! raising a fee threshold is left for the device's own menu.

use crate::menus::MenuId;
use crate::text::Strings;
use bp_bitcoin::validate::Policy;
use bp_bitcoin::Network;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Ko,
}

impl Lang {
    pub const ALL: [Lang; 2] = [Lang::En, Lang::Ko];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Units {
    Btc,
    Sats,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QrDensity {
    Low,
    Medium,
    High,
}

/// Fee warning: percent of the outputs.
pub const FEE_WARN: [u64; 3] = [2, 5, 10];
/// Fee limit (refused): percent of the outputs.
pub const FEE_BLOCK: [u64; 3] = [10, 25, 50];
/// Fee rate warning, sat/vB.
pub const FEE_RATE: [u64; 3] = [500, 1000, 5000];
const FEE_WARN_LABELS: [&str; 3] = ["2%", "5%", "10%"];
const FEE_BLOCK_LABELS: [&str; 3] = ["10%", "25%", "50%"];
const FEE_RATE_LABELS: [&str; 3] = ["500 sat/vB", "1,000 sat/vB", "5,000 sat/vB"];

/// Settings menu rows.
pub const ROW_NETWORK: u8 = 0;
pub const ROW_UNITS: u8 = 1;
pub const ROW_DENSITY: u8 = 2;
pub const ROW_ADVANCED: u8 = 3;
pub const ROW_LANG: u8 = 4;
pub const ROW_MSG: u8 = 5;
pub const ROW_FEE_WARN: u8 = 6;
pub const ROW_FEE_BLOCK: u8 = 7;
pub const ROW_FEE_RATE: u8 = 8;
pub const ROW_SD_WIPE: u8 = 9;
pub const ROW_FX: u8 = 10;
pub const ROW_SAVER: u8 = 11;
/// Rows that hold a value (the rest are actions).
pub const VALUE_ROWS: u8 = 12;
/// Screen saver delays (the last choice turns it off).
pub const SAVER_MS: [Option<u32>; 3] = [Some(60_000), Some(300_000), None];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub network: Network,
    pub units: Units,
    pub qr_density: QrDensity,
    pub advanced: bool,
    pub lang: Lang,
    /// Message signing (off by default; only the device turns it on).
    pub msg_signing: bool,
    /// Indexes into FEE_WARN, FEE_BLOCK and FEE_RATE.
    pub fee_warn: u8,
    pub fee_block: u8,
    pub fee_rate: u8,
    /// After saving a signed PSBT file, wipe the original (zeros, blank
    /// name, delete). Off by default; set on the device only (not in
    /// SettingsQR or the settings file).
    pub sd_wipe_original: bool,
    /// Screen effects (M9): device only, like `sd_wipe_original`.
    pub fx: bp_ui::fx::Fx,
    /// Screen saver (M9): index into SAVER_MS; device only.
    pub saver: u8,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            units: Units::Sats,
            qr_density: QrDensity::Medium,
            advanced: false,
            lang: Lang::En,
            msg_signing: false,
            fee_warn: 1,
            fee_block: 0,
            fee_rate: 1,
            sd_wipe_original: false,
            fx: bp_ui::fx::Fx::Reduced,
            saver: 0,
        }
    }
}

fn step<T: Copy + PartialEq>(all: &[T], cur: T, dir: i8) -> T {
    let i = all.iter().position(|&v| v == cur).unwrap_or(0) as i32;
    let n = all.len() as i32;
    all[((i + dir as i32).rem_euclid(n)) as usize]
}

impl Settings {
    /// The validator's thresholds from these settings.
    pub fn policy(&self) -> Policy {
        Policy {
            fee_warn_percent: FEE_WARN[self.fee_warn as usize % 3],
            fee_block_percent: FEE_BLOCK[self.fee_block as usize % 3],
            fee_rate_warn: FEE_RATE[self.fee_rate as usize % 3],
            ..Policy::default()
        }
    }

    /// Change the setting at row `sel` of `menu`. Returns true if it changed.
    pub fn cycle(&mut self, menu: MenuId, sel: u8, dir: i8) -> bool {
        if menu != MenuId::Settings {
            return false;
        }
        match sel {
            ROW_NETWORK => self.network = step(&Network::ALL, self.network, dir),
            ROW_UNITS => self.units = step(&[Units::Btc, Units::Sats], self.units, dir),
            ROW_DENSITY => {
                self.qr_density = step(
                    &[QrDensity::Low, QrDensity::Medium, QrDensity::High],
                    self.qr_density,
                    dir,
                )
            }
            ROW_ADVANCED => self.advanced = !self.advanced,
            ROW_LANG => self.lang = step(&Lang::ALL, self.lang, dir),
            ROW_MSG => self.msg_signing = !self.msg_signing,
            ROW_FEE_WARN => self.fee_warn = step(&[0, 1, 2], self.fee_warn, dir),
            ROW_FEE_BLOCK => self.fee_block = step(&[0, 1, 2], self.fee_block, dir),
            ROW_FEE_RATE => self.fee_rate = step(&[0, 1, 2], self.fee_rate, dir),
            ROW_SD_WIPE => self.sd_wipe_original = !self.sd_wipe_original,
            ROW_FX => self.fx = step(&bp_ui::fx::Fx::ALL, self.fx, dir),
            ROW_SAVER => self.saver = step(&[0, 1, 2], self.saver, dir),
            _ => return false,
        }
        true
    }

    /// Current value shown in the menu's right-hand column.
    pub fn value_label(&self, menu: MenuId, sel: u8, s: &Strings) -> Option<&'static str> {
        if menu != MenuId::Settings {
            return None;
        }
        Some(match sel {
            ROW_NETWORK => self.network.name(),
            ROW_UNITS => match self.units {
                Units::Btc => "BTC",
                Units::Sats => "sats",
            },
            ROW_DENSITY => s.densities[1 + self.qr_density as usize],
            ROW_ADVANCED => s.on_off[self.advanced as usize],
            ROW_LANG => crate::text::LANGUAGES[self.lang as usize],
            ROW_MSG => s.on_off[self.msg_signing as usize],
            ROW_FEE_WARN => FEE_WARN_LABELS[self.fee_warn as usize % 3],
            ROW_FEE_BLOCK => FEE_BLOCK_LABELS[self.fee_block as usize % 3],
            ROW_FEE_RATE => FEE_RATE_LABELS[self.fee_rate as usize % 3],
            ROW_SD_WIPE => s.on_off[self.sd_wipe_original as usize],
            ROW_FX => s.fx_values[self.fx as usize],
            ROW_SAVER => s.saver_values[self.saver as usize % 3],
            _ => return None,
        })
    }

    /// The SettingsQR text of every setting.
    pub fn to_qr(&self, out: &mut [u8]) -> usize {
        let net = match self.network {
            Network::Mainnet => "main",
            Network::Testnet => "test",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        };
        let units = if self.units == Units::Btc { "btc" } else { "sats" };
        let density = ["low", "medium", "high"][self.qr_density as usize];
        let lang = ["en", "ko"][self.lang as usize];
        let b = bp_ui::bformat!(
            240,
            "{PREFIX} network={net} units={units} qr_density={density} advanced={} lang={lang} msg_signing={} fee_warn={} fee_limit={} fee_rate={}",
            self.advanced as u8,
            self.msg_signing as u8,
            FEE_WARN[self.fee_warn as usize % 3],
            FEE_BLOCK[self.fee_block as usize % 3],
            FEE_RATE[self.fee_rate as usize % 3]
        );
        let n = b.as_str().len().min(out.len());
        out[..n].copy_from_slice(&b.as_str().as_bytes()[..n]);
        n
    }

    /// Settings from a SettingsQR, applied on top of `self`. Weakening
    /// changes are not applied but reported in `Import::blocked`.
    pub fn import(&self, text: &[u8]) -> Result<Import, ImportError> {
        let text = core::str::from_utf8(text).map_err(|_| ImportError::Format)?;
        let mut words = text.split_ascii_whitespace();
        if words.next() != Some(PREFIX) {
            return Err(ImportError::Format);
        }
        let mut want = *self;
        let mut seen = 0u16;
        for w in words {
            let (k, v) = w.split_once('=').ok_or(ImportError::Format)?;
            let pick = |opts: &[&str]| opts.iter().position(|o| *o == v).ok_or(ImportError::Value);
            let bit: u16 = match k {
                "network" => {
                    want.network = [
                        Network::Mainnet,
                        Network::Testnet,
                        Network::Signet,
                        Network::Regtest,
                    ][pick(&["main", "test", "signet", "regtest"])?];
                    1
                }
                "units" => {
                    want.units = [Units::Sats, Units::Btc][pick(&["sats", "btc"])?];
                    2
                }
                "qr_density" => {
                    want.qr_density = [QrDensity::Low, QrDensity::Medium, QrDensity::High]
                        [pick(&["low", "medium", "high"])?];
                    4
                }
                "advanced" => {
                    want.advanced = pick(&["0", "1"])? == 1;
                    8
                }
                "lang" => {
                    want.lang = Lang::ALL[pick(&["en", "ko"])?];
                    16
                }
                "msg_signing" => {
                    want.msg_signing = pick(&["0", "1"])? == 1;
                    32
                }
                "fee_warn" => {
                    want.fee_warn = pick(&["2", "5", "10"])? as u8;
                    64
                }
                "fee_limit" => {
                    want.fee_block = pick(&["10", "25", "50"])? as u8;
                    128
                }
                "fee_rate" => {
                    want.fee_rate = pick(&["500", "1000", "5000"])? as u8;
                    256
                }
                _ => return Err(ImportError::Key),
            };
            if seen & bit != 0 {
                return Err(ImportError::Duplicate);
            }
            seen |= bit;
        }
        // never weaken safety from a QR
        let mut blocked = Blocked::default();
        if want.msg_signing && !self.msg_signing {
            want.msg_signing = false;
            blocked.msg_signing = true;
        }
        if want.fee_warn > self.fee_warn {
            want.fee_warn = self.fee_warn;
            blocked.fee_warn = true;
        }
        if want.fee_block > self.fee_block {
            want.fee_block = self.fee_block;
            blocked.fee_block = true;
        }
        if want.fee_rate > self.fee_rate {
            want.fee_rate = self.fee_rate;
            blocked.fee_rate = true;
        }
        Ok(Import {
            settings: want,
            blocked,
        })
    }
}

pub const PREFIX: &str = "bitpunk-settings::v1";

/// Settings a QR asked to weaken (not applied).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Blocked {
    pub msg_signing: bool,
    pub fee_warn: bool,
    pub fee_block: bool,
    pub fee_rate: bool,
}

impl Blocked {
    pub fn any(&self) -> bool {
        self.msg_signing || self.fee_warn || self.fee_block || self.fee_rate
    }

    /// Menu rows of the blocked settings.
    pub fn rows(&self) -> impl Iterator<Item = u8> + '_ {
        [
            (self.msg_signing, ROW_MSG),
            (self.fee_warn, ROW_FEE_WARN),
            (self.fee_block, ROW_FEE_BLOCK),
            (self.fee_rate, ROW_FEE_RATE),
        ]
        .into_iter()
        .filter_map(|(b, r)| b.then_some(r))
    }
}

/// A scanned SettingsQR: the settings it would give, and what it may not
/// change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Import {
    pub settings: Settings,
    pub blocked: Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// Not "bitpunk-settings::v1 key=value ...".
    Format,
    Key,
    Value,
    Duplicate,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_qr_round_trips() {
        let s = Settings {
            network: Network::Signet,
            units: Units::Btc,
            qr_density: QrDensity::High,
            advanced: true,
            lang: Lang::Ko,
            msg_signing: false,
            fee_warn: 0,
            fee_block: 0,
            fee_rate: 0,
            sd_wipe_original: false,
            fx: bp_ui::fx::Fx::Reduced,
            saver: 0,
        };
        let mut b = [0u8; 256];
        let n = s.to_qr(&mut b);
        let i = Settings::default().import(&b[..n]).unwrap();
        // the defaults are stricter in nothing here, so all applies
        assert_eq!(i.settings, s);
        assert!(!i.blocked.any());
    }

    #[test]
    fn a_qr_never_weakens_safety() {
        let strict = Settings::default();
        let i = strict
            .import(b"bitpunk-settings::v1 msg_signing=1 fee_warn=10 fee_limit=50 fee_rate=5000 lang=ko")
            .unwrap();
        assert_eq!(i.settings.lang, Lang::Ko, "harmless changes apply");
        assert_eq!(
            (
                i.settings.msg_signing,
                i.settings.fee_warn,
                i.settings.fee_block,
                i.settings.fee_rate
            ),
            (false, 1, 0, 1)
        );
        assert!(i.blocked.msg_signing && i.blocked.fee_warn && i.blocked.fee_block && i.blocked.fee_rate);
        // tightening is fine
        let loose = Settings {
            msg_signing: true,
            fee_block: 2,
            ..Settings::default()
        };
        let i = loose
            .import(b"bitpunk-settings::v1 msg_signing=0 fee_limit=10")
            .unwrap();
        assert!(!i.settings.msg_signing && i.settings.fee_block == 0 && !i.blocked.any());
    }

    #[test]
    fn mutated_settings_qrs_never_panic_or_weaken() {
        let base = b"bitpunk-settings::v1 network=main units=sats qr_density=medium advanced=0 lang=en msg_signing=1 fee_warn=10 fee_limit=50 fee_rate=5000";
        let strict = Settings::default();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut ok = 0;
        for _ in 0..20_000 {
            let mut v = base.to_vec();
            for _ in 0..1 + next() % 4 {
                let i = (next() as usize) % v.len();
                match next() % 3 {
                    0 => v[i] = next() as u8,
                    1 => {
                        v.remove(i);
                    }
                    _ => v.insert(i, b"= 01a"[(next() % 5) as usize]),
                }
                if v.is_empty() {
                    break;
                }
            }
            if let Ok(i) = strict.import(&v) {
                ok += 1;
                let p = i.settings.policy();
                assert!(!i.settings.msg_signing);
                assert!(p.fee_warn_percent <= 5 && p.fee_block_percent <= 10 && p.fee_rate_warn <= 1000);
            }
        }
        assert!(ok > 100, "{ok}");
    }

    #[test]
    fn bad_settings_qrs_are_refused() {
        let s = Settings::default();
        for (t, e) in [
            (&b"settings::v1 lang=ko"[..], ImportError::Format),
            (b"bitpunk-settings::v2 lang=ko", ImportError::Format),
            (b"bitpunk-settings::v1 lang", ImportError::Format),
            (b"bitpunk-settings::v1 lang=fr", ImportError::Value),
            (b"bitpunk-settings::v1 fee_warn=3", ImportError::Value),
            (b"bitpunk-settings::v1 colour=red", ImportError::Key),
            (b"bitpunk-settings::v1 lang=ko lang=en", ImportError::Duplicate),
        ] {
            assert_eq!(s.import(t), Err(e), "{}", core::str::from_utf8(t).unwrap());
        }
    }
}
