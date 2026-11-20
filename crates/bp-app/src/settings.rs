//! User settings (in RAM; persistence arrives with secure storage in Phase 3).

use crate::menus::MenuId;
use bp_bitcoin::Network;

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

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub network: Network,
    pub units: Units,
    pub qr_density: QrDensity,
    pub advanced: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            units: Units::Sats,
            qr_density: QrDensity::Medium,
            advanced: false,
        }
    }
}

fn step<T: Copy + PartialEq>(all: &[T], cur: T, dir: i8) -> T {
    let i = all.iter().position(|&v| v == cur).unwrap_or(0) as i32;
    let n = all.len() as i32;
    all[((i + dir as i32).rem_euclid(n)) as usize]
}

impl Settings {
    /// Change the setting at row `sel` of `menu`. Returns true if it changed.
    pub fn cycle(&mut self, menu: MenuId, sel: u8, dir: i8) -> bool {
        if menu != MenuId::Settings {
            return false;
        }
        match sel {
            0 => self.network = step(&Network::ALL, self.network, dir),
            1 => self.units = step(&[Units::Btc, Units::Sats], self.units, dir),
            2 => {
                self.qr_density = step(
                    &[QrDensity::Low, QrDensity::Medium, QrDensity::High],
                    self.qr_density,
                    dir,
                )
            }
            3 => self.advanced = !self.advanced,
            _ => return false,
        }
        true
    }

    /// Current value shown in the menu's right-hand column.
    pub fn value_label(&self, menu: MenuId, sel: u8) -> Option<&'static str> {
        if menu != MenuId::Settings {
            return None;
        }
        Some(match sel {
            0 => self.network.name(),
            1 => match self.units {
                Units::Btc => "BTC",
                Units::Sats => "sats",
            },
            2 => match self.qr_density {
                QrDensity::Low => "Low",
                QrDensity::Medium => "Medium",
                QrDensity::High => "High",
            },
            3 => {
                if self.advanced {
                    "On"
                } else {
                    "Off"
                }
            }
            _ => return None,
        })
    }
}
