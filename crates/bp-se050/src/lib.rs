//! NXP SE050 secure element driver (M10-8, decision 1).
//!
//! Layers, each a module, each tested on its own:
//!
//! | module | what |
//! |---|---|
//! | `crc` | CRC-16/X.25 of T=1 frames |
//! | `t1` | T=1 over I2C (NXP UM11225): blocks, chaining, WTX, resync, soft reset |
//! | `apdu` | ISO 7816-4 commands (short and extended length), BER-TLV |
//! | `scp03` | GlobalPlatform SCP03 (Amendment D): session keys, C-MAC + C-ENC, R-MAC + R-ENC, PUT KEY |
//! | `cmd` | the SE05x applet commands the vault needs |
//! | `device` | `Se050`: the vault's `SecureElement` on those objects |
//! | `mock` | (feature `mock`) a simulated SE050 at the I2C level |
//!
//! Written from the specifications; the frames and APDUs are compared in
//! tests with the `se05x` crate (Nitrokey), used only there. Until the
//! chip is on the bench (H track) every byte is checked against that
//! reference and the simulated chip, not against silicon.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(test, feature = "mock"))]
extern crate std;

pub mod apdu;
pub mod cmd;
pub mod crc;
pub mod device;
pub mod scp03;
pub mod t1;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

pub use device::Se050;

#[cfg(test)]
mod tests;
