//! Bitpunk Signer Bitcoin protocol layer (Bitcoin-only).
//!
//! Planned: BIP-39, BIP-32, addresses (Base58Check, Bech32/Bech32m),
//! PSBT v0/v2, output descriptors, miniscript.
#![no_std]

pub mod address;
pub mod base58;
pub mod base64;
pub mod bech32;
pub mod bip32;
pub mod bip39;
pub mod entropy;
pub mod psbt;
pub mod qrinput;
pub mod seedqr;
pub mod sighash;
pub mod tx;
pub mod urtypes;

/// Bitcoin networks supported by the signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    pub const ALL: [Network; 4] = [Self::Mainnet, Self::Testnet, Self::Signet, Self::Regtest];

    /// Short badge label for the status bar.
    pub const fn badge(self) -> &'static str {
        match self {
            Self::Mainnet => "MAIN",
            Self::Testnet => "TEST",
            Self::Signet => "SIGNET",
            Self::Regtest => "REGTEST",
        }
    }

    /// BIP-44 coin type: 0 on mainnet, 1 on every test network.
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            _ => 1,
        }
    }

    /// Bech32 human-readable part.
    pub const fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "bc",
            Self::Testnet | Self::Signet => "tb",
            Self::Regtest => "bcrt",
        }
    }

    pub const fn p2pkh_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x00,
            _ => 0x6f,
        }
    }

    pub const fn p2sh_version(self) -> u8 {
        match self {
            Self::Mainnet => 0x05,
            _ => 0xc4,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "Mainnet",
            Self::Testnet => "Testnet",
            Self::Signet => "Signet",
            Self::Regtest => "Regtest",
        }
    }
}
