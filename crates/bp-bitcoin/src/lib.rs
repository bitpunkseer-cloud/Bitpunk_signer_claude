//! Bitpunk Signer Bitcoin protocol layer (Bitcoin-only).
//!
//! Planned: BIP-39, BIP-32, addresses (Base58Check, Bech32/Bech32m),
//! PSBT v0/v2, output descriptors, miniscript.
#![no_std]

pub mod bip39;

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

    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "Mainnet",
            Self::Testnet => "Testnet",
            Self::Signet => "Signet",
            Self::Regtest => "Regtest",
        }
    }
}
