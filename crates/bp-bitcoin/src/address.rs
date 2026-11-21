//! Single-key addresses: P2PKH, P2SH-P2WPKH, P2WPKH and P2TR (BIP-86).

use crate::bech32;
use crate::bip32::{DerivationPath, KeyVersion, HARDENED};
use crate::{base58, Network};
use bp_crypto::hashes::hash160;
use bp_crypto::secp256k1::PublicKey;

pub const MAX_ADDRESS_LEN: usize = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptType {
    /// P2WPKH, BIP-84
    NativeSegwit,
    /// P2TR key path, BIP-86
    Taproot,
    /// P2SH-P2WPKH, BIP-49
    NestedSegwit,
    /// P2PKH, BIP-44
    Legacy,
}

impl ScriptType {
    pub const ALL: [ScriptType; 4] = [
        ScriptType::NativeSegwit,
        ScriptType::Taproot,
        ScriptType::NestedSegwit,
        ScriptType::Legacy,
    ];

    pub const fn purpose(self) -> u32 {
        match self {
            ScriptType::NativeSegwit => 84,
            ScriptType::Taproot => 86,
            ScriptType::NestedSegwit => 49,
            ScriptType::Legacy => 44,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            ScriptType::NativeSegwit => "Native SegWit",
            ScriptType::Taproot => "Taproot",
            ScriptType::NestedSegwit => "Nested SegWit",
            ScriptType::Legacy => "Legacy",
        }
    }

    /// SLIP-132 version for the account xpub (Taproot uses plain xpub).
    pub const fn key_version(self) -> KeyVersion {
        match self {
            ScriptType::NativeSegwit => KeyVersion::Z,
            ScriptType::NestedSegwit => KeyVersion::Y,
            ScriptType::Taproot | ScriptType::Legacy => KeyVersion::X,
        }
    }

    /// Descriptor function wrapping the key, e.g. `wpkh(...)`.
    pub const fn descriptor_prefix(self) -> &'static str {
        match self {
            ScriptType::NativeSegwit => "wpkh(",
            ScriptType::Taproot => "tr(",
            ScriptType::NestedSegwit => "sh(wpkh(",
            ScriptType::Legacy => "pkh(",
        }
    }

    pub const fn descriptor_suffix(self) -> &'static str {
        match self {
            ScriptType::NestedSegwit => "))",
            _ => ")",
        }
    }

    /// `m/purpose'/coin'/account'`
    pub fn account_path(self, net: Network, account: u32) -> DerivationPath {
        let steps = [
            self.purpose() | HARDENED,
            net.coin_type() | HARDENED,
            (account & !HARDENED) | HARDENED,
        ];
        DerivationPath::from_steps(&steps).expect("depth 3")
    }
}

/// BIP-86 output key: x(lift_x(P) + H_TapTweak(x(P)) * G).
pub fn taproot_output_key(internal: &PublicKey) -> Option<[u8; 32]> {
    bp_crypto::secp256k1::schnorr::tweak_public_key(&internal.x_only(), None).map(|(q, _)| q)
}

/// Encode the address for `pk`; returns its length.
pub fn encode(pk: &PublicKey, st: ScriptType, net: Network, out: &mut [u8; MAX_ADDRESS_LEN]) -> usize {
    match st {
        ScriptType::NativeSegwit => {
            bech32::encode_segwit(net.hrp(), 0, &hash160(&pk.serialize()), out).expect("valid program")
        }
        ScriptType::Taproot => {
            let q = taproot_output_key(pk).expect("tweak is valid except with negligible probability");
            bech32::encode_segwit(net.hrp(), 1, &q, out).expect("valid program")
        }
        ScriptType::NestedSegwit => {
            let mut redeem = [0u8; 22];
            redeem[0] = 0x00;
            redeem[1] = 0x14;
            redeem[2..].copy_from_slice(&hash160(&pk.serialize()));
            let mut payload = [0u8; 21];
            payload[0] = net.p2sh_version();
            payload[1..].copy_from_slice(&hash160(&redeem));
            base58::encode_check(&payload, out).expect("fits")
        }
        ScriptType::Legacy => {
            let mut payload = [0u8; 21];
            payload[0] = net.p2pkh_version();
            payload[1..].copy_from_slice(&hash160(&pk.serialize()));
            base58::encode_check(&payload, out).expect("fits")
        }
    }
}
