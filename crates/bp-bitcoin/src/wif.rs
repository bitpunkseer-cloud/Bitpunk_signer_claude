//! Wallet Import Format for single private keys (compressed only).

use crate::base58;
use crate::Network;
use bp_crypto::secp256k1::SecretKey;

/// Longest WIF string (52 characters for a compressed key).
pub const WIF_LEN: usize = 52;

fn prefix(net: Network) -> u8 {
    if net == Network::Mainnet {
        0x80
    } else {
        0xEF
    }
}

/// Encode a compressed-key WIF. Returns its length.
pub fn encode(sk: &SecretKey, net: Network, out: &mut [u8; WIF_LEN]) -> usize {
    let mut raw = [0u8; 34];
    raw[0] = prefix(net);
    raw[1..33].copy_from_slice(&sk.to_bytes());
    raw[33] = 0x01;
    let n = base58::encode_check(&raw, out).unwrap_or(0);
    bp_crypto::secret::wipe(&mut raw);
    n
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifError {
    /// Not Base58Check, or not a key of the right length.
    Invalid,
    /// A key of another network.
    Network,
    /// An uncompressed key (not supported: every script here needs the
    /// compressed form).
    Uncompressed,
    /// Zero or not below the curve order.
    OutOfRange,
}

/// Decode a WIF. Mainnet keys for mainnet, testnet keys for the test
/// networks (testnet, signet, regtest).
pub fn decode(s: &str, net: Network) -> Result<SecretKey, WifError> {
    let mut raw = [0u8; 40];
    let n = base58::decode_check(s.trim(), &mut raw).map_err(|_| WifError::Invalid)?;
    let r = (|| {
        if n != 33 && n != 34 {
            return Err(WifError::Invalid);
        }
        match raw[0] {
            0x80 | 0xEF => {}
            _ => return Err(WifError::Invalid),
        }
        if raw[0] != prefix(net) {
            return Err(WifError::Network);
        }
        if n == 33 {
            return Err(WifError::Uncompressed);
        }
        if raw[33] != 0x01 {
            return Err(WifError::Invalid);
        }
        let key: [u8; 32] = raw[1..33].try_into().map_err(|_| WifError::Invalid)?;
        SecretKey::from_bytes(&key).ok_or(WifError::OutOfRange)
    })();
    bp_crypto::secret::wipe(&mut raw);
    r
}
