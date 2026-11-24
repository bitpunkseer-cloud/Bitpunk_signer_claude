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
