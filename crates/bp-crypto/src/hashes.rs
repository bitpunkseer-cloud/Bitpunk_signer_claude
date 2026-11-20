//! Bitcoin hash compositions.

use crate::ripemd160::Ripemd160;
use crate::sha256::Sha256;

/// RIPEMD160(SHA256(data)) — public key and script hashes.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(&Sha256::digest(data))
}

/// SHA256(SHA256(data)) — Base58Check checksums, txids.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(&Sha256::digest(data))
}

/// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data...).
pub fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let t = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(&t);
    h.update(&t);
    for p in parts {
        h.update(p);
    }
    h.finalize()
}
