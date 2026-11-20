//! PBKDF2-HMAC-SHA512 (RFC 8018), as used by BIP-39.

use crate::hmac::HmacSha512;
use crate::secret::wipe;
use crate::sha512::DIGEST_LEN;

/// Derive `out.len()` bytes. The salt may be given in several parts that are
/// concatenated (BIP-39 uses `"mnemonic" || passphrase`), avoiding allocation.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt_parts: &[&[u8]], iterations: u32, out: &mut [u8]) {
    assert!(iterations > 0, "iterations must be positive");
    let keyed = HmacSha512::new(password);
    for (block_idx, chunk) in out.chunks_mut(DIGEST_LEN).enumerate() {
        let mut mac = keyed.clone();
        for part in salt_parts {
            mac.update(part);
        }
        mac.update(&((block_idx as u32) + 1).to_be_bytes());
        let mut u = mac.finalize();
        let mut t = u;
        for _ in 1..iterations {
            let mut mac = keyed.clone();
            mac.update(&u);
            let next = mac.finalize();
            u = next;
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= ui;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
        wipe(&mut u);
        wipe(&mut t);
    }
}
