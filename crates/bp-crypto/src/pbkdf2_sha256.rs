//! PBKDF2-HMAC-SHA256 (RFC 8018), as used by the SLIP-39 Feistel cipher
//! (M11). New file under the file-level freeze: `pbkdf2.rs` (SHA-512, BIP-39)
//! stays as it was.

use crate::hmac::HmacSha256;
use crate::secret::wipe;

const DIGEST_LEN: usize = 32;

/// Derive `out.len()` bytes. The salt may be given in several parts that are
/// concatenated (SLIP-39 uses `salt || R`), avoiding allocation.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt_parts: &[&[u8]], iterations: u32, out: &mut [u8]) {
    assert!(iterations > 0, "iterations must be positive");
    let keyed = HmacSha256::new(password);
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
            u = mac.finalize();
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= ui;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
        wipe(&mut u);
        wipe(&mut t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(password: &[u8], salt: &[u8], iterations: u32, len: usize) -> [u8; 80] {
        let mut out = [0u8; 80];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, &mut out[..len]);
        out
    }

    #[test]
    fn rfc7914_vectors() {
        // RFC 7914 section 11 (PBKDF2-HMAC-SHA256).
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha256(b"passwd", &[b"salt"], 1, &mut out);
        assert_eq!(
            out[..16],
            [
                0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6,
                0x05
            ]
        );
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha256(b"Password", &[b"NaCl"], 80000, &mut out);
        assert_eq!(
            out[..16],
            [
                0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21, 0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27, 0x01,
                0xf9
            ]
        );
    }

    #[test]
    fn matches_the_reference_crate() {
        let mut seed = 7u32;
        let mut next = || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (seed >> 16) as u8
        };
        for case in 0..60usize {
            let pw_len = case * 3 % 90; // longer than a block too
            let salt_len = case * 7 % 40;
            let len = 1 + case % 80;
            let iterations = 1 + (case as u32 % 5) * 7;
            let mut pw = [0u8; 90];
            let mut salt = [0u8; 40];
            pw.iter_mut().for_each(|b| *b = next());
            salt.iter_mut().for_each(|b| *b = next());
            let want = reference(&pw[..pw_len], &salt[..salt_len], iterations, len);
            let mut got = [0u8; 80];
            let (a, b) = salt[..salt_len].split_at(salt_len / 2);
            pbkdf2_hmac_sha256(&pw[..pw_len], &[a, b], iterations, &mut got[..len]);
            assert_eq!(got[..len], want[..len], "case {case}");
        }
    }
}
