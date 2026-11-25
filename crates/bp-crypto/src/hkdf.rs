//! HKDF-SHA256 (RFC 5869): binds the vault's secrets into one key (M10).

use crate::hmac::HmacSha256;
use crate::secret::wipe;

/// The output asked for is longer than 255 x 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong;

/// HKDF-Extract: a pseudorandom key from input keying material parts.
pub fn extract(salt: &[u8], ikm: &[&[u8]]) -> [u8; 32] {
    let mut h = HmacSha256::new(salt);
    for part in ikm {
        h.update(part);
    }
    h.finalize()
}

/// HKDF-Expand: fill `out` from the pseudorandom key and `info`.
pub fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), TooLong> {
    if out.len() > 255 * 32 {
        return Err(TooLong);
    }
    let mut t = [0u8; 32];
    let mut have = 0usize;
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let mut h = HmacSha256::new(prk);
        if i > 0 {
            h.update(&t);
        }
        h.update(info);
        h.update(&[(i + 1) as u8]);
        t = h.finalize();
        chunk.copy_from_slice(&t[..chunk.len()]);
        have += chunk.len();
    }
    debug_assert_eq!(have, out.len());
    wipe(&mut t);
    Ok(())
}

/// Extract then expand.
pub fn hkdf(salt: &[u8], ikm: &[&[u8]], info: &[u8], out: &mut [u8]) -> Result<(), TooLong> {
    let mut prk = extract(salt, ikm);
    let r = expand(&prk, info, out);
    wipe(&mut prk);
    r
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        let s: std::string::String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5869 A.1
    #[test]
    fn rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let prk = extract(&salt, &[&ikm]);
        assert_eq!(
            prk.as_slice(),
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").as_slice()
        );
        let mut okm = [0u8; 42];
        expand(&prk, &info, &mut okm).unwrap();
        assert_eq!(
            okm.as_slice(),
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
                .as_slice()
        );
    }

    /// RFC 5869 A.3 (no salt, no info)
    #[test]
    fn rfc5869_case_3() {
        let mut okm = [0u8; 42];
        hkdf(&[], &[&[0x0bu8; 22]], &[], &mut okm).unwrap();
        assert_eq!(
            okm.as_slice(),
            hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
                .as_slice()
        );
    }

    #[test]
    fn matches_the_reference_crate_and_parts_concatenate() {
        let mut x = 0xfeed_beef_0123_4567u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..200 {
            let salt: Vec<u8> = (0..next() % 80).map(|_| next() as u8).collect();
            let a: Vec<u8> = (0..next() % 50).map(|_| next() as u8).collect();
            let b: Vec<u8> = (0..next() % 50).map(|_| next() as u8).collect();
            let info: Vec<u8> = (0..next() % 40).map(|_| next() as u8).collect();
            let n = 1 + (next() % 200) as usize;
            let mut ours = std::vec![0u8; n];
            hkdf(&salt, &[&a, &b], &info, &mut ours).unwrap();
            let ikm: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
            let mut want = std::vec![0u8; n];
            ::hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &ikm)
                .expand(&info, &mut want)
                .unwrap();
            assert_eq!(ours, want);
        }
        let mut big = std::vec![0u8; 255 * 32 + 1];
        assert_eq!(hkdf(b"s", &[b"k"], b"", &mut big), Err(TooLong));
    }
}
