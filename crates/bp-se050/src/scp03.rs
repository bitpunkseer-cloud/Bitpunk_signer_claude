//! GlobalPlatform SCP03 (Card Specification Amendment D), host side, S8
//! mode: 8-byte challenges, cryptograms and MACs.
//!
//! ```text
//! KDF(key, c, L, ctx) = CMAC(key, 00×11 | c | 00 | L (2) | 01 | ctx)   (L ≤ 128)
//! ctx      = host challenge | card challenge
//! S-ENC    = KDF(ENC, 04, 128)     S-MAC = KDF(MAC, 06, 128)    S-RMAC = KDF(MAC, 07, 128)
//! card     = KDF(S-MAC, 00, 64)    host  = KDF(S-MAC, 01, 64)
//! C-ENC    = AES-CBC(S-ENC, ICV = AES(S-ENC, counter), data | 80 00..)
//! C-MAC    = CMAC(S-MAC, chain | CLA|04 INS P1 P2 Lc | data)  -> chain; first 8 sent
//! R-MAC    = CMAC(S-RMAC, chain | data | SW), first 8
//! R-ENC    = AES-CBC⁻¹(S-ENC, ICV = AES(S-ENC, 80 | counter))
//! ```
//! The counter starts at 1 with the first command after EXTERNAL
//! AUTHENTICATE and goes up with every command, with data or not.
//! Checked against the published known-answer vectors of an independent
//! implementation (GP default keys 40..4F; see the tests).

use crate::apdu::{Apdu, Le, APDU_MAX};
use bp_crypto::aes::{Aes128, Cmac};
use bp_crypto::chacha20poly1305::ct_eq;
use bp_crypto::secret::wipe;

/// C-MAC, C-DECRYPTION, R-MAC, R-ENCRYPTION.
pub const LEVEL_FULL: u8 = 0x33;

/// A static SCP03 key set (the chip holds the same).
#[derive(Clone)]
pub struct StaticKeys {
    pub enc: [u8; 16],
    pub mac: [u8; 16],
    pub dek: [u8; 16],
    /// Key version number (0 = any).
    pub version: u8,
}

impl Drop for StaticKeys {
    fn drop(&mut self) {
        wipe(&mut self.enc);
        wipe(&mut self.mac);
        wipe(&mut self.dek);
    }
}

pub fn kdf(key: &[u8; 16], constant: u8, l_bits: u16, ctx: &[u8]) -> [u8; 16] {
    let mut m = Cmac::new(key);
    m.update(&[0u8; 11]);
    m.update(&[constant, 0]);
    m.update(&l_bits.to_be_bytes());
    m.update(&[1]);
    m.update(ctx);
    m.finalize()
}

/// The answer to INITIALIZE UPDATE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub key_version: u8,
    pub card_challenge: [u8; 8],
    pub card_cryptogram: [u8; 8],
}

/// Diversification data (10), key information (3: version, 03, i),
/// card challenge (8), card cryptogram (8), [sequence counter (3)].
pub fn parse_initialize_update(r: &[u8]) -> Option<Challenge> {
    if !(r.len() == 29 || r.len() == 32) || r[11] != 0x03 {
        return None;
    }
    Some(Challenge {
        key_version: r[10],
        card_challenge: r[13..21].try_into().ok()?,
        card_cryptogram: r[21..29].try_into().ok()?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScpError {
    /// The card's cryptogram is wrong (other keys, or not that card).
    CardCryptogram,
    /// A response MAC is wrong or missing.
    Mac,
    /// A response that cannot be taken apart.
    Format,
    /// Too long to wrap.
    TooLong,
}

/// An open SCP03 session (keys wiped on drop).
pub struct Session {
    s_enc: Aes128,
    s_mac: [u8; 16],
    s_rmac: [u8; 16],
    chain: [u8; 16],
    counter: u32,
    level: u8,
}

impl Drop for Session {
    fn drop(&mut self) {
        wipe(&mut self.s_mac);
        wipe(&mut self.s_rmac);
        wipe(&mut self.chain);
    }
}

fn pad(data: &[u8], out: &mut [u8]) -> usize {
    let n = data.len() / 16 * 16 + 16;
    out[..data.len()].copy_from_slice(data);
    out[data.len()] = 0x80;
    out[data.len() + 1..n].fill(0);
    n
}

impl Session {
    /// The session keys for `host` challenge and the card's answer, and the
    /// host cryptogram. Fails if the card's cryptogram is not the expected
    /// one (wrong keys, or someone else answering).
    pub fn begin(keys: &StaticKeys, host: &[u8; 8], answer: &[u8]) -> Result<(Session, [u8; 8]), ScpError> {
        let ch = parse_initialize_update(answer).ok_or(ScpError::Format)?;
        let mut ctx = [0u8; 16];
        ctx[..8].copy_from_slice(host);
        ctx[8..].copy_from_slice(&ch.card_challenge);
        let mut s_enc = kdf(&keys.enc, 0x04, 128, &ctx);
        let s_mac = kdf(&keys.mac, 0x06, 128, &ctx);
        let s_rmac = kdf(&keys.mac, 0x07, 128, &ctx);
        let card = kdf(&s_mac, 0x00, 64, &ctx);
        let host_c = kdf(&s_mac, 0x01, 64, &ctx);
        let s = Session {
            s_enc: Aes128::new(&s_enc),
            s_mac,
            s_rmac,
            chain: [0; 16],
            counter: 0,
            level: 0,
        };
        wipe(&mut s_enc);
        if !ct_eq(&card[..8], &ch.card_cryptogram) {
            return Err(ScpError::CardCryptogram);
        }
        Ok((s, host_c[..8].try_into().expect("8")))
    }

    /// EXTERNAL AUTHENTICATE at `level`, MACed (the session's first command).
    pub fn external_authenticate(&mut self, level: u8, host_cryptogram: &[u8; 8], out: &mut [u8]) -> usize {
        let head = [0x84, 0x82, level, 0x00, 0x10];
        let mut m = Cmac::new(&self.s_mac);
        m.update(&self.chain);
        m.update(&head);
        m.update(host_cryptogram);
        self.chain = m.finalize();
        out[..5].copy_from_slice(&head);
        out[5..13].copy_from_slice(host_cryptogram);
        out[13..21].copy_from_slice(&self.chain[..8]);
        self.level = level;
        21
    }

    fn icv(&self, response: bool) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[12..].copy_from_slice(&self.counter.to_be_bytes());
        if response {
            b[0] = 0x80;
        }
        self.s_enc.encrypt_block(&mut b);
        b
    }

    /// Wrap a plain command: encrypt its data, MAC it, set the secure
    /// messaging bit of CLA. Short Lc/Le whenever the result fits.
    pub fn wrap(&mut self, a: &Apdu, out: &mut [u8]) -> Result<usize, ScpError> {
        self.counter = self.counter.checked_add(1).ok_or(ScpError::TooLong)?;
        let mut body = [0u8; APDU_MAX];
        let mut n = a.data.len();
        if n + 16 > body.len() {
            return Err(ScpError::TooLong);
        }
        if self.level & 0x02 != 0 && n > 0 {
            n = pad(a.data, &mut body);
            let icv = self.icv(false);
            self.s_enc.cbc_encrypt(&icv, &mut body[..n]);
        } else {
            body[..n].copy_from_slice(a.data);
        }
        let lc = n + 8;
        let extended = lc > 255;
        let mut head = [0u8; 7];
        head[..4].copy_from_slice(&[a.cla | 0x04, a.ins, a.p1, a.p2]);
        let hl = if extended {
            head[4..7].copy_from_slice(&[0, (lc >> 8) as u8, lc as u8]);
            7
        } else {
            head[4] = lc as u8;
            5
        };
        let mut m = Cmac::new(&self.s_mac);
        m.update(&self.chain);
        m.update(&head[..hl]);
        m.update(&body[..n]);
        self.chain = m.finalize();
        let total = hl + n + 8 + 3;
        if total > out.len() {
            return Err(ScpError::TooLong);
        }
        out[..hl].copy_from_slice(&head[..hl]);
        out[hl..hl + n].copy_from_slice(&body[..n]);
        out[hl + n..hl + n + 8].copy_from_slice(&self.chain[..8]);
        let mut len = hl + n + 8;
        let le: &[u8] = match (a.le, extended) {
            (Le::None, _) => &[],
            (Le::Short(l), false) => &[(l & 0xFF) as u8][..],
            (Le::Max, false) => &[0][..],
            (_, true) => &[0, 0][..],
        };
        out[len..len + le.len()].copy_from_slice(le);
        len += le.len();
        wipe(&mut body);
        Ok(len)
    }

    /// Check and open a response `data | R-MAC | SW` in place. Returns the
    /// plain data length (at the start of `resp`) and the status word. A
    /// response with only an error status carries no MAC.
    pub fn unwrap(&mut self, resp: &mut [u8]) -> Result<(usize, u16), ScpError> {
        let n = resp.len();
        if n < 2 {
            return Err(ScpError::Format);
        }
        let sw = u16::from_be_bytes([resp[n - 2], resp[n - 1]]);
        if self.level & 0x10 == 0 {
            return Ok((n - 2, sw));
        }
        if n == 2 {
            return if sw == 0x9000 {
                Err(ScpError::Mac)
            } else {
                Ok((0, sw))
            };
        }
        if n < 10 {
            return Err(ScpError::Format);
        }
        let dlen = n - 10;
        let mut m = Cmac::new(&self.s_rmac);
        m.update(&self.chain);
        m.update(&resp[..dlen]);
        m.update(&resp[n - 2..]);
        let mac = m.finalize();
        if !ct_eq(&mac[..8], &resp[dlen..dlen + 8]) {
            return Err(ScpError::Mac);
        }
        if self.level & 0x20 == 0 || dlen == 0 {
            return Ok((dlen, sw));
        }
        if !dlen.is_multiple_of(16) {
            return Err(ScpError::Format);
        }
        let icv = self.icv(true);
        self.s_enc.cbc_decrypt(&icv, &mut resp[..dlen]);
        // strip 80 00..
        let mut end = dlen;
        while end > 0 && resp[end - 1] == 0 {
            end -= 1;
        }
        if end == 0 || resp[end - 1] != 0x80 || dlen - end >= 16 {
            return Err(ScpError::Format);
        }
        Ok((end - 1, sw))
    }
}

/// Length of the PUT KEY data: version, then three entries of key type
/// (88 = AES), length 11, 10 and the key encrypted under the current DEK,
/// check value length 03 and the check value (first 3 bytes of
/// AES(key, 01×16)).
pub const PUT_KEY_LEN: usize = 1 + 3 * 23;

/// The PUT KEY data for a new key set (ENC, MAC, DEK).
pub fn put_key_data(current_dek: &[u8; 16], new: &StaticKeys, out: &mut [u8; PUT_KEY_LEN]) {
    out[0] = new.version;
    let dek = Aes128::new(current_dek);
    for (i, key) in [&new.enc, &new.mac, &new.dek].into_iter().enumerate() {
        let e = &mut out[1 + 23 * i..1 + 23 * (i + 1)];
        let mut k = *key;
        dek.encrypt_block(&mut k);
        let mut kcv = [1u8; 16];
        Aes128::new(key).encrypt_block(&mut kcv);
        e[0] = 0x88;
        e[1] = 0x11;
        e[2] = 0x10;
        e[3..19].copy_from_slice(&k);
        e[19] = 0x03;
        e[20..23].copy_from_slice(&kcv[..3]);
        wipe(&mut k);
    }
}

/// The check values PUT KEY answers with (version and three KCVs).
pub fn put_key_answer(new: &StaticKeys) -> [u8; 10] {
    let mut a = [0u8; 10];
    a[0] = new.version;
    for (i, key) in [&new.enc, &new.mac, &new.dek].into_iter().enumerate() {
        let mut kcv = [1u8; 16];
        Aes128::new(key).encrypt_block(&mut kcv);
        a[1 + 3 * i..4 + 3 * i].copy_from_slice(&kcv[..3]);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const KEY: [u8; 16] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    ];

    fn keys() -> StaticKeys {
        StaticKeys {
            enc: KEY,
            mac: KEY,
            dek: KEY,
            version: 0,
        }
    }

    /// INITIALIZE UPDATE answer with the card challenge 08..0F and the
    /// card cryptogram of the published vectors.
    fn answer() -> Vec<u8> {
        let mut r = std::vec![0u8; 10];
        r.extend_from_slice(&[0x30, 0x03, 0x70]);
        r.extend_from_slice(&[8, 9, 10, 11, 12, 13, 14, 15]);
        r.extend_from_slice(&hx("114f6bc5052c5228"));
        r
    }

    // Known answers from scll-backend-rustcrypto 1.0.5 tests/scp03_kat.rs
    // (an independent pyca/cryptography reference), GP default keys 40..4F,
    // host challenge 00..07, card challenge 08..0F, level 33.
    #[test]
    fn published_known_answers() {
        let host = [0, 1, 2, 3, 4, 5, 6, 7];
        let (mut s, hc) = Session::begin(&keys(), &host, &answer()).unwrap();
        assert_eq!(hc.to_vec(), hx("fafa93c2ede62463"));
        let mut out = [0u8; 64];
        let n = s.external_authenticate(LEVEL_FULL, &hc, &mut out);
        assert_eq!(
            out[..n].to_vec(),
            hx("8482330010fafa93c2ede62463cb51e38ec18eb00b")
        );
        let cmd = Apdu {
            cla: 0x80,
            ins: 0xe6,
            p1: 0,
            p2: 0,
            data: &[1, 2, 3, 4, 5],
            le: Le::None,
        };
        let mut w = [0u8; 64];
        let n = s.wrap(&cmd, &mut w).unwrap();
        assert_eq!(
            w[..n].to_vec(),
            hx("84e6000018199dd7ff46730b64ac254c903ec573505c4291bb0b788746")
        );
        let mut resp = hx("4c7f4e27e4f90aa7b13c60860f69fcd0989a968b68138d8e9000");
        let (len, sw) = s.unwrap(&mut resp).unwrap();
        assert_eq!((resp[..len].to_vec(), sw), (hx("00a40400"), 0x9000));
    }

    #[test]
    fn a_wrong_card_cryptogram_or_mac_is_refused() {
        let host = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut a = answer();
        a[25] ^= 1;
        assert_eq!(
            Session::begin(&keys(), &host, &a).err(),
            Some(ScpError::CardCryptogram)
        );
        let (mut s, hc) = Session::begin(&keys(), &host, &answer()).unwrap();
        let mut out = [0u8; 64];
        s.external_authenticate(LEVEL_FULL, &hc, &mut out);
        let cmd = Apdu {
            cla: 0x80,
            ins: 0xe6,
            p1: 0,
            p2: 0,
            data: &[1, 2, 3, 4, 5],
            le: Le::None,
        };
        s.wrap(&cmd, &mut out).unwrap();
        let mut bad = hx("4c7f4e27e4f90aa7b13c60860f69fcd0989a968b68138d8e9000");
        bad[20] ^= 0xff;
        assert_eq!(s.unwrap(&mut bad).err(), Some(ScpError::Mac));
        // a 9000 without a MAC is refused; an error status passes
        assert_eq!(s.unwrap(&mut [0x90, 0x00]).err(), Some(ScpError::Mac));
        assert_eq!(s.unwrap(&mut [0x69, 0x82]), Ok((0, 0x6982)));
    }

    #[test]
    fn put_key_encrypts_under_the_dek() {
        // the published PUT KEY block: new key 0f0e..00 under DEK 40..4F
        let new = StaticKeys {
            enc: hx("0f0e0d0c0b0a09080706050403020100").try_into().unwrap(),
            mac: [0x22; 16],
            dek: [0x33; 16],
            version: 0x31,
        };
        let mut out = [0u8; PUT_KEY_LEN];
        put_key_data(&KEY, &new, &mut out);
        assert_eq!(out[0], 0x31);
        assert_eq!(&out[1..4], &[0x88, 0x11, 0x10]);
        assert_eq!(out[4..20].to_vec(), hx("fac3af9fb177982eaba2e63d9ef03986"));
    }
}
