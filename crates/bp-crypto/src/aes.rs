//! AES-128 (FIPS-197), for the secure element's SCP03 channel (M10-8).
//!
//! Every S-box lookup reads the whole table and keeps the wanted byte with
//! a mask, so no memory access depends on key or data (no cache-timing
//! leak). That costs about 4 kB of table reads per byte; SCP03 moves only
//! a few dozen blocks per command, so speed does not matter here.

use crate::secret::wipe;

pub const BLOCK: usize = 16;

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// The inverse table, built at compile time from `SBOX`.
const INV_SBOX: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    t
};

/// `table[x]`, reading every entry.
#[inline(never)]
fn lookup(table: &[u8; 256], x: u8) -> u8 {
    let mut r = 0u8;
    for (i, v) in table.iter().enumerate() {
        // 0xff when i == x, else 0, without a branch
        let d = (i as u8 ^ x) as u16;
        let mask = (d.wrapping_sub(1) >> 8) as u8;
        r |= v & mask;
    }
    r
}

fn xtime(b: u8) -> u8 {
    (b << 1) ^ (0x1b & 0u8.wrapping_sub(b >> 7))
}

fn mul(mut a: u8, mut b: u8) -> u8 {
    // constant time: 8 rounds whatever the values
    let mut r = 0u8;
    for _ in 0..8 {
        r ^= a & 0u8.wrapping_sub(b & 1);
        a = xtime(a);
        b >>= 1;
    }
    r
}

/// An expanded AES-128 key (wiped on drop).
pub struct Aes128 {
    rk: [u8; 176],
}

impl Drop for Aes128 {
    fn drop(&mut self) {
        wipe(&mut self.rk);
    }
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut rk = [0u8; 176];
        rk[..16].copy_from_slice(key);
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = [rk[4 * i - 4], rk[4 * i - 3], rk[4 * i - 2], rk[4 * i - 1]];
            if i % 4 == 0 {
                t = [
                    lookup(&SBOX, t[1]) ^ rcon,
                    lookup(&SBOX, t[2]),
                    lookup(&SBOX, t[3]),
                    lookup(&SBOX, t[0]),
                ];
                rcon = xtime(rcon);
            }
            for j in 0..4 {
                rk[4 * i + j] = rk[4 * i - 16 + j] ^ t[j];
            }
        }
        Aes128 { rk }
    }

    fn add_round_key(&self, s: &mut [u8; 16], round: usize) {
        for (b, k) in s.iter_mut().zip(&self.rk[16 * round..16 * round + 16]) {
            *b ^= k;
        }
    }

    pub fn encrypt_block(&self, s: &mut [u8; 16]) {
        self.add_round_key(s, 0);
        for round in 1..=10 {
            for b in s.iter_mut() {
                *b = lookup(&SBOX, *b);
            }
            shift_rows(s);
            if round != 10 {
                mix_columns(s);
            }
            self.add_round_key(s, round);
        }
    }

    pub fn decrypt_block(&self, s: &mut [u8; 16]) {
        self.add_round_key(s, 10);
        for round in (0..10).rev() {
            inv_shift_rows(s);
            for b in s.iter_mut() {
                *b = lookup(&INV_SBOX, *b);
            }
            self.add_round_key(s, round);
            if round != 0 {
                inv_mix_columns(s);
            }
        }
    }

    /// CBC encryption in place (`data` a whole number of blocks).
    pub fn cbc_encrypt(&self, iv: &[u8; 16], data: &mut [u8]) {
        let mut prev = *iv;
        for chunk in data.chunks_exact_mut(BLOCK) {
            let mut b = [0u8; 16];
            for i in 0..16 {
                b[i] = chunk[i] ^ prev[i];
            }
            self.encrypt_block(&mut b);
            chunk.copy_from_slice(&b);
            prev = b;
        }
    }

    /// CBC decryption in place (`data` a whole number of blocks).
    pub fn cbc_decrypt(&self, iv: &[u8; 16], data: &mut [u8]) {
        let mut prev = *iv;
        for chunk in data.chunks_exact_mut(BLOCK) {
            let mut c = [0u8; 16];
            c.copy_from_slice(chunk);
            let mut b = c;
            self.decrypt_block(&mut b);
            for i in 0..16 {
                chunk[i] = b[i] ^ prev[i];
            }
            prev = c;
            wipe(&mut b);
        }
    }
}

// The state is column-major: s[4 * c + r] is row r of column c.
fn shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[4 * c + r] = t[4 * ((c + r) % 4) + r];
        }
    }
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[4 * ((c + r) % 4) + r] = t[4 * c + r];
        }
    }
}

fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        s[4 * c] = xtime(a[0]) ^ (xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3];
        s[4 * c + 1] = a[0] ^ xtime(a[1]) ^ (xtime(a[2]) ^ a[2]) ^ a[3];
        s[4 * c + 2] = a[0] ^ a[1] ^ xtime(a[2]) ^ (xtime(a[3]) ^ a[3]);
        s[4 * c + 3] = (xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ xtime(a[3]);
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        s[4 * c] = mul(a[0], 14) ^ mul(a[1], 11) ^ mul(a[2], 13) ^ mul(a[3], 9);
        s[4 * c + 1] = mul(a[0], 9) ^ mul(a[1], 14) ^ mul(a[2], 11) ^ mul(a[3], 13);
        s[4 * c + 2] = mul(a[0], 13) ^ mul(a[1], 9) ^ mul(a[2], 14) ^ mul(a[3], 11);
        s[4 * c + 3] = mul(a[0], 11) ^ mul(a[1], 13) ^ mul(a[2], 9) ^ mul(a[3], 14);
    }
}

/// AES-CMAC (NIST SP 800-38B, RFC 4493) with AES-128.
pub struct Cmac {
    aes: Aes128,
    k1: [u8; 16],
    k2: [u8; 16],
    x: [u8; 16],
    buf: [u8; 16],
    n: usize,
}

impl Drop for Cmac {
    fn drop(&mut self) {
        wipe(&mut self.k1);
        wipe(&mut self.k2);
        wipe(&mut self.x);
        wipe(&mut self.buf);
    }
}

fn dbl(b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    let carry = b[0] >> 7;
    for i in 0..16 {
        o[i] = (b[i] << 1) | if i < 15 { b[i + 1] >> 7 } else { 0 };
    }
    o[15] ^= 0x87 & 0u8.wrapping_sub(carry);
    o
}

impl Cmac {
    pub fn new(key: &[u8; 16]) -> Self {
        let aes = Aes128::new(key);
        let mut l = [0u8; 16];
        aes.encrypt_block(&mut l);
        let k1 = dbl(&l);
        let k2 = dbl(&k1);
        wipe(&mut l);
        Cmac {
            aes,
            k1,
            k2,
            x: [0; 16],
            buf: [0; 16],
            n: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.n == 16 {
                // a full block is processed only once more data follows
                for i in 0..16 {
                    self.x[i] ^= self.buf[i];
                }
                self.aes.encrypt_block(&mut self.x);
                self.n = 0;
            }
            let take = (16 - self.n).min(data.len());
            self.buf[self.n..self.n + take].copy_from_slice(&data[..take]);
            self.n += take;
            data = &data[take..];
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let mut last = [0u8; 16];
        let key = if self.n == 16 {
            last.copy_from_slice(&self.buf);
            &self.k1
        } else {
            last[..self.n].copy_from_slice(&self.buf[..self.n]);
            last[self.n] = 0x80;
            &self.k2
        };
        for ((x, l), k) in self.x.iter_mut().zip(last.iter()).zip(key.iter()) {
            *x ^= l ^ k;
        }
        wipe(&mut last);
        self.aes.encrypt_block(&mut self.x);
        self.x
    }

    pub fn mac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
        let mut c = Cmac::new(key);
        c.update(data);
        c.finalize()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        let s: std::string::String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn fips197_vector() {
        let key: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let mut b: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        let a = Aes128::new(&key);
        a.encrypt_block(&mut b);
        assert_eq!(b.to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
        a.decrypt_block(&mut b);
        assert_eq!(b.to_vec(), hex("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn rfc4493_cmac_vectors() {
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let m = hex("6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
             30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710");
        for (n, want) in [
            (0, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
        ] {
            assert_eq!(Cmac::mac(&key, &m[..n]).to_vec(), hex(want), "{n} bytes");
            // fed in pieces
            let mut c = Cmac::new(&key);
            for piece in m[..n].chunks(7) {
                c.update(piece);
            }
            assert_eq!(c.finalize().to_vec(), hex(want));
        }
    }

    #[test]
    fn matches_the_reference_crates() {
        use aes_ref::cipher::{BlockEncrypt, KeyInit};
        use cmac_ref::Mac;
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        };
        for len in 0..200 {
            let key: [u8; 16] = core::array::from_fn(|_| next());
            let data: Vec<u8> = (0..len).map(|_| next()).collect();
            let mut block: [u8; 16] = core::array::from_fn(|_| next());
            let r = aes_ref::Aes128::new(&key.into());
            let mut want = block.into();
            r.encrypt_block(&mut want);
            Aes128::new(&key).encrypt_block(&mut block);
            assert_eq!(block, <[u8; 16]>::from(want));
            let mut m = <cmac_ref::Cmac<aes_ref::Aes128> as Mac>::new(&key.into());
            m.update(&data);
            let want: [u8; 16] = m.finalize().into_bytes().into();
            assert_eq!(Cmac::mac(&key, &data), want);
            // CBC round trip
            let iv: [u8; 16] = core::array::from_fn(|_| next());
            let mut d: Vec<u8> = (0..(len / 16 * 16)).map(|_| next()).collect();
            let orig = d.clone();
            let a = Aes128::new(&key);
            a.cbc_encrypt(&iv, &mut d);
            a.cbc_decrypt(&iv, &mut d);
            assert_eq!(d, orig);
        }
    }
}
