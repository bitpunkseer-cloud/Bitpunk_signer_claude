//! RS1024: the Reed–Solomon checksum over GF(1024) at the end of every
//! SLIP-39 share (three words). It finds any error in up to three words and
//! almost every other error.

/// Words of checksum at the end of a share.
pub const CHECKSUM_WORDS: usize = 3;

const GEN: [u32; 10] = [
    0x00E0_E040,
    0x01C1_C080,
    0x0383_8100,
    0x0707_0200,
    0x0E0E_0009,
    0x1C0C_2412,
    0x3808_6C24,
    0x3090_FC48,
    0x21B1_F890,
    0x03F3_F120,
];

fn step(chk: u32, v: u32) -> u32 {
    let b = chk >> 20;
    let mut chk = ((chk & 0xF_FFFF) << 10) ^ v;
    for (i, g) in GEN.iter().enumerate() {
        if (b >> i) & 1 == 1 {
            chk ^= g;
        }
    }
    chk
}

fn polymod(custom: &[u8], data: &[u16], zeros: usize) -> u32 {
    let mut chk = 1u32;
    for &c in custom {
        chk = step(chk, c as u32);
    }
    for &d in data {
        chk = step(chk, d as u32);
    }
    for _ in 0..zeros {
        chk = step(chk, 0);
    }
    chk
}

/// The three checksum words for `data` (all words of the share before the
/// checksum).
pub fn create(custom: &[u8], data: &[u16]) -> [u16; CHECKSUM_WORDS] {
    let p = polymod(custom, data, CHECKSUM_WORDS) ^ 1;
    [
        ((p >> 20) & 1023) as u16,
        ((p >> 10) & 1023) as u16,
        (p & 1023) as u16,
    ]
}

/// Whether `words` (a whole share, checksum included) is consistent.
pub fn verify(custom: &[u8], words: &[u16]) -> bool {
    polymod(custom, words, 0) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_change_of_one_to_three_words_is_caught() {
        let custom = b"shamir";
        let mut data = [0u16; 20];
        for (i, d) in data.iter_mut().enumerate() {
            *d = (i as u16 * 97 + 13) % 1024;
        }
        let c = create(custom, &data[..17]);
        data[17..].copy_from_slice(&c);
        assert!(verify(custom, &data));
        assert!(!verify(b"shamir_extendable", &data));
        for i in 0..20 {
            for delta in [1u16, 2, 511, 1023] {
                let mut d = data;
                d[i] ^= delta;
                assert!(!verify(custom, &d), "word {i}");
                for j in i + 1..20 {
                    let mut e = d;
                    e[j] ^= delta.rotate_left(3) & 1023 | 1;
                    assert!(!verify(custom, &e), "words {i} {j}");
                }
            }
        }
    }
}
