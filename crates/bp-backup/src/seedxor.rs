//! Seed XOR (M11-3, decision 5): a BIP-39 seed split into parts that are
//! themselves ordinary BIP-39 seeds; the XOR of all parts' entropy is the
//! seed's entropy. Fewer than all parts tell nothing about it.
//!
//! Splitting takes no device randomness. Without dice the parts are
//! Coldcard's deterministic ones (`docs/seed-xor.md` of its firmware): part
//! `i` of `n` (0-based, all but the last) is the start of
//! SHA256d("Batshitoshi " ‖ entropy ‖ "i of n parts"), so a split can be
//! made again to check what was written, on this device or a Coldcard. With
//! dice the rolls are bound in as well (another prefix), so nobody can check
//! that the parts came from that formula. The last part is the XOR of the
//! entropy and the others.

use bp_crypto::secret::wipe;
use bp_crypto::sha256::Sha256;

/// Parts a seed is split into, at most (as Coldcard).
pub const MAX_PARTS: usize = 4;
/// Parts combined when restoring, at most.
pub const MAX_COMBINE: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Entropy must be 16, 20, 24, 28 or 32 bytes (12–24 words).
    Length,
    /// Two to four parts.
    Parts,
}

fn valid_len(n: usize) -> bool {
    matches!(n, 16 | 20 | 24 | 28 | 32)
}

fn sha256d(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut once = h.finalize();
    let twice = Sha256::digest(&once);
    wipe(&mut once);
    twice
}

/// "i of n parts" (one-digit counts).
fn label(i: usize, n: usize) -> [u8; 12] {
    let mut l = *b"0 of 0 parts";
    l[0] = b'0' + i as u8;
    l[5] = b'0' + n as u8;
    l
}

/// XOR `part` into `acc` (same length).
pub fn xor_into(acc: &mut [u8], part: &[u8]) {
    for (a, p) in acc.iter_mut().zip(part) {
        *a ^= p;
    }
}

/// Split `entropy` (a seed's) into `n` parts of the same length, in
/// `out[..n]`. Empty `dice`: Coldcard's deterministic parts.
pub fn split(entropy: &[u8], n: usize, dice: &[u8], out: &mut [[u8; 32]; MAX_PARTS]) -> Result<(), Error> {
    let len = entropy.len();
    if !valid_len(len) {
        return Err(Error::Length);
    }
    if !(2..=MAX_PARTS).contains(&n) {
        return Err(Error::Parts);
    }
    let mut last = [0u8; 32];
    last[..len].copy_from_slice(entropy);
    let dice_hash = Sha256::digest(dice);
    for (i, part) in out.iter_mut().enumerate().take(n - 1) {
        let l = label(i, n);
        let mut mask = if dice.is_empty() {
            sha256d(&[b"Batshitoshi ", entropy, &l])
        } else {
            sha256d(&[b"Bitpunk dice ", &dice_hash, entropy, &l])
        };
        *part = [0; 32];
        part[..len].copy_from_slice(&mask[..len]);
        xor_into(&mut last[..len], &mask[..len]);
        wipe(&mut mask);
    }
    out[n - 1] = last;
    wipe(&mut last);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_bitcoin::bip39::{word_index, Mnemonic};
    use std::string::String;
    use std::vec::Vec;

    const FIXTURES: &str = include_str!("../tests/data/seedxor_split.txt");

    fn entropy_of(words: &str) -> Vec<u8> {
        let idx: Vec<u16> = words.split_whitespace().map(|w| word_index(w).unwrap()).collect();
        let m = Mnemonic::from_indices(&idx).unwrap();
        let mut e = [0u8; 32];
        let n = m.entropy(&mut e);
        e[..n].to_vec()
    }

    fn words_of(entropy: &[u8]) -> String {
        let m = Mnemonic::from_entropy(entropy).unwrap();
        (0..m.len()).map(|i| m.word(i)).collect::<Vec<_>>().join(" ")
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn coldcard_documentation_examples() {
        // docs/seed-xor.md of the Coldcard firmware: 24 and 12 words, 3 parts
        let cases = [
            (
                [
                    "romance wink lottery autumn shop bring dawn tongue range crater truth ability miss spice fitness easy legal release recall obey exchange recycle dragon room",
                    "lion misery divide hurry latin fluid camp advance illegal lab pyramid unaware eager fringe sick camera series noodle toy crowd jeans select depth lounge",
                    "vault nominee cradle silk own frown throw leg cactus recall talent worry gadget surface shy planet purpose coffee drip few seven term squeeze educate",
                ],
                "silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary indoor",
            ),
            (
                [
                    "romance wink lottery autumn shop bring dawn tongue range crater truth ability",
                    "boat unfair shell violin tree robust open ride visual forest vintage approve",
                    "lion misery divide hurry latin fluid camp advance illegal lab pyramid unhappy",
                ],
                "cannon opinion leader nephew found yard metal galaxy crouch between real trade",
            ),
        ];
        for (parts, want) in cases {
            let mut acc = entropy_of(parts[0]);
            for p in &parts[1..] {
                xor_into(&mut acc, &entropy_of(p));
            }
            assert_eq!(words_of(&acc), want);
        }
    }

    #[test]
    fn deterministic_parts_match_the_reference_formula() {
        // fixtures from Python's hashlib (tools/gen_seedxor_fixtures.py)
        let mut count = 0;
        for line in FIXTURES.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f: Vec<&str> = line.split(' ').collect();
            let secret = hex(f[0]);
            let n: usize = f[1].parse().unwrap();
            let mut out = [[0u8; 32]; MAX_PARTS];
            split(&secret, n, b"", &mut out).unwrap();
            for i in 0..n {
                assert_eq!(out[i][..secret.len()], hex(f[2 + i])[..], "{line}");
            }
            count += 1;
        }
        assert_eq!(count, 15);
    }

    #[test]
    fn parts_xor_back_and_dice_change_them() {
        for len in [16, 20, 24, 28, 32] {
            let secret: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37) ^ 0xA5).collect();
            for n in 2..=MAX_PARTS {
                for dice in [&b""[..], b"3141592653589793"] {
                    let mut out = [[0u8; 32]; MAX_PARTS];
                    split(&secret, n, dice, &mut out).unwrap();
                    let mut acc = out[0][..len].to_vec();
                    for p in &out[1..n] {
                        xor_into(&mut acc, &p[..len]);
                    }
                    assert_eq!(acc, secret);
                    // every part is a seed of its own (any entropy is)
                    for p in &out[..n] {
                        assert!(Mnemonic::from_entropy(&p[..len]).is_ok());
                        assert_ne!(&p[..len], &secret[..]);
                    }
                }
                let mut a = [[0u8; 32]; MAX_PARTS];
                let mut b = [[0u8; 32]; MAX_PARTS];
                split(&secret, n, b"", &mut a).unwrap();
                split(&secret, n, b"1", &mut b).unwrap();
                assert_ne!(a[0], b[0]);
            }
        }
        let mut out = [[0u8; 32]; MAX_PARTS];
        assert_eq!(split(&[0; 17], 2, b"", &mut out), Err(Error::Length));
        assert_eq!(split(&[0; 16], 1, b"", &mut out), Err(Error::Parts));
        assert_eq!(split(&[0; 16], 5, b"", &mut out), Err(Error::Parts));
    }
}
