//! BIP-39 known-answer tests (Trezor vectors), wordlist pinning, and
//! differential tests against the `bip39` crate (dev-dependency only).

mod data {
    include!("data/trezor_bip39.rs");
}

use bp_bitcoin::bip39::{self, final_word, final_word_free_bits, word_index, Error, Mnemonic, WORDS};
use bp_crypto::Sha256;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn phrase(m: &Mnemonic) -> String {
    let mut buf = [0u8; bip39::MAX_PHRASE_LEN];
    let n = m.write_phrase(&mut buf);
    String::from_utf8(buf[..n].to_vec()).unwrap()
}
fn indices(words: &str) -> Vec<u16> {
    words
        .split(' ')
        .map(|w| word_index(w).expect("known word"))
        .collect()
}

#[test]
fn wordlist_matches_official_file_hash() {
    let mut file = String::new();
    for w in WORDS.iter() {
        file.push_str(w);
        file.push('\n');
    }
    assert_eq!(
        hex(&Sha256::digest(file.as_bytes())),
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
}

#[test]
fn wordlist_matches_reference_crate() {
    let theirs = bip39_ref::Language::English.word_list();
    assert_eq!(theirs.len(), 2048);
    for (a, b) in WORDS.iter().zip(theirs.iter()) {
        assert_eq!(a, b);
    }
}

#[test]
fn trezor_vectors() {
    for (ent, words, seed, _xprv) in data::TREZOR_BIP39 {
        let m = Mnemonic::from_entropy(&unhex(ent)).unwrap();
        assert_eq!(phrase(&m), *words);
        let parsed = Mnemonic::from_indices(&indices(words)).unwrap();
        let mut e = [0u8; 32];
        let n = parsed.entropy(&mut e);
        assert_eq!(hex(&e[..n]), *ent);
        assert_eq!(hex(parsed.to_seed("TREZOR").unwrap().expose()), *seed);
    }
}

#[test]
fn final_word_recovers_last_word_of_every_vector() {
    for (_, words, _, _) in data::TREZOR_BIP39 {
        let idx = indices(words);
        let n = idx.len();
        let cs = bip39::checksum_bits(n);
        let free = idx[n - 1] >> cs;
        assert_eq!(final_word_free_bits(n), 11 - cs);
        assert_eq!(final_word(&idx[..n - 1], free).unwrap(), idx[n - 1], "{words}");
    }
}

#[test]
fn seedsigner_entropy_vectors() {
    // From SeedSigner tests/test_mnemonic_generation.py (iancoleman.io).
    let m = Mnemonic::from_entropy(&unhex("3350f6ac9eeb07d2c6209932808aa7f6")).unwrap();
    assert_eq!(
        phrase(&m),
        "crew marble private differ race truly blush basket crater affair prepare unique"
    );
    let m = Mnemonic::from_entropy(&unhex(
        "5bf41629fce815c3570955e8f45422abd7e2234141bd4d7ec63b741043b98cad",
    ))
    .unwrap();
    assert_eq!(
        phrase(&m),
        "fossil pass media what life ticket found click trophy pencil anger fish lawsuit balance agree dash estate wage mom trial aerobic system crawl review"
    );
}

#[test]
fn rejects_bad_input() {
    let mut idx = indices(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    assert!(Mnemonic::from_indices(&idx).is_ok());
    idx[11] = word_index("abandon").unwrap();
    assert_eq!(Mnemonic::from_indices(&idx).unwrap_err(), Error::InvalidChecksum);
    assert_eq!(
        Mnemonic::from_indices(&idx[..11]).unwrap_err(),
        Error::InvalidWordCount
    );
    assert_eq!(
        Mnemonic::from_entropy(&[0u8; 15]).unwrap_err(),
        Error::InvalidEntropyLength
    );
    let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
    assert_eq!(m.to_seed("caf\u{e9}").unwrap_err(), Error::NonAsciiPassphrase);
}

#[test]
fn differential_against_reference_crate() {
    let mut x: u64 = 0x1234_5678_9abc_def1;
    for round in 0..300 {
        let len = [16, 20, 24, 28, 32][round % 5];
        let ent: Vec<u8> = (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let ours = Mnemonic::from_entropy(&ent).unwrap();
        let theirs = bip39_ref::Mnemonic::from_entropy(&ent).unwrap();
        assert_eq!(phrase(&ours), theirs.to_string());
        if round % 50 == 0 {
            assert_eq!(
                ours.to_seed("pw").unwrap().expose().as_slice(),
                theirs.to_seed("pw").as_slice()
            );
        }
    }
}
