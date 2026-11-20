//! SeedQR against the SeedSigner specification test vectors.

mod data {
    include!("data/seedqr_vectors.rs");
}

use bp_bitcoin::bip39::{word_index, Mnemonic, MAX_PHRASE_LEN};
use bp_bitcoin::seedqr::{compact_bytes, from_compact, from_standard, standard_digits, MAX_DIGITS};

fn phrase(m: &Mnemonic) -> String {
    let mut b = [0u8; MAX_PHRASE_LEN];
    let n = m.write_phrase(&mut b);
    String::from_utf8(b[..n].to_vec()).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn seedsigner_spec_vectors() {
    for (words, digits, compact_hex) in data::SEEDQR_VECTORS {
        let idx: Vec<u16> = words.split(' ').map(|w| word_index(w).unwrap()).collect();
        let m = Mnemonic::from_indices(&idx).unwrap();
        let mut d = [0u8; MAX_DIGITS];
        let n = standard_digits(&m, &mut d);
        assert_eq!(std::str::from_utf8(&d[..n]).unwrap(), *digits);
        let mut c = [0u8; 32];
        let k = compact_bytes(&m, &mut c);
        assert_eq!(hex(&c[..k]), *compact_hex);
        assert_eq!(phrase(&from_standard(digits.as_bytes()).unwrap()), *words);
        let raw: Vec<u8> = (0..compact_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&compact_hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(phrase(&from_compact(&raw).unwrap()), *words);
    }
}

#[test]
fn abandon_about_digits_and_rejects() {
    let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
    let mut d = [0u8; MAX_DIGITS];
    let n = standard_digits(&m, &mut d);
    assert_eq!(&d[..n], b"000000000000000000000000000000000000000000000003");
    assert!(from_standard(b"0000000000000000000000000000000000000000000000000000").is_err()); // 13 words
    assert!(from_standard(b"000000000000000000000000000000000000000000000000").is_err()); // bad checksum
    assert!(from_standard(b"00000000000000000000000000000000000000000000000x").is_err());
    assert!(from_compact(&[0u8; 20]).is_err());
}
