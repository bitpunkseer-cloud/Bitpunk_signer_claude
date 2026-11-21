//! Base58 (Bitcoin Core vectors + rust-bitcoin differential) and
//! Bech32/Bech32m (BIP-173 / BIP-350 vectors).

mod data {
    include!("data/bech32_vectors.rs");
}

use bp_bitcoin::base58;
use bp_bitcoin::bech32::{self, Variant};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn base58_known_answers() {
    // Bitcoin Core src/test/data/base58_encode_decode.json
    let cases = [
        ("", ""),
        ("61", "2g"),
        ("626262", "a3gV"),
        ("636363", "aPEr"),
        (
            "73696d706c792061206c6f6e6720737472696e67",
            "2cFupjhnEsSn59qHXstmK2ffpLv2",
        ),
        (
            "00eb15231dfceb60925886b67d065299925915aeb172c06647",
            "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
        ),
        ("516b6fcd0f", "ABnLTmg"),
        ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
        ("572e4794", "3EFU7m"),
        ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
        ("10c8511e", "Rt5zm"),
        ("00000000000000000000", "1111111111"),
    ];
    for (h, s) in cases {
        let mut out = [0u8; 200];
        let n = base58::encode(&unhex(h), &mut out).unwrap();
        assert_eq!(std::str::from_utf8(&out[..n]).unwrap(), s);
        let mut back = [0u8; 128];
        let m = base58::decode(s, &mut back).unwrap();
        assert_eq!(hex(&back[..m]), h);
    }
    assert_eq!(
        base58::decode("0OIl", &mut [0u8; 8]).unwrap_err(),
        base58::Error::InvalidCharacter
    );
}

#[test]
fn base58check_differential_and_tamper() {
    let mut x: u64 = 0x1234_5678;
    for len in 0..83 {
        let data: Vec<u8> = (0..len)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if i < len % 3 {
                    0
                } else {
                    x as u8
                }
            })
            .collect();
        let mut out = [0u8; 200];
        let n = base58::encode_check(&data, &mut out).unwrap();
        let s = std::str::from_utf8(&out[..n]).unwrap();
        assert_eq!(s, bitcoin::base58::encode_check(&data));
        let mut back = [0u8; 128];
        let m = base58::decode_check(s, &mut back).unwrap();
        assert_eq!(&back[..m], &data[..]);
    }
    // flipping a character breaks the checksum
    let mut out = [0u8; 200];
    let n = base58::encode_check(b"bitpunk", &mut out).unwrap();
    out[n - 1] = if out[n - 1] == b'2' { b'3' } else { b'2' };
    let s = std::str::from_utf8(&out[..n]).unwrap();
    assert_eq!(
        base58::decode_check(s, &mut [0u8; 64]).unwrap_err(),
        base58::Error::BadChecksum
    );
}

#[test]
fn bech32_valid_and_invalid_strings() {
    for s in data::VALID_BECH32 {
        assert_eq!(bech32::decode(s).map(|d| d.variant), Ok(Variant::Bech32), "{s}");
    }
    for s in data::VALID_BECH32M {
        assert_eq!(bech32::decode(s).map(|d| d.variant), Ok(Variant::Bech32m), "{s}");
    }
    for s in data::INVALID_BECH32 {
        assert_ne!(
            bech32::decode(s).map(|d| d.variant).ok(),
            Some(Variant::Bech32),
            "{s:?}"
        );
    }
    for s in data::INVALID_BECH32M {
        assert_ne!(
            bech32::decode(s).map(|d| d.variant).ok(),
            Some(Variant::Bech32m),
            "{s:?}"
        );
    }
}

#[test]
fn segwit_addresses_bip350() {
    for (addr, spk) in data::VALID_ADDRESSES {
        let hrp = if addr.to_ascii_lowercase().starts_with("bc1") {
            "bc"
        } else {
            "tb"
        };
        let a = bech32::decode_segwit(hrp, addr).unwrap_or_else(|e| panic!("{addr}: {e:?}"));
        let mut s = [0u8; 42];
        let n = a.script_pubkey(&mut s);
        assert_eq!(hex(&s[..n]), *spk, "{addr}");
        // re-encode gives the lowercase form
        let mut out = [0u8; bech32::MAX_LEN];
        let m = bech32::encode_segwit(hrp, a.version, a.program(), &mut out).unwrap();
        assert_eq!(std::str::from_utf8(&out[..m]).unwrap(), addr.to_ascii_lowercase());
    }
    for addr in data::INVALID_ADDRESSES {
        assert!(
            bech32::decode_segwit("bc", addr).is_err() && bech32::decode_segwit("tb", addr).is_err(),
            "{addr:?} should be invalid"
        );
    }
}

#[test]
fn addresses_from_scripts_match_rust_bitcoin() {
    use bitcoin::{Address, Network as RefNet, Script};
    use bp_bitcoin::address::{from_script, MAX_ADDRESS_LEN};
    use bp_bitcoin::Network;
    let mut x = 0x1357_9bdf_2468_ace0u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let nets = [
        (Network::Mainnet, RefNet::Bitcoin),
        (Network::Testnet, RefNet::Testnet),
        (Network::Signet, RefNet::Signet),
        (Network::Regtest, RefNet::Regtest),
    ];
    for i in 0..2000 {
        let body: Vec<u8> = (0..40).map(|_| next() as u8).collect();
        let spk: Vec<u8> = match i % 7 {
            0 => [&[0x76, 0xA9, 0x14][..], &body[..20], &[0x88, 0xAC]].concat(),
            1 => [&[0xA9, 0x14][..], &body[..20], &[0x87]].concat(),
            2 => [&[0x00, 0x14][..], &body[..20]].concat(),
            3 => [&[0x00, 0x20][..], &body[..32]].concat(),
            4 => [&[0x51, 0x20][..], &body[..32]].concat(),
            5 => {
                let n = 2 + (next() % 39) as usize;
                [&[0x52 + (next() % 15) as u8, n as u8][..], &body[..n]].concat()
            }
            _ => [&[0x6A, 0x04][..], &body[..4]].concat(),
        };
        for (net, rnet) in nets {
            let mut out = [0u8; MAX_ADDRESS_LEN];
            let ours =
                from_script(&spk, net, &mut out).map(|n| String::from_utf8(out[..n].to_vec()).unwrap());
            let theirs = Address::from_script(Script::from_bytes(&spk), rnet)
                .ok()
                .map(|a| a.to_string());
            assert_eq!(ours, theirs, "{spk:02x?} {net:?}");
        }
    }
}
