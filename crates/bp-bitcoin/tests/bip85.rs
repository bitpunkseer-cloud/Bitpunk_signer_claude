//! BIP-85 2.1.0: every test vector of the specification.

use bp_bitcoin::bip32::{DerivationPath, Xpriv};
use bp_bitcoin::bip85::{self, base85, derive, entropy, App, Derived, MAX_TEXT};
use bp_bitcoin::Network;

const ROOT: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

fn root() -> Xpriv {
    Xpriv::decode(ROOT).unwrap().0
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn text(d: &Derived) -> String {
    let mut out = [0u8; MAX_TEXT];
    let n = d.write_text(&mut out);
    String::from_utf8(out[..n].to_vec()).unwrap()
}

#[test]
fn derived_entropy_vectors() {
    let m = root();
    for (path, key, ent) in [
        (
            "m/83696968'/0'/0'",
            "cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0",
            "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7",
        ),
        (
            "m/83696968'/0'/1'",
            "503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba",
            "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e",
        ),
    ] {
        let p = DerivationPath::parse(path).unwrap();
        assert_eq!(hex(&m.derive_path(&p).unwrap().secret_key().to_bytes()), key);
        assert_eq!(hex(&entropy(&m, &p).unwrap().0), ent);
    }
}

#[test]
fn application_vectors() {
    let m = root();
    let net = Network::Mainnet;
    let cases: [(App, &str); 8] = [
        (App::Bip39 { words: 12 }, "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"),
        (
            App::Bip39 { words: 18 },
            "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token",
        ),
        (
            App::Bip39 { words: 24 },
            "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano",
        ),
        (App::Wif, "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"),
        (
            App::Xprv,
            "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX",
        ),
        (
            App::Hex { bytes: 64 },
            "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c",
        ),
        (App::PwdBase64 { len: 21 }, "dKLoepugzdVJvdL56ogNV"),
        (App::PwdBase85 { len: 12 }, "_s`{TW89)i4`"),
    ];
    for (app, want) in cases {
        let d = derive(&m, app, 0, net).unwrap();
        assert_eq!(text(&d), want, "{app:?}");
    }
    // the length is part of the path: 16 bytes are not a prefix of 64
    let h16 = text(&derive(&m, App::Hex { bytes: 16 }, 0, net).unwrap());
    assert_eq!(h16.len(), 32);
    assert!(!"492db4698cf3b73a5a24998aa3e9d7fa".starts_with(&h16));
    // the paths of the specification
    assert_eq!(
        App::Bip39 { words: 12 }.path(0).unwrap().to_string(),
        "m/83696968'/39'/0'/12'/0'"
    );
    assert_eq!(
        App::Hex { bytes: 64 }.path(0).unwrap().to_string(),
        "m/83696968'/128169'/64'/0'"
    );
    assert_eq!(
        App::PwdBase85 { len: 12 }.path(7).unwrap().to_string(),
        "m/83696968'/707785'/12'/7'"
    );
    // testnet keys
    let t = text(&derive(&m, App::Xprv, 0, Network::Testnet).unwrap());
    assert!(t.starts_with("tprv"));
    let w = text(&derive(&m, App::Wif, 0, Network::Testnet).unwrap());
    assert!(w.starts_with('c'));
}

#[test]
fn parameters_are_checked() {
    let m = root();
    for app in [
        App::Bip39 { words: 15 },
        App::Hex { bytes: 15 },
        App::Hex { bytes: 65 },
        App::PwdBase64 { len: 19 },
        App::PwdBase64 { len: 87 },
        App::PwdBase85 { len: 9 },
        App::PwdBase85 { len: 81 },
    ] {
        assert_eq!(
            derive(&m, app, 0, Network::Mainnet).err(),
            Some(bip85::Error::Param),
            "{app:?}"
        );
    }
    assert_eq!(
        derive(&m, App::Wif, 1 << 31, Network::Mainnet).err(),
        Some(bip85::Error::Param)
    );
    // other indexes give other results
    let a = text(&derive(&m, App::Wif, 1, Network::Mainnet).unwrap());
    assert_ne!(a, "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp");
}

#[test]
fn base85_matches_python_b85encode() {
    // base64.b85encode(bytes(range(64)))
    let data: [u8; 64] = core::array::from_fn(|i| i as u8);
    let mut out = [0u8; 80];
    base85(&data, &mut out);
    assert_eq!(&out[..10], b"009C61O)~M");
    let zeros = [0u8; 64];
    base85(&zeros, &mut out);
    assert!(out.iter().all(|&c| c == b'0'));
    let ones = [0xFFu8; 64];
    base85(&ones, &mut out);
    assert_eq!(&out[..5], b"|NsC0");
}

mod embit {
    use bp_bitcoin::bip85::App;
    include!("data/embit_bip85.rs");
}

/// Agreement with embit (the library of SeedSigner, Krux and Specter DIY)
/// at indexes and lengths the specification does not cover.
#[test]
fn embit_vectors() {
    let m = bp_bitcoin::bip39::Mnemonic::from_entropy(&[0; 16]).unwrap();
    let master = Xpriv::master(m.to_seed("").unwrap().expose()).unwrap();
    for (app, index, want) in embit::VECTORS {
        let d = derive(&master, *app, *index, Network::Mainnet).unwrap();
        assert_eq!(text(&d), *want, "{app:?} #{index}");
    }
    assert_eq!(embit::VECTORS.len(), 24);
}
