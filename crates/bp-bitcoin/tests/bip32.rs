//! BIP-32 vectors 1-5, Trezor root keys, BIP-44/49/84/86 address vectors,
//! and differential tests against rust-bitcoin (dev-dependency only).

mod v32 {
    include!("data/bip32_vectors.rs");
}
mod trezor {
    include!("data/trezor_bip39.rs");
}

use bp_bitcoin::address::{self, ScriptType};
use bp_bitcoin::bip32::{DerivationPath, KeyVersion, Xpriv, Xpub, XKEY_LEN};
use bp_bitcoin::bip39::{word_index, Mnemonic};
use bp_bitcoin::Network;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn xprv_str(k: &Xpriv, v: [u8; 4]) -> String {
    let mut o = [0u8; XKEY_LEN];
    let n = k.encode(v, &mut o);
    String::from_utf8(o[..n].to_vec()).unwrap()
}
fn xpub_str(k: &Xpub, v: [u8; 4]) -> String {
    let mut o = [0u8; XKEY_LEN];
    let n = k.encode(v, &mut o);
    String::from_utf8(o[..n].to_vec()).unwrap()
}
fn addr(pk: &bp_crypto::secp256k1::PublicKey, st: ScriptType, net: Network) -> String {
    let mut o = [0u8; address::MAX_ADDRESS_LEN];
    let n = address::encode(pk, st, net, &mut o);
    String::from_utf8(o[..n].to_vec()).unwrap()
}
fn seed_of(words: &str, pass: &str) -> [u8; 64] {
    let idx: Vec<u16> = words.split(' ').map(|w| word_index(w).unwrap()).collect();
    *Mnemonic::from_indices(&idx)
        .unwrap()
        .to_seed(pass)
        .unwrap()
        .expose()
}
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const XPUB: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
const XPRV: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];

#[test]
fn bip32_vectors_1_to_4() {
    for (seed, chains) in v32::VECTORS {
        let master = Xpriv::master(&unhex(seed)).unwrap();
        for (path, xpub, xprv) in chains.iter() {
            let p = DerivationPath::parse(path).unwrap();
            let k = master.derive_path(&p).unwrap();
            assert_eq!(xprv_str(&k, XPRV), *xprv, "{seed} {path}");
            assert_eq!(xpub_str(&k.to_xpub(), XPUB), *xpub, "{seed} {path}");
            // round trips
            let (pubk, net, kv) = Xpub::decode(xpub).unwrap();
            assert_eq!((net, kv), (Network::Mainnet, KeyVersion::X));
            assert_eq!(pubk, k.to_xpub());
            let (prvk, _, _) = Xpriv::decode(xprv).unwrap();
            assert_eq!(xprv_str(&prvk, XPRV), *xprv);
            assert_eq!(p.to_string(), *path);
        }
    }
}

#[test]
fn public_derivation_matches_private() {
    let master = Xpriv::master(&unhex("000102030405060708090a0b0c0d0e0f")).unwrap();
    let acct = master
        .derive_path(&DerivationPath::parse("m/84'/0'/0'").unwrap())
        .unwrap();
    for i in 0..5 {
        let via_priv = acct.derive_child(0).unwrap().derive_child(i).unwrap().to_xpub();
        let via_pub = acct.to_xpub().derive_child(0).unwrap().derive_child(i).unwrap();
        assert_eq!(via_priv, via_pub);
    }
    assert!(acct.to_xpub().derive_child(0x8000_0000).is_err());
}

#[test]
fn bip32_vector_5_invalid_keys() {
    for s in v32::INVALID {
        assert!(
            Xpub::decode(s).is_err() && Xpriv::decode(s).is_err(),
            "{s} must be rejected"
        );
    }
}

#[test]
fn trezor_root_keys() {
    for (_, words, seed, xprv) in trezor::TREZOR_BIP39 {
        let s = seed_of(words, "TREZOR");
        assert_eq!(hex(&s), *seed);
        assert_eq!(xprv_str(&Xpriv::master(&s).unwrap(), XPRV), *xprv);
    }
}

#[test]
fn bip84_vectors() {
    let master = Xpriv::master(&seed_of(ABANDON, "")).unwrap();
    let z = KeyVersion::Z;
    assert_eq!(master.fingerprint(), [0x73, 0xc5, 0xda, 0x0a]);
    assert_eq!(
        xprv_str(&master, z.private(Network::Mainnet)),
        "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5"
    );
    let acct = master
        .derive_path(&ScriptType::NativeSegwit.account_path(Network::Mainnet, 0))
        .unwrap();
    assert_eq!(
        xpub_str(&acct.to_xpub(), z.public(Network::Mainnet)),
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
    );
    let x = acct.to_xpub();
    let a = |c: u32, i: u32| {
        addr(
            &x.derive_child(c).unwrap().derive_child(i).unwrap().key,
            ScriptType::NativeSegwit,
            Network::Mainnet,
        )
    };
    assert_eq!(a(0, 0), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(a(0, 1), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    assert_eq!(a(1, 0), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
}

#[test]
fn bip86_vectors() {
    let master = Xpriv::master(&seed_of(ABANDON, "")).unwrap();
    let acct = master
        .derive_path(&ScriptType::Taproot.account_path(Network::Mainnet, 0))
        .unwrap();
    assert_eq!(
        xpub_str(&acct.to_xpub(), XPUB),
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
    );
    let k0 = acct
        .to_xpub()
        .derive_child(0)
        .unwrap()
        .derive_child(0)
        .unwrap()
        .key;
    assert_eq!(
        hex(&k0.x_only()),
        "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
    );
    assert_eq!(
        hex(&address::taproot_output_key(&k0).unwrap()),
        "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    );
    assert_eq!(
        addr(&k0, ScriptType::Taproot, Network::Mainnet),
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    );
    let k1 = acct
        .to_xpub()
        .derive_child(0)
        .unwrap()
        .derive_child(1)
        .unwrap()
        .key;
    assert_eq!(
        addr(&k1, ScriptType::Taproot, Network::Mainnet),
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
    );
}

#[test]
fn bip49_testnet_vector() {
    let master = Xpriv::master(&seed_of(ABANDON, "")).unwrap();
    let y = KeyVersion::Y;
    assert_eq!(
        xprv_str(&master, y.private(Network::Testnet)),
        "uprv8tXDerPXZ1QsVNjUJWTurs9kA1KGfKUAts74GCkcXtU8GwnH33GDRbNJpEqTvipfCyycARtQJhmdfWf8oKt41X9LL1zeD2pLsWmxEk3VAwd"
    );
    let acct = master
        .derive_path(&ScriptType::NestedSegwit.account_path(Network::Testnet, 0))
        .unwrap();
    assert_eq!(
        xpub_str(&acct.to_xpub(), y.public(Network::Testnet)),
        "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY"
    );
    let k = acct
        .to_xpub()
        .derive_child(0)
        .unwrap()
        .derive_child(0)
        .unwrap()
        .key;
    assert_eq!(
        hex(&k.serialize()),
        "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    );
    assert_eq!(
        addr(&k, ScriptType::NestedSegwit, Network::Testnet),
        "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"
    );
}

#[test]
fn bip44_first_address() {
    // widely published value for the "abandon ... about" seed
    let master = Xpriv::master(&seed_of(ABANDON, "")).unwrap();
    let acct = master
        .derive_path(&ScriptType::Legacy.account_path(Network::Mainnet, 0))
        .unwrap();
    let k = acct
        .to_xpub()
        .derive_child(0)
        .unwrap()
        .derive_child(0)
        .unwrap()
        .key;
    assert_eq!(
        addr(&k, ScriptType::Legacy, Network::Mainnet),
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
    );
}

#[test]
fn differential_against_rust_bitcoin() {
    use bitcoin::bip32 as rb;
    use bitcoin::secp256k1::Secp256k1;
    use std::str::FromStr;
    let secp = Secp256k1::new();
    let mut x: u64 = 0xFEED_FACE;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let nets = [
        Network::Mainnet,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ];
    for round in 0..40 {
        let seed: Vec<u8> = (0..64).map(|_| rnd() as u8).collect();
        let net = nets[round % 4];
        let rnet = match net {
            Network::Mainnet => bitcoin::Network::Bitcoin,
            Network::Testnet => bitcoin::Network::Testnet,
            Network::Signet => bitcoin::Network::Signet,
            Network::Regtest => bitcoin::Network::Regtest,
        };
        let ours = Xpriv::master(&seed).unwrap();
        let theirs = rb::Xpriv::new_master(rnet, &seed).unwrap();
        for st in ScriptType::ALL {
            let account = (rnd() % 3) as u32;
            let path = st.account_path(net, account);
            let acct = ours.derive_path(&path).unwrap();
            let racct = theirs
                .derive_priv(&secp, &rb::DerivationPath::from_str(&path.to_string()).unwrap())
                .unwrap();
            assert_eq!(
                xpub_str(&acct.to_xpub(), KeyVersion::X.public(net)),
                rb::Xpub::from_priv(&secp, &racct).to_string()
            );
            for (change, index) in [(0u32, 0u32), (0, (rnd() % 1000) as u32), (1, 3)] {
                let k = acct
                    .to_xpub()
                    .derive_child(change)
                    .unwrap()
                    .derive_child(index)
                    .unwrap()
                    .key;
                let rk = rb::Xpub::from_priv(&secp, &racct)
                    .derive_pub(
                        &secp,
                        &[rb::ChildNumber::from(change), rb::ChildNumber::from(index)],
                    )
                    .unwrap();
                let cpk = bitcoin::CompressedPublicKey(rk.public_key);
                let expected = match st {
                    ScriptType::NativeSegwit => bitcoin::Address::p2wpkh(&cpk, rnet),
                    ScriptType::NestedSegwit => bitcoin::Address::p2shwpkh(&cpk, rnet),
                    ScriptType::Legacy => bitcoin::Address::p2pkh(cpk, rnet),
                    ScriptType::Taproot => {
                        let (xo, _) = rk.public_key.x_only_public_key();
                        bitcoin::Address::p2tr(&secp, xo, None, rnet)
                    }
                };
                assert_eq!(
                    addr(&k, st, net),
                    expected.to_string(),
                    "{st:?} {net:?} {path}/{change}/{index}"
                );
            }
        }
    }
}

#[test]
fn path_parsing() {
    let p = DerivationPath::parse("m/84h/0h/0h/0/7").unwrap();
    assert_eq!(p.to_string(), "m/84'/0'/0'/0/7");
    assert!(DerivationPath::parse("84'/0'").is_err());
    assert!(DerivationPath::parse("m/2147483648").is_err());
    assert!(DerivationPath::parse("m/x").is_err());
}
