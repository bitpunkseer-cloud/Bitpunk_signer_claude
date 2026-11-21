//! Multisig descriptors and scripts: BIP-380 checksum, the strict parser,
//! and differential tests against rust-miniscript (dev-dependency only):
//! every address and witness script must match for both branches.

use bp_bitcoin::bip32::{DerivationPath, KeyVersion, Xpriv, XKEY_LEN};
use bp_bitcoin::multisig::descriptor::{self, checksum, Error, Form, Range};
use bp_bitcoin::multisig::{self, is_sorted, parse_multisig_script, Cosigner, MsScript, Wallet};
use bp_bitcoin::Network;
use miniscript::{Descriptor, DescriptorPublicKey};
use std::str::FromStr;

fn master(i: u8) -> Xpriv {
    Xpriv::master(&[i; 32]).unwrap()
}

/// `[fp/48h/c'/0h/t']key` for seed `i` (BIP-48 account 0).
fn cosigner(i: u8, script: MsScript, net: Network) -> Cosigner {
    let m = master(i);
    let path = script.account_path(net, 0);
    let acct = m.derive_path(&path).unwrap();
    Cosigner {
        fingerprint: m.fingerprint(),
        origin: path,
        xpub: acct.to_xpub(),
        version: KeyVersion::X,
    }
}

fn key_text(c: &Cosigner, net: Network, v: KeyVersion) -> String {
    let mut o = String::new();
    descriptor::write_origin(&mut o, &c.fingerprint, &c.origin).unwrap();
    let mut x = [0u8; XKEY_LEN];
    let n = c.xpub.encode(v.public(net), &mut x);
    o.push_str(std::str::from_utf8(&x[..n]).unwrap());
    o
}

fn desc_text(script: MsScript, m: u8, keys: &[String], suffix: &str) -> String {
    let inner = format!(
        "sortedmulti({m},{})",
        keys.iter()
            .map(|k| format!("{k}{suffix}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    match script {
        MsScript::Wsh => format!("wsh({inner})"),
        MsScript::ShWsh => format!("sh(wsh({inner}))"),
    }
}

fn with_checksum(body: &str) -> String {
    format!(
        "{body}#{}",
        std::str::from_utf8(&checksum(body).unwrap()).unwrap()
    )
}

fn written(w: &Wallet, form: Form) -> String {
    let mut out = [0u8; descriptor::MAX_DESCRIPTOR];
    let n = descriptor::write(w, form, &mut out).unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

fn btc_net(net: Network) -> bitcoin::Network {
    match net {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet => bitcoin::Network::Testnet,
        Network::Signet => bitcoin::Network::Signet,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn bip380_checksum_vectors() {
    assert_eq!(&checksum("raw(deadbeef)").unwrap(), b"89f8spxm");
    // characters outside the descriptor alphabet
    assert_eq!(checksum("raw(Ü)"), None);
    assert_eq!(checksum("a\tb"), None);
}

#[test]
fn generator_constant() {
    assert_eq!(
        hex(&bp_crypto::secp256k1::PublicKey::GENERATOR.serialize()),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
}

#[test]
fn slip132_multisig_versions() {
    let c = cosigner(1, MsScript::Wsh, Network::Mainnet);
    for (v, net, prefix) in [
        (KeyVersion::MultiZ, Network::Mainnet, "Zpub"),
        (KeyVersion::MultiY, Network::Mainnet, "Ypub"),
        (KeyVersion::MultiZ, Network::Testnet, "Vpub"),
        (KeyVersion::MultiY, Network::Testnet, "Upub"),
    ] {
        let mut x = [0u8; XKEY_LEN];
        let n = c.xpub.encode(v.public(net), &mut x);
        let s = std::str::from_utf8(&x[..n]).unwrap();
        assert!(s.starts_with(prefix), "{s}");
        let (back, test, kv) = multisig::decode_xpub(s).unwrap();
        assert_eq!((back, test, kv), (c.xpub, net != Network::Mainnet, v));
    }
}

/// Our addresses and scripts against rust-miniscript, for the parser (text
/// we build) and the writer (text we emit), both branches, both forms.
#[test]
fn matches_miniscript() {
    let cases: &[(MsScript, u8, u8, Network)] = &[
        (MsScript::Wsh, 1, 1, Network::Mainnet),
        (MsScript::Wsh, 2, 3, Network::Mainnet),
        (MsScript::Wsh, 2, 3, Network::Signet),
        (MsScript::ShWsh, 2, 3, Network::Mainnet),
        (MsScript::ShWsh, 3, 5, Network::Testnet),
        (MsScript::Wsh, 7, 15, Network::Mainnet),
        (MsScript::ShWsh, 15, 15, Network::Regtest),
    ];
    for &(script, m, n, net) in cases {
        let keys: Vec<Cosigner> = (1..=n).map(|i| cosigner(i * 3 + m, script, net)).collect();
        let texts: Vec<String> = keys.iter().map(|c| key_text(c, net, KeyVersion::X)).collect();
        let body = desc_text(script, m, &texts, "/<0;1>/*");
        let parsed = descriptor::parse(&with_checksum(&body)).unwrap();
        assert!(parsed.had_checksum);
        assert_eq!(parsed.range, Range::Both);
        let w = parsed.wallet;
        assert_eq!(
            (w.script, w.m, w.n(), w.test),
            (script, m, n, net != Network::Mainnet)
        );
        assert_eq!(w.keys(), &keys[..]);

        // the writer round-trips and miniscript agrees with its checksum
        let mp = written(&w, Form::Multipath);
        assert_eq!(descriptor::parse(&mp).unwrap().wallet, w);
        let theirs = Descriptor::<DescriptorPublicKey>::from_str(&mp).unwrap();
        let singles = theirs.clone().into_single_descriptors().unwrap();
        assert_eq!(singles.len(), 2);
        let s = theirs.to_string();
        let (b, cs) = s.split_once('#').unwrap();
        assert_eq!(std::str::from_utf8(&checksum(b).unwrap()).unwrap(), cs);

        for branch in 0..2u32 {
            let one = written(&w, Form::Branch(branch));
            let p1 = descriptor::parse(&one).unwrap();
            assert_eq!(
                p1.range,
                if branch == 0 {
                    Range::Receive
                } else {
                    Range::Change
                }
            );
            let d1 = Descriptor::<DescriptorPublicKey>::from_str(&one).unwrap();
            let ours = w.branch(branch).unwrap();
            for index in [0u32, 1, 2, 19, 1000, 0x7fff_ffff] {
                let sc = ours.derive(index).unwrap();
                assert!(is_sorted(sc.pubkeys()));
                let mut a = [0u8; 90];
                let al = sc.address(net, &mut a);
                for d in [&d1, &singles[branch as usize]] {
                    let def = d.at_derivation_index(index).unwrap();
                    assert_eq!(
                        std::str::from_utf8(&a[..al]).unwrap(),
                        def.address(btc_net(net)).unwrap().to_string()
                    );
                    assert_eq!(sc.script_pubkey(), def.script_pubkey().as_bytes());
                    assert_eq!(sc.witness_script(), def.explicit_script().unwrap().as_bytes());
                }
                if script == MsScript::ShWsh {
                    assert_eq!(sc.script_pubkey()[..2], [0xA9, 0x14]);
                    let r = sc.redeem_script();
                    assert_eq!(&r[..2], &[0x00, 0x20]);
                }
                let (pm, pk, pn) = parse_multisig_script(sc.witness_script()).unwrap();
                assert_eq!((pm, pn), (m, n));
                assert_eq!(&pk[..n as usize], sc.pubkeys());
            }
        }
    }
}

#[test]
fn suffix_forms_and_old_exports() {
    let net = Network::Mainnet;
    let keys: Vec<String> = (1..=3)
        .map(|i| key_text(&cosigner(i, MsScript::Wsh, net), net, KeyVersion::X))
        .collect();
    // BIP-388 shorthand, apostrophes, upper-case fingerprint, no checksum
    let a = descriptor::parse(&desc_text(MsScript::Wsh, 2, &keys, "/**")).unwrap();
    let b = descriptor::parse(
        &desc_text(MsScript::Wsh, 2, &keys, "/<0;1>/*")
            .replace("h/", "'/")
            .replace("h]", "']"),
    )
    .unwrap();
    let c = descriptor::parse(
        &desc_text(MsScript::Wsh, 2, &keys, "/<0;1>/*")
            .to_uppercase()
            .replace("WSH(SORTEDMULTI(", "wsh(sortedmulti("),
    )
    .err();
    assert_eq!(a.wallet, b.wallet);
    assert!(!a.had_checksum);
    assert!(c.is_some()); // upper-casing the xpubs breaks them
                          // surrounding whitespace is fine, inside is not
    let d = format!(
        "  {}\n",
        with_checksum(&desc_text(MsScript::Wsh, 2, &keys, "/0/*"))
    );
    assert_eq!(descriptor::parse(&d).unwrap().range, Range::Receive);
    let e = desc_text(MsScript::Wsh, 2, &keys, "/0/*").replacen(',', ", ", 1);
    assert_eq!(descriptor::parse(&e).unwrap_err(), Error::Syntax);
}

#[test]
fn rejections() {
    let net = Network::Mainnet;
    let c1 = cosigner(1, MsScript::Wsh, net);
    let k: Vec<String> = (1..=3)
        .map(|i| key_text(&cosigner(i, MsScript::Wsh, net), net, KeyVersion::X))
        .collect();
    let ok = desc_text(MsScript::Wsh, 2, &k, "/<0;1>/*");
    let bad = |s: &str| descriptor::parse(s).unwrap_err();

    assert_eq!(bad(&ok.replace("sortedmulti", "multi")), Error::Unsorted);
    assert_eq!(bad(&ok.replace("wsh(", "sh(")), Error::UnsupportedScript);
    assert_eq!(bad(&format!("wpkh({}/0/*)", k[0])), Error::UnsupportedScript);
    assert_eq!(bad(&format!("tr({}/0/*)", k[0])), Error::UnsupportedScript);
    assert_eq!(bad(&ok.replace("(2,", "(0,")), Error::Threshold);
    assert_eq!(bad(&ok.replace("(2,", "(4,")), Error::Threshold);
    assert_eq!(bad(&ok.replace("(2,", "(02,")), Error::Syntax);
    let many: Vec<String> = (1..=16)
        .map(|i| key_text(&cosigner(i, MsScript::Wsh, net), net, KeyVersion::X))
        .collect();
    assert_eq!(
        bad(&desc_text(MsScript::Wsh, 2, &many, "/<0;1>/*")),
        Error::TooManyKeys
    );

    // a key without origin
    let mut x = [0u8; XKEY_LEN];
    let n = c1.xpub.encode(KeyVersion::X.public(net), &mut x);
    let bare = std::str::from_utf8(&x[..n]).unwrap().to_string();
    let no_origin = vec![bare, k[1].clone(), k[2].clone()];
    assert_eq!(
        bad(&desc_text(MsScript::Wsh, 2, &no_origin, "/<0;1>/*")),
        Error::MissingOrigin
    );

    // a private key is refused, not silently converted
    let xprv = {
        let m = master(1);
        let a = m.derive_path(&MsScript::Wsh.account_path(net, 0)).unwrap();
        let mut o = [0u8; XKEY_LEN];
        let n = a.encode(KeyVersion::X.private(net), &mut o);
        format!(
            "[{}/48h/0h/0h/2h]{}",
            hex(&m.fingerprint()),
            std::str::from_utf8(&o[..n]).unwrap()
        )
    };
    let with_prv = vec![xprv, k[1].clone(), k[2].clone()];
    assert_eq!(
        bad(&desc_text(MsScript::Wsh, 2, &with_prv, "/<0;1>/*")),
        Error::PrivateKey
    );

    // suffixes
    assert_eq!(
        bad(&desc_text(MsScript::Wsh, 2, &k, "/<0;1>/*'")),
        Error::Hardened
    );
    assert_eq!(bad(&desc_text(MsScript::Wsh, 2, &k, "/0h/*")), Error::Hardened);
    assert_eq!(bad(&desc_text(MsScript::Wsh, 2, &k, "/0/0/*")), Error::Suffix);
    assert_eq!(bad(&desc_text(MsScript::Wsh, 2, &k, "/<1;0>/*")), Error::Suffix);
    assert_eq!(bad(&desc_text(MsScript::Wsh, 2, &k, "")), Error::Suffix);
    let mixed = format!(
        "wsh(sortedmulti(2,{}/0/*,{}/<0;1>/*,{}/<0;1>/*))",
        k[0], k[1], k[2]
    );
    assert_eq!(bad(&mixed), Error::MixedSuffix);

    // mainnet and test keys together
    let t = key_text(
        &cosigner(9, MsScript::Wsh, Network::Testnet),
        Network::Testnet,
        KeyVersion::X,
    );
    let mixed_net = vec![k[0].clone(), k[1].clone(), t];
    assert_eq!(
        bad(&desc_text(MsScript::Wsh, 2, &mixed_net, "/<0;1>/*")),
        Error::MixedNetwork
    );

    // checksum must match; trailing text; missing closing parens
    let cs = with_checksum(&ok);
    let mut flipped = cs.clone().into_bytes();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'q' { b'p' } else { b'q' };
    assert_eq!(bad(std::str::from_utf8(&flipped).unwrap()), Error::Checksum);
    assert_eq!(bad(&format!("{ok}#abc")), Error::Checksum);
    assert_eq!(bad(&format!("{ok}x")), Error::Syntax);
    assert_eq!(bad(&ok[..ok.len() - 1]), Error::Syntax);
    assert_eq!(bad(&ok.replacen('[', "[0", 1)), Error::Syntax);
}

#[test]
fn identity_ignores_order_and_spelling() {
    let net = Network::Mainnet;
    let keys: Vec<Cosigner> = (1..=3).map(|i| cosigner(i, MsScript::Wsh, net)).collect();
    let a = Wallet::new(false, MsScript::Wsh, 2, &keys).unwrap();
    let mut rev = keys.clone();
    rev.reverse();
    rev[0].version = KeyVersion::MultiZ;
    let mut b = Wallet::new(false, MsScript::Wsh, 2, &rev).unwrap();
    b.set_name("Family vault");
    assert_eq!(a.id(), b.id());
    assert_eq!(b.name(), "Family vault");
    // same keys, another threshold or script type: another wallet
    let c = Wallet::new(false, MsScript::Wsh, 1, &keys).unwrap();
    let d = Wallet::new(false, MsScript::ShWsh, 2, &keys).unwrap();
    assert_ne!(a.id(), c.id());
    assert_ne!(a.id(), d.id());
    // a different origin on one key changes identity too
    let mut e_keys = keys.clone();
    e_keys[1].origin = DerivationPath::parse("m/48'/0'/1'/2'").unwrap();
    assert_ne!(
        a.id(),
        Wallet::new(false, MsScript::Wsh, 2, &e_keys).unwrap().id()
    );
    assert!(Wallet::new(false, MsScript::Wsh, 4, &keys).is_none());
    assert!(Wallet::new(false, MsScript::Wsh, 0, &keys).is_none());
}

#[test]
fn script_parser_is_exact() {
    let w = Wallet::new(
        false,
        MsScript::Wsh,
        2,
        &(1..=3)
            .map(|i| cosigner(i, MsScript::Wsh, Network::Mainnet))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let sc = w.derive(0, 5).unwrap();
    let ws = sc.witness_script().to_vec();
    assert!(parse_multisig_script(&ws).is_some());
    let mut trailing = ws.clone();
    trailing.push(0x00);
    assert!(parse_multisig_script(&trailing).is_none());
    let mut wrong_n = ws.clone();
    let l = wrong_n.len();
    wrong_n[l - 2] = 0x54;
    assert!(parse_multisig_script(&wrong_n).is_none());
    let mut not_cms = ws.clone();
    not_cms[l - 1] = 0xAF;
    assert!(parse_multisig_script(&not_cms).is_none());
    let mut bad_prefix = ws.clone();
    bad_prefix[2] = 0x04;
    assert!(parse_multisig_script(&bad_prefix).is_none());
    // m > n
    let mut big_m = ws.clone();
    big_m[0] = 0x54;
    assert!(parse_multisig_script(&big_m).is_none());
    // unsorted keys are parsed, but not sorted
    let (_, keys, n) = parse_multisig_script(&ws).unwrap();
    let mut swapped = keys;
    swapped.swap(0, 1);
    assert!(!is_sorted(&swapped[..n as usize]));
    assert!(w.derive(2, 0).is_err());
    assert!(w.derive(0, 0x8000_0000).is_err());
}
