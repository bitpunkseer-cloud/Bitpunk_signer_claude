//! Registration rules (R1–R11), the seed-keyed wallet code and the session
//! registry. Every rejection has a case; the code must not depend on key
//! order, key spelling or the name, and must change with anything that
//! changes the scripts.

use bp_bitcoin::bip32::{DerivationPath, KeyVersion, Xpriv};
use bp_bitcoin::multisig::register::{
    check, key_set_id, AddError, Code, CodeKey, Entry, Registry, RejectKind, MAX_WALLETS,
};
use bp_bitcoin::multisig::{Cosigner, MsScript, Wallet};
use bp_bitcoin::Network;

fn master(i: u8) -> Xpriv {
    Xpriv::master(&[i; 32]).unwrap()
}

fn key_at(i: u8, path: &DerivationPath) -> Cosigner {
    let m = master(i);
    Cosigner {
        fingerprint: m.fingerprint(),
        origin: *path,
        xpub: m.derive_path(path).unwrap().to_xpub(),
        version: KeyVersion::X,
    }
}

fn bip48(i: u8, script: MsScript, net: Network, account: u32) -> Cosigner {
    key_at(i, &script.account_path(net, account))
}

fn keys(script: MsScript, net: Network) -> Vec<Cosigner> {
    (1..=3).map(|i| bip48(i, script, net, 0)).collect()
}

fn wallet(script: MsScript, m: u8, k: &[Cosigner], net: Network) -> Wallet {
    Wallet::new(net != Network::Mainnet, script, m, k).unwrap()
}

fn rejected(w: &Wallet, net: Network, seed: u8) -> (RejectKind, Option<u8>) {
    let e = check(w, net, &master(seed), &Registry::new()).unwrap_err();
    (e.kind, e.key)
}

#[test]
fn honest_wallet_passes() {
    for (script, net) in [
        (MsScript::Wsh, Network::Mainnet),
        (MsScript::ShWsh, Network::Mainnet),
        (MsScript::Wsh, Network::Signet),
        (MsScript::ShWsh, Network::Testnet),
    ] {
        let k = keys(script, net);
        let w = wallet(script, 2, &k, net);
        for seed in 1..=3u8 {
            let c = check(&w, net, &master(seed), &Registry::new()).unwrap();
            assert_eq!(c.ours, Some(seed - 1));
            assert_eq!(c.warnings, Default::default());
            assert_eq!(c.duplicate, None);
        }
    }
}

#[test]
fn every_rejection() {
    let net = Network::Mainnet;
    let s = MsScript::Wsh;
    let k = keys(s, net);

    // network: mainnet keys on a test network
    let w = wallet(s, 2, &k, net);
    assert_eq!(
        check(&w, Network::Signet, &master(1), &Registry::new())
            .unwrap_err()
            .kind,
        RejectKind::Network
    );

    // depth and child number lies
    let mut bad = k.clone();
    bad[1].xpub.depth = 3;
    assert_eq!(
        rejected(&wallet(s, 2, &bad, net), net, 1),
        (RejectKind::Depth, Some(1))
    );
    let mut bad = k.clone();
    bad[2].xpub.child_number ^= 1;
    assert_eq!(
        rejected(&wallet(s, 2, &bad, net), net, 1),
        (RejectKind::ChildNumber, Some(2))
    );

    // depth-1 key whose parent is not the master
    let p45 = DerivationPath::parse("m/45'").unwrap();
    let mut bad = k.clone();
    bad[1] = key_at(2, &p45);
    bad[1].xpub.parent_fingerprint = [1, 2, 3, 4];
    assert_eq!(
        rejected(&wallet(s, 2, &bad, net), net, 1),
        (RejectKind::ParentFingerprint, Some(1))
    );

    // coin type 1' on mainnet
    let mut bad = k.clone();
    bad[2] = bip48(3, s, Network::Testnet, 0);
    assert_eq!(
        rejected(&wallet(s, 2, &bad, net), net, 1),
        (RejectKind::CoinType, Some(2))
    );

    // SLIP-132 versions that name another script
    let mut bad = k.clone();
    bad[1].version = KeyVersion::MultiY;
    assert_eq!(
        rejected(&wallet(s, 2, &bad, net), net, 1),
        (RejectKind::VersionScript, Some(1))
    );
    let mut bad = k.clone();
    bad[1].version = KeyVersion::Z;
    assert_eq!(
        rejected(&wallet(s, 2, &bad, net), net, 1),
        (RejectKind::VersionScript, Some(1))
    );
    let sh = keys(MsScript::ShWsh, net);
    let mut bad = sh.clone();
    bad[0].version = KeyVersion::MultiZ;
    assert_eq!(
        rejected(&wallet(MsScript::ShWsh, 2, &bad, net), net, 2),
        (RejectKind::VersionScript, Some(0))
    );

    // our fingerprint on a key the seed does not derive (wrong passphrase / swap)
    let mut bad = k.clone();
    bad[0].xpub = bip48(9, s, net, 0).xpub;
    assert_eq!(
        rejected(&wallet(s, 2, &bad, net), net, 1),
        (RejectKind::OurKeyMismatch, Some(0))
    );

    // our key twice (same key repeated)
    let twice = vec![k[0], k[1], k[0]];
    assert_eq!(
        rejected(&wallet(s, 2, &twice, net), net, 1).0,
        RejectKind::OurKeyTwice
    );
    // our key on two accounts: one seed counted twice
    let two_accounts = vec![k[0], k[1], bip48(1, s, net, 1)];
    assert_eq!(
        rejected(&wallet(s, 2, &two_accounts, net), net, 1),
        (RejectKind::OurKeyTwice, Some(2))
    );

    // our key under another fingerprint
    let mut bad = k.clone();
    bad[0].fingerprint = [0xde, 0xad, 0xbe, 0xef];
    assert_eq!(
        rejected(&wallet(s, 2, &bad, net), net, 1),
        (RejectKind::OurKeyHidden, Some(0))
    );

    // a cosigner repeated under two fingerprints
    let mut bad = vec![k[0], k[1], k[1]];
    bad[2].fingerprint = [9, 9, 9, 9];
    assert_eq!(
        rejected(&wallet(s, 2, &bad, net), net, 1),
        (RejectKind::DuplicateKey, Some(2))
    );
    // one cosigner seed on two accounts
    let bad = vec![k[0], k[1], bip48(2, s, net, 1)];
    assert_eq!(
        rejected(&wallet(s, 2, &bad, net), net, 1),
        (RejectKind::DuplicateFingerprint, Some(2))
    );
}

#[test]
fn warnings() {
    let net = Network::Mainnet;
    let s = MsScript::Wsh;
    let k = keys(s, net);
    // our key and one cosigner off BIP-48 (P2SH-P2WSH type in a P2WSH wallet)
    let mut odd = k.clone();
    odd[0] = bip48(1, MsScript::ShWsh, net, 0);
    odd[2] = key_at(3, &DerivationPath::parse("m/87'/0'/0'").unwrap());
    let c = check(&wallet(s, 2, &odd, net), net, &master(1), &Registry::new()).unwrap();
    assert!(c.warnings.our_path);
    assert_eq!(c.warnings.cosigner_paths, 1);
    // verify-only: this seed has no key
    let c = check(&wallet(s, 2, &k, net), net, &master(9), &Registry::new()).unwrap();
    assert_eq!(c.ours, None);
    assert!(c.warnings.watch_only);
    // 1-of-3
    let c = check(&wallet(s, 1, &k, net), net, &master(1), &Registry::new()).unwrap();
    assert!(c.warnings.one_of_n);
    // same keys with another threshold already registered, and an exact duplicate
    let mut reg = Registry::new();
    let w2 = wallet(s, 2, &k, net);
    let ck = CodeKey::new(&master(1));
    reg.add(Entry {
        wallet: w2,
        slot: 0,
        ours: Some(0),
        code: ck.code(&w2),
        tag: ck.tag(&w2),
    })
    .unwrap();
    let c = check(&wallet(s, 1, &k, net), net, &master(1), &reg).unwrap();
    assert_eq!(c.warnings.similar, Some(0));
    assert_eq!(c.duplicate, None);
    let c = check(&w2, net, &master(1), &reg).unwrap();
    assert_eq!(c.duplicate, Some(0));
    assert_eq!(c.warnings.similar, None);
}

#[test]
fn wallet_code() {
    let net = Network::Mainnet;
    let s = MsScript::Wsh;
    let k = keys(s, net);
    let w = wallet(s, 2, &k, net);
    let ck = CodeKey::new(&master(1));
    let code = ck.code(&w);
    // same wallet however it was written
    let mut rev = k.clone();
    rev.reverse();
    rev[1].version = KeyVersion::MultiZ;
    let mut w2 = wallet(s, 2, &rev, net);
    w2.set_name("renamed");
    assert_eq!(ck.code(&w2), code);
    assert_eq!(ck.tag(&w2), ck.tag(&w));
    // anything that changes the scripts changes the code
    assert_ne!(ck.code(&wallet(s, 1, &k, net)), code);
    assert_ne!(ck.code(&wallet(MsScript::ShWsh, 2, &k, net)), code);
    let mut swapped = k.clone();
    swapped[2] = bip48(7, s, net, 0);
    assert_ne!(ck.code(&wallet(s, 2, &swapped, net)), code);
    // another seed gives another code for the same wallet
    assert_ne!(CodeKey::new(&master(2)).code(&w), code);
    // a passphrase is another master: another code
    let other = Xpriv::master(&[1; 33]).unwrap();
    assert_ne!(CodeKey::new(&other).code(&w), code);
    // deterministic, and only from the alphabet
    assert_eq!(CodeKey::new(&master(1)).code(&w), code);
    assert!(code
        .0
        .iter()
        .all(|c| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c)));
    // the code key is not the master's raw material and differs per label
    assert_ne!(master(1).symmetric_key(b"a"), master(1).symmetric_key(b"b"));
}

#[test]
fn code_text() {
    assert_eq!(Code::from_tag(&[0; 32]).0, *b"00000000");
    assert_eq!(Code::from_tag(&[0xFF; 32]).0, *b"ZZZZZZZZ");
    let mut t = [0u8; 32];
    // symbols 1,2,…,8 as 5-bit groups: 00001 00010 00011 00100 00101 00110 00111 01000
    t[..5].copy_from_slice(&[0x08, 0x86, 0x42, 0x98, 0xE8]);
    assert_eq!(&Code::from_tag(&t).0, b"12345678");
    let c = Code(*b"7KQ2M9XD");
    assert_eq!(&c.display(), b"7KQ2-M9XD");
    assert_eq!(Code::parse("7kq2-m9xd"), Some(c));
    assert_eq!(Code::parse(" 7KQ2 M9XD "), Some(c));
    assert_eq!(Code::parse("O1L0-I000"), Some(Code(*b"01101000")));
    assert_eq!(Code::parse("7KQ2-M9X"), None);
    assert_eq!(Code::parse("7KQ2-M9XDD"), None);
    assert_eq!(Code::parse("7KQ2-M9XU"), None);
}

#[test]
fn registry() {
    let net = Network::Mainnet;
    let s = MsScript::Wsh;
    let k = keys(s, net);
    let ck = CodeKey::new(&master(1));
    let entry = |w: Wallet, slot: u8| Entry {
        wallet: w,
        slot,
        ours: Some(0),
        code: ck.code(&w),
        tag: ck.tag(&w),
    };
    let mut reg = Registry::new();
    assert!(reg.is_empty());
    let a = wallet(s, 1, &k, net);
    let b = wallet(s, 2, &k, net);
    let c = wallet(s, 3, &k, net);
    let d = wallet(MsScript::ShWsh, 2, &keys(MsScript::ShWsh, net), net);
    assert_eq!(reg.add(entry(a, 0)), Ok(0));
    assert_eq!(reg.add(entry(b, 1)), Ok(1));
    assert_eq!(reg.add(entry(a, 0)), Err(AddError::Duplicate(0)));
    assert_eq!(reg.add(entry(c, 2)), Ok(2));
    assert_eq!(reg.add(entry(d, 1)), Ok(3));
    assert!(reg.is_full());
    assert_eq!(MAX_WALLETS, 4);
    let e = wallet(MsScript::ShWsh, 1, &keys(MsScript::ShWsh, net), net);
    assert_eq!(reg.add(entry(e, 0)), Err(AddError::Full));
    // unloading seed slot 1 drops its wallets and shifts later slots down
    reg.forget_slot(1);
    assert_eq!(reg.len(), 2);
    assert_eq!(reg.get(0).unwrap().slot, 0);
    assert_eq!(reg.get(2).unwrap().slot, 1);
    reg.remove(0);
    assert_eq!(reg.add(entry(e, 0)), Ok(0));
    reg.clear();
    assert!(reg.is_empty());
    assert_ne!(key_set_id(&a), key_set_id(&d));
    assert_eq!(key_set_id(&a), key_set_id(&b));
}
