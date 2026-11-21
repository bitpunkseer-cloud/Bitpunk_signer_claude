//! Multisig wallet flows: import, the two registration paths (every
//! cosigner + code written down, or the code from an earlier session),
//! refusals, export round trips, and wallets forgotten with their seed.

use super::*;
use crate::wallets::{Problem, WlStep};
use bp_bitcoin::bip32::{KeyVersion, Xpriv as BpXpriv};
use bp_bitcoin::multisig::descriptor::{self, Form};
use bp_bitcoin::multisig::register::{Code, RejectKind};
use bp_bitcoin::multisig::{formats, Cosigner, MsScript, Wallet};

/// Our key (the loaded "abandon" seed) plus `n - 1` cosigners.
pub(super) fn wallet_of(a: &App, script: MsScript, m: u8, n: u8) -> Wallet {
    let net = a.settings.network;
    let path = script.account_path(net, 0);
    let seed = a.slot(0).unwrap();
    let ours = Cosigner {
        fingerprint: seed.fingerprint,
        origin: path,
        xpub: seed.master().derive_path(&path).unwrap().to_xpub(),
        version: KeyVersion::X,
    };
    let mut keys = vec![ours];
    for i in 1..n {
        let mk = BpXpriv::master(&[i + 40; 32]).unwrap();
        keys.push(Cosigner {
            fingerprint: mk.fingerprint(),
            origin: path,
            xpub: mk.derive_path(&path).unwrap().to_xpub(),
            version: KeyVersion::X,
        });
    }
    // our key second, as a coordinator might order them
    keys.swap(0, 1);
    Wallet::new(net != bp_bitcoin::Network::Mainnet, script, m, &keys).unwrap()
}

pub(super) fn descriptor_of(w: &Wallet) -> String {
    let mut o = [0u8; descriptor::MAX_DESCRIPTOR];
    let n = descriptor::write(w, Form::Multipath, &mut o).unwrap();
    String::from_utf8(o[..n].to_vec()).unwrap()
}

/// Main > Tools > Multisig wallets.
pub(super) fn open_wallets(a: &mut App) {
    press(a, Key::Char('3'));
    press(a, Key::Char('6'));
}

fn step(a: &App) -> WlStep {
    match a.current() {
        Screen::Wallets { step } => step,
        s => panic!("not a wallet screen: {s:?}"),
    }
}

fn to_main(a: &mut App) {
    for _ in 0..20 {
        if matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }) {
            return;
        }
        press(a, Key::Esc);
    }
    panic!("stuck at {:?}", a.current());
}

fn import(a: &mut App, text: &str) {
    to_main(a);
    open_wallets(a);
    // the import row is last
    let n = a.wallets.len();
    press(a, Key::Char((b'1' + n as u8) as char));
    assert!(matches!(a.current(), Screen::Scan { .. }));
    a.on_qr_text(text.as_bytes());
}

fn code_of(a: &App) -> Code {
    a.wl.pending.as_ref().unwrap().code
}

#[test]
fn no_seed_no_wallets() {
    let mut a = app();
    open_wallets(&mut a);
    assert_eq!(step(&a), WlStep::NeedSeed);
    press(&mut a, Key::Esc);
    assert!(matches!(
        a.current(),
        Screen::Menu {
            id: MenuId::Tools,
            ..
        }
    ));
}

#[test]
fn register_by_checking_every_cosigner() {
    let mut a = app();
    load_abandon(&mut a);
    let w = wallet_of(&a, MsScript::Wsh, 2, 3);
    import(&mut a, &descriptor_of(&w));
    assert_eq!(step(&a), WlStep::Summary { sel: 0 });
    let p = a.wl.pending.as_ref().unwrap();
    assert_eq!(p.checked.ours, Some(1));
    assert_eq!(p.checked.warnings, Default::default());
    render(&a);
    // check each cosigner: every page, then addresses, then the code
    press(&mut a, Key::Char('1'));
    for i in 0..3 {
        assert_eq!(step(&a), WlStep::Cosigner { i });
        render(&a);
        press(&mut a, Key::Enter);
    }
    assert_eq!(step(&a), WlStep::Addresses);
    render(&a);
    // the first receive address is the wallet's
    let mut want = [0u8; 90];
    let wl = w.derive(0, 0).unwrap().address(a.settings.network, &mut want);
    assert_eq!(
        a.wl.pending.as_ref().unwrap().address(0),
        core::str::from_utf8(&want[..wl]).unwrap()
    );
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), WlStep::CodeShow);
    render(&a);
    let code = code_of(&a);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), WlStep::CodeEntry { rereg: false });
    // a wrong code, then something that is not a code
    type_str(&mut a, "0000-0000");
    press(&mut a, Key::Enter);
    assert_eq!(a.wl.bad, 1);
    render(&a);
    for _ in 0..9 {
        press(&mut a, Key::Backspace);
    }
    type_str(&mut a, "UUUU");
    press(&mut a, Key::Enter);
    assert_eq!(a.wl.bad, 2);
    for _ in 0..4 {
        press(&mut a, Key::Backspace);
    }
    // lower case and without the dash
    type_str(&mut a, &std::str::from_utf8(&code.0).unwrap().to_lowercase());
    press(&mut a, Key::Enter);
    assert!(matches!(step(&a), WlStep::Registered { idx: 0, .. }));
    assert_eq!(a.wallets.len(), 1);
    let e = a.wallets.get(0).unwrap();
    assert_eq!(e.wallet.id(), w.id());
    assert_eq!(e.code, code);
    assert_eq!(e.ours, Some(1));
    render(&a);
    // Done: the list now shows the wallet
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), WlStep::List { sel: 0 });
    render(&a);
    // importing it again: already registered
    let n_before = a.wallets.len();
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    import(&mut a, &descriptor_of(&w));
    assert_eq!(a.wl.pending.as_ref().unwrap().checked.duplicate, Some(0));
    render(&a);
    press(&mut a, Key::Enter);
    assert_eq!(a.wallets.len(), n_before);
}

#[test]
fn register_with_code_from_earlier_session() {
    // session 1: learn the code
    let mut a = app();
    load_abandon(&mut a);
    let w = wallet_of(&a, MsScript::ShWsh, 2, 3);
    import(&mut a, &descriptor_of(&w));
    let code = code_of(&a);
    // session 2 (power cycle): the same wallet from a Coldcard file
    let mut b = app();
    load_abandon(&mut b);
    let mut file = [0u8; 4096];
    let n = formats::write_coldcard(&w, "Vault", &mut file).unwrap();
    import(&mut b, std::str::from_utf8(&file[..n]).unwrap());
    assert_eq!(code_of(&b), code, "same wallet, same seed: same code");
    press(&mut b, Key::Char('2'));
    assert_eq!(step(&b), WlStep::CodeEntry { rereg: true });
    // a wrong code is refused with the "not this wallet" message
    type_str(&mut b, "ZZZZZZZZ");
    press(&mut b, Key::Enter);
    assert_eq!(b.wl.bad, 1);
    render(&b);
    assert!(b.wallets.is_empty());
    for _ in 0..8 {
        press(&mut b, Key::Backspace);
    }
    let d = code.display();
    type_str(&mut b, std::str::from_utf8(&d).unwrap());
    press(&mut b, Key::Enter);
    assert!(matches!(step(&b), WlStep::Registered { .. }));
    assert_eq!(b.wallets.get(0).unwrap().wallet.name(), "Vault");
}

#[test]
fn a_changed_wallet_gets_another_code() {
    let mut a = app();
    load_abandon(&mut a);
    let w = wallet_of(&a, MsScript::Wsh, 2, 3);
    import(&mut a, &descriptor_of(&w));
    let code = code_of(&a);
    press(&mut a, Key::Esc);
    // the coordinator lowers the threshold: different code
    let w1 = wallet_of(&a, MsScript::Wsh, 1, 3);
    press(&mut a, Key::Esc);
    import(&mut a, &descriptor_of(&w1));
    assert_ne!(code_of(&a), code);
    assert!(a.wl.pending.as_ref().unwrap().checked.warnings.one_of_n);
}

#[test]
fn refusals_name_the_reason() {
    let mut a = app();
    load_abandon(&mut a);
    // not a multisig descriptor
    import(&mut a, "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)");
    assert_eq!(step(&a), WlStep::Refused);
    assert!(matches!(a.wl.problem, Some(Problem::Format(_))));
    render(&a);
    press(&mut a, Key::Enter);
    // our fingerprint on another key
    let mut w = wallet_of(&a, MsScript::Wsh, 2, 3);
    let mut keys: Vec<Cosigner> = w.keys().to_vec();
    keys[1].xpub = keys[0].xpub;
    keys[0].xpub.key = BpXpriv::master(&[99; 32]).unwrap().to_xpub().key;
    keys[0].xpub.depth = 4;
    w = Wallet::new(w.test, w.script, 2, &keys).unwrap();
    press(&mut a, Key::Esc);
    import(&mut a, &descriptor_of(&w));
    assert_eq!(step(&a), WlStep::Refused);
    match a.wl.problem {
        Some(Problem::Reject(r)) => assert_eq!(r.kind, RejectKind::OurKeyMismatch),
        p => panic!("{p:?}"),
    }
    render(&a);
    // a scan that is not a wallet at all
    to_main(&mut a);
    open_wallets(&mut a);
    press(&mut a, Key::Char('1'));
    a.on_qr_text(b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert!(matches!(a.current(), Screen::ScanResult));
    render(&a);
}

#[test]
fn main_menu_scan_opens_wallet_import() {
    let mut a = app();
    load_abandon(&mut a);
    let w = wallet_of(&a, MsScript::Wsh, 2, 3);
    press(&mut a, Key::Char('1')); // Scan QR
    a.on_qr_text(descriptor_of(&w).as_bytes());
    assert_eq!(step(&a), WlStep::Summary { sel: 0 });
}

#[test]
fn verify_only_wallet() {
    let mut a = app();
    load_abandon(&mut a);
    // a wallet without this seed's key
    let net = a.settings.network;
    let path = MsScript::Wsh.account_path(net, 0);
    let keys: Vec<Cosigner> = (1..=3u8)
        .map(|i| {
            let mk = BpXpriv::master(&[i + 70; 32]).unwrap();
            Cosigner {
                fingerprint: mk.fingerprint(),
                origin: path,
                xpub: mk.derive_path(&path).unwrap().to_xpub(),
                version: KeyVersion::X,
            }
        })
        .collect();
    let w = Wallet::new(false, MsScript::Wsh, 2, &keys).unwrap();
    import(&mut a, &descriptor_of(&w));
    let p = a.wl.pending.as_ref().unwrap();
    assert_eq!(p.checked.ours, None);
    assert!(p.checked.warnings.watch_only);
    render(&a);
}

fn register_quick(a: &mut App, w: &Wallet) {
    import(a, &descriptor_of(w));
    let code = code_of(a);
    press(a, Key::Char('2'));
    type_str(a, std::str::from_utf8(&code.0).unwrap());
    press(a, Key::Enter);
    assert!(matches!(step(a), WlStep::Registered { .. }));
}

#[test]
fn export_round_trips() {
    let mut a = app();
    load_abandon(&mut a);
    let w = wallet_of(&a, MsScript::Wsh, 2, 3);
    register_quick(&mut a, &w);
    // Export wallet QR from the "registered" screen
    press(&mut a, Key::Enter);
    assert!(matches!(step(&a), WlStep::Export { .. }));
    render(&a);
    // descriptor in one QR: parses back to the same wallet
    press(&mut a, Key::Char('1'));
    assert!(matches!(a.current(), Screen::QrShow { .. }));
    render(&a);
    let text = qr_text_of(&a);
    assert_eq!(
        formats::parse_wallet(text.as_bytes()).unwrap().wallet.id(),
        w.id()
    );
    press(&mut a, Key::Esc);
    // Coldcard file as UR bytes
    press(&mut a, Key::Char('3'));
    let payload = a.qr.as_ref().unwrap().payload().to_vec();
    let mut r = bp_qr::ur::cbor::Reader::new(&payload);
    let file = r.bytes().unwrap();
    let got = formats::parse_wallet(file).unwrap();
    assert_eq!(got.format, formats::Format::Coldcard);
    assert_eq!(got.wallet.id(), w.id());
    render(&a);
    press(&mut a, Key::Esc);
    // animated descriptor and BBQr open too
    for k in ['2', '4'] {
        press(&mut a, Key::Char(k));
        assert!(matches!(a.current(), Screen::QrShow { .. }), "{k}");
        render(&a);
        press(&mut a, Key::Esc);
    }
}

#[test]
fn wallet_menu_keys_and_remove() {
    let mut a = app();
    load_abandon(&mut a);
    let w = wallet_of(&a, MsScript::Wsh, 2, 3);
    register_quick(&mut a, &w);
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter); // Done -> list
    press(&mut a, Key::Char('1')); // the wallet
    assert!(matches!(step(&a), WlStep::Wallet { idx: 0, .. }));
    render(&a);
    press(&mut a, Key::Char('1')); // cosigners
    for i in 0..3 {
        assert_eq!(step(&a), WlStep::Keys { idx: 0, i });
        render(&a);
        press(&mut a, Key::Right);
    }
    press(&mut a, Key::Esc);
    press(&mut a, Key::Char('3')); // remove
    assert!(matches!(step(&a), WlStep::Remove { .. }));
    render(&a);
    press(&mut a, Key::Char('2'));
    assert_eq!(step(&a), WlStep::List { sel: 0 });
    assert!(a.wallets.is_empty());
}

#[test]
fn discarding_the_seed_forgets_its_wallets() {
    let mut a = app();
    load_abandon(&mut a);
    let w = wallet_of(&a, MsScript::Wsh, 2, 3);
    register_quick(&mut a, &w);
    assert_eq!(a.wallets.len(), 1);
    // Seeds > seed 1 > Discard > Yes
    while !matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }) {
        press(&mut a, Key::Esc);
    }
    a.push(Screen::Confirm {
        what: Confirm::DiscardSeed(0),
        sel: 1,
    });
    press(&mut a, Key::Enter);
    assert!(a.wallets.is_empty());
}

#[test]
fn registry_full() {
    let mut a = app();
    load_abandon(&mut a);
    for m in 1..=4u8 {
        let w = wallet_of(&a, MsScript::Wsh, m.min(4), 4);
        register_quick(&mut a, &w);
        press(&mut a, Key::Down);
        press(&mut a, Key::Enter);
        while !matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }) {
            press(&mut a, Key::Esc);
        }
    }
    assert_eq!(a.wallets.len(), 4);
    open_wallets(&mut a);
    press(&mut a, Key::Char('5'));
    assert_eq!(a.notice, Some(a.text().wl.full));
    render(&a);
}

// ---------- M7-5: air-gapped creation, key export ----------

fn cosigner_key(i: u8, script: MsScript, net: bp_bitcoin::Network) -> Cosigner {
    let mk = BpXpriv::master(&[i; 32]).unwrap();
    let path = script.account_path(net, 0);
    Cosigner {
        fingerprint: mk.fingerprint(),
        origin: path,
        xpub: mk.derive_path(&path).unwrap().to_xpub(),
        version: KeyVersion::X,
    }
}

fn key_text(c: &Cosigner, test: bool) -> String {
    let mut b = [0u8; 256];
    let n = formats::write_key_text(c, test, &mut b).unwrap();
    String::from_utf8(b[..n].to_vec()).unwrap()
}

/// A single-part UR crypto-account QR for `c`, as SeedSigner shows it.
fn account_ur(c: &Cosigner, net: bp_bitcoin::Network) -> String {
    use bp_bitcoin::urtypes::{crypto_account_tags, AccountKey, TAG_WSH};
    let k = AccountKey {
        xpub: &c.xpub,
        master_fingerprint: c.fingerprint,
        path: &c.origin,
        script: bp_bitcoin::address::ScriptType::NativeSegwit,
        network: net,
    };
    let mut p = [0u8; 512];
    let n = crypto_account_tags(&k, &[TAG_WSH], &mut p).unwrap();
    let enc = bp_qr::ur::UrEncoder::new("crypto-account", &p[..n], 1000).unwrap();
    let mut out = [0u8; 2048];
    let k = enc.part(1, &mut out).unwrap();
    String::from_utf8(out[..k].to_vec()).unwrap()
}

/// Main > Tools > Multisig > Create (one seed loaded): defaults 2-of-3.
fn open_create(a: &mut App) {
    to_main(a);
    open_wallets(a);
    let n = a.wallets.len();
    press(a, Key::Char((b'2' + n as u8) as char));
    assert_eq!(step(a), WlStep::CreateSize { field: 0 });
}

fn scan_cosigner(a: &mut App, text: &str) {
    assert_eq!(step(a), WlStep::CreateKeys);
    press(a, Key::Enter);
    assert!(matches!(
        a.current(),
        Screen::Scan {
            purpose: scan::Purpose::Cosigner
        }
    ));
    a.on_qr_text(text.as_bytes());
}

#[test]
fn create_wallet_air_gapped() {
    let mut a = app();
    load_abandon(&mut a);
    let net = a.settings.network;
    open_create(&mut a);
    render(&a);
    // 2-of-3 P2WSH, account 0 (the defaults)
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), WlStep::CreateKeys);
    render(&a);
    let c1 = cosigner_key(41, MsScript::Wsh, net);
    let c2 = cosigner_key(42, MsScript::Wsh, net);
    // cosigner 2 as text (Specter DIY, Krux), shown in full first
    scan_cosigner(&mut a, &key_text(&c1, false));
    assert_eq!(step(&a), WlStep::CreateConfirm { sel: 0 });
    render(&a);
    press(&mut a, Key::Char('1'));
    assert_eq!(a.wl.creating.as_ref().unwrap().count, 2);
    // cosigner 3 as UR crypto-account (SeedSigner)
    scan_cosigner(&mut a, &account_ur(&c2, net));
    assert_eq!(step(&a), WlStep::CreateConfirm { sel: 0 });
    press(&mut a, Key::Char('1'));
    // all keys in: first addresses, then the code
    assert_eq!(step(&a), WlStep::Addresses);
    assert!(a.wl.creating.is_none());
    let p = a.wl.pending.as_ref().unwrap();
    assert_eq!(p.format, None);
    assert_eq!(p.checked.ours, Some(0));
    let seed = a.slot(0).unwrap();
    let path = MsScript::Wsh.account_path(net, 0);
    let ours = Cosigner {
        fingerprint: seed.fingerprint,
        origin: path,
        xpub: seed.master().derive_path(&path).unwrap().to_xpub(),
        version: KeyVersion::X,
    };
    let want = Wallet::new(false, MsScript::Wsh, 2, &[ours, c1, c2]).unwrap();
    assert_eq!(p.wallet.id(), want.id());
    render(&a);
    press(&mut a, Key::Enter);
    let code = code_of(&a);
    press(&mut a, Key::Enter);
    type_str(&mut a, std::str::from_utf8(&code.0).unwrap());
    press(&mut a, Key::Enter);
    assert!(matches!(step(&a), WlStep::Registered { .. }));
    assert_eq!(a.wallets.get(0).unwrap().wallet.id(), want.id());
    // export it for Sparrow and the other cosigners
    press(&mut a, Key::Enter);
    press(&mut a, Key::Char('1'));
    let text = qr_text_of(&a);
    assert_eq!(
        formats::parse_wallet(text.as_bytes()).unwrap().wallet.id(),
        want.id()
    );
}

#[test]
fn create_size_choices() {
    let mut a = app();
    load_abandon(&mut a);
    open_create(&mut a);
    // script type -> P2SH-P2WSH; M up to N; N down clamps M; account 2
    press(&mut a, Key::Right);
    press(&mut a, Key::Down);
    for _ in 0..5 {
        press(&mut a, Key::Right);
    }
    let cr = a.wl.creating.as_ref().unwrap();
    assert_eq!((cr.script, cr.m, cr.n), (MsScript::ShWsh, 3, 3));
    press(&mut a, Key::Down);
    for _ in 0..20 {
        press(&mut a, Key::Right);
    }
    assert_eq!(a.wl.creating.as_ref().unwrap().n, 15);
    for _ in 0..20 {
        press(&mut a, Key::Left);
    }
    let cr = a.wl.creating.as_ref().unwrap();
    assert_eq!((cr.m, cr.n), (2, 2));
    press(&mut a, Key::Down);
    press(&mut a, Key::Right);
    press(&mut a, Key::Right);
    assert_eq!(a.wl.creating.as_ref().unwrap().account, 2);
    render(&a);
    press(&mut a, Key::Enter);
    let cr = a.wl.creating.as_ref().unwrap();
    let ours = cr.keys().next().unwrap();
    assert_eq!(
        ours.origin,
        MsScript::ShWsh.account_path(a.settings.network, 2),
        "our key at BIP-48 account 2, script type 1'"
    );
}

#[test]
fn create_refuses_bad_cosigners() {
    let mut a = app();
    load_abandon(&mut a);
    let net = a.settings.network;
    open_create(&mut a);
    press(&mut a, Key::Enter);
    let c1 = cosigner_key(41, MsScript::Wsh, net);
    let refused = |a: &App| match a.wl.problem {
        Some(Problem::Reject(r)) => Some(r.kind),
        _ => None,
    };
    // this device's own key, scanned back
    let ours = a.wl.creating.as_ref().unwrap().keys().next().copied().unwrap();
    scan_cosigner(&mut a, &key_text(&ours, false));
    assert_eq!(step(&a), WlStep::CreateRefused);
    assert_eq!(refused(&a), Some(RejectKind::OurKeyTwice));
    render(&a);
    press(&mut a, Key::Enter);
    // a cosigner twice
    scan_cosigner(&mut a, &key_text(&c1, false));
    press(&mut a, Key::Char('1'));
    scan_cosigner(&mut a, &key_text(&c1, false));
    assert_eq!(refused(&a), Some(RejectKind::DuplicateKey));
    press(&mut a, Key::Enter);
    // the same cosigner seed on another account
    let mk = BpXpriv::master(&[41; 32]).unwrap();
    let p1 = MsScript::Wsh.account_path(net, 1);
    let other = Cosigner {
        fingerprint: mk.fingerprint(),
        origin: p1,
        xpub: mk.derive_path(&p1).unwrap().to_xpub(),
        version: KeyVersion::X,
    };
    scan_cosigner(&mut a, &key_text(&other, false));
    assert_eq!(refused(&a), Some(RejectKind::DuplicateFingerprint));
    press(&mut a, Key::Enter);
    // a test-network key on mainnet
    let t = cosigner_key(43, MsScript::Wsh, bp_bitcoin::Network::Testnet);
    scan_cosigner(&mut a, &key_text(&t, true));
    assert_eq!(refused(&a), Some(RejectKind::Network));
    press(&mut a, Key::Enter);
    // a Ypub (P2SH-P2WSH) for a P2WSH wallet
    let c3 = cosigner_key(44, MsScript::Wsh, net);
    let mut x = [0u8; bp_bitcoin::bip32::XKEY_LEN];
    let n = c3.xpub.encode(KeyVersion::MultiY.public(net), &mut x);
    let ypub = format!(
        "[{}/48h/0h/0h/2h]{}",
        crate::seeds::fingerprint_hex(&c3.fingerprint),
        std::str::from_utf8(&x[..n]).unwrap()
    );
    scan_cosigner(&mut a, &ypub);
    assert_eq!(refused(&a), Some(RejectKind::VersionScript));
    press(&mut a, Key::Enter);
    // a key without origin
    let n = c3.xpub.encode(KeyVersion::X.public(net), &mut x);
    scan_cosigner(&mut a, std::str::from_utf8(&x[..n]).unwrap());
    assert!(matches!(
        a.wl.problem,
        Some(Problem::Format(formats::Error::MissingOrigin))
    ));
    press(&mut a, Key::Enter);
    // a seed is never taken while scanning a cosigner
    scan_cosigner(
        &mut a,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    assert!(matches!(a.current(), Screen::ScanResult));
    assert_eq!(a.scan.outcome, Some(scan::Outcome::NotAKey));
    assert!(a.scanned.is_none());
    render(&a);
    // only cosigner 2 was added
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), WlStep::CreateKeys);
    assert_eq!(a.wl.creating.as_ref().unwrap().count, 2);
}

#[test]
fn export_my_multisig_key() {
    let mut a = app();
    load_abandon(&mut a);
    let net = a.settings.network;
    to_main(&mut a);
    open_wallets(&mut a);
    press(&mut a, Key::Char('3'));
    assert!(matches!(step(&a), WlStep::KeyScript { .. }));
    press(&mut a, Key::Right);
    press(&mut a, Key::Right);
    assert_eq!(a.wl.key_account, 2);
    render(&a);
    press(&mut a, Key::Enter); // P2WSH
    assert!(matches!(step(&a), WlStep::KeyFormat { .. }));
    render(&a);
    let path = MsScript::Wsh.account_path(net, 2);
    let sh_path = MsScript::ShWsh.account_path(net, 2);
    let (want, want_sh, fp) = {
        let seed = a.slot(0).unwrap();
        (
            seed.master().derive_path(&path).unwrap().to_xpub(),
            seed.master().derive_path(&sh_path).unwrap().to_xpub(),
            seed.fingerprint,
        )
    };
    // key text
    press(&mut a, Key::Char('1'));
    render(&a);
    let (k, _) = formats::parse_cosigner(qr_text_of(&a).as_bytes(), MsScript::Wsh).unwrap();
    assert_eq!((k.fingerprint, k.origin, k.xpub), (fp, path, want));
    press(&mut a, Key::Esc);
    // UR crypto-account
    press(&mut a, Key::Char('2'));
    let payload = a.qr.as_ref().unwrap().payload().to_vec();
    let (k, _) = formats::parse_cosigner_ur("crypto-account", &payload, MsScript::Wsh).unwrap();
    assert_eq!((k.origin, k.xpub), (path, want));
    press(&mut a, Key::Esc);
    // Coldcard JSON: both script types at account 2
    press(&mut a, Key::Char('3'));
    let json = qr_text_of(&a);
    let (k, _) = formats::parse_cosigner(json.as_bytes(), MsScript::ShWsh).unwrap();
    assert_eq!((k.origin, k.xpub), (sh_path, want_sh));
}
