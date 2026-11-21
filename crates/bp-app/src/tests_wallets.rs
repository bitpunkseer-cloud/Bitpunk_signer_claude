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
