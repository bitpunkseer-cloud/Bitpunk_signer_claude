//! Seeds > Import private key: WIF and XPRV, typed or scanned; refusals;
//! a WIF slot's addresses and signing (checked with rust-bitcoin); the
//! features a single key does not offer.

use super::*;
use crate::keys::{KeyProblem, KeyStep};
use crate::seeds::SlotKind;
use bitcoin::key::{CompressedPublicKey, Secp256k1};
use bitcoin::secp256k1::SecretKey as RefSk;
use std::string::{String, ToString};
use std::vec;

const SK: [u8; 32] = [0x42; 32];

fn wif(net: bitcoin::NetworkKind, compressed: bool) -> String {
    bitcoin::PrivateKey {
        compressed,
        network: net,
        inner: RefSk::from_slice(&SK).unwrap(),
    }
    .to_wif()
}

fn step(a: &App) -> KeyStep {
    match a.current() {
        Screen::Key { step } => step,
        s => panic!("not a key screen: {s:?}"),
    }
}

/// Seeds > Import private key > Type it.
fn open_type(a: &mut App) {
    press(a, Key::Char('2'));
    press(a, Key::Char('3'));
    assert_eq!(step(a), KeyStep::Method { sel: 0 });
    press(a, Key::Char('2'));
    assert_eq!(step(a), KeyStep::Type);
}

fn import_typed(a: &mut App, key: &str) {
    open_type(a);
    type_str(a, key);
    render(a);
    press(a, Key::Enter);
}

#[test]
fn wif_typed_loads_a_single_key_slot() {
    let mut a = app();
    import_typed(&mut a, &wif(bitcoin::NetworkKind::Main, true));
    assert_eq!(step(&a), KeyStep::Confirm { sel: 0 });
    render(&a);
    assert_eq!(a.key_in.text(), "", "typed key wiped once checked");
    press(&mut a, Key::Enter);
    assert!(matches!(a.current(), Screen::SeedReady { .. }));
    let s = a.slot(0).unwrap();
    assert_eq!(s.kind, SlotKind::Wif);
    assert!(s.mnemonic.is_none());
    let label = crate::view::seed_label(s);
    assert!(label.as_str().contains("(WIF)"), "{}", label.as_str());
    // options: addresses, discard
    press(&mut a, Key::Enter);
    assert_eq!(a.current(), Screen::SeedOptions { slot: 0, sel: 0 });
    render(&a);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), KeyStep::Addresses { slot: 0, sel: 0 });
    render(&a);
    // the native segwit address is the key's P2WPKH
    let secp = Secp256k1::new();
    let pk = CompressedPublicKey(RefSk::from_slice(&SK).unwrap().public_key(&secp));
    let want = bitcoin::Address::p2wpkh(&pk, bitcoin::Network::Bitcoin).to_string();
    let mut out = [0u8; bp_bitcoin::address::MAX_ADDRESS_LEN];
    let n = a.key_address(0, bp_bitcoin::address::ScriptType::NativeSegwit, &mut out);
    assert_eq!(std::str::from_utf8(&out[..n]).unwrap(), want);
    let n = a.key_address(0, bp_bitcoin::address::ScriptType::Taproot, &mut out);
    let tr = bitcoin::Address::p2tr(&secp, pk.0.x_only_public_key().0, None, bitcoin::Network::Bitcoin)
        .to_string();
    assert_eq!(std::str::from_utf8(&out[..n]).unwrap(), tr);
    for _ in 0..3 {
        press(&mut a, Key::Down);
        render(&a);
    }
}

#[test]
fn xprv_scanned_loads_a_root_slot() {
    let mut a = app();
    let x = bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Main, &[3; 32])
        .unwrap()
        .to_string();
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Char('3'));
    press(&mut a, Key::Char('1')); // Scan
    assert!(matches!(a.current(), Screen::Scan { .. }));
    a.on_qr_text(x.as_bytes());
    assert_eq!(step(&a), KeyStep::Confirm { sel: 0 });
    assert!(a.scan.out.iter().all(|&b| b == 0), "scan buffer wiped");
    press(&mut a, Key::Enter);
    let s = a.slot(0).unwrap();
    assert_eq!(s.kind, SlotKind::Xprv);
    let root = bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Main, &[3; 32]).unwrap();
    let secp = Secp256k1::new();
    assert_eq!(s.fingerprint, root.fingerprint(&secp).to_bytes());
    // options: xpub, explorer, discard; the xpub is derived from the key
    press(&mut a, Key::Enter);
    render(&a);
    press(&mut a, Key::Enter);
    assert!(matches!(
        a.current(),
        Screen::ScriptSelect { explorer: false, .. }
    ));
    let xpub = a
        .slot(0)
        .unwrap()
        .account_xpub(
            bp_bitcoin::address::ScriptType::NativeSegwit,
            bp_bitcoin::Network::Mainnet,
            0,
        )
        .unwrap();
    let path: bitcoin::bip32::DerivationPath = "m/84'/0'/0'".parse().unwrap();
    let want = bitcoin::bip32::Xpub::from_priv(&secp, &root.derive_priv(&secp, &path).unwrap());
    let mut enc = [0u8; bp_bitcoin::bip32::XKEY_LEN];
    let n = xpub.encode(
        bp_bitcoin::bip32::KeyVersion::X.public(bp_bitcoin::Network::Mainnet),
        &mut enc,
    );
    assert_eq!(std::str::from_utf8(&enc[..n]).unwrap(), want.to_string());
}

/// A valid xprv with one character changed (bad checksum).
fn broken_xprv() -> String {
    let mut x = bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Main, &[3; 32])
        .unwrap()
        .to_string();
    let last = x.pop().unwrap();
    x.push(if last == 'a' { 'b' } else { 'a' });
    x
}

#[test]
fn bad_keys_are_refused() {
    let tprv = bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Test, &[3; 32])
        .unwrap()
        .to_string();
    let cases = [
        (wif(bitcoin::NetworkKind::Main, false), KeyProblem::Uncompressed),
        (wif(bitcoin::NetworkKind::Test, true), KeyProblem::Network),
        (tprv, KeyProblem::Network),
        ("notakey".to_string(), KeyProblem::Invalid),
        (broken_xprv(), KeyProblem::Invalid),
    ];
    for (key, want) in cases {
        let mut a = app();
        import_typed(&mut a, &key);
        assert_eq!(step(&a), KeyStep::Refused, "{key}");
        assert_eq!(a.key_problem, Some(want), "{key}");
        render(&a);
        press(&mut a, Key::Enter);
        assert_eq!(step(&a), KeyStep::Type);
        assert_eq!(a.seed_count(), 0);
    }
    // the same key twice
    let mut a = app();
    let w = wif(bitcoin::NetworkKind::Main, true);
    import_typed(&mut a, &w);
    press(&mut a, Key::Enter);
    // (the Seeds menu now lists the slot first: open the import directly)
    a.open_key_import();
    press(&mut a, Key::Char('2'));
    type_str(&mut a, &w);
    press(&mut a, Key::Enter);
    assert_eq!(a.key_problem, Some(KeyProblem::Duplicate));
}

#[test]
fn a_wif_slot_signs_its_inputs() {
    use bitcoin::hashes::Hash;
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    let secp = Secp256k1::new();
    let sk = RefSk::from_slice(&SK).unwrap();
    let pk = CompressedPublicKey(sk.public_key(&secp));
    let ours = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let prev = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ours.clone(),
        }],
    };
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: W::other().wpkh("m/84'/0'/0'/0/1"),
            },
            TxOut {
                value: Amount::from_sat(39_000),
                script_pubkey: ours.clone(),
            },
        ],
    };
    let mut p = bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap();
    p.inputs[0].non_witness_utxo = Some(prev.clone());
    p.inputs[0].witness_utxo = Some(prev.output[0].clone());
    let mut a = app();
    import_typed(&mut a, &wif(bitcoin::NetworkKind::Main, true));
    press(&mut a, Key::Enter);
    a.reset_to(Screen::Menu {
        id: MenuId::Main,
        sel: 0,
    });
    scan_psbt(&mut a, &p);
    assert_eq!(
        super::step(&a),
        crate::review::Step::Overview,
        "{:?}",
        a.review
            .as_ref()
            .unwrap()
            .report
            .as_ref()
            .map(|r| r.issues().to_vec())
    );
    for _ in 0..4 {
        press(&mut a, Key::Enter);
    }
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    assert_eq!(super::step(&a), crate::review::Step::Signed { sel: 0 });
    let signed = a.review.as_ref().unwrap().signed.unwrap();
    let out = bitcoin::psbt::Psbt::deserialize(&a.scan.work()[..signed.len]).unwrap();
    let (key, sig) = out.inputs[0].partial_sigs.iter().next().unwrap();
    assert_eq!(key.inner, pk.0);
    let mut cache = bitcoin::sighash::SighashCache::new(&p.unsigned_tx);
    let h = cache
        .p2wpkh_signature_hash(
            0,
            &ours,
            Amount::from_sat(100_000),
            bitcoin::EcdsaSighashType::All,
        )
        .unwrap();
    secp.verify_ecdsa(
        &bitcoin::secp256k1::Message::from_digest(h.to_byte_array()),
        &sig.signature,
        &pk.0,
    )
    .unwrap();
}

#[test]
fn single_keys_do_not_offer_path_features() {
    let mut a = app();
    import_typed(&mut a, &wif(bitcoin::NetworkKind::Main, true));
    press(&mut a, Key::Enter);
    a.reset_to(Screen::Menu {
        id: MenuId::Main,
        sel: 0,
    });
    // BIP-85
    press(&mut a, Key::Char('3'));
    press(&mut a, Key::Char('7'));
    assert!(matches!(
        a.current(),
        Screen::Menu {
            id: MenuId::Tools,
            ..
        }
    ));
    assert_eq!(a.notice, Some(a.text().key.not_for_wif));
    // the address explorer shows the key's addresses
    press(&mut a, Key::Char('2'));
    assert_eq!(step(&a), KeyStep::Addresses { slot: 0, sel: 0 });
}

#[test]
fn key_screens_fit() {
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(format!("key-{l}-{name}.ppm")));
            }
        };
        let mut a = app();
        a.settings.lang = lang;
        a.set_test_only(true);
        press(&mut a, Key::Char('2'));
        press(&mut a, Key::Char('3'));
        shot(&a, "method");
        press(&mut a, Key::Char('2'));
        let x = bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Main, &[3; 32])
            .unwrap()
            .to_string();
        type_str(&mut a, &x);
        shot(&a, "type");
        press(&mut a, Key::Enter);
        shot(&a, "confirm-xprv");
        press(&mut a, Key::Esc);
        type_str(&mut a, &wif(bitcoin::NetworkKind::Main, false));
        press(&mut a, Key::Enter);
        shot(&a, "refused");
        press(&mut a, Key::Enter);
        type_str(&mut a, &wif(bitcoin::NetworkKind::Main, true));
        press(&mut a, Key::Enter);
        shot(&a, "confirm-wif");
        press(&mut a, Key::Enter);
        press(&mut a, Key::Enter);
        shot(&a, "options-wif");
        press(&mut a, Key::Enter);
        press(&mut a, Key::Down);
        press(&mut a, Key::Down);
        press(&mut a, Key::Down);
        shot(&a, "addresses");
    }
}

#[test]
fn a_network_chip_locks_the_device() {
    use bp_hal::mdio::PhyFound;
    use bp_hal::CommCheck;
    let mut a = app();
    import_typed(&mut a, &wif(bitcoin::NetworkKind::Main, true));
    press(&mut a, Key::Enter);
    assert_eq!(a.seed_count(), 1);
    a.set_comm_check(CommCheck::Detected(PhyFound {
        addr: 1,
        id: 0x001C_C916,
    }));
    assert_eq!(a.current(), Screen::CommDetected);
    assert_eq!(a.seed_count(), 0, "seeds wiped");
    for k in [Key::Enter, Key::Esc, Key::Char('1'), Key::Qr, Key::Down] {
        press(&mut a, k);
        assert_eq!(a.current(), Screen::CommDetected);
    }
    a.tick(10_000);
    assert_eq!(a.current(), Screen::CommDetected);
    // a fresh boot with the chip still there goes straight back
    let mut b = App::new(b"x");
    b.set_comm_check(CommCheck::Detected(PhyFound {
        addr: 31,
        id: 0x0007_C0F1,
    }));
    b.tick(SPLASH_MS);
    assert_eq!(b.current(), Screen::CommDetected);
    // removed: back to the main menu
    a.set_comm_check(CommCheck::Clean);
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let mut c = app();
        c.settings.lang = lang;
        c.set_test_only(true);
        c.set_comm_check(CommCheck::Detected(PhyFound {
            addr: 1,
            id: 0x001C_C916,
        }));
        let mut shot = super::layout::Shot::new();
        c.render(&mut shot);
        if let Some(d) = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from) {
            let l = ["en", "ko"][lang as usize];
            shot.save(&d.join(format!("key-{l}-comm.ppm")));
        }
    }
}
