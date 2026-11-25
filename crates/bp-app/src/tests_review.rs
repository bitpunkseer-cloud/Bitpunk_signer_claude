//! PSBT review and signing flows, driven by key events. PSBTs are built
//! with rust-bitcoin (test-only) for the "abandon ... about" seed.

use super::*;
extern crate std;
use crate::menus::Start;
use crate::nav::{self, To};
use crate::review::Step;
use bitcoin::bip32::{DerivationPath, Xpriv as RefXpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::{CompressedPublicKey, Secp256k1};
use bitcoin::psbt::Psbt as RefPsbt;
use bitcoin::{
    absolute, transaction, Amount, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use bp_hal::input::Key;
use std::format;
use std::str::FromStr;
use std::string::String;
use std::vec;
use std::vec::Vec;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn app() -> App {
    let mut a = App::new(b"test quiz seed");
    a.tick(SPLASH_MS);
    nav::home(&mut a); // past the first-run screen (M9-4)
    a
}

fn press(a: &mut App, k: Key) {
    a.on_key(KeyEvent::new(k));
}

fn type_str(a: &mut App, s: &str) {
    for ch in s.chars() {
        press(a, Key::Char(ch));
    }
}

/// Seeds > Load seed > Type words > 12 words, then back to the main menu.
fn load_abandon(a: &mut App) {
    nav::go(a, To::Start(Start::TypeWords));
    nav::words(a, 12);
    for _ in 0..11 {
        type_str(a, "aban");
    }
    type_str(a, "abou");
    assert!(matches!(a.current(), Screen::SeedReady { .. }));
    while !matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }) {
        press(a, Key::Esc);
    }
}

struct Null;
impl bp_hal::Canvas for Null {
    fn width(&self) -> u16 {
        800
    }
    fn height(&self) -> u16 {
        480
    }
    fn fill_rect(&mut self, _: i32, _: i32, _: i32, _: i32, _: bp_hal::Rgb) {}
    fn blend_pixel(&mut self, _: i32, _: i32, _: bp_hal::Rgb, _: u8) {}
}

fn render(a: &App) {
    a.render(&mut Null);
}

struct W {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    master: RefXpriv,
}

impl W {
    fn from_phrase(p: &str) -> W {
        let m = bip39_ref_seed(p);
        let secp = Secp256k1::new();
        W {
            master: RefXpriv::new_master(NetworkKind::Main, &m).unwrap(),
            secp,
        }
    }
    fn other() -> W {
        let secp = Secp256k1::new();
        W {
            master: RefXpriv::new_master(NetworkKind::Main, &[7; 32]).unwrap(),
            secp,
        }
    }
    fn key(&self, path: &str) -> (bitcoin::secp256k1::PublicKey, DerivationPath) {
        let p = DerivationPath::from_str(path).unwrap();
        (
            self.master
                .derive_priv(&self.secp, &p)
                .unwrap()
                .private_key
                .public_key(&self.secp),
            p,
        )
    }
    fn wpkh(&self, path: &str) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&CompressedPublicKey(self.key(path).0).wpubkey_hash())
    }
}

/// The BIP-39 seed of the phrase (only "abandon ... about" here: zero
/// entropy; our BIP-39 is checked against the reference vectors elsewhere).
fn bip39_ref_seed(p: &str) -> Vec<u8> {
    assert_eq!(p, ABANDON);
    let m = bp_bitcoin::bip39::Mnemonic::from_entropy(&[0; 16]).unwrap();
    m.to_seed("").unwrap().expose().to_vec()
}

/// P2WPKH inputs (index, amount, with previous tx) paying `outs`
/// (script, amount, change index).
fn psbt(w: &W, ins: &[(u32, u64, bool)], outs: &[(ScriptBuf, u64, Option<u32>)]) -> RefPsbt {
    let fp = w.master.fingerprint(&w.secp);
    let prevs: Vec<Transaction> = ins
        .iter()
        .enumerate()
        .map(|(n, &(i, amt, _))| Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([n as u8 + 1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(amt),
                script_pubkey: w.wpkh(&format!("m/84'/0'/0'/0/{i}")),
            }],
        })
        .collect();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: prevs
            .iter()
            .map(|p| TxIn {
                previous_output: OutPoint {
                    txid: p.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outs
            .iter()
            .map(|(s, v, _)| TxOut {
                value: Amount::from_sat(*v),
                script_pubkey: s.clone(),
            })
            .collect(),
    };
    let mut p = RefPsbt::from_unsigned_tx(tx).unwrap();
    for ((inp, &(i, _, with_prev)), prev) in p.inputs.iter_mut().zip(ins).zip(&prevs) {
        if with_prev {
            inp.non_witness_utxo = Some(prev.clone());
        }
        inp.witness_utxo = Some(prev.output[0].clone());
        let (pk, path) = w.key(&format!("m/84'/0'/0'/0/{i}"));
        inp.bip32_derivation.insert(pk, (fp, path));
    }
    for (out, (_, _, change)) in p.outputs.iter_mut().zip(outs) {
        if let Some(c) = change {
            let (pk, path) = w.key(&format!("m/84'/0'/0'/1/{c}"));
            out.bip32_derivation.insert(pk, (fp, path));
        }
    }
    p
}

fn b64(raw: &[u8]) -> String {
    let mut out = vec![0u8; raw.len() * 4 / 3 + 8];
    let n = bp_bitcoin::base64::encode(raw, &mut out).unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

fn scan_psbt(a: &mut App, p: &RefPsbt) {
    nav::go(a, To::Scan(scan::Purpose::Any));
    assert!(matches!(a.current(), Screen::Scan { .. }));
    a.on_qr_text(b64(&p.serialize()).as_bytes());
}

fn step(a: &App) -> Step {
    match a.current() {
        Screen::Review { step } => step,
        s => panic!("not reviewing: {s:?}"),
    }
}

fn standard(w: &W) -> RefPsbt {
    psbt(
        w,
        &[(0, 100_000, true)],
        &[
            (W::other().wpkh("m/84'/0'/0'/0/5"), 60_000, None),
            (w.wpkh("m/84'/0'/0'/1/0"), 39_000, Some(0)),
        ],
    )
}

#[test]
fn review_then_cancel_or_sign() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    let p = standard(&w);
    // walk to the approval, then Cancel (the default)
    scan_psbt(&mut a, &p);
    let expected = [
        Step::Overview,
        Step::Output { idx: 0 },
        Step::Output { idx: 1 },
        Step::Fee,
        Step::Approve { sel: 0 },
    ];
    for (i, want) in expected.iter().enumerate() {
        render(&a);
        assert_eq!(step(&a), *want, "step {i}");
        if i + 1 < expected.len() {
            press(&mut a, Key::Enter);
        }
    }
    press(&mut a, Key::Enter); // Cancel
    assert!(back_where_scans_start(&a));
    assert!(a.review.is_none());
    assert!(a.scan.out.iter().all(|&b| b == 0), "scan buffer wiped");

    // again, this time Sign
    scan_psbt(&mut a, &p);
    for _ in 0..4 {
        press(&mut a, Key::Enter);
    }
    assert_eq!(step(&a), Step::Approve { sel: 0 });
    press(&mut a, Key::Down);
    assert_eq!(step(&a), Step::Approve { sel: 1 });
    render(&a);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), Step::Signed { sel: 0 });
    render(&a);
    let signed = a.review.as_ref().unwrap().signed.unwrap();
    assert_eq!(signed.signatures, 1);
    // the trimmed PSBT carries a valid signature for the right key
    let out = RefPsbt::deserialize(&a.scan.work()[..signed.len]).unwrap();
    assert_eq!(out.unsigned_tx, p.unsigned_tx);
    let (pk, _) = w.key("m/84'/0'/0'/0/0");
    let sig = out.inputs[0].partial_sigs[&bitcoin::PublicKey::new(pk)];
    let mut cache = bitcoin::sighash::SighashCache::new(&p.unsigned_tx);
    let h = cache
        .p2wpkh_signature_hash(
            0,
            &w.wpkh("m/84'/0'/0'/0/0"),
            Amount::from_sat(100_000),
            bitcoin::EcdsaSighashType::All,
        )
        .unwrap();
    w.secp
        .verify_ecdsa(
            &bitcoin::secp256k1::Message::from_digest(h.to_byte_array()),
            &sig.signature,
            &pk,
        )
        .unwrap();
    press(&mut a, Key::Esc);
    assert!(back_where_scans_start(&a));
    assert!(
        a.scan.work().iter().all(|&b| b == 0),
        "signed PSBT wiped after leaving"
    );
}

#[test]
fn back_navigation() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    scan_psbt(&mut a, &standard(&w));
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), Step::Output { idx: 1 });
    press(&mut a, Key::Left);
    assert_eq!(step(&a), Step::Output { idx: 0 });
    press(&mut a, Key::Esc);
    assert_eq!(step(&a), Step::Overview);
    press(&mut a, Key::Esc); // leaving the first step discards the PSBT
    assert!(back_where_scans_start(&a));
    assert!(a.review.is_none());
}

#[test]
fn wrong_seed_shows_need_and_found() {
    let other = W::other();
    let p = standard(&other);
    // no seed at all
    let mut a = app();
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::WrongSeed);
    render(&a);
    let r = a.review.as_ref().unwrap();
    assert_eq!(
        &r.need[..r.n_need],
        &[other.master.fingerprint(&other.secp).to_bytes()]
    );
    press(&mut a, Key::Esc);
    assert!(a.review.is_none());
    // a different seed loaded
    load_abandon(&mut a);
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::WrongSeed);
    render(&a);
    press(&mut a, Key::Enter);
    assert!(back_where_scans_start(&a));
}

#[test]
fn attacks_end_the_review() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    // change that claims this seed's key but pays someone else
    let mut p = standard(&w);
    p.unsigned_tx.output[1].script_pubkey = W::other().wpkh("m/84'/0'/0'/1/0");
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::Problem);
    render(&a);
    let r = a.review.as_ref().unwrap().report.as_ref().unwrap();
    assert_eq!(r.worst(), Some(bp_bitcoin::validate::Class::Attack));
    // no key reaches the approval
    for k in [Key::Down, Key::Right, Key::Tab] {
        press(&mut a, k);
        assert_eq!(step(&a), Step::Problem);
    }
    press(&mut a, Key::Enter);
    assert!(back_where_scans_start(&a));
    // an error (fee of 10% or more) ends it too
    let p = psbt(
        &w,
        &[(0, 100_000, true)],
        &[
            (W::other().wpkh("m/84'/0'/0'/0/5"), 50_000, None),
            (w.wpkh("m/84'/0'/0'/1/0"), 35_000, Some(0)),
        ],
    );
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::Problem);
    render(&a);
}

#[test]
fn warnings_are_confirmed_one_by_one() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    // no change: one warning, then the overview
    let p = psbt(
        &w,
        &[(0, 100_000, true)],
        &[(W::other().wpkh("m/84'/0'/0'/0/5"), 99_000, None)],
    );
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::Warning { idx: 0, sel: 0 });
    render(&a);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), Step::Overview);
    press(&mut a, Key::Esc);
    assert_eq!(step(&a), Step::Warning { idx: 0, sel: 0 });
}

#[test]
fn unverified_amounts_need_an_explicit_override() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    let p = psbt(
        &w,
        &[(0, 60_000, false), (1, 40_000, false)],
        &[
            (W::other().wpkh("m/84'/0'/0'/0/5"), 60_000, None),
            (w.wpkh("m/84'/0'/0'/1/0"), 39_000, Some(0)),
        ],
    );
    // Enter on the default (Cancel) discards
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::Warning { idx: 0, sel: 0 });
    render(&a);
    press(&mut a, Key::Enter);
    assert!(back_where_scans_start(&a));
    // choosing "sign without verifying" continues and signing works
    scan_psbt(&mut a, &p);
    press(&mut a, Key::Down);
    assert_eq!(step(&a), Step::Warning { idx: 0, sel: 1 });
    press(&mut a, Key::Enter);
    assert!(a.review.as_ref().unwrap().overridden);
    assert_eq!(step(&a), Step::Overview);
    for _ in 0..4 {
        press(&mut a, Key::Enter);
    }
    assert_eq!(step(&a), Step::Approve { sel: 0 });
    press(&mut a, Key::Up);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), Step::Signed { sel: 0 });
    assert_eq!(a.review.as_ref().unwrap().signed.unwrap().signatures, 2);
}

#[test]
fn signed_amounts_are_remembered_until_power_off() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    let p = standard(&w);
    scan_psbt(&mut a, &p);
    for _ in 0..4 {
        press(&mut a, Key::Enter);
    }
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), Step::Signed { sel: 0 });
    press(&mut a, Key::Esc);
    // the same coins with another amount (no previous tx to contradict it)
    let mut q = psbt(
        &w,
        &[(0, 100_500, false)],
        &[
            (W::other().wpkh("m/84'/0'/0'/0/5"), 60_000, None),
            (w.wpkh("m/84'/0'/0'/1/0"), 39_500, Some(0)),
        ],
    );
    q.unsigned_tx.input[0] = p.unsigned_tx.input[0].clone();
    scan_psbt(&mut a, &q);
    assert_eq!(step(&a), Step::Problem);
    assert!(a
        .review
        .as_ref()
        .unwrap()
        .report
        .as_ref()
        .unwrap()
        .has(bp_bitcoin::validate::Issue::UtxoAmountChanged(0)));
}

/// Sign the standard PSBT and return the app on the signed screen.
fn signed_app() -> (App, RefPsbt) {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    let p = standard(&w);
    scan_psbt(&mut a, &p);
    for _ in 0..4 {
        press(&mut a, Key::Enter);
    }
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), Step::Signed { sel: 0 });
    (a, p)
}

#[test]
fn signed_psbt_qr_round_trips_in_every_format() {
    use bp_bitcoin::qrinput::{Collector, Content, Feed, Source};
    let (mut a, p) = signed_app();
    let len = a.review.as_ref().unwrap().signed.unwrap().len;
    let signed = a.scan.work()[..len].to_vec();
    for (sel, source) in [(0u8, Source::Ur), (1, Source::Bbqr), (2, Source::Specter)] {
        while step(&a) != (Step::Signed { sel }) {
            press(&mut a, Key::Down);
        }
        press(&mut a, Key::Enter);
        assert!(matches!(a.current(), Screen::QrShow { .. }), "format {sel}");
        render(&a);
        // small density forces several frames
        a.qr.as_mut().unwrap().set_density(qrview::Density::High);
        let mut col: std::boxed::Box<Collector<{ 32 * 1024 }>> = std::boxed::Box::new(Collector::new());
        let mut done = false;
        for k in 0..400u32 {
            let q = a.qr.as_mut().unwrap();
            q.frame = if sel == 0 { k + 1 } else { k % q.frames() as u32 };
            let mut t = [0u8; qrview::TEXT_MAX];
            let n = q.text(&mut t);
            assert!(q.qr().is_some(), "frame {k} encodes");
            if col.feed(&t[..n]) == Feed::Complete {
                done = true;
                break;
            }
        }
        assert!(done, "format {sel} completes");
        let mut work = vec![0u8; 32 * 1024];
        let mut out = vec![0u8; 32 * 1024];
        let (content, src) = col.finish(&mut work, &mut out).unwrap();
        assert_eq!(src, source);
        let Content::Psbt { len: n, .. } = content else {
            panic!("format {sel}: not a PSBT")
        };
        assert_eq!(&out[..n], &signed[..], "format {sel}");
        press(&mut a, Key::Esc); // back to the signed screen
        assert_eq!(step(&a), Step::Signed { sel });
    }
    // Done wipes everything
    while step(&a) != (Step::Signed { sel: 3 }) {
        press(&mut a, Key::Down);
    }
    press(&mut a, Key::Enter);
    assert!(back_where_scans_start(&a));
    assert!(a.qr.is_none() && a.review.is_none());
    let _ = p;
}

/// A demo PSBT for the "abandon ... about" seed on mainnet (one P2WPKH
/// input, a recipient and change), for trying the simulator:
/// cargo test -p bp-app demo_psbt -- --ignored --nocapture
#[test]
#[ignore]
fn demo_psbt() {
    let w = W::from_phrase(ABANDON);
    std::println!("{}", b64(&standard(&w).serialize()));
}

// ---------- M6: address verification ----------

use crate::verify::VaStep;
use bitcoin::Address;
use std::string::ToString;

/// A P2WPKH (or P2TR) address of `w` at m/{84,86}'/0'/account'/chain/index.
fn addr_of(w: &W, taproot: bool, account: u32, chain: u32, index: u32) -> String {
    let purpose = if taproot { 86 } else { 84 };
    let (pk, _) = w.key(&format!("m/{purpose}'/0'/{account}'/{chain}/{index}"));
    if taproot {
        Address::p2tr(&w.secp, pk.x_only_public_key().0, None, bitcoin::Network::Bitcoin).to_string()
    } else {
        Address::p2wpkh(&CompressedPublicKey(pk), bitcoin::Network::Bitcoin).to_string()
    }
}

fn va(a: &App) -> VaStep {
    match a.current() {
        Screen::VerifyAddr { step } => step,
        s => panic!("not verifying: {s:?}"),
    }
}

/// Tools > Verify address, then scan `text`.
fn verify_scan(a: &mut App, text: &str) {
    nav::go(a, To::VerifyAddress);
    assert_eq!(
        a.current(),
        Screen::Scan {
            purpose: scan::Purpose::Address
        }
    );
    a.on_qr_text(text.as_bytes());
}

fn search_until_done(a: &mut App) -> u32 {
    let mut ticks = 0;
    while va(a) == VaStep::Searching {
        a.tick(16);
        ticks += 1;
        assert!(ticks < 10_000);
    }
    ticks
}

fn found(a: &App) -> bp_bitcoin::addrcheck::Found {
    match a.verify.as_ref().unwrap().search_state() {
        Some(bp_bitcoin::addrcheck::State::Found(f)) => f,
        s => panic!("not found: {s:?}"),
    }
}

#[test]
fn verify_finds_receive_and_change_addresses() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    for (taproot, chain, index) in [(false, 1, 7), (true, 0, 3)] {
        verify_scan(&mut a, &addr_of(&w, taproot, 0, chain, index));
        assert_eq!(va(&a), VaStep::Confirm { sel: 0 });
        render(&a);
        press(&mut a, Key::Enter);
        assert_eq!(va(&a), VaStep::Searching);
        render(&a);
        search_until_done(&mut a);
        assert_eq!(va(&a), VaStep::Found);
        render(&a);
        let f = found(&a);
        assert_eq!(
            (f.fingerprint, f.account, f.change, f.index),
            ([0x73, 0xc5, 0xda, 0x0a], 0, chain == 1, index)
        );
        assert_eq!(a.last_found, Some(index));
        press(&mut a, Key::Enter);
        assert!(matches!(
            a.current(),
            Screen::Menu { id, .. } if id == nav::menu_of(To::VerifyAddress)
        ));
        assert!(a.verify.is_none(), "state wiped on leaving");
        press(&mut a, Key::Esc);
    }
}

#[test]
fn verify_uses_the_index_hint_and_the_last_index() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    // far beyond the first batch, but the URI names the index
    verify_scan(
        &mut a,
        &format!("bitcoin:{}?index=1500", addr_of(&w, false, 0, 0, 1500)),
    );
    press(&mut a, Key::Enter);
    assert!(search_until_done(&mut a) <= 1);
    assert_eq!(found(&a).index, 1500);
    press(&mut a, Key::Enter);
    press(&mut a, Key::Esc);
    // next time the neighbourhood of 1500 is searched first
    verify_scan(&mut a, &addr_of(&w, false, 0, 1, 1510));
    press(&mut a, Key::Enter);
    assert!(search_until_done(&mut a) <= 6);
    assert_eq!(found(&a).index, 1510);
}

#[test]
fn verify_pauses_after_a_batch_and_offers_more_or_another_account() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    // an address of account 2 is not in account 0
    verify_scan(&mut a, &addr_of(&w, false, 2, 0, 4));
    press(&mut a, Key::Enter);
    // Esc stops mid-batch: "Continue searching"
    a.tick(16);
    press(&mut a, Key::Esc);
    assert_eq!(va(&a), VaStep::Paused { sel: 0 });
    render(&a);
    press(&mut a, Key::Enter);
    assert_eq!(va(&a), VaStep::Searching);
    search_until_done(&mut a);
    assert_eq!(va(&a), VaStep::Paused { sel: 0 });
    let s = a.verify.as_ref().unwrap();
    assert_eq!(s.scanned(), Some(bp_bitcoin::addrcheck::BATCH));
    render(&a);
    // try account 1 (not there), then account 2
    for want in [1, 2] {
        press(&mut a, Key::Down);
        press(&mut a, Key::Enter);
        assert_eq!(va(&a), VaStep::Searching);
        search_until_done(&mut a);
        if want == 1 {
            assert_eq!(va(&a), VaStep::Paused { sel: 0 });
        }
    }
    let f = found(&a);
    assert_eq!((f.account, f.index), (2, 4));
    // an account found is searched by default from now on
    press(&mut a, Key::Enter);
    press(&mut a, Key::Esc);
    verify_scan(&mut a, &addr_of(&w, false, 2, 1, 9));
    press(&mut a, Key::Enter);
    search_until_done(&mut a);
    assert_eq!(found(&a).account, 2);
    // "Stop" leaves
    press(&mut a, Key::Enter);
    press(&mut a, Key::Esc);
    verify_scan(&mut a, &addr_of(&W::other(), false, 0, 0, 0));
    press(&mut a, Key::Enter);
    search_until_done(&mut a);
    press(&mut a, Key::Down);
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    assert!(matches!(
        a.current(),
        Screen::Menu { id, .. } if id == nav::menu_of(To::VerifyAddress)
    ));
}

#[test]
fn verify_refuses_other_networks_scripts_and_non_addresses() {
    let mut a = app();
    // no seed: Verify address explains first
    nav::go(&mut a, To::VerifyAddress);
    assert_eq!(a.current(), Screen::NoSeed);
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    load_abandon(&mut a);
    for (addr, err) in [
        (
            "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
            bp_bitcoin::addrcheck::TargetError::WrongNetwork,
        ),
        (
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            bp_bitcoin::addrcheck::TargetError::Multisig,
        ),
    ] {
        verify_scan(&mut a, addr);
        assert_eq!(va(&a), VaStep::Confirm { sel: 0 });
        assert_eq!(a.verify.as_ref().unwrap().target_error(), Some(err));
        render(&a);
        press(&mut a, Key::Down);
        press(&mut a, Key::Enter); // Enter only closes it
        assert!(matches!(
            a.current(),
            Screen::Menu { id, .. } if id == nav::menu_of(To::VerifyAddress)
        ));
        press(&mut a, Key::Esc);
    }
    // anything else, a seed included, is refused (and not loaded)
    for text in ["hello", ABANDON] {
        verify_scan(&mut a, text);
        assert_eq!(a.current(), Screen::ScanResult);
        assert_eq!(a.scan.outcome, Some(scan::Outcome::NotAnAddress));
        assert!(a.scanned.is_none());
        render(&a);
        press(&mut a, Key::Enter);
        press(&mut a, Key::Esc);
    }
    assert_eq!(a.seed_count(), 1);
}

// ---------- M6: message signing ----------

use crate::msgsign::MsStep;

fn ms(a: &App) -> MsStep {
    match a.current() {
        Screen::MsgSign { step } => step,
        s => panic!("not signing a message: {s:?}"),
    }
}

fn scan_text(a: &mut App, text: &str) {
    nav::go(a, To::Scan(scan::Purpose::Any));
    a.on_qr_text(text.as_bytes());
}

/// Message pages -> address -> confirm -> Sign; returns the signature.
fn approve_message(a: &mut App) -> String {
    while let MsStep::Message { .. } = ms(a) {
        render(a);
        press(a, Key::Enter);
    }
    assert_eq!(ms(a), MsStep::Address);
    render(a);
    press(a, Key::Enter);
    assert_eq!(ms(a), MsStep::Confirm { sel: 0 });
    render(a);
    press(a, Key::Down);
    press(a, Key::Enter);
    assert_eq!(ms(a), MsStep::Done { sel: 0 });
    render(a);
    String::from_utf8(a.signed_psbt().unwrap().to_vec()).unwrap()
}

fn ref_verify(w: &W, path: &str, msg: &str, sig: &str, kind: &str) -> bool {
    let (pk, _) = w.key(path);
    let mut raw = [0u8; 66];
    let n = bp_bitcoin::base64::decode(sig.as_bytes(), &mut raw).unwrap();
    let ms = bitcoin::sign_message::MessageSignature::from_slice(&raw[..n]).unwrap();
    let cpk = CompressedPublicKey(pk);
    let addr = match kind {
        "p2pkh" => Address::p2pkh(cpk, bitcoin::Network::Bitcoin),
        "p2sh" => Address::p2shwpkh(&cpk, bitcoin::Network::Bitcoin),
        _ => Address::p2wpkh(&cpk, bitcoin::Network::Bitcoin),
    };
    let h = bitcoin::sign_message::signed_msg_hash(msg);
    // rust-bitcoin checks P2PKH addresses itself; for SegWit compare the
    // key libsecp256k1 recovers
    match kind {
        "p2pkh" => ms.is_signed_by_address(&w.secp, &addr, h).unwrap(),
        _ => ms.recover_pubkey(&w.secp, h).unwrap().inner == pk,
    }
}

#[test]
fn message_signing_is_off_until_the_device_turns_it_on() {
    let mut a = app();
    load_abandon(&mut a);
    scan_text(&mut a, "signmessage m/84h/0h/0h/0/0 ascii:hello");
    assert_eq!(ms(&a), MsStep::Off);
    render(&a);
    press(&mut a, Key::Enter);
    assert!(back_where_scans_start(&a));
    assert!(a.msg.is_none());
    nav::go(&mut a, To::SignMessage);
    assert_eq!(ms(&a), MsStep::Off);
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    // Settings > Message signing
    nav::go(&mut a, To::Setting(|s| s.msg_signing));
    assert!(a.settings.msg_signing);
}

#[test]
fn signmessage_qr_signs_every_address_type() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    a.settings.msg_signing = true;
    load_abandon(&mut a);
    for (path, kind) in [
        ("m/84'/0'/0'/0/3", "p2wpkh"),
        ("m/49'/0'/0'/1/0", "p2sh"),
        ("m/44'/0'/1'/0/7", "p2pkh"),
    ] {
        let msg = "I control this address. 2026-11-21";
        scan_text(&mut a, &format!("signmessage {path} ascii:{msg}"));
        assert_eq!(ms(&a), MsStep::Message { page: 0 });
        let sig = approve_message(&mut a);
        assert_eq!(sig.len(), 88, "{sig}");
        assert!(ref_verify(&w, path, msg, &sig, kind), "{path}");
        // the signature QR shows the same text
        press(&mut a, Key::Enter);
        assert_eq!(
            a.current(),
            Screen::QrShow {
                kind: QrKind::MessageSig
            }
        );
        render(&a);
        press(&mut a, Key::Esc);
        press(&mut a, Key::Down);
        press(&mut a, Key::Enter);
        assert!(back_where_scans_start(&a));
        assert!(a.msg.is_none(), "wiped");
    }
    // Taproot: BIP-322 simple with the "smp" prefix
    let msg = "Hello World";
    scan_text(
        &mut a,
        &format!("signmessage 73c5da0a/m/86h/0h/0h/0/0 ascii:{msg}"),
    );
    let sig = approve_message(&mut a);
    assert!(sig.starts_with("smp"), "{sig}");
    let addr = addr_of(&w, true, 0, 0, 0);
    assert_eq!(
        bp_bitcoin::bip322::verify_simple(&addr, bp_bitcoin::Network::Mainnet, msg.as_bytes(), &sig),
        Ok(bp_bitcoin::address::ScriptType::Taproot)
    );
}

#[test]
fn long_messages_must_be_read_page_by_page() {
    let mut a = app();
    a.settings.msg_signing = true;
    load_abandon(&mut a);
    let msg = (0..30)
        .map(|i| format!("line {i} of a long statement"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(msg.len() <= 1000);
    scan_text(&mut a, &format!("signmessage m/84h/0h/0h/0/0 ascii:{msg}"));
    let mut pages = 0;
    while let MsStep::Message { page } = ms(&a) {
        assert_eq!(page, pages);
        render(&a);
        pages += 1;
        press(&mut a, Key::Enter);
    }
    assert!(pages >= 4, "{pages}");
    // back from the address goes to the last page
    press(&mut a, Key::Esc);
    assert_eq!(ms(&a), MsStep::Message { page: pages - 1 });
}

#[test]
fn bad_requests_are_refused_with_the_reason() {
    let mut a = app();
    a.settings.msg_signing = true;
    load_abandon(&mut a);
    for text in [
        "signmessage m/84h/1h/0h/0/0 ascii:testnet path",
        "signmessage m/48h/0h/0h/0/0 ascii:multisig path",
        "signmessage m/84h/0h/0h/0/0 ascii:three   spaces",
        "signmessage m/84h/0h/0h/0/0 base64:aGVsbG8=",
        "signmessage deadbeef/m/84h/0h/0h/0/0 ascii:other seed",
    ] {
        scan_text(&mut a, text);
        assert_eq!(ms(&a), MsStep::Problem, "{text}");
        render(&a);
        press(&mut a, Key::Enter);
        assert!(back_where_scans_start(&a));
    }
    // cancel is the default on the final screen
    scan_text(&mut a, "signmessage m/84h/0h/0h/0/0 ascii:hello");
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter);
    assert_eq!(ms(&a), MsStep::Confirm { sel: 0 });
    press(&mut a, Key::Enter);
    assert!(back_where_scans_start(&a));
    assert!(a.signed_psbt().is_none());
}

#[test]
fn typed_message_with_an_address_from_the_explorer() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    a.settings.msg_signing = true;
    load_abandon(&mut a);
    nav::go(&mut a, To::SignMessage);
    assert_eq!(ms(&a), MsStep::Type);
    type_str(&mut a, "a");
    press(&mut a, Key::Enter); // too short: stays, shows the rule
    assert_eq!(ms(&a), MsStep::Type);
    render(&a);
    type_str(&mut a, "bc proof");
    press(&mut a, Key::Enter);
    // one seed: straight to the script types, then the addresses
    assert!(matches!(a.current(), Screen::ScriptSelect { explorer: true, .. }));
    nav::script(&mut a, ScriptType::NativeSegwit);
    press(&mut a, Key::Down);
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter); // receive #2
    assert_eq!(ms(&a), MsStep::Message { page: 0 });
    let sig = approve_message(&mut a);
    assert!(ref_verify(&w, "m/84'/0'/0'/0/2", "abc proof", &sig, "p2wpkh"));
    // from a verified address: S signs a message with it
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    press(&mut a, Key::Esc);
    verify_scan(&mut a, &addr_of(&w, false, 0, 1, 4));
    press(&mut a, Key::Enter);
    search_until_done(&mut a);
    press(&mut a, Key::Char('s'));
    assert_eq!(ms(&a), MsStep::Type);
    type_str(&mut a, "change #4");
    press(&mut a, Key::Enter);
    let sig = approve_message(&mut a);
    assert!(ref_verify(&w, "m/84'/0'/0'/1/4", "change #4", &sig, "p2wpkh"));
}

// ---------- M6: BIP-322 message PSBTs and Proof of Reserves ----------

/// A BIP-322 PSBT as Sparrow builds it for a hardware wallet: to_sign with
/// input 0 spending to_spend of `msg` for `w`'s address at `path`, plus
/// optional real inputs (`extra`: wallet, path, amount) for a Proof of
/// Reserves.
fn bip322_psbt(w: &W, taproot: bool, path: &str, msg: &str, extra: &[(&W, &str, u64)]) -> RefPsbt {
    use bitcoin::psbt::raw::Key as RawKey;
    let (pk, p) = w.key(path);
    let fp = w.master.fingerprint(&w.secp);
    let spk = if taproot {
        ScriptBuf::new_p2tr(&w.secp, pk.x_only_public_key().0, None)
    } else {
        ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash())
    };
    let txid = bp_bitcoin::bip322::to_spend_txid(spk.as_bytes(), msg.as_bytes()).unwrap();
    let mut inputs = vec![TxIn {
        previous_output: OutPoint {
            txid: bitcoin::Txid::from_byte_array(txid),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ZERO,
        witness: Witness::new(),
    }];
    for (n, _) in extra.iter().enumerate() {
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x40 + n as u8; 32]),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        });
    }
    let tx = Transaction {
        version: transaction::Version(0),
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6A]),
        }],
    };
    let mut psbt = RefPsbt::from_unsigned_tx(tx).unwrap();
    psbt.unknown.insert(
        RawKey {
            type_value: 0x09,
            key: vec![],
        },
        msg.as_bytes().to_vec(),
    );
    let mut fill = |i: usize, w: &W, path: &str, amount: u64| {
        let (pk, p) = w.key(path);
        let fp = w.master.fingerprint(&w.secp);
        let inp = &mut psbt.inputs[i];
        inp.sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(1));
        if taproot {
            let x = pk.x_only_public_key().0;
            inp.witness_utxo = Some(TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::new_p2tr(&w.secp, x, None),
            });
            inp.tap_internal_key = Some(x);
            inp.tap_key_origins.insert(x, (vec![], (fp, p)));
        } else {
            inp.witness_utxo = Some(TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash()),
            });
            inp.bip32_derivation.insert(pk, (fp, p));
        }
    };
    let _ = (fp, p);
    fill(0, w, path, 0);
    for (n, (ew, epath, amt)) in extra.iter().enumerate() {
        fill(n + 1, ew, epath, *amt);
    }
    psbt
}

/// The BIP-322 simple signature of input 0 of a signed PSBT.
fn simple_from_signed(raw: &[u8], taproot: bool) -> String {
    let p = RefPsbt::deserialize(raw).unwrap();
    let inp = &p.inputs[0];
    let mut wit = Witness::new();
    if taproot {
        wit.push(inp.tap_key_sig.unwrap().to_vec());
    } else {
        let (pk, sig) = inp.partial_sigs.iter().next().unwrap();
        wit.push(sig.to_vec());
        wit.push(pk.to_bytes());
    }
    let mut out = String::from("smp");
    let ser = bitcoin::consensus::serialize(&wit);
    let mut b = vec![0u8; ser.len() * 2 + 8];
    let n = bp_bitcoin::base64::encode(&ser, &mut b).unwrap();
    out.push_str(std::str::from_utf8(&b[..n]).unwrap());
    out
}

fn sign_message_review(a: &mut App) -> Vec<u8> {
    while let Step::MsgPage { .. } = step(a) {
        render(a);
        press(a, Key::Enter);
    }
    assert_eq!(step(a), Step::MsgAddress);
    render(a);
    press(a, Key::Enter);
    assert_eq!(step(a), Step::Approve { sel: 0 });
    render(a);
    press(a, Key::Up);
    press(a, Key::Enter);
    assert_eq!(
        step(a),
        Step::Signed { sel: 0 },
        "{:?}",
        a.review.as_ref().unwrap().error
    );
    a.signed_psbt().unwrap().to_vec()
}

#[test]
fn bip322_psbts_sign_messages_for_both_address_types() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    a.settings.msg_signing = true;
    load_abandon(&mut a);
    for (taproot, path) in [(false, "m/84'/0'/0'/0/0"), (true, "m/86'/0'/0'/0/1")] {
        let msg = "Hello World";
        scan_psbt(&mut a, &bip322_psbt(&w, taproot, path, msg, &[]));
        assert_eq!(step(&a), Step::MsgPage { page: 0 });
        assert_eq!(a.review_message(), Some(&b"Hello World"[..]));
        let signed = sign_message_review(&mut a);
        let sig = simple_from_signed(&signed, taproot);
        let addr = if taproot {
            addr_of(&w, true, 0, 0, 1)
        } else {
            addr_of(&w, false, 0, 0, 0)
        };
        let st = bp_bitcoin::bip322::verify_simple(&addr, bp_bitcoin::Network::Mainnet, msg.as_bytes(), &sig);
        assert!(st.is_ok(), "{taproot}: {st:?}");
        press(&mut a, Key::Esc); // done: the review ends
        assert!(back_where_scans_start(&a));
    }
    assert!(a.memory.is_empty(), "a message is never remembered as spent");
}

#[test]
fn bip322_psbts_are_refused_when_off_forged_or_against_the_rules() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    let p = bip322_psbt(&w, false, "m/84'/0'/0'/0/0", "Hello World", &[]);
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::MsgOff);
    render(&a);
    press(&mut a, Key::Enter);
    a.settings.msg_signing = true;
    // the message field says one thing, to_spend commits to another
    let mut f = p.clone();
    f.unknown.insert(
        bitcoin::psbt::raw::Key {
            type_value: 0x09,
            key: vec![],
        },
        b"Send me your coins".to_vec(),
    );
    scan_psbt(&mut a, &f);
    assert_eq!(step(&a), Step::Forged);
    assert_eq!(
        a.review.as_ref().unwrap().forgery,
        Some(bp_bitcoin::bip322::Forgery::ToSpendMismatch)
    );
    render(&a);
    for k in [Key::Down, Key::Right, Key::Tab] {
        press(&mut a, k);
        assert_eq!(step(&a), Step::Forged);
    }
    press(&mut a, Key::Enter);
    // the message rules apply here too
    scan_psbt(
        &mut a,
        &bip322_psbt(&w, false, "m/84'/0'/0'/0/0", "three   spaces", &[]),
    );
    assert_eq!(step(&a), Step::MsgRule);
    render(&a);
    press(&mut a, Key::Enter);
    assert!(back_where_scans_start(&a));
}

#[test]
fn proof_of_reserves_needs_every_input_to_be_ours() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    a.settings.msg_signing = true;
    load_abandon(&mut a);
    let msg = "Reserves of 2026-11-21";
    let p = bip322_psbt(
        &w,
        false,
        "m/84'/0'/0'/0/0",
        msg,
        &[(&w, "m/84'/0'/0'/0/1", 50_000), (&w, "m/84'/0'/0'/1/0", 25_000)],
    );
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::MsgPage { page: 0 });
    let r = a.review.as_ref().unwrap();
    assert!(r.message.unwrap().proof_of_reserves);
    let rep = r.report.as_ref().unwrap();
    assert_eq!(rep.totals.ours, 75_000);
    assert!(
        rep.issues().is_empty(),
        "no fee or change checks: {:?}",
        rep.issues()
    );
    let signed = sign_message_review(&mut a);
    let sp = RefPsbt::deserialize(&signed).unwrap();
    assert!(
        sp.inputs.iter().all(|i| i.partial_sigs.len() == 1),
        "every input signed"
    );
    assert!(a.memory.is_empty());
    press(&mut a, Key::Esc);
    // a coin from another wallet cannot be proven
    let p = bip322_psbt(
        &w,
        false,
        "m/84'/0'/0'/0/0",
        msg,
        &[(&W::other(), "m/84'/0'/0'/0/1", 50_000)],
    );
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::Problem);
    assert!(a
        .review
        .as_ref()
        .unwrap()
        .report
        .as_ref()
        .unwrap()
        .has(bp_bitcoin::validate::Issue::ExternalMessageInput));
    render(&a);
}

// ---------- M6: signature verification ----------

use crate::sigverify::SvStep;

fn sv(a: &App) -> SvStep {
    match a.current() {
        Screen::SigVerify { step } => step,
        s => panic!("not verifying a signature: {s:?}"),
    }
}

fn verdict(a: &App) -> crate::sigverify::Verdict {
    a.sig.as_ref().unwrap().verdict.unwrap()
}

fn armored(msg: &str, addr: &str, sig: &str) -> String {
    format!("-----BEGIN BITCOIN SIGNED MESSAGE-----\n{msg}\n-----BEGIN BITCOIN SIGNATURE-----\n{addr}\n{sig}\n-----END BITCOIN SIGNATURE-----\n")
}

#[test]
fn armored_messages_verify_from_the_main_scanner() {
    use bp_bitcoin::message::{CheckError, SigKind};
    let mut a = app();
    // BIP-322 simple (official vector)
    let smp = "smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";
    scan_text(
        &mut a,
        &armored("Hello World", "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", smp),
    );
    assert_eq!(sv(&a), SvStep::Result { sel: 0 });
    assert_eq!(
        verdict(&a),
        Ok((bp_bitcoin::address::ScriptType::NativeSegwit, SigKind::Bip322))
    );
    render(&a);
    press(&mut a, Key::Enter); // no seed: only "Done"
    assert!(back_where_scans_start(&a));
    assert!(a.sig.is_none());
    // a changed message is invalid
    scan_text(
        &mut a,
        &armored("Hello World!", "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", smp),
    );
    assert_eq!(verdict(&a), Err(CheckError::Invalid));
    render(&a);
    press(&mut a, Key::Enter);
    // Coldcard's BIP-137 header on another address type: valid, with a warning
    a.settings.network = bp_bitcoin::Network::Testnet;
    let sig = "J3jE1G2pv+6GG35Unak824xig8GzotLE8pFfvNwlgGU7KebANAxo7RuwybCNXrK9+RvjUEohtffM521N+phQNX0=";
    scan_text(
        &mut a,
        &armored("aaaaaaaaaaaaaaaaaa", "mwhrUneshkXh8yUw2L2T16UYCoF3ouy4L2", sig),
    );
    assert!(matches!(
        verdict(&a),
        Ok((
            _,
            SigKind::Legacy {
                header_matches: false,
                bip137: true
            }
        ))
    ));
    render(&a);
}

#[test]
fn verify_signature_step_by_step_then_check_the_address() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    a.settings.msg_signing = true;
    load_abandon(&mut a);
    // sign on the device first
    scan_text(&mut a, "signmessage m/84h/0h/0h/0/5 ascii:proof of address");
    let sig = approve_message(&mut a);
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    // Tools > Verify signature: address, message, signature
    nav::go(&mut a, To::VerifySignature);
    assert_eq!(
        a.current(),
        Screen::Scan {
            purpose: scan::Purpose::Signed
        }
    );
    a.on_qr_text(addr_of(&w, false, 0, 0, 5).as_bytes());
    assert_eq!(sv(&a), SvStep::Type);
    type_str(&mut a, "proof of address");
    render(&a);
    press(&mut a, Key::Enter);
    assert_eq!(
        a.current(),
        Screen::Scan {
            purpose: scan::Purpose::SigText
        }
    );
    a.on_qr_text(sig.as_bytes());
    assert_eq!(sv(&a), SvStep::Result { sel: 0 });
    assert!(verdict(&a).is_ok());
    render(&a);
    // "is this address mine?" continues with Verify address
    press(&mut a, Key::Enter);
    assert!(matches!(a.current(), Screen::VerifyAddr { .. }));
    press(&mut a, Key::Enter);
    search_until_done(&mut a);
    assert_eq!(found(&a).index, 5);
    // a seed QR given as the signature is not loaded
    press(&mut a, Key::Enter);
    nav::go(&mut a, To::VerifySignature);
    a.on_qr_text(addr_of(&w, false, 0, 0, 5).as_bytes());
    type_str(&mut a, "x");
    press(&mut a, Key::Enter);
    a.on_qr_text(ABANDON.as_bytes());
    assert_eq!(verdict(&a), Err(bp_bitcoin::message::CheckError::Encoding));
    assert!(a.scanned.is_none());
    assert_eq!(a.seed_count(), 1);
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    // something else entirely
    nav::go(&mut a, To::VerifySignature);
    a.on_qr_text(b"hello");
    assert_eq!(a.scan.outcome, Some(scan::Outcome::NotSigned));
    render(&a);
}

// ---------- M6: fee settings and SettingsQR ----------

#[test]
fn fee_settings_change_the_review() {
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    // a 15% fee is refused by default (limit 10%)
    let p = psbt(
        &w,
        &[(0, 100_000, true)],
        &[
            (W::other().wpkh("m/84'/0'/0'/0/5"), 50_000, None),
            (w.wpkh("m/84'/0'/0'/1/0"), 37_000, Some(0)),
        ],
    );
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::Problem);
    press(&mut a, Key::Enter);
    // Settings > Fee limit: 25%
    nav::go(&mut a, To::Setting(|s| s.fee_block_label));
    assert_eq!(a.settings.fee_block, 1);
    assert_eq!(a.settings.policy().fee_block_percent, 25);
    press(&mut a, Key::Esc);
    scan_psbt(&mut a, &p);
    assert_eq!(step(&a), Step::Warning { idx: 0, sel: 0 });
    let r = a.review.as_ref().unwrap().report.as_ref().unwrap();
    assert!(r.has(bp_bitcoin::validate::Issue::HighFee) && !r.has(bp_bitcoin::validate::Issue::FeeTooHigh));
    render(&a);
    // the warning text names the setting's threshold
    let t: bp_ui::fmt::Buf<128> = bp_ui::fmt::fill(text::EN.rv.issues[33].1, &[&2u64, &25u64, &1000u64]);
    assert_eq!(t.as_str(), "The fee is 2% or more of the outputs.");
}

#[test]
fn settings_qr_exports_and_imports_without_weakening() {
    let mut a = app();
    a.settings.lang = settings::Lang::Ko;
    a.settings.fee_rate = 0;
    // Settings > Settings as QR
    nav::go(&mut a, To::SettingsQr);
    assert_eq!(
        a.current(),
        Screen::QrShow {
            kind: QrKind::Settings
        }
    );
    render(&a);
    let mut b = [0u8; 256];
    let n = a.settings.to_qr(&mut b);
    assert_eq!(qr_text_of(&a), std::str::from_utf8(&b[..n]).unwrap());
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    // after a power cycle the QR restores the harmless settings
    let exported = std::str::from_utf8(&b[..n])
        .unwrap()
        .replace("msg_signing=0", "msg_signing=1");
    let mut a = app();
    scan_text(&mut a, &exported);
    assert_eq!(a.current(), Screen::SettingsImport { sel: 0 });
    render(&a);
    press(&mut a, Key::Enter); // Cancel is the default
    assert_eq!(a.settings.lang, settings::Lang::En);
    scan_text(&mut a, &exported);
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    assert_eq!(a.settings.lang, settings::Lang::Ko);
    assert_eq!(a.settings.fee_rate, 0, "a stricter fee rate warning applies");
    assert!(
        !a.settings.msg_signing,
        "message signing is never turned on by a QR"
    );
    // invalid settings
    scan_text(&mut a, "bitpunk-settings::v1 colour=red");
    assert_eq!(a.current(), Screen::SettingsImport { sel: 0 });
    assert!(matches!(a.import, Some(Err(_))));
    render(&a);
    press(&mut a, Key::Enter);
    assert!(back_where_scans_start(&a));
}

fn qr_text_of(a: &App) -> String {
    let q = a.qr.as_ref().unwrap();
    String::from_utf8(q.payload().to_vec()).unwrap()
}

#[path = "tests_layout.rs"]
mod layout;

#[path = "tests_wallets.rs"]
mod wallets_flow;

#[path = "tests_sd.rs"]
mod sd_flow;

#[path = "tests_b85.rs"]
mod b85_flow;

#[path = "tests_keys.rs"]
mod keys_flow;

#[path = "tests_vault.rs"]
mod vault_flow;

#[path = "tests_slip39.rs"]
mod slip39_flow;

#[path = "tests_seedxor.rs"]
mod seedxor_flow;

#[path = "tests_metal.rs"]
mod metal_flow;

/// A BIP-85 result recorded from embit (see tools/gen_embit_bip85.py).
pub(crate) fn b85_embit(app: &str, index: u32) -> String {
    let src = include_str!("../../bp-bitcoin/tests/data/embit_bip85.rs");
    let prefix = format!("(App::{app}, {index}, \"");
    let line = src
        .lines()
        .find(|l| l.trim_start().starts_with(&prefix))
        .expect("vector");
    let rest = &line.trim_start()[prefix.len()..];
    String::from(&rest[..rest.find('"').unwrap()])
}

/// Every screen kind and flow step is drawn by the screen tests (M9-0).
#[test]
fn every_screen_and_step_is_drawn() {
    crate::coverage::start();
    crate::tests::every_screen_renders_without_panicking();
    crate::tests::m2_screens_render();
    crate::tests::qr_screens_render();
    crate::tests::scan_screens_render();
    layout::every_screen_fits_in_every_language();
    sd_flow::sd_screens_fit();
    sd_flow::sd_signing_screens_fit();
    sd_flow::sd_export_screens_fit();
    b85_flow::b85_screens_fit();
    keys_flow::key_screens_fit();
    keys_flow::a_network_chip_locks_the_device();
    vault_flow::vault_screens_fit();
    slip39_flow::slip39_screens_fit();
    seedxor_flow::seedxor_screens_fit();
    metal_flow::metal_screens_fit();
    let seen = crate::coverage::finish();
    let all = crate::coverage::all();
    let missing: std::vec::Vec<_> = all.iter().filter(|k| !seen.contains(*k)).collect();
    let unknown: std::vec::Vec<_> = seen.iter().filter(|k| !all.contains(k)).collect();
    assert!(unknown.is_empty(), "drawn but not listed: {unknown:?}");
    assert!(
        missing.is_empty(),
        "{} of {} never drawn: {missing:?}",
        missing.len(),
        all.len()
    );
}

// ---------- M8 output baseline (M9-0) ----------
//
// Every output the device produces — QR payloads and frames, files written to
// the card, signatures, addresses, BIP-85 results, wallet codes — recorded
// from the M8 build in `golden/m8-outputs.txt`. M9 changes screens, never
// outputs, so this must match byte for byte. Re-record only for an intended
// output change, and say so in the commit:
//   BP_BLESS=1 cargo test -p bp-app outputs_match_the_m8_baseline

/// Bytes as escaped text when printable, else hex.
pub(super) fn show(b: &[u8]) -> String {
    let printable = b
        .iter()
        .all(|&c| (0x20..0x7f).contains(&c) || matches!(c, b'\n' | b'\r' | b'\t'));
    if printable {
        String::from_utf8(b.to_vec())
            .unwrap()
            .replace('\\', "\\\\")
            .replace('\r', "\\r")
            .replace('\n', "\\n")
            .replace('\t', "\\t")
    } else {
        let mut s = String::from("hex:");
        for x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }
}

/// One `key = value` line.
pub(super) fn rec(out: &mut String, key: &str, b: &[u8]) {
    out.push_str(key);
    out.push_str(" = ");
    out.push_str(&show(b));
    out.push('\n');
}

/// A QR export: payload, frame count and first frame, then close it.
pub(super) fn rec_qr(out: &mut String, key: &str, a: &mut App, kind: QrKind) {
    a.open_qr(kind);
    assert!(
        matches!(a.current(), Screen::QrShow { .. }),
        "{key}: {:?}",
        a.current()
    );
    let q = a.qr.as_ref().unwrap_or_else(|| panic!("{key}: no QR"));
    rec(out, &format!("{key}.payload"), q.payload());
    rec(out, &format!("{key}.frames"), q.frames().to_string().as_bytes());
    let mut t = [0u8; qrview::TEXT_MAX];
    let n = q.text(&mut t);
    rec(out, &format!("{key}.frame0"), &t[..n]);
    press(a, Key::Esc);
}

fn golden_core(out: &mut String) {
    let mut a = app();
    a.settings.advanced = true;
    load_abandon(&mut a);
    let fp = a.slot(0).unwrap().fingerprint;
    rec(
        out,
        "abandon.fingerprint",
        crate::seeds::fingerprint_hex(&fp).as_str().as_bytes(),
    );
    // xpubs in every format, and addresses, for every script type
    for net in [bp_bitcoin::Network::Mainnet, bp_bitcoin::Network::Testnet] {
        a.settings.network = net;
        for st in a.visible_scripts().to_vec() {
            for format in XpubFormat::ALL {
                for account in [0, 1] {
                    rec_qr(
                        out,
                        &format!("abandon.{net:?}.xpub.{st:?}.{format:?}.{account}"),
                        &mut a,
                        QrKind::Xpub {
                            slot: 0,
                            st,
                            account,
                            format,
                        },
                    );
                }
            }
            for change in [false, true] {
                for index in [0u32, 1, 2, 999] {
                    let mut o = [0u8; bp_bitcoin::address::MAX_ADDRESS_LEN];
                    let n = a
                        .slot(0)
                        .unwrap()
                        .address(st, net, 0, change, index, &mut o)
                        .unwrap();
                    rec(
                        out,
                        &format!("abandon.{net:?}.addr.{st:?}.{change}.{index}"),
                        &o[..n],
                    );
                }
            }
        }
    }
    a.settings.network = bp_bitcoin::Network::Mainnet;
    for compact in [false, true] {
        rec_qr(
            out,
            &format!("abandon.seedqr.{compact}"),
            &mut a,
            QrKind::SeedQr { slot: 0, compact },
        );
    }
    for script in [
        bp_bitcoin::multisig::MsScript::Wsh,
        bp_bitcoin::multisig::MsScript::ShWsh,
    ] {
        for format in crate::wallets::KeyFormat::ALL {
            rec_qr(
                out,
                &format!("abandon.mskey.{script:?}.{format:?}"),
                &mut a,
                QrKind::MsKey {
                    slot: 0,
                    script,
                    account: 0,
                    format,
                },
            );
        }
    }
    // settings: defaults, then every value changed
    rec_qr(out, "settings.default", &mut a, QrKind::Settings);
    a.settings.lang = settings::Lang::Ko;
    a.settings.fee_rate = 0;
    a.settings.fee_block = 2;
    a.settings.msg_signing = true;
    rec_qr(out, "settings.changed", &mut a, QrKind::Settings);
    // a passphrase changes the wallet
    let m = a.slot(0).unwrap().mnemonic.clone().unwrap();
    a.seeds[1] = crate::seeds::SeedSlot::new(m, b"TREZOR");
    let fp = a.slot(1).unwrap().fingerprint;
    rec(
        out,
        "abandon+TREZOR.fingerprint",
        crate::seeds::fingerprint_hex(&fp).as_str().as_bytes(),
    );
    rec_qr(
        out,
        "abandon+TREZOR.xpub",
        &mut a,
        QrKind::Xpub {
            slot: 1,
            st: ScriptType::NativeSegwit,
            account: 0,
            format: XpubFormat::StaticText,
        },
    );

    // a signed PSBT in every QR format
    let (mut a, _) = signed_app();
    let len = a.review.as_ref().unwrap().signed.unwrap().len;
    rec(out, "psbt.signed", &a.scan.work()[..len]);
    for format in [PsbtFormat::Ur, PsbtFormat::Bbqr, PsbtFormat::Specter] {
        rec_qr(
            out,
            &format!("psbt.signed.{format:?}"),
            &mut a,
            QrKind::SignedPsbt { format },
        );
    }

    // message signatures for every address type, and the signature QR
    let mut a = app();
    a.settings.msg_signing = true;
    load_abandon(&mut a);
    for path in [
        "m/84'/0'/0'/0/3",
        "m/49'/0'/0'/1/0",
        "m/44'/0'/1'/0/7",
        "73c5da0a/m/86h/0h/0h/0/0",
    ] {
        scan_text(&mut a, &format!("signmessage {path} ascii:Golden message 1"));
        let sig = approve_message(&mut a);
        rec(out, &format!("message.{path}"), sig.as_bytes());
        rec_qr(out, &format!("message.{path}.qr"), &mut a, QrKind::MessageSig);
        while !matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }) {
            press(&mut a, Key::Esc);
        }
    }
}

#[test]
fn outputs_match_the_m8_baseline() {
    let mut out = String::new();
    golden_core(&mut out);
    sd_flow::golden(&mut out);
    wallets_flow::golden(&mut out);
    b85_flow::golden(&mut out);
    keys_flow::golden(&mut out);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("golden/m8-outputs.txt");
    if std::env::var_os("BP_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &out).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).expect("golden file (BP_BLESS=1 to record)");
    for (i, (got, want)) in out.lines().zip(want.lines()).enumerate() {
        assert_eq!(got, want, "output line {} differs from the M8 baseline", i + 1);
    }
    assert_eq!(
        out.lines().count(),
        want.lines().count(),
        "number of outputs differs"
    );
}

/// Print the sizes the resource budget checks (M9-0):
/// cargo test -p bp-app resource_budget -- --nocapture
#[test]
fn resource_budget() {
    let app = core::mem::size_of::<App>();
    let fonts: usize = [
        &bp_ui::font::SMALL,
        &bp_ui::font::BODY,
        &bp_ui::font::TITLE,
        &bp_ui::font::HUGE,
        &bp_ui::font::DOUBLE,
    ]
    .iter()
    .map(|f| f.data.len() + f.wide.map_or(0, |w| w.data.len()))
    .sum();
    std::println!("App {app} bytes, fonts {fonts} bytes");
    // M8 end: App 485 KB, fonts 417 KB. Effects and new screens must not grow RAM much.
    assert!(app <= 560 * 1024, "App is {app} bytes (budget 560 KB)");
    assert!(fonts <= 1024 * 1024, "fonts are {fonts} bytes (budget 1 MB)");
}

/// UX language (M9): screens take every colour from `bp_ui::theme`. A
/// colour value written anywhere else must say why on its line
/// (`// palette: ...`), e.g. the camera picture.
#[test]
fn screens_use_theme_colours_only() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut bad = Vec::new();
    for dir in [
        root.join("src"),
        root.join("../bp-ui/src"),
        root.join("../bp-ui/src/font"),
    ] {
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".rs") || name.starts_with("tests") || name == "theme.rs" || name == "bench.rs"
            {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            // test modules at the end of a file may build colours freely
            let body = src.split("#[cfg(test)]\nmod tests").next().unwrap();
            for (i, line) in body.lines().enumerate() {
                let colour = line.contains("Rgb(") || line.contains("Rgb::hex(");
                if colour && !line.contains("palette:") && !line.trim_start().starts_with("//") {
                    bad.push(format!("{name}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }
    assert!(bad.is_empty(), "colours outside the theme:\n{}", bad.join("\n"));
}

/// M9-2: with the strongest screen effects, every QR code on screen still
/// reads back with our own scanner (effects skip the QR box), and the
/// effects setting stays on the device (not in the settings QR).
#[test]
fn qr_codes_read_through_screen_effects() {
    struct Rgba {
        px: Vec<u8>,
    }
    impl bp_hal::Canvas for Rgba {
        fn width(&self) -> u16 {
            800
        }
        fn height(&self) -> u16 {
            480
        }
        fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, c: bp_hal::Rgb) {
            for yy in y.max(0)..(y + h).min(480) {
                for xx in x.max(0)..(x + w).min(800) {
                    let i = (yy * 800 + xx) as usize * 3;
                    self.px[i..i + 3].copy_from_slice(&[c.0, c.1, c.2]);
                }
            }
        }
        fn blend_pixel(&mut self, x: i32, y: i32, c: bp_hal::Rgb, a: u8) {
            if !(0..800).contains(&x) || !(0..480).contains(&y) {
                return;
            }
            let i = (y * 800 + x) as usize * 3;
            for (k, v) in [c.0, c.1, c.2].into_iter().enumerate() {
                let d = self.px[i + k] as u16;
                self.px[i + k] = ((v as u16 * a as u16 + d * (255 - a as u16) + 127) / 255) as u8;
            }
        }
    }
    let mut a = app();
    a.settings.advanced = true;
    load_abandon(&mut a);
    a.settings.fx = bp_ui::fx::Fx::Full;
    let kinds = [
        QrKind::Settings,
        QrKind::SeedQr {
            slot: 0,
            compact: false,
        },
        QrKind::Xpub {
            slot: 0,
            st: ScriptType::NativeSegwit,
            account: 0,
            format: XpubFormat::StaticText,
        },
        QrKind::Xpub {
            slot: 0,
            st: ScriptType::Taproot,
            account: 0,
            format: XpubFormat::UrAccount,
        },
    ];
    for kind in kinds {
        a.open_qr(kind);
        for fullscreen in [false, true] {
            a.qr.as_mut().unwrap().fullscreen = fullscreen;
            let mut b = Rgba {
                px: vec![0; 800 * 480 * 3],
            };
            let mut fx = bp_ui::fx::FxCanvas::new(&mut b, a.settings.fx);
            a.render(&mut fx);
            let keep = a.qr_area();
            assert!(keep.is_some(), "{kind:?}: QR area recorded");
            fx.finish(keep);
            let gray: Vec<u8> =
                b.px.chunks(3)
                    .map(|p| ((p[0] as u16 * 77 + p[1] as u16 * 150 + p[2] as u16 * 29) >> 8) as u8)
                    .collect();
            let img = bp_qr::scan::Image::new(&gray, 800, 480).unwrap();
            let mut out = vec![0u8; 4096];
            let found = bp_qr::scan::Scanner::default()
                .scan(img, &mut out)
                .unwrap_or_else(|| panic!("{kind:?} fullscreen={fullscreen}: not read"));
            let mut t = [0u8; qrview::TEXT_MAX];
            let n = a.qr.as_ref().unwrap().text(&mut t);
            assert_eq!(&out[..found.decoded.len], &t[..n], "{kind:?}");
        }
        // Esc leaves full screen first, then the QR
        while matches!(a.current(), Screen::QrShow { .. }) {
            press(&mut a, Key::Esc);
        }
    }
    // not a QR screen: nothing to keep
    let mut b = Rgba {
        px: vec![0; 800 * 480 * 3],
    };
    a.render(&mut b);
    assert_eq!(a.qr_area(), None);
    // the setting cycles on the device and never goes into the settings QR
    let mut q1 = [0u8; 256];
    let n1 = a.settings.to_qr(&mut q1);
    nav::go(&mut a, To::Setting(|s| s.fx_label));
    assert_eq!(a.settings.fx, bp_ui::fx::Fx::Reduced);
    let mut q2 = [0u8; 256];
    let n2 = a.settings.to_qr(&mut q2);
    assert_eq!(&q1[..n1], &q2[..n2]);
}

/// M9 (C8): every error code with its English and Korean message, kept in
/// docs/ERROR_CODES.md for the user guide (M15). Re-record after changing
/// a message table: BP_BLESS=1 cargo test -p bp-app error_codes_are_documented
#[test]
fn error_codes_are_documented() {
    use crate::errors::{code, Area};
    fn table(s: &'static text::Strings, area: Area) -> Vec<&'static str> {
        match area {
            Area::Card => s.sd.problems.iter().map(|p| p[0]).collect(),
            Area::Save => s.sd.save_problems.to_vec(),
            Area::Tx => s.rv.issues.iter().map(|i| i.0).collect(),
            Area::Sign => s.rv.sign_errors.to_vec(),
            Area::Wallet => s.wl.rejects.to_vec(),
            Area::Key => s.key.problems.to_vec(),
            Area::Msg => s.ms_problems.to_vec(),
            Area::Addr => s.va_errors.to_vec(),
            Area::Sig => s.sv_reasons.to_vec(),
            Area::Settings => s.si_errors.to_vec(),
            Area::Hw => std::vec![s.key.comm_title],
            Area::Vault => s.vault.problems.to_vec(),
        }
    }
    let mut out = String::from(
        "# 오류 코드 (Error codes)\n\n\
         <!-- generated by the test error_codes_are_documented; do not edit by hand -->\n\n\
         거부·실패 화면은 키 막대 오른쪽에 `E-영역-번호` 코드를 보여 준다 (UX 언어 C8). \
         번호는 그 영역 메시지 표의 순서이며, M15 사용 가이드의 문제 해결 장이 이 목록을 쓴다. \
         `{}`는 화면에서 실제 값으로 바뀐다.\n",
    );
    for area in Area::ALL {
        let (en, ko) = (table(&text::EN, area), table(&text::KO, area));
        assert_eq!(en.len(), ko.len(), "{area:?}: both languages");
        out.push_str(&format!(
            "\n## {}\n\n| 코드 | English | 한국어 |\n|---|---|---|\n",
            area.tag()
        ));
        for (i, (e, k)) in en.iter().zip(ko.iter()).enumerate() {
            let cell = |t: &str| t.replace('|', "\\|").replace('\n', " ");
            out.push_str(&format!(
                "| `{}` | {} | {} |\n",
                code(area, i).as_str(),
                cell(e),
                cell(k)
            ));
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ERROR_CODES.md");
    if std::env::var_os("BP_BLESS").is_some() {
        std::fs::write(&path, &out).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).expect("docs/ERROR_CODES.md (BP_BLESS=1 to record)");
    assert_eq!(out, want, "error codes changed: re-record docs/ERROR_CODES.md");
}

/// M9 (C8): refusal screens show their code.
#[test]
fn refusal_screens_show_their_error_code() {
    // a forged change output: an attack, first in the list
    let w = W::from_phrase(ABANDON);
    let mut a = app();
    load_abandon(&mut a);
    let p = psbt(
        &w,
        &[(0, 100_000, false)],
        &[
            (W::other().wpkh("m/84'/0'/0'/0/5"), 50_000, None),
            (w.wpkh("m/84'/0'/0'/1/0"), 9_000, Some(0)),
        ],
    );
    scan_psbt(&mut a, &p);
    render(&a);
    assert_eq!(step(&a), Step::Problem);
    let code = a.shown_error().expect("a code on the problem screen");
    assert!(code.as_str().starts_with("E-TX-"), "{}", code.as_str());
    // a settings QR that cannot be read
    nav::home(&mut a);
    scan_text(&mut a, "bitpunk-settings::v1 colour=red");
    render(&a);
    assert!(a.shown_error().unwrap().as_str().starts_with("E-SET-"));
    // screens without an error show none
    nav::home(&mut a);
    render(&a);
    assert!(a.shown_error().is_none());
}

/// Flows started from the scanner or message signing end back on the menu
/// that holds them (M9-4: Sign; it was the main menu before).
fn back_where_scans_start(a: &App) -> bool {
    matches!(a.current(), Screen::Menu { id, .. } if id == nav::menu_of(To::Scan(scan::Purpose::Any)))
}

/// M9 C10: BTC amounts group their eight decimals (0.01 234 567) so the
/// sats can be read off them; sats keep the thousands commas. The review
/// headline also shows the other unit, which is the same number of sats.
#[test]
fn amounts_group_the_sats_in_btc() {
    use crate::review_view::{amount, other_unit};
    use crate::settings::Units::{Btc, Sats};
    let cases: &[(u64, &str, &str)] = &[
        (0, "0 sats", "0.00 000 000 BTC"),
        (1, "1 sats", "0.00 000 001 BTC"),
        (60_000, "60,000 sats", "0.00 060 000 BTC"),
        (1_234_567, "1,234,567 sats", "0.01 234 567 BTC"),
        (123_456_789, "123,456,789 sats", "1.23 456 789 BTC"),
        (
            2_100_000_000_000_000,
            "2,100,000,000,000,000 sats",
            "21,000,000.00 000 000 BTC",
        ),
    ];
    for &(v, sats, btc) in cases {
        assert_eq!(amount(v, Sats).as_str(), sats);
        assert_eq!(amount(v, Btc).as_str(), btc);
        // the BTC digits, separators removed, are the sats
        let digits: std::string::String = btc.chars().filter(|c| c.is_ascii_digit()).collect();
        assert_eq!(digits.parse::<u64>().unwrap(), v);
        assert_eq!(other_unit(v, Sats).as_str(), std::format!("= {btc}"));
        assert_eq!(other_unit(v, Btc).as_str(), std::format!("= {sats}"));
    }
    // the largest amount still fits the double-size headline
    let widest = amount(2_100_000_000_000_000, Sats);
    assert!(bp_ui::font::DOUBLE.text_width(widest.as_str()) <= 800 - 2 * 16);
}

#[test]
fn task_psbt_qr() {
    for (name, shortcut) in [("psbt-qr", false), ("psbt-qr-fn-q", true)] {
        let w = W::from_phrase(ABANDON);
        let mut a = app();
        load_abandon(&mut a);
        nav::home(&mut a);
        crate::taskcount::start(&a.current());
        if shortcut {
            press(&mut a, Key::Qr);
            a.on_qr_text(b64(&standard(&w).serialize()).as_bytes());
        } else {
            scan_psbt(&mut a, &standard(&w));
        }
        for _ in 0..4 {
            press(&mut a, Key::Enter);
        }
        press(&mut a, Key::Down);
        press(&mut a, Key::Enter); // sign
        press(&mut a, Key::Enter); // show QR (UR)
        assert!(matches!(a.current(), Screen::QrShow { .. }));
        super::tests::task_done(name, &a);
    }
}

/// M9-10: the feature inventory has no duplicate numbers, every test it
/// names exists, and the simulator's checklist lists exactly its features.
#[test]
fn feature_inventory_and_checklist_agree() {
    use std::collections::BTreeSet;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inv = std::fs::read_to_string(root.join("docs/FEATURE_INVENTORY.md")).unwrap();
    let mut ids = BTreeSet::new();
    let mut named = Vec::new();
    for line in inv.lines().filter(|l| l.starts_with("| F-")) {
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        assert!(ids.insert(cols[1].to_string()), "{} is listed twice", cols[1]);
        for t in cols[4].split(',').map(str::trim) {
            let ident = t
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
            if ident && t.contains('_') {
                named.push(t.to_string());
            }
        }
    }
    // every named test is a function somewhere in the crates
    let mut sources = String::new();
    let mut stack = vec![root.join("crates")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                if !p.ends_with("target") {
                    stack.push(p);
                }
            } else if p.extension().is_some_and(|x| x == "rs") {
                sources.push_str(&std::fs::read_to_string(&p).unwrap());
            }
        }
    }
    let missing: Vec<&String> = named
        .iter()
        .filter(|t| !sources.contains(&format!("fn {t}(")))
        .collect();
    assert!(
        missing.is_empty(),
        "the inventory names tests that do not exist: {missing:?}"
    );
    // the checklist in the simulator page
    let list = std::fs::read_to_string(root.join("sim/web/checklist.json")).unwrap();
    let listed: BTreeSet<String> = list
        .match_indices("\"id\": \"")
        .map(|(i, m)| list[i + m.len()..i + m.len() + 5].to_string())
        .collect();
    assert_eq!(
        listed.len(),
        list.matches("\"id\": \"").count(),
        "a checklist id repeats"
    );
    assert_eq!(
        listed, ids,
        "the checklist and the inventory list different features"
    );
}
