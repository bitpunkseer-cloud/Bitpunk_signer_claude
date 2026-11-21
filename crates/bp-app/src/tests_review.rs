//! PSBT review and signing flows, driven by key events. PSBTs are built
//! with rust-bitcoin (test-only) for the "abandon ... about" seed.

use super::*;
extern crate std;
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
    press(a, Key::Char('2'));
    press(a, Key::Char('2'));
    press(a, Key::Char('1'));
    press(a, Key::Char('1'));
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
    press(a, Key::Char('1')); // Main > Scan QR
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
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
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
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
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
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
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
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
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
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
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
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
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
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
    assert!(a.qr.is_none() && a.review.is_none());
    let _ = p;
}
