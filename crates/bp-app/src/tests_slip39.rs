//! SLIP-39 screens (M11-2): opening a wallet from shares, making one from
//! dice, another set of a loaded one, and every step drawn in both
//! languages.

extern crate std;

use super::*;
use crate::keys::SlotOpt;
use crate::nav::{self, To};
use crate::slip39ui::{SlStep, CHECKS, MIN_DICE};
use bp_backup::slip39::{self, Added, Error};
use bp_hal::input::Key;
use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

const VECTORS: &str = include_str!("../../bp-backup/tests/data/slip39_vectors.txt");

fn app() -> App {
    let mut a = App::new(b"test quiz seed");
    a.tick(SPLASH_MS);
    nav::home(&mut a);
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

/// Shares and xprv of published vector `n` ("## n. ...").
fn vector(n: usize) -> (Vec<String>, String) {
    let block = VECTORS
        .split("\n## ")
        .find(|b| b.starts_with(&format!("{n}. ")))
        .unwrap();
    let shares = block
        .lines()
        .filter_map(|l| l.strip_prefix("share "))
        .map(String::from)
        .collect();
    let xprv = block
        .lines()
        .find_map(|l| l.strip_prefix("xprv "))
        .unwrap()
        .to_string();
    (shares, xprv)
}

fn fp_of_xprv(x: &str) -> [u8; 4] {
    bp_bitcoin::bip32::Xpriv::decode(x).unwrap().0.fingerprint()
}

fn step(a: &App) -> SlStep {
    match a.current() {
        Screen::Slip39 { step } => step,
        s => panic!("not a SLIP-39 screen: {s:?}"),
    }
}

/// Type a whole share, word by word (four letters choose a word).
fn type_share(a: &mut App, share: &str) {
    for w in share.split(' ') {
        type_str(a, w);
    }
}

/// Load > SLIP-39 shares, `words` per share.
fn open_load(a: &mut App, words33: bool) {
    nav::go(a, To::Slip39Load);
    assert_eq!(step(a), SlStep::Length { sel: 0 });
    press(a, Key::Char(if words33 { '2' } else { '1' }));
    assert_eq!(step(a), SlStep::Words);
}

/// Let the screen saver come on (one minute without keys).
fn saver(a: &mut App) {
    for _ in 0..13 {
        a.tick(5_000);
    }
}

/// Esc, then "discard": leave a flow.
fn discard(a: &mut App) {
    press(a, Key::Esc);
    assert!(matches!(a.current(), Screen::Confirm { .. }), "{:?}", a.current());
    press(a, Key::Char('2'));
}

fn last(a: &App) -> Option<Result<Added, Error>> {
    a.slip.as_ref().unwrap().last
}

/// Type `shares`, then `passphrase`, then load: the slot it went to.
fn open_wallet(a: &mut App, shares: &[&str], passphrase: &str) -> u8 {
    open_load(a, shares[0].split(' ').count() == 33);
    for (i, sh) in shares.iter().enumerate() {
        if i > 0 {
            press(a, Key::Enter); // next share
        }
        type_share(a, sh);
        assert_eq!(step(a), SlStep::Status, "share {i}");
        assert_eq!(last(a), Some(Ok(Added::Accepted)), "share {i}");
    }
    assert!(a.slip.as_ref().unwrap().rec.is_complete());
    press(a, Key::Enter);
    assert_eq!(step(a), SlStep::Passphrase);
    type_str(a, passphrase);
    press(a, Key::Enter);
    assert_eq!(step(a), SlStep::Ready { sel: 0 });
    press(a, Key::Enter);
    match a.current() {
        Screen::SeedReady { slot, created: false } => slot,
        s => panic!("{s:?}"),
    }
}

#[test]
fn published_shares_open_their_wallet() {
    for n in [4, 23] {
        // 2 of 3, 128 and 256 bits, passphrase TREZOR
        let (shares, xprv) = vector(n);
        let mut a = app();
        let picks: Vec<&str> = shares.iter().map(|s| s.as_str()).collect();
        let slot = open_wallet(&mut a, &picks, "TREZOR");
        let s = a.slot(slot as usize).unwrap();
        assert_eq!(s.kind, crate::seeds::SlotKind::Slip39);
        assert_eq!(s.fingerprint, fp_of_xprv(&xprv), "vector {n}");
        assert!(s.has_passphrase());
        assert!(a.slip.is_none(), "the screens' state is wiped");
        // its options: no words or SeedQR, but xpub, passphrase, shares
        assert_eq!(
            crate::keys::slot_opts(s.kind),
            [
                SlotOpt::Xpub,
                SlotOpt::Explorer,
                SlotOpt::Passphrase,
                SlotOpt::Slip39Shares,
                SlotOpt::Discard
            ]
        );
    }
}

#[test]
fn the_passphrase_can_be_set_later_like_seed_words() {
    let (shares, xprv) = vector(4);
    let mut a = app();
    let picks: Vec<&str> = shares.iter().map(|s| s.as_str()).collect();
    let slot = open_wallet(&mut a, &picks, "");
    assert_ne!(a.slot(slot as usize).unwrap().fingerprint, fp_of_xprv(&xprv));
    press(&mut a, Key::Enter); // SeedReady -> options
    nav::seed_opt(&mut a, SlotOpt::Passphrase);
    type_str(&mut a, "TREZOR");
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter); // apply
    assert_eq!(a.slot(slot as usize).unwrap().fingerprint, fp_of_xprv(&xprv));
    assert!(matches!(a.current(), Screen::SeedOptions { sel: 2, .. }));
}

#[test]
fn typos_other_sets_and_repeats_are_reported() {
    let (shares, xprv) = vector(4);
    let (others, _) = vector(43); // extendable 2-of-3, another set
    let mut a = app();
    open_load(&mut a, false);
    // a typo: the checksum fails; pick the word and type it again
    let mut words: Vec<&str> = shares[0].split(' ').collect();
    let right = words[5];
    words[5] = if right == "academic" { "acid" } else { "academic" };
    type_share(&mut a, &words.join(" "));
    assert_eq!(step(&a), SlStep::Fix { sel: 0 });
    for _ in 0..5 {
        press(&mut a, Key::Down);
    }
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), SlStep::Words);
    type_str(&mut a, right);
    assert_eq!(step(&a), SlStep::Status);
    assert_eq!(last(&a), Some(Ok(Added::Accepted)));
    // the same share again, then one of another set
    press(&mut a, Key::Enter);
    type_share(&mut a, &shares[0]);
    assert_eq!(last(&a), Some(Ok(Added::Again)));
    press(&mut a, Key::Enter);
    type_share(&mut a, &others[0]);
    assert_eq!(last(&a), Some(Err(Error::OtherSet)));
    // not complete yet: Enter asks for the next share
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), SlStep::Words);
    type_share(&mut a, &shares[1]);
    assert!(a.slip.as_ref().unwrap().rec.is_complete());
    press(&mut a, Key::Enter);
    type_str(&mut a, "TREZOR");
    press(&mut a, Key::Enter);
    let fp = a.slip.as_ref().unwrap().pending.as_ref().unwrap().fingerprint;
    assert_eq!(fp, fp_of_xprv(&xprv));
    // Back: another passphrase opens another wallet
    press(&mut a, Key::Char('2'));
    assert_eq!(step(&a), SlStep::Passphrase);
    type_str(&mut a, "x");
    press(&mut a, Key::Enter);
    let other = a.slip.as_ref().unwrap().pending.as_ref().unwrap().fingerprint;
    assert_ne!(other, fp);
    // Esc on the status screen asks before throwing the shares away
    press(&mut a, Key::Char('2'));
    press(&mut a, Key::Esc);
    assert_eq!(step(&a), SlStep::Status);
    press(&mut a, Key::Esc);
    assert!(matches!(a.current(), Screen::Confirm { .. }));
    press(&mut a, Key::Char('2'));
    assert!(a.slip.is_none());
}

/// Show and check every share; returns their words.
fn write_and_check_all(a: &mut App) -> Vec<String> {
    let mut out = Vec::new();
    while let Screen::Slip39 {
        step: SlStep::Show { idx },
    } = a.current()
    {
        let st = a.slip.as_ref().unwrap();
        let mut w = [0u16; slip39::MAX_SHARE_WORDS];
        let n = st.share_words(idx, &mut w);
        out.push(
            w[..n]
                .iter()
                .map(|&i| slip39::WORDS[i as usize])
                .collect::<Vec<_>>()
                .join(" "),
        );
        press(a, Key::Enter);
        for q in 0..CHECKS {
            let SlStep::Check { q: qq, .. } = step(a) else {
                panic!()
            };
            assert_eq!(qq as usize, q);
            // the right choice is the word at the asked position
            let st = a.slip.as_ref().unwrap();
            let words: Vec<&str> = out.last().unwrap().split(' ').collect();
            let pick = (0..4u8).find(|&i| st_check(st, q, i, &words)).unwrap();
            press(a, Key::Char((b'1' + pick) as char));
        }
    }
    out
}

/// Whether choice `i` of check `q` is the share's word at the asked position.
fn st_check(st: &crate::slip39ui::SlipState, q: usize, i: u8, words: &[&str]) -> bool {
    let (pos, options) = st.check_for_test(q);
    slip39::WORDS[options[i as usize] as usize] == words[pos]
}

/// New seed > SLIP-39 wallet > dice > 20 words, rolled; at the groups.
fn new_from_dice(a: &mut App, seed: u64) -> [u8; 16] {
    nav::go(a, To::Slip39New);
    assert_eq!(step(a), SlStep::Source { sel: 0 });
    press(a, Key::Enter);
    assert!(matches!(step(a), SlStep::Strength { .. }));
    press(a, Key::Enter); // 20 words
    assert_eq!(a.current(), Screen::EntropyIntro);
    press(a, Key::Enter);
    let mut x = seed;
    for _ in 0..400 {
        let pe = a.flow.as_ref().unwrap().entropy.as_ref().unwrap();
        if pe.analyze().all_pass() {
            break;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        press(a, Key::Char((b'1' + (x % 6) as u8) as char));
    }
    press(a, Key::Enter);
    assert_eq!(a.current(), Screen::EntropySummary);
    let mut e = [0u8; 32];
    let n = a
        .flow
        .as_ref()
        .unwrap()
        .mnemonic
        .as_ref()
        .unwrap()
        .entropy(&mut e);
    assert_eq!(n, 16);
    press(a, Key::Enter);
    assert_eq!(step(a), SlStep::Groups { sel: 1 });
    assert!(a.flow.is_none(), "the dice record is wiped");
    e[..16].try_into().unwrap()
}

#[test]
fn a_wallet_from_dice_is_its_entropy_and_opens_from_its_shares() {
    let mut a = app();
    let entropy = new_from_dice(&mut a, 7);
    press(&mut a, Key::Enter); // 2 of 3
    assert_eq!(step(&a), SlStep::Mix { sel: 0 });
    press(&mut a, Key::Enter); // from the secret
    let shares = write_and_check_all(&mut a);
    assert_eq!(shares.len(), 3);
    let Screen::SeedReady { slot, created: true } = a.current() else {
        panic!("{:?}", a.current())
    };
    let fp = a.slot(slot as usize).unwrap().fingerprint;
    // the master secret is the dice entropy, used as the BIP-32 seed
    assert_eq!(
        fp,
        bp_bitcoin::bip32::Xpriv::master(&entropy).unwrap().fingerprint()
    );
    // any two shares open the same wallet
    let mut b = app();
    let slot = open_wallet(&mut b, &[&shares[2], &shares[0]], "");
    assert_eq!(b.slot(slot as usize).unwrap().fingerprint, fp);
    // made again with the same dice and groups: the same shares
    let mut c = app();
    let again = new_from_dice(&mut c, 7);
    assert_eq!(again, entropy);
    press(&mut c, Key::Enter);
    press(&mut c, Key::Enter);
    assert_eq!(write_and_check_all(&mut c), shares);
}

#[test]
fn a_wrong_check_shows_the_share_again() {
    let mut a = app();
    new_from_dice(&mut a, 9);
    press(&mut a, Key::Char('1')); // one share
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), SlStep::Show { idx: 0 });
    press(&mut a, Key::Enter);
    let st = a.slip.as_ref().unwrap();
    let (_, _) = st.check_for_test(0);
    let right = st.answer_for_test(0);
    press(&mut a, Key::Char((b'1' + (right + 1) % 4) as char));
    assert_eq!(step(&a), SlStep::Show { idx: 0 });
    assert_eq!(a.notice, Some(a.text().bk.sl_check_wrong));
    // the screen saver covers a share; the waking key does nothing else
    saver(&mut a);
    assert!(a.saver);
    press(&mut a, Key::Char('x'));
    assert_eq!(step(&a), SlStep::Covered { idx: 0 });
    press(&mut a, Key::Enter);
    assert!(matches!(step(&a), SlStep::Check { idx: 0, q: 0, .. }));
}

#[test]
fn dice_mixed_in_make_another_set_of_the_same_wallet() {
    let mut a = app();
    new_from_dice(&mut a, 11);
    press(&mut a, Key::Enter); // 2 of 3
    press(&mut a, Key::Char('2')); // with dice
    assert_eq!(step(&a), SlStep::Dice);
    type_str(&mut a, "1234561");
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), SlStep::Dice, "50 rolls are needed");
    for i in 0..MIN_DICE {
        press(&mut a, Key::Char((b'1' + (i * 5 % 6) as u8) as char));
    }
    press(&mut a, Key::Enter);
    let mixed = write_and_check_all(&mut a);
    let Screen::SeedReady { slot, .. } = a.current() else {
        panic!()
    };
    let fp = a.slot(slot as usize).unwrap().fingerprint;
    let mut b = app();
    new_from_dice(&mut b, 11);
    press(&mut b, Key::Enter);
    press(&mut b, Key::Enter);
    let plain = write_and_check_all(&mut b);
    let first2 = |s: &str| s.split(' ').take(2).collect::<Vec<_>>().join(" ");
    assert_ne!(
        first2(&mixed[0]),
        first2(&plain[0]),
        "dice give another identifier"
    );
    let mut c = app();
    let s = open_wallet(&mut c, &[&mixed[1], &mixed[2]], "");
    assert_eq!(c.slot(s as usize).unwrap().fingerprint, fp);
}

#[test]
fn another_set_of_a_loaded_wallet_opens_it_too() {
    let (shares, xprv) = vector(4);
    let mut a = app();
    let picks: Vec<&str> = shares.iter().map(|s| s.as_str()).collect();
    open_wallet(&mut a, &picks, "TREZOR");
    press(&mut a, Key::Enter);
    nav::seed_opt(&mut a, SlotOpt::Slip39Shares);
    assert_eq!(step(&a), SlStep::Groups { sel: 1 });
    press(&mut a, Key::Char('3')); // 3 of 5
    press(&mut a, Key::Enter);
    let set = write_and_check_all(&mut a);
    assert_eq!(set.len(), 5);
    assert!(matches!(a.current(), Screen::SeedOptions { sel: 3, .. }));
    assert_eq!(a.notice, Some(a.text().bk.sl_done));
    // the same identifier (extendable), three of them open the wallet
    assert_eq!(set[0].split(' ').next(), shares[0].split(' ').next());
    let mut b = app();
    let s = open_wallet(&mut b, &[&set[4], &set[1], &set[2]], "TREZOR");
    assert_eq!(b.slot(s as usize).unwrap().fingerprint, fp_of_xprv(&xprv));
    // Esc while choosing goes back to the options without a question
    nav::seed(&mut a, 0);
    nav::seed_opt(&mut a, SlotOpt::Slip39Shares);
    press(&mut a, Key::Esc);
    assert!(matches!(a.current(), Screen::SeedOptions { .. }));
}

#[test]
fn custom_groups_keep_to_the_rules() {
    let mut a = app();
    new_from_dice(&mut a, 13);
    press(&mut a, Key::Char('4'));
    assert_eq!(step(&a), SlStep::Custom { sel: 0 });
    let groups = |a: &App| {
        let st = a.slip.as_ref().unwrap();
        (
            st.gt,
            st.groups[..st.ngroups as usize]
                .iter()
                .map(|g| (g.threshold, g.count))
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(groups(&a), (2, vec![(1, 1), (1, 1), (2, 3)]));
    // groups needed cannot pass the number of groups
    for _ in 0..5 {
        press(&mut a, Key::Right);
    }
    assert_eq!(groups(&a).0, 3);
    // fewer groups pull "needed" down
    press(&mut a, Key::Down);
    press(&mut a, Key::Left);
    assert_eq!(groups(&a), (2, vec![(1, 1), (1, 1)]));
    press(&mut a, Key::Right);
    assert_eq!(groups(&a).1.len(), 3);
    // group 1 shares: 1 -> 2 makes it need 2; needs cannot drop to 1
    press(&mut a, Key::Down); // group 1 needs
    press(&mut a, Key::Down); // group 1 shares
    press(&mut a, Key::Right);
    assert_eq!(groups(&a).1[0], (2, 2));
    press(&mut a, Key::Up);
    press(&mut a, Key::Left);
    assert_eq!(groups(&a).1[0], (2, 2));
    for _ in 0..20 {
        press(&mut a, Key::Down);
        press(&mut a, Key::Right);
        press(&mut a, Key::Up);
        press(&mut a, Key::Right);
        press(&mut a, Key::Down);
    }
    let (gt, gs) = groups(&a);
    assert!(gs.iter().all(|&(t, c)| t <= c && c <= 16 && (c == 1 || t >= 2)));
    assert!(gt as usize <= gs.len());
    let st = a.slip.as_ref().unwrap();
    assert!(slip39::check_config(st.gt, &st.groups[..st.ngroups as usize]).is_ok());
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), SlStep::Mix { sel: 0 });
}

#[test]
fn shares_that_take_too_long_are_refused() {
    // a set made with iteration exponent 7 (1.28 million rounds)
    let ms = slip39::MasterSecret::new(&[1; 16]).unwrap();
    let ems = slip39::Ems::encrypt(&ms, b"", 5, true, 7).unwrap();
    let mut words = Vec::new();
    slip39::reshare(
        &ems,
        1,
        &[slip39::Group {
            threshold: 1,
            count: 1,
        }],
        b"",
        |s| {
            let mut w = [0u16; slip39::MAX_SHARE_WORDS];
            let n = s.to_indices(&mut w);
            words.push(
                w[..n]
                    .iter()
                    .map(|&i| slip39::WORDS[i as usize])
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        },
    )
    .unwrap();
    let mut a = app();
    open_load(&mut a, false);
    type_share(&mut a, &words[0]);
    assert_eq!(step(&a), SlStep::Status);
    assert!(a.slip.as_ref().unwrap().slow);
    assert_eq!(a.slip.as_ref().unwrap().rec.shares(), 0);
}

#[test]
fn power_off_and_menus_wipe_the_shares() {
    let (shares, _) = vector(4);
    let mut a = app();
    open_load(&mut a, false);
    type_share(&mut a, &shares[0]);
    assert!(a.slip.is_some());
    a.wipe_ram(); // power off and Lock now
    assert!(a.slip.is_none());
    // leaving through the menus wipes them too
    open_load(&mut a, false);
    type_share(&mut a, &shares[0]);
    press(&mut a, Key::Esc);
    press(&mut a, Key::Char('2'));
    assert!(a.slip.is_none());
    assert!(matches!(a.current(), Screen::Menu { .. }));
}

/// Every SLIP-39 step drawn in both languages (screen tour, M9 coverage).
#[test]
pub(crate) fn slip39_screens_fit() {
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(format!("slip39-{l}-{name}.ppm")));
            }
        };
        let (shares, _) = vector(4);
        let (big, _) = vector(23);
        let (others, _) = vector(43);
        let mut a = app();
        a.settings.lang = lang;
        a.set_test_only(true);
        nav::go(&mut a, To::Slip39Load);
        shot(&a, "length");
        press(&mut a, Key::Enter);
        type_share(
            &mut a,
            &shares[0].split(' ').take(6).collect::<Vec<_>>().join(" "),
        );
        type_str(&mut a, "ac");
        shot(&a, "words");
        discard(&mut a);
        // a typo in word 4: pick it, type it again
        let mut w: Vec<&str> = shares[0].split(' ').collect();
        let right = w[3];
        w[3] = if right == "acid" { "academic" } else { "acid" };
        open_load(&mut a, false);
        type_share(&mut a, &w.join(" "));
        shot(&a, "fix");
        for _ in 0..3 {
            press(&mut a, Key::Down);
        }
        press(&mut a, Key::Enter);
        shot(&a, "words-fix");
        type_str(&mut a, right);
        assert_eq!(step(&a), SlStep::Status);
        shot(&a, "status");
        press(&mut a, Key::Enter);
        type_share(&mut a, &others[0]);
        shot(&a, "status-other");
        press(&mut a, Key::Enter);
        type_share(&mut a, &shares[1]);
        shot(&a, "status-done");
        press(&mut a, Key::Enter);
        type_str(&mut a, "TREZOR");
        shot(&a, "passphrase");
        press(&mut a, Key::Enter);
        shot(&a, "ready");
        press(&mut a, Key::Enter);
        // 33-word shares
        open_load(&mut a, true);
        type_share(&mut a, &big[0].split(' ').take(30).collect::<Vec<_>>().join(" "));
        shot(&a, "words-33");
        discard(&mut a);
        // making a wallet
        nav::go(&mut a, To::Slip39New);
        shot(&a, "source");
        press(&mut a, Key::Char('3'));
        shot(&a, "strength");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Esc);
        new_from_dice(&mut a, 3 + lang as u64);
        shot(&a, "groups");
        press(&mut a, Key::Char('4'));
        shot(&a, "custom");
        press(&mut a, Key::Down);
        for _ in 0..4 {
            press(&mut a, Key::Right);
        }
        shot(&a, "custom-long");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('2'));
        shot(&a, "mix");
        press(&mut a, Key::Char('2'));
        type_str(&mut a, "123456");
        press(&mut a, Key::Enter);
        shot(&a, "dice");
        press(&mut a, Key::Esc);
        press(&mut a, Key::Char('1'));
        shot(&a, "show");
        press(&mut a, Key::Enter);
        shot(&a, "check");
        press(&mut a, Key::Esc);
        saver(&mut a);
        press(&mut a, Key::Char('x'));
        assert_eq!(step(&a), SlStep::Covered { idx: 0 });
        shot(&a, "covered");
        discard(&mut a);
        // help on a SLIP-39 screen
        nav::go(&mut a, To::Slip39Load);
        press(&mut a, Key::Char('?'));
        assert!(a.help.get());
        shot(&a, "help");
    }
}
