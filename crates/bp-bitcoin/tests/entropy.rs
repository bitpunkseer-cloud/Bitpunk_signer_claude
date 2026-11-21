//! Physical entropy: hash compatibility with SeedSigner and behaviour of the
//! entropy checks on fair and deliberately bad input.

use bp_bitcoin::bip39::MAX_PHRASE_LEN;
use bp_bitcoin::entropy::{analyze, mnemonic_from_record, PhysicalEntropy, Source, Status};

fn phrase(m: &bp_bitcoin::bip39::Mnemonic) -> String {
    let mut buf = [0u8; MAX_PHRASE_LEN];
    let n = m.write_phrase(&mut buf);
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn face(&mut self, sides: u64) -> u8 {
        (self.next() % sides) as u8
    }
}

#[test]
fn seedsigner_known_dice_vectors() {
    // SeedSigner tests/test_mnemonic_generation.py::test_known_dice_rolls
    let a =
        "522222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555";
    assert_eq!(
        phrase(&mnemonic_from_record(a.as_bytes(), 24)),
        "resource timber firm banner horror pupil frozen main pear direct pioneer broken grid core insane begin sister pony end debate task silk empty curious"
    );
    let b =
        "222222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555";
    assert_eq!(
        phrase(&mnemonic_from_record(b.as_bytes(), 24)),
        "garden uphold level clog sword globe armor issue two cute scorpion improve verb artwork blind tail raw butter combine move produce foil feature wave"
    );
    // ...but such input is rejected by the checks before a seed can be made.
    // (99 rolls is also below our 24-word minimum of 100.)
    let an = analyze(Source::Dice, 24, a.as_bytes());
    assert!(!an.all_pass());
    assert_eq!(an.count_status, Status::Pending);
    assert_eq!(an.repeat_status, Status::Fail); // 44 identical rolls in a row
}

#[test]
fn twelve_words_use_first_16_bytes() {
    // Same truncation as SeedSigner/Krux: SHA-256(record)[..16].
    let rec = b"36152463125416325416235142365124635214365241362514";
    let full = mnemonic_from_record(rec, 24);
    let short = mnemonic_from_record(rec, 12);
    let mut e24 = [0u8; 32];
    let mut e12 = [0u8; 32];
    full.entropy(&mut e24);
    short.entropy(&mut e12);
    assert_eq!(&e24[..16], &e12[..16]);
}

/// Simulate an honest user: roll fair values and stop at the first moment the
/// count and entropy targets are met. Returns (all checks passed, extra values).
fn honest_run(rng: &mut XorShift, source: Source, words: usize) -> (bool, usize) {
    let mut pe = PhysicalEntropy::new(source, words);
    let sides = source.sides() as u64;
    loop {
        let v = rng.face(sides);
        pe.push(if source == Source::Coin { v } else { v + 1 }).unwrap();
        let a = pe.analyze();
        if a.count_status == Status::Pass && a.entropy_status == Status::Pass {
            return (a.all_pass(), pe.len() - a.min_count);
        }
    }
}

#[test]
fn honest_input_rarely_fails_and_finishes_near_minimum() {
    let mut rng = XorShift(0xDEAD_BEEF_CAFE_F00D);
    for (source, words) in [
        (Source::Dice, 12),
        (Source::Dice, 24),
        (Source::Coin, 12),
        (Source::Coin, 24),
        (Source::D20, 12),
        (Source::D20, 24),
    ] {
        let trials = 3000;
        let mut fails = 0;
        let mut extras = Vec::new();
        for _ in 0..trials {
            let (ok, extra) = honest_run(&mut rng, source, words);
            if !ok {
                fails += 1;
            }
            extras.push(extra);
        }
        extras.sort();
        let p99 = extras[trials * 99 / 100];
        // False rejection under 1%; 99% of users need at most 10 extra values.
        assert!(
            fails * 100 < trials,
            "{source:?}/{words}: {fails} of {trials} honest runs failed"
        );
        assert!(p99 <= 10, "{source:?}/{words}: p99 extra values {p99}");
    }
}

fn status_of(source: Source, words: usize, rec: &str) -> bp_bitcoin::entropy::Analysis {
    analyze(source, words, rec.as_bytes())
}

#[test]
fn rejects_constant_input() {
    let a = status_of(Source::Dice, 12, &"1".repeat(60));
    assert_eq!(a.repeat_status, Status::Fail);
    assert!(!a.all_pass());
}

#[test]
fn rejects_arithmetic_progression() {
    let a = status_of(Source::Dice, 12, &"123456".repeat(10));
    assert_eq!(a.pattern_status, Status::Fail);
}

#[test]
fn rejects_repeated_shuffle() {
    // Perfect frequencies; only periodicity gives it away.
    let a = status_of(Source::Dice, 12, &"162534".repeat(10));
    assert_eq!(a.bias_status, Status::Pass);
    assert_eq!(a.pattern_status, Status::Fail);
}

#[test]
fn rejects_two_faces_only() {
    let mut rng = XorShift(99);
    let rec: String = (0..120)
        .map(|_| if rng.next() & 1 == 0 { '2' } else { '5' })
        .collect();
    let a = status_of(Source::Dice, 24, &rec);
    assert_eq!(a.bias_status, Status::Fail);
}

#[test]
fn rejects_alternating_and_blocky_coins() {
    assert_eq!(
        status_of(Source::Coin, 12, &"01".repeat(70)).pattern_status,
        Status::Fail
    );
    assert_eq!(
        status_of(Source::Coin, 12, &"0011".repeat(35)).pattern_status,
        Status::Fail
    );
    let mostly_heads: String = (0..140).map(|i| if i % 5 == 0 { '0' } else { '1' }).collect();
    let a = status_of(Source::Coin, 12, &mostly_heads);
    assert_eq!(a.bias_status, Status::Fail);
}

#[test]
fn checks_pending_until_minimum() {
    let a = status_of(Source::Dice, 12, "3615");
    assert_eq!(a.count_status, Status::Pending);
    assert_eq!(a.bias_status, Status::Pending);
    assert!(!a.all_pass() && !a.any_fail());
}

#[test]
fn to_mnemonic_requires_all_checks() {
    let mut pe = PhysicalEntropy::new(Source::Dice, 12);
    for c in "123456".repeat(10).bytes() {
        pe.push(c - b'0').unwrap();
    }
    assert!(pe.to_mnemonic().is_err());
    assert!(pe.push(7).is_err());
}

#[test]
fn d20_hashes_values_joined_with_dashes_like_krux() {
    use bp_bitcoin::entropy::MAX_TEXT;
    assert_eq!(Source::D20.min_count(12), 30);
    assert_eq!(Source::D20.min_count(24), 60);
    let mut pe = PhysicalEntropy::new(Source::D20, 12);
    for v in [1, 20, 7, 10] {
        pe.push(v).unwrap();
    }
    assert!(pe.push(0).is_err() && pe.push(21).is_err());
    let mut t = [0u8; MAX_TEXT];
    let n = pe.text(&mut t);
    assert_eq!(&t[..n], b"1-20-7-10");
    assert_eq!(pe.sha256(), bp_crypto::Sha256::digest(b"1-20-7-10"));
    // the seed is SHA-256 of that text, as for D6
    let rolls: Vec<u8> = (0..60).map(|i| (i * 7 % 20 + 1) as u8).collect();
    let text = rolls.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-");
    let m = mnemonic_from_record(text.as_bytes(), 24);
    let mut pe = PhysicalEntropy::new(Source::D20, 24);
    for &v in &rolls {
        pe.push(v).unwrap();
    }
    let n = pe.text(&mut t);
    assert_eq!(&t[..n], text.as_bytes());
    assert_eq!(phrase(&mnemonic_from_record(&t[..n], 24)), phrase(&m));
}

#[test]
fn d20_rejects_bad_input() {
    let run = |vals: &[u8]| analyze(Source::D20, 12, vals);
    // one face only
    let a = run(&[13; 40]);
    assert_eq!(a.repeat_status, Status::Fail);
    assert!(!a.all_pass());
    // 1, 2, ..., 20, 1, 2, ...: perfectly flat but patterned
    let prog: Vec<u8> = (0..80).map(|i| (i % 20 + 1) as u8).collect();
    let a = run(&prog);
    assert_eq!(a.pattern_status, Status::Fail);
    // only two faces
    let two: Vec<u8> = (0..60).map(|i| if (i * 7) % 3 == 0 { 4 } else { 17 }).collect();
    let a = run(&two);
    assert!(!a.all_pass());
    // five equal rolls in a row
    let mut five = prog[..40].to_vec();
    five.splice(10..10, [9, 9, 9, 9, 9]);
    assert_eq!(run(&five).repeat_status, Status::Fail);
}
