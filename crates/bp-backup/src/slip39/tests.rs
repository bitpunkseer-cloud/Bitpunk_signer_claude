//! SLIP-39 against the published vectors and, byte for byte, against the
//! reference implementation (fixtures from tools/gen_slip39_fixtures.py).

use super::*;
use bp_crypto::sha256::Sha256;
use std::string::String;
use std::vec::Vec;

const VECTORS: &str = include_str!("../../tests/data/slip39_vectors.txt");
const SPLITS: &str = include_str!("../../tests/data/slip39_split.txt");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn indices(mnemonic: &str) -> Option<Vec<u16>> {
    mnemonic.split_whitespace().map(word_index).collect()
}

fn words_of(share: &Share) -> String {
    let mut out = [0u16; MAX_SHARE_WORDS];
    let n = share.to_indices(&mut out);
    out[..n]
        .iter()
        .map(|&i| WORDS[i as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Blocks of `key value` lines after `## title`.
fn blocks(text: &str) -> Vec<Vec<(&str, &str)>> {
    let mut out = Vec::new();
    for block in text.split("\n## ").skip(1) {
        let lines = block
            .lines()
            .skip(1)
            .filter(|l| !l.is_empty())
            .map(|l| l.split_once(' ').unwrap_or((l, "")))
            .collect();
        out.push(lines);
    }
    out
}

fn get<'a>(b: &[(&str, &'a str)], key: &str) -> &'a str {
    b.iter().find(|(k, _)| *k == key).map(|(_, v)| *v).unwrap()
}

/// Recover from mnemonics; `Err` at the first refusal.
fn recover(mnemonics: &[&str], passphrase: &[u8]) -> Result<MasterSecret, Error> {
    let mut r = Recovery::new();
    for m in mnemonics {
        let w = indices(m).ok_or(Error::WordIndex)?;
        r.add(&Share::from_indices(&w)?)?;
    }
    r.ems()?.decrypt(passphrase)
}

#[test]
fn the_word_list_is_sorted_and_told_apart_by_four_letters() {
    assert_eq!(WORDS.len(), 1024);
    for i in 1..1024 {
        assert!(WORDS[i - 1] < WORDS[i]);
        assert_ne!(WORDS[i - 1][..4.min(WORDS[i - 1].len())], WORDS[i][..4]);
    }
    for (i, w) in WORDS.iter().enumerate() {
        assert_eq!(word_index(w), Some(i as u16));
        assert_eq!(prefix_range(&w[..UNIQUE_PREFIX_LEN]), i..i + 1);
    }
    assert_eq!(word_index("abandon"), None); // a BIP-39 word, not SLIP-39
    assert_eq!(prefix_range("ac").len(), 7); // academic .. actress
    assert_eq!(share_words(16), MIN_SHARE_WORDS);
    assert_eq!(share_words(32), MAX_SHARE_WORDS);
}

#[test]
fn published_vectors() {
    let mut valid = 0;
    let mut invalid = 0;
    for b in blocks(VECTORS) {
        let shares: Vec<&str> = b.iter().filter(|(k, _)| *k == "share").map(|(_, v)| *v).collect();
        let want = get(&b, "secret");
        let got = recover(&shares, b"TREZOR");
        if want == "-" {
            assert!(got.is_err(), "{shares:?} must be refused");
            invalid += 1;
            continue;
        }
        let ms = got.unwrap_or_else(|e| panic!("{e:?} for {shares:?}"));
        assert_eq!(ms.expose(), &hex(want)[..]);
        let master = bp_bitcoin::bip32::Xpriv::master(ms.expose()).unwrap();
        let mut out = [0u8; bp_bitcoin::bip32::XKEY_LEN];
        let n = master.encode([0x04, 0x88, 0xAD, 0xE4], &mut out);
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), get(&b, "xprv"));
        valid += 1;
    }
    assert_eq!((valid, invalid), (15, 30));
}

#[test]
fn published_invalid_vectors_fail_for_the_right_reason() {
    let reasons: Vec<Result<(), Error>> = blocks(VECTORS)
        .iter()
        .filter(|b| get(b, "secret") == "-")
        .map(|b| {
            let shares: Vec<&str> = b.iter().filter(|(k, _)| *k == "share").map(|(_, v)| *v).collect();
            recover(&shares, b"TREZOR").map(|_| ())
        })
        .collect();
    use Error::*;
    // In the vectors' order: the 128-bit half, the 256-bit half, then the
    // two length vectors. Each reason matches the vector's description.
    let half = [
        Checksum,        // invalid checksum
        Padding,         // invalid padding
        Incomplete,      // 2-of-3 with one share
        OtherSet,        // different identifiers
        OtherSet,        // different iteration exponents
        OtherSet,        // mismatching group thresholds
        OtherSet,        // mismatching group counts
        GroupThreshold,  // group threshold above group count
        SameIndex,       // duplicate member indices
        MemberThreshold, // mismatching member thresholds
        Digest,          // invalid digest
        Incomplete,      // insufficient groups, case 1
        Incomplete,      // insufficient groups, case 2
        Incomplete,      // threshold groups, too few members in one
    ];
    let got: Vec<Error> = reasons.iter().map(|r| r.unwrap_err()).collect();
    assert_eq!(got.len(), 30);
    assert_eq!(got[..14], half);
    assert_eq!(got[14..28], half);
    assert_eq!(got[28..], [Length, Length]);
}

/// The reference's random stream: SHA-256(seed || counter) blocks.
struct Stream {
    seed: [u8; 32],
    counter: u32,
    buf: [u8; 32],
    used: usize,
}

impl Stream {
    fn new(seed: &[u8]) -> Stream {
        Stream {
            seed: seed.try_into().unwrap(),
            counter: 0,
            buf: [0; 32],
            used: 32,
        }
    }
}

impl Randomness for Stream {
    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            if self.used == 32 {
                let mut h = Sha256::new();
                h.update(&self.seed);
                h.update(&self.counter.to_be_bytes());
                self.buf = h.finalize();
                self.counter += 1;
                self.used = 0;
            }
            *b = self.buf[self.used];
            self.used += 1;
        }
    }
}

struct Case {
    seed: Vec<u8>,
    secret: Vec<u8>,
    passphrase: Vec<u8>,
    ext: bool,
    exp: u8,
    group_threshold: u8,
    groups: Vec<Group>,
    shares: Vec<String>,
}

fn cases() -> Vec<Case> {
    blocks(SPLITS)
        .iter()
        .map(|b| {
            let mut ee = get(b, "ext").split_whitespace();
            let ext = ee.next().unwrap() == "1";
            ee.next();
            let exp = ee.next().unwrap().parse().unwrap();
            let mut gg = get(b, "groups").split_whitespace();
            let group_threshold = gg.next().unwrap().parse().unwrap();
            let groups = gg
                .map(|g| {
                    let (t, c) = g.split_once('/').unwrap();
                    Group {
                        threshold: t.parse().unwrap(),
                        count: c.parse().unwrap(),
                    }
                })
                .collect();
            let p = get(b, "passphrase");
            Case {
                seed: hex(get(b, "seed")),
                secret: hex(get(b, "secret")),
                passphrase: if p == "-" { Vec::new() } else { hex(p) },
                ext,
                exp,
                group_threshold,
                groups,
                shares: b
                    .iter()
                    .filter(|(k, _)| *k == "share")
                    .map(|(_, v)| String::from(*v))
                    .collect(),
            }
        })
        .collect()
}

#[test]
fn splits_match_the_reference_byte_for_byte() {
    let all = cases();
    assert_eq!(all.len(), 56);
    for (n, c) in all.iter().enumerate() {
        let mut rng = Stream::new(&c.seed);
        let id = random_identifier(&mut rng);
        let ms = MasterSecret::new(&c.secret).unwrap();
        let ems = Ems::encrypt(&ms, &c.passphrase, id, c.ext, c.exp).unwrap();
        let mut got = Vec::new();
        split(&ems, c.group_threshold, &c.groups, &mut rng, |s| {
            got.push(words_of(s))
        })
        .unwrap();
        assert_eq!(got, c.shares, "case {}", n + 1);
    }
}

#[test]
fn every_reference_share_reads_back_to_the_same_words() {
    for c in cases() {
        for m in &c.shares {
            let s = Share::from_indices(&indices(m).unwrap()).unwrap();
            assert_eq!(&words_of(&s), m);
            assert_eq!(s.value().len(), c.secret.len());
        }
    }
}

/// Shares of a case by group: `by_group[g]` in member order.
fn by_group(c: &Case) -> Vec<Vec<&str>> {
    let mut out = Vec::new();
    let mut it = c.shares.iter();
    for g in &c.groups {
        out.push((0..g.count).map(|_| it.next().unwrap().as_str()).collect());
    }
    out
}

#[test]
fn any_enough_shares_recover_the_reference_secret() {
    for (n, c) in cases().iter().enumerate() {
        let groups = by_group(c);
        let k = groups.len();
        // Groups in a rotated order, members from a rotated start.
        for rot in 0..3usize {
            let mut r = Recovery::new();
            let mut taken = 0;
            for gi in 0..k {
                let g = (gi + rot + n) % k;
                let need = c.groups[g].threshold as usize;
                let count = c.groups[g].count as usize;
                for m in 0..need {
                    let w = indices(groups[g][(m + rot) % count]).unwrap();
                    let added = r.add(&Share::from_indices(&w).unwrap()).unwrap();
                    if taken < c.group_threshold as usize {
                        assert_eq!(added, Added::Accepted);
                    } else {
                        assert_eq!(added, Added::NotNeeded);
                    }
                }
                if r.group((g) % 16).done {
                    taken += 1;
                }
            }
            assert!(r.is_complete());
            let ms = r.ems().unwrap().decrypt(&c.passphrase).unwrap();
            assert_eq!(ms.expose(), &c.secret[..], "case {} rotation {rot}", n + 1);
            let other = r.ems().unwrap().decrypt(b"wrong").unwrap();
            assert_ne!(other.expose(), &c.secret[..]);
        }
    }
}

/// The first 16-byte case with one group of 3 of 5.
fn three_of_five(all: &[Case]) -> &Case {
    all.iter()
        .find(|c| {
            c.groups
                == [Group {
                    threshold: 3,
                    count: 5,
                }]
                && c.secret.len() == 16
        })
        .unwrap()
}

#[test]
fn shares_are_checked_as_they_come() {
    let all = cases();
    let c = three_of_five(&all);
    let s: Vec<Share> = c
        .shares
        .iter()
        .map(|m| Share::from_indices(&indices(m).unwrap()).unwrap())
        .collect();
    let mut r = Recovery::new();
    assert_eq!(r.ems().err(), Some(Error::Incomplete));
    assert_eq!(r.add(&s[0]), Ok(Added::Accepted));
    assert_eq!(r.add(&s[0]), Ok(Added::Again));
    assert_eq!(
        r.group(0),
        GroupProgress {
            have: 1,
            need: 3,
            done: false
        }
    );
    // The same member number with other words.
    let mut forged = s[1].clone();
    forged.member_index = s[0].member_index;
    assert_eq!(r.add(&forged), Err(Error::SameIndex));
    // A share of another set.
    let other = Share::from_indices(&indices(&all[0].shares[0]).unwrap()).unwrap();
    assert_eq!(r.add(&other), Err(Error::OtherSet));
    assert_eq!(r.add(&s[1]), Ok(Added::Accepted));
    assert_eq!(r.add(&s[4]), Ok(Added::Accepted));
    assert!(r.is_complete());
    // A further good share lies on the polynomial; a changed one does not.
    assert_eq!(r.add(&s[2]), Ok(Added::NotNeeded));
    let mut bad = s[3].clone();
    bad.value[0] ^= 1;
    assert_eq!(r.add(&bad), Err(Error::Digest));
    assert_eq!(
        r.ems().unwrap().decrypt(&c.passphrase).unwrap().expose(),
        &c.secret[..]
    );
}

#[test]
fn a_wrong_share_empties_its_group_to_be_typed_again() {
    let all = cases();
    let c = three_of_five(&all);
    let s: Vec<Share> = c
        .shares
        .iter()
        .map(|m| Share::from_indices(&indices(m).unwrap()).unwrap())
        .collect();
    let mut r = Recovery::new();
    r.add(&s[0]).unwrap();
    r.add(&s[1]).unwrap();
    let mut bad = s[2].clone();
    bad.value[5] ^= 0x40; // passes the checksum check (no words) but not the digest
    assert_eq!(r.add(&bad), Err(Error::Digest));
    assert_eq!(r.shares(), 0);
    assert_eq!(r.group_threshold(), None);
    for i in [2, 3, 4] {
        r.add(&s[i]).unwrap();
    }
    assert_eq!(
        r.ems().unwrap().decrypt(&c.passphrase).unwrap().expose(),
        &c.secret[..]
    );
}

#[test]
fn a_changed_word_or_a_missing_word_is_refused() {
    for c in cases().iter().step_by(5) {
        let w = indices(&c.shares[0]).unwrap();
        for i in 0..w.len() {
            let mut v = w.clone();
            v[i] = (v[i] + 1) % 1024;
            assert_eq!(Share::from_indices(&v).err(), Some(Error::Checksum), "word {i}");
            let mut v = w.clone();
            v.remove(i);
            assert!(Share::from_indices(&v).is_err());
        }
        let mut v = w.clone();
        v[3] = 1024;
        assert_eq!(Share::from_indices(&v).err(), Some(Error::WordIndex));
    }
}

#[test]
fn configs_and_secrets_that_cannot_be_split() {
    let g = |t, c| Group {
        threshold: t,
        count: c,
    };
    assert!(check_config(1, &[g(1, 1)]).is_ok());
    assert!(check_config(2, &[g(2, 3), g(3, 5), g(1, 1)]).is_ok());
    assert_eq!(check_config(0, &[g(1, 1)]), Err(Error::Config));
    assert_eq!(check_config(2, &[g(1, 1)]), Err(Error::Config));
    assert_eq!(check_config(1, &[g(1, 2)]), Err(Error::Config)); // 1-of-2 members
    assert_eq!(check_config(1, &[g(3, 2)]), Err(Error::Config));
    assert_eq!(check_config(1, &[g(2, 17)]), Err(Error::Config));
    assert_eq!(check_config(1, &[g(1, 1); 17]), Err(Error::Config));
    assert_eq!(check_config(1, &[]), Err(Error::Config));
    assert!(MasterSecret::new(&[0; 15]).is_err());
    assert!(MasterSecret::new(&[0; 17]).is_err());
    assert!(MasterSecret::new(&[0; 34]).is_err());
    let ms = MasterSecret::new(&[7; 16]).unwrap();
    assert_eq!(
        Ems::encrypt(&ms, "é".as_bytes(), 1, true, 0).err(),
        Some(Error::Passphrase)
    );
    assert_eq!(
        Ems::encrypt(&ms, b"", 1 << 15, true, 0).err(),
        Some(Error::Config)
    );
}

#[test]
fn fuzz_words_and_share_sequences_never_panic() {
    let mut seed = 0x1234_5678u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    let all = cases();
    for _ in 0..3000 {
        let n = (next() % 40) as usize;
        let w: Vec<u16> = (0..n).map(|_| (next() % 1100) as u16).collect();
        let _ = Share::from_indices(&w);
    }
    for round in 0..300 {
        let mut r = Recovery::new();
        for _ in 0..12 {
            let c = &all[(next() as usize) % all.len()];
            let c = if round % 2 == 0 {
                &all[round % all.len()]
            } else {
                c
            };
            let mut s =
                Share::from_indices(&indices(&c.shares[next() as usize % c.shares.len()]).unwrap()).unwrap();
            if next() % 4 == 0 {
                s.value[(next() % 16) as usize] ^= 1 << (next() % 8);
            }
            let _ = r.add(&s);
            if r.is_complete() {
                let _ = r.ems();
            }
        }
    }
}

fn set_words(ms: &MasterSecret, pass: &[u8], gt: u8, groups: &[Group], dice: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    make_set(ms, pass, gt, groups, dice, |s| out.push(words_of(s))).unwrap();
    out
}

#[test]
fn the_same_choices_make_the_same_set_and_others_an_unrelated_one() {
    let ms = MasterSecret::new(&[0x42; 16]).unwrap();
    let g23 = [Group {
        threshold: 2,
        count: 3,
    }];
    let a = set_words(&ms, b"", 1, &g23, b"");
    assert_eq!(a, set_words(&ms, b"", 1, &g23, b""));
    assert_eq!(a.len(), 3);
    let first_two = |s: &str| s.split(' ').take(2).collect::<Vec<_>>().join(" ");
    for other in [
        set_words(&ms, b"p", 1, &g23, b""),
        set_words(&ms, b"", 1, &g23, b"3141592653"),
        set_words(&MasterSecret::new(&[0x43; 16]).unwrap(), b"", 1, &g23, b""),
    ] {
        assert_ne!(first_two(&a[0]), first_two(&other[0]), "a new identifier");
    }
    // Other groups: the same wallet's identifier, other shares.
    let g24 = [Group {
        threshold: 2,
        count: 4,
    }];
    let other = set_words(&ms, b"", 1, &g24, b"");
    assert_eq!(first_two(&a[0]), first_two(&other[0]));
    assert_ne!(a[0], other[0]);
    // Each set recovers its secret, with the passphrase it was made with.
    let picks: Vec<&str> = a.iter().skip(1).map(|s| s.as_str()).collect();
    assert_eq!(recover(&picks, b"").unwrap().expose(), ms.expose());
    let b = set_words(&ms, b"p", 1, &g23, b"");
    let picks: Vec<&str> = b.iter().take(2).map(|s| s.as_str()).collect();
    assert_eq!(recover(&picks, b"p").unwrap().expose(), ms.expose());
    // Another set of the same wallet keeps the identifier (extendable),
    // recovers it, and its shares do not combine with the first set's.
    let mut first = Vec::new();
    let e = make_set(&ms, b"", 1, &g23, b"", |s| first.push(words_of(s))).unwrap();
    let mut second = Vec::new();
    reshare(
        &e,
        1,
        &[Group {
            threshold: 2,
            count: 4,
        }],
        b"",
        |s| second.push(words_of(s)),
    )
    .unwrap();
    assert_eq!(first_two(&first[0]), first_two(&second[0]));
    let picks = [second[1].as_str(), second[3].as_str()];
    assert_eq!(recover(&picks, b"").unwrap().expose(), ms.expose());
    let mixed = [first[0].as_str(), second[1].as_str()];
    assert!(recover(&mixed, b"").is_err());
    let again = Ems::from_parts(e.identifier, e.extendable, e.iteration_exponent, e.value()).unwrap();
    let mut third = Vec::new();
    reshare(&again, 1, &g23, b"", |s| third.push(words_of(s))).unwrap();
    assert_eq!(third, first, "the stored parts make the same set");
    // Two groups, 256 bits: shares are 33 words, extendable, exponent 1.
    let big = MasterSecret::new(&[0x99; 32]).unwrap();
    let two = [
        Group {
            threshold: 1,
            count: 1,
        },
        Group {
            threshold: 2,
            count: 3,
        },
    ];
    let c = set_words(&big, b"", 2, &two, b"");
    assert_eq!(c.len(), 4);
    let s = Share::from_indices(&indices(&c[0]).unwrap()).unwrap();
    assert!(s.extendable);
    assert_eq!(s.iteration_exponent, DEFAULT_ITERATION_EXPONENT);
    assert_eq!(c[0].split(' ').count(), 33);
    let picks = [c[0].as_str(), c[2].as_str(), c[3].as_str()];
    assert_eq!(recover(&picks, b"").unwrap().expose(), big.expose());
    assert_eq!(recover(&picks[..2], b"").err(), Some(Error::Incomplete));
}
