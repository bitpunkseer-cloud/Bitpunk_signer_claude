//! Screen tour: renders every screen in every language. With bp-ui's
//! `layout-check` feature (on for tests) any text that runs off the screen
//! or overflows its buffer panics, naming the string. Set `BP_SHOTS=<dir>`
//! to also save each screen as a PPM image for review.

use super::*;
use crate::settings::Lang;

/// 800 x 480 RGB framebuffer.
struct Shot {
    px: Vec<u8>,
}

impl Shot {
    fn new() -> Shot {
        Shot {
            px: vec![0; 800 * 480 * 3],
        }
    }

    fn save(&self, path: &std::path::Path) {
        let mut out = b"P6\n800 480\n255\n".to_vec();
        out.extend_from_slice(&self.px);
        std::fs::write(path, out).unwrap();
    }
}

impl bp_hal::Canvas for Shot {
    fn width(&self) -> u16 {
        800
    }
    fn height(&self) -> u16 {
        480
    }
    fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, c: bp_hal::Rgb) {
        for yy in y.max(0)..(y + h).min(480) {
            for xx in x.max(0)..(x + w).min(800) {
                let i = (yy as usize * 800 + xx as usize) * 3;
                self.px[i..i + 3].copy_from_slice(&[c.0, c.1, c.2]);
            }
        }
    }
    fn blend_pixel(&mut self, x: i32, y: i32, c: bp_hal::Rgb, a: u8) {
        if !(0..800).contains(&x) || !(0..480).contains(&y) {
            return;
        }
        let i = (y as usize * 800 + x as usize) * 3;
        let a = a as u16;
        for (k, v) in [c.0, c.1, c.2].into_iter().enumerate() {
            let old = self.px[i + k] as u16;
            self.px[i + k] = ((v as u16 * a + old * (255 - a)) / 255) as u8;
        }
    }
}

struct Tour {
    lang: Lang,
    dir: Option<std::path::PathBuf>,
    n: usize,
}

impl Tour {
    fn app(&self) -> App {
        let mut a = App::new(b"tour");
        a.settings.lang = self.lang;
        a.set_test_only(true);
        a.tick(SPLASH_MS);
        a
    }

    /// Render the current screen (panics on overflow) and maybe save it.
    fn snap(&mut self, a: &App, name: &str) {
        let mut c = Shot::new();
        a.render(&mut c);
        self.n += 1;
        if let Some(dir) = &self.dir {
            let lang = ["en", "ko"][self.lang as usize];
            c.save(&dir.join(format!("{lang}-{:03}-{name}.ppm", self.n)));
        }
    }

    fn push_snap(&mut self, a: &mut App, s: Screen, name: &str) {
        a.push(s);
        self.snap(a, name);
        a.pop();
    }
}

fn roll_until_ready(a: &mut App) {
    let mut x = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..400 {
        let pe = a.flow.as_ref().unwrap().entropy.as_ref().unwrap();
        if pe.analyze().all_pass() {
            return;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        press(a, Key::Char((b'1' + (x % 6) as u8) as char));
    }
    panic!("never became ready");
}

fn answer(a: &mut App, wrong_at: Option<usize>) {
    while let Screen::Quiz { .. } = a.current() {
        let q = &a.flow.as_ref().unwrap().quiz;
        let right = q.answer[q.q];
        let choice = if Some(q.q) == wrong_at {
            (right + 1) % 4
        } else {
            right
        };
        press(a, Key::Char((b'1' + choice) as char));
    }
}

fn tour(lang: Lang) -> usize {
    let mut t = Tour {
        lang,
        dir: std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from),
        n: 0,
    };
    if let Some(d) = &t.dir {
        std::fs::create_dir_all(d).unwrap();
    }

    // splash, menus, placeholders, about, power off
    let mut a = App::new(b"tour");
    a.settings.lang = lang;
    a.set_test_only(true);
    t.snap(&a, "splash");
    let mut a = t.app();
    for id in [
        MenuId::Main,
        MenuId::Seeds,
        MenuId::NewSeed,
        MenuId::LoadSeed,
        MenuId::Tools,
        MenuId::Settings,
        MenuId::Power,
    ] {
        let last = menus::table(id).len() as u8 - 1;
        t.push_snap(&mut a, Screen::Menu { id, sel: 0 }, &format!("menu-{id:?}"));
        t.push_snap(
            &mut a,
            Screen::Menu { id, sel: last },
            &format!("menu-{id:?}-last"),
        );
        for e in menus::table(id) {
            if let menus::Action::Todo(label, phase) = e.action {
                let s = a.text();
                t.push_snap(
                    &mut a,
                    Screen::Placeholder {
                        title: label(s),
                        phase: phase(s),
                    },
                    "todo",
                );
            }
        }
    }
    a.settings.advanced = true;
    a.settings.network = bp_bitcoin::Network::Testnet;
    t.push_snap(
        &mut a,
        Screen::Menu {
            id: MenuId::Settings,
            sel: 4,
        },
        "settings-changed",
    );
    t.push_snap(&mut a, Screen::About, "about");
    t.push_snap(&mut a, Screen::PoweredOff, "powered-off");
    for kind in [Start::Dice, Start::Coin, Start::FinalWord] {
        t.push_snap(&mut a, Screen::ChooseWords { kind, sel: 1 }, "choose-words");
    }
    t.push_snap(&mut a, Screen::NoSeed, "no-seed");
    t.push_snap(&mut a, Screen::SlotsFull, "slots-full");

    // dice: intro, entry (empty, some, ready), summary, words, quiz
    let mut a = t.app();
    for k in ['2', '1', '1', '2'] {
        press(&mut a, Key::Char(k));
    }
    t.snap(&a, "dice-intro");
    press(&mut a, Key::Enter);
    t.snap(&a, "dice-entry-empty");
    type_str(&mut a, "3141592653");
    t.snap(&a, "dice-entry-some");
    press(&mut a, Key::Enter);
    t.snap(&a, "dice-not-ready");
    roll_until_ready(&mut a);
    t.snap(&a, "dice-ready");
    for name in ["summary", "words-warning", "words", "quiz-intro", "quiz"] {
        press(&mut a, Key::Enter);
        t.snap(&a, name);
    }
    answer(&mut a, Some(3));
    t.snap(&a, "quiz-failed");
    press(&mut a, Key::Char('1'));
    t.snap(&a, "quiz-retry-words");
    while a.current() != Screen::QuizIntro {
        press(&mut a, Key::Enter);
    }
    press(&mut a, Key::Enter);
    answer(&mut a, None);
    t.snap(&a, "seed-created");

    // coin: intro, entry, failed pattern
    let mut a = t.app();
    for k in ['2', '1', '2', '1'] {
        press(&mut a, Key::Char(k));
    }
    t.snap(&a, "coin-intro");
    press(&mut a, Key::Enter);
    type_str(&mut a, &"HT".repeat(40));
    t.snap(&a, "coin-failed");

    // final word calculator
    let mut a = t.app();
    for k in ['3', '1', '1'] {
        press(&mut a, Key::Char(k));
    }
    t.snap(&a, "final-intro");
    press(&mut a, Key::Enter);
    type_str(&mut a, "aban");
    t.snap(&a, "final-words");
    for _ in 0..10 {
        type_str(&mut a, "aban");
    }
    t.snap(&a, "final-coins-empty");
    type_str(&mut a, "THT");
    t.snap(&a, "final-coins");
    type_str(&mut a, "TTTT");
    press(&mut a, Key::Enter);
    t.snap(&a, "final-result");

    // word entry: typing, numbers, checksum error, confirm cancel
    let mut a = t.app();
    for k in ['2', '2', '1', '1'] {
        press(&mut a, Key::Char(k));
    }
    type_str(&mut a, "zo");
    t.snap(&a, "type-words");
    press(&mut a, Key::Backspace);
    press(&mut a, Key::Backspace);
    type_str(&mut a, "zzz");
    t.snap(&a, "type-words-no-match");
    press(&mut a, Key::Esc);
    t.snap(&a, "confirm-cancel");
    let mut a = t.app();
    for k in ['2', '2', '2', '1'] {
        press(&mut a, Key::Char(k));
    }
    type_str(&mut a, "4000");
    t.snap(&a, "word-numbers");
    let mut a = t.app();
    for k in ['2', '2', '1', '1'] {
        press(&mut a, Key::Char(k));
    }
    for _ in 0..12 {
        type_str(&mut a, "aban");
    }
    t.snap(&a, "checksum-error");

    // a loaded seed: seed screens, xpub, addresses, QR codes
    let mut a = t.app();
    load_abandon(&mut a);
    t.push_snap(
        &mut a,
        Screen::Menu {
            id: MenuId::Seeds,
            sel: 0,
        },
        "seeds-loaded",
    );
    t.push_snap(&mut a, Screen::SeedOptions { slot: 0, sel: 0 }, "seed-options");
    t.push_snap(
        &mut a,
        Screen::SeedReady {
            slot: 0,
            created: false,
        },
        "seed-loaded",
    );
    a.push(Screen::PassphraseEntry { slot: 0 });
    t.snap(&a, "passphrase-empty");
    type_str(&mut a, "Correct horse battery staple");
    t.snap(&a, "passphrase");
    press(&mut a, Key::Enter);
    t.snap(&a, "passphrase-review");
    while a.current()
        != (Screen::Menu {
            id: MenuId::Main,
            sel: 0,
        })
        && a.depth > 1
    {
        press(&mut a, Key::Esc);
    }
    for explorer in [false, true] {
        t.push_snap(
            &mut a,
            Screen::ScriptSelect {
                slot: 0,
                explorer,
                sel: 0,
            },
            "script-select",
        );
    }
    for st in ScriptType::ALL {
        t.push_snap(
            &mut a,
            Screen::XpubView {
                slot: 0,
                st,
                account: 0,
            },
            "xpub",
        );
        t.push_snap(&mut a, Screen::XpubFormat { slot: 0, st, sel: 0 }, "xpub-format");
        let list = Screen::AddressList {
            slot: 0,
            st,
            change: true,
            page: 0,
            sel: 0,
        };
        t.push_snap(&mut a, list, "addresses");
        let detail = Screen::AddressDetail {
            slot: 0,
            st,
            change: false,
            index: 7,
        };
        t.push_snap(&mut a, detail, "address");
    }
    for format in [
        XpubFormat::UrAccount,
        XpubFormat::UrOutput,
        XpubFormat::StaticText,
        XpubFormat::Specter,
    ] {
        let kind = QrKind::Xpub {
            slot: 0,
            st: ScriptType::NativeSegwit,
            account: 0,
            format,
        };
        a.open_qr(kind);
        t.snap(&a, "xpub-qr");
        a.pop();
    }
    t.push_snap(&mut a, Screen::SeedQrSelect { slot: 0, sel: 0 }, "seedqr-select");
    t.push_snap(
        &mut a,
        Screen::SeedQrWarning {
            slot: 0,
            compact: true,
        },
        "seedqr-warning",
    );
    for compact in [false, true] {
        a.open_qr(QrKind::SeedQr { slot: 0, compact });
        t.snap(&a, "seedqr");
        a.pop();
    }
    for line in [false, true] {
        let tr = Screen::Transcribe {
            slot: 0,
            line,
            x: 1,
            y: 1,
        };
        t.push_snap(&mut a, tr, "transcribe");
    }
    t.push_snap(
        &mut a,
        Screen::Confirm {
            what: Confirm::DiscardSeed(0),
            sel: 0,
        },
        "confirm-discard",
    );
    let mut b = t.app();
    load_abandon(&mut b);
    // a second seed: Seeds lists the loaded seed first, so Load seed is 3
    for k in ['2', '3', '1', '1'] {
        press(&mut b, Key::Char(k));
    }
    for w in [
        "lega", "winn", "than", "year", "wave", "saus", "wort", "usef", "lega", "winn", "than", "yell",
    ] {
        type_str(&mut b, w);
    }
    assert!(matches!(b.current(), Screen::SeedReady { .. }));
    t.push_snap(&mut b, Screen::PickSeed { sel: 0 }, "pick-seed");

    // scanning: waiting, results of every kind, seed found, verify, progress
    let mut a = t.app();
    press(&mut a, Key::Char('1'));
    t.snap(&a, "scan-waiting");
    for (text, name) in [
        (&b"HELLO WORLD"[..], "scan-text"),
        (b"bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", "scan-address"),
        (b"[73c5da0a/84h/0h/0h]zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs", "scan-xpub"),
        (b"wsh(sortedmulti(2,[aa/48h/0h/0h/2h]xpub1,[bb]xpub2))", "scan-descriptor"),
        (b"ur:crypto-account/aeaeae", "scan-unknown-ur"),
        (&[0xFF, 0x00, 0x12][..], "scan-binary"),
    ] {
        a.on_qr_text(text);
        t.snap(&a, name);
        press(&mut a, Key::Enter);
        press(&mut a, Key::Char('1'));
    }
    let data = [5u8; 600];
    let enc = bp_qr::ur::UrEncoder::new("bytes", &data, 50).unwrap();
    let mut buf = [0u8; 400];
    let k = enc.part(2, &mut buf).unwrap();
    a.on_qr_text(&buf[..k]);
    t.snap(&a, "scan-progress");
    press(&mut a, Key::Esc);
    press(&mut a, Key::Char('1'));
    a.on_qr_text(ABANDON.as_bytes());
    t.snap(&a, "scan-seed");
    let mut a = t.app();
    for k in ['2', '2', '3'] {
        press(&mut a, Key::Char(k));
    }
    a.on_qr_text(b"HELLO");
    t.snap(&a, "scan-not-a-seed");
    let mut a = t.app();
    load_abandon(&mut a);
    for k in ['5', '1'] {
        press(&mut a, Key::Char(k));
    }
    press(&mut a, Key::Enter);
    press(&mut a, Key::Char('t'));
    press(&mut a, Key::Char('v'));
    let digits = format!("{}0003", "0000".repeat(11));
    a.on_qr_text(digits.as_bytes());
    t.snap(&a, "verify-ok");
    press(&mut a, Key::Enter);
    press(&mut a, Key::Char('v'));
    a.on_qr_text(format!("{}0003", "0000".repeat(23)).as_bytes());
    t.snap(&a, "verify-bad");

    // PSBT review: every step
    let w = W::from_phrase(ABANDON);
    let mut a = t.app();
    load_abandon(&mut a);
    scan_psbt(&mut a, &standard(&w));
    for name in [
        "review-overview",
        "review-output-1",
        "review-output-2",
        "review-fee",
    ] {
        t.snap(&a, name);
        press(&mut a, Key::Enter);
    }
    assert_eq!(step(&a), Step::Approve { sel: 0 });
    t.snap(&a, "review-approve");
    press(&mut a, Key::Up);
    press(&mut a, Key::Enter);
    assert_eq!(step(&a), Step::Signed { sel: 0 });
    t.snap(&a, "review-signed");
    for name in ["signed-ur", "signed-bbqr", "signed-specter"] {
        press(&mut a, Key::Enter);
        t.snap(&a, name);
        press(&mut a, Key::Esc);
        press(&mut a, Key::Down);
    }
    a.review.as_mut().unwrap().error = Some(bp_bitcoin::sign::Error::Changed);
    t.push_snap(&mut a, Screen::Review { step: Step::Failed }, "review-failed");
    let mut a = t.app();
    load_abandon(&mut a);
    scan_psbt(&mut a, &standard(&W::other()));
    t.snap(&a, "review-wrong-seed");
    let mut a = t.app();
    let mut p = standard(&w);
    load_abandon(&mut a);
    p.unsigned_tx.output[1].script_pubkey = W::other().wpkh("m/84'/0'/0'/1/0");
    scan_psbt(&mut a, &p);
    t.snap(&a, "review-attack");
    let mut a = t.app();
    load_abandon(&mut a);
    let p = psbt(
        &w,
        &[(0, 60_000, false), (1, 40_000, false)],
        &[
            (W::other().wpkh("m/84'/0'/0'/0/5"), 60_000, None),
            (w.wpkh("m/84'/0'/0'/1/0"), 39_000, Some(0)),
        ],
    );
    scan_psbt(&mut a, &p);
    t.snap(&a, "review-unverified");
    let mut a = t.app();
    load_abandon(&mut a);
    let p = psbt(
        &w,
        &[(0, 100_000, true)],
        &[(W::other().wpkh("m/84'/0'/0'/0/5"), 94_000, None)],
    );
    scan_psbt(&mut a, &p);
    t.snap(&a, "review-warning");

    // address verification: confirm, searching, found, paused, refusals
    let mut a = t.app();
    load_abandon(&mut a);
    verify_scan(&mut a, &addr_of(&w, false, 0, 1, 7));
    t.snap(&a, "verify-confirm");
    press(&mut a, Key::Enter);
    search_until_done(&mut a);
    t.snap(&a, "verify-found");
    press(&mut a, Key::Enter);
    press(&mut a, Key::Esc);
    verify_scan(&mut a, &addr_of(&W::other(), false, 0, 0, 0));
    press(&mut a, Key::Enter);
    for _ in 0..20 {
        a.tick(16);
    }
    t.snap(&a, "verify-searching");
    press(&mut a, Key::Enter);
    press(&mut a, Key::Esc);
    verify_scan(&mut a, &addr_of(&W::other(), true, 0, 0, 0));
    press(&mut a, Key::Enter);
    a.tick(16);
    press(&mut a, Key::Esc);
    t.snap(&a, "verify-stopped");
    press(&mut a, Key::Enter);
    search_until_done(&mut a);
    t.snap(&a, "verify-paused");
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    for (text, name) in [
        (
            "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
            "verify-wrong-network",
        ),
        (
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            "verify-multisig",
        ),
        ("hello", "verify-not-an-address"),
    ] {
        verify_scan(&mut a, text);
        t.snap(&a, name);
        press(&mut a, Key::Enter);
        press(&mut a, Key::Esc);
    }
    let mut a = t.app();
    press(&mut a, Key::Char('1'));
    a.on_qr_text(b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    t.snap(&a, "verify-no-seed");

    // message signing: off, problems, pages, address, confirm, done, editor
    let mut a = t.app();
    load_abandon(&mut a);
    scan_text(&mut a, "signmessage m/84h/0h/0h/0/0 ascii:hello");
    t.snap(&a, "msg-off");
    press(&mut a, Key::Enter);
    a.settings.msg_signing = true;
    t.push_snap(
        &mut a,
        Screen::Menu {
            id: MenuId::Settings,
            sel: 5,
        },
        "settings-msg-signing",
    );
    for (text, name) in [
        ("signmessage m/84h/1h/0h/0/0 ascii:testnet path", "msg-network"),
        ("signmessage m/84h/0h/0h/0/0 ascii:three   spaces", "msg-rule"),
        (
            "signmessage deadbeef/m/84h/0h/0h/0/0 ascii:other seed",
            "msg-seed-missing",
        ),
        ("signmessage x", "msg-format"),
        ("signmessage m/48h/0h/0h/0/0 ascii:x2", "msg-path"),
    ] {
        scan_text(&mut a, text);
        t.snap(&a, name);
        press(&mut a, Key::Enter);
    }
    let long = (0..30)
        .map(|i| format!("line {i} of a long statement"))
        .collect::<Vec<_>>()
        .join("\n");
    scan_text(&mut a, &format!("signmessage m/86h/0h/0h/0/0 ascii:{long}"));
    t.snap(&a, "msg-page-1");
    while let MsStep::Message { page } = ms(&a) {
        press(&mut a, Key::Enter);
        if page == 0 {
            t.snap(&a, "msg-page-2");
        }
    }
    t.snap(&a, "msg-address");
    press(&mut a, Key::Esc);
    t.snap(&a, "msg-last-page");
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter);
    t.snap(&a, "msg-confirm");
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    t.snap(&a, "msg-done");
    press(&mut a, Key::Enter);
    t.snap(&a, "msg-qr");
    press(&mut a, Key::Esc);
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    press(&mut a, Key::Char('3'));
    press(&mut a, Key::Char('4'));
    type_str(&mut a, "I own this address");
    t.snap(&a, "msg-type");
    type_str(&mut a, "   ");
    press(&mut a, Key::Enter);
    t.snap(&a, "msg-type-rule");
    let mut b = t.app();
    b.settings.msg_signing = true;
    load_abandon(&mut b);
    for k in ['2', '3', '1', '1'] {
        press(&mut b, Key::Char(k));
    }
    for w in [
        "lega", "winn", "than", "year", "wave", "saus", "wort", "usef", "lega", "winn", "than", "yell",
    ] {
        type_str(&mut b, w);
    }
    while !matches!(b.current(), Screen::Menu { id: MenuId::Main, .. }) {
        press(&mut b, Key::Esc);
    }
    scan_text(&mut b, "signmessage m/84h/0h/0h/0/0 ascii:which seed?");
    t.snap(&b, "msg-pick-seed");

    // BIP-322 PSBTs: off, forged, rule, pages, address, proof of reserves
    let mut a = t.app();
    load_abandon(&mut a);
    let p = bip322_psbt(&w, false, "m/84'/0'/0'/0/0", "Hello World", &[]);
    scan_psbt(&mut a, &p);
    t.snap(&a, "bip322-off");
    press(&mut a, Key::Enter);
    a.settings.msg_signing = true;
    let mut f = p.clone();
    f.unknown.insert(
        bitcoin::psbt::raw::Key {
            type_value: 0x09,
            key: vec![],
        },
        b"Send me your coins".to_vec(),
    );
    scan_psbt(&mut a, &f);
    t.snap(&a, "bip322-forged");
    press(&mut a, Key::Enter);
    scan_psbt(&mut a, &bip322_psbt(&w, false, "m/84'/0'/0'/0/0", "a   b", &[]));
    t.snap(&a, "bip322-rule");
    press(&mut a, Key::Enter);
    scan_psbt(
        &mut a,
        &bip322_psbt(&w, true, "m/86'/0'/0'/0/1", "Hello World", &[]),
    );
    t.snap(&a, "bip322-page");
    press(&mut a, Key::Enter);
    t.snap(&a, "bip322-address");
    press(&mut a, Key::Enter);
    t.snap(&a, "bip322-approve");
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    let por = bip322_psbt(
        &w,
        false,
        "m/84'/0'/0'/0/0",
        "Reserves of 2026-11-21",
        &[(&w, "m/84'/0'/0'/0/1", 50_000), (&w, "m/84'/0'/0'/1/0", 25_000)],
    );
    scan_psbt(&mut a, &por);
    t.snap(&a, "por-page");
    press(&mut a, Key::Enter);
    t.snap(&a, "por-address");
    press(&mut a, Key::Enter);
    t.snap(&a, "por-approve");
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    press(&mut a, Key::Esc);
    let ext = bip322_psbt(
        &w,
        false,
        "m/84'/0'/0'/0/0",
        "Reserves",
        &[(&W::other(), "m/84'/0'/0'/0/1", 1)],
    );
    scan_psbt(&mut a, &ext);
    t.snap(&a, "por-external");

    // signature verification
    let mut a = t.app();
    load_abandon(&mut a);
    let smp = "smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";
    scan_text(
        &mut a,
        &armored("Hello World", "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", smp),
    );
    t.snap(&a, "sig-valid");
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    scan_text(
        &mut a,
        &armored("Hello World!", "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", smp),
    );
    t.snap(&a, "sig-invalid");
    press(&mut a, Key::Enter);
    a.settings.network = bp_bitcoin::Network::Testnet;
    let sig = "J3jE1G2pv+6GG35Unak824xig8GzotLE8pFfvNwlgGU7KebANAxo7RuwybCNXrK9+RvjUEohtffM521N+phQNX0=";
    scan_text(
        &mut a,
        &armored("aaaaaaaaaaaaaaaaaa", "mwhrUneshkXh8yUw2L2T16UYCoF3ouy4L2", sig),
    );
    t.snap(&a, "sig-header-warning");
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    scan_text(
        &mut a,
        &armored("aaa", "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", sig),
    );
    t.snap(&a, "sig-wrong-network");
    press(&mut a, Key::Enter);
    press(&mut a, Key::Char('3'));
    press(&mut a, Key::Char('5'));
    t.snap(&a, "sig-scan");
    a.on_qr_text(b"mwhrUneshkXh8yUw2L2T16UYCoF3ouy4L2");
    type_str(&mut a, "aaaaaaaaaaaaaaaaaa");
    t.snap(&a, "sig-type");
    press(&mut a, Key::Enter);
    t.snap(&a, "sig-scan-signature");
    a.on_qr_text(b"hello");
    t.snap(&a, "sig-bad-encoding");
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    press(&mut a, Key::Char('5'));
    a.on_qr_text(b"hello");
    t.snap(&a, "sig-not-signed");

    // settings: fee rows, settings QR, import with blocked items, invalid
    let mut a = t.app();
    a.settings.fee_block = 1;
    t.push_snap(
        &mut a,
        Screen::Menu {
            id: MenuId::Settings,
            sel: 8,
        },
        "settings-fees",
    );
    a.open_qr(QrKind::Settings);
    t.snap(&a, "settings-qr");
    a.pop();
    scan_text(
        &mut a,
        "bitpunk-settings::v1 lang=ko units=btc msg_signing=1 fee_limit=50 fee_warn=10",
    );
    t.snap(&a, "settings-import");
    press(&mut a, Key::Enter);
    scan_text(&mut a, "bitpunk-settings::v1 msg_signing=1");
    t.snap(&a, "settings-import-nothing");
    press(&mut a, Key::Enter);
    scan_text(&mut a, "bitpunk-settings::v1 fee_warn=3");
    t.snap(&a, "settings-import-invalid");

    // D20: intro, entry with a number being typed, ready, summary
    let mut a = t.app();
    for k in ['2', '1', '3', '2'] {
        press(&mut a, Key::Char(k));
    }
    t.snap(&a, "d20-intro");
    press(&mut a, Key::Enter);
    type_str(&mut a, "7 12 20 3 1");
    t.snap(&a, "d20-entry");
    type_str(&mut a, " ");
    let mut x = 0x0bad_c0de_1234_5677u64;
    for _ in 0..300 {
        if a.flow
            .as_ref()
            .unwrap()
            .entropy
            .as_ref()
            .unwrap()
            .analyze()
            .all_pass()
        {
            break;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        type_str(&mut a, &format!("{} ", x % 20 + 1));
    }
    t.snap(&a, "d20-ready");
    press(&mut a, Key::Enter);
    t.snap(&a, "d20-summary");
    wallet_tour(&mut t);
    t.n
}

/// Seeds > Load seed > Type words > 12 words (4-letter prefixes), back to main.
fn load_words(a: &mut App, words: &[&str]) {
    // loaded seeds are listed above the Seeds menu's static rows
    let load = (b'2' + a.seed_count() as u8) as char;
    for k in ['2', load, '1', '1'] {
        press(a, Key::Char(k));
    }
    for w in words {
        type_str(a, &w[..4.min(w.len())]);
    }
    assert!(
        matches!(a.current(), Screen::SeedReady { .. }),
        "{:?}",
        a.current()
    );
    while !matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }) {
        press(a, Key::Esc);
    }
}

fn to_main(a: &mut App) {
    while !matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }) {
        press(a, Key::Esc);
    }
}

/// Multisig wallet screens, including every refusal message and a summary
/// with every warning.
fn wallet_tour(t: &mut Tour) {
    use super::wallets_flow::{descriptor_of, open_wallets, wallet_of};
    use crate::wallets::{Problem, WlStep};
    use bp_bitcoin::bip32::{DerivationPath, KeyVersion, Xpriv as BpXpriv};
    use bp_bitcoin::multisig::register::{Reject, RejectKind};
    use bp_bitcoin::multisig::{formats, Cosigner, MsScript, Wallet};

    let mut a = t.app();
    open_wallets(&mut a);
    t.snap(&a, "wallets-need-seed");

    let mut a = t.app();
    load_abandon(&mut a);
    open_wallets(&mut a);
    t.snap(&a, "wallets-empty");
    press(&mut a, Key::Char('1'));
    t.snap(&a, "wallets-scan");
    // 15 keys, P2SH-P2WSH, a 20-character label
    let w = wallet_of(&a, MsScript::ShWsh, 11, 15);
    let json = format!(
        "{{\"label\": \"WWWWWWWWWWWWWWWWWWWW\", \"descriptor\": \"{}\"}}",
        descriptor_of(&w)
    );
    a.on_qr_text(json.as_bytes());
    t.snap(&a, "wallets-summary");
    press(&mut a, Key::Char('1'));
    t.snap(&a, "wallets-cosigner-1");
    press(&mut a, Key::Right);
    t.snap(&a, "wallets-cosigner-ours");
    for _ in 2..15 {
        press(&mut a, Key::Right);
    }
    t.snap(&a, "wallets-cosigner-15");
    press(&mut a, Key::Right);
    t.snap(&a, "wallets-addresses");
    press(&mut a, Key::Enter);
    t.snap(&a, "wallets-code");
    press(&mut a, Key::Enter);
    t.snap(&a, "wallets-code-entry");
    type_str(&mut a, "0000-0000");
    press(&mut a, Key::Enter);
    t.snap(&a, "wallets-code-mismatch");
    for _ in 0..9 {
        press(&mut a, Key::Backspace);
    }
    type_str(&mut a, "UUUU-UUUU-UUUU");
    press(&mut a, Key::Enter);
    t.snap(&a, "wallets-code-invalid");
    for _ in 0..14 {
        press(&mut a, Key::Backspace);
    }
    let code = a.wl.pending.as_ref().unwrap().code;
    type_str(&mut a, std::str::from_utf8(&code.0).unwrap());
    press(&mut a, Key::Enter);
    t.snap(&a, "wallets-registered");
    press(&mut a, Key::Enter);
    t.snap(&a, "wallets-export");
    for (k, name) in [
        ('1', "wallets-qr-descriptor"),
        ('2', "wallets-qr-specter"),
        ('3', "wallets-qr-coldcard"),
        ('4', "wallets-qr-bbqr"),
    ] {
        press(&mut a, Key::Char(k));
        t.snap(&a, name);
        press(&mut a, Key::Esc);
    }
    press(&mut a, Key::Esc);
    press(&mut a, Key::Down);
    press(&mut a, Key::Enter);
    t.snap(&a, "wallets-list");
    press(&mut a, Key::Char('1'));
    t.snap(&a, "wallets-wallet");
    press(&mut a, Key::Char('1'));
    t.snap(&a, "wallets-keys");
    press(&mut a, Key::Esc);
    press(&mut a, Key::Char('3'));
    t.snap(&a, "wallets-remove");
    press(&mut a, Key::Esc);

    // the re-registration path with a wrong code
    to_main(&mut a);
    open_wallets(&mut a);
    press(&mut a, Key::Char('2'));
    let w2 = wallet_of(&a, MsScript::Wsh, 2, 3);
    a.on_qr_text(descriptor_of(&w2).as_bytes());
    press(&mut a, Key::Char('2'));
    type_str(&mut a, "ZZZZZZZZ");
    press(&mut a, Key::Enter);
    t.snap(&a, "wallets-rereg-mismatch");

    // export with keys on different paths: the Coldcard-file note
    to_main(&mut a);
    let net = a.settings.network;
    let mut keys: Vec<Cosigner> = w2.keys().to_vec();
    let p1 = MsScript::Wsh.account_path(net, 7);
    let mk = BpXpriv::master(&[41; 32]).unwrap();
    keys[0] = Cosigner {
        fingerprint: mk.fingerprint(),
        origin: p1,
        xpub: mk.derive_path(&p1).unwrap().to_xpub(),
        version: KeyVersion::MultiZ,
    };
    let w3 = Wallet::new(w2.test, MsScript::Wsh, 2, &keys).unwrap();
    open_wallets(&mut a);
    press(&mut a, Key::Char('2'));
    a.on_qr_text(descriptor_of(&w3).as_bytes());
    let code = a.wl.pending.as_ref().unwrap().code;
    press(&mut a, Key::Char('2'));
    type_str(&mut a, std::str::from_utf8(&code.0).unwrap());
    press(&mut a, Key::Enter);
    press(&mut a, Key::Enter);
    press(&mut a, Key::Down);
    press(&mut a, Key::Down);
    t.snap(&a, "wallets-export-paths-note");

    // a summary with every warning: two loaded seeds in the wallet, our key
    // and one cosigner off BIP-48, 1-of-3, and the 2-of-3 already registered
    let mut b = t.app();
    load_abandon(&mut b);
    load_words(
        &mut b,
        &[
            "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner",
            "thank", "yellow",
        ],
    );
    let net = b.settings.network;
    let odd = DerivationPath::parse("m/48'/0'/0'/1'").unwrap();
    let std_path = MsScript::Wsh.account_path(net, 0);
    let s0 = b.slot(0).unwrap();
    let s1 = b.slot(1).unwrap();
    let mk = BpXpriv::master(&[77; 32]).unwrap();
    let odd2 = DerivationPath::parse("m/87'/0'/0'").unwrap();
    let keys = vec![
        Cosigner {
            fingerprint: s0.fingerprint,
            origin: odd,
            xpub: s0.master().derive_path(&odd).unwrap().to_xpub(),
            version: KeyVersion::X,
        },
        Cosigner {
            fingerprint: s1.fingerprint,
            origin: std_path,
            xpub: s1.master().derive_path(&std_path).unwrap().to_xpub(),
            version: KeyVersion::X,
        },
        Cosigner {
            fingerprint: mk.fingerprint(),
            origin: odd2,
            xpub: mk.derive_path(&odd2).unwrap().to_xpub(),
            version: KeyVersion::X,
        },
    ];
    let two = Wallet::new(false, MsScript::Wsh, 2, &keys).unwrap();
    let one = Wallet::new(false, MsScript::Wsh, 1, &keys).unwrap();
    open_wallets(&mut b);
    press(&mut b, Key::Char('1'));
    b.on_qr_text(descriptor_of(&two).as_bytes());
    let code = b.wl.pending.as_ref().unwrap().code;
    press(&mut b, Key::Char('2'));
    type_str(&mut b, std::str::from_utf8(&code.0).unwrap());
    press(&mut b, Key::Enter);
    to_main(&mut b);
    open_wallets(&mut b);
    press(&mut b, Key::Char('2'));
    b.on_qr_text(descriptor_of(&one).as_bytes());
    let wn = b.wl.pending.as_ref().unwrap().checked.warnings;
    assert!(wn.our_path && wn.cosigner_paths == 1 && wn.one_of_n && wn.similar.is_some());
    assert!(b.wl.pending.as_ref().unwrap().two_seeds);
    t.snap(&b, "wallets-summary-warnings");
    // duplicate
    to_main(&mut b);
    open_wallets(&mut b);
    press(&mut b, Key::Char('2'));
    b.on_qr_text(descriptor_of(&two).as_bytes());
    t.snap(&b, "wallets-summary-duplicate");
    // verify-only
    let watch = Wallet::new(false, MsScript::Wsh, 1, &keys[2..]).unwrap();
    to_main(&mut b);
    open_wallets(&mut b);
    press(&mut b, Key::Char('2'));
    b.on_qr_text(descriptor_of(&watch).as_bytes());
    t.snap(&b, "wallets-summary-watch-only");

    // every refusal message
    let mut c = t.app();
    load_abandon(&mut c);
    let all_formats = [
        formats::Error::Unknown,
        formats::Error::Descriptor(bp_bitcoin::multisig::descriptor::Error::Syntax),
        formats::Error::Descriptor(bp_bitcoin::multisig::descriptor::Error::Checksum),
        formats::Error::Descriptor(bp_bitcoin::multisig::descriptor::Error::Unsorted),
        formats::Error::Descriptor(bp_bitcoin::multisig::descriptor::Error::UnsupportedScript),
        formats::Error::Descriptor(bp_bitcoin::multisig::descriptor::Error::Threshold),
        formats::Error::Descriptor(bp_bitcoin::multisig::descriptor::Error::TooManyKeys),
        formats::Error::MissingOrigin,
        formats::Error::Key,
        formats::Error::PrivateKey,
        formats::Error::Descriptor(bp_bitcoin::multisig::descriptor::Error::Hardened),
        formats::Error::Descriptor(bp_bitcoin::multisig::descriptor::Error::Suffix),
        formats::Error::Descriptor(bp_bitcoin::multisig::descriptor::Error::MixedSuffix),
        formats::Error::MixedNetwork,
        formats::Error::Descriptor(bp_bitcoin::multisig::descriptor::Error::PathTooDeep),
        formats::Error::ChangeOnly,
        formats::Error::LinesDiffer,
        formats::Error::Policy,
        formats::Error::Derivation,
        formats::Error::ScriptFormat,
        formats::Error::KeyCount,
        formats::Error::Cbor,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (i, e) in all_formats.iter().enumerate() {
        seen.insert(crate::wallets::format_error_index(*e));
        c.wl.problem = Some(Problem::Format(*e));
        t.push_snap(
            &mut c,
            Screen::Wallets {
                step: WlStep::Refused,
            },
            &format!("wallets-refused-format-{i}"),
        );
    }
    assert_eq!(seen.len(), crate::text::WALLET_FORMAT_ERRORS);
    let kinds = [
        RejectKind::OurKeyMismatch,
        RejectKind::OurKeyTwice,
        RejectKind::OurKeyHidden,
        RejectKind::DuplicateKey,
        RejectKind::DuplicateFingerprint,
        RejectKind::Depth,
        RejectKind::ChildNumber,
        RejectKind::ParentFingerprint,
        RejectKind::Network,
        RejectKind::CoinType,
        RejectKind::VersionScript,
    ];
    for (i, k) in kinds.iter().enumerate() {
        c.wl.problem = Some(Problem::Reject(Reject {
            kind: *k,
            key: Some(14),
        }));
        t.push_snap(
            &mut c,
            Screen::Wallets {
                step: WlStep::Refused,
            },
            &format!("wallets-refused-rule-{i}"),
        );
    }
    // not a wallet
    to_main(&mut c);
    open_wallets(&mut c);
    press(&mut c, Key::Char('1'));
    c.on_qr_text(b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    t.snap(&c, "wallets-not-a-wallet");

    // air-gapped creation with two seeds loaded: pick a seed, size, keys
    to_main(&mut b);
    open_wallets(&mut b);
    let n = b.wallets.len() as u8;
    press(&mut b, Key::Char((b'2' + n) as char));
    t.snap(&b, "wallets-pick-seed");
    press(&mut b, Key::Enter);
    t.snap(&b, "wallets-create-size");
    for _ in 0..3 {
        press(&mut b, Key::Down);
    }
    press(&mut b, Key::Right);
    t.snap(&b, "wallets-create-size-account");
    // account -> N: three steps down (the rows wrap)
    for _ in 0..3 {
        press(&mut b, Key::Down);
    }
    for _ in 0..12 {
        press(&mut b, Key::Right);
    }
    assert_eq!(b.wl.creating.as_ref().unwrap().n, 15);
    press(&mut b, Key::Enter);
    t.snap(&b, "wallets-create-keys-1");
    let net = b.settings.network;
    let acct = MsScript::Wsh.account_path(net, 0);
    for i in 0..13u8 {
        let mk = BpXpriv::master(&[i + 100; 32]).unwrap();
        let c = Cosigner {
            fingerprint: mk.fingerprint(),
            origin: acct,
            xpub: mk.derive_path(&acct).unwrap().to_xpub(),
            version: KeyVersion::X,
        };
        let mut buf = [0u8; 256];
        let len = formats::write_key_text(&c, false, &mut buf).unwrap();
        press(&mut b, Key::Enter);
        b.on_qr_text(&buf[..len]);
        if i == 0 {
            t.snap(&b, "wallets-create-confirm");
        }
        press(&mut b, Key::Char('1'));
    }
    t.snap(&b, "wallets-create-keys-14");
    press(&mut b, Key::Enter);
    b.on_qr_text(b"[deadbeef]xpub");
    t.snap(&b, "wallets-create-refused");
    press(&mut b, Key::Enter);
    press(&mut b, Key::Enter);
    b.on_qr_text(b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    t.snap(&b, "wallets-not-a-key");

    // export this device's key
    to_main(&mut c);
    open_wallets(&mut c);
    press(&mut c, Key::Char('3'));
    t.snap(&c, "wallets-key-script");
    press(&mut c, Key::Enter);
    t.snap(&c, "wallets-key-format");
    for (k, name) in [
        ('1', "wallets-key-qr-text"),
        ('2', "wallets-key-qr-ur"),
        ('3', "wallets-key-qr-coldcard"),
    ] {
        press(&mut c, Key::Char(k));
        t.snap(&c, name);
        press(&mut c, Key::Esc);
    }
}

#[test]
fn every_screen_fits_in_every_language() {
    let en = tour(Lang::En);
    let ko = tour(Lang::Ko);
    assert_eq!(en, ko);
    assert!(en > 100, "{en} screens");
}

/// Every issue kind's text fits its screen in every language.
#[test]
fn every_issue_text_fits() {
    for s in [&text::EN, &text::KO] {
        for (title, body) in s.rv.issues {
            let mut c = Shot::new();
            bp_ui::font::TITLE.draw(&mut c, MARGIN_X, 60, title, bp_hal::Rgb(255, 255, 255));
            let end = bp_ui::font::BODY.draw_wrapped(
                &mut c,
                MARGIN_X,
                120,
                800 - 2 * MARGIN_X,
                28,
                5,
                body,
                bp_hal::Rgb(255, 255, 255),
            );
            assert!(end <= 120 + 4 * 28, "{body:?} needs more than 4 lines");
        }
    }
}

const MARGIN_X: i32 = bp_ui::widgets::MARGIN;
