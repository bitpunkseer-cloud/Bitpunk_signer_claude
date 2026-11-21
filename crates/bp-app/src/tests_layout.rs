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
    t.n
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
