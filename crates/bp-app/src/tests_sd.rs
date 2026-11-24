//! microSD flows with an in-memory card: probing, problems, removal, the
//! power rule (the card is touched only while powered), and the file
//! manager (folders, pages, kinds, text view, delete, format).

use super::*;
use crate::nav::{self, SdRow, To};
use crate::sd::FileAction;
use crate::sd::{sniff, CardProblem, FileKind, SdStep, PAGE};
use bp_hal::{BlockDevice, IoError, SdCard, Sector};
use std::format;
use std::io::{Cursor, Write};
use std::string::String;
use std::vec;
use std::vec::Vec;

/// In-memory card. Panics if accessed while powered off.
pub(super) struct MemCard {
    pub data: Vec<u8>,
    pub present: bool,
    pub powered: bool,
    pub cycles: u32,
}

impl MemCard {
    pub fn blank(bytes: usize) -> Self {
        MemCard {
            data: vec![0; bytes],
            present: true,
            powered: false,
            cycles: 0,
        }
    }

    pub fn image(data: Vec<u8>) -> Self {
        MemCard {
            data,
            present: true,
            powered: false,
            cycles: 0,
        }
    }

    /// A card formatted by our own formatter.
    pub fn formatted(bytes: usize) -> Self {
        let mut c = Self::blank(bytes);
        c.powered = true;
        let mut x = 0x1234_5678u32;
        bp_fat::format(&mut c, &mut |b: &mut [u8]| {
            for v in b.iter_mut() {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                *v = x as u8;
            }
        })
        .unwrap();
        c.powered = false;
        c
    }

    /// Read a file by path from the card (test side, outside the app).
    pub fn file(&mut self, path: &str) -> Option<Vec<u8>> {
        self.powered = true;
        let r = (|| {
            let mut v = bp_fat::Volume::mount(&mut *self).ok()?;
            let e = v.open_path(path).ok()?;
            let mut buf = vec![0u8; e.size() as usize];
            v.read_file(&e, &mut buf).ok()?;
            Some(buf)
        })();
        self.powered = false;
        r
    }
}

impl BlockDevice for MemCard {
    fn sectors(&self) -> u32 {
        (self.data.len() / 512) as u32
    }
    fn read(&mut self, lba: u32, buf: &mut Sector) -> Result<(), IoError> {
        assert!(self.powered, "card read while powered off");
        if !self.present {
            return Err(IoError);
        }
        let at = lba as usize * 512;
        buf.copy_from_slice(self.data.get(at..at + 512).ok_or(IoError)?);
        Ok(())
    }
    fn write(&mut self, lba: u32, buf: &Sector) -> Result<(), IoError> {
        assert!(self.powered, "card written while powered off");
        if !self.present {
            return Err(IoError);
        }
        let at = lba as usize * 512;
        self.data
            .get_mut(at..at + 512)
            .ok_or(IoError)?
            .copy_from_slice(buf);
        Ok(())
    }
}

impl SdCard for MemCard {
    fn present(&self) -> bool {
        self.present
    }
    fn set_power(&mut self, on: bool) {
        if on && !self.powered {
            self.cycles += 1;
        }
        self.powered = on;
    }
}

/// A 16 MB card built with `fatfs` (test-only reference): files of every
/// kind, a folder, hidden files, and folders five levels deep.
pub(super) fn sample_card() -> MemCard {
    let mut img = Cursor::new(vec![0u8; 16 << 20]);
    fatfs::format_volume(
        &mut img,
        fatfs::FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat16),
    )
    .unwrap();
    {
        let fs = fatfs::FileSystem::new(&mut img, fatfs::FsOptions::new()).unwrap();
        let root = fs.root_dir();
        let put = |d: &fatfs::Dir<&mut Cursor<Vec<u8>>>, name: &str, data: &[u8]| {
            d.create_file(name).unwrap().write_all(data).unwrap();
        };
        put(&root, "notes.txt", b"first line\nsecond line\n");
        put(&root, "tx.psbt", b"psbt\xff\x01\x00");
        put(&root, "tx-base64.txt", b"cHNidP8BAHECAAAAAQ");
        put(&root, "bitpunk-settings.txt", b"bitpunk-settings::v1 lang=ko");
        put(
            &root,
            "signed.txt",
            b"-----BEGIN BITCOIN SIGNED MESSAGE-----\nhi\n",
        );
        put(
            &root,
            "wallet.txt",
            b"wsh(sortedmulti(2,[73c5da0a/48h/0h/0h/2h]xpub...))",
        );
        put(&root, "random.bin", &[0u8, 1, 2, 0xFF, 0x80, 7]);
        put(&root, "._apple", b"resource fork");
        put(
            &root,
            "a very long file name that will not fit on one row of the list-signed.psbt",
            b"psbt\xff",
        );
        let sub = root.create_dir("Sub Dir").unwrap();
        put(&sub, "inner.txt", b"inner");
        let mut d = root.create_dir("d1").unwrap();
        for name in ["d2", "d3", "d4", "d5"] {
            d = d.create_dir(name).unwrap();
        }
        put(&d, "deep.txt", b"deep");
    }
    MemCard::image(img.into_inner())
}

/// Run queued card jobs, as the host does after each event.
pub(super) fn serve(a: &mut App, card: &mut MemCard) {
    while a.sd_pending() {
        a.sd_service(card);
        assert!(!card.powered, "card left powered");
    }
}

pub(super) fn sd_press(a: &mut App, card: &mut MemCard, k: Key) {
    press(a, k);
    serve(a, card);
    render(a);
}

/// Pick an action on the open file, by meaning.
fn sd_file(a: &mut App, card: &mut MemCard, f: FileAction) {
    let k = nav::file_action(a, f);
    sd_press(a, card, k);
}

/// The open file's main action (sign, import, or view).
fn sd_file_main(a: &mut App, card: &mut MemCard) {
    let k = nav::file_main(a);
    sd_press(a, card, k);
}

/// Main > SD card.
pub(super) fn open_sd(a: &mut App, card: &mut MemCard) {
    a.set_card_present(card.present);
    nav::go(a, To::SdCard);
    serve(a, card);
    render(a);
}

/// Main > SD card > Browse files.
fn open_browse(a: &mut App, card: &mut MemCard) {
    open_sd(a, card);
    sd_press(a, card, nav::sd_row(SdRow::Browse));
    assert!(matches!(
        a.current(),
        Screen::Sd {
            step: SdStep::Browse { .. }
        }
    ));
}

fn names(a: &App) -> Vec<String> {
    a.sd.list[..a.sd.count]
        .iter()
        .map(|e| String::from(e.unwrap().name()))
        .collect()
}

/// Move the selection to `name` in the listing.
fn select(a: &mut App, card: &mut MemCard, name: &str) {
    let i = names(a)
        .iter()
        .position(|n| n == name)
        .unwrap_or_else(|| panic!("{name} not listed"));
    a.set_current(Screen::Sd {
        step: SdStep::Browse { sel: i as u8 },
    });
    let _ = card;
}

fn step(a: &App) -> SdStep {
    match a.current() {
        Screen::Sd { step } => step,
        s => panic!("not an SD screen: {s:?}"),
    }
}

#[test]
fn probes_a_formatted_card() {
    let mut a = app();
    let mut card = MemCard::formatted(64 << 20);
    open_sd(&mut a, &mut card);
    assert_eq!(step(&a), SdStep::Status { sel: 0 });
    let info = a.sd.card.unwrap().unwrap();
    assert_eq!(info.kind, bp_fat::FatKind::Fat16);
    assert_eq!(info.entries, 0);
    assert!(info.bytes > 60_000_000);
    assert_eq!(card.cycles, 1);
    // Read again: one more power cycle.
    sd_press(&mut a, &mut card, nav::sd_row(SdRow::ReadAgain));
    assert_eq!(card.cycles, 2);
    sd_press(&mut a, &mut card, Key::Esc);
    assert!(matches!(a.current(), Screen::Menu { id: MenuId::Main, .. }));
}

#[test]
fn explains_unusable_cards() {
    let mut a = app();
    let mut none = MemCard::blank(8 << 20);
    none.present = false;
    open_sd(&mut a, &mut none);
    assert_eq!(a.sd.card, Some(Err(CardProblem::NoCard)));
    assert_eq!(none.cycles, 0, "no power without a card");
    // nothing to sign, browse or format
    sd_press(&mut a, &mut none, nav::sd_row(SdRow::SignPsbt));
    assert_eq!(a.notice, Some(a.text().sd.not_ready));
    sd_press(&mut a, &mut none, nav::sd_row(SdRow::Browse));
    assert_eq!(a.notice, Some(a.text().sd.not_ready));
    sd_press(&mut a, &mut none, nav::sd_row(SdRow::Format));
    assert_eq!(step(&a), SdStep::Status { sel: 2 });
    press(&mut a, Key::Esc);

    let mut blank = MemCard::blank(8 << 20);
    open_sd(&mut a, &mut blank);
    assert_eq!(a.sd.card, Some(Err(CardProblem::Blank)));
    press(&mut a, Key::Esc);

    let mut ex = MemCard::blank(8 << 20);
    ex.data[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    ex.data[3..11].copy_from_slice(b"EXFAT   ");
    ex.data[510] = 0x55;
    ex.data[511] = 0xAA;
    open_sd(&mut a, &mut ex);
    assert_eq!(a.sd.card, Some(Err(CardProblem::Exfat)));
    press(&mut a, Key::Esc);

    let mut broken = MemCard::formatted(64 << 20);
    // boot sector: 3 sectors per cluster is not a power of two
    let start = u32::from_le_bytes(broken.data[454..458].try_into().unwrap()) as usize;
    broken.data[start * 512 + 13] = 3;
    open_sd(&mut a, &mut broken);
    assert_eq!(a.sd.card, Some(Err(CardProblem::Damaged)));
}

#[test]
fn removal_and_insertion_are_noticed() {
    let mut a = app();
    let mut card = MemCard::formatted(64 << 20);
    open_sd(&mut a, &mut card);
    assert!(a.sd.card.unwrap().is_ok());
    // pulled out while the screen is open
    card.present = false;
    a.set_card_present(false);
    assert_eq!(a.notice, Some(a.text().sd.removed));
    serve(&mut a, &mut card);
    assert_eq!(a.sd.card, Some(Err(CardProblem::NoCard)));
    // put back
    card.present = true;
    a.set_card_present(true);
    serve(&mut a, &mut card);
    assert!(a.sd.card.unwrap().is_ok());
    // away from the SD screen, presence changes queue nothing
    press(&mut a, Key::Esc);
    a.set_card_present(false);
    assert!(!a.sd_pending());
    assert!(!a.card_present());
}

#[test]
fn badge_follows_the_card() {
    let mut a = app();
    assert!(!a.card_present());
    a.set_card_present(true);
    assert!(a.card_present());
    render(&a);
}

#[test]
fn browses_folders_and_hides_dot_files() {
    let mut a = app();
    let mut card = sample_card();
    open_browse(&mut a, &mut card);
    let root = names(&a);
    assert!(root.contains(&String::from("notes.txt")));
    assert!(root.contains(&String::from("Sub Dir")));
    assert!(!root.iter().any(|n| n.starts_with('.')));
    assert_eq!(a.sd.hidden, 1);
    assert_eq!(a.sd.total as usize, root.len());
    // into "Sub Dir" and back
    select(&mut a, &mut card, "Sub Dir");
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(a.sd.depth, 1);
    assert_eq!(names(&a), ["inner.txt"]);
    sd_press(&mut a, &mut card, Key::Esc);
    assert_eq!(a.sd.depth, 0);
    assert_eq!(names(&a), root);
    // four levels down, then no further
    for d in ["d1", "d2", "d3", "d4"] {
        select(&mut a, &mut card, d);
        sd_press(&mut a, &mut card, Key::Enter);
    }
    assert_eq!(a.sd.depth, 4);
    assert_eq!(names(&a), ["d5"]);
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(a.sd.depth, 4);
    assert_eq!(a.notice, Some(a.text().sd.too_deep));
    for _ in 0..4 {
        sd_press(&mut a, &mut card, Key::Esc);
    }
    assert_eq!(a.sd.depth, 0);
    sd_press(&mut a, &mut card, Key::Esc);
    assert!(matches!(step(&a), SdStep::Status { .. }));
}

#[test]
fn tells_file_kinds_from_content() {
    let mut a = app();
    let mut card = sample_card();
    open_browse(&mut a, &mut card);
    for (name, kind) in [
        ("notes.txt", FileKind::Text),
        ("tx.psbt", FileKind::Psbt),
        ("tx-base64.txt", FileKind::Psbt),
        ("bitpunk-settings.txt", FileKind::Settings),
        ("signed.txt", FileKind::SignedMessage),
        ("wallet.txt", FileKind::Wallet),
        ("random.bin", FileKind::Binary),
    ] {
        select(&mut a, &mut card, name);
        sd_press(&mut a, &mut card, Key::Enter);
        assert_eq!(step(&a), SdStep::File { sel: 0 });
        assert_eq!(a.sd.kind, Some(kind), "{name}");
        // the bytes read to tell the kind are not kept
        assert_eq!(a.sd.view_len, 0);
        assert!(a.sd.view.iter().all(|&b| b == 0));
        sd_press(&mut a, &mut card, Key::Esc);
    }
    assert_eq!(sniff(b"70736274FF0100"), FileKind::Psbt);
    assert_eq!(sniff(b"\xEF\xBB\xBF  cHNidP8B"), FileKind::Psbt);
    assert_eq!(sniff(b"Name: x\nPolicy: 2 of 3\n"), FileKind::Wallet);
    assert_eq!(sniff(b""), FileKind::Text);
}

#[test]
fn text_view_is_wiped_on_close() {
    let mut a = app();
    let mut card = sample_card();
    open_browse(&mut a, &mut card);
    select(&mut a, &mut card, "notes.txt");
    sd_press(&mut a, &mut card, Key::Enter);
    sd_file(&mut a, &mut card, FileAction::View);
    assert_eq!(step(&a), SdStep::Text { top: 0 });
    assert_eq!(&a.sd.view[..a.sd.view_len], b"first line\nsecond line\n");
    sd_press(&mut a, &mut card, Key::Down);
    sd_press(&mut a, &mut card, Key::Esc);
    assert_eq!(step(&a), SdStep::File { sel: 1 });
    assert_eq!(a.sd.view_len, 0);
    assert!(a.sd.view.iter().all(|&b| b == 0));
}

#[test]
fn delete_asks_then_removes() {
    let mut a = app();
    let mut card = sample_card();
    open_browse(&mut a, &mut card);
    select(&mut a, &mut card, "notes.txt");
    sd_press(&mut a, &mut card, Key::Enter);
    sd_file(&mut a, &mut card, FileAction::Delete);
    assert_eq!(step(&a), SdStep::Delete { sel: 0 });
    // Cancel keeps the file
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(step(&a), SdStep::File { sel: 2 });
    assert!(card.file("notes.txt").is_some());
    sd_file(&mut a, &mut card, FileAction::Delete);
    sd_press(&mut a, &mut card, Key::Char('2'));
    assert!(matches!(step(&a), SdStep::Browse { .. }));
    assert_eq!(a.notice, Some(a.text().sd.deleted));
    assert!(card.file("notes.txt").is_none());
    assert!(!names(&a).contains(&String::from("notes.txt")));
    assert!(card.file("tx.psbt").is_some());
}

#[test]
fn long_folders_come_in_pages() {
    let mut img = Cursor::new(vec![0u8; 16 << 20]);
    fatfs::format_volume(
        &mut img,
        fatfs::FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat16),
    )
    .unwrap();
    {
        let fs = fatfs::FileSystem::new(&mut img, fatfs::FsOptions::new()).unwrap();
        let d = fs.root_dir().create_dir("many").unwrap();
        for i in 0..70 {
            d.create_file(&format!("file {i:02}.txt"))
                .unwrap()
                .write_all(b"x")
                .unwrap();
        }
    }
    let mut card = MemCard::image(img.into_inner());
    let mut a = app();
    open_browse(&mut a, &mut card);
    select(&mut a, &mut card, "many");
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!((a.sd.count, a.sd.total), (PAGE, 70));
    let first = names(&a)[0].clone();
    // down past the last row: next page
    a.set_current(Screen::Sd {
        step: SdStep::Browse { sel: PAGE as u8 - 1 },
    });
    sd_press(&mut a, &mut card, Key::Down);
    assert_eq!((a.sd.page, a.sd.count), (1, PAGE));
    sd_press(&mut a, &mut card, Key::Down);
    a.set_current(Screen::Sd {
        step: SdStep::Browse { sel: PAGE as u8 - 1 },
    });
    sd_press(&mut a, &mut card, Key::Down);
    assert_eq!((a.sd.page, a.sd.count), (2, 6));
    // up past the first row: previous page
    a.set_current(Screen::Sd {
        step: SdStep::Browse { sel: 0 },
    });
    sd_press(&mut a, &mut card, Key::Up);
    assert_eq!(a.sd.page, 1);
    assert_eq!(step(&a), SdStep::Browse { sel: PAGE as u8 - 1 });
    a.set_current(Screen::Sd {
        step: SdStep::Browse { sel: 0 },
    });
    sd_press(&mut a, &mut card, Key::Up);
    assert_eq!(names(&a)[0], first);
}

#[test]
fn format_asks_twice() {
    let mut a = app();
    let mut card = MemCard::blank(64 << 20);
    card.data[0] = 0x5A; // old junk
    open_sd(&mut a, &mut card);
    assert_eq!(a.sd.card, Some(Err(CardProblem::Blank)));
    sd_press(&mut a, &mut card, nav::sd_row(SdRow::Format));
    assert_eq!(step(&a), SdStep::Format { stage: 0, sel: 0 });
    // cancel at either question changes nothing
    sd_press(&mut a, &mut card, Key::Char('1'));
    assert!(matches!(step(&a), SdStep::Status { .. }));
    sd_press(&mut a, &mut card, nav::sd_row(SdRow::Format));
    sd_press(&mut a, &mut card, Key::Char('2'));
    assert_eq!(step(&a), SdStep::Format { stage: 1, sel: 0 });
    sd_press(&mut a, &mut card, Key::Esc);
    assert_eq!(card.data[0], 0x5A);
    // both confirmed
    sd_press(&mut a, &mut card, nav::sd_row(SdRow::Format));
    sd_press(&mut a, &mut card, Key::Char('2'));
    sd_press(&mut a, &mut card, Key::Char('2'));
    assert_eq!(step(&a), SdStep::Formatted);
    let info = a.sd.card.unwrap().unwrap();
    assert_eq!(info.kind, bp_fat::FatKind::Fat16);
    sd_press(&mut a, &mut card, Key::Enter);
    assert!(matches!(step(&a), SdStep::Status { .. }));
    assert!(a.sd.card.unwrap().is_ok());
}

#[test]
fn card_changes_close_open_files() {
    let mut a = app();
    let mut card = sample_card();
    open_browse(&mut a, &mut card);
    select(&mut a, &mut card, "notes.txt");
    sd_press(&mut a, &mut card, Key::Enter);
    sd_file(&mut a, &mut card, FileAction::View);
    assert!(a.sd.view_len > 0);
    card.present = false;
    a.set_card_present(false);
    serve(&mut a, &mut card);
    assert!(matches!(step(&a), SdStep::Browse { .. }));
    assert_eq!(a.sd.view_len, 0);
    assert_eq!(a.sd.list_err, Some(CardProblem::NoCard));
    render(&a);
}

/// Every SD screen in both languages (layout check), saved as pictures
/// when `BP_SHOTS` is set.
#[test]
pub(crate) fn sd_screens_fit() {
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(format!("sd-{l}-{name}.ppm")));
            }
        };
        let mut a = app();
        a.settings.lang = lang;
        a.set_test_only(true);
        let mut card = sample_card();
        open_browse(&mut a, &mut card);
        shot(&a, "browse");
        a.set_current(Screen::Sd {
            step: SdStep::Browse { sel: 9 },
        });
        shot(&a, "browse-scrolled");
        select(
            &mut a,
            &mut card,
            "a very long file name that will not fit on one row of the list-signed.psbt",
        );
        sd_press(&mut a, &mut card, Key::Enter);
        shot(&a, "file-long-name");
        sd_file(&mut a, &mut card, FileAction::Delete);
        shot(&a, "delete");
        sd_press(&mut a, &mut card, Key::Esc);
        sd_press(&mut a, &mut card, Key::Esc);
        select(&mut a, &mut card, "wallet.txt");
        sd_press(&mut a, &mut card, Key::Enter);
        sd_file(&mut a, &mut card, FileAction::View);
        shot(&a, "text");
        sd_press(&mut a, &mut card, Key::Esc);
        sd_press(&mut a, &mut card, Key::Esc);
        for d in ["d1", "d2", "d3", "d4"] {
            select(&mut a, &mut card, d);
            sd_press(&mut a, &mut card, Key::Enter);
        }
        sd_press(&mut a, &mut card, Key::Enter);
        shot(&a, "too-deep");
        for _ in 0..5 {
            sd_press(&mut a, &mut card, Key::Esc);
        }
        shot(&a, "status");
        sd_press(&mut a, &mut card, nav::sd_row(SdRow::SignPsbt));
        shot(&a, "psbt-list-empty");
        sd_press(&mut a, &mut card, Key::Esc);
        sd_press(&mut a, &mut card, nav::sd_row(SdRow::Format));
        shot(&a, "format-1");
        sd_press(&mut a, &mut card, Key::Char('2'));
        shot(&a, "format-2");
        sd_press(&mut a, &mut card, Key::Char('2'));
        shot(&a, "formatted");
        sd_press(&mut a, &mut card, Key::Enter);
        sd_press(&mut a, &mut card, nav::sd_row(SdRow::Browse));
        shot(&a, "empty");
    }
}

// ---------- PSBT and message files (M8-5) ----------

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// A card with the standard PSBT in three encodings, an already signed
/// one, a message file, an oversized and a broken PSBT.
fn psbt_card(p: &RefPsbt) -> MemCard {
    let raw = p.serialize();
    let mut img = Cursor::new(vec![0u8; 16 << 20]);
    fatfs::format_volume(
        &mut img,
        fatfs::FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat16),
    )
    .unwrap();
    {
        let fs = fatfs::FileSystem::new(&mut img, fatfs::FsOptions::new()).unwrap();
        let root = fs.root_dir();
        let put = |name: &str, data: &[u8]| root.create_file(name).unwrap().write_all(data).unwrap();
        put("tx.psbt", &raw);
        // Base64 in lines with CRLF, as some wallets write it
        let text = b64(&raw);
        let wrapped: Vec<String> = text
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        put("tx64.txt", format!("{}\r\n", wrapped.join("\r\n")).as_bytes());
        put("txhex.hex", format!("{}\n", hex(&raw).to_uppercase()).as_bytes());
        put("old-signed.psbt", &raw);
        put("message.txt", b"hello from the card\nm/84h/0h/0h/0/0\n");
        let mut big = raw.clone();
        big.resize(130 * 1024, 0);
        put("big.psbt", &big);
        put("bad.txt", b"cHNidP8B!!not base64!!");
    }
    MemCard::image(img.into_inner())
}

/// Main > SD card > Sign PSBT.
fn open_psbt_list(a: &mut App, card: &mut MemCard) {
    open_sd(a, card);
    sd_press(a, card, nav::sd_row(SdRow::SignPsbt));
    assert!(matches!(step(a), SdStep::PsbtList { .. }));
}

/// From the review's first screen to "Signed".
fn approve(a: &mut App, card: &mut MemCard) {
    assert_eq!(super::step(a), Step::Overview);
    for _ in 0..4 {
        sd_press(a, card, Key::Enter);
    }
    sd_press(a, card, Key::Down);
    sd_press(a, card, Key::Enter);
    assert_eq!(super::step(a), Step::Signed { sel: 0 });
}

/// The saved file: the original with one valid signature added.
fn check_signed_file(w: &W, p: &RefPsbt, data: &[u8]) {
    let out = RefPsbt::deserialize(data).unwrap();
    assert_eq!(out.unsigned_tx, p.unsigned_tx);
    // everything of the original kept
    assert_eq!(out.outputs, p.outputs);
    assert_eq!(out.inputs[0].witness_utxo, p.inputs[0].witness_utxo);
    assert_eq!(out.inputs[0].non_witness_utxo, p.inputs[0].non_witness_utxo);
    assert_eq!(out.inputs[0].bip32_derivation, p.inputs[0].bip32_derivation);
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
    // the same as combining the original with the signature
    let mut want = p.clone();
    want.inputs[0]
        .partial_sigs
        .insert(bitcoin::PublicKey::new(pk), sig);
    assert_eq!(out, want);
}

#[test]
fn signs_psbt_files_and_saves_the_full_psbt() {
    let w = W::from_phrase(ABANDON);
    let p = standard(&w);
    let mut card = psbt_card(&p);
    let mut a = app();
    load_abandon(&mut a);
    open_psbt_list(&mut a, &mut card);
    let listed = names(&a);
    for n in ["tx.psbt", "tx64.txt", "txhex.hex", "big.psbt"] {
        assert!(listed.contains(&String::from(n)), "{n} in {listed:?}");
    }
    // signed files and messages are left out (bad.txt starts like a
    // Base64 PSBT: listed, refused when read)
    for n in ["old-signed.psbt", "message.txt"] {
        assert!(!listed.contains(&String::from(n)), "{n}");
    }
    let mut saved = Vec::new();
    for (file, out) in [
        ("tx.psbt", "tx-signed.psbt"),
        ("tx64.txt", "tx64-signed.psbt"),
        ("txhex.hex", "txhex-signed.psbt"),
    ] {
        select(&mut a, &mut card, file);
        a.set_current(Screen::Sd {
            step: SdStep::PsbtList {
                sel: names(&a).iter().position(|n| n == file).unwrap() as u8,
            },
        });
        sd_press(&mut a, &mut card, Key::Enter);
        approve(&mut a, &mut card);
        assert!(a.review.as_ref().unwrap().from_sd);
        sd_press(&mut a, &mut card, Key::Enter); // Save to SD card
        assert_eq!(step(&a), SdStep::Saved { sel: 0 });
        let s = a.sd.saved.unwrap().unwrap();
        assert_eq!(s.name.as_str(), out);
        assert!(!s.wiped);
        let data = card.file(out).unwrap();
        check_signed_file(&w, &p, &data);
        saved.push(data);
        // Done: back to the refreshed list, buffers wiped
        sd_press(&mut a, &mut card, Key::Enter);
        assert!(matches!(step(&a), SdStep::PsbtList { .. }));
        assert!(a.review.is_none() && a.sd.origin.is_none());
        assert!(a.scan.out.iter().all(|&b| b == 0) && a.scan.work().iter().all(|&b| b == 0));
        assert!(!names(&a).iter().any(|n| n.contains("-signed")));
    }
    // the three encodings give the same signed PSBT
    assert!(saved.windows(2).all(|w| w[0] == w[1]));
    // signing the same file again never replaces the first result
    a.set_current(Screen::Sd {
        step: SdStep::PsbtList {
            sel: names(&a).iter().position(|n| n == "tx.psbt").unwrap() as u8,
        },
    });
    sd_press(&mut a, &mut card, Key::Enter);
    approve(&mut a, &mut card);
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(a.sd.saved.unwrap().unwrap().name.as_str(), "tx-signed-2.psbt");
    assert_eq!(card.file("tx-signed.psbt").unwrap(), saved[0]);
}

#[test]
fn refuses_large_and_broken_psbt_files() {
    let w = W::from_phrase(ABANDON);
    let mut card = psbt_card(&standard(&w));
    let mut a = app();
    load_abandon(&mut a);
    open_psbt_list(&mut a, &mut card);
    let i = names(&a).iter().position(|n| n == "big.psbt").unwrap();
    a.set_current(Screen::Sd {
        step: SdStep::PsbtList { sel: i as u8 },
    });
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(a.notice, Some(a.text().sd.too_large));
    assert!(matches!(step(&a), SdStep::PsbtList { .. }));
    assert!(a.scan.out.iter().all(|&b| b == 0));
    // a broken one opened from the file manager
    sd_press(&mut a, &mut card, Key::Esc);
    sd_press(&mut a, &mut card, nav::sd_row(SdRow::Browse));
    select(&mut a, &mut card, "bad.txt");
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(a.sd.kind, Some(FileKind::Psbt));
    sd_file_main(&mut a, &mut card);
    assert_eq!(a.notice, Some(a.text().sd.bad_encoding));
    assert!(matches!(step(&a), SdStep::File { .. }));
}

#[test]
fn wipes_the_original_when_asked() {
    let w = W::from_phrase(ABANDON);
    let p = standard(&w);
    let mut card = psbt_card(&p);
    let mut a = app();
    load_abandon(&mut a);
    a.settings.sd_wipe_original = true;
    open_psbt_list(&mut a, &mut card);
    let i = names(&a).iter().position(|n| n == "tx.psbt").unwrap();
    a.set_current(Screen::Sd {
        step: SdStep::PsbtList { sel: i as u8 },
    });
    sd_press(&mut a, &mut card, Key::Enter);
    approve(&mut a, &mut card);
    sd_press(&mut a, &mut card, Key::Enter);
    let s = a.sd.saved.unwrap().unwrap();
    assert!(s.wiped);
    assert!(card.file("tx.psbt").is_none());
    check_signed_file(&w, &p, &card.file("tx-signed.psbt").unwrap());
    // the original's bytes are gone from the card image
    let raw = p.serialize();
    let count = card
        .data
        .windows(raw.len())
        .filter(|x| *x == raw.as_slice())
        .count();
    assert_eq!(count, 2, "only old-signed.psbt and big.psbt still hold them");
}

#[test]
fn a_pulled_card_can_be_saved_to_again() {
    let w = W::from_phrase(ABANDON);
    let p = standard(&w);
    let mut card = psbt_card(&p);
    let mut a = app();
    load_abandon(&mut a);
    open_psbt_list(&mut a, &mut card);
    let i = names(&a).iter().position(|n| n == "tx.psbt").unwrap();
    a.set_current(Screen::Sd {
        step: SdStep::PsbtList { sel: i as u8 },
    });
    sd_press(&mut a, &mut card, Key::Enter);
    approve(&mut a, &mut card);
    card.present = false;
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(a.sd.saved, Some(Err(crate::sdfile::SaveProblem::NoCard)));
    // still signed, in memory: put the card back and try again
    card.present = true;
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(a.sd.saved.unwrap().unwrap().name.as_str(), "tx-signed.psbt");
    check_signed_file(&w, &p, &card.file("tx-signed.psbt").unwrap());
    // or cancel: back to the signed screen
    sd_press(&mut a, &mut card, Key::Enter);
}

#[test]
fn signs_message_files_and_saves_the_signature() {
    let w = W::from_phrase(ABANDON);
    let mut card = psbt_card(&standard(&w));
    let mut a = app();
    load_abandon(&mut a);
    a.settings.msg_signing = true;
    open_browse(&mut a, &mut card);
    select(&mut a, &mut card, "message.txt");
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(a.sd.kind, Some(FileKind::Text));
    sd_file_main(&mut a, &mut card); // Sign message
    assert!(matches!(a.current(), Screen::MsgSign { .. }), "{:?}", a.current());
    sd_press(&mut a, &mut card, Key::Enter); // message page
    sd_press(&mut a, &mut card, Key::Enter); // address
    sd_press(&mut a, &mut card, Key::Char('2')); // sign
    assert!(matches!(
        a.current(),
        Screen::MsgSign {
            step: crate::msgsign::MsStep::Done { .. }
        }
    ));
    sd_press(&mut a, &mut card, Key::Char('1')); // Save to SD card
    assert_eq!(a.sd.saved.unwrap().unwrap().name.as_str(), "message.sig");
    let sig = card.file("message.sig").unwrap();
    let armored = bp_bitcoin::message::parse_armored(&sig).unwrap();
    assert_eq!(armored.message, b"hello from the card");
    assert_eq!(armored.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert!(bp_bitcoin::message::verify(
        armored.address,
        bp_bitcoin::Network::Mainnet,
        armored.message,
        armored.signature
    )
    .is_ok());
    sd_press(&mut a, &mut card, Key::Enter);
    assert!(matches!(step(&a), SdStep::Browse { .. }));
    assert!(names(&a).contains(&String::from("message.sig")));
    assert!(a.msg.is_none());
}

#[test]
fn psbt_file_helpers() {
    use crate::sdfile::{message_request, signed_stem, Decoder, LoadError};
    let net = bp_bitcoin::Network::Mainnet;
    let mut out = [0u8; 256];
    let n = message_request(b"signmessage m/84h/0h/0h/0/5 ascii:hi\r\nignored", net, &mut out);
    assert_eq!(&out[..n], b"signmessage m/84h/0h/0h/0/5 ascii:hi");
    let n = message_request(b"\xEF\xBB\xBFjust a message\n", net, &mut out);
    assert_eq!(&out[..n], b"signmessage m/84h/0h/0h/0/0 ascii:just a message");
    let n = message_request(
        b"msg\nm/44h/1h/0h/0/2\nP2PKH\n",
        bp_bitcoin::Network::Signet,
        &mut out,
    );
    assert_eq!(&out[..n], b"signmessage m/44h/1h/0h/0/2 ascii:msg");
    let n = message_request(b"msg\n\n", bp_bitcoin::Network::Signet, &mut out);
    assert_eq!(&out[..n], b"signmessage m/84h/1h/0h/0/0 ascii:msg");

    assert_eq!(signed_stem("tx.psbt", None).as_str(), "tx-signed");
    assert_eq!(signed_stem("tx-signed-2.psbt", None).as_str(), "tx-signed");
    assert_eq!(
        signed_stem("tx.psbt", Some([0x73, 0xc5, 0xda, 0x0a])).as_str(),
        "tx-signed-73c5da0a"
    );
    assert_eq!(signed_stem("??.psbt", None).as_str(), "__-signed");
    assert_eq!(
        signed_stem(".psbt", None).as_str(),
        "_psbt-signed".replace("_psbt", ".psbt").as_str()
    );

    let decode = |data: &[u8]| -> Result<Vec<u8>, LoadError> {
        let mut out = vec![0u8; 64];
        let mut d = Decoder::detect(data)?;
        for chunk in data.chunks(3) {
            d.feed(chunk, &mut out)?;
        }
        let n = d.finish()?;
        Ok(out[..n].to_vec())
    };
    let raw = b"psbt\xff\x01\x00\x02";
    assert_eq!(decode(raw).unwrap(), raw);
    assert_eq!(decode(b"70736274FF01 0002\n").unwrap(), raw);
    assert_eq!(decode(b"cHNidP8BAAI=\n").unwrap(), raw);
    assert_eq!(decode(b" cHNi\r\ndP8B\r\nAAI").unwrap(), raw);
    assert_eq!(decode(b"70736274ff010").err(), Some(LoadError::Encoding));
    assert_eq!(decode(b"cHNidP8BAAI=x").err(), Some(LoadError::Encoding));
    assert_eq!(decode(b"cHNidP8BAAI===").err(), Some(LoadError::Encoding));
    assert_eq!(decode(b"cHNidP8BA").err(), Some(LoadError::Encoding));
    assert_eq!(decode(b"hello").err(), Some(LoadError::Encoding));
    assert_eq!(
        decode(&[b"psbt\xff".as_slice(), &[0u8; 70]].concat()).err(),
        Some(LoadError::TooLarge)
    );
}

/// The signing screens of SD files in both languages (layout check, and
/// pictures when `BP_SHOTS` is set).
#[test]
pub(crate) fn sd_signing_screens_fit() {
    let w = W::from_phrase(ABANDON);
    let p = standard(&w);
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(format!("sd-{l}-{name}.ppm")));
            }
        };
        let mut card = psbt_card(&p);
        let mut a = app();
        load_abandon(&mut a);
        a.settings.lang = lang;
        a.settings.msg_signing = true;
        a.set_test_only(true);
        open_psbt_list(&mut a, &mut card);
        shot(&a, "psbt-list");
        let i = names(&a).iter().position(|n| n == "big.psbt").unwrap();
        a.set_current(Screen::Sd {
            step: SdStep::PsbtList { sel: i as u8 },
        });
        sd_press(&mut a, &mut card, Key::Enter);
        shot(&a, "psbt-too-large");
        let i = names(&a).iter().position(|n| n == "tx.psbt").unwrap();
        a.set_current(Screen::Sd {
            step: SdStep::PsbtList { sel: i as u8 },
        });
        sd_press(&mut a, &mut card, Key::Enter);
        approve(&mut a, &mut card);
        shot(&a, "signed-sd");
        card.present = false;
        sd_press(&mut a, &mut card, Key::Enter);
        shot(&a, "save-failed");
        card.present = true;
        a.settings.sd_wipe_original = true;
        sd_press(&mut a, &mut card, Key::Enter);
        shot(&a, "saved-wiped");
        sd_press(&mut a, &mut card, Key::Enter);
        sd_press(&mut a, &mut card, Key::Esc);
        sd_press(&mut a, &mut card, nav::sd_row(SdRow::Browse));
        select(&mut a, &mut card, "message.txt");
        sd_press(&mut a, &mut card, Key::Enter);
        shot(&a, "file-text");
        sd_file_main(&mut a, &mut card);
        sd_press(&mut a, &mut card, Key::Enter);
        sd_press(&mut a, &mut card, Key::Enter);
        sd_press(&mut a, &mut card, Key::Char('2'));
        shot(&a, "msg-done-sd");
        sd_press(&mut a, &mut card, Key::Char('1'));
        shot(&a, "saved");
    }
}

// ---------- wallet, key and settings files (M8-6) ----------

/// A formatted card, the "abandon" seed loaded, the card inserted.
fn export_setup() -> (App, MemCard) {
    let mut a = app();
    load_abandon(&mut a);
    let card = MemCard::formatted(64 << 20);
    a.set_card_present(true);
    (a, card)
}

/// On a QR screen: S saves the export; returns the saved file name.
fn save_qr(a: &mut App, card: &mut MemCard, kind: QrKind) -> String {
    a.open_qr(kind);
    assert!(matches!(a.current(), Screen::QrShow { .. }));
    render(a);
    sd_press(a, card, Key::Char('s'));
    assert!(matches!(step(a), SdStep::Saved { .. }), "{:?}", a.current());
    let name = String::from(a.sd.saved.unwrap().unwrap().name.as_str());
    sd_press(a, card, Key::Enter);
    assert!(matches!(a.current(), Screen::QrShow { .. }), "back to the QR");
    sd_press(a, card, Key::Esc);
    name
}

#[test]
fn qr_exports_save_as_files() {
    let (mut a, mut card) = export_setup();
    let st = bp_bitcoin::address::ScriptType::NativeSegwit;
    let name = save_qr(
        &mut a,
        &mut card,
        QrKind::Xpub {
            slot: 0,
            st,
            account: 0,
            format: XpubFormat::UrAccount,
        },
    );
    assert_eq!(name, "bitpunk-73c5da0a.json");
    let json = String::from_utf8(card.file(&name).unwrap()).unwrap();
    assert!(json.contains("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"));
    assert!(json.contains("\"bip86\""));
    // the same export again gets a number
    let again = save_qr(
        &mut a,
        &mut card,
        QrKind::Xpub {
            slot: 0,
            st,
            account: 0,
            format: XpubFormat::StaticText,
        },
    );
    assert_eq!(again, "bitpunk-73c5da0a-2.json");

    let kind = QrKind::MsKey {
        slot: 0,
        script: bp_bitcoin::multisig::MsScript::Wsh,
        account: 0,
        format: crate::wallets::KeyFormat::Text,
    };
    let name = save_qr(&mut a, &mut card, kind);
    assert_eq!(name, "ccxp-73c5da0a.json");
    let json = String::from_utf8(card.file(&name).unwrap()).unwrap();
    assert!(json.contains("\"p2wsh_deriv\": \"m/48'/0'/0'/2'\"") && json.contains("\"xfp\": \"73C5DA0A\""));

    let name = save_qr(&mut a, &mut card, QrKind::Settings);
    assert_eq!(name, "bitpunk-settings.txt");
    let text = card.file(&name).unwrap();
    assert!(text.starts_with(crate::settings::PREFIX.as_bytes()));

    // never a SeedQR or a signed result
    for k in [
        QrKind::SeedQr {
            slot: 0,
            compact: false,
        },
        QrKind::MessageSig,
        QrKind::SignedPsbt {
            format: PsbtFormat::Ur,
        },
    ] {
        assert!(!a.export_allowed(k));
    }
    // no card: a note, nothing written
    card.present = false;
    a.set_card_present(false);
    a.open_qr(QrKind::Settings);
    sd_press(&mut a, &mut card, Key::Char('s'));
    assert!(matches!(a.current(), Screen::QrShow { .. }));
    assert_eq!(a.notice, Some(a.text().sd.problems[0][0]));
    render(&a);
}

#[test]
fn wallet_files_round_trip_and_tags_register() {
    use bp_bitcoin::multisig::MsScript;
    let (mut a, mut card) = export_setup();
    let w = super::wallets_flow::wallet_of(&a, MsScript::Wsh, 2, 3);
    super::wallets_flow::register_quick(&mut a, &w);
    assert_eq!(a.wallets.len(), 1);
    let (idx, e) = a.wallets.iter().next().map(|(i, e)| (i as u8, *e)).unwrap();
    let wname = String::from(a.wallet_name(&e).as_str());
    // Export > Bitpunk wallet file (row 5)
    a.push(Screen::Wallets {
        step: crate::wallets::WlStep::Export { idx, sel: 0 },
    });
    sd_press(&mut a, &mut card, Key::Char('5'));
    let bpw = String::from(a.sd.saved.unwrap().unwrap().name.as_str());
    assert_eq!(bpw, format!("{wname}.bpw"));
    sd_press(&mut a, &mut card, Key::Enter);
    let desc = save_qr(
        &mut a,
        &mut card,
        QrKind::Wallet {
            idx,
            format: crate::wallets::WalletFormat::Descriptor,
        },
    );
    assert_eq!(desc, format!("{wname}-descriptor.txt"));
    let cc = save_qr(
        &mut a,
        &mut card,
        QrKind::Wallet {
            idx,
            format: crate::wallets::WalletFormat::ColdcardUr,
        },
    );
    assert_eq!(cc, format!("{wname}-coldcard.txt"));
    let bpw_text = card.file(&bpw).unwrap();
    assert!(bpw_text.starts_with(b"# Bitpunk wallet v1"));

    // a new session: the .bpw registers without the code
    let mut b = app();
    load_abandon(&mut b);
    b.set_card_present(true);
    open_browse(&mut b, &mut card);
    select(&mut b, &mut card, &bpw);
    sd_press(&mut b, &mut card, Key::Enter);
    assert_eq!(b.sd.kind, Some(FileKind::Wallet));
    sd_file_main(&mut b, &mut card); // Import wallet
    assert!(
        matches!(
            b.current(),
            Screen::Wallets {
                step: crate::wallets::WlStep::Registered { .. }
            }
        ),
        "{:?}",
        b.current()
    );
    assert_eq!(b.notice, Some(b.text().sd.registered_from_file));
    let (_, e2) = b.wallets.iter().next().unwrap();
    assert_eq!(e2.wallet.id(), w.id());
    assert_eq!(e2.code, e.code);
    assert_eq!(b.wallet_name(e2).as_str(), wname);
    render(&b);

    // the descriptor file goes through the normal import (checks)
    let mut c = app();
    load_abandon(&mut c);
    c.set_card_present(true);
    open_browse(&mut c, &mut card);
    select(&mut c, &mut card, &desc);
    sd_press(&mut c, &mut card, Key::Enter);
    sd_file_main(&mut c, &mut card);
    assert!(matches!(
        c.current(),
        Screen::Wallets {
            step: crate::wallets::WlStep::Summary { .. }
        }
    ));
    assert!(c.wallets.is_empty());
}

#[test]
fn tampered_wallet_files_do_not_register() {
    use bp_bitcoin::multisig::MsScript;
    let (mut a, _card) = export_setup();
    let w = super::wallets_flow::wallet_of(&a, MsScript::Wsh, 2, 3);
    super::wallets_flow::register_quick(&mut a, &w);
    let (idx, _) = a.wallets.iter().next().map(|(i, e)| (i as u8, *e)).unwrap();
    let mut buf = [0u8; 8192];
    let (_, n) = a.wallet_bpw(idx, &mut buf).unwrap();
    let good = String::from_utf8(buf[..n].to_vec()).unwrap();
    let lines: Vec<String> = good.lines().map(String::from).collect();
    // another tag (as if made with another seed): normal import, the code is asked
    let mut tag = lines[3].clone().into_bytes();
    tag[10] = if tag[10] == b'0' { b'1' } else { b'0' };
    let other_tag = good.replace(&lines[3], &String::from_utf8(tag).unwrap());
    // a code that does not belong to the tag
    let other_code = good.replace(&lines[2], "code: AAAA-AAAA");
    // a broken descriptor checksum
    let mut d = lines[4].clone();
    d.pop();
    d.push('q');
    let bad_desc = good.replace(&lines[4], &d);
    for (text, want_summary) in [(other_tag, true), (other_code, true), (bad_desc, false)] {
        let mut b = app();
        load_abandon(&mut b);
        b.wallet_import_file(text.as_bytes());
        assert!(b.wallets.is_empty(), "{text}");
        let st = match b.current() {
            Screen::Wallets { step } => step,
            s => panic!("{s:?}"),
        };
        if want_summary {
            assert!(matches!(st, crate::wallets::WlStep::Summary { .. }), "{st:?}");
        } else {
            assert_eq!(st, crate::wallets::WlStep::Refused);
        }
        render(&b);
    }
}

#[test]
fn settings_files_never_weaken() {
    let (mut a, mut card) = export_setup();
    a.settings.lang = crate::settings::Lang::En;
    let name = save_qr(&mut a, &mut card, QrKind::Settings);
    // edit the file: Korean (harmless) and message signing on (refused)
    let text = String::from_utf8(card.file(&name).unwrap()).unwrap();
    let edited = text
        .replace("lang=en", "lang=ko")
        .replace("msg_signing=0", "msg_signing=1");
    card.powered = true;
    {
        let mut v = bp_fat::Volume::mount(&mut card).unwrap();
        let e = v.find(bp_fat::DirId::Root, &name).unwrap();
        v.delete(&e).unwrap();
        v.create(bp_fat::DirId::Root, &name, edited.as_bytes()).unwrap();
    }
    card.powered = false;
    let mut b = app();
    b.set_card_present(true);
    open_browse(&mut b, &mut card);
    select(&mut b, &mut card, &name);
    sd_press(&mut b, &mut card, Key::Enter);
    assert_eq!(b.sd.kind, Some(FileKind::Settings));
    sd_file_main(&mut b, &mut card); // Import settings
    assert_eq!(b.current(), Screen::SettingsImport { sel: 0 });
    render(&b);
    let imp = b.import.as_ref().unwrap().as_ref().unwrap();
    assert!(imp.blocked.any());
    // Apply
    sd_press(&mut b, &mut card, Key::Down);
    sd_press(&mut b, &mut card, Key::Enter);
    assert_eq!(b.settings.lang, crate::settings::Lang::Ko);
    assert!(!b.settings.msg_signing, "never turned on from a file");
    assert!(matches!(step(&b), SdStep::File { .. }));
}

/// Export and import screens in both languages (layout check, pictures
/// with `BP_SHOTS`).
#[test]
pub(crate) fn sd_export_screens_fit() {
    use bp_bitcoin::multisig::MsScript;
    for lang in [crate::settings::Lang::En, crate::settings::Lang::Ko] {
        let dir = std::env::var_os("BP_SHOTS").map(std::path::PathBuf::from);
        let shot = |a: &App, name: &str| {
            let mut c = super::layout::Shot::new();
            a.render(&mut c);
            if let Some(d) = &dir {
                let l = ["en", "ko"][lang as usize];
                c.save(&d.join(format!("sd-{l}-{name}.ppm")));
            }
        };
        let (mut a, mut card) = export_setup();
        a.settings.lang = lang;
        a.set_test_only(true);
        a.open_qr(QrKind::Xpub {
            slot: 0,
            st: bp_bitcoin::address::ScriptType::NativeSegwit,
            account: 0,
            format: XpubFormat::UrAccount,
        });
        shot(&a, "qr-save");
        sd_press(&mut a, &mut card, Key::Char('s'));
        shot(&a, "qr-saved");
        sd_press(&mut a, &mut card, Key::Enter);
        sd_press(&mut a, &mut card, Key::Esc);
        let w = super::wallets_flow::wallet_of(&a, MsScript::Wsh, 2, 3);
        super::wallets_flow::register_quick(&mut a, &w);
        let idx = a.wallets.iter().next().map(|(i, _)| i as u8).unwrap();
        a.push(Screen::Wallets {
            step: crate::wallets::WlStep::Export { idx, sel: 4 },
        });
        shot(&a, "wallet-export");
        sd_press(&mut a, &mut card, Key::Enter);
        sd_press(&mut a, &mut card, Key::Enter);
        let mut b = app();
        load_abandon(&mut b);
        b.settings.lang = lang;
        b.set_card_present(true);
        open_browse(&mut b, &mut card);
        let bpw = names(&b).into_iter().find(|n| n.ends_with(".bpw")).unwrap();
        select(&mut b, &mut card, &bpw);
        sd_press(&mut b, &mut card, Key::Enter);
        shot(&b, "file-wallet");
        sd_file_main(&mut b, &mut card);
        shot(&b, "registered-from-file");
    }
}

// ---------- attacks and fuzzing (M8-10) ----------

/// Seed words in a text file are only text: no action loads them.
#[test]
fn seed_words_in_a_file_are_never_loaded() {
    let mut img = Cursor::new(vec![0u8; 16 << 20]);
    fatfs::format_volume(
        &mut img,
        fatfs::FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat16),
    )
    .unwrap();
    {
        let fs = fatfs::FileSystem::new(&mut img, fatfs::FsOptions::new()).unwrap();
        let words =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n";
        fs.root_dir()
            .create_file("my seed.txt")
            .unwrap()
            .write_all(words.as_bytes())
            .unwrap();
    }
    let mut card = MemCard::image(img.into_inner());
    let mut a = app();
    open_browse(&mut a, &mut card);
    select(&mut a, &mut card, "my seed.txt");
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(a.sd.kind, Some(FileKind::Text));
    // every action: sign message (refused: message signing is off), view, delete
    sd_file_main(&mut a, &mut card);
    sd_press(&mut a, &mut card, Key::Esc);
    assert_eq!(a.seed_count(), 0, "never a seed from the card");
}

/// Random damage to a card with every kind of file: browsing, telling
/// kinds, listing PSBTs and opening them never panic.
#[test]
fn fuzz_damaged_cards_through_the_app() {
    let w = W::from_phrase(ABANDON);
    let base = psbt_card(&standard(&w)).data;
    let meta_end = {
        let mut c = MemCard::image(base.clone());
        c.powered = true;
        let v = bp_fat::Volume::mount(&mut c).unwrap();
        let g = *v.geometry();
        (g.data_start as usize + 64 * g.sectors_per_cluster as usize) * 512
    };
    let mut x = 0x5eed_1234_u64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut a = app();
    load_abandon(&mut a);
    for _ in 0..150 {
        let mut data = base.clone();
        for _ in 0..1 + next() % 6 {
            let at = (next() % meta_end as u64) as usize;
            data[at] = next() as u8;
        }
        let mut card = MemCard::image(data);
        a.reset_to(Screen::Menu {
            id: MenuId::Main,
            sel: 0,
        });
        a.set_card_present(true);
        nav::go(&mut a, To::SdCard);
        serve(&mut a, &mut card);
        sd_press(&mut a, &mut card, nav::sd_row(SdRow::SignPsbt)); // PSBT list
        if matches!(
            a.current(),
            Screen::Sd {
                step: SdStep::PsbtList { .. }
            }
        ) && a.sd.count > 0
        {
            sd_press(&mut a, &mut card, Key::Enter);
            for _ in 0..8 {
                sd_press(&mut a, &mut card, Key::Esc);
            }
        }
        a.reset_to(Screen::Menu {
            id: MenuId::Main,
            sel: 0,
        });
        nav::go(&mut a, To::SdCard);
        serve(&mut a, &mut card);
        sd_press(&mut a, &mut card, nav::sd_row(SdRow::Browse)); // browse
        for i in 0..4u8 {
            if !matches!(
                a.current(),
                Screen::Sd {
                    step: SdStep::Browse { .. }
                }
            ) || a.sd.count == 0
            {
                break;
            }
            a.set_current(Screen::Sd {
                step: SdStep::Browse {
                    sel: i % a.sd.count as u8,
                },
            });
            sd_press(&mut a, &mut card, Key::Enter);
            sd_file(&mut a, &mut card, FileAction::View);
            sd_press(&mut a, &mut card, Key::Esc);
            sd_press(&mut a, &mut card, Key::Esc);
        }
    }
}

/// The streaming PSBT decoder and the .bpw parser on random input.
#[test]
fn fuzz_file_decoders() {
    use crate::sdfile::Decoder;
    let mut x = 0xdec0_de42_u64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let alphabet = b"cHNidP8BAAI=+/ \r\n70736274ffABCDEFabcdef0123456789\xEF\xBB\xBF";
    let mut out = vec![0u8; 512];
    for _ in 0..3000 {
        let n = (next() % 200) as usize;
        let mut data: Vec<u8> = (0..n)
            .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
            .collect();
        if next() % 3 == 0 {
            data.splice(0..0, *b"cHNidP");
        }
        if let Ok(mut d) = Decoder::detect(&data) {
            for chunk in data.chunks(1 + (next() % 17) as usize) {
                if d.feed(chunk, &mut out).is_err() {
                    break;
                }
            }
            let _ = d.finish();
        }
        let _ = bp_bitcoin::multisig::formats::parse_bpw(&data);
        let mut bpw = b"# Bitpunk wallet v1\nname: x\ncode: ".to_vec();
        bpw.extend_from_slice(&data);
        let _ = bp_bitcoin::multisig::formats::parse_bpw(&bpw);
        let _ = crate::sd::sniff(&data);
        let _ = crate::sdfile::message_request(&data, bp_bitcoin::Network::Mainnet, &mut [0u8; 300]);
    }
}

/// M8 output baseline: every file the device writes to the card.
pub(super) fn golden(out: &mut String) {
    use super::rec;
    let file = |out: &mut String, card: &mut MemCard, key: &str, name: &str| {
        rec(out, &format!("{key}.name"), name.as_bytes());
        rec(out, &format!("{key}.file"), &card.file(name).unwrap());
    };
    // a signed PSBT file
    let w = W::from_phrase(ABANDON);
    let mut card = psbt_card(&standard(&w));
    let mut a = app();
    load_abandon(&mut a);
    a.settings.msg_signing = true;
    open_psbt_list(&mut a, &mut card);
    a.set_current(Screen::Sd {
        step: SdStep::PsbtList {
            sel: names(&a).iter().position(|n| n == "tx.psbt").unwrap() as u8,
        },
    });
    sd_press(&mut a, &mut card, Key::Enter);
    approve(&mut a, &mut card);
    sd_press(&mut a, &mut card, Key::Enter); // Save to SD card
    let name = String::from(a.sd.saved.unwrap().unwrap().name.as_str());
    file(out, &mut card, "sd.psbt", &name);
    sd_press(&mut a, &mut card, Key::Enter);
    // a signed message file
    open_browse(&mut a, &mut card);
    select(&mut a, &mut card, "message.txt");
    sd_press(&mut a, &mut card, Key::Enter);
    sd_file_main(&mut a, &mut card);
    sd_press(&mut a, &mut card, Key::Enter); // message page
    sd_press(&mut a, &mut card, Key::Enter); // address
    sd_press(&mut a, &mut card, Key::Char('2')); // sign
    sd_press(&mut a, &mut card, Key::Char('1')); // Save to SD card
    let name = String::from(a.sd.saved.unwrap().unwrap().name.as_str());
    file(out, &mut card, "sd.message", &name);
    // QR exports saved as files, and the wallet files
    let (mut a, mut card) = export_setup();
    for (key, kind) in [
        (
            "sd.xpub",
            QrKind::Xpub {
                slot: 0,
                st: ScriptType::NativeSegwit,
                account: 0,
                format: XpubFormat::UrAccount,
            },
        ),
        (
            "sd.mskey",
            QrKind::MsKey {
                slot: 0,
                script: bp_bitcoin::multisig::MsScript::Wsh,
                account: 0,
                format: crate::wallets::KeyFormat::ColdcardJson,
            },
        ),
        ("sd.settings", QrKind::Settings),
    ] {
        let name = save_qr(&mut a, &mut card, kind);
        file(out, &mut card, key, &name);
    }
    let wl = super::wallets_flow::wallet_of(&a, bp_bitcoin::multisig::MsScript::Wsh, 2, 3);
    super::wallets_flow::register_quick(&mut a, &wl);
    let idx = a.wallets.iter().next().map(|(i, _)| i as u8).unwrap();
    for format in [
        crate::wallets::WalletFormat::Descriptor,
        crate::wallets::WalletFormat::ColdcardUr,
    ] {
        let name = save_qr(&mut a, &mut card, QrKind::Wallet { idx, format });
        file(out, &mut card, &format!("sd.wallet.{format:?}"), &name);
    }
    a.push(Screen::Wallets {
        step: crate::wallets::WlStep::Export { idx, sel: 0 },
    });
    sd_press(&mut a, &mut card, Key::Char('5')); // Bitpunk wallet file
    let name = String::from(a.sd.saved.unwrap().unwrap().name.as_str());
    file(out, &mut card, "sd.bpw", &name);
}
