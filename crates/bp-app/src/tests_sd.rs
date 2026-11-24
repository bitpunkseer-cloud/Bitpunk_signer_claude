//! microSD flows with an in-memory card: probing, problems, removal, the
//! power rule (the card is touched only while powered), and the file
//! manager (folders, pages, kinds, text view, delete, format).

use super::*;
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

/// Main > SD card.
pub(super) fn open_sd(a: &mut App, card: &mut MemCard) {
    a.set_card_present(card.present);
    sd_press(a, card, Key::Char('5'));
}

/// Main > SD card > Browse files.
fn open_browse(a: &mut App, card: &mut MemCard) {
    open_sd(a, card);
    sd_press(a, card, Key::Char('2'));
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
    sd_press(&mut a, &mut card, Key::Char('4'));
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
    sd_press(&mut a, &mut none, Key::Char('1'));
    assert_eq!(a.notice, Some(a.text().sd.not_ready));
    sd_press(&mut a, &mut none, Key::Char('2'));
    assert_eq!(a.notice, Some(a.text().sd.not_ready));
    sd_press(&mut a, &mut none, Key::Char('3'));
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
    sd_press(&mut a, &mut card, Key::Char('2'));
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
    sd_press(&mut a, &mut card, Key::Char('3'));
    assert_eq!(step(&a), SdStep::Delete { sel: 0 });
    // Cancel keeps the file
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(step(&a), SdStep::File { sel: 2 });
    assert!(card.file("notes.txt").is_some());
    sd_press(&mut a, &mut card, Key::Char('3'));
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
    sd_press(&mut a, &mut card, Key::Char('3'));
    assert_eq!(step(&a), SdStep::Format { stage: 0, sel: 0 });
    // cancel at either question changes nothing
    sd_press(&mut a, &mut card, Key::Char('1'));
    assert!(matches!(step(&a), SdStep::Status { .. }));
    sd_press(&mut a, &mut card, Key::Char('3'));
    sd_press(&mut a, &mut card, Key::Char('2'));
    assert_eq!(step(&a), SdStep::Format { stage: 1, sel: 0 });
    sd_press(&mut a, &mut card, Key::Esc);
    assert_eq!(card.data[0], 0x5A);
    // both confirmed
    sd_press(&mut a, &mut card, Key::Char('3'));
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
    sd_press(&mut a, &mut card, Key::Char('2'));
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
fn sd_screens_fit() {
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
        sd_press(&mut a, &mut card, Key::Char('3'));
        shot(&a, "delete");
        sd_press(&mut a, &mut card, Key::Esc);
        sd_press(&mut a, &mut card, Key::Esc);
        select(&mut a, &mut card, "wallet.txt");
        sd_press(&mut a, &mut card, Key::Enter);
        sd_press(&mut a, &mut card, Key::Char('1'));
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
        sd_press(&mut a, &mut card, Key::Char('1'));
        shot(&a, "psbt-list-empty");
        sd_press(&mut a, &mut card, Key::Esc);
        sd_press(&mut a, &mut card, Key::Char('3'));
        shot(&a, "format-1");
        sd_press(&mut a, &mut card, Key::Char('2'));
        shot(&a, "format-2");
        sd_press(&mut a, &mut card, Key::Char('2'));
        shot(&a, "formatted");
        sd_press(&mut a, &mut card, Key::Enter);
        sd_press(&mut a, &mut card, Key::Char('2'));
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
    sd_press(a, card, Key::Char('1'));
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
    sd_press(&mut a, &mut card, Key::Char('2'));
    select(&mut a, &mut card, "bad.txt");
    sd_press(&mut a, &mut card, Key::Enter);
    assert_eq!(a.sd.kind, Some(FileKind::Psbt));
    sd_press(&mut a, &mut card, Key::Char('1'));
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
    sd_press(&mut a, &mut card, Key::Char('1')); // Sign message
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
fn sd_signing_screens_fit() {
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
        sd_press(&mut a, &mut card, Key::Char('2'));
        select(&mut a, &mut card, "message.txt");
        sd_press(&mut a, &mut card, Key::Enter);
        shot(&a, "file-text");
        sd_press(&mut a, &mut card, Key::Char('1'));
        sd_press(&mut a, &mut card, Key::Enter);
        sd_press(&mut a, &mut card, Key::Enter);
        sd_press(&mut a, &mut card, Key::Char('2'));
        shot(&a, "msg-done-sd");
        sd_press(&mut a, &mut card, Key::Char('1'));
        shot(&a, "saved");
    }
}
