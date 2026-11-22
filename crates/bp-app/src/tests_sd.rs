//! microSD flows with an in-memory card: probing, problems, removal, and
//! the power rule (the card is touched only while powered).

use super::*;
use crate::sd::{CardProblem, SdStep};
use bp_hal::{BlockDevice, IoError, SdCard, Sector};
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
}

/// Main > SD card.
pub(super) fn open_sd(a: &mut App, card: &mut MemCard) {
    a.set_card_present(card.present);
    sd_press(a, card, Key::Char('5'));
}

#[test]
fn probes_a_formatted_card() {
    let mut a = app();
    let mut card = MemCard::formatted(64 << 20);
    open_sd(&mut a, &mut card);
    assert_eq!(
        a.current(),
        Screen::Sd {
            step: SdStep::Status { sel: 0 }
        }
    );
    let info = a.sd.card.unwrap().unwrap();
    assert_eq!(info.kind, bp_fat::FatKind::Fat16);
    assert_eq!(info.entries, 0);
    assert!(info.bytes > 60_000_000);
    assert_eq!(card.cycles, 1);
    render(&a);
    // Read again: one more power cycle.
    sd_press(&mut a, &mut card, Key::Enter);
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
    render(&a);
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
    render(&a);
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
