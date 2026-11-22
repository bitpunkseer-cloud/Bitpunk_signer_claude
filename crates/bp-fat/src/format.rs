//! Formatting a card: one MBR partition, FAT16 below 2 GB, FAT32 above
//! (the SD Association's choice for SDSC / SDHC cards).

use crate::geometry::FatKind;
use crate::{BlockDevice, Error, Sector, SECTOR};

const LABEL: &[u8; 11] = b"BITPUNK    ";
const OEM: &[u8; 8] = b"BITPUNK ";
/// Smallest card we format (4 MiB).
const MIN_SECTORS: u32 = 8192;
/// FAT32 from 2 GiB up.
const FAT32_FROM: u32 = 4 * 1024 * 1024;

fn put16(s: &mut [u8], at: usize, v: u32) {
    s[at..at + 2].copy_from_slice(&(v as u16).to_le_bytes());
}

fn put32(s: &mut [u8], at: usize, v: u32) {
    s[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

struct Layout {
    kind: FatKind,
    start: u32,
    sectors: u32,
    spc: u32,
    reserved: u32,
    root_entries: u32,
    fat_size: u32,
}

fn layout(total: u32) -> Result<Layout, Error> {
    if total < MIN_SECTORS {
        return Err(Error::TooSmall);
    }
    // Partition aligned to 4 MiB on real cards, 1 MiB on small ones.
    let start = if total >= 1 << 21 { 8192 } else { 2048 };
    let sectors = total - start;
    let kind = if sectors >= FAT32_FROM {
        FatKind::Fat32
    } else {
        FatKind::Fat16
    };
    let (reserved, root_entries) = match kind {
        FatKind::Fat16 => (1, 512),
        FatKind::Fat32 => (32, 0),
    };
    let root_sectors = root_entries * 32 / SECTOR as u32;
    let fat_size = |spc: u32| {
        // Microsoft's FAT size formula.
        let tmp1 = (sectors - reserved - root_sectors) as u64;
        let mut tmp2 = 256 * spc as u64 + 2;
        if kind == FatKind::Fat32 {
            tmp2 /= 2;
        }
        tmp1.div_ceil(tmp2) as u32
    };
    let clusters = |spc: u32, fsz: u32| (sectors - reserved - 2 * fsz - root_sectors) / spc;
    let spc = match kind {
        FatKind::Fat32 => match sectors {
            s if s < 16 << 20 => 8,
            s if s < 32 << 20 => 16,
            s if s < 64 << 20 => 32,
            _ => 64,
        },
        FatKind::Fat16 => {
            let mut spc = 1;
            while clusters(spc, fat_size(spc)) >= 65525 && spc < 64 {
                spc *= 2;
            }
            spc
        }
    };
    let fsz = fat_size(spc);
    let n = clusters(spc, fsz);
    let ok = match kind {
        FatKind::Fat16 => (4085..65525).contains(&n),
        FatKind::Fat32 => (65525..0x0FFF_FFF5).contains(&n),
    };
    if !ok {
        return Err(Error::TooSmall);
    }
    Ok(Layout {
        kind,
        start,
        sectors,
        spc,
        reserved,
        root_entries,
        fat_size: fsz,
    })
}

fn boot_sector(l: &Layout, serial: u32) -> Sector {
    let mut s = [0u8; SECTOR];
    let fat32 = l.kind == FatKind::Fat32;
    s[0] = 0xEB;
    s[1] = if fat32 { 0x58 } else { 0x3C };
    s[2] = 0x90;
    s[3..11].copy_from_slice(OEM);
    put16(&mut s, 11, SECTOR as u32);
    s[13] = l.spc as u8;
    put16(&mut s, 14, l.reserved);
    s[16] = 2;
    put16(&mut s, 17, l.root_entries);
    if !fat32 && l.sectors < 0x10000 {
        put16(&mut s, 19, l.sectors);
    } else {
        put32(&mut s, 32, l.sectors);
    }
    s[21] = 0xF8;
    put16(&mut s, 24, 63);
    put16(&mut s, 26, 255);
    put32(&mut s, 28, l.start);
    let ext = if fat32 {
        put32(&mut s, 36, l.fat_size);
        put32(&mut s, 44, 2);
        put16(&mut s, 48, 1);
        put16(&mut s, 50, 6);
        64
    } else {
        put16(&mut s, 22, l.fat_size);
        36
    };
    s[ext] = 0x80;
    s[ext + 2] = 0x29;
    put32(&mut s, ext + 3, serial);
    s[ext + 7..ext + 18].copy_from_slice(LABEL);
    s[ext + 18..ext + 26].copy_from_slice(if fat32 { b"FAT32   " } else { b"FAT16   " });
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

/// Erase the card's partition table and file system and make a fresh
/// FAT volume. `random` fills buffers from the hardware RNG: it scrambles
/// the area before the partition and picks the disk and volume serials.
/// Old file contents in the data area are not erased.
pub fn format<D: BlockDevice>(dev: &mut D, random: &mut dyn FnMut(&mut [u8])) -> Result<FatKind, Error> {
    let l = layout(dev.sectors())?;
    let mut s: Sector = [0; SECTOR];
    for lba in 1..l.start {
        random(&mut s);
        dev.write(lba, &s)?;
    }
    let mut ids = [0u8; 8];
    random(&mut ids);
    let disk_id = u32::from_le_bytes([ids[0], ids[1], ids[2], ids[3]]);
    let serial = u32::from_le_bytes([ids[4], ids[5], ids[6], ids[7]]);
    let zero: Sector = [0; SECTOR];
    // Reserved area, both FATs and the root directory.
    let root_sectors = l.root_entries * 32 / SECTOR as u32;
    let meta = l.reserved + 2 * l.fat_size + root_sectors;
    for k in 0..meta {
        dev.write(l.start + k, &zero)?;
    }
    let fat32 = l.kind == FatKind::Fat32;
    let data_start = l.start + meta;
    if fat32 {
        for k in 0..l.spc {
            dev.write(data_start + k, &zero)?;
        }
    }
    // FAT heads: media byte, end-of-chain marker, FAT32 root cluster.
    let mut head = zero;
    if fat32 {
        put32(&mut head, 0, 0x0FFF_FFF8);
        put32(&mut head, 4, 0x0FFF_FFFF);
        put32(&mut head, 8, 0x0FFF_FFFF);
    } else {
        put16(&mut head, 0, 0xFFF8);
        put16(&mut head, 2, 0xFFFF);
    }
    for copy in 0..2 {
        dev.write(l.start + l.reserved + copy * l.fat_size, &head)?;
    }
    // Volume label as the first root entry.
    let mut root = zero;
    root[..11].copy_from_slice(LABEL);
    root[11] = 0x08;
    let root_lba = if fat32 {
        data_start
    } else {
        l.start + l.reserved + 2 * l.fat_size
    };
    dev.write(root_lba, &root)?;
    let boot = boot_sector(&l, serial);
    if fat32 {
        let clusters = (l.sectors - meta) / l.spc;
        let mut info = zero;
        put32(&mut info, 0, 0x4161_5252);
        put32(&mut info, 484, 0x6141_7272);
        put32(&mut info, 488, clusters - 1);
        put32(&mut info, 492, 3);
        put32(&mut info, 508, 0xAA55_0000);
        dev.write(l.start + 1, &info)?;
        dev.write(l.start + 7, &info)?;
        dev.write(l.start + 6, &boot)?;
    }
    dev.write(l.start, &boot)?;
    // Partition table last: until here the card has no valid layout.
    let mut mbr = zero;
    put32(&mut mbr, 440, disk_id);
    let p = 446;
    mbr[p + 1..p + 4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    mbr[p + 4] = if fat32 { 0x0C } else { 0x0E };
    mbr[p + 5..p + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    put32(&mut mbr, p + 8, l.start);
    put32(&mut mbr, p + 12, l.sectors);
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    dev.write(0, &mbr)?;
    Ok(l.kind)
}
