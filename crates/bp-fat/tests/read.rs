//! Reading images made by the `fatfs` crate (outside reference).

mod common;

use bp_fat::{Corrupt, DirId, Error, FatKind, Unsupported, Volume, SECTOR};
use common::*;
use std::io::Cursor;

fn check_against_fatfs(img: Vec<u8>, kind: FatKind) {
    let mut cur = Cursor::new(img.clone());
    let fs = fatfs::FileSystem::new(&mut cur, fatfs::FsOptions::new()).unwrap();
    let mut disk = MemDisk::new(img);
    let mut vol = Volume::mount(&mut disk).unwrap();
    assert_eq!(vol.geometry().kind, kind);
    let n = compare_tree(&mut vol, DirId::Root, &fs.root_dir());
    assert!(n > 80, "{n} entries");
}

#[test]
fn fat32_matches_fatfs() {
    check_against_fatfs(sample(fatfs::FatType::Fat32, 64 << 20, Some(512)), FatKind::Fat32);
}

#[test]
fn fat32_large_clusters_match_fatfs() {
    check_against_fatfs(
        sample(fatfs::FatType::Fat32, 300 << 20, Some(4096)),
        FatKind::Fat32,
    );
}

#[test]
fn fat16_matches_fatfs() {
    check_against_fatfs(sample(fatfs::FatType::Fat16, 16 << 20, None), FatKind::Fat16);
}

#[test]
fn fat16_small_clusters_match_fatfs() {
    check_against_fatfs(sample(fatfs::FatType::Fat16, 8 << 20, Some(512)), FatKind::Fat16);
}

#[test]
fn reads_inside_mbr_partition() {
    let vol = sample(fatfs::FatType::Fat32, 64 << 20, Some(512));
    for kind in [0x0B, 0x0C] {
        let mut disk = MemDisk::new(partitioned(&vol, 8192, kind));
        let mut v = Volume::mount(&mut disk).unwrap();
        assert_eq!(v.geometry().start, 8192);
        let e = v.open_path("Sub Dir/deeper/d3/d4/deep.txt").unwrap();
        let mut buf = [0u8; 64];
        let n = v.read_file(&e, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"four levels down");
    }
}

#[test]
fn names_hidden_and_non_ascii() {
    let mut disk = MemDisk::new(sample(fatfs::FatType::Fat16, 16 << 20, None));
    let mut vol = Volume::mount(&mut disk).unwrap();
    assert!(vol.find(DirId::Root, "._resource").unwrap().is_hidden());
    assert!(vol.find(DirId::Root, ".Trashes").unwrap().is_hidden());
    assert!(!vol.find(DirId::Root, "hello.txt").unwrap().is_hidden());
    // Non-ASCII long names are shown with '?' and remain readable.
    let k = vol.find(DirId::Root, "??.psbt").unwrap();
    let mut buf = [0u8; 32];
    let n = vol.read_file(&k, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"korean name");
    // Case-insensitive lookup, and by 8.3 name.
    assert!(vol.find(DirId::Root, "HELLO.TXT").is_ok());
    assert!(vol.find(DirId::Root, "upper.txt").is_ok());
    let long = vol
        .find(DirId::Root, "A long file name with spaces.psbt")
        .unwrap();
    let short: String = {
        let raw = long.short_raw();
        let base = String::from_utf8_lossy(&raw[..8]).trim_end().to_string();
        let ext = String::from_utf8_lossy(&raw[8..]).trim_end().to_string();
        format!("{base}.{ext}")
    };
    assert!(vol
        .find(DirId::Root, &short)
        .unwrap()
        .matches("a long FILE name with spaces.psbt"));
    assert_eq!(vol.find(DirId::Root, "nope"), Err(Error::NotFound));
}

#[test]
fn read_at_offsets_and_too_large() {
    let mut disk = MemDisk::new(sample(fatfs::FatType::Fat32, 64 << 20, Some(512)));
    let mut vol = Volume::mount(&mut disk).unwrap();
    let e = vol.open_path("Sub Dir/deeper/x.bin").unwrap();
    let mut all = vec![0u8; e.size() as usize];
    vol.read_file(&e, &mut all).unwrap();
    for off in [0u32, 1, 511, 512, 513, 4095, 50_000, 99_999] {
        let mut part = [0u8; 700];
        let n = vol.read_at(&e, off, &mut part).unwrap();
        let end = (off as usize + 700).min(all.len());
        assert_eq!(&part[..n], &all[off as usize..end], "offset {off}");
    }
    assert_eq!(vol.read_at(&e, 100_000, &mut [0u8; 4]).unwrap(), 0);
    let mut small = [0u8; 1000];
    assert_eq!(vol.read_file(&e, &mut small), Err(Error::TooLarge));
    let d = vol.find(DirId::Root, "Sub Dir").unwrap();
    assert_eq!(vol.read_file(&d, &mut small), Err(Error::NotAFile));
    let f = vol.find(DirId::Root, "hello.txt").unwrap();
    assert_eq!(vol.open_dir(&f), Err(Error::NotADirectory));
    let empty = vol.find(DirId::Root, "empty.bin").unwrap();
    assert_eq!(vol.read_file(&empty, &mut small), Ok(0));
}

#[test]
fn refuses_other_file_systems() {
    // Blank card.
    let mut blank = MemDisk::new(vec![0u8; 4 << 20]);
    assert_eq!(Volume::mount(&mut blank).err(), Some(Error::NoFilesystem));
    // exFAT boot sector, bare and inside a partition.
    let mut ex = vec![0u8; 4 << 20];
    ex[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    ex[3..11].copy_from_slice(b"EXFAT   ");
    ex[510] = 0x55;
    ex[511] = 0xAA;
    assert_eq!(
        Volume::mount(&mut MemDisk::new(ex.clone())).err(),
        Some(Error::Unsupported(Unsupported::Exfat))
    );
    let mut part = partitioned(&ex[..1 << 20], 2048, 0x07);
    part.resize(4 << 20, 0);
    assert_eq!(
        Volume::mount(&mut MemDisk::new(part)).err(),
        Some(Error::Unsupported(Unsupported::Exfat))
    );
    // GPT protective MBR.
    let mut gpt = partitioned(&[0u8; 1 << 20], 1, 0xEE);
    gpt.resize(4 << 20, 0);
    assert_eq!(
        Volume::mount(&mut MemDisk::new(gpt)).err(),
        Some(Error::Unsupported(Unsupported::Gpt))
    );
    // FAT12 (tiny volume).
    let tiny = format(1 << 20, fatfs::FatType::Fat12, None).into_inner();
    assert_eq!(
        Volume::mount(&mut MemDisk::new(tiny)).err(),
        Some(Error::Unsupported(Unsupported::Fat12))
    );
    // Partition running past the end of the card.
    let vol = sample(fatfs::FatType::Fat16, 16 << 20, None);
    let mut short = partitioned(&vol, 2048, 0x0E);
    short.truncate(short.len() - SECTOR);
    assert_eq!(
        Volume::mount(&mut MemDisk::new(short)).err(),
        Some(Error::Corrupt(Corrupt::Geometry))
    );
}

/// Volumes formatted by `mkfs.fat` (dosfstools), populated with `fatfs`.
/// Skipped when dosfstools is not installed.
#[test]
fn mkfs_fat_volumes_match_fatfs() {
    let dir = env!("CARGO_TARGET_TMPDIR");
    for (fat, kb, spc) in [
        ("16", 16 * 1024, "4"),
        ("32", 64 * 1024, "1"),
        ("32", 300 * 1024, "8"),
    ] {
        let path = format!("{dir}/mkfs-{fat}-{spc}.img");
        let _ = std::fs::remove_file(&path);
        let status = std::process::Command::new("mkfs.fat")
            .args([
                "-C",
                "-F",
                fat,
                "-s",
                spc,
                "-n",
                "BITPUNK",
                &path,
                &kb.to_string(),
            ])
            .output();
        match status {
            Ok(o) if o.status.success() => {}
            _ => {
                eprintln!("mkfs.fat unavailable: skipped");
                return;
            }
        }
        let img = std::fs::read(&path).unwrap();
        let mut cur = Cursor::new(img);
        {
            let fs = fatfs::FileSystem::new(&mut cur, fatfs::FsOptions::new())
                .unwrap_or_else(|e| panic!("{path}: {e}"));
            let root = fs.root_dir();
            put(&root, "from fatfs on mkfs volume.psbt", &[0xA5; 9000]);
            let d = root.create_dir("folder").unwrap();
            put(&d, "inside.txt", b"inside");
        }
        let img = cur.into_inner();
        let kind = if fat == "16" {
            FatKind::Fat16
        } else {
            FatKind::Fat32
        };
        let mut c2 = Cursor::new(img.clone());
        let fs = fatfs::FileSystem::new(&mut c2, fatfs::FsOptions::new()).unwrap();
        let mut disk = MemDisk::new(img);
        let mut vol = Volume::mount(&mut disk).unwrap();
        assert_eq!(vol.geometry().kind, kind);
        assert_eq!(vol.geometry().sectors_per_cluster, spc.parse::<u32>().unwrap());
        assert_eq!(compare_tree(&mut vol, DirId::Root, &fs.root_dir()), 3);
    }
    // mkfs.fat can be forced to write "FAT32" with too few clusters; by the
    // specification that is FAT16, so the volume is refused.
    let path = format!("{dir}/mkfs-bad.img");
    let _ = std::fs::remove_file(&path);
    let ok = std::process::Command::new("mkfs.fat")
        .args(["-C", "-F", "32", "-s", "8", &path, "131072"])
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(ok);
    let img = std::fs::read(&path).unwrap();
    assert_eq!(
        Volume::mount(&mut MemDisk::new(img)).err(),
        Some(Error::Corrupt(Corrupt::BootSector))
    );
}
