//! Hostile file systems: every case is refused cleanly, nothing hangs.

mod common;

use bp_fat::{Corrupt, DirEntry, DirId, Error, FatKind, Geometry, Unsupported, Volume, SECTOR};
use common::*;

/// Small FAT32 image with a three-cluster file and a sub-directory.
fn base() -> Vec<u8> {
    let mut img = format(40 << 20, fatfs::FatType::Fat32, Some(512));
    {
        let fs = fatfs::FileSystem::new(&mut img, fatfs::FsOptions::new()).unwrap();
        let root = fs.root_dir();
        put(&root, "three.bin", &[7u8; 1500]);
        put(&root, "other.bin", &[9u8; 1000]);
        let sub = root.create_dir("sub").unwrap();
        put(&sub, "inner.txt", b"inner");
    }
    img.into_inner()
}

fn info(img: &[u8], name: &str) -> (Geometry, DirEntry) {
    let mut d = MemDisk::new(img.to_vec());
    let mut v = Volume::mount(&mut d).unwrap();
    let e = v.find(DirId::Root, name).unwrap();
    (*v.geometry(), e)
}

fn fat_off(g: &Geometry, copy: u32, c: u32) -> usize {
    (g.fat_start + copy * g.fat_size) as usize * SECTOR + c as usize * 4
}

fn set_fat(img: &mut [u8], g: &Geometry, c: u32, v: u32) {
    for copy in 0..g.fats {
        let o = fat_off(g, copy, c);
        img[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// Byte offset of a root-directory slot (first root cluster only).
fn root_slot(g: &Geometry, slot: u32) -> usize {
    g.cluster_lba(g.root_cluster) as usize * SECTOR + slot as usize * 32
}

fn read(img: Vec<u8>, name: &str) -> Result<usize, Error> {
    let mut d = MemDisk::new(img);
    let mut v = Volume::mount(&mut d)?;
    let e = v.find(DirId::Root, name)?;
    let mut buf = vec![0u8; 1 << 20];
    v.read_file(&e, &mut buf)
}

#[test]
fn chain_loop_is_refused() {
    let mut img = base();
    let (g, e) = info(&img, "three.bin");
    let c2 = {
        let o = fat_off(&g, 0, e.cluster());
        u32::from_le_bytes(img[o..o + 4].try_into().unwrap())
    };
    set_fat(&mut img, &g, c2, e.cluster()); // c1 -> c2 -> c1 -> ...
    assert_eq!(read(img, "three.bin"), Err(Error::Corrupt(Corrupt::Chain)));
}

#[test]
fn short_chain_and_bad_links() {
    let base = base();
    let (g, e) = info(&base, "three.bin");
    // Chain ends after one cluster but the file claims three.
    let mut img = base.clone();
    set_fat(&mut img, &g, e.cluster(), 0x0FFF_FFFF);
    assert_eq!(read(img, "three.bin"), Err(Error::Corrupt(Corrupt::ShortChain)));
    // Free, bad, reserved and out-of-range links.
    for link in [0u32, 1, 0x0FFF_FFF7, g.clusters + 2, 0x0FFF_FFF0] {
        let mut img = base.clone();
        set_fat(&mut img, &g, e.cluster(), link);
        assert_eq!(
            read(img, "three.bin"),
            Err(Error::Corrupt(Corrupt::Chain)),
            "link {link:#x}"
        );
    }
}

#[test]
fn fat_copies_must_agree() {
    let mut img = base();
    let (g, e) = info(&img, "three.bin");
    let o = fat_off(&g, 1, e.cluster());
    img[o] ^= 1;
    assert_eq!(read(img, "three.bin"), Err(Error::Corrupt(Corrupt::FatMismatch)));
}

#[test]
fn false_sizes_and_clusters() {
    let base = base();
    let (g, e) = info(&base, "three.bin");
    let at = root_slot(&g, e.slots().1);
    // Size far beyond the volume.
    let mut img = base.clone();
    img[at + 28..at + 32].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(read(img, "three.bin"), Err(Error::Corrupt(Corrupt::Entry)));
    // First cluster out of range.
    let mut img = base.clone();
    img[at + 20..at + 22].copy_from_slice(&0xFFFFu16.to_le_bytes());
    assert_eq!(read(img, "three.bin"), Err(Error::Corrupt(Corrupt::Entry)));
    // Size larger than the chain (but within the volume).
    let mut img = base.clone();
    img[at + 28..at + 32].copy_from_slice(&100_000u32.to_le_bytes());
    assert_eq!(read(img, "three.bin"), Err(Error::Corrupt(Corrupt::ShortChain)));
}

#[test]
fn cross_linked_files_do_not_panic() {
    let mut img = base();
    let (g, a) = info(&img, "three.bin");
    let (_, b) = info(&img, "other.bin");
    // other.bin's chain now continues into three.bin's clusters.
    set_fat(&mut img, &g, b.cluster(), a.cluster());
    let mut d = MemDisk::new(img);
    let mut v = Volume::mount(&mut d).unwrap();
    let mut buf = vec![0u8; 4096];
    let a = v.find(DirId::Root, "three.bin").unwrap();
    assert_eq!(v.read_file(&a, &mut buf), Ok(1500));
    let b = v.find(DirId::Root, "other.bin").unwrap();
    // Two clusters needed; the shared chain is long enough.
    assert_eq!(v.read_file(&b, &mut buf), Ok(1000));
}

#[test]
fn endless_directory_ends() {
    let mut img = base();
    let (g, e) = info(&img, "sub");
    // Fill the sub-directory cluster with live-looking entries and make it
    // point at itself.
    let lba = g.cluster_lba(e.cluster()) as usize * SECTOR;
    for i in 0..(g.cluster_bytes() as usize / 32) {
        let s = lba + i * 32;
        img[s..s + 11].copy_from_slice(b"LOOP    BIN");
        img[s + 11] = 0x20;
    }
    set_fat(&mut img, &g, e.cluster(), e.cluster());
    let mut d = MemDisk::new(img);
    let mut v = Volume::mount(&mut d).unwrap();
    let dir = v.open_dir(&e).unwrap();
    let mut it = v.iter(dir);
    let mut n = 0;
    let end = loop {
        match v.next_entry(&mut it) {
            Ok(Some(_)) => n += 1,
            other => break other,
        }
    };
    assert_eq!(end, Err(Error::Corrupt(Corrupt::DirTooLong)));
    assert_eq!(n, 65_536);
    assert!(d.reads < 10_000, "{} reads", d.reads);
}

#[test]
fn broken_long_names_fall_back_to_short_names() {
    let base = base();
    let (g, e) = info(&base, "three.bin");
    let (first, short) = e.slots();
    assert!(first < short, "long name expected");
    let mut img = base.clone();
    img[root_slot(&g, first) + 13] ^= 0xFF; // checksum
    let mut d = MemDisk::new(img);
    let mut v = Volume::mount(&mut d).unwrap();
    assert_eq!(v.find(DirId::Root, "three.bin").unwrap().name(), "THREE.BIN");
    // Wrong ordinal order.
    let mut img = base.clone();
    img[root_slot(&g, first)] = 0x45;
    let mut d = MemDisk::new(img);
    let mut v = Volume::mount(&mut d).unwrap();
    assert_eq!(v.find(DirId::Root, "three.bin").unwrap().name(), "THREE.BIN");
}

#[test]
fn bad_boot_sectors() {
    let base = base();
    let cases: [(usize, &[u8], Error); 8] = [
        (13, &[0], Error::Corrupt(Corrupt::BootSector)), // 0 sectors/cluster
        (13, &[3], Error::Corrupt(Corrupt::BootSector)), // not a power of two
        (11, &[0, 4], Error::Unsupported(Unsupported::SectorSize)), // 1024-byte sectors
        (11, &[0, 0], Error::Corrupt(Corrupt::BootSector)),
        (16, &[0], Error::Corrupt(Corrupt::BootSector)), // no FATs
        (36, &[0, 0, 0, 0], Error::Corrupt(Corrupt::BootSector)), // FAT size 0
        (32, &[0xFF, 0xFF, 0xFF, 0x0F], Error::Corrupt(Corrupt::Geometry)), // too many sectors
        (44, &[0xFF, 0xFF, 0xFF, 0x00], Error::Corrupt(Corrupt::BootSector)), // root cluster
    ];
    for (at, bytes, want) in cases {
        let mut img = base.clone();
        img[at..at + bytes.len()].copy_from_slice(bytes);
        let got = Volume::mount(&mut MemDisk::new(img)).err();
        // Some edits make the sector unrecognisable as a boot sector.
        assert!(
            got == Some(want) || got == Some(Error::NoFilesystem),
            "offset {at}: {got:?}"
        );
    }
    let mut img = base.clone();
    img[40] |= 0x80; // FAT mirroring off
    assert_eq!(
        Volume::mount(&mut MemDisk::new(img)).err(),
        Some(Error::Unsupported(Unsupported::NoMirror))
    );
    let mut img = base;
    img[510] = 0;
    assert_eq!(
        Volume::mount(&mut MemDisk::new(img)).err(),
        Some(Error::NoFilesystem)
    );
}

#[test]
fn fat16_root_is_bounded() {
    let mut img = format(16 << 20, fatfs::FatType::Fat16, None).into_inner();
    let g = *Volume::mount(&mut MemDisk::new(img.clone())).unwrap().geometry();
    assert_eq!(g.kind, FatKind::Fat16);
    // Fill every root slot with entries: the listing stops at the end.
    let start = g.root_start as usize * SECTOR;
    for i in 0..g.root_entries as usize {
        let s = start + i * 32;
        img[s..s + 11].copy_from_slice(b"FILL    TXT");
        img[s + 11] = 0x20;
    }
    let mut d = MemDisk::new(img);
    let mut v = Volume::mount(&mut d).unwrap();
    let mut it = v.iter(DirId::Root);
    let mut n = 0;
    while v.next_entry(&mut it).unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, g.root_entries);
}
