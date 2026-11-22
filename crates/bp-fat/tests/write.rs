//! Writing: files made by bp-fat must read back in `fatfs` and pass
//! `fsck.fat`; existing files must survive a pulled card.

mod common;

use bp_fat::{format as bp_format, valid_name, BlockDevice, DirId, Error, FatKind, Volume, SECTOR};
use common::*;
use std::io::{Cursor, Read};

fn fatfs_read(img: &[u8], path: &str) -> Option<Vec<u8>> {
    let mut cur = Cursor::new(img.to_vec());
    let fs = fatfs::FileSystem::new(&mut cur, fatfs::FsOptions::new()).unwrap();
    let mut f = fs.root_dir().open_file(path).ok()?;
    let mut v = Vec::new();
    f.read_to_end(&mut v).unwrap();
    Some(v)
}

fn fatfs_names(img: &[u8], dir: &str) -> Vec<String> {
    let mut cur = Cursor::new(img.to_vec());
    let fs = fatfs::FileSystem::new(&mut cur, fatfs::FsOptions::new()).unwrap();
    let root = fs.root_dir();
    let d = if dir.is_empty() {
        root
    } else {
        root.open_dir(dir).unwrap()
    };
    d.iter()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n != "." && n != "..")
        .collect()
}

fn sizes(cs: usize) -> Vec<usize> {
    vec![0, 1, 511, 512, 513, cs - 1, cs, cs + 1, 3 * cs + 7, 100_000]
}

fn create_and_check(img: Vec<u8>, tag: &str) {
    let before = img.clone();
    let mut disk = MemDisk::new(img);
    let mut r = Prng(7);
    let mut made = Vec::new();
    {
        let mut v = Volume::mount(&mut disk).unwrap();
        let cs = v.geometry().cluster_bytes() as usize;
        let sub_entry = v.find(DirId::Root, "Sub Dir").unwrap();
        let sub = v.open_dir(&sub_entry).unwrap();
        for (i, n) in sizes(cs).into_iter().enumerate() {
            let data = r.bytes(n);
            let name = format!("Signed Transaction {i} with a Long Name-signed.psbt");
            v.create(DirId::Root, &name, &data).unwrap();
            let short = format!("S{i}.TXT");
            v.create(sub, &short, &data).unwrap();
            made.push((name, format!("Sub Dir/{short}"), data));
        }
        // Our own reader sees them.
        for (name, path, data) in &made {
            let e = v.find(DirId::Root, name).unwrap();
            let mut buf = vec![0u8; data.len()];
            v.read_file(&e, &mut buf).unwrap();
            assert_eq!(&buf, data);
            let e = v.open_path(path).unwrap();
            assert_eq!(e.size() as usize, data.len());
        }
    }
    for (name, path, data) in &made {
        assert_eq!(fatfs_read(&disk.data, name).as_ref(), Some(data), "{name}");
        assert_eq!(fatfs_read(&disk.data, path).as_ref(), Some(data), "{path}");
    }
    // Earlier files untouched.
    assert_eq!(fatfs_read(&disk.data, "hello.txt").unwrap(), b"hello, card\n");
    assert_no_new_problems(&before, &disk.data, tag);
}

#[test]
fn created_files_read_back_fat32() {
    create_and_check(sample(fatfs::FatType::Fat32, 40 << 20, Some(512)), "c32");
    create_and_check(sample(fatfs::FatType::Fat32, 300 << 20, Some(4096)), "c32b");
}

#[test]
fn created_files_read_back_fat16() {
    create_and_check(sample(fatfs::FatType::Fat16, 16 << 20, None), "c16");
    create_and_check(sample(fatfs::FatType::Fat16, 8 << 20, Some(512)), "c16b");
}

#[test]
fn names_are_checked_and_never_replaced() {
    for bad in [
        "", ".", "..", "a/b", "a\\b", "x:y", "q?", "star*", "pipe|", "end.", "end ", "tab\t", "\u{c9c0}",
    ] {
        assert!(!valid_name(bad), "{bad:?}");
    }
    assert!(valid_name("tx-signed-7a1b2c3d.psbt"));
    assert!(valid_name(&"a".repeat(255)));
    assert!(!valid_name(&"a".repeat(256)));
    let mut disk = MemDisk::new(sample(fatfs::FatType::Fat16, 16 << 20, None));
    let mut v = Volume::mount(&mut disk).unwrap();
    assert_eq!(
        v.create(DirId::Root, "bad?name", b"x").err(),
        Some(Error::BadName)
    );
    assert_eq!(
        v.create(DirId::Root, "HELLO.TXT", b"x").err(),
        Some(Error::Exists)
    );
    assert_eq!(v.create(DirId::Root, "sub dir", b"x").err(), Some(Error::Exists));
    assert_eq!(
        v.unique_name(DirId::Root, "hello", "txt").unwrap().as_str(),
        "hello-2.txt"
    );
    v.create(DirId::Root, "hello-2.txt", b"2").unwrap();
    assert_eq!(
        v.unique_name(DirId::Root, "hello", "txt").unwrap().as_str(),
        "hello-3.txt"
    );
    assert_eq!(
        v.unique_name(DirId::Root, "fresh", "psbt").unwrap().as_str(),
        "fresh.psbt"
    );
    assert_eq!(
        v.unique_name(DirId::Root, "no-ext", "").unwrap().as_str(),
        "no-ext"
    );
    assert_eq!(
        v.unique_name(DirId::Root, "bad?", "txt").err(),
        Some(Error::BadName)
    );
}

#[test]
fn short_names_stay_unique() {
    let before = sample(fatfs::FatType::Fat32, 40 << 20, Some(512));
    let mut disk = MemDisk::new(before.clone());
    {
        let mut v = Volume::mount(&mut disk).unwrap();
        for i in 0..40 {
            v.create(DirId::Root, &format!("transaction number {i}.psbt"), b"x")
                .unwrap();
        }
        // Names that differ only in characters the 8.3 form drops.
        for n in [
            "a+b.txt", "a,b.txt", "a;b.txt", "a=b.txt", "a[b].txt", ".hidden", "x.tar.gz",
        ] {
            v.create(DirId::Root, n, n.as_bytes()).unwrap();
        }
    }
    let names = fatfs_names(&disk.data, "");
    for i in 0..40 {
        assert!(names.contains(&format!("transaction number {i}.psbt")));
    }
    assert_eq!(fatfs_read(&disk.data, "a[b].txt").unwrap(), b"a[b].txt");
    assert_eq!(fatfs_read(&disk.data, "x.tar.gz").unwrap(), b"x.tar.gz");
    assert_no_new_problems(&before, &disk.data, "short");
}

#[test]
fn directories_grow_and_fat16_root_fills() {
    let before = sample(fatfs::FatType::Fat32, 40 << 20, Some(512));
    let mut disk = MemDisk::new(before.clone());
    {
        let mut v = Volume::mount(&mut disk).unwrap();
        let sub_entry = v.find(DirId::Root, "Sub Dir").unwrap();
        let sub = v.open_dir(&sub_entry).unwrap();
        for i in 0..100 {
            let name = format!("a rather long file name number {i:03} to fill clusters.json");
            v.create(sub, &name, format!("{i}").as_bytes()).unwrap();
        }
    }
    let names = fatfs_names(&disk.data, "Sub Dir");
    assert_eq!(names.len(), 102);
    assert_eq!(
        fatfs_read(
            &disk.data,
            "Sub Dir/a rather long file name number 099 to fill clusters.json"
        )
        .unwrap(),
        b"99"
    );
    assert_no_new_problems(&before, &disk.data, "grow");

    let mut disk = MemDisk::new(format(16 << 20, fatfs::FatType::Fat16, None).into_inner());
    {
        let mut v = Volume::mount(&mut disk).unwrap();
        let slots = v.geometry().root_entries;
        let mut made = 0;
        let err = loop {
            match v.create(DirId::Root, &format!("F{made}.TXT"), b"") {
                Ok(_) => made += 1,
                Err(e) => break e,
            }
        };
        assert_eq!(err, Error::DirFull);
        // Each file takes a long-name slot and an 8.3 slot; the label one.
        assert_eq!(made, (slots - 1) / 2);
    }
    assert_clean(&disk.data, "rootfull");
}

#[test]
fn delete_and_wipe() {
    let before = sample(fatfs::FatType::Fat32, 40 << 20, Some(512));
    let mut disk = MemDisk::new(before.clone());
    let secret_name = "wallet-backup-do-not-keep.psbt";
    {
        let mut v = Volume::mount(&mut disk).unwrap();
        v.create(DirId::Root, secret_name, &[0xAB; 3000]).unwrap();
        let e = v.find(DirId::Root, "A long file name with spaces.psbt").unwrap();
        v.delete(&e).unwrap();
        assert_eq!(v.delete(&e).err(), Some(Error::NotFound));
        let s = v.find(DirId::Root, secret_name).unwrap();
        v.wipe(&s).unwrap();
        let d = v.find(DirId::Root, "Sub Dir").unwrap();
        assert_eq!(v.delete(&d).err(), Some(Error::NotAFile));
        // Freed space is used again.
        v.create(DirId::Root, "reuse.bin", &[1u8; 4000]).unwrap();
    }
    let names = fatfs_names(&disk.data, "");
    assert!(!names.iter().any(|n| n.starts_with("A long") || n == secret_name));
    assert_eq!(fatfs_read(&disk.data, "reuse.bin").unwrap(), vec![1u8; 4000]);
    // The wiped data and name are gone from the raw image.
    assert!(!disk.data.windows(64).any(|w| w.iter().all(|&b| b == 0xAB)));
    let utf16: Vec<u8> = "do-not-k".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    assert!(!disk.data.windows(utf16.len()).any(|w| w == utf16.as_slice()));
    assert_no_new_problems(&before, &disk.data, "delete");
}

#[test]
fn full_card_leaves_no_trace() {
    let before = sample(fatfs::FatType::Fat16, 8 << 20, Some(512));
    let mut disk = MemDisk::new(before.clone());
    {
        let mut v = Volume::mount(&mut disk).unwrap();
        assert_eq!(
            v.create(DirId::Root, "huge.bin", &vec![3u8; 9 << 20]).err(),
            Some(Error::DiskFull)
        );
        assert_eq!(v.find(DirId::Root, "huge.bin").err(), Some(Error::NotFound));
        v.create(DirId::Root, "after.bin", b"still works").unwrap();
    }
    assert_eq!(fatfs_read(&disk.data, "after.bin").unwrap(), b"still works");
    assert_no_new_problems(&before, &disk.data, "full");
}

#[test]
fn pulled_card_keeps_existing_files() {
    let base = sample(fatfs::FatType::Fat32, 40 << 20, Some(512));
    let data = Prng(9).bytes(2500);
    let mut failures = 0;
    for k in 0..40 {
        let mut disk = MemDisk::new(base.clone());
        disk.fail_after_writes = Some(k);
        let res = {
            let mut v = Volume::mount(&mut disk).unwrap();
            v.create(DirId::Root, "interrupted-signed.psbt", &data)
        };
        if res.is_err() {
            assert_eq!(res.err(), Some(Error::Io));
            failures += 1;
        }
        disk.fail_after_writes = None;
        disk.pulled = false;
        // Every original file is intact, and the new one is either absent
        // or complete.
        let mut cur = Cursor::new(base.clone());
        let fs = fatfs::FileSystem::new(&mut cur, fatfs::FsOptions::new()).unwrap();
        let mut v = Volume::mount(&mut disk).unwrap();
        let sub_entry = v.find(DirId::Root, "Sub Dir").unwrap();
        let sub = v.open_dir(&sub_entry).unwrap();
        compare_tree(&mut v, sub, &fs.root_dir().open_dir("Sub Dir").unwrap());
        let mut buf = vec![0u8; 8192];
        let e = v.find(DirId::Root, "fragmented.bin").unwrap();
        let mut want = Vec::new();
        fs.root_dir()
            .open_file("fragmented.bin")
            .unwrap()
            .read_to_end(&mut want)
            .unwrap();
        let mut got = vec![0u8; want.len()];
        v.read_file(&e, &mut got).unwrap();
        assert_eq!(got, want);
        match v.find(DirId::Root, "interrupted-signed.psbt") {
            Ok(e) => {
                assert!(res.is_ok());
                let n = v.read_file(&e, &mut buf).unwrap();
                assert_eq!(&buf[..n], &data[..]);
            }
            Err(Error::NotFound) => assert!(res.is_err()),
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(failures > 10);
}

#[test]
fn hidden_entries_behind_end_marker_stay_hidden() {
    let mut img = format(16 << 20, fatfs::FatType::Fat16, None).into_inner();
    let g = *Volume::mount(&mut MemDisk::new(img.clone())).unwrap().geometry();
    // Root: label at slot 0, end marker at slot 1, junk at slots 2..10.
    let root = g.root_start as usize * SECTOR;
    for slot in 2..10 {
        let s = root + slot * 32;
        img[s..s + 11].copy_from_slice(b"JUNK    BIN");
        img[s + 11] = 0x20;
    }
    let mut disk = MemDisk::new(img);
    let mut v = Volume::mount(&mut disk).unwrap();
    v.create(DirId::Root, "new.txt", b"n").unwrap();
    let mut it = v.iter(DirId::Root);
    let mut names = Vec::new();
    while let Some(e) = v.next_entry(&mut it).unwrap() {
        names.push(e.name().to_string());
    }
    assert_eq!(names, ["new.txt"]);
}

fn rng(seed: u64) -> impl FnMut(&mut [u8]) {
    let mut r = Prng(seed);
    move |b: &mut [u8]| b.iter_mut().for_each(|x| *x = r.next() as u8)
}

#[test]
fn format_small_cards() {
    for (mb, kind) in [
        (4u64, FatKind::Fat16),
        (64, FatKind::Fat16),
        (1024, FatKind::Fat16),
    ] {
        let mut disk = SparseDisk::new(mb << 20);
        // Old content everywhere it matters.
        for lba in 0..4096 {
            disk.write(lba, &[0x5A; SECTOR]).unwrap();
        }
        assert_eq!(bp_format(&mut disk, &mut rng(mb)).unwrap(), kind);
        let start = {
            let mut v = Volume::mount(&mut disk).unwrap();
            assert_eq!(v.geometry().kind, kind);
            let mut it = v.iter(DirId::Root);
            assert!(v.next_entry(&mut it).unwrap().is_none(), "fresh card is empty");
            v.create(DirId::Root, "first file.psbt", b"psbt").unwrap();
            v.geometry().start
        };
        // The gap before the partition is scrambled, not left as it was.
        let mut s = [0u8; SECTOR];
        disk.read(1, &mut s).unwrap();
        assert_ne!(s, [0x5A; SECTOR]);
        let mut view = SparseView {
            disk: &mut disk,
            base: start as u64 * SECTOR as u64,
            pos: 0,
        };
        {
            let fs = fatfs::FileSystem::new(&mut view, fatfs::FsOptions::new()).unwrap();
            let mut f = fs.root_dir().open_file("first file.psbt").unwrap();
            let mut got = Vec::new();
            f.read_to_end(&mut got).unwrap();
            assert_eq!(got, b"psbt");
        }
        let path = format!("{}/fmt-{mb}.img", env!("CARGO_TARGET_TMPDIR"));
        disk.to_file(start, &path);
        if let Some(p) = fsck_file(&path) {
            assert!(p.is_empty(), "{mb} MB: {p:#?}");
        }
    }
    assert_eq!(
        bp_format(&mut SparseDisk::new(3 << 20), &mut rng(1)).err(),
        Some(Error::TooSmall)
    );
}

#[test]
fn format_large_cards() {
    for (gb, spc) in [(3u64, 8), (16, 16), (40, 64)] {
        let mut disk = SparseDisk::new(gb << 30);
        assert_eq!(bp_format(&mut disk, &mut rng(gb)).unwrap(), FatKind::Fat32);
        let start = {
            let mut v = Volume::mount(&mut disk).unwrap();
            assert_eq!(v.geometry().sectors_per_cluster, spc, "{gb} GB");
            v.create(DirId::Root, "big card.txt", &[9u8; 70_000]).unwrap();
            v.geometry().start
        };
        let mut view = SparseView {
            disk: &mut disk,
            base: start as u64 * SECTOR as u64,
            pos: 0,
        };
        {
            let fs = fatfs::FileSystem::new(&mut view, fatfs::FsOptions::new()).unwrap();
            let mut got = Vec::new();
            fs.root_dir()
                .open_file("big card.txt")
                .unwrap()
                .read_to_end(&mut got)
                .unwrap();
            assert_eq!(got, vec![9u8; 70_000]);
        }
        if gb == 3 {
            let path = format!("{}/fmt-{gb}g.img", env!("CARGO_TARGET_TMPDIR"));
            disk.to_file(start, &path);
            if let Some(p) = fsck_file(&path) {
                assert!(p.is_empty(), "{gb} GB: {p:#?}");
            }
        }
    }
}
