//! Random damage to file system structures: no panic, bounded work.

mod common;

use bp_fat::{BlockDevice, DirId, Volume, SECTOR};
use common::*;

/// Walk the whole tree, reading every file (errors are fine).
fn walk<D: BlockDevice>(v: &mut Volume<D>, dir: DirId, depth: usize, budget: &mut u32) {
    let mut it = v.iter(dir);
    let mut buf = vec![0u8; 1 << 17];
    loop {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let e = match v.next_entry(&mut it) {
            Ok(Some(e)) => e,
            _ => return,
        };
        if e.is_dir() {
            if depth < 4 {
                if let Ok(d) = v.open_dir(&e) {
                    walk(v, d, depth + 1, budget);
                }
            }
        } else {
            let _ = v.read_file(&e, &mut buf);
            let _ = v.read_at(&e, 700, &mut buf[..900]);
        }
    }
}

fn fuzz(img: Vec<u8>, iterations: u32, seed: u64) {
    let meta_end = {
        let mut d = MemDisk::new(img.clone());
        let v = Volume::mount(&mut d).unwrap();
        let g = *v.geometry();
        // Boot sector, FATs, root and the first data clusters.
        (g.data_start as usize + 64 * g.sectors_per_cluster as usize) * SECTOR
    };
    let mut r = Prng(seed);
    let mut img = img;
    let mut mounted = 0;
    for _ in 0..iterations {
        let mut saved = Vec::new();
        let edits = 1 + r.below(8);
        for _ in 0..edits {
            // Bias towards the boot sector and the FAT start.
            let at = match r.below(4) {
                0 => r.below(512) as usize,
                _ => r.below(meta_end as u64) as usize,
            };
            saved.push((at, img[at]));
            img[at] = match r.below(3) {
                0 => r.next() as u8,
                1 => img[at] ^ (1 << r.below(8)),
                _ => [0x00, 0xFF, 0xE5, 0x0F, 0x10][r.below(5) as usize],
            };
        }
        let mut d = MemDisk::new(std::mem::take(&mut img));
        if let Ok(mut v) = Volume::mount(&mut d) {
            mounted += 1;
            let mut budget = 2_000;
            walk(&mut v, DirId::Root, 0, &mut budget);
        }
        assert!(d.reads < 3_000_000, "{} reads", d.reads);
        img = d.data;
        for (at, b) in saved.into_iter().rev() {
            img[at] = b;
        }
    }
    assert!(mounted > iterations / 4, "only {mounted} mounted");
}

#[test]
fn fuzz_fat32() {
    fuzz(sample(fatfs::FatType::Fat32, 40 << 20, Some(512)), 1500, 0xF32);
}

#[test]
fn fuzz_fat16() {
    fuzz(sample(fatfs::FatType::Fat16, 16 << 20, None), 1500, 0xF16);
}
