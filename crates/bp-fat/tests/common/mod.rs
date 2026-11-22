//! Shared test helpers: an in-memory card and images built with `fatfs`.
#![allow(dead_code)]

use bp_fat::{BlockDevice, DirId, IoError, Sector, Volume, SECTOR};
use std::io::{Cursor, Read, Write};

/// In-memory card. Counts reads so tests can bound work on bad images.
pub struct MemDisk {
    pub data: Vec<u8>,
    pub reads: u64,
    pub writes: u64,
    /// The card is pulled when this many writes have succeeded: the next
    /// write and every later access fail.
    pub fail_after_writes: Option<u64>,
    pub pulled: bool,
}

impl MemDisk {
    pub fn new(data: Vec<u8>) -> Self {
        MemDisk {
            data,
            reads: 0,
            writes: 0,
            fail_after_writes: None,
            pulled: false,
        }
    }
}

impl BlockDevice for MemDisk {
    fn sectors(&self) -> u32 {
        (self.data.len() / SECTOR) as u32
    }
    fn read(&mut self, lba: u32, buf: &mut Sector) -> Result<(), IoError> {
        self.reads += 1;
        if self.pulled {
            return Err(IoError);
        }
        let at = lba as usize * SECTOR;
        let src = self.data.get(at..at + SECTOR).ok_or(IoError)?;
        buf.copy_from_slice(src);
        Ok(())
    }
    fn write(&mut self, lba: u32, buf: &Sector) -> Result<(), IoError> {
        if self.pulled || self.fail_after_writes.is_some_and(|n| self.writes >= n) {
            self.pulled = true;
            return Err(IoError);
        }
        self.writes += 1;
        let at = lba as usize * SECTOR;
        let dst = self.data.get_mut(at..at + SECTOR).ok_or(IoError)?;
        dst.copy_from_slice(buf);
        Ok(())
    }
}

/// Deterministic pseudo-random bytes.
pub struct Prng(pub u64);

impl Prng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

pub type Fs<'a> = fatfs::FileSystem<&'a mut Cursor<Vec<u8>>>;

/// Format an image with `fatfs`.
pub fn format(bytes: usize, fat: fatfs::FatType, cluster: Option<u32>) -> Cursor<Vec<u8>> {
    let mut img = Cursor::new(vec![0u8; bytes]);
    let mut opts = fatfs::FormatVolumeOptions::new()
        .fat_type(fat)
        .volume_label(*b"BPTEST     ");
    if let Some(c) = cluster {
        opts = opts.bytes_per_cluster(c);
    }
    fatfs::format_volume(&mut img, opts).expect("format");
    img
}

pub fn put(dir: &fatfs::Dir<&mut Cursor<Vec<u8>>>, name: &str, data: &[u8]) {
    let mut f = dir.create_file(name).expect("create");
    f.truncate().unwrap();
    f.write_all(data).expect("write");
}

/// A populated image: long names, sub-directories, an empty file, hidden
/// files, a non-ASCII name and a fragmented file.
pub fn sample(fat: fatfs::FatType, bytes: usize, cluster: Option<u32>) -> Vec<u8> {
    let mut img = format(bytes, fat, cluster);
    {
        let fs = fatfs::FileSystem::new(&mut img, fatfs::FsOptions::new()).expect("mount");
        let root = fs.root_dir();
        let mut r = Prng(0x5eed);
        put(&root, "hello.txt", b"hello, card\n");
        put(&root, "A long file name with spaces.psbt", &r.bytes(5000));
        put(&root, "UPPER.TXT", b"upper");
        put(&root, "empty.bin", b"");
        put(&root, "._resource", b"apple double");
        put(&root, "\u{c9c0}\u{ac11}.psbt", b"korean name");
        let sub = root.create_dir("Sub Dir").unwrap();
        put(&sub, "nested-file-name.json", b"{\"a\":1}");
        let deeper = sub.create_dir("deeper").unwrap();
        put(&deeper, "x.bin", &r.bytes(100_000));
        let d3 = deeper.create_dir("d3").unwrap();
        let d4 = d3.create_dir("d4").unwrap();
        put(&d4, "deep.txt", b"four levels down");
        put(&root, "frag1.bin", &r.bytes(3000));
        put(&root, "frag2.bin", &r.bytes(3000));
        root.remove("frag1.bin").unwrap();
        put(&root, "fragmented.bin", &r.bytes(20_000));
        // Many entries so the directory spans several sectors / clusters.
        let many = root.create_dir("many").unwrap();
        for i in 0..70 {
            put(
                &many,
                &format!("file number {i:03} with a long name.txt"),
                format!("{i}").as_bytes(),
            );
        }
    }
    img.into_inner()
}

/// Put a volume image inside an MBR partition starting at `start`.
pub fn partitioned(vol: &[u8], start: u32, kind: u8) -> Vec<u8> {
    let mut disk = vec![0u8; start as usize * SECTOR + vol.len()];
    disk[start as usize * SECTOR..].copy_from_slice(vol);
    let p = 446;
    disk[p + 4] = kind;
    disk[p + 8..p + 12].copy_from_slice(&start.to_le_bytes());
    disk[p + 12..p + 16].copy_from_slice(&((vol.len() / SECTOR) as u32).to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk
}

/// Compare every entry `fatfs` sees with what `bp-fat` reads.
pub fn compare_tree<D: BlockDevice>(
    vol: &mut Volume<D>,
    ours: DirId,
    theirs: &fatfs::Dir<&mut Cursor<Vec<u8>>>,
) -> usize {
    let mut seen = 0;
    for e in theirs.iter() {
        let e = e.unwrap();
        let name = e.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let display: String = name
            .chars()
            .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
            .collect();
        let mine = vol
            .find(ours, &display)
            .unwrap_or_else(|err| panic!("{display}: {err:?}"));
        assert_eq!(mine.name(), display);
        assert_eq!(mine.is_dir(), e.is_dir(), "{display}");
        seen += 1;
        if e.is_dir() {
            let sub = vol.open_dir(&mine).unwrap();
            seen += compare_tree(vol, sub, &e.to_dir());
        } else {
            assert_eq!(mine.size() as u64, e.len(), "{display}");
            let mut want = Vec::new();
            e.to_file().read_to_end(&mut want).unwrap();
            let mut got = vec![0u8; want.len()];
            assert_eq!(vol.read_file(&mine, &mut got).unwrap(), want.len());
            assert_eq!(got, want, "{display}");
        }
    }
    // And nothing extra on our side.
    let mut it = vol.iter(ours);
    let mut count = 0;
    while vol.next_entry(&mut it).unwrap().is_some() {
        count += 1;
    }
    let theirs_count = theirs
        .iter()
        .filter(|e| {
            let n = e.as_ref().unwrap().file_name();
            n != "." && n != ".."
        })
        .count();
    assert_eq!(count, theirs_count);
    seen
}

/// `fsck.fat -n` on a volume image (no partition table). Returns the
/// problems it reports, or `None` when dosfstools is not installed.
pub fn fsck(volume: &[u8], tag: &str) -> Option<Vec<String>> {
    let path = format!("{}/fsck-{tag}.img", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, volume).unwrap();
    fsck_file(&path)
}

pub fn fsck_file(path: &str) -> Option<Vec<String>> {
    let out = std::process::Command::new("fsck.fat")
        .args(["-n", "-V", path])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    let problems: Vec<String> = text
        .lines()
        .filter(|l| {
            !l.starts_with("fsck.fat ")
                && !l.starts_with("Checking")
                && !l.starts_with("Starting check")
                && !l.starts_with("Starting verification")
                // We set the FSInfo free count to "unknown" (0xFFFFFFFF) on
                // purpose: the hint is never trusted, so it is not kept.
                && !l.starts_with("Free cluster summary uninitialized")
                && !l.contains(" files, ")
                && !l.trim().is_empty()
        })
        .map(str::to_string)
        .collect();
    if !out.status.success() && problems.is_empty() {
        return Some(vec![format!("exit {:?}", out.status.code())]);
    }
    Some(problems)
}

/// Assert a clean `fsck.fat` result when dosfstools is available.
pub fn assert_clean(volume: &[u8], tag: &str) {
    if let Some(p) = fsck(volume, tag) {
        assert!(p.is_empty(), "{tag}: {p:#?}");
    }
}

/// Assert `fsck.fat` finds nothing in `after` that it did not already find
/// in `before` (`fatfs` 0.3 writes sub-directories that fsck.fat flags, so
/// sample images are not clean to begin with).
pub fn assert_no_new_problems(before: &[u8], after: &[u8], tag: &str) {
    let (Some(old), Some(new)) = (fsck(before, &format!("{tag}-before")), fsck(after, tag)) else {
        return;
    };
    let extra: Vec<&String> = new.iter().filter(|l| !old.contains(l)).collect();
    assert!(extra.is_empty(), "{tag}: {extra:#?}");
}

/// Sparse card for multi-gigabyte format tests.
pub struct SparseDisk {
    pub sectors: u32,
    pub map: std::collections::HashMap<u32, Box<Sector>>,
}

impl SparseDisk {
    pub fn new(bytes: u64) -> Self {
        SparseDisk {
            sectors: (bytes / SECTOR as u64) as u32,
            map: Default::default(),
        }
    }

    /// Write the sectors from `start` on into a sparse file (for fsck).
    pub fn to_file(&self, start: u32, path: &str) {
        use std::io::{Seek, SeekFrom};
        let mut f = std::fs::File::create(path).unwrap();
        f.set_len((self.sectors - start) as u64 * SECTOR as u64).unwrap();
        for (&lba, s) in &self.map {
            if lba >= start {
                f.seek(SeekFrom::Start((lba - start) as u64 * SECTOR as u64))
                    .unwrap();
                f.write_all(&s[..]).unwrap();
            }
        }
    }
}

impl BlockDevice for SparseDisk {
    fn sectors(&self) -> u32 {
        self.sectors
    }
    fn read(&mut self, lba: u32, buf: &mut Sector) -> Result<(), IoError> {
        if lba >= self.sectors {
            return Err(IoError);
        }
        *buf = self.map.get(&lba).map_or([0; SECTOR], |s| **s);
        Ok(())
    }
    fn write(&mut self, lba: u32, buf: &Sector) -> Result<(), IoError> {
        if lba >= self.sectors {
            return Err(IoError);
        }
        if buf.iter().all(|&b| b == 0) {
            self.map.remove(&lba);
        } else {
            self.map.insert(lba, Box::new(*buf));
        }
        Ok(())
    }
}

/// `Read + Write + Seek` view of a sparse card from `base` (for fatfs).
pub struct SparseView<'a> {
    pub disk: &'a mut SparseDisk,
    pub base: u64,
    pub pos: u64,
}

impl std::io::Read for SparseView<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let at = self.base + self.pos;
        let lba = (at / SECTOR as u64) as u32;
        let off = (at % SECTOR as u64) as usize;
        let mut s = [0u8; SECTOR];
        self.disk
            .read(lba, &mut s)
            .map_err(|_| std::io::Error::other("eof"))?;
        let n = out.len().min(SECTOR - off);
        out[..n].copy_from_slice(&s[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl std::io::Write for SparseView<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let at = self.base + self.pos;
        let lba = (at / SECTOR as u64) as u32;
        let off = (at % SECTOR as u64) as usize;
        let mut s = [0u8; SECTOR];
        self.disk
            .read(lba, &mut s)
            .map_err(|_| std::io::Error::other("eof"))?;
        let n = data.len().min(SECTOR - off);
        s[off..off + n].copy_from_slice(&data[..n]);
        self.disk
            .write(lba, &s)
            .map_err(|_| std::io::Error::other("eof"))?;
        self.pos += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for SparseView<'_> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        let len = self.disk.sectors as u64 * SECTOR as u64 - self.base;
        self.pos = match to {
            std::io::SeekFrom::Start(p) => p,
            std::io::SeekFrom::End(d) => (len as i64 + d) as u64,
            std::io::SeekFrom::Current(d) => (self.pos as i64 + d) as u64,
        };
        Ok(self.pos)
    }
}
