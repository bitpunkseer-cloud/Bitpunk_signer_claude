//! The simulator's microSD card: a 32 MB image in page memory, formatted
//! and written by the same FAT code the device uses. The page plays the
//! role of a computer: it copies files onto the card and reads them back.

use bp_fat::{format, valid_name, BlockDevice, DirId, IoError, Sector, Volume, SECTOR};
use bp_hal::SdCard;

pub const ERR_FULL: u32 = 1;
pub const ERR_NAME: u32 = 2;
pub const ERR_OTHER: u32 = 4;

const CARD_BYTES: usize = 32 << 20;

pub struct VirtualCard {
    data: Vec<u8>,
    pub present: bool,
    powered: bool,
    pub cycles: u32,
    rng: u64,
}

impl VirtualCard {
    pub fn new(seed: &[u8; 32]) -> Self {
        let mut rng = 0x9E37_79B9_7F4A_7C15u64;
        for (i, b) in seed.iter().enumerate() {
            rng ^= (*b as u64) << ((i % 8) * 8);
        }
        let mut c = VirtualCard {
            data: vec![0; CARD_BYTES],
            present: true,
            powered: false,
            cycles: 0,
            rng: rng | 1,
        };
        c.erase();
        c
    }

    fn random(&mut self, out: &mut [u8]) {
        for b in out {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            *b = self.rng as u8;
        }
    }

    /// Reformat (the page acting as a computer).
    pub fn erase(&mut self) {
        self.data.fill(0);
        let mut rng = self.rng;
        let mut fill = |b: &mut [u8]| {
            for v in b {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                *v = rng as u8;
            }
        };
        self.powered = true;
        let _ = format(&mut Raw(&mut self.data), &mut fill);
        self.powered = false;
        self.rng = rng;
        let mut spare = [0u8; 1];
        self.random(&mut spare);
    }

    /// Copy a file into the root directory. A name FAT does not allow is
    /// cleaned up; an existing name gets a number (nothing is replaced).
    pub fn put(&mut self, name: &[u8], data: &[u8]) -> u32 {
        let clean = clean_name(name);
        let (stem, ext) = match clean.rfind('.') {
            Some(i) if i > 0 => (&clean[..i], &clean[i + 1..]),
            _ => (clean.as_str(), ""),
        };
        let mut v = match Volume::mount(Raw(&mut self.data)) {
            Ok(v) => v,
            Err(_) => return ERR_OTHER,
        };
        let name = match v.unique_name(DirId::Root, stem, ext) {
            Ok(n) => n,
            Err(_) => return ERR_NAME,
        };
        match v.create(DirId::Root, name.as_str(), data) {
            Ok(_) => 0,
            Err(bp_fat::Error::DiskFull) | Err(bp_fat::Error::DirFull) => ERR_FULL,
            Err(_) => ERR_OTHER,
        }
    }

    /// `path\tsize\n` for every file (sub-folders to depth 4).
    pub fn list(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Ok(mut v) = Volume::mount(Raw(&mut self.data)) {
            walk(&mut v, DirId::Root, "", 0, &mut out);
        }
        out
    }

    pub fn get(&mut self, path: &str) -> Option<Vec<u8>> {
        let mut v = Volume::mount(Raw(&mut self.data)).ok()?;
        let e = v.open_path(path).ok()?;
        let mut buf = vec![0u8; e.size() as usize];
        v.read_file(&e, &mut buf).ok()?;
        Some(buf)
    }

    pub fn delete(&mut self, path: &str) -> u32 {
        let Ok(mut v) = Volume::mount(Raw(&mut self.data)) else {
            return ERR_OTHER;
        };
        match v.open_path(path).and_then(|e| v.delete(&e)) {
            Ok(()) => 0,
            Err(_) => ERR_OTHER,
        }
    }
}

fn walk<D: BlockDevice>(v: &mut Volume<D>, dir: DirId, prefix: &str, depth: usize, out: &mut Vec<u8>) {
    let mut it = v.iter(dir);
    let mut subdirs = Vec::new();
    while let Ok(Some(e)) = v.next_entry(&mut it) {
        let path = format!("{prefix}{}", e.name());
        if e.is_dir() {
            if depth < 4 && !e.is_hidden() {
                if let Ok(d) = v.open_dir(&e) {
                    subdirs.push((d, path));
                }
            }
        } else {
            out.extend_from_slice(format!("{path}\t{}\n", e.size()).as_bytes());
        }
    }
    for (d, path) in subdirs {
        walk(v, d, &format!("{path}/"), depth + 1, out);
    }
}

/// Printable ASCII only, FAT's reserved characters as '_', no trailing
/// dots or spaces, at most 120 characters.
fn clean_name(name: &[u8]) -> String {
    let text = String::from_utf8_lossy(name);
    let mut s: String = text
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() && !"\"*/:<>?\\|".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(120)
        .collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    if s.is_empty() || !valid_name(&s) {
        s = "file".into();
    }
    s
}

/// The image as a block device for page-side access (always powered).
struct Raw<'a>(&'a mut Vec<u8>);

impl BlockDevice for Raw<'_> {
    fn sectors(&self) -> u32 {
        (self.0.len() / SECTOR) as u32
    }
    fn read(&mut self, lba: u32, buf: &mut Sector) -> Result<(), IoError> {
        let at = lba as usize * SECTOR;
        buf.copy_from_slice(self.0.get(at..at + SECTOR).ok_or(IoError)?);
        Ok(())
    }
    fn write(&mut self, lba: u32, buf: &Sector) -> Result<(), IoError> {
        let at = lba as usize * SECTOR;
        self.0
            .get_mut(at..at + SECTOR)
            .ok_or(IoError)?
            .copy_from_slice(buf);
        Ok(())
    }
}

impl BlockDevice for VirtualCard {
    fn sectors(&self) -> u32 {
        (self.data.len() / SECTOR) as u32
    }
    fn read(&mut self, lba: u32, buf: &mut Sector) -> Result<(), IoError> {
        if !self.present || !self.powered {
            return Err(IoError);
        }
        Raw(&mut self.data).read(lba, buf)
    }
    fn write(&mut self, lba: u32, buf: &Sector) -> Result<(), IoError> {
        if !self.present || !self.powered {
            return Err(IoError);
        }
        Raw(&mut self.data).write(lba, buf)
    }
}

impl SdCard for VirtualCard {
    fn present(&self) -> bool {
        self.present
    }
    fn set_power(&mut self, on: bool) {
        if on && !self.powered {
            self.cycles = self.cycles.wrapping_add(1);
        }
        self.powered = on;
    }
}
