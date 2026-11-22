//! Directories: slots, long names, entries.

use crate::geometry::FatKind;
use crate::{BlockDevice, Corrupt, Error, Volume, MAX_DIR_SLOTS, SECTOR};

pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_LFN: u8 = 0x0F;

/// Slots per sector.
pub(crate) const SLOTS: u32 = (SECTOR / 32) as u32;
/// Long name limit in UTF-16 units, and entries needed for it.
pub(crate) const MAX_NAME: usize = 255;
pub(crate) const MAX_LFN: usize = 20;
/// Characters per long-name entry and their byte offsets.
pub(crate) const LFN_CHARS: usize = 13;
pub(crate) const LFN_OFFSETS: [usize; LFN_CHARS] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

/// A directory: the root, or a sub-directory by first cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirId {
    Root,
    Cluster(u32),
}

/// A display name: printable ASCII only (other characters become `?`).
#[derive(Clone, Copy)]
pub struct Name {
    buf: [u8; MAX_NAME],
    len: u8,
}

impl Name {
    pub const fn empty() -> Self {
        Name {
            buf: [0; MAX_NAME],
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, c: u32) {
        if (self.len as usize) < MAX_NAME {
            let b = if (0x20..0x7F).contains(&c) { c as u8 } else { b'?' };
            self.buf[self.len as usize] = b;
            self.len += 1;
        }
    }

    pub fn as_str(&self) -> &str {
        // Only printable ASCII is ever stored.
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("?")
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

/// A file or sub-directory found in a directory listing.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DirEntry {
    name: Name,
    short: [u8; 11],
    attr: u8,
    cluster: u32,
    size: u32,
    dir: DirId,
    first_slot: u32,
    slot: u32,
}

impl DirEntry {
    /// Display name: the long name when it is intact, else the 8.3 name.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Raw 8.3 name as stored (11 bytes, space padded).
    pub fn short_raw(&self) -> &[u8; 11] {
        &self.short
    }

    pub fn attr(&self) -> u8 {
        self.attr
    }

    pub fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }

    /// Hidden, system, or dot-file (`.Trashes`, macOS `._` files).
    pub fn is_hidden(&self) -> bool {
        self.attr & (ATTR_HIDDEN | ATTR_SYSTEM) != 0 || self.name().starts_with('.')
    }

    pub fn size(&self) -> u32 {
        if self.is_dir() {
            0
        } else {
            self.size
        }
    }

    pub fn cluster(&self) -> u32 {
        self.cluster
    }

    /// Directory holding this entry.
    pub fn parent(&self) -> DirId {
        self.dir
    }

    /// Slot range used by this entry (long-name slots, then the 8.3 slot).
    pub fn slots(&self) -> (u32, u32) {
        (self.first_slot, self.slot)
    }

    /// Case-insensitive match on the display or 8.3 name.
    pub fn matches(&self, name: &str) -> bool {
        if self.name().eq_ignore_ascii_case(name) {
            return true;
        }
        let mut short = Name::empty();
        short_name(&self.short, 0, &mut short);
        short.as_str().eq_ignore_ascii_case(name)
    }
}

/// Position in a directory listing.
#[derive(Clone, Copy, Debug)]
pub struct DirIter {
    dir: DirId,
    slot: u32,
    cluster: u32,
    end: bool,
}

/// Short-name checksum stored in each long-name entry.
pub(crate) fn lfn_checksum(short: &[u8; 11]) -> u8 {
    short
        .iter()
        .fold(0u8, |s, &b| ((s & 1) << 7).wrapping_add(s >> 1).wrapping_add(b))
}

/// Render an 8.3 name, applying the NT lower-case flags.
fn short_name(raw: &[u8; 11], nt: u8, out: &mut Name) {
    let base_end = raw[..8].iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    let ext_end = raw[8..].iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    for (i, &b) in raw[..base_end].iter().enumerate() {
        let b = if i == 0 && b == 0x05 { 0xE5 } else { b };
        let b = if nt & 0x08 != 0 { b.to_ascii_lowercase() } else { b };
        out.push(b as u32);
    }
    if ext_end > 0 {
        out.push(b'.' as u32);
        for &b in &raw[8..8 + ext_end] {
            let b = if nt & 0x10 != 0 { b.to_ascii_lowercase() } else { b };
            out.push(b as u32);
        }
    }
}

/// Long-name entries collected before an 8.3 entry.
struct Lfn {
    units: [u16; MAX_LFN * LFN_CHARS],
    count: u8,
    next: u8,
    sum: u8,
    first_slot: u32,
    active: bool,
}

impl Lfn {
    fn new() -> Self {
        Lfn {
            units: [0; MAX_LFN * LFN_CHARS],
            count: 0,
            next: 0,
            sum: 0,
            first_slot: 0,
            active: false,
        }
    }

    fn push(&mut self, raw: &[u8], slot: u32) {
        let ord = raw[0];
        let n = (ord & 0x1F) as usize;
        let well_formed = raw[12] == 0 && raw[26] == 0 && raw[27] == 0 && (1..=MAX_LFN).contains(&n);
        if !well_formed {
            self.active = false;
            return;
        }
        if ord & 0x40 != 0 {
            self.active = true;
            self.count = n as u8;
            self.sum = raw[13];
            self.first_slot = slot;
        } else if !self.active || n as u8 != self.next || raw[13] != self.sum {
            self.active = false;
            return;
        }
        for (k, &off) in LFN_OFFSETS.iter().enumerate() {
            self.units[(n - 1) * LFN_CHARS + k] = u16::from_le_bytes([raw[off], raw[off + 1]]);
        }
        self.next = n as u8 - 1;
    }

    /// The collected name, if complete and matching `sum`.
    fn name(&self, sum: u8, out: &mut Name) -> bool {
        if !self.active || self.next != 0 || self.sum != sum {
            return false;
        }
        let units = &self.units[..self.count as usize * LFN_CHARS];
        let len = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        if len == 0 || len > MAX_NAME {
            return false;
        }
        for c in char::decode_utf16(units[..len].iter().copied()) {
            out.push(c.map_or(0xFFFD, |c| c as u32));
        }
        true
    }
}

impl<D: BlockDevice> Volume<D> {
    /// Start a listing of `dir`.
    pub fn iter(&self, dir: DirId) -> DirIter {
        let cluster = match dir {
            DirId::Root if self.geo.kind == FatKind::Fat32 => self.geo.root_cluster,
            DirId::Root => 0,
            DirId::Cluster(c) => c,
        };
        DirIter {
            dir,
            slot: 0,
            cluster,
            end: false,
        }
    }

    /// Fixed FAT16 root directory?
    pub(crate) fn fixed_root(&self, dir: DirId) -> bool {
        dir == DirId::Root && self.geo.kind == FatKind::Fat16
    }

    /// Sector holding the iterator's current slot, advancing through the
    /// cluster chain as needed. `None` past the end of the directory.
    pub(crate) fn slot_lba(&mut self, it: &mut DirIter) -> Result<Option<u32>, Error> {
        if self.fixed_root(it.dir) {
            if it.slot >= self.geo.root_entries {
                return Ok(None);
            }
            return Ok(Some(self.geo.root_start + it.slot / SLOTS));
        }
        if it.slot >= MAX_DIR_SLOTS {
            return Err(Error::Corrupt(Corrupt::DirTooLong));
        }
        let per_cluster = self.geo.sectors_per_cluster * SLOTS;
        if it.slot > 0 && it.slot.is_multiple_of(per_cluster) {
            match self.next(it.cluster)? {
                Some(c) => it.cluster = c,
                None => return Ok(None),
            }
        } else if !self.geo.is_cluster(it.cluster) {
            return Err(Error::Corrupt(Corrupt::Entry));
        }
        Ok(Some(
            self.geo.cluster_lba(it.cluster) + (it.slot % per_cluster) / SLOTS,
        ))
    }

    /// Next file or sub-directory (skipping `.`, `..`, deleted entries and
    /// the volume label). `None` at the end.
    pub fn next_entry(&mut self, it: &mut DirIter) -> Result<Option<DirEntry>, Error> {
        let mut lfn = Lfn::new();
        while !it.end {
            let slot = it.slot;
            let Some(lba) = self.slot_lba(it)? else {
                it.end = true;
                break;
            };
            self.load(lba)?;
            let at = (slot % SLOTS) as usize * 32;
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&self.buf[at..at + 32]);
            it.slot += 1;
            match raw[0] {
                0x00 => {
                    it.end = true;
                    break;
                }
                0xE5 => {
                    lfn.active = false;
                    continue;
                }
                _ => {}
            }
            let attr = raw[11];
            if attr & 0x3F == ATTR_LFN {
                lfn.push(&raw, slot);
                continue;
            }
            if attr & ATTR_VOLUME != 0 || &raw[..2] == b". " || &raw[..3] == b".. " {
                lfn.active = false;
                continue;
            }
            let mut short = [0u8; 11];
            short.copy_from_slice(&raw[..11]);
            let mut name = Name::empty();
            let has_long = lfn.name(lfn_checksum(&short), &mut name);
            if !has_long {
                name = Name::empty();
                short_name(&short, raw[12], &mut name);
            }
            let lo = u16::from_le_bytes([raw[26], raw[27]]) as u32;
            let hi = u16::from_le_bytes([raw[20], raw[21]]) as u32;
            let cluster = match self.geo.kind {
                FatKind::Fat16 => lo,
                FatKind::Fat32 => (hi << 16) | lo,
            };
            return Ok(Some(DirEntry {
                name,
                short,
                attr: attr & 0x3F,
                cluster,
                size: u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]),
                dir: it.dir,
                first_slot: if has_long { lfn.first_slot } else { slot },
                slot,
            }));
        }
        Ok(None)
    }

    /// Find an entry by name (case-insensitive, long or 8.3 name).
    pub fn find(&mut self, dir: DirId, name: &str) -> Result<DirEntry, Error> {
        let mut it = self.iter(dir);
        while let Some(e) = self.next_entry(&mut it)? {
            if e.matches(name) {
                return Ok(e);
            }
        }
        Err(Error::NotFound)
    }

    /// Open a sub-directory entry.
    pub fn open_dir(&self, e: &DirEntry) -> Result<DirId, Error> {
        if !e.is_dir() {
            return Err(Error::NotADirectory);
        }
        if !self.geo.is_cluster(e.cluster) {
            return Err(Error::Corrupt(Corrupt::Entry));
        }
        Ok(DirId::Cluster(e.cluster))
    }

    /// Look up a `/`-separated path from the root.
    pub fn open_path(&mut self, path: &str) -> Result<DirEntry, Error> {
        let mut dir = DirId::Root;
        let mut parts = path.split('/').filter(|p| !p.is_empty()).peekable();
        while let Some(part) = parts.next() {
            let e = self.find(dir, part)?;
            if parts.peek().is_none() {
                return Ok(e);
            }
            dir = self.open_dir(&e)?;
        }
        Err(Error::NotFound)
    }
}
