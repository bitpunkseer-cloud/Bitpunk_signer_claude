//! Creating and deleting files.
//!
//! Write order keeps existing files safe if the card is pulled: data goes
//! to free clusters first, then the FAT links (both copies), and the
//! directory entry last. An interrupted write leaves only unreachable
//! clusters, never a damaged file.

use crate::dir::{
    lfn_checksum, DirEntry, DirId, DirIter, Name, ATTR_ARCHIVE, ATTR_LFN, LFN_CHARS, LFN_OFFSETS, MAX_LFN,
    SLOTS,
};
use crate::geometry::FatKind;
use crate::{BlockDevice, Corrupt, Error, Sector, Volume, MAX_DIR_SLOTS, SECTOR};

/// Characters FAT forbids in long names.
const RESERVED: &[u8] = b"\"*/:<>?\\|";
/// Fixed timestamp (no clock on the device): 1980-01-01 00:00.
const DOS_DATE: u16 = (1 << 5) | 1;
/// Largest numbered copy tried by `unique_name`.
const MAX_COPY: u32 = 999;

/// Is `name` acceptable as a new long name?
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 255
        && name != "."
        && name != ".."
        && b.iter()
            .all(|&c| (0x20..0x7F).contains(&c) && !RESERVED.contains(&c))
        && !matches!(b[b.len() - 1], b' ' | b'.')
}

/// Short-name character, or `_` for anything FAT does not allow there.
fn short_char(c: u8) -> u8 {
    let c = c.to_ascii_uppercase();
    if c.is_ascii_alphanumeric() || b"$%'-_@~`!(){}^#&".contains(&c) {
        c
    } else {
        b'_'
    }
}

/// FNV-1a over the long name, for hashed short-name tails.
fn name_hash(name: &str) -> u16 {
    let h = name
        .bytes()
        .fold(0x811C_9DC5u32, |h, b| (h ^ b as u32).wrapping_mul(0x0100_0193));
    (h ^ (h >> 16)) as u16
}

/// Candidate 8.3 name number `attempt` for `name`: `BASE~N.EXT`, then
/// `BAhhhh~N.EXT` with a hash of the long name.
fn short_candidate(name: &str, attempt: u32) -> [u8; 11] {
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i + 1..]),
        _ => (name, ""),
    };
    let mut out = [b' '; 11];
    let mut base = [b'_'; 8];
    let mut blen = 0;
    for c in stem.bytes().filter(|&c| c != b' ' && c != b'.') {
        if blen == 8 {
            break;
        }
        base[blen] = short_char(c);
        blen += 1;
    }
    if blen == 0 {
        blen = 1;
    }
    let mut tail = [0u8; 8];
    let mut t = 0;
    let n = if attempt < 4 {
        attempt + 1
    } else {
        (attempt - 4) % 9 + 1
    };
    if attempt >= 4 {
        let h = name_hash(name);
        for shift in [12, 8, 4, 0] {
            tail[t] = b"0123456789ABCDEF"[((h >> shift) & 0xF) as usize];
            t += 1;
        }
        blen = blen.min(2);
    }
    tail[t] = b'~';
    t += 1;
    tail[t] = b'0' + n as u8;
    t += 1;
    let keep = blen.min(8 - t);
    out[..keep].copy_from_slice(&base[..keep]);
    out[keep..keep + t].copy_from_slice(&tail[..t]);
    for (i, c) in ext
        .bytes()
        .filter(|&c| c != b' ' && c != b'.')
        .take(3)
        .enumerate()
    {
        out[8 + i] = short_char(c);
    }
    out
}

impl<D: BlockDevice> Volume<D> {
    /// Sector holding slot `slot` of `dir`, walking from the start.
    fn slot_sector(&mut self, dir: DirId, slot: u32) -> Result<Option<u32>, Error> {
        let mut it = self.iter(dir);
        if self.fixed_root(dir) {
            it.slot = slot;
            return self.slot_lba(&mut it);
        }
        let per_cluster = self.geo.sectors_per_cluster * SLOTS;
        for _ in 0..slot / per_cluster {
            match self.next(it.cluster)? {
                Some(c) => it.cluster = c,
                None => return Ok(None),
            }
        }
        if !self.geo.is_cluster(it.cluster) {
            return Err(Error::Corrupt(Corrupt::Entry));
        }
        Ok(Some(
            self.geo.cluster_lba(it.cluster) + (slot % per_cluster) / SLOTS,
        ))
    }

    /// Change one 32-byte slot.
    fn edit_slot(&mut self, dir: DirId, slot: u32, f: impl FnOnce(&mut [u8])) -> Result<(), Error> {
        let lba = self
            .slot_sector(dir, slot)?
            .ok_or(Error::Corrupt(Corrupt::Entry))?;
        self.load(lba)?;
        let mut s = self.buf;
        let at = (slot % SLOTS) as usize * 32;
        f(&mut s[at..at + 32]);
        self.store(lba, &s)
    }

    fn zero_cluster(&mut self, c: u32) -> Result<(), Error> {
        let lba = self.geo.cluster_lba(c);
        for k in 0..self.geo.sectors_per_cluster {
            self.store(lba + k, &[0; SECTOR])?;
        }
        Ok(())
    }

    /// Find `count` consecutive free slots, growing a sub-directory (or
    /// FAT32 root) by a zeroed cluster when needed. Returns the first slot.
    fn free_slots(&mut self, dir: DirId, count: u32) -> Result<u32, Error> {
        let (first, past_end) = self.find_slots(dir, count)?;
        if past_end {
            // Slots after the end marker are free by definition but may not
            // be zero; end the directory right after the new entries so
            // nothing hidden there becomes visible.
            let after = first + count;
            if after < MAX_DIR_SLOTS {
                if let Some(lba) = self.slot_sector(dir, after)? {
                    self.load(lba)?;
                    if self.buf[(after % SLOTS) as usize * 32] != 0 {
                        self.edit_slot(dir, after, |s| s[0] = 0)?;
                    }
                }
            }
        }
        Ok(first)
    }

    /// First of `count` consecutive free slots, and whether the run lies
    /// at or past the end-of-directory marker.
    fn find_slots(&mut self, dir: DirId, count: u32) -> Result<(u32, bool), Error> {
        let mut it: DirIter = self.iter(dir);
        let mut run_start = 0;
        let mut run = 0;
        let mut ended = false;
        loop {
            let slot = it.slot;
            if slot >= MAX_DIR_SLOTS {
                return Err(Error::DirFull);
            }
            let last = it.cluster;
            match self.slot_lba(&mut it)? {
                Some(lba) => {
                    let first = if ended {
                        0
                    } else {
                        self.load(lba)?;
                        self.buf[(slot % SLOTS) as usize * 32]
                    };
                    ended |= first == 0x00;
                    if ended || first == 0xE5 {
                        if run == 0 {
                            run_start = slot;
                        }
                        run += 1;
                        if run == count {
                            return Ok((run_start, ended));
                        }
                    } else {
                        run = 0;
                    }
                    it.slot += 1;
                }
                None if self.fixed_root(dir) => return Err(Error::DirFull),
                None => {
                    let c = self.find_free()?.ok_or(Error::DiskFull)?;
                    self.zero_cluster(c)?;
                    self.set_fat(c, self.eoc())?;
                    self.set_fat(last, c)?;
                    it.cluster = c;
                    // The new cluster is all zero: the run continues there.
                    let per_cluster = self.geo.sectors_per_cluster * SLOTS;
                    if run == 0 {
                        run_start = slot;
                    }
                    run += per_cluster;
                    if run >= count {
                        return Ok((run_start, true));
                    }
                    it.slot += per_cluster;
                }
            }
        }
    }

    /// A listing positioned at `slot`.
    fn iter_at(&mut self, dir: DirId, slot: u32) -> Result<DirIter, Error> {
        let mut it = self.iter(dir);
        if !self.fixed_root(dir) && slot > 0 {
            // `slot_lba` expects the cluster of the previous slot.
            let per_cluster = self.geo.sectors_per_cluster * SLOTS;
            for _ in 0..(slot - 1) / per_cluster {
                it.cluster = self.next(it.cluster)?.ok_or(Error::Corrupt(Corrupt::Entry))?;
            }
        }
        it.slot = slot;
        Ok(it)
    }

    /// Does `dir` hold an entry with this long or 8.3 name?
    pub fn exists(&mut self, dir: DirId, name: &str) -> Result<bool, Error> {
        match self.find(dir, name) {
            Ok(_) => Ok(true),
            Err(Error::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn short_taken(&mut self, dir: DirId, short: &[u8; 11]) -> Result<bool, Error> {
        let mut it = self.iter(dir);
        while let Some(e) = self.next_entry(&mut it)? {
            if e.short_raw() == short {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `stem.ext`, or `stem-2.ext`, `stem-3.ext`… — the first name not in
    /// `dir`. Existing files are never overwritten.
    pub fn unique_name(&mut self, dir: DirId, stem: &str, ext: &str) -> Result<Name, Error> {
        for n in 1..=MAX_COPY {
            let mut name = Name::empty();
            let mut num = [0u8; 4];
            let suffix = if n == 1 { "" } else { fmt_num(n, &mut num) };
            let ok = name.push_str(stem)
                && (n == 1 || (name.push_str("-") && name.push_str(suffix)))
                && (ext.is_empty() || (name.push_str(".") && name.push_str(ext)));
            if !ok || !valid_name(name.as_str()) {
                return Err(Error::BadName);
            }
            if !self.exists(dir, name.as_str())? {
                return Ok(name);
            }
        }
        Err(Error::Exists)
    }

    /// Create a new file holding `data`. Fails with `Exists` rather than
    /// replacing a file.
    pub fn create(&mut self, dir: DirId, name: &str, data: &[u8]) -> Result<DirEntry, Error> {
        if !valid_name(name) {
            return Err(Error::BadName);
        }
        if data.len() > u32::MAX as usize {
            return Err(Error::TooLarge);
        }
        if self.exists(dir, name)? {
            return Err(Error::Exists);
        }
        let mut short = None;
        for attempt in 0..13 {
            let cand = short_candidate(name, attempt);
            if !self.short_taken(dir, &cand)? {
                short = Some(cand);
                break;
            }
        }
        let short = short.ok_or(Error::Exists)?;
        let lfn = name.len().div_ceil(LFN_CHARS);
        debug_assert!(lfn <= MAX_LFN);
        let first = self.free_slots(dir, lfn as u32 + 1)?;
        let cluster = self.write_chain(data)?;
        let sum = lfn_checksum(&short);
        let units = name.as_bytes();
        for k in 0..lfn {
            // Physical order: highest ordinal first.
            let ord = (lfn - k) as u8;
            let part = ord as usize - 1;
            let flag = if k == 0 { 0x40 } else { 0 };
            self.edit_slot(dir, first + k as u32, |e| {
                e.fill(0);
                e[0] = ord | flag;
                e[11] = ATTR_LFN;
                e[13] = sum;
                for (i, &off) in LFN_OFFSETS.iter().enumerate() {
                    let at = part * LFN_CHARS + i;
                    let u: u16 = match at.cmp(&units.len()) {
                        core::cmp::Ordering::Less => units[at] as u16,
                        core::cmp::Ordering::Equal => 0,
                        core::cmp::Ordering::Greater => 0xFFFF,
                    };
                    e[off..off + 2].copy_from_slice(&u.to_le_bytes());
                }
            })?;
        }
        let slot = first + lfn as u32;
        let size = data.len() as u32;
        let fat32 = self.geo.kind == FatKind::Fat32;
        self.edit_slot(dir, slot, |e| {
            e.fill(0);
            e[..11].copy_from_slice(&short);
            e[11] = ATTR_ARCHIVE;
            for off in [16, 18, 24] {
                e[off..off + 2].copy_from_slice(&DOS_DATE.to_le_bytes());
            }
            if fat32 {
                e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
            }
            e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
            e[28..32].copy_from_slice(&size.to_le_bytes());
        })?;
        let mut it = self.iter_at(dir, first)?;
        self.next_entry(&mut it)?.ok_or(Error::Corrupt(Corrupt::Entry))
    }

    /// Write `data` into newly allocated clusters; returns the first
    /// cluster (0 for empty data). On a full card the partial chain is
    /// released again.
    fn write_chain(&mut self, data: &[u8]) -> Result<u32, Error> {
        let csize = self.geo.cluster_bytes() as usize;
        let mut first = 0;
        let mut prev = 0;
        for chunk in data.chunks(csize) {
            let c = match self.find_free()? {
                Some(c) => c,
                None => {
                    if first != 0 {
                        self.free_chain(first)?;
                    }
                    return Err(Error::DiskFull);
                }
            };
            let lba = self.geo.cluster_lba(c);
            for (k, part) in chunk.chunks(SECTOR).enumerate() {
                let mut s: Sector = [0; SECTOR];
                s[..part.len()].copy_from_slice(part);
                self.store(lba + k as u32, &s)?;
            }
            for k in chunk.len().div_ceil(SECTOR)..self.geo.sectors_per_cluster as usize {
                self.store(lba + k as u32, &[0; SECTOR])?;
            }
            self.set_fat(c, self.eoc())?;
            if prev == 0 {
                first = c;
            } else {
                self.set_fat(prev, c)?;
            }
            prev = c;
        }
        Ok(first)
    }

    /// Delete a file: directory entry first, then its clusters.
    pub fn delete(&mut self, e: &DirEntry) -> Result<(), Error> {
        self.remove(e, false)
    }

    /// Overwrite a file's clusters with zeros, blank its names, then delete
    /// it. (Flash cards may still keep old copies internally.)
    pub fn wipe(&mut self, e: &DirEntry) -> Result<(), Error> {
        self.remove(e, true)
    }

    fn remove(&mut self, e: &DirEntry, wipe: bool) -> Result<(), Error> {
        if e.is_dir() {
            return Err(Error::NotAFile);
        }
        // Re-read the entry: it must still be where the caller saw it.
        let mut it = self.iter_at(e.parent(), e.slots().0)?;
        match self.next_entry(&mut it)? {
            Some(now) if now == *e => {}
            _ => return Err(Error::NotFound),
        }
        let chain = e.size() > 0 && self.geo.is_cluster(e.cluster());
        if chain {
            let need = e.size().div_ceil(self.geo.cluster_bytes());
            if self.chain_len(e.cluster())? < need {
                return Err(Error::Corrupt(Corrupt::ShortChain));
            }
            if wipe {
                let mut c = e.cluster();
                for _ in 0..need {
                    self.zero_cluster(c)?;
                    match self.next(c)? {
                        Some(n) => c = n,
                        None => break,
                    }
                }
            }
        }
        let (first, last) = e.slots();
        for slot in first..=last {
            self.edit_slot(e.parent(), slot, |s| {
                if wipe {
                    s[1..11].fill(b'_');
                    if s[11] & 0x3F == ATTR_LFN {
                        for &off in LFN_OFFSETS.iter() {
                            s[off..off + 2].copy_from_slice(&[0, 0]);
                        }
                    } else {
                        s[20..22].fill(0);
                        s[26..32].fill(0);
                    }
                }
                s[0] = 0xE5;
            })?;
        }
        if chain {
            self.free_chain(e.cluster())?;
        }
        Ok(())
    }
}

/// Decimal digits of `n` (1..=9999).
fn fmt_num(n: u32, buf: &mut [u8; 4]) -> &str {
    let mut len = 0;
    let mut digits = [0u8; 4];
    let mut v = n;
    while v > 0 && len < 4 {
        digits[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        buf[i] = digits[len - 1 - i];
    }
    core::str::from_utf8(&buf[..len]).unwrap_or("0")
}
