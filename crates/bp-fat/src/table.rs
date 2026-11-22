//! File allocation table access.

use crate::geometry::FatKind;
use crate::{BlockDevice, Corrupt, Error, Volume, NO_LBA, SECTOR};

impl<D: BlockDevice> Volume<D> {
    /// Sector and byte offset of cluster `c`'s entry in FAT copy `copy`.
    pub(crate) fn fat_pos(&self, copy: u32, c: u32) -> (u32, usize) {
        let bytes = match self.geo.kind {
            FatKind::Fat16 => 2u64,
            FatKind::Fat32 => 4,
        };
        let off = c as u64 * bytes;
        let lba = self.geo.fat_start + copy * self.geo.fat_size + (off / SECTOR as u64) as u32;
        (lba, (off % SECTOR as u64) as usize)
    }

    pub(crate) fn fat_load(&mut self, copy: u32, lba: u32) -> Result<(), Error> {
        let slot = copy as usize;
        if self.fat_lba[slot] != lba {
            self.fat_lba[slot] = NO_LBA;
            self.dev.read(lba, &mut self.fat_buf[slot])?;
            self.fat_lba[slot] = lba;
        }
        Ok(())
    }

    fn fat_raw(&mut self, copy: u32, c: u32) -> Result<u32, Error> {
        let (lba, i) = self.fat_pos(copy, c);
        self.fat_load(copy, lba)?;
        let b = &self.fat_buf[copy as usize];
        Ok(match self.geo.kind {
            FatKind::Fat16 => u16::from_le_bytes([b[i], b[i + 1]]) as u32,
            FatKind::Fat32 => u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) & 0x0FFF_FFFF,
        })
    }

    /// Write cluster `c`'s entry in every FAT copy (FAT32 keeps the top
    /// four reserved bits).
    pub(crate) fn set_fat(&mut self, c: u32, v: u32) -> Result<(), Error> {
        if !self.geo.is_cluster(c) {
            return Err(Error::Corrupt(Corrupt::Chain));
        }
        self.clear_fsinfo()?;
        for copy in 0..self.geo.fats {
            let (lba, i) = self.fat_pos(copy, c);
            self.fat_load(copy, lba)?;
            let b = &mut self.fat_buf[copy as usize];
            match self.geo.kind {
                FatKind::Fat16 => b[i..i + 2].copy_from_slice(&(v as u16).to_le_bytes()),
                FatKind::Fat32 => {
                    let old = u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
                    let new = (old & 0xF000_0000) | (v & 0x0FFF_FFFF);
                    b[i..i + 4].copy_from_slice(&new.to_le_bytes());
                }
            }
            let sector = self.fat_buf[copy as usize];
            if let Err(e) = self.dev.write(lba, &sector) {
                self.fat_lba[copy as usize] = NO_LBA;
                return Err(e.into());
            }
        }
        Ok(())
    }

    pub(crate) fn eoc(&self) -> u32 {
        match self.geo.kind {
            FatKind::Fat16 => 0xFFFF,
            FatKind::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// The FSInfo free-cluster hints go stale on the first change; mark
    /// them unknown so other systems recount (we never trust them).
    fn clear_fsinfo(&mut self) -> Result<(), Error> {
        if self.fsinfo_cleared || self.geo.fsinfo == 0 {
            return Ok(());
        }
        self.fsinfo_cleared = true;
        let lba = self.geo.fsinfo;
        self.load(lba)?;
        let b = &self.buf;
        let signed = b[0..4] == 0x4161_5252u32.to_le_bytes()
            && b[484..488] == 0x6141_7272u32.to_le_bytes()
            && b[508..512] == 0xAA55_0000u32.to_le_bytes();
        if signed {
            let mut s = self.buf;
            s[488..496].copy_from_slice(&[0xFF; 8]);
            self.store(lba, &s)?;
        }
        Ok(())
    }

    /// First free cluster at or after the search hint (wrapping), or
    /// `None` when the volume is full.
    pub(crate) fn find_free(&mut self) -> Result<Option<u32>, Error> {
        let n = self.geo.clusters;
        let start = if self.geo.is_cluster(self.alloc_hint) {
            self.alloc_hint - 2
        } else {
            0
        };
        for k in 0..n {
            let c = 2 + (start + k) % n;
            if self.fat_get(c)? == 0 {
                self.alloc_hint = c + 1;
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    /// Release a chain (bounded; a loop stops at the first freed link).
    pub(crate) fn free_chain(&mut self, first: u32) -> Result<(), Error> {
        let mut c = first;
        for _ in 0..self.geo.clusters {
            let next = self.next(c)?;
            self.set_fat(c, 0)?;
            match next {
                Some(n) => c = n,
                None => return Ok(()),
            }
        }
        Err(Error::Corrupt(Corrupt::Chain))
    }

    /// FAT entry for cluster `c`; both copies must agree.
    pub(crate) fn fat_get(&mut self, c: u32) -> Result<u32, Error> {
        if !self.geo.is_cluster(c) {
            return Err(Error::Corrupt(Corrupt::Chain));
        }
        let a = self.fat_raw(0, c)?;
        if self.geo.fats == 2 && self.fat_raw(1, c)? != a {
            return Err(Error::Corrupt(Corrupt::FatMismatch));
        }
        Ok(a)
    }

    pub(crate) fn is_eoc(&self, v: u32) -> bool {
        match self.geo.kind {
            FatKind::Fat16 => v >= 0xFFF8,
            FatKind::Fat32 => v >= 0x0FFF_FFF8,
        }
    }

    /// Next cluster in a chain: `None` at end of chain. Free, reserved,
    /// bad or out-of-range links are corruption.
    pub(crate) fn next(&mut self, c: u32) -> Result<Option<u32>, Error> {
        let v = self.fat_get(c)?;
        if self.is_eoc(v) {
            Ok(None)
        } else if self.geo.is_cluster(v) {
            Ok(Some(v))
        } else {
            Err(Error::Corrupt(Corrupt::Chain))
        }
    }

    /// Number of clusters in the chain starting at `c` (bounded by the
    /// volume's cluster count, so loops are reported as corruption).
    pub fn chain_len(&mut self, c: u32) -> Result<u32, Error> {
        if !self.geo.is_cluster(c) {
            return Err(Error::Corrupt(Corrupt::Chain));
        }
        let mut n = 1;
        let mut cur = c;
        while let Some(nx) = self.next(cur)? {
            n += 1;
            if n > self.geo.clusters {
                return Err(Error::Corrupt(Corrupt::Chain));
            }
            cur = nx;
        }
        Ok(n)
    }
}
