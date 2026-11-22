//! File allocation table access.

use crate::geometry::FatKind;
use crate::{BlockDevice, Corrupt, Error, Volume, NO_LBA, SECTOR};

impl<D: BlockDevice> Volume<D> {
    /// Sector and byte offset of cluster `c`'s entry in FAT copy `copy`.
    fn fat_pos(&self, copy: u32, c: u32) -> (u32, usize) {
        let bytes = match self.geo.kind {
            FatKind::Fat16 => 2u64,
            FatKind::Fat32 => 4,
        };
        let off = c as u64 * bytes;
        let lba = self.geo.fat_start + copy * self.geo.fat_size + (off / SECTOR as u64) as u32;
        (lba, (off % SECTOR as u64) as usize)
    }

    fn fat_load(&mut self, copy: u32, lba: u32) -> Result<(), Error> {
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
