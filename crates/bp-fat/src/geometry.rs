//! Partition table and boot sector parsing.

use crate::{BlockDevice, Corrupt, Error, Sector, Unsupported, SECTOR};

/// FAT variant, decided by cluster count as the specification requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatKind {
    Fat16,
    Fat32,
}

/// Checked layout of a mounted volume. All sector numbers are absolute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub kind: FatKind,
    /// First sector of the volume (partition start, 0 without a table).
    pub start: u32,
    /// Sectors in the volume.
    pub sectors: u32,
    pub sectors_per_cluster: u32,
    /// First sector of FAT copy 0.
    pub fat_start: u32,
    /// Sectors per FAT copy.
    pub fat_size: u32,
    /// Number of FAT copies (1 or 2).
    pub fats: u32,
    /// FAT16 fixed root directory: first sector and slot count.
    pub root_start: u32,
    pub root_entries: u32,
    /// First data sector (cluster 2).
    pub data_start: u32,
    /// Number of data clusters (valid cluster numbers are 2..clusters+2).
    pub clusters: u32,
    /// FAT32 root directory cluster.
    pub root_cluster: u32,
    /// FAT32 FSInfo sector, or 0.
    pub fsinfo: u32,
    pub serial: u32,
}

impl Geometry {
    pub fn cluster_bytes(&self) -> u32 {
        self.sectors_per_cluster * SECTOR as u32
    }

    pub fn is_cluster(&self, c: u32) -> bool {
        c >= 2 && c - 2 < self.clusters
    }

    /// First sector of a data cluster (caller checks `is_cluster`).
    pub fn cluster_lba(&self, c: u32) -> u32 {
        self.data_start + (c - 2) * self.sectors_per_cluster
    }

    pub fn total_bytes(&self) -> u64 {
        self.clusters as u64 * self.cluster_bytes() as u64
    }
}

fn u16_at(s: &[u8], i: usize) -> u32 {
    u16::from_le_bytes([s[i], s[i + 1]]) as u32
}

fn u32_at(s: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([s[i], s[i + 1], s[i + 2], s[i + 3]])
}

fn signed(s: &Sector) -> bool {
    s[510] == 0x55 && s[511] == 0xAA
}

fn is_exfat(s: &Sector) -> bool {
    &s[3..11] == b"EXFAT   "
}

/// Does this sector look like a FAT boot sector (rather than an MBR)?
fn looks_like_boot(s: &Sector) -> bool {
    let jump = s[0] == 0xE9 || (s[0] == 0xEB && s[2] == 0x90);
    let spc = s[13];
    jump && u16_at(s, 11) == 512
        && spc != 0
        && spc.is_power_of_two()
        && u16_at(s, 14) >= 1
        && (s[16] == 1 || s[16] == 2)
}

const FAT_TYPES: [u8; 6] = [0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E];

/// Locate the volume: an unpartitioned card or the first FAT partition.
pub(crate) fn find<D: BlockDevice>(dev: &mut D, s: &mut Sector) -> Result<Geometry, Error> {
    let total = dev.sectors();
    dev.read(0, s)?;
    if !signed(s) {
        return Err(Error::NoFilesystem);
    }
    if is_exfat(s) {
        return Err(Error::Unsupported(Unsupported::Exfat));
    }
    if looks_like_boot(s) {
        return parse(s, 0, total);
    }
    let mut chosen = None;
    let mut other = None;
    for i in 0..4 {
        let p = &s[446 + 16 * i..446 + 16 * (i + 1)];
        let kind = p[4];
        if kind == 0 {
            continue;
        }
        if p[0] != 0x00 && p[0] != 0x80 {
            return Err(Error::NoFilesystem);
        }
        if kind == 0xEE {
            return Err(Error::Unsupported(Unsupported::Gpt));
        }
        let lba = u32_at(p, 8);
        let len = u32_at(p, 12);
        if FAT_TYPES.contains(&kind) {
            chosen.get_or_insert((lba, len));
        } else {
            other.get_or_insert((lba, len));
        }
    }
    let Some((lba, len)) = chosen.or(other) else {
        return Err(Error::NoFilesystem);
    };
    if lba == 0 || len == 0 || lba as u64 + len as u64 > total as u64 {
        return Err(Error::Corrupt(Corrupt::Geometry));
    }
    dev.read(lba, s)?;
    if is_exfat(s) {
        return Err(Error::Unsupported(Unsupported::Exfat));
    }
    if !signed(s) {
        return Err(if chosen.is_some() {
            Error::Corrupt(Corrupt::BootSector)
        } else {
            Error::Unsupported(Unsupported::Other)
        });
    }
    if chosen.is_none() && !looks_like_boot(s) {
        return Err(Error::Unsupported(Unsupported::Other));
    }
    parse(s, lba, len)
}

/// Check a boot sector and derive the layout. `limit` is the partition
/// (or device) size the volume must fit in.
fn parse(s: &Sector, start: u32, limit: u32) -> Result<Geometry, Error> {
    let bad = Error::Corrupt(Corrupt::BootSector);
    let bps = u16_at(s, 11);
    if bps != 512 {
        return Err(if matches!(bps, 1024 | 2048 | 4096) {
            Error::Unsupported(Unsupported::SectorSize)
        } else {
            bad
        });
    }
    let spc = s[13] as u32;
    if spc == 0 || !spc.is_power_of_two() {
        return Err(bad);
    }
    let reserved = u16_at(s, 14);
    let fats = s[16] as u32;
    let root_entries = u16_at(s, 17);
    let tot16 = u16_at(s, 19);
    let fat16_size = u16_at(s, 22);
    let tot32 = u32_at(s, 32);
    let fat32_size = u32_at(s, 36);
    let sectors = if tot16 != 0 { tot16 } else { tot32 };
    let fat_size = if fat16_size != 0 { fat16_size } else { fat32_size };
    if reserved == 0 || !(fats == 1 || fats == 2) || sectors == 0 || fat_size == 0 {
        return Err(bad);
    }
    if sectors > limit {
        return Err(Error::Corrupt(Corrupt::Geometry));
    }
    let root_sectors = (root_entries * 32).div_ceil(SECTOR as u32);
    let meta = reserved as u64 + fats as u64 * fat_size as u64 + root_sectors as u64;
    if meta >= sectors as u64 {
        return Err(Error::Corrupt(Corrupt::Geometry));
    }
    let clusters = ((sectors as u64 - meta) / spc as u64) as u32;
    let kind = if clusters < 4085 {
        return Err(Error::Unsupported(Unsupported::Fat12));
    } else if clusters < 65525 {
        FatKind::Fat16
    } else {
        FatKind::Fat32
    };
    let fat_start = start + reserved;
    let root_start = fat_start + fats * fat_size;
    let data_start = root_start + root_sectors;
    let entry_bytes = if kind == FatKind::Fat16 { 2 } else { 4 };
    if (fat_size as u64 * SECTOR as u64 / entry_bytes) < clusters as u64 + 2 {
        return Err(bad);
    }
    let (root_cluster, fsinfo, serial) = match kind {
        FatKind::Fat16 => {
            if fat16_size == 0 || root_entries == 0 || !root_entries.is_multiple_of(16) {
                return Err(bad);
            }
            (0, 0, u32_at(s, 39))
        }
        FatKind::Fat32 => {
            if fat16_size != 0 || root_entries != 0 || u16_at(s, 42) != 0 {
                return Err(bad);
            }
            if clusters > 0x0FFF_FFF5 {
                return Err(bad);
            }
            if u16_at(s, 40) & 0x80 != 0 {
                return Err(Error::Unsupported(Unsupported::NoMirror));
            }
            let root = u32_at(s, 44);
            if root < 2 || root - 2 >= clusters {
                return Err(bad);
            }
            let info = u16_at(s, 48);
            let fsinfo = if info == 0 || info == 0xFFFF || info >= reserved {
                0
            } else {
                start + info
            };
            (root, fsinfo, u32_at(s, 67))
        }
    };
    Ok(Geometry {
        kind,
        start,
        sectors,
        sectors_per_cluster: spc,
        fat_start,
        fat_size,
        fats,
        root_start,
        root_entries: if kind == FatKind::Fat16 { root_entries } else { 0 },
        data_start,
        clusters,
        root_cluster,
        fsinfo,
        serial,
    })
}
