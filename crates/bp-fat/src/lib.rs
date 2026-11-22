//! Bitpunk Signer FAT16/FAT32 file system for the microSD card.
//!
//! The card is treated as attacker-made media: every structure (partition
//! table, boot sector, FAT, directory entries) is checked before use, every
//! walk is bounded, and nothing panics on bad input. No allocation; a
//! mounted volume holds three 512-byte sector buffers.
//!
//! Independent implementation; the `fatfs` crate is a test-only reference.
#![no_std]
#![forbid(unsafe_code)]

mod dir;
mod format;
mod geometry;
mod table;
mod write;

pub use dir::{DirEntry, DirId, DirIter, Name, ATTR_DIRECTORY, ATTR_HIDDEN, ATTR_READ_ONLY, ATTR_SYSTEM};
pub use format::format;
pub use geometry::{FatKind, Geometry};
pub use write::valid_name;

/// Bytes per sector. Only 512-byte sectors are supported (all SD cards).
pub const SECTOR: usize = 512;

/// One sector.
pub type Sector = [u8; SECTOR];

/// Largest directory, in 32-byte slots (FAT limit: 2 MiB per directory).
pub const MAX_DIR_SLOTS: u32 = 65_536;

/// Device-level failure (card removed, CRC error, timeout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;

/// A block device addressed in 512-byte sectors.
pub trait BlockDevice {
    /// Number of sectors on the device.
    fn sectors(&self) -> u32;
    fn read(&mut self, lba: u32, buf: &mut Sector) -> Result<(), IoError>;
    fn write(&mut self, lba: u32, buf: &Sector) -> Result<(), IoError>;
}

impl<T: BlockDevice + ?Sized> BlockDevice for &mut T {
    fn sectors(&self) -> u32 {
        (**self).sectors()
    }
    fn read(&mut self, lba: u32, buf: &mut Sector) -> Result<(), IoError> {
        (**self).read(lba, buf)
    }
    fn write(&mut self, lba: u32, buf: &Sector) -> Result<(), IoError> {
        (**self).write(lba, buf)
    }
}

/// File systems the card may carry that this crate refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// Sector size other than 512 bytes.
    SectorSize,
    /// FAT12 (cards under ~2 MB).
    Fat12,
    /// exFAT (most cards over 32 GB as shipped): format on the device.
    Exfat,
    /// GUID partition table.
    Gpt,
    /// FAT32 with FAT mirroring turned off.
    NoMirror,
    /// Any other partition type (NTFS, ext4, …).
    Other,
}

/// Structural damage found while reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Corrupt {
    /// Boot sector values out of range.
    BootSector,
    /// Volume does not fit its partition or the device.
    Geometry,
    /// FAT entry outside the cluster range, free or bad inside a chain.
    Chain,
    /// Chain ends before the file's size is covered.
    ShortChain,
    /// The two FAT copies disagree.
    FatMismatch,
    /// Directory longer than the FAT limit (or looping).
    DirTooLong,
    /// Directory entry with impossible values (size beyond the volume,
    /// cluster out of range).
    Entry,
}

/// File system error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The card failed to read or write.
    Io,
    /// No FAT file system found (blank or unknown card).
    NoFilesystem,
    Unsupported(Unsupported),
    Corrupt(Corrupt),
    NotFound,
    /// A directory was given where a file was expected.
    NotAFile,
    /// A file was given where a directory was expected.
    NotADirectory,
    /// File larger than the caller's buffer.
    TooLarge,
    /// Name not allowed (empty, too long, reserved characters, `.`/`..`).
    BadName,
    /// A file or directory with this name already exists.
    Exists,
    /// No free clusters left.
    DiskFull,
    /// No room for more entries (fixed FAT16 root, or 65536 slots).
    DirFull,
    /// Card too small to format.
    TooSmall,
}

impl From<IoError> for Error {
    fn from(_: IoError) -> Self {
        Error::Io
    }
}

const NO_LBA: u32 = u32::MAX;

/// A mounted FAT volume.
pub struct Volume<D: BlockDevice> {
    dev: D,
    geo: Geometry,
    /// Cached FAT sector per copy (index 0 and 1).
    fat_buf: [Sector; 2],
    fat_lba: [u32; 2],
    /// Cached data or directory sector.
    buf: Sector,
    buf_lba: u32,
    /// Where the next free-cluster search starts.
    alloc_hint: u32,
    /// FSInfo free-count hint already invalidated in this mount.
    fsinfo_cleared: bool,
}

impl<D: BlockDevice> Volume<D> {
    /// Find and check the file system on `dev`.
    pub fn mount(mut dev: D) -> Result<Self, Error> {
        let mut buf = [0u8; SECTOR];
        let geo = geometry::find(&mut dev, &mut buf)?;
        Ok(Volume {
            dev,
            geo,
            fat_buf: [[0; SECTOR]; 2],
            fat_lba: [NO_LBA; 2],
            buf,
            buf_lba: NO_LBA,
            alloc_hint: 2,
            fsinfo_cleared: false,
        })
    }

    pub fn geometry(&self) -> &Geometry {
        &self.geo
    }

    /// Give the device back (unmount).
    pub fn into_inner(self) -> D {
        self.dev
    }

    /// Write a sector, keeping the cache coherent.
    fn store(&mut self, lba: u32, data: &Sector) -> Result<(), Error> {
        if self.buf_lba == lba {
            self.buf_lba = NO_LBA;
        }
        self.dev.write(lba, data)?;
        if lba == self.fat_lba[0] {
            self.fat_lba[0] = NO_LBA;
        }
        if lba == self.fat_lba[1] {
            self.fat_lba[1] = NO_LBA;
        }
        Ok(())
    }

    fn load(&mut self, lba: u32) -> Result<(), Error> {
        if self.buf_lba != lba {
            self.buf_lba = NO_LBA;
            self.dev.read(lba, &mut self.buf)?;
            self.buf_lba = lba;
        }
        Ok(())
    }

    /// Read up to `buf.len()` bytes of a file starting at `offset`.
    /// Returns the number of bytes read (short only at end of file).
    pub fn read_at(&mut self, e: &DirEntry, offset: u32, buf: &mut [u8]) -> Result<usize, Error> {
        if e.is_dir() {
            return Err(Error::NotAFile);
        }
        self.check_size(e)?;
        if offset >= e.size() || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min((e.size() - offset) as usize);
        let csize = self.geo.cluster_bytes();
        let mut cluster = e.cluster();
        for _ in 0..offset / csize {
            cluster = self.next(cluster)?.ok_or(Error::Corrupt(Corrupt::ShortChain))?;
        }
        let mut pos = offset % csize;
        let mut done = 0;
        while done < want {
            let lba = self.geo.cluster_lba(cluster) + pos / SECTOR as u32;
            let at = (pos % SECTOR as u32) as usize;
            let n = (SECTOR - at).min(want - done);
            self.load(lba)?;
            buf[done..done + n].copy_from_slice(&self.buf[at..at + n]);
            done += n;
            pos += n as u32;
            if pos == csize && done < want {
                cluster = self.next(cluster)?.ok_or(Error::Corrupt(Corrupt::ShortChain))?;
                pos = 0;
            }
        }
        Ok(done)
    }

    /// Read a whole file into `buf`.
    pub fn read_file(&mut self, e: &DirEntry, buf: &mut [u8]) -> Result<usize, Error> {
        if e.is_dir() {
            return Err(Error::NotAFile);
        }
        self.check_size(e)?;
        if e.size() as usize > buf.len() {
            return Err(Error::TooLarge);
        }
        if e.size() > 0 {
            // Walk the whole chain first: loops and short chains are refused
            // even when the bytes we need would come back.
            let need = e.size().div_ceil(self.geo.cluster_bytes());
            if self.chain_len(e.cluster())? < need {
                return Err(Error::Corrupt(Corrupt::ShortChain));
            }
        }
        self.read_at(e, 0, buf)
    }

    /// A file's size must fit the volume and point at a real cluster.
    fn check_size(&self, e: &DirEntry) -> Result<(), Error> {
        if e.size() == 0 {
            return Ok(());
        }
        let need = e.size().div_ceil(self.geo.cluster_bytes());
        if need > self.geo.clusters || !self.geo.is_cluster(e.cluster()) {
            return Err(Error::Corrupt(Corrupt::Entry));
        }
        Ok(())
    }
}
