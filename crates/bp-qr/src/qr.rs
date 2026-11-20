//! QR Code Model 2 encoder (ISO/IEC 18004). Versions 1-40, ECC L/M/Q/H,
//! numeric / alphanumeric / byte modes, automatic mask selection.
//! Allocation-free: everything lives in fixed-size buffers.

pub const MAX_VERSION: u8 = 40;
pub const MAX_SIZE: usize = 17 + 4 * MAX_VERSION as usize; // 177
pub(crate) const MODULE_BYTES: usize = (MAX_SIZE * MAX_SIZE).div_ceil(8);
/// Raw codewords of version 40.
pub(crate) const MAX_CODEWORDS: usize = 3706;
const MAX_ECC_BYTES_PER_BLOCK: usize = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ecc {
    Low,
    Medium,
    Quartile,
    High,
}

impl Ecc {
    pub(crate) const fn ordinal(self) -> usize {
        match self {
            Ecc::Low => 0,
            Ecc::Medium => 1,
            Ecc::Quartile => 2,
            Ecc::High => 3,
        }
    }
    pub(crate) const fn format_bits(self) -> u32 {
        match self {
            Ecc::Low => 1,
            Ecc::Medium => 0,
            Ecc::Quartile => 3,
            Ecc::High => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Numeric,
    Alphanumeric,
    Byte,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Data does not fit in the allowed version range.
    DataTooLong,
    InvalidVersion,
    InvalidMask,
}

pub(crate) const ALNUM: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

// ISO/IEC 18004 Table 9: error correction codewords per block, and number of blocks.
pub(crate) static ECC_CODEWORDS_PER_BLOCK: [[u8; 41]; 4] = [
    [
        0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26,
        28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    [
        0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    ],
    [
        0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30,
        30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    [
        0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30,
        30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
];
pub(crate) static NUM_ECC_BLOCKS: [[u8; 41]; 4] = [
    [
        0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15,
        16, 17, 18, 19, 19, 20, 21, 22, 24, 25,
    ],
    [
        0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26,
        28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
    ],
    [
        0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34,
        35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68,
    ],
    [
        0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40,
        42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81,
    ],
];

/// Smallest mode that can represent `data`.
pub fn best_mode(data: &[u8]) -> Mode {
    if data.iter().all(u8::is_ascii_digit) {
        Mode::Numeric
    } else if data.iter().all(|c| ALNUM.contains(c)) {
        Mode::Alphanumeric
    } else {
        Mode::Byte
    }
}

pub(crate) const fn char_count_bits(mode: Mode, ver: u8) -> usize {
    let i = if ver <= 9 {
        0
    } else if ver <= 26 {
        1
    } else {
        2
    };
    match mode {
        Mode::Numeric => [10, 12, 14][i],
        Mode::Alphanumeric => [9, 11, 13][i],
        Mode::Byte => [8, 16, 16][i],
    }
}

const fn mode_indicator(mode: Mode) -> u32 {
    match mode {
        Mode::Numeric => 0x1,
        Mode::Alphanumeric => 0x2,
        Mode::Byte => 0x4,
    }
}

fn data_bits(mode: Mode, len: usize) -> usize {
    match mode {
        Mode::Numeric => 10 * (len / 3) + [0, 4, 7][len % 3],
        Mode::Alphanumeric => 11 * (len / 2) + 6 * (len % 2),
        Mode::Byte => 8 * len,
    }
}

/// Data modules (excluding function patterns) of a version.
pub const fn num_raw_data_modules(ver: u8) -> usize {
    let v = ver as usize;
    let mut result = (16 * v + 128) * v + 64;
    if v >= 2 {
        let numalign = v / 7 + 2;
        result -= (25 * numalign - 10) * numalign - 55;
        if v >= 7 {
            result -= 36;
        }
    }
    result
}

/// Data codewords available at a version and ECC level.
pub fn num_data_codewords(ver: u8, ecc: Ecc) -> usize {
    let e = ecc.ordinal();
    num_raw_data_modules(ver) / 8
        - ECC_CODEWORDS_PER_BLOCK[e][ver as usize] as usize * NUM_ECC_BLOCKS[e][ver as usize] as usize
}

/// Maximum characters of `mode` at a version and ECC level.
pub fn capacity(ver: u8, ecc: Ecc, mode: Mode) -> usize {
    let bits = num_data_codewords(ver, ecc) * 8;
    let header = 4 + char_count_bits(mode, ver);
    if bits < header {
        return 0;
    }
    let avail = bits - header;
    let max_count = (1usize << char_count_bits(mode, ver)) - 1;
    let n = match mode {
        Mode::Numeric => {
            let full = avail / 10 * 3;
            let rest = avail % 10;
            full + if rest >= 7 {
                2
            } else if rest >= 4 {
                1
            } else {
                0
            }
        }
        Mode::Alphanumeric => avail / 11 * 2 + usize::from(avail % 11 >= 6),
        Mode::Byte => avail / 8,
    };
    n.min(max_count)
}

/// Smallest version in `min..=max` that fits `len` characters of `mode`.
pub fn fit_version(len: usize, mode: Mode, ecc: Ecc, min: u8, max: u8) -> Option<u8> {
    (min..=max).find(|&v| {
        let need = 4 + char_count_bits(mode, v) + data_bits(mode, len);
        need <= num_data_codewords(v, ecc) * 8 && len < (1 << char_count_bits(mode, v))
    })
}

// ---------- GF(256) Reed-Solomon ----------

fn gf_mul(x: u8, y: u8) -> u8 {
    let mut z: u32 = 0;
    for i in (0..8).rev() {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= ((y as u32 >> i) & 1) * x as u32;
    }
    z as u8
}

fn rs_divisor(degree: usize, out: &mut [u8; MAX_ECC_BYTES_PER_BLOCK]) {
    out.fill(0);
    out[degree - 1] = 1;
    let mut root: u8 = 1;
    for _ in 0..degree {
        for j in 0..degree {
            out[j] = gf_mul(out[j], root);
            if j + 1 < degree {
                out[j] ^= out[j + 1];
            }
        }
        root = gf_mul(root, 0x02);
    }
}

fn rs_remainder(data: &[u8], divisor: &[u8], out: &mut [u8]) {
    let d = divisor.len();
    out[..d].fill(0);
    for &b in data {
        let factor = b ^ out[0];
        out.copy_within(1..d, 0);
        out[d - 1] = 0;
        for i in 0..d {
            out[i] ^= gf_mul(divisor[i], factor);
        }
    }
}

// ---------- bit buffer ----------

struct Bits<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Bits<'_> {
    fn push(&mut self, value: u32, n: usize) {
        for i in (0..n).rev() {
            let bit = (value >> i) & 1;
            if bit == 1 {
                self.buf[self.len / 8] |= 0x80 >> (self.len % 8);
            }
            self.len += 1;
        }
    }
}

// ---------- symbol ----------

/// A finished QR symbol.
#[derive(Clone)]
pub struct QrCode {
    version: u8,
    size: usize,
    ecc: Ecc,
    mask: u8,
    modules: [u8; MODULE_BYTES],
}

pub(crate) struct Builder {
    pub(crate) size: usize,
    modules: [u8; MODULE_BYTES],
    function: [u8; MODULE_BYTES],
}

impl Builder {
    fn get(&self, x: usize, y: usize) -> bool {
        let i = y * self.size + x;
        self.modules[i / 8] >> (i % 8) & 1 == 1
    }
    fn set(&mut self, x: usize, y: usize, dark: bool) {
        let i = y * self.size + x;
        if dark {
            self.modules[i / 8] |= 1 << (i % 8);
        } else {
            self.modules[i / 8] &= !(1 << (i % 8));
        }
    }
    pub(crate) fn is_function(&self, x: usize, y: usize) -> bool {
        let i = y * self.size + x;
        self.function[i / 8] >> (i % 8) & 1 == 1
    }
    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        self.set(x, y, dark);
        let i = y * self.size + x;
        self.function[i / 8] |= 1 << (i % 8);
    }

    /// Function-pattern map of a symbol (finders, timing, alignment,
    /// format and version areas) for the decoder.
    pub(crate) fn function_map(ver: u8) -> Builder {
        let size = 17 + 4 * ver as usize;
        let mut b = Builder {
            size,
            modules: [0; MODULE_BYTES],
            function: [0; MODULE_BYTES],
        };
        b.draw_function_patterns(ver, Ecc::Low);
        b
    }

    fn draw_function_patterns(&mut self, ver: u8, ecc: Ecc) {
        let size = self.size;
        for i in 0..size {
            self.set_function(6, i, i % 2 == 0);
            self.set_function(i, 6, i % 2 == 0);
        }
        self.draw_finder(3, 3);
        self.draw_finder(size as i32 - 4, 3);
        self.draw_finder(3, size as i32 - 4);
        let mut pos = [0usize; 7];
        let n = alignment_positions(ver, &mut pos);
        for i in 0..n {
            for j in 0..n {
                if (i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0) {
                    continue;
                }
                self.draw_alignment(pos[i], pos[j]);
            }
        }
        self.draw_format(ecc, 0);
        self.draw_version(ver);
    }

    fn draw_finder(&mut self, x: i32, y: i32) {
        for dy in -4..=4i32 {
            for dx in -4..=4i32 {
                let (xx, yy) = (x + dx, y + dy);
                if xx >= 0 && yy >= 0 && (xx as usize) < self.size && (yy as usize) < self.size {
                    let dist = dx.abs().max(dy.abs());
                    self.set_function(xx as usize, yy as usize, dist != 2 && dist != 4);
                }
            }
        }
    }

    fn draw_alignment(&mut self, x: usize, y: usize) {
        for dy in -2..=2i32 {
            for dx in -2..=2i32 {
                let d = dx.abs().max(dy.abs());
                self.set_function((x as i32 + dx) as usize, (y as i32 + dy) as usize, d != 1);
            }
        }
    }

    fn draw_format(&mut self, ecc: Ecc, mask: u8) {
        let size = self.size;
        let data = (ecc.format_bits() << 3) | mask as u32;
        let mut rem = data;
        for _ in 0..10 {
            rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        }
        let bits = ((data << 10) | rem) ^ 0x5412;
        let bit = |i: usize| (bits >> i) & 1 == 1;
        for i in 0..6 {
            self.set_function(8, i, bit(i));
        }
        self.set_function(8, 7, bit(6));
        self.set_function(8, 8, bit(7));
        self.set_function(7, 8, bit(8));
        for i in 9..15 {
            self.set_function(14 - i, 8, bit(i));
        }
        for i in 0..8 {
            self.set_function(size - 1 - i, 8, bit(i));
        }
        for i in 8..15 {
            self.set_function(8, size - 15 + i, bit(i));
        }
        self.set_function(8, size - 8, true);
    }

    fn draw_version(&mut self, ver: u8) {
        if ver < 7 {
            return;
        }
        let mut rem = ver as u32;
        for _ in 0..12 {
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        }
        let bits = ((ver as u32) << 12) | rem;
        for i in 0..18 {
            let bit = (bits >> i) & 1 == 1;
            let a = self.size - 11 + i % 3;
            let b = i / 3;
            self.set_function(a, b, bit);
            self.set_function(b, a, bit);
        }
    }

    fn draw_codewords(&mut self, data: &[u8]) {
        let size = self.size;
        let mut i = 0usize;
        let mut right = size as i32 - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vert in 0..size {
                for j in 0..2 {
                    let x = (right - j) as usize;
                    let upward = (right + 1) & 2 == 0;
                    let y = if upward { size - 1 - vert } else { vert };
                    if !self.is_function(x, y) && i < data.len() * 8 {
                        let bit = (data[i >> 3] >> (7 - (i & 7))) & 1 == 1;
                        self.set(x, y, bit);
                        i += 1;
                    }
                }
            }
            right -= 2;
        }
    }

    fn apply_mask(&mut self, mask: u8) {
        for y in 0..self.size {
            for x in 0..self.size {
                if self.is_function(x, y) {
                    continue;
                }
                if mask_bit(mask, x, y) {
                    let v = self.get(x, y);
                    self.set(x, y, !v);
                }
            }
        }
    }

    /// ISO 18004 penalty rules N1..N4 (finder-like run detection as in
    /// Nayuki's reference implementation).
    fn penalty(&self) -> i32 {
        let size = self.size as i32;
        let mut result = 0;
        for pass in 0..2 {
            for a in 0..size {
                let mut run_color = false;
                let mut run_len = 0;
                let mut hist = FinderRuns::new(size);
                for b in 0..size {
                    let (x, y) = if pass == 0 { (b, a) } else { (a, b) };
                    let c = self.get(x as usize, y as usize);
                    if c == run_color {
                        run_len += 1;
                        if run_len == 5 {
                            result += 3;
                        } else if run_len > 5 {
                            result += 1;
                        }
                    } else {
                        hist.add(run_len);
                        if !run_color {
                            result += hist.count() * 40;
                        }
                        run_color = c;
                        run_len = 1;
                    }
                }
                result += hist.terminate(run_color, run_len) * 40;
            }
        }
        for y in 0..self.size - 1 {
            for x in 0..self.size - 1 {
                let c = self.get(x, y);
                if c == self.get(x + 1, y) && c == self.get(x, y + 1) && c == self.get(x + 1, y + 1) {
                    result += 3;
                }
            }
        }
        let total = size * size;
        let mut dark = 0;
        for y in 0..self.size {
            for x in 0..self.size {
                dark += self.get(x, y) as i32;
            }
        }
        let k = ((dark * 20 - total * 10).abs() + total - 1) / total - 1;
        result + k * 10
    }
}

struct FinderRuns {
    size: i32,
    h: [i32; 7],
}

impl FinderRuns {
    fn new(size: i32) -> Self {
        Self { size, h: [0; 7] }
    }
    fn add(&mut self, mut len: i32) {
        if self.h[0] == 0 {
            len += self.size; // light border before the first run
        }
        self.h.copy_within(0..6, 1);
        self.h[0] = len;
    }
    fn count(&self) -> i32 {
        let h = &self.h;
        let n = h[1];
        let core = n > 0 && h[2] == n && h[3] == n * 3 && h[4] == n && h[5] == n;
        i32::from(core && h[0] >= n * 4 && h[6] >= n) + i32::from(core && h[6] >= n * 4 && h[0] >= n)
    }
    fn terminate(mut self, color: bool, mut len: i32) -> i32 {
        if color {
            self.add(len);
            len = 0;
        }
        len += self.size; // light border after the last run
        self.add(len);
        self.count()
    }
}

/// True where data mask pattern `mask` (0..8) inverts module (x, y).
pub(crate) fn mask_bit(mask: u8, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y).is_multiple_of(2),
        1 => y.is_multiple_of(2),
        2 => x.is_multiple_of(3),
        3 => (x + y).is_multiple_of(3),
        4 => (x / 3 + y / 2).is_multiple_of(2),
        5 => x * y % 2 + x * y % 3 == 0,
        6 => (x * y % 2 + x * y % 3).is_multiple_of(2),
        _ => ((x + y) % 2 + x * y % 3).is_multiple_of(2),
    }
}

pub(crate) fn alignment_positions(ver: u8, out: &mut [usize; 7]) -> usize {
    if ver == 1 {
        return 0;
    }
    let v = ver as usize;
    let n = v / 7 + 2;
    let size = 17 + 4 * v;
    let step = (v * 8 + n * 3 + 5) / (n * 4 - 4) * 2;
    out[0] = 6;
    for i in 0..n - 1 {
        out[n - 1 - i] = size - 7 - i * step;
    }
    n
}

impl QrCode {
    /// Encode `data` with the smallest suitable mode and version in
    /// `min_ver..=max_ver`. `mask` forces a mask pattern (0..8).
    pub fn encode(
        data: &[u8],
        ecc: Ecc,
        min_ver: u8,
        max_ver: u8,
        mask: Option<u8>,
    ) -> Result<QrCode, Error> {
        Self::encode_mode(data, best_mode(data), ecc, min_ver, max_ver, mask)
    }

    pub fn encode_mode(
        data: &[u8],
        mode: Mode,
        ecc: Ecc,
        min_ver: u8,
        max_ver: u8,
        mask: Option<u8>,
    ) -> Result<QrCode, Error> {
        if min_ver < 1 || max_ver > MAX_VERSION || min_ver > max_ver {
            return Err(Error::InvalidVersion);
        }
        if mask.is_some_and(|m| m > 7) {
            return Err(Error::InvalidMask);
        }
        let ver = fit_version(data.len(), mode, ecc, min_ver, max_ver).ok_or(Error::DataTooLong)?;
        let cap_bytes = num_data_codewords(ver, ecc);

        // data codewords
        let mut codewords = [0u8; MAX_CODEWORDS];
        let mut bits = Bits {
            buf: &mut codewords,
            len: 0,
        };
        bits.push(mode_indicator(mode), 4);
        bits.push(data.len() as u32, char_count_bits(mode, ver));
        match mode {
            Mode::Numeric => {
                for chunk in data.chunks(3) {
                    let v = chunk.iter().fold(0u32, |a, &c| a * 10 + (c - b'0') as u32);
                    bits.push(v, chunk.len() * 3 + 1);
                }
            }
            Mode::Alphanumeric => {
                let val = |c: u8| ALNUM.iter().position(|&a| a == c).unwrap_or(0) as u32;
                for chunk in data.chunks(2) {
                    if chunk.len() == 2 {
                        bits.push(val(chunk[0]) * 45 + val(chunk[1]), 11);
                    } else {
                        bits.push(val(chunk[0]), 6);
                    }
                }
            }
            Mode::Byte => {
                for &b in data {
                    bits.push(b as u32, 8);
                }
            }
        }
        let cap_bits = cap_bytes * 8;
        let term = (cap_bits - bits.len).min(4);
        bits.push(0, term);
        let pad = (8 - bits.len % 8) % 8;
        bits.push(0, pad);
        let mut pad_byte = 0xEC;
        while bits.len < cap_bits {
            bits.push(pad_byte, 8);
            pad_byte ^= 0xEC ^ 0x11;
        }

        // error correction and interleaving
        let e = ecc.ordinal();
        let nblocks = NUM_ECC_BLOCKS[e][ver as usize] as usize;
        let ecc_len = ECC_CODEWORDS_PER_BLOCK[e][ver as usize] as usize;
        let raw = num_raw_data_modules(ver) / 8;
        let nshort = nblocks - raw % nblocks;
        let short_len = raw / nblocks;
        let mut divisor = [0u8; MAX_ECC_BYTES_PER_BLOCK];
        rs_divisor(ecc_len, &mut divisor);
        let mut eccs = [0u8; MAX_CODEWORDS];
        let mut block_start = [0usize; 81];
        let mut k = 0;
        for b in 0..nblocks {
            let dlen = short_len - ecc_len + usize::from(b >= nshort);
            block_start[b] = k;
            rs_remainder(
                &codewords[k..k + dlen],
                &divisor[..ecc_len],
                &mut eccs[b * ecc_len..b * ecc_len + ecc_len],
            );
            k += dlen;
        }
        let mut out = [0u8; MAX_CODEWORDS];
        let mut n = 0;
        // data part: byte i of every block (short blocks have one byte fewer)
        for i in 0..short_len - ecc_len + 1 {
            for b in 0..nblocks {
                let dlen = short_len - ecc_len + usize::from(b >= nshort);
                if i < dlen {
                    out[n] = codewords[block_start[b] + i];
                    n += 1;
                }
            }
        }
        for i in 0..ecc_len {
            for b in 0..nblocks {
                out[n] = eccs[b * ecc_len + i];
                n += 1;
            }
        }
        debug_assert_eq!(n, raw);

        // draw
        let size = 17 + 4 * ver as usize;
        let mut q = Builder {
            size,
            modules: [0; MODULE_BYTES],
            function: [0; MODULE_BYTES],
        };
        q.draw_function_patterns(ver, ecc);
        q.draw_codewords(&out[..raw]);
        let chosen = match mask {
            Some(m) => m,
            None => {
                let mut best = 0;
                let mut best_score = i32::MAX;
                for m in 0..8 {
                    q.apply_mask(m);
                    q.draw_format(ecc, m);
                    let s = q.penalty();
                    if s < best_score {
                        best = m;
                        best_score = s;
                    }
                    q.apply_mask(m); // undo (XOR)
                }
                best
            }
        };
        q.apply_mask(chosen);
        q.draw_format(ecc, chosen);
        Ok(QrCode {
            version: ver,
            size,
            ecc,
            mask: chosen,
            modules: q.modules,
        })
    }

    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn size(&self) -> usize {
        self.size
    }
    pub fn ecc(&self) -> Ecc {
        self.ecc
    }
    pub fn mask(&self) -> u8 {
        self.mask
    }
    /// True for a dark module. Out-of-range coordinates are light.
    pub fn get(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        let i = y * self.size + x;
        self.modules[i / 8] >> (i % 8) & 1 == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacities_match_iso_table() {
        // ISO 18004 Table 7 spot checks
        assert_eq!(capacity(1, Ecc::Low, Mode::Numeric), 41);
        assert_eq!(capacity(1, Ecc::Low, Mode::Alphanumeric), 25);
        assert_eq!(capacity(1, Ecc::Low, Mode::Byte), 17);
        assert_eq!(capacity(1, Ecc::High, Mode::Byte), 7);
        assert_eq!(capacity(10, Ecc::Medium, Mode::Alphanumeric), 311);
        assert_eq!(capacity(40, Ecc::Low, Mode::Numeric), 7089);
        assert_eq!(capacity(40, Ecc::Low, Mode::Alphanumeric), 4296);
        assert_eq!(capacity(40, Ecc::Low, Mode::Byte), 2953);
    }

    #[test]
    fn alignment_positions_v7_and_v32() {
        let mut p = [0usize; 7];
        assert_eq!(alignment_positions(7, &mut p), 3);
        assert_eq!(&p[..3], &[6, 22, 38]);
        assert_eq!(alignment_positions(32, &mut p), 6);
        assert_eq!(&p[..6], &[6, 34, 60, 86, 112, 138]);
    }
}
