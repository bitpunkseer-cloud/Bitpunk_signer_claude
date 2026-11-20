//! Raw DEFLATE compressor (RFC 1951): greedy LZ77 with hash chains and one
//! fixed-Huffman block. Match distances never exceed 1024 bytes, so the
//! stream decompresses with a 2^10 window (zlib `wbits=-10`, as BBQr uses).
//! Allocation-free.

pub const WINDOW: usize = 1024;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const HASH_BITS: usize = 12;
const MAX_CHAIN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BufferTooSmall,
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195,
    227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 20] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
];
const DIST_EXTRA: [u8; 20] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8];

struct BitWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
    acc: u32,
    nbits: u32,
}

impl BitWriter<'_> {
    /// Append `n` bits of `v`, least significant bit first.
    fn put(&mut self, v: u32, n: u32) -> Result<(), Error> {
        self.acc |= v << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            *self.out.get_mut(self.pos).ok_or(Error::BufferTooSmall)? = self.acc as u8;
            self.pos += 1;
            self.acc >>= 8;
            self.nbits -= 8;
        }
        Ok(())
    }

    /// Huffman codes are defined most significant bit first.
    fn put_code(&mut self, code: u32, n: u32) -> Result<(), Error> {
        self.put(code.reverse_bits() >> (32 - n), n)
    }

    fn finish(mut self) -> Result<usize, Error> {
        if self.nbits > 0 {
            *self.out.get_mut(self.pos).ok_or(Error::BufferTooSmall)? = self.acc as u8;
            self.pos += 1;
        }
        Ok(self.pos)
    }

    fn literal(&mut self, sym: u32) -> Result<(), Error> {
        match sym {
            0..=143 => self.put_code(0x30 + sym, 8),
            144..=255 => self.put_code(0x190 + sym - 144, 9),
            256..=279 => self.put_code(sym - 256, 7),
            _ => self.put_code(0xC0 + sym - 280, 8),
        }
    }

    fn matched(&mut self, len: usize, dist: usize) -> Result<(), Error> {
        let li = LEN_BASE
            .iter()
            .rposition(|&b| b as usize <= len)
            .expect("len >= 3");
        self.literal(257 + li as u32)?;
        if LEN_EXTRA[li] > 0 {
            self.put((len - LEN_BASE[li] as usize) as u32, LEN_EXTRA[li] as u32)?;
        }
        let di = DIST_BASE
            .iter()
            .rposition(|&b| b as usize <= dist)
            .expect("dist >= 1");
        self.put_code(di as u32, 5)?;
        if DIST_EXTRA[di] > 0 {
            self.put((dist - DIST_BASE[di] as usize) as u32, DIST_EXTRA[di] as u32)?;
        }
        Ok(())
    }
}

fn hash(d: &[u8], i: usize) -> usize {
    let v = (d[i] as u32) << 16 | (d[i + 1] as u32) << 8 | d[i + 2] as u32;
    (v.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
}

/// Compress `data` into `out`; returns the compressed length.
pub fn compress(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut w = BitWriter {
        out,
        pos: 0,
        acc: 0,
        nbits: 0,
    };
    w.put(1, 1)?; // BFINAL
    w.put(1, 2)?; // BTYPE = fixed Huffman
                  // head/prev hold position + 1 (0 = empty)
    let mut head = [0u32; 1 << HASH_BITS];
    let mut prev = [0u32; WINDOW];
    let mut i = 0;
    let n = data.len();
    let insert = |pos: usize, head: &mut [u32; 1 << HASH_BITS], prev: &mut [u32; WINDOW]| {
        if pos + MIN_MATCH <= n {
            let h = hash(data, pos);
            prev[pos % WINDOW] = head[h];
            head[h] = pos as u32 + 1;
        }
    };
    while i < n {
        let mut best_len = 0;
        let mut best_dist = 0;
        if i + MIN_MATCH <= n {
            let mut cand = head[hash(data, i)];
            let mut steps = 0;
            while cand != 0 && steps < MAX_CHAIN {
                let c = cand as usize - 1;
                if i - c > WINDOW - 1 || c >= i {
                    break;
                }
                let max = (n - i).min(MAX_MATCH);
                let mut l = 0;
                while l < max && data[c + l] == data[i + l] {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_dist = i - c;
                    if l == max {
                        break;
                    }
                }
                let next = prev[c % WINDOW];
                // stop when the chain leaves the window (slot reused)
                if next == 0 || (next as usize - 1) >= c {
                    break;
                }
                cand = next;
                steps += 1;
            }
        }
        if best_len >= MIN_MATCH {
            w.matched(best_len, best_dist)?;
            for k in 0..best_len {
                insert(i + k, &mut head, &mut prev);
            }
            i += best_len;
        } else {
            w.literal(data[i] as u32)?;
            insert(i, &mut head, &mut prev);
            i += 1;
        }
    }
    w.literal(256)?; // end of block
    w.finish()
}
