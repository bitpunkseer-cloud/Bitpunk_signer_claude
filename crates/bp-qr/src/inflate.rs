//! Raw DEFLATE decompressor (RFC 1951): stored, fixed-Huffman and
//! dynamic-Huffman blocks, canonical codes decoded bit by bit (the method
//! of Mark Adler's `puff`), with every code set checked for validity.
//! Output never exceeds the caller's buffer (decompression bombs stop
//! with `OutputFull`). Allocation-free.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ended inside a block.
    Truncated,
    /// Malformed stream (bad block type, code set, length or distance).
    Invalid,
    /// The output would exceed the buffer.
    OutputFull,
}

const MAX_BITS: usize = 15;
const MAX_LCODES: usize = 286;
const MAX_DCODES: usize = 30;
const FIX_LCODES: usize = 288;

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195,
    227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
    4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

/// Canonical Huffman code: number of codes per length and symbols in
/// code order.
struct Huffman<const N: usize> {
    count: [u16; MAX_BITS + 1],
    symbol: [u16; N],
}

impl<const N: usize> Huffman<N> {
    /// Build from code lengths. Returns the number of unused codes (0 for
    /// a complete code), or an error for an over-subscribed set.
    fn new(lengths: &[u8]) -> Result<(Self, i32), Error> {
        let mut h = Self {
            count: [0; MAX_BITS + 1],
            symbol: [0; N],
        };
        for &l in lengths {
            h.count[l as usize] += 1;
        }
        if h.count[0] as usize == lengths.len() {
            return Ok((h, 0)); // no codes: complete but useless
        }
        let mut left: i32 = 1;
        for len in 1..=MAX_BITS {
            left <<= 1;
            left -= h.count[len] as i32;
            if left < 0 {
                return Err(Error::Invalid);
            }
        }
        let mut offs = [0u16; MAX_BITS + 1];
        for len in 1..MAX_BITS {
            offs[len + 1] = offs[len] + h.count[len];
        }
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                h.symbol[offs[l as usize] as usize] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Ok((h, left))
    }
}

struct State<'a, 'b> {
    input: &'a [u8],
    pos: usize,
    bitbuf: u32,
    bitcnt: u32,
    out: &'b mut [u8],
    outlen: usize,
}

impl State<'_, '_> {
    fn bits(&mut self, need: u32) -> Result<u32, Error> {
        let mut val = self.bitbuf;
        while self.bitcnt < need {
            let b = *self.input.get(self.pos).ok_or(Error::Truncated)?;
            self.pos += 1;
            val |= (b as u32) << self.bitcnt;
            self.bitcnt += 8;
        }
        self.bitbuf = val >> need;
        self.bitcnt -= need;
        Ok(val & ((1u32 << need) - 1))
    }

    fn push(&mut self, b: u8) -> Result<(), Error> {
        *self.out.get_mut(self.outlen).ok_or(Error::OutputFull)? = b;
        self.outlen += 1;
        Ok(())
    }

    fn decode<const N: usize>(&mut self, h: &Huffman<N>) -> Result<u16, Error> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAX_BITS {
            code |= self.bits(1)? as i32;
            let count = h.count[len] as i32;
            if code - count < first {
                return Ok(h.symbol[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(Error::Invalid)
    }

    fn stored(&mut self) -> Result<(), Error> {
        self.bitbuf = 0;
        self.bitcnt = 0; // discard to the byte boundary
        let hdr = self.input.get(self.pos..self.pos + 4).ok_or(Error::Truncated)?;
        let len = u16::from_le_bytes([hdr[0], hdr[1]]);
        let nlen = u16::from_le_bytes([hdr[2], hdr[3]]);
        if len != !nlen {
            return Err(Error::Invalid);
        }
        self.pos += 4;
        let data = self
            .input
            .get(self.pos..self.pos + len as usize)
            .ok_or(Error::Truncated)?;
        let dst = self
            .out
            .get_mut(self.outlen..self.outlen + len as usize)
            .ok_or(Error::OutputFull)?;
        dst.copy_from_slice(data);
        self.pos += len as usize;
        self.outlen += len as usize;
        Ok(())
    }

    fn codes<const L: usize, const D: usize>(
        &mut self,
        lens: &Huffman<L>,
        dists: &Huffman<D>,
    ) -> Result<(), Error> {
        loop {
            let sym = self.decode(lens)? as usize;
            if sym < 256 {
                self.push(sym as u8)?;
            } else if sym == 256 {
                return Ok(());
            } else {
                let li = sym - 257;
                if li >= 29 {
                    return Err(Error::Invalid);
                }
                let len = LEN_BASE[li] as usize + self.bits(LEN_EXTRA[li] as u32)? as usize;
                let di = self.decode(dists)? as usize;
                if di >= 30 {
                    return Err(Error::Invalid);
                }
                let dist = DIST_BASE[di] as usize + self.bits(DIST_EXTRA[di] as u32)? as usize;
                if dist > self.outlen {
                    return Err(Error::Invalid);
                }
                if self.outlen + len > self.out.len() {
                    return Err(Error::OutputFull);
                }
                for _ in 0..len {
                    let b = self.out[self.outlen - dist];
                    self.out[self.outlen] = b;
                    self.outlen += 1;
                }
            }
        }
    }

    fn fixed(&mut self) -> Result<(), Error> {
        let mut lengths = [0u8; FIX_LCODES];
        for (i, l) in lengths.iter_mut().enumerate() {
            *l = match i {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        let (lens, _) = Huffman::<FIX_LCODES>::new(&lengths)?;
        let (dists, _) = Huffman::<MAX_DCODES>::new(&[5u8; MAX_DCODES])?;
        self.codes(&lens, &dists)
    }

    fn dynamic(&mut self) -> Result<(), Error> {
        const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
        let nlen = self.bits(5)? as usize + 257;
        let ndist = self.bits(5)? as usize + 1;
        let ncode = self.bits(4)? as usize + 4;
        if nlen > MAX_LCODES || ndist > MAX_DCODES {
            return Err(Error::Invalid);
        }
        let mut lengths = [0u8; MAX_LCODES + MAX_DCODES];
        for &o in &ORDER[..ncode] {
            lengths[o] = self.bits(3)? as u8;
        }
        let (lencode, left) = Huffman::<19>::new(&lengths[..19])?;
        if left != 0 {
            return Err(Error::Invalid); // code-length code must be complete
        }
        lengths[..19].fill(0);
        let mut index = 0;
        while index < nlen + ndist {
            let sym = self.decode(&lencode)?;
            if sym < 16 {
                lengths[index] = sym as u8;
                index += 1;
            } else {
                let (val, rep) = match sym {
                    16 => {
                        if index == 0 {
                            return Err(Error::Invalid);
                        }
                        (lengths[index - 1], 3 + self.bits(2)? as usize)
                    }
                    17 => (0, 3 + self.bits(3)? as usize),
                    _ => (0, 11 + self.bits(7)? as usize),
                };
                if index + rep > nlen + ndist {
                    return Err(Error::Invalid);
                }
                lengths[index..index + rep].fill(val);
                index += rep;
            }
        }
        if lengths[256] == 0 {
            return Err(Error::Invalid); // no end-of-block code
        }
        let (lens, left) = Huffman::<MAX_LCODES>::new(&lengths[..nlen])?;
        // an incomplete literal/length code is only allowed with a single code
        if left > 0 && nlen - lens.count[0] as usize != 1 {
            return Err(Error::Invalid);
        }
        let (dists, left) = Huffman::<MAX_DCODES>::new(&lengths[nlen..nlen + ndist])?;
        if left > 0 && ndist - dists.count[0] as usize != 1 {
            return Err(Error::Invalid);
        }
        self.codes(&lens, &dists)
    }
}

/// Decompress raw DEFLATE `input` into `out`; returns the output length.
pub fn inflate(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut s = State {
        input,
        pos: 0,
        bitbuf: 0,
        bitcnt: 0,
        out,
        outlen: 0,
    };
    loop {
        let last = s.bits(1)?;
        match s.bits(2)? {
            0 => s.stored()?,
            1 => s.fixed()?,
            2 => s.dynamic()?,
            _ => return Err(Error::Invalid),
        }
        if last == 1 {
            return Ok(s.outlen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_and_fixed_blocks() {
        // stored block "hi": BFINAL=1, BTYPE=00, LEN=2, NLEN=!2
        let stored = [0x01, 0x02, 0x00, 0xFD, 0xFF, b'h', b'i'];
        let mut out = [0u8; 8];
        assert_eq!(inflate(&stored, &mut out), Ok(2));
        assert_eq!(&out[..2], b"hi");
        // our own compressor emits fixed-Huffman blocks
        let data = b"abcabcabcabcabcabc hello hello hello";
        let mut z = [0u8; 128];
        let n = crate::deflate::compress(data, &mut z).unwrap();
        let mut back = [0u8; 64];
        assert_eq!(inflate(&z[..n], &mut back), Ok(data.len()));
        assert_eq!(&back[..data.len()], data);
    }

    #[test]
    fn output_cap_and_bad_input() {
        let data = [b'x'; 1000];
        let mut z = [0u8; 64];
        let n = crate::deflate::compress(&data, &mut z).unwrap();
        let mut small = [0u8; 999];
        assert_eq!(inflate(&z[..n], &mut small), Err(Error::OutputFull));
        let mut out = [0u8; 1000];
        assert_eq!(inflate(&z[..n - 1], &mut out), Err(Error::Truncated));
        assert_eq!(inflate(&[0x07], &mut out), Err(Error::Invalid)); // BTYPE 11
        assert_eq!(
            inflate(&[0x01, 0x02, 0x00, 0x00, 0x00], &mut out),
            Err(Error::Invalid)
        );
    }
}
