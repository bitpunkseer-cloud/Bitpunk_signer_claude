//! Minimal deterministic CBOR writer (RFC 8949): unsigned integers, byte and
//! text strings, arrays, maps, tags and booleans. Allocation-free.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BufferTooSmall,
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn put(&mut self, b: &[u8]) -> Result<(), Error> {
        if self.len + b.len() > self.buf.len() {
            return Err(Error::BufferTooSmall);
        }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        Ok(())
    }

    /// Major type + argument in the shortest form.
    fn head(&mut self, major: u8, v: u64) -> Result<(), Error> {
        let m = major << 5;
        if v < 24 {
            self.put(&[m | v as u8])
        } else if v <= 0xFF {
            self.put(&[m | 24, v as u8])
        } else if v <= 0xFFFF {
            let b = (v as u16).to_be_bytes();
            self.put(&[m | 25, b[0], b[1]])
        } else if v <= 0xFFFF_FFFF {
            let b = (v as u32).to_be_bytes();
            self.put(&[m | 26, b[0], b[1], b[2], b[3]])
        } else {
            self.put(&[m | 27])?;
            self.put(&v.to_be_bytes())
        }
    }

    pub fn uint(&mut self, v: u64) -> Result<(), Error> {
        self.head(0, v)
    }

    pub fn bytes(&mut self, b: &[u8]) -> Result<(), Error> {
        self.head(2, b.len() as u64)?;
        self.put(b)
    }

    /// Header of a byte string whose content follows via `reserve`.
    pub fn bytes_header(&mut self, len: usize) -> Result<(), Error> {
        self.head(2, len as u64)
    }

    /// Reserve `n` zeroed bytes and return them for in-place filling.
    pub fn reserve(&mut self, n: usize) -> Result<&mut [u8], Error> {
        if self.len + n > self.buf.len() {
            return Err(Error::BufferTooSmall);
        }
        let start = self.len;
        self.buf[start..start + n].fill(0);
        self.len += n;
        Ok(&mut self.buf[start..start + n])
    }

    pub fn text(&mut self, s: &str) -> Result<(), Error> {
        self.head(3, s.len() as u64)?;
        self.put(s.as_bytes())
    }

    pub fn array(&mut self, n: u64) -> Result<(), Error> {
        self.head(4, n)
    }

    pub fn map(&mut self, n: u64) -> Result<(), Error> {
        self.head(5, n)
    }

    pub fn tag(&mut self, t: u64) -> Result<(), Error> {
        self.head(6, t)
    }

    pub fn bool(&mut self, v: bool) -> Result<(), Error> {
        self.put(&[if v { 0xF5 } else { 0xF4 }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8949_examples() {
        let cases: [(u64, &[u8]); 7] = [
            (0, &[0x00]),
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (100, &[0x18, 0x64]),
            (1000, &[0x19, 0x03, 0xe8]),
            (1_000_000, &[0x1a, 0x00, 0x0f, 0x42, 0x40]),
            (
                1_000_000_000_000,
                &[0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00],
            ),
        ];
        for (v, enc) in cases {
            let mut b = [0u8; 16];
            let mut w = Writer::new(&mut b);
            w.uint(v).unwrap();
            assert_eq!(w.as_bytes(), enc, "{v}");
        }
        let mut b = [0u8; 16];
        let mut w = Writer::new(&mut b);
        w.text("IETF").unwrap();
        assert_eq!(w.as_bytes(), &[0x64, 0x49, 0x45, 0x54, 0x46]);
    }
}
