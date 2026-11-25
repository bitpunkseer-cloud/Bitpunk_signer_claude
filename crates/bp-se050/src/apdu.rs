//! ISO 7816-4 command APDUs and BER-TLV, the way the SE05x applet takes
//! them (lengths as in the `iso7816` crate the reference driver uses: an
//! answer of any length is asked for with extended Lc/Le).

/// Largest APDU the vault sends or receives.
pub const APDU_MAX: usize = 600;

/// What answer length the command asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Le {
    /// No data expected (case 1/3).
    None,
    /// Up to `n` bytes (1..=256), short encoding.
    Short(u16),
    /// As much as the card has (extended encoding).
    Max,
}

#[derive(Clone, Copy, Debug)]
pub struct Apdu<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: &'a [u8],
    pub le: Le,
}

impl Apdu<'_> {
    /// Encode into `out`; the length. `None` if it does not fit.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&[self.cla, self.ins, self.p1, self.p2])?;
        let n = self.data.len();
        let extended = matches!(self.le, Le::Max) || n > 255;
        if n > 0 {
            if extended {
                w.bytes(&[0, (n >> 8) as u8, n as u8])?;
            } else {
                w.bytes(&[n as u8])?;
            }
            w.bytes(self.data)?;
        }
        match (self.le, extended, n > 0) {
            (Le::None, _, _) => {}
            (Le::Short(l), false, _) => w.bytes(&[(l & 0xFF) as u8])?,
            (Le::Short(l), true, true) => w.bytes(&[(l >> 8) as u8, l as u8])?,
            (Le::Short(l), true, false) => w.bytes(&[0, (l >> 8) as u8, l as u8])?,
            (Le::Max, _, true) => w.bytes(&[0, 0])?,
            (Le::Max, _, false) => w.bytes(&[0, 0, 0])?,
        }
        Some(w.len())
    }
}

/// A command APDU taken apart (the simulated chip, and SCP03 wrapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parsed<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: &'a [u8],
    /// Lc/Le in the extended form.
    pub extended: bool,
    /// Le present.
    pub le: bool,
}

pub fn parse(a: &[u8]) -> Option<Parsed<'_>> {
    let (head, body) = a.split_at_checked(4)?;
    let mut p = Parsed {
        cla: head[0],
        ins: head[1],
        p1: head[2],
        p2: head[3],
        data: &[],
        extended: false,
        le: false,
    };
    match body.len() {
        0 => {}
        1 => p.le = true,
        _ if body[0] == 0 && body.len() >= 3 => {
            p.extended = true;
            let n = u16::from_be_bytes([body[1], body[2]]) as usize;
            if body.len() == 3 {
                p.le = true; // case 2E
            } else {
                p.data = body.get(3..3 + n)?;
                match body.len() - 3 - n {
                    0 => {}
                    2 => p.le = true,
                    _ => return None,
                }
            }
        }
        _ => {
            let n = body[0] as usize;
            p.data = body.get(1..1 + n)?;
            match body.len() - 1 - n {
                0 => {}
                1 => p.le = true,
                _ => return None,
            }
        }
    }
    Some(p)
}

/// Bytes into a buffer, failing softly when it is full.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    n: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, n: 0 }
    }
    pub fn len(&self) -> usize {
        self.n
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    pub fn bytes(&mut self, b: &[u8]) -> Option<()> {
        self.buf.get_mut(self.n..self.n + b.len())?.copy_from_slice(b);
        self.n += b.len();
        Some(())
    }
    /// A BER-TLV with a one-byte tag.
    pub fn tlv(&mut self, tag: u8, value: &[u8]) -> Option<()> {
        self.bytes(&[tag])?;
        let n = value.len();
        if n < 0x80 {
            self.bytes(&[n as u8])?;
        } else if n < 0x100 {
            self.bytes(&[0x81, n as u8])?;
        } else {
            self.bytes(&[0x82, (n >> 8) as u8, n as u8])?;
        }
        self.bytes(value)
    }
    pub fn done(&self) -> &[u8] {
        &self.buf[..self.n]
    }
}

/// The value of the first TLV with `tag` in a flat sequence.
pub fn find(mut data: &[u8], tag: u8) -> Option<&[u8]> {
    while !data.is_empty() {
        let t = data[0];
        let (len, hdr) = match *data.get(1)? {
            l if l < 0x80 => (l as usize, 2),
            0x81 => (*data.get(2)? as usize, 3),
            0x82 => (u16::from_be_bytes([*data.get(2)?, *data.get(3)?]) as usize, 4),
            _ => return None,
        };
        let v = data.get(hdr..hdr + len)?;
        if t == tag {
            return Some(v);
        }
        data = &data[hdr + len..];
    }
    None
}

/// The status word at the end of a response, and the data before it.
pub fn split_sw(resp: &[u8]) -> Option<(&[u8], u16)> {
    let n = resp.len().checked_sub(2)?;
    Some((&resp[..n], u16::from_be_bytes([resp[n], resp[n + 1]])))
}

pub const SW_OK: u16 = 0x9000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_round_trip() {
        let data = [7u8; 300];
        for n in [0usize, 1, 200, 255, 256, 300] {
            for le in [Le::None, Le::Short(7), Le::Short(256), Le::Max] {
                let a = Apdu {
                    cla: 0x80,
                    ins: 4,
                    p1: 0,
                    p2: 0x1B,
                    data: &data[..n],
                    le,
                };
                let mut buf = [0u8; APDU_MAX];
                let len = a.encode(&mut buf).unwrap();
                let p = parse(&buf[..len]).unwrap_or_else(|| panic!("{n} {le:?}"));
                assert_eq!(p.data, &data[..n]);
                assert_eq!(p.le, le != Le::None, "{n} {le:?}");
            }
        }
    }

    #[test]
    fn tlvs() {
        let mut b = [0u8; 600];
        let mut w = Writer::new(&mut b);
        w.tlv(0x41, &[1, 2, 3, 4]).unwrap();
        w.tlv(0x42, &[9; 200]).unwrap();
        w.tlv(0x43, &[8; 300]).unwrap();
        let d = w.done();
        assert_eq!(&d[..6], &[0x41, 4, 1, 2, 3, 4]);
        assert_eq!(&d[6..9], &[0x42, 0x81, 200]);
        assert_eq!(find(d, 0x43).unwrap().len(), 300);
        assert_eq!(find(d, 0x42).unwrap(), &[9; 200]);
        assert_eq!(find(d, 0x44), None);
        assert_eq!(find(&[0x41, 5, 1], 0x41), None, "truncated");
    }
}
