//! Bitcoin transactions in consensus serialization (with or without the
//! BIP-144 witness): zero-copy parsing, txid, and the byte sinks that the
//! sighash and PSBT code stream into. Nothing is copied or allocated:
//! inputs and outputs are read from the original bytes on demand.
//!
//! Parsing is as strict as Bitcoin Core's deserializer: canonical compact
//! sizes no larger than 2^25, witness flag 1 only, no superfluous (all
//! empty) witness, no trailing bytes. Additionally a transaction must have
//! at least one input and one output.

use bp_crypto::sha256::Sha256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The data ends early.
    Truncated,
    /// Invalid structure (see the module documentation).
    Malformed,
}

/// 21 million BTC in satoshis.
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;
/// Bitcoin Core's limit for compact sizes.
const MAX_SIZE: u64 = 0x0200_0000;

/// Something bytes can be written to: a hash or a buffer.
pub trait Sink {
    fn put(&mut self, b: &[u8]);
}

impl Sink for Sha256 {
    fn put(&mut self, b: &[u8]) {
        self.update(b);
    }
}

/// Write a compact size (CompactSize / "varint").
pub fn put_compact_size<S: Sink + ?Sized>(s: &mut S, n: u64) {
    match n {
        0..=0xFC => s.put(&[n as u8]),
        0xFD..=0xFFFF => {
            s.put(&[0xFD]);
            s.put(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            s.put(&[0xFE]);
            s.put(&(n as u32).to_le_bytes());
        }
        _ => {
            s.put(&[0xFF]);
            s.put(&n.to_le_bytes());
        }
    }
}

/// A fixed buffer that remembers if anything did not fit.
pub struct Buf<'a> {
    buf: &'a mut [u8],
    len: usize,
    overflow: bool,
}

impl<'a> Buf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Buf {
            buf,
            len: 0,
            overflow: false,
        }
    }

    /// The bytes written, or `None` if the buffer was too small.
    pub fn finish(self) -> Option<usize> {
        (!self.overflow).then_some(self.len)
    }
}

impl Sink for Buf<'_> {
    fn put(&mut self, b: &[u8]) {
        match self.buf.get_mut(self.len..self.len + b.len()) {
            Some(dst) if !self.overflow => {
                dst.copy_from_slice(b);
                self.len += b.len();
            }
            _ => self.overflow = true,
        }
    }
}

/// Cursor over consensus-encoded bytes.
#[derive(Clone)]
pub struct Reader<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    pub fn new(d: &'a [u8]) -> Self {
        Reader { d, p: 0 }
    }

    pub fn pos(&self) -> usize {
        self.p
    }

    pub fn remaining(&self) -> usize {
        self.d.len() - self.p
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.p.checked_add(n).ok_or(Error::Malformed)?;
        let s = self.d.get(self.p..end).ok_or(Error::Truncated)?;
        self.p = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, Error> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }

    pub fn array32(&mut self) -> Result<[u8; 32], Error> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }

    /// A canonical compact size no larger than 2^25 (as Bitcoin Core).
    pub fn compact_size(&mut self) -> Result<u64, Error> {
        let (v, min) = match self.u8()? {
            0xFD => {
                let b = self.take(2)?;
                (u16::from_le_bytes([b[0], b[1]]) as u64, 0xFD)
            }
            0xFE => (self.u32()? as u64, 0x1_0000),
            0xFF => (self.u64()?, 0x1_0000_0000),
            v => (v as u64, 0),
        };
        if v < min || v > MAX_SIZE {
            return Err(Error::Malformed);
        }
        Ok(v)
    }

    /// Compact size length followed by that many bytes.
    pub fn var_bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.compact_size()? as usize;
        self.take(n)
    }
}

/// One input. `txid` is in internal byte order (as hashed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxIn<'a> {
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: &'a [u8],
    pub sequence: u32,
    /// The 36-byte serialized outpoint.
    pub outpoint: &'a [u8],
}

/// One output, with its serialized bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxOut<'a> {
    pub value: u64,
    pub script_pubkey: &'a [u8],
    /// value || compact size || script (empty for outputs that were not
    /// read from a transaction).
    pub raw: &'a [u8],
}

impl<'a> TxOut<'a> {
    pub fn new(value: u64, script_pubkey: &'a [u8]) -> Self {
        TxOut {
            value,
            script_pubkey,
            raw: &[],
        }
    }

    /// Serialize (value || script with length).
    pub fn write<S: Sink + ?Sized>(&self, s: &mut S) {
        s.put(&self.value.to_le_bytes());
        put_compact_size(s, self.script_pubkey.len() as u64);
        s.put(self.script_pubkey);
    }
}

fn read_input<'a>(r: &mut Reader<'a>) -> Result<TxIn<'a>, Error> {
    let outpoint = r.take(36)?;
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&outpoint[..32]);
    let vout = u32::from_le_bytes([outpoint[32], outpoint[33], outpoint[34], outpoint[35]]);
    let script_sig = r.var_bytes()?;
    let sequence = r.u32()?;
    Ok(TxIn {
        txid,
        vout,
        script_sig,
        sequence,
        outpoint,
    })
}

fn read_output<'a>(r: &mut Reader<'a>, d: &'a [u8]) -> Result<TxOut<'a>, Error> {
    let start = r.pos();
    let value = r.u64()?;
    let script_pubkey = r.var_bytes()?;
    Ok(TxOut {
        value,
        script_pubkey,
        raw: &d[start..r.pos()],
    })
}

/// A parsed transaction (a view of the original bytes).
#[derive(Clone, Copy, Debug)]
pub struct Tx<'a> {
    raw: &'a [u8],
    pub version: u32,
    pub lock_time: u32,
    n_in: usize,
    n_out: usize,
    /// The input list (after its count).
    ins: (usize, usize),
    /// The output list (after its count).
    outs: (usize, usize),
    /// Non-witness body: input count to the end of the outputs.
    body: (usize, usize),
    /// Witness section, if any.
    witness: Option<(usize, usize)>,
}

impl<'a> Tx<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Tx<'a>, Error> {
        let mut r = Reader::new(raw);
        let version = r.u32()?;
        let segwit = raw.get(4) == Some(&0);
        if segwit {
            r.take(1)?;
            if r.u8()? != 1 {
                return Err(Error::Malformed);
            }
        }
        let body_start = r.pos();
        let n_in = r.compact_size()? as usize;
        if n_in == 0 || n_in > r.remaining() / 41 {
            return Err(if n_in == 0 {
                Error::Malformed
            } else {
                Error::Truncated
            });
        }
        let ins_start = r.pos();
        for _ in 0..n_in {
            read_input(&mut r)?;
        }
        let ins = (ins_start, r.pos());
        let n_out = r.compact_size()? as usize;
        if n_out == 0 || n_out > r.remaining() / 9 {
            return Err(if n_out == 0 {
                Error::Malformed
            } else {
                Error::Truncated
            });
        }
        let outs_start = r.pos();
        for _ in 0..n_out {
            read_output(&mut r, raw)?;
        }
        let outs = (outs_start, r.pos());
        let body = (body_start, r.pos());
        let witness = if segwit {
            let start = r.pos();
            let mut any = false;
            for _ in 0..n_in {
                let items = r.compact_size()?;
                any |= items > 0;
                for _ in 0..items {
                    r.var_bytes()?;
                }
            }
            if !any {
                return Err(Error::Malformed); // superfluous witness record
            }
            Some((start, r.pos()))
        } else {
            None
        };
        let lock_time = r.u32()?;
        if r.remaining() != 0 {
            return Err(Error::Malformed);
        }
        Ok(Tx {
            raw,
            version,
            lock_time,
            n_in,
            n_out,
            ins,
            outs,
            body,
            witness,
        })
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn has_witness(&self) -> bool {
        self.witness.is_some()
    }

    pub fn n_inputs(&self) -> usize {
        self.n_in
    }

    pub fn n_outputs(&self) -> usize {
        self.n_out
    }

    pub fn inputs(&self) -> Inputs<'a> {
        Inputs {
            r: Reader::new(&self.raw[..self.ins.1]),
            start: self.ins.0,
            left: self.n_in,
        }
    }

    pub fn outputs(&self) -> Outputs<'a> {
        Outputs {
            d: &self.raw[..self.outs.1],
            p: self.outs.0,
            left: self.n_out,
        }
    }

    pub fn input(&self, i: usize) -> Option<TxIn<'a>> {
        self.inputs().nth(i)
    }

    pub fn output(&self, i: usize) -> Option<TxOut<'a>> {
        self.outputs().nth(i)
    }

    /// The serialized output list without its count (BIP-143 / BIP-341
    /// output hashes).
    pub fn outputs_bytes(&self) -> &'a [u8] {
        &self.raw[self.outs.0..self.outs.1]
    }

    /// Witness stack of input `i` (empty for non-witness transactions).
    pub fn witness(&self, i: usize) -> Witness<'a> {
        let Some((start, end)) = self.witness else {
            return Witness {
                r: Reader::new(&[]),
                left: 0,
            };
        };
        let mut r = Reader::new(&self.raw[start..end]);
        for _ in 0..i {
            let n = r.compact_size().unwrap_or(0);
            for _ in 0..n {
                let _ = r.var_bytes();
            }
        }
        let left = if i < self.n_in {
            r.compact_size().unwrap_or(0) as usize
        } else {
            0
        };
        Witness { r, left }
    }

    /// Transaction id in internal byte order (reverse for display).
    pub fn txid(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.version.to_le_bytes());
        h.update(&self.raw[self.body.0..self.body.1]);
        h.update(&self.lock_time.to_le_bytes());
        Sha256::digest(&h.finalize())
    }

    /// Size without witness data (bytes).
    pub fn base_size(&self) -> usize {
        8 + self.body.1 - self.body.0
    }
}

pub struct Inputs<'a> {
    r: Reader<'a>,
    start: usize,
    left: usize,
}

impl<'a> Iterator for Inputs<'a> {
    type Item = TxIn<'a>;
    fn next(&mut self) -> Option<TxIn<'a>> {
        if self.left == 0 {
            return None;
        }
        if self.r.pos() < self.start {
            self.r.take(self.start).ok()?;
        }
        self.left -= 1;
        read_input(&mut self.r).ok()
    }
}

pub struct Outputs<'a> {
    d: &'a [u8],
    p: usize,
    left: usize,
}

impl<'a> Iterator for Outputs<'a> {
    type Item = TxOut<'a>;
    fn next(&mut self) -> Option<TxOut<'a>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let mut r = Reader::new(self.d);
        r.take(self.p).ok()?;
        let o = read_output(&mut r, self.d).ok()?;
        self.p = r.pos();
        Some(o)
    }
}

/// Items of one witness stack.
pub struct Witness<'a> {
    r: Reader<'a>,
    left: usize,
}

impl<'a> Iterator for Witness<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        self.r.var_bytes().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_is_canonical() {
        let ok: &[(&[u8], u64)] = &[
            (&[0xFC], 0xFC),
            (&[0xFD, 0xFD, 0x00], 0xFD),
            (&[0xFE, 0, 0, 1, 0], 0x1_0000),
        ];
        for (b, v) in ok {
            assert_eq!(Reader::new(b).compact_size(), Ok(*v));
        }
        let bad: &[&[u8]] = &[
            &[0xFD, 0xFC, 0x00],
            &[0xFE, 0xFF, 0xFF, 0, 0],
            &[0xFF, 0, 0, 0, 0, 1, 0, 0, 0],
            &[0xFE, 0x01, 0x00, 0x00, 0x02], // > 2^25
        ];
        for b in bad {
            assert_eq!(Reader::new(b).compact_size(), Err(Error::Malformed));
        }
        for v in [0u64, 0xFC, 0xFD, 0xFFFF, 0x1_0000, 0x0200_0000] {
            let mut buf = [0u8; 9];
            let mut w = Buf::new(&mut buf);
            put_compact_size(&mut w, v);
            let n = w.finish().unwrap();
            assert_eq!(Reader::new(&buf[..n]).compact_size(), Ok(v));
        }
    }

    #[test]
    fn buf_reports_overflow() {
        let mut b = [0u8; 3];
        let mut w = Buf::new(&mut b);
        w.put(&[1, 2]);
        w.put(&[3, 4]);
        assert_eq!(w.finish(), None);
    }
}
