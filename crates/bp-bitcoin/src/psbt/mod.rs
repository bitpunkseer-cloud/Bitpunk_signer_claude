//! PSBT (BIP-174). `summary` is a quick structure check that also accepts
//! v2 (BIP-370) for the scan result screen; `parse` is the strict v0 parser
//! that everything the signer decides on goes through; `write` serializes.

mod parse;
pub mod write;

pub use parse::{
    is_valid_ecdsa_sig_encoding, Error as ParseError, InputMap, KeySource, OutputMap, Pair, Pairs, Psbt,
    TapDerivation,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Missing `psbt\xff` magic.
    Magic,
    /// Data ends inside a map or transaction.
    Truncated,
    /// Structure is invalid (missing transaction, counts, bad lengths).
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    pub version: u32,
    pub inputs: usize,
    pub outputs: usize,
}

pub const MAGIC: &[u8; 5] = b"psbt\xff";

/// A key and its value.
type RawPair<'a> = (&'a [u8], &'a [u8]);

struct Cur<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.p.checked_add(n).ok_or(Error::Malformed)?;
        let s = self.d.get(self.p..end).ok_or(Error::Truncated)?;
        self.p = end;
        Ok(s)
    }
    fn varint(&mut self) -> Result<u64, Error> {
        let b = self.take(1)?[0];
        Ok(match b {
            0xFD => u16::from_le_bytes(self.take(2)?.try_into().unwrap_or([0; 2])) as u64,
            0xFE => u32::from_le_bytes(self.take(4)?.try_into().unwrap_or([0; 4])) as u64,
            0xFF => u64::from_le_bytes(self.take(8)?.try_into().unwrap_or([0; 8])),
            v => v as u64,
        })
    }
    /// Next key-value pair; `None` at the 0x00 separator.
    fn pair(&mut self) -> Result<Option<RawPair<'a>>, Error> {
        let klen = self.varint()? as usize;
        if klen == 0 {
            return Ok(None);
        }
        let key = self.take(klen)?;
        let vlen = self.varint()? as usize;
        let val = self.take(vlen)?;
        Ok(Some((key, val)))
    }
}

/// Input and output counts of an unsigned (non-witness) transaction.
fn tx_counts(tx: &[u8]) -> Result<(usize, usize), Error> {
    let mut c = Cur { d: tx, p: 0 };
    c.take(4)?; // version
    let n_in = c.varint()? as usize;
    if n_in == 0 || n_in > 10_000 {
        return Err(Error::Malformed); // 0 would mean a witness marker
    }
    for _ in 0..n_in {
        c.take(36)?;
        let sl = c.varint()? as usize;
        c.take(sl)?;
        c.take(4)?;
    }
    let n_out = c.varint()? as usize;
    if n_out > 10_000 {
        return Err(Error::Malformed);
    }
    for _ in 0..n_out {
        c.take(8)?;
        let sl = c.varint()? as usize;
        c.take(sl)?;
    }
    c.take(4)?; // locktime
    if c.p != tx.len() {
        return Err(Error::Malformed);
    }
    Ok((n_in, n_out))
}

/// Check the map structure and return the summary.
pub fn summary(psbt: &[u8]) -> Result<Summary, Error> {
    if psbt.len() < MAGIC.len() || &psbt[..5] != MAGIC {
        return Err(Error::Magic);
    }
    let mut c = Cur { d: psbt, p: 5 };
    let mut version = 0u32;
    let mut counts: Option<(usize, usize)> = None;
    let (mut v2_in, mut v2_out) = (None, None);
    while let Some((key, val)) = c.pair()? {
        match key[0] {
            0x00 if key.len() == 1 => counts = Some(tx_counts(val)?),
            0x04 if key.len() == 1 => v2_in = Some(Cur { d: val, p: 0 }.varint()? as usize),
            0x05 if key.len() == 1 => v2_out = Some(Cur { d: val, p: 0 }.varint()? as usize),
            0xFB if key.len() == 1 => {
                version = u32::from_le_bytes(val.try_into().map_err(|_| Error::Malformed)?);
            }
            _ => {}
        }
    }
    let (inputs, outputs) = match version {
        0 => counts.ok_or(Error::Malformed)?,
        2 => match (counts, v2_in, v2_out) {
            (None, Some(i), Some(o)) => (i, o),
            _ => return Err(Error::Malformed),
        },
        _ => return Err(Error::Malformed),
    };
    if inputs > 10_000 || outputs > 10_000 {
        return Err(Error::Malformed);
    }
    for _ in 0..inputs + outputs {
        while c.pair()?.is_some() {}
    }
    if c.p != psbt.len() {
        return Err(Error::Malformed);
    }
    Ok(Summary {
        version,
        inputs,
        outputs,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A minimal valid v0 PSBT: 1 input, 2 outputs, empty input/output maps.
    pub(crate) fn sample() -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&2u32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&[0x11; 32]);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.push(0);
        tx.extend_from_slice(&0xFFFF_FFFDu32.to_le_bytes());
        tx.push(2);
        for v in [50_000u64, 49_000] {
            tx.extend_from_slice(&v.to_le_bytes());
            tx.push(22);
            tx.extend_from_slice(&[0x00, 0x14]);
            tx.extend_from_slice(&[0x22; 20]);
        }
        tx.extend_from_slice(&0u32.to_le_bytes());
        let mut p = MAGIC.to_vec();
        p.extend_from_slice(&[1, 0x00]);
        p.push(tx.len() as u8);
        p.extend_from_slice(&tx);
        p.push(0); // end of global map
        p.extend_from_slice(&[0, 0, 0]); // 1 input map + 2 output maps
        p
    }

    #[test]
    fn counts_inputs_and_outputs() {
        let p = sample();
        assert_eq!(
            summary(&p),
            Ok(Summary {
                version: 0,
                inputs: 1,
                outputs: 2
            })
        );
        assert_eq!(summary(&p[..p.len() - 1]), Err(Error::Truncated));
        assert_eq!(summary(b"psbt"), Err(Error::Magic));
        let mut extra = p.clone();
        extra.push(0);
        assert_eq!(summary(&extra), Err(Error::Malformed));
    }

    #[test]
    fn v2_counts() {
        let mut p = MAGIC.to_vec();
        for (k, v) in [
            (0x02u8, &[2u8, 0, 0, 0][..]),
            (0x04, &[3][..]),
            (0x05, &[1][..]),
            (0xFB, &[2, 0, 0, 0][..]),
        ] {
            p.extend_from_slice(&[1, k, v.len() as u8]);
            p.extend_from_slice(v);
        }
        p.push(0);
        p.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            summary(&p),
            Ok(Summary {
                version: 2,
                inputs: 3,
                outputs: 1
            })
        );
    }
}
