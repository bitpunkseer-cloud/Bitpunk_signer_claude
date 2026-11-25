//! T=1 over I2C (NXP UM11225), host side.
//!
//! A frame is `NAD | PCB | LEN | INF (0..254) | CRC (2, low byte first)`.
//! The host writes a whole frame in one I2C write; it reads the 3-byte
//! prologue, then the rest. While the chip is busy it NACKs its address:
//! the host polls every MPOT until BWT (longer after a WTX request).
//!
//! PCB: I-block `0 N(S) M 00000`, R-block `100 N(R) 00 EE`, S-block
//! `11 R 0 CODE` (R = response). Chaining: each I-block with M = 1 is
//! acknowledged by an R-block carrying the next sequence number.

use crate::crc::crc16;

pub const NAD_HOST: u8 = 0x5A;
pub const NAD_SE: u8 = 0xA5;
/// Largest information field (both directions).
pub const IFS: usize = 254;
const FRAME_MAX: usize = 3 + IFS + 2;

/// S-block codes (request; the response has bit 5 set).
pub mod s {
    pub const RESYNC: u8 = 0xC0;
    pub const IFS: u8 = 0xC1;
    pub const ABORT: u8 = 0xC2;
    pub const WTX: u8 = 0xC3;
    pub const END_OF_APDU_SESSION: u8 = 0xC5;
    pub const CHIP_RESET: u8 = 0xC6;
    pub const GET_ATR: u8 = 0xC7;
    pub const SOFT_RESET: u8 = 0xCF;
    pub const RESPONSE: u8 = 0x20;
}

pub fn i_pcb(seq: bool, more: bool) -> u8 {
    ((seq as u8) << 6) | ((more as u8) << 5)
}

pub fn r_pcb(seq: bool, err: u8) -> u8 {
    0x80 | ((seq as u8) << 4) | (err & 3)
}

/// A parsed PCB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pcb {
    I { seq: bool, more: bool },
    R { seq: bool, err: u8 },
    S(u8),
}

impl Pcb {
    pub fn parse(b: u8) -> Option<Pcb> {
        if b & 0x9F == 0 {
            Some(Pcb::I {
                seq: b & 0x40 != 0,
                more: b & 0x20 != 0,
            })
        } else if b & 0xEC == 0x80 {
            if b & 3 == 3 {
                return None;
            }
            Some(Pcb::R {
                seq: b & 0x10 != 0,
                err: b & 3,
            })
        } else if b & 0xC0 == 0xC0 {
            Some(Pcb::S(b))
        } else {
            None
        }
    }
}

/// A whole frame into `out`; its length.
pub fn frame(nad: u8, pcb: u8, data: &[u8], out: &mut [u8]) -> usize {
    let n = data.len();
    out[0] = nad;
    out[1] = pcb;
    out[2] = n as u8;
    out[3..3 + n].copy_from_slice(data);
    let c = crc16(&out[..3 + n]);
    out[3 + n..5 + n].copy_from_slice(&c.to_le_bytes());
    5 + n
}

/// The bus and its timing.
pub trait I2c {
    /// One write transaction to the chip.
    fn write(&mut self, data: &[u8]) -> Result<(), Nack>;
    /// One read transaction from the chip.
    fn read(&mut self, buf: &mut [u8]) -> Result<(), Nack>;
    fn delay_us(&mut self, us: u32);
}

/// The chip did not acknowledge (busy, absent or the bus failed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nack;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T1Error {
    /// No answer within the waiting time.
    Timeout,
    /// A frame that is not T=1 (address, PCB, length) or out of order.
    Protocol,
    /// A frame whose CRC stayed wrong after the retries.
    Crc,
    /// The answer does not fit the buffer.
    TooLong,
}

/// Retransmissions of one block before giving up.
const RETRIES: usize = 3;

pub struct T1<B: I2c> {
    pub bus: B,
    seq_send: bool,
    seq_recv: bool,
    /// Block waiting time, minimum polling time, guard time (µs).
    pub bwt_us: u32,
    pub mpot_us: u32,
    pub segt_us: u32,
}

impl<B: I2c> T1<B> {
    pub fn new(bus: B) -> Self {
        T1 {
            bus,
            seq_send: false,
            seq_recv: false,
            bwt_us: 100_000,
            mpot_us: 1_000,
            segt_us: 10,
        }
    }

    fn write_frame(&mut self, buf: &[u8]) -> Result<(), T1Error> {
        // a busy chip NACKs: retry for a block waiting time
        for _ in 0..=self.bwt_us / self.mpot_us.max(1) {
            if self.bus.write(buf).is_ok() {
                return Ok(());
            }
            self.bus.delay_us(self.mpot_us);
        }
        Err(T1Error::Timeout)
    }

    fn send(&mut self, pcb: u8, data: &[u8]) -> Result<(), T1Error> {
        let mut f = [0u8; FRAME_MAX];
        let n = frame(NAD_HOST, pcb, data, &mut f);
        self.write_frame(&f[..n])
    }

    /// Read one frame: its PCB, and its information field in `inf`.
    /// `Err(Crc)` for a damaged frame (the caller asks for it again).
    fn read_frame(&mut self, wait_us: u32, inf: &mut [u8; IFS]) -> Result<(Pcb, usize), T1Error> {
        let mut head = [0u8; 3];
        let mut polled = false;
        for _ in 0..=wait_us / self.mpot_us.max(1) {
            if self.bus.read(&mut head).is_ok() {
                polled = true;
                break;
            }
            self.bus.delay_us(self.mpot_us);
        }
        if !polled {
            return Err(T1Error::Timeout);
        }
        let n = head[2] as usize;
        if head[0] != NAD_SE || n > IFS {
            return Err(T1Error::Protocol);
        }
        let mut rest = [0u8; IFS + 2];
        self.bus.read(&mut rest[..n + 2]).map_err(|_| T1Error::Timeout)?;
        let mut whole = [0u8; FRAME_MAX];
        whole[..3].copy_from_slice(&head);
        whole[3..3 + n].copy_from_slice(&rest[..n]);
        let want = crc16(&whole[..3 + n]).to_le_bytes();
        if rest[n..n + 2] != want {
            return Err(T1Error::Crc);
        }
        let pcb = Pcb::parse(head[1]).ok_or(T1Error::Protocol)?;
        inf[..n].copy_from_slice(&rest[..n]);
        Ok((pcb, n))
    }

    /// Exchange an S-block: send `code` with `data`, expect its response.
    fn s_exchange(&mut self, code: u8, data: &[u8], out: &mut [u8]) -> Result<usize, T1Error> {
        let mut inf = [0u8; IFS];
        for _ in 0..RETRIES {
            self.send(code, data)?;
            self.bus.delay_us(self.segt_us);
            match self.read_frame(self.bwt_us, &mut inf) {
                Ok((Pcb::S(p), n)) if p == code | s::RESPONSE => {
                    let n = n.min(out.len());
                    out[..n].copy_from_slice(&inf[..n]);
                    return Ok(n);
                }
                Ok(_) | Err(T1Error::Crc) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(T1Error::Protocol)
    }

    /// Resynchronise: both sides start again at sequence 0.
    pub fn resync(&mut self) -> Result<(), T1Error> {
        self.s_exchange(s::RESYNC, &[], &mut [])?;
        self.seq_send = false;
        self.seq_recv = false;
        Ok(())
    }

    /// Soft reset of the interface; the chip answers with its ATR, whose
    /// timings are taken. Returns the ATR length in `atr`.
    pub fn soft_reset(&mut self, atr: &mut [u8; IFS]) -> Result<usize, T1Error> {
        let n = self.s_exchange(s::SOFT_RESET, &[], atr)?;
        self.seq_send = false;
        self.seq_recv = false;
        if let Some((bwt_ms, mpot_ms, segt_us)) = atr_timings(&atr[..n]) {
            self.bwt_us = (bwt_ms as u32 * 1000).max(10_000);
            self.mpot_us = (mpot_ms as u32 * 1000).max(100);
            self.segt_us = (segt_us as u32).max(10);
        }
        Ok(n)
    }

    /// Send an APDU, return the response (with its status word) in `resp`.
    pub fn transceive(&mut self, apdu: &[u8], resp: &mut [u8]) -> Result<usize, T1Error> {
        let mut inf = [0u8; IFS];
        // ---- send, chained in blocks of IFS ----
        let chunks = apdu.len().div_ceil(IFS).max(1);
        for i in 0..chunks {
            let part = &apdu[i * IFS..((i + 1) * IFS).min(apdu.len())];
            let more = i + 1 < chunks;
            let pcb = i_pcb(self.seq_send, more);
            let mut sent = false;
            for _ in 0..RETRIES {
                self.send(pcb, part)?;
                if !more {
                    sent = true;
                    break;
                }
                self.bus.delay_us(self.segt_us);
                match self.read_frame(self.bwt_us, &mut inf) {
                    // the next block is asked for: this one arrived
                    Ok((Pcb::R { seq, err: 0 }, 0)) if seq != self.seq_send => {
                        sent = true;
                        break;
                    }
                    // an error R-block or a damaged frame: send it again
                    Ok((Pcb::R { .. }, _)) | Err(T1Error::Crc) => continue,
                    Ok(_) => return Err(T1Error::Protocol),
                    Err(e) => return Err(e),
                }
            }
            if !sent {
                return Err(T1Error::Protocol);
            }
            self.seq_send = !self.seq_send;
        }
        // ---- receive ----
        let mut got = 0;
        let mut wait = self.bwt_us;
        let mut bad = 0;
        loop {
            self.bus.delay_us(self.segt_us);
            match self.read_frame(wait, &mut inf) {
                Ok((Pcb::S(p), n)) if p == s::WTX && n == 1 => {
                    // the chip needs more time: confirm, and wait longer
                    self.send(s::WTX | s::RESPONSE, &inf[..1])?;
                    wait = self.bwt_us.saturating_mul(inf[0].max(1) as u32);
                }
                Ok((Pcb::I { seq, more }, n)) => {
                    wait = self.bwt_us;
                    if seq != self.seq_recv {
                        // a repeat of a block already taken: ask for the next
                        self.send(r_pcb(self.seq_recv, 0), &[])?;
                        continue;
                    }
                    if got + n > resp.len() {
                        return Err(T1Error::TooLong);
                    }
                    resp[got..got + n].copy_from_slice(&inf[..n]);
                    got += n;
                    self.seq_recv = !self.seq_recv;
                    bad = 0;
                    if !more {
                        return Ok(got);
                    }
                    self.send(r_pcb(self.seq_recv, 0), &[])?;
                }
                Err(T1Error::Crc) => {
                    bad += 1;
                    if bad > RETRIES {
                        return Err(T1Error::Crc);
                    }
                    // ask for the block again
                    self.send(r_pcb(self.seq_recv, 1), &[])?;
                }
                Ok((Pcb::R { .. }, _)) => {
                    // our last block was damaged on the way: the chip asks
                    // for it again (an APDU that fits one block only)
                    bad += 1;
                    if bad > RETRIES || apdu.len() > IFS {
                        return Err(T1Error::Protocol);
                    }
                    self.send(i_pcb(!self.seq_send, false), apdu)?;
                }
                Ok(_) => return Err(T1Error::Protocol),
                Err(e) => return Err(e),
            }
        }
    }
}

/// BWT (ms), MPOT (ms) and SEGT (µs) from an ATR (UM11225 §4.2): PVER,
/// VID (5), DLLP length and DLLP (BWT, IFSC), PLID, PLP length and PLP
/// (MCF, CONFIG, MPOT, RFU×3, SEGT, WUT), historical bytes.
pub fn atr_timings(atr: &[u8]) -> Option<(u16, u8, u16)> {
    let dllp_len = *atr.get(6)? as usize;
    let dllp = atr.get(7..7 + dllp_len)?;
    let bwt = u16::from_be_bytes([*dllp.first()?, *dllp.get(1)?]);
    let rest = atr.get(7 + dllp_len..)?;
    let plp_len = *rest.get(1)? as usize;
    let plp = rest.get(2..2 + plp_len)?;
    let mpot = *plp.get(3)?;
    let segt = u16::from_be_bytes([*plp.get(7)?, *plp.get(8)?]);
    Some((bwt, mpot, segt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use se05x::t1::{Pcb as RefPcb, Seq};

    #[test]
    fn pcbs_match_the_reference() {
        for seq in [false, true] {
            let rs = if seq { Seq::ONE } else { Seq::ZERO };
            for more in [false, true] {
                assert_eq!(i_pcb(seq, more), RefPcb::i_pcb(rs, more));
                assert_eq!(Pcb::parse(i_pcb(seq, more)), Some(Pcb::I { seq, more }));
            }
            for (err, re) in [
                (0, se05x::t1::RBlockError::NoError),
                (1, se05x::t1::RBlockError::CrcError),
                (2, se05x::t1::RBlockError::OtherError),
            ] {
                assert_eq!(r_pcb(seq, err), RefPcb::r_pcb(rs, re));
                assert_eq!(Pcb::parse(r_pcb(seq, err)), Some(Pcb::R { seq, err }));
            }
        }
        for (code, re) in [
            (s::RESYNC, se05x::t1::SBlock::ResyncRequest),
            (s::RESYNC | s::RESPONSE, se05x::t1::SBlock::ResyncResponse),
            (s::WTX, se05x::t1::SBlock::WtxRequest),
            (s::WTX | s::RESPONSE, se05x::t1::SBlock::WtxResponse),
            (s::SOFT_RESET, se05x::t1::SBlock::InterfaceSoftResetRequest),
            (
                s::SOFT_RESET | s::RESPONSE,
                se05x::t1::SBlock::InterfaceSoftResetResponse,
            ),
            (s::END_OF_APDU_SESSION, se05x::t1::SBlock::EndOfApduSessionRequest),
            (s::GET_ATR, se05x::t1::SBlock::GetAtrRequest),
        ] {
            assert_eq!(code, RefPcb::s_pcb(re));
            assert_eq!(Pcb::parse(code), Some(Pcb::S(code)));
        }
    }

    #[test]
    fn a_frame_carries_its_crc() {
        let mut f = [0u8; 16];
        let n = frame(NAD_HOST, s::RESYNC, &[], &mut f);
        let c = se05x::t1::Crc::calculate(&[0x5A, 0xC0, 0x00]).to_le_bytes();
        assert_eq!(&f[..n], &[0x5A, 0xC0, 0x00, c[0], c[1]]);
    }
}
