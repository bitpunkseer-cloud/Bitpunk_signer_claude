//! Boot-time check that no Ethernet PHY is on the board (M8 decision 9-2).
//!
//! The development board's PHY and RJ45 jack are removed by hand. To catch
//! a board where that was not done (or a PHY put back), the firmware reads
//! the PHY identifier registers at every MDIO address on each boot, driving
//! the MDC and MDIO pins as plain GPIO: the Ethernet MAC itself is never
//! clocked. Any answer means a network chip is present and the device
//! refuses to load seeds or sign.
//!
//! IEEE 802.3 clause 22 read frame: 32 preamble ones, start `01`, read
//! `10`, 5-bit PHY address, 5-bit register, turnaround (the PHY drives a
//! 0), 16 data bits. With no PHY the pulled-up line reads all ones.

/// GPIO access for bit-banged MDIO.
pub trait MdioPins {
    /// Drive the MDC clock line.
    fn mdc(&mut self, high: bool);
    /// Drive MDIO (output mode).
    fn mdio_out(&mut self, high: bool);
    /// Release MDIO (input mode, pulled up).
    fn mdio_release(&mut self);
    /// Read MDIO.
    fn mdio_in(&mut self) -> bool;
    /// Wait half an MDC period (at least 200 ns for 2.5 MHz).
    fn half_period(&mut self);
}

/// A PHY that answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhyFound {
    pub addr: u8,
    /// Registers 2 and 3 (OUI and model).
    pub id: u32,
}

fn clock_out<P: MdioPins>(p: &mut P, bit: bool) {
    p.mdio_out(bit);
    p.half_period();
    p.mdc(true);
    p.half_period();
    p.mdc(false);
}

fn clock_in<P: MdioPins>(p: &mut P) -> bool {
    p.half_period();
    p.mdc(true);
    let b = p.mdio_in();
    p.half_period();
    p.mdc(false);
    b
}

/// Read one register (clause 22). Returns the 16 data bits.
pub fn mdio_read<P: MdioPins>(p: &mut P, phy: u8, reg: u8) -> u16 {
    p.mdc(false);
    for _ in 0..32 {
        clock_out(p, true);
    }
    // start 01, read 10
    for b in [false, true, true, false] {
        clock_out(p, b);
    }
    for i in (0..5).rev() {
        clock_out(p, (phy >> i) & 1 == 1);
    }
    for i in (0..5).rev() {
        clock_out(p, (reg >> i) & 1 == 1);
    }
    // turnaround: release; the PHY drives 0 on the second bit
    p.mdio_release();
    clock_in(p);
    clock_in(p);
    let mut v = 0u16;
    for _ in 0..16 {
        v = (v << 1) | clock_in(p) as u16;
    }
    // idle
    clock_in(p);
    v
}

/// Read the identifier at every address. `None`: no PHY answered (every
/// read gave all ones or all zeros).
pub fn scan_phys<P: MdioPins>(p: &mut P) -> Option<PhyFound> {
    for addr in 0..32u8 {
        let id1 = mdio_read(p, addr, 2);
        let id2 = mdio_read(p, addr, 3);
        let blank = |v: u16| v == 0xFFFF || v == 0x0000;
        if !(blank(id1) && blank(id2)) {
            return Some(PhyFound {
                addr,
                id: (id1 as u32) << 16 | id2 as u32,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simulated MDIO bus: an optional PHY at one address answering
    /// registers 2 and 3, sampling on MDC rising edges like real parts.
    struct Bus {
        phy: Option<(u8, u16, u16)>,
        mdc: bool,
        out: Option<bool>,
        written: [bool; 64],
        n: usize,
        read: Option<(u16, bool)>,
        read_edge: u32,
        cur: bool,
        edges: u32,
    }

    impl Bus {
        fn new(phy: Option<(u8, u16, u16)>) -> Self {
            Bus {
                phy,
                mdc: false,
                out: None,
                written: [false; 64],
                n: 0,
                read: None,
                read_edge: 0,
                cur: true,
                edges: 0,
            }
        }

        fn bits(&self, from: usize, len: usize) -> u8 {
            (0..len).fold(0u8, |v, i| (v << 1) | self.written[self.n - from + i] as u8)
        }
    }

    impl MdioPins for Bus {
        fn mdc(&mut self, high: bool) {
            let rising = high && !self.mdc;
            self.mdc = high;
            if !rising {
                return;
            }
            self.edges += 1;
            if let Some(b) = self.out {
                if self.n == 64 {
                    self.written.copy_within(1.., 0);
                    self.n -= 1;
                }
                self.written[self.n] = b;
                self.n += 1;
            } else if let Some((v, present)) = self.read {
                self.read_edge += 1;
                self.cur = match self.read_edge {
                    1 => true,
                    2 => !present,
                    e @ 3..=18 => (v >> (18 - e)) & 1 == 1,
                    _ => true,
                };
                if self.read_edge >= 19 {
                    self.read = None;
                }
            }
        }
        fn mdio_out(&mut self, high: bool) {
            self.out = Some(high);
        }
        fn mdio_release(&mut self) {
            self.out = None;
            if self.n < 46 || !self.written[self.n - 46..self.n - 14].iter().all(|&b| b) {
                return;
            }
            if self.bits(14, 4) != 0b0110 {
                return;
            }
            let phy = self.bits(10, 5);
            let reg = self.bits(5, 5);
            let reply = match self.phy {
                Some((a, i1, _)) if a == phy && reg == 2 => Some(i1),
                Some((a, _, i2)) if a == phy && reg == 3 => Some(i2),
                _ => None,
            };
            self.read = Some((reply.unwrap_or(0xFFFF), reply.is_some()));
            self.read_edge = 0;
            self.n = 0;
        }
        fn mdio_in(&mut self) -> bool {
            self.cur
        }
        fn half_period(&mut self) {}
    }

    #[test]
    fn finds_a_phy_at_any_address() {
        for addr in [0u8, 1, 7, 31] {
            let mut b = Bus::new(Some((addr, 0x001C, 0xC916))); // RTL8211F
            assert_eq!(
                scan_phys(&mut b),
                Some(PhyFound {
                    addr,
                    id: 0x001C_C916
                })
            );
        }
    }

    #[test]
    fn a_board_without_phy_is_clean() {
        let mut b = Bus::new(None);
        assert_eq!(scan_phys(&mut b), None);
        // every address read, both registers
        assert_eq!(b.edges, 32 * 2 * 65);
    }

    #[test]
    fn reads_one_register() {
        let mut b = Bus::new(Some((3, 0x1234, 0xABCD)));
        assert_eq!(mdio_read(&mut b, 3, 2), 0x1234);
        assert_eq!(mdio_read(&mut b, 3, 3), 0xABCD);
        assert_eq!(mdio_read(&mut b, 4, 2), 0xFFFF);
    }
}
