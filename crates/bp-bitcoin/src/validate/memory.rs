//! Amounts of the UTXOs signed since power-on (Coldcard's idea against
//! CVE-2020-14199): if the same outpoint comes back with another amount,
//! a host is lying about one of them. Lives in RAM only.

pub const CAPACITY: usize = 64;

pub struct UtxoMemory {
    entries: [([u8; 36], u64); CAPACITY],
    len: usize,
    next: usize,
}

impl UtxoMemory {
    pub const fn new() -> Self {
        UtxoMemory {
            entries: [([0; 36], 0); CAPACITY],
            len: 0,
            next: 0,
        }
    }

    /// The amount remembered for a 36-byte outpoint.
    pub fn amount(&self, outpoint: &[u8]) -> Option<u64> {
        self.entries[..self.len]
            .iter()
            .find(|(o, _)| o[..] == *outpoint)
            .map(|(_, a)| *a)
    }

    /// Remember an outpoint's amount (the oldest entry goes when full).
    pub fn remember(&mut self, outpoint: &[u8], amount: u64) {
        let Ok(op) = <[u8; 36]>::try_from(outpoint) else {
            return;
        };
        if let Some(e) = self.entries[..self.len].iter_mut().find(|(o, _)| *o == op) {
            e.1 = amount;
            return;
        }
        self.entries[self.next] = (op, amount);
        self.next = (self.next + 1) % CAPACITY;
        self.len = (self.len + 1).min(CAPACITY);
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl Default for UtxoMemory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_and_rotates() {
        let mut m = UtxoMemory::new();
        let op = |i: u8| [i; 36];
        m.remember(&op(1), 10);
        assert_eq!(m.amount(&op(1)), Some(10));
        m.remember(&op(1), 11);
        assert_eq!(m.amount(&op(1)), Some(11));
        for i in 2..(CAPACITY as u8 + 2) {
            m.remember(&op(i), i as u64);
        }
        assert_eq!(m.amount(&op(1)), None); // rotated out
        assert_eq!(m.amount(&op(CAPACITY as u8 + 1)), Some(CAPACITY as u64 + 1));
        m.remember(&[0; 35], 1); // wrong length is ignored
        m.clear();
        assert_eq!(m.amount(&op(5)), None);
    }
}
