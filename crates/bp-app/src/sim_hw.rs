//! Secure storage hardware for the simulator and the tests (M10-2). They
//! keep the rules of the real parts (`bp_hal::secure`):
//! - the secure element locks its secret for good when the attempts run
//!   out, compares authenticators in constant time and its counter only
//!   goes up;
//! - the hidden device key differs per chip, so a vault copied to another
//!   chip does not open;
//! - the flash follows NOR rules and can lose power after any number of
//!   bytes, to test that a vault write is never half-done.
//!
//! The simulator's "chip" lives in page memory only (decision 10).

use bp_crypto::chacha20poly1305::ct_eq;
use bp_crypto::hmac::HmacSha256;
use bp_crypto::secret::wipe;
use bp_hal::secure::{DeviceKey, DeviceKeyError, FlashError, SeError, SeState, SecureElement, VaultFlash};

/// A deterministic stream for the simulated parts (not cryptographic: the
/// simulator holds only test seeds).
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn fill(state: &mut u64, out: &mut [u8]) {
    for chunk in out.chunks_mut(8) {
        let v = splitmix(state).to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
}

/// Simulated NXP SE050 for the vault.
#[derive(Clone)]
pub struct SimSecureElement {
    rng: u64,
    hmac_key: [u8; 32],
    auth: [u8; 32],
    secret: [u8; 32],
    state: SeState,
    max: u8,
    counter: u32,
    /// Answers `Bus` to everything (a missing or broken element).
    pub broken: bool,
    /// Calls answered before the power fails (then `Bus`); `None` = no cut.
    pub calls_left: Option<u32>,
}

impl SimSecureElement {
    /// A new element; `chip` makes its HMAC key and its secrets differ
    /// from other elements'.
    pub fn new(chip: u64) -> Self {
        let mut rng = chip ^ 0x5EC0_E1E0_5EC0_E1E0;
        let mut hmac_key = [0u8; 32];
        fill(&mut rng, &mut hmac_key);
        Self {
            rng,
            hmac_key,
            auth: [0; 32],
            secret: [0; 32],
            state: SeState::Blank,
            max: 0,
            counter: 0,
            broken: false,
            calls_left: None,
        }
    }

    fn check(&mut self) -> Result<(), SeError> {
        if let Some(n) = self.calls_left {
            if n == 0 {
                self.broken = true;
            } else {
                self.calls_left = Some(n - 1);
            }
        }
        if self.broken {
            Err(SeError::Bus)
        } else {
            Ok(())
        }
    }

    /// One presentation of `auth`: right, or one attempt used.
    fn present(&mut self, auth: &[u8; 32]) -> Result<(), SeError> {
        let left = match self.state {
            SeState::Blank => return Err(SeError::Blank),
            SeState::Locked => return Err(SeError::Locked),
            SeState::Ready { left } => left,
        };
        if ct_eq(&self.auth, auth) {
            self.state = SeState::Ready { left: self.max };
            return Ok(());
        }
        let left = left.saturating_sub(1);
        if left == 0 {
            // the secret is gone for good
            wipe(&mut self.secret);
            wipe(&mut self.auth);
            self.state = SeState::Locked;
        } else {
            self.state = SeState::Ready { left };
        }
        Err(SeError::WrongAuth { left })
    }
}

impl SecureElement for SimSecureElement {
    fn state(&mut self) -> Result<SeState, SeError> {
        self.check()?;
        Ok(self.state)
    }

    fn provision(&mut self, auth: &[u8; 32], max_attempts: u8) -> Result<(), SeError> {
        self.check()?;
        if self.state != SeState::Blank {
            return Err(SeError::Exists);
        }
        let mut s = [0u8; 32];
        fill(&mut self.rng, &mut s);
        self.secret = s;
        wipe(&mut s);
        self.auth = *auth;
        self.max = max_attempts.max(1);
        self.state = SeState::Ready { left: self.max };
        Ok(())
    }

    fn unlock(&mut self, auth: &[u8; 32], secret: &mut [u8; 32]) -> Result<(), SeError> {
        self.check()?;
        self.present(auth)?;
        *secret = self.secret;
        Ok(())
    }

    fn change_auth(&mut self, old: &[u8; 32], new: &[u8; 32]) -> Result<(), SeError> {
        self.check()?;
        self.present(old)?;
        self.auth = *new;
        Ok(())
    }

    fn destroy(&mut self) -> Result<(), SeError> {
        self.check()?;
        wipe(&mut self.secret);
        wipe(&mut self.auth);
        self.state = SeState::Blank;
        Ok(())
    }

    fn hmac(&mut self, msg: &[u8], out: &mut [u8; 32]) -> Result<(), SeError> {
        self.check()?;
        *out = HmacSha256::mac(&self.hmac_key, msg);
        Ok(())
    }

    fn counter(&mut self) -> Result<u32, SeError> {
        self.check()?;
        Ok(self.counter)
    }

    fn bump_counter(&mut self) -> Result<u32, SeError> {
        self.check()?;
        self.counter = self.counter.checked_add(1).ok_or(SeError::Bus)?;
        Ok(self.counter)
    }
}

/// Simulated SAES + DHUK: a per-chip mask (its own inverse).
pub struct SimDeviceKey {
    chip: u64,
}

impl SimDeviceKey {
    pub fn new(chip: u64) -> Self {
        Self { chip }
    }

    fn apply(&self, data: &mut [u8; 32]) {
        let mut st = self.chip ^ 0xD10C_0DE5_D10C_0DE5;
        let mut mask = [0u8; 32];
        fill(&mut st, &mut mask);
        for (d, m) in data.iter_mut().zip(mask.iter()) {
            *d ^= m;
        }
        wipe(&mut mask);
    }
}

impl DeviceKey for SimDeviceKey {
    fn encipher(&mut self, data: &mut [u8; 32]) -> Result<(), DeviceKeyError> {
        self.apply(data);
        Ok(())
    }
    fn decipher(&mut self, data: &mut [u8; 32]) -> Result<(), DeviceKeyError> {
        self.apply(data);
        Ok(())
    }
}

/// Bytes per vault slot (two slots).
pub const SLOT_LEN: usize = 16 * 1024;

/// Simulated vault flash with NOR rules and power cuts.
pub struct SimFlash {
    pub slots: [[u8; SLOT_LEN]; 2],
    /// Operations left before the power fails (each programmed byte and
    /// each erase is one); `None` = no failure. After the cut nothing more
    /// happens until `power_on`.
    pub budget: Option<usize>,
    cut: bool,
}

impl Default for SimFlash {
    fn default() -> Self {
        Self::new()
    }
}

impl SimFlash {
    pub fn new() -> Self {
        Self {
            slots: [[0xFF; SLOT_LEN]; 2],
            budget: None,
            cut: false,
        }
    }

    /// Power returns: the flash works again (with what it holds).
    pub fn power_on(&mut self) {
        self.cut = false;
        self.budget = None;
    }

    /// Spend one operation; false once the power is gone.
    fn spend(&mut self) -> bool {
        if self.cut {
            return false;
        }
        match self.budget {
            Some(0) => {
                self.cut = true;
                false
            }
            Some(n) => {
                self.budget = Some(n - 1);
                true
            }
            None => true,
        }
    }
}

impl VaultFlash for SimFlash {
    fn slot_len(&self) -> usize {
        SLOT_LEN
    }

    fn read(&mut self, slot: u8, offset: usize, buf: &mut [u8]) -> Result<(), FlashError> {
        let s = self.slots.get(slot as usize).ok_or(FlashError::Range)?;
        let end = offset.checked_add(buf.len()).ok_or(FlashError::Range)?;
        buf.copy_from_slice(s.get(offset..end).ok_or(FlashError::Range)?);
        Ok(())
    }

    fn erase(&mut self, slot: u8) -> Result<(), FlashError> {
        if slot > 1 {
            return Err(FlashError::Range);
        }
        if self.cut {
            return Err(FlashError::Io);
        }
        if self.budget == Some(0) {
            // the power fails during this erase: only the first half got erased
            self.cut = true;
            self.slots[slot as usize][..SLOT_LEN / 2].fill(0xFF);
            return Err(FlashError::Io);
        }
        self.spend();
        self.slots[slot as usize].fill(0xFF);
        Ok(())
    }

    fn program(&mut self, slot: u8, offset: usize, data: &[u8]) -> Result<(), FlashError> {
        if slot > 1 || offset.checked_add(data.len()).is_none_or(|e| e > SLOT_LEN) {
            return Err(FlashError::Range);
        }
        for (i, &b) in data.iter().enumerate() {
            if !self.spend() {
                return Err(FlashError::Io);
            }
            // NOR: programming can only clear bits
            self.slots[slot as usize][offset + i] &= b;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_element_locks_for_good_after_the_attempts() {
        let mut se = SimSecureElement::new(1);
        assert_eq!(se.state(), Ok(SeState::Blank));
        let mut s = [0u8; 32];
        assert_eq!(se.unlock(&[1; 32], &mut s), Err(SeError::Blank));
        se.provision(&[1; 32], 3).unwrap();
        assert_eq!(se.provision(&[2; 32], 3), Err(SeError::Exists));
        se.unlock(&[1; 32], &mut s).unwrap();
        let secret = s;
        assert_ne!(secret, [0; 32]);
        // two wrong, then right: the attempts start over
        assert_eq!(se.unlock(&[9; 32], &mut s), Err(SeError::WrongAuth { left: 2 }));
        assert_eq!(se.unlock(&[9; 32], &mut s), Err(SeError::WrongAuth { left: 1 }));
        se.unlock(&[1; 32], &mut s).unwrap();
        assert_eq!(se.state(), Ok(SeState::Ready { left: 3 }));
        // a changed authenticator; the old one no longer works
        se.change_auth(&[1; 32], &[5; 32]).unwrap();
        assert_eq!(se.unlock(&[1; 32], &mut s), Err(SeError::WrongAuth { left: 2 }));
        se.unlock(&[5; 32], &mut s).unwrap();
        assert_eq!(s, secret, "the secret is kept");
        // three wrong: locked, and the right one no longer helps
        for left in [2, 1, 0] {
            assert_eq!(se.unlock(&[9; 32], &mut s), Err(SeError::WrongAuth { left }));
        }
        assert_eq!(se.state(), Ok(SeState::Locked));
        assert_eq!(se.unlock(&[5; 32], &mut s), Err(SeError::Locked));
        assert_eq!(se.change_auth(&[5; 32], &[6; 32]), Err(SeError::Locked));
        // destroy makes it blank; a new secret is a different one
        se.destroy().unwrap();
        se.provision(&[5; 32], 3).unwrap();
        se.unlock(&[5; 32], &mut s).unwrap();
        assert_ne!(s, secret);
    }

    #[test]
    fn counter_hmac_and_chips_differ() {
        let mut a = SimSecureElement::new(1);
        let mut b = SimSecureElement::new(2);
        assert_eq!(a.counter(), Ok(0));
        assert_eq!(a.bump_counter(), Ok(1));
        a.destroy().unwrap();
        assert_eq!(a.counter(), Ok(1), "the counter survives destroy");
        let (mut ha, mut ha2, mut hb) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        a.hmac(b"prefix", &mut ha).unwrap();
        a.hmac(b"prefix", &mut ha2).unwrap();
        b.hmac(b"prefix", &mut hb).unwrap();
        assert_eq!(ha, ha2);
        assert_ne!(ha, hb);
        a.broken = true;
        assert_eq!(a.state(), Err(SeError::Bus));
        // the hidden key: its own inverse, different per chip
        let (mut k1, mut k2) = (SimDeviceKey::new(1), SimDeviceKey::new(2));
        let mut d = [7u8; 32];
        k1.encipher(&mut d).unwrap();
        assert_ne!(d, [7u8; 32]);
        let mut e = d;
        k2.decipher(&mut e).unwrap();
        assert_ne!(e, [7u8; 32], "another chip cannot decipher");
        k1.decipher(&mut d).unwrap();
        assert_eq!(d, [7u8; 32]);
    }

    #[test]
    fn flash_follows_nor_rules_and_power_cuts() {
        let mut f = SimFlash::new();
        f.program(0, 10, &[0xF0, 0x0F]).unwrap();
        f.program(0, 10, &[0x3C, 0xFF]).unwrap();
        let mut b = [0u8; 2];
        f.read(0, 10, &mut b).unwrap();
        assert_eq!(b, [0x30, 0x0F], "bits only clear");
        assert_eq!(f.program(0, SLOT_LEN - 1, &[0, 0]), Err(FlashError::Range));
        assert_eq!(f.read(2, 0, &mut b), Err(FlashError::Range));
        f.erase(0).unwrap();
        f.read(0, 10, &mut b).unwrap();
        assert_eq!(b, [0xFF, 0xFF]);
        // the power fails after 3 bytes
        f.budget = Some(3);
        assert_eq!(f.program(1, 0, &[1, 2, 3, 4, 5]), Err(FlashError::Io));
        assert_eq!(f.erase(0), Err(FlashError::Io), "nothing more until power on");
        let mut five = [0u8; 5];
        f.read(1, 0, &mut five).unwrap();
        assert_eq!(five, [1, 2, 3, 0xFF, 0xFF]);
        f.power_on();
        f.program(1, 3, &[4, 5]).unwrap();
        // a cut during an erase leaves it half done; a later erase does nothing
        f.program(0, 0, &[0u8; SLOT_LEN]).unwrap();
        f.budget = Some(0);
        assert_eq!(f.erase(0), Err(FlashError::Io));
        assert!(f.slots[0][..SLOT_LEN / 2].iter().all(|&b| b == 0xFF));
        assert!(f.slots[0][SLOT_LEN / 2..].iter().all(|&b| b == 0));
        assert_eq!(f.erase(1), Err(FlashError::Io));
        assert_eq!(f.slots[1][0], 1, "untouched after the cut");
    }
}
