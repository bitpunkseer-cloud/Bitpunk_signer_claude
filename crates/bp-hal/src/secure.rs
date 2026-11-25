//! Secure storage hardware (M10): the secure element, the chip's hidden
//! key and the vault's flash area. The app never holds these: like the
//! microSD card, the platform lends them for one vault job at a time.
//!
//! - Device: NXP SE050 on I2C (OM-SE050ARD-E shield), SAES with the
//!   derived hardware unique key (DHUK), the external XSPI flash.
//! - Simulator and tests: implementations that keep the same rules
//!   (attempts that run out lock the secret for good; the counter only
//!   goes up; the hidden key differs per chip).

/// What the secure element holds for the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeState {
    /// No PIN-gated secret yet (new device, or after `destroy`).
    Blank,
    /// The secret exists; `left` wrong attempts remain before it locks.
    Ready { left: u8 },
    /// The attempts ran out: the secret can never be read again. Only
    /// `destroy` (then a new `provision`) makes the element usable.
    Locked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeError {
    /// The element did not answer or answered nonsense.
    Bus,
    /// No secret to unlock or change.
    Blank,
    /// A secret already exists (destroy it first).
    Exists,
    /// Wrong authenticator; `left` attempts remain (0: now locked).
    WrongAuth { left: u8 },
    /// The attempts ran out earlier.
    Locked,
}

/// The secure element (M10 decision 1: NXP SE050).
pub trait SecureElement {
    fn state(&mut self) -> Result<SeState, SeError>;
    /// Create the PIN-gated secret. The element makes the 32-byte secret
    /// itself (its own TRNG); it can be read only after presenting `auth`,
    /// and `max_attempts` wrong presentations lock it for good.
    fn provision(&mut self, auth: &[u8; 32], max_attempts: u8) -> Result<(), SeError>;
    /// Present `auth`: on success the secret is copied to `secret` and the
    /// attempts start over; on failure one attempt is used.
    fn unlock(&mut self, auth: &[u8; 32], secret: &mut [u8; 32]) -> Result<(), SeError>;
    /// Replace the authenticator, keeping the secret (needs the current one;
    /// a wrong `old` uses an attempt).
    fn change_auth(&mut self, old: &[u8; 32], new: &[u8; 32]) -> Result<(), SeError>;
    /// Erase the PIN-gated secret now (vault wipe, trick PIN, after lockout).
    fn destroy(&mut self) -> Result<(), SeError>;
    /// HMAC-SHA256 with a key that never leaves the element and needs no PIN
    /// (anti-phishing words, tamper check code). The same on every call.
    fn hmac(&mut self, msg: &[u8], out: &mut [u8; 32]) -> Result<(), SeError>;
    /// The monotonic counter (never goes down, survives `destroy`).
    fn counter(&mut self) -> Result<u32, SeError>;
    /// Add one to the counter and return the new value.
    fn bump_counter(&mut self) -> Result<u32, SeError>;
}

/// The chip's hidden key could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceKeyError;

/// The chip's hidden key (SAES with DHUK): data enciphered here can be
/// deciphered only by this chip; the key itself is never readable.
pub trait DeviceKey {
    fn encipher(&mut self, data: &mut [u8; 32]) -> Result<(), DeviceKeyError>;
    fn decipher(&mut self, data: &mut [u8; 32]) -> Result<(), DeviceKeyError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlashError {
    /// The flash did not complete the operation.
    Io,
    /// Outside the slot.
    Range,
}

/// The vault's flash area: two slots (0 and 1) of `slot_len` bytes with NOR
/// rules (erase sets every byte to 0xFF; programming can only clear bits).
pub trait VaultFlash {
    fn slot_len(&self) -> usize;
    fn read(&mut self, slot: u8, offset: usize, buf: &mut [u8]) -> Result<(), FlashError>;
    fn erase(&mut self, slot: u8) -> Result<(), FlashError>;
    fn program(&mut self, slot: u8, offset: usize, data: &[u8]) -> Result<(), FlashError>;
}
