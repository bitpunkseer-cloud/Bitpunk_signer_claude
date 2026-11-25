//! The vault (M10-3): what the device keeps between power-ons, encrypted.
//!
//! Keys (M10 plan 3-1):
//! ```text
//! D  = a random 32-byte device key, stored enciphered by the chip's hidden key
//! P  = Argon2id(PIN, salt, params, secret = D)           device-bound
//! A  = HKDF(salt, P, "bitpunk se auth")                  the secure element's authenticator
//! S  = the secure element's secret, released only for A (10 attempts, then locked)
//! K  = HKDF(salt, P || S || D, "bitpunk vault v1")        the vault key
//! ```
//! Layout of a slot (two slots, written in turn):
//! ```text
//!   0  magic "BPV1", version, language, t, p, m (KiB), generation
//!  16  salt (16)            32  D enciphered (32)      64  nonce (12)
//!  76  body length (2)      78  reserved (2)           80  trick area (256)
//! 336  tag (16)            352  body (ChaCha20-Poly1305, the header is the AD)
//!      then an 8-byte check (SHA-256 of all before it), written last
//! ```
//! A write goes to the other slot, the check last, then the secure
//! element's counter goes up and the old slot is erased: a power cut at
//! any point leaves one whole vault, and a slot older than the counter is
//! refused (rollback).
//!
//! Trick PINs (M10-6, decision 6) live in the trick area, encrypted with a
//! key from D (so only this device reads them, and nobody can tell how
//! many there are). Every attempt stretches the PIN once; the result is
//! compared with every trick first, in constant time, and a trick never
//! reaches the secure element's attempt counter:
//! ```text
//! area     = nonce (12) | ChaCha20-Poly1305(T, 3 entries of 72) | tag (16) | zeros
//! T        = HKDF(salt, D, "bitpunk tricks")
//! entry    = kind | source fingerprint (4) | BIP-85 index (2) | verifier (16)
//!            | nonce (12) | decoy entropy (16, under HKDF(salt, P, "bitpunk decoy")) | tag (16)
//! verifier = HMAC-SHA256(P, "bitpunk trick pin")[..16]
//! ```

use bp_crypto::argon2::{argon2id, Block, Params};
use bp_crypto::chacha20poly1305::{ct_eq, open as aead_open, seal as aead_seal};
use bp_crypto::hkdf::hkdf;
use bp_crypto::hmac::HmacSha256;
use bp_crypto::secret::{wipe, Secret};
use bp_crypto::sha256::Sha256;
use bp_hal::secure::{DeviceKey, SeError, SeState, SecureElement, VaultFlash};
use bp_hal::Rng;

/// Any secure element, hidden key or flash failure is a hardware error.
macro_rules! hw {
    ($e:expr) => {
        $e.map_err(|_| VaultError::Hardware)
    };
}

pub const MAGIC: &[u8; 4] = b"BPV1";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 352;
const AD_LEN: usize = 336;
pub const CHECK_LEN: usize = 8;
pub const TRICK_LEN: usize = 256;
/// Wrong PINs before the secure element locks the secret (decision 4).
pub const MAX_ATTEMPTS: u8 = 10;
/// Starting KDF cost (decision 8; tuned on the device).
pub const DEFAULT_KDF: Params = Params {
    m_kib: 8192,
    t: 3,
    p: 1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// No complete vault in either slot.
    NoVault,
    /// Wrong PIN; `left` attempts remain.
    WrongPin { left: u8 },
    /// The attempts ran out: the vault is gone for good (and was erased).
    Wiped,
    /// No slot opens with the right PIN (damaged, or written by another chip).
    Corrupt,
    /// Only slots older than the secure element's counter (rolled back).
    Rollback,
    /// The contents do not fit a slot.
    TooLarge,
    /// The secure element, hidden key or flash failed.
    Hardware,
    /// The PIN is already the vault's PIN or a trick PIN (M10-6).
    PinClash,
    /// Three trick PINs are set already.
    TricksFull,
}

/// Trick PINs a vault holds (M10-6).
pub const TRICKS: usize = 3;
const ENTRY_LEN: usize = 72;
const AREA_PLAIN: usize = TRICKS * ENTRY_LEN;

/// What a trick PIN does (decision 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrickKind {
    /// Opens like the vault, with a decoy seed instead.
    Decoy,
    /// Erases the vault, then looks like a wrong PIN.
    WipeWrong,
    /// Erases the vault, then opens the decoy seed.
    WipeDecoy,
    /// Starts like a device without a vault (nothing erased).
    Blank,
}

impl TrickKind {
    pub const ALL: [TrickKind; 4] = [
        TrickKind::Decoy,
        TrickKind::WipeWrong,
        TrickKind::WipeDecoy,
        TrickKind::Blank,
    ];
    fn code(self) -> u8 {
        self as u8 + 1
    }
    fn from_code(c: u8) -> Option<TrickKind> {
        Self::ALL.get((c as usize).wrapping_sub(1)).copied()
    }
    pub fn has_decoy(self) -> bool {
        matches!(self, TrickKind::Decoy | TrickKind::WipeDecoy)
    }
}

/// A trick PIN as the list shows it (the PIN itself is never kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrickInfo {
    pub kind: TrickKind,
    /// The seed the decoy was derived from, and the BIP-85 index.
    pub src_fp: [u8; 4],
    pub index: u16,
}

/// What a PIN opened. (Returned once per attempt and moved straight into
/// the app; there is no heap to box the vault keys into.)
#[allow(clippy::large_enum_variant)]
pub enum Opened {
    /// The vault: its plaintext body is in `body[..len]`.
    Vault(Unlocked, usize),
    /// A trick PIN; the decoy seed's entropy for the decoy kinds.
    Trick {
        kind: TrickKind,
        decoy: Option<Secret<16>>,
    },
}

impl Opened {
    /// The vault, if the PIN was the vault's own.
    pub fn vault(self) -> Option<(Unlocked, usize)> {
        match self {
            Opened::Vault(u, n) => Some((u, n)),
            Opened::Trick { .. } => None,
        }
    }
}

/// The parts lent for one vault job.
pub struct VaultHw<'a> {
    pub se: &'a mut dyn SecureElement,
    pub key: &'a mut dyn DeviceKey,
    pub flash: &'a mut dyn VaultFlash,
    pub rng: &'a mut dyn Rng,
    /// Argon2 memory (the KDF parameters' blocks, or more).
    pub mem: &'a mut [Block],
}

/// A slot's plaintext header.
#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    pub lang: u8,
    pub kdf: Params,
    pub gen: u32,
    pub salt: [u8; 16],
    pub wrapped_d: [u8; 32],
    pub nonce: [u8; 12],
    pub body_len: u16,
    pub tricks: [u8; TRICK_LEN],
    pub tag: [u8; 16],
}

impl Header {
    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(MAGIC);
        b[4] = VERSION;
        b[5] = self.lang;
        b[6] = self.kdf.t as u8;
        b[7] = self.kdf.p as u8;
        b[8..12].copy_from_slice(&self.kdf.m_kib.to_le_bytes());
        b[12..16].copy_from_slice(&self.gen.to_le_bytes());
        b[16..32].copy_from_slice(&self.salt);
        b[32..64].copy_from_slice(&self.wrapped_d);
        b[64..76].copy_from_slice(&self.nonce);
        b[76..78].copy_from_slice(&self.body_len.to_le_bytes());
        b[80..80 + TRICK_LEN].copy_from_slice(&self.tricks);
        b[AD_LEN..HEADER_LEN].copy_from_slice(&self.tag);
        b
    }

    fn parse(b: &[u8; HEADER_LEN], slot_len: usize) -> Option<Header> {
        if &b[0..4] != MAGIC || b[4] != VERSION || b[78..80] != [0, 0] {
            return None;
        }
        let u32le = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let kdf = Params {
            m_kib: u32le(8),
            t: b[6] as u32,
            p: b[7] as u32,
        };
        // sane costs only (a forged header must not make the device hang)
        if kdf.t == 0 || kdf.t > 16 || kdf.p == 0 || kdf.p > 8 || kdf.m_kib < 8 * kdf.p || kdf.m_kib > 1 << 20
        {
            return None;
        }
        let body_len = u16::from_le_bytes([b[76], b[77]]);
        if HEADER_LEN + body_len as usize + CHECK_LEN > slot_len {
            return None;
        }
        Some(Header {
            lang: b[5],
            kdf,
            gen: u32le(12),
            salt: b[16..32].try_into().ok()?,
            wrapped_d: b[32..64].try_into().ok()?,
            nonce: b[64..76].try_into().ok()?,
            body_len,
            tricks: b[80..80 + TRICK_LEN].try_into().ok()?,
            tag: b[AD_LEN..HEADER_LEN].try_into().ok()?,
        })
    }
}

/// A complete slot found without the PIN.
#[derive(Clone)]
pub struct Found {
    pub slot: u8,
    pub header: Header,
}

/// The keys held while the vault is open (wiped when it locks).
pub struct Unlocked {
    k: Secret<32>,
    s: Secret<32>,
    d: Secret<32>,
    auth: Secret<32>,
    salt: [u8; 16],
    kdf: Params,
    lang: u8,
    gen: u32,
    slot: u8,
    tricks: [u8; TRICK_LEN],
}

impl Unlocked {
    pub fn lang(&self) -> u8 {
        self.lang
    }
    /// The language the next write puts in the header (for the lock screen).
    pub fn set_lang(&mut self, lang: u8) {
        self.lang = lang;
    }
    pub fn generation(&self) -> u32 {
        self.gen
    }
    pub fn tricks(&self) -> &[u8; TRICK_LEN] {
        &self.tricks
    }
}

/// Read slot `slot`: its header if the slot is complete (check matches);
/// the body ciphertext is left in `body`.
fn read_slot(flash: &mut dyn VaultFlash, slot: u8, body: &mut [u8]) -> Result<Option<Header>, VaultError> {
    let slot_len = flash.slot_len();
    let mut hb = [0u8; HEADER_LEN];
    flash.read(slot, 0, &mut hb).map_err(|_| VaultError::Hardware)?;
    let Some(h) = Header::parse(&hb, slot_len) else {
        return Ok(None);
    };
    let n = h.body_len as usize;
    if n > body.len() {
        return Err(VaultError::TooLarge);
    }
    flash
        .read(slot, HEADER_LEN, &mut body[..n])
        .map_err(|_| VaultError::Hardware)?;
    let mut check = [0u8; CHECK_LEN];
    flash
        .read(slot, HEADER_LEN + n, &mut check)
        .map_err(|_| VaultError::Hardware)?;
    let mut sha = Sha256::new();
    sha.update(&hb);
    sha.update(&body[..n]);
    let want = sha.finalize();
    if want[..CHECK_LEN] != check {
        return Ok(None);
    }
    Ok(Some(h))
}

/// The newest complete slot, if any (no PIN needed: the lock screen uses
/// it for the language, and the anti-phishing words for the device key).
pub fn scan(flash: &mut dyn VaultFlash, body: &mut [u8]) -> Result<Option<Found>, VaultError> {
    let mut best: Option<Found> = None;
    for slot in 0..2u8 {
        if let Some(header) = read_slot(flash, slot, body)? {
            if best.as_ref().is_none_or(|b| header.gen > b.header.gen) {
                best = Some(Found { slot, header });
            }
        }
    }
    Ok(best)
}

/// Whether a vault exists (the secure element holds its secret, or is
/// locked) — what decides the lock screen at power on.
pub fn exists(hw: &mut VaultHw, body: &mut [u8]) -> Result<bool, VaultError> {
    Ok(scan(hw.flash, body)?.is_some() && hw!(hw.se.state())? != SeState::Blank)
}

fn derive_p(
    pin: &[u8],
    salt: &[u8; 16],
    kdf: Params,
    d: &[u8; 32],
    mem: &mut [Block],
) -> Result<Secret<32>, VaultError> {
    let mut p = Secret::new([0u8; 32]);
    argon2id(kdf, pin, salt, d, b"bitpunk pin", mem, p.expose_mut()).map_err(|_| VaultError::Hardware)?;
    Ok(p)
}

fn derive_auth(salt: &[u8; 16], p: &[u8; 32]) -> Secret<32> {
    let mut a = Secret::new([0u8; 32]);
    let _ = hkdf(salt, &[p], b"bitpunk se auth", a.expose_mut());
    a
}

fn derive_k(salt: &[u8; 16], p: &[u8; 32], s: &[u8; 32], d: &[u8; 32]) -> Secret<32> {
    let mut k = Secret::new([0u8; 32]);
    let _ = hkdf(salt, &[p, s, d], b"bitpunk vault v1", k.expose_mut());
    k
}

fn tricks_key(salt: &[u8; 16], d: &[u8; 32]) -> Secret<32> {
    let mut t = Secret::new([0u8; 32]);
    let _ = hkdf(salt, &[d], b"bitpunk tricks", t.expose_mut());
    t
}

fn decoy_key(salt: &[u8; 16], p: &[u8; 32]) -> Secret<32> {
    let mut t = Secret::new([0u8; 32]);
    let _ = hkdf(salt, &[p], b"bitpunk decoy", t.expose_mut());
    t
}

fn verifier(p: &[u8; 32]) -> [u8; 16] {
    let mut m = HmacSha256::mac(p, b"bitpunk trick pin");
    let mut v = [0u8; 16];
    v.copy_from_slice(&m[..16]);
    wipe(&mut m);
    v
}

/// The trick entries (all empty if the area does not open: a vault made
/// before M10-6 has random bytes there).
fn read_area(area: &[u8; TRICK_LEN], salt: &[u8; 16], d: &[u8; 32]) -> Secret<AREA_PLAIN> {
    let mut plain = Secret::new([0u8; AREA_PLAIN]);
    plain.expose_mut().copy_from_slice(&area[12..12 + AREA_PLAIN]);
    let nonce: [u8; 12] = area[..12].try_into().expect("12");
    let tag: [u8; 16] = area[12 + AREA_PLAIN..28 + AREA_PLAIN].try_into().expect("16");
    let key = tricks_key(salt, d);
    if aead_open(
        key.expose(),
        &nonce,
        b"bitpunk tricks v1",
        plain.expose_mut(),
        &tag,
    )
    .is_err()
    {
        plain.expose_mut().fill(0);
    }
    plain
}

fn write_area(plain: &[u8; AREA_PLAIN], salt: &[u8; 16], d: &[u8; 32], rng: &mut dyn Rng) -> [u8; TRICK_LEN] {
    let mut area = [0u8; TRICK_LEN];
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    area[..12].copy_from_slice(&nonce);
    area[12..12 + AREA_PLAIN].copy_from_slice(plain);
    let key = tricks_key(salt, d);
    let tag = aead_seal(
        key.expose(),
        &nonce,
        b"bitpunk tricks v1",
        &mut area[12..12 + AREA_PLAIN],
    );
    area[12 + AREA_PLAIN..28 + AREA_PLAIN].copy_from_slice(&tag);
    area
}

/// The entry whose verifier is `v`, comparing every entry (no early exit).
fn match_trick(plain: &[u8; AREA_PLAIN], v: &[u8; 16]) -> Option<usize> {
    let mut hit = None;
    for i in 0..TRICKS {
        let e = &plain[i * ENTRY_LEN..(i + 1) * ENTRY_LEN];
        let same = ct_eq(&e[7..23], v) & (e[0] != 0);
        if same {
            hit = Some(i);
        }
    }
    hit
}

fn entry_info(e: &[u8]) -> Option<TrickInfo> {
    Some(TrickInfo {
        kind: TrickKind::from_code(e[0])?,
        src_fp: e[1..5].try_into().ok()?,
        index: u16::from_le_bytes([e[5], e[6]]),
    })
}

/// The trick PINs of an open vault, in order.
pub fn tricks(u: &Unlocked) -> [Option<TrickInfo>; TRICKS] {
    let plain = read_area(&u.tricks, &u.salt, u.d.expose());
    core::array::from_fn(|i| entry_info(&plain.expose()[i * ENTRY_LEN..(i + 1) * ENTRY_LEN]))
}

/// The entry the next trick PIN takes.
pub fn next_trick(u: &Unlocked) -> Option<usize> {
    tricks(u).iter().position(|t| t.is_none())
}

/// Add a trick PIN to an open vault (written by the next save). Refused if
/// `pin` is the vault's PIN or another trick PIN.
#[allow(clippy::too_many_arguments)]
pub fn add_trick(
    hw: &mut VaultHw,
    u: &mut Unlocked,
    pin: &[u8],
    kind: TrickKind,
    src_fp: [u8; 4],
    index: u16,
    decoy: Option<&[u8; 16]>,
) -> Result<(), VaultError> {
    let p = derive_p(pin, &u.salt, u.kdf, u.d.expose(), hw.mem)?;
    let k = derive_k(&u.salt, p.expose(), u.s.expose(), u.d.expose());
    let v = verifier(p.expose());
    let mut plain = read_area(&u.tricks, &u.salt, u.d.expose());
    if ct_eq(k.expose(), u.k.expose()) || match_trick(plain.expose(), &v).is_some() {
        return Err(VaultError::PinClash);
    }
    let i = (0..TRICKS)
        .find(|i| plain.expose()[i * ENTRY_LEN] == 0)
        .ok_or(VaultError::TricksFull)?;
    let e = &mut plain.expose_mut()[i * ENTRY_LEN..(i + 1) * ENTRY_LEN];
    e.fill(0);
    e[0] = kind.code();
    e[1..5].copy_from_slice(&src_fp);
    e[5..7].copy_from_slice(&index.to_le_bytes());
    e[7..23].copy_from_slice(&v);
    if let Some(ent) = decoy.filter(|_| kind.has_decoy()) {
        let mut nonce = [0u8; 12];
        hw.rng.fill_bytes(&mut nonce);
        e[23..35].copy_from_slice(&nonce);
        e[35..51].copy_from_slice(ent);
        let key = decoy_key(&u.salt, p.expose());
        let tag = aead_seal(key.expose(), &nonce, b"bitpunk decoy v1", &mut e[35..51]);
        e[51..67].copy_from_slice(&tag);
    }
    u.tricks = write_area(plain.expose(), &u.salt, u.d.expose(), hw.rng);
    Ok(())
}

/// Remove trick PIN `i` (the rest keep their order; written by the next save).
pub fn remove_trick(rng: &mut dyn Rng, u: &mut Unlocked, i: usize) {
    let mut plain = read_area(&u.tricks, &u.salt, u.d.expose());
    if i < TRICKS {
        let p = plain.expose_mut();
        p.copy_within((i + 1) * ENTRY_LEN.., i * ENTRY_LEN);
        p[AREA_PLAIN - ENTRY_LEN..].fill(0);
    }
    u.tricks = write_area(plain.expose(), &u.salt, u.d.expose(), rng);
}

/// Stretch `pin` the way an attempt does, for nothing (after a silent
/// wipe the lock screen still takes as long as before).
pub fn spend_an_attempt(hw: &mut VaultHw, pin: &[u8], kdf: Params) {
    let mut salt = [0u8; 16];
    hw.rng.fill_bytes(&mut salt);
    let _ = derive_p(pin, &salt, kdf, &[0; 32], hw.mem);
}

/// Encrypt `body[..n]` in place and write it to `slot` as generation `gen`.
fn write_slot(
    hw: &mut VaultHw,
    u: &Unlocked,
    slot: u8,
    gen: u32,
    body: &mut [u8],
    n: usize,
) -> Result<(), VaultError> {
    if n > u16::MAX as usize || HEADER_LEN + n + CHECK_LEN > hw.flash.slot_len() || n > body.len() {
        return Err(VaultError::TooLarge);
    }
    let mut wrapped_d = *u.d.expose();
    hw.key
        .encipher(&mut wrapped_d)
        .map_err(|_| VaultError::Hardware)?;
    let mut nonce = [0u8; 12];
    hw.rng.fill_bytes(&mut nonce);
    let mut h = Header {
        lang: u.lang,
        kdf: u.kdf,
        gen,
        salt: u.salt,
        wrapped_d,
        nonce,
        body_len: n as u16,
        tricks: u.tricks,
        tag: [0; 16],
    };
    let ad = h.to_bytes();
    h.tag = aead_seal(u.k.expose(), &nonce, &ad[..AD_LEN], &mut body[..n]);
    let hb = h.to_bytes();
    let mut sha = Sha256::new();
    sha.update(&hb);
    sha.update(&body[..n]);
    let check = sha.finalize();
    hw!(hw.flash.erase(slot))?;
    hw!(hw.flash.program(slot, 0, &hb))?;
    hw!(hw.flash.program(slot, HEADER_LEN, &body[..n]))?;
    // the check last: until it is there the slot does not count
    hw!(hw.flash.program(slot, HEADER_LEN + n, &check[..CHECK_LEN]))?;
    Ok(())
}

/// Commit a written generation: count it in the secure element, then erase
/// the other slot (what it held must not stay readable).
fn commit(hw: &mut VaultHw, written: u8, gen: u32) -> Result<(), VaultError> {
    let now = hw!(hw.se.counter())?;
    if now < gen {
        hw!(hw.se.bump_counter())?;
    }
    hw!(hw.flash.erase(1 - written))
}

/// Make a new vault holding `body[..n]` (plaintext; encrypted in place).
/// Any old vault and the secure element's old secret are replaced.
#[allow(clippy::too_many_arguments)]
pub fn create(
    hw: &mut VaultHw,
    pin: &[u8],
    kdf: Params,
    lang: u8,
    body: &mut [u8],
    n: usize,
) -> Result<Unlocked, VaultError> {
    let mut d = Secret::new([0u8; 32]);
    hw.rng.fill_bytes(d.expose_mut());
    let mut salt = [0u8; 16];
    hw.rng.fill_bytes(&mut salt);
    let tricks = write_area(&[0u8; AREA_PLAIN], &salt, d.expose(), hw.rng);
    let p = derive_p(pin, &salt, kdf, d.expose(), hw.mem)?;
    let auth = derive_auth(&salt, p.expose());
    if hw!(hw.se.state())? != SeState::Blank {
        hw!(hw.se.destroy())?;
    }
    hw!(hw.se.provision(auth.expose(), MAX_ATTEMPTS))?;
    let mut s = Secret::new([0u8; 32]);
    hw!(hw.se.unlock(auth.expose(), s.expose_mut()))?;
    let k = derive_k(&salt, p.expose(), s.expose(), d.expose());
    let gen = hw!(hw.se.counter())? + 1;
    let u = Unlocked {
        k,
        s,
        d,
        auth,
        salt,
        kdf,
        lang,
        gen,
        slot: 0,
        tricks,
    };
    write_slot(hw, &u, 0, gen, body, n)?;
    commit(hw, 0, gen)?;
    Ok(u)
}

/// Open the vault with `pin`; the plaintext body is left in `body` and its
/// length returned. A trick PIN is recognised before the secure element is
/// asked, and uses no attempt.
pub fn open(hw: &mut VaultHw, pin: &[u8], body: &mut [u8]) -> Result<Opened, VaultError> {
    let found = scan(hw.flash, body)?.ok_or(VaultError::NoVault)?;
    match hw!(hw.se.state())? {
        SeState::Blank => return Err(VaultError::NoVault),
        SeState::Locked => {
            wipe_all(hw)?;
            return Err(VaultError::Wiped);
        }
        SeState::Ready { .. } => {}
    }
    let h = &found.header;
    let mut d = Secret::new(h.wrapped_d);
    hw.key
        .decipher(d.expose_mut())
        .map_err(|_| VaultError::Hardware)?;
    let p = derive_p(pin, &h.salt, h.kdf, d.expose(), hw.mem)?;
    let plain = read_area(&h.tricks, &h.salt, d.expose());
    if let Some(i) = match_trick(plain.expose(), &verifier(p.expose())) {
        let e = &plain.expose()[i * ENTRY_LEN..(i + 1) * ENTRY_LEN];
        let kind = TrickKind::from_code(e[0]).ok_or(VaultError::Corrupt)?;
        let decoy = if kind.has_decoy() {
            let mut ent = Secret::new([0u8; 16]);
            ent.expose_mut().copy_from_slice(&e[35..51]);
            let nonce: [u8; 12] = e[23..35].try_into().expect("12");
            let tag: [u8; 16] = e[51..67].try_into().expect("16");
            let key = decoy_key(&h.salt, p.expose());
            aead_open(key.expose(), &nonce, b"bitpunk decoy v1", ent.expose_mut(), &tag)
                .ok()
                .map(|_| ent)
        } else {
            None
        };
        // the secure element is asked something, as for a real attempt
        let _ = hw.se.counter();
        return Ok(Opened::Trick { kind, decoy });
    }
    let auth = derive_auth(&h.salt, p.expose());
    let mut s = Secret::new([0u8; 32]);
    match hw.se.unlock(auth.expose(), s.expose_mut()) {
        Ok(()) => {}
        Err(SeError::WrongAuth { left: 0 }) | Err(SeError::Locked) => {
            wipe_all(hw)?;
            return Err(VaultError::Wiped);
        }
        Err(SeError::WrongAuth { left }) => return Err(VaultError::WrongPin { left }),
        Err(_) => return Err(VaultError::Hardware),
    }
    let k = derive_k(&h.salt, p.expose(), s.expose(), d.expose());
    let counter = hw!(hw.se.counter())?;
    // newest first; a slot that does not open falls back to the other
    let order = [found.slot, 1 - found.slot];
    let mut rollback = false;
    for slot in order.iter() {
        let Some(hh) = read_slot(hw.flash, *slot, body)? else {
            continue;
        };
        if hh.gen < counter {
            rollback = true;
            continue;
        }
        let n = hh.body_len as usize;
        let mut ad = hh.to_bytes();
        if aead_open(k.expose(), &hh.nonce, &ad[..AD_LEN], &mut body[..n], &hh.tag).is_err() {
            wipe(&mut ad);
            continue;
        }
        let u = Unlocked {
            k,
            s,
            d,
            auth,
            salt: hh.salt,
            kdf: hh.kdf,
            lang: hh.lang,
            gen: hh.gen,
            slot: *slot,
            tricks: hh.tricks,
        };
        if hh.gen > counter {
            // a write whose commit was cut short: finish it
            commit(hw, *slot, hh.gen)?;
        }
        return Ok(Opened::Vault(u, n));
    }
    Err(if rollback {
        VaultError::Rollback
    } else {
        VaultError::Corrupt
    })
}

/// Write `body[..n]` (plaintext; encrypted in place) as the next generation.
pub fn save(hw: &mut VaultHw, u: &mut Unlocked, body: &mut [u8], n: usize) -> Result<(), VaultError> {
    let gen = hw!(hw.se.counter())?.max(u.gen) + 1;
    let slot = 1 - u.slot;
    write_slot(hw, u, slot, gen, body, n)?;
    commit(hw, slot, gen)?;
    u.gen = gen;
    u.slot = slot;
    Ok(())
}

/// Change the PIN (same salt and cost) and write `body[..n]` under the new
/// key. The new slot is written before the secure element changes, so a
/// power cut leaves the old PIN or the new one working.
pub fn change_pin(
    hw: &mut VaultHw,
    u: &mut Unlocked,
    new_pin: &[u8],
    body: &mut [u8],
    n: usize,
) -> Result<(), VaultError> {
    let p = derive_p(new_pin, &u.salt, u.kdf, u.d.expose(), hw.mem)?;
    let plain = read_area(&u.tricks, &u.salt, u.d.expose());
    if match_trick(plain.expose(), &verifier(p.expose())).is_some() {
        return Err(VaultError::PinClash);
    }
    let auth = derive_auth(&u.salt, p.expose());
    let k = derive_k(&u.salt, p.expose(), u.s.expose(), u.d.expose());
    let gen = hw!(hw.se.counter())?.max(u.gen) + 1;
    let slot = 1 - u.slot;
    let old_k = core::mem::replace(&mut u.k, k);
    if let Err(e) = write_slot(hw, u, slot, gen, body, n) {
        u.k = old_k;
        return Err(e);
    }
    hw!(hw.se.change_auth(u.auth.expose(), auth.expose()))?;
    u.auth = auth;
    commit(hw, slot, gen)?;
    u.gen = gen;
    u.slot = slot;
    Ok(())
}

/// Erase the vault: the secure element's secret first (the vault can never
/// open again), then both slots.
pub fn wipe_all(hw: &mut VaultHw) -> Result<(), VaultError> {
    hw!(hw.se.destroy())?;
    hw!(hw.flash.erase(0))?;
    hw!(hw.flash.erase(1))
}

/// Anti-phishing words for a PIN prefix: two BIP-39 word indexes from the
/// device key, the header and the secure element's HMAC key. Another
/// device, firmware without this chip and element, or a changed header
/// cannot make the same words.
pub fn phishing_words(hw: &mut VaultHw, found: &Found, prefix: &[u8]) -> Result<[u16; 2], VaultError> {
    let mut d = Secret::new(found.header.wrapped_d);
    hw.key
        .decipher(d.expose_mut())
        .map_err(|_| VaultError::Hardware)?;
    let h = &found.header;
    let mut inner = HmacSha256::new(d.expose());
    inner.update(b"bitpunk words");
    // a changed salt or cost changes the words too: the user stops before
    // a correct PIN is counted as wrong against a tampered header
    inner.update(&h.salt);
    inner.update(&h.kdf.m_kib.to_le_bytes());
    inner.update(&[h.kdf.t as u8, h.kdf.p as u8]);
    inner.update(prefix);
    let mut m = inner.finalize();
    let mut out = [0u8; 32];
    hw!(hw.se.hmac(&m, &mut out))?;
    wipe(&mut m);
    let w0 = u16::from_be_bytes([out[0], out[1]]) >> 5;
    let w1 = u16::from_be_bytes([out[2], out[3]]) >> 5;
    wipe(&mut out);
    Ok([w0, w1])
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sim_hw::{SimDeviceKey, SimFlash, SimSecureElement, SLOT_LEN};
    use std::vec;
    use std::vec::Vec;

    /// Small KDF cost for tests (the format does not depend on it).
    const KDF: Params = Params {
        m_kib: 16,
        t: 1,
        p: 1,
    };

    struct TestRng(u64);
    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *b = self.0 as u8;
            }
        }
    }

    /// One simulated device: secure element, hidden key, flash.
    struct Dev {
        se: SimSecureElement,
        key: SimDeviceKey,
        flash: SimFlash,
        rng: TestRng,
        mem: Vec<Block>,
    }

    impl Dev {
        fn new(chip: u64) -> Dev {
            Dev {
                se: SimSecureElement::new(chip),
                key: SimDeviceKey::new(chip),
                flash: SimFlash::new(),
                rng: TestRng(chip.wrapping_mul(0x9E37_79B9) | 1),
                mem: vec![[0u64; 128]; 64],
            }
        }
        fn hw(&mut self) -> VaultHw<'_> {
            VaultHw {
                se: &mut self.se,
                key: &mut self.key,
                flash: &mut self.flash,
                rng: &mut self.rng,
                mem: &mut self.mem,
            }
        }
    }

    fn body(text: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; SLOT_LEN];
        b[..text.len()].copy_from_slice(text);
        b
    }

    fn open_text(dev: &mut Dev, pin: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut b = vec![0u8; SLOT_LEN];
        let (_, n) = open(&mut dev.hw(), pin, &mut b)?
            .vault()
            .ok_or(VaultError::Corrupt)?;
        Ok(b[..n].to_vec())
    }

    #[test]
    fn create_open_save_and_wrong_pins() {
        let mut dev = Dev::new(7);
        let mut b = vec![0u8; SLOT_LEN];
        assert!(!exists(&mut dev.hw(), &mut b).unwrap());
        assert_eq!(open_text(&mut dev, b"pin"), Err(VaultError::NoVault));
        let mut b = body(b"seed one");
        let mut u = create(&mut dev.hw(), b"correct horse", KDF, 1, &mut b, 8).unwrap();
        assert!(exists(&mut dev.hw(), &mut vec![0u8; SLOT_LEN]).unwrap());
        assert_eq!(open_text(&mut dev, b"correct horse").unwrap(), b"seed one");
        // what is on the flash is not the plaintext
        assert!(!dev
            .flash
            .slots
            .iter()
            .any(|s| s.windows(8).any(|w| w == b"seed one")));
        // the next generation, in the other slot; the old slot is erased
        let mut b = body(b"seed one + two");
        save(&mut dev.hw(), &mut u, &mut b, 14).unwrap();
        assert_eq!(open_text(&mut dev, b"correct horse").unwrap(), b"seed one + two");
        assert!(
            dev.flash.slots[0].iter().all(|&x| x == 0xFF) || dev.flash.slots[1].iter().all(|&x| x == 0xFF)
        );
        // wrong PINs count down; a right one starts over
        assert_eq!(
            open_text(&mut dev, b"wrong"),
            Err(VaultError::WrongPin { left: 9 })
        );
        assert_eq!(
            open_text(&mut dev, b"wrong"),
            Err(VaultError::WrongPin { left: 8 })
        );
        assert!(open_text(&mut dev, b"correct horse").is_ok());
        for left in (1..10).rev() {
            assert_eq!(open_text(&mut dev, b"wrong"), Err(VaultError::WrongPin { left }));
        }
        // the tenth: wiped for good, flash erased
        assert_eq!(open_text(&mut dev, b"wrong"), Err(VaultError::Wiped));
        assert!(dev.flash.slots.iter().all(|s| s.iter().all(|&x| x == 0xFF)));
        assert_eq!(open_text(&mut dev, b"correct horse"), Err(VaultError::NoVault));
        // the device can start a new vault
        let mut b = body(b"fresh");
        create(&mut dev.hw(), b"new pin", KDF, 0, &mut b, 5).unwrap();
        assert_eq!(open_text(&mut dev, b"new pin").unwrap(), b"fresh");
    }

    #[test]
    fn another_chip_or_element_cannot_open_it() {
        let mut a = Dev::new(1);
        let mut b = body(b"secret seed");
        create(&mut a.hw(), b"pin pin pin", KDF, 0, &mut b, 11).unwrap();
        // the flash moved to another device (other chip and element)
        let mut other = Dev::new(2);
        other.flash.slots = a.flash.slots;
        assert_eq!(open_text(&mut other, b"pin pin pin"), Err(VaultError::NoVault));
        // flash and element moved to another chip: the hidden key differs,
        // so even the right PIN does not open it
        let mut moved = Dev::new(4);
        moved.se = a.se.clone();
        moved.flash.slots = a.flash.slots;
        assert!(matches!(
            open_text(&mut moved, b"pin pin pin"),
            Err(VaultError::WrongPin { .. })
        ));
        // the original still opens
        assert_eq!(open_text(&mut a, b"pin pin pin").unwrap(), b"secret seed");
    }

    #[test]
    fn an_older_flash_image_is_refused() {
        let mut dev = Dev::new(5);
        let mut b = body(b"gen 1");
        let mut u = create(&mut dev.hw(), b"pin", KDF, 0, &mut b, 5).unwrap();
        let old = dev.flash.slots;
        let mut b = body(b"gen 2 deleted a seed");
        save(&mut dev.hw(), &mut u, &mut b, 20).unwrap();
        dev.flash.slots = old;
        assert_eq!(open_text(&mut dev, b"pin"), Err(VaultError::Rollback));
        assert_eq!(
            dev.se.state(),
            Ok(SeState::Ready { left: MAX_ATTEMPTS }),
            "the right PIN used no attempt"
        );
    }

    #[test]
    fn a_power_cut_anywhere_leaves_one_whole_vault() {
        let mut base = Dev::new(9);
        let mut b = body(b"old contents");
        create(&mut base.hw(), b"pin", KDF, 0, &mut b, 12).unwrap();
        let new = b"new contents, a little longer";
        // every flash operation of a save (erase + header + body + check +
        // erase of the old slot), and a cut of the secure element at each
        // of its calls
        let flash_ops = 1 + HEADER_LEN + new.len() + CHECK_LEN + 1;
        let cuts = (0..=flash_ops)
            .map(|c| (Some(c), None))
            .chain((0..4).map(|c| (None, Some(c))));
        for (flash_cut, se_cut) in cuts {
            let mut dev = Dev::new(9);
            dev.flash.slots = base.flash.slots;
            dev.se = base.se.clone();
            let mut uu = reopen(&mut dev);
            dev.flash.budget = flash_cut;
            dev.se.calls_left = se_cut;
            let mut b = body(new);
            let r = save(&mut dev.hw(), &mut uu, &mut b, new.len());
            // power returns
            dev.flash.power_on();
            dev.se.calls_left = None;
            dev.se.broken = false;
            let what = (flash_cut, se_cut);
            let got = open_text(&mut dev, b"pin").unwrap_or_else(|e| panic!("cut {what:?}: {e:?}"));
            assert!(got == b"old contents" || got == new, "cut {what:?}: {got:?}");
            if r.is_ok() {
                assert_eq!(got, new, "cut {what:?}");
            }
            // and the next save works from there
            let mut uu = reopen(&mut dev);
            let mut b = body(b"after");
            save(&mut dev.hw(), &mut uu, &mut b, 5).unwrap();
            assert_eq!(open_text(&mut dev, b"pin").unwrap(), b"after", "cut {what:?}");
        }
    }

    /// Open again, as a device that stayed on would hold it.
    fn reopen(dev: &mut Dev) -> Unlocked {
        let mut b = vec![0u8; SLOT_LEN];
        open(&mut dev.hw(), b"pin", &mut b).unwrap().vault().unwrap().0
    }

    #[test]
    fn a_pin_change_survives_a_power_cut() {
        let mut base = Dev::new(11);
        let mut b = body(b"contents");
        let mut u = create(&mut base.hw(), b"old pin", KDF, 0, &mut b, 8).unwrap();
        // completes
        let mut b = body(b"contents");
        change_pin(&mut base.hw(), &mut u, b"new pin", &mut b, 8).unwrap();
        assert_eq!(open_text(&mut base, b"new pin").unwrap(), b"contents");
        assert_eq!(
            open_text(&mut base, b"old pin"),
            Err(VaultError::WrongPin { left: 9 })
        );
        // the power fails right after the new slot is written, before the
        // element changes (its second call in change_pin): the old PIN opens
        let mut dev = Dev::new(12);
        let mut b = body(b"contents");
        let mut u = create(&mut dev.hw(), b"old pin", KDF, 0, &mut b, 8).unwrap();
        dev.se.calls_left = Some(1);
        let mut b = body(b"contents");
        assert!(change_pin(&mut dev.hw(), &mut u, b"new pin", &mut b, 8).is_err());
        dev.se.calls_left = None;
        dev.se.broken = false;
        assert_eq!(
            open_text(&mut dev, b"old pin").unwrap(),
            b"contents",
            "the old PIN still opens"
        );
        // the power fails after the element changed, before the commit: the
        // new PIN opens and finishes the commit
        let mut dev = Dev::new(13);
        let mut b = body(b"contents");
        let mut u = create(&mut dev.hw(), b"old pin", KDF, 0, &mut b, 8).unwrap();
        dev.se.calls_left = Some(2);
        let mut b = body(b"contents");
        assert!(change_pin(&mut dev.hw(), &mut u, b"new pin", &mut b, 8).is_err());
        dev.se.calls_left = None;
        dev.se.broken = false;
        assert_eq!(open_text(&mut dev, b"new pin").unwrap(), b"contents");
        assert_eq!(open_text(&mut dev, b"new pin").unwrap(), b"contents");
    }

    #[test]
    fn any_changed_byte_is_refused_without_panicking() {
        let mut x = 0x1234_5678u64;
        let n = 13;
        let used = HEADER_LEN + n;
        for i in (0..used + CHECK_LEN).step_by(2) {
            for recheck in [false, true] {
                let mut d = Dev::new(21);
                let mut bb = body(b"tamper target");
                create(&mut d.hw(), b"pin", KDF, 0, &mut bb, n).unwrap();
                let slot = if d.flash.slots[0][0] == b'B' { 0 } else { 1 };
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let s = &mut d.flash.slots[slot];
                s[i] ^= 1 << (x % 8);
                if recheck && i < used {
                    // an attacker can recompute the check: only the tag protects
                    let mut sha = Sha256::new();
                    sha.update(&s[..used]);
                    let c = sha.finalize();
                    s[used..used + CHECK_LEN].copy_from_slice(&c[..CHECK_LEN]);
                }
                let r = open_text(&mut d, b"pin");
                assert!(r.is_err(), "byte {i} (recheck {recheck}) changed, still opened");
            }
        }
    }

    #[test]
    fn random_flash_contents_never_panic() {
        let mut x = 0xfeed_u64;
        for _ in 0..300 {
            let mut dev = Dev::new(3);
            for s in dev.flash.slots.iter_mut() {
                for b in s.iter_mut().take(HEADER_LEN + 64) {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    *b = x as u8;
                }
                s[..4].copy_from_slice(MAGIC);
                s[4] = VERSION;
            }
            let mut b = vec![0u8; SLOT_LEN];
            let _ = scan(&mut dev.flash, &mut b);
            let _ = open_text(&mut dev, b"pin");
        }
    }

    #[test]
    fn phishing_words_are_per_device_and_prefix() {
        let mut a = Dev::new(31);
        let mut b = body(b"x");
        create(&mut a.hw(), b"abcd efgh", KDF, 0, &mut b, 1).unwrap();
        let mut bb = vec![0u8; SLOT_LEN];
        let found = scan(&mut a.flash, &mut bb).unwrap().unwrap();
        let w1 = phishing_words(&mut a.hw(), &found, b"abcd").unwrap();
        let w2 = phishing_words(&mut a.hw(), &found, b"abcd").unwrap();
        let w3 = phishing_words(&mut a.hw(), &found, b"abce").unwrap();
        assert_eq!(w1, w2);
        assert_ne!(w1, w3);
        assert!(w1.iter().all(|&w| w < 2048));
        // the same flash on another device gives other words
        let mut other = Dev::new(32);
        other.flash.slots = a.flash.slots;
        let w4 = phishing_words(&mut other.hw(), &found, b"abcd").unwrap();
        assert_ne!(w1, w4);
    }

    #[test]
    fn trick_pins_open_before_the_secure_element_and_stay_hidden() {
        let mut dev = Dev::new(31);
        let mut b = [0u8; 4096];
        b[..5].copy_from_slice(b"hello");
        let mut u = create(&mut dev.hw(), b"pin", KDF, 0, &mut b, 5).unwrap();
        let before = u.tricks;
        add_trick(
            &mut dev.hw(),
            &mut u,
            b"trick",
            TrickKind::Decoy,
            [1, 2, 3, 4],
            1001,
            Some(&[7u8; 16]),
        )
        .unwrap();
        assert_ne!(u.tricks, before);
        assert_eq!(
            add_trick(&mut dev.hw(), &mut u, b"pin", TrickKind::Blank, [0; 4], 0, None),
            Err(VaultError::PinClash)
        );
        assert_eq!(
            add_trick(&mut dev.hw(), &mut u, b"trick", TrickKind::Blank, [0; 4], 0, None),
            Err(VaultError::PinClash)
        );
        b[..5].copy_from_slice(b"hello");
        save(&mut dev.hw(), &mut u, &mut b, 5).unwrap();
        // the area never shows the decoy or the kind in the clear
        assert!(!u.tricks.windows(16).any(|w| w == [7u8; 16]));
        let left = |dev: &mut Dev| match dev.se.state().unwrap() {
            SeState::Ready { left } => left,
            s => panic!("{s:?}"),
        };
        match open(&mut dev.hw(), b"trick", &mut b).unwrap() {
            Opened::Trick { kind, decoy } => {
                assert_eq!(kind, TrickKind::Decoy);
                assert_eq!(decoy.unwrap().expose(), &[7u8; 16]);
            }
            Opened::Vault(..) => panic!("the trick opened the vault"),
        }
        assert_eq!(left(&mut dev), MAX_ATTEMPTS, "no attempt used");
        assert!(matches!(
            open(&mut dev.hw(), b"wrong", &mut b),
            Err(VaultError::WrongPin { left: 9 })
        ));
        let (u2, n) = open(&mut dev.hw(), b"pin", &mut b).unwrap().vault().unwrap();
        assert_eq!(&b[..n], b"hello");
        assert_eq!(tricks(&u2)[0].map(|t| t.index), Some(1001));
        // a vault made before trick PINs (random area) has none
        let mut old = u2;
        let mut rng = TestRng(5);
        old.tricks.iter_mut().for_each(|x| *x = 0x5a);
        assert!(tricks(&old).iter().all(|t| t.is_none()));
        remove_trick(&mut rng, &mut old, 0);
        assert!(tricks(&old).iter().all(|t| t.is_none()));
    }
}
