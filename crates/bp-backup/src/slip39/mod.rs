//! SLIP-39: Shamir's secret-sharing for mnemonic codes (M11-1).
//!
//! A master secret (16–32 bytes, used directly as the BIP-32 seed) is
//! encrypted with a passphrase (four-round Feistel cipher on
//! PBKDF2-HMAC-SHA256) and split in two levels: `group_threshold` of the
//! groups are needed, and in each group `member_threshold` of its shares.
//! Every share is 20–33 words from the SLIP-39 list of 1024, ending in an
//! RS1024 checksum; its first two words name the set, the third the group.
//!
//! Written from the specification (SLIP-0039); checked against its
//! published vectors and, byte for byte, against the reference
//! implementation (python-shamir-mnemonic) fed the same random bytes.

pub mod gf256;
pub mod rs1024;
pub mod words;

#[cfg(test)]
mod tests;

use core::ops::Range;

use bp_crypto::hmac::HmacSha256;
use bp_crypto::pbkdf2_sha256::pbkdf2_hmac_sha256;
use bp_crypto::secret::wipe;
use gf256::{interpolate, Point, MAX_LEN};
pub use words::WORDS;

/// Shortest master secret (128 bits).
pub const MIN_SECRET: usize = 16;
/// Longest master secret this device takes (256 bits; SLIP-39 allows more).
pub const MAX_SECRET: usize = 32;
/// Words in a share of a 128-bit secret.
pub const MIN_SHARE_WORDS: usize = 20;
/// Words in a share of a 256-bit secret.
pub const MAX_SHARE_WORDS: usize = 33;
/// Most groups, and most shares in a group.
pub const MAX_SHARES: usize = 16;
/// Letters that tell every word of the list apart.
pub const UNIQUE_PREFIX_LEN: usize = 4;
/// Longest passphrase (printable ASCII).
pub const MAX_PASSPHRASE: usize = 128;
/// Iteration exponent of new shares (as Trezor: 20 000 PBKDF2 rounds).
pub const DEFAULT_ITERATION_EXPONENT: u8 = 1;

const METADATA_WORDS: usize = 7;
const DIGEST_LEN: usize = 4;
const SECRET_X: u8 = 255;
const DIGEST_X: u8 = 254;
const BASE_ITERATIONS: u32 = 10_000;
const ROUNDS: u8 = 4;
const CUSTOM: &[u8] = b"shamir";
const CUSTOM_EXTENDABLE: &[u8] = b"shamir_extendable";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a length a share of a 128–256-bit secret can have.
    Length,
    /// A word number of 1024 or more.
    WordIndex,
    /// The RS1024 checksum does not match: a word is wrong.
    Checksum,
    /// The padding bits of the value are not zero.
    Padding,
    /// The share says more groups are needed than there are.
    GroupThreshold,
    /// The share belongs to another set (first words, group threshold,
    /// group count or length differ).
    OtherSet,
    /// The share's member threshold differs from its group's other shares.
    MemberThreshold,
    /// Another share of the group has the same number but other words.
    SameIndex,
    /// The shares do not combine to the secret they were made from.
    Digest,
    /// Not enough shares yet.
    Incomplete,
    /// The passphrase is not printable ASCII or is too long.
    Passphrase,
    /// Groups or thresholds a set cannot have.
    Config,
    /// A master secret must be an even number of bytes, 16 to 32.
    SecretLength,
}

/// Look up a word's value.
pub fn word_index(word: &str) -> Option<u16> {
    WORDS.binary_search(&word).ok().map(|i| i as u16)
}

/// Values whose words start with `prefix` (the list is sorted).
pub fn prefix_range(prefix: &str) -> Range<usize> {
    let start = WORDS.partition_point(|w| *w < prefix);
    let end = start
        + WORDS[start..]
            .iter()
            .take_while(|w| w.starts_with(prefix))
            .count();
    start..end
}

/// Words in a share of a `len`-byte secret.
pub const fn share_words(len: usize) -> usize {
    METADATA_WORDS + (len * 8).div_ceil(10)
}

fn custom(extendable: bool) -> &'static [u8] {
    if extendable {
        CUSTOM_EXTENDABLE
    } else {
        CUSTOM
    }
}

/// One share, as its words say.
#[derive(Clone)]
pub struct Share {
    /// 15-bit identifier of the set (random when the set is made).
    pub identifier: u16,
    /// Extendable backup flag (the passphrase does not depend on the identifier).
    pub extendable: bool,
    /// PBKDF2 runs `10 000 << e` rounds in all.
    pub iteration_exponent: u8,
    pub group_index: u8,
    pub group_threshold: u8,
    pub group_count: u8,
    pub member_index: u8,
    pub member_threshold: u8,
    value: [u8; MAX_SECRET],
    len: u8,
}

impl Drop for Share {
    fn drop(&mut self) {
        wipe(&mut self.value);
    }
}

impl Share {
    /// The share value (as long as the master secret).
    pub fn value(&self) -> &[u8] {
        &self.value[..self.len as usize]
    }

    /// Read a share from its word values.
    pub fn from_indices(w: &[u16]) -> Result<Share, Error> {
        let n = w.len();
        if !(MIN_SHARE_WORDS..=MAX_SHARE_WORDS).contains(&n) {
            return Err(Error::Length);
        }
        let bits = 10 * (n - METADATA_WORDS);
        let pad = bits % 16;
        if pad > 8 {
            return Err(Error::Length);
        }
        if w.iter().any(|&x| x >= 1024) {
            return Err(Error::WordIndex);
        }
        let id_exp = (w[0] as u32) << 10 | w[1] as u32;
        let extendable = (id_exp >> 4) & 1 == 1;
        if !rs1024::verify(custom(extendable), w) {
            return Err(Error::Checksum);
        }
        let params = (w[2] as u32) << 10 | w[3] as u32;
        let nibble = |shift: u32| ((params >> shift) & 15) as u8;
        let group_threshold = nibble(12) + 1;
        let group_count = nibble(8) + 1;
        if group_count < group_threshold {
            return Err(Error::GroupThreshold);
        }
        let len = (bits - pad) / 8;
        let mut share = Share {
            identifier: (id_exp >> 5) as u16,
            extendable,
            iteration_exponent: (id_exp & 15) as u8,
            group_index: nibble(16),
            group_threshold,
            group_count,
            member_index: nibble(4),
            member_threshold: nibble(0) + 1,
            value: [0; MAX_SECRET],
            len: len as u8,
        };
        unpack(&w[4..n - rs1024::CHECKSUM_WORDS], pad, &mut share.value[..len])?;
        Ok(share)
    }

    /// The share's word values; returns how many.
    pub fn to_indices(&self, out: &mut [u16; MAX_SHARE_WORDS]) -> usize {
        let len = self.len as usize;
        let n = share_words(len);
        let id_exp =
            (self.identifier as u32) << 5 | (self.extendable as u32) << 4 | self.iteration_exponent as u32;
        out[0] = (id_exp >> 10) as u16;
        out[1] = (id_exp & 1023) as u16;
        let params = (self.group_index as u32) << 16
            | (self.group_threshold as u32 - 1) << 12
            | (self.group_count as u32 - 1) << 8
            | (self.member_index as u32) << 4
            | (self.member_threshold as u32 - 1);
        out[2] = (params >> 10) as u16;
        out[3] = (params & 1023) as u16;
        pack(self.value(), &mut out[4..n - rs1024::CHECKSUM_WORDS]);
        let c = rs1024::create(custom(self.extendable), &out[..n - rs1024::CHECKSUM_WORDS]);
        out[n - rs1024::CHECKSUM_WORDS..n].copy_from_slice(&c);
        n
    }
}

/// 10-bit words to bytes, the first `pad` bits being zero padding.
fn unpack(words: &[u16], pad: usize, out: &mut [u8]) -> Result<(), Error> {
    let mut acc = 0u32;
    let mut nbits = 0usize;
    let mut o = 0usize;
    for (i, &w) in words.iter().enumerate() {
        acc = (acc << 10) | w as u32;
        nbits += 10;
        if i == 0 {
            if acc >> (10 - pad) != 0 {
                return Err(Error::Padding);
            }
            nbits -= pad;
            acc &= (1 << nbits) - 1;
        }
        while nbits >= 8 {
            out[o] = (acc >> (nbits - 8)) as u8;
            o += 1;
            nbits -= 8;
            acc &= (1 << nbits) - 1;
        }
    }
    debug_assert!(nbits == 0 && o == out.len());
    Ok(())
}

/// Bytes to 10-bit words, zero padding first.
fn pack(value: &[u8], out: &mut [u16]) {
    let mut nbits = out.len() * 10 - value.len() * 8;
    let mut acc = 0u32;
    let mut o = 0usize;
    for &b in value {
        acc = (acc << 8) | b as u32;
        nbits += 8;
        while nbits >= 10 {
            out[o] = ((acc >> (nbits - 10)) & 1023) as u16;
            o += 1;
            nbits -= 10;
            acc &= (1 << nbits) - 1;
        }
    }
    debug_assert!(nbits == 0 && o == out.len());
}

/// A master secret: the BIP-32 seed of a SLIP-39 wallet. Wiped on drop.
pub struct MasterSecret {
    bytes: [u8; MAX_SECRET],
    len: u8,
}

impl Drop for MasterSecret {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl MasterSecret {
    /// An even number of bytes, 16 to 32.
    pub fn new(bytes: &[u8]) -> Result<MasterSecret, Error> {
        if !(MIN_SECRET..=MAX_SECRET).contains(&bytes.len()) || !bytes.len().is_multiple_of(2) {
            return Err(Error::SecretLength);
        }
        let mut m = MasterSecret {
            bytes: [0; MAX_SECRET],
            len: bytes.len() as u8,
        };
        m.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(m)
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// The encrypted master secret: what the shares split.
#[derive(Clone)]
pub struct Ems {
    pub identifier: u16,
    pub extendable: bool,
    pub iteration_exponent: u8,
    value: [u8; MAX_SECRET],
    len: u8,
}

impl Drop for Ems {
    fn drop(&mut self) {
        wipe(&mut self.value);
    }
}

fn check_passphrase(p: &[u8]) -> Result<(), Error> {
    if p.len() > MAX_PASSPHRASE || p.iter().any(|&c| !(32..=126).contains(&c)) {
        return Err(Error::Passphrase);
    }
    Ok(())
}

impl Ems {
    /// Encrypt `master` with `passphrase` (four Feistel rounds).
    pub fn encrypt(
        master: &MasterSecret,
        passphrase: &[u8],
        identifier: u16,
        extendable: bool,
        iteration_exponent: u8,
    ) -> Result<Ems, Error> {
        check_passphrase(passphrase)?;
        if identifier >= 1 << 15 || iteration_exponent > 15 {
            return Err(Error::Config);
        }
        let mut e = Ems {
            identifier,
            extendable,
            iteration_exponent,
            value: [0; MAX_SECRET],
            len: master.len,
        };
        e.value[..master.len as usize].copy_from_slice(master.expose());
        e.feistel(passphrase, false);
        Ok(e)
    }

    /// Decrypt with `passphrase`. Any passphrase gives a wallet: a wrong
    /// one gives another wallet, not an error (as in BIP-39).
    pub fn decrypt(&self, passphrase: &[u8]) -> Result<MasterSecret, Error> {
        check_passphrase(passphrase)?;
        let mut d = Ems {
            identifier: self.identifier,
            extendable: self.extendable,
            iteration_exponent: self.iteration_exponent,
            value: self.value,
            len: self.len,
        };
        d.feistel(passphrase, true);
        MasterSecret::new(&d.value[..d.len as usize])
    }

    /// An encrypted master secret kept by the device (vault record).
    pub fn from_parts(
        identifier: u16,
        extendable: bool,
        iteration_exponent: u8,
        value: &[u8],
    ) -> Result<Ems, Error> {
        if identifier >= 1 << 15 || iteration_exponent > 15 {
            return Err(Error::Config);
        }
        if !(MIN_SECRET..=MAX_SECRET).contains(&value.len()) || !value.len().is_multiple_of(2) {
            return Err(Error::SecretLength);
        }
        let mut e = Ems {
            identifier,
            extendable,
            iteration_exponent,
            value: [0; MAX_SECRET],
            len: value.len() as u8,
        };
        e.value[..value.len()].copy_from_slice(value);
        Ok(e)
    }

    /// The encrypted value (secret: with the passphrase it is the wallet).
    pub fn value(&self) -> &[u8] {
        &self.value[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// PBKDF2 rounds a decryption runs (for "this takes a while" screens).
    pub fn rounds(&self) -> u32 {
        BASE_ITERATIONS << self.iteration_exponent
    }

    fn feistel(&mut self, passphrase: &[u8], reverse: bool) {
        let len = self.len as usize;
        let half = len / 2;
        let mut salt = [0u8; 8];
        let salt_len = if self.extendable {
            0
        } else {
            salt[..6].copy_from_slice(CUSTOM);
            salt[6..8].copy_from_slice(&self.identifier.to_be_bytes());
            8
        };
        let iterations = (BASE_ITERATIONS << self.iteration_exponent) / ROUNDS as u32;
        let mut password = [0u8; 1 + MAX_PASSPHRASE];
        password[1..1 + passphrase.len()].copy_from_slice(passphrase);
        let mut l = [0u8; MAX_SECRET / 2];
        let mut r = [0u8; MAX_SECRET / 2];
        l[..half].copy_from_slice(&self.value[..half]);
        r[..half].copy_from_slice(&self.value[half..len]);
        for k in 0..ROUNDS {
            let i = if reverse { ROUNDS - 1 - k } else { k };
            password[0] = i;
            let mut f = [0u8; MAX_SECRET / 2];
            pbkdf2_hmac_sha256(
                &password[..1 + passphrase.len()],
                &[&salt[..salt_len], &r[..half]],
                iterations,
                &mut f[..half],
            );
            for j in 0..half {
                f[j] ^= l[j];
            }
            l = r;
            r = f;
            wipe(&mut f);
        }
        self.value[..half].copy_from_slice(&r[..half]);
        self.value[half..len].copy_from_slice(&l[..half]);
        wipe(&mut l);
        wipe(&mut r);
        wipe(&mut password);
    }
}

/// Where the random values of a new set come from. The device feeds a
/// stream derived from the secret (and optional dice); tests feed the
/// reference implementation's bytes.
pub trait Randomness {
    fn fill(&mut self, out: &mut [u8]);
}

/// The identifier of a new set (decision 5: no device randomness): derived
/// from the master secret, the passphrase and optional dice.
pub fn derive_identifier(master: &MasterSecret, passphrase: &[u8], dice: &[u8]) -> u16 {
    let mut mac = HmacSha256::new(b"bitpunk slip39 identifier v1");
    mac.update(&[master.len]);
    mac.update(master.expose());
    mac.update(&(passphrase.len() as u16).to_be_bytes());
    mac.update(passphrase);
    mac.update(&bp_crypto::sha256::Sha256::digest(dice));
    let d = mac.finalize();
    u16::from_be_bytes([d[0], d[1]]) & 0x7FFF
}

/// The random values of a set's shares (decision 5): a stream derived from
/// the encrypted master secret, the groups and optional dice. The same
/// choices give the same shares again (a written set can be checked by
/// making it again); other groups give an unrelated set. Block `i` is
/// HMAC-SHA256(key, i), the key binding all of the above.
pub struct DerivedStream {
    key: [u8; 32],
    counter: u32,
    block: [u8; 32],
    used: usize,
}

impl Drop for DerivedStream {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.block);
    }
}

impl DerivedStream {
    pub fn new(ems: &Ems, group_threshold: u8, groups: &[Group], dice: &[u8]) -> Self {
        let mut mac = HmacSha256::new(b"bitpunk slip39 shares v1");
        mac.update(&ems.identifier.to_be_bytes());
        mac.update(&[ems.extendable as u8, ems.iteration_exponent, ems.len]);
        mac.update(&ems.value[..ems.len as usize]);
        mac.update(&[group_threshold, groups.len() as u8]);
        for g in groups {
            mac.update(&[g.threshold, g.count]);
        }
        mac.update(&bp_crypto::sha256::Sha256::digest(dice));
        DerivedStream {
            key: mac.finalize(),
            counter: 0,
            block: [0; 32],
            used: 32,
        }
    }
}

impl Randomness for DerivedStream {
    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            if self.used == 32 {
                self.block = HmacSha256::mac(&self.key, &self.counter.to_be_bytes());
                self.counter += 1;
                self.used = 0;
            }
            *b = self.block[self.used];
            self.used += 1;
        }
    }
}

/// A new set for `master`: identifier, encryption (extendable, exponent 1)
/// and shares, all derived (no device randomness). `visit` sees every
/// share, group by group. Returns the encrypted master secret, which the
/// device keeps to make further sets of the same wallet (`reshare`).
pub fn make_set(
    master: &MasterSecret,
    passphrase: &[u8],
    group_threshold: u8,
    groups: &[Group],
    dice: &[u8],
    visit: impl FnMut(&Share),
) -> Result<Ems, Error> {
    check_config(group_threshold, groups)?;
    let id = derive_identifier(master, passphrase, dice);
    let ems = Ems::encrypt(master, passphrase, id, true, DEFAULT_ITERATION_EXPONENT)?;
    reshare(&ems, group_threshold, groups, dice, visit)?;
    Ok(ems)
}

/// Another set of the same wallet (same identifier and encryption, so an
/// extendable set; shares of different sets do not combine).
pub fn reshare(
    ems: &Ems,
    group_threshold: u8,
    groups: &[Group],
    dice: &[u8],
    visit: impl FnMut(&Share),
) -> Result<(), Error> {
    check_config(group_threshold, groups)?;
    let mut rng = DerivedStream::new(ems, group_threshold, groups, dice);
    split(ems, group_threshold, groups, &mut rng, visit)
}

/// A 15-bit identifier drawn from `rng` (as the reference does).
pub fn random_identifier(rng: &mut impl Randomness) -> u16 {
    let mut b = [0u8; 2];
    rng.fill(&mut b);
    u16::from_be_bytes(b) & 0x7FFF
}

/// One group of a new set: `threshold` of its `count` shares are needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group {
    pub threshold: u8,
    pub count: u8,
}

/// Whether a set can be made with these groups.
pub fn check_config(group_threshold: u8, groups: &[Group]) -> Result<(), Error> {
    let ok = !groups.is_empty()
        && groups.len() <= MAX_SHARES
        && group_threshold >= 1
        && group_threshold as usize <= groups.len()
        && groups.iter().all(|g| {
            g.threshold >= 1
                && g.threshold <= g.count
                && g.count as usize <= MAX_SHARES
                && !(g.threshold == 1 && g.count > 1)
        });
    if ok {
        Ok(())
    } else {
        Err(Error::Config)
    }
}

fn digest(random: &[u8], secret: &[u8]) -> [u8; DIGEST_LEN] {
    let d = HmacSha256::mac(random, secret);
    [d[0], d[1], d[2], d[3]]
}

fn blank() -> [Point; MAX_SHARES] {
    core::array::from_fn(|_| Point::new(0, &[]))
}

/// Shamir split of `secret` into `count` points, `threshold` needed.
fn split_secret(
    threshold: u8,
    count: u8,
    secret: &[u8],
    rng: &mut impl Randomness,
    out: &mut [Point; MAX_SHARES],
) {
    let len = secret.len();
    if threshold == 1 {
        for i in 0..count {
            out[i as usize] = Point::new(i, secret);
        }
        return;
    }
    let random = (threshold - 2) as usize;
    let mut base = blank();
    let mut y = [0u8; MAX_LEN];
    for (i, b) in base.iter_mut().enumerate().take(random) {
        rng.fill(&mut y[..len]);
        *b = Point::new(i as u8, &y[..len]);
        out[i] = b.clone();
    }
    let mut r = [0u8; MAX_LEN];
    rng.fill(&mut r[..len - DIGEST_LEN]);
    y[..DIGEST_LEN].copy_from_slice(&digest(&r[..len - DIGEST_LEN], secret));
    y[DIGEST_LEN..len].copy_from_slice(&r[..len - DIGEST_LEN]);
    base[random] = Point::new(DIGEST_X, &y[..len]);
    base[random + 1] = Point::new(SECRET_X, secret);
    for (i, o) in out.iter_mut().enumerate().take(count as usize).skip(random) {
        interpolate(&base[..threshold as usize], len, i as u8, &mut y);
        *o = Point::new(i as u8, &y[..len]);
    }
    wipe(&mut y);
    wipe(&mut r);
}

/// Split `ems` into shares, handing each to `visit` (group by group). The
/// random values come from `rng` in the reference implementation's order.
pub fn split(
    ems: &Ems,
    group_threshold: u8,
    groups: &[Group],
    rng: &mut impl Randomness,
    mut visit: impl FnMut(&Share),
) -> Result<(), Error> {
    check_config(group_threshold, groups)?;
    let len = ems.len();
    let mut group_secrets = blank();
    split_secret(
        group_threshold,
        groups.len() as u8,
        &ems.value[..len],
        rng,
        &mut group_secrets,
    );
    let mut members = blank();
    for (g, spec) in groups.iter().enumerate() {
        split_secret(
            spec.threshold,
            spec.count,
            &group_secrets[g].y[..len],
            rng,
            &mut members,
        );
        for m in members.iter().take(spec.count as usize) {
            let mut share = Share {
                identifier: ems.identifier,
                extendable: ems.extendable,
                iteration_exponent: ems.iteration_exponent,
                group_index: g as u8,
                group_threshold,
                group_count: groups.len() as u8,
                member_index: m.x,
                member_threshold: spec.threshold,
                value: [0; MAX_SECRET],
                len: len as u8,
            };
            share.value[..len].copy_from_slice(&m.y[..len]);
            visit(&share);
        }
    }
    Ok(())
}

/// The secret behind `threshold` points, checking the digest when there is
/// one (threshold 2 or more).
fn recover_secret(threshold: u8, points: &[Point], len: usize) -> Result<[u8; MAX_LEN], Error> {
    let mut secret = [0u8; MAX_LEN];
    if threshold == 1 {
        secret[..len].copy_from_slice(&points[0].y[..len]);
        return Ok(secret);
    }
    interpolate(points, len, SECRET_X, &mut secret);
    let mut d = [0u8; MAX_LEN];
    interpolate(points, len, DIGEST_X, &mut d);
    let want = digest(&d[DIGEST_LEN..len], &secret[..len]);
    let same = want
        .iter()
        .zip(&d[..DIGEST_LEN])
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0;
    wipe(&mut d);
    if !same {
        wipe(&mut secret);
        return Err(Error::Digest);
    }
    Ok(secret)
}

/// What adding a share did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    /// Kept; one share closer.
    Accepted,
    /// This share was entered before.
    Again,
    /// A good share of a group that is already complete, or of a group not
    /// needed any more.
    NotNeeded,
}

/// How far a group is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupProgress {
    /// Shares entered.
    pub have: u8,
    /// Shares needed (0 while none of this group was entered).
    pub need: u8,
    pub done: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Common {
    identifier: u16,
    extendable: bool,
    iteration_exponent: u8,
    group_threshold: u8,
    group_count: u8,
    len: u8,
}

struct GroupState {
    member_threshold: u8,
    have: u8,
    members: [Point; MAX_SHARES],
    secret: Option<Point>,
}

/// Collects shares as they are typed, checking each against the others.
pub struct Recovery {
    common: Option<Common>,
    groups: [GroupState; MAX_SHARES],
}

impl Default for Recovery {
    fn default() -> Self {
        Self::new()
    }
}

impl Recovery {
    pub fn new() -> Recovery {
        Recovery {
            common: None,
            groups: core::array::from_fn(|_| GroupState {
                member_threshold: 0,
                have: 0,
                members: blank(),
                secret: None,
            }),
        }
    }

    /// Groups needed (`None` before the first share).
    pub fn group_threshold(&self) -> Option<u8> {
        self.common.map(|c| c.group_threshold)
    }

    /// Groups in the set (`None` before the first share).
    pub fn group_count(&self) -> Option<u8> {
        self.common.map(|c| c.group_count)
    }

    /// Bytes of the secret (`None` before the first share).
    pub fn secret_len(&self) -> Option<usize> {
        self.common.map(|c| c.len as usize)
    }

    /// The set's iteration exponent (`None` before the first share).
    pub fn iteration_exponent(&self) -> Option<u8> {
        self.common.map(|c| c.iteration_exponent)
    }

    pub fn group(&self, g: usize) -> GroupProgress {
        let s = &self.groups[g];
        GroupProgress {
            have: s.have,
            need: s.member_threshold,
            done: s.secret.is_some(),
        }
    }

    pub fn groups_done(&self) -> u8 {
        self.groups.iter().filter(|g| g.secret.is_some()).count() as u8
    }

    pub fn is_complete(&self) -> bool {
        self.common
            .is_some_and(|c| self.groups_done() >= c.group_threshold)
    }

    /// Shares entered in all.
    pub fn shares(&self) -> usize {
        self.groups.iter().map(|g| g.have as usize).sum()
    }

    /// Add a share. A share of another set, or one that contradicts the
    /// shares of its group, is refused and changes nothing — except that a
    /// group whose shares fail their digest is emptied (one of them is
    /// wrong; they are typed again).
    pub fn add(&mut self, share: &Share) -> Result<Added, Error> {
        let c = Common {
            identifier: share.identifier,
            extendable: share.extendable,
            iteration_exponent: share.iteration_exponent,
            group_threshold: share.group_threshold,
            group_count: share.group_count,
            len: share.len,
        };
        if self.common.is_some_and(|have| have != c) {
            return Err(Error::OtherSet);
        }
        let len = share.len as usize;
        let g = share.group_index as usize;
        let complete = self.is_complete();
        {
            let st = &self.groups[g];
            if st.member_threshold != 0 && st.member_threshold != share.member_threshold {
                return Err(Error::MemberThreshold);
            }
            let held = &st.members[..st.have as usize];
            if let Some(p) = held.iter().find(|p| p.x == share.member_index) {
                return if p.y[..len] == *share.value() {
                    Ok(Added::Again)
                } else {
                    Err(Error::SameIndex)
                };
            }
            if st.secret.is_some() {
                // Complete: a further share must lie on the same polynomial.
                let mut y = [0u8; MAX_LEN];
                interpolate(held, len, share.member_index, &mut y);
                let same = y[..len] == *share.value();
                wipe(&mut y);
                return if same {
                    Ok(Added::NotNeeded)
                } else {
                    Err(Error::Digest)
                };
            }
        }
        self.common = Some(c);
        if complete {
            return Ok(Added::NotNeeded);
        }
        let st = &mut self.groups[g];
        st.member_threshold = share.member_threshold;
        st.members[st.have as usize] = Point::new(share.member_index, share.value());
        st.have += 1;
        if st.have < st.member_threshold {
            return Ok(Added::Accepted);
        }
        match recover_secret(st.member_threshold, &st.members[..st.have as usize], len) {
            Ok(mut s) => {
                st.secret = Some(Point::new(share.group_index, &s[..len]));
                wipe(&mut s);
                Ok(Added::Accepted)
            }
            Err(e) => {
                st.have = 0;
                st.member_threshold = 0;
                st.members = blank();
                if self.shares() == 0 {
                    self.common = None;
                }
                Err(e)
            }
        }
    }

    /// The encrypted master secret, once enough groups are complete.
    pub fn ems(&self) -> Result<Ems, Error> {
        let c = self.common.ok_or(Error::Incomplete)?;
        if !self.is_complete() {
            return Err(Error::Incomplete);
        }
        let len = c.len as usize;
        let mut points = blank();
        for (slot, s) in points
            .iter_mut()
            .zip(self.groups.iter().filter_map(|g| g.secret.as_ref()))
            .take(c.group_threshold as usize)
        {
            *slot = s.clone();
        }
        let mut secret = recover_secret(c.group_threshold, &points[..c.group_threshold as usize], len)?;
        let mut e = Ems {
            identifier: c.identifier,
            extendable: c.extendable,
            iteration_exponent: c.iteration_exponent,
            value: [0; MAX_SECRET],
            len: c.len,
        };
        e.value[..len].copy_from_slice(&secret[..len]);
        wipe(&mut secret);
        Ok(e)
    }
}
