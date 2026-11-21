//! Output descriptors (BIP-380/381/382/383/389), the multisig subset:
//! `wsh(sortedmulti(k,KEY,…))` and `sh(wsh(sortedmulti(k,KEY,…)))`, where
//! every KEY is `[fingerprint/origin]xpub` followed by `/<0;1>/*`, `/0/*`,
//! `/1/*` or the BIP-388 shorthand `/**`.
//!
//! Strict on purpose: no whitespace inside, no private keys, no hardened
//! steps after the xpub, one suffix shared by all keys, and a checksum that
//! must match when present.

use super::{decode_xpub, Cosigner, MsScript, Wallet, MAX_KEYS};
use crate::bip32::{DerivationPath, KeyVersion, Xpriv, HARDENED, MAX_DEPTH, XKEY_LEN};
use core::fmt::{self, Write};

const INPUT_CHARSET: &[u8] =
    b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u64; 5] = [
    0xf5dee51989,
    0xa9fdca3312,
    0x1bab10e32d,
    0x3706b1677a,
    0x644d626ffd,
];

/// Longest descriptor written: 15 keys with 10-step origins, `sh(wsh(…))`.
pub const MAX_DESCRIPTOR: usize = 4096;

fn polymod_step(c: u64, val: u64) -> u64 {
    let top = c >> 35;
    let mut c = ((c & 0x7_ffff_ffff) << 5) ^ val;
    for (i, g) in GENERATOR.iter().enumerate() {
        if (top >> i) & 1 == 1 {
            c ^= g;
        }
    }
    c
}

/// The 8-character BIP-380 checksum of a descriptor body; `None` if it holds
/// a character outside the descriptor alphabet.
pub fn checksum(body: &str) -> Option<[u8; 8]> {
    let mut c = 1u64;
    let mut cls = 0u64;
    let mut clscount = 0;
    for b in body.bytes() {
        let pos = INPUT_CHARSET.iter().position(|&x| x == b)? as u64;
        c = polymod_step(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if clscount == 3 {
            c = polymod_step(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        c = polymod_step(c, cls);
    }
    for _ in 0..8 {
        c = polymod_step(c, 0);
    }
    c ^= 1;
    let mut out = [0u8; 8];
    for (j, o) in out.iter_mut().enumerate() {
        *o = CHECKSUM_CHARSET[((c >> (5 * (7 - j))) & 31) as usize];
    }
    Some(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not the grammar above (also: whitespace inside, empty parts).
    Syntax,
    /// A checksum that does not match, or is not 8 characters.
    Checksum,
    /// `multi(...)`: only BIP-67 `sortedmulti` is accepted.
    Unsorted,
    /// Another script: single key, legacy `sh(multi)`, Taproot, miniscript.
    UnsupportedScript,
    /// k outside 1..=n.
    Threshold,
    /// More than 15 keys.
    TooManyKeys,
    /// A key without `[fingerprint/path]`.
    MissingOrigin,
    /// Not an extended public key (bad encoding, plain hex key).
    Key,
    /// An extended private key: refused outright.
    PrivateKey,
    /// A hardened step after the xpub (`/*'`, `/1h/*`).
    Hardened,
    /// Not ranged, or a suffix other than `/<0;1>/*`, `/0/*`, `/1/*`, `/**`.
    Suffix,
    /// Keys with different suffixes.
    MixedSuffix,
    /// Mainnet and test-network keys together.
    MixedNetwork,
    /// An origin deeper than the device supports.
    PathTooDeep,
}

/// Which addresses a descriptor covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Range {
    /// `<0;1>/*` or `/**`: receive and change.
    Both,
    /// `/0/*`: receive (change is taken to be `/1/*`).
    Receive,
    /// `/1/*`: change only.
    Change,
}

#[derive(Clone, Copy, Debug)]
pub struct Parsed {
    pub wallet: Wallet,
    pub range: Range,
    pub had_checksum: bool,
}

struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn eat(&mut self, lit: &[u8]) -> bool {
        if self.s[self.i..].starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, lit: &[u8]) -> Result<(), Error> {
        self.eat(lit).then_some(()).ok_or(Error::Syntax)
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn rest(&self) -> &'a [u8] {
        &self.s[self.i..]
    }

    /// Decimal without sign or leading zeros, below `limit`.
    fn number(&mut self, limit: u64) -> Result<u32, Error> {
        let start = self.i;
        let mut v: u64 = 0;
        while let Some(c @ b'0'..=b'9') = self.peek() {
            v = v * 10 + (c - b'0') as u64;
            if v >= limit {
                return Err(Error::Syntax);
            }
            self.i += 1;
        }
        let len = self.i - start;
        if len == 0 || (len > 1 && self.s[start] == b'0') {
            return Err(Error::Syntax);
        }
        Ok(v as u32)
    }
}

/// Parse one descriptor (surrounding whitespace allowed).
pub fn parse(text: &str) -> Result<Parsed, Error> {
    let text = text.trim();
    let (body, had_checksum) = match text.find('#') {
        Some(p) => {
            let (b, c) = (&text[..p], &text[p + 1..]);
            let want = checksum(b).ok_or(Error::Syntax)?;
            if c.as_bytes() != want {
                return Err(Error::Checksum);
            }
            (b, true)
        }
        None => {
            checksum(text).ok_or(Error::Syntax)?;
            (text, false)
        }
    };
    if body.bytes().any(|b| b == b' ') {
        return Err(Error::Syntax);
    }
    let mut c = Cursor {
        s: body.as_bytes(),
        i: 0,
    };
    let script = if c.eat(b"wsh(") {
        MsScript::Wsh
    } else if c.eat(b"sh(wsh(") {
        MsScript::ShWsh
    } else {
        return Err(Error::UnsupportedScript);
    };
    if c.eat(b"multi(") {
        return Err(Error::Unsorted);
    }
    if !c.eat(b"sortedmulti(") {
        return Err(Error::UnsupportedScript);
    }
    let k = c.number(100)?;
    let mut keys = [None; MAX_KEYS];
    let mut n = 0;
    let mut range = None;
    let mut test = None;
    while c.eat(b",") {
        if n == MAX_KEYS {
            return Err(Error::TooManyKeys);
        }
        let (key, r, t) = parse_key(&mut c)?;
        match range {
            None => range = Some(r),
            Some(prev) if prev != r => return Err(Error::MixedSuffix),
            _ => {}
        }
        match test {
            None => test = Some(t),
            Some(prev) if prev != t => return Err(Error::MixedNetwork),
            _ => {}
        }
        keys[n] = Some(key);
        n += 1;
    }
    c.expect(b")")?;
    c.expect(b")")?;
    if script == MsScript::ShWsh {
        c.expect(b")")?;
    }
    if !c.rest().is_empty() {
        return Err(Error::Syntax);
    }
    if n == 0 {
        return Err(Error::Syntax);
    }
    if k == 0 || k as usize > n {
        return Err(Error::Threshold);
    }
    let mut list = [keys[0].expect("n ≥ 1"); MAX_KEYS];
    for (slot, key) in list.iter_mut().zip(&keys[..n]) {
        *slot = key.expect("filled");
    }
    let wallet = Wallet::new(test.expect("n ≥ 1"), script, k as u8, &list[..n]).ok_or(Error::Threshold)?;
    Ok(Parsed {
        wallet,
        range: range.expect("n ≥ 1"),
        had_checksum,
    })
}

/// `[fingerprint/origin]xpub/suffix`
fn parse_key(c: &mut Cursor) -> Result<(Cosigner, Range, bool), Error> {
    if !c.eat(b"[") {
        // a key without origin: say so if it parses as a key at all
        return Err(match c.peek() {
            Some(b'x' | b't' | b'Z' | b'Y' | b'V' | b'U' | b'z' | b'y' | b'v' | b'u') => Error::MissingOrigin,
            _ => Error::Syntax,
        });
    }
    let fp_hex = c.rest().get(..8).ok_or(Error::Syntax)?;
    let mut fingerprint = [0u8; 4];
    for (i, f) in fingerprint.iter_mut().enumerate() {
        *f = (hex(fp_hex[2 * i])? << 4) | hex(fp_hex[2 * i + 1])?;
    }
    c.i += 8;
    let mut steps = [0u32; MAX_DEPTH];
    let mut depth = 0;
    while c.eat(b"/") {
        if depth == MAX_DEPTH {
            return Err(Error::PathTooDeep);
        }
        let v = c.number(HARDENED as u64)?;
        let hard = c.eat(b"'") || c.eat(b"h");
        steps[depth] = if hard { v | HARDENED } else { v };
        depth += 1;
    }
    c.expect(b"]")?;
    let origin = DerivationPath::from_steps(&steps[..depth]).map_err(|_| Error::PathTooDeep)?;
    // the extended key: base58 up to the suffix or the next key
    let start = c.i;
    while let Some(b) = c.peek() {
        if b == b'/' || b == b',' || b == b')' {
            break;
        }
        c.i += 1;
    }
    let ktext = core::str::from_utf8(&c.s[start..c.i]).map_err(|_| Error::Syntax)?;
    if ktext.len() > XKEY_LEN {
        return Err(Error::Key);
    }
    let (xpub, test, version) = match decode_xpub(ktext) {
        Ok(v) => v,
        Err(_) => {
            if Xpriv::decode(ktext).is_ok() {
                return Err(Error::PrivateKey);
            }
            return Err(Error::Key);
        }
    };
    let range = parse_suffix(c)?;
    Ok((
        Cosigner {
            fingerprint,
            origin,
            xpub,
            version,
        },
        range,
        test,
    ))
}

fn parse_suffix(c: &mut Cursor) -> Result<Range, Error> {
    let r = if c.eat(b"/<0;1>/*") || c.eat(b"/**") {
        Range::Both
    } else if c.eat(b"/0/*") {
        Range::Receive
    } else if c.eat(b"/1/*") {
        Range::Change
    } else {
        // tell hardening apart from other unsupported paths
        let tail = c.rest();
        let end = tail
            .iter()
            .position(|&b| b == b',' || b == b')')
            .unwrap_or(tail.len());
        let seg = &tail[..end];
        return Err(if seg.iter().any(|&b| b == b'\'' || b == b'h') {
            Error::Hardened
        } else {
            Error::Suffix
        });
    };
    if matches!(c.peek(), Some(b'\'' | b'h')) {
        return Err(Error::Hardened);
    }
    Ok(r)
}

fn hex(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::Syntax),
    }
}

/// How to write the key suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// `/<0;1>/*` (BIP-389).
    Multipath,
    /// `/0/*` or `/1/*` (one descriptor per branch, for older software).
    Branch(u32),
}

/// A byte buffer as `fmt::Write`.
pub struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Out<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Out { buf, len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl Write for Out<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        self.buf
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Write `[fingerprint/origin]` with `h` for hardened steps.
pub fn write_origin(o: &mut dyn Write, fp: &[u8; 4], origin: &DerivationPath) -> fmt::Result {
    o.write_char('[')?;
    for b in fp {
        write!(o, "{:02x}", b)?;
    }
    for &s in origin.steps() {
        if s & HARDENED != 0 {
            write!(o, "/{}h", s & !HARDENED)?;
        } else {
            write!(o, "/{}", s)?;
        }
    }
    o.write_char(']')
}

/// The descriptor with checksum (keys in the wallet's order, plain
/// xpub/tpub versions, `h` for hardened); its length in `out`.
pub fn write(w: &Wallet, form: Form, out: &mut [u8]) -> Option<usize> {
    let mut o = Out::new(out);
    write_body(w, form, &mut o).ok()?;
    let cs = checksum(o.as_str())?;
    o.write_char('#').ok()?;
    o.write_str(core::str::from_utf8(&cs).ok()?).ok()?;
    Some(o.len())
}

fn write_body(w: &Wallet, form: Form, o: &mut Out) -> fmt::Result {
    o.write_str(match w.script {
        MsScript::Wsh => "wsh(sortedmulti(",
        MsScript::ShWsh => "sh(wsh(sortedmulti(",
    })?;
    write!(o, "{}", w.m)?;
    let net = if w.test {
        crate::Network::Testnet
    } else {
        crate::Network::Mainnet
    };
    for k in w.keys() {
        o.write_char(',')?;
        write_origin(o, &k.fingerprint, &k.origin)?;
        let mut x = [0u8; XKEY_LEN];
        let n = k.xpub.encode(KeyVersion::X.public(net), &mut x);
        o.write_str(core::str::from_utf8(&x[..n]).map_err(|_| fmt::Error)?)?;
        match form {
            Form::Multipath => o.write_str("/<0;1>/*")?,
            Form::Branch(b) => write!(o, "/{}/*", b)?,
        }
    }
    o.write_str(match w.script {
        MsScript::Wsh => "))",
        MsScript::ShWsh => ")))",
    })
}
