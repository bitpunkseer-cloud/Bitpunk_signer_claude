//! Wallet and cosigner formats other tools export.
//!
//! Wallets: descriptor text (one line, or the receive/change pair Sparrow
//! and Bitcoin Core write), JSON with a `"descriptor"` (Specter, Sparrow,
//! Krux), the Coldcard multisig setup file (Coldcard, Sparrow, Nunchuk,
//! Keystone, SeedSigner), and UR `crypto-output` with a sorted multisig.
//!
//! Cosigners: `[fingerprint/path]xpub` text (SeedSigner, Krux, Specter DIY),
//! the Coldcard xpub JSON, UR `crypto-account` and `crypto-hdkey`.
//!
//! Every path ends in the same `Wallet` record and the same registration
//! rules; formats only differ in how they are read.

use super::descriptor::{self, Range, MAX_DESCRIPTOR};
use super::{decode_xpub, Cosigner, MsScript, Wallet, MAX_KEYS};
use crate::bip32::{DerivationPath, KeyVersion, Xpriv, Xpub, HARDENED, MAX_DEPTH};
use bp_crypto::secp256k1::PublicKey;
use bp_qr::ur::cbor::Reader;

/// Most descriptor lines in one text (Sparrow writes three).
const MAX_LINES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Descriptor,
    Json,
    Coldcard,
    UrOutput,
}

#[derive(Clone, Copy, Debug)]
pub struct Imported {
    pub wallet: Wallet,
    pub format: Format,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a wallet in any known format.
    Unknown,
    Descriptor(descriptor::Error),
    /// Only the change descriptor (`/1/*`).
    ChangeOnly,
    /// Several descriptors that are not the same wallet.
    LinesDiffer,
    /// Coldcard file: no valid `Policy: M of N`.
    Policy,
    /// Coldcard file: a key before any `Derivation:` line.
    Derivation,
    /// Coldcard file: `Format:` missing, legacy `P2SH`, or unknown.
    ScriptFormat,
    /// Number of keys differs from the policy.
    KeyCount,
    /// A key that does not decode.
    Key,
    PrivateKey,
    MissingOrigin,
    MixedNetwork,
    /// Malformed UR payload.
    Cbor,
}

impl From<descriptor::Error> for Error {
    fn from(e: descriptor::Error) -> Self {
        Error::Descriptor(e)
    }
}

fn trim(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let e = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(s, |p| p + 1);
    &b[s..e]
}

/// Parse a wallet from text (UTF-8 bytes as scanned).
pub fn parse_wallet(text: &[u8]) -> Result<Imported, Error> {
    let t = trim(text);
    if t.first() == Some(&b'{') {
        return parse_json(t);
    }
    if contains_ci(t, b"policy:") {
        return parse_coldcard(t);
    }
    if t.starts_with(b"wsh(") || t.starts_with(b"sh(") || t.starts_with(b"#") || contains(t, b"multi(") {
        let wallet = parse_descriptor_lines(t)?;
        return Ok(Imported {
            wallet,
            format: Format::Descriptor,
        });
    }
    Err(Error::Unknown)
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

fn contains_ci(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// One or more descriptor lines (comments with `#` at the start ignored).
/// All must describe the same wallet, and together cover receiving.
fn parse_descriptor_lines(t: &[u8]) -> Result<Wallet, Error> {
    let text = core::str::from_utf8(t).map_err(|_| Error::Unknown)?;
    let mut first: Option<Wallet> = None;
    let mut receive = false;
    let mut count = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        count += 1;
        if count > MAX_LINES {
            return Err(Error::LinesDiffer);
        }
        let p = descriptor::parse(line)?;
        if p.range != Range::Change {
            receive = true;
        }
        match &first {
            None => first = Some(p.wallet),
            Some(w) if w.id() != p.wallet.id() => return Err(Error::LinesDiffer),
            _ => {}
        }
    }
    let w = first.ok_or(Error::Unknown)?;
    if !receive {
        return Err(Error::ChangeOnly);
    }
    Ok(w)
}

/// The value of a top-level string field, JSON escapes `\"` `\\` `\/`
/// resolved into `out`; other escapes are refused.
fn json_string<'o>(t: &[u8], key: &[u8], out: &'o mut [u8]) -> Option<&'o [u8]> {
    let mut i = 0;
    while i + key.len() + 2 <= t.len() {
        if t[i] == b'"' && t[i + 1..].starts_with(key) && t.get(i + 1 + key.len()) == Some(&b'"') {
            let mut j = i + key.len() + 2;
            while j < t.len() && t[j].is_ascii_whitespace() {
                j += 1;
            }
            if t.get(j) != Some(&b':') {
                i += 1;
                continue;
            }
            j += 1;
            while j < t.len() && t[j].is_ascii_whitespace() {
                j += 1;
            }
            if t.get(j) != Some(&b'"') {
                return None;
            }
            j += 1;
            let mut n = 0;
            while j < t.len() {
                let c = match t[j] {
                    b'"' => return Some(&out[..n]),
                    b'\\' => {
                        j += 1;
                        match t.get(j)? {
                            b'"' => b'"',
                            b'\\' => b'\\',
                            b'/' => b'/',
                            _ => return None,
                        }
                    }
                    c => c,
                };
                *out.get_mut(n)? = c;
                n += 1;
                j += 1;
            }
            return None;
        }
        i += 1;
    }
    None
}

fn parse_json(t: &[u8]) -> Result<Imported, Error> {
    let mut buf = [0u8; MAX_DESCRIPTOR];
    let d = json_string(t, b"descriptor", &mut buf).ok_or(Error::Unknown)?;
    let mut wallet = parse_descriptor_lines(d)?;
    let mut nb = [0u8; 64];
    let name = json_string(t, b"label", &mut nb)
        .map(|n| n.len())
        .or_else(|| json_string(t, b"name", &mut nb).map(|n| n.len()));
    if let Some(n) = name {
        wallet.set_name(core::str::from_utf8(&nb[..n]).unwrap_or(""));
    }
    Ok(Imported {
        wallet,
        format: Format::Json,
    })
}

/// `label: value` with a case-insensitive label.
fn field<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let (l, v) = line.split_once(':')?;
    l.trim().eq_ignore_ascii_case(label).then(|| v.trim())
}

fn parse_coldcard(t: &[u8]) -> Result<Imported, Error> {
    let text = core::str::from_utf8(t).map_err(|_| Error::Unknown)?;
    let mut name: Option<&str> = None;
    let mut policy: Option<(u8, u8)> = None;
    let mut script: Option<MsScript> = None;
    let mut derivation: Option<DerivationPath> = None;
    let mut keys = [None::<Cosigner>; MAX_KEYS];
    let mut n = 0;
    let mut test: Option<bool> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(v) = field(line, "name") {
            name = Some(v);
        } else if let Some(v) = field(line, "policy") {
            policy = Some(parse_policy(v).ok_or(Error::Policy)?);
        } else if let Some(v) = field(line, "derivation") {
            derivation = Some(parse_path(v).ok_or(Error::Derivation)?);
        } else if let Some(v) = field(line, "format") {
            script = Some(if v.eq_ignore_ascii_case("P2WSH") {
                MsScript::Wsh
            } else if v.eq_ignore_ascii_case("P2SH-P2WSH") || v.eq_ignore_ascii_case("P2WSH-P2SH") {
                MsScript::ShWsh
            } else {
                return Err(Error::ScriptFormat);
            });
        } else if let Some((xfp, key)) = line.split_once(':') {
            let xfp = xfp.trim();
            let key = key.trim();
            // anything but `XFP: key` is an unknown field: ignored, as Coldcard
            // does (a mistyped key line then fails the key count)
            let Some(fingerprint) = parse_fp(xfp) else {
                continue;
            };
            let origin = derivation.ok_or(Error::Derivation)?;
            let (xpub, t, version) = decode_key(key)?;
            match test {
                None => test = Some(t),
                Some(p) if p != t => return Err(Error::MixedNetwork),
                _ => {}
            }
            if n == MAX_KEYS {
                return Err(Error::KeyCount);
            }
            keys[n] = Some(Cosigner {
                fingerprint,
                origin,
                xpub,
                version,
            });
            n += 1;
        }
    }
    let (m, total) = policy.ok_or(Error::Policy)?;
    let script = script.ok_or(Error::ScriptFormat)?;
    if n != total as usize {
        return Err(Error::KeyCount);
    }
    let list = collect(&keys[..n]);
    let mut wallet = Wallet::new(test.unwrap_or(false), script, m, &list[..n]).ok_or(Error::Policy)?;
    if let Some(nm) = name {
        wallet.set_name(nm);
    }
    Ok(Imported {
        wallet,
        format: Format::Coldcard,
    })
}

fn collect(keys: &[Option<Cosigner>]) -> [Cosigner; MAX_KEYS] {
    let mut out = [keys[0].expect("at least one key"); MAX_KEYS];
    for (o, k) in out.iter_mut().zip(keys) {
        *o = k.expect("filled");
    }
    out
}

/// `2 of 3` or `2/3`.
fn parse_policy(v: &str) -> Option<(u8, u8)> {
    let (a, b) = v
        .split_once(" of ")
        .or_else(|| v.split_once(" OF "))
        .or_else(|| v.split_once('/'))?;
    let m: u8 = small(a.trim())?;
    let n: u8 = small(b.trim())?;
    (m >= 1 && m <= n && n as usize <= MAX_KEYS).then_some((m, n))
}

fn small(s: &str) -> Option<u8> {
    if s.is_empty() || s.len() > 2 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `m/48'/0'/0'/2'` (also `h`); strict digits.
fn parse_path(v: &str) -> Option<DerivationPath> {
    let mut parts = v.split('/');
    if !parts.next()?.eq_ignore_ascii_case("m") {
        return None;
    }
    let mut steps = [0u32; MAX_DEPTH];
    let mut d = 0;
    for p in parts {
        let (num, hard) = match p.strip_suffix('\'').or_else(|| p.strip_suffix('h')) {
            Some(x) => (x, true),
            None => (p, false),
        };
        if num.is_empty() || !num.bytes().all(|c| c.is_ascii_digit()) || num.len() > 10 || d == MAX_DEPTH {
            return None;
        }
        let v: u64 = num.parse().ok()?;
        if v >= HARDENED as u64 {
            return None;
        }
        steps[d] = if hard { v as u32 | HARDENED } else { v as u32 };
        d += 1;
    }
    DerivationPath::from_steps(&steps[..d]).ok()
}

fn parse_fp(s: &str) -> Option<[u8; 4]> {
    let b = s.as_bytes();
    if b.len() != 8 {
        return None;
    }
    let mut fp = [0u8; 4];
    for (i, f) in fp.iter_mut().enumerate() {
        let h = (b[2 * i] as char).to_digit(16)?;
        let l = (b[2 * i + 1] as char).to_digit(16)?;
        *f = (h * 16 + l) as u8;
    }
    Some(fp)
}

fn decode_key(s: &str) -> Result<(Xpub, bool, KeyVersion), Error> {
    match decode_xpub(s) {
        Ok(v) => Ok(v),
        Err(_) if Xpriv::decode(s).is_ok() => Err(Error::PrivateKey),
        Err(_) => Err(Error::Key),
    }
}

/// A cosigner key: `[fingerprint/path]xpub` text (optionally followed by
/// `/<0;1>/*`, `/0/*` or `/**`), or the Coldcard xpub JSON. `script` picks
/// the entry of a JSON that holds several. Returns the key and whether it
/// is a test-network key.
pub fn parse_cosigner(text: &[u8], script: MsScript) -> Result<(Cosigner, bool), Error> {
    let t = trim(text);
    if t.first() == Some(&b'{') {
        return parse_coldcard_xpub_json(t, script);
    }
    let s = core::str::from_utf8(t).map_err(|_| Error::Key)?;
    let Some(rest) = s.strip_prefix('[') else {
        return Err(if decode_key(s).is_ok() {
            Error::MissingOrigin
        } else {
            Error::Unknown
        });
    };
    let (origin_text, key) = rest.split_once(']').ok_or(Error::Key)?;
    let (fp_text, path_text) = match origin_text.split_once('/') {
        Some((f, p)) => (f, p),
        None => (origin_text, ""),
    };
    let fingerprint = parse_fp(fp_text).ok_or(Error::Key)?;
    let mut full = [0u8; 128];
    let path = {
        let p = path_text.as_bytes();
        if p.len() + 2 > full.len() {
            return Err(Error::Key);
        }
        full[0] = b'm';
        let mut n = 1;
        if !p.is_empty() {
            full[1] = b'/';
            full[2..2 + p.len()].copy_from_slice(p);
            n = 2 + p.len();
        }
        parse_path(core::str::from_utf8(&full[..n]).map_err(|_| Error::Key)?).ok_or(Error::Key)?
    };
    let key = key
        .strip_suffix("/<0;1>/*")
        .or_else(|| key.strip_suffix("/**"))
        .or_else(|| key.strip_suffix("/0/*"))
        .unwrap_or(key);
    let (xpub, test, version) = decode_key(key)?;
    Ok((
        Cosigner {
            fingerprint,
            origin: path,
            xpub,
            version,
        },
        test,
    ))
}

/// Coldcard "Export XPUB" multisig JSON: `xfp`, `p2wsh`/`p2wsh_deriv`,
/// `p2sh_p2wsh`/`p2sh_p2wsh_deriv`.
fn parse_coldcard_xpub_json(t: &[u8], script: MsScript) -> Result<(Cosigner, bool), Error> {
    let (kname, dname): (&[u8], &[u8]) = match script {
        MsScript::Wsh => (b"p2wsh", b"p2wsh_deriv"),
        MsScript::ShWsh => (b"p2sh_p2wsh", b"p2sh_p2wsh_deriv"),
    };
    let mut fb = [0u8; 16];
    let mut kb = [0u8; 128];
    let mut db = [0u8; 64];
    let fp = json_string(t, b"xfp", &mut fb).ok_or(Error::Unknown)?;
    let fingerprint = parse_fp(core::str::from_utf8(fp).map_err(|_| Error::Key)?).ok_or(Error::Key)?;
    let key = json_string(t, kname, &mut kb).ok_or(Error::ScriptFormat)?;
    let deriv = json_string(t, dname, &mut db).ok_or(Error::Derivation)?;
    let origin =
        parse_path(core::str::from_utf8(deriv).map_err(|_| Error::Derivation)?).ok_or(Error::Derivation)?;
    let (xpub, test, version) = decode_key(core::str::from_utf8(key).map_err(|_| Error::Key)?)?;
    Ok((
        Cosigner {
            fingerprint,
            origin,
            xpub,
            version,
        },
        test,
    ))
}

// ---- UR (BCR-2020-007/010/015) ----

const TAG_HDKEY: u64 = 303;
const TAG_KEYPATH: u64 = 304;
const TAG_COININFO: u64 = 305;
const TAG_SH: u64 = 400;
const TAG_WSH: u64 = 401;
const TAG_MULTI: u64 = 406;
const TAG_SORTED: u64 = 407;

/// A decoded `crypto-hdkey` with its origin and children range.
struct HdKey {
    cosigner: Cosigner,
    test: bool,
    range: Range,
}

fn cbor<T>(r: Result<T, bp_qr::ur::cbor::Error>) -> Result<T, Error> {
    r.map_err(|_| Error::Cbor)
}

fn read_hdkey(r: &mut Reader) -> Result<HdKey, Error> {
    if cbor(r.tag())? != TAG_HDKEY {
        return Err(Error::Cbor);
    }
    let entries = cbor(r.map())?;
    let mut key: Option<[u8; 33]> = None;
    let mut chain: Option<[u8; 32]> = None;
    let mut test = false;
    let mut origin: Option<KeyPath> = None;
    let mut range = Range::Both;
    let mut parent = [0u8; 4];
    for _ in 0..entries {
        match cbor(r.uint())? {
            2 => {
                if cbor(r.boolean())? {
                    return Err(Error::PrivateKey);
                }
            }
            3 => {
                let k = cbor(r.bytes())?;
                if k.len() != 33 || !(k[0] == 2 || k[0] == 3) {
                    return Err(if k.len() == 33 && k[0] == 0 {
                        Error::PrivateKey
                    } else {
                        Error::Key
                    });
                }
                key = Some(k.try_into().expect("33"));
            }
            4 => {
                let c = cbor(r.bytes())?;
                chain = Some(c.try_into().map_err(|_| Error::Key)?);
            }
            5 => {
                if cbor(r.tag())? != TAG_COININFO {
                    return Err(Error::Cbor);
                }
                for _ in 0..cbor(r.map())? {
                    match cbor(r.uint())? {
                        1 => {
                            if cbor(r.uint())? != 0 {
                                return Err(Error::Key); // not Bitcoin
                            }
                        }
                        2 => test = cbor(r.uint())? == 1,
                        _ => cbor(r.skip())?,
                    }
                }
            }
            6 => origin = Some(read_keypath(r)?),
            7 => range = read_children(r)?,
            8 => parent = (cbor(r.uint())? as u32).to_be_bytes(),
            _ => cbor(r.skip())?,
        }
    }
    let key = key.ok_or(Error::Key)?;
    let chain_code = chain.ok_or(Error::Key)?;
    let (path, source, depth) = origin.ok_or(Error::MissingOrigin)?;
    let fingerprint = source.ok_or(Error::MissingOrigin)?;
    let steps = path.steps();
    if let Some(d) = depth {
        if d != steps.len() as u64 {
            return Err(Error::Key);
        }
    }
    let xpub = Xpub {
        depth: steps.len() as u8,
        parent_fingerprint: parent,
        child_number: steps.last().copied().unwrap_or(0),
        chain_code,
        key: PublicKey::parse(&key).ok_or(Error::Key)?,
    };
    Ok(HdKey {
        cosigner: Cosigner {
            fingerprint,
            origin: path,
            xpub,
            version: KeyVersion::X,
        },
        test,
        range,
    })
}

/// `#6.304({1: [index, hardened, …], 2: source fingerprint, 3: depth})`
/// A key path: steps, source fingerprint, depth.
type KeyPath = (DerivationPath, Option<[u8; 4]>, Option<u64>);

fn read_keypath(r: &mut Reader) -> Result<KeyPath, Error> {
    if cbor(r.tag())? != TAG_KEYPATH {
        return Err(Error::Cbor);
    }
    let mut path = DerivationPath::new();
    let mut source = None;
    let mut depth = None;
    for _ in 0..cbor(r.map())? {
        match cbor(r.uint())? {
            1 => {
                let n = cbor(r.array())?;
                if n % 2 != 0 || n / 2 > MAX_DEPTH as u64 {
                    return Err(Error::Key);
                }
                let mut steps = [0u32; MAX_DEPTH];
                for s in steps.iter_mut().take((n / 2) as usize) {
                    let i = cbor(r.uint())?;
                    let h = cbor(r.boolean())?;
                    if i >= HARDENED as u64 {
                        return Err(Error::Key);
                    }
                    *s = if h { i as u32 | HARDENED } else { i as u32 };
                }
                path = DerivationPath::from_steps(&steps[..(n / 2) as usize]).map_err(|_| Error::Key)?;
            }
            2 => source = Some((cbor(r.uint())? as u32).to_be_bytes()),
            3 => depth = Some(cbor(r.uint())?),
            _ => cbor(r.skip())?,
        }
    }
    Ok((path, source, depth))
}

/// Children: `[0, false, [], false]` = `/0/*`, `[1, false, [], false]` =
/// `/1/*`; anything else is refused.
fn read_children(r: &mut Reader) -> Result<Range, Error> {
    if cbor(r.tag())? != TAG_KEYPATH {
        return Err(Error::Cbor);
    }
    let mut range = Err(Error::Descriptor(descriptor::Error::Suffix));
    for _ in 0..cbor(r.map())? {
        match cbor(r.uint())? {
            1 => {
                if cbor(r.array())? != 4 {
                    return Err(Error::Descriptor(descriptor::Error::Suffix));
                }
                let branch = cbor(r.uint())?;
                let h1 = cbor(r.boolean())?;
                let wild = cbor(r.array())?;
                let h2 = cbor(r.boolean())?;
                if h1 || h2 {
                    return Err(Error::Descriptor(descriptor::Error::Hardened));
                }
                range = match (branch, wild) {
                    (0, 0) => Ok(Range::Receive),
                    (1, 0) => Ok(Range::Change),
                    _ => Err(Error::Descriptor(descriptor::Error::Suffix)),
                };
            }
            _ => cbor(r.skip())?,
        }
    }
    range
}

/// UR `crypto-output` holding `wsh(sortedmulti)` or `sh(wsh(sortedmulti))`.
pub fn parse_output_ur(payload: &[u8]) -> Result<Imported, Error> {
    let mut r = Reader::new(payload);
    let script = match cbor(r.tag())? {
        TAG_WSH => MsScript::Wsh,
        TAG_SH => {
            if cbor(r.tag())? != TAG_WSH {
                return Err(Error::Descriptor(descriptor::Error::UnsupportedScript));
            }
            MsScript::ShWsh
        }
        _ => return Err(Error::Descriptor(descriptor::Error::UnsupportedScript)),
    };
    match cbor(r.tag())? {
        TAG_SORTED => {}
        TAG_MULTI => return Err(Error::Descriptor(descriptor::Error::Unsorted)),
        _ => return Err(Error::Descriptor(descriptor::Error::UnsupportedScript)),
    }
    let mut m = None;
    let mut keys = [None::<Cosigner>; MAX_KEYS];
    let mut n = 0;
    let mut test = None;
    let mut range = None;
    for _ in 0..cbor(r.map())? {
        match cbor(r.uint())? {
            1 => m = Some(cbor(r.uint())?),
            2 => {
                let count = cbor(r.array())?;
                if count as usize > MAX_KEYS {
                    return Err(Error::Descriptor(descriptor::Error::TooManyKeys));
                }
                for _ in 0..count {
                    let k = read_hdkey(&mut r)?;
                    match test {
                        None => test = Some(k.test),
                        Some(t) if t != k.test => return Err(Error::MixedNetwork),
                        _ => {}
                    }
                    match range {
                        None => range = Some(k.range),
                        Some(p) if p != k.range => {
                            return Err(Error::Descriptor(descriptor::Error::MixedSuffix))
                        }
                        _ => {}
                    }
                    keys[n] = Some(k.cosigner);
                    n += 1;
                }
            }
            _ => cbor(r.skip())?,
        }
    }
    if !r.is_at_end() {
        return Err(Error::Cbor);
    }
    if n == 0 {
        return Err(Error::KeyCount);
    }
    if range == Some(Range::Change) {
        return Err(Error::ChangeOnly);
    }
    let m = m.ok_or(Error::Policy)?;
    if m == 0 || m > n as u64 {
        return Err(Error::Descriptor(descriptor::Error::Threshold));
    }
    let list = collect(&keys[..n]);
    let wallet = Wallet::new(test.unwrap_or(false), script, m as u8, &list[..n])
        .ok_or(Error::Descriptor(descriptor::Error::Threshold))?;
    Ok(Imported {
        wallet,
        format: Format::UrOutput,
    })
}

/// A cosigner from UR `crypto-account` (the output for `script`) or
/// `crypto-hdkey` (which must carry its origin).
pub fn parse_cosigner_ur(ur_type: &str, payload: &[u8], script: MsScript) -> Result<(Cosigner, bool), Error> {
    let mut r = Reader::new(payload);
    match ur_type {
        "crypto-hdkey" | "hdkey" => {
            // an untagged hdkey map: re-read with the tag the reader expects
            let k = read_untagged_hdkey(payload)?;
            Ok((k.cosigner, k.test))
        }
        "crypto-account" | "account-descriptor" => {
            let mut master = None;
            let mut found = None;
            for _ in 0..cbor(r.map())? {
                match cbor(r.uint())? {
                    1 => master = Some((cbor(r.uint())? as u32).to_be_bytes()),
                    2 => {
                        for _ in 0..cbor(r.array())? {
                            let mut tags = [0u64; 2];
                            let mut nt = 0;
                            // outer script tags, then the hdkey
                            while nt < 2 {
                                let save = r.clone();
                                let t = cbor(r.tag())?;
                                if t == TAG_HDKEY {
                                    r = save;
                                    break;
                                }
                                tags[nt] = t;
                                nt += 1;
                            }
                            let want: &[u64] = match script {
                                MsScript::Wsh => &[TAG_WSH],
                                MsScript::ShWsh => &[TAG_SH, TAG_WSH],
                            };
                            if &tags[..nt] == want && found.is_none() {
                                found = Some(read_hdkey(&mut r)?);
                            } else {
                                cbor(r.skip())?;
                            }
                        }
                    }
                    _ => cbor(r.skip())?,
                }
            }
            let k = found.ok_or(Error::ScriptFormat)?;
            if master.is_some_and(|m| m != k.cosigner.fingerprint) {
                return Err(Error::Key);
            }
            Ok((k.cosigner, k.test))
        }
        _ => Err(Error::Unknown),
    }
}

/// `crypto-hdkey` payloads are the map without the 303 tag.
fn read_untagged_hdkey(payload: &[u8]) -> Result<HdKey, Error> {
    let mut buf = [0u8; 512];
    if payload.len() + 3 > buf.len() {
        return Err(Error::Cbor);
    }
    // 0xD9 0x01 0x2F = tag(303)
    buf[..3].copy_from_slice(&[0xD9, 0x01, 0x2F]);
    buf[3..3 + payload.len()].copy_from_slice(payload);
    let mut r = Reader::new(&buf[..3 + payload.len()]);
    let k = read_hdkey(&mut r)?;
    if !r.is_at_end() {
        return Err(Error::Cbor);
    }
    Ok(k)
}

/// The Coldcard multisig setup file for `w`. One `Derivation:` line when
/// every key shares its origin (what SeedSigner's reader expects), one per
/// key otherwise (Coldcard, Sparrow). Keys keep the wallet's order.
pub fn write_coldcard(w: &Wallet, name: &str, out: &mut [u8]) -> Option<usize> {
    use core::fmt::Write;
    let mut o = descriptor::Out::new(out);
    let net = if w.test {
        crate::Network::Testnet
    } else {
        crate::Network::Mainnet
    };
    let keys = w.keys();
    let shared = keys.iter().all(|k| k.origin == keys[0].origin);
    let r: core::fmt::Result = (|| {
        o.write_str("# Bitpunk multisig setup file\n#\n")?;
        writeln!(o, "Name: {}", name)?;
        writeln!(o, "Policy: {} of {}", w.m, w.n())?;
        if shared {
            writeln!(o, "Derivation: {}", keys[0].origin)?;
        }
        writeln!(o, "Format: {}", w.script.name())?;
        o.write_str("\n")?;
        for k in keys {
            if !shared {
                writeln!(o, "Derivation: {}", k.origin)?;
            }
            for b in k.fingerprint {
                write!(o, "{:02X}", b)?;
            }
            let mut x = [0u8; crate::bip32::XKEY_LEN];
            let n = k.xpub.encode(KeyVersion::X.public(net), &mut x);
            writeln!(
                o,
                ": {}",
                core::str::from_utf8(&x[..n]).map_err(|_| core::fmt::Error)?
            )?;
        }
        Ok(())
    })();
    r.ok()?;
    Some(o.len())
}
