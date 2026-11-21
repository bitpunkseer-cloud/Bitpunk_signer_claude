//! What a scanned QR code means. `Collector` takes the decoded text of each
//! camera frame, assembles animated codes (UR, BBQr, Specter) and hands the
//! result to `classify`, which recognises SeedQR / Compact SeedQR, mnemonic
//! words (full or 4-letter), PSBTs (binary, Base64, hex, UR, BBQr),
//! extended public keys (optionally with `[fingerprint/path]`), addresses
//! and `bitcoin:` URIs, output descriptors, and plain text. Everything a QR
//! carries is untrusted input: every parser is bounds-checked.

use crate::bip39::{self, Mnemonic};
use crate::{base58, base64, bech32, bip32, psbt, seedqr, Network};
use bp_qr::bbqr::{self, specter};
use bp_qr::ur::cbor::Reader;
use bp_qr::ur::decoder::{self as urdec, UrState};

/// Where a seed came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedSource {
    SeedQrStandard,
    SeedQrCompact,
    Words,
    UrSeed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    P2pkh,
    P2sh,
    /// SegWit v0 (P2WPKH or P2WSH)
    SegwitV0,
    /// Taproot (SegWit v1)
    Taproot,
}

/// A recognised payload. Byte content is in the caller's `out` buffer.
pub enum Content {
    Seed {
        mnemonic: Mnemonic,
        source: SeedSource,
    },
    /// PSBT bytes in `out[..len]`.
    Psbt {
        len: usize,
        summary: psbt::Summary,
    },
    /// Key text (as scanned, origin included) in `out[..len]`.
    Xpub {
        len: usize,
        network: Network,
        depth: u8,
    },
    /// Address text in `out[..len]` (from a URI: just the address).
    Address {
        len: usize,
        network: Network,
        kind: AddressKind,
        /// `index=N` from a `bitcoin:` URI: where to start looking for it.
        index: Option<u32>,
    },
    /// A `signmessage <path> ascii:<message>` request in `out[..len]`.
    SignMessage {
        len: usize,
    },
    /// Descriptor or wallet-file text in `out[..len]`.
    Descriptor {
        len: usize,
    },
    /// A UR type Bitpunk does not handle yet; its name in `out[..len]`.
    UnknownUr {
        len: usize,
    },
    Text {
        len: usize,
    },
    Binary {
        len: usize,
    },
}

/// How the payload arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Static,
    Ur,
    Bbqr,
    Specter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Nothing complete to classify yet.
    Incomplete,
    /// Output buffer too small.
    BufferTooSmall,
    /// The assembled data is corrupt (bad checksum, CBOR, compression).
    Corrupt,
}

fn copy(out: &mut [u8], data: &[u8]) -> Result<usize, Error> {
    out.get_mut(..data.len())
        .ok_or(Error::BufferTooSmall)?
        .copy_from_slice(data);
    Ok(data.len())
}

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |e| e + 1);
    &s[start..end]
}

fn is_printable(data: &[u8]) -> bool {
    data.iter()
        .all(|&c| c == b'\n' || c == b'\r' || c == b'\t' || (0x20..0x7F).contains(&c))
}

/// Mnemonic from words separated by whitespace; each word is a full BIP-39
/// word or its unique 4-letter prefix.
pub fn parse_words(text: &[u8]) -> Option<Mnemonic> {
    let mut idx = [0u16; bip39::MAX_WORDS];
    let mut n = 0;
    for w in text.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()) {
        if n == bip39::MAX_WORDS || w.len() > 8 {
            return None;
        }
        let mut lw = [0u8; 8];
        for (d, s) in lw.iter_mut().zip(w) {
            *d = s.to_ascii_lowercase();
        }
        let word = core::str::from_utf8(&lw[..w.len()]).ok()?;
        let i = match bip39::word_index(word) {
            Some(i) => i,
            None if w.len() >= bip39::UNIQUE_PREFIX_LEN => {
                let r = bip39::prefix_range(word);
                if r.len() != 1 {
                    return None;
                }
                r.start as u16
            }
            None => return None,
        };
        idx[n] = i;
        n += 1;
    }
    let m = Mnemonic::from_indices(&idx[..n]).ok();
    bp_crypto::secret::wipe_u16(&mut idx);
    m
}

fn address_info(addr: &[u8]) -> Option<(Network, AddressKind)> {
    let s = core::str::from_utf8(addr).ok()?;
    // "<hrp>1" prefix, any case
    let lower_hrp = |h: &str| {
        s.len() > h.len() + 1
            && s.as_bytes()[..h.len()].eq_ignore_ascii_case(h.as_bytes())
            && s.as_bytes()[h.len()] == b'1'
    };
    for (hrp, net) in [
        ("bcrt", Network::Regtest),
        ("bc", Network::Mainnet),
        ("tb", Network::Testnet),
    ] {
        if lower_hrp(hrp) {
            let a = bech32::decode_segwit(hrp, s).ok()?;
            let kind = match a.version {
                0 => AddressKind::SegwitV0,
                1 => AddressKind::Taproot,
                _ => return None,
            };
            return Some((net, kind));
        }
    }
    let mut raw = [0u8; 25];
    let n = base58::decode_check(s, &mut raw).ok()?;
    if n != 21 {
        return None;
    }
    match raw[0] {
        0x00 => Some((Network::Mainnet, AddressKind::P2pkh)),
        0x05 => Some((Network::Mainnet, AddressKind::P2sh)),
        0x6F => Some((Network::Testnet, AddressKind::P2pkh)),
        0xC4 => Some((Network::Testnet, AddressKind::P2sh)),
        _ => None,
    }
}

/// `index=N` among the `&`-separated URI parameters (N < 2^31).
fn uri_index(query: &[u8]) -> Option<u32> {
    query.split(|&c| c == b'&').find_map(|p| {
        let v = p.strip_prefix(b"index=")?;
        if v.is_empty() || v.len() > 10 || !v.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let n = core::str::from_utf8(v).ok()?.parse::<u32>().ok()?;
        (n < 1 << 31).then_some(n)
    })
}

fn is_descriptor(t: &[u8]) -> bool {
    const MARKS: [&[u8]; 8] = [
        b"wpkh(",
        b"wsh(",
        b"tr(",
        b"pkh(",
        b"sh(",
        b"multi(",
        b"sortedmulti(",
        b"\"descriptor\"",
    ];
    MARKS
        .iter()
        .any(|m| t.windows(m.len()).any(|w| w.eq_ignore_ascii_case(m)))
}

/// Recognise a single (already assembled) payload.
pub fn classify(data: &[u8], out: &mut [u8]) -> Result<Content, Error> {
    if data.starts_with(psbt::MAGIC) {
        let summary = psbt::summary(data).map_err(|_| Error::Corrupt)?;
        return Ok(Content::Psbt {
            len: copy(out, data)?,
            summary,
        });
    }
    if !is_printable(data) {
        if let Ok(m) = seedqr::from_compact(data) {
            return Ok(Content::Seed {
                mnemonic: m,
                source: SeedSource::SeedQrCompact,
            });
        }
        return Ok(Content::Binary {
            len: copy(out, data)?,
        });
    }
    let t = trim(data);
    if t.iter().all(u8::is_ascii_digit) && matches!(t.len(), 48 | 60 | 72 | 84 | 96) {
        if let Ok(m) = seedqr::from_standard(t) {
            return Ok(Content::Seed {
                mnemonic: m,
                source: SeedSource::SeedQrStandard,
            });
        }
    }
    // PSBT as Base64 or hex
    if t.starts_with(b"cHNidP") {
        let n = base64::decode(t, out).map_err(|e| match e {
            base64::Error::BufferTooSmall => Error::BufferTooSmall,
            _ => Error::Corrupt,
        })?;
        let summary = psbt::summary(&out[..n]).map_err(|_| Error::Corrupt)?;
        return Ok(Content::Psbt { len: n, summary });
    }
    if t.len() >= 10 && t[..10].eq_ignore_ascii_case(b"70736274ff") && t.len().is_multiple_of(2) {
        let n = t.len() / 2;
        let dst = out.get_mut(..n).ok_or(Error::BufferTooSmall)?;
        for (i, d) in dst.iter_mut().enumerate() {
            let h = (t[2 * i] as char).to_digit(16).ok_or(Error::Corrupt)?;
            let l = (t[2 * i + 1] as char).to_digit(16).ok_or(Error::Corrupt)?;
            *d = (h * 16 + l) as u8;
        }
        let summary = psbt::summary(&out[..n]).map_err(|_| Error::Corrupt)?;
        return Ok(Content::Psbt { len: n, summary });
    }
    if let Some(m) = parse_words(t) {
        return Ok(Content::Seed {
            mnemonic: m,
            source: SeedSource::Words,
        });
    }
    if t.starts_with(b"signmessage ") {
        return Ok(Content::SignMessage { len: copy(out, t)? });
    }
    // bitcoin: URI or a bare address
    let (addr, query) = if t.len() > 8 && t[..8].eq_ignore_ascii_case(b"bitcoin:") {
        let rest = &t[8..];
        let q = rest.iter().position(|&c| c == b'?').unwrap_or(rest.len());
        (&rest[..q], rest.get(q + 1..).unwrap_or(&[]))
    } else {
        (t, &[][..])
    };
    if let Some((network, kind)) = address_info(addr) {
        return Ok(Content::Address {
            len: copy(out, addr)?,
            network,
            kind,
            index: uri_index(query),
        });
    }
    // extended public key, optionally "[fingerprint/path]key"
    let key = match t.iter().position(|&c| c == b']') {
        Some(e) if t.first() == Some(&b'[') => &t[e + 1..],
        _ => t,
    };
    if let Ok(k) = core::str::from_utf8(key) {
        if let Ok((x, network, _)) = bip32::Xpub::decode(k) {
            return Ok(Content::Xpub {
                len: copy(out, t)?,
                network,
                depth: x.depth,
            });
        }
    }
    if is_descriptor(t) {
        return Ok(Content::Descriptor { len: copy(out, t)? });
    }
    Ok(Content::Text { len: copy(out, t)? })
}

/// Recognise a complete UR message by type.
pub fn classify_ur(ur_type: &str, message: &[u8], out: &mut [u8]) -> Result<Content, Error> {
    match ur_type {
        "crypto-psbt" | "psbt" => {
            let p = Reader::new(message).bytes().map_err(|_| Error::Corrupt)?;
            let summary = psbt::summary(p).map_err(|_| Error::Corrupt)?;
            Ok(Content::Psbt {
                len: copy(out, p)?,
                summary,
            })
        }
        "bytes" => {
            let inner = Reader::new(message).bytes().map_err(|_| Error::Corrupt)?;
            classify(inner, out)
        }
        "crypto-seed" | "seed" => {
            // map {1: entropy bytes, ...}; deterministic CBOR puts key 1 first
            let mut r = Reader::new(message);
            let n = r.map().map_err(|_| Error::Corrupt)?;
            if n == 0 || r.uint().map_err(|_| Error::Corrupt)? != 1 {
                return Err(Error::Corrupt);
            }
            let e = r.bytes().map_err(|_| Error::Corrupt)?;
            let mnemonic = Mnemonic::from_entropy(e).map_err(|_| Error::Corrupt)?;
            Ok(Content::Seed {
                mnemonic,
                source: SeedSource::UrSeed,
            })
        }
        other => Ok(Content::UnknownUr {
            len: copy(out, other.as_bytes())?,
        }),
    }
}

// ---------- assembling frames ----------

#[derive(Clone)]
enum Active {
    Idle,
    Static(usize),
    Ur(UrState),
    Bbqr(bbqr::JoinState),
    Specter(specter::JoinState),
}

/// What a frame did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feed {
    /// Part of an animated code was added (or was a repeat).
    Progress,
    /// The payload is complete: call `finish`.
    Complete,
    /// The frame did not fit the code being collected (or was garbage).
    Ignored,
}

/// Progress for the scan screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub source: Option<Source>,
    /// Parts known / parts total (UR: pure fragments).
    pub received: usize,
    pub total: usize,
}

/// Consecutive foreign frames after which collection restarts (the user
/// pointed the camera at another code).
const SWITCH_AFTER: u8 = 3;

/// Assembles scanned frames into one payload, in `N` bytes of its own
/// storage (wiped on reset and drop).
pub struct Collector<const N: usize> {
    store: [u8; N],
    active: Active,
    foreign: u8,
}

impl<const N: usize> Default for Collector<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Collector<N> {
    pub const fn new() -> Self {
        Self {
            store: [0; N],
            active: Active::Idle,
            foreign: 0,
        }
    }

    /// Drop everything collected (storage is wiped).
    pub fn reset(&mut self) {
        self.store.fill(0);
        self.active = Active::Idle;
        self.foreign = 0;
    }

    pub fn progress(&self) -> Progress {
        let (source, (received, total)) = match &self.active {
            Active::Ur(d) => (Some(Source::Ur), d.progress()),
            Active::Bbqr(j) => (Some(Source::Bbqr), j.progress()),
            Active::Specter(j) => (Some(Source::Specter), j.progress()),
            Active::Static(_) => (Some(Source::Static), (1, 1)),
            Active::Idle => (None, (0, 0)),
        };
        Progress {
            source,
            received,
            total,
        }
    }

    /// Whether part `i` has arrived (for a progress grid).
    pub fn has_part(&self, i: usize) -> bool {
        match &self.active {
            Active::Ur(d) => d.has_fragment(i),
            Active::Bbqr(j) => j.has_part(i),
            Active::Specter(j) => j.has_part(i),
            Active::Static(_) => i == 0,
            Active::Idle => false,
        }
    }

    /// UR type name while collecting a UR.
    pub fn ur_type(&self) -> Option<&str> {
        match &self.active {
            Active::Ur(d) => Some(d.ur_type()),
            _ => None,
        }
    }

    pub fn is_complete(&self) -> bool {
        match &self.active {
            Active::Ur(d) => d.is_complete(),
            Active::Bbqr(j) => j.is_complete(),
            Active::Specter(j) => j.is_complete(),
            Active::Static(_) => true,
            Active::Idle => false,
        }
    }

    /// Feed the decoded content of one QR code.
    pub fn feed(&mut self, frame: &[u8]) -> Feed {
        if self.is_complete() {
            return Feed::Complete;
        }
        let store = &mut self.store[..];
        let fits = match &mut self.active {
            Active::Ur(d) => Some(
                d.receive(store, frame)
                    .map_err(|e| e == urdec::Error::Mismatch || e == urdec::Error::NotUr),
            ),
            Active::Bbqr(j) => Some(
                j.add(store, frame)
                    .map_err(|e| e == bbqr::JoinError::Mismatch || e == bbqr::JoinError::NotBbqr),
            ),
            Active::Specter(j) => Some(
                j.add(store, frame)
                    .map_err(|e| e == bbqr::JoinError::Mismatch || e == bbqr::JoinError::NotBbqr),
            ),
            _ => None,
        };
        match fits {
            Some(Ok(done)) => {
                self.foreign = 0;
                if done {
                    Feed::Complete
                } else {
                    Feed::Progress
                }
            }
            Some(Err(foreign)) => {
                if foreign {
                    self.foreign += 1;
                    if self.foreign >= SWITCH_AFTER {
                        self.reset();
                        return self.start(frame);
                    }
                }
                Feed::Ignored
            }
            None => self.start(frame),
        }
    }

    fn start(&mut self, frame: &[u8]) -> Feed {
        self.reset();
        let store = &mut self.store[..];
        let r = if frame.len() > 3 && frame[..3].eq_ignore_ascii_case(b"ur:") {
            let mut d = UrState::new();
            let r = d.receive(store, frame).map_err(|_| ());
            self.active = Active::Ur(d);
            r
        } else if bbqr::parse_header(frame).is_some() {
            let mut j = bbqr::JoinState::new();
            let r = j.add(store, frame).map_err(|_| ());
            self.active = Active::Bbqr(j);
            r
        } else if specter::parse(frame).is_some() {
            let mut j = specter::JoinState::new();
            let r = j.add(store, frame).map_err(|_| ());
            self.active = Active::Specter(j);
            r
        } else if frame.len() <= store.len() {
            store[..frame.len()].copy_from_slice(frame);
            self.active = Active::Static(frame.len());
            Ok(true)
        } else {
            Err(())
        };
        match r {
            Ok(true) => Feed::Complete,
            Ok(false) => Feed::Progress,
            Err(()) => {
                self.reset();
                Feed::Ignored
            }
        }
    }

    /// Classify the complete payload. `work` holds intermediate bytes
    /// (joined text, compressed data); the result goes to `out`.
    pub fn finish(&self, work: &mut [u8], out: &mut [u8]) -> Result<(Content, Source), Error> {
        if !self.is_complete() {
            return Err(Error::Incomplete);
        }
        let store = &self.store[..];
        match &self.active {
            Active::Static(len) => classify(&store[..*len], out).map(|c| (c, Source::Static)),
            Active::Ur(d) => {
                let msg = d.message(store).ok_or(Error::Incomplete)?;
                classify_ur(d.ur_type(), msg, out).map(|c| (c, Source::Ur))
            }
            Active::Bbqr(j) => {
                let h = j.header().ok_or(Error::Incomplete)?;
                let n = j.finish(store, work, out).map_err(|e| match e {
                    bbqr::JoinError::BufferTooSmall => Error::BufferTooSmall,
                    _ => Error::Corrupt,
                })?;
                // the joined bytes are in `out`; move them to `work` to classify
                let w = work.get_mut(..n).ok_or(Error::BufferTooSmall)?;
                w.copy_from_slice(&out[..n]);
                out[..n].fill(0);
                let c = match h.file_type {
                    b'P' => psbt::summary(w).map_err(|_| Error::Corrupt).and_then(|summary| {
                        Ok(Content::Psbt {
                            len: copy(out, w)?,
                            summary,
                        })
                    }),
                    b'U' | b'J' => classify(w, out),
                    _ => copy(out, w).map(|len| Content::Binary { len }),
                };
                w.fill(0);
                c.map(|c| (c, Source::Bbqr))
            }
            Active::Specter(j) => {
                let n = j.finish(store, work).map_err(|_| Error::BufferTooSmall)?;
                let c = classify(&work[..n], out);
                work[..n].fill(0);
                c.map(|c| (c, Source::Specter))
            }
            Active::Idle => Err(Error::Incomplete),
        }
    }
}

impl<const N: usize> Drop for Collector<N> {
    fn drop(&mut self) {
        self.store.fill(0);
    }
}
