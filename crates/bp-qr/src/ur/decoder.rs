//! UR decoder: single-part URs and the multipart fountain decoder of
//! BCR-2020-005 (pure fragments are stored, mixed parts are reduced by
//! XOR against known fragments and against each other until every
//! fragment is known; the message CRC32 is then checked). Accepts upper-
//! or lower-case text. Allocation-free: fragments live in caller storage.

// Bitset loops walk several word arrays in step, so indexing is clearer
// than zipped iterators here.
#![allow(clippy::needless_range_loop)]

use super::{choose_fragments, crc32, BYTEWORDS, MAX_FRAGMENTS};
use crate::ur::cbor::Reader;

/// Mixed (not yet reducible) parts kept at once.
pub const MAX_MIXED: usize = 32;
/// Longest UR type name accepted.
pub const MAX_TYPE: usize = 32;

const WORDS: usize = MAX_FRAGMENTS / 64;
type Set = [u64; WORDS];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a UR (`ur:<type>/...`).
    NotUr,
    /// Bad Bytewords (unknown pair, odd length or CRC mismatch).
    Bytewords,
    /// The multipart CBOR header is malformed.
    Cbor,
    /// A part of a different message or type.
    Mismatch,
    /// Too many fragments, or the storage is too small for the message.
    TooBig,
    /// The reassembled message failed its checksum.
    Checksum,
}

/// Minimal Bytewords pair (first and last letter) -> byte.
const fn build_pairs() -> [i16; 676] {
    let mut t = [-1i16; 676];
    let mut b = 0;
    while b < 256 {
        let first = (BYTEWORDS[b * 4] - b'a') as usize;
        let last = (BYTEWORDS[b * 4 + 3] - b'a') as usize;
        t[first * 26 + last] = b as i16;
        b += 1;
    }
    t
}
const PAIRS: [i16; 676] = build_pairs();

/// Decode minimal Bytewords (with the trailing CRC32) into `out`; returns
/// the payload length (without the CRC).
pub fn decode_bytewords(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if !text.len().is_multiple_of(2) || text.len() < 8 {
        return Err(Error::Bytewords);
    }
    let n = text.len() / 2;
    if n - 4 > out.len() {
        return Err(Error::TooBig);
    }
    let mut crc = [0u8; 4];
    for i in 0..n {
        let a = text[2 * i].to_ascii_lowercase();
        let b = text[2 * i + 1].to_ascii_lowercase();
        if !a.is_ascii_lowercase() || !b.is_ascii_lowercase() {
            return Err(Error::Bytewords);
        }
        let v = PAIRS[(a - b'a') as usize * 26 + (b - b'a') as usize];
        if v < 0 {
            return Err(Error::Bytewords);
        }
        if i < n - 4 {
            out[i] = v as u8;
        } else {
            crc[i - (n - 4)] = v as u8;
        }
    }
    if crc32(&out[..n - 4]).to_be_bytes() != crc {
        return Err(Error::Bytewords);
    }
    Ok(n - 4)
}

/// A parsed UR string.
struct Parsed<'a> {
    ur_type: &'a [u8],
    /// (seq_num, seq_len) for multipart
    seq: Option<(u32, u32)>,
    body: &'a [u8],
}

fn parse_number(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 9 || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(s.iter().fold(0u32, |a, &c| a * 10 + (c - b'0') as u32))
}

fn parse(text: &[u8]) -> Result<Parsed<'_>, Error> {
    if text.len() < 4 || !text[..3].eq_ignore_ascii_case(b"ur:") {
        return Err(Error::NotUr);
    }
    let rest = &text[3..];
    let slash = rest.iter().position(|&c| c == b'/').ok_or(Error::NotUr)?;
    let ur_type = &rest[..slash];
    if ur_type.is_empty()
        || ur_type.len() > MAX_TYPE
        || !ur_type.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
    {
        return Err(Error::NotUr);
    }
    let rest = &rest[slash + 1..];
    match rest.iter().position(|&c| c == b'/') {
        None => Ok(Parsed {
            ur_type,
            seq: None,
            body: rest,
        }),
        Some(s2) => {
            let seq = &rest[..s2];
            let dash = seq.iter().position(|&c| c == b'-').ok_or(Error::NotUr)?;
            let num = parse_number(&seq[..dash]).ok_or(Error::NotUr)?;
            let len = parse_number(&seq[dash + 1..]).ok_or(Error::NotUr)?;
            if num == 0 || len == 0 {
                return Err(Error::NotUr);
            }
            Ok(Parsed {
                ur_type,
                seq: Some((num, len)),
                body: &rest[s2 + 1..],
            })
        }
    }
}

fn set_from(mask: &[bool; MAX_FRAGMENTS], n: usize) -> Set {
    let mut s = [0u64; WORDS];
    for (i, &b) in mask.iter().enumerate().take(n) {
        if b {
            s[i / 64] |= 1 << (i % 64);
        }
    }
    s
}

fn count(s: &Set) -> u32 {
    s.iter().map(|w| w.count_ones()).sum()
}

fn first(s: &Set) -> Option<usize> {
    s.iter()
        .enumerate()
        .find(|(_, w)| **w != 0)
        .map(|(i, w)| i * 64 + w.trailing_zeros() as usize)
}

fn is_strict_subset(a: &Set, b: &Set) -> bool {
    a != b && a.iter().zip(b).all(|(x, y)| x & !y == 0)
}

#[derive(Clone, Copy)]
struct Mixed {
    set: Set,
    used: bool,
}

/// UR decoder state. The fragments live in caller storage passed to each
/// call (`UrDecoder` bundles the two for convenience).
#[derive(Clone)]
pub struct UrState {
    ur_type: [u8; MAX_TYPE],
    type_len: usize,
    started: bool,
    multipart: bool,
    seq_len: usize,
    message_len: usize,
    checksum: u32,
    fragment_len: usize,
    solved: Set,
    n_solved: usize,
    mixed: [Mixed; MAX_MIXED],
    parts_seen: u32,
    done: bool,
}

impl Default for UrState {
    fn default() -> Self {
        Self::new()
    }
}

impl UrState {
    pub const fn new() -> Self {
        Self {
            ur_type: [0; MAX_TYPE],
            type_len: 0,
            started: false,
            multipart: false,
            seq_len: 0,
            message_len: 0,
            checksum: 0,
            fragment_len: 0,
            solved: [0; WORDS],
            n_solved: 0,
            mixed: [Mixed {
                set: [0; WORDS],
                used: false,
            }; MAX_MIXED],
            parts_seen: 0,
            done: false,
        }
    }

    /// Forget everything (storage is wiped).
    pub fn reset(&mut self, store: &mut [u8]) {
        store.fill(0);
        *self = Self::new();
    }

    /// The UR type (lower case) once a part has been accepted.
    pub fn ur_type(&self) -> &str {
        core::str::from_utf8(&self.ur_type[..self.type_len]).unwrap_or("")
    }

    pub fn is_complete(&self) -> bool {
        self.done
    }

    /// (fragments known, fragments in the message); (1, 1) for a finished
    /// single-part UR, (0, 0) before the first part.
    pub fn progress(&self) -> (usize, usize) {
        if self.multipart {
            (self.n_solved, self.seq_len)
        } else if self.done {
            (1, 1)
        } else {
            (0, 0)
        }
    }

    /// Parts accepted so far (including repeats and fountain parts).
    pub fn parts_seen(&self) -> u32 {
        self.parts_seen
    }

    /// Whether pure fragment `i` is known (for a progress grid).
    pub fn has_fragment(&self, i: usize) -> bool {
        i < MAX_FRAGMENTS && self.solved[i / 64] >> (i % 64) & 1 == 1
    }

    /// The reassembled CBOR message once complete.
    pub fn message<'s>(&self, store: &'s [u8]) -> Option<&'s [u8]> {
        self.done.then(|| &store[..self.message_len])
    }

    /// Feed one scanned part; returns true once the message is complete.
    pub fn receive(&mut self, store: &mut [u8], text: &[u8]) -> Result<bool, Error> {
        if self.done {
            return Ok(true);
        }
        let p = parse(text)?;
        let mut ty = [0u8; MAX_TYPE];
        for (d, s) in ty.iter_mut().zip(p.ur_type) {
            *d = s.to_ascii_lowercase();
        }
        if self.started && ty[..p.ur_type.len()] != self.ur_type[..self.type_len] {
            return Err(Error::Mismatch);
        }
        match p.seq {
            None => {
                if self.started && self.multipart {
                    return Err(Error::Mismatch);
                }
                let n = decode_bytewords(p.body, store)?;
                self.accept_type(&ty, p.ur_type.len());
                self.message_len = n;
                self.done = true;
                self.parts_seen += 1;
                Ok(true)
            }
            Some((seq, len)) => {
                self.multipart_part(store, seq, len, p.body)?;
                self.accept_type(&ty, p.ur_type.len());
                self.parts_seen += 1;
                Ok(self.done)
            }
        }
    }

    fn accept_type(&mut self, ty: &[u8; MAX_TYPE], len: usize) {
        if !self.started {
            self.ur_type = *ty;
            self.type_len = len;
            self.started = true;
        }
    }

    /// Storage offset of mixed slot `k` (after the fragment area).
    fn mixed_range(&self, k: usize) -> core::ops::Range<usize> {
        let fl = self.fragment_len;
        let base = self.seq_len * fl;
        base + k * fl..base + (k + 1) * fl
    }

    fn multipart_part(&mut self, store: &mut [u8], seq: u32, len: u32, body: &[u8]) -> Result<(), Error> {
        // CBOR: [seq, seq_len, message_len, checksum, fragment]
        let mut cbor = [0u8; 4200];
        let n = decode_bytewords(body, &mut cbor)?;
        let mut r = Reader::new(&cbor[..n]);
        let fields = (|| {
            if r.array()? != 5 {
                return Err(super::cbor::Error::Malformed);
            }
            let s = r.uint()?;
            let l = r.uint()?;
            let ml = r.uint()?;
            let ck = r.uint()?;
            let data = r.bytes()?;
            Ok((s, l, ml, ck, data))
        })();
        let (s, l, ml, ck, data) = fields.map_err(|_| Error::Cbor)?;
        if s != seq as u64 || l != len as u64 || ck > u32::MAX as u64 || !r.is_at_end() {
            return Err(Error::Cbor);
        }
        let (seq_len, message_len, fl) = (l as usize, ml as usize, data.len());
        if seq_len > MAX_FRAGMENTS
            || fl == 0
            || message_len == 0
            || message_len > seq_len * fl
            || message_len <= (seq_len - 1) * fl
        {
            return Err(Error::Cbor);
        }
        if !self.multipart {
            if self.started {
                return Err(Error::Mismatch);
            }
            if seq_len * fl + MAX_MIXED * fl > store.len() {
                return Err(Error::TooBig);
            }
            self.multipart = true;
            self.seq_len = seq_len;
            self.message_len = message_len;
            self.checksum = ck as u32;
            self.fragment_len = fl;
        } else if (seq_len, message_len, ck as u32, fl)
            != (self.seq_len, self.message_len, self.checksum, self.fragment_len)
        {
            return Err(Error::Mismatch);
        }

        let mut mask = [false; MAX_FRAGMENTS];
        choose_fragments(seq, seq_len, self.checksum, &mut mask);
        let mut set = set_from(&mask, seq_len);
        let mut buf = [0u8; 2048];
        if fl > buf.len() {
            return Err(Error::TooBig);
        }
        buf[..fl].copy_from_slice(data);
        self.reduce_and_add(store, &mut set, &mut buf[..fl]);
        Ok(())
    }

    /// Reduce a part by known fragments and mixed parts, then store it.
    fn reduce_and_add(&mut self, store: &mut [u8], set: &mut Set, data: &mut [u8]) {
        // XOR out every known fragment it contains
        for w in 0..WORDS {
            let mut known = set[w] & self.solved[w];
            while known != 0 {
                let i = w * 64 + known.trailing_zeros() as usize;
                known &= known - 1;
                let fl = self.fragment_len;
                for (d, f) in data.iter_mut().zip(&store[i * fl..(i + 1) * fl]) {
                    *d ^= f;
                }
                set[w] &= !(1 << (i % 64));
            }
        }
        // ...and every stored mixed part that is a strict subset of it
        for k in 0..MAX_MIXED {
            if self.mixed[k].used && is_strict_subset(&self.mixed[k].set, set) {
                let r = self.mixed_range(k);
                for (d, m) in data.iter_mut().zip(&store[r]) {
                    *d ^= m;
                }
                let ms = self.mixed[k].set;
                for w in 0..WORDS {
                    set[w] &= !ms[w];
                }
            }
        }
        match count(set) {
            0 => {}
            1 => {
                let i = first(set).unwrap_or(0);
                self.solve(store, i, data);
            }
            _ => {
                if self.mixed.iter().any(|m| m.used && m.set == *set) {
                    return;
                }
                // reduce stored mixed parts that contain this one
                for k in 0..MAX_MIXED {
                    if self.mixed[k].used && is_strict_subset(set, &self.mixed[k].set) {
                        let r = self.mixed_range(k);
                        for (m, d) in store[r].iter_mut().zip(data.iter()) {
                            *m ^= d;
                        }
                        for w in 0..WORDS {
                            self.mixed[k].set[w] &= !set[w];
                        }
                    }
                }
                if let Some(k) = self.mixed.iter().position(|m| !m.used) {
                    let r = self.mixed_range(k);
                    store[r].copy_from_slice(data);
                    self.mixed[k] = Mixed {
                        set: *set,
                        used: true,
                    };
                }
                self.cascade(store);
            }
        }
    }

    /// Record pure fragment `i`, then keep reducing mixed parts.
    fn solve(&mut self, store: &mut [u8], i: usize, data: &[u8]) {
        if !self.has_fragment(i) {
            let fl = self.fragment_len;
            store[i * fl..(i + 1) * fl].copy_from_slice(data);
            self.solved[i / 64] |= 1 << (i % 64);
            self.n_solved += 1;
        }
        self.cascade(store);
    }

    /// Reduce mixed parts by known fragments until nothing changes.
    fn cascade(&mut self, store: &mut [u8]) {
        loop {
            let mut progress = false;
            for k in 0..MAX_MIXED {
                if !self.mixed[k].used {
                    continue;
                }
                let mut set = self.mixed[k].set;
                for w in 0..WORDS {
                    let mut known = set[w] & self.solved[w];
                    while known != 0 {
                        let i = w * 64 + known.trailing_zeros() as usize;
                        known &= known - 1;
                        let fl = self.fragment_len;
                        let r = self.mixed_range(k);
                        let (frags, rest) = store.split_at_mut(r.start);
                        for (m, f) in rest[..fl].iter_mut().zip(&frags[i * fl..(i + 1) * fl]) {
                            *m ^= f;
                        }
                        set[w] &= !(1 << (i % 64));
                    }
                }
                self.mixed[k].set = set;
                match count(&set) {
                    0 => self.mixed[k].used = false,
                    1 => {
                        let i = first(&set).unwrap_or(0);
                        self.mixed[k].used = false;
                        if !self.has_fragment(i) {
                            let r = self.mixed_range(k);
                            let fl = self.fragment_len;
                            store.copy_within(r, i * fl);
                            self.solved[i / 64] |= 1 << (i % 64);
                            self.n_solved += 1;
                            progress = true;
                        }
                    }
                    _ => {}
                }
            }
            if !progress {
                break;
            }
        }
        if self.n_solved == self.seq_len && !self.done {
            self.finish(store);
        }
    }

    fn finish(&mut self, store: &mut [u8]) {
        // the message is the fragments in order, cut to its length
        if crc32(&store[..self.message_len]) == self.checksum {
            let end = (self.seq_len + MAX_MIXED) * self.fragment_len;
            let cap = store.len();
            store[self.message_len..end.min(cap)].fill(0);
            self.done = true;
        } else {
            // inconsistent parts: start over
            self.reset(store);
        }
    }
}

/// A UR decoder bound to its storage.
pub struct UrDecoder<'a> {
    state: UrState,
    store: &'a mut [u8],
}

impl<'a> UrDecoder<'a> {
    pub fn new(store: &'a mut [u8]) -> Self {
        Self {
            state: UrState::new(),
            store,
        }
    }

    pub fn reset(&mut self) {
        self.state.reset(self.store);
    }

    /// Wipe and give the storage back.
    pub fn into_store(mut self) -> &'a mut [u8] {
        self.store.fill(0);
        core::mem::take(&mut self.store)
    }

    pub fn ur_type(&self) -> &str {
        self.state.ur_type()
    }

    pub fn is_complete(&self) -> bool {
        self.state.is_complete()
    }

    pub fn progress(&self) -> (usize, usize) {
        self.state.progress()
    }

    pub fn parts_seen(&self) -> u32 {
        self.state.parts_seen()
    }

    pub fn has_fragment(&self, i: usize) -> bool {
        self.state.has_fragment(i)
    }

    pub fn message(&self) -> Option<&[u8]> {
        self.state.message(self.store)
    }

    pub fn receive(&mut self, text: &[u8]) -> Result<bool, Error> {
        self.state.receive(self.store, text)
    }
}

impl Drop for UrDecoder<'_> {
    fn drop(&mut self) {
        self.store.fill(0);
    }
}
