//! Uniform Resources (BCR-2020-005) with minimal Bytewords (BCR-2020-012)
//! and the multipart fountain encoder. Allocation-free.
//!
//! Part selection reproduces the reference algorithm exactly (Xoshiro256**
//! seeded with SHA-256, Walker alias sampler, shuffle), so any standard UR
//! decoder can reassemble the message from any sufficient subset of parts.

use bp_crypto::Sha256;

pub mod cbor;

/// Fragment-count limit (keeps the sampler tables on the stack bounded).
pub const MAX_FRAGMENTS: usize = 512;
pub const MIN_FRAGMENT_LEN: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BufferTooSmall,
    TooManyFragments,
    EmptyMessage,
}

// ---------- CRC32 (IEEE, as in zlib) ----------

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

// ---------- Bytewords ----------

/// BCR-2020-012 word list, 4 letters per word, in byte order.
const BYTEWORDS: &[u8; 1024] = b"ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom";

/// Full word for a byte (for tests and display).
pub fn byteword(b: u8) -> &'static str {
    let i = b as usize * 4;
    core::str::from_utf8(&BYTEWORDS[i..i + 4]).unwrap_or("")
}

/// Minimal Bytewords (first + last letter) of `data` followed by its CRC32.
pub fn bytewords_minimal(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let need = (data.len() + 4) * 2;
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    let crc = crc32(data).to_be_bytes();
    for (i, &b) in data.iter().chain(crc.iter()).enumerate() {
        let w = b as usize * 4;
        out[2 * i] = BYTEWORDS[w];
        out[2 * i + 1] = BYTEWORDS[w + 3];
    }
    Ok(need)
}

// ---------- Xoshiro256** and the alias sampler ----------

struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    fn from_seed_bytes(seed: &[u8]) -> Self {
        let d = Sha256::digest(seed);
        let mut s = [0u64; 4];
        for (i, v) in s.iter_mut().enumerate() {
            *v = u64::from_be_bytes(d[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        }
        Self { s }
    }

    fn next(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    fn next_double(&mut self) -> f64 {
        self.next() as f64 / (u64::MAX as f64 + 1.0)
    }

    fn next_int(&mut self, low: u64, high: u64) -> u64 {
        (self.next_double() * (high - low + 1) as f64 + low as f64) as u64
    }
}

/// Degree in 1..=n with P(d) proportional to 1/d (Walker alias method,
/// constructed exactly as in the reference implementation).
fn choose_degree(n: usize, rng: &mut Xoshiro256) -> usize {
    let mut p = [0f64; MAX_FRAGMENTS];
    let mut total = 0f64;
    for i in 0..n {
        total += 1.0 / (i + 1) as f64;
    }
    for (i, v) in p.iter_mut().enumerate().take(n) {
        *v = (1.0 / (i + 1) as f64 * n as f64) / total;
    }
    let mut small = [0u16; MAX_FRAGMENTS];
    let mut large = [0u16; MAX_FRAGMENTS];
    let (mut ns, mut nl) = (0usize, 0usize);
    for i in (0..n).rev() {
        if p[i] < 1.0 {
            small[ns] = i as u16;
            ns += 1;
        } else {
            large[nl] = i as u16;
            nl += 1;
        }
    }
    let mut probs = [0f64; MAX_FRAGMENTS];
    let mut alias = [0u16; MAX_FRAGMENTS];
    while ns > 0 && nl > 0 {
        ns -= 1;
        let a = small[ns] as usize;
        nl -= 1;
        let g = large[nl] as usize;
        probs[a] = p[a];
        alias[a] = g as u16;
        p[g] += p[a] - 1.0;
        if p[g] < 1.0 {
            small[ns] = g as u16;
            ns += 1;
        } else {
            large[nl] = g as u16;
            nl += 1;
        }
    }
    while nl > 0 {
        nl -= 1;
        probs[large[nl] as usize] = 1.0;
    }
    while ns > 0 {
        ns -= 1;
        probs[small[ns] as usize] = 1.0;
    }
    let r1 = rng.next_double();
    let r2 = rng.next_double();
    let i = (n as f64 * r1) as usize;
    1 + if r2 < probs[i] { i } else { alias[i] as usize }
}

/// Fragment indexes mixed into part `seq_num` (1-based). Returns a mask.
fn choose_fragments(seq_num: u32, seq_len: usize, checksum: u32, chosen: &mut [bool; MAX_FRAGMENTS]) {
    chosen[..seq_len].fill(false);
    if seq_num as usize <= seq_len {
        chosen[seq_num as usize - 1] = true;
        return;
    }
    let mut seed = [0u8; 8];
    seed[..4].copy_from_slice(&seq_num.to_be_bytes());
    seed[4..].copy_from_slice(&checksum.to_be_bytes());
    let mut rng = Xoshiro256::from_seed_bytes(&seed);
    let degree = choose_degree(seq_len, &mut rng);
    let mut remaining = [0u16; MAX_FRAGMENTS];
    for (i, v) in remaining.iter_mut().enumerate().take(seq_len) {
        *v = i as u16;
    }
    let mut left = seq_len;
    for _ in 0..degree {
        let idx = rng.next_int(0, left as u64 - 1) as usize;
        chosen[remaining[idx] as usize] = true;
        remaining.copy_within(idx + 1..left, idx);
        left -= 1;
    }
}

/// Reference "nominal fragment length": the smallest fragment count whose
/// equal-sized fragments fit `max_fragment_len`.
pub fn nominal_fragment_len(message_len: usize, max_fragment_len: usize) -> usize {
    let max_count = (message_len / MIN_FRAGMENT_LEN).max(1);
    let mut frag = message_len;
    for count in 1..=max_count {
        frag = message_len.div_ceil(count);
        if frag <= max_fragment_len {
            break;
        }
    }
    frag
}

// ---------- UR encoder ----------

/// Streams UR parts for one message. Single-part when it fits.
pub struct UrEncoder<'a> {
    ur_type: &'a str,
    message: &'a [u8],
    checksum: u32,
    fragment_len: usize,
    seq_len: usize,
    seq_num: u32,
}

impl<'a> UrEncoder<'a> {
    /// `message` is the CBOR payload; `max_fragment_len` in bytes.
    pub fn new(ur_type: &'a str, message: &'a [u8], max_fragment_len: usize) -> Result<Self, Error> {
        if message.is_empty() {
            return Err(Error::EmptyMessage);
        }
        let fragment_len = nominal_fragment_len(message.len(), max_fragment_len.max(MIN_FRAGMENT_LEN));
        let seq_len = message.len().div_ceil(fragment_len);
        if seq_len > MAX_FRAGMENTS {
            return Err(Error::TooManyFragments);
        }
        Ok(Self {
            ur_type,
            message,
            checksum: crc32(message),
            fragment_len,
            seq_len,
            seq_num: 0,
        })
    }

    pub fn is_single_part(&self) -> bool {
        self.seq_len == 1
    }

    /// Number of distinct (pure) fragments.
    pub fn seq_len(&self) -> usize {
        self.seq_len
    }

    pub fn seq_num(&self) -> u32 {
        self.seq_num
    }

    pub fn fragment_len(&self) -> usize {
        self.fragment_len
    }

    /// Write the next part as a lowercase UR string; returns its length.
    pub fn next_part(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if !self.is_single_part() {
            self.seq_num = self.seq_num.wrapping_add(1);
        }
        self.part(self.seq_num.max(1), out)
    }

    /// Write part `seq_num` (1-based) without changing the encoder state.
    pub fn part(&self, seq_num: u32, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer { buf: out, len: 0 };
        w.push(b"ur:")?;
        w.push(self.ur_type.as_bytes())?;
        w.push(b"/")?;
        if self.is_single_part() {
            let n = bytewords_minimal(self.message, &mut w.buf[w.len..])?;
            return Ok(w.len + n);
        }
        let seq = seq_num.max(1);
        let mut num = [0u8; 10];
        w.push(fmt_u32(seq, &mut num))?;
        w.push(b"-")?;
        w.push(fmt_u32(self.seq_len as u32, &mut num))?;
        w.push(b"/")?;

        // mixed fragment
        let mut chosen = [false; MAX_FRAGMENTS];
        choose_fragments(seq, self.seq_len, self.checksum, &mut chosen);
        let mut part = [0u8; 2048 + 32];
        let fl = self.fragment_len;
        if fl > 2048 {
            return Err(Error::BufferTooSmall);
        }
        let mut c = cbor::Writer::new(&mut part);
        let r = (|| {
            c.array(5)?;
            c.uint(seq as u64)?;
            c.uint(self.seq_len as u64)?;
            c.uint(self.message.len() as u64)?;
            c.uint(self.checksum as u64)?;
            c.bytes_header(fl)?;
            let start = c.len();
            let data = c.reserve(fl)?;
            for (i, sel) in chosen.iter().enumerate().take(self.seq_len) {
                if !*sel {
                    continue;
                }
                for (j, d) in data.iter_mut().enumerate() {
                    let k = i * fl + j;
                    if k < self.message.len() {
                        *d ^= self.message[k];
                    }
                }
            }
            Ok::<usize, cbor::Error>(start + fl)
        })();
        let part_len = r.map_err(|_| Error::BufferTooSmall)?;
        let n = bytewords_minimal(&part[..part_len], &mut w.buf[w.len..])?;
        Ok(w.len + n)
    }
}

/// Largest fragment length whose parts fit in `max_chars` characters
/// (for sizing UR parts to a QR capacity).
pub fn max_fragment_len_for_chars(ur_type: &str, message_len: usize, max_chars: usize) -> usize {
    // "ur:" + type + "/" + "nnnnn-nnn/" + 2 * (cbor overhead + fragment + crc32)
    let fixed = 3 + ur_type.len() + 1 + 11;
    let cbor_overhead = 1 + 5 + 3 + 5 + 5 + 3;
    if max_chars <= fixed + 2 * (cbor_overhead + 4) {
        return MIN_FRAGMENT_LEN;
    }
    let f = (max_chars - fixed) / 2 - cbor_overhead - 4;
    f.clamp(MIN_FRAGMENT_LEN, message_len.max(MIN_FRAGMENT_LEN))
}

struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    fn push(&mut self, s: &[u8]) -> Result<(), Error> {
        if self.len + s.len() > self.buf.len() {
            return Err(Error::BufferTooSmall);
        }
        self.buf[self.len..self.len + s.len()].copy_from_slice(s);
        self.len += s.len();
        Ok(())
    }
}

fn fmt_u32(mut v: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_value() {
        // BCR-2020-012 example
        assert_eq!(crc32(b"Hello, world!"), 0xebe6c6e6);
    }

    #[test]
    fn nominal_fragment_lengths() {
        assert_eq!(nominal_fragment_len(100, 30), 25);
        assert_eq!(nominal_fragment_len(100, 200), 100);
        assert_eq!(nominal_fragment_len(5, 30), 5);
    }
}
