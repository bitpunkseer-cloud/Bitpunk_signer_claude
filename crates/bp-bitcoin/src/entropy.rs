//! Seed entropy from **physical** sources only: dice (D6) and coin flips.
//!
//! The recorded values are concatenated as ASCII digits and hashed with
//! SHA-256, the same method SeedSigner, Krux and Coldcard use. Before a seed
//! may be created every check in [`Analysis`] must pass:
//!
//! | check | rule |
//! |---|---|
//! | count | at least `ceil(target_bits / bits_per_value)` values |
//! | entropy | `N * H(observed frequencies)` >= target bits (conservative) |
//! | bias | chi-square goodness of fit, 0.1% significance |
//! | pattern | lag 1..=16 autocorrelation within 4 sigma (+ Krux step-entropy test for dice) |
//! | repeats | longest run of one value below 8 (dice) / 20 (coin) |
//!
//! Device or software random numbers are never used for seed material.

use crate::bip39::Mnemonic;
use bp_crypto::secret::wipe;
use bp_crypto::Sha256;

pub const MAX_VALUES: usize = 512;
/// Minimum number of value pairs for an autocorrelation lag to be tested.
const MIN_PAIRS: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Six-sided die; values 1..=6 recorded as '1'..'6'.
    Dice,
    /// Coin; heads recorded as '1', tails as '0'.
    Coin,
}

impl Source {
    pub const fn sides(self) -> usize {
        match self {
            Source::Dice => 6,
            Source::Coin => 2,
        }
    }

    /// Maximum entropy per value in bits.
    pub fn bits_per_value(self) -> f64 {
        log2(self.sides() as f64)
    }

    /// Minimum number of values for `words` (12 or 24).
    pub fn min_count(self, words: usize) -> usize {
        let target = target_bits(words) as f64;
        let per = self.bits_per_value();
        let mut n = (target / per) as usize;
        if (n as f64) * per < target {
            n += 1;
        }
        n
    }

    /// Longest allowed run of identical values (exclusive).
    pub const fn run_limit(self) -> usize {
        match self {
            Source::Dice => 8,
            Source::Coin => 20,
        }
    }

    /// Chi-square critical value at 0.1% for `sides - 1` degrees of freedom.
    pub const fn chi2_limit(self) -> f64 {
        match self {
            Source::Dice => 20.515,
            Source::Coin => 10.828,
        }
    }

    /// Bucket index of a recorded ASCII value.
    fn bucket(self, c: u8) -> usize {
        match self {
            Source::Dice => (c - b'1') as usize,
            Source::Coin => (c - b'0') as usize,
        }
    }

    /// ASCII value for face `v` (dice 1..=6, coin 0/1), if valid.
    pub fn record_char(self, v: u8) -> Option<u8> {
        match (self, v) {
            (Source::Dice, 1..=6) => Some(b'0' + v),
            (Source::Coin, 0 | 1) => Some(b'0' + v),
            _ => None,
        }
    }
}

/// Security target in bits for a 12- or 24-word seed.
pub const fn target_bits(words: usize) -> u32 {
    if words >= 24 {
        256
    } else {
        128
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Not enough data yet.
    Pending,
    Pass,
    Fail,
}

#[derive(Clone, Copy, Debug)]
pub struct Analysis {
    pub count: usize,
    pub min_count: usize,
    pub counts: [u16; 6],
    /// Conservative entropy estimate: N * H(observed frequencies).
    pub est_bits: f64,
    /// Upper bound: N * log2(sides).
    pub max_bits: f64,
    pub target_bits: u32,
    pub chi2: f64,
    pub longest_run: usize,
    /// Largest |z| over the autocorrelation lags (0 when pending).
    pub autocorr_z: f64,
    /// Krux step-entropy deficit in percent (dice only, 0 otherwise).
    pub step_deficit_pct: f64,
    pub count_status: Status,
    pub entropy_status: Status,
    pub bias_status: Status,
    pub pattern_status: Status,
    pub repeat_status: Status,
}

impl Analysis {
    pub fn all_pass(&self) -> bool {
        [
            self.count_status,
            self.entropy_status,
            self.bias_status,
            self.pattern_status,
            self.repeat_status,
        ]
        .iter()
        .all(|s| *s == Status::Pass)
    }

    pub fn any_fail(&self) -> bool {
        [
            self.count_status,
            self.entropy_status,
            self.bias_status,
            self.pattern_status,
            self.repeat_status,
        ]
        .contains(&Status::Fail)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The entropy checks have not all passed.
    ChecksNotPassed,
    Full,
    InvalidValue,
}

/// Values recorded from a die or coin. Wiped on drop.
pub struct PhysicalEntropy {
    source: Source,
    words: usize,
    rec: [u8; MAX_VALUES],
    len: usize,
}

impl PhysicalEntropy {
    /// `words` is 12 or 24.
    pub fn new(source: Source, words: usize) -> Self {
        Self {
            source,
            words: if words >= 24 { 24 } else { 12 },
            rec: [0; MAX_VALUES],
            len: 0,
        }
    }

    pub fn source(&self) -> Source {
        self.source
    }

    pub fn words(&self) -> usize {
        self.words
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Recorded ASCII string (e.g. `b"3615..."`).
    pub fn record(&self) -> &[u8] {
        &self.rec[..self.len]
    }

    /// Record a face: dice 1..=6, coin 1 = heads / 0 = tails.
    pub fn push(&mut self, value: u8) -> Result<(), Error> {
        let c = self.source.record_char(value).ok_or(Error::InvalidValue)?;
        if self.len >= MAX_VALUES {
            return Err(Error::Full);
        }
        self.rec[self.len] = c;
        self.len += 1;
        Ok(())
    }

    pub fn pop(&mut self) {
        if self.len > 0 {
            self.len -= 1;
            self.rec[self.len] = 0;
        }
    }

    pub fn clear(&mut self) {
        wipe(&mut self.rec);
        self.len = 0;
    }

    /// SHA-256 of the recorded string.
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.record())
    }

    pub fn analyze(&self) -> Analysis {
        analyze(self.source, self.words, self.record())
    }

    /// Create the mnemonic. Fails unless every check passes.
    pub fn to_mnemonic(&self) -> Result<Mnemonic, Error> {
        if !self.analyze().all_pass() {
            return Err(Error::ChecksNotPassed);
        }
        Ok(mnemonic_from_record(self.record(), self.words))
    }
}

impl Drop for PhysicalEntropy {
    fn drop(&mut self) {
        wipe(&mut self.rec);
    }
}

/// SHA-256(record) truncated to 16 bytes (12 words) or 32 bytes (24 words).
/// No checks are applied; use [`PhysicalEntropy::to_mnemonic`] in the app.
pub fn mnemonic_from_record(record: &[u8], words: usize) -> Mnemonic {
    let mut h = Sha256::digest(record);
    let n = if words >= 24 { 32 } else { 16 };
    let m = Mnemonic::from_entropy(&h[..n]).expect("16 or 32 bytes");
    wipe(&mut h);
    m
}

pub fn analyze(source: Source, words: usize, rec: &[u8]) -> Analysis {
    let n = rec.len();
    let sides = source.sides();
    let min_count = source.min_count(words);
    let target = target_bits(words);

    let mut counts = [0u16; 6];
    for &c in rec {
        counts[source.bucket(c)] += 1;
    }

    // Conservative entropy estimate from observed frequencies.
    let mut est_bits = 0.0;
    if n > 0 {
        let nf = n as f64;
        let mut h = 0.0;
        for &c in &counts[..sides] {
            if c > 0 {
                let p = c as f64 / nf;
                h -= p * log2(p);
            }
        }
        est_bits = h * nf;
    }
    let max_bits = n as f64 * source.bits_per_value();

    // Chi-square goodness of fit against a fair source.
    let mut chi2 = 0.0;
    if n > 0 {
        let e = n as f64 / sides as f64;
        for &c in &counts[..sides] {
            let d = c as f64 - e;
            chi2 += d * d / e;
        }
    }

    // Longest run of identical values.
    let mut longest_run = 0;
    let mut run = 0;
    for i in 0..n {
        run = if i > 0 && rec[i] == rec[i - 1] { run + 1 } else { 1 };
        longest_run = longest_run.max(run);
    }

    // Statistical tests are evaluated once the minimum count is reached:
    // smaller samples give unreliable statistics and false alarms.
    let enough = n >= min_count;

    // Autocorrelation: fraction of equal values at lag L vs. 1/sides.
    let mut autocorr_z = 0.0;
    let mut autocorr_bad = false;
    if enough {
        let p = 1.0 / sides as f64;
        for lag in 1..=16usize {
            if n < lag + MIN_PAIRS {
                break;
            }
            let pairs = (n - lag) as f64;
            let matches = (lag..n).filter(|&i| rec[i] == rec[i - lag]).count() as f64;
            let mu = pairs * p;
            let var = pairs * p * (1.0 - p);
            let d = matches - mu;
            // |z| = |d| / sqrt(var); compare squares to avoid sqrt.
            let z2 = d * d / var;
            if z2 > autocorr_z * autocorr_z {
                autocorr_z = sqrt(z2);
            }
            if z2 > 16.0 {
                autocorr_bad = true;
            }
        }
    }

    // Krux: entropy deficit of consecutive differences (dice only).
    let mut step_deficit_pct = 0.0;
    let mut step_bad = false;
    if enough && source == Source::Dice && n >= 2 {
        let mut bins = [0u16; 11];
        for i in 1..n {
            let d = rec[i] as i16 - rec[i - 1] as i16;
            bins[(d + 5) as usize] += 1;
        }
        let total = (n - 1) as f64;
        let mut h = 0.0;
        for &b in &bins {
            if b > 0 {
                let p = b as f64 / total;
                h -= p * log2(p);
            }
        }
        let max = log2(11.0);
        step_deficit_pct = (max - h) / max * 100.0;
        step_bad = step_deficit_pct > 30.0;
    }

    let pending_or = |ok: bool| if ok { Status::Pass } else { Status::Pending };
    let tested = |bad: bool| {
        if !enough {
            Status::Pending
        } else if bad {
            Status::Fail
        } else {
            Status::Pass
        }
    };

    Analysis {
        count: n,
        min_count,
        counts,
        est_bits,
        max_bits,
        target_bits: target,
        chi2,
        longest_run,
        autocorr_z,
        step_deficit_pct,
        count_status: pending_or(n >= min_count),
        entropy_status: pending_or(est_bits >= target as f64),
        bias_status: tested(chi2 > source.chi2_limit()),
        pattern_status: tested(autocorr_bad || step_bad),
        repeat_status: if longest_run >= source.run_limit() {
            Status::Fail
        } else if n >= min_count {
            Status::Pass
        } else {
            Status::Pending
        },
    }
}

/// Natural-log based log2 using only `core` arithmetic (no libm in no_std).
pub fn log2(x: f64) -> f64 {
    debug_assert!(x > 0.0);
    let bits = x.to_bits();
    let mut exp = ((bits >> 52) & 0x7ff) as i64 - 1023;
    let mut m = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    if m > core::f64::consts::SQRT_2 {
        m /= 2.0;
        exp += 1;
    }
    // ln(m) = 2 * atanh(s), s = (m-1)/(m+1), |s| <= 0.1716
    let s = (m - 1.0) / (m + 1.0);
    let s2 = s * s;
    let mut term = s;
    let mut sum = 0.0;
    let mut k = 1.0;
    for _ in 0..14 {
        sum += term / k;
        term *= s2;
        k += 2.0;
    }
    exp as f64 + 2.0 * sum / core::f64::consts::LN_2
}

/// Square root by Newton's method (display only).
pub fn sqrt(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut r = if x > 1.0 { x / 2.0 } else { 1.0 };
    for _ in 0..60 {
        let next = 0.5 * (r + x / r);
        if (next - r).abs() <= 1e-12 * r {
            return next;
        }
        r = next;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log2_and_sqrt_accuracy() {
        extern crate std;
        for i in 1..2000 {
            let x = i as f64 * 0.37;
            assert!((log2(x) - x.log2()).abs() < 1e-12, "log2({x})");
            assert!((sqrt(x) - x.sqrt()).abs() < 1e-9, "sqrt({x})");
        }
    }

    #[test]
    fn min_counts() {
        assert_eq!(Source::Dice.min_count(12), 50);
        assert_eq!(Source::Dice.min_count(24), 100);
        assert_eq!(Source::Coin.min_count(12), 128);
        assert_eq!(Source::Coin.min_count(24), 256);
    }
}
