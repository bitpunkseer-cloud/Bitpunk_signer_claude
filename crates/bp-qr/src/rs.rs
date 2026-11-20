//! Reed–Solomon decoding over GF(256) (primitive polynomial 0x11D, first
//! consecutive root alpha^0), as used by QR codes. Syndromes,
//! Berlekamp–Massey, Chien search and Forney's formula. Allocation-free.

const fn build_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u32 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11D;
        }
        i += 1;
    }
    // exp is doubled so exp[a + b] needs no reduction for a, b < 255
    while i < 512 {
        exp[i] = exp[i - 255];
        i += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = build_tables();
const EXP: [u8; 512] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

/// Largest number of error-correction codewords in one QR block.
pub const MAX_ECC: usize = 30;

#[inline]
fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

#[inline]
fn div(a: u8, b: u8) -> u8 {
    debug_assert!(b != 0);
    if a == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + 255 - LOG[b as usize] as usize]
    }
}

/// alpha^e for any e >= 0.
#[inline]
fn pow_alpha(e: usize) -> u8 {
    EXP[e % 255]
}

/// Evaluate a polynomial stored lowest degree first.
fn eval_low(p: &[u8], x: u8) -> u8 {
    p.iter().rev().fold(0, |acc, &c| mul(acc, x) ^ c)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// More errors than the code (or `max_errors`) can correct.
    TooManyErrors,
    /// Block shorter than its ECC part, or ECC part too long.
    BadLength,
}

/// Correct `block` (data then `ecc_len` ECC bytes, first byte = highest
/// degree) in place, fixing at most `max_errors` symbols. Returns the number
/// of corrected symbols. A corrected block is always re-checked to be a
/// valid codeword.
pub fn correct(block: &mut [u8], ecc_len: usize, max_errors: usize) -> Result<usize, Error> {
    let n = block.len();
    if ecc_len == 0 || ecc_len > MAX_ECC || ecc_len > n || n > 255 {
        return Err(Error::BadLength);
    }
    let max_errors = max_errors.min(ecc_len / 2);

    // syndromes S_j = r(alpha^j), j = 0..ecc_len
    let mut synd = [0u8; MAX_ECC];
    let mut any = false;
    for (j, s) in synd.iter_mut().enumerate().take(ecc_len) {
        let x = pow_alpha(j);
        *s = block.iter().fold(0, |acc, &c| mul(acc, x) ^ c);
        any |= *s != 0;
    }
    if !any {
        return Ok(0);
    }

    // Berlekamp–Massey: error locator Lambda(x), lowest degree first
    let mut lambda = [0u8; MAX_ECC + 1];
    let mut prev = [0u8; MAX_ECC + 1];
    lambda[0] = 1;
    prev[0] = 1;
    let mut l = 0usize; // current number of assumed errors
    let mut m = 1usize; // steps since `prev` was saved
    let mut b = 1u8; // discrepancy when `prev` was saved
    for k in 0..ecc_len {
        let mut d = synd[k];
        for i in 1..=l {
            d ^= mul(lambda[i], synd[k - i]);
        }
        if d == 0 {
            m += 1;
            continue;
        }
        let coef = div(d, b);
        if 2 * l <= k {
            let saved = lambda;
            for i in 0..(MAX_ECC + 1).saturating_sub(m) {
                lambda[i + m] ^= mul(coef, prev[i]);
            }
            l = k + 1 - l;
            prev = saved;
            b = d;
            m = 1;
        } else {
            for i in 0..(MAX_ECC + 1).saturating_sub(m) {
                lambda[i + m] ^= mul(coef, prev[i]);
            }
            m += 1;
        }
    }
    if l == 0 || l > max_errors {
        return Err(Error::TooManyErrors);
    }

    // Omega(x) = S(x) * Lambda(x) mod x^ecc_len
    let mut omega = [0u8; MAX_ECC];
    for i in 0..ecc_len {
        let mut v = 0;
        for j in 0..=i.min(l) {
            v ^= mul(lambda[j], synd[i - j]);
        }
        omega[i] = v;
    }

    // Chien search over the n positions; position p (from the end) has
    // locator X = alpha^p and Lambda(X^-1) = 0 marks an error there.
    let mut found = 0usize;
    let mut positions = [0usize; MAX_ECC / 2 + 1];
    let mut values = [0u8; MAX_ECC / 2 + 1];
    for p in 0..n {
        let x_inv = pow_alpha(255 - p % 255);
        if eval_low(&lambda[..=l], x_inv) != 0 {
            continue;
        }
        if found == l {
            return Err(Error::TooManyErrors);
        }
        // Forney with first root alpha^0: e = X * Omega(X^-1) / Lambda'(X^-1)
        let mut deriv = 0u8;
        let mut i = 1;
        while i <= l {
            // odd-power terms survive formal differentiation in GF(2^m)
            deriv ^= mul(lambda[i], pow_alpha((255 - p % 255) * (i - 1)));
            i += 2;
        }
        if deriv == 0 {
            return Err(Error::TooManyErrors);
        }
        let num = mul(pow_alpha(p), eval_low(&omega[..ecc_len], x_inv));
        positions[found] = n - 1 - p;
        values[found] = div(num, deriv);
        found += 1;
    }
    if found != l {
        return Err(Error::TooManyErrors);
    }
    let mut fixed = [0u8; 255];
    fixed[..n].copy_from_slice(block);
    for k in 0..found {
        fixed[positions[k]] ^= values[k];
    }
    // reject miscorrections: the result must be a codeword
    for j in 0..ecc_len {
        let x = pow_alpha(j);
        if fixed[..n].iter().fold(0, |acc, &c| mul(acc, x) ^ c) != 0 {
            return Err(Error::TooManyErrors);
        }
    }
    block.copy_from_slice(&fixed[..n]);
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Systematic encoder used only to make test codewords.
    fn encode(data: &[u8], ecc_len: usize, out: &mut [u8]) {
        // generator g(x) = prod (x - alpha^i), highest degree first
        let mut g = [0u8; MAX_ECC + 1];
        g[0] = 1;
        for i in 0..ecc_len {
            let r = pow_alpha(i);
            for j in (1..=i + 1).rev() {
                g[j] ^= mul(g[j - 1], r);
            }
        }
        let n = data.len() + ecc_len;
        out[..data.len()].copy_from_slice(data);
        out[data.len()..n].fill(0);
        let mut rem = [0u8; MAX_ECC];
        for &d in data {
            let f = d ^ rem[0];
            rem.copy_within(1..ecc_len, 0);
            rem[ecc_len - 1] = 0;
            for j in 0..ecc_len {
                rem[j] ^= mul(g[j + 1], f);
            }
        }
        out[data.len()..n].copy_from_slice(&rem[..ecc_len]);
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn tables_are_consistent() {
        for a in 1..=255u8 {
            assert_eq!(EXP[LOG[a as usize] as usize], a);
            assert_eq!(mul(a, div(1, a)), 1);
        }
    }

    #[test]
    fn corrects_up_to_half_the_ecc() {
        let mut rng = Rng(99);
        for round in 0..3000 {
            let ecc_len = [7, 10, 13, 15, 17, 18, 20, 22, 24, 26, 28, 30][round % 12];
            let dlen = 1 + (rng.next() % (255 - ecc_len as u64)) as usize;
            let data: [u8; 255] = core::array::from_fn(|_| rng.next() as u8);
            let mut cw = [0u8; 255];
            encode(&data[..dlen], ecc_len, &mut cw);
            let n = dlen + ecc_len;
            let good = cw;
            let errors = (rng.next() % (ecc_len as u64 / 2 + 1)) as usize;
            let mut hit = [false; 255];
            let mut made = 0;
            while made < errors {
                let p = (rng.next() % n as u64) as usize;
                if hit[p] {
                    continue;
                }
                hit[p] = true;
                cw[p] ^= 1 + (rng.next() % 255) as u8;
                made += 1;
            }
            let fixed = correct(&mut cw[..n], ecc_len, ecc_len).unwrap();
            assert_eq!(fixed, errors, "round {round}");
            assert_eq!(&cw[..n], &good[..n], "round {round}");
        }
    }

    #[test]
    fn too_many_errors_never_returns_a_non_codeword() {
        let mut rng = Rng(7);
        // [ecc_len] -> (trials, rejected)
        let mut stats = [(0u32, 0u32); 4];
        for round in 0..4000 {
            let k = round % 4;
            let ecc_len = [7, 10, 18, 30][k];
            let dlen = 20;
            let data: [u8; 20] = core::array::from_fn(|_| rng.next() as u8);
            let mut cw = [0u8; 255];
            encode(&data, ecc_len, &mut cw);
            let n = dlen + ecc_len;
            // t+1 .. t+4 errors at distinct positions
            let errors = ecc_len / 2 + 1 + (round / 4) % 4;
            let mut hit = [false; 255];
            let mut made = 0;
            while made < errors {
                let p = (rng.next() % n as u64) as usize;
                if !hit[p] {
                    hit[p] = true;
                    cw[p] ^= 1 + (rng.next() % 255) as u8;
                    made += 1;
                }
            }
            stats[k].0 += 1;
            match correct(&mut cw[..n], ecc_len, ecc_len) {
                Err(_) => stats[k].1 += 1,
                Ok(_) => {
                    // a miscorrection is possible but must be a codeword
                    let mut re = [0u8; 255];
                    encode(&cw[..dlen], ecc_len, &mut re);
                    assert_eq!(&re[..n], &cw[..n]);
                }
            }
        }
        extern crate std;
        std::println!("{stats:?}");
        // short codes miscorrect more often; QR protects them with p
        // misdecode-protection codewords (see decode.rs)
        assert!(stats[2].1 * 100 >= stats[2].0 * 99, "{stats:?}");
        assert!(stats[3].1 * 1000 >= stats[3].0 * 999, "{stats:?}");
    }

    #[test]
    fn max_errors_limits_correction() {
        let data = [0x40u8, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC];
        let mut cw = [0u8; 255];
        encode(&data, 10, &mut cw);
        let n = data.len() + 10;
        let good = cw;
        cw[0] ^= 1;
        cw[3] ^= 2;
        cw[5] ^= 3;
        assert_eq!(correct(&mut cw[..n], 10, 2), Err(Error::TooManyErrors));
        assert_eq!(correct(&mut cw[..n], 10, 4), Ok(3));
        assert_eq!(&cw[..n], &good[..n]);
    }

    #[test]
    fn clean_block_needs_no_work() {
        let mut cw = [0u8; 255];
        encode(b"hello", 7, &mut cw);
        assert_eq!(correct(&mut cw[..12], 7, 3), Ok(0));
        assert_eq!(correct(&mut cw[..12], 0, 3), Err(Error::BadLength));
    }
}
