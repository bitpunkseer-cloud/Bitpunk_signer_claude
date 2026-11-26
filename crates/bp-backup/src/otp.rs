//! One-time passwords (M11-7, decision 8): HOTP (RFC 4226) and TOTP
//! (RFC 6238) with HMAC-SHA1, -SHA256 or -SHA512, keys in Base32
//! (RFC 4648) and `otpauth://` URIs (the key-URI format authenticator
//! apps use).

use bp_crypto::hmac::{HmacSha256, HmacSha512};
use bp_crypto::secret::wipe;
use bp_crypto::sha1::HmacSha1;

/// Longest key kept (bytes).
pub const MAX_SECRET: usize = 64;
/// Longest label kept (printable ASCII).
pub const MAX_LABEL: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

/// The HOTP value of `counter` with `digits` digits (6 to 8).
pub fn hotp(key: &[u8], counter: u64, digits: u8, alg: Algorithm) -> u32 {
    let msg = counter.to_be_bytes();
    let mut mac = [0u8; 64];
    let n = match alg {
        Algorithm::Sha1 => {
            mac[..20].copy_from_slice(&HmacSha1::mac(key, &msg));
            20
        }
        Algorithm::Sha256 => {
            mac[..32].copy_from_slice(&HmacSha256::mac(key, &msg));
            32
        }
        Algorithm::Sha512 => {
            mac.copy_from_slice(&HmacSha512::mac(key, &msg));
            64
        }
    };
    // dynamic truncation (RFC 4226 section 5.3)
    let off = (mac[n - 1] & 0x0F) as usize;
    let bin = u32::from_be_bytes([mac[off] & 0x7F, mac[off + 1], mac[off + 2], mac[off + 3]]);
    wipe(&mut mac);
    bin % 10u32.pow(digits.clamp(6, 8) as u32)
}

/// The TOTP value at `unix_time` (seconds) for steps of `period` seconds.
pub fn totp(key: &[u8], unix_time: u64, period: u32, digits: u8, alg: Algorithm) -> u32 {
    hotp(key, unix_time / period.max(1) as u64, digits, alg)
}

/// Decode Base32 (RFC 4648 alphabet, any case; spaces, hyphens and `=`
/// padding ignored). `None` on another character or a key too long.
pub fn base32_decode(text: &str, out: &mut [u8]) -> Option<usize> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut n = 0usize;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            b' ' | b'-' | b'=' => continue,
            _ => return None,
        };
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(n)? = (acc >> bits) as u8;
            n += 1;
            acc &= (1 << bits) - 1;
        }
    }
    Some(n)
}

/// A key's counter or time step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpKind {
    Totp { period: u32 },
    Hotp { counter: u64 },
}

/// An authenticator key: kind, algorithm, digits, label and secret.
#[derive(Clone)]
pub struct OtpKey {
    pub kind: OtpKind,
    pub alg: Algorithm,
    pub digits: u8,
    secret: [u8; MAX_SECRET],
    secret_len: u8,
    label: [u8; MAX_LABEL],
    label_len: u8,
}

impl Drop for OtpKey {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

impl PartialEq for OtpKey {
    fn eq(&self, o: &OtpKey) -> bool {
        self.alg == o.alg
            && self.digits == o.digits
            && self.secret() == o.secret()
            && self.label() == o.label()
    }
}

/// Why a key was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Not an `otpauth://totp/` or `otpauth://hotp/` URI.
    NotOtpauth,
    /// No `secret`, or it is not Base32.
    Secret,
    /// The key is too short (under 10 bytes, 80 bits) or too long.
    SecretLength,
    /// Digits other than 6 to 8, an unknown algorithm, a period of 0, an
    /// HOTP key without a counter.
    Parameter,
}

impl OtpKey {
    /// A key from its parts; the label is kept as printable ASCII (other
    /// characters become `?`), cut at 40.
    pub fn new(
        kind: OtpKind,
        alg: Algorithm,
        digits: u8,
        secret: &[u8],
        label: &[u8],
    ) -> Result<OtpKey, KeyError> {
        if !(10..=MAX_SECRET).contains(&secret.len()) {
            return Err(KeyError::SecretLength);
        }
        if !(6..=8).contains(&digits) || matches!(kind, OtpKind::Totp { period: 0 }) {
            return Err(KeyError::Parameter);
        }
        let mut k = OtpKey {
            kind,
            alg,
            digits,
            secret: [0; MAX_SECRET],
            secret_len: secret.len() as u8,
            label: [0; MAX_LABEL],
            label_len: 0,
        };
        k.secret[..secret.len()].copy_from_slice(secret);
        k.set_label(label);
        Ok(k)
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret[..self.secret_len as usize]
    }

    pub fn label(&self) -> &str {
        core::str::from_utf8(&self.label[..self.label_len as usize]).unwrap_or("")
    }

    pub fn set_label(&mut self, label: &[u8]) {
        let n = label.len().min(MAX_LABEL);
        for (d, &c) in self.label.iter_mut().zip(&label[..n]) {
            *d = if (32..=126).contains(&c) { c } else { b'?' };
        }
        self.label_len = n as u8;
    }

    /// The code now (TOTP: at `unix_time`; HOTP: at its counter).
    pub fn code(&self, unix_time: u64) -> u32 {
        match self.kind {
            OtpKind::Totp { period } => totp(self.secret(), unix_time, period, self.digits, self.alg),
            OtpKind::Hotp { counter } => hotp(self.secret(), counter, self.digits, self.alg),
        }
    }

    /// Read an `otpauth://` URI.
    pub fn from_uri(uri: &str) -> Result<OtpKey, KeyError> {
        let rest = strip_prefix_ci(uri.trim(), "otpauth://").ok_or(KeyError::NotOtpauth)?;
        let (kind_name, rest) = rest.split_once('/').ok_or(KeyError::NotOtpauth)?;
        let totp = kind_name.eq_ignore_ascii_case("totp");
        if !totp && !kind_name.eq_ignore_ascii_case("hotp") {
            return Err(KeyError::NotOtpauth);
        }
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut secret = [0u8; MAX_SECRET + 8];
        let mut secret_len = None;
        let (mut alg, mut digits, mut period, mut counter) = (Algorithm::Sha1, 6u8, 30u32, None);
        let mut issuer = [0u8; MAX_LABEL];
        let mut issuer_len = 0;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let mut dec = [0u8; 160];
            let dn = percent_decode(v, &mut dec);
            let v = core::str::from_utf8(&dec[..dn]).unwrap_or("");
            match k {
                "secret" => secret_len = Some(base32_decode(v, &mut secret).ok_or(KeyError::Secret)?),
                "algorithm" => {
                    alg = match v {
                        _ if v.eq_ignore_ascii_case("SHA1") => Algorithm::Sha1,
                        _ if v.eq_ignore_ascii_case("SHA256") => Algorithm::Sha256,
                        _ if v.eq_ignore_ascii_case("SHA512") => Algorithm::Sha512,
                        _ => return Err(KeyError::Parameter),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| KeyError::Parameter)?,
                "period" => period = v.parse().map_err(|_| KeyError::Parameter)?,
                "counter" => counter = Some(v.parse::<u64>().map_err(|_| KeyError::Parameter)?),
                "issuer" => {
                    issuer_len = dn.min(MAX_LABEL);
                    issuer[..issuer_len].copy_from_slice(&dec[..issuer_len]);
                }
                _ => {}
            }
            wipe(&mut dec);
        }
        let n = secret_len.ok_or(KeyError::Secret)?;
        let kind = if totp {
            OtpKind::Totp { period }
        } else {
            OtpKind::Hotp {
                counter: counter.ok_or(KeyError::Parameter)?,
            }
        };
        // the label: "Issuer:account"; the issuer parameter when the path
        // has none
        let mut lab = [0u8; 2 * MAX_LABEL + 1];
        let mut ln = percent_decode(label, &mut lab[..MAX_LABEL]);
        if issuer_len > 0 && !lab[..ln].contains(&b':') {
            let mut both = [0u8; 2 * MAX_LABEL + 1];
            both[..issuer_len].copy_from_slice(&issuer[..issuer_len]);
            both[issuer_len] = b':';
            both[issuer_len + 1..issuer_len + 1 + ln].copy_from_slice(&lab[..ln]);
            ln += issuer_len + 1;
            lab = both;
        }
        let key = OtpKey::new(kind, alg, digits, &secret[..n], &lab[..ln]);
        wipe(&mut secret);
        key
    }

    /// The vault form: kind, algorithm, digits, period or counter, label,
    /// secret.
    pub fn encode(&self, out: &mut [u8; 2 + 1 + 8 + 1 + MAX_LABEL + 1 + MAX_SECRET]) -> usize {
        let (k, v) = match self.kind {
            OtpKind::Totp { period } => (0u8, period as u64),
            OtpKind::Hotp { counter } => (1u8, counter),
        };
        out[0] = k;
        out[1] = self.alg as u8;
        out[2] = self.digits;
        out[3..11].copy_from_slice(&v.to_be_bytes());
        let l = self.label_len as usize;
        out[11] = l as u8;
        out[12..12 + l].copy_from_slice(&self.label[..l]);
        let s = self.secret_len as usize;
        out[12 + l] = s as u8;
        out[13 + l..13 + l + s].copy_from_slice(self.secret());
        13 + l + s
    }

    /// Read the vault form.
    pub fn decode(d: &[u8]) -> Option<OtpKey> {
        let v = u64::from_be_bytes(d.get(3..11)?.try_into().ok()?);
        let kind = match *d.first()? {
            0 => OtpKind::Totp {
                period: u32::try_from(v).ok()?,
            },
            1 => OtpKind::Hotp { counter: v },
            _ => return None,
        };
        let alg = [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512]
            .get(*d.get(1)? as usize)
            .copied()?;
        let l = *d.get(11)? as usize;
        let label = d.get(12..12 + l)?;
        let s = *d.get(12 + l)? as usize;
        let secret = d.get(13 + l..13 + l + s)?;
        if d.len() != 13 + l + s || l > MAX_LABEL || label.iter().any(|&c| !(32..=126).contains(&c)) {
            return None;
        }
        OtpKey::new(kind, alg, *d.get(2)?, secret, label).ok()
    }
}

/// Seconds since 1970 of a UTC date and time; `None` if not a real one or
/// outside 2024–2099 (the clock is typed by hand).
pub fn unix_time(year: u32, month: u32, day: u32, hour: u32, minute: u32) -> Option<u64> {
    if !(2024..=2099).contains(&year) || !(1..=12).contains(&month) || hour > 23 || minute > 59 || day == 0 {
        return None;
    }
    let days = days_from_civil(year as i64, month, day);
    (civil_from_days(days) == (year, month, day))
        .then(|| days as u64 * 86_400 + hour as u64 * 3600 + minute as u64 * 60)
}

/// (year, month, day, hour, minute, second) of seconds since 1970.
pub fn utc(t: u64) -> (u32, u32, u32, u32, u32, u32) {
    let (y, m, d) = civil_from_days((t / 86_400) as i64);
    let s = t % 86_400;
    (y, m, d, (s / 3600) as u32, (s / 60 % 60) as u32, (s % 60) as u32)
}

// Howard Hinnant's civil-date algorithms (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (u32, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = (yoe + era * 400) as u32 + (m <= 2) as u32;
    (y, m, d)
}

fn strip_prefix_ci<'a>(s: &'a str, p: &str) -> Option<&'a str> {
    (s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p)).then(|| &s[p.len()..])
}

/// `%XX` and `+` decoded into `out`; returns the length (cut at its end).
fn percent_decode(s: &str, out: &mut [u8]) -> usize {
    let b = s.as_bytes();
    let (mut i, mut n) = (0, 0);
    while i < b.len() && n < out.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        out[n] = match b[i] {
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    i += 2;
                    (h * 16 + l) as u8
                }
                _ => b'%',
            },
            b'+' => b' ',
            c => c,
        };
        i += 1;
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4226_hotp() {
        let key = b"12345678901234567890";
        let want = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (c, w) in want.iter().enumerate() {
            assert_eq!(hotp(key, c as u64, 6, Algorithm::Sha1), *w, "counter {c}");
        }
    }

    #[test]
    fn rfc_6238_totp() {
        let k1 = b"12345678901234567890";
        let k256 = b"12345678901234567890123456789012";
        let k512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let rows: [(u64, u32, u32, u32); 6] = [
            (59, 94287082, 46119246, 90693936),
            (1111111109, 7081804, 68084774, 25091201),
            (1111111111, 14050471, 67062674, 99943326),
            (1234567890, 89005924, 91819424, 93441116),
            (2000000000, 69279037, 90698825, 38618901),
            (20000000000, 65353130, 77737706, 47863826),
        ];
        for (t, a, b, c) in rows {
            assert_eq!(totp(k1, t, 30, 8, Algorithm::Sha1), a, "{t}");
            assert_eq!(totp(k256, t, 30, 8, Algorithm::Sha256), b, "{t}");
            assert_eq!(totp(k512, t, 30, 8, Algorithm::Sha512), c, "{t}");
        }
    }

    #[test]
    fn rfc_4648_base32() {
        let mut out = [0u8; 16];
        for (text, want) in [
            ("", &b""[..]),
            ("MY======", b"f"),
            ("MZXQ====", b"fo"),
            ("MZXW6===", b"foo"),
            ("MZXW6YQ=", b"foob"),
            ("MZXW6YTB", b"fooba"),
            ("MZXW6YTBOI======", b"foobar"),
            ("mzxw 6ytb-oi", b"foobar"),
        ] {
            let n = base32_decode(text, &mut out).unwrap();
            assert_eq!(&out[..n], want, "{text}");
        }
        assert_eq!(base32_decode("MZXW1", &mut out), None, "1 is not Base32");
        assert_eq!(
            base32_decode("MZXW6YTBOIMZXW6YTBOIMZXW6YTBOI", &mut out),
            None,
            "too long"
        );
    }

    #[test]
    fn otpauth_uris() {
        // the key-URI format's example: a 10-byte key, the least taken
        let k = OtpKey::from_uri(
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        assert_eq!(k.label(), "Example:alice@google.com");
        assert_eq!(k.secret(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(
            OtpKey::new(OtpKind::Totp { period: 30 }, Algorithm::Sha1, 6, &[1; 9], b"x").err(),
            Some(KeyError::SecretLength)
        );
        let k = OtpKey::from_uri(
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
        )
        .unwrap();
        assert_eq!(k.label(), "ACME Co:john.doe@email.com");
        assert_eq!(k.kind, OtpKind::Totp { period: 30 });
        assert_eq!((k.alg, k.digits, k.secret().len()), (Algorithm::Sha1, 6, 20));
        // RFC 6238's key as a URI: the code matches
        let k =
            OtpKey::from_uri("OTPAUTH://totp/rfc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8").unwrap();
        assert_eq!(k.code(59), 94287082);
        // the issuer parameter becomes the label's front
        let k = OtpKey::from_uri(
            "otpauth://hotp/bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=3&issuer=Bank",
        )
        .unwrap();
        assert_eq!(k.label(), "Bank:bob");
        assert_eq!(k.code(0), 969429);
        // SHA-256, 8 digits, 60 s
        let k = OtpKey::from_uri(
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(k.kind, OtpKind::Totp { period: 60 });
        assert_eq!(
            k.code(59 * 2),
            totp(b"12345678901234567890123456789012", 59, 30, 8, Algorithm::Sha256)
        );
        // refused
        for (uri, e) in [
            ("https://example.com", KeyError::NotOtpauth),
            ("otpauth://sms/x?secret=GEZDGNBV", KeyError::NotOtpauth),
            ("otpauth://totp/x", KeyError::Secret),
            ("otpauth://totp/x?secret=GEZDG!", KeyError::Secret),
            (
                "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=9",
                KeyError::Parameter,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
                KeyError::Parameter,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=0",
                KeyError::Parameter,
            ),
            (
                "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                KeyError::Parameter,
            ),
        ] {
            assert_eq!(OtpKey::from_uri(uri).err(), Some(e), "{uri}");
        }
    }

    #[test]
    fn the_vault_form_round_trips_and_refuses_garbage() {
        let k = OtpKey::from_uri("otpauth://hotp/Bank:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=7")
            .unwrap();
        let mut b = [0u8; 2 + 1 + 8 + 1 + MAX_LABEL + 1 + MAX_SECRET];
        let n = k.encode(&mut b);
        let back = OtpKey::decode(&b[..n]).unwrap();
        assert!(back == k);
        assert_eq!(back.kind, OtpKind::Hotp { counter: 7 });
        for cut in 0..n {
            assert!(OtpKey::decode(&b[..cut]).is_none(), "cut at {cut}");
        }
        let mut bad = b;
        bad[0] = 2;
        assert!(OtpKey::decode(&bad[..n]).is_none());
        let mut bad = b;
        bad[1] = 3;
        assert!(OtpKey::decode(&bad[..n]).is_none());
    }

    #[test]
    fn dates_typed_by_hand() {
        // RFC 6238's test times
        assert_eq!(utc(1_111_111_109), (2005, 3, 18, 1, 58, 29));
        assert_eq!(utc(2_000_000_000), (2033, 5, 18, 3, 33, 20));
        assert_eq!(unix_time(2033, 5, 18, 3, 33), Some(2_000_000_000 - 20));
        assert_eq!(unix_time(2024, 2, 29, 0, 0), Some(1_709_164_800));
        assert_eq!(unix_time(2026, 11, 26, 12, 0), Some(1_795_694_400));
        for bad in [
            (2025, 2, 29, 0, 0),
            (2026, 13, 1, 0, 0),
            (2026, 4, 31, 0, 0),
            (2023, 1, 1, 0, 0),
            (2026, 1, 1, 24, 0),
            (2026, 1, 0, 0, 0),
        ] {
            assert_eq!(unix_time(bad.0, bad.1, bad.2, bad.3, bad.4), None, "{bad:?}");
        }
        for t in (1_704_067_200..4_102_444_800u64).step_by(86_400 * 7 + 3601) {
            let (y, m, d, h, mi, s) = utc(t);
            assert_eq!(unix_time(y, m, d, h, mi).unwrap() + s as u64, t);
        }
    }

    #[test]
    fn fuzz_uris_never_panic() {
        let mut seed = 99u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        let base = b"otpauth://totp/A%2:b?secret=GEZDGNBVGY3TQOJQ&digits=6&period=30&issuer=%ZZ%";
        for _ in 0..5000 {
            let mut s = *base;
            for _ in 0..4 {
                let i = next() as usize % s.len();
                s[i] = (next() % 128) as u8;
            }
            if let Ok(text) = core::str::from_utf8(&s[..(next() as usize % s.len())]) {
                let _ = OtpKey::from_uri(text);
            }
        }
    }
}
