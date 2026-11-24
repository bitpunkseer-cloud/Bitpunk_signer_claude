//! BIP-85 (2.1.0): deterministic entropy for other wallets from this seed.
//!
//! k = the private key at a fully hardened path under m/83696968';
//! entropy = HMAC-SHA512(key = "bip-entropy-from-k", msg = k), truncated by
//! each application. Applications here: BIP-39 (English 12/18/24 words),
//! HD-seed WIF, XPRV, HEX, and passwords in Base64 and Base85 (decision 8:
//! no DICE). Every buffer holding entropy is wiped.

use crate::bip32::{DerivationPath, KeyVersion, Xpriv, HARDENED, XKEY_LEN};
use crate::bip39::Mnemonic;
use crate::Network;
use bp_crypto::hmac::HmacSha512;
use bp_crypto::secret::wipe;

pub const PURPOSE: u32 = 83_696_968;
/// Longest text an application produces (24 words, an XPRV, 128 hex
/// digits, 86 password characters).
pub const MAX_TEXT: usize = 24 * 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum App {
    /// English mnemonic of 12, 18 or 24 words.
    Bip39 {
        words: u8,
    },
    Wif,
    Xprv,
    /// 16 to 64 bytes, as hex.
    Hex {
        bytes: u8,
    },
    /// 20 to 86 characters.
    PwdBase64 {
        len: u8,
    },
    /// 10 to 80 characters.
    PwdBase85 {
        len: u8,
    },
}

impl App {
    /// Whether the length parameter is in range.
    pub fn valid(self) -> bool {
        match self {
            App::Bip39 { words } => matches!(words, 12 | 18 | 24),
            App::Wif | App::Xprv => true,
            App::Hex { bytes } => (16..=64).contains(&bytes),
            App::PwdBase64 { len } => (20..=86).contains(&len),
            App::PwdBase85 { len } => (10..=80).contains(&len),
        }
    }

    /// The derivation path for `index` (index below 2^31).
    pub fn path(self, index: u32) -> Option<DerivationPath> {
        if index >= HARDENED || !self.valid() {
            return None;
        }
        let h = |v: u32| v | HARDENED;
        let steps: &[u32] = match self {
            App::Bip39 { words } => &[h(PURPOSE), h(39), h(0), h(words as u32), h(index)],
            App::Wif => &[h(PURPOSE), h(2), h(index)],
            App::Xprv => &[h(PURPOSE), h(32), h(index)],
            App::Hex { bytes } => &[h(PURPOSE), h(128_169), h(bytes as u32), h(index)],
            App::PwdBase64 { len } => &[h(PURPOSE), h(707_764), h(len as u32), h(index)],
            App::PwdBase85 { len } => &[h(PURPOSE), h(707_785), h(len as u32), h(index)],
        };
        DerivationPath::from_steps(steps).ok()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Index or length out of range.
    Param,
    /// A derived key is invalid (probability below 2^-127): use the next
    /// index.
    InvalidKey,
}

/// The 64 bytes of entropy at `path` (wiped on drop).
pub struct Entropy(pub [u8; 64]);

impl Drop for Entropy {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

pub fn entropy(master: &Xpriv, path: &DerivationPath) -> Result<Entropy, Error> {
    let child = master.derive_path(path).map_err(|_| Error::InvalidKey)?;
    let mut k = child.secret_key().to_bytes();
    let e = Entropy(HmacSha512::mac(b"bip-entropy-from-k", &k));
    wipe(&mut k);
    Ok(e)
}

/// A derived result.
pub enum Derived {
    Mnemonic(Mnemonic),
    /// Printable text (WIF, XPRV, hex or password) in `text[..len]`.
    Text {
        text: [u8; MAX_TEXT],
        len: usize,
    },
}

impl Derived {
    /// The result as text (words separated by spaces).
    pub fn write_text(&self, out: &mut [u8; MAX_TEXT]) -> usize {
        match self {
            Derived::Mnemonic(m) => {
                let mut n = 0;
                for (i, w) in (0..m.len()).map(|i| m.word(i)).enumerate() {
                    if i > 0 {
                        out[n] = b' ';
                        n += 1;
                    }
                    out[n..n + w.len()].copy_from_slice(w.as_bytes());
                    n += w.len();
                }
                n
            }
            Derived::Text { text, len } => {
                out[..*len].copy_from_slice(&text[..*len]);
                *len
            }
        }
    }
}

impl Drop for Derived {
    fn drop(&mut self) {
        if let Derived::Text { text, .. } = self {
            wipe(text);
        }
    }
}

const B85: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

/// Base85 (RFC 1924 alphabet, as Python's `b85encode`) of 64 bytes: 80
/// characters.
pub fn base85(data: &[u8; 64], out: &mut [u8; 80]) {
    for (g, chunk) in data.chunks(4).enumerate() {
        let mut v = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        for k in (0..5).rev() {
            out[g * 5 + k] = B85[(v % 85) as usize];
            v /= 85;
        }
    }
}

/// Derive `app` at `index` from the master key.
pub fn derive(master: &Xpriv, app: App, index: u32, net: Network) -> Result<Derived, Error> {
    let path = app.path(index).ok_or(Error::Param)?;
    let e = entropy(master, &path)?;
    let mut text = [0u8; MAX_TEXT];
    let len = match app {
        App::Bip39 { words } => {
            let n = match words {
                12 => 16,
                18 => 24,
                _ => 32,
            };
            let m = Mnemonic::from_entropy(&e.0[..n]).map_err(|_| Error::Param)?;
            return Ok(Derived::Mnemonic(m));
        }
        App::Wif => {
            let key: [u8; 32] = e.0[..32].try_into().expect("32");
            let sk = bp_crypto::secp256k1::SecretKey::from_bytes(&key).ok_or(Error::InvalidKey)?;
            let mut w = [0u8; crate::wif::WIF_LEN];
            let n = crate::wif::encode(&sk, net, &mut w);
            text[..n].copy_from_slice(&w[..n]);
            wipe(&mut w);
            n
        }
        App::Xprv => {
            // chain code first, then the key (the reverse of BIP-32)
            let cc: [u8; 32] = e.0[..32].try_into().expect("32");
            let mut key: [u8; 32] = e.0[32..].try_into().expect("32");
            let x = Xpriv::from_parts(&cc, &key).map_err(|_| Error::InvalidKey);
            wipe(&mut key);
            let x = x?;
            let mut s = [0u8; XKEY_LEN];
            let n = x.encode(KeyVersion::X.private(net), &mut s);
            text[..n].copy_from_slice(&s[..n]);
            wipe(&mut s);
            n
        }
        App::Hex { bytes } => {
            for (i, b) in e.0[..bytes as usize].iter().enumerate() {
                text[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
                text[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
            }
            2 * bytes as usize
        }
        App::PwdBase64 { len } => {
            let mut b = [0u8; 88];
            crate::base64::encode(&e.0, &mut b).map_err(|_| Error::Param)?;
            text[..len as usize].copy_from_slice(&b[..len as usize]);
            wipe(&mut b);
            len as usize
        }
        App::PwdBase85 { len } => {
            let mut b = [0u8; 80];
            base85(&e.0, &mut b);
            text[..len as usize].copy_from_slice(&b[..len as usize]);
            wipe(&mut b);
            len as usize
        }
    };
    Ok(Derived::Text { text, len })
}
