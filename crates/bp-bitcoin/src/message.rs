//! Signed messages ("Bitcoin Signed Message"): the message hash, compact
//! recoverable ECDSA signatures and their verification, the message rules
//! the device enforces before signing, and the armored text format.
//!
//! Signing writes the Electrum / Bitcoin Core header (31-34: compressed
//! key) for every single-key address type, as Bitcoin Core, Electrum and
//! Sparrow expect. Verification also accepts the BIP-137 headers (35-38
//! P2SH-P2WPKH, 39-42 P2WPKH) and 27-30 (uncompressed P2PKH) and reports a
//! header that does not match the address type. Taproot addresses use
//! BIP-322 instead.

use crate::addrcheck::{script_pubkey, Target, TargetError, MAX_SPK};
use crate::address::ScriptType;
use crate::{base64, Network};
use bp_crypto::hashes::hash160;
use bp_crypto::secp256k1::ecdsa::{self, Signature};
use bp_crypto::secp256k1::{PublicKey, SecretKey};

pub const MAGIC: &[u8] = b"\x18Bitcoin Signed Message:\n";
/// Longest message the device signs (decision 2).
pub const MAX_MESSAGE: usize = 1000;
pub const MIN_MESSAGE: usize = 2;
/// Base64 of a 65-byte signature.
pub const SIG_B64_LEN: usize = 88;

/// SHA-256d(magic || compact size || message), as Bitcoin Core.
pub fn message_hash(msg: &[u8]) -> [u8; 32] {
    let mut h = bp_crypto::sha256::Sha256::new();
    h.update(MAGIC);
    let n = msg.len();
    match n {
        0..=0xFC => h.update(&[n as u8]),
        0xFD..=0xFFFF => {
            h.update(&[0xFD]);
            h.update(&(n as u16).to_le_bytes());
        }
        _ => {
            h.update(&[0xFE]);
            h.update(&(n as u32).to_le_bytes());
        }
    }
    h.update(msg);
    bp_crypto::sha256::Sha256::digest(&h.finalize())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageError {
    TooShort,
    TooLong,
    /// Anything but printable ASCII and newlines.
    NotPrintable,
    LeadingOrTrailingSpace,
    /// Three spaces in a row (Coldcard's rule: hides text on screen).
    TooManySpaces,
}

/// The rules a message must meet before the device signs it.
pub fn check_message(msg: &[u8]) -> Result<(), MessageError> {
    if msg.len() < MIN_MESSAGE {
        return Err(MessageError::TooShort);
    }
    if msg.len() > MAX_MESSAGE {
        return Err(MessageError::TooLong);
    }
    if !msg.iter().all(|&c| (0x20..0x7F).contains(&c) || c == b'\n') {
        return Err(MessageError::NotPrintable);
    }
    if msg[0] == b' ' || msg[msg.len() - 1] == b' ' {
        return Err(MessageError::LeadingOrTrailingSpace);
    }
    if msg.windows(3).any(|w| w == b"   ") {
        return Err(MessageError::TooManySpaces);
    }
    Ok(())
}

/// Sign `msg` with `sk`: [header 31-34, r, s]. The signature is checked by
/// recovering the public key before it is returned.
pub fn sign(sk: &SecretKey, msg: &[u8]) -> Option<[u8; 65]> {
    let digest = message_hash(msg);
    let (sig, recid) = ecdsa::sign_recoverable(sk, &digest)?;
    if ecdsa::recover(&digest, &sig, recid)? != sk.public_key() {
        return None;
    }
    let mut out = [0u8; 65];
    out[0] = 31 + recid;
    out[1..].copy_from_slice(&sig.to_compact());
    Some(out)
}

/// Base64 of a 65-byte signature (88 characters).
pub fn to_base64(sig: &[u8; 65], out: &mut [u8; SIG_B64_LEN]) -> usize {
    base64::encode(sig, out).expect("88 bytes fit")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The address is not usable (wrong network, multisig, invalid).
    Address(TargetError),
    /// A Taproot address: verified with BIP-322 instead.
    Taproot,
    /// Not Base64 of 65 bytes.
    Encoding,
    /// A header byte outside 27-42.
    Header,
    /// The signature is not this address's for this message.
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    pub script_type: ScriptType,
    /// False when the header names another address type than the address
    /// (still a valid signature by the address's key).
    pub header_matches: bool,
    pub public_key: PublicKey,
}

/// Verify a Base64 compact signature of `msg` by `address`.
pub fn verify(address: &str, net: Network, msg: &[u8], sig_b64: &str) -> Result<Verified, VerifyError> {
    let target = Target::parse(address.trim(), net).map_err(VerifyError::Address)?;
    let st = target.script_type();
    if st == ScriptType::Taproot {
        return Err(VerifyError::Taproot);
    }
    let mut raw = [0u8; 66];
    let n = base64::decode(sig_b64.trim().as_bytes(), &mut raw).map_err(|_| VerifyError::Encoding)?;
    if n != 65 {
        return Err(VerifyError::Encoding);
    }
    let header = raw[0];
    if !(27..=42).contains(&header) {
        return Err(VerifyError::Header);
    }
    let recid = (header - 27) & 3;
    // 0: uncompressed P2PKH, 1: compressed (Electrum: any type),
    // 2: P2SH-P2WPKH, 3: P2WPKH (BIP-137)
    let kind = (header - 27) >> 2;
    let sig = Signature::from_compact(raw[1..65].try_into().expect("64"));
    let pk = ecdsa::recover(&message_hash(msg), &sig, recid).ok_or(VerifyError::Invalid)?;
    let mut spk = [0u8; MAX_SPK];
    let len = if kind == 0 {
        // an uncompressed key only makes P2PKH addresses
        if st != ScriptType::Legacy {
            return Err(VerifyError::Invalid);
        }
        spk[..3].copy_from_slice(&[0x76, 0xA9, 0x14]);
        spk[3..23].copy_from_slice(&hash160(&pk.serialize_uncompressed()));
        spk[23..25].copy_from_slice(&[0x88, 0xAC]);
        25
    } else {
        script_pubkey(&pk, st, &mut spk)
    };
    if &spk[..len] != target.script() {
        return Err(VerifyError::Invalid);
    }
    let header_matches = matches!(
        (kind, st),
        (0 | 1, ScriptType::Legacy) | (1 | 2, ScriptType::NestedSegwit) | (1 | 3, ScriptType::NativeSegwit)
    );
    Ok(Verified {
        script_type: st,
        header_matches,
        public_key: pk,
    })
}

const BEGIN_MSG: &[u8] = b"-----BEGIN BITCOIN SIGNED MESSAGE-----";
const BEGIN_SIG: &[u8] = b"-----BEGIN BITCOIN SIGNATURE-----";
const END_SIG: &[u8] = b"-----END BITCOIN SIGNATURE-----";

/// A message in the armored text format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Armored<'a> {
    pub message: &'a [u8],
    pub address: &'a str,
    pub signature: &'a str,
}

/// Parse
/// ```text
/// -----BEGIN BITCOIN SIGNED MESSAGE-----
/// <message, any number of lines>
/// -----BEGIN BITCOIN SIGNATURE-----
/// <address>
/// <signature>
/// -----END BITCOIN SIGNATURE-----
/// ```
/// The message may contain dashes; its line breaks are `\n` or `\r\n`.
pub fn parse_armored(text: &[u8]) -> Option<Armored<'_>> {
    let t = trim(text);
    let rest = t.strip_prefix(BEGIN_MSG)?;
    let rest = strip_newline(rest)?;
    // the last BEGIN SIGNATURE line ends the message
    let at = find_last(rest, BEGIN_SIG)?;
    let message = strip_trailing_newline(&rest[..at])?;
    let tail = strip_newline(&rest[at + BEGIN_SIG.len()..])?;
    let body = tail.strip_suffix(END_SIG)?;
    let mut words = body.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty());
    let address = core::str::from_utf8(words.next()?).ok()?;
    let signature = core::str::from_utf8(words.next()?).ok()?;
    if words.next().is_some() {
        return None;
    }
    Some(Armored {
        message,
        address,
        signature,
    })
}

fn trim(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let e = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(s, |e| e + 1);
    &b[s..e.max(s)]
}

fn strip_newline(b: &[u8]) -> Option<&[u8]> {
    b.strip_prefix(b"\r\n").or_else(|| b.strip_prefix(b"\n"))
}

fn strip_trailing_newline(b: &[u8]) -> Option<&[u8]> {
    b.strip_suffix(b"\r\n").or_else(|| b.strip_suffix(b"\n"))
}

fn find_last(hay: &[u8], needle: &[u8]) -> Option<usize> {
    (0..=hay.len().checked_sub(needle.len())?)
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_rules() {
        assert_eq!(check_message(b"hi"), Ok(()));
        assert_eq!(check_message(b"two\nlines"), Ok(()));
        assert_eq!(check_message(b"a"), Err(MessageError::TooShort));
        assert_eq!(check_message(&[b'a'; 1001]), Err(MessageError::TooLong));
        assert_eq!(check_message(&[b'a'; 1000]), Ok(()));
        assert_eq!(check_message(b"tab\there"), Err(MessageError::NotPrintable));
        assert_eq!(
            check_message("caf\u{e9}".as_bytes()),
            Err(MessageError::NotPrintable)
        );
        assert_eq!(check_message(b"cr\r\nlf"), Err(MessageError::NotPrintable));
        assert_eq!(check_message(b" lead"), Err(MessageError::LeadingOrTrailingSpace));
        assert_eq!(
            check_message(b"trail "),
            Err(MessageError::LeadingOrTrailingSpace)
        );
        assert_eq!(check_message(b"a   b"), Err(MessageError::TooManySpaces));
        assert_eq!(check_message(b"a  b"), Ok(()));
    }

    #[test]
    fn armored_format() {
        let t = b"-----BEGIN BITCOIN SIGNED MESSAGE-----\nhello\n-- dashes -----\n-----BEGIN BITCOIN SIGNATURE-----\n1Addr\nSIG=\n-----END BITCOIN SIGNATURE-----\n";
        let a = parse_armored(t).unwrap();
        assert_eq!(a.message, b"hello\n-- dashes -----");
        assert_eq!((a.address, a.signature), ("1Addr", "SIG="));
        let crlf = b"-----BEGIN BITCOIN SIGNED MESSAGE-----\r\nhi\r\n-----BEGIN BITCOIN SIGNATURE-----\r\n1Addr\r\nSIG=\r\n-----END BITCOIN SIGNATURE-----";
        assert_eq!(parse_armored(crlf).unwrap().message, b"hi");
        assert!(parse_armored(
            b"-----BEGIN BITCOIN SIGNED MESSAGE-----\nhi\n-----END BITCOIN SIGNATURE-----"
        )
        .is_none());
        let extra = b"-----BEGIN BITCOIN SIGNED MESSAGE-----\nhi\n-----BEGIN BITCOIN SIGNATURE-----\na b c\n-----END BITCOIN SIGNATURE-----";
        assert!(parse_armored(extra).is_none());
    }
}
