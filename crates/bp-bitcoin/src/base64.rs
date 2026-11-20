//! RFC 4648 Base64 (standard alphabet, `=` padding), as PSBTs are shared.
//! Allocation-free.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BufferTooSmall,
    /// A character outside the alphabet, bad padding or length.
    Invalid,
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let need = data.len().div_ceil(3) * 4;
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    for (i, chunk) in data.chunks(3).enumerate() {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let v = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        let o = &mut out[i * 4..i * 4 + 4];
        o[0] = ALPHABET[(v >> 18) as usize & 63];
        o[1] = ALPHABET[(v >> 12) as usize & 63];
        o[2] = if chunk.len() > 1 {
            ALPHABET[(v >> 6) as usize & 63]
        } else {
            b'='
        };
        o[3] = if chunk.len() > 2 {
            ALPHABET[v as usize & 63]
        } else {
            b'='
        };
    }
    Ok(need)
}

fn value(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// Decode padded or unpadded Base64; returns the byte count.
pub fn decode(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let body = text
        .strip_suffix(b"==")
        .or_else(|| text.strip_suffix(b"="))
        .unwrap_or(text);
    if body.len() % 4 == 1 || (body.len() != text.len() && !text.len().is_multiple_of(4)) {
        return Err(Error::Invalid);
    }
    let mut n = 0;
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in body {
        acc = (acc << 6) | value(c).ok_or(Error::Invalid)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(n).ok_or(Error::BufferTooSmall)? = (acc >> bits) as u8;
            n += 1;
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err(Error::Invalid); // non-canonical trailing bits
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases: [(&[u8], &[u8]); 7] = [
            (b"", b""),
            (b"f", b"Zg=="),
            (b"fo", b"Zm8="),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg=="),
            (b"fooba", b"Zm9vYmE="),
            (b"foobar", b"Zm9vYmFy"),
        ];
        for (raw, enc) in cases {
            let mut out = [0u8; 16];
            let n = encode(raw, &mut out).unwrap();
            assert_eq!(&out[..n], enc);
            let mut back = [0u8; 16];
            let m = decode(enc, &mut back).unwrap();
            assert_eq!(&back[..m], raw);
        }
        let mut out = [0u8; 16];
        assert_eq!(decode(b"Zm9vYmE", &mut out), Ok(5)); // unpadded
        assert_eq!(decode(b"Zm9v!", &mut out), Err(Error::Invalid));
        assert_eq!(decode(b"Z", &mut out), Err(Error::Invalid));
        assert_eq!(decode(b"Zh==", &mut out), Err(Error::Invalid)); // stray bits
    }
}
