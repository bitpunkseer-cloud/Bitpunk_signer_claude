//! Bech32 (BIP-173) and Bech32m (BIP-350), plus SegWit address encoding.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
pub const MAX_LEN: usize = 90;
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Bech32,
    Bech32m,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    InvalidChar,
    MixedCase,
    NoSeparator,
    EmptyHrp,
    InvalidChecksum,
    InvalidPadding,
    InvalidWitnessVersion,
    InvalidProgramLength,
    WrongVariant,
}

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &[u8]) -> impl Iterator<Item = u8> + '_ {
    hrp.iter()
        .map(|c| c >> 5)
        .chain(core::iter::once(0))
        .chain(hrp.iter().map(|c| c & 31))
}

fn constant(v: Variant) -> u32 {
    match v {
        Variant::Bech32 => BECH32_CONST,
        Variant::Bech32m => BECH32M_CONST,
    }
}

/// Encode a lowercase `hrp` and 5-bit `data`; returns the length written.
pub fn encode(hrp: &str, data: &[u8], variant: Variant, out: &mut [u8; MAX_LEN]) -> Result<usize, Error> {
    let h = hrp.as_bytes();
    if h.is_empty() {
        return Err(Error::EmptyHrp);
    }
    if h.len() + 1 + data.len() + 6 > MAX_LEN {
        return Err(Error::InvalidLength);
    }
    if h.iter()
        .any(|&c| !(33..=126).contains(&c) || c.is_ascii_uppercase())
    {
        return Err(Error::InvalidChar);
    }
    let pm = polymod(hrp_expand(h).chain(data.iter().copied()).chain([0u8; 6])) ^ constant(variant);
    let mut n = 0;
    for &c in h {
        out[n] = c;
        n += 1;
    }
    out[n] = b'1';
    n += 1;
    for &d in data {
        out[n] = CHARSET[(d & 31) as usize];
        n += 1;
    }
    for i in 0..6 {
        out[n] = CHARSET[((pm >> (5 * (5 - i))) & 31) as usize];
        n += 1;
    }
    Ok(n)
}

pub struct Decoded {
    hrp: [u8; MAX_LEN],
    hrp_len: usize,
    data: [u8; MAX_LEN],
    data_len: usize,
    pub variant: Variant,
}

impl Decoded {
    pub fn hrp(&self) -> &str {
        core::str::from_utf8(&self.hrp[..self.hrp_len]).unwrap_or("")
    }
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

/// Decode and verify a Bech32 or Bech32m string.
pub fn decode(s: &str) -> Result<Decoded, Error> {
    let b = s.as_bytes();
    if b.len() > MAX_LEN || b.len() < 8 {
        return Err(Error::InvalidLength);
    }
    if b.iter().any(|&c| !(33..=126).contains(&c)) {
        return Err(Error::InvalidChar);
    }
    let lower = b.iter().any(|c| c.is_ascii_lowercase());
    let upper = b.iter().any(|c| c.is_ascii_uppercase());
    if lower && upper {
        return Err(Error::MixedCase);
    }
    let sep = b.iter().rposition(|&c| c == b'1').ok_or(Error::NoSeparator)?;
    if sep == 0 {
        return Err(Error::EmptyHrp);
    }
    if b.len() - sep - 1 < 6 {
        return Err(Error::InvalidLength);
    }
    let mut d = Decoded {
        hrp: [0; MAX_LEN],
        hrp_len: sep,
        data: [0; MAX_LEN],
        data_len: 0,
        variant: Variant::Bech32,
    };
    for (i, &c) in b[..sep].iter().enumerate() {
        d.hrp[i] = c.to_ascii_lowercase();
    }
    let mut vals = [0u8; MAX_LEN];
    let nvals = b.len() - sep - 1;
    for (i, &c) in b[sep + 1..].iter().enumerate() {
        let c = c.to_ascii_lowercase();
        vals[i] = CHARSET.iter().position(|&x| x == c).ok_or(Error::InvalidChar)? as u8;
    }
    let pm = polymod(hrp_expand(&d.hrp[..d.hrp_len]).chain(vals[..nvals].iter().copied()));
    d.variant = match pm {
        BECH32_CONST => Variant::Bech32,
        BECH32M_CONST => Variant::Bech32m,
        _ => return Err(Error::InvalidChecksum),
    };
    d.data_len = nvals - 6;
    d.data[..d.data_len].copy_from_slice(&vals[..d.data_len]);
    Ok(d)
}

/// Regroup bits (e.g. 8 -> 5 with padding, 5 -> 8 without).
pub fn convert_bits(input: &[u8], from: u32, to: u32, pad: bool, out: &mut [u8]) -> Result<usize, Error> {
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut n = 0;
    let maxv = (1u32 << to) - 1;
    for &v in input {
        if (v as u32) >> from != 0 {
            return Err(Error::InvalidChar);
        }
        acc = (acc << from) | v as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            *out.get_mut(n).ok_or(Error::InvalidLength)? = ((acc >> bits) & maxv) as u8;
            n += 1;
        }
    }
    if pad {
        if bits > 0 {
            *out.get_mut(n).ok_or(Error::InvalidLength)? = ((acc << (to - bits)) & maxv) as u8;
            n += 1;
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(Error::InvalidPadding);
    }
    Ok(n)
}

/// Encode a SegWit address (v0: Bech32, v1+: Bech32m).
pub fn encode_segwit(
    hrp: &str,
    version: u8,
    program: &[u8],
    out: &mut [u8; MAX_LEN],
) -> Result<usize, Error> {
    if version > 16 {
        return Err(Error::InvalidWitnessVersion);
    }
    if !(2..=40).contains(&program.len()) || (version == 0 && program.len() != 20 && program.len() != 32) {
        return Err(Error::InvalidProgramLength);
    }
    let mut data = [0u8; 1 + 65];
    data[0] = version;
    let n = convert_bits(program, 8, 5, true, &mut data[1..])?;
    let variant = if version == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };
    encode(hrp, &data[..1 + n], variant, out)
}

pub struct SegwitAddress {
    pub version: u8,
    program: [u8; 40],
    program_len: usize,
}

impl SegwitAddress {
    pub fn program(&self) -> &[u8] {
        &self.program[..self.program_len]
    }

    /// scriptPubKey: OP_n <program>
    pub fn script_pubkey(&self, out: &mut [u8; 42]) -> usize {
        out[0] = if self.version == 0 { 0 } else { 0x50 + self.version };
        out[1] = self.program_len as u8;
        out[2..2 + self.program_len].copy_from_slice(self.program());
        2 + self.program_len
    }
}

/// Decode a SegWit address and check it uses `hrp`.
pub fn decode_segwit(hrp: &str, s: &str) -> Result<SegwitAddress, Error> {
    let d = decode(s)?;
    if d.hrp() != hrp {
        return Err(Error::InvalidChar);
    }
    let data = d.data();
    if data.is_empty() {
        return Err(Error::InvalidLength);
    }
    let version = data[0];
    if version > 16 {
        return Err(Error::InvalidWitnessVersion);
    }
    let expected = if version == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };
    if d.variant != expected {
        return Err(Error::WrongVariant);
    }
    let mut prog = [0u8; 64];
    let n = convert_bits(&data[1..], 5, 8, false, &mut prog)?;
    if !(2..=40).contains(&n) || (version == 0 && n != 20 && n != 32) {
        return Err(Error::InvalidProgramLength);
    }
    let mut a = SegwitAddress {
        version,
        program: [0; 40],
        program_len: n,
    };
    a.program[..n].copy_from_slice(&prog[..n]);
    Ok(a)
}
