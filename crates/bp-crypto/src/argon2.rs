//! Argon2id (RFC 9106, version 0x13): the memory-hard key derivation that
//! turns a PIN into a key (M10). No heap: the caller lends the memory as
//! 1 KiB blocks, and it is wiped before returning. Lanes are computed one
//! after another (same result as parallel lanes).

use crate::blake2b::{wipe_u64, Blake2b};
use crate::secret::wipe;

/// One Argon2 memory block: 1024 bytes as 128 little-endian words.
pub type Block = [u64; 128];

pub const VERSION: u32 = 0x13;
const ARGON2ID: u32 = 2;
const SYNC_POINTS: u32 = 4;
const ADDRESSES_IN_BLOCK: u32 = 128;

/// Cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Memory in KiB (= blocks); at least 8 per lane.
    pub m_kib: u32,
    /// Passes over the memory, at least 1.
    pub t: u32,
    /// Lanes, at least 1.
    pub p: u32,
}

impl Params {
    /// Blocks actually used: m rounded down to a multiple of 4 lanes' segments.
    pub fn blocks(&self) -> usize {
        let q = self.m_kib / (SYNC_POINTS * self.p) * SYNC_POINTS;
        (q * self.p) as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Parameters outside RFC 9106 (t < 1, p < 1, m < 8p, salt < 8 bytes,
    /// tag < 4 bytes).
    Params,
    /// The memory lent holds fewer blocks than the parameters need.
    Memory,
}

fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// H' (variable-length BLAKE2b, RFC 9106 3.3) over the concatenated parts.
fn hprime(out: &mut [u8], parts: &[&[u8]]) {
    let t = out.len() as u32;
    if out.len() <= 64 {
        let mut h = Blake2b::new(out.len());
        h.update(&le32(t));
        for p in parts {
            h.update(p);
        }
        h.finalize(out);
        return;
    }
    let mut v = [0u8; 64];
    let mut h = Blake2b::new(64);
    h.update(&le32(t));
    for p in parts {
        h.update(p);
    }
    h.finalize(&mut v);
    out[..32].copy_from_slice(&v[..32]);
    let mut pos = 32;
    let mut left = out.len() - 32;
    while left > 64 {
        let prev = v;
        Blake2b::digest(&mut v, &prev);
        out[pos..pos + 32].copy_from_slice(&v[..32]);
        pos += 32;
        left -= 32;
    }
    let prev = v;
    let mut last = [0u8; 64];
    Blake2b::digest(&mut last[..left], &prev);
    out[pos..pos + left].copy_from_slice(&last[..left]);
    wipe(&mut v);
    wipe(&mut last);
}

#[inline(always)]
fn fbla(x: u64, y: u64) -> u64 {
    // x + y + 2 * lo32(x) * lo32(y)
    let m = (x & 0xFFFF_FFFF).wrapping_mul(y & 0xFFFF_FFFF);
    x.wrapping_add(y).wrapping_add(m.wrapping_mul(2))
}

#[inline(always)]
fn gb(v: &mut Block, a: usize, b: usize, c: usize, d: usize) {
    v[a] = fbla(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = fbla(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = fbla(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = fbla(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The BLAKE2b-round permutation P on 16 words picked by `i`.
#[inline(always)]
fn permute(v: &mut Block, i: &[usize; 16]) {
    gb(v, i[0], i[4], i[8], i[12]);
    gb(v, i[1], i[5], i[9], i[13]);
    gb(v, i[2], i[6], i[10], i[14]);
    gb(v, i[3], i[7], i[11], i[15]);
    gb(v, i[0], i[5], i[10], i[15]);
    gb(v, i[1], i[6], i[11], i[12]);
    gb(v, i[2], i[7], i[8], i[13]);
    gb(v, i[3], i[4], i[9], i[14]);
}

/// The compression G(x, y) into `out` (xor-ed into it when `xor`).
fn fill_block(x: &Block, y: &Block, out: &mut Block, xor: bool) {
    let mut r = [0u64; 128];
    for k in 0..128 {
        r[k] = x[k] ^ y[k];
    }
    let mut z = r;
    for row in 0..8 {
        let b = row * 16;
        let idx: [usize; 16] = core::array::from_fn(|k| b + k);
        permute(&mut z, &idx);
    }
    for col in 0..8 {
        let b = col * 2;
        let idx: [usize; 16] = core::array::from_fn(|k| b + (k / 2) * 16 + (k % 2));
        permute(&mut z, &idx);
    }
    for k in 0..128 {
        let v = z[k] ^ r[k];
        out[k] = if xor { out[k] ^ v } else { v };
    }
    wipe_u64(&mut r);
    wipe_u64(&mut z);
}

fn block_from_bytes(b: &[u8; 1024]) -> Block {
    core::array::from_fn(|k| {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[k * 8..k * 8 + 8]);
        u64::from_le_bytes(w)
    })
}

/// Argon2id: derive `out` (4 bytes or more) from `password` and `salt`
/// (8 bytes or more), with an optional `secret` key and associated data
/// `ad`. `memory` must hold `params.blocks()` blocks or more.
#[allow(clippy::too_many_arguments)]
pub fn argon2id(
    params: Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    memory: &mut [Block],
    out: &mut [u8],
) -> Result<(), Error> {
    let Params { m_kib, t, p } = params;
    if t < 1 || p < 1 || m_kib < 8 * p || salt.len() < 8 || out.len() < 4 {
        return Err(Error::Params);
    }
    let blocks = params.blocks();
    if memory.len() < blocks {
        return Err(Error::Memory);
    }
    let memory = &mut memory[..blocks];
    let lane_len = (blocks as u32) / p;
    let seg_len = lane_len / SYNC_POINTS;

    // H0
    let mut h0 = [0u8; 72];
    {
        let mut h = Blake2b::new(64);
        for v in [p, out.len() as u32, m_kib, t, VERSION, ARGON2ID] {
            h.update(&le32(v));
        }
        for part in [password, salt, secret, ad] {
            h.update(&le32(part.len() as u32));
            h.update(part);
        }
        h.finalize(&mut h0[..64]);
    }
    // the first two blocks of each lane
    let mut bytes = [0u8; 1024];
    for l in 0..p {
        for j in 0..2u32 {
            h0[64..68].copy_from_slice(&le32(j));
            h0[68..72].copy_from_slice(&le32(l));
            hprime(&mut bytes, &[&h0]);
            memory[(l * lane_len + j) as usize] = block_from_bytes(&bytes);
        }
    }
    wipe(&mut bytes);
    wipe(&mut h0);

    let zero: Block = [0; 128];
    let mut input: Block = [0; 128];
    let mut address: Block = [0; 128];
    let mut tmp: Block = [0; 128];
    for pass in 0..t {
        for slice in 0..SYNC_POINTS {
            for lane in 0..p {
                let independent = pass == 0 && slice < 2;
                if independent {
                    input = [0; 128];
                    input[0] = pass as u64;
                    input[1] = lane as u64;
                    input[2] = slice as u64;
                    input[3] = blocks as u64;
                    input[4] = t as u64;
                    input[5] = ARGON2ID as u64;
                }
                let mut start = 0u32;
                if pass == 0 && slice == 0 {
                    start = 2;
                    if independent {
                        input[6] += 1;
                        fill_block(&zero, &input, &mut address, false);
                        let a = address;
                        fill_block(&zero, &a, &mut address, false);
                    }
                }
                for index in start..seg_len {
                    let cur = lane * lane_len + slice * seg_len + index;
                    let prev = if cur.is_multiple_of(lane_len) {
                        cur + lane_len - 1
                    } else {
                        cur - 1
                    };
                    let rand = if independent {
                        if index.is_multiple_of(ADDRESSES_IN_BLOCK) {
                            input[6] += 1;
                            fill_block(&zero, &input, &mut address, false);
                            let a = address;
                            fill_block(&zero, &a, &mut address, false);
                        }
                        address[(index % ADDRESSES_IN_BLOCK) as usize]
                    } else {
                        memory[prev as usize][0]
                    };
                    let mut ref_lane = ((rand >> 32) % p as u64) as u32;
                    if pass == 0 && slice == 0 {
                        ref_lane = lane;
                    }
                    let same = ref_lane == lane;
                    // RFC 9106 3.4.1.2: the reference area and position
                    let area: u64 = if pass == 0 {
                        if slice == 0 {
                            index as u64 - 1
                        } else if same {
                            (slice * seg_len + index) as u64 - 1
                        } else {
                            (slice * seg_len) as u64 - if index == 0 { 1 } else { 0 }
                        }
                    } else if same {
                        (lane_len - seg_len + index) as u64 - 1
                    } else {
                        (lane_len - seg_len) as u64 - if index == 0 { 1 } else { 0 }
                    };
                    let j1 = rand & 0xFFFF_FFFF;
                    let x = (j1 * j1) >> 32;
                    let rel = area - 1 - ((area * x) >> 32);
                    let start_pos: u64 = if pass == 0 || slice == SYNC_POINTS - 1 {
                        0
                    } else {
                        ((slice + 1) * seg_len) as u64
                    };
                    let ref_index = ((start_pos + rel) % lane_len as u64) as u32;
                    let r = (ref_lane * lane_len + ref_index) as usize;
                    fill_block(&memory[prev as usize], &memory[r], &mut tmp, false);
                    let c = &mut memory[cur as usize];
                    if pass == 0 {
                        *c = tmp;
                    } else {
                        for k in 0..128 {
                            c[k] ^= tmp[k];
                        }
                    }
                }
            }
        }
    }

    // the final block: xor of each lane's last block
    let mut fin = memory[(lane_len - 1) as usize];
    for l in 1..p {
        let b = &memory[(l * lane_len + lane_len - 1) as usize];
        for k in 0..128 {
            fin[k] ^= b[k];
        }
    }
    let mut fb = [0u8; 1024];
    for (k, w) in fin.iter().enumerate() {
        fb[k * 8..k * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    hprime(out, &[&fb]);
    wipe(&mut fb);
    wipe_u64(&mut fin);
    wipe_u64(&mut input);
    wipe_u64(&mut address);
    wipe_u64(&mut tmp);
    for b in memory.iter_mut() {
        wipe_u64(b);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn mem(n: usize) -> Vec<Block> {
        vec![[0u64; 128]; n]
    }

    /// RFC 9106 5.3 (Argon2id test vector).
    #[test]
    fn rfc9106_argon2id_vector() {
        let params = Params {
            m_kib: 32,
            t: 3,
            p: 4,
        };
        let mut out = [0u8; 32];
        argon2id(
            params,
            &[1u8; 32],
            &[2u8; 16],
            &[3u8; 8],
            &[4u8; 12],
            &mut mem(32),
            &mut out,
        )
        .unwrap();
        let want = [
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
            0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
        ];
        assert_eq!(out, want);
    }

    #[test]
    fn matches_the_reference_crate() {
        let mut x = 0x0bad_5eed_dead_beefu64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..24 {
            let p = 1 + (next() % 4) as u32;
            let m_kib = 8 * p + (next() % 200) as u32;
            let t = 1 + (next() % 3) as u32;
            let out_len = 4 + (next() % 100) as usize;
            let pw: Vec<u8> = (0..(next() % 40)).map(|_| next() as u8).collect();
            let salt: Vec<u8> = (0..8 + (next() % 24)).map(|_| next() as u8).collect();
            let params = Params { m_kib, t, p };
            let mut ours = vec![0u8; out_len];
            argon2id(params, &pw, &salt, &[], &[], &mut mem(params.blocks()), &mut ours).unwrap();
            let rp = ::argon2::Params::new(m_kib, t, p, Some(out_len)).unwrap();
            let r = ::argon2::Argon2::new(::argon2::Algorithm::Argon2id, ::argon2::Version::V0x13, rp);
            let mut want = vec![0u8; out_len];
            r.hash_password_into(&pw, &salt, &mut want).unwrap();
            assert_eq!(ours, want, "m {m_kib} t {t} p {p} out {out_len}");
        }
    }

    #[test]
    fn refuses_bad_parameters_and_short_memory() {
        let mut out = [0u8; 32];
        let ok = Params {
            m_kib: 64,
            t: 1,
            p: 1,
        };
        assert_eq!(
            argon2id(ok, b"pw", b"short", &[], &[], &mut mem(64), &mut out),
            Err(Error::Params)
        );
        assert_eq!(
            argon2id(
                Params { t: 0, ..ok },
                b"pw",
                b"saltsalt",
                &[],
                &[],
                &mut mem(64),
                &mut out
            ),
            Err(Error::Params)
        );
        assert_eq!(
            argon2id(
                Params { m_kib: 7, ..ok },
                b"pw",
                b"saltsalt",
                &[],
                &[],
                &mut mem(64),
                &mut out
            ),
            Err(Error::Params)
        );
        assert_eq!(
            argon2id(ok, b"pw", b"saltsalt", &[], &[], &mut mem(63), &mut out),
            Err(Error::Memory)
        );
        assert_eq!(
            argon2id(ok, b"pw", b"saltsalt", &[], &[], &mut mem(64), &mut out[..3]),
            Err(Error::Params)
        );
    }

    #[test]
    fn memory_is_wiped_after_use() {
        let params = Params {
            m_kib: 16,
            t: 1,
            p: 1,
        };
        let mut m = mem(16);
        let mut out = [0u8; 32];
        argon2id(params, b"pin", b"saltsalt", &[], &[], &mut m, &mut out).unwrap();
        assert!(m.iter().all(|b| b.iter().all(|&w| w == 0)));
        assert_ne!(out, [0u8; 32]);
    }
}

#[cfg(test)]
mod timing {
    extern crate std;
    use super::*;

    /// The vault's starting cost (M10 decision 8). Run with
    /// `cargo test --release -p bp-crypto argon2_vault_cost -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn argon2_vault_cost() {
        let params = Params {
            m_kib: 8192,
            t: 3,
            p: 1,
        };
        let mut m = std::vec![[0u64; 128]; params.blocks()];
        let mut out = [0u8; 32];
        let t0 = std::time::Instant::now();
        argon2id(
            params,
            b"correct horse",
            b"vault salt 16 by",
            &[],
            &[],
            &mut m,
            &mut out,
        )
        .unwrap();
        std::println!("Argon2id m=8 MiB t=3 p=1: {:?}", t0.elapsed());
    }
}
