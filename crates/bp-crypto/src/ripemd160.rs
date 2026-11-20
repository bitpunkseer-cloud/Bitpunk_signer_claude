//! RIPEMD-160 (Dobbertin, Bosselaers, Preneel 1996). Used for HASH160.

use crate::secret::wipe;

pub const DIGEST_LEN: usize = 20;
const BLOCK_LEN: usize = 64;

const H0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

// Message word selection, left and right lines.
const RL: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11,
    8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5,
    6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const RR: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1,
    2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7,
    10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
// Rotation amounts.
const SL: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7,
    13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5,
    6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const SR: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15,
    13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9,
    12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];
const KL: [u32; 5] = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
const KR: [u32; 5] = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];

#[inline(always)]
fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j / 16 {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

fn compress(h: &mut [u32; 5], block: &[u8; BLOCK_LEN]) {
    let mut x = [0u32; 16];
    for (i, c) in block.chunks_exact(4).enumerate() {
        x[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    let (mut al, mut bl, mut cl, mut dl, mut el) = (h[0], h[1], h[2], h[3], h[4]);
    let (mut ar, mut br, mut cr, mut dr, mut er) = (h[0], h[1], h[2], h[3], h[4]);
    for j in 0..80 {
        let t = al
            .wrapping_add(f(j, bl, cl, dl))
            .wrapping_add(x[RL[j]])
            .wrapping_add(KL[j / 16])
            .rotate_left(SL[j])
            .wrapping_add(el);
        al = el;
        el = dl;
        dl = cl.rotate_left(10);
        cl = bl;
        bl = t;
        let t = ar
            .wrapping_add(f(79 - j, br, cr, dr))
            .wrapping_add(x[RR[j]])
            .wrapping_add(KR[j / 16])
            .rotate_left(SR[j])
            .wrapping_add(er);
        ar = er;
        er = dr;
        dr = cr.rotate_left(10);
        cr = br;
        br = t;
    }
    let t = h[1].wrapping_add(cl).wrapping_add(dr);
    h[1] = h[2].wrapping_add(dl).wrapping_add(er);
    h[2] = h[3].wrapping_add(el).wrapping_add(ar);
    h[3] = h[4].wrapping_add(al).wrapping_add(br);
    h[4] = h[0].wrapping_add(bl).wrapping_add(cr);
    h[0] = t;
    for v in x.iter_mut() {
        // SAFETY: valid exclusive reference.
        unsafe { core::ptr::write_volatile(v, 0) };
    }
}

#[derive(Clone)]
pub struct Ripemd160 {
    h: [u32; 5],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    total: u64,
}

impl Default for Ripemd160 {
    fn default() -> Self {
        Self::new()
    }
}

impl Ripemd160 {
    pub const fn new() -> Self {
        Self {
            h: H0,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
            total: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_LEN {
                let b = self.buf;
                compress(&mut self.h, &b);
                self.buf_len = 0;
            }
        }
        while data.len() >= BLOCK_LEN {
            let (b, rest) = data.split_at(BLOCK_LEN);
            compress(&mut self.h, b.try_into().expect("64 bytes"));
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.total.wrapping_mul(8);
        let mut pad = [0u8; BLOCK_LEN * 2];
        pad[0] = 0x80;
        let n = if self.buf_len < 56 {
            56 - self.buf_len
        } else {
            120 - self.buf_len
        };
        pad[n..n + 8].copy_from_slice(&bits.to_le_bytes());
        self.update(&pad[..n + 8]);
        let mut out = [0u8; DIGEST_LEN];
        for (c, w) in out.chunks_exact_mut(4).zip(self.h.iter()) {
            c.copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

impl Drop for Ripemd160 {
    fn drop(&mut self) {
        wipe(&mut self.buf);
    }
}
