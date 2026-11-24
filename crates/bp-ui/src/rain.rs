//! Matrix rain (M9-2): columns of falling bech32 characters on the 64x20
//! grid. Used only where the screen holds no information (boot, screen
//! saver, long calculations — M9-5).
//!
//! The randomness is a small screen-only generator seeded with a constant:
//! it never touches, and is never touched by, seed material (seeds come
//! from dice and coins only).

use crate::font::BODY;
use crate::grid::{x, y, CELL_H, COLS, ROWS};
use crate::theme::{ACCENT, BRIGHT, LINE};
use bp_hal::{Canvas, Rgb};

/// The bech32 character set: the rain is made of Bitcoin address letters.
pub const CHARS: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const TRAIL: usize = 14;

#[derive(Clone, Copy)]
struct Column {
    /// Head position in quarter rows (may start above the screen).
    head: i32,
    /// Quarter rows per step.
    speed: i32,
    len: i32,
    chars: [u8; TRAIL],
}

pub struct Rain {
    cols: [Column; COLS as usize],
    rng: u32,
    elapsed: u32,
}

impl Rain {
    pub fn new() -> Self {
        let mut r = Self {
            cols: [Column {
                head: 0,
                speed: 1,
                len: 8,
                chars: [b'q'; TRAIL],
            }; COLS as usize],
            rng: 0x2545_F491,
            elapsed: 0,
        };
        for i in 0..COLS as usize {
            r.reset(i, true);
        }
        r
    }

    fn next(&mut self) -> u32 {
        // xorshift32: screen effect only, not cryptographic
        let mut v = self.rng;
        v ^= v << 13;
        v ^= v >> 17;
        v ^= v << 5;
        self.rng = v;
        v
    }

    fn reset(&mut self, i: usize, anywhere: bool) {
        let speed = 1 + (self.next() % 4) as i32;
        let len = 6 + (self.next() % (TRAIL as u32 - 6)) as i32;
        let start = if anywhere {
            (self.next() % (ROWS as u32 * 4 * 2)) as i32 - ROWS * 4
        } else {
            -((self.next() % 40) as i32)
        };
        let mut chars = [0u8; TRAIL];
        for c in chars.iter_mut() {
            *c = CHARS[(self.next() % 32) as usize];
        }
        self.cols[i] = Column {
            head: start,
            speed,
            len,
            chars,
        };
    }

    /// Advance by `ms`; one step every 60 ms. Returns true if it moved.
    pub fn tick(&mut self, ms: u32) -> bool {
        self.elapsed += ms;
        let mut moved = false;
        while self.elapsed >= 60 {
            self.elapsed -= 60;
            moved = true;
            for i in 0..COLS as usize {
                self.cols[i].head += self.cols[i].speed;
                if (self.cols[i].head / 4 - self.cols[i].len) > ROWS {
                    self.reset(i, false);
                }
                // the head keeps changing character, like the film's
                if self.next().is_multiple_of(3) {
                    let k = (self.next() % TRAIL as u32) as usize;
                    self.cols[i].chars[k] = CHARS[(self.next() % 32) as usize];
                }
            }
        }
        moved
    }

    /// Draw the rain on rows `top..top + rows` (screen ground already drawn).
    pub fn draw(&self, c: &mut dyn Canvas, top: i32, rows: i32) {
        let mut s = [0u8; 4];
        for (i, col) in self.cols.iter().enumerate() {
            let head_row = col.head / 4;
            for k in 0..col.len {
                let row = head_row - k;
                if row < top || row >= top + rows {
                    continue;
                }
                let ch = col.chars[(k as usize) % TRAIL] as char;
                let (color, a): (Rgb, u8) = if k == 0 {
                    (BRIGHT, 255)
                } else {
                    let fade = 255 - (k * 220 / col.len) as u8;
                    (ACCENT, fade)
                };
                let t = ch.encode_utf8(&mut s);
                let gx = x(i as i32);
                let gy = y(row) + (CELL_H - BODY.height as i32) / 2;
                if a == 255 {
                    BODY.draw(c, gx, gy, t, color);
                } else {
                    // a dimmer copy of the colour stands in for alpha
                    let m = |v: u8, b: u8| ((v as u16 * a as u16 + b as u16 * (255 - a) as u16) / 255) as u8;
                    let faded = Rgb(m(color.0, LINE.0), m(color.1, LINE.1), m(color.2, LINE.2)); // palette: ACCENT faded toward LINE
                    BODY.draw(c, gx, gy, t, faded);
                }
            }
        }
    }
}

impl Default for Rain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rain_is_deterministic_and_uses_address_letters() {
        let mut a = Rain::new();
        let mut b = Rain::new();
        for _ in 0..50 {
            assert_eq!(a.tick(60), b.tick(60));
        }
        for (ca, cb) in a.cols.iter().zip(b.cols.iter()) {
            assert_eq!(ca.head, cb.head);
            assert!(ca.chars.iter().all(|c| CHARS.contains(c)));
        }
    }

    #[test]
    fn columns_come_back_after_falling_off() {
        let mut r = Rain::new();
        for _ in 0..2000 {
            r.tick(60);
        }
        // every column is somewhere sensible
        assert!(r
            .cols
            .iter()
            .all(|c| c.head / 4 - c.len <= ROWS + 1 && c.head > -200));
    }

    #[test]
    fn small_ticks_accumulate() {
        let mut r = Rain::new();
        assert!(!r.tick(30));
        assert!(r.tick(30));
    }
}
