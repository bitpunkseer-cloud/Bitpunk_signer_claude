//! Screen effects (M9-2): phosphor glow on text and scanlines, applied by
//! the host around `App::render`:
//!
//! ```ignore
//! let mut fx = FxCanvas::new(&mut framebuffer, settings.fx);
//! app.render(&mut fx);
//! fx.finish(app.qr_area());
//! ```
//!
//! Glow follows anti-aliased glyph pixels only, so rectangles (panels, QR
//! modules) never glow; scanlines skip the QR box. On the board the
//! scanlines can move to a static LTDC overlay layer (H2).

use bp_hal::{Canvas, Rgb};

/// The effects setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fx {
    Full,
    Reduced,
    Off,
}

impl Fx {
    pub const ALL: [Fx; 3] = [Fx::Full, Fx::Reduced, Fx::Off];

    /// Darkening of every other pixel row (of 255).
    pub fn scan_alpha(self) -> u8 {
        match self {
            Fx::Full => 64,
            Fx::Reduced => 31,
            Fx::Off => 0,
        }
    }

    /// Halo strength around glyph pixels: the halo alpha is `a / divisor`.
    fn glow_divisor(self) -> Option<u16> {
        match self {
            Fx::Full => Some(4),
            Fx::Reduced => Some(9),
            Fx::Off => None,
        }
    }
}

/// A canvas that adds the effects while the app draws through it.
pub struct FxCanvas<'a> {
    inner: &'a mut dyn Canvas,
    fx: Fx,
}

impl<'a> FxCanvas<'a> {
    pub fn new(inner: &'a mut dyn Canvas, fx: Fx) -> Self {
        Self { inner, fx }
    }

    /// Lay the scanlines over the finished frame, except inside `keep`
    /// (x, y, w, h): the QR code on screen, if any.
    pub fn finish(self, keep: Option<[i32; 4]>) {
        let a = self.fx.scan_alpha();
        if a == 0 {
            return;
        }
        let (w, h) = (self.inner.width() as i32, self.inner.height() as i32);
        let black = Rgb(0, 0, 0); // palette: scanline shade (darkens only)
        let mut y = 1;
        while y < h {
            for x in 0..w {
                let inside =
                    keep.is_some_and(|[kx, ky, kw, kh]| x >= kx && x < kx + kw && y >= ky && y < ky + kh);
                if !inside {
                    self.inner.blend_pixel(x, y, black, a);
                }
            }
            y += 2;
        }
    }
}

impl Canvas for FxCanvas<'_> {
    fn width(&self) -> u16 {
        self.inner.width()
    }
    fn height(&self) -> u16 {
        self.inner.height()
    }
    fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, c: Rgb) {
        self.inner.fill_rect(x, y, w, h, c);
    }
    fn blend_pixel(&mut self, x: i32, y: i32, c: Rgb, a: u8) {
        // the halo first, so the glyph pixel itself stays exact
        if let Some(d) = self.fx.glow_divisor() {
            let ha = (a as u16 / d) as u8;
            if ha > 2 {
                for (dx, dy) in [(-1, 0), (1, 0), (0, -1), (0, 1)] {
                    self.inner.blend_pixel(x + dx, y + dy, c, ha);
                }
            }
        }
        self.inner.blend_pixel(x, y, c, a);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    struct Buf {
        px: Vec<Rgb>,
    }
    impl Canvas for Buf {
        fn width(&self) -> u16 {
            20
        }
        fn height(&self) -> u16 {
            10
        }
        fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, c: Rgb) {
            for yy in y.max(0)..(y + h).min(10) {
                for xx in x.max(0)..(x + w).min(20) {
                    self.px[(yy * 20 + xx) as usize] = c;
                }
            }
        }
        fn blend_pixel(&mut self, x: i32, y: i32, c: Rgb, a: u8) {
            if !(0..20).contains(&x) || !(0..10).contains(&y) {
                return;
            }
            let p = &mut self.px[(y * 20 + x) as usize];
            let m = |d: u8, s: u8| ((s as u16 * a as u16 + d as u16 * (255 - a as u16) + 127) / 255) as u8;
            *p = Rgb(m(p.0, c.0), m(p.1, c.1), m(p.2, c.2));
        }
    }
    fn buf() -> Buf {
        Buf {
            px: vec![Rgb(100, 100, 100); 200],
        }
    }

    #[test]
    fn off_changes_nothing() {
        let mut b = buf();
        let mut f = FxCanvas::new(&mut b, Fx::Off);
        f.blend_pixel(5, 5, Rgb(0, 255, 0), 255);
        f.finish(None);
        assert_eq!(b.px[5 * 20 + 4], Rgb(100, 100, 100));
        assert_eq!(b.px[3 * 20 + 3], Rgb(100, 100, 100));
    }

    #[test]
    fn glow_surrounds_glyph_pixels_but_not_rectangles() {
        let mut b = buf();
        let mut f = FxCanvas::new(&mut b, Fx::Full);
        f.blend_pixel(5, 4, Rgb(0, 255, 0), 255);
        f.fill_rect(10, 2, 3, 3, Rgb(0, 0, 0));
        assert_eq!(b.px[4 * 20 + 5], Rgb(0, 255, 0), "the glyph pixel stays exact");
        assert!(b.px[4 * 20 + 4].1 > 100, "halo to the left");
        assert_eq!(b.px[3 * 20 + 9], Rgb(100, 100, 100), "no halo around rectangles");
    }

    #[test]
    fn scanlines_darken_odd_rows_outside_the_qr() {
        let mut b = buf();
        let f = FxCanvas::new(&mut b, Fx::Full);
        f.finish(Some([0, 0, 10, 10]));
        assert_eq!(b.px[20 + 5], Rgb(100, 100, 100), "inside the QR box");
        assert!(b.px[20 + 15].0 < 100, "odd row outside");
        assert_eq!(b.px[2 * 20 + 15], Rgb(100, 100, 100), "even row");
    }
}
