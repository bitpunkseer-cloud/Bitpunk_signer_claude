//! RGBA8 framebuffer implementing `bp_hal::Canvas`.

use bp_hal::{Canvas, Rgb, DISPLAY_HEIGHT, DISPLAY_WIDTH};

pub const W: usize = DISPLAY_WIDTH as usize;
pub const H: usize = DISPLAY_HEIGHT as usize;

pub struct Framebuffer {
    px: Vec<u8>,
}

impl Framebuffer {
    pub fn new() -> Self {
        let mut px = vec![0u8; W * H * 4];
        for a in px.iter_mut().skip(3).step_by(4) {
            *a = 255;
        }
        Self { px }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.px.as_ptr()
    }

    #[cfg(test)]
    pub fn pixel(&self, x: usize, y: usize) -> [u8; 3] {
        let i = (y * W + x) * 4;
        [self.px[i], self.px[i + 1], self.px[i + 2]]
    }
}

impl Canvas for Framebuffer {
    fn width(&self) -> u16 {
        W as u16
    }
    fn height(&self) -> u16 {
        H as u16
    }

    fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, c: Rgb) {
        let x0 = x.clamp(0, W as i32) as usize;
        let y0 = y.clamp(0, H as i32) as usize;
        let x1 = (x + w).clamp(0, W as i32) as usize;
        let y1 = (y + h).clamp(0, H as i32) as usize;
        for row in y0..y1 {
            let line = &mut self.px[(row * W + x0) * 4..(row * W + x1) * 4];
            for p in line.as_chunks_mut::<4>().0 {
                p[0] = c.0;
                p[1] = c.1;
                p[2] = c.2;
            }
        }
    }

    fn blend_pixel(&mut self, x: i32, y: i32, c: Rgb, a: u8) {
        if x < 0 || y < 0 || x >= W as i32 || y >= H as i32 {
            return;
        }
        let i = (y as usize * W + x as usize) * 4;
        let a = a as u16;
        let mix = |dst: u8, src: u8| ((src as u16 * a + dst as u16 * (255 - a) + 127) / 255) as u8;
        self.px[i] = mix(self.px[i], c.0);
        self.px[i + 1] = mix(self.px[i + 1], c.1);
        self.px[i + 2] = mix(self.px[i + 2], c.2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_is_clipped() {
        let mut fb = Framebuffer::new();
        fb.fill_rect(-10, -10, 20, 20, Rgb(255, 0, 0));
        fb.fill_rect(W as i32 - 5, H as i32 - 5, 50, 50, Rgb(0, 255, 0));
        assert_eq!(fb.pixel(0, 0), [255, 0, 0]);
        assert_eq!(fb.pixel(W - 1, H - 1), [0, 255, 0]);
    }

    #[test]
    fn blend_half() {
        let mut fb = Framebuffer::new();
        fb.blend_pixel(1, 1, Rgb(255, 255, 255), 128);
        assert_eq!(fb.pixel(1, 1), [128, 128, 128]);
    }
}
