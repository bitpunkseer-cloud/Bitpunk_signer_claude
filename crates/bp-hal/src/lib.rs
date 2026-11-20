//! Hardware abstraction boundary for Bitpunk Signer.
//!
//! Deliberately contains **no** radio, USB-data or NFC interfaces: the only
//! output paths are the display (QR codes) and the microSD card.
#![no_std]

pub mod input;

/// 24-bit RGB colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    pub const fn hex(v: u32) -> Self {
        Rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
    }
}

/// Native display resolution the UI is designed for (5:3 landscape).
/// Finalised when the board is chosen in Phase 4.
pub const DISPLAY_WIDTH: u16 = 800;
pub const DISPLAY_HEIGHT: u16 = 480;

/// A pixel surface the UI draws into.
pub trait Canvas {
    fn width(&self) -> u16;
    fn height(&self) -> u16;
    /// Fill a rectangle; implementations must clip to bounds.
    fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, color: Rgb);
    /// Blend `color` over the pixel with coverage `alpha` (0..=255).
    fn blend_pixel(&mut self, x: i32, y: i32, color: Rgb, alpha: u8);
}

/// Hardware random number generator.
pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

/// Grayscale camera frame source for QR scanning (Phase 1C).
pub trait Camera {
    /// Returns (width, height) and fills `buf` with 8-bit luma, or `None`
    /// if no new frame is ready.
    fn capture(&mut self, buf: &mut [u8]) -> Option<(u16, u16)>;
}

/// microSD file storage (Phase 2).
pub trait Storage {
    type Error;
    fn read(&mut self, path: &str, buf: &mut [u8]) -> Result<usize, Self::Error>;
    fn write(&mut self, path: &str, data: &[u8]) -> Result<(), Self::Error>;
}
