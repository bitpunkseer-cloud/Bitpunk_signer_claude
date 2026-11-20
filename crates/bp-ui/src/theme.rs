//! Colour palette. Black ground, Bitcoin-orange accent, high contrast text.

use bp_hal::Rgb;

pub const BG: Rgb = Rgb::hex(0x0B0B0D);
pub const SURFACE: Rgb = Rgb::hex(0x17171B);
pub const SURFACE_HI: Rgb = Rgb::hex(0x24242A);
pub const LINE: Rgb = Rgb::hex(0x2E2E35);
pub const TEXT: Rgb = Rgb::hex(0xF2F2F0);
pub const TEXT_DIM: Rgb = Rgb::hex(0x9A9AA2);
pub const TEXT_FAINT: Rgb = Rgb::hex(0x5E5E66);
pub const ACCENT: Rgb = Rgb::hex(0xF7931A);
pub const ACCENT_TEXT: Rgb = Rgb::hex(0x0B0B0D);
pub const OK: Rgb = Rgb::hex(0x3DDC84);
pub const WARN: Rgb = Rgb::hex(0xFFC53D);
pub const DANGER: Rgb = Rgb::hex(0xFF4D4F);
