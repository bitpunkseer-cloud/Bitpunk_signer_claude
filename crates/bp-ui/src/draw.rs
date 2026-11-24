//! Shape helpers built on `Canvas`.

use bp_hal::{Canvas, Rgb};

/// Filled rectangle. The UX language (M9) uses square terminal corners, so
/// the radius is ignored; the name stays for the callers.
pub fn round_rect(c: &mut dyn Canvas, x: i32, y: i32, w: i32, h: i32, _r: i32, color: Rgb) {
    c.fill_rect(x, y, w, h, color);
}

/// 1px rectangle outline.
pub fn outline(c: &mut dyn Canvas, x: i32, y: i32, w: i32, h: i32, color: Rgb) {
    c.fill_rect(x, y, w, 1, color);
    c.fill_rect(x, y + h - 1, w, 1, color);
    c.fill_rect(x, y, 1, h, color);
    c.fill_rect(x + w - 1, y, 1, h, color);
}
