//! Shape helpers built on `Canvas`.

use bp_hal::{Canvas, Rgb};

/// Filled rectangle with anti-aliased rounded corners of radius `r`.
pub fn round_rect(c: &mut dyn Canvas, x: i32, y: i32, w: i32, h: i32, r: i32, color: Rgb) {
    let r = r.min(w / 2).min(h / 2).max(0);
    if r == 0 {
        c.fill_rect(x, y, w, h, color);
        return;
    }
    c.fill_rect(x + r, y, w - 2 * r, h, color);
    c.fill_rect(x, y + r, r, h - 2 * r, color);
    c.fill_rect(x + w - r, y + r, r, h - 2 * r, color);
    // corners: 4x4 supersampled coverage
    let rf = r as f32;
    for dy in 0..r {
        for dx in 0..r {
            let mut cov = 0u32;
            for sy in 0..4 {
                for sx in 0..4 {
                    let fx = rf - (dx as f32 + (sx as f32 + 0.5) / 4.0);
                    let fy = rf - (dy as f32 + (sy as f32 + 0.5) / 4.0);
                    if fx * fx + fy * fy <= rf * rf {
                        cov += 1;
                    }
                }
            }
            if cov == 0 {
                continue;
            }
            let a = (cov * 255 / 16) as u8;
            c.blend_pixel(x + dx, y + dy, color, a);
            c.blend_pixel(x + w - 1 - dx, y + dy, color, a);
            c.blend_pixel(x + dx, y + h - 1 - dy, color, a);
            c.blend_pixel(x + w - 1 - dx, y + h - 1 - dy, color, a);
        }
    }
}

/// 1px rectangle outline.
pub fn outline(c: &mut dyn Canvas, x: i32, y: i32, w: i32, h: i32, color: Rgb) {
    c.fill_rect(x, y, w, 1, color);
    c.fill_rect(x, y + h - 1, w, 1, color);
    c.fill_rect(x, y, 1, h, color);
    c.fill_rect(x + w - 1, y, 1, h, color);
}
