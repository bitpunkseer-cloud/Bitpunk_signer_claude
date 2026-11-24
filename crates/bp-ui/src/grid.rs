//! The 64 x 20 terminal grid (M9): 12 x 24 px cells on the 800 x 480
//! screen, 16 px side margins. Row 0 is the status line, row 1 and row 18
//! rules, rows 2-17 the content, row 19 the key bar. ASCII takes one cell,
//! Korean two. See docs/UX_LANGUAGE.md.

use crate::font::{Font, BODY};
use crate::theme::LINE;
use bp_hal::{Canvas, Rgb};

pub const CELL_W: i32 = 12;
pub const CELL_H: i32 = 24;
pub const COLS: i32 = 64;
pub const ROWS: i32 = 20;
/// Left edge of column 0.
pub const LEFT: i32 = 16;

pub const STATUS_ROW: i32 = 0;
pub const CONTENT_TOP: i32 = 2;
pub const CONTENT_ROWS: i32 = 16;
pub const KEYBAR_ROW: i32 = ROWS - 1;

/// Left edge of column `col`.
pub const fn x(col: i32) -> i32 {
    LEFT + col * CELL_W
}

/// Top edge of row `row`.
pub const fn y(row: i32) -> i32 {
    row * CELL_H
}

/// Where to draw a font's glyph box so its ink sits in row `row`
/// (`rows` tall: 1 for body text, 2 for the double-size font).
pub fn text_y(font: &Font, row: i32, rows: i32) -> i32 {
    y(row) + (rows * CELL_H - font.height as i32) / 2
}

/// Display width of `s` in cells (wide characters take two).
pub fn cells(s: &str) -> i32 {
    s.chars().map(|c| if (c as u32) < 0x80 { 1 } else { 2 }).sum()
}

/// Body text at a cell.
pub fn text(c: &mut dyn Canvas, col: i32, row: i32, s: &str, color: Rgb) {
    BODY.draw(c, x(col), text_y(&BODY, row, 1), s, color);
}

/// A rule along the bottom of row `row`, across the content width.
pub fn rule(c: &mut dyn Canvas, row: i32) {
    c.fill_rect(x(0) - 4, y(row + 1) - 1, COLS * CELL_W + 8, 1, LINE);
}

/// A box around cells (`col`, `row`) to (`col + w`, `row + h`); `double`
/// draws two lines (danger boxes).
#[allow(clippy::too_many_arguments)]
pub fn frame(c: &mut dyn Canvas, col: i32, row: i32, w: i32, h: i32, color: Rgb, double: bool) {
    let (x0, y0, pw, ph) = (x(col), y(row), w * CELL_W, h * CELL_H);
    let lines = if double { 2 } else { 1 };
    for i in 0..lines {
        let o = i * 4;
        c.fill_rect(x0 + o, y0 + o, pw - 2 * o, 2, color);
        c.fill_rect(x0 + o, y0 + ph - 2 - o, pw - 2 * o, 2, color);
        c.fill_rect(x0 + o, y0 + o, 2, ph - 2 * o, color);
        c.fill_rect(x0 + pw - 2 - o, y0 + o, 2, ph - 2 * o, color);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_fills_the_screen() {
        assert_eq!(ROWS * CELL_H, 480);
        assert_eq!(2 * LEFT + COLS * CELL_W, 800);
        assert_eq!(CONTENT_TOP + CONTENT_ROWS, KEYBAR_ROW - 1);
        // the body font is one cell wide; Korean two
        assert_eq!(BODY.width as i32, CELL_W);
        assert_eq!(cells("ab한"), 4);
    }

    #[test]
    fn double_size_is_two_cells_by_two_rows() {
        use crate::font::DOUBLE;
        assert_eq!(DOUBLE.width as i32, 2 * CELL_W);
        let top = text_y(&DOUBLE, 2, 2);
        assert!(top >= y(2) - 4 && top + DOUBLE.height as i32 <= y(4) + 4);
    }

    #[test]
    fn body_ink_stays_in_its_row() {
        // glyph box may overhang by a few pixels (line gap); ink must not
        let top = text_y(&BODY, 5, 1);
        assert!(top >= y(5) - 3 && top + BODY.height as i32 <= y(6) + 3);
    }
}
