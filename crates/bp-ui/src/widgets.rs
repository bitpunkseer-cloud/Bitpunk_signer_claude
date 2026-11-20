//! Screen furniture: status bar, hint bar, menu list, message panel.

use crate::draw::round_rect;
use crate::font::{BODY, SMALL, TITLE};
use crate::theme::*;
use bp_hal::Canvas;

pub const STATUS_H: i32 = 44;
pub const HINT_H: i32 = 34;
pub const MARGIN: i32 = 24;

/// Top bar: title on the left, network badge + AIR-GAPPED on the right.
pub fn status_bar(c: &mut dyn Canvas, title: &str, network_badge: &str, mainnet: bool) {
    let w = c.width() as i32;
    c.fill_rect(0, 0, w, STATUS_H, SURFACE);
    c.fill_rect(0, STATUS_H - 1, w, 1, LINE);
    BODY.draw(c, MARGIN, (STATUS_H - BODY.height as i32) / 2, title, TEXT);

    // right side, laid out right-to-left
    let mut x = w - MARGIN;
    let tag = "AIR-GAPPED";
    let tw = SMALL.text_width(tag);
    x -= tw;
    let ty = (STATUS_H - SMALL.height as i32) / 2;
    SMALL.draw(c, x, ty, tag, OK);
    // small shield dot before AIR-GAPPED
    round_rect(c, x - 14, STATUS_H / 2 - 4, 8, 8, 4, OK);
    x -= 30;

    let bw = SMALL.text_width(network_badge) + 16;
    x -= bw;
    let (bg, fg) = if mainnet {
        (ACCENT, ACCENT_TEXT)
    } else {
        (WARN, ACCENT_TEXT)
    };
    round_rect(c, x, STATUS_H / 2 - 12, bw, 24, 6, bg);
    SMALL.draw(
        c,
        x + 8,
        STATUS_H / 2 - SMALL.height as i32 / 2,
        network_badge,
        fg,
    );
}

/// Bottom bar listing available keys, e.g. `[("↑↓","Move"),("Enter","Select")]`.
pub fn hint_bar(c: &mut dyn Canvas, hints: &[(&str, &str)]) {
    let (w, h) = (c.width() as i32, c.height() as i32);
    let y = h - HINT_H;
    c.fill_rect(0, y, w, HINT_H, SURFACE);
    c.fill_rect(0, y, w, 1, LINE);
    let mut x = MARGIN;
    let ty = y + (HINT_H - SMALL.height as i32) / 2;
    for (key, label) in hints {
        let kw = SMALL.text_width(key) + 12;
        round_rect(c, x, y + 6, kw, HINT_H - 12, 4, SURFACE_HI);
        SMALL.draw(c, x + 6, ty, key, TEXT);
        x += kw + 8;
        x = SMALL.draw(c, x, ty, label, TEXT_DIM) + 20;
    }
}

pub struct MenuItem<'a> {
    pub label: &'a str,
    pub detail: &'a str,
}

/// Vertical menu with numbered rows (1-9 hotkeys) and a highlighted row.
/// Scrolls so that `selected` is always visible.
pub fn menu_list(c: &mut dyn Canvas, items: &[MenuItem], selected: usize) {
    let w = c.width() as i32;
    let top = STATUS_H + 16;
    let bottom = c.height() as i32 - HINT_H - 12;
    let row_h = 52;
    let visible = ((bottom - top) / row_h).max(1) as usize;
    let first = if selected >= visible {
        selected + 1 - visible
    } else {
        0
    };

    for (i, item) in items.iter().enumerate().skip(first).take(visible) {
        let y = top + (i - first) as i32 * row_h;
        let sel = i == selected;
        let (x, rw) = (MARGIN, w - 2 * MARGIN);
        if sel {
            round_rect(c, x, y, rw, row_h - 6, 10, ACCENT);
        }
        let (fg, dim) = if sel {
            (ACCENT_TEXT, ACCENT_TEXT)
        } else {
            (TEXT, TEXT_DIM)
        };
        let ty = y + (row_h - 6 - BODY.height as i32) / 2;
        if i < 9 {
            let n = [b'1' + i as u8];
            let ns = core::str::from_utf8(&n).unwrap_or("?");
            if !sel {
                round_rect(c, x + 12, y + 9, 28, 28, 6, SURFACE_HI);
            }
            BODY.draw(c, x + 20, ty, ns, if sel { ACCENT_TEXT } else { TEXT_DIM });
        }
        BODY.draw(c, x + 56, ty, item.label, fg);
        if !item.detail.is_empty() {
            let dw = SMALL.text_width(item.detail);
            SMALL.draw(
                c,
                x + rw - 20 - dw,
                y + (row_h - 6 - SMALL.height as i32) / 2,
                item.detail,
                dim,
            );
        }
    }

    // scroll indicator
    if items.len() > visible {
        let track_h = bottom - top;
        let thumb_h = (track_h * visible as i32 / items.len() as i32).max(20);
        let thumb_y = top + (track_h - thumb_h) * first as i32 / (items.len() - visible) as i32;
        c.fill_rect(w - 10, top, 3, track_h, SURFACE_HI);
        c.fill_rect(w - 10, thumb_y, 3, thumb_h, TEXT_DIM);
    }
}

/// Centred message panel with a heading and body lines.
pub fn message_panel(c: &mut dyn Canvas, heading: &str, lines: &[&str]) {
    let w = c.width() as i32;
    let top = STATUS_H + 40;
    TITLE.draw_centered(c, 0, w, top, heading, TEXT);
    let mut y = top + TITLE.height as i32 + 18;
    for line in lines {
        BODY.draw_centered(c, 0, w, y, line, TEXT_DIM);
        y += BODY.height as i32 + 4;
    }
}

/// Key/value rows (used by About and similar info screens).
pub fn info_rows(c: &mut dyn Canvas, rows: &[(&str, &str)]) {
    let w = c.width() as i32;
    let mut y = STATUS_H + 24;
    for (k, v) in rows {
        SMALL.draw(c, MARGIN, y + 4, k, TEXT_DIM);
        BODY.draw(c, MARGIN + 200, y, v, TEXT);
        y += BODY.height as i32 + 10;
        c.fill_rect(MARGIN, y - 5, w - 2 * MARGIN, 1, LINE);
    }
}
