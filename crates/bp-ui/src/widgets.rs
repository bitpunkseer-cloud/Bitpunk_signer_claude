//! Screen furniture and reusable widgets.

use crate::draw::{outline, round_rect};
use crate::font::{Font, BODY, SMALL, TITLE};
use crate::theme::*;
use bp_hal::{Canvas, Rgb};

pub const STATUS_H: i32 = 44;
pub const HINT_H: i32 = 34;
pub const MARGIN: i32 = 24;

/// Top-of-screen status: title on the left; TEST ONLY, network and
/// AIR-GAPPED badges on the right.
pub struct Status<'a> {
    pub title: &'a str,
    pub network_badge: &'a str,
    pub mainnet: bool,
    pub test_only: bool,
}

pub fn status_bar(c: &mut dyn Canvas, s: &Status) {
    let w = c.width() as i32;
    c.fill_rect(0, 0, w, STATUS_H, SURFACE);
    c.fill_rect(0, STATUS_H - 1, w, 1, LINE);
    BODY.draw(c, MARGIN, (STATUS_H - BODY.height as i32) / 2, s.title, TEXT);

    let mut x = w - MARGIN;
    let tag = "AIR-GAPPED";
    x -= SMALL.text_width(tag);
    SMALL.draw(c, x, (STATUS_H - SMALL.height as i32) / 2, tag, OK);
    round_rect(c, x - 14, STATUS_H / 2 - 4, 8, 8, 4, OK);
    x -= 30;

    let (bg, fg) = if s.mainnet {
        (ACCENT, ACCENT_TEXT)
    } else {
        (WARN, ACCENT_TEXT)
    };
    x -= badge_width(s.network_badge);
    badge(c, x, STATUS_H / 2 - 12, s.network_badge, bg, fg);

    if s.test_only {
        x -= badge_width("TEST ONLY") + 10;
        badge(c, x, STATUS_H / 2 - 12, "TEST ONLY", DANGER, TEXT);
    }
}

pub fn badge_width(text: &str) -> i32 {
    SMALL.text_width(text) + 16
}

/// Rounded label, 24px tall, top-left at (x, y).
pub fn badge(c: &mut dyn Canvas, x: i32, y: i32, text: &str, bg: Rgb, fg: Rgb) {
    round_rect(c, x, y, badge_width(text), 24, 6, bg);
    SMALL.draw(c, x + 8, y + 12 - SMALL.height as i32 / 2, text, fg);
}

/// Bottom bar listing available keys, e.g. `[("^v","Move"),("Enter","Select")]`.
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

/// Full-height vertical menu with numbered rows (1-9 hotkeys).
pub fn menu_list(c: &mut dyn Canvas, items: &[MenuItem], selected: usize) {
    let top = STATUS_H + 16;
    let bottom = c.height() as i32 - HINT_H - 12;
    let w = c.width() as i32 - 2 * MARGIN;
    list(c, MARGIN, top, w, bottom - top, items, selected, true);
}

/// Numbered list in an arbitrary box; scrolls to keep `selected` visible.
#[allow(clippy::too_many_arguments)]
pub fn list(
    c: &mut dyn Canvas,
    x: i32,
    top: i32,
    rw: i32,
    height: i32,
    items: &[MenuItem],
    selected: usize,
    scrollbar: bool,
) {
    let row_h = 52;
    let visible = (height / row_h).max(1) as usize;
    let first = if selected >= visible {
        selected + 1 - visible
    } else {
        0
    };
    for (i, item) in items.iter().enumerate().skip(first).take(visible) {
        let y = top + (i - first) as i32 * row_h;
        let sel = i == selected;
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
    if scrollbar && items.len() > visible {
        let w = c.width() as i32;
        let track_h = visible as i32 * row_h - 6;
        let thumb_h = (track_h * visible as i32 / items.len() as i32).max(20);
        let thumb_y = top + (track_h - thumb_h) * first as i32 / (items.len() - visible) as i32;
        c.fill_rect(w - 10, top, 3, track_h, SURFACE_HI);
        c.fill_rect(w - 10, thumb_y, 3, thumb_h, TEXT_DIM);
    }
}

/// Heading plus body lines, horizontally centred, starting at `top`.
pub fn message_at(c: &mut dyn Canvas, top: i32, heading: &str, heading_color: Rgb, lines: &[&str]) -> i32 {
    let w = c.width() as i32;
    TITLE.draw_centered(c, 0, w, top, heading, heading_color);
    let mut y = top + TITLE.height as i32 + 14;
    for line in lines {
        BODY.draw_centered(c, 0, w, y, line, TEXT_DIM);
        y += BODY.height as i32 + 2;
    }
    y
}

/// Centred message panel with a heading and body lines.
pub fn message_panel(c: &mut dyn Canvas, heading: &str, lines: &[&str]) {
    message_at(c, STATUS_H + 40, heading, TEXT, lines);
}

/// Key/value rows (About and similar info screens).
pub fn info_rows(c: &mut dyn Canvas, rows: &[(&str, &str)]) {
    let w = c.width() as i32;
    let mut y = STATUS_H + 20;
    for (k, v) in rows {
        SMALL.draw(c, MARGIN, y + 4, k, TEXT_DIM);
        BODY.draw(c, MARGIN + 200, y, v, TEXT);
        y += BODY.height as i32 + 8;
        c.fill_rect(MARGIN, y - 4, w - 2 * MARGIN, 1, LINE);
    }
}

/// Small uppercase-style section label.
pub fn label(c: &mut dyn Canvas, x: i32, y: i32, text: &str) {
    SMALL.draw(c, x, y, text, TEXT_DIM);
}

/// Horizontal progress bar; `frac` is clamped to 0..=1.
pub fn progress_bar(c: &mut dyn Canvas, x: i32, y: i32, w: i32, h: i32, frac: f64, color: Rgb) {
    round_rect(c, x, y, w, h, h / 2, SURFACE_HI);
    let f = if frac.is_nan() { 0.0 } else { frac.clamp(0.0, 1.0) };
    let fw = (w as f64 * f) as i32;
    if fw > 0 {
        round_rect(c, x, y, fw.max(h), h, h / 2, color);
    }
}

/// Vertical bar chart. `labels[i]` is drawn under bar `i`, counts above.
#[allow(clippy::too_many_arguments)]
pub fn bar_chart(
    c: &mut dyn Canvas,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    counts: &[u16],
    labels: &[&str],
    expected: f64,
) {
    let n = counts.len() as i32;
    if n == 0 {
        return;
    }
    let gap = 12;
    let bw = (w - gap * (n - 1)) / n;
    let label_h = SMALL.height as i32 + 2;
    let chart_h = h - label_h * 2;
    let max = counts.iter().copied().max().unwrap_or(0).max(1) as f64;
    let scale_max = max.max(expected * 1.6).max(1.0);
    for (i, &cnt) in counts.iter().enumerate() {
        let bx = x + i as i32 * (bw + gap);
        let bh = ((cnt as f64 / scale_max) * chart_h as f64) as i32;
        let base = y + label_h + chart_h;
        c.fill_rect(bx, y + label_h, bw, chart_h, SURFACE);
        if bh > 0 {
            c.fill_rect(bx, base - bh, bw, bh, ACCENT);
        }
        let mut nb = crate::fmt::Buf::<8>::new();
        let _ = core::fmt::Write::write_fmt(&mut nb, format_args!("{cnt}"));
        SMALL.draw_centered(c, bx, bw, (base - bh - label_h).max(y), nb.as_str(), TEXT_DIM);
        if let Some(l) = labels.get(i) {
            SMALL.draw_centered(c, bx, bw, base + 2, l, TEXT);
        }
    }
    if expected > 0.0 {
        let ey = y + label_h + chart_h - ((expected / scale_max) * chart_h as f64) as i32;
        let mut xx = x;
        while xx < x + w {
            c.fill_rect(xx, ey, 6, 1, TEXT_FAINT);
            xx += 10;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Wait,
    Pass,
    Fail,
}

/// One row of a checklist: pill + label + detail text.
pub fn check_row(c: &mut dyn Canvas, x: i32, y: i32, w: i32, state: CheckState, name: &str, detail: &str) {
    let (txt, bg, fg) = match state {
        CheckState::Wait => ("WAIT", SURFACE_HI, TEXT_DIM),
        CheckState::Pass => ("PASS", OK, ACCENT_TEXT),
        CheckState::Fail => ("FAIL", DANGER, TEXT),
    };
    round_rect(c, x, y, 52, 22, 5, bg);
    SMALL.draw_centered(c, x, 52, y + 11 - SMALL.height as i32 / 2, txt, fg);
    BODY.draw(c, x + 64, y + 11 - BODY.height as i32 / 2, name, TEXT);
    let dw = SMALL.text_width(detail);
    SMALL.draw(c, x + w - dw, y + 11 - SMALL.height as i32 / 2, detail, TEXT_DIM);
}

/// Grid of numbered words. `words[i]` empty = not filled yet.
/// `cursor` highlights one cell; `selected` draws an accent outline.
#[allow(clippy::too_many_arguments)]
pub fn word_grid(
    c: &mut dyn Canvas,
    x: i32,
    y: i32,
    w: i32,
    words: &[&str],
    cols: usize,
    row_h: i32,
    cursor: Option<usize>,
    font: &Font,
) {
    let col_w = w / cols as i32;
    let rows = words.len().div_ceil(cols);
    for (i, word) in words.iter().enumerate() {
        // column-major order so numbering reads down each column
        let col = i / rows;
        let row = i % rows;
        let cx = x + col as i32 * col_w;
        let cy = y + row as i32 * row_h;
        let here = cursor == Some(i);
        if here {
            round_rect(c, cx - 6, cy - 3, col_w - 8, row_h - 2, 6, SURFACE_HI);
            outline(c, cx - 6, cy - 3, col_w - 8, row_h - 2, ACCENT);
        }
        let nb = crate::bformat!(4, "{:>2}", i + 1);
        let ty = cy + (row_h - 4 - font.height as i32) / 2;
        font.draw(c, cx, ty, nb.as_str(), TEXT_FAINT);
        let wx = cx + font.width as i32 * 3;
        if word.is_empty() {
            c.fill_rect(
                wx,
                ty + font.baseline as i32 + 2,
                font.width as i32 * 6,
                1,
                TEXT_FAINT,
            );
        } else {
            font.draw(c, wx, ty, word, if here { ACCENT } else { TEXT });
        }
    }
}

/// Text field with a block cursor. Returns the x after the text.
pub fn text_field(c: &mut dyn Canvas, x: i32, y: i32, w: i32, text: &str, ghost: &str, font: &Font) -> i32 {
    let h = font.height as i32 + 16;
    round_rect(c, x, y, w, h, 10, SURFACE);
    outline(c, x, y, w, h, LINE);
    let tx = x + 16;
    let ty = y + 8;
    let end = font.draw(c, tx, ty, text, TEXT);
    if !ghost.is_empty() {
        font.draw(c, end, ty, ghost, TEXT_FAINT);
    }
    c.fill_rect(end, ty + 4, 3, font.height as i32 - 8, ACCENT);
    end
}

/// Horizontal row of chips; `selected` gets the accent fill.
pub fn chips(c: &mut dyn Canvas, x: i32, y: i32, w: i32, items: &[&str], selected: usize) {
    let mut cx = x;
    for (i, it) in items.iter().enumerate() {
        let cw = BODY.text_width(it) + 24;
        if cx + cw > x + w {
            break;
        }
        let sel = i == selected;
        round_rect(c, cx, y, cw, 36, 8, if sel { ACCENT } else { SURFACE_HI });
        BODY.draw(
            c,
            cx + 12,
            y + 18 - BODY.height as i32 / 2,
            it,
            if sel { ACCENT_TEXT } else { TEXT },
        );
        cx += cw + 10;
    }
}
