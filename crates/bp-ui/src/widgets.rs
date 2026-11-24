//! Screen furniture and reusable widgets.

use crate::draw::{outline, round_rect};
use crate::font::{split_line, Font, BODY, SMALL, TITLE};
use crate::theme::*;
use bp_hal::{Canvas, Rgb};

/// Status band: grid rows 0-1 (the path in row 0's band, the rule under it).
pub const STATUS_H: i32 = 2 * crate::grid::CELL_H;
/// Key bar: grid row 19.
pub const HINT_H: i32 = crate::grid::CELL_H;
/// Left edge of grid column 0.
pub const MARGIN: i32 = crate::grid::LEFT;

/// Top-of-screen status: where you are on the left (a shell-style path);
/// TEST ONLY, SD, network and the air-gap mark on the right.
pub struct Status<'a> {
    /// The path, e.g. `BITPUNK:~/Tools/BIP-85>`; shortened from the left
    /// when it does not fit.
    pub title: &'a str,
    pub network_badge: &'a str,
    pub mainnet: bool,
    /// "AIR-GAPPED" label.
    pub air_gapped: &'a str,
    /// False when the boot check found a network chip: the label is then
    /// drawn as a warning instead of the green air-gap mark.
    pub air_gap_ok: bool,
    /// "TEST ONLY" badge, shown when set.
    pub test_only: Option<&'a str>,
    /// microSD badge, shown while a card is in the slot.
    pub sd: Option<&'a str>,
}

pub fn status_bar(c: &mut dyn Canvas, s: &Status) {
    let w = c.width() as i32;
    c.fill_rect(0, 0, w, STATUS_H, SURFACE);
    c.fill_rect(0, STATUS_H - 1, w, 1, LINE);
    let by = STATUS_H / 2 - 12;

    let mut x = w - MARGIN;
    let tag = s.air_gapped;
    x -= SMALL.text_width(tag);
    let mark = if s.air_gap_ok { OK } else { DANGER };
    SMALL.draw(c, x, (STATUS_H - SMALL.height as i32) / 2, tag, mark);
    c.fill_rect(x - 14, STATUS_H / 2 - 4, 8, 8, mark);
    x -= 30;

    // mainnet (real money) in amber, test networks dim
    x -= badge_width(s.network_badge);
    badge_outline(c, x, by, s.network_badge, if s.mainnet { WARN } else { TEXT_DIM });

    if let Some(t) = s.sd {
        x -= badge_width(t) + 8;
        badge_outline(c, x, by, t, TEXT);
    }

    if let Some(t) = s.test_only {
        x -= badge_width(t) + 8;
        badge(c, x, by, t, WARN, ACCENT_TEXT);
    }

    // the path, shortened from the left to fit before the badges
    let room = x - 16 - MARGIN;
    let ty = (STATUS_H - BODY.height as i32) / 2;
    if BODY.text_width(s.title) <= room {
        BODY.draw(c, MARGIN, ty, s.title, TEXT);
    } else {
        let ell = "..";
        let mut start = 0;
        for (i, _) in s.title.char_indices() {
            if BODY.text_width(&s.title[i..]) + BODY.text_width(ell) <= room {
                start = i;
                break;
            }
        }
        let x1 = BODY.draw(c, MARGIN, ty, ell, TEXT_DIM);
        BODY.draw(c, x1, ty, &s.title[start..], TEXT);
    }
}

pub fn badge_width(text: &str) -> i32 {
    SMALL.text_width(text) + 16
}

/// Filled label, 24px tall, top-left at (x, y).
pub fn badge(c: &mut dyn Canvas, x: i32, y: i32, text: &str, bg: Rgb, fg: Rgb) {
    c.fill_rect(x, y, badge_width(text), 24, bg);
    SMALL.draw(c, x + 8, y + 12 - SMALL.height as i32 / 2, text, fg);
}

/// Bottom bar listing available keys, e.g. `[("^v","Move"),("Enter","Select")]`.
/// A badge drawn as an outline (text in the outline colour).
pub fn badge_outline(c: &mut dyn Canvas, x: i32, y: i32, text: &str, color: Rgb) {
    let w = badge_width(text);
    outline(c, x, y, w, 24, color);
    SMALL.draw_centered(c, x, w, y + 12 - SMALL.height as i32 / 2, text, color);
}

/// Key bar (grid row 19): each key as an inverse key cap, then what it
/// does. Enter, the main action, is lit in the signal colour.
pub fn hint_bar(c: &mut dyn Canvas, hints: &[(&str, &str)]) {
    let (w, h) = (c.width() as i32, c.height() as i32);
    let y = h - HINT_H;
    c.fill_rect(0, y, w, HINT_H, SURFACE);
    c.fill_rect(0, y, w, 1, LINE);
    let mut x = MARGIN;
    let ty = y + (HINT_H - SMALL.height as i32) / 2;
    for (key, label) in hints {
        let kw = SMALL.text_width(key) + 10;
        let cap = if *key == "Enter" { ACCENT } else { TEXT_DIM };
        c.fill_rect(x, y + 3, kw, HINT_H - 6, cap);
        SMALL.draw(c, x + 5, ty, key, ACCENT_TEXT);
        x += kw + 6;
        x = SMALL.draw(c, x, ty, label, TEXT) + 18;
    }
}

pub struct MenuItem<'a> {
    pub label: &'a str,
    pub detail: &'a str,
}

/// Full-height vertical menu with numbered rows (1-9 hotkeys).
pub fn menu_list(c: &mut dyn Canvas, items: &[MenuItem], selected: usize) {
    let top = STATUS_H + 8;
    let bottom = c.height() as i32 - HINT_H - 8;
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
    // two grid rows per item; the selection is an inverse bar
    list_rows(
        c,
        x,
        top,
        rw,
        height,
        items,
        selected,
        scrollbar,
        2 * crate::grid::CELL_H,
    );
}

/// `list` with a chosen row height (the main menu uses compact rows to
/// leave room for the session log).
#[allow(clippy::too_many_arguments)]
pub fn list_rows(
    c: &mut dyn Canvas,
    x: i32,
    top: i32,
    rw: i32,
    height: i32,
    items: &[MenuItem],
    selected: usize,
    scrollbar: bool,
    row_h: i32,
) {
    let visible = (height / row_h).max(1) as usize;
    let first = if selected >= visible {
        selected + 1 - visible
    } else {
        0
    };
    let cw = BODY.width as i32;
    for (i, item) in items.iter().enumerate().skip(first).take(visible) {
        let y = top + (i - first) as i32 * row_h;
        let sel = i == selected;
        if sel {
            let pad = if row_h >= 40 { 4 } else { 2 };
            c.fill_rect(x, y + pad, rw, row_h - 2 * pad, ACCENT);
        }
        let (fg, dim) = if sel {
            (ACCENT_TEXT, ACCENT_TEXT)
        } else {
            (TEXT, TEXT_DIM)
        };
        let ty = y + (row_h - BODY.height as i32) / 2;
        if sel {
            BODY.draw(c, x + 4, ty, ">", ACCENT_TEXT);
        }
        if i < 9 {
            let n = [b'[', b'1' + i as u8, b']'];
            let ns = core::str::from_utf8(&n).unwrap_or("?");
            BODY.draw(c, x + 4 + cw, ty, ns, dim);
        }
        BODY.draw(c, x + 4 + 5 * cw, ty, item.label, fg);
        if !item.detail.is_empty() {
            let dw = SMALL.text_width(item.detail);
            SMALL.draw(
                c,
                x + rw - 12 - dw,
                y + (row_h - SMALL.height as i32) / 2,
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

/// Heading plus body lines, horizontally centred, starting at `top`. Lines
/// wider than the screen wrap.
pub fn message_at(c: &mut dyn Canvas, top: i32, heading: &str, heading_color: Rgb, lines: &[&str]) -> i32 {
    let w = c.width() as i32;
    // UX language, three levels: caution "[!]", danger "[!!!]" in a double
    // red frame; the symbol says it without colour
    let mark = if heading_color == DANGER {
        "[!!!] "
    } else if heading_color == WARN {
        "[!] "
    } else {
        ""
    };
    let hw = TITLE.text_width(mark) + TITLE.text_width(heading);
    let hx = ((w - hw) / 2).max(MARGIN);
    let hx = TITLE.draw(c, hx, top, mark, heading_color);
    TITLE.draw(c, hx, top, heading, heading_color);
    let mut y = top + TITLE.height as i32 + 14;
    let max = ((w - 2 * MARGIN - 16) / BODY.width as i32) as usize;
    for line in lines {
        let mut rest = *line;
        loop {
            let (part, tail) = split_line(rest, max);
            BODY.draw_centered(c, 0, w, y, part, TEXT_DIM);
            y += BODY.height as i32 + 2;
            if tail.is_empty() {
                break;
            }
            rest = tail;
        }
    }
    if heading_color == DANGER {
        danger_frame(c, top - 14, y + 14 - (top - 14));
    }
    y
}

/// The field of a typed-word confirmation (UX language): the prompt that
/// names the word, then what is typed so far in large letters and a cursor
/// block; `wrong` after Enter with another word. Returns the bottom.
pub fn typed_field(c: &mut dyn Canvas, top: i32, prompt: &str, typed: &str, wrong: Option<&str>) -> i32 {
    use crate::font::DOUBLE;
    let w = c.width() as i32;
    BODY.draw_centered(c, 0, w, top, prompt, TEXT);
    let y = top + BODY.height as i32 + 10;
    let cw = DOUBLE.width as i32;
    let tw = DOUBLE.text_width("> ") + DOUBLE.text_width(typed) + cw;
    let mut x = (w - tw) / 2;
    x = DOUBLE.draw(c, x, y, "> ", TEXT_DIM);
    x = DOUBLE.draw(c, x, y, typed, DANGER);
    c.fill_rect(x + 2, y + 8, cw - 4, DOUBLE.height as i32 - 14, DANGER);
    let mut bottom = y + DOUBLE.height as i32;
    if let Some(m) = wrong {
        BODY.draw_centered(c, 0, w, bottom + 6, m, WARN);
        bottom += BODY.height as i32 + 6;
    }
    bottom
}

/// An error code (UX language C8) at the right of the key bar.
pub fn error_code(c: &mut dyn Canvas, code: &str) {
    let (w, h) = (c.width() as i32, c.height() as i32);
    let tw = SMALL.text_width(code);
    let x = w - MARGIN - tw;
    let y = h - HINT_H;
    c.fill_rect(x - 10, y + 1, tw + 10 + MARGIN, HINT_H - 1, SURFACE);
    SMALL.draw(c, x, y + (HINT_H - SMALL.height as i32) / 2, code, TEXT_DIM);
}

/// The double red frame of danger messages, across the screen.
pub fn danger_frame(c: &mut dyn Canvas, y: i32, h: i32) {
    let w = c.width() as i32;
    for i in 0..2 {
        let o = 4 + i * 5;
        outline(c, o, y + i * 5, w - 2 * o, h - i * 10, DANGER);
        outline(c, o + 1, y + i * 5 + 1, w - 2 * o - 2, h - i * 10 - 2, DANGER);
    }
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
    let gap = if n > 8 { 3 } else { 12 };
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
        // with many narrow bars, empty ones carry no count
        if cnt > 0 || n <= 8 {
            let mut nb = crate::fmt::Buf::<8>::new();
            let _ = core::fmt::Write::write_fmt(&mut nb, format_args!("{cnt}"));
            SMALL.draw_centered(c, bx, bw, (base - bh - label_h).max(y), nb.as_str(), TEXT_DIM);
        }
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

/// One row of a checklist: pill + label + detail text. `pills` are the
/// wait / pass / fail labels.
#[allow(clippy::too_many_arguments)]
pub fn check_row(
    c: &mut dyn Canvas,
    x: i32,
    y: i32,
    w: i32,
    state: CheckState,
    _pills: &[&str; 3],
    name: &str,
    detail: &str,
) {
    // UX language: checks are log lines with language-neutral tags
    let tag = match state {
        CheckState::Wait => Tag::Pending,
        CheckState::Pass => Tag::Ok,
        CheckState::Fail => Tag::Fail,
    };
    log_line(c, x, y + 11 - BODY.height as i32 / 2, w, tag, name, detail);
}

/// Log tags (UX language): the symbol says it even without colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    Ok,
    Info,
    Warn,
    Fail,
    /// Not done yet.
    Pending,
}

impl Tag {
    pub fn text(self) -> &'static str {
        match self {
            Tag::Ok => "[ OK ]",
            Tag::Info => "[ i  ]",
            Tag::Warn => "[WARN]",
            Tag::Fail => "[FAIL]",
            Tag::Pending => "[ -- ]",
        }
    }
    pub fn color(self) -> Rgb {
        match self {
            Tag::Ok => OK,
            Tag::Info => TEXT,
            Tag::Warn => WARN,
            Tag::Fail => DANGER,
            Tag::Pending => TEXT_DIM,
        }
    }
}

/// One log line: tag, text, and a detail at the right edge of `w`.
pub fn log_line(c: &mut dyn Canvas, x: i32, y: i32, w: i32, tag: Tag, text: &str, detail: &str) {
    let x1 = BODY.draw(c, x, y, tag.text(), tag.color()) + BODY.width as i32;
    let color = if tag == Tag::Pending { TEXT_DIM } else { TEXT };
    BODY.draw(c, x1, y, text, color);
    if !detail.is_empty() {
        let dw = SMALL.text_width(detail);
        SMALL.draw(
            c,
            x + w - dw,
            y + (BODY.height as i32 - SMALL.height as i32) / 2,
            detail,
            TEXT_DIM,
        );
    }
}

/// Table cell alignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

/// One table row: cells of fixed widths in grid cells, from column `col`
/// of grid row `row` (UX language: tables line up on the grid).
pub fn table_row(c: &mut dyn Canvas, col: i32, row: i32, cells: &[(&str, i32, Align, Rgb)]) {
    let mut at = col;
    for (text, width, align, color) in cells {
        let tx = match align {
            Align::Left => crate::grid::x(at),
            Align::Right => crate::grid::x(at + width) - BODY.text_width(text),
        };
        BODY.draw(c, tx, crate::grid::text_y(&BODY, row, 1), text, *color);
        at += width;
    }
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
        } else if here {
            font.draw(c, wx, ty, word, ACCENT);
        } else {
            // BIP-39 words are told apart by their first four letters (UX
            // language: the same rule as typing them)
            let k = if word.is_char_boundary(4.min(word.len())) {
                4.min(word.len())
            } else {
                word.len()
            };
            let x1 = font.draw(c, wx, ty, &word[..k], BRIGHT);
            font.draw(c, x1, ty, &word[k..], TEXT);
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

/// How a QR symbol is drawn.
#[derive(Clone, Copy)]
pub struct QrStyle {
    /// Brightness of the light modules (255 = full white). Lower values
    /// reduce glare for the scanning camera.
    pub light: u8,
    /// Swap dark and light (some cameras read inverted codes better).
    pub invert: bool,
}

/// The square `qr_code` fills for `q` in the box (x, y, w, h), quiet zone
/// included: [x, y, side, side].
pub fn qr_box(q: &bp_qr::QrCode, x: i32, y: i32, w: i32, h: i32) -> [i32; 4] {
    let modules = q.size() as i32 + 8;
    let side = (w.min(h) / modules).max(1) * modules;
    [x + (w - side) / 2, y + (h - side) / 2, side, side]
}

/// Draw `q` centred in the box (x, y, w, h) at the largest integer module
/// size, with a 4-module quiet zone. Returns the module size in pixels.
pub fn qr_code(c: &mut dyn Canvas, q: &bp_qr::QrCode, x: i32, y: i32, w: i32, h: i32, style: QrStyle) -> i32 {
    let modules = q.size() as i32 + 8;
    let px = (w.min(h) / modules).max(1);
    let [ox, oy, side, _] = qr_box(q, x, y, w, h);
    // a pale phosphor panel, dimmed by the user's glare setting
    let dim = |v: u8| (v as u16 * style.light as u16 / 255) as u8;
    let light = Rgb(dim(QR_LIGHT.0), dim(QR_LIGHT.1), dim(QR_LIGHT.2)); // palette: QR_LIGHT dimmed
    let dark = QR_DARK;
    let (bg, fg) = if style.invert {
        (dark, light)
    } else {
        (light, dark)
    };
    c.fill_rect(ox, oy, side, side, bg);
    for my in 0..q.size() {
        // merge horizontal runs of dark modules into one rectangle
        let mut mx = 0;
        while mx < q.size() {
            if q.get(mx, my) {
                let start = mx;
                while mx < q.size() && q.get(mx, my) {
                    mx += 1;
                }
                c.fill_rect(
                    ox + (start as i32 + 4) * px,
                    oy + (my as i32 + 4) * px,
                    (mx - start) as i32 * px,
                    px,
                    fg,
                );
            } else {
                mx += 1;
            }
        }
    }
    px
}
