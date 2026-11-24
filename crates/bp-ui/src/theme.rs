//! Colour palette — "Bitpunk Phosphor" (M9): green phosphor on near-black.
//! One green carries the hierarchy by brightness; amber and red are kept for
//! caution and danger. Every colour a screen uses comes from here (a test
//! checks the contrast of every text colour). See docs/UX_LANGUAGE.md.

use bp_hal::Rgb;

/// Screen ground.
pub const BG: Rgb = Rgb::hex(0x030B05);
/// Panels (status line, key bar).
pub const SURFACE: Rgb = Rgb::hex(0x07160C);
/// Raised panels: key caps, unselected chips.
pub const SURFACE_HI: Rgb = Rgb::hex(0x0C2414);
/// Rules, grid and empty cells only — never text (2.2:1).
pub const LINE: Rgb = Rgb::hex(0x13532A);
/// Data the user must check: amounts, addresses, words, fingerprints.
pub const BRIGHT: Rgb = Rgb::hex(0xD2FFDC);
/// Body text.
pub const TEXT: Rgb = Rgb::hex(0x4DFF7C);
/// Labels and secondary text.
pub const TEXT_DIM: Rgb = Rgb::hex(0x2BB457);
/// Least important text that is still read (hints, placeholders).
pub const TEXT_FAINT: Rgb = Rgb::hex(0x23A04E);
/// "Signal" green: the selection bar, cursor and progress.
pub const ACCENT: Rgb = Rgb::hex(0x00FF41);
/// Text on ACCENT, WARN and DANGER fills (inverse video).
pub const ACCENT_TEXT: Rgb = BG;
/// Passed checks.
pub const OK: Rgb = Rgb::hex(0x00FF41);
/// Caution: warnings, mainnet, TEST ONLY.
pub const WARN: Rgb = Rgb::hex(0xFFB000);
/// Danger and failures.
pub const DANGER: Rgb = Rgb::hex(0xFF5555);
/// QR codes are drawn without effects: black modules on a pale panel.
pub const QR_LIGHT: Rgb = Rgb::hex(0xDFFFE6);
pub const QR_DARK: Rgb = Rgb::hex(0x000000);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// WCAG contrast ratio of two colours (1.0 to 21.0).
    fn contrast(a: Rgb, b: Rgb) -> f32 {
        fn lum(c: Rgb) -> f32 {
            let ch = |v: u8| {
                let s = v as f32 / 255.0;
                if s <= 0.039_28 {
                    s / 12.92
                } else {
                    ((s + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * ch(c.0) + 0.7152 * ch(c.1) + 0.0722 * ch(c.2)
        }
        let (x, y) = (lum(a), lum(b));
        let (hi, lo) = if x > y { (x, y) } else { (y, x) };
        (hi + 0.05) / (lo + 0.05)
    }

    #[test]
    fn text_colours_are_readable() {
        // body text and data: AAA; secondary text: AA
        for (name, c, min) in [
            ("BRIGHT", BRIGHT, 7.0),
            ("TEXT", TEXT, 7.0),
            ("ACCENT", ACCENT, 7.0),
            ("TEXT_DIM", TEXT_DIM, 4.5),
            ("TEXT_FAINT", TEXT_FAINT, 4.5),
            ("WARN", WARN, 4.5),
            ("DANGER", DANGER, 4.5),
        ] {
            for (bg_name, bg) in [("BG", BG), ("SURFACE", SURFACE), ("SURFACE_HI", SURFACE_HI)] {
                let r = contrast(c, bg);
                assert!(r >= min, "{name} on {bg_name}: {r:.2}:1 < {min}:1");
            }
        }
        // inverse video on the fills
        for (name, fill) in [
            ("ACCENT", ACCENT),
            ("WARN", WARN),
            ("DANGER", DANGER),
            ("TEXT_DIM", TEXT_DIM),
        ] {
            let r = contrast(ACCENT_TEXT, fill);
            assert!(r >= 4.5, "text on {name}: {r:.2}:1");
        }
        // LINE is for rules only: visible, but too faint for text
        assert!(contrast(LINE, BG) < 3.0 && contrast(LINE, BG) > 1.8);
        // QR codes: maximum contrast
        assert!(contrast(QR_DARK, QR_LIGHT) > 18.0);
    }

    #[test]
    fn contrast_matches_known_values() {
        assert!((contrast(Rgb(0, 0, 0), Rgb(255, 255, 255)) - 21.0).abs() < 0.05);
        assert!((contrast(TEXT, BG) - 15.1).abs() < 0.1);
        assert!((contrast(TEXT_DIM, BG) - 7.37).abs() < 0.05);
    }
}
