//! Metal plate formats for seed words (M11-4, decision 6): a word's number
//! (1–2048, its BIP-39 index plus one) punched as dots.
//!
//! - **Tinyseed**: twelve dots per word, the binary digits of the number
//!   from 2048 down to 1 (as Krux draws and reads them).
//! - **Stackbit 1248**: four groups per word, one per decimal digit of the
//!   number written with four digits (thousands, hundreds, tens, ones);
//!   each group has dots worth 1, 2, 4 and 8 that add up to the digit.
//!
//! Transcribing a plate keeps the seed's checksum: the device never fills
//! in a last word for the user, so a dot copied wrong is caught.

/// Dots per word on a Tinyseed.
pub const TINYSEED_DOTS: usize = 12;
/// Dots per word on a Stackbit 1248 (four digits of four dots).
pub const STACKBIT_DOTS: usize = 16;

/// The Tinyseed dots of word `index` (0–2047): bit 11 is the 2048 dot,
/// bit 0 the 1 dot.
pub fn tinyseed_dots(index: u16) -> u16 {
    (index & 0x7FF) + 1
}

/// The word index the Tinyseed dots `dots` stand for; `None` if no word
/// (no dot, or more than 2048).
pub fn tinyseed_index(dots: u16) -> Option<u16> {
    let n = dots & 0xFFF;
    (1..=2048).contains(&n).then(|| n - 1)
}

/// The Stackbit dots of word `index`: bit `4 * d + k` is the dot worth
/// `2^k` in digit `d` (0 thousands .. 3 ones).
pub fn stackbit_dots(index: u16) -> u16 {
    let n = (index & 0x7FF) + 1;
    let digits = [n / 1000, n / 100 % 10, n / 10 % 10, n % 10];
    digits
        .iter()
        .enumerate()
        .fold(0, |acc, (d, &v)| acc | (v << (4 * d)))
}

/// The word index the Stackbit dots `dots` stand for; `None` if a digit is
/// above 9 or the number is not 1–2048.
pub fn stackbit_index(dots: u16) -> Option<u16> {
    let mut n = 0u16;
    for d in 0..4 {
        let v = (dots >> (4 * d)) & 0xF;
        if v > 9 {
            return None;
        }
        n = n * 10 + v;
    }
    (1..=2048).contains(&n).then(|| n - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tinyseed_is_the_word_number_in_binary() {
        assert_eq!(tinyseed_dots(0), 0b0000_0000_0001); // abandon = 1
        assert_eq!(tinyseed_dots(2047), 0b1000_0000_0000); // zoo = 2048
        assert_eq!(tinyseed_dots(432), 433); // the dots Krux starts a 12-word grid with
        for i in 0..2048u16 {
            assert_eq!(tinyseed_index(tinyseed_dots(i)), Some(i));
        }
        assert_eq!(tinyseed_index(0), None, "no dot is no word");
        assert_eq!(tinyseed_index(0b1000_0000_0001), None, "above 2048");
    }

    #[test]
    fn stackbit_is_each_decimal_digit_in_1248_dots() {
        // 1 = 0001: only the ones' 1 dot
        assert_eq!(stackbit_dots(0), 0x1000);
        // 2048 = 2 0 4 8
        assert_eq!(stackbit_dots(2047), 0x8402);
        // 1999 = 1 9 9 9: 9 is the 8 and the 1 dots
        assert_eq!(stackbit_dots(1998), 0x9991);
        for i in 0..2048u16 {
            let d = stackbit_dots(i);
            assert!((0..4).all(|k| (d >> (4 * k)) & 0xF <= 9));
            assert_eq!(stackbit_index(d), Some(i));
        }
        assert_eq!(stackbit_index(0), None, "0000");
        assert_eq!(stackbit_index(0x000A), None, "a digit of 10");
        assert_eq!(stackbit_index(0x9402), None, "2049");
    }
}
