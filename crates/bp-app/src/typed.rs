//! Typed-word confirmation (M9, UX language): actions that cannot be undone
//! — formatting the card, discarding a seed — go ahead only after the user
//! types a word (`FORMAT`, `WIPE`). Esc, or Backspace on an empty field,
//! cancels; Enter with the wrong word changes nothing.

use bp_hal::input::Key;

pub const FORMAT: &str = "FORMAT";
pub const WIPE: &str = "WIPE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Typed {
    /// Still typing (or the word was wrong).
    Pending,
    Confirmed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TypedWord {
    buf: [u8; 8],
    len: u8,
    /// The last Enter had the wrong word.
    pub wrong: bool,
}

impl TypedWord {
    pub const fn new() -> Self {
        Self {
            buf: [0; 8],
            len: 0,
            wrong: false,
        }
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    pub fn text(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }

    /// A key for a field that confirms with `word`.
    pub fn key(&mut self, k: Key, word: &str) -> Typed {
        match k {
            Key::Char(c) if c.is_ascii_alphabetic() => {
                if (self.len as usize) < self.buf.len() {
                    self.buf[self.len as usize] = c.to_ascii_uppercase() as u8;
                    self.len += 1;
                }
                self.wrong = false;
                Typed::Pending
            }
            Key::Backspace if self.len > 0 => {
                self.len -= 1;
                self.buf[self.len as usize] = 0;
                self.wrong = false;
                Typed::Pending
            }
            Key::Backspace | Key::Esc => {
                self.clear();
                Typed::Cancelled
            }
            Key::Enter if self.text() == word => {
                self.clear();
                Typed::Confirmed
            }
            Key::Enter => {
                self.wrong = true;
                Typed::Pending
            }
            _ => Typed::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(w: &mut TypedWord, s: &str) {
        for c in s.chars() {
            w.key(Key::Char(c), FORMAT);
        }
    }

    #[test]
    fn only_the_word_confirms() {
        let mut w = TypedWord::new();
        typed(&mut w, "forma");
        assert_eq!(w.key(Key::Enter, FORMAT), Typed::Pending);
        assert!(w.wrong);
        typed(&mut w, "t");
        assert!(!w.wrong);
        assert_eq!(w.text(), "FORMAT");
        assert_eq!(w.key(Key::Enter, FORMAT), Typed::Confirmed);
        assert_eq!(w.text(), "", "cleared once used");
    }

    #[test]
    fn digits_are_ignored_and_backspace_edits_then_cancels() {
        let mut w = TypedWord::new();
        typed(&mut w, "W1i");
        assert_eq!(w.text(), "WI");
        assert_eq!(w.key(Key::Backspace, WIPE), Typed::Pending);
        assert_eq!(w.key(Key::Backspace, WIPE), Typed::Pending);
        assert_eq!(w.key(Key::Backspace, WIPE), Typed::Cancelled);
        typed(&mut w, "WIPE");
        assert_eq!(w.key(Key::Esc, WIPE), Typed::Cancelled);
        assert_eq!(w.text(), "");
    }
}
