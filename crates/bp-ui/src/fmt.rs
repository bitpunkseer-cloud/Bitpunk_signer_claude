//! Allocation-free string formatting into a stack buffer.

use core::fmt;

pub struct Buf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Default for Buf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Buf<N> {
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    pub fn as_str(&self) -> &str {
        // Only whole UTF-8 sequences are ever written (see write_str).
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }

    pub fn clear(&mut self) {
        self.bytes.fill(0);
        self.len = 0;
    }

    pub fn push_str(&mut self, s: &str) {
        let _ = fmt::Write::write_str(self, s);
    }
}

impl<const N: usize> fmt::Write for Buf<N> {
    /// Writes as much as fits, never splitting a UTF-8 character.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            let mut tmp = [0u8; 4];
            let enc = ch.encode_utf8(&mut tmp).as_bytes();
            if self.len + enc.len() > N {
                return Err(fmt::Error);
            }
            self.bytes[self.len..self.len + enc.len()].copy_from_slice(enc);
            self.len += enc.len();
        }
        Ok(())
    }
}

impl<const N: usize> Drop for Buf<N> {
    fn drop(&mut self) {
        // Buffers may hold seed words; wipe them.
        bp_hal_wipe(&mut self.bytes);
    }
}

fn bp_hal_wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: valid exclusive reference.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
}

impl<const N: usize> fmt::Display for Buf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Substitute each `{}` in a translatable `template` with the next argument.
/// Keeps word order in the string table, so translations can reorder text.
pub fn fill<const N: usize>(template: &str, args: &[&dyn fmt::Display]) -> Buf<N> {
    let mut out = Buf::<N>::new();
    let mut rest = template;
    let mut it = args.iter();
    while let Some(pos) = rest.find("{}") {
        out.push_str(&rest[..pos]);
        if let Some(a) = it.next() {
            let _ = fmt::Write::write_fmt(&mut out, format_args!("{a}"));
        }
        rest = &rest[pos + 2..];
    }
    out.push_str(rest);
    out
}

/// `format!`-like macro returning a `Buf<N>`.
#[macro_export]
macro_rules! bformat {
    ($n:expr, $($arg:tt)*) => {{
        let mut b = $crate::fmt::Buf::<$n>::new();
        let _ = core::fmt::Write::write_fmt(&mut b, format_args!($($arg)*));
        b
    }};
}

#[cfg(test)]
mod tests {

    #[test]
    fn fill_substitutes_in_order() {
        let b: super::Buf<32> = super::fill("{} of {} words", &[&3, &"12"]);
        assert_eq!(b.as_str(), "3 of 12 words");
    }

    #[test]
    fn formats_and_truncates() {
        let b = bformat!(16, "{} / {}", 57, 50);
        assert_eq!(b.as_str(), "57 / 50");
        let t = bformat!(4, "abcdef");
        assert_eq!(t.as_str(), "abcd");
    }
}
