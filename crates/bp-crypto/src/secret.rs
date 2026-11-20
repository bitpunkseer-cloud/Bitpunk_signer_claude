//! Containers for secret material that are wiped on drop and never printed.

use core::fmt;
use core::sync::atomic::{compiler_fence, Ordering};

/// Overwrite a byte slice with zeros in a way the optimizer must not elide.
pub fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference to a u8.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Overwrite a u16 slice (e.g. word indices) with zeros.
pub fn wipe_u16(values: &mut [u16]) {
    for v in values.iter_mut() {
        // SAFETY: `v` is a valid, aligned, exclusive reference to a u16.
        unsafe { core::ptr::write_volatile(v, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Fixed-size secret buffer. Zeroized on drop; `Debug` never shows contents.
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_zeroes() {
        let mut b = [0xAAu8; 32];
        wipe(&mut b);
        assert!(b.iter().all(|&x| x == 0));
    }

    #[test]
    fn debug_hides_contents() {
        extern crate std;
        use std::format;
        let s = Secret::new([7u8; 4]);
        assert_eq!(format!("{s:?}"), "Secret<4>(***)");
    }
}
