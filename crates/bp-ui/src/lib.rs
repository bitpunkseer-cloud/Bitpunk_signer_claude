//! Drawing primitives, bitmap fonts and widgets shared by the device
//! firmware and the web simulator.
#![no_std]

pub mod draw;
pub mod font;
pub mod theme;
pub mod widgets;

pub use bp_hal::{Canvas, Rgb};
