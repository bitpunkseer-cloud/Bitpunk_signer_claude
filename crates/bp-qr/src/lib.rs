//! Bitpunk Signer QR layer: QR encoder, BC-UR, BBQr and Specter formats.
//!
//! Independent implementation; reference crates are dev-dependencies only.
#![no_std]

pub mod bbqr;
pub mod deflate;
pub mod qr;
pub mod ur;

pub use qr::{Ecc, Mode, QrCode};
