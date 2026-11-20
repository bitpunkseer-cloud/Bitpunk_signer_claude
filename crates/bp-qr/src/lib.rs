//! Bitpunk Signer QR layer: QR encoder and decoder, BC-UR, BBQr and
//! Specter formats.
//!
//! Independent implementation; reference crates are dev-dependencies only.
#![no_std]

pub mod bbqr;
pub mod decode;
pub mod deflate;
pub mod qr;
pub mod rs;
pub mod ur;

pub use qr::{Ecc, Mode, QrCode};
