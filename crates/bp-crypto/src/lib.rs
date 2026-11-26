//! Bitpunk Signer cryptographic primitives.
//!
//! Independent implementation: no external crypto crates in production code.
//! Reference crates are used only as `dev-dependencies` for differential tests.
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod aes;
pub mod argon2;
pub mod blake2b;
pub mod chacha20poly1305;
pub mod drbg;
pub mod hashes;
pub mod hkdf;
pub mod hmac;
pub mod pbkdf2;
pub mod pbkdf2_sha256;
pub mod ripemd160;
pub mod secp256k1;
pub mod secret;
pub mod sha1;
pub mod sha256;
pub mod sha512;

pub use hmac::HmacSha512;
pub use pbkdf2::pbkdf2_hmac_sha512;
pub use ripemd160::Ripemd160;
pub use sha256::Sha256;
pub use sha512::Sha512;
