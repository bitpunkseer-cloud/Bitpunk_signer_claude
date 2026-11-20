//! Bitpunk Signer cryptographic primitives.
//!
//! Independent implementation (no external crypto crates in production code).
//! Planned for Phase 1A: SHA-256/512, RIPEMD-160, HMAC, PBKDF2, secp256k1,
//! ECDSA (RFC 6979), Schnorr (BIP-340). Reference libraries are allowed only
//! as `dev-dependencies` for differential testing.
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod secret;
