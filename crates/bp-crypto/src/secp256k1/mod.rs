//! secp256k1 elliptic curve: field, scalars and points.
//!
//! Independent implementation. Differentially tested against libsecp256k1
//! (dev-dependency only). Signing (ECDSA, Schnorr) arrives in M5.

pub mod ct;
pub mod field;
pub mod point;
pub mod scalar;

pub use point::{Point, PublicKey};
pub use scalar::{Scalar, SecretKey};
