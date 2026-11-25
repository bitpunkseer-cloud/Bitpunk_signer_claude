//! Backups and offline tools (M11, approved plan `docs/milestones/M11_PLAN.md`).
//!
//! | module | what |
//! |---|---|
//! | `slip39` | SLIP-39 Shamir shares: words, RS1024, GF(256), Feistel cipher, split and recovery |
//! | `seedxor` | Seed XOR: Coldcard's deterministic split (optionally with dice), combining parts |
//!
//! Independent code: reference implementations are used only in tests (as
//! fixtures generated from them, or dev-dependencies).
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod seedxor;
pub mod slip39;
