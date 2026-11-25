//! Backups and offline tools (M11, approved plan `docs/milestones/M11_PLAN.md`).
//!
//! | module | what |
//! |---|---|
//! | `slip39` | SLIP-39 Shamir shares: words, RS1024, GF(256), Feistel cipher, split and recovery |
//!
//! Independent code: reference implementations are used only in tests (as
//! fixtures generated from them, or dev-dependencies).
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod slip39;
