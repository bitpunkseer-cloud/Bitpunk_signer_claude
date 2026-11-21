//! Address verification: does a scanned address belong to a loaded seed?
//!
//! The address is decoded to its scriptPubKey for the device's network
//! (strictly: an address of another network is refused, never guessed),
//! then compared byte for byte with the scriptPubKeys derived from every
//! loaded seed and account, receive and change chains interleaved at each
//! index. The search runs in small steps so the screen stays responsive:
//!
//! 1. the index the QR names (`?index=N`), if any;
//! 2. around the index found last in this session;
//! 3. indices 0, 1, 2, ... in batches of [`BATCH`]; after each batch the
//!    user chooses to search more, try another account, or stop.

use crate::address::{taproot_output_key, ScriptType};
use crate::bip32::Xpub;
use crate::{base58, bech32, Network};
use bp_crypto::hashes::hash160;
use bp_crypto::secp256k1::PublicKey;

/// Longest single-key scriptPubKey (P2TR: OP_1 <32 bytes>).
pub const MAX_SPK: usize = 34;
/// Indices per batch before asking the user.
pub const BATCH: u32 = 1000;
/// Seeds x accounts searched at once.
pub const MAX_ACCOUNTS: usize = 12;
/// Indices checked on each side of the last index found.
const NEAR: u32 = 20;

/// The scriptPubKey `st` gives `pk`; returns its length.
pub fn script_pubkey(pk: &PublicKey, st: ScriptType, out: &mut [u8; MAX_SPK]) -> usize {
    match st {
        ScriptType::NativeSegwit => {
            out[0] = 0x00;
            out[1] = 0x14;
            out[2..22].copy_from_slice(&hash160(&pk.serialize()));
            22
        }
        ScriptType::Taproot => {
            out[0] = 0x51;
            out[1] = 0x20;
            let q = taproot_output_key(pk).expect("tweak is valid except with negligible probability");
            out[2..34].copy_from_slice(&q);
            34
        }
        ScriptType::NestedSegwit => {
            let mut redeem = [0u8; 22];
            redeem[1] = 0x14;
            redeem[2..].copy_from_slice(&hash160(&pk.serialize()));
            out[0] = 0xA9;
            out[1] = 0x14;
            out[2..22].copy_from_slice(&hash160(&redeem));
            out[22] = 0x87;
            23
        }
        ScriptType::Legacy => {
            out[..3].copy_from_slice(&[0x76, 0xA9, 0x14]);
            out[3..23].copy_from_slice(&hash160(&pk.serialize()));
            out[23..25].copy_from_slice(&[0x88, 0xAC]);
            25
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetError {
    /// Not a valid address.
    Invalid,
    /// A valid address of another network than the device's.
    WrongNetwork,
    /// P2WSH: a multisig or script wallet (descriptor wallets arrive in M7).
    Multisig,
    /// A valid address of a kind single-key wallets do not use.
    Unsupported,
}

/// The address being verified, as a scriptPubKey and the script type
/// (BIP-44/49/84/86) that would produce it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    spk: [u8; MAX_SPK],
    len: u8,
    st: ScriptType,
}

impl Target {
    /// Decode `addr` for `net`. P2SH is taken as P2SH-P2WPKH (BIP-49).
    pub fn parse(addr: &str, net: Network) -> Result<Target, TargetError> {
        let lower = |s: &str, hrp: &str| {
            s.len() > hrp.len() + 1
                && s.as_bytes()[..hrp.len()].eq_ignore_ascii_case(hrp.as_bytes())
                && s.as_bytes()[hrp.len()] == b'1'
        };
        let mut spk = [0u8; MAX_SPK];
        // "bcrt" before "bc": the longer prefix wins
        for hrp in ["bcrt", "bc", "tb"] {
            if !lower(addr, hrp) {
                continue;
            }
            let a = bech32::decode_segwit(hrp, addr).map_err(|_| TargetError::Invalid)?;
            if hrp != net.hrp() {
                return Err(TargetError::WrongNetwork);
            }
            let st = match (a.version, a.program().len()) {
                (0, 20) => ScriptType::NativeSegwit,
                (0, 32) => return Err(TargetError::Multisig),
                (1, 32) => ScriptType::Taproot,
                _ => return Err(TargetError::Unsupported),
            };
            let mut s = [0u8; 42];
            let n = a.script_pubkey(&mut s);
            spk[..n].copy_from_slice(&s[..n]);
            return Ok(Target {
                spk,
                len: n as u8,
                st,
            });
        }
        let mut raw = [0u8; 25];
        let n = base58::decode_check(addr, &mut raw).map_err(|_| TargetError::Invalid)?;
        if n != 21 {
            return Err(TargetError::Invalid);
        }
        let hash = &raw[1..21];
        let st = if raw[0] == net.p2pkh_version() {
            ScriptType::Legacy
        } else if raw[0] == net.p2sh_version() {
            ScriptType::NestedSegwit
        } else if Network::ALL
            .iter()
            .any(|o| raw[0] == o.p2pkh_version() || raw[0] == o.p2sh_version())
        {
            return Err(TargetError::WrongNetwork);
        } else {
            return Err(TargetError::Invalid);
        };
        let len = match st {
            ScriptType::Legacy => {
                spk[..3].copy_from_slice(&[0x76, 0xA9, 0x14]);
                spk[3..23].copy_from_slice(hash);
                spk[23..25].copy_from_slice(&[0x88, 0xAC]);
                25
            }
            _ => {
                spk[..2].copy_from_slice(&[0xA9, 0x14]);
                spk[2..22].copy_from_slice(hash);
                spk[22] = 0x87;
                23
            }
        };
        Ok(Target { spk, len, st })
    }

    pub fn script(&self) -> &[u8] {
        &self.spk[..self.len as usize]
    }

    pub fn script_type(&self) -> ScriptType {
        self.st
    }
}

/// One seed's account: its receive and change chain keys.
#[derive(Clone, Copy, Debug)]
pub struct Account {
    pub slot: u8,
    pub fingerprint: [u8; 4],
    pub account: u32,
    chains: [Xpub; 2],
}

impl Account {
    /// From the account xpub (`m/purpose'/coin'/account'`).
    pub fn new(slot: u8, fingerprint: [u8; 4], account: u32, xpub: &Xpub) -> Option<Account> {
        Some(Account {
            slot,
            fingerprint,
            account,
            chains: [xpub.derive_child(0).ok()?, xpub.derive_child(1).ok()?],
        })
    }
}

/// Where the address was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub slot: u8,
    pub fingerprint: [u8; 4],
    pub account: u32,
    pub change: bool,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Searching,
    Found(Found),
    /// The batch ended without a match: `more()` continues.
    Paused,
}

/// An index range still to check, [from, to).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Range {
    from: u32,
    to: u32,
}

pub struct Search {
    target: Target,
    accounts: [Option<Account>; MAX_ACCOUNTS],
    n: usize,
    /// Hint, near-last, then the sequential batch (index 2).
    ranges: [Option<Range>; 3],
    stage: usize,
    index: u32,
    /// Next (account, chain) at `index`: account * 2 + chain.
    sub: usize,
    checked: u32,
    state: State,
}

impl Search {
    /// Search `accounts` (the first [`MAX_ACCOUNTS`]) for `target`, first at
    /// `hint`, then around `near`, then from index 0.
    pub fn new<I: IntoIterator<Item = Account>>(
        target: Target,
        accounts: I,
        hint: Option<u32>,
        near: Option<u32>,
    ) -> Search {
        let mut acc = [None; MAX_ACCOUNTS];
        let mut n = 0;
        for a in accounts.into_iter().take(MAX_ACCOUNTS) {
            acc[n] = Some(a);
            n += 1;
        }
        let hint = hint
            .filter(|&i| i < 1 << 31)
            .map(|i| Range { from: i, to: i + 1 });
        let near = near.map(|i| Range {
            from: i.saturating_sub(NEAR),
            to: i.saturating_add(NEAR + 1).min(1 << 31),
        });
        let mut s = Search {
            target,
            accounts: acc,
            n,
            ranges: [hint, near, Some(Range { from: 0, to: BATCH })],
            stage: 0,
            index: 0,
            sub: 0,
            checked: 0,
            state: if n == 0 { State::Paused } else { State::Searching },
        };
        s.enter_stage();
        s
    }

    fn enter_stage(&mut self) {
        while self.stage < 3 && self.ranges[self.stage].is_none() {
            self.stage += 1;
        }
        if let Some(r) = self.ranges.get(self.stage).copied().flatten() {
            self.index = r.from;
            self.sub = 0;
        }
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Candidates (address derivations) checked so far.
    pub fn checked(&self) -> u32 {
        self.checked
    }

    /// The sequential range done so far: indices [0, scanned) of every
    /// account and both chains were checked.
    pub fn scanned(&self) -> u32 {
        match self.stage {
            2 => self.index,
            s if s > 2 => self.ranges[2].map_or(0, |r| r.to),
            _ => 0,
        }
    }

    /// End of the current batch.
    pub fn limit(&self) -> u32 {
        self.ranges[2].map_or(0, |r| r.to)
    }

    pub fn accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts[..self.n].iter().flatten()
    }

    /// Check up to `budget` candidates.
    pub fn step(&mut self, budget: usize) -> State {
        let mut spk = [0u8; MAX_SPK];
        let mut left = budget;
        while self.state == State::Searching && left > 0 {
            let Some(r) = self.ranges.get(self.stage).copied().flatten() else {
                self.state = State::Paused;
                break;
            };
            if self.index >= r.to {
                self.stage += 1;
                self.enter_stage();
                continue;
            }
            let (a, chain) = (self.sub / 2, self.sub % 2);
            if let Some(acc) = self.accounts[a] {
                if let Ok(child) = acc.chains[chain].derive_child(self.index) {
                    let n = script_pubkey(&child.key, self.target.st, &mut spk);
                    self.checked += 1;
                    if &spk[..n] == self.target.script() {
                        self.state = State::Found(Found {
                            slot: acc.slot,
                            fingerprint: acc.fingerprint,
                            account: acc.account,
                            change: chain == 1,
                            index: self.index,
                        });
                    }
                }
            }
            left -= 1;
            self.sub += 1;
            if self.sub == self.n * 2 {
                self.sub = 0;
                self.index += 1;
            }
        }
        self.state
    }

    /// After a pause: search the next batch.
    pub fn more(&mut self) {
        if self.state != State::Paused || self.n == 0 {
            return;
        }
        let to = self.limit();
        self.ranges = [
            None,
            None,
            Some(Range {
                from: to,
                to: to.saturating_add(BATCH).min(1 << 31),
            }),
        ];
        self.stage = 0;
        self.enter_stage();
        self.state = State::Searching;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_of_every_kind_and_network() {
        let t = Target::parse("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", Network::Mainnet).unwrap();
        assert_eq!(t.script_type(), ScriptType::NativeSegwit);
        assert_eq!(t.script().len(), 22);
        assert_eq!(
            Target::parse("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", Network::Testnet),
            Err(TargetError::WrongNetwork)
        );
        assert_eq!(
            Target::parse("BC1QCR8TE4KR609GCAWUTMRZA0J4XV80JY8Z306FYU", Network::Mainnet)
                .map(|t| t.script_type()),
            Ok(ScriptType::NativeSegwit)
        );
        let tr = Target::parse(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(tr.script_type(), ScriptType::Taproot);
        assert_eq!(&tr.script()[..2], &[0x51, 0x20]);
        assert_eq!(
            Target::parse(
                "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
                Network::Mainnet
            ),
            Err(TargetError::Multisig)
        );
        let p2pkh = Target::parse("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Network::Mainnet).unwrap();
        assert_eq!(p2pkh.script_type(), ScriptType::Legacy);
        let p2sh = Target::parse("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Network::Mainnet).unwrap();
        assert_eq!(p2sh.script_type(), ScriptType::NestedSegwit);
        assert_eq!(
            Target::parse("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Network::Signet),
            Err(TargetError::WrongNetwork)
        );
        assert_eq!(
            Target::parse("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3", Network::Mainnet),
            Err(TargetError::Invalid)
        );
        assert_eq!(
            Target::parse("hello", Network::Mainnet),
            Err(TargetError::Invalid)
        );
    }
}
