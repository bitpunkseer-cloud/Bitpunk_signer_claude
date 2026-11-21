//! Multisig inputs and outputs (M7 plan 8, S1–S9).
//!
//! A multisig script is trusted only when it is rebuilt from a registered
//! wallet: the PSBT's derivation paths are used to find the (branch, index)
//! to rebuild at, and every one of them must then agree with the wallet.
//! An input this seed would sign must be a registered wallet's script; an
//! output that claims to be a registered wallet's address but is not is an
//! attack.

use super::{At, Context, Issue};
use crate::bip32::{DerivationPath, HARDENED};
use crate::multisig::{is_sorted, parse_multisig_script, Branch, MsScript, Scripts, Wallet, MAX_KEYS};
use crate::psbt::KeySource;
use crate::sighash::{self, SegwitV0Hashes};
use crate::tx::Tx;
use bp_crypto::secp256k1::{ecdsa, PublicKey};

/// Where in a registered wallet a script is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsSpend {
    /// Registry slot of the wallet.
    pub wallet: u8,
    pub m: u8,
    pub n: u8,
    /// 0 receive, 1 change.
    pub branch: u8,
    pub index: u32,
}

/// One wallet's two branches, derived once per validation.
pub(super) struct Cache {
    wallet: Option<u8>,
    branches: [Option<Branch>; 2],
}

impl Cache {
    pub(super) fn new() -> Self {
        Cache {
            wallet: None,
            branches: [None, None],
        }
    }

    fn branch(&mut self, slot: u8, w: &Wallet, b: u8) -> Option<&Branch> {
        if self.wallet != Some(slot) {
            self.wallet = Some(slot);
            self.branches = [None, None];
        }
        let e = &mut self.branches[b as usize];
        if e.is_none() {
            *e = w.branch(b as u32).ok();
        }
        e.as_ref()
    }
}

/// The registered wallets (slot, wallet) whose key with this seed's
/// fingerprint is a prefix of `path` followed by exactly `/branch/index`.
fn candidates<'w>(
    ctx: &Context<'w>,
    fp: [u8; 4],
    script: MsScript,
    path: &DerivationPath,
) -> impl Iterator<Item = (u8, &'w Wallet, u8, u32)> + 'w {
    let path = *path;
    ctx.multisig.iter().enumerate().filter_map(move |(slot, w)| {
        let w = (*w)?;
        if w.script != script {
            return None;
        }
        let ours = w.keys().iter().find(|k| k.fingerprint == fp)?;
        let (b, i) = tail(&ours.origin, &path)?;
        Some((slot as u8, w, b, i))
    })
}

/// `path` = `origin / b / i` with b ∈ {0, 1} and i unhardened.
fn tail(origin: &DerivationPath, path: &DerivationPath) -> Option<(u8, u32)> {
    let o = origin.steps();
    let p = path.steps();
    if p.len() != o.len() + 2 || &p[..o.len()] != o {
        return None;
    }
    let (b, i) = (p[o.len()], p[o.len() + 1]);
    (b <= 1 && i & HARDENED == 0).then_some((b as u8, i))
}

/// Every derivation claim must name a wallet key at `origin/b/i` and give
/// the key the wallet derives there.
fn claims_agree<'a, I: Iterator<Item = (&'a [u8], KeySource<'a>)>>(
    w: &Wallet,
    child: &[[u8; 33]; MAX_KEYS],
    b: u8,
    i: u32,
    claims: &dyn Fn() -> I,
) -> bool {
    for (key, src) in claims() {
        let Some(path) = src.to_path() else { return false };
        let found = w.keys().iter().enumerate().any(|(j, k)| {
            k.fingerprint == src.fingerprint && tail(&k.origin, &path) == Some((b, i)) && key == child[j]
        });
        if !found {
            return false;
        }
    }
    true
}

/// What a multisig input turned out to be. (No allocator: the rebuilt
/// scripts are returned by value; the value lives for one input.)
#[allow(clippy::large_enum_variant)]
pub(super) enum InputMatch {
    /// A registered wallet's script; the scripts as rebuilt.
    Registered(MsSpend, Scripts),
    /// Not rebuilt from any registered wallet (also: unsorted keys).
    Unregistered,
    /// Rebuilt, but a derivation claim contradicts the wallet.
    ClaimMismatch,
}

/// An input whose script is `ws` (wrapped as `script`), where this seed's
/// key `ours` is claimed at `path`.
#[allow(clippy::too_many_arguments)]
pub(super) fn input<'a, I: Iterator<Item = (&'a [u8], KeySource<'a>)>>(
    ctx: &Context,
    cache: &mut Cache,
    script: MsScript,
    path: &DerivationPath,
    ours: &PublicKey,
    spk: &[u8],
    ws: &[u8],
    claims: &dyn Fn() -> I,
) -> InputMatch {
    let Some((_, keys, n)) = parse_multisig_script(ws) else {
        return InputMatch::Unregistered;
    };
    if !is_sorted(&keys[..n as usize]) {
        return InputMatch::Unregistered;
    }
    let fp = ctx.master.fingerprint();
    for (slot, w, b, i) in candidates(ctx, fp, script, path) {
        let Some(br) = cache.branch(slot, w, b) else {
            continue;
        };
        let Ok(child) = br.child_keys(i) else { continue };
        let sc = br.scripts(&child);
        if sc.witness_script() != ws || sc.script_pubkey() != spk {
            continue;
        }
        // this seed's key really is in it (the registered key is ours)
        if !sc.pubkeys().contains(&ours.serialize()) {
            continue;
        }
        if !claims_agree(w, &child, b, i, claims) {
            return InputMatch::ClaimMismatch;
        }
        return InputMatch::Registered(
            MsSpend {
                wallet: slot,
                m: w.m,
                n: w.n(),
                branch: b,
                index: i,
            },
            sc,
        );
    }
    InputMatch::Unregistered
}

/// What a multisig output turned out to be.
pub(super) enum OutputMatch {
    /// No claim of this seed's key at a registered wallet's path.
    Unknown,
    /// A registered wallet's address.
    Registered(MsSpend),
}

/// An output paying `spk` (P2WSH, or P2SH that may wrap one) with this
/// seed's key claimed at `path`: if the path is a registered wallet's, the
/// script must be that wallet's (else `Err`: an attack).
pub(super) fn output<'a, I: Iterator<Item = (&'a [u8], KeySource<'a>)>>(
    ctx: &Context,
    cache: &mut Cache,
    idx: u16,
    path: &DerivationPath,
    spk: &[u8],
    ws: Option<&[u8]>,
    claims: &dyn Fn() -> I,
) -> Result<OutputMatch, Issue> {
    let fp = ctx.master.fingerprint();
    let mut claimed = false;
    for script in [MsScript::Wsh, MsScript::ShWsh] {
        for (slot, w, b, i) in candidates(ctx, fp, script, path) {
            claimed = true;
            let Some(br) = cache.branch(slot, w, b) else {
                continue;
            };
            let Ok(child) = br.child_keys(i) else { continue };
            let sc = br.scripts(&child);
            if sc.script_pubkey() != spk {
                continue;
            }
            if ws.is_some_and(|ws| ws != sc.witness_script()) || !claims_agree(w, &child, b, i, claims) {
                return Err(Issue::ChangeContradiction(idx));
            }
            return Ok(OutputMatch::Registered(MsSpend {
                wallet: slot,
                m: w.m,
                n: w.n(),
                branch: b,
                index: i,
            }));
        }
    }
    if claimed {
        // claims to be a registered wallet's address, and is not
        return Err(Issue::ChangeContradiction(idx));
    }
    Ok(OutputMatch::Unknown)
}

/// Valid signatures by the wallet's other keys on input `i` (scripts as
/// rebuilt), and whether any signature is bad or by a key not in it.
pub(super) fn cosigner_signatures<'a>(
    tx: &Tx,
    hashes: &SegwitV0Hashes,
    i: usize,
    sc: &Scripts,
    amount: u64,
    ours: &PublicKey,
    sigs: impl Iterator<Item = (&'a [u8], &'a [u8])>,
) -> (u8, bool) {
    let digest = sighash::segwit_v0(tx, hashes, i, sc.witness_script(), amount, sighash::ALL as u32);
    let (mut good, mut bad) = (0u8, false);
    let our = ours.serialize();
    for (key, sig) in sigs {
        if key == our {
            continue; // this seed's own: checked elsewhere ("already signed")
        }
        let ok = (|| {
            if !sc.pubkeys().iter().any(|k| k[..] == *key) {
                return None;
            }
            let (&ht, der) = sig.split_last()?;
            if ht != sighash::ALL {
                return None;
            }
            let pk = PublicKey::parse(key)?;
            let s = ecdsa::Signature::from_der(der)?;
            ecdsa::verify(&pk, digest.as_ref()?, &s).then_some(())
        })();
        match ok {
            Some(()) => good += 1,
            None => bad = true,
        }
    }
    (good, bad)
}

/// Global xpubs naming a key of the spending wallet at its origin must be
/// that key (another chain code or key there is an attack).
pub(super) fn global_xpubs(psbt: &crate::psbt::Psbt, w: &Wallet) -> Option<Issue> {
    for (x, src) in psbt.xpubs() {
        let Some(path) = src.to_path() else { continue };
        for k in w.keys() {
            if k.fingerprint == src.fingerprint && k.origin == path {
                let same = x[13..45] == k.xpub.chain_code && x[45..78] == k.xpub.key.serialize();
                if !same {
                    return Some(Issue::GlobalXpubMismatch);
                }
            }
        }
    }
    None
}

/// For `Issue` locations in this module.
pub(super) fn at_input(i: usize) -> At {
    At::Input(i as u16)
}
