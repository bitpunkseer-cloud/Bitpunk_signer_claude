//! PSBT validation: everything the device establishes before a
//! transaction is shown or signed.
//!
//! Trust model (M5 plan §3). Every fingerprint, path, key, script and
//! amount in a PSBT is a claim by the host: `Claimed<T>` can be displayed,
//! never decided on. A fact the device relies on is a `Verified<T>`, which
//! only this module can create, and only after re-deriving the key from the
//! seed and rebuilding the script (or hashing the previous transaction).
//! Screens and the signer take `Verified<T>` only.
//!
//! Problems are classified as attacks (red screen, no signing), errors
//! (no signing) and warnings (each must be confirmed; some block by
//! default until the user explicitly overrides them).

mod inputs;
pub mod script;

use crate::address::ScriptType;
use crate::bip32::{DerivationPath, Xpriv, Xpub, HARDENED};
use crate::psbt::{KeySource, ParseError, Psbt};
use crate::Network;
use bp_crypto::secp256k1::PublicKey;

/// A value as the host stated it. It may be shown, never relied on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claimed<T>(T);

impl<T> Claimed<T> {
    pub fn new(t: T) -> Self {
        Claimed(t)
    }

    pub fn claim(&self) -> &T {
        &self.0
    }
}

/// A fact the device established itself. There is no public constructor:
/// only the checks in this module create one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    pub fn get(&self) -> &T {
        &self.0
    }
}

pub const MAX_INPUTS: usize = 128;
pub const MAX_OUTPUTS: usize = 64;
pub const MAX_ISSUES: usize = 24;
/// Fingerprints listed on the "wrong seed" screen.
pub const MAX_FINGERPRINTS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    Warning,
    Error,
    Attack,
}

/// Where a problem is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    Input(u16),
    Output(u16),
    Global,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issue {
    // ---- attacks
    /// A key or xpub with this seed's fingerprint that the seed does not
    /// derive at the stated path.
    KeyNotFromSeed(At),
    /// An input claims this seed's key, but its scriptPubKey is not built
    /// from it.
    ScriptNotOurs(u16),
    /// A redeem script that does not hash to the P2SH commitment.
    RedeemMismatch(u16),
    /// A witness script that does not hash to the P2WSH commitment.
    WitnessScriptMismatch(u16),
    /// The previous transaction is not the one the outpoint names, or the
    /// witness UTXO contradicts it.
    PrevTxMismatch(u16),

    // ---- errors (no signing)
    Parse(ParseError),
    /// More inputs or outputs than the device handles.
    TooLarge,
    /// An input of this seed with neither previous transaction nor witness
    /// UTXO, or (Taproot) any input without one.
    MissingUtxo(u16),
    /// A legacy input without its previous transaction.
    MissingPrevTx(u16),
    MissingRedeemScript(u16),
    /// A redeem or witness script the input's type does not use.
    UnneededScript(u16),
    /// This seed's key in a script the signer does not support yet
    /// (multisig, P2WSH, script trees: M7).
    UnsupportedInput(u16),
    /// This seed's key only in a Taproot script leaf (M7).
    TaprootScriptPath(u16),
    /// Claims that contradict each other (e.g. Taproot internal key).
    InconsistentInput(u16),
    UncompressedKey(u16),
    DuplicateInput(u16),
    /// A derivation path deeper than the device supports.
    PathTooDeep(At),
    /// A global xpub of this seed for another network.
    XpubNetwork,
    /// No input belongs to this seed (see `Report::fingerprints`).
    NoInputsForSeed,
    /// Every input of this seed is already signed or finalized.
    NothingToSign,

    // ---- warnings
    /// Segwit v0 inputs without previous transactions in a transaction
    /// with several inputs: amounts cannot be verified (CVE-2020-14199).
    /// Blocks until the user explicitly overrides it for this transaction.
    UnverifiedAmounts,
    /// Inputs that do not belong to this seed (e.g. PayJoin).
    ExternalInputs,
    /// Some inputs of this seed already carry signatures.
    PartlySigned,
}

impl Issue {
    pub fn class(&self) -> Class {
        use Issue::*;
        match self {
            KeyNotFromSeed(_)
            | ScriptNotOurs(_)
            | RedeemMismatch(_)
            | WitnessScriptMismatch(_)
            | PrevTxMismatch(_) => Class::Attack,
            Parse(ParseError::UtxoMismatch) => Class::Attack,
            UnverifiedAmounts | ExternalInputs | PartlySigned => Class::Warning,
            _ => Class::Error,
        }
    }

    /// Warnings that block signing until explicitly overridden.
    pub fn needs_override(&self) -> bool {
        matches!(self, Issue::UnverifiedAmounts)
    }
}

/// How an input amount is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountSource {
    /// From the previous transaction, whose hash is the outpoint.
    PrevTx,
    /// From the witness UTXO of a Taproot input: BIP-341 signatures commit
    /// to every input's amount, so a wrong value invalidates them.
    TaprootCommitted,
    /// From the witness UTXO only (a claim). BIP-143 commits to this
    /// input's amount alone, so with several inputs a host can lie across
    /// signing rounds (CVE-2020-14199).
    WitnessUtxo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendKind {
    P2wpkh,
    P2shP2wpkh,
    P2pkh,
    P2trKey,
}

impl SpendKind {
    pub fn script_type(self) -> ScriptType {
        match self {
            SpendKind::P2wpkh => ScriptType::NativeSegwit,
            SpendKind::P2shP2wpkh => ScriptType::NestedSegwit,
            SpendKind::P2pkh => ScriptType::Legacy,
            SpendKind::P2trKey => ScriptType::Taproot,
        }
    }
}

/// An input whose key the seed derives and whose script is built from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedInput {
    pub kind: SpendKind,
    pub path: DerivationPath,
    pub pubkey: PublicKey,
    pub amount: u64,
    pub source: AmountSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputReport {
    pub owned: Option<Verified<OwnedInput>>,
    /// The amount if known (a claim for other inputs without a previous
    /// transaction; see `source`).
    pub amount: Option<u64>,
    pub source: Option<AmountSource>,
    pub finalized: bool,
    /// Already carries this seed's signature.
    pub signed: bool,
}

impl InputReport {
    const EMPTY: InputReport = InputReport {
        owned: None,
        amount: None,
        source: None,
        finalized: false,
        signed: false,
    };
}

/// The result of validation.
pub struct Report {
    pub master_fingerprint: [u8; 4],
    n_inputs: usize,
    inputs: [InputReport; MAX_INPUTS],
    issues: [Issue; MAX_ISSUES],
    n_issues: usize,
    /// More issues than fit (the worst ones are kept).
    pub truncated: bool,
    fingerprints: [[u8; 4]; MAX_FINGERPRINTS],
    n_fingerprints: usize,
}

impl Report {
    fn new(master_fingerprint: [u8; 4]) -> Self {
        Report {
            master_fingerprint,
            n_inputs: 0,
            inputs: [InputReport::EMPTY; MAX_INPUTS],
            issues: [Issue::TooLarge; MAX_ISSUES],
            n_issues: 0,
            truncated: false,
            fingerprints: [[0; 4]; MAX_FINGERPRINTS],
            n_fingerprints: 0,
        }
    }

    pub fn issues(&self) -> &[Issue] {
        &self.issues[..self.n_issues]
    }

    pub fn inputs(&self) -> &[InputReport] {
        &self.inputs[..self.n_inputs]
    }

    /// Other fingerprints the PSBT names (the "need / found" screen).
    pub fn fingerprints(&self) -> &[[u8; 4]] {
        &self.fingerprints[..self.n_fingerprints]
    }

    pub fn worst(&self) -> Option<Class> {
        self.issues().iter().map(|i| i.class()).max()
    }

    pub fn has(&self, issue: Issue) -> bool {
        self.issues().contains(&issue)
    }

    /// Signing is possible: no attack or error, and every blocking
    /// warning overridden.
    pub fn can_sign(&self, overridden: bool) -> bool {
        self.worst() < Some(Class::Error) && (overridden || !self.issues().iter().any(|i| i.needs_override()))
    }

    fn push(&mut self, issue: Issue) {
        if self.has(issue) {
            return;
        }
        if self.n_issues < MAX_ISSUES {
            self.issues[self.n_issues] = issue;
            self.n_issues += 1;
            return;
        }
        self.truncated = true;
        // keep the worst: replace the first strictly milder issue
        if let Some(slot) = self.issues.iter_mut().find(|i| i.class() < issue.class()) {
            *slot = issue;
        }
    }

    fn note_fingerprint(&mut self, fp: [u8; 4]) {
        if fp != self.master_fingerprint
            && !self.fingerprints().contains(&fp)
            && self.n_fingerprints < MAX_FINGERPRINTS
        {
            self.fingerprints[self.n_fingerprints] = fp;
            self.n_fingerprints += 1;
        }
    }
}

/// What validation needs from the loaded seed.
pub struct Context<'a> {
    pub master: &'a Xpriv,
    pub network: Network,
}

/// Why a claimed key could not be confirmed.
enum DeriveError {
    TooDeep,
    Failed,
}

/// Re-derives claimed keys from the master key. Only public account keys
/// are cached; private keys exist just while a hardened prefix is derived.
struct Deriver<'a> {
    master: &'a Xpriv,
    fingerprint: [u8; 4],
    cache: [Option<(DerivationPath, Xpub)>; 4],
    next: usize,
}

impl<'a> Deriver<'a> {
    fn new(master: &'a Xpriv) -> Self {
        Deriver {
            master,
            fingerprint: master.fingerprint(),
            cache: [None; 4],
            next: 0,
        }
    }

    fn xpub(&mut self, src: &KeySource) -> Result<Xpub, DeriveError> {
        let path = src.to_path().ok_or(DeriveError::TooDeep)?;
        let steps = path.steps();
        let split = steps.iter().rposition(|s| s & HARDENED != 0).map_or(0, |i| i + 1);
        let prefix = DerivationPath::from_steps(&steps[..split]).map_err(|_| DeriveError::TooDeep)?;
        let cached = self
            .cache
            .iter()
            .flatten()
            .find(|(p, _)| *p == prefix)
            .map(|(_, x)| *x);
        let mut x = match cached {
            Some(x) => x,
            None => {
                let k = self
                    .master
                    .derive_path(&prefix)
                    .map_err(|_| DeriveError::Failed)?;
                let x = k.to_xpub();
                self.cache[self.next] = Some((prefix, x));
                self.next = (self.next + 1) % self.cache.len();
                x
            }
        };
        for &s in &steps[split..] {
            x = x.derive_child(s).map_err(|_| DeriveError::Failed)?;
        }
        Ok(x)
    }
}

/// Parse and validate. The PSBT view is returned when it parsed.
pub fn validate<'a>(raw: &'a [u8], ctx: &Context) -> (Option<Psbt<'a>>, Report) {
    let mut d = Deriver::new(ctx.master);
    let mut report = Report::new(d.fingerprint);
    let psbt = match Psbt::parse(raw) {
        Ok(p) => p,
        Err(e) => {
            report.push(Issue::Parse(e));
            return (None, report);
        }
    };
    if psbt.tx.n_inputs() > MAX_INPUTS || psbt.tx.n_outputs() > MAX_OUTPUTS {
        report.push(Issue::TooLarge);
        return (Some(psbt), report);
    }
    report.n_inputs = psbt.tx.n_inputs();
    check_global_xpubs(&psbt, ctx, &mut d, &mut report);
    inputs::check(&psbt, &mut d, &mut report);
    (Some(psbt), report)
}

/// Global xpubs naming this seed must be what the seed derives there.
fn check_global_xpubs(psbt: &Psbt, ctx: &Context, d: &mut Deriver, report: &mut Report) {
    for (x, src) in psbt.xpubs() {
        if src.fingerprint != d.fingerprint {
            report.note_fingerprint(src.fingerprint);
            continue;
        }
        let mainnet = x[..4] == [0x04, 0x88, 0xB2, 0x1E];
        if mainnet != (ctx.network == Network::Mainnet) {
            report.push(Issue::XpubNetwork);
        }
        let ours = match d.xpub(&src) {
            Ok(x) => x,
            Err(DeriveError::TooDeep) => {
                report.push(Issue::PathTooDeep(At::Global));
                continue;
            }
            Err(DeriveError::Failed) => {
                report.push(Issue::KeyNotFromSeed(At::Global));
                continue;
            }
        };
        let same = x[4] == ours.depth
            && x[5..9] == ours.parent_fingerprint
            && x[9..13] == ours.child_number.to_be_bytes()
            && x[13..45] == ours.chain_code
            && x[45..78] == ours.key.serialize();
        if !same {
            report.push(Issue::KeyNotFromSeed(At::Global));
        }
    }
}
