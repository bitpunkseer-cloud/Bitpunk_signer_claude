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

mod fees;
mod inputs;
pub mod memory;
mod outputs;
pub mod script;

pub use memory::UtxoMemory;

use crate::address::ScriptType;
use crate::bip32::{DerivationPath, Xpriv, Xpub, HARDENED};
use crate::psbt::{KeySource, ParseError, Psbt};
use crate::Network;
use bp_crypto::secp256k1::PublicKey;
use bp_crypto::sha256::Sha256;
use core::fmt::Write as _;

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
    /// An output claims this seed's key, but its script is not built from
    /// it (SeedSigner's "output ownership contradiction").
    ChangeContradiction(u16),
    /// Change that breaks the path rules: wrong depth or hardening, purpose
    /// not matching the script, branch other than 0/1, or change into an
    /// account that is not spending.
    ChangePathViolation(u16),
    /// An outpoint signed since power-on comes back with another amount.
    UtxoAmountChanged(u16),

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
    /// A claim on the master key or a one-level path (no wallet uses it).
    PathTooShort(At),
    /// A single-key output with more than one derivation entry, or entries
    /// in both the BIP-32 and the Taproot maps.
    SurplusClaims(u16),
    /// Segwit v0 inputs from different base paths without previous
    /// transactions (SeedSigner refuses this; no override).
    UnverifiedMixedBasePaths,
    /// A global xpub of this seed for another network.
    XpubNetwork,
    /// No input belongs to this seed (see `Report::fingerprints`).
    NoInputsForSeed,
    /// Every input of this seed is already signed or finalized.
    NothingToSign,
    /// Outputs exceed inputs.
    NegativeFee,
    /// The fee is at least the blocking share of the outputs (policy;
    /// adjustable in M6).
    FeeTooHigh,
    /// An amount above 21 million BTC, or totals that overflow.
    ValueOutOfRange,
    /// A sighash type other than ALL (Taproot: DEFAULT or ALL).
    NonStandardSighash(u16),
    /// An OP_RETURN output with a non-zero amount (burns coins).
    BadOpReturn(u16),
    /// A path of this seed for another network (coin type).
    NetworkMismatch(At),

    // ---- warnings
    /// Segwit v0 inputs without previous transactions in a transaction
    /// with several inputs: amounts cannot be verified (CVE-2020-14199).
    /// Blocks until the user explicitly overrides it for this transaction.
    UnverifiedAmounts,
    /// Inputs that do not belong to this seed (e.g. PayJoin).
    ExternalInputs,
    /// Some inputs of this seed already carry signatures.
    PartlySigned,
    /// The fee is at least the warning share of the outputs.
    HighFee,
    /// More than the warning fee rate (sat/vB).
    HighFeeRate,
    /// Some input amounts are unknown, so the fee is too.
    FeeUnknown,
    /// No change: everything goes to recipients and the fee.
    NoChange,
    /// A change index far beyond the inputs' indexes.
    ChangeIndexFar(u16),
    /// Inputs of different script types.
    MixedScriptTypes,
    /// Inputs from different accounts.
    MultipleAccounts,
    /// Several OP_RETURN outputs or more than 80 bytes of data.
    OpReturnNonStandard,
    /// An output script the device cannot show as an address.
    UnknownScript(u16),
    /// A zero-amount output.
    ZeroValue(u16),
}

impl Issue {
    pub fn class(&self) -> Class {
        use Issue::*;
        match self {
            KeyNotFromSeed(_)
            | ScriptNotOurs(_)
            | RedeemMismatch(_)
            | WitnessScriptMismatch(_)
            | PrevTxMismatch(_)
            | ChangeContradiction(_)
            | ChangePathViolation(_)
            | UtxoAmountChanged(_)
            | Parse(ParseError::UtxoMismatch) => Class::Attack,
            UnverifiedAmounts | ExternalInputs | PartlySigned | HighFee | HighFeeRate | FeeUnknown
            | NoChange | ChangeIndexFar(_) | MixedScriptTypes | MultipleAccounts | OpReturnNonStandard
            | UnknownScript(_) | ZeroValue(_) => Class::Warning,
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

/// An output whose key the seed derives and whose script is built from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedOutput {
    pub kind: SpendKind,
    pub path: DerivationPath,
    pub pubkey: PublicKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputKind {
    /// A recipient (anything not verified as this seed's).
    External,
    /// Branch 1 of an account that is spending.
    Change(Verified<OwnedOutput>),
    /// Branch 0 of one of this seed's accounts.
    SelfSend(Verified<OwnedOutput>),
    OpReturn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputReport {
    pub kind: OutputKind,
    pub amount: u64,
}

impl OutputReport {
    const EMPTY: OutputReport = OutputReport {
        kind: OutputKind::External,
        amount: 0,
    };
}

/// Amounts for the overview screen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    /// This seed's inputs.
    pub ours: u64,
    /// All inputs, if every amount is known.
    pub inputs: Option<u64>,
    pub outputs: u64,
    pub recipients: u64,
    pub change: u64,
    pub self_send: u64,
    pub fee: Option<u64>,
    /// Estimated size of the signed transaction.
    pub vsize: u64,
}

impl Totals {
    /// Fee rate in milli-satoshi per vbyte.
    pub fn fee_rate_msat_vb(&self) -> Option<u64> {
        Some(self.fee? * 1000 / self.vsize.max(1))
    }
}

/// Thresholds (defaults from the M5 plan; settings arrive in M6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Warn when the fee is at least this percentage of all outputs.
    pub fee_warn_percent: u64,
    /// Refuse when the fee is at least this percentage of all outputs.
    pub fee_block_percent: u64,
    /// Warn above this fee rate (sat/vB).
    pub fee_rate_warn: u64,
    /// Warn when change is this far beyond the inputs' address indexes.
    pub change_index_gap: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            fee_warn_percent: 5,
            fee_block_percent: 10,
            fee_rate_warn: 1000,
            change_index_gap: 10_000,
        }
    }
}

/// The result of validation.
pub struct Report {
    pub master_fingerprint: [u8; 4],
    n_inputs: usize,
    inputs: [InputReport; MAX_INPUTS],
    n_outputs: usize,
    outputs: [OutputReport; MAX_OUTPUTS],
    pub totals: Totals,
    /// Non-zero lock time (shown for information).
    pub lock_time: u32,
    /// Replace-by-fee signalled.
    pub rbf: bool,
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
            n_outputs: 0,
            outputs: [OutputReport::EMPTY; MAX_OUTPUTS],
            totals: Totals {
                ours: 0,
                inputs: None,
                outputs: 0,
                recipients: 0,
                change: 0,
                self_send: 0,
                fee: None,
                vsize: 0,
            },
            lock_time: 0,
            rbf: false,
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

    pub fn outputs(&self) -> &[OutputReport] {
        &self.outputs[..self.n_outputs]
    }

    /// Other fingerprints the PSBT names (the "need / found" screen).
    pub fn fingerprints(&self) -> &[[u8; 4]] {
        &self.fingerprints[..self.n_fingerprints]
    }

    /// A hash of the whole verdict (issues, inputs, outputs, totals, lock
    /// time). The signer recomputes the report right before signing and
    /// refuses if this differs from the approved one.
    pub fn digest(&self) -> [u8; 32] {
        struct H(Sha256);
        impl core::fmt::Write for H {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                self.0.update(s.as_bytes());
                Ok(())
            }
        }
        let mut h = H(Sha256::new());
        let _ = write!(
            h,
            "{:?}|{:?}|{:?}|{:?}|{:?}|{}|{}|{:?}",
            self.master_fingerprint,
            self.issues(),
            self.inputs(),
            self.outputs(),
            self.totals,
            self.lock_time,
            self.rbf,
            self.fingerprints()
        );
        h.0.finalize()
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

/// What validation needs: the loaded seed, the network, the thresholds
/// and the amounts signed since power-on.
pub struct Context<'a> {
    pub master: &'a Xpriv,
    pub network: Network,
    pub policy: Policy,
    pub memory: Option<&'a UtxoMemory>,
}

impl<'a> Context<'a> {
    pub fn new(master: &'a Xpriv, network: Network) -> Self {
        Context {
            master,
            network,
            policy: Policy::default(),
            memory: None,
        }
    }
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
    report.n_outputs = psbt.tx.n_outputs();
    report.lock_time = psbt.tx.lock_time;
    report.rbf = psbt.tx.inputs().any(|i| i.sequence < 0xFFFF_FFFE);
    check_global_xpubs(&psbt, ctx, &mut d, &mut report);
    inputs::check(&psbt, ctx, &mut d, &mut report);
    if report.has(Issue::NoInputsForSeed) {
        return (Some(psbt), report); // nothing here concerns this seed
    }
    outputs::check(&psbt, ctx, &mut d, &mut report);
    fees::check(&psbt, ctx, &mut report);
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
