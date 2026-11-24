//! Reviewing and signing a scanned PSBT (M5 plan §6).
//!
//! The seed is chosen by fingerprint. Attacks and errors end the review.
//! Warnings are confirmed one at a time; a blocking one (input amounts that
//! cannot be verified) needs an explicit "sign without verifying" choice
//! whose default is Cancel. Then the overview, every output, the fee, and
//! the final approval, whose default is also Cancel. Signing validates the
//! PSBT again and refuses if anything differs from what was approved.
//!
//! The PSBT stays in the scan buffer and the signed result goes to the scan
//! work buffer; both are wiped when the review ends.

use crate::{App, Screen, SEED_SLOTS};
use bp_bitcoin::bip322::{classify_psbt, Forgery, PsbtKind};
use bp_bitcoin::message::{check_message, MessageError};
use bp_bitcoin::psbt::Psbt;
use bp_bitcoin::sign::{self, Signed, Signer};
use bp_bitcoin::validate::{self, validate, Class, Context, Issue, Policy, Report};
use bp_hal::input::{Key, KeyEvent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// No loaded seed has inputs in this PSBT (need / found).
    WrongSeed,
    /// Attacks and errors: the review ends here.
    Problem,
    /// Warning `idx` (of the report's warnings); `sel` for the override.
    Warning {
        idx: u8,
        sel: u8,
    },
    Overview,
    Output {
        idx: u8,
    },
    Fee,
    /// Final approval; `sel` 0 = Cancel (the default), 1 = Sign.
    Approve {
        sel: u8,
    },
    /// Signed: choose the QR format (0 UR, 1 BBQr, 2 Specter) or 3 Done.
    Signed {
        sel: u8,
    },
    Failed,
    /// It claims to be a BIP-322 message but signs something else.
    Forged,
    /// A BIP-322 message while message signing is off.
    MsgOff,
    /// The BIP-322 message breaks the message rules.
    MsgRule,
    /// A page of the BIP-322 message (every page must be shown).
    MsgPage {
        page: u8,
    },
    /// The address (input 0) and, for Proof of Reserves, the total.
    MsgAddress,
    /// A multisig spend from a wallet not registered this session, which
    /// the PSBT's global xpubs rebuild: type its code or cancel.
    MsRegister {
        sel: u8,
    },
    /// Typing that wallet's code.
    MsCode,
    /// Verify-only: the review ended without signing.
    VerifiedOnly,
}

/// A BIP-322 message (or Proof of Reserves) PSBT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageMode {
    pub proof_of_reserves: bool,
}

pub const MAX_NEED: usize = 4;

pub struct Review {
    pub slot: Option<u8>,
    pub report: Option<Report>,
    pub digest: [u8; 32],
    /// The user chose to sign without verified amounts (this PSBT only).
    pub overridden: bool,
    pub psbt_len: usize,
    pub signed: Option<Signed>,
    pub error: Option<sign::Error>,
    /// Fingerprints the PSBT names, for the wrong-seed screen.
    pub need: [[u8; 4]; MAX_NEED],
    pub n_need: usize,
    /// Set for BIP-322 message PSBTs.
    pub message: Option<MessageMode>,
    pub forgery: Option<Forgery>,
    pub rule: Option<MessageError>,
    /// The unregistered multisig wallet the PSBT's global xpubs rebuild.
    pub candidate: Option<bp_bitcoin::multisig::Wallet>,
    pub code_in: [u8; 16],
    pub code_len: usize,
    /// 0 none, 1 not this wallet's code, 2 not a code, 3 breaks a rule, 4 full.
    pub code_bad: u8,
    /// Read from a microSD file: the full PSBT is produced and saved.
    pub from_sd: bool,
}

impl Review {
    fn empty(psbt_len: usize, need: [[u8; 4]; MAX_NEED], n_need: usize) -> Review {
        Review {
            slot: None,
            report: None,
            digest: [0; 32],
            overridden: false,
            psbt_len,
            signed: None,
            error: None,
            need,
            n_need,
            message: None,
            forgery: None,
            rule: None,
            candidate: None,
            code_in: [0; 16],
            code_len: 0,
            code_bad: 0,
            from_sd: false,
        }
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Issue> {
        self.report
            .iter()
            .flat_map(|r| r.issues().iter())
            .filter(|i| i.class() == Class::Warning)
    }

    pub fn warning(&self, idx: u8) -> Option<Issue> {
        self.warnings().nth(idx as usize).copied()
    }

    fn n_warnings(&self) -> u8 {
        self.warnings().count() as u8
    }

    fn n_outputs(&self) -> u8 {
        self.report.as_ref().map_or(0, |r| r.outputs().len() as u8)
    }

    pub fn first_step(&self) -> Step {
        match &self.report {
            _ if self.forgery.is_some() => Step::Forged,
            _ if self.rule.is_some() => Step::MsgRule,
            _ if self.slot.is_none() => Step::WrongSeed,
            Some(r) if self.candidate.is_some() && only_unregistered(r) => Step::MsRegister { sel: 0 },
            Some(r) if r.worst() >= Some(Class::Error) => Step::Problem,
            _ if self.n_warnings() > 0 => Step::Warning { idx: 0, sel: 0 },
            _ if self.message.is_some() => Step::MsgPage { page: 0 },
            _ => Step::Overview,
        }
    }

    fn next(&self, step: Step) -> Option<Step> {
        Some(match step {
            Step::Warning { idx, .. } if idx + 1 < self.n_warnings() => {
                Step::Warning { idx: idx + 1, sel: 0 }
            }
            Step::Warning { .. } if self.message.is_some() => Step::MsgPage { page: 0 },
            Step::Warning { .. } => Step::Overview,
            Step::MsgAddress => Step::Approve { sel: 0 },
            Step::Overview if self.n_outputs() > 0 => Step::Output { idx: 0 },
            Step::Output { idx } if idx + 1 < self.n_outputs() => Step::Output { idx: idx + 1 },
            Step::Overview | Step::Output { .. } => Step::Fee,
            Step::Fee if self.report.as_ref().is_some_and(|r| r.watch_only) => Step::VerifiedOnly,
            Step::Fee => Step::Approve { sel: 0 },
            _ => return None,
        })
    }

    fn prev(&self, step: Step) -> Option<Step> {
        let last_warning = || {
            self.n_warnings()
                .checked_sub(1)
                .map(|i| Step::Warning { idx: i, sel: 0 })
        };
        match step {
            Step::Warning { idx: 0, .. } => None,
            Step::Warning { idx, .. } => Some(Step::Warning { idx: idx - 1, sel: 0 }),
            Step::Overview => last_warning(),
            Step::Output { idx: 0 } => Some(Step::Overview),
            Step::Output { idx } => Some(Step::Output { idx: idx - 1 }),
            Step::Fee => Some(match self.n_outputs() {
                0 => Step::Overview,
                n => Step::Output { idx: n - 1 },
            }),
            Step::Approve { .. } if self.message.is_some() => Some(Step::MsgAddress),
            Step::Approve { .. } | Step::VerifiedOnly => Some(Step::Fee),
            Step::MsgPage { page: 0 } => last_warning(),
            Step::MsgPage { page } => Some(Step::MsgPage { page: page - 1 }),
            _ => None,
        }
    }
}

/// Every error is an unregistered multisig input (nothing else blocks).
fn only_unregistered(r: &Report) -> bool {
    r.issues()
        .iter()
        .filter(|i| i.class() >= Class::Error)
        .all(|i| matches!(i, Issue::UnregisteredMultisig(_)))
        && r.issues()
            .iter()
            .any(|i| matches!(i, Issue::UnregisteredMultisig(_)))
}

/// Fingerprints named by the PSBT's derivations and xpubs.
fn claimed_fingerprints(raw: &[u8]) -> ([[u8; 4]; MAX_NEED], usize) {
    let mut out = [[0u8; 4]; MAX_NEED];
    let mut n = 0;
    let Ok(p) = Psbt::parse(raw) else {
        return (out, 0);
    };
    let mut add = |fp: [u8; 4]| {
        if !out[..n].contains(&fp) && n < MAX_NEED {
            out[n] = fp;
            n += 1;
        }
    };
    for m in p.inputs() {
        m.bip32_derivations().for_each(|(_, s)| add(s.fingerprint));
        m.tap_bip32_derivations().for_each(|t| add(t.source.fingerprint));
    }
    p.xpubs().for_each(|(_, s)| add(s.fingerprint));
    (out, n)
}

impl App {
    /// A PSBT of `len` bytes is in the scan buffer: choose the seed and
    /// validate.
    pub(crate) fn start_review(&mut self, len: usize) {
        let raw = &self.scan.out[..len.min(self.scan.out.len())];
        let (need, n_need) = claimed_fingerprints(raw);
        // a BIP-322 message (or a forgery of one)?
        let (mut message, mut forgery, mut rule) = (None, None, None);
        if let Ok(p) = Psbt::parse(raw) {
            match classify_psbt(&p) {
                PsbtKind::Forged(f) => forgery = Some(f),
                PsbtKind::Message {
                    message: m,
                    proof_of_reserves,
                    ..
                } => {
                    rule = check_message(m).err();
                    message = Some(MessageMode { proof_of_reserves });
                }
                PsbtKind::Transaction => {}
            }
        }
        if message.is_some() && !self.settings.msg_signing {
            self.review = Some(Review::empty(len, need, n_need));
            self.set_current(Screen::Review { step: Step::MsgOff });
            return;
        }
        let policy = Policy {
            message: message.is_some(),
            ..self.settings.policy()
        };
        let mut chosen: Option<(u8, Report)> = None;
        for slot in 0..SEED_SLOTS {
            if forgery.is_some() || rule.is_some() {
                break;
            }
            let Some(seed) = self.seeds[slot].as_ref() else {
                continue;
            };
            let wallets = self.multisig_wallets();
            let none: [Option<&bp_bitcoin::multisig::Wallet>; 0] = [];
            let ctx = Context {
                master: seed.master(),
                network: self.settings.network,
                policy,
                memory: Some(&self.memory),
                multisig: if seed.single_key() { &none } else { &wallets },
                watch: false,
                single_key: seed.single_key(),
            };
            let (_, report) = validate(raw, &ctx);
            if !report.has(Issue::NoInputsForSeed) {
                chosen = Some((slot as u8, report));
                break;
            }
        }
        // verify-only: no seed has inputs, but a registered wallet without
        // this device's key may (decision 5); never signable
        if chosen.is_none()
            && forgery.is_none()
            && rule.is_none()
            && message.is_none()
            && !self.wallets.is_empty()
        {
            if let Some((slot, seed)) = self
                .seeds
                .iter()
                .enumerate()
                .find_map(|(i, s)| s.as_ref().filter(|s| !s.single_key()).map(|s| (i, s)))
            {
                let wallets = self.multisig_wallets();
                let ctx = Context {
                    master: seed.master(),
                    network: self.settings.network,
                    policy,
                    memory: Some(&self.memory),
                    multisig: &wallets,
                    watch: true,
                    single_key: false,
                };
                let (_, report) = validate(raw, &ctx);
                if report.watch_only && !report.has(Issue::NoInputsForSeed) {
                    chosen = Some((slot as u8, report));
                }
            }
        }
        let (slot, report) = match chosen {
            Some((s, r)) => (Some(s), Some(r)),
            None => (None, None),
        };
        let digest = report.as_ref().map_or([0; 32], |r| r.digest());
        // an unregistered multisig wallet the PSBT can rebuild (code entry)
        let candidate = match (slot, report.as_ref()) {
            (Some(sl), Some(rep))
                if rep
                    .issues()
                    .iter()
                    .any(|i| matches!(i, Issue::UnregisteredMultisig(_))) =>
            {
                let raw = &self.scan.out[..len.min(self.scan.out.len())];
                let fp = self.seeds[sl as usize].as_ref().map(|s| s.fingerprint);
                let test = self.settings.network != bp_bitcoin::Network::Mainnet;
                match (Psbt::parse(raw), fp) {
                    (Ok(p), Some(fp)) => bp_bitcoin::multisig::reconstruct(&p, fp, test),
                    _ => None,
                }
            }
            _ => None,
        };
        let review = Review {
            slot,
            report,
            digest,
            candidate,
            message,
            forgery: forgery.take(),
            rule: rule.take(),
            ..Review::empty(len, need, n_need)
        };
        let step = review.first_step();
        self.review = Some(review);
        self.set_current(Screen::Review { step });
    }

    /// The message of a BIP-322 review (read again from the PSBT).
    pub(crate) fn review_message(&self) -> Option<&[u8]> {
        let r = self.review.as_ref()?;
        r.message?;
        let p = Psbt::parse(&self.scan.out[..r.psbt_len.min(self.scan.out.len())]).ok()?;
        match classify_psbt(&p) {
            PsbtKind::Message { message, .. } => Some(message),
            _ => None,
        }
    }

    fn end_review(&mut self) {
        self.review = None;
        self.pop(); // back below the review; the scan session ends
    }

    pub(crate) fn review_key(&mut self, step: Step, ev: KeyEvent) {
        let Some(r) = self.review.as_ref() else {
            self.pop();
            return;
        };
        let back = matches!(ev.key, Key::Esc | Key::Backspace);
        match step {
            Step::MsRegister { sel } => match crate::pick(ev.key, sel, 2) {
                crate::Pick::Move(s) => self.set_current(Screen::Review {
                    step: Step::MsRegister { sel: s },
                }),
                crate::Pick::Choose(0) => {
                    if let Some(r) = self.review.as_mut() {
                        r.code_in = [0; 16];
                        r.code_len = 0;
                        r.code_bad = 0;
                    }
                    self.set_current(Screen::Review { step: Step::MsCode });
                }
                crate::Pick::Choose(_) | crate::Pick::Back => self.end_review(),
                crate::Pick::None => {}
            },
            Step::MsCode => {
                let Some(r) = self.review.as_mut() else { return };
                match ev.key {
                    Key::Char(c) if c.is_ascii_alphanumeric() || c == '-' || c == ' ' => {
                        if r.code_len < r.code_in.len() {
                            r.code_in[r.code_len] = c.to_ascii_uppercase() as u8;
                            r.code_len += 1;
                        }
                        r.code_bad = 0;
                    }
                    Key::Backspace if r.code_len > 0 => {
                        r.code_len -= 1;
                        r.code_in[r.code_len] = 0;
                        r.code_bad = 0;
                    }
                    Key::Enter => self.review_register_code(),
                    Key::Esc | Key::Backspace => self.set_current(Screen::Review {
                        step: Step::MsRegister { sel: 0 },
                    }),
                    _ => {}
                }
            }
            Step::VerifiedOnly => match ev.key {
                Key::Enter => self.end_review(),
                _ if back => self.set_current(Screen::Review { step: Step::Fee }),
                _ => {}
            },
            Step::WrongSeed | Step::Problem | Step::Failed | Step::Forged | Step::MsgOff | Step::MsgRule => {
                if back || ev.key == Key::Enter {
                    self.end_review();
                }
            }
            Step::MsgPage { page } => {
                let pages = self.review_message().map_or(1, crate::msgsign::message_pages);
                let to = |a: &mut App, s: Step| a.set_current(Screen::Review { step: s });
                match ev.key {
                    Key::Right | Key::Down | Key::Enter if page + 1 < pages => {
                        to(self, Step::MsgPage { page: page + 1 })
                    }
                    Key::Enter => to(self, Step::MsgAddress),
                    Key::Left | Key::Up if page > 0 => to(self, Step::MsgPage { page: page - 1 }),
                    _ if back => match r.prev(step) {
                        Some(s) => to(self, s),
                        None => self.end_review(),
                    },
                    _ => {}
                }
            }
            Step::MsgAddress => match ev.key {
                Key::Enter => self.set_current(Screen::Review {
                    step: Step::Approve { sel: 0 },
                }),
                _ if back => {
                    let pages = self.review_message().map_or(1, crate::msgsign::message_pages);
                    self.set_current(Screen::Review {
                        step: Step::MsgPage { page: pages - 1 },
                    });
                }
                _ => {}
            },
            Step::Signed { sel } if r.from_sd => match crate::pick(ev.key, sel, 2) {
                crate::Pick::Move(s) => self.set_current(Screen::Review {
                    step: Step::Signed { sel: s },
                }),
                crate::Pick::Choose(0) => self.start_save(crate::sd::Job::SavePsbt),
                crate::Pick::Choose(_) | crate::Pick::Back => self.end_review(),
                crate::Pick::None => {}
            },
            Step::Signed { sel } => match ev.key {
                Key::Up => self.set_current(Screen::Review {
                    step: Step::Signed {
                        sel: sel.saturating_sub(1),
                    },
                }),
                Key::Down => self.set_current(Screen::Review {
                    step: Step::Signed {
                        sel: (sel + 1).min(3),
                    },
                }),
                Key::Enter if sel < 3 => self.open_qr(crate::QrKind::SignedPsbt {
                    format: crate::PsbtFormat::ALL[sel as usize],
                }),
                Key::Enter => self.end_review(),
                _ if back => self.end_review(),
                _ => {}
            },
            Step::Warning { idx, sel } => {
                let blocking = r.warning(idx).is_some_and(|w| w.needs_override());
                match ev.key {
                    Key::Up | Key::Down if blocking => {
                        self.set_current(Screen::Review {
                            step: Step::Warning {
                                idx,
                                sel: 1 - sel.min(1),
                            },
                        });
                    }
                    Key::Enter if blocking && sel == 0 => self.end_review(),
                    Key::Enter => {
                        let next = r.next(step);
                        if blocking {
                            if let Some(r) = self.review.as_mut() {
                                r.overridden = true;
                            }
                        }
                        if let Some(s) = next {
                            self.set_current(Screen::Review { step: s });
                        }
                    }
                    _ if back => match r.prev(step) {
                        Some(s) => self.set_current(Screen::Review { step: s }),
                        None => self.end_review(),
                    },
                    _ => {}
                }
            }
            Step::Overview | Step::Output { .. } | Step::Fee => match ev.key {
                Key::Enter | Key::Right | Key::Down => {
                    if let Some(s) = r.next(step) {
                        self.set_current(Screen::Review { step: s });
                    }
                }
                Key::Left | Key::Up if !matches!(step, Step::Overview) => {
                    if let Some(s) = r.prev(step) {
                        self.set_current(Screen::Review { step: s });
                    }
                }
                _ if back => match r.prev(step) {
                    Some(s) => self.set_current(Screen::Review { step: s }),
                    None => self.end_review(),
                },
                _ => {}
            },
            Step::Approve { sel } => match ev.key {
                Key::Up | Key::Down => self.set_current(Screen::Review {
                    step: Step::Approve { sel: 1 - sel.min(1) },
                }),
                Key::Enter if sel == 1 => self.review_sign(),
                Key::Enter => self.end_review(),
                _ if back => {
                    if let Some(s) = r.prev(step) {
                        self.set_current(Screen::Review { step: s });
                    }
                }
                _ => {}
            },
        }
    }

    /// The typed code must be the candidate wallet's (this seed's code key);
    /// then the wallet must pass the registration rules. Registered, the
    /// PSBT is reviewed again from the start.
    fn review_register_code(&mut self) {
        use bp_bitcoin::multisig::register::{self, AddError, Code, CodeKey, Entry};
        let net = self.settings.network;
        let Some(r) = self.review.as_ref() else { return };
        let (Some(cand), Some(slot)) = (r.candidate, r.slot) else {
            return;
        };
        let Some(seed) = self.seeds[slot as usize].as_ref() else {
            return;
        };
        let typed = core::str::from_utf8(&r.code_in[..r.code_len]).unwrap_or("");
        let ck = CodeKey::new(seed.master());
        let code = ck.code(&cand);
        let bad = match Code::parse(typed) {
            None => 2,
            Some(c) if c != code => 1,
            Some(_) => match register::check(&cand, net, seed.master(), &self.wallets) {
                Err(_) => 3,
                Ok(checked) => {
                    let e = Entry {
                        wallet: cand,
                        slot,
                        ours: checked.ours,
                        code,
                        tag: ck.tag(&cand),
                    };
                    match self.wallets.add(e) {
                        Ok(_) | Err(AddError::Duplicate(_)) => 0,
                        Err(AddError::Full) => 4,
                    }
                }
            },
        };
        if bad != 0 {
            if let Some(r) = self.review.as_mut() {
                r.code_bad = bad;
            }
            return;
        }
        let len = r.psbt_len;
        self.start_review(len);
    }

    fn review_sign(&mut self) {
        let Some(r) = self.review.as_mut() else { return };
        let Some(seed) = r.slot.and_then(|s| self.seeds[s as usize].as_ref()) else {
            return;
        };
        let wallets: [Option<&bp_bitcoin::multisig::Wallet>; bp_bitcoin::multisig::register::MAX_WALLETS] =
            core::array::from_fn(|i| self.wallets.get(i as u8).map(|e| &e.wallet));
        // a single imported key has no multisig wallets
        let none: [Option<&bp_bitcoin::multisig::Wallet>; 0] = [];
        let signer = Signer {
            master: seed.master(),
            network: self.settings.network,
            policy: Policy {
                message: r.message.is_some(),
                ..self.settings.policy()
            },
            multisig: if seed.single_key() { &none } else { &wallets },
            single_key: seed.single_key(),
        };
        let (psbt, out) = self.scan.buffers();
        // a file gets the whole PSBT back; a QR only the signatures
        let sign = if r.from_sd {
            sign::sign_psbt_full
        } else {
            sign::sign_psbt
        };
        let result = sign(
            &psbt[..r.psbt_len],
            &signer,
            &mut self.memory,
            &r.digest,
            r.overridden,
            out,
        );
        let step = match result {
            Ok(s) => {
                r.signed = Some(s);
                Step::Signed { sel: 0 }
            }
            Err(e) => {
                r.error = Some(e);
                Step::Failed
            }
        };
        self.set_current(Screen::Review { step });
    }
}

/// Index into `ReviewStrings::issues`.
pub fn issue_index(i: &Issue) -> usize {
    use bp_bitcoin::psbt::ParseError;
    use Issue::*;
    match i {
        KeyNotFromSeed(_) => 0,
        ScriptNotOurs(_) => 1,
        RedeemMismatch(_) => 2,
        WitnessScriptMismatch(_) => 3,
        PrevTxMismatch(_) => 4,
        ChangeContradiction(_) => 5,
        ChangePathViolation(_) => 6,
        UtxoAmountChanged(_) => 7,
        Parse(ParseError::UtxoMismatch) => 8,
        Parse(_) => 9,
        TooLarge => 10,
        MissingUtxo(_) => 11,
        MissingPrevTx(_) => 12,
        MissingRedeemScript(_) => 13,
        UnneededScript(_) => 14,
        UnsupportedInput(_) => 15,
        TaprootScriptPath(_) => 16,
        InconsistentInput(_) => 17,
        UncompressedKey(_) => 18,
        DuplicateInput(_) => 19,
        PathTooDeep(_) => 20,
        XpubNetwork => 21,
        NoInputsForSeed => 22,
        NothingToSign => 23,
        NegativeFee => 24,
        FeeTooHigh => 25,
        ValueOutOfRange => 26,
        NonStandardSighash(_) => 27,
        BadOpReturn(_) => 28,
        NetworkMismatch(_) => 29,
        UnverifiedAmounts => 30,
        ExternalInputs => 31,
        PartlySigned => 32,
        HighFee => 33,
        HighFeeRate => 34,
        FeeUnknown => 35,
        NoChange => 36,
        ChangeIndexFar(_) => 37,
        MixedScriptTypes => 38,
        MultipleAccounts => 39,
        OpReturnNonStandard => 40,
        UnknownScript(_) => 41,
        ZeroValue(_) => 42,
        PathTooShort(_) => 43,
        SurplusClaims(_) => 44,
        UnverifiedMixedBasePaths => 45,
        ExternalMessageInput => 46,
        MissingWitnessScript(_) => 47,
        UnregisteredMultisig(_) => 48,
        MultisigClaimMismatch(_) => 49,
        MixedWallets => 50,
        GlobalXpubMismatch => 51,
        BadCosignerSignature(_) => 52,
    }
}

/// Where an issue is, if it names an input, output or the wallet xpub.
pub fn issue_at(i: &Issue) -> Option<validate::At> {
    use validate::At;
    use Issue::*;
    match *i {
        KeyNotFromSeed(a)
        | PathTooDeep(a)
        | PathTooShort(a)
        | NetworkMismatch(a)
        | MultisigClaimMismatch(a) => Some(a),
        ScriptNotOurs(n)
        | RedeemMismatch(n)
        | WitnessScriptMismatch(n)
        | PrevTxMismatch(n)
        | UtxoAmountChanged(n)
        | MissingUtxo(n)
        | MissingPrevTx(n)
        | MissingRedeemScript(n)
        | UnneededScript(n)
        | UnsupportedInput(n)
        | TaprootScriptPath(n)
        | InconsistentInput(n)
        | UncompressedKey(n)
        | DuplicateInput(n)
        | MissingWitnessScript(n)
        | UnregisteredMultisig(n)
        | BadCosignerSignature(n)
        | NonStandardSighash(n) => Some(At::Input(n)),
        ChangeContradiction(n)
        | ChangePathViolation(n)
        | BadOpReturn(n)
        | ChangeIndexFar(n)
        | UnknownScript(n)
        | ZeroValue(n) => Some(At::Output(n)),
        XpubNetwork => Some(At::Global),
        _ => None,
    }
}
