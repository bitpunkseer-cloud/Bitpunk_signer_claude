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
}

impl Review {
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
            _ if self.slot.is_none() => Step::WrongSeed,
            Some(r) if r.worst() >= Some(Class::Error) => Step::Problem,
            _ if self.n_warnings() > 0 => Step::Warning { idx: 0, sel: 0 },
            _ => Step::Overview,
        }
    }

    fn next(&self, step: Step) -> Option<Step> {
        Some(match step {
            Step::Warning { idx, .. } if idx + 1 < self.n_warnings() => {
                Step::Warning { idx: idx + 1, sel: 0 }
            }
            Step::Warning { .. } => Step::Overview,
            Step::Overview if self.n_outputs() > 0 => Step::Output { idx: 0 },
            Step::Output { idx } if idx + 1 < self.n_outputs() => Step::Output { idx: idx + 1 },
            Step::Overview | Step::Output { .. } => Step::Fee,
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
            Step::Approve { .. } => Some(Step::Fee),
            _ => None,
        }
    }
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
        let mut chosen: Option<(u8, Report)> = None;
        for slot in 0..SEED_SLOTS {
            let Some(seed) = self.seeds[slot].as_ref() else {
                continue;
            };
            let ctx = Context {
                master: seed.master(),
                network: self.settings.network,
                policy: Policy::default(),
                memory: Some(&self.memory),
            };
            let (_, report) = validate(raw, &ctx);
            if !report.has(Issue::NoInputsForSeed) {
                chosen = Some((slot as u8, report));
                break;
            }
        }
        let (slot, report) = match chosen {
            Some((s, r)) => (Some(s), Some(r)),
            None => (None, None),
        };
        let digest = report.as_ref().map_or([0; 32], |r| r.digest());
        let review = Review {
            slot,
            report,
            digest,
            overridden: false,
            psbt_len: len,
            signed: None,
            error: None,
            need,
            n_need,
        };
        let step = review.first_step();
        self.review = Some(review);
        self.set_current(Screen::Review { step });
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
            Step::WrongSeed | Step::Problem | Step::Failed => {
                if back || ev.key == Key::Enter {
                    self.end_review();
                }
            }
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
                _ if back => self.set_current(Screen::Review { step: Step::Fee }),
                _ => {}
            },
        }
    }

    fn review_sign(&mut self) {
        let Some(r) = self.review.as_mut() else { return };
        let Some(seed) = r.slot.and_then(|s| self.seeds[s as usize].as_ref()) else {
            return;
        };
        let signer = Signer {
            master: seed.master(),
            network: self.settings.network,
            policy: Policy::default(),
        };
        let (psbt, out) = self.scan.buffers();
        let result = sign::sign_psbt(
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
    }
}

/// Where an issue is, if it names an input, output or the wallet xpub.
pub fn issue_at(i: &Issue) -> Option<validate::At> {
    use validate::At;
    use Issue::*;
    match *i {
        KeyNotFromSeed(a) | PathTooDeep(a) | PathTooShort(a) | NetworkMismatch(a) => Some(a),
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
