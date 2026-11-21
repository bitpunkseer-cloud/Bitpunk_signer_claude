//! Bitpunk Signer application: screen state machine shared by the device
//! firmware and the web simulator. Allocation-free.
#![no_std]

mod flow;
mod menus;
mod qrview;
pub mod review;
mod review_view;
mod scan;
mod seeds;
mod settings;
mod text;
mod verify;
mod view;

use bp_bitcoin::address::ScriptType;
use bp_bitcoin::bip39::{self, Mnemonic};
use bp_crypto::drbg::Drbg;
use bp_hal::input::{Key, KeyEvent};
use flow::{Flow, Quiz};
use menus::{Action, Start};

pub use menus::MenuId;
pub use settings::Settings;
pub use text::Strings;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Git commit the build came from (set by the build script / CI).
pub const GIT_HASH: &str = match option_env!("BP_GIT_HASH") {
    Some(h) => h,
    None => "dev",
};

const SPLASH_MS: u32 = 1800;
const STACK_DEPTH: usize = 10;
pub const SEED_SLOTS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    /// Abandon the flow in progress.
    CancelFlow,
    /// Discard a loaded seed.
    DiscardSeed(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QrKind {
    Xpub {
        slot: u8,
        st: ScriptType,
        account: u32,
        format: XpubFormat,
    },
    SeedQr {
        slot: u8,
        compact: bool,
    },
    /// The signed PSBT in the review's work buffer.
    SignedPsbt {
        format: PsbtFormat,
    },
}

/// QR formats for the signed PSBT (decision 5: UR by default).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PsbtFormat {
    Ur,
    Bbqr,
    Specter,
}

impl PsbtFormat {
    pub const ALL: [PsbtFormat; 3] = [PsbtFormat::Ur, PsbtFormat::Bbqr, PsbtFormat::Specter];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XpubFormat {
    UrAccount,
    UrOutput,
    StaticText,
    Specter,
}

impl XpubFormat {
    pub const ALL: [XpubFormat; 4] = [
        XpubFormat::UrAccount,
        XpubFormat::UrOutput,
        XpubFormat::StaticText,
        XpubFormat::Specter,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Splash,
    PoweredOff,
    About,
    Menu {
        id: MenuId,
        sel: u8,
    },
    Placeholder {
        title: &'static str,
        phase: &'static str,
    },
    ChooseWords {
        kind: Start,
        sel: u8,
    },
    EntropyIntro,
    /// Final-word calculator: explanation before entering words.
    FinalIntro,
    /// Coin flips for the last word's free bits.
    FinalCoins,
    /// Shows the computed last word.
    FinalResult,
    EntropyEntry,
    EntropySummary,
    /// `view`: `None` during seed creation, `Some(slot)` to view a loaded seed.
    WordsWarning {
        view: Option<u8>,
    },
    ShowWords {
        view: Option<u8>,
    },
    QuizIntro,
    Quiz {
        sel: u8,
    },
    QuizFailed {
        sel: u8,
    },
    SeedReady {
        slot: u8,
        created: bool,
    },
    SlotsFull,
    WordEntry,
    ChecksumError {
        sel: u8,
    },
    SeedOptions {
        slot: u8,
        sel: u8,
    },
    /// Type a BIP-39 passphrase for a loaded seed.
    PassphraseEntry {
        slot: u8,
    },
    /// Show the passphrase and the resulting fingerprint before applying.
    PassphraseReview {
        slot: u8,
        sel: u8,
    },
    /// Choose a script type for the xpub view or the address explorer.
    ScriptSelect {
        slot: u8,
        explorer: bool,
        sel: u8,
    },
    XpubView {
        slot: u8,
        st: ScriptType,
        account: u32,
    },
    AddressList {
        slot: u8,
        st: ScriptType,
        change: bool,
        page: u32,
        sel: u8,
    },
    AddressDetail {
        slot: u8,
        st: ScriptType,
        change: bool,
        index: u32,
    },
    /// Tools > Address explorer with several seeds loaded.
    PickSeed {
        sel: u8,
    },
    NoSeed,
    /// Choose the xpub QR format.
    XpubFormat {
        slot: u8,
        st: ScriptType,
        sel: u8,
    },
    /// Any QR (xpub, SeedQR) shown through the shared QR engine.
    QrShow {
        kind: QrKind,
    },
    SeedQrSelect {
        slot: u8,
        sel: u8,
    },
    SeedQrWarning {
        slot: u8,
        compact: bool,
    },
    /// SeedQR transcription guide: 5x5-module blocks or one row at a time.
    Transcribe {
        slot: u8,
        line: bool,
        x: u8,
        y: u8,
    },
    Confirm {
        what: Confirm,
        sel: u8,
    },
    /// Camera scanning (any code, a SeedQR, or checking a copied SeedQR).
    Scan {
        purpose: scan::Purpose,
    },
    /// A scanned seed: fingerprint, then load or discard.
    ScanSeed {
        sel: u8,
    },
    /// Result of checking a hand-copied SeedQR.
    ScanVerify {
        slot: u8,
    },
    /// What a scanned code was (PSBT, key, address, text...).
    ScanResult,
    /// Reviewing and signing a scanned PSBT.
    Review {
        step: review::Step,
    },
    /// Is this scanned address one of a loaded seed's?
    VerifyAddr {
        step: verify::VaStep,
    },
}

pub struct App {
    stack: [Screen; STACK_DEPTH],
    depth: usize,
    pub settings: Settings,
    dirty: bool,
    splash_ms: u32,
    test_only: bool,
    seeds: [Option<seeds::SeedSlot>; SEED_SLOTS],
    flow: Option<Flow>,
    /// Shuffles quiz questions only; never used for seed material.
    quiz_rng: Drbg,
    notice: Option<&'static str>,
    /// Passphrase being typed (wiped on drop and when leaving the screen).
    pass_in: PassInput,
    /// Seed recomputed with the typed passphrase, waiting for "Apply".
    pending: Option<seeds::SeedSlot>,
    /// QR engine state for the QR screen on top (wiped when it closes).
    qr: Option<qrview::QrSession>,
    /// Camera scanning state (wiped when scanning ends).
    scan: scan::ScanState,
    scan_live: bool,
    /// A scanned seed with its master key, waiting for "Load".
    scanned: Option<seeds::SeedSlot>,
    /// The PSBT being reviewed (with the scan buffers that hold it).
    review: Option<review::Review>,
    /// Amounts of the UTXOs signed since power-on.
    memory: bp_bitcoin::validate::UtxoMemory,
    /// The address being verified and its search.
    verify: Option<verify::VerifyState>,
    /// Index of the address verified last (searched first next time).
    last_found: Option<u32>,
    /// Accounts used this session (0 first), searched by Verify address.
    session_accounts: [u32; verify::SESSION_ACCOUNTS],
    n_session_accounts: usize,
}

/// Passphrase input buffer. Wiped on clear and on drop.
struct PassInput {
    buf: [u8; seeds::MAX_PASSPHRASE],
    len: usize,
    show: bool,
}

impl PassInput {
    const fn new() -> Self {
        Self {
            buf: [0; seeds::MAX_PASSPHRASE],
            len: 0,
            show: true,
        }
    }
    fn text(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    fn clear(&mut self) {
        bp_crypto::secret::wipe(&mut self.buf);
        self.len = 0;
    }
    fn set(&mut self, v: &[u8]) {
        self.clear();
        let n = v.len().min(self.buf.len());
        self.buf[..n].copy_from_slice(&v[..n]);
        self.len = n;
    }
}

impl Drop for PassInput {
    fn drop(&mut self) {
        self.clear();
    }
}

impl App {
    /// `quiz_seed` seeds the quiz shuffler (device or browser randomness is
    /// fine here: it only orders questions and picks decoy words).
    pub fn new(quiz_seed: &[u8]) -> Self {
        Self {
            stack: [Screen::Splash; STACK_DEPTH],
            depth: 1,
            settings: Settings::default(),
            dirty: true,
            splash_ms: 0,
            test_only: false,
            seeds: [None, None, None],
            flow: None,
            quiz_rng: Drbg::new(quiz_seed),
            notice: None,
            pass_in: PassInput::new(),
            pending: None,
            qr: None,
            scan: scan::ScanState::new(),
            scan_live: false,
            scanned: None,
            review: None,
            memory: bp_bitcoin::validate::UtxoMemory::new(),
            verify: None,
            last_found: None,
            session_accounts: [0; verify::SESSION_ACCOUNTS],
            n_session_accounts: 1,
        }
    }

    /// Mark this build as a test build (simulator): shows a TEST ONLY badge.
    pub fn set_test_only(&mut self, on: bool) {
        self.test_only = on;
        self.dirty = true;
    }

    pub fn text(&self) -> &'static Strings {
        match self.settings.lang {
            settings::Lang::En => &text::EN,
            settings::Lang::Ko => &text::KO,
        }
    }

    pub fn current(&self) -> Screen {
        self.stack[self.depth - 1]
    }

    pub fn seed(&self, slot: usize) -> Option<&Mnemonic> {
        self.slot(slot).map(|s| &s.mnemonic)
    }

    pub fn slot(&self, slot: usize) -> Option<&seeds::SeedSlot> {
        self.seeds.get(slot).and_then(|s| s.as_ref())
    }

    pub fn seed_count(&self) -> usize {
        self.seeds.iter().filter(|s| s.is_some()).count()
    }

    fn set_current(&mut self, s: Screen) {
        self.stack[self.depth - 1] = s;
        self.dirty = true;
    }

    fn push(&mut self, s: Screen) {
        if self.depth < STACK_DEPTH {
            self.stack[self.depth] = s;
            self.depth += 1;
        } else {
            self.set_current(s);
        }
        self.dirty = true;
    }

    fn pop(&mut self) {
        if self.depth > 1 {
            self.depth -= 1;
            self.dirty = true;
        }
        if matches!(self.current(), Screen::Menu { .. } | Screen::ChooseWords { .. }) {
            self.flow = None; // leaving a flow wipes its state
        }
    }

    fn reset_to(&mut self, s: Screen) {
        self.depth = 1;
        self.set_current(s);
    }

    /// Return to Main > Seeds and optionally show `then` on top.
    fn go_seeds(&mut self, then: Option<Screen>) {
        self.flow = None;
        self.reset_to(Screen::Menu {
            id: MenuId::Main,
            sel: 1,
        });
        self.push(Screen::Menu {
            id: MenuId::Seeds,
            sel: 0,
        });
        if let Some(s) = then {
            self.push(s);
        }
    }

    fn free_slot(&self) -> Option<usize> {
        self.seeds.iter().position(|s| s.is_none())
    }

    /// Advance timers. Returns true when the screen needs redrawing.
    pub fn tick(&mut self, dt_ms: u32) -> bool {
        if self.current() == Screen::Splash {
            self.splash_ms = self.splash_ms.saturating_add(dt_ms);
            if self.splash_ms >= SPLASH_MS {
                self.reset_to(Screen::Menu {
                    id: MenuId::Main,
                    sel: 0,
                });
            }
        }
        if matches!(self.current(), Screen::Scan { .. }) && self.scan.tick(dt_ms) {
            self.dirty = true;
        }
        if matches!(self.current(), Screen::QrShow { .. }) {
            if let Some(q) = self.qr.as_mut() {
                if q.tick(dt_ms) {
                    self.dirty = true;
                }
            }
        }
        if self.verify_tick() {
            self.dirty = true;
        }
        core::mem::take(&mut self.dirty)
    }

    pub fn on_key(&mut self, ev: KeyEvent) {
        self.handle_key(ev);
        // the QR session (and any SeedQR payload) lives only while a QR
        // screen is on the stack
        if !self.stack[..self.depth]
            .iter()
            .any(|s| matches!(s, Screen::QrShow { .. }))
        {
            self.qr = None;
        }
        if !self.stack[..self.depth]
            .iter()
            .any(|s| matches!(s, Screen::VerifyAddr { .. }))
        {
            self.verify = None;
        }
        self.end_scan_if_left();
    }

    fn end_scan_if_left(&mut self) {
        let scanning = self.stack[..self.depth].iter().any(|s| {
            matches!(
                s,
                Screen::Scan { .. }
                    | Screen::ScanSeed { .. }
                    | Screen::ScanVerify { .. }
                    | Screen::ScanResult
                    | Screen::Review { .. }
            )
        });
        if self.scan_live && !scanning {
            self.scan.clear();
            self.scanned = None;
            self.review = None;
            self.scan_live = false;
        }
    }

    /// The signed PSBT while its review is open (the simulator offers it as
    /// text; the device only shows it as QR codes).
    pub fn signed_psbt(&self) -> Option<&[u8]> {
        let len = self.review.as_ref()?.signed?.len;
        self.scan.work().get(..len)
    }

    /// True while the scan screen wants camera frames.
    pub fn wants_camera(&self) -> bool {
        matches!(self.current(), Screen::Scan { .. })
    }

    /// One camera frame (8-bit luma, row-major). Ignored unless scanning.
    pub fn on_frame(&mut self, gray: &[u8], width: usize, height: usize) {
        let Screen::Scan { purpose } = self.current() else {
            return;
        };
        self.dirty = true;
        if self.scan.frame(gray, width, height) {
            self.finish_scan(purpose);
        }
    }

    /// QR content typed or pasted (simulator). Ignored unless scanning.
    pub fn on_qr_text(&mut self, text: &[u8]) {
        let Screen::Scan { purpose } = self.current() else {
            return;
        };
        self.dirty = true;
        if self.scan.text(text) {
            self.finish_scan(purpose);
        }
    }

    fn start_scan(&mut self, purpose: scan::Purpose) {
        self.scan.clear();
        self.scanned = None;
        self.scan_live = true;
        self.push(Screen::Scan { purpose });
    }

    fn finish_scan(&mut self, purpose: scan::Purpose) {
        self.scan.finish(purpose);
        if let Some(m) = self.scan.seed.take() {
            match purpose {
                scan::Purpose::Verify { slot } => {
                    self.scan.seed = Some(m);
                    self.set_current(Screen::ScanVerify { slot });
                }
                _ => {
                    // the master key (PBKDF2) is computed once, here
                    self.scanned = seeds::SeedSlot::new(m, b"");
                    self.set_current(Screen::ScanSeed { sel: 0 });
                }
            }
        } else if let Some(scan::Outcome::Psbt { len, .. }) = self.scan.outcome {
            self.start_review(len);
        } else if let Some(scan::Outcome::Address { len, index, .. }) = self.scan.outcome {
            let mut addr = [0u8; bp_bitcoin::address::MAX_ADDRESS_LEN];
            let n = len.min(addr.len());
            addr[..n].copy_from_slice(&self.scan.out[..n]);
            self.start_verify(&addr[..n], index);
            bp_crypto::secret::wipe(&mut addr);
            // the scan buffers are no longer needed: wipe them now
            self.end_scan_if_left();
        } else {
            self.set_current(Screen::ScanResult);
        }
    }

    fn handle_key(&mut self, ev: KeyEvent) {
        self.dirty = true;
        if self.notice.take().is_some() {
            self.dirty = true;
        }
        let back = matches!(ev.key, Key::Esc);
        // QR key: shortcut to the scanner from any menu.
        if ev.key == Key::Qr {
            if matches!(self.current(), Screen::Menu { .. }) {
                self.start_scan(scan::Purpose::Any);
            }
            return;
        }
        match self.current() {
            Screen::Splash => self.reset_to(Screen::Menu {
                id: MenuId::Main,
                sel: 0,
            }),
            Screen::PoweredOff => {
                self.splash_ms = 0;
                self.reset_to(Screen::Splash);
            }
            Screen::Placeholder { .. } | Screen::About => {
                if matches!(ev.key, Key::Esc | Key::Backspace | Key::Enter | Key::Left) {
                    self.pop();
                }
            }
            Screen::Menu { id, sel } => self.menu_key(id, sel, ev),
            Screen::ChooseWords { kind, sel } => match pick(ev.key, sel, 2) {
                Pick::Move(s) => self.set_current(Screen::ChooseWords { kind, sel: s }),
                Pick::Choose(s) => self.start_flow(kind, if s == 0 { 12 } else { 24 }),
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            Screen::EntropyIntro => match ev.key {
                Key::Enter => self.set_current(Screen::EntropyEntry),
                Key::Esc => self.pop(),
                _ => {}
            },
            Screen::EntropyEntry => self.entropy_key(ev),
            Screen::EntropySummary => match ev.key {
                Key::Enter => self.push(Screen::WordsWarning { view: None }),
                Key::Esc | Key::Backspace => {
                    if let Some(f) = self.flow.as_mut() {
                        f.mnemonic = None;
                    }
                    self.pop();
                }
                _ => {}
            },
            Screen::WordsWarning { view } => match (ev.key, view) {
                (Key::Enter, _) => self.set_current(Screen::ShowWords { view }),
                (Key::Esc, None) => self.confirm_cancel(),
                (Key::Esc | Key::Backspace, Some(_)) => self.pop(),
                _ => {}
            },
            Screen::ShowWords { view } => match (ev.key, view) {
                (Key::Enter, None) => self.push(Screen::QuizIntro),
                (Key::Esc, None) => self.confirm_cancel(),
                (Key::Esc | Key::Backspace | Key::Enter, Some(_)) => self.pop(),
                _ => {}
            },
            Screen::QuizIntro => match ev.key {
                Key::Enter => self.start_quiz(),
                Key::Esc | Key::Backspace => self.pop(),
                _ => {}
            },
            Screen::Quiz { sel } => match pick(ev.key, sel, 4) {
                Pick::Move(s) => self.set_current(Screen::Quiz { sel: s }),
                Pick::Choose(s) => self.answer(s),
                Pick::Back if back => self.confirm_cancel(),
                _ => {}
            },
            Screen::QuizFailed { sel } => match pick(ev.key, sel, 2) {
                Pick::Move(s) => self.set_current(Screen::QuizFailed { sel: s }),
                Pick::Choose(0) => {
                    // back to the words, then a fresh quiz
                    self.depth -= 1; // drop QuizFailed
                    self.set_current(Screen::ShowWords { view: None });
                }
                Pick::Choose(_) => self.go_seeds(None),
                _ => {}
            },
            Screen::SeedReady { slot, .. } => {
                if matches!(ev.key, Key::Enter | Key::Esc) {
                    self.set_current(Screen::SeedOptions { slot, sel: 0 });
                }
            }
            Screen::SlotsFull => self.pop(),
            Screen::FinalIntro => match ev.key {
                Key::Enter => self.set_current(Screen::WordEntry),
                Key::Esc => self.pop(),
                _ => {}
            },
            Screen::FinalCoins => self.final_coins_key(ev),
            Screen::FinalResult => match ev.key {
                Key::Enter => self.push(Screen::WordsWarning { view: None }),
                Key::Esc | Key::Backspace => {
                    if let Some(f) = self.flow.as_mut() {
                        f.mnemonic = None;
                    }
                    self.pop();
                }
                _ => {}
            },
            Screen::WordEntry => self.word_entry_key(ev),
            Screen::ChecksumError { sel } => self.checksum_key(sel, ev),
            Screen::SeedOptions { slot, sel } => match pick(ev.key, sel, 6) {
                Pick::Move(s) => self.set_current(Screen::SeedOptions { slot, sel: s }),
                Pick::Choose(0) => self.push(Screen::WordsWarning { view: Some(slot) }),
                Pick::Choose(1) => self.push(Screen::ScriptSelect {
                    slot,
                    explorer: false,
                    sel: 0,
                }),
                Pick::Choose(2) => self.push(Screen::ScriptSelect {
                    slot,
                    explorer: true,
                    sel: 0,
                }),
                Pick::Choose(3) => {
                    let current = self.slot(slot as usize).map(|s| {
                        let mut b = [0u8; seeds::MAX_PASSPHRASE];
                        let p = s.passphrase();
                        b[..p.len()].copy_from_slice(p);
                        (b, p.len())
                    });
                    if let Some((mut b, n)) = current {
                        self.pass_in.set(&b[..n]);
                        bp_crypto::secret::wipe(&mut b);
                    }
                    self.push(Screen::PassphraseEntry { slot });
                }
                Pick::Choose(4) => self.push(Screen::SeedQrSelect { slot, sel: 0 }),
                Pick::Choose(_) => self.push(Screen::Confirm {
                    what: Confirm::DiscardSeed(slot),
                    sel: 0,
                }),
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            Screen::PassphraseEntry { slot } => self.passphrase_key(slot, ev),
            Screen::PassphraseReview { slot, sel } => match pick(ev.key, sel, 2) {
                Pick::Move(s) => self.set_current(Screen::PassphraseReview { slot, sel: s }),
                Pick::Choose(0) => {
                    if let Some(p) = self.pending.take() {
                        self.seeds[slot as usize] = Some(p);
                    }
                    self.pass_in.clear();
                    self.go_seeds(Some(Screen::SeedOptions { slot, sel: 3 }));
                }
                Pick::Choose(_) | Pick::Back => {
                    self.pending = None;
                    self.pop();
                }
                Pick::None => {}
            },
            Screen::ScriptSelect { slot, explorer, sel } => {
                let n = self.visible_scripts().len() as u8;
                match pick(ev.key, sel, n) {
                    Pick::Move(s) => self.set_current(Screen::ScriptSelect {
                        slot,
                        explorer,
                        sel: s,
                    }),
                    Pick::Choose(s) => {
                        let st = self.visible_scripts()[s as usize];
                        if explorer {
                            self.push(Screen::AddressList {
                                slot,
                                st,
                                change: false,
                                page: 0,
                                sel: 0,
                            });
                        } else {
                            self.push(Screen::XpubFormat { slot, st, sel: 0 });
                        }
                    }
                    Pick::Back => self.pop(),
                    Pick::None => {}
                }
            }
            Screen::XpubView { slot, st, account } => match ev.key {
                Key::Left => self.set_current(Screen::XpubView {
                    slot,
                    st,
                    account: account.saturating_sub(1),
                }),
                Key::Right => {
                    self.note_account((account + 1).min(99));
                    self.set_current(Screen::XpubView {
                        slot,
                        st,
                        account: (account + 1).min(99),
                    })
                }
                Key::Esc | Key::Backspace | Key::Enter => {
                    self.pop();
                    // details opened from an xpub QR: follow the account change
                    if let Screen::QrShow {
                        kind:
                            QrKind::Xpub {
                                slot: s,
                                st: t,
                                account: a,
                                format,
                            },
                    } = self.current()
                    {
                        if a != account {
                            self.open_qr(QrKind::Xpub {
                                slot: s,
                                st: t,
                                account,
                                format,
                            });
                        }
                    }
                }
                _ => {}
            },
            Screen::AddressList {
                slot,
                st,
                change,
                page,
                sel,
            } => match ev.key {
                Key::Up => {
                    if sel > 0 {
                        self.set_current(Screen::AddressList {
                            slot,
                            st,
                            change,
                            page,
                            sel: sel - 1,
                        });
                    } else if page > 0 {
                        self.set_current(Screen::AddressList {
                            slot,
                            st,
                            change,
                            page: page - 1,
                            sel: 9,
                        });
                    }
                }
                Key::Down => {
                    if sel < 9 {
                        self.set_current(Screen::AddressList {
                            slot,
                            st,
                            change,
                            page,
                            sel: sel + 1,
                        });
                    } else {
                        self.set_current(Screen::AddressList {
                            slot,
                            st,
                            change,
                            page: page + 1,
                            sel: 0,
                        });
                    }
                }
                Key::Left => self.set_current(Screen::AddressList {
                    slot,
                    st,
                    change,
                    page: page.saturating_sub(1),
                    sel,
                }),
                Key::Right => self.set_current(Screen::AddressList {
                    slot,
                    st,
                    change,
                    page: page + 1,
                    sel,
                }),
                Key::Tab => self.set_current(Screen::AddressList {
                    slot,
                    st,
                    change: !change,
                    page: 0,
                    sel: 0,
                }),
                Key::Enter => self.push(Screen::AddressDetail {
                    slot,
                    st,
                    change,
                    index: page * 10 + sel as u32,
                }),
                Key::Esc | Key::Backspace => self.pop(),
                _ => {}
            },
            Screen::AddressDetail {
                slot,
                st,
                change,
                index,
            } => match ev.key {
                Key::Left | Key::Up => self.set_current(Screen::AddressDetail {
                    slot,
                    st,
                    change,
                    index: index.saturating_sub(1),
                }),
                Key::Right | Key::Down => self.set_current(Screen::AddressDetail {
                    slot,
                    st,
                    change,
                    index: index + 1,
                }),
                Key::Esc | Key::Backspace | Key::Enter => self.pop(),
                _ => {}
            },
            Screen::PickSeed { sel } => {
                let n = self.seed_count() as u8;
                match pick(ev.key, sel, n.max(1)) {
                    Pick::Move(s) => self.set_current(Screen::PickSeed { sel: s }),
                    Pick::Choose(s) => {
                        if let Some(slot) = self.seed_row_slot(s as usize) {
                            self.push(Screen::ScriptSelect {
                                slot: slot as u8,
                                explorer: true,
                                sel: 0,
                            });
                        }
                    }
                    Pick::Back => self.pop(),
                    Pick::None => {}
                }
            }
            Screen::NoSeed => self.pop(),
            Screen::XpubFormat { slot, st, sel } => match pick(ev.key, sel, 4) {
                Pick::Move(s) => self.set_current(Screen::XpubFormat { slot, st, sel: s }),
                Pick::Choose(s) => {
                    let format = XpubFormat::ALL[s as usize];
                    self.open_qr(QrKind::Xpub {
                        slot,
                        st,
                        account: 0,
                        format,
                    });
                }
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            Screen::QrShow { kind } => self.qr_key(kind, ev),
            Screen::SeedQrSelect { slot, sel } => match pick(ev.key, sel, 2) {
                Pick::Move(s) => self.set_current(Screen::SeedQrSelect { slot, sel: s }),
                Pick::Choose(s) => self.push(Screen::SeedQrWarning {
                    slot,
                    compact: s == 1,
                }),
                Pick::Back => self.pop(),
                Pick::None => {}
            },
            Screen::SeedQrWarning { slot, compact } => match ev.key {
                Key::Enter => {
                    self.depth -= 1; // the warning is replaced by the QR
                    self.open_qr(QrKind::SeedQr { slot, compact });
                }
                Key::Esc | Key::Backspace => self.pop(),
                _ => {}
            },
            Screen::Transcribe { slot, line, x, y } => self.transcribe_key(slot, line, x, y, ev),
            Screen::Scan { .. } => {
                if matches!(ev.key, Key::Esc | Key::Backspace) {
                    self.pop();
                }
            }
            Screen::ScanSeed { sel } => match pick(ev.key, sel, 2) {
                Pick::Move(s) => self.set_current(Screen::ScanSeed { sel: s }),
                Pick::Choose(0) => match (self.free_slot(), self.scanned.take()) {
                    (Some(slot), Some(seed)) => {
                        self.seeds[slot] = Some(seed);
                        self.go_seeds(Some(Screen::SeedReady {
                            slot: slot as u8,
                            created: false,
                        }));
                    }
                    (None, _) => self.go_seeds(Some(Screen::SlotsFull)),
                    _ => self.pop(),
                },
                Pick::Choose(_) | Pick::Back => {
                    self.scanned = None;
                    self.pop();
                }
                Pick::None => {}
            },
            Screen::Review { step } => self.review_key(step, ev),
            Screen::VerifyAddr { step } => self.verify_key(step, ev),
            Screen::ScanVerify { .. } | Screen::ScanResult => match ev.key {
                Key::Enter | Key::Esc | Key::Backspace => self.pop(),
                _ => {}
            },
            Screen::Confirm { what, sel } => match pick(ev.key, sel, 2) {
                Pick::Move(s) => self.set_current(Screen::Confirm { what, sel: s }),
                Pick::Choose(0) | Pick::Back => self.pop(),
                Pick::Choose(_) => match what {
                    Confirm::CancelFlow => self.go_seeds(None),
                    Confirm::DiscardSeed(slot) => {
                        self.seeds[slot as usize] = None; // Mnemonic wipes itself
                        self.go_seeds(None);
                    }
                },
                Pick::None => {}
            },
        }
    }

    /// Script types offered: Native SegWit and Taproot, plus Nested SegWit
    /// and Legacy when "Advanced features" is on.
    pub fn visible_scripts(&self) -> &'static [ScriptType] {
        if self.settings.advanced {
            &ScriptType::ALL
        } else {
            &ScriptType::ALL[..2]
        }
    }

    fn passphrase_key(&mut self, slot: u8, ev: KeyEvent) {
        match ev.key {
            Key::Char(c) if (' '..='~').contains(&c) => {
                if self.pass_in.len < self.pass_in.buf.len() {
                    self.pass_in.buf[self.pass_in.len] = c as u8;
                    self.pass_in.len += 1;
                }
            }
            Key::Backspace => {
                if self.pass_in.len > 0 {
                    self.pass_in.len -= 1;
                    self.pass_in.buf[self.pass_in.len] = 0;
                }
            }
            Key::Tab => self.pass_in.show = !self.pass_in.show,
            Key::Enter => {
                let Some(m) = self.seed(slot as usize).cloned() else {
                    return;
                };
                self.pending = seeds::SeedSlot::new(m, self.pass_in.text());
                if self.pending.is_some() {
                    self.push(Screen::PassphraseReview { slot, sel: 0 });
                }
            }
            Key::Esc => {
                self.pass_in.clear();
                self.pop();
            }
            _ => {}
        }
    }

    /// Build the QR session for `kind` and show it.
    fn open_qr(&mut self, kind: QrKind) {
        let net = self.settings.network;
        let session = match kind {
            QrKind::Xpub {
                slot,
                st,
                account,
                format,
            } => {
                let Some(seed) = self.slot(slot as usize) else {
                    return;
                };
                let Some(xpub) = seed.account_xpub(st, net, account) else {
                    return;
                };
                let path = st.account_path(net, account);
                let key = bp_bitcoin::urtypes::AccountKey {
                    xpub: &xpub,
                    master_fingerprint: seed.fingerprint,
                    path: &path,
                    script: st,
                    network: net,
                };
                let mut buf = [0u8; qrview::PAYLOAD_MAX];
                let (fmt, n) = match format {
                    XpubFormat::UrAccount => (
                        qrview::Format::Ur(bp_bitcoin::urtypes::UR_ACCOUNT),
                        bp_bitcoin::urtypes::crypto_account(&key, &mut buf).unwrap_or(0),
                    ),
                    XpubFormat::UrOutput => (
                        qrview::Format::Ur(bp_bitcoin::urtypes::UR_OUTPUT),
                        bp_bitcoin::urtypes::crypto_output(&key, &mut buf).unwrap_or(0),
                    ),
                    XpubFormat::StaticText | XpubFormat::Specter => {
                        let n = view::xpub_origin_text(seed.fingerprint, &xpub, st, net, account, &mut buf);
                        let f = if format == XpubFormat::Specter {
                            qrview::Format::Specter
                        } else {
                            qrview::Format::Static
                        };
                        (f, n)
                    }
                };
                // Jade policy: xpub exports start at low density and slow speed.
                qrview::QrSession::new(fmt, &buf[..n], qrview::Density::Low, qrview::Speed::Slow)
            }
            QrKind::SeedQr { slot, compact } => {
                let Some(m) = self.seed(slot as usize) else { return };
                let mut digits = [0u8; bp_bitcoin::seedqr::MAX_DIGITS];
                let mut ent = [0u8; 32];
                let s = if compact {
                    let n = bp_bitcoin::seedqr::compact_bytes(m, &mut ent);
                    qrview::QrSession::new(
                        qrview::Format::SeedCompact,
                        &ent[..n],
                        qrview::Density::Auto,
                        qrview::Speed::Slow,
                    )
                } else {
                    let n = bp_bitcoin::seedqr::standard_digits(m, &mut digits);
                    qrview::QrSession::new(
                        qrview::Format::SeedStandard,
                        &digits[..n],
                        qrview::Density::Auto,
                        qrview::Speed::Slow,
                    )
                };
                bp_crypto::secret::wipe(&mut digits);
                bp_crypto::secret::wipe(&mut ent);
                s
            }
            QrKind::SignedPsbt { format } => {
                let Some(len) = self.review.as_ref().and_then(|r| r.signed).map(|s| s.len) else {
                    return;
                };
                let psbt = &self.scan.work()[..len];
                let s = signed_psbt_session(psbt, format);
                if s.is_none() {
                    self.notice = Some(self.text().rv.qr_too_large);
                    return;
                }
                s
            }
        };
        // keep the viewer's display preferences when only the content changes
        let keep = self
            .qr
            .as_ref()
            .map(|q| (q.brightness, q.invert, q.fullscreen, q.speed));
        self.qr = session;
        if let (Some(q), Some((b, i, f, sp))) = (self.qr.as_mut(), keep) {
            q.brightness = b;
            q.invert = i;
            q.fullscreen = f;
            q.speed = sp;
        }
        if self.qr.is_some() {
            if matches!(self.current(), Screen::QrShow { .. }) {
                self.set_current(Screen::QrShow { kind });
            } else {
                self.push(Screen::QrShow { kind });
            }
        }
    }

    fn close_qr(&mut self) {
        self.qr = None; // wipes the payload
        self.pop();
    }

    fn qr_key(&mut self, kind: QrKind, ev: KeyEvent) {
        let Some(q) = self.qr.as_mut() else {
            self.pop();
            return;
        };
        let animatable = matches!(
            q.format,
            qrview::Format::Ur(_) | qrview::Format::Specter | qrview::Format::Bbqr { .. }
        );
        match ev.key {
            Key::Left if animatable => q.set_density(q.density.step(-1)),
            Key::Right if animatable => q.set_density(q.density.step(1)),
            Key::Up => q.brightness = q.brightness.saturating_sub(1),
            Key::Down => q.brightness = (q.brightness + 1).min(qrview::QrSession::brightness_levels() - 1),
            Key::Tab => q.speed = q.speed.next(),
            Key::Char(' ') => q.paused = !q.paused,
            Key::Char('i' | 'I') => q.invert = !q.invert,
            Key::Enter => q.fullscreen = !q.fullscreen,
            Key::Esc if q.fullscreen => q.fullscreen = false,
            Key::Esc | Key::Backspace => self.close_qr(),
            Key::Char('v' | 'V') => {
                if let QrKind::SeedQr { slot, .. } = kind {
                    self.start_scan(scan::Purpose::Verify { slot });
                }
            }
            Key::Char('t' | 'T') => {
                if let QrKind::SeedQr { slot, .. } = kind {
                    self.push(Screen::Transcribe {
                        slot,
                        line: false,
                        x: 0,
                        y: 0,
                    });
                }
            }
            Key::Char('d' | 'D') => {
                if let QrKind::Xpub {
                    slot, st, account, ..
                } = kind
                {
                    self.push(Screen::XpubView { slot, st, account });
                }
            }
            Key::Char(c @ '0'..='9') => {
                if let QrKind::Xpub { slot, st, format, .. } = kind {
                    let account = c as u32 - '0' as u32;
                    self.open_qr(QrKind::Xpub {
                        slot,
                        st,
                        account,
                        format,
                    });
                }
            }
            _ => {}
        }
        self.dirty = true;
    }

    fn transcribe_key(&mut self, slot: u8, line: bool, x: u8, y: u8, ev: KeyEvent) {
        let Some(size) = self.qr.as_ref().and_then(|q| q.qr()).map(|q| q.size() as u8) else {
            self.pop();
            return;
        };
        let blocks = size.div_ceil(5);
        let (mx, my) = if line {
            (0, size - 1)
        } else {
            (blocks - 1, blocks - 1)
        };
        let (nx, ny) = match ev.key {
            Key::Left => (x.saturating_sub(1), y),
            Key::Right => ((x + 1).min(mx), y),
            Key::Up => (x, y.saturating_sub(1)),
            Key::Down => (x, (y + 1).min(my)),
            Key::Tab => {
                self.set_current(Screen::Transcribe {
                    slot,
                    line: !line,
                    x: 0,
                    y: 0,
                });
                return;
            }
            Key::Char('v' | 'V') => {
                self.start_scan(scan::Purpose::Verify { slot });
                return;
            }
            Key::Esc | Key::Backspace | Key::Enter => {
                self.pop();
                return;
            }
            _ => (x, y),
        };
        self.set_current(Screen::Transcribe {
            slot,
            line,
            x: nx,
            y: ny,
        });
    }

    fn confirm_cancel(&mut self) {
        self.push(Screen::Confirm {
            what: Confirm::CancelFlow,
            sel: 0,
        });
    }

    fn menu_rows(&self, id: MenuId) -> usize {
        let extra = if id == MenuId::Seeds { self.seed_count() } else { 0 };
        extra + menus::table(id).len()
    }

    fn menu_key(&mut self, id: MenuId, sel: u8, ev: KeyEvent) {
        let n = self.menu_rows(id) as u8;
        match ev.key {
            Key::Left if menus::is_settings(id) => self.change_setting(sel, -1),
            Key::Right if menus::is_settings(id) => self.change_setting(sel, 1),
            Key::Left => self.pop(),
            _ => match pick(ev.key, sel, n) {
                Pick::Move(s) => self.set_current(Screen::Menu { id, sel: s }),
                Pick::Choose(s) => {
                    self.set_current(Screen::Menu { id, sel: s });
                    self.activate(id, s);
                }
                Pick::Back => self.pop(),
                Pick::None => {}
            },
        }
    }

    fn change_setting(&mut self, sel: u8, dir: i8) {
        if self.settings.cycle(MenuId::Settings, sel, dir) {
            self.dirty = true;
        }
    }

    /// Map a Seeds-menu row to a loaded seed slot, if it is one.
    fn seed_row_slot(&self, row: usize) -> Option<usize> {
        self.seeds
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .nth(row)
            .map(|(i, _)| i)
    }

    fn activate(&mut self, id: MenuId, sel: u8) {
        let mut row = sel as usize;
        if id == MenuId::Seeds {
            if let Some(slot) = self.seed_row_slot(row) {
                self.push(Screen::SeedOptions {
                    slot: slot as u8,
                    sel: 0,
                });
                return;
            }
            row -= self.seed_count();
        }
        match menus::table(id)[row].action {
            Action::Open(sub) => self.push(Screen::Menu { id: sub, sel: 0 }),
            Action::Todo(label, phase) => self.push(Screen::Placeholder {
                title: label(self.text()),
                phase: phase(self.text()),
            }),
            Action::Start(kind) => {
                if self.free_slot().is_none() {
                    self.push(Screen::SlotsFull);
                } else {
                    self.push(Screen::ChooseWords { kind, sel: 0 });
                }
            }
            Action::CycleSetting => self.change_setting(row as u8, 1),
            Action::About => self.push(Screen::About),
            Action::Scan(purpose) => self.start_scan(purpose),
            Action::Explorer => match self.seed_count() {
                0 => self.push(Screen::NoSeed),
                1 => {
                    let slot = self.seed_row_slot(0).unwrap_or(0) as u8;
                    self.push(Screen::ScriptSelect {
                        slot,
                        explorer: true,
                        sel: 0,
                    });
                }
                _ => self.push(Screen::PickSeed { sel: 0 }),
            },
            Action::VerifyAddress => {
                if self.seed_count() == 0 {
                    self.push(Screen::NoSeed);
                } else {
                    self.start_scan(scan::Purpose::Address);
                }
            }
            Action::PowerOff => {
                self.flow = None;
                self.seeds = [None, None, None];
                self.review = None;
                self.verify = None;
                self.last_found = None;
                self.n_session_accounts = 1;
                self.memory.clear();
                self.reset_to(Screen::PoweredOff);
            }
        }
    }

    fn start_flow(&mut self, kind: Start, words: usize) {
        self.flow = Some(Flow::new(kind, words));
        match kind {
            Start::Dice | Start::Coin => self.push(Screen::EntropyIntro),
            Start::TypeWords | Start::WordNumbers => self.push(Screen::WordEntry),
            Start::FinalWord => self.push(Screen::FinalIntro),
        }
    }

    fn final_coins_key(&mut self, ev: KeyEvent) {
        let Some(flow) = self.flow.as_mut() else { return };
        let free = flow.free_bits();
        match ev.key {
            Key::Char(c) => {
                let bit = match c {
                    '1' | 'h' | 'H' => Some(1),
                    '0' | 't' | 'T' => Some(0),
                    _ => None,
                };
                if let Some(b) = bit {
                    if flow.coin_len < free {
                        flow.coins[flow.coin_len] = b;
                        flow.coin_len += 1;
                    }
                }
            }
            Key::Backspace => {
                if flow.coin_len > 0 {
                    flow.coin_len -= 1;
                } else {
                    // back to the words to edit the last one
                    flow.entry.step_back();
                    self.set_current(Screen::WordEntry);
                }
            }
            Key::Enter => {
                if flow.coin_len < free {
                    self.notice = Some(self.text().not_ready);
                    return;
                }
                let n = flow.entry.n;
                let Ok(last) = bip39::final_word(&flow.entry.idx[..n], flow.coin_value()) else {
                    return;
                };
                let mut all = [0u16; bip39::MAX_WORDS];
                all[..n].copy_from_slice(&flow.entry.idx[..n]);
                all[n] = last;
                let m = Mnemonic::from_indices(&all[..n + 1]);
                bp_crypto::secret::wipe_u16(&mut all);
                if let Ok(m) = m {
                    flow.mnemonic = Some(m);
                    self.push(Screen::FinalResult);
                }
            }
            Key::Esc => self.confirm_cancel(),
            _ => {}
        }
    }

    fn entropy_key(&mut self, ev: KeyEvent) {
        let Some(flow) = self.flow.as_mut() else { return };
        let Some(pe) = flow.entropy.as_mut() else { return };
        let dice = flow.kind == Start::Dice;
        match ev.key {
            Key::Char(c) => {
                let v = match (dice, c) {
                    (true, '1'..='6') => Some(c as u8 - b'0'),
                    (false, '1' | 'h' | 'H') => Some(1),
                    (false, '0' | 't' | 'T') => Some(0),
                    _ => None,
                };
                if let Some(v) = v {
                    let _ = pe.push(v);
                }
            }
            Key::Backspace => pe.pop(),
            Key::Enter => match pe.to_mnemonic() {
                Ok(m) => {
                    flow.mnemonic = Some(m);
                    self.push(Screen::EntropySummary);
                }
                Err(_) => self.notice = Some(self.text().not_ready),
            },
            Key::Esc => self.confirm_cancel(),
            _ => {}
        }
    }

    fn start_quiz(&mut self) {
        let Some(flow) = self.flow.as_mut() else { return };
        let Some(m) = flow.mnemonic.as_ref() else { return };
        flow.quiz = Quiz::new(m, &mut self.quiz_rng);
        self.set_current(Screen::Quiz { sel: 0 });
    }

    fn answer(&mut self, choice: u8) {
        let Some(flow) = self.flow.as_mut() else { return };
        let q = flow.quiz.q;
        if flow.quiz.answer[q] != choice {
            self.set_current(Screen::QuizFailed { sel: 0 });
            return;
        }
        flow.quiz.q += 1;
        if !flow.quiz.done() {
            self.set_current(Screen::Quiz { sel: 0 });
            return;
        }
        // Every word confirmed: only now does the seed exist.
        let m = flow.mnemonic.take();
        self.store_seed(m, true);
    }

    fn store_seed(&mut self, m: Option<Mnemonic>, created: bool) {
        let Some(m) = m else { return };
        match self.free_slot() {
            Some(slot) => {
                self.seeds[slot] = seeds::SeedSlot::new(m, b"");
                self.go_seeds(Some(Screen::SeedReady {
                    slot: slot as u8,
                    created,
                }));
            }
            None => self.go_seeds(Some(Screen::SlotsFull)),
        }
    }

    fn word_entry_key(&mut self, ev: KeyEvent) {
        enum Next {
            Stay,
            Accept,
            AutoAccept,
            Notice(&'static str),
            Cancel,
            Recheck,
        }
        let s = self.text();
        let Some(flow) = self.flow.as_mut() else { return };
        let numbers = flow.numbers_mode();
        let e = &mut flow.entry;
        let next = match ev.key {
            Key::Char(' ') if e.input_len == 0 => {
                e.tail = None;
                Next::Stay
            }
            Key::Char(' ') => Next::Accept,
            Key::Char(c) => {
                let before = e.input_len;
                if !e.push_char(c, numbers) {
                    Next::Notice(if numbers { s.number_range } else { s.no_match })
                } else if !numbers && e.input_len > before && e.auto_accept_ready() {
                    Next::AutoAccept
                } else {
                    Next::Stay
                }
            }
            Key::Up if !numbers => {
                e.cand = e.cand.saturating_sub(1);
                Next::Stay
            }
            Key::Down if !numbers => {
                if e.cand + 1 < e.candidates().len() {
                    e.cand += 1;
                }
                Next::Stay
            }
            Key::Enter | Key::Tab if e.input_len == 0 && !numbers => {
                e.tail = None;
                Next::Stay
            }
            Key::Enter | Key::Tab => Next::Accept,
            Key::Backspace => {
                e.tail = None;
                if !e.backspace_char() && e.fixing.is_none() {
                    e.step_back();
                }
                Next::Stay
            }
            Key::Esc if e.fixing.is_some() => {
                e.fixing = None;
                Next::Recheck
            }
            Key::Esc => Next::Cancel,
            _ => Next::Stay,
        };
        match next {
            Next::Stay => {}
            Next::Accept => self.accept_word(),
            Next::AutoAccept => {
                if let Some(f) = self.flow.as_mut() {
                    f.entry.auto_accept();
                    if f.entry.complete() {
                        self.check_entry();
                    }
                }
            }
            Next::Notice(m) => self.notice = Some(m),
            Next::Cancel => self.confirm_cancel(),
            Next::Recheck => self.check_entry(),
        }
    }

    fn accept_word(&mut self) {
        let Some(flow) = self.flow.as_mut() else { return };
        let numbers = flow.numbers_mode();
        let e = &mut flow.entry;
        let word = if numbers {
            match e.number_value() {
                Some(w) => w,
                None => {
                    self.notice = Some(self.text().number_range);
                    return;
                }
            }
        } else {
            let r = e.candidates();
            if e.input_len == 0 || r.is_empty() {
                return;
            }
            (r.start + e.cand.min(r.len() - 1)) as u16
        };
        e.accept(word);
        if e.complete() {
            self.check_entry();
        }
    }

    fn check_entry(&mut self) {
        let Some(flow) = self.flow.as_ref() else { return };
        if !flow.entry.complete() {
            self.set_current(Screen::WordEntry);
            return;
        }
        if flow.kind == Start::FinalWord {
            // words drawn by the user; coin flips complete the last word
            self.set_current(Screen::FinalCoins);
            return;
        }
        match Mnemonic::from_indices(flow.entry.indices()) {
            Ok(m) => self.store_seed(Some(m), false),
            Err(_) => self.set_current(Screen::ChecksumError { sel: 0 }),
        }
    }

    fn checksum_key(&mut self, sel: u8, ev: KeyEvent) {
        let Some(flow) = self.flow.as_mut() else { return };
        let n = flow.words as u8;
        let rows = n / 4;
        let sel = match ev.key {
            Key::Up => (sel + n - 1) % n,
            Key::Down => (sel + 1) % n,
            Key::Left => (sel + n - rows) % n,
            Key::Right => (sel + rows) % n,
            Key::Enter => {
                flow.entry.start_fix(sel as usize);
                self.set_current(Screen::WordEntry);
                return;
            }
            Key::Esc => {
                self.confirm_cancel();
                return;
            }
            _ => sel,
        };
        self.set_current(Screen::ChecksumError { sel });
    }
}

enum Pick {
    Move(u8),
    Choose(u8),
    Back,
    None,
}

/// Shared list navigation: arrows move (wrapping), Enter/Right choose,
/// digits jump-and-choose, Esc/Backspace go back.
fn pick(key: Key, sel: u8, n: u8) -> Pick {
    match key {
        Key::Up => Pick::Move(if sel == 0 { n - 1 } else { sel - 1 }),
        Key::Down | Key::Tab => Pick::Move((sel + 1) % n),
        Key::Enter | Key::Right => Pick::Choose(sel),
        Key::Char(c @ '1'..='9') if (c as u8 - b'1') < n => Pick::Choose(c as u8 - b'1'),
        Key::Esc | Key::Backspace => Pick::Back,
        _ => Pick::None,
    }
}

/// QR session for a signed PSBT: UR crypto-psbt (CBOR bytes), BBQr
/// (zlib + base32) or Specter (base64 text). `None` if it does not fit.
fn signed_psbt_session(psbt: &[u8], format: PsbtFormat) -> Option<qrview::QrSession> {
    let mut buf = [0u8; qrview::PAYLOAD_MAX];
    let (fmt, n) = match format {
        PsbtFormat::Ur => {
            let mut w = bp_qr::ur::cbor::Writer::new(&mut buf);
            w.bytes(psbt).ok()?;
            (qrview::Format::Ur("crypto-psbt"), w.len())
        }
        PsbtFormat::Specter => (
            qrview::Format::Specter,
            bp_bitcoin::base64::encode(psbt, &mut buf).ok()?,
        ),
        PsbtFormat::Bbqr => {
            let mut work = [0u8; qrview::PAYLOAD_MAX];
            let b = bp_qr::bbqr::Bbqr::new(
                psbt,
                bp_qr::bbqr::FileType::Psbt,
                bp_qr::bbqr::Encoding::Zlib,
                1,
                40,
                &mut work,
                &mut buf,
            )
            .ok()?;
            (
                qrview::Format::Bbqr {
                    encoding: b.encoding(),
                    file_type: bp_qr::bbqr::FileType::Psbt,
                },
                b.chars().len(),
            )
        }
    };
    qrview::QrSession::new(fmt, &buf[..n], qrview::Density::Auto, qrview::Speed::Normal)
}

#[cfg(test)]
mod bench;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_review;
