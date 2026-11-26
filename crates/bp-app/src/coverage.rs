//! Screen coverage (M9-0): every screen kind and flow step, named by
//! exhaustive matches. A new screen or step does not compile until it is
//! listed here, and `every_screen_and_step_is_drawn` then fails until the
//! screen tests draw it.

extern crate std;

use super::*;
use crate::b85::B85Step;
use crate::keys::KeyStep;
use crate::metalui::MetalStep;
use crate::msgsign::MsStep;
use crate::notesui::NoteStep;
use crate::review::Step as RvStep;
use crate::scan::Purpose;
use crate::sd::SdStep;
use crate::seedxorui::XorStep;
use crate::sigverify::SvStep;
use crate::slip39ui::SlStep;
use crate::vaultseeds::SeedVaultStep;
use crate::vaulttamper::TamperStep;
use crate::vaulttricks::TrickStep;
use crate::vaultui::VStep;
use crate::verify::VaStep;
use crate::wallets::WlStep;
use core::cell::RefCell;
use std::collections::BTreeSet;
use std::string::{String, ToString};
use std::vec::Vec;

/// `fn $f(&$e) -> &str` with one arm per variant, and `const $all` listing them.
macro_rules! kinds {
    ($f:ident, $all:ident, $e:ident, [$($v:ident),* $(,)?]) => {
        fn $f(x: &$e) -> &'static str {
            match x {
                $($e::$v { .. } => stringify!($v),)*
            }
        }
        const $all: &[&str] = &[$(stringify!($v)),*];
    };
}

kinds!(
    screen,
    SCREENS,
    Screen,
    [
        Splash,
        Welcome,
        PoweredOff,
        About,
        Menu,
        ChooseWords,
        EntropyIntro,
        FinalIntro,
        FinalCoins,
        FinalResult,
        EntropyEntry,
        EntropySummary,
        WordsWarning,
        ShowWords,
        QuizIntro,
        Quiz,
        QuizFailed,
        SeedReady,
        SlotsFull,
        WordEntry,
        ChecksumError,
        WordReview,
        SeedOptions,
        PassphraseEntry,
        PassphraseReview,
        ScriptSelect,
        XpubView,
        AddressList,
        AddressDetail,
        PickSeed,
        NoSeed,
        XpubFormat,
        QrShow,
        SeedQrSelect,
        SeedQrWarning,
        Transcribe,
        Confirm,
        Scan,
        ScanSeed,
        ScanVerify,
        ScanResult,
        Review,
        VerifyAddr,
        MsgSign,
        SigVerify,
        SettingsImport,
        Wallets,
        Sd,
        Bip85,
        Key,
        Vault,
        SeedVault,
        Tricks,
        Tamper,
        Slip39,
        SeedXor,
        Metal,
        Notes,
        CommDetected,
    ]
);
kinds!(
    menu,
    MENUS,
    MenuId,
    [Main, Sign, Verify, Seeds, NewSeed, LoadSeed, Settings, Security, Power, Tools]
);
kinds!(
    qr,
    QRS,
    QrKind,
    [Xpub, SeedQr, SignedPsbt, MessageSig, Settings, Wallet, Bip85, Note, MsKey]
);
kinds!(confirm, CONFIRMS, Confirm, [CancelFlow, DiscardSeed]);
kinds!(
    purpose,
    PURPOSES,
    Purpose,
    [Any, Seed, Verify, Address, Signed, SigText, Wallet, PrivKey, Cosigner,]
);
kinds!(
    review,
    REVIEW,
    RvStep,
    [
        WrongSeed,
        Problem,
        Warning,
        Overview,
        Output,
        Fee,
        Approve,
        Signed,
        Failed,
        Forged,
        MsgOff,
        MsgRule,
        MsgPage,
        MsgAddress,
        MsRegister,
        MsCode,
        VerifiedOnly,
    ]
);
kinds!(va, VA, VaStep, [Confirm, Searching, Paused, Found]);
kinds!(
    ms,
    MS,
    MsStep,
    [Off, Problem, PickSeed, Type, Message, Address, Confirm, Done, Failed,]
);
kinds!(sv, SV, SvStep, [Type, Result]);
kinds!(
    wl,
    WL,
    WlStep,
    [
        List,
        NeedSeed,
        Refused,
        Summary,
        Cosigner,
        Addresses,
        CodeShow,
        CodeEntry,
        Registered,
        Wallet,
        Keys,
        Export,
        Remove,
        PickSeed,
        CreateSize,
        CreateKeys,
        CreateConfirm,
        CreateRefused,
        KeyScript,
        KeyFormat,
        Address,
        AddrSearch,
        AddrPaused,
        AddrFound,
    ]
);
kinds!(
    sd,
    SD,
    SdStep,
    [Status, Browse, File, Text, Delete, Format, Formatted, PsbtList, Saved,]
);
kinds!(b85, B85, B85Step, [PickSeed, App, Params, Warning, Result]);
kinds!(key, KEY, KeyStep, [Method, Type, Confirm, Refused, Addresses]);
kinds!(
    vs,
    VS,
    VStep,
    [
        Prefix,
        Words,
        Suffix,
        Working,
        Delay,
        Wiped,
        Problem,
        Intro,
        NewPrefix,
        NewSuffix,
        AgainPrefix,
        AgainSuffix,
        Remember,
        Wipe,
    ]
);

kinds!(svt, SVT, SeedVaultStep, [List, Seed, Pick, Remove]);
kinds!(tr, TR, TrickStep, [List, Kind, Seed, Remove]);
kinds!(tc, TC, TamperStep, [Code, Working, Words]);
kinds!(
    sl,
    SL,
    SlStep,
    [
        Length, Words, Fix, Status, Passphrase, Ready, Source, Strength, Groups, Custom, Mix, Dice, Show,
        Covered, Check
    ]
);

kinds!(
    xr,
    XR,
    XorStep,
    [Parts, Mode, Dice, Show, Covered, Check, Done, Combined]
);
kinds!(mt, MT, MetalStep, [Format, View, Covered, Grid]);
kinds!(nt, NT, NoteStep, [List, View, Edit, Field, Generate, Delete]);

/// "Screen" or "Screen/Step" for screens that hold a step or a kind.
pub fn key_of(s: &Screen) -> String {
    let sub = match s {
        Screen::Menu { id, .. } => menu(id),
        Screen::QrShow { kind } => qr(kind),
        Screen::Confirm { what, .. } => confirm(what),
        Screen::Scan { purpose: p } => purpose(p),
        Screen::Review { step } => review(step),
        Screen::VerifyAddr { step } => va(step),
        Screen::MsgSign { step } => ms(step),
        Screen::SigVerify { step } => sv(step),
        Screen::Wallets { step } => wl(step),
        Screen::Sd { step } => sd(step),
        Screen::Bip85 { step } => b85(step),
        Screen::Key { step } => key(step),
        Screen::Vault { step } => vs(step),
        Screen::SeedVault { step } => svt(step),
        Screen::Tricks { step } => tr(step),
        Screen::Tamper { step } => tc(step),
        Screen::Slip39 { step } => sl(step),
        Screen::SeedXor { step } => xr(step),
        Screen::Metal { step } => mt(step),
        Screen::Notes { step } => nt(step),
        _ => return screen(s).to_string(),
    };
    let mut k = String::from(screen(s));
    k.push('/');
    k.push_str(sub);
    k
}

/// Every key `key_of` can return.
pub fn all() -> Vec<String> {
    let subs: &[(&str, &[&str])] = &[
        ("Menu", MENUS),
        ("QrShow", QRS),
        ("Confirm", CONFIRMS),
        ("Scan", PURPOSES),
        ("Review", REVIEW),
        ("VerifyAddr", VA),
        ("MsgSign", MS),
        ("SigVerify", SV),
        ("Wallets", WL),
        ("Sd", SD),
        ("Bip85", B85),
        ("Key", KEY),
        ("Vault", VS),
        ("SeedVault", SVT),
        ("Tricks", TR),
        ("Tamper", TC),
        ("Slip39", SL),
        ("SeedXor", XR),
        ("Metal", MT),
        ("Notes", NT),
    ];
    let mut out = Vec::new();
    for s in SCREENS {
        match subs.iter().find(|(n, _)| n == s) {
            Some((_, list)) => {
                for v in *list {
                    let mut k = String::from(*s);
                    k.push('/');
                    k.push_str(v);
                    out.push(k);
                }
            }
            None => out.push(String::from(*s)),
        }
    }
    out
}

std::thread_local! {
    static SEEN: RefCell<Option<BTreeSet<String>>> = const { RefCell::new(None) };
}

/// Called by `App::render` in test builds.
pub fn note(s: &Screen) {
    SEEN.with(|seen| {
        if let Some(set) = seen.borrow_mut().as_mut() {
            set.insert(key_of(s));
        }
    });
}

/// Start recording the screens this thread draws.
pub fn start() {
    SEEN.with(|seen| *seen.borrow_mut() = Some(BTreeSet::new()));
}

/// Stop recording and return what was drawn.
pub fn finish() -> BTreeSet<String> {
    SEEN.with(|seen| seen.borrow_mut().take().unwrap_or_default())
}
