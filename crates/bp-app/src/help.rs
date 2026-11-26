//! Screen help (M9-9, C11). `?` (F1 on a host keyboard) opens a box that
//! explains the screen; any key closes it and does nothing else. On the
//! screens where text is typed (passphrase, message, signature message) `?`
//! is a character as before, and only F1 opens the help.

use crate::{menus::MenuId, msgsign, sigverify, App, QrKind, Screen};
use bp_hal::input::Key;

/// Help topics, in `text_help::HelpStrings::topics` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topic {
    Menus,
    MakeSeed,
    Backup,
    TypeWords,
    Seeds,
    Passphrase,
    Addresses,
    QrCodes,
    Scanning,
    Review,
    VerifyAddress,
    SignMessage,
    VerifySignature,
    Multisig,
    Sd,
    Settings,
    Bip85,
    PrivateKey,
    Vault,
    /// SLIP-39 shares (M11-2).
    Slip39,
    /// Seed XOR (M11-3).
    SeedXor,
    /// Metal plates (M11-4).
    Metal,
    /// Secure notes (M11-6).
    Notes,
}

/// The topic for a screen; `None` where help is not offered (start-up,
/// power off, the communication-chip lock).
pub fn topic(s: &Screen) -> Option<Topic> {
    use Topic::*;
    Some(match s {
        Screen::Splash | Screen::PoweredOff | Screen::CommDetected => return None,
        Screen::Welcome { .. } | Screen::About => Menus,
        Screen::Menu { id, .. } => match id {
            MenuId::Settings => Settings,
            MenuId::Security => Vault,
            MenuId::NewSeed => MakeSeed,
            MenuId::Seeds | MenuId::LoadSeed => Seeds,
            MenuId::Tools => Notes,
            _ => Menus,
        },
        Screen::ChooseWords { .. }
        | Screen::EntropyIntro
        | Screen::EntropyEntry
        | Screen::EntropySummary
        | Screen::FinalIntro
        | Screen::FinalCoins
        | Screen::FinalResult => MakeSeed,
        Screen::WordsWarning { .. }
        | Screen::ShowWords { .. }
        | Screen::QuizIntro
        | Screen::Quiz { .. }
        | Screen::QuizFailed { .. }
        | Screen::SeedQrSelect { .. }
        | Screen::SeedQrWarning { .. }
        | Screen::Transcribe { .. } => Backup,
        Screen::WordEntry | Screen::ChecksumError { .. } | Screen::WordReview { .. } => TypeWords,
        Screen::SeedReady { .. }
        | Screen::SlotsFull
        | Screen::SeedOptions { .. }
        | Screen::PickSeed { .. }
        | Screen::NoSeed
        | Screen::Confirm { .. } => Seeds,
        Screen::PassphraseEntry { .. } | Screen::PassphraseReview { .. } => Passphrase,
        Screen::ScriptSelect { .. }
        | Screen::XpubView { .. }
        | Screen::XpubFormat { .. }
        | Screen::AddressList { .. }
        | Screen::AddressDetail { .. } => Addresses,
        Screen::QrShow { kind } => match kind {
            QrKind::Xpub { .. } | QrKind::MsKey { .. } => Addresses,
            QrKind::SeedQr { .. } => Backup,
            _ => QrCodes,
        },
        Screen::Scan { .. } | Screen::ScanSeed { .. } | Screen::ScanVerify { .. } | Screen::ScanResult => {
            Scanning
        }
        Screen::Review { .. } => Review,
        Screen::VerifyAddr { .. } => VerifyAddress,
        Screen::MsgSign { .. } => SignMessage,
        Screen::SigVerify { .. } => VerifySignature,
        Screen::SettingsImport { .. } => Settings,
        Screen::Wallets { .. } => Multisig,
        Screen::Sd { .. } => Sd,
        Screen::Bip85 { .. } => Bip85,
        Screen::Key { .. } => PrivateKey,
        Screen::Vault { .. } | Screen::SeedVault { .. } | Screen::Tricks { .. } | Screen::Tamper { .. } => {
            Vault
        }
        Screen::Slip39 { .. } => Slip39,
        Screen::SeedXor { .. } => SeedXor,
        Screen::Metal { .. } => Metal,
        Screen::Notes { .. } | Screen::Otp { .. } => Notes,
    })
}

/// Screens where `?` is typed text.
fn types_text(s: &Screen) -> bool {
    matches!(
        s,
        Screen::PassphraseEntry { .. }
            | Screen::MsgSign {
                step: msgsign::MsStep::Type
            }
            | Screen::SigVerify {
                step: sigverify::SvStep::Type
            }
            | Screen::Slip39 {
                step: crate::slip39ui::SlStep::Passphrase
            }
            | Screen::Notes {
                step: crate::notesui::NoteStep::Field { .. }
            }
            | Screen::Otp {
                step: crate::otpui::OtpStep::Type { .. }
            }
    )
}

impl App {
    /// The help topic of the screen shown, if help can open here.
    pub(crate) fn help_topic(&self) -> Option<Topic> {
        topic(&self.current())
    }

    /// Whether `key` opens the help on this screen.
    pub(crate) fn opens_help(&self, key: Key) -> bool {
        let s = self.current();
        let wants = match key {
            Key::F(1) => true,
            Key::Char('?') => !types_text(&s),
            _ => false,
        };
        wants && topic(&s).is_some()
    }
}
