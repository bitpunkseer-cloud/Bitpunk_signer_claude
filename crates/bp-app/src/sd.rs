//! microSD card: presence, the jobs the host runs, and the card screens
//! (status, file manager, text view, delete, format).
//!
//! The app never touches the card by itself. A screen queues a job; the
//! host calls [`App::sd_service`] with its card driver, and the job runs
//! inside one power-on, mount, unmount, power-off cycle. Nothing stays
//! mounted between jobs, so the card may be pulled at any time, and what
//! was read is already in the app's own buffers (M8 plan §0, §4).

use crate::{App, Pick, Screen};
use bp_fat::{DirEntry, DirId, Error as FatError, FatKind, Name, Unsupported, Volume};
use bp_hal::input::{Key, KeyEvent};
use bp_hal::{Canvas, SdCard};
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, SMALL, TITLE};
use bp_ui::theme;
use bp_ui::widgets::{self, MenuItem, MARGIN, STATUS_H};

/// Entries per listing page.
pub const PAGE: usize = 32;
/// Deepest folder opened below the root.
pub const MAX_DEPTH: usize = 4;
/// Bytes shown by the text viewer (and read to tell a file's kind).
pub const VIEW_MAX: usize = 4096;
/// Bytes read to tell a file's kind.
const SNIFF: usize = 512;
const W: i32 = 800 - 2 * MARGIN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdStep {
    /// Card status: file system and size, then actions.
    Status {
        sel: u8,
    },
    /// Folder listing (the folder is `SdState::dirs[depth]`).
    Browse {
        sel: u8,
    },
    /// One file: name, size, kind, actions.
    File {
        sel: u8,
    },
    /// The file as text, from line `top`.
    Text {
        top: u16,
    },
    Delete {
        sel: u8,
    },
    /// Two confirmations (`stage` 0 and 1) before formatting.
    Format {
        stage: u8,
        sel: u8,
    },
    Formatted,
    /// PSBT files to sign (top folder, "-signed" names left out).
    PsbtList {
        sel: u8,
    },
    /// Saving a signed PSBT or message signature: result, retry.
    Saved {
        sel: u8,
    },
}

/// Why the card cannot be used (order matches `SdStrings::problems`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardProblem {
    NoCard,
    ReadFailed,
    Blank,
    Exfat,
    Gpt,
    OtherFs,
    Damaged,
}

impl CardProblem {
    pub fn from_fat(e: FatError) -> Self {
        match e {
            FatError::Io => CardProblem::ReadFailed,
            FatError::NoFilesystem => CardProblem::Blank,
            FatError::Unsupported(Unsupported::Exfat) => CardProblem::Exfat,
            FatError::Unsupported(Unsupported::Gpt) => CardProblem::Gpt,
            FatError::Unsupported(_) => CardProblem::OtherFs,
            _ => CardProblem::Damaged,
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// What a file holds, judged from its first bytes (order matches
/// `SdStrings::kinds`). The name is never trusted for this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    Psbt,
    SignedMessage,
    Wallet,
    Settings,
    Text,
    Binary,
}

fn trim_start(b: &[u8]) -> &[u8] {
    // UTF-8 byte order mark, then white space
    let b = b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b);
    let skip = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    &b[skip..]
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Tell a file's kind from its first bytes.
pub fn sniff(head: &[u8]) -> FileKind {
    let t = trim_start(head);
    let hex = t.len() >= 10 && t[..10].eq_ignore_ascii_case(b"70736274ff");
    if head.starts_with(b"psbt\xff") || t.starts_with(b"cHNidP") || hex {
        return FileKind::Psbt;
    }
    if t.starts_with(b"-----BEGIN BITCOIN SIGNED MESSAGE-----") {
        return FileKind::SignedMessage;
    }
    if t.starts_with(crate::settings::PREFIX.as_bytes()) {
        return FileKind::Settings;
    }
    let text = head
        .iter()
        .all(|&c| c == b'\t' || c == b'\n' || c == b'\r' || c >= 0x20)
        && !head.contains(&0x7F);
    if text
        && (contains(t, b"wsh(")
            || contains(t, b"Policy:")
            || contains(t, b"\"xfp\"")
            || contains(t, b"Derivation:")
            || t.starts_with(b"# Bitpunk wallet"))
    {
        return FileKind::Wallet;
    }
    if text {
        FileKind::Text
    } else {
        FileKind::Binary
    }
}

/// What a probe found on a usable card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardInfo {
    pub kind: FatKind,
    pub bytes: u64,
    pub cluster: u32,
    pub entries: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Job {
    /// Mount and describe the card.
    Probe,
    /// List the current folder's current page.
    List,
    /// Read a file's first bytes to tell its kind.
    Sniff(DirEntry),
    /// Read a file's first `VIEW_MAX` bytes for the text viewer.
    View(DirEntry),
    Delete(DirEntry),
    Format,
    /// PSBT files in the top folder.
    ListPsbt,
    /// Read, decode and review a PSBT file.
    LoadPsbt(DirEntry),
    /// Read a message file and start signing it.
    LoadMessage(DirEntry),
    /// Save the signed PSBT next to its original.
    SavePsbt,
    /// Save the message signature next to its message file.
    SaveSig,
    /// Save what a QR screen shows as a file (xpub JSON, key JSON,
    /// wallet descriptor or Coldcard file, settings).
    SaveExport(crate::QrKind),
    /// Save a registered wallet as a Bitpunk wallet file (`.bpw`).
    SaveWalletFile(u8),
    /// Read a wallet file and import it.
    LoadWallet(DirEntry),
    /// Read a settings file and show what it would change.
    LoadSettings(DirEntry),
}

pub struct SdState {
    pub present: bool,
    pub job: Option<Job>,
    /// Last probe result (`None` before the first one).
    pub card: Option<Result<CardInfo, CardProblem>>,
    /// Card power cycles since boot (the simulator's SD LED).
    pub cycles: u32,
    /// Folder path: `dirs[0]` is the root, `dirs[depth]` the folder shown.
    pub dirs: [DirId; MAX_DEPTH + 1],
    pub names: [Name; MAX_DEPTH],
    pub depth: usize,
    /// Listing page (`PAGE` visible entries each).
    pub page: u16,
    pub list: [Option<DirEntry>; PAGE],
    pub count: usize,
    /// Visible and hidden entries in the whole folder.
    pub total: u32,
    pub hidden: u32,
    pub list_err: Option<CardProblem>,
    pub listed: bool,
    /// The file opened from the listing and its kind once read.
    pub file: Option<DirEntry>,
    pub kind: Option<FileKind>,
    /// File bytes for the viewer (wiped when it closes).
    pub view: [u8; VIEW_MAX],
    pub view_len: usize,
    pub view_err: bool,
    /// The file the review or message signing on the stack came from.
    pub origin: Option<crate::sdfile::Origin>,
    /// Result of the last save (`None` while it runs).
    pub saved: Option<Result<crate::sdfile::Saved, crate::sdfile::SaveProblem>>,
    /// The save to repeat on "Try again".
    pub last_save: Option<Job>,
}

impl SdState {
    pub const fn new() -> Self {
        SdState {
            present: false,
            job: None,
            card: None,
            cycles: 0,
            dirs: [DirId::Root; MAX_DEPTH + 1],
            names: [Name::empty(); MAX_DEPTH],
            depth: 0,
            page: 0,
            list: [None; PAGE],
            count: 0,
            total: 0,
            hidden: 0,
            list_err: None,
            listed: false,
            file: None,
            kind: None,
            view: [0; VIEW_MAX],
            view_len: 0,
            view_err: false,
            origin: None,
            saved: None,
            last_save: None,
        }
    }

    fn wipe_view(&mut self) {
        bp_crypto::secret::wipe(&mut self.view);
        self.view_len = 0;
        self.view_err = false;
    }

    fn clear_list(&mut self) {
        self.list = [None; PAGE];
        self.count = 0;
        self.listed = false;
        self.list_err = None;
    }
}

/// Rows on the status screen: sign PSBT, browse, format, read again.
const STATUS_ROWS: u8 = 4;

/// File screen actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileAction {
    Sign,
    SignMessage,
    ImportWallet,
    ImportSettings,
    View,
    Delete,
}

/// Actions offered for a file of this kind.
pub(crate) fn file_actions(kind: Option<FileKind>) -> &'static [FileAction] {
    match kind {
        Some(FileKind::Psbt) => &[FileAction::Sign, FileAction::View, FileAction::Delete],
        Some(FileKind::Text) => &[FileAction::SignMessage, FileAction::View, FileAction::Delete],
        Some(FileKind::Wallet) => &[FileAction::ImportWallet, FileAction::View, FileAction::Delete],
        Some(FileKind::Settings) => &[FileAction::ImportSettings, FileAction::View, FileAction::Delete],
        _ => &[FileAction::View, FileAction::Delete],
    }
}

/// "29.7 GB" / "31.9 MB" (decimal units, as cards are sold).
pub fn size_text(bytes: u64) -> Buf<16> {
    let (unit, div) = if bytes >= 1_000_000_000 {
        ("GB", 1_000_000_000)
    } else {
        ("MB", 1_000_000)
    };
    let tenths = bytes * 10 / div;
    fill("{}.{} {}", &[&(tenths / 10), &(tenths % 10), &unit])
}

/// File size: "980 B", "12.3 KB", "1.4 MB".
pub fn file_size(n: u32) -> Buf<16> {
    let n = n as u64;
    if n < 1024 {
        fill("{} B", &[&n])
    } else if n < 1024 * 1024 {
        let t = n * 10 / 1024;
        fill("{}.{} KB", &[&(t / 10), &(t % 10)])
    } else {
        let t = n * 10 / (1024 * 1024);
        fill("{}.{} MB", &[&(t / 10), &(t % 10)])
    }
}

/// `name` shortened to `max` columns, keeping its end (the extension).
pub fn fit_name(name: &str, max: usize) -> Buf<96> {
    let mut out: Buf<96> = Buf::new();
    let max = max.clamp(12, 95);
    if name.len() <= max {
        out.push_str(name);
    } else {
        let tail = 8;
        out.push_str(&name[..max - tail - 3]);
        out.push_str("...");
        out.push_str(&name[name.len() - tail..]);
    }
    out
}

fn probe(card: &mut dyn SdCard) -> Result<CardInfo, FatError> {
    let mut v = Volume::mount(card)?;
    let g = *v.geometry();
    let mut it = v.iter(DirId::Root);
    let mut entries = 0;
    while v.next_entry(&mut it)?.is_some() {
        entries += 1;
    }
    Ok(CardInfo {
        kind: g.kind,
        bytes: g.total_bytes(),
        cluster: g.cluster_bytes(),
        entries,
    })
}

impl App {
    /// Card-detect changed (insert or removal).
    pub fn set_card_present(&mut self, present: bool) {
        if self.sd.present == present {
            return;
        }
        self.sd.present = present;
        self.dirty = true;
        if self.on_sd_screen() {
            if !present {
                self.notice = Some(self.text().sd.removed);
            }
            self.card_changed();
        }
    }

    /// The card changed (inserted, removed, or written outside the device:
    /// simulator files added from the page). Screens showing the card read
    /// it again; a file screen goes back to its folder.
    pub fn card_changed(&mut self) {
        let Screen::Sd { step } = self.current() else {
            return;
        };
        self.dirty = true;
        match step {
            SdStep::Status { .. } | SdStep::Formatted | SdStep::Format { .. } => {
                self.sd.card = None;
                self.sd.job = Some(Job::Probe);
            }
            SdStep::Browse { .. } => self.sd.job = Some(Job::List),
            SdStep::PsbtList { .. } => self.sd.job = Some(Job::ListPsbt),
            // the result stays on screen; the folder is read when it closes
            SdStep::Saved { .. } => {}
            SdStep::File { .. } | SdStep::Text { .. } | SdStep::Delete { .. } => {
                // the entry may no longer be what it was
                while matches!(self.current(), Screen::Sd { step } if !matches!(step, SdStep::Browse { .. } | SdStep::Status { .. } | SdStep::PsbtList { .. }))
                {
                    self.pop();
                }
                self.sd.file = None;
                self.sd.wipe_view();
                self.sd.job = Some(match self.current() {
                    Screen::Sd {
                        step: SdStep::Browse { .. },
                    } => Job::List,
                    Screen::Sd {
                        step: SdStep::PsbtList { .. },
                    } => Job::ListPsbt,
                    _ => Job::Probe,
                });
            }
        }
    }

    pub fn card_present(&self) -> bool {
        self.sd.present
    }

    /// Card power cycles since boot.
    pub fn card_cycles(&self) -> u32 {
        self.sd.cycles
    }

    /// True when a card job waits for [`App::sd_service`].
    pub fn sd_pending(&self) -> bool {
        self.sd.job.is_some()
    }

    /// Run the queued card job with the host's driver: power on, work,
    /// power off. Call after every key event and tick while
    /// [`App::sd_pending`] is true.
    pub fn sd_service(&mut self, card: &mut dyn SdCard) {
        let Some(job) = self.sd.job.take() else { return };
        self.dirty = true;
        self.sd.present = card.present();
        if !self.sd.present {
            self.card_failed(job, CardProblem::NoCard);
            return;
        }
        card.set_power(true);
        self.sd.cycles = self.sd.cycles.wrapping_add(1);
        self.run_job(job, card);
        card.set_power(false);
    }

    fn card_failed(&mut self, job: Job, p: CardProblem) {
        match job {
            Job::Probe | Job::Format => self.sd.card = Some(Err(p)),
            Job::List | Job::Delete(_) => {
                self.sd.clear_list();
                self.sd.list_err = Some(p);
                self.sd.listed = true;
            }
            Job::ListPsbt => {
                self.sd.clear_list();
                self.sd.list_err = Some(p);
                self.sd.listed = true;
            }
            Job::Sniff(_) | Job::View(_) => self.sd.view_err = true,
            Job::LoadPsbt(_) | Job::LoadMessage(_) => {
                self.notice = Some(self.text().sd.problems[p.index()][0])
            }
            Job::SavePsbt | Job::SaveSig | Job::SaveExport(_) | Job::SaveWalletFile(_) => {
                self.sd.saved = Some(Err(crate::sdfile::SaveProblem::NoCard))
            }
            Job::LoadWallet(_) | Job::LoadSettings(_) => {
                self.notice = Some(self.text().sd.problems[p.index()][0])
            }
        }
    }

    fn run_job(&mut self, job: Job, card: &mut dyn SdCard) {
        match job {
            Job::Probe => self.sd.card = Some(probe(card).map_err(CardProblem::from_fat)),
            Job::List => self.list_job(card),
            Job::ListPsbt => self.list_psbt_job(card),
            Job::LoadPsbt(e) => self.load_psbt_job(card, e),
            Job::LoadMessage(e) => self.load_message_job(card, e),
            Job::SavePsbt | Job::SaveSig => self.save_job(card, job),
            Job::SaveExport(_) | Job::SaveWalletFile(_) => self.save_export_job(card, job),
            Job::LoadWallet(e) => self.load_wallet_job(card, e),
            Job::LoadSettings(e) => self.load_settings_job(card, e),
            Job::Sniff(e) | Job::View(e) => {
                let n = if matches!(job, Job::Sniff(_)) {
                    SNIFF
                } else {
                    VIEW_MAX
                };
                self.sd.wipe_view();
                let r = Volume::mount(&mut *card).and_then(|mut v| v.read_at(&e, 0, &mut self.sd.view[..n]));
                match r {
                    Ok(len) => {
                        self.sd.view_len = len;
                        if matches!(job, Job::Sniff(_)) {
                            self.sd.kind = Some(sniff(&self.sd.view[..len]));
                            self.sd.wipe_view();
                        }
                    }
                    Err(_) => self.sd.view_err = true,
                }
            }
            Job::Delete(e) => {
                let r = Volume::mount(&mut *card).and_then(|mut v| v.delete(&e));
                self.notice = Some(match r {
                    Ok(()) => self.text().sd.deleted,
                    Err(_) => self.text().sd.delete_failed,
                });
                self.list_job(card);
            }
            Job::Format => {
                let rng = &mut self.quiz_rng;
                let r = bp_fat::format(&mut *card, &mut |b: &mut [u8]| rng.fill(b));
                self.sd.card = Some(match r {
                    Ok(_) => probe(card).map_err(CardProblem::from_fat),
                    Err(e) => Err(CardProblem::from_fat(e)),
                });
                self.sd.depth = 0;
                self.sd.clear_list();
            }
        }
    }

    /// Fill the current page of the current folder (hidden entries are
    /// counted, not listed).
    fn list_job(&mut self, card: &mut dyn SdCard) {
        let sd = &mut self.sd;
        sd.clear_list();
        sd.total = 0;
        sd.hidden = 0;
        let skip = sd.page as u32 * PAGE as u32;
        let r = Volume::mount(&mut *card).and_then(|mut v| {
            let mut it = v.iter(sd.dirs[sd.depth]);
            while let Some(e) = v.next_entry(&mut it)? {
                if e.is_hidden() {
                    sd.hidden += 1;
                    continue;
                }
                if sd.total >= skip && sd.count < PAGE {
                    sd.list[sd.count] = Some(e);
                    sd.count += 1;
                }
                sd.total += 1;
            }
            Ok(())
        });
        sd.listed = true;
        if let Err(e) = r {
            sd.list = [None; PAGE];
            sd.count = 0;
            sd.list_err = Some(CardProblem::from_fat(e));
        }
        // a page that emptied (files deleted) falls back to the last one
        if sd.count == 0 && sd.page > 0 && sd.list_err.is_none() {
            sd.page = ((sd.total.max(1) - 1) / PAGE as u32) as u16;
            sd.job = Some(Job::List);
        }
    }

    fn on_sd_screen(&self) -> bool {
        self.stack[..self.depth]
            .iter()
            .any(|s| matches!(s, Screen::Sd { .. }))
    }

    /// Main > SD card.
    pub(crate) fn open_sd(&mut self) {
        self.sd.card = None;
        self.sd.job = Some(Job::Probe);
        self.push(Screen::Sd {
            step: SdStep::Status { sel: 0 },
        });
    }

    fn sd_set(&mut self, step: SdStep) {
        self.set_current(Screen::Sd { step });
    }

    fn open_browse(&mut self) {
        self.sd.depth = 0;
        self.sd.page = 0;
        self.sd.clear_list();
        self.sd.job = Some(Job::List);
        self.push(Screen::Sd {
            step: SdStep::Browse { sel: 0 },
        });
    }

    pub(crate) fn sd_key(&mut self, step: SdStep, ev: KeyEvent) {
        let t = self.text().sd;
        match step {
            SdStep::Status { sel } => match crate::pick(ev.key, sel, STATUS_ROWS) {
                Pick::Move(s) => self.sd_set(SdStep::Status { sel: s }),
                Pick::Choose(s) => {
                    self.sd_set(SdStep::Status { sel: s });
                    let ready = matches!(self.sd.card, Some(Ok(_)));
                    match s {
                        0 if ready => {
                            self.sd.clear_list();
                            self.sd.job = Some(Job::ListPsbt);
                            self.push(Screen::Sd {
                                step: SdStep::PsbtList { sel: 0 },
                            });
                        }
                        1 if ready => self.open_browse(),
                        0 | 1 => self.notice = Some(t.not_ready),
                        2 if self.sd.present => self.push(Screen::Sd {
                            step: SdStep::Format { stage: 0, sel: 0 },
                        }),
                        2 => self.notice = Some(t.problems[0][0]),
                        _ => {
                            self.sd.card = None;
                            self.sd.job = Some(Job::Probe);
                        }
                    }
                }
                Pick::Back => {
                    self.sd.job = None;
                    self.pop();
                }
                Pick::None => {}
            },
            SdStep::Browse { sel } => self.browse_key(sel, ev),
            SdStep::File { sel } => match crate::pick(ev.key, sel, file_actions(self.sd.kind).len() as u8) {
                Pick::Move(s) => self.sd_set(SdStep::File { sel: s }),
                Pick::Choose(s) => {
                    let Some(e) = self.sd.file else { return };
                    self.sd_set(SdStep::File { sel: s });
                    match file_actions(self.sd.kind)[s as usize] {
                        FileAction::Sign => self.sd.job = Some(Job::LoadPsbt(e)),
                        FileAction::SignMessage => self.sd.job = Some(Job::LoadMessage(e)),
                        FileAction::ImportWallet => self.sd.job = Some(Job::LoadWallet(e)),
                        FileAction::ImportSettings => self.sd.job = Some(Job::LoadSettings(e)),
                        FileAction::View => {
                            self.sd.job = Some(Job::View(e));
                            self.push(Screen::Sd {
                                step: SdStep::Text { top: 0 },
                            });
                        }
                        FileAction::Delete => self.push(Screen::Sd {
                            step: SdStep::Delete { sel: 0 },
                        }),
                    }
                }
                Pick::Back => {
                    self.sd.file = None;
                    self.sd.kind = None;
                    self.pop();
                }
                Pick::None => {}
            },
            SdStep::Text { top } => match ev.key {
                Key::Up => self.sd_set(SdStep::Text {
                    top: top.saturating_sub(1),
                }),
                Key::Down => {
                    let max = self.text_lines().saturating_sub(TEXT_ROWS) as u16;
                    self.sd_set(SdStep::Text {
                        top: (top + 1).min(max),
                    });
                }
                Key::Esc | Key::Backspace | Key::Left | Key::Enter => {
                    self.sd.wipe_view();
                    self.pop();
                }
                _ => {}
            },
            SdStep::Delete { sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.sd_set(SdStep::Delete { sel: s }),
                Pick::Choose(1) => {
                    if let Some(e) = self.sd.file.take() {
                        self.sd.job = Some(Job::Delete(e));
                    }
                    self.sd.kind = None;
                    self.pop(); // the delete question
                    self.pop(); // the file screen
                }
                Pick::Choose(_) | Pick::Back => self.pop(),
                Pick::None => {}
            },
            // the last question: type FORMAT (cannot be undone)
            SdStep::Format { stage: 1, .. } => match self.typed.key(ev.key, crate::typed::FORMAT) {
                crate::typed::Typed::Confirmed => {
                    self.sd.card = None;
                    self.sd.job = Some(Job::Format);
                    self.sd_set(SdStep::Formatted);
                }
                crate::typed::Typed::Cancelled => self.pop(),
                crate::typed::Typed::Pending => {}
            },
            SdStep::Format { stage, sel } => match crate::pick(ev.key, sel, 2) {
                Pick::Move(s) => self.sd_set(SdStep::Format { stage, sel: s }),
                Pick::Choose(1) => {
                    self.typed.clear();
                    self.sd_set(SdStep::Format { stage: 1, sel: 0 })
                }
                Pick::Choose(_) | Pick::Back => self.pop(),
                Pick::None => {}
            },
            SdStep::Formatted => {
                if matches!(ev.key, Key::Enter | Key::Esc | Key::Backspace) {
                    self.pop();
                }
            }
            SdStep::PsbtList { sel } => {
                let n = self.sd.count as u8;
                match ev.key {
                    Key::Esc | Key::Backspace | Key::Left => {
                        self.sd.clear_list();
                        self.pop();
                    }
                    _ if n == 0 => {}
                    _ => match crate::pick(ev.key, sel, n) {
                        Pick::Move(s) => self.sd_set(SdStep::PsbtList { sel: s }),
                        Pick::Choose(s) => {
                            self.sd_set(SdStep::PsbtList { sel: s });
                            if let Some(e) = self.sd.list[s as usize] {
                                self.sd.job = Some(Job::LoadPsbt(e));
                            }
                        }
                        _ => {}
                    },
                }
            }
            SdStep::Saved { sel } => match self.sd.saved {
                None => {}
                Some(Ok(_)) => {
                    if matches!(ev.key, Key::Enter | Key::Esc | Key::Backspace) {
                        self.finish_save();
                    }
                }
                Some(Err(_)) => match crate::pick(ev.key, sel, 2) {
                    Pick::Move(s) => self.sd_set(SdStep::Saved { sel: s }),
                    Pick::Choose(0) => {
                        self.sd.saved = None;
                        self.sd.job = self.sd.last_save;
                    }
                    Pick::Choose(_) | Pick::Back => {
                        self.sd.saved = None;
                        self.pop();
                    }
                    Pick::None => {}
                },
            },
        }
    }

    fn browse_key(&mut self, sel: u8, ev: KeyEvent) {
        let sd = &self.sd;
        let pages = sd.total.div_ceil(PAGE as u32).max(1) as u16;
        let up = matches!(ev.key, Key::Esc | Key::Backspace | Key::Left);
        if up {
            if self.sd.depth > 0 {
                self.sd.depth -= 1;
                self.sd.page = 0;
                self.sd.clear_list();
                self.sd.job = Some(Job::List);
                self.sd_set(SdStep::Browse { sel: 0 });
            } else {
                self.sd.clear_list();
                self.pop();
            }
            return;
        }
        if sd.count == 0 {
            return;
        }
        let n = sd.count as u8;
        match ev.key {
            Key::Up if sel == 0 && sd.page > 0 => {
                self.sd.page -= 1;
                self.sd.job = Some(Job::List);
                self.sd_set(SdStep::Browse { sel: PAGE as u8 - 1 });
            }
            Key::Down if sel + 1 == n && sd.page + 1 < pages => {
                self.sd.page += 1;
                self.sd.job = Some(Job::List);
                self.sd_set(SdStep::Browse { sel: 0 });
            }
            Key::Up => self.sd_set(SdStep::Browse {
                sel: sel.saturating_sub(1),
            }),
            Key::Down => self.sd_set(SdStep::Browse {
                sel: (sel + 1).min(n - 1),
            }),
            Key::Enter | Key::Right => {
                let Some(e) = self.sd.list[sel as usize] else {
                    return;
                };
                if e.is_dir() {
                    if self.sd.depth >= MAX_DEPTH {
                        self.notice = Some(self.text().sd.too_deep);
                        return;
                    }
                    match bp_fat::DirId::Cluster(e.cluster()) {
                        d if e.cluster() >= 2 => {
                            self.sd.names[self.sd.depth] =
                                Name::from_ascii(e.name()).unwrap_or(Name::empty());
                            self.sd.depth += 1;
                            self.sd.dirs[self.sd.depth] = d;
                            self.sd.page = 0;
                            self.sd.clear_list();
                            self.sd.job = Some(Job::List);
                            self.sd_set(SdStep::Browse { sel: 0 });
                        }
                        _ => self.notice = Some(self.text().sd.problems[CardProblem::Damaged.index()][0]),
                    }
                } else {
                    self.sd.file = Some(e);
                    self.sd.kind = None;
                    self.sd.view_err = false;
                    self.sd.job = Some(Job::Sniff(e));
                    self.push(Screen::Sd {
                        step: SdStep::File { sel: 0 },
                    });
                }
            }
            _ => {}
        }
    }

    /// Lines the text viewer shows for the file read.
    fn text_lines(&self) -> usize {
        let text = core::str::from_utf8(&self.sd.view[..self.sd.view_len]).unwrap_or("");
        let mut rest = text;
        let mut n = 0;
        while !rest.is_empty() && n < 10_000 {
            let (_, tail) = bp_ui::font::split_line(rest, TEXT_COLS);
            rest = tail;
            n += 1;
        }
        n
    }

    pub(crate) fn render_sd(&self, c: &mut dyn Canvas, step: SdStep) {
        let s = self.text();
        let t = s.sd;
        match step {
            SdStep::Status { sel } => self.render_sd_status(c, sel),
            SdStep::PsbtList { sel } => self.render_psbt_list(c, sel),
            SdStep::Saved { sel } => self.render_saved(c, sel),
            SdStep::Browse { sel } => self.render_browse(c, sel),
            SdStep::File { sel } => self.render_file(c, sel),
            SdStep::Text { top } => self.render_text(c, top),
            SdStep::Delete { sel } => {
                self.status(c, t.delete);
                let name = self.sd.file.map(|e| fit_name(e.name(), 60)).unwrap_or_default();
                TITLE.draw(c, MARGIN, STATUS_H + 24, t.delete_q, theme::TEXT);
                BODY.draw(c, MARGIN, STATUS_H + 80, name.as_str(), theme::ACCENT);
                SMALL.draw(c, MARGIN, STATUS_H + 124, t.delete_note, theme::TEXT_DIM);
                let items = [
                    MenuItem {
                        label: t.cancel,
                        detail: "",
                    },
                    MenuItem {
                        label: t.delete,
                        detail: "",
                    },
                ];
                widgets::list(c, MARGIN, STATUS_H + 180, W, 120, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            SdStep::Format { stage, sel } => {
                self.status(c, t.format);
                if stage == 0 {
                    TITLE.draw(c, MARGIN, STATUS_H + 24, t.format_warn[0], theme::WARN);
                    BODY.draw(c, MARGIN, STATUS_H + 80, t.format_warn[1], theme::TEXT);
                    BODY.draw(c, MARGIN, STATUS_H + 116, t.format_warn[2], theme::TEXT);
                } else {
                    let y = widgets::message_at(
                        c,
                        STATUS_H + 40,
                        t.format_final[0],
                        theme::DANGER,
                        &[t.format_final[1]],
                    );
                    let prompt: Buf<96> = fill(s.typed_prompt, &[&crate::typed::FORMAT]);
                    let wrong = self.typed.wrong.then_some(s.typed_wrong);
                    widgets::typed_field(c, y + 40, prompt.as_str(), self.typed.text(), wrong);
                    widgets::hint_bar(c, &[("A-Z", s.h_type), ("Enter", t.format_go), ("Esc", t.cancel)]);
                    return;
                }
                let go = if stage == 0 { t.proceed } else { t.format_go };
                let items = [
                    MenuItem {
                        label: t.cancel,
                        detail: "",
                    },
                    MenuItem {
                        label: go,
                        detail: "",
                    },
                ];
                widgets::list(c, MARGIN, STATUS_H + 180, W, 120, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            SdStep::Formatted => {
                self.status(c, t.format);
                match self.sd.card {
                    Some(Ok(info)) => {
                        TITLE.draw(c, MARGIN, STATUS_H + 24, t.formatted, theme::OK);
                        let kind = kind_name(info.kind);
                        let size = size_text(info.bytes);
                        let line: Buf<48> = fill("{} - {}", &[&kind, &size.as_str()]);
                        BODY.draw(c, MARGIN, STATUS_H + 80, line.as_str(), theme::TEXT);
                    }
                    Some(Err(p)) => {
                        TITLE.draw(c, MARGIN, STATUS_H + 24, t.format_failed, theme::DANGER);
                        BODY.draw(c, MARGIN, STATUS_H + 80, t.problems[p.index()][0], theme::TEXT);
                        self.show_error(crate::errors::Area::Card, p.index());
                    }
                    None => {
                        BODY.draw(c, MARGIN, STATUS_H + 24, t.reading, theme::TEXT_DIM);
                    }
                }
                widgets::hint_bar(c, &[("Enter", s.h_back)]);
            }
        }
    }

    fn render_sd_status(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        let t = s.sd;
        self.status(c, t.menu);
        let top = STATUS_H + 16;
        match self.sd.card {
            None => {
                BODY.draw(c, MARGIN, top, t.reading, theme::TEXT_DIM);
            }
            Some(Ok(info)) => {
                let size = size_text(info.bytes);
                let line: Buf<48> = fill("{} - {}", &[&kind_name(info.kind), &size.as_str()]);
                BODY.draw(c, MARGIN, top, line.as_str(), theme::TEXT);
                let cluster: Buf<16> = if info.cluster < 1024 {
                    fill("{} B", &[&info.cluster])
                } else {
                    fill("{} KB", &[&(info.cluster / 1024)])
                };
                let detail: Buf<80> = fill(t.detail_line, &[&cluster.as_str(), &info.entries]);
                SMALL.draw(c, MARGIN, top + 36, detail.as_str(), theme::TEXT_DIM);
            }
            Some(Err(p)) => {
                let lines = t.problems[p.index()];
                self.show_error(crate::errors::Area::Card, p.index());
                BODY.draw(c, MARGIN, top, lines[0], theme::WARN);
                SMALL.draw(c, MARGIN, top + 32, lines[1], theme::TEXT);
                SMALL.draw(c, MARGIN, top + 54, lines[2], theme::TEXT);
            }
        }
        // (below the problem's three lines: they overlapped before M9)
        SMALL.draw(c, MARGIN, STATUS_H + 96, t.power_note, theme::TEXT_DIM);
        let items = [
            MenuItem {
                label: t.sign_psbt,
                detail: ">",
            },
            MenuItem {
                label: t.browse,
                detail: ">",
            },
            MenuItem {
                label: t.format,
                detail: ">",
            },
            MenuItem {
                label: t.refresh,
                detail: "",
            },
        ];
        widgets::list(c, MARGIN, STATUS_H + 124, W, 4 * 52, &items, sel as usize, false);
        if let Some(n) = self.notice {
            BODY.draw(c, MARGIN, STATUS_H + 340, n, theme::WARN);
        }
        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
    }

    fn render_psbt_list(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        let t = s.sd;
        let sd = &self.sd;
        self.status(c, t.sign_psbt);
        let top = STATUS_H + 8;
        if !sd.listed {
            BODY.draw(c, MARGIN, top + 12, t.reading, theme::TEXT_DIM);
        } else if let Some(p) = sd.list_err {
            BODY.draw(c, MARGIN, top + 12, t.problems[p.index()][0], theme::WARN);
            SMALL.draw(c, MARGIN, top + 52, t.problems[p.index()][1], theme::TEXT);
            self.show_error(crate::errors::Area::Card, p.index());
        } else if sd.count == 0 {
            BODY.draw(c, MARGIN, top + 12, t.psbt_none[0], theme::TEXT_DIM);
            SMALL.draw(c, MARGIN, top + 52, t.psbt_none[1], theme::TEXT_DIM);
        } else {
            let mut names: [Buf<96>; PAGE] = [const { Buf::new() }; PAGE];
            let mut sizes: [Buf<16>; PAGE] = [const { Buf::new() }; PAGE];
            for (i, e) in sd.list[..sd.count].iter().enumerate() {
                if let Some(e) = e {
                    names[i] = fit_name(e.name(), 46);
                    sizes[i] = file_size(e.size());
                }
            }
            let items: [MenuItem; PAGE] = core::array::from_fn(|i| MenuItem {
                label: names[i].as_str(),
                detail: sizes[i].as_str(),
            });
            widgets::list(c, MARGIN, top, W, 364, &items[..sd.count], sel as usize, true);
        }
        if let Some(n) = self.notice {
            SMALL.draw(c, MARGIN, 480 - widgets::HINT_H - 24, n, theme::WARN);
        }
        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", t.sign), ("Esc", s.h_back)]);
    }

    fn render_saved(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        let t = s.sd;
        self.status(c, t.save_sd);
        match self.sd.saved {
            None => {
                BODY.draw(c, MARGIN, STATUS_H + 24, t.saving, theme::TEXT_DIM);
            }
            Some(Ok(saved)) => {
                TITLE.draw(c, MARGIN, STATUS_H + 24, t.saved, theme::OK);
                let name = fit_name(saved.name.as_str(), 60);
                let line: Buf<128> = fill(t.saved_as, &[&name.as_str()]);
                BODY.draw(c, MARGIN, STATUS_H + 84, line.as_str(), theme::TEXT);
                let mut y = STATUS_H + 130;
                if saved.wiped {
                    SMALL.draw(c, MARGIN, y, t.wiped_original, theme::WARN);
                    y += 30;
                }
                BODY.draw(c, MARGIN, y, t.remove_ok, theme::TEXT_DIM);
                widgets::hint_bar(c, &[("Enter", t.done)]);
            }
            Some(Err(p)) => {
                TITLE.draw(c, MARGIN, STATUS_H + 24, t.save_failed, theme::DANGER);
                BODY.draw(c, MARGIN, STATUS_H + 84, t.save_problems[p as usize], theme::TEXT);
                self.show_error(crate::errors::Area::Save, p as usize);
                let items = [
                    MenuItem {
                        label: t.retry,
                        detail: "",
                    },
                    MenuItem {
                        label: t.cancel,
                        detail: "",
                    },
                ];
                widgets::list(c, MARGIN, STATUS_H + 150, W, 120, &items, sel as usize, false);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
        }
    }

    fn render_browse(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        let t = s.sd;
        let sd = &self.sd;
        // "SD card / Sub Dir / deeper", shortened to fit
        let mut path: Buf<96> = Buf::new();
        path.push_str(t.menu);
        for name in &sd.names[..sd.depth] {
            path.push_str(" / ");
            path.push_str(name.as_str());
        }
        let title = fit_name(path.as_str(), 40);
        self.status(c, title.as_str());
        let top = STATUS_H + 8;
        if !sd.listed {
            BODY.draw(c, MARGIN, top + 12, t.reading, theme::TEXT_DIM);
        } else if let Some(p) = sd.list_err {
            BODY.draw(c, MARGIN, top + 12, t.problems[p.index()][0], theme::WARN);
            SMALL.draw(c, MARGIN, top + 52, t.problems[p.index()][1], theme::TEXT);
            SMALL.draw(c, MARGIN, top + 78, t.problems[p.index()][2], theme::TEXT);
            self.show_error(crate::errors::Area::Card, p.index());
        } else if sd.count == 0 {
            BODY.draw(c, MARGIN, top + 12, t.empty_dir, theme::TEXT_DIM);
        } else {
            let mut names: [Buf<96>; PAGE] = [const { Buf::new() }; PAGE];
            let mut sizes: [Buf<16>; PAGE] = [const { Buf::new() }; PAGE];
            for (i, e) in sd.list[..sd.count].iter().enumerate() {
                let Some(e) = e else { continue };
                names[i] = fit_name(e.name(), 46);
                sizes[i] = if e.is_dir() {
                    fill(">", &[])
                } else {
                    file_size(e.size())
                };
            }
            let items: [MenuItem; PAGE] = core::array::from_fn(|i| MenuItem {
                label: names[i].as_str(),
                detail: sizes[i].as_str(),
            });
            widgets::list(c, MARGIN, top, W, 364, &items[..sd.count], sel as usize, true);
        }
        // "33-64 of 120 · 3 hidden"
        let first = sd.page as u32 * PAGE as u32;
        let mut foot: Buf<64> = Buf::new();
        if sd.count > 0 {
            let range: Buf<32> = fill(t.range, &[&(first + 1), &(first + sd.count as u32), &sd.total]);
            foot.push_str(range.as_str());
        }
        if sd.hidden > 0 {
            if !foot.as_str().is_empty() {
                foot.push_str("  ");
            }
            let h: Buf<24> = fill(t.hidden, &[&sd.hidden]);
            foot.push_str(h.as_str());
        }
        let y = 480 - widgets::HINT_H - 24;
        if let Some(n) = self.notice {
            SMALL.draw(c, MARGIN, y, n, theme::WARN);
        } else {
            SMALL.draw(c, MARGIN, y, foot.as_str(), theme::TEXT_DIM);
        }
        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
    }

    fn render_file(&self, c: &mut dyn Canvas, sel: u8) {
        let s = self.text();
        let t = s.sd;
        self.status(c, t.browse);
        let Some(e) = self.sd.file else { return };
        let name = fit_name(e.name(), 46);
        let size = file_size(e.size());
        let kind = match (self.sd.kind, self.sd.view_err) {
            (Some(k), _) => t.kinds[k as usize],
            (None, true) => t.problems[CardProblem::ReadFailed.index()][0],
            (None, false) => t.reading,
        };
        widgets::info_rows(
            c,
            &[
                (t.name, name.as_str()),
                (t.size_label, size.as_str()),
                (t.kind_label, kind),
            ],
        );
        let actions = file_actions(self.sd.kind);
        let mut items = [
            MenuItem {
                label: "",
                detail: ">",
            },
            MenuItem {
                label: "",
                detail: ">",
            },
            MenuItem {
                label: "",
                detail: ">",
            },
        ];
        for (item, a) in items.iter_mut().zip(actions) {
            item.label = match a {
                FileAction::Sign => t.sign,
                FileAction::SignMessage => t.sign_message,
                FileAction::ImportWallet => t.import_wallet,
                FileAction::ImportSettings => t.import_settings,
                FileAction::View => t.view_text,
                FileAction::Delete => t.delete,
            };
        }
        widgets::list(
            c,
            MARGIN,
            STATUS_H + 176,
            W,
            3 * 52,
            &items[..actions.len()],
            sel as usize,
            false,
        );
        if let Some(n) = self.notice {
            SMALL.draw(c, MARGIN, STATUS_H + 344, n, theme::WARN);
        }
        widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
    }

    fn render_text(&self, c: &mut dyn Canvas, top: u16) {
        let s = self.text();
        let t = s.sd;
        let title = self.sd.file.map(|e| fit_name(e.name(), 40)).unwrap_or_default();
        self.status(c, title.as_str());
        if self.sd.view_err {
            BODY.draw(
                c,
                MARGIN,
                STATUS_H + 24,
                t.problems[CardProblem::ReadFailed.index()][0],
                theme::WARN,
            );
        } else {
            // printable ASCII only; anything else shows as '?'
            let mut shown = [0u8; VIEW_MAX];
            let n = self.sd.view_len;
            for (o, &b) in shown.iter_mut().zip(&self.sd.view[..n]) {
                *o = match b {
                    b'\n' => b'\n',
                    b'\t' => b' ',
                    0x20..=0x7E => b,
                    _ => b'?',
                };
            }
            let text = core::str::from_utf8(&shown[..n]).unwrap_or("");
            let mut rest = text;
            let mut line = 0usize;
            let mut y = STATUS_H + 14;
            while !rest.is_empty() && line < top as usize + TEXT_ROWS {
                let (l, tail) = bp_ui::font::split_line(rest, TEXT_COLS);
                if line >= top as usize {
                    SMALL.draw(c, MARGIN, y, l, theme::TEXT);
                    y += TEXT_LINE_H;
                }
                rest = tail;
                line += 1;
            }
            let file_size = self.sd.file.map_or(0, |e| e.size() as usize);
            if file_size > VIEW_MAX {
                SMALL.draw(
                    c,
                    MARGIN,
                    480 - widgets::HINT_H - 24,
                    t.truncated,
                    theme::TEXT_DIM,
                );
            }
        }
        widgets::hint_bar(c, &[("^v", t.h_scroll), ("Esc", s.h_back)]);
    }
}

/// Text viewer geometry (SMALL font).
const TEXT_COLS: usize = 70;
const TEXT_ROWS: usize = 15;
const TEXT_LINE_H: i32 = 24;

fn kind_name(k: FatKind) -> &'static str {
    match k {
        FatKind::Fat16 => "FAT16",
        FatKind::Fat32 => "FAT32",
    }
}
