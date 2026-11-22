//! microSD card: presence, the jobs the host runs, and the card screens.
//!
//! The app never touches the card by itself. A screen queues a job; the
//! host calls [`App::sd_service`] with its card driver, and the job runs
//! inside one power-on, mount, unmount, power-off cycle. Nothing stays
//! mounted between jobs, so the card may be pulled at any time, and what
//! was read is already in the app's own buffers (M8 plan §0, §4).

use crate::{App, Pick, Screen};
use bp_fat::{DirId, Error as FatError, FatKind, Unsupported, Volume};
use bp_hal::input::{Key, KeyEvent};
use bp_hal::{Canvas, SdCard};
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, SMALL};
use bp_ui::theme;
use bp_ui::widgets::{self, MenuItem, MARGIN, STATUS_H};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdStep {
    /// Card status: file system and size, then actions.
    Status { sel: u8 },
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

/// What a probe found on a usable card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardInfo {
    pub kind: FatKind,
    pub bytes: u64,
    pub cluster: u32,
    pub entries: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Job {
    /// Mount and describe the card.
    Probe,
}

pub struct SdState {
    pub present: bool,
    pub job: Option<Job>,
    /// Last probe result (`None` before the first one).
    pub card: Option<Result<CardInfo, CardProblem>>,
    /// Card power cycles since boot (the simulator's SD LED).
    pub cycles: u32,
}

impl SdState {
    pub const fn new() -> Self {
        SdState {
            present: false,
            job: None,
            card: None,
            cycles: 0,
        }
    }
}

/// Rows on the status screen.
const STATUS_ROWS: u8 = 1;

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
            self.sd.job = Some(Job::Probe);
        }
    }

    /// The card's contents changed outside the device (simulator: files
    /// added from the page). Screens showing the card read it again.
    pub fn card_changed(&mut self) {
        if self.on_sd_screen() {
            self.sd.job = Some(Job::Probe);
            self.dirty = true;
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
            self.sd.card = Some(Err(CardProblem::NoCard));
            return;
        }
        card.set_power(true);
        self.sd.cycles = self.sd.cycles.wrapping_add(1);
        match job {
            Job::Probe => {
                self.sd.card = Some(probe(card).map_err(CardProblem::from_fat));
            }
        }
        card.set_power(false);
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

    pub(crate) fn sd_key(&mut self, step: SdStep, ev: KeyEvent) {
        match step {
            SdStep::Status { sel } => match crate::pick(ev.key, sel, STATUS_ROWS) {
                Pick::Move(s) => self.set_current(Screen::Sd {
                    step: SdStep::Status { sel: s },
                }),
                Pick::Choose(_) => {
                    self.sd.card = None;
                    self.sd.job = Some(Job::Probe);
                }
                Pick::Back => self.pop(),
                Pick::None => {}
            },
        }
        if ev.key == Key::Esc {
            self.sd.job = None;
        }
    }

    pub(crate) fn render_sd(&self, c: &mut dyn Canvas, step: SdStep) {
        let s = self.text();
        let t = s.sd;
        self.status(c, t.menu);
        match step {
            SdStep::Status { sel } => {
                let top = STATUS_H + 24;
                match self.sd.card {
                    None => {
                        BODY.draw(c, MARGIN, top, t.reading, theme::TEXT_DIM);
                    }
                    Some(Ok(info)) => {
                        let kind = match info.kind {
                            FatKind::Fat16 => "FAT16",
                            FatKind::Fat32 => "FAT32",
                        };
                        let size = size_text(info.bytes);
                        let cluster: Buf<16> = fill("{} KB", &[&(info.cluster / 1024)]);
                        let cluster = if info.cluster < 1024 {
                            fill("{} B", &[&info.cluster])
                        } else {
                            cluster
                        };
                        let entries: Buf<16> = fill("{}", &[&info.entries]);
                        widgets::info_rows(
                            c,
                            &[
                                (t.fs, kind),
                                (t.size, size.as_str()),
                                (t.cluster, cluster.as_str()),
                                (t.entries, entries.as_str()),
                            ],
                        );
                    }
                    Some(Err(p)) => {
                        let lines = t.problems[p.index()];
                        BODY.draw(c, MARGIN, top, lines[0], theme::WARN);
                        SMALL.draw(c, MARGIN, top + 40, lines[1], theme::TEXT);
                        SMALL.draw(c, MARGIN, top + 66, lines[2], theme::TEXT);
                    }
                }
                let items = [MenuItem {
                    label: t.refresh,
                    detail: "",
                }];
                let w = c.width() as i32 - 2 * MARGIN;
                widgets::list(c, MARGIN, STATUS_H + 220, w, 56, &items, sel as usize, true);
                SMALL.draw(c, MARGIN, STATUS_H + 300, t.power_note, theme::TEXT_DIM);
                if let Some(n) = self.notice {
                    BODY.draw(c, MARGIN, STATUS_H + 336, n, theme::WARN);
                }
                widgets::hint_bar(c, &[("Enter", s.h_select), ("Esc", s.h_back)]);
            }
        }
    }
}
