//! Session log (M9-4, UX language C4): what happened since power on, shown
//! under the main menu. RAM only and wiped at power off; it never holds
//! amounts, addresses or secrets — only what kind of thing happened, when
//! (time since power on: the device has no clock) and, for seeds, the
//! fingerprint.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    SeedCreated,
    SeedLoaded,
    KeyImported,
    SeedDiscarded,
    XpubShown,
    PsbtSigned,
    MessageSigned,
    WalletRegistered,
    FileSaved,
    CardFormatted,
}

pub const EVENTS: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Seconds since power on.
    pub secs: u32,
    pub event: Event,
    pub fingerprint: Option<[u8; 4]>,
}

/// Entries kept (the newest).
pub const KEEP: usize = 4;

#[derive(Clone, Copy, Debug, Default)]
pub struct Log {
    items: [Option<Entry>; KEEP],
    next: usize,
    uptime_ms: u64,
}

impl Log {
    pub const fn new() -> Self {
        Self {
            items: [None; KEEP],
            next: 0,
            uptime_ms: 0,
        }
    }

    /// Count time since power on. A single gap over 5 s is not counted
    /// (a host's first tick, or a paused simulator tab).
    pub fn tick(&mut self, ms: u32) {
        if ms <= 5_000 {
            self.uptime_ms = self.uptime_ms.saturating_add(ms as u64);
        }
    }

    pub fn push(&mut self, event: Event, fingerprint: Option<[u8; 4]>) {
        self.items[self.next] = Some(Entry {
            secs: (self.uptime_ms / 1000) as u32,
            event,
            fingerprint,
        });
        self.next = (self.next + 1) % KEEP;
    }

    /// Newest first.
    pub fn latest(&self) -> impl Iterator<Item = Entry> + '_ {
        (1..=KEEP).filter_map(move |k| self.items[(self.next + KEEP - k) % KEEP])
    }

    pub fn is_empty(&self) -> bool {
        self.items.iter().all(|e| e.is_none())
    }

    /// Power off: forget everything.
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

/// "00:02:11"
pub fn clock(secs: u32) -> bp_ui::fmt::Buf<12> {
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    let d = |v: u32| [b'0' + (v / 10 % 10) as u8, b'0' + (v % 10) as u8];
    let mut b = bp_ui::fmt::Buf::new();
    for (i, v) in [h.min(99), m, s].into_iter().enumerate() {
        if i > 0 {
            b.push_str(":");
        }
        b.push_str(core::str::from_utf8(&d(v)).unwrap_or("00"));
    }
    b
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn keeps_the_newest_and_clears() {
        let mut l = Log::new();
        assert!(l.is_empty());
        for _ in 0..131 {
            l.tick(1000);
        }
        l.tick(60_000); // a gap: not counted
        l.push(Event::SeedLoaded, Some([0x73, 0xc5, 0xda, 0x0a]));
        for e in [
            Event::XpubShown,
            Event::PsbtSigned,
            Event::FileSaved,
            Event::CardFormatted,
        ] {
            l.tick(1000);
            l.push(e, None);
        }
        let v: std::vec::Vec<Event> = l.latest().map(|e| e.event).collect();
        assert_eq!(
            v,
            [
                Event::CardFormatted,
                Event::FileSaved,
                Event::PsbtSigned,
                Event::XpubShown
            ]
        );
        assert_eq!(l.latest().next().unwrap().secs, 135);
        l.clear();
        assert!(l.is_empty());
        assert_eq!(clock(3 * 3600 + 2 * 60 + 11).as_str(), "03:02:11");
    }
}
