//! QR display session shared by every QR screen: payload, format, density,
//! speed, brightness, inversion, full screen and pause. The current frame is
//! computed on demand, so rendering never mutates state.

use bp_qr::bbqr::{specter, Bbqr, FileType};
use bp_qr::qr::{capacity, Ecc, Mode, QrCode};
use bp_qr::ur::{max_fragment_len_for_chars, UrEncoder};

/// Largest payload: a signed PSBT as base64 (Specter) or BBQr characters.
pub const PAYLOAD_MAX: usize = 12 * 1024;
pub const TEXT_MAX: usize = 2400;

/// Side of the square the QR screen gives the symbol (800x480 minus the
/// status bar and a small margin). Full screen uses the whole 480.
pub const QR_BOX_PX: i32 = 480 - 44 - 8;

/// Auto stays at Low density until Low would need more frames than this.
const AUTO_MAX_LOW_FRAMES: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Density {
    Auto,
    Low,
    Medium,
    High,
}

impl Density {
    const ALL: [Density; 4] = [Density::Auto, Density::Low, Density::Medium, Density::High];

    pub fn step(self, dir: i8) -> Density {
        let i = Self::ALL.iter().position(|d| *d == self).unwrap_or(0) as i32;
        Self::ALL[(i + dir as i32).clamp(0, 3) as usize]
    }

    /// Smallest module size, in screen pixels, a frame may use. The scan
    /// bench (docs/QR_SCAN_BENCH.md) shows module size decides
    /// whether a phone reads the code: Low keeps 8 px modules.
    pub fn module_px(self) -> i32 {
        match self {
            Density::Auto | Density::Low => 8,
            Density::Medium => 6,
            Density::High => 5,
        }
    }

    /// Largest QR version whose modules stay at least `module_px` in the
    /// QR box (4-module quiet zone on each side).
    pub fn max_version(self) -> u8 {
        let modules = QR_BOX_PX / self.module_px() - 8;
        ((modules - 17) / 4).clamp(1, 40) as u8
    }

    /// Characters per Specter part (SeedSigner's mapping).
    fn specter_chunk(self) -> usize {
        match self {
            Density::Low => 40,
            Density::Auto | Density::Medium => 65,
            Density::High => 90,
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|d| *d == self).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Speed {
    Slow,
    Normal,
    Fast,
}

impl Speed {
    pub fn next(self) -> Speed {
        match self {
            Speed::Slow => Speed::Normal,
            Speed::Normal => Speed::Fast,
            Speed::Fast => Speed::Slow,
        }
    }
    /// Frame period (Jade uses about 800 / 450 / 270 ms).
    pub fn period_ms(self) -> u32 {
        match self {
            Speed::Slow => 800,
            Speed::Normal => 450,
            Speed::Fast => 270,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// BC-UR with this type (e.g. "crypto-account").
    Ur(&'static str),
    /// One static QR of the payload text/bytes.
    Static,
    /// Specter "pM/N" animated text.
    Specter,
    /// Standard SeedQR (numeric mode, ECC L).
    SeedStandard,
    /// Compact SeedQR (byte mode, ECC L).
    SeedCompact,
    /// BBQr parts cut from the encoded characters in the payload
    /// (`encoding` is 'Z', '2' or 'H').
    Bbqr { encoding: u8, file_type: FileType },
}

/// Light-module brightness levels (SeedSigner lets users dim the QR to
/// stop the scanning camera from over-exposing).
const LIGHT_LEVELS: [u8; 5] = [255, 215, 175, 135, 95];

pub struct QrSession {
    pub format: Format,
    payload: [u8; PAYLOAD_MAX],
    len: usize,
    pub density: Density,
    pub speed: Speed,
    pub brightness: usize,
    pub invert: bool,
    pub fullscreen: bool,
    pub paused: bool,
    /// UR: sequence number (1-based, keeps counting = fountain parts).
    /// Specter: part index (0-based, cycles).
    pub frame: u32,
    elapsed: u32,
}

impl QrSession {
    pub fn new(format: Format, payload: &[u8], density: Density, speed: Speed) -> Option<QrSession> {
        if payload.len() > PAYLOAD_MAX || payload.is_empty() {
            return None;
        }
        // single-symbol formats show the whole payload in one frame
        if matches!(
            format,
            Format::Static | Format::SeedStandard | Format::SeedCompact
        ) && payload.len() > TEXT_MAX
        {
            return None;
        }
        let mut s = QrSession {
            format,
            payload: [0; PAYLOAD_MAX],
            len: payload.len(),
            density,
            speed,
            brightness: 0,
            invert: false,
            fullscreen: false,
            paused: false,
            frame: 1,
            elapsed: 0,
        };
        s.payload[..payload.len()].copy_from_slice(payload);
        s.reset_frame();
        Some(s)
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.len]
    }

    fn reset_frame(&mut self) {
        self.frame = if matches!(self.format, Format::Specter | Format::Bbqr { .. }) {
            0
        } else {
            1
        };
        self.elapsed = 0;
    }

    pub fn set_density(&mut self, d: Density) {
        self.density = d;
        self.reset_frame();
    }

    /// Density actually used: Auto picks Low unless that needs too many
    /// frames, then Medium, then High.
    pub fn effective_density(&self) -> Density {
        if self.density != Density::Auto {
            return self.density;
        }
        for d in [Density::Low, Density::Medium] {
            if self.frames_at(d) <= AUTO_MAX_LOW_FRAMES {
                return d;
            }
        }
        Density::High
    }

    fn ur_encoder_at(&self, ur_type: &'static str, d: Density) -> Option<UrEncoder<'_>> {
        let msg = self.payload();
        let max_chars = capacity(d.max_version(), Ecc::Low, Mode::Alphanumeric);
        let single_len = 3 + ur_type.len() + 1 + 2 * (msg.len() + 4);
        let frag = if single_len <= max_chars {
            msg.len()
        } else {
            max_fragment_len_for_chars(ur_type, msg.len(), max_chars)
        };
        UrEncoder::new(ur_type, msg, frag).ok()
    }

    fn ur_encoder(&self, ur_type: &'static str) -> Option<UrEncoder<'_>> {
        self.ur_encoder_at(ur_type, self.effective_density())
    }

    fn bbqr_at(&self, d: Density) -> Option<Bbqr<'_>> {
        let Format::Bbqr { encoding, file_type } = self.format else {
            return None;
        };
        Bbqr::from_encoded(self.payload(), encoding, file_type, 1, d.max_version()).ok()
    }

    fn frames_at(&self, d: Density) -> usize {
        match self.format {
            Format::Ur(t) => self.ur_encoder_at(t, d).map(|e| e.seq_len()).unwrap_or(1),
            Format::Specter => specter::count(self.len, d.specter_chunk()),
            Format::Bbqr { .. } => self.bbqr_at(d).map_or(1, |b| b.count()),
            _ => 1,
        }
    }

    /// Distinct frames (UR: pure fragments; it keeps adding fountain parts).
    pub fn frames(&self) -> usize {
        self.frames_at(self.effective_density())
    }

    pub fn is_animated(&self) -> bool {
        self.frames() > 1
    }

    /// Text of the current frame (UR upper-cased for QR alphanumeric mode).
    pub fn text(&self, out: &mut [u8; TEXT_MAX]) -> usize {
        match self.format {
            Format::Ur(t) => {
                let Some(e) = self.ur_encoder(t) else { return 0 };
                let n = e.part(self.frame.max(1), out).unwrap_or(0);
                out[..n].make_ascii_uppercase();
                n
            }
            Format::Specter => specter::part(
                self.payload(),
                self.effective_density().specter_chunk(),
                self.frame as usize,
                out,
            )
            .unwrap_or(0),
            Format::Bbqr { .. } => self
                .bbqr_at(self.effective_density())
                .and_then(|b| b.part(self.frame as usize, out).ok())
                .unwrap_or(0),
            _ => {
                out[..self.len].copy_from_slice(self.payload());
                self.len
            }
        }
    }

    /// QR symbol for the current frame.
    pub fn qr(&self) -> Option<QrCode> {
        let mut buf = [0u8; TEXT_MAX];
        let n = self.text(&mut buf);
        let r = match self.format {
            Format::SeedCompact => QrCode::encode_mode(&buf[..n], Mode::Byte, Ecc::Low, 1, 40, None),
            Format::SeedStandard => QrCode::encode_mode(&buf[..n], Mode::Numeric, Ecc::Low, 1, 40, None),
            _ => QrCode::encode(&buf[..n], Ecc::Low, 1, 40, None),
        };
        bp_crypto::secret::wipe(&mut buf);
        r.ok()
    }

    pub fn light(&self) -> u8 {
        LIGHT_LEVELS[self.brightness.min(LIGHT_LEVELS.len() - 1)]
    }

    pub fn brightness_levels() -> usize {
        LIGHT_LEVELS.len()
    }

    /// Advance animation; returns true when the frame changed.
    pub fn tick(&mut self, dt_ms: u32) -> bool {
        if self.paused || !self.is_animated() {
            return false;
        }
        self.elapsed += dt_ms;
        if self.elapsed < self.speed.period_ms() {
            return false;
        }
        self.elapsed = 0;
        match self.format {
            Format::Specter | Format::Bbqr { .. } => self.frame = (self.frame + 1) % self.frames() as u32,
            _ => self.frame = self.frame.wrapping_add(1).max(1),
        }
        true
    }
}

impl Drop for QrSession {
    fn drop(&mut self) {
        // SeedQR payloads are secrets; wipe every payload regardless.
        bp_crypto::secret::wipe(&mut self.payload);
    }
}
