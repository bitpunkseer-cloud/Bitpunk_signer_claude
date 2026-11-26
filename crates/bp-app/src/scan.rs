//! Camera scanning state: the QR scanner, the frame collector (UR, BBQr,
//! Specter), a small preview of the camera image, and the last result.
//! Everything here is wiped when scanning ends.

use bp_bitcoin::bip39::Mnemonic;
use bp_bitcoin::qrinput::{AddressKind, Collector, Content, Feed, Progress, SeedSource, Source, UrKey};
use bp_bitcoin::{psbt, Network};
use bp_qr::scan::{Image, Point, Scanner};

/// QR frame collector (PSBTs scanned up to this size).
pub const STORE: usize = 32 * 1024;
/// Largest PSBT read from a file (M8 plan §5).
pub const PSBT_MAX: usize = 128 * 1024;
/// Payload and work buffers: a file PSBT plus room for the signatures
/// added to it.
pub const BUF: usize = PSBT_MAX + 16 * 1024;
pub const PREVIEW_W: usize = 200;
pub const PREVIEW_H: usize = 150;
const FRAME_TEXT: usize = 4096;
/// How long the "found" outline stays on the preview.
const FOUND_MS: u32 = 400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Main menu / QR key: anything.
    Any,
    /// Load seed > Scan SeedQR.
    Seed,
    /// Check a hand-copied SeedQR against the seed in this slot.
    Verify { slot: u8 },
    /// Tools > Verify address: an address (anything else is refused).
    Address,
    /// Tools > Verify signature: an armored signed message or the signer's
    /// address.
    Signed,
    /// The signature itself (text), after the address and the message.
    SigText,
    /// Tools > Multisig wallets > Import: a wallet (descriptor, Coldcard
    /// file, JSON, UR crypto-output).
    Wallet,
    /// Seeds > Import private key: a WIF or an extended private key (text).
    PrivKey,
    /// Multisig > Create: a cosigner's key (text, Coldcard JSON, UR
    /// crypto-account / crypto-hdkey). Never a seed.
    Cosigner,
    /// Backup & tools > OTP codes: an `otpauth://` key (text).
    Otp,
}

/// What the scan produced (data in `ScanState::out`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Psbt {
        len: usize,
        summary: psbt::Summary,
        source: Source,
    },
    Xpub {
        len: usize,
        network: Network,
        depth: u8,
    },
    Address {
        len: usize,
        network: Network,
        kind: AddressKind,
        index: Option<u32>,
    },
    Descriptor {
        len: usize,
    },
    SignMessage {
        len: usize,
    },
    SignedMessage {
        len: usize,
    },
    Settings {
        len: usize,
    },
    KeyUr {
        len: usize,
        kind: UrKey,
    },
    UnknownUr {
        len: usize,
    },
    Text {
        len: usize,
    },
    Binary {
        len: usize,
    },
    /// A seed arrived where something else was expected (or vice versa).
    NotASeed,
    /// Something other than an address arrived for Verify address.
    NotAnAddress,
    /// Neither a signed message nor an address, for Verify signature.
    NotSigned,
    /// Not a wallet, for Multisig > Import.
    NotAWallet,
    /// Not a cosigner key, for Multisig > Create.
    NotAKey,
    Failed,
}

pub struct ScanState {
    scanner: Scanner,
    collector: Collector<STORE>,
    work: [u8; BUF],
    pub out: [u8; BUF],
    text: [u8; FRAME_TEXT],
    pub preview: [u8; PREVIEW_W * PREVIEW_H],
    pub has_preview: bool,
    /// Last symbol outline in preview coordinates, and its age.
    pub found: Option<[(i32, i32); 4]>,
    found_ms: u32,
    pub frames: u32,
    /// A scanned seed waiting for confirmation (wiped on drop).
    pub seed: Option<Mnemonic>,
    pub seed_source: Option<SeedSource>,
    pub outcome: Option<Outcome>,
}

impl ScanState {
    pub const fn new() -> Self {
        Self {
            scanner: Scanner::new(),
            collector: Collector::new(),
            work: [0; BUF],
            out: [0; BUF],
            text: [0; FRAME_TEXT],
            preview: [0; PREVIEW_W * PREVIEW_H],
            has_preview: false,
            found: None,
            found_ms: 0,
            frames: 0,
            seed: None,
            seed_source: None,
            outcome: None,
        }
    }

    /// Wipe everything (buffers, collector, scanned seed).
    pub fn clear(&mut self) {
        self.collector.reset();
        bp_crypto::secret::wipe(&mut self.work);
        bp_crypto::secret::wipe(&mut self.out);
        bp_crypto::secret::wipe(&mut self.text);
        self.preview.fill(0);
        self.has_preview = false;
        self.found = None;
        self.frames = 0;
        self.seed = None;
        self.seed_source = None;
        self.outcome = None;
    }

    /// The received payload and the work buffer (the signed PSBT goes
    /// there; it is wiped with everything else).
    pub fn buffers(&mut self) -> (&[u8], &mut [u8]) {
        (&self.out, &mut self.work)
    }

    /// The work buffer (read-only; the signed PSBT after signing).
    pub fn work(&self) -> &[u8] {
        &self.work
    }

    pub fn progress(&self) -> Progress {
        self.collector.progress()
    }

    pub fn has_part(&self, i: usize) -> bool {
        self.collector.has_part(i)
    }

    pub fn ur_type(&self) -> Option<&str> {
        self.collector.ur_type()
    }

    /// Age the outline; true if the screen should redraw.
    pub fn tick(&mut self, dt: u32) -> bool {
        if self.found.is_some() {
            self.found_ms += dt;
            if self.found_ms > FOUND_MS {
                self.found = None;
                return true;
            }
        }
        false
    }

    fn update_preview(&mut self, gray: &[u8], w: usize, h: usize) {
        // fit the frame into the preview (nearest neighbour, centred crop
        // to the 4:3 preview shape)
        let scale = (w as f32 / PREVIEW_W as f32).min(h as f32 / PREVIEW_H as f32);
        let ox = (w as f32 - PREVIEW_W as f32 * scale) / 2.0;
        let oy = (h as f32 - PREVIEW_H as f32 * scale) / 2.0;
        for py in 0..PREVIEW_H {
            let sy = ((oy + (py as f32 + 0.5) * scale) as usize).min(h - 1);
            for px in 0..PREVIEW_W {
                let sx = ((ox + (px as f32 + 0.5) * scale) as usize).min(w - 1);
                self.preview[py * PREVIEW_W + px] = gray[sy * w + sx];
            }
        }
        self.has_preview = true;
    }

    fn to_preview(&self, p: Point, w: usize, h: usize) -> (i32, i32) {
        let scale = (w as f32 / PREVIEW_W as f32).min(h as f32 / PREVIEW_H as f32);
        let ox = (w as f32 - PREVIEW_W as f32 * scale) / 2.0;
        let oy = (h as f32 - PREVIEW_H as f32 * scale) / 2.0;
        (((p.x - ox) / scale) as i32, ((p.y - oy) / scale) as i32)
    }

    /// Process one camera frame; returns true when the payload is complete.
    pub fn frame(&mut self, gray: &[u8], w: usize, h: usize) -> bool {
        if w == 0 || h == 0 || gray.len() < w * h {
            return false;
        }
        self.frames = self.frames.wrapping_add(1);
        self.update_preview(gray, w, h);
        let Some(img) = Image::new(gray, w, h) else {
            return false;
        };
        let Some(f) = self.scanner.scan(img, &mut self.text) else {
            return false;
        };
        let corners = f.corners.map(|p| self.to_preview(p, w, h));
        self.found = Some(corners);
        self.found_ms = 0;
        let len = f.decoded.len;
        let done = self.collector.feed(&self.text[..len]) == Feed::Complete;
        bp_crypto::secret::wipe(&mut self.text[..len]);
        done
    }

    /// Feed QR text directly (the simulator's paste box).
    pub fn text(&mut self, text: &[u8]) -> bool {
        self.collector.feed(text) == Feed::Complete
    }

    /// Classify the completed payload for `purpose` and reset the
    /// collector. Seeds go to `self.seed`; everything else to `outcome`.
    pub fn finish(&mut self, purpose: Purpose) {
        let r = self.collector.finish(&mut self.work, &mut self.out);
        self.collector.reset();
        bp_crypto::secret::wipe(&mut self.work);
        let outcome = match r {
            // a seed (or anything else) is never taken for an address
            Ok((c, _)) if purpose == Purpose::Address && !matches!(c, Content::Address { .. }) => {
                Some(Outcome::NotAnAddress)
            }
            Ok((c, _)) if purpose == Purpose::Signed => Some(match c {
                Content::SignedMessage { len } => Outcome::SignedMessage { len },
                Content::Settings { len } => Outcome::Settings { len },
                Content::Address {
                    len,
                    network,
                    kind,
                    index,
                } => Outcome::Address {
                    len,
                    network,
                    kind,
                    index,
                },
                _ => Outcome::NotSigned,
            }),
            // the signature is text; nothing else (a seed least of all)
            Ok((c, _)) if purpose == Purpose::SigText => Some(match c {
                Content::Text { len } => Outcome::Text { len },
                _ => Outcome::Text { len: 0 },
            }),
            // a wallet: descriptor-like text, plain text (checked later) or UR crypto-output
            Ok((c, _)) if purpose == Purpose::Wallet => Some(match c {
                Content::Descriptor { len } => Outcome::Descriptor { len },
                Content::Text { len } => Outcome::Descriptor { len },
                Content::KeyUr {
                    len,
                    kind: UrKey::Output,
                } => Outcome::KeyUr {
                    len,
                    kind: UrKey::Output,
                },
                _ => Outcome::NotAWallet,
            }),
            // a private key arrives as text; nothing else is taken
            Ok((c, _)) if purpose == Purpose::Otp => Some(match c {
                Content::Text { len } => Outcome::Text { len },
                _ => Outcome::Text { len: 0 },
            }),
            Ok((c, _)) if purpose == Purpose::PrivKey => Some(match c {
                Content::Text { len } => Outcome::Text { len },
                _ => Outcome::Text { len: 0 },
            }),
            Ok((c, _)) if purpose == Purpose::Cosigner => Some(match c {
                Content::Xpub { len, network, depth } => Outcome::Xpub { len, network, depth },
                Content::Text { len } => Outcome::Text { len },
                Content::KeyUr {
                    len,
                    kind: kind @ (UrKey::Account | UrKey::HdKey),
                } => Outcome::KeyUr { len, kind },
                _ => Outcome::NotAKey,
            }),
            Ok((Content::Seed { mnemonic, source }, _)) => {
                self.seed = Some(mnemonic);
                self.seed_source = Some(source);
                None
            }
            Ok(_) if matches!(purpose, Purpose::Seed | Purpose::Verify { .. }) => Some(Outcome::NotASeed),
            Ok((c, source)) => Some(match c {
                Content::Psbt { len, summary } => Outcome::Psbt { len, summary, source },
                Content::Xpub { len, network, depth } => Outcome::Xpub { len, network, depth },
                Content::Address {
                    len,
                    network,
                    kind,
                    index,
                } => Outcome::Address {
                    len,
                    network,
                    kind,
                    index,
                },
                Content::Descriptor { len } => Outcome::Descriptor { len },
                Content::SignMessage { len } => Outcome::SignMessage { len },
                Content::SignedMessage { len } => Outcome::SignedMessage { len },
                Content::Settings { len } => Outcome::Settings { len },
                Content::KeyUr { len, kind } => Outcome::KeyUr { len, kind },
                Content::UnknownUr { len } => Outcome::UnknownUr { len },
                Content::Text { len } => Outcome::Text { len },
                Content::Binary { len } => Outcome::Binary { len },
                Content::Seed { .. } => Outcome::Failed,
            }),
            Err(_) => Some(Outcome::Failed),
        };
        self.outcome = outcome;
    }
}

impl Default for ScanState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ScanState {
    fn drop(&mut self) {
        self.clear();
    }
}
