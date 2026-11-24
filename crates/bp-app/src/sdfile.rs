//! PSBT and message files on the microSD card (M8 plan §5).
//!
//! A PSBT file (binary, Base64 or hex) is decoded while it is read, with
//! the 128 KB limit checked on the decoded bytes, into the scan buffer the
//! QR path uses; the review and signing are the same. The result saved is
//! the whole PSBT with this seed's signatures added (decision 3), named
//! `name-signed.psbt` (`name-signed-<fingerprint>.psbt` for multisig) and
//! never written over an existing file (decision 4). The original can be
//! wiped afterwards when the setting is on (decision 5).
//!
//! A message file is one to three lines: a `signmessage` request, or the
//! message, then a derivation path. The armored signature is saved as
//! `name.sig`.

use crate::scan::PSBT_MAX;
use crate::sd::{sniff, FileKind, Job, SdStep, PAGE, VIEW_MAX};
use crate::{App, Screen};
use bp_bitcoin::validate::SpendKind;
use bp_fat::{DirEntry, DirId, Error as FatError, Name, Volume};
use bp_hal::SdCard;

/// Largest message file (a request line, or message and path).
pub const MSG_FILE_MAX: usize = 2048;
/// Longest stem kept from the original name.
const STEM_MAX: usize = 180;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginKind {
    Psbt,
    Message,
}

/// The file a review or message signing started from.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Origin {
    pub kind: OriginKind,
    pub entry: DirEntry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    TooLarge,
    Encoding,
    Read,
}

/// Why a save failed (order matches `SdStrings::save_problems`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveProblem {
    NoCard,
    Io,
    Full,
    DirFull,
    Card,
}

impl SaveProblem {
    fn from_fat(e: FatError) -> Self {
        match e {
            FatError::Io => SaveProblem::Io,
            FatError::DiskFull => SaveProblem::Full,
            FatError::DirFull => SaveProblem::DirFull,
            _ => SaveProblem::Card,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Saved {
    pub name: Name,
    pub wiped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Enc {
    Binary,
    Base64,
    Hex,
}

/// Streaming PSBT decoder: binary, Base64 or hex, white space allowed in
/// the text forms. The size limit is checked on the decoded bytes.
pub struct Decoder {
    enc: Enc,
    acc: u32,
    bits: u32,
    chars: usize,
    pad: u8,
    hi: Option<u8>,
    n: usize,
}

fn after_bom_and_space(b: &[u8]) -> &[u8] {
    let b = b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b);
    let skip = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    &b[skip..]
}

fn b64_value(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

impl Decoder {
    /// Choose the encoding from the file's first bytes.
    pub fn detect(head: &[u8]) -> Result<Decoder, LoadError> {
        // the first ten characters, line breaks and spaces left out
        let mut sig = [0u8; 10];
        let mut k = 0;
        for &c in after_bom_and_space(head) {
            if k == sig.len() {
                break;
            }
            if !c.is_ascii_whitespace() {
                sig[k] = c;
                k += 1;
            }
        }
        let enc = if head.starts_with(bp_bitcoin::psbt::MAGIC) {
            Enc::Binary
        } else if sig.starts_with(b"cHNidP") {
            Enc::Base64
        } else if k == 10 && sig.eq_ignore_ascii_case(b"70736274ff") {
            Enc::Hex
        } else {
            return Err(LoadError::Encoding);
        };
        Ok(Decoder {
            enc,
            acc: 0,
            bits: 0,
            chars: 0,
            pad: 0,
            hi: None,
            n: 0,
        })
    }

    fn put(&mut self, b: u8, out: &mut [u8]) -> Result<(), LoadError> {
        let slot = out.get_mut(self.n).ok_or(LoadError::TooLarge)?;
        *slot = b;
        self.n += 1;
        Ok(())
    }

    pub fn feed(&mut self, chunk: &[u8], out: &mut [u8]) -> Result<(), LoadError> {
        match self.enc {
            Enc::Binary => {
                let end = self.n + chunk.len();
                out.get_mut(self.n..end)
                    .ok_or(LoadError::TooLarge)?
                    .copy_from_slice(chunk);
                self.n = end;
            }
            Enc::Hex => {
                for &c in chunk {
                    if c.is_ascii_whitespace() || (self.n == 0 && self.hi.is_none() && c == 0xEF) {
                        continue;
                    }
                    let v = (c as char).to_digit(16).ok_or(LoadError::Encoding)? as u8;
                    match self.hi.take() {
                        None => self.hi = Some(v),
                        Some(h) => self.put((h << 4) | v, out)?,
                    }
                }
            }
            Enc::Base64 => {
                for &c in chunk {
                    if c.is_ascii_whitespace() {
                        continue;
                    }
                    if c == b'=' {
                        self.pad += 1;
                        if self.pad > 2 {
                            return Err(LoadError::Encoding);
                        }
                        continue;
                    }
                    if self.pad > 0 {
                        return Err(LoadError::Encoding);
                    }
                    let Some(v) = b64_value(c) else {
                        // a byte order mark before the text
                        if self.chars == 0 && matches!(c, 0xEF | 0xBB | 0xBF) {
                            continue;
                        }
                        return Err(LoadError::Encoding);
                    };
                    self.chars += 1;
                    self.acc = (self.acc << 6) | v;
                    self.bits += 6;
                    if self.bits >= 8 {
                        self.bits -= 8;
                        self.put((self.acc >> self.bits) as u8, out)?;
                        self.acc &= (1 << self.bits) - 1;
                    }
                }
            }
        }
        Ok(())
    }

    /// The decoded length, once the text form ended cleanly.
    pub fn finish(&self) -> Result<usize, LoadError> {
        let ok = match self.enc {
            Enc::Binary => true,
            Enc::Hex => self.hi.is_none(),
            Enc::Base64 => {
                self.chars % 4 != 1 && (self.pad == 0 || (self.chars + self.pad as usize).is_multiple_of(4))
            }
        };
        if ok && self.n > 0 {
            Ok(self.n)
        } else {
            Err(LoadError::Encoding)
        }
    }
}

/// Characters FAT allows in a new name; others become '_'.
fn clean_stem(name: &str, out: &mut Name) {
    let stem = match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    };
    // a name signed before keeps one "-signed" only
    let stem = match stem.find("-signed") {
        Some(i) if i > 0 => &stem[..i],
        _ => stem,
    };
    for c in stem.chars().take(STEM_MAX) {
        let ok = c.is_ascii() && !c.is_ascii_control() && !"\"*/:<>?\\|".contains(c);
        let mut b = [0u8; 4];
        out.push_str(if ok { c.encode_utf8(&mut b) } else { "_" });
    }
    while out.as_str().ends_with(['.', ' ']) {
        let mut n = Name::empty();
        let s = out.as_str();
        n.push_str(&s[..s.len() - 1]);
        *out = n;
    }
    if out.is_empty() {
        out.push_str("file");
    }
}

/// `tx` → `tx-signed`, or `tx-signed-73c5da0a` for a multisig signer.
pub fn signed_stem(original: &str, multisig_fp: Option<[u8; 4]>) -> Name {
    let mut n = Name::empty();
    clean_stem(original, &mut n);
    n.push_str("-signed");
    if let Some(fp) = multisig_fp {
        n.push_str("-");
        n.push_str(crate::seeds::fingerprint_hex(&fp).as_str());
    }
    n
}

/// Is this the name of a file the PSBT list offers?
pub fn psbt_candidate(e: &DirEntry) -> bool {
    let name = e.name();
    let lower_has = |needle: &str| {
        name.as_bytes()
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
    };
    let ext = match name.rfind('.') {
        Some(i) => &name[i + 1..],
        None => "",
    };
    !e.is_dir()
        && !e.is_hidden()
        && e.size() > 0
        && !lower_has("-signed")
        && ["psbt", "txt", "base64", "b64", "hex"]
            .iter()
            .any(|x| ext.eq_ignore_ascii_case(x))
}

impl App {
    /// Files of the PSBT list: candidates in the top folder whose content
    /// is a PSBT.
    pub(crate) fn list_psbt_job(&mut self, card: &mut dyn SdCard) {
        let sd = &mut self.sd;
        sd.list = [None; PAGE];
        sd.count = 0;
        sd.total = 0;
        sd.hidden = 0;
        sd.list_err = None;
        let r = Volume::mount(&mut *card).and_then(|mut v| {
            let mut it = v.iter(DirId::Root);
            // candidates first (the listing reuses the volume's buffer)
            let mut found: [Option<DirEntry>; PAGE] = [None; PAGE];
            let mut n = 0;
            while let Some(e) = v.next_entry(&mut it)? {
                if psbt_candidate(&e) && n < PAGE {
                    found[n] = Some(e);
                    n += 1;
                }
            }
            for e in found[..n].iter().flatten() {
                let len = v.read_at(e, 0, &mut sd.view[..512]).unwrap_or(0);
                if sniff(&sd.view[..len]) == FileKind::Psbt {
                    sd.list[sd.count] = Some(*e);
                    sd.count += 1;
                }
                bp_crypto::secret::wipe(&mut sd.view[..512]);
            }
            Ok(())
        });
        sd.total = sd.count as u32;
        sd.listed = true;
        if let Err(e) = r {
            sd.list = [None; PAGE];
            sd.count = 0;
            sd.list_err = Some(crate::sd::CardProblem::from_fat(e));
        }
    }

    /// Read and decode a PSBT file into the scan buffer, then review it.
    pub(crate) fn load_psbt_job(&mut self, card: &mut dyn SdCard, e: DirEntry) {
        let t = self.text().sd;
        // the text forms are at most twice the size (hex)
        if e.size() as usize > 2 * PSBT_MAX + 4096 {
            self.notice = Some(t.too_large);
            return;
        }
        self.scan.clear();
        let view = &mut self.sd.view;
        let out = &mut self.scan.out[..PSBT_MAX];
        let r = (|| -> Result<usize, LoadError> {
            let mut v = Volume::mount(&mut *card).map_err(|_| LoadError::Read)?;
            let mut off = 0u32;
            let mut dec: Option<Decoder> = None;
            while off < e.size() {
                let n = v
                    .read_at(&e, off, &mut view[..VIEW_MAX])
                    .map_err(|_| LoadError::Read)?;
                if n == 0 {
                    return Err(LoadError::Read);
                }
                let d = match dec.as_mut() {
                    Some(d) => d,
                    None => dec.insert(Decoder::detect(&view[..n])?),
                };
                d.feed(&view[..n], out)?;
                off += n as u32;
            }
            dec.ok_or(LoadError::Encoding)?.finish()
        })();
        bp_crypto::secret::wipe(view);
        match r {
            Ok(len) => {
                self.sd.origin = Some(Origin {
                    kind: OriginKind::Psbt,
                    entry: e,
                });
                self.scan_live = true;
                // the review goes on top of the file screen
                self.push(Screen::Review {
                    step: crate::review::Step::Overview,
                });
                self.start_review(len);
                if let Some(r) = self.review.as_mut() {
                    r.from_sd = true;
                }
            }
            Err(err) => {
                self.scan.clear();
                self.notice = Some(match err {
                    LoadError::TooLarge => t.too_large,
                    LoadError::Encoding => t.bad_encoding,
                    LoadError::Read => t.problems[crate::sd::CardProblem::ReadFailed as usize][0],
                });
            }
        }
    }

    /// Read a message file and start message signing with it.
    pub(crate) fn load_message_job(&mut self, card: &mut dyn SdCard, e: DirEntry) {
        let t = self.text().sd;
        if e.size() as usize > MSG_FILE_MAX {
            self.notice = Some(t.msg_too_large);
            return;
        }
        let r =
            Volume::mount(&mut *card).and_then(|mut v| v.read_file(&e, &mut self.sd.view[..MSG_FILE_MAX]));
        let Ok(n) = r else {
            bp_crypto::secret::wipe(&mut self.sd.view);
            self.notice = Some(t.problems[crate::sd::CardProblem::ReadFailed as usize][0]);
            return;
        };
        let mut req = [0u8; MSG_FILE_MAX + 64];
        let len = message_request(&self.sd.view[..n], self.settings.network, &mut req);
        bp_crypto::secret::wipe(&mut self.sd.view);
        self.sd.origin = Some(Origin {
            kind: OriginKind::Message,
            entry: e,
        });
        self.push(Screen::MsgSign {
            step: crate::msgsign::MsStep::Off,
        });
        self.start_msg_request(&req[..len]);
        bp_crypto::secret::wipe(&mut req);
    }

    /// The fingerprint used in a multisig signer's output name.
    fn multisig_fp(&self) -> Option<[u8; 4]> {
        let r = self.review.as_ref()?;
        let multisig = r.report.as_ref()?.inputs().iter().any(|i| {
            i.owned
                .is_some_and(|o| matches!(o.get().kind, SpendKind::P2wshMulti | SpendKind::P2shP2wshMulti))
        });
        if !multisig {
            return None;
        }
        r.slot
            .and_then(|s| self.seeds[s as usize].as_ref())
            .map(|s| s.fingerprint)
    }

    /// Write the signed PSBT (or message signature) next to its original.
    pub(crate) fn save_job(&mut self, card: &mut dyn SdCard, job: Job) {
        let Some(origin) = self.sd.origin else { return };
        let (stem, ext) = match job {
            Job::SavePsbt => (signed_stem(origin.entry.name(), self.multisig_fp()), "psbt"),
            _ => {
                let mut n = Name::empty();
                clean_stem(origin.entry.name(), &mut n);
                (n, "sig")
            }
        };
        let mut armored = [0u8; bp_bitcoin::message::MAX_MESSAGE + 256];
        let data: &[u8] = match job {
            Job::SavePsbt => {
                let len = self.review.as_ref().and_then(|r| r.signed).map_or(0, |s| s.len);
                &self.scan.work()[..len]
            }
            _ => {
                let n = self
                    .msg
                    .as_ref()
                    .and_then(|m| m.armored(&mut armored))
                    .unwrap_or(0);
                &armored[..n]
            }
        };
        if data.is_empty() {
            self.sd.saved = Some(Err(SaveProblem::Card));
            return;
        }
        let wipe = job == Job::SavePsbt && self.settings.sd_wipe_original;
        let dir = origin.entry.parent();
        let r = Volume::mount(&mut *card).and_then(|mut v| {
            let name = v.unique_name(dir, stem.as_str(), ext)?;
            v.create(dir, name.as_str(), data)?;
            let wiped = wipe && v.wipe(&origin.entry).is_ok();
            Ok(Saved { name, wiped })
        });
        self.sd.saved = Some(r.map_err(SaveProblem::from_fat));
        bp_crypto::secret::wipe(&mut armored);
    }

    /// Signed step / Done step: save to the card.
    pub(crate) fn start_save(&mut self, job: Job) {
        self.sd.saved = None;
        self.sd.last_save = Some(job);
        self.sd.job = Some(job);
        self.push(Screen::Sd {
            step: SdStep::Saved { sel: 0 },
        });
    }

    /// Leave the saved screen: the flow that signed ends, and the folder it
    /// came from is read again (it has a new file, maybe one less).
    pub(crate) fn finish_save(&mut self) {
        self.pop(); // the saved screen
        self.sd.last_save = None;
        if self.sd.origin.is_none() {
            // an export: back to the QR or menu it came from
            self.sd.saved = None;
            return;
        }
        match self.sd.origin.map(|o| o.kind) {
            Some(OriginKind::Psbt) => {
                self.review = None;
                self.pop();
            }
            Some(OriginKind::Message) => {
                self.msg = None;
                self.pop();
            }
            None => {}
        }
        self.sd.origin = None;
        self.sd.saved = None;
        self.card_changed();
    }
}

impl App {
    /// QR screens whose content can also be saved as a file (never a
    /// SeedQR, a signed PSBT or a signature: secrets stay off the card,
    /// and signing results are saved by their own flow).
    pub(crate) fn export_allowed(&self, kind: crate::QrKind) -> bool {
        matches!(
            kind,
            crate::QrKind::Xpub { .. }
                | crate::QrKind::MsKey { .. }
                | crate::QrKind::Wallet { .. }
                | crate::QrKind::Settings
        )
    }

    /// The file for a QR export or a `.bpw`: stem, extension, length.
    fn export_file(&self, job: Job, out: &mut [u8]) -> Option<(Name, &'static str, usize)> {
        use crate::QrKind;
        use bp_bitcoin::address::ScriptType;
        let named = |prefix: &str, fp: [u8; 4]| {
            let mut n = Name::empty();
            n.push_str(prefix);
            n.push_str(crate::seeds::fingerprint_hex(&fp).as_str());
            n
        };
        match job {
            Job::SaveWalletFile(idx) => self.wallet_bpw(idx, out).map(|(n, len)| (n, "bpw", len)),
            Job::SaveExport(QrKind::Xpub { slot, account, .. }) => {
                let net = self.settings.network;
                let seed = self.slot(slot as usize)?;
                let types = [
                    ScriptType::Legacy,
                    ScriptType::NestedSegwit,
                    ScriptType::NativeSegwit,
                    ScriptType::Taproot,
                ];
                let paths = types.map(|st| st.account_path(net, account));
                let mut xpubs = [None; 4];
                for (x, st) in xpubs.iter_mut().zip(types) {
                    *x = seed.account_xpub(st, net, account);
                }
                let keys = [0, 1, 2, 3].map(|i| {
                    xpubs[i].as_ref().map(|x| bp_bitcoin::export::AccountExport {
                        script: types[i],
                        path: &paths[i],
                        xpub: x,
                    })
                });
                let keys = [keys[0]?, keys[1]?, keys[2]?, keys[3]?];
                let n = bp_bitcoin::export::write_generic_json(seed.fingerprint, net, account, &keys, out)?;
                Some((named("bitpunk-", seed.fingerprint), "json", n))
            }
            Job::SaveExport(QrKind::MsKey { slot, account, .. }) => {
                let fp = self.slot(slot as usize)?.fingerprint;
                let n = self.ms_key_json(slot, account, out)?;
                Some((named("ccxp-", fp), "json", n))
            }
            Job::SaveExport(QrKind::Wallet { idx, format }) => self
                .wallet_export_file(idx, format, out)
                .map(|(n, len)| (n, "txt", len)),
            Job::SaveExport(QrKind::Settings) => {
                let n = self.settings.to_qr(out);
                *out.get_mut(n)? = b'\n';
                let mut stem = Name::empty();
                stem.push_str("bitpunk-settings");
                Some((stem, "txt", n + 1))
            }
            _ => None,
        }
    }

    /// Save an export to the card's top folder (never replacing a file).
    pub(crate) fn save_export_job(&mut self, card: &mut dyn SdCard, job: Job) {
        let mut buf = [0u8; 8192];
        let Some((stem, ext, n)) = self.export_file(job, &mut buf) else {
            self.sd.saved = Some(Err(SaveProblem::Card));
            return;
        };
        let r = Volume::mount(&mut *card).and_then(|mut v| {
            let name = v.unique_name(DirId::Root, stem.as_str(), ext)?;
            v.create(DirId::Root, name.as_str(), &buf[..n])?;
            Ok(Saved { name, wiped: false })
        });
        self.sd.saved = Some(r.map_err(SaveProblem::from_fat));
    }

    /// A wallet file: import (a `.bpw` with a matching tag registers).
    pub(crate) fn load_wallet_job(&mut self, card: &mut dyn SdCard, e: DirEntry) {
        let t = self.text().sd;
        if e.size() as usize > VIEW_MAX {
            self.notice = Some(t.file_too_large);
            return;
        }
        let r = Volume::mount(&mut *card).and_then(|mut v| v.read_file(&e, &mut self.sd.view));
        let mut text = [0u8; VIEW_MAX];
        let n = match r {
            Ok(n) => n,
            Err(_) => {
                self.notice = Some(t.problems[crate::sd::CardProblem::ReadFailed as usize][0]);
                return;
            }
        };
        text[..n].copy_from_slice(&self.sd.view[..n]);
        bp_crypto::secret::wipe(&mut self.sd.view);
        self.wallet_import_file(&text[..n]);
        bp_crypto::secret::wipe(&mut text);
    }

    /// A settings file: the same import as a SettingsQR (never weakens).
    pub(crate) fn load_settings_job(&mut self, card: &mut dyn SdCard, e: DirEntry) {
        let t = self.text().sd;
        if e.size() > 1024 {
            self.notice = Some(t.file_too_large);
            return;
        }
        let r = Volume::mount(&mut *card).and_then(|mut v| v.read_file(&e, &mut self.sd.view[..1024]));
        let Ok(n) = r else {
            self.notice = Some(t.problems[crate::sd::CardProblem::ReadFailed as usize][0]);
            return;
        };
        let text = after_bom_and_space(&self.sd.view[..n]);
        let end = text
            .iter()
            .rposition(|c| !c.is_ascii_whitespace())
            .map_or(0, |i| i + 1);
        self.import = Some(self.settings.import(&text[..end]));
        bp_crypto::secret::wipe(&mut self.sd.view);
        self.push(Screen::SettingsImport { sel: 0 });
    }
}

/// A `signmessage` request from a message file: the request itself, or
/// the message on the first line and the path on the second (default: the
/// first native segwit receive address). Returns the request length.
pub fn message_request(file: &[u8], net: bp_bitcoin::Network, out: &mut [u8]) -> usize {
    let text = after_bom_and_space(file);
    let end = text
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(0, |i| i + 1);
    let text = &text[..end];
    let mut w = 0;
    let mut put = |b: &[u8], w: &mut usize| {
        let n = b.len().min(out.len() - *w);
        out[*w..*w + n].copy_from_slice(&b[..n]);
        *w += n;
    };
    if text.starts_with(b"signmessage ") {
        let line = text.split(|&c| c == b'\n').next().unwrap_or(text);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        put(line, &mut w);
        return w;
    }
    let mut lines = text
        .split(|&c| c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let message = lines.next().unwrap_or(&[]);
    let path = lines.next().map(|l| l.trim_ascii()).filter(|l| !l.is_empty());
    put(b"signmessage ", &mut w);
    match path {
        Some(p) => put(p, &mut w),
        None => {
            let coin: &[u8] = if net == bp_bitcoin::Network::Mainnet {
                b"0"
            } else {
                b"1"
            };
            put(b"m/84h/", &mut w);
            put(coin, &mut w);
            put(b"h/0h/0/0", &mut w);
        }
    }
    put(b" ascii:", &mut w);
    put(message, &mut w);
    w
}
