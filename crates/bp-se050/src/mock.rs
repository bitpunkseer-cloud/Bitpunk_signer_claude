//! A simulated SE050 at the I2C level (feature `mock`, tests): T=1 card
//! side, SCP03 card side, and the part of the SE05x applet the vault uses —
//! objects with policies, sessions, UserID attempts that lock for good,
//! HMAC keys, counters. Faults can be injected: a busy chip (NACKs), a
//! damaged frame, a waiting-time extension, a power cut.
//!
//! It follows the same documents as the driver, so it cannot prove the
//! driver right on its own: the frames and APDUs are pinned to the
//! reference driver and SCP03 to published vectors in the other modules'
//! tests. What it proves is that the layers fit together and that the
//! vault's rules hold through the whole stack.

use crate::apdu::{self, APDU_MAX};
use crate::cmd::{self, allow, ins, p1, p2, tag, ANYONE};
use crate::crc::crc16;
use crate::scp03::{kdf, put_key_answer, StaticKeys};
use crate::t1::{self, s, I2c, Nack, Pcb, IFS, NAD_HOST, NAD_SE};
use bp_crypto::aes::{Aes128, Cmac};
use bp_crypto::hmac::HmacSha256;
use std::collections::{BTreeMap, VecDeque};
use std::vec;
use std::vec::Vec;

#[derive(Clone, Debug)]
enum Kind {
    UserId { value: Vec<u8>, max: u8, failed: u8 },
    Binary(Vec<u8>),
    Hmac(Vec<u8>),
    Counter(u64),
}

#[derive(Clone, Debug)]
struct Obj {
    kind: Kind,
    policy: Vec<([u8; 4], u32)>,
}

impl Obj {
    fn allows(&self, who: [u8; 4], what: u32) -> bool {
        self.policy.is_empty() || self.policy.iter().any(|(id, f)| *id == who && f & what != 0)
    }
}

#[derive(Clone)]
struct CardScp {
    s_enc: [u8; 16],
    s_mac: [u8; 16],
    s_rmac: [u8; 16],
    host_challenge: [u8; 8],
    card_challenge: [u8; 8],
    chain: [u8; 16],
    counter: u32,
    level: u8,
    open: bool,
}

/// The chip's ATR (UM11225): BWT 5 ms, IFSC 254, MPOT 1 ms, SEGT 100 µs.
const ATR: [u8; 25] = [
    0x01, 0xA0, 0x00, 0x00, 0x03, 0x96, 0x04, 0x00, 0x05, 0x00, 0xFE, 0x02, 0x0B, 0x03, 0xE8, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,
];

#[derive(Clone)]
pub struct MockSe050 {
    out: VecDeque<u8>,
    rx: Vec<u8>,
    seq_recv: bool,
    seq_send: bool,
    pending: VecDeque<Vec<u8>>,
    last_frame: Vec<u8>,
    wtx_waiting: bool,
    keys: StaticKeys,
    scp: Option<CardScp>,
    objects: BTreeMap<[u8; 4], Obj>,
    sessions: BTreeMap<[u8; 8], ([u8; 4], bool)>,
    rng: u64,
    /// NACK the next `busy` reads (a busy chip).
    pub busy: u32,
    /// Damage the next frame sent (the host must ask for it again).
    pub corrupt_next: bool,
    /// Ask for more time before the next answer.
    pub wtx_next: bool,
    /// APDUs answered before the power fails; `None`: no cut.
    pub apdus_left: Option<u32>,
    /// No power: every transaction NACKs.
    pub dead: bool,
    /// Commands outside SCP03 are refused (Platform SCP required).
    pub require_scp: bool,
    /// The plain APDUs seen (after SCP03 is taken off).
    pub log: Vec<Vec<u8>>,
}

impl MockSe050 {
    /// A chip with these SCP03 keys; `chip` seeds its generator.
    pub fn new(chip: u64, keys: StaticKeys) -> Self {
        MockSe050 {
            out: VecDeque::new(),
            rx: Vec::new(),
            seq_recv: false,
            seq_send: false,
            pending: VecDeque::new(),
            last_frame: Vec::new(),
            wtx_waiting: false,
            keys,
            scp: None,
            objects: BTreeMap::new(),
            sessions: BTreeMap::new(),
            rng: chip | 1,
            busy: 0,
            corrupt_next: false,
            wtx_next: false,
            apdus_left: None,
            dead: false,
            require_scp: true,
            log: Vec::new(),
        }
    }

    /// Power comes back: the interface and the channel start over, the
    /// objects (non-volatile) stay.
    pub fn power_on(&mut self) {
        self.dead = false;
        self.apdus_left = None;
        self.out.clear();
        self.rx.clear();
        self.pending.clear();
        self.seq_recv = false;
        self.seq_send = false;
        self.scp = None;
        self.sessions.clear();
    }

    /// What a probe sees of an object: its value, for tests that look
    /// behind the interface (the real chip shows none of this).
    pub fn peek_binary(&self, id: [u8; 4]) -> Option<Vec<u8>> {
        match &self.objects.get(&id)?.kind {
            Kind::Binary(v) => Some(v.clone()),
            _ => None,
        }
    }

    fn random(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            *b = self.rng as u8;
        }
    }

    // ---------------- T=1 ----------------

    fn send_frame(&mut self, pcb: u8, data: &[u8]) {
        let mut f = vec![0u8; 5 + data.len()];
        let n = t1::frame(NAD_SE, pcb, data, &mut f);
        f.truncate(n);
        self.last_frame = f.clone();
        if self.corrupt_next {
            self.corrupt_next = false;
            let last = f.len() - 1;
            f[last] ^= 0x55;
        }
        self.out.extend(f);
    }

    fn send_next_chunk(&mut self) {
        if let Some(chunk) = self.pending.pop_front() {
            let more = !self.pending.is_empty();
            let pcb = t1::i_pcb(self.seq_send, more);
            self.seq_send = !self.seq_send;
            self.send_frame(pcb, &chunk);
        }
    }

    fn answer(&mut self, resp: Vec<u8>) {
        self.pending = resp.chunks(IFS).map(|c| c.to_vec()).collect();
        if self.pending.is_empty() {
            self.pending.push_back(Vec::new());
        }
        if self.wtx_next {
            self.wtx_next = false;
            self.wtx_waiting = true;
            self.send_frame(s::WTX, &[2]);
        } else {
            self.send_next_chunk();
        }
    }

    fn on_frame(&mut self, f: &[u8]) {
        if f.len() < 5 || f[0] != NAD_HOST || f[2] as usize != f.len() - 5 {
            return;
        }
        let n = f.len() - 2;
        if crc16(&f[..n]).to_le_bytes() != f[n..] {
            let pcb = t1::r_pcb(self.seq_recv, 1);
            self.send_frame(pcb, &[]);
            return;
        }
        let data = &f[3..n];
        match Pcb::parse(f[1]) {
            Some(Pcb::S(code)) => match code {
                s::RESYNC => {
                    self.seq_recv = false;
                    self.seq_send = false;
                    self.send_frame(s::RESYNC | s::RESPONSE, &[]);
                }
                s::SOFT_RESET => {
                    self.seq_recv = false;
                    self.seq_send = false;
                    self.scp = None;
                    self.sessions.clear();
                    self.send_frame(s::SOFT_RESET | s::RESPONSE, &ATR);
                }
                c if c == s::WTX | s::RESPONSE && self.wtx_waiting => {
                    self.wtx_waiting = false;
                    self.send_next_chunk();
                }
                _ => {}
            },
            Some(Pcb::R { err, .. }) => {
                if err != 0 {
                    let f = self.last_frame.clone();
                    self.out.extend(f);
                } else {
                    self.send_next_chunk();
                }
            }
            Some(Pcb::I { seq, more }) => {
                if seq != self.seq_recv {
                    // a repeat: acknowledge again
                    let pcb = t1::r_pcb(self.seq_recv, 0);
                    self.send_frame(pcb, &[]);
                    return;
                }
                self.seq_recv = !self.seq_recv;
                self.rx.extend_from_slice(data);
                if more {
                    let pcb = t1::r_pcb(self.seq_recv, 0);
                    self.send_frame(pcb, &[]);
                    return;
                }
                let apdu = core::mem::take(&mut self.rx);
                if let Some(left) = self.apdus_left {
                    if left == 0 {
                        self.dead = true;
                        return;
                    }
                    self.apdus_left = Some(left - 1);
                }
                let resp = self.process(&apdu);
                self.answer(resp);
            }
            None => {}
        }
    }

    // ---------------- SCP03 ----------------

    fn icv(scp: &CardScp, response: bool) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[12..].copy_from_slice(&scp.counter.to_be_bytes());
        if response {
            b[0] = 0x80;
        }
        Aes128::new(&scp.s_enc).encrypt_block(&mut b);
        b
    }

    fn process(&mut self, raw: &[u8]) -> Vec<u8> {
        let Some(a) = apdu::parse(raw) else {
            return sw(0x6700);
        };
        // SELECT
        if a.cla == 0 && a.ins == 0xA4 {
            self.scp = None;
            if a.data == cmd::APP_ID {
                return ok(&[0x03, 0x01, 0x00, 0x6F, 0xFF, 0x01, 0x0B]);
            }
            return sw(0x6A82);
        }
        if a.cla == cmd::CLA && a.ins == ins::INITIALIZE_UPDATE {
            return self.initialize_update(a.data);
        }
        if a.cla == 0x84 && a.ins == ins::EXTERNAL_AUTHENTICATE {
            return self.external_authenticate(raw, a);
        }
        if a.cla & 0x04 != 0 {
            let Some(scp) = self.scp.clone().filter(|s| s.open) else {
                return sw(0x6982);
            };
            return self.secure(raw, a, scp);
        }
        if self.require_scp {
            return sw(0x6982);
        }
        let (data, status) = self.dispatch(a.ins, a.p1, a.p2, a.data, None);
        self.log.push(raw.to_vec());
        with_sw(data, status)
    }

    fn initialize_update(&mut self, host: &[u8]) -> Vec<u8> {
        let Ok(host_challenge) = <[u8; 8]>::try_from(host) else {
            return sw(0x6700);
        };
        let mut card_challenge = [0u8; 8];
        self.random(&mut card_challenge);
        let mut ctx = [0u8; 16];
        ctx[..8].copy_from_slice(&host_challenge);
        ctx[8..].copy_from_slice(&card_challenge);
        let s_mac = kdf(&self.keys.mac, 0x06, 128, &ctx);
        let scp = CardScp {
            s_enc: kdf(&self.keys.enc, 0x04, 128, &ctx),
            s_mac,
            s_rmac: kdf(&self.keys.mac, 0x07, 128, &ctx),
            host_challenge,
            card_challenge,
            chain: [0; 16],
            counter: 0,
            level: 0,
            open: false,
        };
        let card = kdf(&s_mac, 0x00, 64, &ctx);
        let mut r = vec![0u8; 10];
        r.extend_from_slice(&[self.keys.version, 0x03, 0x70]);
        r.extend_from_slice(&card_challenge);
        r.extend_from_slice(&card[..8]);
        self.scp = Some(scp);
        ok(&r)
    }

    fn external_authenticate(&mut self, raw: &[u8], a: apdu::Parsed) -> Vec<u8> {
        let Some(mut scp) = self.scp.clone() else {
            return sw(0x6985);
        };
        if a.data.len() != 16 || raw.len() < 21 {
            return sw(0x6700);
        }
        let mut ctx = [0u8; 16];
        ctx[..8].copy_from_slice(&scp.host_challenge);
        ctx[8..].copy_from_slice(&scp.card_challenge);
        let host = kdf(&scp.s_mac, 0x01, 64, &ctx);
        let mut m = Cmac::new(&scp.s_mac);
        m.update(&scp.chain);
        m.update(&raw[..5]);
        m.update(&a.data[..8]);
        let mac = m.finalize();
        if host[..8] != a.data[..8] || mac[..8] != a.data[8..16] {
            self.scp = None;
            return sw(0x6300);
        }
        scp.chain = mac;
        scp.level = a.p1;
        scp.open = true;
        self.scp = Some(scp);
        sw(0x9000)
    }

    fn secure(&mut self, raw: &[u8], a: apdu::Parsed, mut scp: CardScp) -> Vec<u8> {
        if a.data.len() < 8 {
            return sw(0x6700);
        }
        let hl = if a.extended { 7 } else { 5 };
        let body = &a.data[..a.data.len() - 8];
        let mut m = Cmac::new(&scp.s_mac);
        m.update(&scp.chain);
        m.update(&raw[..hl]);
        m.update(body);
        let mac = m.finalize();
        if mac[..8] != a.data[a.data.len() - 8..] {
            self.scp = None;
            return sw(0x6982);
        }
        scp.chain = mac;
        scp.counter += 1;
        let mut plain = body.to_vec();
        if scp.level & 0x02 != 0 && !plain.is_empty() {
            if !plain.len().is_multiple_of(16) {
                return sw(0x6700);
            }
            let icv = Self::icv(&scp, false);
            Aes128::new(&scp.s_enc).cbc_decrypt(&icv, &mut plain);
            while plain.last() == Some(&0) {
                plain.pop();
            }
            if plain.pop() != Some(0x80) {
                return sw(0x6700);
            }
        }
        // the plain command, as it would have been sent without SCP03
        let le = if a.le { apdu::Le::Max } else { apdu::Le::None };
        let mut pbuf = [0u8; APDU_MAX];
        let pn = apdu::Apdu {
            cla: a.cla & !0x04,
            ins: a.ins,
            p1: a.p1,
            p2: a.p2,
            data: &plain,
            le,
        }
        .encode(&mut pbuf)
        .unwrap_or(0);
        self.log.push(pbuf[..pn].to_vec());
        let (mut data, status) = if a.ins == ins::PUT_KEY {
            self.put_key(a.p1, &plain)
        } else {
            self.dispatch(a.ins, a.p1, a.p2, &plain, None)
        };
        // wrap the answer
        if scp.level & 0x20 != 0 && !data.is_empty() {
            let n = data.len() / 16 * 16 + 16;
            data.push(0x80);
            data.resize(n, 0);
            let icv = Self::icv(&scp, true);
            Aes128::new(&scp.s_enc).cbc_encrypt(&icv, &mut data);
        }
        if scp.level & 0x10 != 0 && (status == 0x9000 || !data.is_empty()) {
            let mut m = Cmac::new(&scp.s_rmac);
            m.update(&scp.chain);
            m.update(&data);
            m.update(&status.to_be_bytes());
            data.extend_from_slice(&m.finalize()[..8]);
        }
        // the new keys apply to the next channel
        let keep = self.scp.is_some();
        if keep {
            self.scp = Some(scp);
        }
        with_sw(data, status)
    }

    fn put_key(&mut self, old: u8, d: &[u8]) -> (Vec<u8>, u16) {
        if d.len() != 70 || (old != 0 && old != self.keys.version) {
            return (Vec::new(), 0x6A80);
        }
        let dek = Aes128::new(&self.keys.dek);
        let mut keys = [[0u8; 16]; 3];
        for (i, k) in keys.iter_mut().enumerate() {
            let e = &d[1 + 23 * i..1 + 23 * (i + 1)];
            if e[..3] != [0x88, 0x11, 0x10] || e[19] != 3 {
                return (Vec::new(), 0x6A80);
            }
            k.copy_from_slice(&e[3..19]);
            dek.decrypt_block(k);
            let mut kcv = [1u8; 16];
            Aes128::new(k).encrypt_block(&mut kcv);
            if kcv[..3] != e[20..23] {
                return (Vec::new(), 0x6A80);
            }
        }
        let new = StaticKeys {
            enc: keys[0],
            mac: keys[1],
            dek: keys[2],
            version: d[0],
        };
        let answer = put_key_answer(&new).to_vec();
        self.keys = new;
        (answer, 0x9000)
    }

    // ---------------- applet ----------------

    /// Run one applet command for `who` (the session's verified UserID, or
    /// the default session).
    fn dispatch(&mut self, ins_: u8, p1_: u8, p2_: u8, d: &[u8], session: Option<[u8; 8]>) -> (Vec<u8>, u16) {
        let who = session
            .and_then(|s| self.sessions.get(&s).copied())
            .and_then(|(id, verified)| verified.then_some(id))
            .unwrap_or(ANYONE);
        let id = |d: &[u8]| apdu::find(d, tag::T1).and_then(|v| <[u8; 4]>::try_from(v).ok());
        match (ins_ & !ins::AUTH_OBJECT, p1_, p2_) {
            (ins::PROCESS, _, _) => {
                let Some(sid) = apdu::find(d, tag::SESSION_ID).and_then(|v| <[u8; 8]>::try_from(v).ok())
                else {
                    return (Vec::new(), 0x6A80);
                };
                let Some(inner) = apdu::find(d, tag::T1).and_then(apdu::parse) else {
                    return (Vec::new(), 0x6A80);
                };
                if !self.sessions.contains_key(&sid) {
                    return (Vec::new(), 0x6985);
                }
                self.dispatch(inner.ins, inner.p1, inner.p2, inner.data, Some(sid))
            }
            (ins::MGMT, _, p2::SESSION_CREATE) => {
                let Some(oid) = id(d) else {
                    return (Vec::new(), 0x6A80);
                };
                match self.objects.get(&oid).map(|o| &o.kind) {
                    Some(Kind::UserId { max, failed, .. }) if failed < max => {}
                    Some(Kind::UserId { .. }) => return (Vec::new(), 0x6983),
                    _ => return (Vec::new(), 0x6A80),
                }
                let mut sid = [0u8; 8];
                self.random(&mut sid);
                self.sessions.insert(sid, (oid, false));
                (tlv(tag::T1, &sid), 0x9000)
            }
            (ins::MGMT, _, p2::SESSION_CLOSE) => {
                if let Some(sid) = session {
                    self.sessions.remove(&sid);
                }
                (Vec::new(), 0x9000)
            }
            (ins::MGMT, _, p2::SESSION_USERID) => {
                let Some(sid) = session else {
                    return (Vec::new(), 0x6985);
                };
                let Some((oid, _)) = self.sessions.get(&sid).copied() else {
                    return (Vec::new(), 0x6985);
                };
                let given = apdu::find(d, tag::T1).unwrap_or(&[]).to_vec();
                let Some(Obj {
                    kind: Kind::UserId { value, max, failed },
                    ..
                }) = self.objects.get_mut(&oid)
                else {
                    return (Vec::new(), 0x6A80);
                };
                if *failed >= *max {
                    return (Vec::new(), 0x6983);
                }
                if bp_crypto::chacha20poly1305::ct_eq(value, &given) {
                    *failed = 0;
                    self.sessions.insert(sid, (oid, true));
                    (Vec::new(), 0x9000)
                } else {
                    *failed += 1;
                    (Vec::new(), 0x6982)
                }
            }
            (ins::MGMT, _, p2::EXIST) => {
                let Some(oid) = id(d) else {
                    return (Vec::new(), 0x6A80);
                };
                let r = if self.objects.contains_key(&oid) { 1 } else { 2 };
                (tlv(tag::T1, &[r]), 0x9000)
            }
            (ins::MGMT, _, p2::DELETE_OBJECT) => {
                let Some(oid) = id(d) else {
                    return (Vec::new(), 0x6A80);
                };
                match self.objects.get(&oid) {
                    Some(o) if o.allows(who, allow::DELETE) => {
                        self.objects.remove(&oid);
                        (Vec::new(), 0x9000)
                    }
                    Some(_) => (Vec::new(), 0x6985),
                    None => (Vec::new(), 0x6A88),
                }
            }
            (ins::MGMT, _, p2::RANDOM) => {
                let n = apdu::find(d, tag::T1)
                    .and_then(|v| <[u8; 2]>::try_from(v).ok())
                    .map_or(0, u16::from_be_bytes) as usize;
                let mut r = vec![0u8; n.min(256)];
                self.random(&mut r);
                (tlv(tag::T1, &r), 0x9000)
            }
            (ins::WRITE, kind, p2::DEFAULT) => self.write(kind, d, who),
            (ins::READ, _, p2::DEFAULT) => {
                let Some(oid) = id(d) else {
                    return (Vec::new(), 0x6A80);
                };
                match self.objects.get(&oid) {
                    Some(o) if o.allows(who, allow::READ) => match &o.kind {
                        Kind::Binary(v) => (tlv(tag::T1, v), 0x9000),
                        Kind::Counter(c) => (tlv(tag::T1, &c.to_be_bytes()), 0x9000),
                        _ => (Vec::new(), 0x6985),
                    },
                    Some(_) => (Vec::new(), 0x6985),
                    None => (Vec::new(), 0x6A88),
                }
            }
            (ins::READ, _, p2::ATTRIBUTES) => {
                let Some(oid) = id(d) else {
                    return (Vec::new(), 0x6A80);
                };
                let Some(o) = self.objects.get(&oid) else {
                    return (Vec::new(), 0x6A88);
                };
                let (failed, max) = match o.kind {
                    Kind::UserId { failed, max, .. } => (failed as u16, max as u16),
                    _ => (0, 0),
                };
                let mut a = oid.to_vec();
                a.extend_from_slice(&[0x07, 0x02]);
                a.extend_from_slice(&failed.to_be_bytes());
                a.extend_from_slice(&[0; 4]);
                a.extend_from_slice(&max.to_be_bytes());
                (tlv(tag::T1, &a), 0x9000)
            }
            (ins::CRYPTO, p1::MAC, p2::GENERATE_ONESHOT) => {
                let Some(oid) = id(d) else {
                    return (Vec::new(), 0x6A80);
                };
                if apdu::find(d, tag::T2) != Some(&[cmd::HMAC_SHA256]) {
                    return (Vec::new(), 0x6A80);
                }
                let msg = apdu::find(d, tag::T3).unwrap_or(&[]);
                match self.objects.get(&oid) {
                    Some(o) if o.allows(who, allow::SIGN) => match &o.kind {
                        Kind::Hmac(k) => {
                            let key: [u8; 32] = k.as_slice().try_into().unwrap_or([0; 32]);
                            (tlv(tag::T1, &HmacSha256::mac(&key, msg)), 0x9000)
                        }
                        _ => (Vec::new(), 0x6985),
                    },
                    Some(_) => (Vec::new(), 0x6985),
                    None => (Vec::new(), 0x6A88),
                }
            }
            _ => (Vec::new(), 0x6D00),
        }
    }

    fn write(&mut self, kind: u8, d: &[u8], who: [u8; 4]) -> (Vec<u8>, u16) {
        let Some(oid) = apdu::find(d, tag::T1).and_then(|v| <[u8; 4]>::try_from(v).ok()) else {
            return (Vec::new(), 0x6A80);
        };
        let policy: Vec<([u8; 4], u32)> = apdu::find(d, tag::POLICY)
            .map(|p| {
                p.chunks(9)
                    .filter(|c| c.len() == 9 && c[0] == 8)
                    .map(|c| {
                        (
                            [c[1], c[2], c[3], c[4]],
                            u32::from_be_bytes([c[5], c[6], c[7], c[8]]),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(o) = self.objects.get_mut(&oid) {
            // writing an object that exists
            return match (&mut o.kind, kind) {
                (Kind::Counter(c), p1::COUNTER) if apdu::find(d, tag::T2).is_none() => {
                    if !o.policy.is_empty()
                        && !o.policy.iter().any(|(id, f)| *id == who && f & allow::WRITE != 0)
                    {
                        return (Vec::new(), 0x6985);
                    }
                    *c += 1;
                    (Vec::new(), 0x9000)
                }
                (Kind::UserId { value, .. }, p1::USERID) => {
                    // only its own session may change it
                    if who != oid {
                        return (Vec::new(), 0x6985);
                    }
                    *value = apdu::find(d, tag::T2).unwrap_or(&[]).to_vec();
                    (Vec::new(), 0x9000)
                }
                _ => (Vec::new(), 0x6985),
            };
        }
        let obj = match kind {
            p1::USERID => Kind::UserId {
                value: apdu::find(d, tag::T2).unwrap_or(&[]).to_vec(),
                max: apdu::find(d, tag::MAX_ATTEMPTS)
                    .and_then(|v| v.first().copied())
                    .unwrap_or(0),
                failed: 0,
            },
            p1::BINARY => Kind::Binary(apdu::find(d, tag::T4).unwrap_or(&[]).to_vec()),
            p1::HMAC => Kind::Hmac(apdu::find(d, tag::T3).unwrap_or(&[]).to_vec()),
            p1::COUNTER => Kind::Counter(0),
            _ => return (Vec::new(), 0x6A86),
        };
        self.objects.insert(oid, Obj { kind: obj, policy });
        (Vec::new(), 0x9000)
    }
}

fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; v.len() + 4];
    let mut w = apdu::Writer::new(&mut b);
    let _ = w.tlv(t, v);
    let n = w.len();
    b.truncate(n);
    b
}

fn sw(s: u16) -> Vec<u8> {
    s.to_be_bytes().to_vec()
}

fn ok(d: &[u8]) -> Vec<u8> {
    with_sw(d.to_vec(), 0x9000)
}

fn with_sw(mut d: Vec<u8>, s: u16) -> Vec<u8> {
    d.extend_from_slice(&s.to_be_bytes());
    d
}

impl I2c for MockSe050 {
    fn write(&mut self, data: &[u8]) -> Result<(), Nack> {
        if self.dead {
            return Err(Nack);
        }
        self.on_frame(data);
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(), Nack> {
        if self.dead {
            return Err(Nack);
        }
        if self.busy > 0 {
            self.busy -= 1;
            return Err(Nack);
        }
        if self.out.len() < buf.len() {
            return Err(Nack);
        }
        for b in buf.iter_mut() {
            *b = self.out.pop_front().unwrap_or(0);
        }
        Ok(())
    }

    fn delay_us(&mut self, _us: u32) {}
}

/// A simple deterministic generator for tests.
#[derive(Clone)]
pub struct TestRng(pub u64);

impl bp_hal::Rng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *b = self.0 as u8;
        }
    }
}
