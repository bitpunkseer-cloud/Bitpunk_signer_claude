//! `Se050`: the vault's `SecureElement` on four SE050 objects, every
//! command under Platform SCP03 (C-MAC + C-ENC + R-MAC + R-ENC), so
//! nothing crosses the I2C bus in the clear.
//!
//! | object | type | rights |
//! |---|---|---|
//! | `AUTH` | UserID, 16 bytes (A), `max_attempts` | its own session may rewrite it; anyone may delete it |
//! | `SECRET` | binary, 32 bytes from the element's TRNG (S) | read only in a session opened with `AUTH`; anyone may delete it |
//! | `HMAC` | HMAC key, 32 bytes from the TRNG | anyone may MAC with it; never read, never deleted |
//! | `COUNTER` | counter, 8 bytes | read and add one; never deleted |
//!
//! A wrong UserID uses an attempt; at `max_attempts` the element refuses
//! the UserID for good, so `SECRET` can never be read again. The element
//! keeps that count, not the firmware.

use crate::apdu::{self, APDU_MAX, SW_OK};
use crate::cmd::{self, allow, Cmd, ANYONE};
use crate::scp03::{put_key_answer, put_key_data, Session, StaticKeys, LEVEL_FULL, PUT_KEY_LEN};
use crate::t1::{I2c, IFS, T1};
use bp_crypto::chacha20poly1305::ct_eq;
use bp_crypto::secret::wipe;
use bp_hal::secure::{SeError, SeState, SecureElement};
use bp_hal::Rng;

/// The vault's objects (user identifier range).
pub mod obj {
    pub const AUTH: [u8; 4] = [0x7B, 0x10, 0x00, 0x01];
    pub const SECRET: [u8; 4] = [0x7B, 0x10, 0x00, 0x02];
    pub const HMAC: [u8; 4] = [0x7B, 0x10, 0x00, 0x03];
    pub const COUNTER: [u8; 4] = [0x7B, 0x10, 0x00, 0x04];
}

/// The UserID holds the first 16 bytes of the authenticator.
const UID_LEN: usize = 16;

pub struct Se050<B: I2c, R: Rng> {
    t1: T1<B>,
    rng: R,
    keys: StaticKeys,
    scp: Option<Session>,
}

type Resp = [u8; APDU_MAX];

impl<B: I2c, R: Rng> Se050<B, R> {
    pub fn new(bus: B, keys: StaticKeys, rng: R) -> Self {
        Se050 {
            t1: T1::new(bus),
            rng,
            keys,
            scp: None,
        }
    }

    pub fn bus(&mut self) -> &mut B {
        &mut self.t1.bus
    }

    /// Forget the channel (at power-up): the next command opens a new one.
    pub fn reset(&mut self) {
        self.scp = None;
    }

    /// Start over: interface reset, select the applet, open SCP03.
    fn connect(&mut self) -> Result<(), SeError> {
        self.scp = None;
        let _ = self.t1.resync();
        let mut atr = [0u8; IFS];
        self.t1.soft_reset(&mut atr).map_err(|_| SeError::Bus)?;
        let mut r: Resp = [0; APDU_MAX];
        if self.plain(&cmd::select().ok_or(SeError::Bus)?, &mut r)?.1 != SW_OK {
            return Err(SeError::Bus);
        }
        let mut host = [0u8; 8];
        self.rng.fill_bytes(&mut host);
        let (n, sw) = self.plain(
            &cmd::initialize_update(&host, self.keys.version).ok_or(SeError::Bus)?,
            &mut r,
        )?;
        if sw != SW_OK {
            return Err(SeError::Bus);
        }
        // a chip that does not know our keys (or is not ours) stops here
        let (mut s, hc) = Session::begin(&self.keys, &host, &r[..n]).map_err(|_| SeError::Bus)?;
        let mut ea = [0u8; 32];
        let len = s.external_authenticate(LEVEL_FULL, &hc, &mut ea);
        let got = self.t1.transceive(&ea[..len], &mut r).map_err(|_| SeError::Bus)?;
        match apdu::split_sw(&r[..got]) {
            Some((_, SW_OK)) => {}
            _ => return Err(SeError::Bus),
        }
        self.scp = Some(s);
        Ok(())
    }

    /// A command without secure messaging (SELECT, INITIALIZE UPDATE).
    fn plain(&mut self, c: &Cmd, r: &mut Resp) -> Result<(usize, u16), SeError> {
        let mut a = [0u8; APDU_MAX];
        let n = c.apdu().encode(&mut a).ok_or(SeError::Bus)?;
        let got = self.t1.transceive(&a[..n], r).map_err(|_| SeError::Bus)?;
        let (data, sw) = apdu::split_sw(&r[..got]).ok_or(SeError::Bus)?;
        Ok((data.len(), sw))
    }

    /// A command under SCP03: the plain answer's length in `r`, and the
    /// status word. Any transport or channel failure drops the channel;
    /// the next command opens a new one.
    fn run(&mut self, c: &Cmd, r: &mut Resp) -> Result<(usize, u16), SeError> {
        if self.scp.is_none() {
            self.connect()?;
        }
        let res = self.run_once(c, r);
        if res.is_err() {
            self.scp = None;
        }
        res
    }

    fn run_once(&mut self, c: &Cmd, r: &mut Resp) -> Result<(usize, u16), SeError> {
        let s = self.scp.as_mut().ok_or(SeError::Bus)?;
        let mut w = [0u8; APDU_MAX];
        let n = s.wrap(&c.apdu(), &mut w).map_err(|_| SeError::Bus)?;
        let got = self.t1.transceive(&w[..n], r).map_err(|_| SeError::Bus)?;
        wipe(&mut w);
        let s = self.scp.as_mut().ok_or(SeError::Bus)?;
        s.unwrap(&mut r[..got]).map_err(|_| SeError::Bus)
    }

    fn ok(&mut self, c: Option<Cmd>, r: &mut Resp) -> Result<usize, SeError> {
        match self.run(&c.ok_or(SeError::Bus)?, r)? {
            (n, SW_OK) => Ok(n),
            _ => Err(SeError::Bus),
        }
    }

    /// `inner` run in session `sid`.
    fn in_session(
        &mut self,
        sid: &[u8; 8],
        inner: Option<Cmd>,
        r: &mut Resp,
    ) -> Result<(usize, u16), SeError> {
        let inner = inner.ok_or(SeError::Bus)?;
        let mut a = [0u8; APDU_MAX];
        let n = inner.apdu().encode(&mut a).ok_or(SeError::Bus)?;
        let c = cmd::process(sid, &a[..n]).ok_or(SeError::Bus);
        wipe(&mut a);
        self.run(&c?, r)
    }

    fn exists(&mut self, id: [u8; 4]) -> Result<bool, SeError> {
        let mut r: Resp = [0; APDU_MAX];
        let n = self.ok(cmd::exists(id), &mut r)?;
        let v = apdu::find(&r[..n], cmd::tag::T1).ok_or(SeError::Bus)?;
        Ok(v == [cmd::RESULT_SUCCESS])
    }

    /// The UserID's wrong attempts and its maximum.
    fn attempts(&mut self) -> Result<(u16, u16), SeError> {
        let mut r: Resp = [0; APDU_MAX];
        let n = self.ok(cmd::read_attributes(obj::AUTH), &mut r)?;
        let a = apdu::find(&r[..n], cmd::tag::T1).ok_or(SeError::Bus)?;
        if a.len() < 14 {
            return Err(SeError::Bus);
        }
        Ok((
            u16::from_be_bytes([a[6], a[7]]),
            u16::from_be_bytes([a[12], a[13]]),
        ))
    }

    /// Bytes from the element's generator (up to 256).
    pub(crate) fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), SeError> {
        let mut r: Resp = [0; APDU_MAX];
        let n = self.ok(cmd::random(out.len() as u16), &mut r)?;
        let v = apdu::find(&r[..n], cmd::tag::T1).ok_or(SeError::Bus)?;
        if v.len() != out.len() {
            return Err(SeError::Bus);
        }
        out.copy_from_slice(v);
        wipe(&mut r);
        Ok(())
    }

    fn random32(&mut self) -> Result<[u8; 32], SeError> {
        let mut out = [0u8; 32];
        self.random_bytes(&mut out)?;
        Ok(out)
    }

    fn ensure_hmac_key(&mut self) -> Result<(), SeError> {
        if self.exists(obj::HMAC)? {
            return Ok(());
        }
        let mut key = self.random32()?;
        let mut pol = [0u8; 16];
        let pn = cmd::policy(&[(ANYONE, allow::SIGN)], &mut pol);
        let mut r: Resp = [0; APDU_MAX];
        let res = self.ok(cmd::write_hmac_key(obj::HMAC, &key, Some(&pol[..pn])), &mut r);
        wipe(&mut key);
        res.map(|_| ())
    }

    /// Open a session with the UserID and present `auth`: the session, or
    /// the error (one attempt used if `auth` is wrong).
    fn authenticate(&mut self, auth: &[u8; 32]) -> Result<[u8; 8], SeError> {
        match self.state()? {
            SeState::Blank => return Err(SeError::Blank),
            SeState::Locked => return Err(SeError::Locked),
            SeState::Ready { .. } => {}
        }
        let mut r: Resp = [0; APDU_MAX];
        let n = self.ok(cmd::create_session(obj::AUTH), &mut r)?;
        let sid: [u8; 8] = apdu::find(&r[..n], cmd::tag::T1)
            .and_then(|v| v.try_into().ok())
            .ok_or(SeError::Bus)?;
        let (_, sw) = self.in_session(&sid, cmd::verify_user_id(&auth[..UID_LEN]), &mut r)?;
        if sw != SW_OK {
            let _ = self.in_session(&sid, cmd::close_session(), &mut r);
            return Err(match self.state()? {
                SeState::Ready { left } => SeError::WrongAuth { left },
                SeState::Locked => SeError::WrongAuth { left: 0 },
                SeState::Blank => SeError::Blank,
            });
        }
        Ok(sid)
    }

    /// Replace the SCP03 keys (PUT KEY); the channel reopens with the new
    /// ones. The element must answer with their check values.
    pub fn rotate_keys(&mut self, new: StaticKeys) -> Result<(), SeError> {
        let mut data = [0u8; PUT_KEY_LEN];
        put_key_data(&self.keys.dek, &new, &mut data);
        let mut r: Resp = [0; APDU_MAX];
        let res = self.ok(cmd::put_key(self.keys.version, &data), &mut r);
        wipe(&mut data);
        let n = res?;
        if !ct_eq(&r[..n], &put_key_answer(&new)) {
            return Err(SeError::Bus);
        }
        self.keys = new;
        self.scp = None;
        Ok(())
    }
}

impl<B: I2c, R: Rng> SecureElement for Se050<B, R> {
    fn state(&mut self) -> Result<SeState, SeError> {
        if !self.exists(obj::AUTH)? {
            return Ok(SeState::Blank);
        }
        let (failed, max) = self.attempts()?;
        Ok(if failed >= max {
            SeState::Locked
        } else {
            SeState::Ready {
                left: (max - failed).min(255) as u8,
            }
        })
    }

    fn provision(&mut self, auth: &[u8; 32], max_attempts: u8) -> Result<(), SeError> {
        if self.exists(obj::AUTH)? {
            return Err(SeError::Exists);
        }
        let mut r: Resp = [0; APDU_MAX];
        // what a cut provision may have left
        if self.exists(obj::SECRET)? {
            self.ok(cmd::delete(obj::SECRET), &mut r)?;
        }
        self.ensure_hmac_key()?;
        let mut pol = [0u8; 32];
        // the secret from the element's own generator, readable only after AUTH
        let mut s = self.random32()?;
        let pn = cmd::policy(&[(obj::AUTH, allow::READ), (ANYONE, allow::DELETE)], &mut pol);
        let res = self.ok(cmd::write_binary(obj::SECRET, &s, Some(&pol[..pn])), &mut r);
        wipe(&mut s);
        res?;
        // the UserID last: until it exists the element counts as blank
        let pn = cmd::policy(&[(obj::AUTH, allow::WRITE), (ANYONE, allow::DELETE)], &mut pol);
        self.ok(
            cmd::write_user_id(
                obj::AUTH,
                &auth[..UID_LEN],
                Some(max_attempts.max(1)),
                Some(&pol[..pn]),
            ),
            &mut r,
        )?;
        Ok(())
    }

    fn unlock(&mut self, auth: &[u8; 32], secret: &mut [u8; 32]) -> Result<(), SeError> {
        let sid = self.authenticate(auth)?;
        let mut r: Resp = [0; APDU_MAX];
        let (n, sw) = self.in_session(&sid, cmd::read_object(obj::SECRET), &mut r)?;
        let got = (sw == SW_OK)
            .then(|| apdu::find(&r[..n], cmd::tag::T1))
            .flatten()
            .and_then(|v| <[u8; 32]>::try_from(v).ok());
        let _ = self.in_session(&sid, cmd::close_session(), &mut [0; APDU_MAX]);
        let res = match got {
            Some(s) => {
                *secret = s;
                Ok(())
            }
            None => Err(SeError::Bus),
        };
        wipe(&mut r);
        res
    }

    fn change_auth(&mut self, old: &[u8; 32], new: &[u8; 32]) -> Result<(), SeError> {
        let sid = self.authenticate(old)?;
        let mut r: Resp = [0; APDU_MAX];
        let (_, sw) = self.in_session(
            &sid,
            cmd::write_user_id(obj::AUTH, &new[..UID_LEN], None, None),
            &mut r,
        )?;
        let _ = self.in_session(&sid, cmd::close_session(), &mut r);
        if sw == SW_OK {
            Ok(())
        } else {
            Err(SeError::Bus)
        }
    }

    fn destroy(&mut self) -> Result<(), SeError> {
        let mut r: Resp = [0; APDU_MAX];
        for id in [obj::SECRET, obj::AUTH] {
            if self.exists(id)? {
                self.ok(cmd::delete(id), &mut r)?;
            }
        }
        Ok(())
    }

    fn hmac(&mut self, msg: &[u8], out: &mut [u8; 32]) -> Result<(), SeError> {
        self.ensure_hmac_key()?;
        let mut r: Resp = [0; APDU_MAX];
        let n = self.ok(cmd::hmac(obj::HMAC, msg), &mut r)?;
        let v = apdu::find(&r[..n], cmd::tag::T1).ok_or(SeError::Bus)?;
        *out = v.try_into().map_err(|_| SeError::Bus)?;
        Ok(())
    }

    fn counter(&mut self) -> Result<u32, SeError> {
        if !self.exists(obj::COUNTER)? {
            return Ok(0);
        }
        let mut r: Resp = [0; APDU_MAX];
        let n = self.ok(cmd::read_object(obj::COUNTER), &mut r)?;
        let v = apdu::find(&r[..n], cmd::tag::T1).ok_or(SeError::Bus)?;
        let mut b = [0u8; 8];
        let k = v.len().min(8);
        b[8 - k..].copy_from_slice(&v[v.len() - k..]);
        u32::try_from(u64::from_be_bytes(b)).map_err(|_| SeError::Bus)
    }

    fn bump_counter(&mut self) -> Result<u32, SeError> {
        let mut r: Resp = [0; APDU_MAX];
        if !self.exists(obj::COUNTER)? {
            let mut pol = [0u8; 16];
            let pn = cmd::policy(&[(ANYONE, allow::READ | allow::WRITE)], &mut pol);
            self.ok(
                cmd::write_counter(obj::COUNTER, Some(8), Some(&pol[..pn])),
                &mut r,
            )?;
        }
        self.ok(cmd::write_counter(obj::COUNTER, None, None), &mut r)?;
        self.counter()
    }
}
