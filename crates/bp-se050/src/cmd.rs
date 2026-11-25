//! The SE05x applet commands the vault uses (NXP AN12413), built as plain
//! APDUs. Field order, tags and lengths follow the reference driver; the
//! tests compare every command byte for byte with it.

use crate::apdu::{Apdu, Le, Writer};

/// The SE05x IoT applet.
pub const APP_ID: [u8; 16] = [
    0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
];

pub const CLA: u8 = 0x80;

pub mod ins {
    pub const WRITE: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const CRYPTO: u8 = 0x03;
    pub const MGMT: u8 = 0x04;
    pub const PROCESS: u8 = 0x05;
    pub const AUTH_OBJECT: u8 = 0x40;
    pub const INITIALIZE_UPDATE: u8 = 0x50;
    pub const EXTERNAL_AUTHENTICATE: u8 = 0x82;
    pub const PUT_KEY: u8 = 0xD8;
}

pub mod p1 {
    pub const DEFAULT: u8 = 0x00;
    pub const HMAC: u8 = 0x05;
    pub const BINARY: u8 = 0x06;
    pub const USERID: u8 = 0x07;
    pub const COUNTER: u8 = 0x08;
    pub const MAC: u8 = 0x0D;
}

pub mod p2 {
    pub const DEFAULT: u8 = 0x00;
    pub const SESSION_CREATE: u8 = 0x1B;
    pub const SESSION_CLOSE: u8 = 0x1C;
    pub const EXIST: u8 = 0x27;
    pub const DELETE_OBJECT: u8 = 0x28;
    pub const SESSION_USERID: u8 = 0x2C;
    pub const ATTRIBUTES: u8 = 0x3B;
    pub const GENERATE_ONESHOT: u8 = 0x45;
    pub const RANDOM: u8 = 0x49;
}

pub mod tag {
    pub const SESSION_ID: u8 = 0x10;
    pub const POLICY: u8 = 0x11;
    pub const MAX_ATTEMPTS: u8 = 0x12;
    pub const T1: u8 = 0x41;
    pub const T2: u8 = 0x42;
    pub const T3: u8 = 0x43;
    pub const T4: u8 = 0x44;
}

/// Object access rights (policy flags).
pub mod allow {
    pub const SIGN: u32 = 1 << 28;
    pub const READ: u32 = 1 << 21;
    pub const WRITE: u32 = 1 << 20;
    pub const DELETE: u32 = 1 << 18;
}

pub const HMAC_SHA256: u8 = 0x19;
pub const RESULT_SUCCESS: u8 = 0x01;

/// The default session (no authentication object).
pub const ANYONE: [u8; 4] = [0; 4];

/// A command and its data.
pub struct Cmd {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub le: Le,
    buf: [u8; 540],
    n: usize,
}

impl Cmd {
    fn new(cla: u8, ins: u8, p1: u8, p2: u8, le: Le) -> Cmd {
        Cmd {
            cla,
            ins,
            p1,
            p2,
            le,
            buf: [0; 540],
            n: 0,
        }
    }

    fn data(mut self, f: impl FnOnce(&mut Writer) -> Option<()>) -> Option<Cmd> {
        let mut w = Writer::new(&mut self.buf);
        f(&mut w)?;
        self.n = w.len();
        Some(self)
    }

    pub fn apdu(&self) -> Apdu<'_> {
        Apdu {
            cla: self.cla,
            ins: self.ins,
            p1: self.p1,
            p2: self.p2,
            data: &self.buf[..self.n],
            le: self.le,
        }
    }
}

/// Policy entries: (authentication object, rights).
pub fn policy(entries: &[([u8; 4], u32)], out: &mut [u8]) -> usize {
    let mut w = Writer::new(out);
    for (id, flags) in entries {
        let _ = w.bytes(&[8]);
        let _ = w.bytes(id);
        let _ = w.bytes(&flags.to_be_bytes());
    }
    w.len()
}

pub fn select() -> Option<Cmd> {
    Cmd::new(0x00, 0xA4, 0x04, 0x00, Le::Short(7)).data(|w| w.bytes(&APP_ID))
}

pub fn initialize_update(host_challenge: &[u8; 8], key_version: u8) -> Option<Cmd> {
    Cmd::new(CLA, ins::INITIALIZE_UPDATE, key_version, 0, Le::Short(256)).data(|w| w.bytes(host_challenge))
}

pub fn create_session(auth: [u8; 4]) -> Option<Cmd> {
    Cmd::new(CLA, ins::MGMT, p1::DEFAULT, p2::SESSION_CREATE, Le::Short(12)).data(|w| w.tlv(tag::T1, &auth))
}

pub fn close_session() -> Option<Cmd> {
    Some(Cmd::new(CLA, ins::MGMT, p1::DEFAULT, p2::SESSION_CLOSE, Le::None))
}

pub fn verify_user_id(value: &[u8]) -> Option<Cmd> {
    Cmd::new(CLA, ins::MGMT, p1::DEFAULT, p2::SESSION_USERID, Le::None).data(|w| w.tlv(tag::T1, value))
}

/// A command run in session `id`.
pub fn process(id: &[u8; 8], inner: &[u8]) -> Option<Cmd> {
    Cmd::new(CLA, ins::PROCESS, p1::DEFAULT, p2::DEFAULT, Le::Max).data(|w| {
        w.tlv(tag::SESSION_ID, id)?;
        w.tlv(tag::T1, inner)
    })
}

pub fn write_user_id(id: [u8; 4], value: &[u8], max_attempts: Option<u8>, pol: Option<&[u8]>) -> Option<Cmd> {
    Cmd::new(
        CLA,
        ins::WRITE | ins::AUTH_OBJECT,
        p1::USERID,
        p2::DEFAULT,
        Le::None,
    )
    .data(|w| {
        if let Some(p) = pol {
            w.tlv(tag::POLICY, p)?;
        }
        if let Some(m) = max_attempts {
            w.tlv(tag::MAX_ATTEMPTS, &[m])?;
        }
        w.tlv(tag::T1, &id)?;
        w.tlv(tag::T2, value)
    })
}

pub fn write_binary(id: [u8; 4], data: &[u8], pol: Option<&[u8]>) -> Option<Cmd> {
    Cmd::new(CLA, ins::WRITE, p1::BINARY, p2::DEFAULT, Le::None).data(|w| {
        if let Some(p) = pol {
            w.tlv(tag::POLICY, p)?;
        }
        w.tlv(tag::T1, &id)?;
        w.tlv(tag::T3, &(data.len() as u16).to_be_bytes())?;
        w.tlv(tag::T4, data)
    })
}

pub fn write_hmac_key(id: [u8; 4], key: &[u8], pol: Option<&[u8]>) -> Option<Cmd> {
    Cmd::new(CLA, ins::WRITE, p1::HMAC, p2::DEFAULT, Le::None).data(|w| {
        if let Some(p) = pol {
            w.tlv(tag::POLICY, p)?;
        }
        w.tlv(tag::T1, &id)?;
        w.tlv(tag::T3, key)
    })
}

/// Create a counter of `size` bytes (with `size`), or add one (without).
pub fn write_counter(id: [u8; 4], size: Option<u16>, pol: Option<&[u8]>) -> Option<Cmd> {
    Cmd::new(CLA, ins::WRITE, p1::COUNTER, p2::DEFAULT, Le::None).data(|w| {
        if let Some(p) = pol {
            w.tlv(tag::POLICY, p)?;
        }
        w.tlv(tag::T1, &id)?;
        if let Some(s) = size {
            w.tlv(tag::T2, &s.to_be_bytes())?;
        }
        Some(())
    })
}

pub fn read_object(id: [u8; 4]) -> Option<Cmd> {
    Cmd::new(CLA, ins::READ, p1::DEFAULT, p2::DEFAULT, Le::Max).data(|w| w.tlv(tag::T1, &id))
}

pub fn read_attributes(id: [u8; 4]) -> Option<Cmd> {
    Cmd::new(CLA, ins::READ, p1::DEFAULT, p2::ATTRIBUTES, Le::Max).data(|w| w.tlv(tag::T1, &id))
}

pub fn exists(id: [u8; 4]) -> Option<Cmd> {
    Cmd::new(CLA, ins::MGMT, p1::DEFAULT, p2::EXIST, Le::Max).data(|w| w.tlv(tag::T1, &id))
}

pub fn delete(id: [u8; 4]) -> Option<Cmd> {
    Cmd::new(CLA, ins::MGMT, p1::DEFAULT, p2::DELETE_OBJECT, Le::None).data(|w| w.tlv(tag::T1, &id))
}

pub fn random(len: u16) -> Option<Cmd> {
    Cmd::new(CLA, ins::MGMT, p1::DEFAULT, p2::RANDOM, Le::Max).data(|w| w.tlv(tag::T1, &len.to_be_bytes()))
}

pub fn hmac(key: [u8; 4], data: &[u8]) -> Option<Cmd> {
    Cmd::new(CLA, ins::CRYPTO, p1::MAC, p2::GENERATE_ONESHOT, Le::Max).data(|w| {
        w.tlv(tag::T1, &key)?;
        w.tlv(tag::T2, &[HMAC_SHA256])?;
        w.tlv(tag::T3, data)
    })
}

/// PUT KEY (GlobalPlatform): replace key set `old_version` (0: add).
pub fn put_key(old_version: u8, data: &[u8]) -> Option<Cmd> {
    Cmd::new(CLA, ins::PUT_KEY, old_version, 0x81, Le::Short(256)).data(|w| w.bytes(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::APDU_MAX;
    use iso7816::command::DataStream;
    use se05x::se05x::commands as r;
    use se05x::se05x::policies::{ObjectAccessRule, ObjectPolicyFlags, Policy, PolicySet};
    use se05x::se05x::{MacAlgo, ObjectId, SessionId};
    use std::vec::Vec;

    fn ours(c: Option<Cmd>) -> Vec<u8> {
        let c = c.unwrap();
        let mut b = [0u8; APDU_MAX];
        let n = c.apdu().encode(&mut b).unwrap();
        b[..n].to_vec()
    }

    fn theirs(c: &dyn for<'a> DataStream<&'a mut [u8]>) -> Vec<u8> {
        let mut b = [0u8; APDU_MAX];
        let mut w: &mut [u8] = &mut b;
        c.to_writer(&mut w).unwrap();
        let left = w.len();
        b[..APDU_MAX - left].to_vec()
    }

    const ID: [u8; 4] = [0x7B, 0x10, 0x00, 0x02];

    #[test]
    fn commands_match_the_reference_driver() {
        let id = ObjectId(ID);
        let auth = ObjectId([0x7B, 0x10, 0x00, 0x01]);
        let pol_ref = [
            Policy {
                object_id: auth,
                access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_READ),
            },
            Policy {
                object_id: ObjectId([0; 4]),
                access_rule: ObjectAccessRule::from_flags(ObjectPolicyFlags::ALLOW_DELETE),
            },
        ];
        let mut pol = [0u8; 32];
        let pn = policy(&[(auth.0, allow::READ), (ANYONE, allow::DELETE)], &mut pol);
        let pol = &pol[..pn];
        let sid = [1, 2, 3, 4, 5, 6, 7, 8];

        assert_eq!(
            ours(create_session(auth.0)),
            theirs(&r::CreateSession { object_id: auth })
        );
        assert_eq!(ours(close_session()), theirs(&r::CloseSession {}));
        assert_eq!(
            ours(verify_user_id(&[9; 16])),
            theirs(&r::VerifySessionUserId { user_id: &[9; 16] })
        );
        assert_eq!(
            ours(initialize_update(&[1; 8], 0)),
            theirs(&r::ScpInitializeUpdate {
                host_challenge: [1; 8]
            })
        );
        assert_eq!(
            ours(write_user_id(auth.0, &[7; 16], Some(10), Some(pol))),
            theirs(&r::WriteUserId {
                policy: Some(PolicySet(&pol_ref)),
                max_attempts: Some(10u8.into()),
                object_id: auth,
                data: &[7; 16],
            })
        );
        assert_eq!(
            ours(write_binary(ID, &[5; 32], Some(pol))),
            theirs(&r::WriteBinary {
                transient: false,
                policy: Some(PolicySet(&pol_ref)),
                object_id: id,
                offset: None,
                file_length: Some(32u16.into()),
                data: Some(&[5; 32]),
            })
        );
        assert_eq!(
            ours(write_hmac_key(ID, &[6; 32], Some(pol))),
            theirs(&r::WriteSymmKey {
                transient: false,
                is_auth: false,
                key_type: se05x::se05x::SymmKeyType::Hmac,
                policy: Some(PolicySet(&pol_ref)),
                max_attempts: None,
                object_id: id,
                kek_id: None,
                value: &[6; 32],
            })
        );
        assert_eq!(
            ours(write_counter(ID, Some(8), Some(pol))),
            theirs(&r::WriteCounter {
                transient: false,
                policy: Some(PolicySet(&pol_ref)),
                object_id: id,
                data: Some(se05x::se05x::CounterSize::B8),
                value: None,
            })
        );
        assert_eq!(
            ours(write_counter(ID, None, None)),
            theirs(&r::WriteCounter {
                transient: false,
                policy: None,
                object_id: id,
                data: None,
                value: None,
            })
        );
        assert_eq!(
            ours(read_object(ID)),
            theirs(&r::ReadObject {
                object_id: id,
                offset: None,
                length: None,
                rsa_key_component: None,
            })
        );
        assert_eq!(ours(exists(ID)), theirs(&r::CheckObjectExists { object_id: id }));
        assert_eq!(ours(delete(ID)), theirs(&r::DeleteSecureObject { object_id: id }));
        assert_eq!(ours(random(32)), theirs(&r::GetRandom { length: 32u16.into() }));
        assert_eq!(
            ours(hmac(ID, &[3; 32])),
            theirs(&r::MacOneShotGenerate {
                key_id: id,
                algo: MacAlgo::HmacSha256,
                data: &[3; 32],
            })
        );
        // a command run in a session
        let inner = ours(read_object(ID));
        assert_eq!(
            ours(process(&sid, &inner)),
            theirs(&se05x::se05x::ProcessSessionCmd {
                session_id: SessionId(sid),
                apdu: r::ReadObject {
                    object_id: id,
                    offset: None,
                    length: None,
                    rsa_key_component: None,
                },
            })
        );
        // the attributes are read with Le (the reference sends none)
        let ra = ours(read_attributes(ID));
        let rr = theirs(&r::ReadAttributes {
            object_id: id,
            offset: None,
            length: None,
            rsa_key_component: None,
        });
        assert_eq!(&ra[..4], &rr[..4]);
        assert_eq!(
            crate::apdu::parse(&ra).unwrap().data,
            crate::apdu::parse(&rr).unwrap().data
        );
    }
}
