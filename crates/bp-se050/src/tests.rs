//! The driver against the simulated chip, through every layer.

use crate::device::obj;
use crate::mock::{MockSe050, TestRng};
use crate::scp03::StaticKeys;
use crate::t1::{I2c, Nack};
use crate::Se050;
use bp_hal::secure::{SeError, SeState, SecureElement};
use std::vec::Vec;

fn keys() -> StaticKeys {
    StaticKeys {
        enc: [0x40; 16],
        mac: [0x41; 16],
        dek: [0x42; 16],
        version: 0x0B,
    }
}

/// The bus with everything that crosses it recorded.
struct Tap {
    chip: MockSe050,
    wire: Vec<u8>,
}

impl I2c for Tap {
    fn write(&mut self, data: &[u8]) -> Result<(), Nack> {
        self.wire.extend_from_slice(data);
        self.chip.write(data)
    }
    fn read(&mut self, buf: &mut [u8]) -> Result<(), Nack> {
        let r = self.chip.read(buf);
        if r.is_ok() {
            self.wire.extend_from_slice(buf);
        }
        r
    }
    fn delay_us(&mut self, _: u32) {}
}

fn device(chip: u64) -> Se050<Tap, TestRng> {
    Se050::new(
        Tap {
            chip: MockSe050::new(chip, keys()),
            wire: Vec::new(),
        },
        keys(),
        TestRng(chip ^ 0x9E37),
    )
}

const A: [u8; 32] = [7; 32];
const B: [u8; 32] = [8; 32];

#[test]
fn the_vault_rules_hold_through_the_driver() {
    let mut se = device(1);
    assert_eq!(se.state(), Ok(SeState::Blank));
    assert_eq!(se.unlock(&A, &mut [0; 32]), Err(SeError::Blank));
    assert_eq!(se.counter(), Ok(0));
    se.provision(&A, 10).unwrap();
    assert_eq!(se.provision(&A, 10), Err(SeError::Exists));
    assert_eq!(se.state(), Ok(SeState::Ready { left: 10 }));
    let mut s = [0u8; 32];
    se.unlock(&A, &mut s).unwrap();
    assert_eq!(
        Some(s.to_vec()),
        se.bus().chip.peek_binary(obj::SECRET),
        "the element's secret"
    );
    // wrong: one attempt each; right: the count starts over
    assert_eq!(se.unlock(&B, &mut [0; 32]), Err(SeError::WrongAuth { left: 9 }));
    assert_eq!(se.unlock(&B, &mut [0; 32]), Err(SeError::WrongAuth { left: 8 }));
    se.unlock(&A, &mut [0; 32]).unwrap();
    assert_eq!(se.state(), Ok(SeState::Ready { left: 10 }));
    // change the authenticator
    se.change_auth(&A, &B).unwrap();
    assert_eq!(se.unlock(&A, &mut [0; 32]), Err(SeError::WrongAuth { left: 9 }));
    let mut s2 = [0u8; 32];
    se.unlock(&B, &mut s2).unwrap();
    assert_eq!(s, s2, "the secret stays");
    // ten wrong: locked for good
    for left in (0..10).rev() {
        assert_eq!(se.unlock(&A, &mut [0; 32]), Err(SeError::WrongAuth { left }));
    }
    assert_eq!(se.state(), Ok(SeState::Locked));
    assert_eq!(se.unlock(&B, &mut [0; 32]), Err(SeError::Locked));
    // the HMAC key and the counter outlive destroy
    let mut h1 = [0u8; 32];
    se.hmac(b"words", &mut h1).unwrap();
    assert_eq!(se.bump_counter(), Ok(1));
    assert_eq!(se.bump_counter(), Ok(2));
    se.destroy().unwrap();
    assert_eq!(se.state(), Ok(SeState::Blank));
    let mut h2 = [0u8; 32];
    se.hmac(b"words", &mut h2).unwrap();
    assert_eq!(h1, h2);
    assert_eq!(se.counter(), Ok(2));
    // a new secret after a new provision
    se.provision(&A, 10).unwrap();
    let mut s3 = [0u8; 32];
    se.unlock(&A, &mut s3).unwrap();
    assert_ne!(s3, s);
}

#[test]
fn nothing_secret_crosses_the_bus_in_the_clear() {
    let mut se = device(2);
    se.provision(&A, 10).unwrap();
    let mut s = [0u8; 32];
    se.unlock(&A, &mut s).unwrap();
    let wire = &se.bus().wire;
    let has = |needle: &[u8]| wire.windows(needle.len()).any(|w| w == needle);
    assert!(!has(&s[..12]), "the secret");
    assert!(!has(&A[..12]), "the authenticator");
    // but the plain APDUs (behind SCP03) did carry the UserID
    let log = &se.bus().chip.log;
    assert!(log.iter().any(|a| a.windows(12).any(|w| w == &A[..12])));
}

#[test]
fn the_link_survives_busy_chips_damaged_frames_and_waits() {
    let mut se = device(3);
    se.provision(&A, 10).unwrap();
    let mut s = [0u8; 32];
    // busy for less than the block waiting time (BWT 10 ms, polled every 1 ms)
    se.bus().chip.busy = 8;
    se.unlock(&A, &mut s).unwrap();
    se.bus().chip.corrupt_next = true;
    se.unlock(&A, &mut s).unwrap();
    se.bus().chip.wtx_next = true;
    se.unlock(&A, &mut s).unwrap();
    // a long command goes out in chained blocks...
    let mut h = [0u8; 32];
    se.hmac(&[0x5A; 480], &mut h).unwrap();
    let mut want = [0u8; 32];
    se.hmac(&[0x5A; 480], &mut want).unwrap();
    assert_eq!(h, want);
    // ...and a long answer comes back so
    let mut r = [0u8; 256];
    se.random_bytes(&mut r).unwrap();
    assert!(r.iter().any(|&b| b != 0));
}

#[test]
fn wrong_channel_keys_or_no_channel_are_refused() {
    let mut chip = MockSe050::new(4, keys());
    let mut other = keys();
    other.mac[0] ^= 1;
    let mut se = Se050::new(
        Tap {
            chip: chip.clone(),
            wire: Vec::new(),
        },
        other,
        TestRng(4),
    );
    assert_eq!(se.state(), Err(SeError::Bus), "another chip, or another key set");
    // commands without SCP03 are refused by the chip
    chip.require_scp = true;
    let mut a = [0u8; 600];
    let c = crate::cmd::exists(obj::AUTH).unwrap();
    let n = c.apdu().encode(&mut a).unwrap();
    let mut t = crate::t1::T1::new(chip);
    let mut atr = [0u8; crate::t1::IFS];
    t.soft_reset(&mut atr).unwrap();
    let mut r = [0u8; 600];
    let m = t.transceive(&a[..n], &mut r).unwrap();
    assert_eq!(&r[..m], &[0x69, 0x82]);
}

#[test]
fn rotated_keys_replace_the_old_ones() {
    let mut se = device(5);
    se.provision(&A, 10).unwrap();
    let new = StaticKeys {
        enc: [0x51; 16],
        mac: [0x52; 16],
        dek: [0x53; 16],
        version: 0x0C,
    };
    se.rotate_keys(new.clone()).unwrap();
    // the driver goes on with the new keys
    let mut s = [0u8; 32];
    se.unlock(&A, &mut s).unwrap();
    // the old ones open nothing any more
    let chip = se.bus().chip.clone();
    let mut old = Se050::new(
        Tap {
            chip,
            wire: Vec::new(),
        },
        keys(),
        TestRng(9),
    );
    assert_eq!(old.state(), Err(SeError::Bus));
}

#[test]
fn a_power_cut_anywhere_in_provision_leaves_blank_or_ready() {
    for cut in 0..40 {
        let mut se = device(6);
        se.bus().chip.apdus_left = Some(cut);
        let r = se.provision(&A, 10);
        // the device powers up again: the chip and the driver start over
        se.bus().chip.power_on();
        se.reset();
        match se.state().unwrap() {
            SeState::Blank => {
                assert!(r.is_err() || cut > 30, "cut {cut}");
                se.provision(&A, 10).unwrap();
            }
            SeState::Ready { left: 10 } => {}
            s => panic!("cut {cut}: {s:?}"),
        }
        let mut s = [0u8; 32];
        se.unlock(&A, &mut s)
            .unwrap_or_else(|e| panic!("cut {cut}: {e:?}"));
    }
}
