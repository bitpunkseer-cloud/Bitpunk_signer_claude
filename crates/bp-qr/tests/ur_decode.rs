//! UR decoder against parts made by the independent `ur` crate (test-only)
//! and by our encoder: single and multipart, lost frames, upper case,
//! parts of another message, corruption.

use bp_qr::ur::decoder::{decode_bytewords, Error, UrDecoder};
use bp_qr::ur::{bytewords_minimal, UrEncoder};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn bytewords_round_trip_and_errors() {
    let mut rng = Rng(1);
    for len in [0usize, 1, 10, 300] {
        let data = rng.bytes(len);
        let mut text = vec![0u8; (len + 4) * 2];
        bytewords_minimal(&data, &mut text).unwrap();
        let mut out = vec![0u8; len.max(1)];
        assert_eq!(decode_bytewords(&text, &mut out), Ok(len));
        assert_eq!(&out[..len], &data[..]);
        // upper case is fine
        let upper = text.to_ascii_uppercase();
        assert_eq!(decode_bytewords(&upper, &mut out), Ok(len));
        // a changed letter breaks the pair table or the CRC
        let mut bad = text.clone();
        bad[0] = if bad[0] == b'a' { b'b' } else { b'a' };
        assert!(decode_bytewords(&bad, &mut out).is_err());
    }
}

#[test]
fn single_part_from_reference() {
    let mut rng = Rng(2);
    let data = rng.bytes(120);
    let text = ur::ur::encode(&data, &ur::Type::Bytes);
    for t in [text.clone(), text.to_uppercase()] {
        let mut store = vec![0u8; 1024];
        let mut dec = UrDecoder::new(&mut store);
        assert_eq!(dec.receive(t.as_bytes()), Ok(true));
        assert_eq!(dec.ur_type(), "bytes");
        assert_eq!(dec.message().unwrap(), &data[..]);
        assert_eq!(dec.progress(), (1, 1));
    }
}

fn run_reference(len: usize, frag: usize, drop_every: usize, seed: u64) -> usize {
    let mut rng = Rng(seed);
    let data = rng.bytes(len);
    let mut enc = ur::Encoder::new(&data, frag, "crypto-psbt").unwrap();
    let mut store = vec![0u8; 256 * 1024];
    let mut dec = UrDecoder::new(&mut store);
    let mut sent = 0;
    loop {
        let p = enc.next_part().unwrap();
        sent += 1;
        if drop_every != 0 && sent % drop_every == 0 {
            continue;
        }
        let p = if sent % 2 == 0 { p.to_uppercase() } else { p };
        if dec.receive(p.as_bytes()).unwrap() {
            break;
        }
        assert!(
            sent < 20 * (len / frag + 2),
            "len {len} frag {frag}: no convergence"
        );
    }
    assert_eq!(dec.ur_type(), "crypto-psbt");
    assert_eq!(dec.message().unwrap(), &data[..], "len {len} frag {frag}");
    sent
}

#[test]
fn multipart_from_reference_in_order() {
    for (len, frag) in [
        (50usize, 20usize),
        (300, 30),
        (1000, 100),
        (5000, 400),
        (20000, 250),
    ] {
        let sent = run_reference(len, frag, 0, len as u64);
        // with no losses the pure parts are enough
        let seq_len = ur::Encoder::new(&vec![0u8; len], frag, "x")
            .unwrap()
            .fragment_count();
        assert_eq!(sent, seq_len, "len {len}");
    }
}

#[test]
fn multipart_with_lost_frames() {
    for (len, frag, drop) in [
        (300usize, 30usize, 3usize),
        (1000, 50, 2),
        (3000, 150, 3),
        (8000, 200, 4),
    ] {
        for seed in 0..5 {
            run_reference(len, frag, drop, seed * 31 + len as u64);
        }
    }
}

#[test]
fn our_encoder_round_trip_skipping_the_pure_parts() {
    let mut rng = Rng(5);
    let data = rng.bytes(2000);
    let enc = UrEncoder::new("crypto-psbt", &data, 100).unwrap();
    let mut store = vec![0u8; 64 * 1024];
    let mut dec = UrDecoder::new(&mut store);
    // start after all pure parts: only fountain parts
    let mut seq = enc.seq_len() as u32 + 1;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = enc.part(seq, &mut buf).unwrap();
        if dec.receive(&buf[..n]).unwrap() {
            break;
        }
        seq += 1;
        assert!(seq < 200, "no convergence");
    }
    assert_eq!(dec.message().unwrap(), &data[..]);
}

#[test]
fn foreign_parts_are_rejected_without_losing_progress() {
    let mut rng = Rng(6);
    let a = rng.bytes(600);
    let b = rng.bytes(600);
    let mut ea = ur::Encoder::new(&a, 100, "crypto-psbt").unwrap();
    let mut eb = ur::Encoder::new(&b, 100, "crypto-psbt").unwrap();
    let mut ec = ur::Encoder::new(&a, 100, "crypto-output").unwrap();
    let mut store = vec![0u8; 64 * 1024];
    let mut dec = UrDecoder::new(&mut store);
    dec.receive(ea.next_part().unwrap().as_bytes()).unwrap();
    assert_eq!(
        dec.receive(eb.next_part().unwrap().as_bytes()),
        Err(Error::Mismatch)
    );
    assert_eq!(
        dec.receive(ec.next_part().unwrap().as_bytes()),
        Err(Error::Mismatch)
    );
    assert_eq!(
        dec.receive(ur::ur::encode(&a, &ur::Type::Bytes).as_bytes()),
        Err(Error::Mismatch)
    );
    while !dec.receive(ea.next_part().unwrap().as_bytes()).unwrap() {}
    assert_eq!(dec.message().unwrap(), &a[..]);
}

#[test]
fn garbage_never_panics() {
    let mut rng = Rng(7);
    let mut store = vec![0u8; 16 * 1024];
    let mut dec = UrDecoder::new(&mut store);
    let samples = [
        "ur:",
        "ur:bytes/",
        "ur:bytes/1-0/abcd",
        "ur:bytes/0-3/abcd",
        "ur:by tes/aeae",
        "UR:BYTES/1-3/LPADAXCFAXHLCYJTWNMEADHDGRINJNHKFXGAAYCFNSFDISBNIHNTRF",
        "hello",
    ];
    for s in samples {
        let _ = dec.receive(s.as_bytes());
    }
    let data = rng.bytes(500);
    let mut enc = ur::Encoder::new(&data, 60, "crypto-psbt").unwrap();
    for _ in 0..300 {
        let mut p = enc.next_part().unwrap().into_bytes();
        let i = (rng.next() as usize) % p.len();
        p[i] = b"abcdefghijklmnopqrstuvwxyz/-0123456789"[(rng.next() % 38) as usize];
        let _ = dec.receive(&p);
    }
}
