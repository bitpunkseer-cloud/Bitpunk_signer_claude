//! Inflate against miniz_oxide (test-only) at every compression level,
//! plus corrupted and truncated streams.

use bp_qr::inflate::{inflate, Error};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn sample(rng: &mut Rng, len: usize, kind: usize) -> Vec<u8> {
    match kind {
        // random bytes (stored / dynamic blocks with flat statistics)
        0 => (0..len).map(|_| rng.next() as u8).collect(),
        // text-like: small alphabet with repeats
        1 => (0..len)
            .map(|_| b"abcdefgh  \n"[(rng.next() % 11) as usize])
            .collect(),
        // PSBT-like: repeated structures with random keys
        _ => {
            let mut v = Vec::new();
            while v.len() < len {
                v.extend_from_slice(b"\x00\x01\x00\x55\x02\x00\x00\x00\x01");
                for _ in 0..33 {
                    v.push(rng.next() as u8);
                }
                v.extend_from_slice(b"\xff\xff\xff\xff\x01\x00\xe1\xf5\x05");
            }
            v.truncate(len);
            v
        }
    }
}

#[test]
fn matches_miniz_at_every_level() {
    let mut rng = Rng(1);
    let mut out = vec![0u8; 70_000];
    for i in 0..300 {
        let len = [0, 1, 10, 100, 1000, 5000, 40_000][i % 7];
        let data = sample(&mut rng, len, i % 3);
        let level = (i % 11) as u8;
        let z = miniz_oxide::deflate::compress_to_vec(&data, level);
        let n = inflate(&z, &mut out).unwrap_or_else(|e| panic!("#{i} level {level}: {e:?}"));
        assert_eq!(&out[..n], &data[..], "#{i}");
    }
}

#[test]
fn corrupted_streams_never_panic_or_overrun() {
    let mut rng = Rng(2);
    let mut out = vec![0u8; 20_000];
    let mut caught = 0;
    for i in 0..3000 {
        let data = sample(&mut rng, 2000, i % 3);
        let mut z = miniz_oxide::deflate::compress_to_vec(&data, (i % 10) as u8);
        for _ in 0..1 + i % 4 {
            let p = (rng.next() as usize) % z.len();
            z[p] ^= 1 << (rng.next() % 8);
        }
        match inflate(&z, &mut out) {
            Ok(n) => assert!(n <= out.len()),
            Err(_) => caught += 1,
        }
    }
    // DEFLATE has no checksum: many flips still give a valid (different)
    // stream. The PSBT parser above validates the content; here we only
    // require no panic, no overrun, and that broken structure is caught.
    assert!(caught > 300, "{caught}");
}

#[test]
fn truncation_and_output_limits() {
    let data: Vec<u8> = (0..5000u32).map(|i| (i % 7) as u8).collect();
    let z = miniz_oxide::deflate::compress_to_vec(&data, 6);
    let mut out = vec![0u8; 5000];
    for cut in [0, 1, z.len() / 2, z.len() - 1] {
        assert_eq!(inflate(&z[..cut], &mut out), Err(Error::Truncated), "cut {cut}");
    }
    let mut small = vec![0u8; 4999];
    assert_eq!(inflate(&z, &mut small), Err(Error::OutputFull));
    // a 1 MB "bomb" stops at the buffer
    let bomb = miniz_oxide::deflate::compress_to_vec(&vec![0u8; 1 << 20], 9);
    assert!(bomb.len() < 2000);
    assert_eq!(inflate(&bomb, &mut out), Err(Error::OutputFull));
}
