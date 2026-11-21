//! PSBT serialization into a `Sink` (a hash or a buffer).

use super::parse::{Pairs, Psbt};
use super::MAGIC;
use crate::tx::{put_compact_size, Sink};

fn compact_len(n: u64) -> usize {
    match n {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

pub fn put_magic<S: Sink + ?Sized>(s: &mut S) {
    s.put(MAGIC);
}

/// A pair from its key type, key data and value.
pub fn put_pair<S: Sink + ?Sized>(s: &mut S, key_type: u64, key_data: &[u8], value: &[u8]) {
    put_compact_size(s, (compact_len(key_type) + key_data.len()) as u64);
    put_compact_size(s, key_type);
    s.put(key_data);
    put_compact_size(s, value.len() as u64);
    s.put(value);
}

/// A pair from its whole key (type and data) and value.
pub fn put_raw_pair<S: Sink + ?Sized>(s: &mut S, key: &[u8], value: &[u8]) {
    put_compact_size(s, key.len() as u64);
    s.put(key);
    put_compact_size(s, value.len() as u64);
    s.put(value);
}

pub fn put_separator<S: Sink + ?Sized>(s: &mut S) {
    s.put(&[0]);
}

fn put_map<S: Sink + ?Sized>(s: &mut S, pairs: Pairs) {
    for p in pairs {
        put_raw_pair(s, p.key, p.value);
    }
    put_separator(s);
}

impl Psbt<'_> {
    /// Serialize every map as parsed (byte-identical to the input).
    pub fn write<S: Sink + ?Sized>(&self, s: &mut S) {
        put_magic(s);
        put_map(s, self.global_pairs());
        for m in self.inputs() {
            put_map(s, m.pairs());
        }
        for m in self.outputs() {
            put_map(s, m.pairs());
        }
    }
}
