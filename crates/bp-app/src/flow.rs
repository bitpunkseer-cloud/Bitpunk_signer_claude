//! State of the seed flow in progress (create from dice/coin, or type words).
//! Dropped — and wiped — as soon as the user leaves the flow.

use crate::menus::Start;
use bp_bitcoin::bip39::{self, Mnemonic, MAX_WORDS, WORDS};
use bp_bitcoin::entropy::{PhysicalEntropy, Source};
use bp_crypto::drbg::Drbg;

pub const MAX_INPUT: usize = 8;

pub struct Flow {
    pub kind: Start,
    pub words: usize,
    pub entropy: Option<PhysicalEntropy>,
    pub mnemonic: Option<Mnemonic>,
    pub entry: WordEntry,
    pub quiz: Quiz,
}

impl Flow {
    pub fn new(kind: Start, words: usize) -> Self {
        let entropy = match kind {
            Start::Dice => Some(PhysicalEntropy::new(Source::Dice, words)),
            Start::Coin => Some(PhysicalEntropy::new(Source::Coin, words)),
            _ => None,
        };
        Self {
            kind,
            words,
            entropy,
            mnemonic: None,
            entry: WordEntry::new(words),
            quiz: Quiz::default(),
        }
    }

    pub fn numbers_mode(&self) -> bool {
        self.kind == Start::WordNumbers
    }
}

/// Typing words (or word numbers) one at a time.
pub struct WordEntry {
    pub n: usize,
    pub idx: [u16; MAX_WORDS],
    pub filled: [bool; MAX_WORDS],
    pub pos: usize,
    pub input: [u8; MAX_INPUT],
    pub input_len: usize,
    /// Selected candidate within the prefix range.
    pub cand: usize,
    /// Re-entering a single word after a checksum error.
    pub fixing: Option<usize>,
    /// After an auto-accept: (word, letters already typed). Further letters
    /// that continue the same word are swallowed, so typing "aban" and
    /// typing "abandon" both work.
    pub tail: Option<(u16, usize)>,
}

impl WordEntry {
    pub fn new(n: usize) -> Self {
        Self {
            n,
            idx: [0; MAX_WORDS],
            filled: [false; MAX_WORDS],
            pos: 0,
            input: [0; MAX_INPUT],
            input_len: 0,
            cand: 0,
            fixing: None,
            tail: None,
        }
    }

    pub fn input(&self) -> &str {
        core::str::from_utf8(&self.input[..self.input_len]).unwrap_or("")
    }

    pub fn clear_input(&mut self) {
        self.input = [0; MAX_INPUT];
        self.input_len = 0;
        self.cand = 0;
    }

    pub fn complete(&self) -> bool {
        self.filled[..self.n].iter().all(|f| *f)
    }

    pub fn indices(&self) -> &[u16] {
        &self.idx[..self.n]
    }

    /// Candidates for the current letters (word mode).
    pub fn candidates(&self) -> core::ops::Range<usize> {
        bip39::prefix_range(self.input())
    }

    /// Word for the typed number (number mode), 1-based.
    pub fn number_value(&self) -> Option<u16> {
        let s = self.input();
        if s.is_empty() {
            return None;
        }
        let v: u32 = s.parse().ok()?;
        (1..=2048).contains(&v).then(|| (v - 1) as u16)
    }

    /// Try to append a typed character. Returns false if rejected.
    pub fn push_char(&mut self, ch: char, numbers: bool) -> bool {
        if let Some((w, typed)) = self.tail {
            let word = WORDS[w as usize].as_bytes();
            if !numbers && typed < word.len() && ch.to_ascii_lowercase() as u8 == word[typed] {
                self.tail = if typed + 1 < word.len() {
                    Some((w, typed + 1))
                } else {
                    None
                };
                return true; // continuation of the word just accepted
            }
            self.tail = None;
        }
        if self.input_len >= MAX_INPUT {
            return false;
        }
        let c = if numbers {
            if !ch.is_ascii_digit() || self.input_len >= 4 {
                return false;
            }
            ch as u8
        } else {
            if !ch.is_ascii_alphabetic() {
                return false;
            }
            ch.to_ascii_lowercase() as u8
        };
        self.input[self.input_len] = c;
        self.input_len += 1;
        if !numbers && self.candidates().is_empty() {
            self.input_len -= 1;
            self.input[self.input_len] = 0;
            return false;
        }
        self.cand = 0;
        true
    }

    pub fn backspace_char(&mut self) -> bool {
        if self.input_len == 0 {
            return false;
        }
        self.input_len -= 1;
        self.input[self.input_len] = 0;
        self.cand = 0;
        true
    }

    /// True when the typed letters should be accepted without Enter:
    /// a single candidate, and either 4+ letters or the whole word typed.
    pub fn auto_accept_ready(&self) -> bool {
        let r = self.candidates();
        r.len() == 1 && (self.input_len >= bip39::UNIQUE_PREFIX_LEN || WORDS[r.start].len() == self.input_len)
    }

    /// Accept automatically, remembering the word so its remaining letters
    /// can be swallowed if the user keeps typing it.
    pub fn auto_accept(&mut self) {
        let w = self.candidates().start as u16;
        let typed = self.input_len;
        self.accept(w);
        let len = WORDS[w as usize].len();
        self.tail = if typed < len { Some((w, typed)) } else { None };
    }

    /// Place `word` at the current position and advance.
    pub fn accept(&mut self, word: u16) {
        self.tail = None;
        self.idx[self.pos] = word;
        self.filled[self.pos] = true;
        self.clear_input();
        if self.fixing.take().is_some() {
            self.pos = self.first_empty().unwrap_or(self.n - 1);
        } else if self.pos + 1 < self.n {
            self.pos += 1;
        }
    }

    fn first_empty(&self) -> Option<usize> {
        (0..self.n).find(|&i| !self.filled[i])
    }

    /// Remove the previous word (Backspace on an empty input).
    pub fn step_back(&mut self) {
        let target = if self.filled[self.pos] {
            self.pos
        } else {
            self.pos.saturating_sub(1)
        };
        if self.filled[target] {
            self.filled[target] = false;
            self.idx[target] = 0;
            self.pos = target;
        }
    }

    pub fn start_fix(&mut self, i: usize) {
        self.fixing = Some(i);
        self.pos = i;
        self.clear_input();
    }

    pub fn word_at(&self, i: usize) -> &'static str {
        if self.filled[i] {
            WORDS[self.idx[i] as usize]
        } else {
            ""
        }
    }
}

impl Drop for WordEntry {
    fn drop(&mut self) {
        for v in self.idx.iter_mut() {
            // SAFETY: valid exclusive reference.
            unsafe { core::ptr::write_volatile(v, 0) };
        }
        bp_crypto::secret::wipe(&mut self.input);
    }
}

/// Multiple-choice check of every word, in random order.
#[derive(Default)]
pub struct Quiz {
    pub n: usize,
    pub order: [u8; MAX_WORDS],
    pub options: [[u16; 4]; MAX_WORDS],
    pub answer: [u8; MAX_WORDS],
    pub q: usize,
}

impl Quiz {
    /// Build questions for `m`. The shuffler is not used for seed material.
    pub fn new(m: &Mnemonic, rng: &mut Drbg) -> Self {
        let n = m.len();
        let mut quiz = Quiz {
            n,
            ..Default::default()
        };
        for i in 0..n {
            quiz.order[i] = i as u8;
        }
        for i in (1..n).rev() {
            let j = rng.below(i as u32 + 1) as usize;
            quiz.order.swap(i, j);
        }
        for q in 0..n {
            let correct = m.indices()[quiz.order[q] as usize];
            let mut opts = [correct; 4];
            let mut k = 1;
            while k < 4 {
                let cand = rng.below(2048) as u16;
                if !opts[..k].contains(&cand) {
                    opts[k] = cand;
                    k += 1;
                }
            }
            let pos = rng.below(4) as usize;
            opts.swap(0, pos);
            quiz.options[q] = opts;
            quiz.answer[q] = pos as u8;
        }
        quiz
    }

    pub fn done(&self) -> bool {
        self.q >= self.n
    }

    /// Word position (0-based) asked by the current question.
    pub fn word_pos(&self) -> usize {
        self.order[self.q] as usize
    }
}

impl Drop for Quiz {
    fn drop(&mut self) {
        for row in self.options.iter_mut() {
            for v in row.iter_mut() {
                // SAFETY: valid exclusive reference.
                unsafe { core::ptr::write_volatile(v, 0) };
            }
        }
    }
}
