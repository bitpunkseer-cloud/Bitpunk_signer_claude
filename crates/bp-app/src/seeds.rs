//! A loaded seed: mnemonic, optional passphrase, and the cached master key
//! (PBKDF2 runs once per load, not on every screen). Wiped on drop.
//!
//! A slot can also hold an imported key (M8 plan §8): an XPRV, used as the
//! root (its own fingerprint, every feature but the words), or a WIF, a
//! single key (its four scripts only: no xpub, multisig or BIP-85).
//!
//! A SLIP-39 wallet (M11-2) keeps its encrypted master secret, as a words
//! slot keeps its words: the passphrase decrypts it into the BIP-32 seed,
//! and further share sets are made from it.

use bp_backup::slip39::Ems;
use bp_bitcoin::address::{self, ScriptType};
use bp_bitcoin::bip32::{Xpriv, Xpub};
use bp_bitcoin::bip39::Mnemonic;
use bp_bitcoin::Network;
use bp_crypto::secret::wipe;

pub const MAX_PASSPHRASE: usize = 100;

/// What a slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    Mnemonic,
    Xprv,
    Wif,
    /// A SLIP-39 wallet (M11-2).
    Slip39,
}

pub struct SeedSlot {
    /// `None` for an imported key.
    pub mnemonic: Option<Mnemonic>,
    pub kind: SlotKind,
    /// A SLIP-39 wallet's encrypted master secret.
    pub ems: Option<Ems>,
    passphrase: [u8; MAX_PASSPHRASE],
    passphrase_len: usize,
    master: Xpriv,
    pub fingerprint: [u8; 4],
}

impl SeedSlot {
    /// `passphrase` must be printable ASCII (the keyboard only produces that).
    pub fn new(mnemonic: Mnemonic, passphrase: &[u8]) -> Option<SeedSlot> {
        let pass = core::str::from_utf8(passphrase).ok()?;
        if passphrase.len() > MAX_PASSPHRASE {
            return None;
        }
        let seed = mnemonic.to_seed(pass).ok()?;
        // An invalid master key has probability ~2^-127; treat as unusable.
        let master = Xpriv::master(seed.expose()).ok()?;
        let fingerprint = master.fingerprint();
        let mut p = [0u8; MAX_PASSPHRASE];
        p[..passphrase.len()].copy_from_slice(passphrase);
        Some(SeedSlot {
            mnemonic: Some(mnemonic),
            kind: SlotKind::Mnemonic,
            ems: None,
            passphrase: p,
            passphrase_len: passphrase.len(),
            master,
            fingerprint,
        })
    }

    /// An imported extended private key, used as the root.
    pub fn from_xprv(master: Xpriv) -> SeedSlot {
        let fingerprint = master.fingerprint();
        SeedSlot {
            mnemonic: None,
            kind: SlotKind::Xprv,
            ems: None,
            passphrase: [0; MAX_PASSPHRASE],
            passphrase_len: 0,
            master,
            fingerprint,
        }
    }

    /// An imported single key (WIF). The key is held as a depth-0 extended
    /// key with a zero chain code so the validator and signer can take it;
    /// only its own scripts are ever used (`Context::single_key`).
    pub fn from_wif(sk: &bp_crypto::secp256k1::SecretKey) -> Option<SeedSlot> {
        let mut k = sk.to_bytes();
        let master = Xpriv::from_parts(&[0; 32], &k).ok();
        wipe(&mut k);
        let master = master?;
        let fingerprint = master.fingerprint();
        Some(SeedSlot {
            mnemonic: None,
            kind: SlotKind::Wif,
            ems: None,
            passphrase: [0; MAX_PASSPHRASE],
            passphrase_len: 0,
            master,
            fingerprint,
        })
    }

    /// A SLIP-39 wallet: the encrypted master secret decrypted with
    /// `passphrase` (printable ASCII) is the BIP-32 seed.
    pub fn from_slip39(ems: Ems, passphrase: &[u8]) -> Option<SeedSlot> {
        if passphrase.len() > MAX_PASSPHRASE {
            return None;
        }
        let ms = ems.decrypt(passphrase).ok()?;
        let master = Xpriv::master(ms.expose()).ok()?;
        let fingerprint = master.fingerprint();
        let mut p = [0u8; MAX_PASSPHRASE];
        p[..passphrase.len()].copy_from_slice(passphrase);
        Some(SeedSlot {
            mnemonic: None,
            kind: SlotKind::Slip39,
            ems: Some(ems),
            passphrase: p,
            passphrase_len: passphrase.len(),
            master,
            fingerprint,
        })
    }

    /// The same words or SLIP-39 wallet with another passphrase.
    pub fn with_passphrase(&self, passphrase: &[u8]) -> Option<SeedSlot> {
        match self.kind {
            SlotKind::Mnemonic => SeedSlot::new(self.mnemonic.clone()?, passphrase),
            SlotKind::Slip39 => SeedSlot::from_slip39(self.ems.clone()?, passphrase),
            SlotKind::Xprv | SlotKind::Wif => None,
        }
    }

    /// Words in each share of a SLIP-39 wallet (20 or 33).
    pub fn share_words(&self) -> usize {
        self.ems
            .as_ref()
            .map_or(0, |e| bp_backup::slip39::share_words(e.len()))
    }

    /// A single imported key (WIF).
    pub fn single_key(&self) -> bool {
        self.kind == SlotKind::Wif
    }

    /// The master key (validation and signing only).
    pub(crate) fn master(&self) -> &Xpriv {
        &self.master
    }

    pub fn has_passphrase(&self) -> bool {
        self.passphrase_len > 0
    }

    pub fn passphrase(&self) -> &[u8] {
        &self.passphrase[..self.passphrase_len]
    }

    pub fn account_xpub(&self, st: ScriptType, net: Network, account: u32) -> Option<Xpub> {
        let k = self.master.derive_path(&st.account_path(net, account)).ok()?;
        Some(k.to_xpub())
    }

    /// Address `index` on the receive (`change == false`) or change chain.
    pub fn address(
        &self,
        st: ScriptType,
        net: Network,
        account: u32,
        change: bool,
        index: u32,
        out: &mut [u8; address::MAX_ADDRESS_LEN],
    ) -> Option<usize> {
        let chain = self
            .account_xpub(st, net, account)?
            .derive_child(change as u32)
            .ok()?;
        Some(address::encode(
            &chain.derive_child(index).ok()?.key,
            st,
            net,
            out,
        ))
    }
}

impl Drop for SeedSlot {
    fn drop(&mut self) {
        wipe(&mut self.passphrase);
        // mnemonic and master key wipe themselves
    }
}

/// Hex fingerprint, e.g. "73c5da0a".
pub fn fingerprint_hex(fp: &[u8; 4]) -> bp_ui::fmt::Buf<8> {
    bp_ui::bformat!(8, "{:02x}{:02x}{:02x}{:02x}", fp[0], fp[1], fp[2], fp[3])
}
