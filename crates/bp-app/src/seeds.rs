//! A loaded seed: mnemonic, optional passphrase, and the cached master key
//! (PBKDF2 runs once per load, not on every screen). Wiped on drop.

use bp_bitcoin::address::{self, ScriptType};
use bp_bitcoin::bip32::{Xpriv, Xpub};
use bp_bitcoin::bip39::Mnemonic;
use bp_bitcoin::Network;
use bp_crypto::secret::wipe;

pub const MAX_PASSPHRASE: usize = 100;

pub struct SeedSlot {
    pub mnemonic: Mnemonic,
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
            mnemonic,
            passphrase: p,
            passphrase_len: passphrase.len(),
            master,
            fingerprint,
        })
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
