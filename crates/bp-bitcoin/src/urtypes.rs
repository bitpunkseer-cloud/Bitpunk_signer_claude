//! UR registry types for exporting accounts: `crypto-hdkey` (BCR-2020-007),
//! `crypto-keypath`, `crypto-output` (BCR-2020-010) and `crypto-account`
//! (BCR-2020-015), encoded the way SeedSigner does for Sparrow, Nunchuk,
//! BlueWallet and Keeper.

use crate::address::ScriptType;
use crate::bip32::{DerivationPath, Xpub, HARDENED};
use crate::Network;
use bp_qr::ur::cbor::{Error, Writer};

pub const TAG_HDKEY: u64 = 303;
pub const TAG_KEYPATH: u64 = 304;
pub const TAG_COININFO: u64 = 305;
pub const TAG_SH: u64 = 400;
pub const TAG_PKH: u64 = 403;
pub const TAG_WPKH: u64 = 404;
pub const TAG_TR: u64 = 409;

pub const UR_ACCOUNT: &str = "crypto-account";
pub const UR_OUTPUT: &str = "crypto-output";

/// Account key with its origin, as exported.
pub struct AccountKey<'a> {
    pub xpub: &'a Xpub,
    pub master_fingerprint: [u8; 4],
    pub path: &'a DerivationPath,
    pub script: ScriptType,
    pub network: Network,
}

fn fp_u32(fp: [u8; 4]) -> u64 {
    u32::from_be_bytes(fp) as u64
}

/// `#6.303({3: key, 4: chain code, [5: #6.305({2: 1})], 6: #6.304(origin), 8: parent fp})`
pub fn write_hdkey(w: &mut Writer, k: &AccountKey) -> Result<(), Error> {
    let testnet = k.network != Network::Mainnet;
    w.tag(TAG_HDKEY)?;
    w.map(if testnet { 5 } else { 4 })?;
    w.uint(3)?;
    w.bytes(&k.xpub.key.serialize())?;
    w.uint(4)?;
    w.bytes(&k.xpub.chain_code)?;
    if testnet {
        w.uint(5)?;
        w.tag(TAG_COININFO)?;
        w.map(1)?;
        w.uint(2)?; // network
        w.uint(1)?; // testnet
    }
    w.uint(6)?;
    write_keypath(w, k.path, k.master_fingerprint)?;
    w.uint(8)?;
    w.uint(fp_u32(k.xpub.parent_fingerprint))
}

/// `#6.304({1: [index, hardened, ...], 2: source fingerprint, 3: depth})`
pub fn write_keypath(w: &mut Writer, path: &DerivationPath, source_fp: [u8; 4]) -> Result<(), Error> {
    let steps = path.steps();
    w.tag(TAG_KEYPATH)?;
    w.map(3)?;
    w.uint(1)?;
    w.array(steps.len() as u64 * 2)?;
    for &s in steps {
        w.uint((s & !HARDENED) as u64)?;
        w.bool(s & HARDENED != 0)?;
    }
    w.uint(2)?;
    w.uint(fp_u32(source_fp))?;
    w.uint(3)?;
    w.uint(steps.len() as u64)
}

/// Script expression tags wrapping the key, outermost first.
fn script_tags(st: ScriptType) -> &'static [u64] {
    match st {
        ScriptType::NativeSegwit => &[TAG_WPKH],
        ScriptType::NestedSegwit => &[TAG_SH, TAG_WPKH],
        ScriptType::Taproot => &[TAG_TR],
        ScriptType::Legacy => &[TAG_PKH],
    }
}

/// One output descriptor: script tags around the hdkey.
pub fn write_output(w: &mut Writer, k: &AccountKey) -> Result<(), Error> {
    for &t in script_tags(k.script) {
        w.tag(t)?;
    }
    write_hdkey(w, k)
}

/// `crypto-output` payload. Returns its length.
pub fn crypto_output(k: &AccountKey, out: &mut [u8]) -> Result<usize, Error> {
    let mut w = Writer::new(out);
    write_output(&mut w, k)?;
    Ok(w.len())
}

/// `crypto-account` payload `{1: master fp, 2: [output]}`. Returns its length.
pub fn crypto_account(k: &AccountKey, out: &mut [u8]) -> Result<usize, Error> {
    let mut w = Writer::new(out);
    w.map(2)?;
    w.uint(1)?;
    w.uint(fp_u32(k.master_fingerprint))?;
    w.uint(2)?;
    w.array(1)?;
    write_output(&mut w, k)?;
    Ok(w.len())
}
