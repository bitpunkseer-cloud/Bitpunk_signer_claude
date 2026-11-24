//! Single-signature account export as a JSON file, in the shape of
//! Coldcard's "generic JSON" (read by Sparrow, Specter and Nunchuk):
//! one section per script type with its path and account xpub. The
//! master xpub is left out (it would reveal every account).

use crate::address::ScriptType;
use crate::bip32::{DerivationPath, KeyVersion, Xpub, XKEY_LEN};
use crate::multisig::descriptor::Out;
use crate::Network;

/// One account key of the file.
#[derive(Clone, Copy)]
pub struct AccountExport<'a> {
    pub script: ScriptType,
    pub path: &'a DerivationPath,
    pub xpub: &'a Xpub,
}

fn section(st: ScriptType) -> (&'static str, &'static str) {
    match st {
        ScriptType::Legacy => ("bip44", "p2pkh"),
        ScriptType::NestedSegwit => ("bip49", "p2sh-p2wpkh"),
        ScriptType::NativeSegwit => ("bip84", "p2wpkh"),
        ScriptType::Taproot => ("bip86", "p2tr"),
    }
}

/// Write the JSON. Returns its length, or `None` if `out` is too small.
pub fn write_generic_json(
    fingerprint: [u8; 4],
    net: Network,
    account: u32,
    keys: &[AccountExport],
    out: &mut [u8],
) -> Option<usize> {
    use core::fmt::Write;
    let mut o = Out::new(out);
    let r: core::fmt::Result = (|| {
        let chain = if net == Network::Mainnet { "BTC" } else { "XTN" };
        write!(o, "{{\n  \"chain\": \"{chain}\",\n  \"xfp\": \"")?;
        for b in fingerprint {
            write!(o, "{b:02X}")?;
        }
        write!(o, "\",\n  \"account\": {account}")?;
        for k in keys {
            let (key, name) = section(k.script);
            let mut x = [0u8; XKEY_LEN];
            let n = k.xpub.encode(KeyVersion::X.public(net), &mut x);
            let xs = core::str::from_utf8(&x[..n]).map_err(|_| core::fmt::Error)?;
            write!(
                o,
                ",\n  \"{key}\": {{\"name\": \"{name}\", \"deriv\": \"{}\", \"xpub\": \"{xs}\"",
                k.path
            )?;
            if k.script.key_version() != KeyVersion::X {
                let mut s = [0u8; XKEY_LEN];
                let n = k.xpub.encode(k.script.key_version().public(net), &mut s);
                write!(
                    o,
                    ", \"_pub\": \"{}\"",
                    core::str::from_utf8(&s[..n]).map_err(|_| core::fmt::Error)?
                )?;
            }
            o.write_str("}")?;
        }
        o.write_str("\n}\n")
    })();
    r.ok()?;
    Some(o.len())
}
