//! Single-signature JSON export: the xpubs agree with rust-bitcoin and
//! the published BIP-84 vector for "abandon ... about".

use bitcoin::bip32::{DerivationPath as RefPath, Xpriv as RefXpriv, Xpub as RefXpub};
use bp_bitcoin::address::ScriptType;
use bp_bitcoin::bip32::Xpriv;
use bp_bitcoin::bip39::Mnemonic;
use bp_bitcoin::export::{write_generic_json, AccountExport};
use bp_bitcoin::Network;
use std::str::FromStr;

#[test]
fn generic_json_matches_references() {
    let m = Mnemonic::from_entropy(&[0; 16]).unwrap();
    let seed = m.to_seed("").unwrap();
    let master = Xpriv::master(seed.expose()).unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    for net in [Network::Mainnet, Network::Testnet] {
        let types = [
            ScriptType::Legacy,
            ScriptType::NestedSegwit,
            ScriptType::NativeSegwit,
            ScriptType::Taproot,
        ];
        let paths: Vec<_> = types.iter().map(|st| st.account_path(net, 3)).collect();
        let xpubs: Vec<_> = paths
            .iter()
            .map(|p| master.derive_path(p).unwrap().to_xpub())
            .collect();
        let keys: Vec<AccountExport> = types
            .iter()
            .zip(&paths)
            .zip(&xpubs)
            .map(|((st, p), x)| AccountExport {
                script: *st,
                path: p,
                xpub: x,
            })
            .collect();
        let mut out = [0u8; 4096];
        let n = write_generic_json(master.fingerprint(), net, 3, &keys, &mut out).unwrap();
        let text = std::str::from_utf8(&out[..n]).unwrap();
        let chain = if net == Network::Mainnet { "BTC" } else { "XTN" };
        assert!(text.contains(&format!("\"chain\": \"{chain}\"")));
        assert!(text.contains("\"xfp\": \"73C5DA0A\""));
        assert!(text.contains("\"account\": 3"));
        let ref_net = if net == Network::Mainnet {
            bitcoin::NetworkKind::Main
        } else {
            bitcoin::NetworkKind::Test
        };
        let root = RefXpriv::new_master(ref_net, seed.expose()).unwrap();
        for (st, p) in types.iter().zip(&paths) {
            let rp = RefPath::from_str(&p.to_string()).unwrap();
            let want = RefXpub::from_priv(&secp, &root.derive_priv(&secp, &rp).unwrap()).to_string();
            assert!(
                text.contains(&format!("\"deriv\": \"{p}\", \"xpub\": \"{want}\"")),
                "{st:?}: {text}"
            );
        }
        assert_eq!(text.matches("\"_pub\"").count(), 2, "ypub and zpub only");
    }
    // the BIP-84 vector (account 0)
    let p = ScriptType::NativeSegwit.account_path(Network::Mainnet, 0);
    let x = master.derive_path(&p).unwrap().to_xpub();
    let mut out = [0u8; 1024];
    let keys = [AccountExport {
        script: ScriptType::NativeSegwit,
        path: &p,
        xpub: &x,
    }];
    let n = write_generic_json(master.fingerprint(), Network::Mainnet, 0, &keys, &mut out).unwrap();
    let text = std::str::from_utf8(&out[..n]).unwrap();
    assert!(text.contains(
        "\"_pub\": \"zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs\""
    ));
    assert!(write_generic_json(master.fingerprint(), Network::Mainnet, 0, &keys, &mut out[..50]).is_none());
}
