//! crypto-account / crypto-output against vectors generated with embit +
//! urtypes (what SeedSigner uses), for 2 networks x 4 script types x 2 accounts.

mod data {
    include!("data/ur_account_vectors.rs");
}

use bp_bitcoin::address::ScriptType;
use bp_bitcoin::bip32::Xpriv;
use bp_bitcoin::bip39::Mnemonic;
use bp_bitcoin::urtypes::{crypto_account, crypto_output, AccountKey};
use bp_bitcoin::Network;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn matches_seedsigner_encoding() {
    let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
    let master = Xpriv::master(m.to_seed("").unwrap().expose()).unwrap();
    for (net, purpose, account, acct_hex, out_hex) in data::ACCOUNT_VECTORS {
        let network = if *net == "main" {
            Network::Mainnet
        } else {
            Network::Testnet
        };
        let st = ScriptType::ALL
            .into_iter()
            .find(|s| s.purpose() == *purpose)
            .unwrap();
        let path = st.account_path(network, *account);
        let xpub = master.derive_path(&path).unwrap().to_xpub();
        let k = AccountKey {
            xpub: &xpub,
            master_fingerprint: master.fingerprint(),
            path: &path,
            script: st,
            network,
        };
        let mut buf = [0u8; 512];
        let n = crypto_account(&k, &mut buf).unwrap();
        assert_eq!(hex(&buf[..n]), *acct_hex, "{net} {purpose} {account} account");
        let n = crypto_output(&k, &mut buf).unwrap();
        assert_eq!(hex(&buf[..n]), *out_hex, "{net} {purpose} {account} output");
    }
}
