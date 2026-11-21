//! Address verification against addresses made by rust-bitcoin: every
//! script type, receive and change, several indices, accounts and seeds.

use bitcoin::bip32::{DerivationPath, Xpriv as RefXpriv};
use bitcoin::key::{CompressedPublicKey, Secp256k1};
use bitcoin::{Address, NetworkKind};
use bp_bitcoin::addrcheck::{Account, Found, Search, State, Target, TargetError, BATCH};
use bp_bitcoin::address::ScriptType;
use bp_bitcoin::bip32::Xpriv;
use bp_bitcoin::Network;
use std::str::FromStr;

/// A reference address of `seed` at m/purpose'/coin'/account'/chain/index.
fn ref_address(seed: &[u8], st: ScriptType, net: Network, account: u32, chain: u32, index: u32) -> String {
    let secp = Secp256k1::new();
    let kind = if net == Network::Mainnet {
        NetworkKind::Main
    } else {
        NetworkKind::Test
    };
    let master = RefXpriv::new_master(kind, seed).unwrap();
    let coin = if net == Network::Mainnet { 0 } else { 1 };
    let path =
        DerivationPath::from_str(&format!("m/{}'/{coin}'/{account}'/{chain}/{index}", st.purpose())).unwrap();
    let pk = master
        .derive_priv(&secp, &path)
        .unwrap()
        .private_key
        .public_key(&secp);
    let cpk = CompressedPublicKey(pk);
    let rn = match net {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet => bitcoin::Network::Testnet,
        Network::Signet => bitcoin::Network::Signet,
        Network::Regtest => bitcoin::Network::Regtest,
    };
    match st {
        ScriptType::NativeSegwit => Address::p2wpkh(&cpk, rn),
        ScriptType::NestedSegwit => Address::p2shwpkh(&cpk, rn),
        ScriptType::Legacy => Address::p2pkh(cpk, rn),
        ScriptType::Taproot => Address::p2tr(&secp, pk.x_only_public_key().0, None, rn),
    }
    .to_string()
}

fn accounts(seeds: &[&[u8]], st: ScriptType, net: Network, accts: &[u32]) -> Vec<Account> {
    let mut out = Vec::new();
    for (slot, seed) in seeds.iter().enumerate() {
        let m = Xpriv::master(seed).unwrap();
        for &a in accts {
            let x = m.derive_path(&st.account_path(net, a)).unwrap().to_xpub();
            out.push(Account::new(slot as u8, m.fingerprint(), a, &x).unwrap());
        }
    }
    out
}

fn run(s: &mut Search) -> State {
    loop {
        match s.step(37) {
            State::Searching => continue,
            st => return st,
        }
    }
}

const SEED_A: [u8; 32] = [0x11; 32];
const SEED_B: [u8; 64] = [0x5a; 64];

#[test]
fn finds_every_script_type_on_both_chains() {
    for net in [Network::Mainnet, Network::Testnet] {
        for st in ScriptType::ALL {
            for (account, chain, index) in [(0, 0, 0), (0, 1, 3), (1, 0, 57), (0, 1, 199)] {
                let addr = ref_address(&SEED_B, st, net, account, chain, index);
                let t = Target::parse(&addr, net).unwrap();
                assert_eq!(t.script_type(), st, "{addr}");
                let acc = accounts(&[&SEED_A, &SEED_B], st, net, &[0, 1]);
                let mut s = Search::new(t, acc.iter().copied(), None, None);
                let fp = Xpriv::master(&SEED_B).unwrap().fingerprint();
                assert_eq!(
                    run(&mut s),
                    State::Found(Found {
                        slot: 1,
                        fingerprint: fp,
                        account,
                        change: chain == 1,
                        index
                    }),
                    "{addr}"
                );
            }
        }
    }
}

#[test]
fn foreign_address_pauses_after_a_batch_and_more_continues() {
    let net = Network::Mainnet;
    let addr = ref_address(&[0x77; 32], ScriptType::NativeSegwit, net, 0, 0, 5);
    let t = Target::parse(&addr, net).unwrap();
    let acc = accounts(&[&SEED_A], ScriptType::NativeSegwit, net, &[0]);
    let mut s = Search::new(t, acc.iter().copied(), None, None);
    assert_eq!(s.scanned(), 0);
    assert_eq!(run(&mut s), State::Paused);
    assert_eq!(s.scanned(), BATCH);
    assert_eq!(s.checked(), 2 * BATCH, "receive and change at every index");
    s.more();
    assert_eq!(s.state(), State::Searching);
    s.step(10);
    assert_eq!(s.scanned(), BATCH + 5, "five indices x two chains");
}

#[test]
fn hint_and_last_index_are_checked_first() {
    let net = Network::Mainnet;
    let st = ScriptType::Taproot;
    let addr = ref_address(&SEED_A, st, net, 0, 0, 4321);
    let acc = accounts(&[&SEED_A], st, net, &[0]);
    // beyond the first batch: only the hint finds it at once
    let mut s = Search::new(
        Target::parse(&addr, net).unwrap(),
        acc.iter().copied(),
        Some(4321),
        None,
    );
    assert!(matches!(s.step(2), State::Found(Found { index: 4321, .. })));
    // near the index found last
    let mut s = Search::new(
        Target::parse(&addr, net).unwrap(),
        acc.iter().copied(),
        None,
        Some(4310),
    );
    assert!(matches!(run(&mut s), State::Found(Found { index: 4321, .. })));
    assert!(s.checked() <= 2 * 41, "only the window around the last index");
    // a wrong hint costs one index, then the normal search goes on
    let addr = ref_address(&SEED_A, st, net, 0, 1, 2);
    let mut s = Search::new(
        Target::parse(&addr, net).unwrap(),
        acc.iter().copied(),
        Some(9),
        None,
    );
    assert!(matches!(
        run(&mut s),
        State::Found(Found {
            index: 2,
            change: true,
            ..
        })
    ));
}

#[test]
fn script_types_and_networks_must_match() {
    let addr = ref_address(&SEED_A, ScriptType::NativeSegwit, Network::Testnet, 0, 0, 0);
    assert_eq!(
        Target::parse(&addr, Network::Mainnet),
        Err(TargetError::WrongNetwork)
    );
    // testnet and signet share addresses
    assert!(Target::parse(&addr, Network::Signet).is_ok());
    assert_eq!(
        Target::parse(&addr, Network::Regtest),
        Err(TargetError::WrongNetwork)
    );
    let legacy = ref_address(&SEED_A, ScriptType::Legacy, Network::Testnet, 0, 0, 0);
    assert_eq!(
        Target::parse(&legacy, Network::Mainnet),
        Err(TargetError::WrongNetwork)
    );
    // a P2PKH address is not found among P2WPKH keys of the same seed
    let t = Target::parse(
        &ref_address(&SEED_A, ScriptType::Legacy, Network::Mainnet, 0, 0, 0),
        Network::Mainnet,
    )
    .unwrap();
    let acc = accounts(&[&SEED_A], ScriptType::NativeSegwit, Network::Mainnet, &[0]);
    let mut s = Search::new(t, acc.iter().copied(), None, None);
    s.step(100);
    assert_eq!(s.state(), State::Searching);
    // no accounts: nothing to search
    let s = Search::new(t, core::iter::empty(), None, None);
    assert_eq!(s.state(), State::Paused);
}
