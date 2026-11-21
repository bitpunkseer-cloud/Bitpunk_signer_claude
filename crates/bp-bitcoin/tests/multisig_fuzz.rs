//! Deterministic fuzzing of the multisig inputs a QR code can carry:
//! descriptors, wallet files, cosigner keys, UR payloads, codes, and
//! multisig PSBTs through the validator, the reconstruction and the
//! address search. Mutations of valid payloads and random bytes must never
//! panic or hang.

#[allow(dead_code)]
#[path = "data/embit_multisig.rs"]
mod embit;

use bitcoin::psbt::Psbt as RefPsbt;
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bp_bitcoin::bip32::{Xpriv, XKEY_LEN};
use bp_bitcoin::multisig::descriptor::{self, Form};
use bp_bitcoin::multisig::register::{self, Code, CodeKey, Registry};
use bp_bitcoin::multisig::{formats, reconstruct, MsScript, Search, Wallet};
use bp_bitcoin::validate::{validate, Context};
use bp_bitcoin::Network;
use bp_qr::ur::cbor::Writer;
use std::str::FromStr;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut Rng, v: &[u8]) -> Vec<u8> {
    let mut m = v.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(6) {
            0 if !m.is_empty() => {
                let i = rng.below(m.len());
                m[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(m.len() + 1);
                m.insert(i, rng.next() as u8);
            }
            2 if !m.is_empty() => {
                let i = rng.below(m.len());
                m.remove(i);
            }
            3 if !m.is_empty() => {
                let i = rng.below(m.len());
                const CHARS: &[u8] = b"0123456789abcdefh'/*<>;,()[]#: \n{}\"\\xpubZY";
                m[i] = CHARS[rng.below(CHARS.len())];
            }
            4 if m.len() > 8 => {
                // duplicate a slice (repeated keys, nested brackets)
                let a = rng.below(m.len() - 4);
                let l = 1 + rng.below(m.len() - a).min(60);
                let chunk: Vec<u8> = m[a..a + l].to_vec();
                let at = rng.below(m.len());
                m.splice(at..at, chunk);
            }
            _ => {
                let n = rng.below(m.len() + 1);
                m.truncate(n);
            }
        }
    }
    m
}

fn wallets() -> Vec<Wallet> {
    embit::VECTORS
        .iter()
        .map(|(d, ..)| descriptor::parse(d).unwrap().wallet)
        .collect()
}

#[test]
fn wallet_and_key_parsers_never_panic() {
    let ws = wallets();
    let mut seeds: Vec<Vec<u8>> = vec![];
    for w in &ws {
        let mut o = [0u8; descriptor::MAX_DESCRIPTOR];
        let n = descriptor::write(w, Form::Multipath, &mut o).unwrap();
        seeds.push(o[..n].to_vec());
        let n = descriptor::write(w, Form::Branch(0), &mut o).unwrap();
        seeds.push(o[..n].to_vec());
        let n = formats::write_coldcard(w, "Fuzz", &mut o).unwrap();
        seeds.push(o[..n].to_vec());
        let n = formats::write_key_text(&w.keys()[0], w.test, &mut o).unwrap();
        seeds.push(o[..n].to_vec());
        let shared = w.keys()[0];
        let n = formats::write_coldcard_xpub_json(&shared, &shared, 0, w.test, &mut o).unwrap();
        seeds.push(o[..n].to_vec());
    }
    let json = format!(
        "{{\"label\": \"x\", \"descriptor\": \"{}\"}}",
        embit::VECTORS[0].0
    );
    seeds.push(json.into_bytes());
    let mut rng = Rng(0x5eed_0007);
    let m = Xpriv::master(&[10; 32]).unwrap();
    let reg = Registry::new();
    for i in 0..6000 {
        let base = &seeds[i % seeds.len()];
        let input = if i % 7 == 0 {
            (0..rng.below(300)).map(|_| rng.next() as u8).collect()
        } else {
            mutate(&mut rng, base)
        };
        let text = String::from_utf8_lossy(&input);
        if let Ok(p) = descriptor::parse(&text) {
            // whatever parses goes through the rules and the code
            let _ = register::check(&p.wallet, Network::Mainnet, &m, &reg);
            let _ = CodeKey::new(&m).code(&p.wallet);
            let _ = p.wallet.derive(1, 3);
        }
        if let Ok(imp) = formats::parse_wallet(&input) {
            let _ = register::check(&imp.wallet, Network::Testnet, &m, &reg);
        }
        let _ = formats::parse_cosigner(&input, MsScript::Wsh);
        let _ = formats::parse_cosigner(&input, MsScript::ShWsh);
        let _ = Code::parse(&text);
        let _ = descriptor::checksum(&text);
    }
}

/// A UR crypto-output for `w` (BCR-2020-010 sorted multisig).
fn output_ur(w: &Wallet) -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    let mut wr = Writer::new(&mut buf);
    if w.script == MsScript::ShWsh {
        wr.tag(400).unwrap();
    }
    wr.tag(401).unwrap();
    wr.tag(407).unwrap();
    wr.map(2).unwrap();
    wr.uint(1).unwrap();
    wr.uint(w.m as u64).unwrap();
    wr.uint(2).unwrap();
    wr.array(w.n() as u64).unwrap();
    for k in w.keys() {
        wr.tag(303).unwrap();
        wr.map(4).unwrap();
        wr.uint(3).unwrap();
        wr.bytes(&k.xpub.key.serialize()).unwrap();
        wr.uint(4).unwrap();
        wr.bytes(&k.xpub.chain_code).unwrap();
        wr.uint(6).unwrap();
        wr.tag(304).unwrap();
        wr.map(2).unwrap();
        wr.uint(1).unwrap();
        let steps = k.origin.steps();
        wr.array(steps.len() as u64 * 2).unwrap();
        for &s in steps {
            wr.uint((s & 0x7fff_ffff) as u64).unwrap();
            wr.bool(s & 0x8000_0000 != 0).unwrap();
        }
        wr.uint(2).unwrap();
        wr.uint(u32::from_be_bytes(k.fingerprint) as u64).unwrap();
        wr.uint(8).unwrap();
        wr.uint(0).unwrap();
    }
    let n = wr.len();
    buf.truncate(n);
    buf
}

#[test]
fn ur_payloads_never_panic() {
    let ws = wallets();
    let seeds: Vec<Vec<u8>> = ws.iter().map(output_ur).collect();
    let mut rng = Rng(0x00dd_ba11);
    for i in 0..6000 {
        let input = mutate(&mut rng, &seeds[i % seeds.len()]);
        let _ = formats::parse_output_ur(&input);
        let _ = formats::parse_cosigner_ur("crypto-account", &input, MsScript::Wsh);
        let _ = formats::parse_cosigner_ur("crypto-hdkey", &input, MsScript::ShWsh);
    }
}

/// A 2-of-3 spend from `w` with derivations and global xpubs.
fn ms_psbt(w: &Wallet) -> Vec<u8> {
    let input = w.derive(0, 4).unwrap();
    let change = w.derive(1, 2).unwrap();
    let prev = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(200_000),
            script_pubkey: ScriptBuf::from_bytes(input.script_pubkey().to_vec()),
        }],
    };
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(prev.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(150_000),
                script_pubkey: ScriptBuf::from_bytes(vec![
                    0x00, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                ]),
            },
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(change.script_pubkey().to_vec()),
            },
        ],
    };
    let mut p = RefPsbt::from_unsigned_tx(tx).unwrap();
    p.inputs[0].witness_utxo = Some(prev.output[0].clone());
    p.inputs[0].non_witness_utxo = Some(prev);
    p.inputs[0].witness_script = Some(ScriptBuf::from_bytes(input.witness_script().to_vec()));
    if w.script == MsScript::ShWsh {
        p.inputs[0].redeem_script = Some(ScriptBuf::from_bytes(input.redeem_script().to_vec()));
    }
    let net = if w.test {
        Network::Testnet
    } else {
        Network::Mainnet
    };
    for (b, i, map_in) in [(0u32, 4u32, true), (1, 2, false)] {
        let keys = w.branch(b).unwrap().child_keys(i).unwrap();
        for (j, k) in w.keys().iter().enumerate() {
            let pk = bitcoin::secp256k1::PublicKey::from_slice(&keys[j]).unwrap();
            let path = bitcoin::bip32::DerivationPath::from_str(&format!("{}/{b}/{i}", k.origin)).unwrap();
            let v = (bitcoin::bip32::Fingerprint::from(k.fingerprint), path);
            if map_in {
                p.inputs[0].bip32_derivation.insert(pk, v);
            } else {
                p.outputs[1].bip32_derivation.insert(pk, v);
            }
        }
    }
    for k in w.keys() {
        let mut x = [0u8; XKEY_LEN];
        let n = k
            .xpub
            .encode(bp_bitcoin::bip32::KeyVersion::X.public(net), &mut x);
        let xp = bitcoin::bip32::Xpub::from_str(std::str::from_utf8(&x[..n]).unwrap()).unwrap();
        let origin = bitcoin::bip32::DerivationPath::from_str(&format!("{}", k.origin)).unwrap();
        p.xpub
            .insert(xp, (bitcoin::bip32::Fingerprint::from(k.fingerprint), origin));
    }
    p.serialize()
}

#[test]
fn multisig_validation_never_panics() {
    let ws = wallets();
    // the first wallet's first key is seed [10; 32] (see the generator)
    let ours = Xpriv::master(&[10; 32]).unwrap();
    let small: Vec<&Wallet> = ws.iter().filter(|w| w.n() <= 7).collect();
    let refs: Vec<Option<&Wallet>> = small.iter().map(|w| Some(*w)).collect();
    let seeds: Vec<Vec<u8>> = small.iter().map(|w| ms_psbt(w)).collect();
    let mut rng = Rng(0xfeed_beef);
    for i in 0..1500 {
        let raw = mutate(&mut rng, &seeds[i % seeds.len()]);
        for (net, watch) in [(Network::Mainnet, false), (Network::Testnet, true)] {
            let mut ctx = Context::new(&ours, net);
            ctx.multisig = &refs;
            ctx.watch = watch;
            let (p, report) = validate(&raw, &ctx);
            let _ = report.digest();
            if let Some(p) = p {
                let _ = reconstruct(&p, ours.fingerprint(), net != Network::Mainnet);
            }
        }
        // the address search on random scripts
        let spk: Vec<u8> = mutate(
            &mut rng,
            &[
                0x00, 0x20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );
        if let Some(mut s) = Search::new(&spk, &refs) {
            let _ = s.step(&refs, 16);
        }
    }
    // the honest PSBTs are fine for the wallet holding [10; 32]
    let mut ctx = Context::new(&ours, Network::Mainnet);
    ctx.multisig = &refs;
    let (_, r) = validate(&seeds[0], &ctx);
    assert_eq!(r.issues(), &[], "{:?}", r.issues());
}
