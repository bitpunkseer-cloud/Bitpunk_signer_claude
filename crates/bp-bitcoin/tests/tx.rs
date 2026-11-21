//! Transaction parsing, txid and signature hashes: Bitcoin Core's
//! sighash.json, the BIP-143 examples, the BIP-341 wallet vectors, and
//! random transactions compared with rust-bitcoin (test-only reference).

#[path = "data/bip341_sighash.rs"]
mod bip341;
#[path = "data/core_sighash.rs"]
mod core_sighash;

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{EcdsaSighashType, Prevouts as RefPrevouts, SighashCache, TapSighashType};
use bp_bitcoin::sighash::{self, Prevouts, SegwitV0Hashes, TaprootHashes};
use bp_bitcoin::tx::{Buf, Error, Tx, TxOut};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

fn rev(mut b: [u8; 32]) -> [u8; 32] {
    b.reverse();
    b
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    /// A well-formed script without OP_CODESEPARATOR (rust-bitcoin hashes
    /// the script code as is; Core's removal of separators and its handling
    /// of truncated pushes are covered by sighash.json).
    fn script(&mut self, max: u64) -> Vec<u8> {
        let target = self.below(max + 1) as usize;
        let mut s = Vec::new();
        while s.len() < target {
            let op = self.next() as u8;
            match op {
                0x01..=0x4B => {
                    s.push(op);
                    let data = self.bytes(op as usize);
                    s.extend(data);
                }
                0x4C..=0x4E | 0xAB => s.push(0x51),
                _ => s.push(op),
            }
        }
        s
    }
}

#[test]
fn core_sighash_json() {
    for (i, &(raw, script, input, hash_type, result)) in core_sighash::CORE_SIGHASH.iter().enumerate() {
        let raw = unhex(raw);
        let tx = Tx::parse(&raw).unwrap_or_else(|e| panic!("vector {i}: {e:?}"));
        let h = sighash::legacy(&tx, input, &unhex(script), hash_type as u32);
        assert_eq!(rev(h), arr32(result), "vector {i}");
    }
}

/// (unsigned tx, input, script code with its length prefix, amount, hash
/// type, sighash) from the BIP-143 examples.
const BIP143: &[(&str, usize, &str, u64, u32, &str)] = &[
    // native P2WPKH
    ("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000",
     1, "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac", 600_000_000, 1,
     "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"),
    // P2SH-P2WPKH
    ("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000",
     0, "1976a91479091972186c449eb1ded22b78e40d009bdf008988ac", 1_000_000_000, 1,
     "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"),
    // native P2WSH, OP_CODESEPARATOR and out-of-range SIGHASH_SINGLE
    ("0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000",
     1, "4721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac", 4_900_000_000, 3,
     "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"),
    ("0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000",
     1, "23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac", 4_900_000_000, 3,
     "fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"),
    // native P2WSH, SINGLE|ANYONECANPAY
    ("0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000",
     0, "270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac", 16_777_215, 0x83,
     "e9071e75e25b8a1e298a72f0d2e9f4f95a0f5cdf86a533cda597eb402ed13b3a"),
    ("0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000",
     1, "2468210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac", 16_777_215, 0x83,
     "cd72f1f1a433ee9df816857fad88d8ebd97e09a75cd481583eb841c330275e54"),
    // P2SH-P2WSH 6-of-6 with six hash types
    (P2SH_P2WSH_TX, 0, P2SH_P2WSH_CODE, 987_654_321, 0x01, "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c"),
    (P2SH_P2WSH_TX, 0, P2SH_P2WSH_CODE, 987_654_321, 0x02, "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36"),
    (P2SH_P2WSH_TX, 0, P2SH_P2WSH_CODE, 987_654_321, 0x03, "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea"),
    (P2SH_P2WSH_TX, 0, P2SH_P2WSH_CODE, 987_654_321, 0x81, "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e"),
    (P2SH_P2WSH_TX, 0, P2SH_P2WSH_CODE, 987_654_321, 0x82, "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a"),
    (P2SH_P2WSH_TX, 0, P2SH_P2WSH_CODE, 987_654_321, 0x83, "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b"),
    // no FindAndDelete
    ("010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f14c1d000000ffffffff0101000000000000000000000000",
     0, "4aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01", 200_000, 1,
     "71c9cd9b2869b9c70b01b1f0360c148f42dee72297db312638df136f43311f23"),
];

const P2SH_P2WSH_TX: &str = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000";
const P2SH_P2WSH_CODE: &str = "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae";

#[test]
fn bip143_examples() {
    for (i, &(raw, input, code, value, ht, expected)) in BIP143.iter().enumerate() {
        let raw = unhex(raw);
        let tx = Tx::parse(&raw).unwrap();
        let code = unhex(code);
        assert_eq!(code[0] as usize, code.len() - 1);
        let hashes = SegwitV0Hashes::new(&tx);
        let h = sighash::segwit_v0(&tx, &hashes, input, &code[1..], value, ht).unwrap();
        assert_eq!(h, arr32(expected), "example {i}");
    }
    // the documented intermediate hashes and preimage of the first example
    let raw = unhex(BIP143[0].0);
    let tx = Tx::parse(&raw).unwrap();
    let hashes = SegwitV0Hashes::new(&tx);
    assert_eq!(
        hashes.prevouts,
        arr32("96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37")
    );
    assert_eq!(
        hashes.sequences,
        arr32("52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b")
    );
    assert_eq!(
        hashes.outputs,
        arr32("863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5")
    );
    let mut buf = [0u8; 256];
    let mut w = Buf::new(&mut buf);
    let code = unhex(BIP143[0].2);
    sighash::segwit_v0_preimage(&mut w, &tx, &hashes, 1, &code[1..], 600_000_000, 1).unwrap();
    let n = w.finish().unwrap();
    assert_eq!(&buf[..n], &unhex("0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000")[..]);
    // out of range input
    assert_eq!(sighash::segwit_v0(&tx, &hashes, 2, &code[1..], 1, 1), None);
}

#[test]
fn bip143_signed_transactions_parse_with_witness() {
    let signed = unhex("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000");
    let tx = Tx::parse(&signed).unwrap();
    assert!(tx.has_witness());
    assert_eq!(tx.witness(0).count(), 0);
    let w: Vec<&[u8]> = tx.witness(1).collect();
    assert_eq!(w.len(), 2);
    assert_eq!(
        w[1],
        &unhex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")[..]
    );
    assert_eq!(tx.input(0).unwrap().script_sig.len(), 0x49);
    // txid ignores the witness and matches rust-bitcoin
    let r: bitcoin::Transaction = bitcoin::consensus::deserialize(&signed).unwrap();
    assert_eq!(tx.txid(), r.compute_txid().to_byte_array());
    assert_eq!(tx.base_size(), r.base_size());
}

#[test]
fn bip341_key_path_vectors() {
    let raw = unhex(bip341::RAW_UNSIGNED_TX);
    let tx = Tx::parse(&raw).unwrap();
    let scripts: Vec<Vec<u8>> = bip341::UTXOS_SPENT.iter().map(|(_, s)| unhex(s)).collect();
    let prevouts: Vec<TxOut> = bip341::UTXOS_SPENT
        .iter()
        .zip(&scripts)
        .map(|(&(v, _), s)| TxOut::new(v, s))
        .collect();
    let hashes = TaprootHashes::new(&tx, &prevouts[..]).unwrap();
    let [amounts, outputs, prev, spks, seqs] = bip341::HASHES.map(arr32);
    assert_eq!(hashes.amounts, amounts);
    assert_eq!(hashes.outputs, outputs);
    assert_eq!(hashes.prevouts, prev);
    assert_eq!(hashes.script_pubkeys, spks);
    assert_eq!(hashes.sequences, seqs);
    for &(input, ht, msg, expected) in bip341::INPUTS {
        let mut buf = [0u8; 512];
        let mut w = Buf::new(&mut buf);
        sighash::taproot_sigmsg(&mut w, &tx, &hashes, &prevouts[..], input, ht).unwrap();
        let n = w.finish().unwrap();
        assert_eq!(&buf[..n], &unhex(msg)[..], "input {input} sigMsg");
        let h = sighash::taproot_key_spend(&tx, &hashes, &prevouts[..], input, ht).unwrap();
        assert_eq!(h, arr32(expected), "input {input} sigHash");
    }
    // a missing prevout means no Taproot hashes at all
    assert!(TaprootHashes::new(&tx, &prevouts[..prevouts.len() - 1]).is_none());
    // invalid hash types and SIGHASH_SINGLE without an output
    for ht in [0x04, 0x80, 0x84, 0xFF] {
        assert_eq!(
            sighash::taproot_key_spend(&tx, &hashes, &prevouts[..], 0, ht),
            None
        );
    }
    let last = tx.n_inputs() - 1;
    assert!(last >= tx.n_outputs());
    assert_eq!(
        sighash::taproot_key_spend(&tx, &hashes, &prevouts[..], last, sighash::SINGLE),
        None
    );
    // the fully signed transaction (some inputs are not Taproot and carry
    // scriptSigs) parses with its witness; txid as rust-bitcoin
    let signed = unhex(bip341::FULLY_SIGNED_TX);
    let stx = Tx::parse(&signed).unwrap();
    assert!(stx.has_witness());
    assert_eq!(stx.outputs_bytes(), tx.outputs_bytes());
    let r: bitcoin::Transaction = bitcoin::consensus::deserialize(&signed).unwrap();
    assert_eq!(stx.txid(), r.compute_txid().to_byte_array());
    for (i, inp) in r.input.iter().enumerate() {
        assert_eq!(stx.witness(i).count(), inp.witness.len());
    }
}

fn random_tx(rng: &mut Rng, witness: bool) -> bitcoin::Transaction {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, TxIn, Txid, Witness,
    };
    let n_in = 1 + rng.below(5) as usize;
    let n_out = 1 + rng.below(5) as usize;
    let mut input = Vec::new();
    for _ in 0..n_in {
        let mut w = Witness::new();
        if witness {
            for _ in 0..rng.below(4) {
                let n = rng.below(80) as usize;
                w.push(rng.bytes(n));
            }
        }
        input.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(rng.bytes(32).try_into().unwrap()),
                vout: rng.next() as u32,
            },
            script_sig: ScriptBuf::from_bytes(rng.script(if witness { 0 } else { 120 })),
            sequence: Sequence(rng.next() as u32),
            witness: w,
        });
    }
    if witness && input.iter().all(|i| i.witness.is_empty()) {
        input[0].witness.push([1u8]);
    }
    let output = (0..n_out)
        .map(|_| bitcoin::TxOut {
            value: Amount::from_sat(rng.next() >> rng.below(64)),
            script_pubkey: ScriptBuf::from_bytes(rng.script(300)),
        })
        .collect();
    bitcoin::Transaction {
        version: Version(rng.next() as i32),
        lock_time: LockTime::from_consensus(rng.next() as u32),
        input,
        output,
    }
}

#[test]
fn random_transactions_match_rust_bitcoin() {
    let mut rng = Rng(0x5167);
    for case in 0..600 {
        let r = random_tx(&mut rng, case % 3 == 0);
        let raw = serialize(&r);
        let tx = Tx::parse(&raw).unwrap_or_else(|e| panic!("case {case}: {e:?}"));
        assert_eq!(tx.version, r.version.0 as u32);
        assert_eq!(tx.lock_time, r.lock_time.to_consensus_u32());
        assert_eq!(tx.n_inputs(), r.input.len());
        assert_eq!(tx.n_outputs(), r.output.len());
        assert_eq!(tx.txid(), r.compute_txid().to_byte_array(), "case {case}");
        assert_eq!(tx.base_size(), r.base_size());
        for (i, (a, b)) in tx.inputs().zip(&r.input).enumerate() {
            assert_eq!(a.txid, b.previous_output.txid.to_byte_array());
            assert_eq!(a.vout, b.previous_output.vout);
            assert_eq!(a.script_sig, b.script_sig.as_bytes());
            assert_eq!(a.sequence, b.sequence.0);
            let ours: Vec<&[u8]> = tx.witness(i).collect();
            let theirs: Vec<&[u8]> = b.witness.iter().collect();
            assert_eq!(ours, theirs);
        }
        for (a, b) in tx.outputs().zip(&r.output) {
            assert_eq!(a.value, b.value.to_sat());
            assert_eq!(a.script_pubkey, b.script_pubkey.as_bytes());
        }

        let mut cache = SighashCache::new(&r);
        let prev_scripts: Vec<Vec<u8>> = (0..r.input.len()).map(|_| rng.script(60)).collect();
        let prev_values: Vec<u64> = (0..r.input.len()).map(|_| rng.next() >> 20).collect();
        let prevouts: Vec<TxOut> = prev_values
            .iter()
            .zip(&prev_scripts)
            .map(|(&v, s)| TxOut::new(v, s))
            .collect();
        let ref_prevouts: Vec<bitcoin::TxOut> = prevouts
            .iter()
            .map(|p| bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(p.value),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(p.script_pubkey.to_vec()),
            })
            .collect();
        let v0 = SegwitV0Hashes::new(&tx);
        let tap = TaprootHashes::new(&tx, &prevouts[..]).unwrap();
        for i in 0..r.input.len() {
            let code = &prev_scripts[i];
            let code_script = bitcoin::Script::from_bytes(code);
            // legacy: standard and arbitrary hash types
            for ht in [1u32, 2, 3, 0x81, 0x82, 0x83, rng.next() as u32] {
                let theirs = cache.legacy_signature_hash(i, code_script, ht).unwrap();
                let ours = sighash::legacy(&tx, i, code, ht);
                assert_eq!(
                    ours,
                    theirs.to_byte_array(),
                    "case {case} input {i} legacy {ht:#x}"
                );
            }
            // BIP-143
            for ht in [1u32, 2, 3, 0x81, 0x82, 0x83] {
                let theirs = cache
                    .p2wsh_signature_hash(
                        i,
                        code_script,
                        bitcoin::Amount::from_sat(prev_values[i]),
                        EcdsaSighashType::from_consensus(ht),
                    )
                    .unwrap();
                let ours = sighash::segwit_v0(&tx, &v0, i, code, prev_values[i], ht).unwrap();
                assert_eq!(
                    ours,
                    theirs.to_byte_array(),
                    "case {case} input {i} bip143 {ht:#x}"
                );
            }
            // BIP-341 key path
            for ht in [0u8, 1, 2, 3, 0x81, 0x82, 0x83] {
                let ty = TapSighashType::from_consensus_u8(ht).unwrap();
                let theirs = cache.taproot_key_spend_signature_hash(i, &RefPrevouts::All(&ref_prevouts), ty);
                let ours = sighash::taproot_key_spend(&tx, &tap, &prevouts[..], i, ht);
                match theirs {
                    Ok(h) => assert_eq!(
                        ours,
                        Some(h.to_byte_array()),
                        "case {case} input {i} bip341 {ht:#x}"
                    ),
                    Err(_) => assert_eq!(ours, None, "case {case} input {i} bip341 {ht:#x}"),
                }
            }
        }
        let _ = Prevouts::prevout(&prevouts[..], 0);
    }
}

#[test]
fn strict_parsing() {
    let mut rng = Rng(9);
    let r = random_tx(&mut rng, true);
    let raw = serialize(&r);
    assert!(Tx::parse(&raw).is_ok());
    // every truncation fails
    for n in 0..raw.len() {
        assert!(Tx::parse(&raw[..n]).is_err(), "truncated at {n}");
    }
    // trailing data
    let mut t = raw.clone();
    t.push(0);
    assert_eq!(Tx::parse(&t).err(), Some(Error::Malformed));
    // witness flag other than 1
    let mut t = raw.clone();
    t[5] = 2;
    assert_eq!(Tx::parse(&t).err(), Some(Error::Malformed));
    // superfluous witness: marker and flag with empty stacks
    let legacy = {
        let mut l = r.clone();
        for i in &mut l.input {
            i.witness.clear();
        }
        serialize(&l)
    };
    assert!(!Tx::parse(&legacy).unwrap().has_witness());
    let mut sup = legacy[..4].to_vec();
    sup.extend_from_slice(&[0, 1]);
    sup.extend_from_slice(&legacy[4..legacy.len() - 4]);
    sup.extend(std::iter::repeat_n(0, r.input.len()));
    sup.extend_from_slice(&legacy[legacy.len() - 4..]);
    assert_eq!(Tx::parse(&sup).err(), Some(Error::Malformed));
    // zero outputs; non-canonical input count
    let mut one_in_no_out = vec![1, 0, 0, 0, 1];
    one_in_no_out.extend_from_slice(&[0; 36 + 1 + 4]);
    one_in_no_out.extend_from_slice(&[0; 1 + 4]);
    assert_eq!(Tx::parse(&one_in_no_out).err(), Some(Error::Malformed));
    let mut nc = legacy[..4].to_vec();
    nc.extend_from_slice(&[0xFD, r.input.len() as u8, 0]);
    nc.extend_from_slice(&legacy[5..]);
    assert_eq!(Tx::parse(&nc).err(), Some(Error::Malformed));
}
