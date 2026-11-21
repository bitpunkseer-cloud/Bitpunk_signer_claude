//! Signed messages against rust-bitcoin / libsecp256k1 (byte-identical
//! signatures), Bitcoin Core's `signmessage` test vector, and Coldcard's
//! verification vectors (Electrum and BIP-137 headers, failures).

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sign_message::{signed_msg_hash, MessageSignature};
use bp_bitcoin::addrcheck::TargetError;
use bp_bitcoin::address::ScriptType;
use bp_bitcoin::message::{message_hash, parse_armored, sign, to_base64, verify, VerifyError};
use bp_bitcoin::Network;
use bp_crypto::secp256k1::SecretKey;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn b64(sig: &[u8; 65]) -> String {
    let mut out = [0u8; 88];
    let n = to_base64(sig, &mut out);
    String::from_utf8(out[..n].to_vec()).unwrap()
}

#[test]
fn signatures_match_rust_bitcoin_byte_for_byte() {
    let secp = Secp256k1::new();
    let mut rng = Rng(77);
    for i in 0..300 {
        let mut kb = [0u8; 32];
        for c in kb.chunks_mut(8) {
            c.copy_from_slice(&rng.next().to_le_bytes());
        }
        let Some(sk) = SecretKey::from_bytes(&kb) else {
            continue;
        };
        let rsk = bitcoin::secp256k1::SecretKey::from_slice(&kb).unwrap();
        let len = [2, 10, 252, 253, 300, 1000][i % 6];
        let msg: Vec<u8> = (0..len).map(|_| b'a' + (rng.next() % 26) as u8).collect();
        let h = signed_msg_hash(std::str::from_utf8(&msg).unwrap());
        assert_eq!(message_hash(&msg), h.to_byte_array(), "hash, len {len}");
        let theirs = MessageSignature {
            signature: secp.sign_ecdsa_recoverable(&Message::from_digest(h.to_byte_array()), &rsk),
            compressed: true,
        }
        .serialize();
        let ours = sign(&sk, &msg).unwrap();
        assert_eq!(ours, theirs, "#{i}");
        // and it verifies for each address type of the key
        let pk = bitcoin::PublicKey::new(rsk.public_key(&secp));
        let cpk = bitcoin::CompressedPublicKey(pk.inner);
        for (addr, st) in [
            (
                bitcoin::Address::p2pkh(cpk, bitcoin::Network::Bitcoin),
                ScriptType::Legacy,
            ),
            (
                bitcoin::Address::p2shwpkh(&cpk, bitcoin::Network::Bitcoin),
                ScriptType::NestedSegwit,
            ),
            (
                bitcoin::Address::p2wpkh(&cpk, bitcoin::Network::Bitcoin),
                ScriptType::NativeSegwit,
            ),
        ] {
            let v = verify(&addr.to_string(), Network::Mainnet, &msg, &b64(&ours)).unwrap();
            assert_eq!(v.script_type, st);
            assert!(v.header_matches);
            // another message fails
            assert_eq!(
                verify(&addr.to_string(), Network::Mainnet, b"other", &b64(&ours)),
                Err(VerifyError::Invalid)
            );
        }
    }
}

/// Bitcoin Core test/functional/rpc_signmessage.py
#[test]
fn bitcoin_core_signmessage_vector() {
    let wif = "cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N";
    let k = bitcoin::PrivateKey::from_wif(wif).unwrap();
    let sk = SecretKey::from_bytes(&k.inner.secret_bytes()).unwrap();
    let msg = b"This is just a test message";
    let sig = sign(&sk, msg).unwrap();
    assert_eq!(
        b64(&sig),
        "INbVnW4e6PeRmsv2Qgu8NuopvrVjkcxob+sX8OcZG0SALhWybUjzMLPdAsXI46YZGb0KQTRii+wWIQzRpG/U+S0="
    );
    let v = verify(
        "mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB",
        Network::Testnet,
        msg,
        &b64(&sig),
    )
    .unwrap();
    assert_eq!(v.script_type, ScriptType::Legacy);
}

/// Coldcard testing/test_msg.py: one key, three address types, three
/// header kinds (Electrum P2PKH, BIP-137 P2SH-P2WPKH and P2WPKH).
#[test]
fn coldcard_header_vectors() {
    let addrs = [
        "mwhrUneshkXh8yUw2L2T16UYCoF3ouy4L2",
        "2MudcM4zWNf2rsR1RxvPaMgk5EssH7TXTH8",
        "tb1qkxgmh66fdthecudx042feulz3ymzkyuf7gma0x",
    ];
    let sigs = [
        "H3jE1G2pv+6GG35Unak824xig8GzotLE8pFfvNwlgGU7KebANAxo7RuwybCNXrK9+RvjUEohtffM521N+phQNX0=",
        "I3jE1G2pv+6GG35Unak824xig8GzotLE8pFfvNwlgGU7KebANAxo7RuwybCNXrK9+RvjUEohtffM521N+phQNX0=",
        "J3jE1G2pv+6GG35Unak824xig8GzotLE8pFfvNwlgGU7KebANAxo7RuwybCNXrK9+RvjUEohtffM521N+phQNX0=",
    ];
    for (a, addr) in addrs.iter().enumerate() {
        for (h, sig) in sigs.iter().enumerate() {
            let v = verify(addr, Network::Testnet, b"aaaaaaaaaaaaaaaaaa", sig).unwrap();
            // the Electrum header (31-34) fits every single-key type (we sign
            // that way); a BIP-137 header must name the address's own type
            assert_eq!(v.header_matches, h == 0 || a == h, "{addr} {sig}");
        }
    }
    // signet shares testnet addresses; mainnet does not
    assert!(verify(addrs[2], Network::Signet, b"aaaaaaaaaaaaaaaaaa", sigs[2]).is_ok());
    assert_eq!(
        verify(addrs[2], Network::Mainnet, b"aaaaaaaaaaaaaaaaaa", sigs[2]),
        Err(VerifyError::Address(TargetError::WrongNetwork))
    );
}

#[test]
fn coldcard_failure_vectors() {
    let m = b"aaaaaaaaa";
    let t = Network::Testnet;
    let tb = "tb1qk3vdwdewzqkmagakdxfga3nrqgxnpw74h4w5p4";
    assert_eq!(verify(tb, t, m, &"$".repeat(88)), Err(VerifyError::Encoding));
    assert_eq!(
        verify(
            tb,
            t,
            m,
            "KPxCN2edt9w5ukd0feOlFS6PJjsKwm6ii/erZErKDIApIxjHqxBzoDvVqcTX0mtecNTGCkJPhxjRKCjNtdnTAp0="
        ),
        Err(VerifyError::Invalid)
    );
    let short = "H3h4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4";
    assert_eq!(
        verify("mwxYMLpcbLjBdtbVdb1kKxHiR4rcAzqPxR", t, m, short),
        Err(VerifyError::Encoding)
    );
    let p2tr = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y";
    let sig = "KPxCN2edt9w5ukd0feOlFS6PJjsKwm6ii/erZErKDIApIxjHqxBzoDvVqcTX0mtecNTGCkJPhxjRKCjNtdnTAp0=";
    assert!(matches!(
        verify(p2tr, Network::Mainnet, m, sig),
        Err(VerifyError::Taproot | VerifyError::Address(_))
    ));
    let p2wsh = "bc1q2c8pym4m755pq4n4shu2wgzr7s58pygz8x6pg0mj0l6netq8am8qw69kss";
    assert_eq!(
        verify(p2wsh, Network::Mainnet, m, sig),
        Err(VerifyError::Address(TargetError::Multisig))
    );
    // header outside 27..42
    let mut raw = [0u8; 65];
    raw[0] = 43;
    assert_eq!(verify(tb, t, m, &b64(&raw)), Err(VerifyError::Header));
}

#[test]
fn armored_round_trip() {
    let sk = SecretKey::from_bytes(&[7; 32]).unwrap();
    let msg = b"hello\nworld";
    let sig = b64(&sign(&sk, msg).unwrap());
    let secp = Secp256k1::new();
    let rsk = bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
    let addr = bitcoin::Address::p2wpkh(
        &bitcoin::CompressedPublicKey(rsk.public_key(&secp)),
        bitcoin::Network::Bitcoin,
    )
    .to_string();
    let text = format!(
        "-----BEGIN BITCOIN SIGNED MESSAGE-----\nhello\nworld\n-----BEGIN BITCOIN SIGNATURE-----\n{addr}\n{sig}\n-----END BITCOIN SIGNATURE-----\n"
    );
    let a = parse_armored(text.as_bytes()).unwrap();
    assert_eq!(a.message, msg);
    assert!(
        verify(a.address, Network::Mainnet, a.message, a.signature)
            .unwrap()
            .header_matches
    );
}
