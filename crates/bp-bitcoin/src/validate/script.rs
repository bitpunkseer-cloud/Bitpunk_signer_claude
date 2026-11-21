//! Output script templates: recognise a scriptPubKey, and build the four
//! single-key scripts the signer supports from a public key.

use bp_crypto::hashes::hash160;
use bp_crypto::secp256k1::{schnorr, PublicKey};

/// What a scriptPubKey is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptKind {
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
    P2wpkh([u8; 20]),
    P2wsh([u8; 32]),
    P2tr([u8; 32]),
    /// Segwit v2..v16 or an unusual v0/v1 program length.
    FutureWitness,
    /// OP_RETURN data carrier.
    OpReturn,
    /// Anything else (bare multisig, P2PK, non-standard).
    Other,
}

fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(b);
    a
}

pub fn classify(s: &[u8]) -> ScriptKind {
    match s {
        [0x76, 0xA9, 0x14, h @ .., 0x88, 0xAC] if h.len() == 20 => ScriptKind::P2pkh(arr(h)),
        [0xA9, 0x14, h @ .., 0x87] if h.len() == 20 => ScriptKind::P2sh(arr(h)),
        [0x00, 0x14, h @ ..] if h.len() == 20 => ScriptKind::P2wpkh(arr(h)),
        [0x00, 0x20, h @ ..] if h.len() == 32 => ScriptKind::P2wsh(arr(h)),
        [0x51, 0x20, k @ ..] if k.len() == 32 => ScriptKind::P2tr(arr(k)),
        [0x6A, ..] => ScriptKind::OpReturn,
        // witness program: version opcode then a 2..40-byte push
        [v, n, p @ ..]
            if (*v == 0 || (0x51..=0x60).contains(v)) && (2..=40).contains(n) && p.len() == *n as usize =>
        {
            ScriptKind::FutureWitness
        }
        _ => ScriptKind::Other,
    }
}

/// P2WPKH: OP_0 <hash160(pk)>
pub fn p2wpkh(pk: &PublicKey) -> [u8; 22] {
    let mut s = [0u8; 22];
    s[1] = 0x14;
    s[2..].copy_from_slice(&hash160(&pk.serialize()));
    s
}

/// P2PKH: OP_DUP OP_HASH160 <hash160(pk)> OP_EQUALVERIFY OP_CHECKSIG
pub fn p2pkh(pk: &PublicKey) -> [u8; 25] {
    let mut s = [0u8; 25];
    s[..3].copy_from_slice(&[0x76, 0xA9, 0x14]);
    s[3..23].copy_from_slice(&hash160(&pk.serialize()));
    s[23..].copy_from_slice(&[0x88, 0xAC]);
    s
}

/// P2SH: OP_HASH160 <hash160(redeem)> OP_EQUAL
pub fn p2sh(redeem: &[u8]) -> [u8; 23] {
    let mut s = [0u8; 23];
    s[..2].copy_from_slice(&[0xA9, 0x14]);
    s[2..22].copy_from_slice(&hash160(redeem));
    s[22] = 0x87;
    s
}

/// P2TR key path for an internal key (BIP-86: no script tree).
pub fn p2tr(internal: &PublicKey) -> [u8; 34] {
    let (q, _) = schnorr::tweak_public_key(&internal.x_only(), None)
        .expect("tweak is valid except with negligible probability");
    let mut s = [0u8; 34];
    s[..2].copy_from_slice(&[0x51, 0x20]);
    s[2..].copy_from_slice(&q);
    s
}

/// The BIP-143 script code for a P2WPKH key (the P2PKH script).
pub fn p2wpkh_script_code(pk: &PublicKey) -> [u8; 25] {
    p2pkh(pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_templates() {
        let k = bp_crypto::secp256k1::SecretKey::from_bytes(&[7; 32])
            .unwrap()
            .public_key();
        assert!(matches!(classify(&p2wpkh(&k)), ScriptKind::P2wpkh(_)));
        assert!(matches!(classify(&p2pkh(&k)), ScriptKind::P2pkh(_)));
        assert!(matches!(classify(&p2sh(&p2wpkh(&k))), ScriptKind::P2sh(_)));
        assert!(matches!(classify(&p2tr(&k)), ScriptKind::P2tr(_)));
        let mut wsh = [0u8; 34];
        wsh[1] = 0x20;
        assert!(matches!(classify(&wsh), ScriptKind::P2wsh(_)));
        assert_eq!(classify(&[0x6A, 0x04, 1, 2, 3, 4]), ScriptKind::OpReturn);
        assert_eq!(classify(&[0x52, 0x02, 1, 2]), ScriptKind::FutureWitness);
        assert_eq!(classify(&[0x00, 0x15, 0]), ScriptKind::Other);
        assert_eq!(classify(&[]), ScriptKind::Other);
    }
}
