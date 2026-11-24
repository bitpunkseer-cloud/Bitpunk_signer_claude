//! Error codes (M9, UX language C8): every refusal and failure screen shows
//! a short, stable code at the right of the key bar — `E-<AREA>-<NN>`, NN =
//! the message's place in its table, from 01 — so the user guide (M14) can
//! explain each one. The full list is docs/ERROR_CODES.md, kept in step with
//! the message tables by a test.

use bp_ui::fmt::Buf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Area {
    /// The microSD card cannot be used.
    Card,
    /// A file could not be saved to the card.
    Save,
    /// The transaction review: warnings, refusals and attacks.
    Tx,
    /// Signing failed after approval.
    Sign,
    /// A multisig wallet was refused.
    Wallet,
    /// An imported private key was refused.
    Key,
    /// A message signing request was refused.
    Msg,
    /// Address verification could not run.
    Addr,
    /// A signature could not be checked.
    Sig,
    /// A settings QR or file was refused.
    Settings,
    /// The board itself: a network chip answered at boot.
    Hw,
}

impl Area {
    #[cfg(test)]
    pub const ALL: [Area; 11] = [
        Area::Card,
        Area::Save,
        Area::Tx,
        Area::Sign,
        Area::Wallet,
        Area::Key,
        Area::Msg,
        Area::Addr,
        Area::Sig,
        Area::Settings,
        Area::Hw,
    ];

    pub fn tag(self) -> &'static str {
        match self {
            Area::Card => "CARD",
            Area::Save => "SAVE",
            Area::Tx => "TX",
            Area::Sign => "SIGN",
            Area::Wallet => "WAL",
            Area::Key => "KEY",
            Area::Msg => "MSG",
            Area::Addr => "ADR",
            Area::Sig => "SIG",
            Area::Settings => "SET",
            Area::Hw => "HW",
        }
    }
}

/// `E-CARD-03` for the third card problem.
pub fn code(area: Area, index: usize) -> Buf<16> {
    let n = index + 1;
    let mut b = Buf::new();
    b.push_str("E-");
    b.push_str(area.tag());
    b.push_str("-");
    let d = [b'0' + (n / 10 % 10) as u8, b'0' + (n % 10) as u8];
    b.push_str(core::str::from_utf8(&d).unwrap_or("??"));
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_short_and_padded() {
        assert_eq!(code(Area::Card, 2).as_str(), "E-CARD-03");
        assert_eq!(code(Area::Tx, 52).as_str(), "E-TX-53");
        assert_eq!(code(Area::Hw, 0).as_str(), "E-HW-01");
    }
}
