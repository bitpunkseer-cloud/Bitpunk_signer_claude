//! QWERTY keyboard events.

/// Keys on the device keyboard.
///
/// Layout (Coldcard-Q-style, see docs/HARDWARE_REQUIREMENTS.md): a function
/// cluster with QR, TAB, a D-pad, CANCEL and ENTER above a 10-column QWERTY
/// with SHIFT/CAPS, SPACE, SYM and DEL. CANCEL is reported as `Esc`, DEL as
/// `Backspace`. SHIFT and SYM are resolved by the keyboard driver into `Char`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Printable character, already shifted (e.g. 'A', '!', ' ').
    Char(char),
    Enter,
    Esc,
    Backspace,
    Delete,
    Tab,
    Up,
    Down,
    Left,
    Right,
    /// Function key F1..F12 (not on the device keyboard; kept for hosts).
    F(u8),
    /// Dedicated QR key: open the camera scanner.
    Qr,
}

/// Modifier key state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mods(pub u8);

impl Mods {
    pub const SHIFT: u8 = 1;
    pub const CTRL: u8 = 2;
    pub const ALT: u8 = 4;
    pub const FN: u8 = 8;

    pub const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub key: Key,
    pub mods: Mods,
}

impl KeyEvent {
    pub const fn new(key: Key) -> Self {
        Self { key, mods: Mods(0) }
    }

    /// Decode the compact wire format used by the simulator:
    /// `code` 0 = char (`ch` holds the Unicode scalar), 1.. = special keys.
    pub fn from_code(code: u32, ch: u32, mods: u32) -> Option<Self> {
        let key = match code {
            0 => Key::Char(char::from_u32(ch)?),
            1 => Key::Enter,
            2 => Key::Esc,
            3 => Key::Backspace,
            4 => Key::Delete,
            5 => Key::Tab,
            6 => Key::Up,
            7 => Key::Down,
            8 => Key::Left,
            9 => Key::Right,
            10 => Key::Qr,
            n @ 101..=112 => Key::F((n - 100) as u8),
            _ => return None,
        };
        Some(Self {
            key,
            mods: Mods(mods as u8),
        })
    }
}
