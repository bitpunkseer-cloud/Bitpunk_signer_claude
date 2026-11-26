//! Task efficiency (M9-9): the keys pressed and the screens passed through
//! while a test plays a core task the way a user would (menu digits, Enter,
//! arrows). The M8 numbers below were measured by the same module and the
//! same task scripts on the last M8 build (c027ae4); M9 must not need more,
//! except for intended changes named in the table (docs/M9_TASKS.md).

extern crate std;

use crate::Screen;
use core::cell::RefCell;
use std::string::String;

struct Count {
    keys: u32,
    screens: u32,
    last: String,
}

std::thread_local! {
    static COUNT: RefCell<Option<Count>> = const { RefCell::new(None) };
}

/// The screen without its selection: moving the cursor is not a new screen.
fn id(s: &Screen) -> String {
    let d = std::format!("{s:?}");
    let mut out = String::new();
    let mut rest = d.as_str();
    while let Some(p) = rest.find("sel: ") {
        out.push_str(&rest[..p]);
        rest = rest[p + 5..].trim_start_matches(|c: char| c.is_ascii_digit());
    }
    out.push_str(rest);
    out
}

/// Start counting on screen `s`.
pub fn start(s: &Screen) {
    COUNT.with(|c| {
        *c.borrow_mut() = Some(Count {
            keys: 0,
            screens: 0,
            last: id(s),
        })
    });
}

/// Called by `App::on_key` before and after each key.
pub fn seen(s: &Screen) {
    COUNT.with(|c| {
        if let Some(c) = c.borrow_mut().as_mut() {
            let now = id(s);
            if now != c.last {
                c.screens += 1;
                c.last = now;
            }
        }
    });
}

/// Called by `App::on_key` for each key.
pub fn key() {
    COUNT.with(|c| {
        if let Some(c) = c.borrow_mut().as_mut() {
            c.keys += 1;
        }
    });
}

/// Stop counting on screen `s`: (keys, screens).
pub fn finish(s: &Screen) -> (u32, u32) {
    seen(s);
    COUNT.with(|c| c.borrow_mut().take().map_or((0, 0), |c| (c.keys, c.screens)))
}

/// (task, keys, screens) measured on the last M8 build (c027ae4) with the
/// same scripts (cargo test -p bp-app task_ -- --nocapture).
pub const M8: &[(&str, u32, u32)] = &[
    ("power-on", 0, 0),
    ("seed-dice-12", 74, 12),
    ("seed-typed-12", 53, 6),
    ("xpub-qr", 5, 5),
    ("psbt-qr", 8, 8),
    ("psbt-qr-fn-q", 8, 8),
    ("psbt-sd", 11, 10),
    ("multisig-register", 18, 11),
];

/// More keys and screens allowed by an intended change (keys, screens, why).
pub const ALLOWED: &[(&str, u32, u32, &str)] = &[
    ("power-on", 1, 1, "C3 first-run screen, once per power on"),
    (
        "psbt-qr",
        1,
        1,
        "C1 Sign submenu; Fn+Q from any menu stays one key",
    ),
    (
        "seed-typed-12",
        1,
        1,
        "M11 E3: every typed word once more (and the fingerprint) before loading",
    ),
];

/// Print a task's counts and check them against the M8 build.
pub fn check(name: &str, keys: u32, screens: u32) {
    let (_, k8, s8) = *M8
        .iter()
        .find(|t| t.0 == name)
        .unwrap_or_else(|| panic!("no M8 count for {name}"));
    let (ek, es) = ALLOWED
        .iter()
        .find(|t| t.0 == name)
        .map_or((0, 0), |t| (t.1, t.2));
    std::println!("TASK {name} keys={keys} (M8 {k8}) screens={screens} (M8 {s8})");
    assert!(keys <= k8 + ek, "{name}: {keys} keys, M8 needed {k8}");
    assert!(screens <= s8 + es, "{name}: {screens} screens, M8 showed {s8}");
}
