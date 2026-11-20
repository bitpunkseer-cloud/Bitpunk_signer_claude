//! WASM host for the simulator. Exposes a tiny C ABI to JavaScript:
//!
//! | export | purpose |
//! |---|---|
//! | `bp_seed_buffer()` | 32-byte buffer JS fills with browser randomness before `bp_init` (quiz shuffling only, never seed material) |
//! | `bp_init()` | create the app, draw the first frame |
//! | `bp_width()/bp_height()` | framebuffer size |
//! | `bp_framebuffer()` | pointer to RGBA8 pixels |
//! | `bp_key(code, ch, mods)` | key event (see `KeyEvent::from_code`) |
//! | `bp_tick(ms) -> u32` | advance time; 1 = framebuffer changed |
//!
//! No wasm-bindgen: JS reads the framebuffer straight from linear memory.

mod framebuffer;

use bp_app::App;
use bp_hal::input::KeyEvent;
use framebuffer::Framebuffer;
use std::cell::RefCell;

struct Sim {
    app: App,
    fb: Framebuffer,
}

thread_local! {
    static SIM: RefCell<Option<Sim>> = const { RefCell::new(None) };
    static QUIZ_SEED: RefCell<[u8; 32]> = const { RefCell::new([0u8; 32]) };
}

/// Buffer for JS to fill with `crypto.getRandomValues` before `bp_init`.
/// Only shuffles backup-quiz questions; seeds come from dice and coins.
#[no_mangle]
pub extern "C" fn bp_seed_buffer() -> *mut u8 {
    QUIZ_SEED.with(|b| b.borrow_mut().as_mut_ptr())
}

fn with_sim<R>(f: impl FnOnce(&mut Sim) -> R) -> Option<R> {
    SIM.with(|s| s.borrow_mut().as_mut().map(f))
}

#[no_mangle]
pub extern "C" fn bp_init() {
    let seed = QUIZ_SEED.with(|b| *b.borrow());
    let mut sim = Sim {
        app: App::new(&seed),
        fb: Framebuffer::new(),
    };
    sim.app.set_test_only(true); // a web page is not air-gapped
    sim.app.tick(0);
    sim.app.render(&mut sim.fb);
    SIM.with(|s| *s.borrow_mut() = Some(sim));
}

#[no_mangle]
pub extern "C" fn bp_width() -> u32 {
    framebuffer::W as u32
}

#[no_mangle]
pub extern "C" fn bp_height() -> u32 {
    framebuffer::H as u32
}

#[no_mangle]
pub extern "C" fn bp_framebuffer() -> *const u8 {
    with_sim(|s| s.fb.as_ptr()).unwrap_or(core::ptr::null())
}

#[no_mangle]
pub extern "C" fn bp_key(code: u32, ch: u32, mods: u32) {
    if let Some(ev) = KeyEvent::from_code(code, ch, mods) {
        with_sim(|s| s.app.on_key(ev));
    }
}

#[no_mangle]
pub extern "C" fn bp_tick(ms: u32) -> u32 {
    with_sim(|s| {
        if s.app.tick(ms) {
            s.app.render(&mut s.fb);
            1
        } else {
            0
        }
    })
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boots_and_renders() {
        bp_init();
        assert!(!bp_framebuffer().is_null());
        bp_key(1, 0, 0); // Enter: leave splash
        assert_eq!(bp_tick(16), 1);
        assert_eq!(bp_tick(16), 0);
    }
}
