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
//! | `bp_frame_buffer()` | greyscale camera frame JS fills (up to 1024 x 768) |
//! | `bp_frame(w, h)` | hand the frame to the scanner (only while scanning) |
//! | `bp_text_buffer()` / `bp_text(len)` | pasted QR content (UTF-8, up to 8 KB) |
//! | `bp_wants_camera() -> u32` | 1 while the scan screen is open |
//!
//! No wasm-bindgen: JS reads the framebuffer straight from linear memory.

mod framebuffer;

use bp_app::App;
use bp_hal::input::KeyEvent;
use framebuffer::Framebuffer;
use std::cell::RefCell;

/// Largest camera frame the page may send (the scanner limit is 1024).
const FRAME_W: usize = 1024;
const FRAME_H: usize = 768;
const TEXT_MAX: usize = 8192;

struct Sim {
    app: App,
    fb: Framebuffer,
    frame: Vec<u8>,
    text: Vec<u8>,
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
        frame: vec![0; FRAME_W * FRAME_H],
        text: vec![0; TEXT_MAX],
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

#[no_mangle]
pub extern "C" fn bp_frame_buffer() -> *mut u8 {
    with_sim(|s| s.frame.as_mut_ptr()).unwrap_or(core::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn bp_frame(width: u32, height: u32) {
    let (w, h) = (width as usize, height as usize);
    if w == 0 || h == 0 || w > FRAME_W || h > FRAME_H {
        return;
    }
    with_sim(|s| {
        let Sim { app, frame, .. } = s;
        app.on_frame(&frame[..w * h], w, h);
    });
}

#[no_mangle]
pub extern "C" fn bp_text_buffer() -> *mut u8 {
    with_sim(|s| s.text.as_mut_ptr()).unwrap_or(core::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn bp_text(len: u32) {
    let n = (len as usize).min(TEXT_MAX);
    with_sim(|s| {
        let Sim { app, text, .. } = s;
        app.on_qr_text(&text[..n]);
        text[..n].fill(0);
    });
}

#[no_mangle]
pub extern "C" fn bp_wants_camera() -> u32 {
    with_sim(|s| s.app.wants_camera() as u32).unwrap_or(0)
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
        // main menu 1 = Scan QR; pasted text arrives through the buffer
        bp_key(0, '1' as u32, 0);
        assert_eq!(bp_wants_camera(), 1);
        let addr = b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
        unsafe { core::ptr::copy_nonoverlapping(addr.as_ptr(), bp_text_buffer(), addr.len()) };
        bp_text(addr.len() as u32);
        assert_eq!(bp_wants_camera(), 0); // result screen
        bp_frame(640, 480); // ignored outside the scan screen
    }
}
