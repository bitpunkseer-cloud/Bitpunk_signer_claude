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
//! | `bp_sd_insert(on)` / `bp_sd_state()` | virtual microSD in or out; state bits (1 present, then power cycles << 1) |
//! | `bp_file_buffer(len)` | buffer JS fills with a file name and/or contents |
//! | `bp_sd_put(name_len, data_len) -> u32` | copy a file onto the card like a computer would (0 = done) |
//! | `bp_sd_list() -> u32` / `bp_out_ptr()` | card listing as `path\tsize\n` lines |
//! | `bp_sd_get(path_len) -> u32` | file contents into the out buffer (`u32::MAX` on error) |
//! | `bp_sd_delete(path_len) -> u32` / `bp_sd_erase() -> u32` | delete one file / reformat the card |
//!
//! No wasm-bindgen: JS reads the framebuffer straight from linear memory.

mod card;
mod framebuffer;

use bp_app::App;
use bp_hal::input::KeyEvent;
use card::VirtualCard;
use framebuffer::Framebuffer;
use std::cell::RefCell;

/// Largest camera frame the page may send (the scanner limit is 1024).
const FRAME_W: usize = 1024;
const FRAME_H: usize = 768;
const TEXT_MAX: usize = 48 * 1024;

/// Render the app with the screen effects of its settings (M9-2).
fn draw(s: &mut Sim) {
    let fx = s.app.settings.fx;
    let mut c = bp_ui::fx::FxCanvas::new(&mut s.fb, fx);
    s.app.render(&mut c);
    c.finish(s.app.qr_area());
}

struct Sim {
    app: App,
    fb: Framebuffer,
    frame: Vec<u8>,
    text: Vec<u8>,
    card: VirtualCard,
    file: Vec<u8>,
    out: Vec<u8>,
}

impl Sim {
    /// Run card jobs the app queued (the device firmware does the same
    /// after every event).
    fn serve_card(&mut self) {
        while self.app.sd_pending() {
            self.app.sd_service(&mut self.card);
        }
    }
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
        card: VirtualCard::new(&seed),
        file: Vec::new(),
        out: Vec::new(),
    };
    sim.app.set_test_only(true); // a web page is not air-gapped
    sim.app.set_card_present(true);
    sim.app.tick(0);
    draw(&mut sim);
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
        with_sim(|s| {
            s.app.on_key(ev);
            s.serve_card();
        });
    }
}

#[no_mangle]
pub extern "C" fn bp_tick(ms: u32) -> u32 {
    with_sim(|s| {
        s.serve_card();
        if s.app.tick(ms) {
            draw(s);
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

/// Length of the signed PSBT while its review is open (0 otherwise).
#[no_mangle]
pub extern "C" fn bp_signed_len() -> u32 {
    with_sim(|s| s.app.signed_psbt().map_or(0, |p| p.len() as u32)).unwrap_or(0)
}

/// The signed PSBT bytes (valid while `bp_signed_len` is non-zero).
#[no_mangle]
pub extern "C" fn bp_signed_ptr() -> *const u8 {
    with_sim(|s| s.app.signed_psbt().map_or(core::ptr::null(), |p| p.as_ptr())).unwrap_or(core::ptr::null())
}

#[no_mangle]
pub extern "C" fn bp_sd_insert(on: u32) {
    with_sim(|s| {
        s.card.present = on != 0;
        s.app.set_card_present(on != 0);
        s.serve_card();
    });
}

/// Bit 0: card present. Bits 1..: card power cycles (for the SD LED).
#[no_mangle]
pub extern "C" fn bp_sd_state() -> u32 {
    with_sim(|s| s.card.present as u32 | (s.card.cycles << 1)).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn bp_file_buffer(len: u32) -> *mut u8 {
    with_sim(|s| {
        s.file.clear();
        s.file.resize(len as usize, 0);
        s.file.as_mut_ptr()
    })
    .unwrap_or(core::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn bp_out_ptr() -> *const u8 {
    with_sim(|s| s.out.as_ptr()).unwrap_or(core::ptr::null())
}

/// File name (`name_len` bytes) then contents, from `bp_file_buffer`.
#[no_mangle]
pub extern "C" fn bp_sd_put(name_len: u32, data_len: u32) -> u32 {
    with_sim(|s| {
        let (n, d) = (name_len as usize, data_len as usize);
        if n + d > s.file.len() {
            return card::ERR_OTHER;
        }
        let r = s.card.put(&s.file[..n], &s.file[n..n + d]);
        s.app.card_changed();
        s.serve_card();
        r
    })
    .unwrap_or(card::ERR_OTHER)
}

#[no_mangle]
pub extern "C" fn bp_sd_list() -> u32 {
    with_sim(|s| {
        s.out = s.card.list();
        s.out.len() as u32
    })
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn bp_sd_get(path_len: u32) -> u32 {
    with_sim(|s| {
        let p = String::from_utf8_lossy(&s.file[..(path_len as usize).min(s.file.len())]).into_owned();
        match s.card.get(&p) {
            Some(data) => {
                s.out = data;
                s.out.len() as u32
            }
            None => u32::MAX,
        }
    })
    .unwrap_or(u32::MAX)
}

#[no_mangle]
pub extern "C" fn bp_sd_delete(path_len: u32) -> u32 {
    with_sim(|s| {
        let p = String::from_utf8_lossy(&s.file[..(path_len as usize).min(s.file.len())]).into_owned();
        let r = s.card.delete(&p);
        s.app.card_changed();
        s.serve_card();
        r
    })
    .unwrap_or(card::ERR_OTHER)
}

/// Reformat the virtual card (as a computer would).
#[no_mangle]
pub extern "C" fn bp_sd_erase() -> u32 {
    with_sim(|s| {
        s.card.erase();
        s.app.card_changed();
        s.serve_card();
        0
    })
    .unwrap_or(card::ERR_OTHER)
}

/// Simulate the boot-time network chip check: 0 not run, 1 clean, 2 a PHY
/// answered (the device locks itself).
#[no_mangle]
pub extern "C" fn bp_comm_check(state: u32) {
    use bp_hal::mdio::PhyFound;
    use bp_hal::CommCheck;
    let c = match state {
        1 => CommCheck::Clean,
        2 => CommCheck::Detected(PhyFound {
            addr: 1,
            id: 0x001C_C916,
        }),
        _ => CommCheck::NotRun,
    };
    with_sim(|s| s.app.set_comm_check(c));
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

    #[test]
    fn virtual_card_round_trip() {
        bp_init();
        let put = |name: &str, data: &[u8]| {
            let p = bp_file_buffer((name.len() + data.len()) as u32);
            unsafe {
                core::ptr::copy_nonoverlapping(name.as_ptr(), p, name.len());
                core::ptr::copy_nonoverlapping(data.as_ptr(), p.add(name.len()), data.len());
            }
            bp_sd_put(name.len() as u32, data.len() as u32)
        };
        assert_eq!(put("tx.psbt", b"psbt\xff"), 0);
        // same name again: kept, the copy gets a number
        assert_eq!(put("tx.psbt", b"second"), 0);
        // characters FAT forbids become '_'
        assert_eq!(put("a:b?.txt", b"x"), 0);
        let n = bp_sd_list() as usize;
        let list = unsafe { std::slice::from_raw_parts(bp_out_ptr(), n) };
        let list = String::from_utf8(list.to_vec()).unwrap();
        assert!(list.contains("tx.psbt\t5\n"), "{list}");
        assert!(list.contains("tx-2.psbt\t6\n"), "{list}");
        assert!(list.contains("a_b_.txt\t1\n"), "{list}");
        let path = "tx-2.psbt";
        let p = bp_file_buffer(path.len() as u32);
        unsafe { core::ptr::copy_nonoverlapping(path.as_ptr(), p, path.len()) };
        let n = bp_sd_get(path.len() as u32);
        assert_eq!(n, 6);
        assert_eq!(unsafe { std::slice::from_raw_parts(bp_out_ptr(), 6) }, b"second");
        assert_eq!(bp_sd_delete(path.len() as u32), 0);
        assert_eq!(bp_sd_get(path.len() as u32), u32::MAX);
        assert_eq!(bp_sd_state() & 1, 1);
        bp_sd_insert(0);
        assert_eq!(bp_sd_state() & 1, 0);
        bp_sd_insert(1);
        assert_eq!(bp_sd_erase(), 0);
        assert_eq!(bp_sd_list(), 0);
    }
}
