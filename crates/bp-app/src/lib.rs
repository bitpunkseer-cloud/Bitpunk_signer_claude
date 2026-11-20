//! Bitpunk Signer application: screen state machine shared by the device
//! firmware and the web simulator. Allocation-free.
#![no_std]

mod menus;
mod settings;

use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::font::{BODY, HUGE, SMALL};
use bp_ui::theme;
use bp_ui::widgets::{self, MenuItem};

pub use menus::MenuId;
pub use settings::Settings;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Git commit the build came from (set by the build script / CI).
pub const GIT_HASH: &str = match option_env!("BP_GIT_HASH") {
    Some(h) => h,
    None => "dev",
};

const SPLASH_MS: u32 = 1800;
const STACK_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Splash,
    Menu {
        id: MenuId,
        sel: u8,
    },
    /// Feature not built yet: title + roadmap phase.
    Placeholder {
        title: &'static str,
        phase: &'static str,
    },
    About,
    PoweredOff,
}

pub struct App {
    stack: [Screen; STACK_DEPTH],
    depth: usize,
    pub settings: Settings,
    dirty: bool,
    splash_ms: u32,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            stack: [Screen::Splash; STACK_DEPTH],
            depth: 1,
            settings: Settings::default(),
            dirty: true,
            splash_ms: 0,
        }
    }

    pub fn current(&self) -> Screen {
        self.stack[self.depth - 1]
    }

    fn set_current(&mut self, s: Screen) {
        self.stack[self.depth - 1] = s;
        self.dirty = true;
    }

    fn push(&mut self, s: Screen) {
        if self.depth < STACK_DEPTH {
            self.stack[self.depth] = s;
            self.depth += 1;
        } else {
            self.set_current(s);
        }
        self.dirty = true;
    }

    fn pop(&mut self) {
        if self.depth > 1 {
            self.depth -= 1;
            self.dirty = true;
        }
    }

    fn reset_to(&mut self, s: Screen) {
        self.depth = 1;
        self.set_current(s);
    }

    /// Advance timers. Returns true when the screen needs redrawing.
    pub fn tick(&mut self, dt_ms: u32) -> bool {
        if self.current() == Screen::Splash {
            self.splash_ms = self.splash_ms.saturating_add(dt_ms);
            if self.splash_ms >= SPLASH_MS {
                self.reset_to(Screen::Menu {
                    id: MenuId::Main,
                    sel: 0,
                });
            }
        }
        core::mem::take(&mut self.dirty)
    }

    pub fn on_key(&mut self, ev: KeyEvent) {
        match self.current() {
            Screen::Splash => self.reset_to(Screen::Menu {
                id: MenuId::Main,
                sel: 0,
            }),
            Screen::PoweredOff => {
                self.splash_ms = 0;
                self.reset_to(Screen::Splash);
            }
            Screen::Placeholder { .. } | Screen::About => {
                if matches!(ev.key, Key::Esc | Key::Backspace | Key::Enter | Key::Left) {
                    self.pop();
                }
            }
            Screen::Menu { id, sel } => self.menu_key(id, sel, ev),
        }
    }

    fn menu_key(&mut self, id: MenuId, sel: u8, ev: KeyEvent) {
        let n = menus::len(id) as u8;
        match ev.key {
            Key::Up => self.set_current(Screen::Menu {
                id,
                sel: if sel == 0 { n - 1 } else { sel - 1 },
            }),
            Key::Down | Key::Tab => self.set_current(Screen::Menu {
                id,
                sel: (sel + 1) % n,
            }),
            Key::Esc | Key::Backspace => self.pop(),
            Key::Left if menus::is_settings(id) => self.change_setting(id, sel, -1),
            Key::Right if menus::is_settings(id) => self.change_setting(id, sel, 1),
            Key::Left => self.pop(),
            Key::Enter | Key::Right => self.activate(id, sel),
            Key::Char(c @ '1'..='9') => {
                let i = c as u8 - b'1';
                if i < n {
                    self.set_current(Screen::Menu { id, sel: i });
                    self.activate(id, i);
                }
            }
            _ => {}
        }
    }

    fn change_setting(&mut self, id: MenuId, sel: u8, dir: i8) {
        if self.settings.cycle(id, sel, dir) {
            self.dirty = true;
        }
    }

    fn activate(&mut self, id: MenuId, sel: u8) {
        match menus::action(id, sel) {
            menus::Action::Open(sub) => self.push(Screen::Menu { id: sub, sel: 0 }),
            menus::Action::Todo { title, phase } => self.push(Screen::Placeholder { title, phase }),
            menus::Action::CycleSetting => self.change_setting(id, sel, 1),
            menus::Action::About => self.push(Screen::About),
            menus::Action::PowerOff => self.reset_to(Screen::PoweredOff),
        }
    }

    pub fn render(&self, c: &mut dyn Canvas) {
        let (w, h) = (c.width() as i32, c.height() as i32);
        c.fill_rect(0, 0, w, h, theme::BG);
        let net = self.settings.network;
        let mainnet = net == bp_bitcoin::Network::Mainnet;
        match self.current() {
            Screen::Splash => render_splash(c),
            Screen::PoweredOff => {
                widgets::message_panel(
                    c,
                    "Powered off",
                    &[
                        "All secrets were wiped from memory.",
                        "",
                        "Press any key to boot again.",
                    ],
                );
            }
            Screen::Menu { id, sel } => {
                widgets::status_bar(c, menus::title(id), net.badge(), mainnet);
                let mut items: [MenuItem; menus::MAX_ITEMS] = core::array::from_fn(|_| MenuItem {
                    label: "",
                    detail: "",
                });
                let n = menus::len(id);
                for (i, item) in items.iter_mut().enumerate().take(n) {
                    let entry = menus::entry(id, i as u8);
                    item.label = entry.label;
                    item.detail = self.settings.value_label(id, i as u8).unwrap_or(entry.detail);
                }
                widgets::menu_list(c, &items[..n], sel as usize);
                if menus::is_settings(id) {
                    widgets::hint_bar(c, &[("^v", "Move"), ("<>", "Change"), ("Esc", "Back")]);
                } else if id == MenuId::Main {
                    widgets::hint_bar(c, &[("^v", "Move"), ("Enter", "Select"), ("1-9", "Jump")]);
                } else {
                    widgets::hint_bar(c, &[("^v", "Move"), ("Enter", "Select"), ("Esc", "Back")]);
                }
            }
            Screen::Placeholder { title, phase } => {
                widgets::status_bar(c, title, net.badge(), mainnet);
                widgets::message_panel(c, title, &["Not built yet.", "", phase, "See docs/ROADMAP.md"]);
                widgets::hint_bar(c, &[("Esc", "Back")]);
            }
            Screen::About => {
                widgets::status_bar(c, "About", net.badge(), mainnet);
                widgets::info_rows(
                    c,
                    &[
                        ("Firmware", VERSION),
                        ("Build", GIT_HASH),
                        ("Display", "800 x 480"),
                        ("Radios", "None (no Wi-Fi / BT / NFC)"),
                        ("USB data", "None"),
                        ("Data out", "QR codes and microSD only"),
                        ("Updates", "microSD only"),
                    ],
                );
                widgets::hint_bar(c, &[("Esc", "Back")]);
            }
        }
    }
}

fn render_splash(c: &mut dyn Canvas) {
    let (w, h) = (c.width() as i32, c.height() as i32);
    let y = h / 2 - HUGE.height as i32 + 10;
    let bw = HUGE.text_width("BITPUNK");
    let x = (w - bw) / 2;
    HUGE.draw(c, x, y, "BIT", theme::ACCENT);
    HUGE.draw(c, x + HUGE.text_width("BIT"), y, "PUNK", theme::TEXT);
    let sy = y + HUGE.height as i32;
    BODY.draw_centered(c, 0, w, sy, "S I G N E R", theme::TEXT_DIM);
    c.fill_rect(w / 2 - 40, sy + BODY.height as i32 + 18, 80, 2, theme::ACCENT);
    SMALL.draw_centered(c, 0, w, h - 60, "Air-gapped Bitcoin signer", theme::TEXT_FAINT);
    let mut buf = [0u8; 48];
    let ver = fmt_version(&mut buf);
    SMALL.draw_centered(c, 0, w, h - 36, ver, theme::TEXT_FAINT);
}

fn fmt_version(buf: &mut [u8; 48]) -> &str {
    let mut n = 0;
    for part in ["v", VERSION, " / ", GIT_HASH] {
        for &b in part.as_bytes() {
            if n < buf.len() {
                buf[n] = b;
                n += 1;
            }
        }
    }
    core::str::from_utf8(&buf[..n]).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_hal::input::Key;

    fn press(app: &mut App, k: Key) {
        app.on_key(KeyEvent::new(k));
    }

    #[test]
    fn splash_times_out_to_main_menu() {
        let mut app = App::new();
        assert_eq!(app.current(), Screen::Splash);
        app.tick(SPLASH_MS);
        assert_eq!(
            app.current(),
            Screen::Menu {
                id: MenuId::Main,
                sel: 0
            }
        );
    }

    #[test]
    fn navigate_into_settings_and_back() {
        let mut app = App::new();
        press(&mut app, Key::Enter); // skip splash
        press(&mut app, Key::Char('4')); // Settings
        assert!(matches!(
            app.current(),
            Screen::Menu {
                id: MenuId::Settings,
                ..
            }
        ));
        press(&mut app, Key::Esc);
        assert!(matches!(app.current(), Screen::Menu { id: MenuId::Main, .. }));
    }

    #[test]
    fn network_setting_cycles() {
        let mut app = App::new();
        press(&mut app, Key::Enter);
        press(&mut app, Key::Char('4'));
        let before = app.settings.network;
        press(&mut app, Key::Right);
        assert_ne!(app.settings.network, before);
    }

    #[test]
    fn up_wraps_to_last_item() {
        let mut app = App::new();
        press(&mut app, Key::Enter);
        press(&mut app, Key::Up);
        let n = menus::len(MenuId::Main) as u8;
        assert_eq!(
            app.current(),
            Screen::Menu {
                id: MenuId::Main,
                sel: n - 1
            }
        );
    }
}
