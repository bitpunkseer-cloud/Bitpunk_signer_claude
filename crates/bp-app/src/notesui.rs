//! Secure notes and passwords (M11-6, decision 9): Backup & tools > Secure
//! notes. Kept in the vault when it is open (encrypted with everything
//! else, saved as they change), for the session otherwise. Shown on the
//! screen or as a QR code; a password can be made from dice.

use crate::vaultdata::{Field, Note, NoteKind, MAX_NOTES};
use crate::{typed, App, Pick, QrKind, Screen};
use bp_crypto::secret::wipe;
use bp_hal::input::{Key, KeyEvent};
use bp_hal::Canvas;
use bp_ui::fmt::{fill, Buf};
use bp_ui::font::{BODY, SMALL, TITLE};
use bp_ui::widgets::{self, MenuItem, Tag, MARGIN, STATUS_H};
use bp_ui::{grid, theme};

/// Dice rolls a generated password needs (129 bits).
pub const MIN_DICE: usize = 50;
const MAX_DICE: usize = 200;
/// Characters of a generated password (Base58, 117 bits).
pub const PASSWORD_LEN: usize = 20;
const TEXT_MAX: usize = 400;

/// Steps of the notes screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteStep {
    /// The notes, then "New note" and "New password".
    List { sel: u8 },
    /// One note: show the password, QR, edit, delete.
    View { idx: u8, sel: u8 },
    /// The draft's fields, then "Save".
    Edit { sel: u8 },
    /// Typing one field of the draft.
    Field { field: u8 },
    /// Rolling dice for a password.
    Generate,
    /// Delete a note (type WIPE).
    Delete { idx: u8 },
}

/// What a row of the edit screen does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EditRow {
    Field(Field),
    Generate,
    Save,
}

/// What a row of a note's screen does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ViewRow {
    Show,
    Qr,
    Edit,
    Delete,
}

/// State of the notes screens; wiped when they close.
pub struct NotesState {
    /// The note being written; `editing` is its index (`None`: new).
    pub draft: Note,
    pub editing: Option<u8>,
    /// The field being typed.
    input: [u8; TEXT_MAX],
    pub input_len: usize,
    /// The password is shown (note screen) / typed text is shown.
    pub show: bool,
    dice: [u8; MAX_DICE],
    pub dice_len: usize,
}

impl Drop for NotesState {
    fn drop(&mut self) {
        wipe(&mut self.input);
        wipe(&mut self.dice);
    }
}

impl NotesState {
    fn new() -> NotesState {
        NotesState {
            draft: Note::new(NoteKind::Text),
            editing: None,
            input: [0; TEXT_MAX],
            input_len: 0,
            show: false,
            dice: [0; MAX_DICE],
            dice_len: 0,
        }
    }

    pub fn input(&self) -> &[u8] {
        &self.input[..self.input_len]
    }

    fn edit_rows(&self) -> ([EditRow; 7], usize) {
        let mut rows = [EditRow::Save; 7];
        let mut n = 0;
        for &f in self.draft.fields() {
            rows[n] = EditRow::Field(f);
            n += 1;
            if f == Field::Secret {
                rows[n] = EditRow::Generate;
                n += 1;
            }
        }
        rows[n] = EditRow::Save;
        (rows, n + 1)
    }
}

fn view_rows(kind: NoteKind) -> &'static [ViewRow] {
    match kind {
        NoteKind::Password => &[ViewRow::Show, ViewRow::Qr, ViewRow::Edit, ViewRow::Delete],
        NoteKind::Text => &[ViewRow::Qr, ViewRow::Edit, ViewRow::Delete],
    }
}

/// A password from dice: the first 20 Base58 characters of SHA-256 of the
/// rolls as typed (`1`–`6`).
pub fn password_from_dice(dice: &[u8], out: &mut [u8; PASSWORD_LEN]) {
    let mut h = bp_crypto::sha256::Sha256::digest(dice);
    let mut text = [0u8; 64];
    let n = bp_bitcoin::base58::encode(&h, &mut text).unwrap_or(0);
    out.copy_from_slice(&text[..PASSWORD_LEN.min(n)]);
    wipe(&mut h);
    wipe(&mut text);
}

impl App {
    fn nt_step(&mut self, step: NoteStep) {
        self.set_current(Screen::Notes { step });
    }

    /// Backup & tools > Secure notes.
    pub(crate) fn notes_action(&mut self) {
        self.notes = Some(NotesState::new());
        self.push(Screen::Notes {
            step: NoteStep::List { sel: 0 },
        });
    }

    /// The note shown as a QR (its password, or its text).
    pub(crate) fn note_qr(&self, idx: u8) -> Option<crate::qrview::QrSession> {
        use crate::qrview::{Density, Format, QrSession, Speed};
        let n = self.vault.data.note(idx as usize)?;
        let v = match n.kind {
            NoteKind::Password => n.get(Field::Secret),
            NoteKind::Text => n.get(Field::Text),
        };
        if v.is_empty() {
            return None;
        }
        QrSession::new(Format::Static, v, Density::Auto, Speed::Slow)
    }

    fn nt_edit(&mut self, draft: Note, editing: Option<u8>) {
        if let Some(st) = self.notes.as_mut() {
            st.draft = draft;
            st.editing = editing;
        }
        self.nt_step(NoteStep::Edit { sel: 0 });
    }

    fn nt_back_from_edit(&mut self) {
        let editing = self.notes.as_ref().and_then(|s| s.editing);
        match editing {
            Some(idx) => self.nt_step(NoteStep::View { idx, sel: 0 }),
            None => self.nt_step(NoteStep::List { sel: 0 }),
        }
    }

    pub(crate) fn notes_key(&mut self, step: NoteStep, ev: KeyEvent) {
        let t = self.text().bk;
        self.notice = None;
        if self.notes.is_none() {
            self.pop();
            return;
        }
        let count = self.vault.data.note_count();
        match step {
            NoteStep::List { sel } => match crate::pick(ev.key, sel, count as u8 + 2) {
                Pick::Move(s) => self.nt_step(NoteStep::List { sel: s }),
                Pick::Choose(i) if (i as usize) < count => {
                    if let Some(st) = self.notes.as_mut() {
                        st.show = false;
                    }
                    self.nt_step(NoteStep::View { idx: i, sel: 0 })
                }
                Pick::Choose(i) => {
                    if count >= MAX_NOTES {
                        self.notice = Some(t.nt_full);
                        return;
                    }
                    let kind = if i as usize == count {
                        NoteKind::Text
                    } else {
                        NoteKind::Password
                    };
                    self.nt_edit(Note::new(kind), None);
                }
                Pick::Back => {
                    self.notes = None;
                    self.pop();
                }
                Pick::None => {}
            },
            NoteStep::View { idx, sel } => {
                let Some(kind) = self.vault.data.note(idx as usize).map(|n| n.kind) else {
                    self.nt_step(NoteStep::List { sel: 0 });
                    return;
                };
                let rows = view_rows(kind);
                match crate::pick(ev.key, sel, rows.len() as u8) {
                    Pick::Move(s) => self.nt_step(NoteStep::View { idx, sel: s }),
                    Pick::Choose(r) => match rows[r as usize] {
                        ViewRow::Show => {
                            if let Some(st) = self.notes.as_mut() {
                                st.show = !st.show;
                            }
                        }
                        ViewRow::Qr => {
                            if self.note_qr(idx).is_some() {
                                self.open_qr(QrKind::Note { idx });
                            }
                        }
                        ViewRow::Edit => {
                            if let Some(n) = self.vault.data.note(idx as usize).cloned() {
                                self.nt_edit(n, Some(idx));
                            }
                        }
                        ViewRow::Delete => {
                            self.typed.clear();
                            self.nt_step(NoteStep::Delete { idx });
                        }
                    },
                    Pick::Back => {
                        if let Some(st) = self.notes.as_mut() {
                            st.show = false;
                        }
                        self.nt_step(NoteStep::List { sel: idx });
                    }
                    Pick::None => {}
                }
            }
            NoteStep::Edit { sel } => {
                let Some(st) = self.notes.as_mut() else { return };
                let (rows, n) = st.edit_rows();
                match crate::pick(ev.key, sel, n as u8) {
                    Pick::Move(s) => self.nt_step(NoteStep::Edit { sel: s }),
                    Pick::Choose(r) => match rows[r as usize] {
                        EditRow::Field(f) => {
                            let v = st.draft.get(f);
                            st.input[..v.len()].copy_from_slice(v);
                            st.input_len = v.len();
                            st.show = true;
                            self.nt_step(NoteStep::Field { field: f as u8 });
                        }
                        EditRow::Generate => {
                            wipe(&mut st.dice);
                            st.dice_len = 0;
                            self.nt_step(NoteStep::Generate);
                        }
                        EditRow::Save => self.nt_save(),
                    },
                    Pick::Back => self.nt_back_from_edit(),
                    Pick::None => {}
                }
            }
            NoteStep::Field { field } => {
                let f = Field::ALL[field as usize % 5];
                let Some(st) = self.notes.as_mut() else { return };
                match ev.key {
                    Key::Char(c) if (' '..='~').contains(&c) && st.input_len < f.max() => {
                        st.input[st.input_len] = c as u8;
                        st.input_len += 1;
                    }
                    Key::Backspace if st.input_len > 0 => {
                        st.input_len -= 1;
                        st.input[st.input_len] = 0;
                    }
                    Key::Tab => st.show = !st.show,
                    Key::Enter => {
                        let v = st.input_len;
                        let mut tmp = [0u8; TEXT_MAX];
                        tmp[..v].copy_from_slice(&st.input[..v]);
                        st.draft.set(f, &tmp[..v]);
                        wipe(&mut tmp);
                        wipe(&mut st.input);
                        st.input_len = 0;
                        let (rows, _) = st.edit_rows();
                        let sel = rows.iter().position(|r| *r == EditRow::Field(f)).unwrap_or(0) as u8;
                        self.nt_step(NoteStep::Edit { sel });
                    }
                    Key::Esc => {
                        wipe(&mut st.input);
                        st.input_len = 0;
                        self.nt_step(NoteStep::Edit { sel: 0 });
                    }
                    _ => {}
                }
            }
            NoteStep::Generate => {
                let Some(st) = self.notes.as_mut() else { return };
                match ev.key {
                    Key::Char(c @ '1'..='6') if st.dice_len < MAX_DICE => {
                        st.dice[st.dice_len] = c as u8;
                        st.dice_len += 1;
                    }
                    Key::Backspace if st.dice_len > 0 => {
                        st.dice_len -= 1;
                        st.dice[st.dice_len] = 0;
                    }
                    Key::Enter if st.dice_len >= MIN_DICE => {
                        let mut pw = [0u8; PASSWORD_LEN];
                        password_from_dice(&st.dice[..st.dice_len], &mut pw);
                        st.draft.set(Field::Secret, &pw);
                        wipe(&mut pw);
                        wipe(&mut st.dice);
                        st.dice_len = 0;
                        let (rows, _) = st.edit_rows();
                        let sel = rows.iter().position(|r| *r == EditRow::Generate).unwrap_or(0) as u8;
                        self.nt_step(NoteStep::Edit { sel });
                    }
                    Key::Enter => self.notice = Some(t.sl_dice_short),
                    Key::Esc => self.nt_step(NoteStep::Edit { sel: 0 }),
                    _ => {}
                }
            }
            NoteStep::Delete { idx } => match self.typed.key(ev.key, typed::WIPE) {
                typed::Typed::Confirmed => {
                    self.vault.data.remove_note(idx as usize);
                    self.notice = Some(t.nt_deleted);
                    self.nt_step(NoteStep::List { sel: 0 });
                }
                typed::Typed::Cancelled => self.nt_step(NoteStep::View { idx, sel: 0 }),
                typed::Typed::Pending => {}
            },
        }
    }

    fn nt_save(&mut self) {
        let t = self.text().bk;
        let Some(st) = self.notes.as_mut() else { return };
        if st.draft.get(Field::Title).is_empty() {
            self.notice = Some(t.nt_no_title);
            return;
        }
        let draft = st.draft.clone();
        let editing = st.editing;
        let ok = match editing {
            Some(i) => self.vault.data.set_note(i as usize, draft),
            None => self.vault.data.add_note(draft),
        };
        if !ok {
            self.notice = Some(t.nt_full);
            return;
        }
        let idx = editing.unwrap_or(self.vault.data.note_count() as u8 - 1);
        if let Some(st) = self.notes.as_mut() {
            st.draft = Note::new(NoteKind::Text);
            st.editing = None;
            st.show = false;
        }
        self.notice = Some(t.nt_saved);
        self.nt_step(NoteStep::View { idx, sel: 0 });
    }

    // ---------- drawing ----------

    pub(crate) fn render_notes(&self, c: &mut dyn Canvas, step: NoteStep) {
        let s = self.text();
        let t = s.bk;
        let Some(st) = self.notes.as_ref() else { return };
        let w = grid::COLS * grid::CELL_W;
        let g = |row| grid::text_y(&BODY, row, 1);
        let bottom = c.height() as i32 - widgets::HINT_H - 8;
        let notice = |c: &mut dyn Canvas, row: i32| {
            if let Some(n) = self.notice {
                widgets::log_line(c, MARGIN, g(row), w, Tag::Info, n, "");
            }
        };
        self.status(c, t.nt_menu);
        match step {
            NoteStep::List { sel } => {
                let count = self.vault.data.note_count();
                let head: Buf<48> = fill(t.nt_count, &[&count]);
                widgets::log_line(c, MARGIN, g(2), w, Tag::Info, head.as_str(), "");
                let (tag, kept) = if self.vault.is_open() {
                    (Tag::Ok, t.nt_kept)
                } else {
                    (Tag::Warn, t.nt_session)
                };
                widgets::log_line(c, MARGIN, g(3), w, tag, kept, "");
                let items: [MenuItem; MAX_NOTES + 2] = core::array::from_fn(|i| {
                    if i < count {
                        let n = self.vault.data.note(i);
                        MenuItem {
                            label: n.map_or("", |n| n.text_of(Field::Title)),
                            detail: if n.is_some_and(|n| n.kind == NoteKind::Password) {
                                t.nt_pw_tag
                            } else {
                                ""
                            },
                        }
                    } else if i == count {
                        MenuItem {
                            label: t.nt_new_note,
                            detail: ">",
                        }
                    } else {
                        MenuItem {
                            label: t.nt_new_password,
                            detail: ">",
                        }
                    }
                });
                let top = g(5) - 6;
                widgets::list(
                    c,
                    MARGIN,
                    top,
                    w,
                    bottom - top - 30,
                    &items[..count + 2],
                    sel as usize,
                    true,
                );
                notice(c, 17);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            NoteStep::View { idx, sel } => {
                let Some(n) = self.vault.data.note(idx as usize) else {
                    return;
                };
                TITLE.draw(c, MARGIN, STATUS_H + 12, n.text_of(Field::Title), theme::TEXT);
                let mut row = 4;
                for &f in &n.fields()[1..] {
                    let v = n.text_of(f);
                    if v.is_empty() {
                        continue;
                    }
                    let label = t.nt_fields[f as usize];
                    if f == Field::Text {
                        widgets::label(c, MARGIN, g(row), label);
                        BODY.draw_wrapped(c, MARGIN, g(row + 1), w, 26, 4, v, theme::TEXT);
                        row += 5;
                    } else {
                        let shown = if f == Field::Secret && !st.show {
                            t.nt_masked
                        } else {
                            v
                        };
                        let x = SMALL.draw(c, MARGIN, g(row) + 4, label, theme::TEXT_DIM);
                        let color = if f == Field::Secret {
                            theme::BRIGHT
                        } else {
                            theme::TEXT
                        };
                        BODY.draw(c, x.max(MARGIN + 120) + 8, g(row), shown, color);
                        row += 1;
                    }
                }
                let rows = view_rows(n.kind);
                let items: [MenuItem; 4] = core::array::from_fn(|i| MenuItem {
                    label: match rows.get(i) {
                        Some(ViewRow::Show) if st.show => t.nt_hide,
                        Some(ViewRow::Show) => t.nt_show,
                        Some(ViewRow::Qr) => t.nt_qr,
                        Some(ViewRow::Edit) => t.nt_edit,
                        Some(ViewRow::Delete) => t.nt_delete,
                        None => "",
                    },
                    detail: "",
                });
                let top = g(11);
                widgets::list_rows(
                    c,
                    MARGIN,
                    top,
                    w,
                    bottom - top,
                    &items[..rows.len()],
                    sel as usize,
                    false,
                    36,
                );
                notice(c, 10);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            NoteStep::Edit { sel } => {
                let (rows, n) = st.edit_rows();
                let mut values: [Buf<40>; 7] = core::array::from_fn(|_| Buf::new());
                for (i, r) in rows[..n].iter().enumerate() {
                    if let EditRow::Field(f) = r {
                        let v = st.draft.text_of(*f);
                        if *f == Field::Secret && !v.is_empty() {
                            values[i].push_str(t.nt_masked);
                        } else {
                            let cut = v.char_indices().nth(28).map_or(v.len(), |(p, _)| p);
                            values[i].push_str(&v[..cut]);
                            if cut < v.len() {
                                values[i].push_str("...");
                            }
                        }
                    }
                }
                let items: [MenuItem; 7] = core::array::from_fn(|i| MenuItem {
                    label: match rows[i] {
                        EditRow::Field(f) => t.nt_fields[f as usize],
                        EditRow::Generate => t.nt_generate,
                        EditRow::Save => t.nt_save,
                    },
                    detail: values[i].as_str(),
                });
                let top = STATUS_H + 8;
                widgets::list(
                    c,
                    MARGIN,
                    top,
                    w,
                    bottom - top - 30,
                    &items[..n],
                    sel as usize,
                    true,
                );
                notice(c, 17);
                widgets::hint_bar(c, &[("^v", s.h_move), ("Enter", s.h_select), ("Esc", s.h_back)]);
            }
            NoteStep::Field { field } => {
                let f = Field::ALL[field as usize % 5];
                widgets::label(c, MARGIN, STATUS_H + 12, t.nt_fields[f as usize]);
                let text = st.input();
                let max = ((w - 40) / BODY.width as i32) as usize;
                let start = text.len().saturating_sub(max);
                let mut shown = Buf::<128>::new();
                for &b in &text[start..] {
                    let ch = if st.show || f != Field::Secret {
                        b as char
                    } else {
                        '*'
                    };
                    let mut tmp = [0u8; 4];
                    shown.push_str(ch.encode_utf8(&mut tmp));
                }
                widgets::text_field(c, MARGIN, STATUS_H + 34, w, shown.as_str(), "", &BODY);
                let count: Buf<48> = fill(t.nt_chars, &[&text.len(), &f.max()]);
                SMALL.draw(
                    c,
                    800 - MARGIN - SMALL.text_width(count.as_str()),
                    STATUS_H + 84,
                    count.as_str(),
                    theme::TEXT_DIM,
                );
                widgets::hint_bar(
                    c,
                    &[
                        ("Sym", "!@#"),
                        ("Tab", s.h_display),
                        ("Enter", s.h_accept),
                        ("Esc", s.h_cancel),
                    ],
                );
            }
            NoteStep::Generate => {
                TITLE.draw(c, MARGIN, STATUS_H + 20, t.nt_gen_title, theme::TEXT);
                let count: Buf<48> = fill(t.sl_dice_count, &[&st.dice_len]);
                let tag = if st.dice_len >= MIN_DICE {
                    Tag::Ok
                } else {
                    Tag::Pending
                };
                widgets::log_line(c, MARGIN, g(5), w, tag, count.as_str(), "");
                widgets::log_line(c, MARGIN, g(6), w, Tag::Info, t.nt_gen_note, "");
                for (row, chunk) in st.dice[..st.dice_len].chunks(60).take(4).enumerate() {
                    let line = core::str::from_utf8(chunk).unwrap_or("");
                    BODY.draw(c, MARGIN, g(8 + row as i32), line, theme::TEXT);
                }
                notice(c, 13);
                widgets::hint_bar(
                    c,
                    &[
                        ("1-6", s.h_type),
                        ("Del", s.h_delete),
                        ("Enter", s.h_accept),
                        ("Esc", s.h_back),
                    ],
                );
            }
            NoteStep::Delete { idx } => {
                let title = self
                    .vault
                    .data
                    .note(idx as usize)
                    .map_or("", |n| n.text_of(Field::Title));
                let y = widgets::message_at(
                    c,
                    STATUS_H + 40,
                    t.nt_delete_title,
                    theme::DANGER,
                    &[title, t.nt_delete_line],
                );
                let prompt: Buf<96> = fill(s.typed_prompt, &[&typed::WIPE]);
                let wrong = self.typed.wrong.then_some(s.typed_wrong);
                widgets::typed_field(c, y + 40, prompt.as_str(), self.typed.text(), wrong);
                widgets::hint_bar(c, &[("A-Z", s.h_type), ("Enter", t.nt_delete), ("Esc", s.keep)]);
            }
        }
    }
}
