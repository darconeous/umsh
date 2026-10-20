//! The keyboard as the interface types with it: Shift and Alt, each off,
//! one-shot, or locked; the two typing aids; and what each text field
//! allows of them. See the UX book's Communicator Keyboard page.
//!
//! This decides what a key types. It knows nothing of the board's matrix,
//! only of keys with a legend of their own and one under Alt, and of the
//! text it is typed into only what it is told: which field is focused,
//! whether it is being edited, and where its cursor is.
//!
//! A keyboard that applies its own modifiers reports characters instead,
//! and the aids alone apply to them.

use crate::board::KeyboardKind;

/// What the character picker offers, while it offers only what the keys
/// cannot type.
pub const PICKER: [char; 16] = [
    '#', '&', '%', '~', '(', ')', '[', ']', '{', '}', '<', '>', '|', '\\', '^', '`',
];

/// How soon a second tap locks a modifier, and a second space after a
/// word types a period, in milliseconds.
pub const DOUBLE_TAP_MS: u64 = 400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modifier {
    Shift,
    Alt,
}

/// A modifier's state, apart from being held.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Latch {
    #[default]
    Off,
    /// Applies to the next key it changes.
    Once,
    /// Applies until tapped off.
    Locked,
}

/// A text field, as the keyboard treats it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// Running text: a message.
    Prose,
    /// A name: capitalized, but a period would change it.
    Name,
    /// Search text, codes, addresses, and invitations, typed as they are.
    Literal,
    /// A number, typed from the top row in symbol lock.
    Number,
}

impl Field {
    /// Whether Shift arms itself at the start of a sentence.
    #[must_use]
    pub const fn capitalizes(self) -> bool {
        matches!(self, Self::Prose | Self::Name)
    }

    /// Whether two quick spaces after a word type a period.
    #[must_use]
    pub const fn periods(self) -> bool {
        matches!(self, Self::Prose)
    }

    /// Whether the field opens in symbol lock.
    #[must_use]
    pub const fn symbols(self) -> bool {
        matches!(self, Self::Number)
    }
}

/// The typing aids the user leaves on. A field can only turn them off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aids {
    pub capitalize: bool,
    pub period: bool,
}

/// What Space did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spaced {
    /// It types a space.
    Space,
    /// It ends a sentence: the space just typed becomes a period and a
    /// space.
    Period,
    /// Under Alt it opens the character picker.
    Picker,
    /// It followed a space under Alt quickly: it switches the keyboard
    /// light.
    Light,
}

#[derive(Clone, Copy, Debug, Default)]
struct Key {
    latch: Latch,
    down: bool,
    /// Something happened while it was held, so letting go is not a tap.
    used: bool,
    /// When a tap armed it, for a second tap to lock it.
    armed_at: u64,
}

impl Key {
    /// It applies to the key typed now.
    fn on(&self) -> bool {
        self.down || self.latch != Latch::Off
    }

    /// It changed the key typed now.
    fn applied(&mut self) {
        self.used |= self.down;
        if self.latch == Latch::Once {
            self.latch = Latch::Off;
        }
    }
}

/// What came before a space, for the period on double space and the
/// keyboard light.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Run {
    #[default]
    None,
    /// The last key typed a letter.
    Letter,
    /// A space just followed a letter, at this time.
    Space(u64),
    /// Space was pressed under Alt, at this time.
    AltSpace(u64),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Keyboard {
    shift: Key,
    alt: Key,
    /// Shift was armed at the start of a sentence, not by a tap.
    automatic: bool,
    /// The focused text field, whose keyboard state this is.
    field: Option<Field>,
    /// Whether that field is being edited.
    active: bool,
    /// The field's length and cursor when capitals were last decided.
    settled: Option<(usize, usize)>,
    run: Run,
    kind: KeyboardKind,
}

impl Keyboard {
    /// The keyboard of a board whose keyboard reports as `kind` does.
    #[must_use]
    pub fn new(kind: KeyboardKind) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    /// Shift's and Alt's states, for the status strip.
    #[must_use]
    pub fn latches(&self) -> (Latch, Latch) {
        (self.shift.latch, self.alt.latch)
    }

    /// Whether Alt is held down.
    #[must_use]
    pub fn alt_held(&self) -> bool {
        self.alt.down
    }

    /// The focused text field, if any.
    #[must_use]
    pub fn field(&self) -> Option<Field> {
        self.field
    }

    /// Whether the focused text field is being edited.
    #[must_use]
    pub fn active(&self) -> bool {
        self.field.is_some() && self.active
    }

    /// Focus is on `field`, or on no text field. Moving between fields
    /// starts afresh.
    pub fn focus(&mut self, field: Option<Field>) {
        if field != self.field {
            self.field = field;
            self.active = false;
            self.clear();
        }
    }

    /// The focused field began, or ended, being edited. The modifiers
    /// belong to the edit, so ending it clears them.
    pub fn activity(&mut self, active: bool) {
        if active != self.active {
            self.active = active;
            if !active {
                self.clear();
            }
        }
    }

    /// Back to how the focused field opens. A modifier held through this
    /// stays held, but letting it go is no longer a tap.
    fn clear(&mut self) {
        for key in [&mut self.shift, &mut self.alt] {
            *key = Key {
                down: key.down,
                used: key.down,
                ..Key::default()
            };
        }
        // A keyboard that applies its own modifiers has its own symbol
        // layer, which is the user's to choose.
        if self.kind == KeyboardKind::Legends && self.field.is_some_and(Field::symbols) {
            self.alt.latch = Latch::Locked;
        }
        self.automatic = false;
        self.settled = None;
        self.run = Run::None;
    }

    /// A modifier went down or up at `now`. Pressed and let go with
    /// nothing in between, it was tapped.
    pub fn modifier(&mut self, modifier: Modifier, down: bool, now: u64) {
        self.run = Run::None;
        let key = match modifier {
            Modifier::Shift => &mut self.shift,
            Modifier::Alt => &mut self.alt,
        };
        if down {
            // A down repeated while held is the same hold.
            if !key.down {
                key.down = true;
                key.used = false;
            }
        } else if core::mem::take(&mut key.down) && !key.used {
            self.tap(modifier, now);
        }
    }

    fn tap(&mut self, modifier: Modifier, now: u64) {
        // Either lock is released by a tap of either, which arms nothing.
        if self.shift.latch == Latch::Locked || self.alt.latch == Latch::Locked {
            self.shift.latch = Latch::Off;
            self.alt.latch = Latch::Off;
            self.automatic = false;
            return;
        }
        let automatic = core::mem::take(&mut self.automatic);
        let (this, other) = match modifier {
            Modifier::Shift => (&mut self.shift, &mut self.alt),
            Modifier::Alt => (&mut self.alt, &mut self.shift),
        };
        // A Shift armed at the start of a sentence is not the user's: a tap
        // of Shift disarms it, and a tap of Alt arms Alt in its place.
        if automatic {
            match modifier {
                Modifier::Shift => {
                    this.latch = Latch::Off;
                    return;
                }
                Modifier::Alt => other.latch = Latch::Off,
            }
        }
        // One armed, or held, then the other: the other locks.
        if other.down || other.latch == Latch::Once {
            this.latch = Latch::Locked;
            other.latch = Latch::Off;
            other.used |= other.down;
            return;
        }
        this.latch = match this.latch {
            Latch::Off => {
                this.armed_at = now;
                Latch::Once
            }
            Latch::Once if now.saturating_sub(this.armed_at) <= DOUBLE_TAP_MS => Latch::Locked,
            _ => Latch::Off,
        };
    }

    /// A key with legend `plain`, and `alt` under Alt, was pressed: what
    /// it types.
    pub fn letter(&mut self, plain: char, alt: Option<char>) -> char {
        self.run = Run::None;
        if self.alt.on()
            && let Some(symbol) = alt
        {
            self.alt.applied();
            return symbol;
        }
        let typed = if self.shift.on() {
            self.shift.applied();
            self.automatic = false;
            plain.to_ascii_uppercase()
        } else {
            plain
        };
        if typed.is_alphabetic() {
            self.run = Run::Letter;
        }
        typed
    }

    /// A keyboard that applies its own modifiers typed `c`: what it types.
    /// A capital armed at the start of a sentence makes a lowercase letter
    /// one, and goes with the first character either way.
    pub fn character(&mut self, c: char) -> char {
        self.run = Run::None;
        let typed = if self.automatic && self.shift.latch == Latch::Once {
            self.shift.applied();
            self.automatic = false;
            c.to_ascii_uppercase()
        } else {
            c
        };
        if typed.is_alphabetic() {
            self.run = Run::Letter;
        }
        typed
    }

    /// Space was pressed at `now`. In symbol lock it types a space; under
    /// a one-shot or held Alt it opens the picker.
    pub fn space(&mut self, now: u64, aids: Aids) -> Spaced {
        // A second quick space after one under Alt, which needs Alt no
        // longer: a one-shot Alt was used up by the first.
        if let Run::AltSpace(at) = self.run
            && now.saturating_sub(at) <= DOUBLE_TAP_MS
        {
            self.run = Run::None;
            return Spaced::Light;
        }
        if self.alt.down || self.alt.latch == Latch::Once {
            self.alt.applied();
            self.run = Run::AltSpace(now);
            return Spaced::Picker;
        }
        let periods = aids.period && self.field.is_some_and(Field::periods);
        match self.run {
            Run::Letter => {
                self.run = Run::Space(now);
                Spaced::Space
            }
            Run::Space(at) if periods && now.saturating_sub(at) <= DOUBLE_TAP_MS => {
                self.run = Run::None;
                Spaced::Period
            }
            _ => {
                self.run = Run::None;
                Spaced::Space
            }
        }
    }

    /// A key that types nothing the aids follow, such as Enter or
    /// Backspace, was pressed. One-shot modifiers stay armed.
    pub fn other(&mut self) {
        self.run = Run::None;
    }

    /// The wheel turned. Returns whether Alt is held, for the turn to set
    /// brightness: an Alt held for it is not tapped by letting go.
    pub fn turn(&mut self) -> bool {
        self.run = Run::None;
        self.alt.used |= self.alt.down;
        self.alt.down
    }

    /// The edited field's text is `length` long with the cursor at
    /// `cursor`, which is at the start of a sentence or not. Arms Shift
    /// there, where the field and `aids` allow, each time the cursor lands
    /// somewhere new.
    pub fn settle(&mut self, length: usize, cursor: usize, at_start: bool, aids: Aids) {
        let Some(field) = self.field else {
            return;
        };
        if self.settled == Some((length, cursor)) {
            return;
        }
        self.settled = Some((length, cursor));
        let free = self.shift.latch == Latch::Off && self.alt.latch == Latch::Off;
        if at_start && aids.capitalize && field.capitalizes() && free {
            self.shift.latch = Latch::Once;
            self.automatic = true;
        } else if !at_start && self.automatic {
            self.shift.latch = Latch::Off;
            self.automatic = false;
        }
    }
}

/// Whether `cursor` in `text` is at the start of a sentence: the start of
/// the text, or after `.`, `!`, or `?` and a space.
#[must_use]
pub fn starts_sentence(text: &str, cursor: usize) -> bool {
    let before = text.get(..cursor).unwrap_or(text);
    if before.is_empty() {
        return true;
    }
    let trimmed = before.trim_end_matches(' ');
    trimmed.len() < before.len() && trimmed.ends_with(['.', '!', '?'])
}

#[cfg(test)]
mod tests {
    use super::*;

    const ON: Aids = Aids {
        capitalize: true,
        period: true,
    };

    fn tap(k: &mut Keyboard, modifier: Modifier, now: u64) {
        k.modifier(modifier, true, now);
        k.modifier(modifier, false, now);
    }

    fn prose() -> Keyboard {
        let mut k = Keyboard::default();
        k.focus(Some(Field::Prose));
        k.activity(true);
        k
    }

    #[test]
    fn a_tap_arms_for_one_key_and_a_quick_second_tap_locks() {
        let mut k = prose();
        tap(&mut k, Modifier::Shift, 0);
        assert_eq!(k.latches(), (Latch::Once, Latch::Off));
        assert_eq!(k.letter('a', Some('*')), 'A');
        assert_eq!(k.letter('a', Some('*')), 'a');

        tap(&mut k, Modifier::Shift, 1000);
        tap(&mut k, Modifier::Shift, 1200);
        assert_eq!(k.latches(), (Latch::Locked, Latch::Off));
        assert_eq!(k.letter('a', Some('*')), 'A');
        assert_eq!(k.letter('b', Some('!')), 'B');
        tap(&mut k, Modifier::Shift, 5000);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));

        // A slow second tap disarms.
        tap(&mut k, Modifier::Alt, 6000);
        tap(&mut k, Modifier::Alt, 7000);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));
    }

    #[test]
    fn one_modifier_then_the_other_locks_the_other() {
        let mut k = prose();
        tap(&mut k, Modifier::Alt, 0);
        tap(&mut k, Modifier::Shift, 100);
        assert_eq!(k.latches(), (Latch::Locked, Latch::Off), "caps lock");
        // Tapping either releases the lock and arms nothing.
        tap(&mut k, Modifier::Alt, 200);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));

        // Holding Shift while tapping Alt: symbol lock, and letting go of
        // Shift arms nothing.
        k.modifier(Modifier::Shift, true, 1000);
        tap(&mut k, Modifier::Alt, 1100);
        k.modifier(Modifier::Shift, false, 1200);
        assert_eq!(k.latches(), (Latch::Off, Latch::Locked), "symbol lock");
        assert_eq!(k.letter('q', Some('1')), '1');
        assert_eq!(k.space(1300, ON), Spaced::Space);
    }

    #[test]
    fn a_held_modifier_applies_while_down_and_changes_nothing() {
        let mut k = prose();
        k.modifier(Modifier::Shift, true, 0);
        assert_eq!(k.letter('h', None), 'H');
        assert_eq!(k.letter('i', None), 'I');
        k.modifier(Modifier::Shift, false, 50);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));
        assert_eq!(k.letter('h', None), 'h');
    }

    #[test]
    fn alt_then_space_opens_the_picker_and_held_alt_turns_set_brightness() {
        let mut k = prose();
        tap(&mut k, Modifier::Alt, 0);
        assert_eq!(k.space(10, ON), Spaced::Picker);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));

        k.modifier(Modifier::Alt, true, 1000);
        assert!(k.turn());
        k.modifier(Modifier::Alt, false, 1100);
        // Letting go of an Alt that set brightness arms nothing.
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));
        assert!(!k.turn());
    }

    #[test]
    fn enter_backspace_and_space_leave_a_one_shot_shift_armed() {
        let mut k = prose();
        tap(&mut k, Modifier::Shift, 0);
        k.other();
        assert_eq!(k.space(10, ON), Spaced::Space);
        assert_eq!(k.latches(), (Latch::Once, Latch::Off));
    }

    #[test]
    fn shift_arms_at_the_start_of_a_sentence() {
        let mut k = prose();
        k.settle(0, 0, true, ON);
        assert_eq!(k.latches(), (Latch::Once, Latch::Off));
        assert_eq!(k.letter('s', None), 'S');
        k.settle(1, 1, false, ON);
        assert_eq!(k.letter('o', None), 'o');

        // A tap of Shift disarms it, and it stays disarmed where it is.
        k.settle(5, 5, true, ON);
        tap(&mut k, Modifier::Shift, 100);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));
        k.settle(5, 5, true, ON);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));

        // A tap of Alt arms Alt, not symbol lock.
        k.settle(6, 6, true, ON);
        tap(&mut k, Modifier::Alt, 200);
        assert_eq!(k.latches(), (Latch::Off, Latch::Once));

        // Moving off the start disarms it.
        let mut k = prose();
        k.settle(0, 0, true, ON);
        k.settle(3, 2, false, ON);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));
    }

    #[test]
    fn nothing_arms_where_the_field_or_the_user_says_not_to() {
        let mut k = Keyboard::default();
        k.focus(Some(Field::Literal));
        k.settle(0, 0, true, ON);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));

        let mut k = prose();
        k.settle(
            0,
            0,
            true,
            Aids {
                capitalize: false,
                period: true,
            },
        );
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));
    }

    #[test]
    fn two_quick_spaces_after_a_letter_type_a_period() {
        let mut k = prose();
        k.letter('t', None);
        assert_eq!(k.space(0, ON), Spaced::Space);
        assert_eq!(k.space(200, ON), Spaced::Period);

        // Too slow, or not after a letter.
        k.letter('t', None);
        assert_eq!(k.space(1000, ON), Spaced::Space);
        assert_eq!(k.space(2000, ON), Spaced::Space);
        k.other();
        assert_eq!(k.space(3000, ON), Spaced::Space);
        assert_eq!(k.space(3100, ON), Spaced::Space);

        // A letter typed through Alt is a symbol.
        tap(&mut k, Modifier::Alt, 4000);
        k.letter('q', Some('1'));
        assert_eq!(k.space(4100, ON), Spaced::Space);
        assert_eq!(k.space(4200, ON), Spaced::Space);

        // A name takes no period.
        let mut k = Keyboard::default();
        k.focus(Some(Field::Name));
        k.letter('t', None);
        k.space(0, ON);
        assert_eq!(k.space(100, ON), Spaced::Space);
    }

    #[test]
    fn a_number_field_opens_in_symbol_lock_each_time() {
        let mut k = Keyboard::default();
        k.focus(Some(Field::Number));
        assert_eq!(k.latches(), (Latch::Off, Latch::Locked));
        assert_eq!(k.letter('w', Some('2')), '2');
        k.activity(true);
        tap(&mut k, Modifier::Alt, 0);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));
        k.activity(false);
        assert_eq!(k.latches(), (Latch::Off, Latch::Locked));
    }

    #[test]
    fn ending_the_edit_clears_the_modifiers() {
        let mut k = prose();
        tap(&mut k, Modifier::Shift, 0);
        tap(&mut k, Modifier::Shift, 100);
        k.activity(false);
        assert_eq!(k.latches(), (Latch::Off, Latch::Off));
    }

    #[test]
    fn sentences_start_at_the_start_and_after_an_end_and_a_space() {
        assert!(starts_sentence("", 0));
        assert!(starts_sentence("Hi. ", 4));
        assert!(starts_sentence("Hi!  ", 5));
        assert!(!starts_sentence("Hi.", 3));
        assert!(!starts_sentence("Hi there", 3));
        assert!(starts_sentence("Hi. there", 4));
    }
}
