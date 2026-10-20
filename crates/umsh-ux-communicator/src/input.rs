//! Input as the interface understands it, independent of how a board
//! produces it.
//!
//! What an input means depends on where focus is: Backspace erases while a
//! text field is active and is Back everywhere else, and turning the wheel
//! moves the cursor in an active field and focus elsewhere. The screens
//! decide that through focus; this only delivers inputs, each one to an
//! interface whose focus has settled from the last.
//!
//! Keys are delivered as they are, and typed here through the
//! [`Keyboard`](crate::keyboard::Keyboard): its modifiers, its typing aids,
//! and the character picker.
//!
//! What the node has to say comes in here too: [`events`] takes in its
//! events, after the inputs that led to them or whenever the board wakes
//! for them.

use buoyant::app::{App, Harness as _};
use buoyant::event::Key;
use buoyant::focus::DefaultFocus;
use buoyant::render::AnimatedJoin;
use buoyant::view::{EditBuffer, EditText, ViewLayout};

use crate::keyboard::{Field, Modifier, PICKER, Spaced, starts_sentence};
use crate::model::{HOLD_MS, Press, State};
use crate::nav::keys;

/// One user input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// The wheel turned this many detents: positive is down or forward.
    Turn(i8),
    /// The wheel went down. What it presses is pressed when it comes back
    /// up, unless holding it opened a menu first.
    Press,
    /// The wheel came back up.
    Release,
    Enter,
    Backspace,
    /// A key with legend `plain`, and `alt` under Alt, was pressed.
    Key {
        plain: char,
        alt: Option<char>,
    },
    Space,
    /// A modifier went down, or up.
    Modifier {
        modifier: Modifier,
        down: bool,
    },
    /// Text from a keyboard that applies its own modifiers, typed as it
    /// is.
    Character(char),
}

/// Applies `input`, which happened at `now` on the board's clock in
/// milliseconds, to the running interface.
pub fn apply<V, F>(app: &mut App<V, State, F>, input: Input, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    // The board is turning off.
    if app.state().ending.is_some() {
        return;
    }
    app.state_mut().uptime = now;
    if app.state().lock.locked {
        locked(app, input, now);
        app.finalize_view();
        return;
    }
    app.state_mut().sync_keyboard();
    if app.state().picker.is_some() {
        pick(app, input, now);
    } else {
        deliver(app, input, now);
    }
    app.finalize_view();
    app.state_mut().sync_keyboard();
}

/// An input while locked: the wheel turns toward unlocking and a press
/// unlocks once it has, and keys do nothing. Turned with Alt held, the
/// wheel still sets the brightness.
fn locked<V, F>(app: &mut App<V, State, F>, input: Input, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    let mut state = app.state_mut();
    match input {
        Input::Turn(detents) => {
            if state.keyboard.turn() {
                state.adjust_brightness(detents, now);
            } else {
                state.turn_to_unlock(detents, now);
            }
        }
        Input::Press => state.press_to_unlock(now),
        Input::Modifier { modifier, down } => state.keyboard.modifier(modifier, down, now),
        Input::Release
        | Input::Enter
        | Input::Backspace
        | Input::Key { .. }
        | Input::Space
        | Input::Character(_) => {}
    }
}

/// Takes in the events the node has waiting, oldest first, at `now` on the
/// board's clock, each through [`State::apply`]. Returns whether any calls
/// for attention.
///
/// With nothing waiting, the interface is left as it was, so a board can
/// look as often as it wakes.
pub fn events<V, F>(app: &mut App<V, State, F>, now: u64) -> bool
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    let node = app.state().node;
    app.state_mut().uptime = now;
    let mut attention = false;
    let mut any = false;
    while let Some(event) = node.next_event() {
        any = true;
        attention |= app.state_mut().apply(event, now);
    }
    if any {
        app.finalize_view();
    }
    attention
}

fn deliver<V, F>(app: &mut App<V, State, F>, input: Input, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    match input {
        Input::Turn(detents) => {
            // Turned with Alt held, the wheel sets the brightness.
            if app.state_mut().keyboard.turn() {
                app.state_mut().adjust_brightness(detents, now);
                return;
            }
            // A part of the date and time being changed takes the turn.
            if app.state_mut().turn_set_time(detents) {
                return;
            }
            // Turning while the wheel is down lets go of the press.
            app.state_mut().press = None;
            for _ in 0..detents.unsigned_abs() {
                if detents > 0 {
                    app.next();
                } else {
                    app.previous();
                }
                app.finalize_view();
            }
        }
        Input::Press => {
            app.state_mut().press = Some(Press {
                hold_until: Some(now + HOLD_MS),
                held: false,
            });
        }
        // Only a press this saw go down, which a hold did not take.
        Input::Release => {
            if app.state_mut().press.take().is_some_and(|p| !p.held) {
                app.state_mut().keyboard.other();
                app.select();
            }
        }
        Input::Enter => {
            app.state_mut().keyboard.other();
            press(app, Key::Enter);
        }
        Input::Backspace => {
            app.state_mut().keyboard.other();
            press(app, Key::Backspace);
        }
        Input::Key { plain, alt } => {
            let mut state = app.state_mut();
            state.prepare_typing();
            let typed = state.keyboard.letter(plain, alt);
            if accepts(&state, typed) {
                press(app, Key::Character(typed));
            }
        }
        Input::Space => {
            let mut state = app.state_mut();
            state.prepare_typing();
            let aids = state.node.keyboard().aids();
            match state.keyboard.space(now, aids) {
                Spaced::Space if accepts(&state, ' ') => press(app, Key::Character(' ')),
                Spaced::Space => {}
                Spaced::Period => {
                    // The space just typed becomes the period's.
                    press(app, Key::Backspace);
                    press(app, Key::Character('.'));
                    press(app, Key::Character(' '));
                }
                Spaced::Picker => {
                    // Only into a field being edited.
                    if state.keyboard.active() {
                        state.picker = Some(0);
                    }
                }
                Spaced::Light => state.switch_keyboard_light(now),
            }
        }
        Input::Modifier { modifier, down } => {
            app.state_mut().keyboard.modifier(modifier, down, now);
        }
        Input::Character(c) => {
            let mut state = app.state_mut();
            state.keyboard.other();
            if accepts(&state, c) {
                press(app, Key::Character(c));
            }
        }
    }
}

/// Whether the focused field, if there is one, takes `c`.
fn accepts(state: &State, c: char) -> bool {
    state.keyboard.field().is_none_or(|field| field.accepts(c))
}

/// An input while the character picker is open: the wheel walks it, a
/// press or Enter types the focused character, Backspace closes it, and
/// Space switches the keyboard light.
fn pick<V, F>(app: &mut App<V, State, F>, input: Input, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    let mut state = app.state_mut();
    let Some(at) = state.picker else {
        return;
    };
    match input {
        Input::Turn(detents) => {
            let last = PICKER.len() as i16 - 1;
            state.picker = Some((i16::from(at) + i16::from(detents)).clamp(0, last) as u8);
        }
        Input::Press | Input::Enter => {
            state.press = None;
            state.picker = None;
            state.keyboard.other();
            press(app, Key::Character(PICKER[usize::from(at)]));
        }
        Input::Backspace => {
            state.picker = None;
            state.keyboard.other();
        }
        Input::Space => {
            state.picker = None;
            state.keyboard.other();
            state.switch_keyboard_light(now);
        }
        Input::Modifier { modifier, down } => state.keyboard.modifier(modifier, down, now),
        // Filtering by name comes with the full picker.
        Input::Release | Input::Key { .. } | Input::Character(_) => {}
    }
}

/// A key pressed and released.
fn press<V, F>(app: &mut App<V, State, F>, key: Key)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    app.key_down(key);
    app.key_up(key);
}

impl State {
    /// The focused text field, as the keyboard treats it.
    #[must_use]
    pub fn focused_field(&self) -> Option<Field> {
        self.screen().focus().current().and_then(keys::field)
    }

    /// The focused field began or ended being edited.
    pub fn field_active(&mut self, active: bool) {
        self.keyboard.activity(active);
    }

    /// Keeps the keyboard's state with the focused field, and Shift with
    /// where its cursor lands while it is edited.
    pub fn sync_keyboard(&mut self) {
        self.keyboard.focus(self.focused_field());
        if self.keyboard.active() {
            self.settle_capitals();
        }
    }

    /// A key is about to type into the focused field: decides capitals as
    /// though the field were already being edited, as the key makes it.
    fn prepare_typing(&mut self) {
        if self.keyboard.field().is_some() && !self.keyboard.active() {
            self.settle_capitals();
        }
    }

    fn settle_capitals(&mut self) {
        if let Some((length, cursor, at_start)) = self.field_position() {
            let aids = self.node.keyboard().aids();
            self.keyboard.settle(length, cursor, at_start, aids);
        }
    }

    /// The focused field's text length, its cursor, and whether the cursor
    /// starts a sentence.
    fn field_position(&mut self) -> Option<(usize, usize, bool)> {
        fn of<B: EditText>(buffer: &mut EditBuffer<B>) -> (usize, usize, bool) {
            let (text, cursor) = (buffer.text(), buffer.cursor());
            (text.len(), cursor, starts_sentence(text, cursor))
        }
        match self.screen().focus().current()? {
            keys::COMPOSER => {
                let chat = self.conversation.as_ref()?.chat;
                self.draft_mut(chat).map(of)
            }
            keys::NAME_FIELD => self.name_text_mut().map(of),
            keys::JOIN_NAME => self.join_name_mut().map(of),
            keys::FIND_FIELD => self.find_text_mut().map(of),
            keys::PEER_FIELD => self.peer_text_mut().map(of),
            keys::CHANNEL_FIELD => self.channel_text_mut().map(of),
            keys::POWER_FIELD => self.power_text_mut().map(of),
            _ => None,
        }
    }
}
