//! Input as the interface understands it, independent of how a board
//! produces it.
//!
//! What an input means depends on where focus is: Backspace erases while a
//! text field is active and is Back everywhere else, and turning the wheel
//! moves the cursor in an active field and focus elsewhere. A trackball's
//! moves are arrow keys first, for whatever is focused to take, and move
//! focus that way when nothing does. The screens
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
use buoyant::event::{EventResult, Key};
use buoyant::focus::{DefaultFocus, Direction};
use buoyant::primitives::Point;
use buoyant::render::AnimatedJoin;
use buoyant::view::{EditBuffer, EditText, ViewLayout};
use embedded_touch::{Phase, Tool, Touch, TouchPoint};

use crate::keyboard::{Field, Modifier, Spaced, starts_sentence};
use crate::model::{HOLD_MS, Press, Reaction, State, TouchHold};
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
    /// Text from a keyboard that applies its own modifiers. Only the
    /// typing aids apply to it.
    Character(char),
    /// A trackball rolled a step toward this arrow.
    Move(Arrow),
    /// A finger touched the screen, moved on it, or left it, at this point.
    Touch {
        phase: TouchPhase,
        x: i16,
        y: i16,
    },
}

/// Where a touch is in its course.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchPhase {
    Started,
    Moved,
    Ended,
    /// The touch ended without its meaning anything: the panel went dark
    /// under it, say.
    Cancelled,
}

impl TouchPhase {
    const fn phase(self) -> Phase {
        match self {
            Self::Started => Phase::Started,
            Self::Moved => Phase::Moved,
            Self::Ended => Phase::Ended,
            Self::Cancelled => Phase::Cancelled,
        }
    }
}

/// How far a finger moves before a touch is no longer held in place.
const TOUCH_SLOP: i32 = 6;

/// Which way a trackball rolled: one of the arrow keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrow {
    Up,
    Down,
    Left,
    Right,
}

impl Arrow {
    /// The arrow key it stands for.
    const fn key(self) -> Key {
        match self {
            Self::Up => Key::UpArrow,
            Self::Down => Key::DownArrow,
            Self::Left => Key::LeftArrow,
            Self::Right => Key::RightArrow,
        }
    }

    /// The direction it moves focus.
    const fn direction(self) -> Direction {
        match self {
            Self::Up => Direction::Up,
            Self::Down => Direction::Down,
            Self::Left => Direction::Left,
            Self::Right => Direction::Right,
        }
    }

    /// As a turn of the wheel: up and down, one detent.
    const fn detents(self) -> Option<i8> {
        match self {
            Self::Up => Some(-1),
            Self::Down => Some(1),
            Self::Left | Self::Right => None,
        }
    }
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
    if let Input::Touch { phase, x, y } = input {
        touch(app, phase, Point::new(x.into(), y.into()), now);
        app.finalize_view();
        app.state_mut().sync_keyboard();
        return;
    }
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
/// wheel still sets the brightness, as a trackball does rolled up or down;
/// rolled otherwise, it does nothing.
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
        Input::Move(direction) => {
            if let Some(detents) = direction.detents().filter(|_| state.keyboard.turn()) {
                state.adjust_brightness(detents, now);
            }
        }
        Input::Press => state.press_to_unlock(now),
        Input::Modifier { modifier, down } => state.keyboard.modifier(modifier, down, now),
        Input::Release
        | Input::Enter
        | Input::Backspace
        | Input::Key { .. }
        | Input::Space
        | Input::Character(_)
        | Input::Touch { .. } => {}
    }
}

/// A touch. Locked, the screen takes none; with the character picker open,
/// one closes it. Held in place, a touch is a long press once
/// [`expire`] finds its time up.
///
/// Only a touch whose start was taken goes on to the interface, so one that
/// began on the lock screen does nothing once it is gone.
fn touch<V, F>(app: &mut App<V, State, F>, phase: TouchPhase, point: Point, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    let mut state = app.state_mut();
    match phase {
        TouchPhase::Started => {
            if state.lock.locked {
                return;
            }
            if state.picker.take().is_some() {
                state.keyboard.other();
                return;
            }
            state.touch = Some(TouchHold {
                at: point,
                hold_until: Some(now + HOLD_MS),
            });
        }
        TouchPhase::Moved => {
            let Some(hold) = state.touch.as_mut() else {
                return;
            };
            let moved = point - hold.at;
            if moved.x.abs() > TOUCH_SLOP || moved.y.abs() > TOUCH_SLOP {
                hold.hold_until = None;
            }
        }
        TouchPhase::Ended | TouchPhase::Cancelled => {
            if state.touch.take().is_none() {
                return;
            }
        }
    }
    state.touching = true;
    drop(state);
    app.send_touch(&Touch::new(
        0,
        TouchPoint::new(point.x, point.y),
        phase.phase(),
        Tool::Finger,
    ));
    app.state_mut().touching = false;
}

/// Lets go of whatever has had its time by `now`, as [`State::expire`]
/// does, and makes a touch held in place a long press: focus goes to what
/// is under it, and holds it as the wheel would. A hold that opens
/// something takes the touch, so lifting it presses nothing.
pub fn expire<V, F>(app: &mut App<V, State, F>, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    if let Some(hold) = app.state().touch
        && hold.hold_until.is_some_and(|until| until <= now)
    {
        app.state_mut().touch = Some(TouchHold {
            hold_until: None,
            ..hold
        });
        if app.focus_at(hold.at) && app.state_mut().hold() {
            app.cancel_touch();
        }
    }
    app.state_mut().expire(now);
    app.finalize_view();
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
                    // Only into a field being edited, that takes more
                    // than numbers.
                    if state.keyboard.active() && state.keyboard.field() != Some(Field::Number) {
                        state.open_picker();
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
            state.prepare_typing();
            let typed = state.keyboard.character(c);
            if accepts(&state, typed) {
                press(app, Key::Character(typed));
            }
        }
        Input::Move(direction) => roll(app, direction, now),
        // Taken before anything else, in `apply`.
        Input::Touch { .. } => {}
    }
}

/// A trackball's step: as the wheel's, up or down, for what Alt and the
/// date and time take of it; then the arrow key, for whatever is focused
/// to take; and otherwise focus moves that way.
fn roll<V, F>(app: &mut App<V, State, F>, direction: Arrow, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    let mut state = app.state_mut();
    // Rolled with Alt held, up brightens and down dims.
    if state.keyboard.turn() {
        if let Some(detents) = direction.detents() {
            state.adjust_brightness(detents, now);
        }
        return;
    }
    // A part of the date and time being changed: up is more, and across
    // is done with it.
    match direction.detents() {
        Some(detents) if state.turn_set_time(-detents) => return,
        Some(_) => {}
        None => state.end_part_edit(),
    }
    // Rolling while the ball is down lets go of the press.
    state.press = None;
    let key = direction.key();
    let taken = !matches!(app.key_down(key), EventResult::Deferred);
    app.key_up(key);
    if !taken {
        app.finalize_view();
        app.move_toward(direction.direction());
    }
}

/// Whether the focused field, if there is one, takes `c`.
fn accepts(state: &State, c: char) -> bool {
    state.keyboard.field().is_none_or(|field| field.accepts(c))
}

/// An input while the character picker is open: the wheel walks it, a
/// press or Enter types the focused pick, or reacts with it to the message
/// the picker was opened for, letters type a name to find
/// one by, Backspace takes a letter off the name or closes it, and Space
/// switches the keyboard light.
fn pick<V, F>(app: &mut App<V, State, F>, input: Input, now: u64)
where
    V: ViewLayout<State>,
    V::FocusTree: DefaultFocus,
    V::Renderables: AnimatedJoin,
    F: Fn(&State) -> V,
{
    let mut state = app.state_mut();
    let columns = state.picker_columns();
    let typed = match input {
        Input::Character(c) => Some(state.keyboard.character(c)),
        Input::Key { plain, alt } => Some(state.keyboard.letter(plain, alt)),
        _ => None,
    };
    let State {
        picker, recents, ..
    } = &mut *state;
    let Some(picker) = picker.as_mut() else {
        return;
    };
    let picks = recents.picks();
    match input {
        Input::Turn(detents) => picker.turn(picks, columns, detents.into()),
        Input::Press | Input::Enter => {
            let picked = picker.focused(picks);
            let reacting = picker.reacting();
            state.press = None;
            state.picker = None;
            state.keyboard.other();
            if let Some(pick) = picked {
                state.recents.picked(pick, now);
                match reacting {
                    Some(message) => state.react(message, Reaction::of(pick.text())),
                    None => press(app, Key::Text(pick.text())),
                }
            }
        }
        Input::Backspace => {
            if !picker.erase_letter() {
                state.picker = None;
                state.keyboard.other();
            }
        }
        Input::Space => {
            state.picker = None;
            state.keyboard.other();
            state.switch_keyboard_light(now);
        }
        Input::Modifier { modifier, down } => state.keyboard.modifier(modifier, down, now),
        Input::Move(Arrow::Up) => picker.rows_down(picks, columns, -1),
        Input::Move(Arrow::Down) => picker.rows_down(picks, columns, 1),
        Input::Move(Arrow::Left) => picker.turn(picks, columns, -1),
        Input::Move(Arrow::Right) => picker.turn(picks, columns, 1),
        Input::Character(_) | Input::Key { .. } => {
            if let Some(c) = typed {
                picker.type_letter(c);
            }
        }
        Input::Release | Input::Touch { .. } => {}
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
