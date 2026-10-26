//! The pieces of a settings list: rows that act or read out, the switch an
//! on/off setting wears, and the card a row's choices open in.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::{BoundaryBehavior, FocusKey};
use buoyant::view::Lazy;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::conversation::header;
use super::label;
use crate::board::Metrics;
use crate::model::{LEVELS, State};
use crate::nav::keys;
use crate::{font, icon, theme};

const INSET: u32 = 12;
const RADIUS: u16 = 8;
/// A settings screen's rows.
const ROW: u32 = 36;
/// A level's steps.
const STEP_WIDTH: u32 = 7;
const STEP_HEIGHT: u32 = 12;
/// The switch, and its knob's inset.
const SWITCH_WIDTH: u32 = 40;
const SWITCH_HEIGHT: u32 = 22;
const KNOB_INSET: u32 = 3;
/// How a switch moves from one side to the other.
const SWITCH_MOTION: Animation = Animation::ease_in_out(core::time::Duration::from_millis(180));
/// A choice in a card, and the room its check mark takes.
const CHOICE: u32 = 34;
/// A card's least margin from the screen's edges.
const CARD_MARGIN: u32 = 10;
const CHECK: u32 = 26;

/// A row's value: room for a radio profile's name.
type Value = String<32>;

/// What a row shows at its end.
pub(super) enum End {
    Nothing,
    /// It goes to another screen, or opens choices.
    Chevron,
    Value(Value),
    /// A value, and that pressing changes it.
    ValueChevron(Value),
    Switch(bool),
    /// A level from 1 to [`LEVELS`], lit in the accent while
    /// `active`, as it is being changed. The arrows take it down and up
    /// by `step`, which each level's row names for its own setting.
    Level {
        level: u8,
        active: bool,
        step: fn(&mut State, i8),
    },
}

impl End {
    pub(super) fn value(text: &str) -> Self {
        Self::Value(value(text))
    }

    pub(super) fn value_chevron(text: &str) -> Self {
        Self::ValueChevron(value(text))
    }
}

/// `text` as a row's value, cut short with an ellipsis when it is longer
/// than a value holds.
fn value(text: &str) -> Value {
    let mut value = Value::new();
    for c in text.chars() {
        if value.push(c).is_err() {
            while value.push('\u{2026}').is_err() {
                value.pop();
            }
            break;
        }
    }
    value
}

/// A row `height` tall: an action, or a readout that takes focus so the
/// wheel can pass through it. `danger` sets its name in red.
pub(super) fn row<A: Fn(&mut State) + Clone>(
    m: &'static Metrics,
    name: &'static str,
    key: FocusKey,
    act: A,
    end: End,
    danger: bool,
    height: u32,
) -> impl View<Rgb565, State> + use<A> {
    marked_row(m, name, key, act, end, danger, height, None)
}

/// A row as [`row`] draws it, with a column before its name for a check
/// mark: `Some(true)` checks it, `Some(false)` leaves the room empty, and
/// `None` leaves no room.
// Kept out of line: inlined into a screen, its calls make the esp
// toolchain's Xtensa back end fail with `Cannot select:
// XtensaISD::PCREL_WRAPPER TargetConstantPool` (rustc 1.95.0-nightly esp).
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn marked_row<A: Fn(&mut State) + Clone>(
    m: &'static Metrics,
    name: &'static str,
    key: FocusKey,
    act: A,
    end: End,
    danger: bool,
    height: u32,
    checked: Option<bool>,
) -> impl View<Rgb565, State> + use<A> {
    let (value, chevron, switch, level) = match end {
        End::Nothing => (None, false, None, None),
        End::Chevron => (None, true, None, None),
        End::Value(value) => (Some(value), false, None, None),
        End::ValueChevron(value) => (Some(value), true, None, None),
        End::Switch(on) => (None, false, Some(on), None),
        End::Level {
            level,
            active,
            step,
        } => (None, false, None, Some((level, active, step))),
    };
    let flip = act.clone();
    Button::new(act, move |button: ButtonState| {
        let focused = button.is_focused();
        let look = RowLook {
            name,
            value: value.clone(),
            chevron,
            level: level.map(|(level, active, _)| (level, active)),
            checked,
            danger,
            focused,
            m,
        };
        // The switch is apart from the rest, which is drawn without
        // animation: its knob slides.
        HStack::new((Lazy::new(look, row_look), switch.map(switch_look)))
            .with_spacing(8)
            .padding(Edges::Leading, INSET - 4)
            .padding(Edges::Trailing, 10)
            .frame()
            .with_height(height - 2)
            .background(
                Alignment::Center,
                focused.then(|| {
                    ZStack::new((
                        RoundedRectangle::new(RADIUS).foreground_color(theme::FOCUS),
                        RoundedRectangle::new(RADIUS)
                            .stroked(2)
                            .foreground_color(theme::ACCENT),
                    ))
                }),
            )
            .padding(Edges::Horizontal, 4)
            .padding(Edges::Vertical, 1)
            .overlay(
                Alignment::Bottom,
                (!focused).then(|| {
                    Rectangle
                        .foreground_color(theme::LINE)
                        .frame()
                        .with_height(1)
                        .padding(Edges::Leading, INSET)
                }),
            )
    })
    .focus_key(key)
    // A switch takes the arrows: toward off, and toward on. A level
    // takes them too: down, and up.
    .on_key(move |key, s: &mut State| match (key, switch, level) {
        (Key::LeftArrow, Some(true), _) | (Key::RightArrow, Some(false), _) => {
            flip(s);
            KeyResponse::Handled
        }
        (Key::LeftArrow, _, Some((_, _, step))) => {
            step(s, -1);
            KeyResponse::Handled
        }
        (Key::RightArrow, _, Some((_, _, step))) => {
            step(s, 1);
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
}

/// A row that only reads out `value`, `height` tall. It takes no focus:
/// turning passes it by, and the list scrolls to show it.
pub(super) fn readout(
    m: &'static Metrics,
    name: &'static str,
    value: &str,
    height: u32,
) -> impl View<Rgb565, State> + use<> {
    let look = RowLook {
        name,
        value: (!value.is_empty()).then(|| self::value(value)),
        chevron: false,
        level: None,
        checked: None,
        danger: false,
        focused: false,
        m,
    };
    Lazy::new(look, row_look)
        .padding(Edges::Leading, INSET - 4)
        .padding(Edges::Trailing, 10)
        .frame()
        .with_height(height - 2)
        .padding(Edges::Horizontal, 4)
        .padding(Edges::Vertical, 1)
        .overlay(
            Alignment::Bottom,
            Rectangle
                .foreground_color(theme::LINE)
                .frame()
                .with_height(1)
                .padding(Edges::Leading, INSET),
        )
}

/// What a row draws beside its switch: its check mark, name, value,
/// chevron, and level.
#[derive(Clone)]
struct RowLook {
    name: &'static str,
    value: Option<Value>,
    chevron: bool,
    level: Option<(u8, bool)>,
    checked: Option<bool>,
    danger: bool,
    focused: bool,
    m: &'static Metrics,
}

/// A row, but for its switch.
///
/// Built from its data each time it is drawn ([`Lazy`]): kept in the
/// render trees, every row's would outweigh the rest of the screen, and a
/// screen's rows are built on the stack together.
fn row_look(look: &RowLook) -> impl View<Rgb565, ()> + use<> {
    let face = if look.focused {
        &font::BOLD
    } else {
        &font::REGULAR
    };
    let color = if look.danger { theme::RED } else { theme::TEXT };
    HStack::new((
        (look.checked == Some(true)).then(|| {
            Image::new(&icon::CHECK)
                .as_template()
                .foreground_color(theme::ACCENT)
                .frame()
                .with_width(CHECK - 8)
        }),
        // Static, so drawn as it is rather than copied. Unchecked, the
        // name keeps the check mark's room and its spacing.
        super::line(look.name, face, look.m.body, color).padding(
            Edges::Leading,
            if look.checked == Some(false) {
                CHECK
            } else {
                0
            },
        ),
        Spacer::default(),
        // Already cut short to fit, by [`value`].
        look.value.clone().map(|value| {
            super::line(
                value,
                &font::REGULAR,
                look.m.secondary,
                theme::TEXT_SECONDARY,
            )
        }),
        look.chevron.then(|| {
            Image::new(&icon::CHEVRON)
                .as_template()
                .foreground_color(theme::TEXT_TERTIARY)
        }),
        look.level.map(|(level, active)| level_look(level, active)),
    ))
    .with_spacing(8)
    .hint_background_color(if look.focused {
        theme::FOCUS
    } else {
        theme::BACKGROUND
    })
}

/// A level's steps, lit up to `level`: in the accent while `active`.
fn level_look(level: u8, active: bool) -> impl View<Rgb565, ()> + use<> {
    let lit = if active { theme::ACCENT } else { theme::TEXT };
    let step = move |i: u8| {
        RoundedRectangle::new(2)
            .foreground_color(if i < level { lit } else { theme::LEVEL_OFF })
            .frame_sized(STEP_WIDTH, STEP_HEIGHT)
    };
    const _: () = assert!(LEVELS == 10);
    HStack::new((
        step(0),
        step(1),
        step(2),
        step(3),
        step(4),
        step(5),
        step(6),
        step(7),
        step(8),
        step(9),
    ))
    .with_spacing(2)
}

/// A screen under Device: its header, and `rows` in a list. Backspace goes
/// back. Where nothing in it takes focus, the list takes it, as
/// [`keys::READING`], and turning scrolls it.
pub(super) fn page<V: View<Rgb565, State>>(
    m: &'static Metrics,
    title: &'static str,
    rows: V,
) -> impl View<Rgb565, State> + use<V> {
    VStack::new((
        header(m, title, None, None),
        super::list(rows)
            .with_scroll_step(ROW)
            .with_self_focus(true)
            .focus_key(keys::READING),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        Key::Backspace => {
            s.back();
            KeyResponse::Handled
        }
        _ => KeyResponse::Ignored,
    })
}

/// An on/off setting: where the knob sits and the fill say which. Changed,
/// the knob slides across as the fill changes color.
fn switch_look(on: bool) -> impl View<Rgb565, State> + use<> {
    let (track, knob, alignment) = if on {
        (
            theme::ACCENT,
            Rgb565::new(31, 63, 31),
            HorizontalAlignment::Trailing,
        )
    } else {
        (
            theme::SWITCH_OFF,
            theme::KNOB_OFF,
            HorizontalAlignment::Leading,
        )
    };
    let diameter = SWITCH_HEIGHT - 2 * KNOB_INSET;
    ZStack::new((
        RoundedRectangle::new((SWITCH_HEIGHT / 2) as u16).foreground_color(track),
        Circle
            .foreground_color(knob)
            .frame_sized(diameter, diameter)
            .padding(Edges::Horizontal, KNOB_INSET)
            .flex_infinite_width(alignment),
    ))
    .animated(SWITCH_MOTION, on)
    // Moves within the switch, whatever the row does.
    .geometry_group()
    .frame_sized(SWITCH_WIDTH, SWITCH_HEIGHT)
}

/// Choices in a card `width` wide, or as wide as the screen leaves, over
/// the middle of the screen at its `alignment`. Backspace does `cancel`.
pub(super) fn card<V: View<Rgb565, State>>(
    m: &'static Metrics,
    choices: V,
    width: u32,
    alignment: HorizontalAlignment,
    cancel: fn(&mut State),
) -> impl View<Rgb565, State> + use<V> {
    choices
        .padding(Edges::Vertical, 5)
        .frame()
        .with_width(width.min(m.width - 2 * CARD_MARGIN))
        .background(
            Alignment::Center,
            ZStack::new((
                RoundedRectangle::new(12)
                    .foreground_color(Rgb565::new(0, 0, 0))
                    .offset(1, 3),
                RoundedRectangle::new(12).foreground_color(theme::MENU),
                RoundedRectangle::new(12)
                    .stroked(1)
                    .foreground_color(theme::MENU_LINE),
            )),
        )
        .padding(Edges::Horizontal, CARD_MARGIN)
        .flex_infinite_width(alignment)
        .flex_infinite_height(VerticalAlignment::Center)
        .on_key(move |key, s: &mut State| match key {
            Key::Backspace => {
                cancel(s);
                KeyResponse::Handled
            }
            _ => KeyResponse::Ignored,
        })
}

/// One of a card's choices. `checked` marks the current one of choices that
/// show which is current; `None` leaves no room for the mark.
pub(super) fn choice(
    m: &'static Metrics,
    text: String<48>,
    key: FocusKey,
    act: fn(&mut State),
    color: Rgb565,
    checked: Option<bool>,
) -> impl View<Rgb565, State> + use<> {
    Button::new(act, move |button: ButtonState| {
        let focused = button.is_focused();
        let face = if focused { &font::BOLD } else { &font::REGULAR };
        HStack::new((
            checked.map(|checked| {
                checked
                    .then(|| {
                        Image::new(&icon::CHECK)
                            .as_template()
                            .foreground_color(theme::ACCENT)
                    })
                    .frame()
                    .with_width(CHECK)
            }),
            label::<48>(&text, face, m.body, color),
        ))
        .with_spacing(0)
        .hint_background_color(if focused { theme::FOCUS } else { theme::MENU })
        // The check mark's column brings its own margin.
        .padding(Edges::Leading, if checked.is_some() { 6 } else { 11 })
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(CHOICE - 2)
        .background(
            Alignment::Center,
            focused.then(|| {
                ZStack::new((
                    RoundedRectangle::new(7).foreground_color(theme::FOCUS),
                    RoundedRectangle::new(7)
                        .stroked(2)
                        .foreground_color(theme::ACCENT),
                ))
            }),
        )
        .padding(Edges::Horizontal, 5)
        .padding(Edges::Bottom, 2)
    })
    .focus_key(key)
}
