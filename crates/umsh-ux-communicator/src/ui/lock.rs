//! The lock screen: the time and date, the unread chats, what arrived
//! since locking, and the bar that fills as the wheel turns toward
//! unlocking. It takes no focus; [`crate::input`] hands it the wheel.
//!
//! The time and date show only while the clock is known, and the clock
//! stands in for them otherwise.

use buoyant::font::PrerenderedFont;
use buoyant::match_view;
use buoyant::view::Lazy;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::{line, status};
use crate::avatar::AvatarStyle;
use crate::board::{Metrics, Unlock};
use crate::clock::Local;
use crate::lock::UNLOCK_STEPS;
use crate::model::{Age, State, age};
use crate::text::SharedText;
use crate::{font, icon, theme};

/// The time's size beside the cards, smaller there with AM or PM after it,
/// and alone in the middle.
const TIME: u32 = 56;
const TIME_HALVES: u32 = 46;
const TIME_ALONE: u32 = 72;
/// The column of cards: from the screen's top, from the bar, and each
/// card.
const CARDS_Y: u32 = 30;
const CARDS_GAP: u32 = 9;
const CARDS_HEIGHT: u32 = 160;
const CARD_WIDTH: u32 = 254;
const CARD_HEIGHT: u32 = 52;
const CARD_GAP: u32 = 6;
const CARD_AVATAR: u32 = 26;
/// The most cards listed: the last is cut by the column's edge, so the
/// list plainly goes on.
const SHOWN: usize = 4;
/// The time and the rest beside the cards, from the screen's left.
const COLUMN_X: u32 = 14;
const COLUMN_Y: u32 = 34;
/// The unlock bar, right of everything, from the screen's right edge; and
/// the hint under it all.
const BAR_INSET: u32 = 21;
const BAR_WIDTH: u32 = 6;
const HINT_HEIGHT: u32 = 24;
/// How the bar's fill follows the wheel.
const FILL_MOTION: Animation = Animation::ease_in_out(core::time::Duration::from_millis(120));

/// Beside the cards, the time and the rest need this much at the least;
/// with less, the cards go under them.
const TIME_COLUMN: u32 = 180;

const fn bar_x(m: &Metrics) -> u32 {
    m.width - BAR_INSET
}

/// Where the cards end: before the bar, where there is one, and otherwise
/// as far from the edge as the time is from the other.
const fn cards_right(m: &Metrics, bar: bool) -> u32 {
    if bar {
        bar_x(m) - CARDS_GAP
    } else {
        m.width - COLUMN_X
    }
}

/// Whether the cards fit beside the time.
const fn cards_beside(m: &Metrics, bar: bool) -> bool {
    cards_right(m, bar) >= TIME_COLUMN + CARD_WIDTH
}

const fn cards_x(m: &Metrics, bar: bool) -> u32 {
    cards_right(m, bar) - CARD_WIDTH
}

const fn hint_y(m: &Metrics) -> u32 {
    m.height - HINT_HEIGHT
}

/// A chat that heard something since locking, as its card shows it.
#[derive(Clone, Debug, PartialEq)]
struct Card {
    avatar: AvatarStyle,
    name: String<32>,
    age: Age,
    text: SharedText,
}

pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let now = state.wall_time.map(|time| state.local(time));
    let h24 = state.hour24();
    let uptime = (state.uptime / 1000) as u32;
    let cards: Vec<Card, SHOWN> = state
        .arrived
        .iter()
        .filter_map(|arrived| {
            let chat = state.chat(arrived.chat)?;
            Some(Card {
                avatar: chat.avatar.clone(),
                name: chat.name.clone(),
                age: age(Some((arrived.at / 1000) as u32), Some(uptime)),
                text: arrived.text.clone(),
            })
        })
        .take(SHOWN)
        .collect();
    let unread = state.unread_chats();
    let charge = state
        .status
        .battery_percent
        .filter(|_| state.status.charging);
    let lock = state.lock;
    // The bar counts the wheel's steps, where turning is part of unlocking.
    let steps = matches!(state.board.controls.unlock, Unlock::TurnThenPress);
    ZStack::new((
        status::view(m, &state.status, false, state.keyboard.latches(), None),
        match_view!((cards.is_empty(), cards_beside(m, steps)), {
            (false, true) => beside_cards(m, steps, now, h24, unread, cards),
            (false, false) => under_cards(m, steps, now, h24, unread, cards),
            (true, _) => alone(m, steps, now, h24, unread, charge),
        }),
        steps.then(|| bar(m, lock.steps, lock.ready())),
        hint(m, steps, state.unlock_ready()),
    ))
    .with_alignment(Alignment::TopLeading)
}

/// The time, the date, and the unread chats in a column beside the cards.
fn beside_cards(
    m: &'static Metrics,
    bar: bool,
    now: Option<Local>,
    h24: bool,
    unread: usize,
    cards: Vec<Card, SHOWN>,
) -> impl View<Rgb565, State> + use<> {
    let card = |i: usize| {
        cards
            .get(i)
            .cloned()
            .map(|c| Lazy::new((c, m, CARD_WIDTH), card_look))
    };
    ZStack::new((
        VStack::new((
            when(m, now, h24, if h24 { TIME } else { TIME_HALVES }),
            unread_badge(m, unread).padding(Edges::Top, 10),
        ))
        .with_spacing(0)
        .with_alignment(HorizontalAlignment::Leading)
        .padding(Edges::Leading, COLUMN_X)
        .padding(Edges::Top, COLUMN_Y),
        super::list(
            VStack::new((card(0), card(1), card(2), card(3)))
                .with_spacing(CARD_GAP)
                .with_alignment(HorizontalAlignment::Leading),
        )
        .frame_sized(CARD_WIDTH, CARDS_HEIGHT)
        .padding(Edges::Leading, cards_x(m, bar))
        .padding(Edges::Top, CARDS_Y),
    ))
    .with_alignment(Alignment::TopLeading)
}

/// The time, the date, and the unread chats over the cards, where the
/// cards do not fit beside them.
fn under_cards(
    m: &'static Metrics,
    bar: bool,
    now: Option<Local>,
    h24: bool,
    unread: usize,
    cards: Vec<Card, SHOWN>,
) -> impl View<Rgb565, State> + use<> {
    let width = cards_right(m, bar) - COLUMN_X;
    let card = |i: usize| {
        cards
            .get(i)
            .cloned()
            .map(|c| Lazy::new((c, m, width), card_look))
    };
    VStack::new((
        HStack::new((
            when(m, now, h24, TIME),
            Spacer::default(),
            unread_badge(m, unread),
        ))
        .with_alignment(VerticalAlignment::Center),
        super::list(
            VStack::new((card(0), card(1), card(2), card(3)))
                .with_spacing(CARD_GAP)
                .with_alignment(HorizontalAlignment::Leading),
        ),
    ))
    .with_spacing(CARD_GAP)
    .with_alignment(HorizontalAlignment::Leading)
    .frame()
    .with_width(width)
    .with_height(hint_y(m) - m.strip - CARD_GAP)
    .with_alignment(Alignment::Top)
    .padding(Edges::Leading, COLUMN_X)
    .padding(Edges::Top, m.strip + CARD_GAP)
}

/// The time and date in the middle, with nothing arrived to list.
fn alone(
    m: &'static Metrics,
    bar: bool,
    now: Option<Local>,
    h24: bool,
    unread: usize,
    charge: Option<u8>,
) -> impl View<Rgb565, State> + use<> {
    let mut percent: String<4> = String::new();
    if let Some(charge) = charge {
        _ = core::fmt::write(&mut percent, format_args!("{charge}%"));
    }
    VStack::new((
        when(m, now, h24, TIME_ALONE),
        charge.map(|_| {
            HStack::new((
                Image::new(&icon::BOLT)
                    .as_template()
                    .foreground_color(theme::GREEN),
                line(percent, &font::BOLD, m.secondary, theme::GREEN),
            ))
            .with_spacing(4)
        }),
        unread_badge(m, unread),
    ))
    .with_spacing(10)
    .with_alignment(HorizontalAlignment::Center)
    .frame()
    .with_width(if bar { bar_x(m) - BAR_WIDTH } else { m.width })
    .with_height(hint_y(m) - m.strip)
    .with_alignment(Alignment::Center)
    .padding(Edges::Top, m.strip)
}

/// The time and date while the clock is known; nothing otherwise.
fn when(
    m: &'static Metrics,
    now: Option<Local>,
    h24: bool,
    size: u32,
) -> impl View<Rgb565, State> + use<> {
    match_view!(now, {
        Some(local) => {
            let (face, half) = local.face(h24);
            VStack::new((
                HStack::new((
                    Text::new(face, &font::CLOCK)
                        .with_font_size(size)
                        .foreground_color(theme::TEXT),
                    // On the digits' baseline: the boxes' bottoms differ by
                    // how far each face's line reaches below it.
                    half.map(|half| {
                        line(half, &font::BOLD, m.body, theme::TEXT).padding(
                            Edges::Bottom,
                            below_baseline(&font::CLOCK, size)
                                .saturating_sub(below_baseline(&font::BOLD, m.body)),
                        )
                    }),
                ))
                .with_spacing(6)
                .with_alignment(VerticalAlignment::Bottom),
                line(
                    local.long_date(),
                    &font::REGULAR,
                    m.secondary,
                    theme::TEXT_SECONDARY,
                ),
            ))
            .with_spacing(4)
            .with_alignment(HorizontalAlignment::Center)
        },
        None => EmptyView,
    })
}

/// How far a line of `font` at `size` reaches below its baseline.
fn below_baseline(font: &PrerenderedFont, size: u32) -> u32 {
    let face = font.face(size);
    (i32::from(face.line_gap) - i32::from(face.descent)).max(0) as u32
}

/// The chats with unread messages, counted on a badge beside the Chats
/// glyph. Nothing while there are none.
fn unread_badge(m: &'static Metrics, unread: usize) -> impl View<Rgb565, State> + use<> {
    let mut count: String<4> = String::new();
    _ = core::fmt::write(&mut count, format_args!("{unread}"));
    (unread > 0).then(|| {
        HStack::new((
            Image::new(&icon::CHATS)
                .as_template()
                .foreground_color(theme::TEXT_SECONDARY),
            line(count, &font::BOLD, m.small, Rgb565::new(31, 63, 31))
                .hint_background_color(theme::RED)
                .padding(Edges::Horizontal, 7)
                .frame()
                .with_height(22)
                .background(
                    Alignment::Center,
                    RoundedRectangle::new(11).foreground_color(theme::RED),
                ),
        ))
        .with_spacing(4)
    })
}

/// One chat that heard something: its avatar, name, age, and the newest
/// message on one line.
fn card_look((card, m, width): &(Card, &'static Metrics, u32)) -> impl View<Rgb565, ()> + use<> {
    HStack::new((
        super::avatar::view(&card.avatar, CARD_AVATAR),
        VStack::new((
            HStack::new((
                line(card.name.clone(), &font::BOLD, m.secondary, theme::TEXT),
                Spacer::default(),
                line(
                    card.age.clone(),
                    &font::SEMIBOLD,
                    m.small,
                    theme::TEXT_TERTIARY,
                )
                .fixed_size(true, false),
            ))
            .with_spacing(8),
            line(
                card.text.clone(),
                &font::REGULAR,
                m.small,
                theme::TEXT_SECONDARY,
            ),
        ))
        .with_spacing(2)
        .with_alignment(HorizontalAlignment::Leading),
    ))
    .with_spacing(8)
    .padding(Edges::Leading, 8)
    .padding(Edges::Trailing, 10)
    .hint_background_color(theme::PANEL)
    .frame_sized(*width, CARD_HEIGHT)
    .background(
        Alignment::Center,
        ZStack::new((
            RoundedRectangle::new(10).foreground_color(theme::PANEL),
            RoundedRectangle::new(10)
                .stroked(1)
                .foreground_color(theme::LINE),
        )),
    )
}

/// The bar along the right edge, filled as far as the wheel has turned
/// toward unlocking, green once a press unlocks, and the way to turn under
/// it.
fn bar(m: &'static Metrics, steps: u8, ready: bool) -> impl View<Rgb565, State> + use<> {
    let color = if ready { theme::GREEN } else { theme::ACCENT };
    let filled = CARDS_HEIGHT * u32::from(steps) / u32::from(UNLOCK_STEPS);
    let arrow = if steps > 0 {
        color
    } else {
        theme::TEXT_TERTIARY
    };
    VStack::new((
        ZStack::new((
            RoundedRectangle::new((BAR_WIDTH / 2) as u16).foreground_color(theme::LINE),
            RoundedRectangle::new((BAR_WIDTH / 2) as u16)
                .foreground_color(color)
                .frame()
                .with_height(filled),
        ))
        .with_alignment(Alignment::Top)
        .animated(FILL_MOTION, steps)
        .geometry_group()
        .frame_sized(BAR_WIDTH, CARDS_HEIGHT),
        Image::new(&icon::DOWN)
            .as_template()
            .foreground_color(arrow),
    ))
    .with_spacing(2)
    .padding(Edges::Leading, bar_x(m) - 3)
    .padding(Edges::Top, CARDS_Y)
}

/// How to unlock, along the bottom, or that a press now does. Where there
/// are no steps to turn, a press always does, and says so plainly.
fn hint(m: &'static Metrics, steps: bool, ready: bool) -> impl View<Rgb565, State> + use<> {
    let (image, text, face, color) = if !steps {
        (
            &icon::PADLOCK,
            "Press to unlock",
            &font::MEDIUM,
            theme::TEXT_TERTIARY,
        )
    } else if ready {
        (
            &icon::PADLOCK_OPEN,
            "Press to unlock",
            &font::BOLD,
            theme::GREEN,
        )
    } else {
        (
            &icon::PADLOCK,
            "Scroll down and press to unlock",
            &font::MEDIUM,
            theme::TEXT_TERTIARY,
        )
    };
    HStack::new((
        Image::new(image).as_template().foreground_color(color),
        line(text, face, m.small, color),
    ))
    .with_spacing(4)
    .frame()
    .with_width(m.width)
    .with_height(HINT_HEIGHT)
    .with_alignment(Alignment::Center)
    .padding(Edges::Top, hint_y(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How wide `text` is in `font` at `size`.
    fn width(text: &str, font: &PrerenderedFont, size: u32) -> u32 {
        let face = font.face(size);
        text.chars()
            .filter_map(|c| face.glyph(c).or(face.fallback.as_ref()))
            .map(|glyph| u32::from(glyph.advance))
            .sum()
    }

    #[test]
    fn the_widest_time_fits_beside_the_cards() {
        use crate::board::{Board, Unlock};
        for board in [&Board::PAGER, &Board::TDECK] {
            let m = &board.metrics;
            let bar = board.controls.unlock == Unlock::TurnThenPress;
            // Where the cards go under the time, there is nothing to clear.
            if !cards_beside(m, bar) {
                continue;
            }
            let half = width("PM", &font::BOLD, m.body).max(width("AM", &font::BOLD, m.body));
            let widest = (0..24 * 60)
                .flat_map(|minute| [true, false].map(|h24| (minute, h24)))
                .map(|(minute, h24)| {
                    let (face, am_pm) = Local { day: 0, minute }.face(h24);
                    let size = if h24 { TIME } else { TIME_HALVES };
                    width(&face, &font::CLOCK, size) + am_pm.map_or(0, |_| 6 + half)
                })
                .max()
                .unwrap();
            // Clear of the cards by a little.
            let cards = cards_x(m, bar);
            assert!(
                COLUMN_X + widest + 6 <= cards,
                "{widest} wide, {} room",
                cards - COLUMN_X
            );
        }
    }
}
