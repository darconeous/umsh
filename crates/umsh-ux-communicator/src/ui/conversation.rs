//! A conversation: its header, the history ending at the newest message,
//! and the composer, which folds to one line while you read.
//!
//! Backspace goes back, unless the composer is being edited. Typing while
//! reading goes to the composer.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::{BoundaryBehavior, Role};
use buoyant::primitives::Size;
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use buoyant::view::scroll_view::ScrollBarVisibility;
use buoyant::view::text_field::TextFieldStatus;
use buoyant::view::{GeometryReader, Lazy, TextArea};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::RgbColor;
use heapless::Vec;

use super::label;
use super::setting::{card, choice};
use crate::avatar::AvatarStyle;
use crate::board::Metrics;
use crate::clock::{Local, MONTHS, WEEKDAYS, civil};
use crate::model;
use crate::model::{
    ChannelAccess, ChatId, ChatKind, Delivery, Direction, Draft, MAX_MESSAGES, Message, MessageId,
    Messages, Parts, Presence, Quote, Reacted, Reaction, Reactions, Rule, State, hops_text,
};
use crate::nav::{Screen, Unsent, keys};
use crate::text::{DraftText, SharedText};
use crate::{font, icon, theme};
use buoyant::font::PrerenderedFont;
use buoyant::primitives::geometry::CornerRadii;
use buoyant::render::AreaColors;

/// A header's title from the screen's edge, where no arrow stands before it.
const LEADING: u32 = 10;
/// The back arrow from the screen's edge.
const ARROW_INSET: u32 = 4;
/// Between the back arrow and what follows it.
pub(super) const ARROW_GAP: u32 = 6;
const AVATAR: u32 = 26;
/// The composer's band, and its field inside it.
const COMPOSER_INSET: u32 = 3;
const FIELD_RADIUS: u16 = 14;
/// The composer folded while reading.
const BAR: u32 = 24;
/// From the screen's edges to the bubbles.
const SIDE: u32 = 8;
/// The widest a bubble is: three quarters of the screen, and no wider
/// than reads well.
const fn bubble_max(m: &Metrics) -> u32 {
    let share = m.width * 3 / 4;
    if share < 330 { share } else { 330 }
}
/// The card of how to send a message again.
const RESEND_WIDTH: u32 = 360;
const BUBBLE_PAD_X: u32 = 11;
const BUBBLE_PAD_Y: u32 = 4;
/// A line of a bubble's text: 1.2 em.
const fn body_line(m: &Metrics) -> u32 {
    m.body * 6 / 5
}
const BUBBLE_RADIUS: u16 = 14;
/// The corner on the sender's side, at the bottom.
const TAIL_RADIUS: u16 = 5;
/// The focus ring, outside the bubble, and its line.
const RING_GAP: u32 = 4;
const RING_LINE: u32 = 2;
/// Between messages from the same sender, and from different ones.
const GAP_SAME: u32 = 3;
const GAP_CHANGE: u32 = 8;
const SENDER_LINE: u32 = 18;
/// Where a channel's received bubbles begin, beside their senders' avatars,
/// and those avatars' size and place.
const IN_X: u32 = 42;
const MEMBER_AVATAR: u32 = 30;
const MEMBER_AVATAR_X: u32 = 5;
const STATUS_LINE: u32 = 21;
/// Keeps part of the next message in view when focus moves.
const FOCUS_MARGIN: u32 = 12;
/// How far a turn scrolls through a message taller than the history: a line.
const SCROLL_STEP: u32 = 24;
/// What an empty composer says: "Message" and the chat's name.
type Placeholder = heapless::String<48>;
/// An action in the actions menu, which can name a channel.
type MenuText = heapless::String<40>;
/// Indices `ForEach` can hold without borrowing the state.
static INDICES: [usize; MAX_MESSAGES] = {
    let mut a = [0; MAX_MESSAGES];
    let mut i = 0;
    while i < MAX_MESSAGES {
        a[i] = i;
        i += 1;
    }
    a
};

pub fn view(state: &State, chat: ChatId) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let summary = state.chat(chat);
    let conversation = state.conversation(chat);
    let messages = conversation.map_or(&[][..], |c| &c.messages);
    let sent = conversation.map_or(0, |c| c.sent);
    let (actions, reply, unsent) = match state.screen() {
        Screen::Conversation {
            actions,
            reply,
            unsent,
            ..
        } => (*actions, *reply, *unsent),
        _ => (None, None, None),
    };
    // A message's actions are part of reading it.
    let reading = actions.is_some()
        || state
            .screen()
            .focus()
            .current()
            .is_some_and(keys::is_message);
    let find = |id: Option<MessageId>| id.and_then(|id| messages.iter().find(|m| m.id == id));
    // The menu offers my reaction as the one already chosen, and a
    // member's message offers its sender.
    let over = find(actions)
        .map(|m| {
            if m.delivery == Delivery::Unconfirmed && !m.deleted {
                return Over::Unconfirmed;
            }
            let item = |verb: &str, name: &SharedText| {
                let mut text = MenuText::new();
                _ = core::fmt::write(&mut text, format_args!("{verb} {}", name.as_str()));
                text
            };
            let card = match &m.card {
                Some(model::Card::Channel(invite)) => {
                    Some(CardItem::Join(item("Join", &invite.name)))
                }
                Some(model::Card::Contact(contact)) => {
                    Some(CardItem::Show(item("Show", &contact.name)))
                }
                None => None,
            };
            Over::Actions(m.my_reaction(), m.sender.is_some(), card)
        })
        .or(unsent.map(|unsent| match unsent {
            Unsent::Resend(_) => Over::Resend,
            Unsent::ConfirmDelete(_) => Over::ConfirmDelete,
        }));
    let quoted = find(reply).map(|message| quote(m, message, summary.map_or("", |s| &s.name)));
    let kind = summary.map(|s| s.kind);
    let channel = matches!(kind, Some(ChatKind::Channel { .. }));
    let open = kind.is_some_and(ChatKind::is_open);
    // Editing, the composer takes the color of what it will send: green
    // where anyone can read it, violet under forward secrecy.
    let tone = if open {
        (theme::ACTIVE_FIELD_OPEN, theme::ACCENT_OPEN)
    } else if summary.is_some_and(|s| s.forward_secret) {
        (theme::ACTIVE_FIELD_SECRET, theme::ACCENT_SECRET)
    } else {
        (theme::ACTIVE_FIELD, theme::ACCENT)
    };
    let mut placeholder = Placeholder::new();
    _ = core::fmt::write(
        &mut placeholder,
        format_args!("Message {}", summary.map_or("", |s| &s.name)),
    );
    VStack::new((
        header(
            m,
            summary.map_or("", |s| &s.name),
            summary.map(|s| &s.avatar),
            summary.map(|s| s.kind),
        ),
        history(
            m,
            messages,
            sent,
            actions,
            channel,
            open,
            Times {
                now: state.wall_time,
                zone: state.clock.zone,
                hour24: state.hour24(),
                // A full window may have more behind it.
                older: messages.len() == MAX_MESSAGES,
            },
        ),
        state.airtime_wait.map(|wait| airtime_line(m, wait)),
        quoted,
        summary.map(|s| composer(m, chat, &s.draft, reading, tone, &placeholder)),
    ))
    .with_spacing(0)
    .bound_focus(BoundaryBehavior::Stop)
    .on_key(|key, s: &mut State| match key {
        // A reply is dropped first, keeping its text; then Back.
        Key::Backspace => {
            if !s.drop_reply() {
                s.back();
            }
            KeyResponse::Handled
        }
        Key::Character(_) | Key::Enter => {
            s.focus().request(keys::COMPOSER);
            KeyResponse::Redirect
        }
        _ => KeyResponse::Ignored,
    })
    // One popover for both: each wrapper around the conversation costs the
    // Pager's stack a copy of its render tree.
    .popover(over.as_ref(), |over| {
        buoyant::match_view!(over, {
            Over::Actions(mine, member, card) => actions_menu(m, *mine, *member, card.clone()),
            Over::Unconfirmed => unconfirmed_menu(m),
            Over::Resend => resend_choices(m),
            Over::ConfirmDelete => delete_choices(m),
        })
    })
    // A tap outside closes either, as Backspace does, choosing nothing.
    .on_blur(|s: &mut State| {
        if s.cancel_resend().is_none() {
            s.close_actions();
        }
        Dismissal::Dismiss
    })
}

/// What opens over the conversation.
#[derive(Clone)]
enum Over {
    /// A message's actions: my reaction, whether a member sent it, and what
    /// its card offers.
    Actions(Option<Reaction>, bool, Option<CardItem>),
    /// An unconfirmed message's actions.
    Unconfirmed,
    /// How to send again a message that was to go under forward secrecy.
    Resend,
    /// Deleting an unconfirmed message, asking to be confirmed.
    ConfirmDelete,
}

/// Deleting an unconfirmed message, asking to be confirmed, Cancel
/// focused.
#[inline(never)]
fn delete_choices(m: &'static Metrics) -> impl View<Rgb565, State> + use<> {
    let text = |text: &str| heapless::String::try_from(text).unwrap_or_default();
    card(
        m,
        VStack::new((
            choice(
                m,
                text("Delete for everyone"),
                keys::DELETE_MESSAGE_CONFIRM,
                State::delete_message,
                theme::RED,
                None,
            ),
            choice(
                m,
                text("Cancel"),
                keys::DELETE_MESSAGE_CANCEL,
                |s| _ = s.cancel_resend(),
                theme::TEXT,
                None,
            ),
        ))
        .with_spacing(0),
        RESEND_WIDTH,
        HorizontalAlignment::Center,
        |s| _ = s.cancel_resend(),
    )
}

/// How to send again a message that was to go under forward secrecy.
#[inline(never)]
fn resend_choices(m: &'static Metrics) -> impl View<Rgb565, State> + use<> {
    let text = |text: &str| heapless::String::try_from(text).unwrap_or_default();
    card(
        m,
        VStack::new((
            choice(
                m,
                text("Try again"),
                keys::RESEND,
                State::resend,
                theme::TEXT,
                None,
            ),
            choice(
                m,
                text("Send without forward secrecy"),
                keys::RESEND_WITHOUT_SECRECY,
                State::resend_without_secrecy,
                theme::TEXT,
                None,
            ),
            choice(
                m,
                text("Cancel"),
                keys::RESEND_CANCEL,
                |s| _ = s.cancel_resend(),
                theme::TEXT,
                None,
            ),
        ))
        .with_spacing(0),
        RESEND_WIDTH,
        HorizontalAlignment::Center,
        |s| _ = s.cancel_resend(),
    )
}

/// Back, the peer or channel, and how far away a peer is or that it is a
/// channel; or a screen's title alone.
pub(super) fn header(
    m: &'static Metrics,
    name: &str,
    avatar: Option<&AvatarStyle>,
    kind: Option<ChatKind>,
) -> impl View<Rgb565, State> + use<> {
    let mut distance: heapless::String<16> = heapless::String::new();
    // A channel sent in the clear says so, in red.
    let clear = matches!(
        kind,
        Some(ChatKind::Channel {
            access: ChannelAccess::Clear
        })
    );
    match kind {
        Some(ChatKind::Peer { hops: Some(hops) }) => _ = distance.push_str(&hops_text(hops)),
        Some(ChatKind::Channel {
            access: ChannelAccess::Clear,
        }) => _ = distance.push_str("Not encrypted"),
        Some(ChatKind::Channel { .. }) => _ = distance.push_str("Channel"),
        Some(ChatKind::Peer { hops: None }) | None => {}
    }
    HStack::new((
        back(m, |s| _ = s.back()),
        HStack::new((
            avatar.map(|style| super::avatar::view(style, AVATAR)),
            label::<32>(
                name,
                &font::BOLD,
                m.body,
                if clear { theme::RED } else { theme::TEXT },
            )
            .fixed_size(true, false),
            label::<16>(&distance, &font::MEDIUM, m.small, theme::TEXT_TERTIARY),
            Spacer::default(),
        ))
        .with_spacing(6),
    ))
    .with_spacing(ARROW_GAP)
    .padding(Edges::Leading, if m.back { 0 } else { LEADING })
    .frame()
    .with_height(m.header)
    .overlay(
        Alignment::Bottom,
        Rectangle
            .foreground_color(theme::LINE)
            .frame()
            .with_height(1),
    )
}

/// The way back, doing `act`, for touch alone, where the board has touch:
/// the keys have Back. Its place is the header's height; a finger near it
/// takes it as a minimum touch target.
pub(super) fn back(
    m: &'static Metrics,
    act: fn(&mut State),
) -> Option<impl View<Rgb565, State> + use<>> {
    m.back.then(|| {
        Button::new(act, move |button: ButtonState| {
            Image::new(&icon::BACK)
                .as_template()
                .foreground_color(if button.is_pressed() {
                    theme::TEXT
                } else {
                    theme::TEXT_TERTIARY
                })
                .padding(Edges::Leading, ARROW_INSET)
                .frame()
                .with_height(m.header)
                // All of it takes the touch, not the arrow alone.
                .content_shape(Rectangle)
        })
        .with_role(Role::Pointer)
    })
}

/// The messages, oldest first, ending at the composer. History shorter
/// than the space sits on the composer. The message whose actions are open
/// stays marked while focus is in them. A message sent brings the newest
/// into view, however far back the history was read.
fn history(
    m: &'static Metrics,
    messages: &[Message],
    sent: u32,
    acting_on: Option<MessageId>,
    channel: bool,
    open: bool,
    times: Times,
) -> impl View<Rgb565, State> + use<> {
    let messages = Messages::from_slice(messages).unwrap_or_default();
    let ids: Vec<MessageId, MAX_MESSAGES> = messages.iter().map(|m| m.id).collect();
    // Delivery shows under the newest message sent, the newest delivered,
    // and every one unconfirmed.
    let newest_sent = messages
        .iter()
        .rposition(|m| m.direction == Direction::Outbound);
    let newest_delivered = messages
        .iter()
        .rposition(|m| m.direction == Direction::Outbound && m.delivery == Delivery::Delivered);
    let count = messages.len();
    ScrollView::new(
        ForEach::<MAX_MESSAGES>::new_vertical(&INDICES[..count], move |&i| {
            // A deleted one has nothing left to deliver.
            let delivery = !messages[i].deleted
                && (Some(i) == newest_sent
                    || Some(i) == newest_delivered
                    || messages[i].delivery == Delivery::Unconfirmed);
            item(m, &messages, i, delivery, acting_on, channel, open, times)
        })
        .keyed(move |&i| keys::message(ids[i])),
    )
    .with_bar_visibility(ScrollBarVisibility::Never)
    .with_initial_pin_to_end(true)
    .with_end_generation(sent)
    .with_short_content_at_end(true)
    .with_focus_margin(FOCUS_MARGIN)
    .with_scroll_step(SCROLL_STEP)
}

/// A message, with its delivery below it when asked. In a channel, each run
/// of messages from one member has the member's name above its first and
/// their avatar beside its last.
#[allow(clippy::too_many_arguments)]
fn item(
    m: &'static Metrics,
    messages: &Messages,
    i: usize,
    delivery: bool,
    acting_on: Option<MessageId>,
    channel: bool,
    open: bool,
    times: Times,
) -> impl View<Rgb565, State> + use<> {
    let message = &messages[i];
    // A run of messages on their way again shows as the first of them.
    let pending = message.presence == Presence::PendingRepair;
    let collapsed = pending
        && i.checked_sub(1)
            .is_some_and(|p| messages[p].presence == Presence::PendingRepair);
    let separator = (!collapsed)
        .then(|| separator(messages, i, times))
        .flatten();
    let follows_same = separator.is_none()
        && i.checked_sub(1).is_some_and(|p| {
            messages[p].direction == message.direction && messages[p].sender == message.sender
        });
    let gap = if collapsed {
        0
    } else if i == 0 || follows_same {
        GAP_SAME
    } else {
        GAP_CHANGE
    };
    // What stands in the place of a message that is not there.
    let stand_in = if collapsed {
        None
    } else if pending {
        Some(StandIn::Coming)
    } else if message.presence == Presence::Unavailable {
        Some(StandIn::Gone("Message unavailable"))
    } else if message.deleted {
        Some(StandIn::Gone("Message deleted"))
    } else {
        None
    };
    let shown = !collapsed && stand_in.is_none();
    let outbound = message.direction == Direction::Outbound;
    let alignment = if outbound {
        HorizontalAlignment::Trailing
    } else {
        HorizontalAlignment::Leading
    };
    let sender = (!follows_same && !collapsed)
        .then(|| message.sender.clone())
        .flatten();
    let ends_run = messages
        .get(i + 1)
        .is_none_or(|next| next.direction != message.direction || next.sender != message.sender);
    // A channel's received bubbles stand clear of their senders' avatars.
    let beside_avatar = channel && !outbound;
    let avatar = message
        .sender
        .as_ref()
        .filter(|_| beside_avatar && ends_run && !collapsed)
        .map(|sender| {
            Lazy::new(sender.avatar.clone(), member_avatar)
                .padding(Edges::Leading, MEMBER_AVATAR_X)
                .padding(Edges::Bottom, RING_GAP)
        });
    let lead = if beside_avatar { IN_X } else { SIDE };
    // Chips over the bubble take room above it, which a sender's name
    // beside them shares.
    let reserve = chip_reserve(&message.reactions).saturating_sub(if sender.is_some() {
        SENDER_LINE
    } else {
        0
    });
    let notes = match stand_in {
        Some(stand_in) => Some(Notes::StandIn(stand_in)),
        None if shown => {
            let caption = caption(message, delivery);
            let parts = message.parts;
            (caption.is_some() || parts.is_some()).then_some(Notes::Below { caption, parts })
        }
        None => None,
    };
    let head = (separator.is_some() || sender.is_some()).then(|| Head {
        stamp: separator,
        sender: sender.map(|sender| sender.name),
        beside_avatar,
    });
    VStack::new((
        head.map(|head| Lazy::new((head, m), |(head, m)| head_view(m, head))),
        shown.then(|| {
            bubble(m, message, acting_on == Some(message.id), open)
                .padding(Edges::Leading, lead - SIDE)
        }),
        notes.map(|notes| Lazy::new((notes, outbound, beside_avatar, m), notes_view)),
    ))
    .with_spacing(0)
    .with_alignment(alignment)
    .flex_infinite_width(alignment)
    // Received messages have no delivery line, so the bottom is the bubble's.
    .overlay(Alignment::BottomLeading, avatar)
    .padding(Edges::Top, gap + reserve)
}

/// What goes over a message: when the conversation picked up again, and
/// who sent it, over the first of a run of a member's messages.
#[derive(Clone)]
struct Head {
    stamp: Option<Stamp>,
    sender: Option<heapless::String<24>>,
    beside_avatar: bool,
}

/// A message's head, its sender's name set in from its side as its bubble
/// is.
///
/// Built from its data each time it is drawn ([`Lazy`]), as a bubble's
/// contents are.
fn head_view(m: &'static Metrics, head: &Head) -> impl View<Rgb565, ()> + use<> {
    let lead = if head.beside_avatar { IN_X } else { SIDE };
    VStack::new((
        head.stamp.as_ref().map(|stamp| {
            separator_line(m, stamp)
                .flex_infinite_width(HorizontalAlignment::Center)
                .padding(Edges::Bottom, GAP_SEPARATOR)
        }),
        head.sender.clone().map(|name| {
            super::line(name, &font::BOLD, m.small, theme::TEXT_SECONDARY)
                .frame()
                .with_height(SENDER_LINE)
                .padding(Edges::Leading, lead + 4)
        }),
    ))
    .with_spacing(0)
    .with_alignment(HorizontalAlignment::Leading)
}

/// What goes with a message besides its bubble: what stands in its place
/// when it is not there, or the line about it and the dots of its parts.
#[derive(Clone, Copy)]
enum Notes {
    StandIn(StandIn),
    Below {
        caption: Option<Caption>,
        parts: Option<Parts>,
    },
}

/// A message's notes, set in from its side as its bubble is.
///
/// Built from its data each time it is drawn ([`Lazy`]), as a bubble's
/// contents are.
fn notes_view(
    &(notes, outbound, beside_avatar, m): &(Notes, bool, bool, &'static Metrics),
) -> impl View<Rgb565, ()> + use<> {
    let lead = if beside_avatar { IN_X } else { SIDE };
    let (stand_in, caption, parts) = match notes {
        Notes::StandIn(stand_in) => (Some(stand_in), None, None),
        Notes::Below { caption, parts } => (None, caption, parts),
    };
    VStack::new((
        stand_in.map(|stand_in| {
            stand_in_view(m, stand_in, outbound).padding(Edges::Leading, lead - SIDE)
        }),
        caption.map(|caption| {
            caption_line(m, caption, outbound)
                .padding(Edges::Leading, lead + 4)
                .padding(Edges::Trailing, SIDE)
        }),
        parts.map(|parts| part_dots(parts).padding(Edges::Leading, lead + 2)),
    ))
    .with_spacing(0)
    .with_alignment(if outbound {
        HorizontalAlignment::Trailing
    } else {
        HorizontalAlignment::Leading
    })
}

/// A message in its bubble. Mine are in the color that says who can read
/// them: green in an `open` channel, violet when sent under a session with
/// forward secrecy.
fn bubble(
    m: &'static Metrics,
    message: &Message,
    acting_on: bool,
    open: bool,
) -> impl View<Rgb565, State> + use<> {
    let id = message.id;
    let outbound = message.direction == Direction::Outbound;
    let side = if outbound {
        HorizontalAlignment::Trailing
    } else {
        HorizontalAlignment::Leading
    };
    let look = Look {
        text: message.text.clone(),
        reply: message.reply.clone(),
        card: message.card.as_ref().map(|card| match card {
            model::Card::Channel(invite) => Card {
                name: invite.name.clone(),
                avatar: invite.avatar(),
                kind: "Channel invite",
            },
            model::Card::Contact(contact) => Card {
                name: contact.name.clone(),
                avatar: contact.avatar.clone(),
                kind: "Contact",
            },
        }),
        reactions: message.reactions.clone(),
        to_come: message.parts.map(|parts| parts.lost != 0),
        outbound,
        open,
        forward_secret: message.forward_secret,
        ringed: acting_on,
    };
    // Pressing a message opens its actions. A tap only selects it: holding
    // it does what a press does.
    Button::new(
        move |s: &mut State| {
            if !s.touching {
                s.open_actions(id);
            }
        },
        move |button: ButtonState| {
            let mut look = look.clone();
            look.ringed |= button.is_focused();
            // The room around the bubble, where its ring and chips stand,
            // that the look does not hold.
            let (corner, rest) = look.held();
            let (outer, inner) = look.sides();
            Lazy::new((look, m), |(look, m)| bubble_look(m, look))
                .padding(Edges::Top, RING_GAP - corner)
                .padding(outer, RING_GAP - corner)
                .padding(Edges::Bottom, RING_GAP - rest)
                .padding(inner, RING_GAP - rest)
                // Text wraps to fit; a short bubble keeps to its side.
                .flex_frame()
                .with_max_width(bubble_max(m) + 2 * RING_GAP)
                .with_horizontal_alignment(side)
        },
    )
    .padding(Edges::Horizontal, SIDE - RING_GAP)
}

/// What a bubble draws: its contents, its reactions, and whether it is
/// ringed. Its colors follow from whose it is and who can read it.
#[derive(Clone)]
struct Look {
    text: SharedText,
    reply: Option<Quote>,
    card: Option<Card>,
    reactions: Reactions,
    /// Parts are still to come, and whether one will not.
    to_come: Option<bool>,
    outbound: bool,
    /// In a channel anyone can read, where mine are green.
    open: bool,
    /// Mine, sent under a session with forward secrecy.
    forward_secret: bool,
    /// Focused, or its actions are open.
    ringed: bool,
}

impl Look {
    /// How much of the room around the bubble its look holds, which is
    /// what focus keeps in view with it: what its ring takes while it is
    /// ringed, out to the middle of the ring's line, and the corner its
    /// chips hang from while it has reactions. As the room at its top and
    /// outer side, then at its bottom and inner side.
    fn held(&self) -> (u32, u32) {
        let ring = if self.ringed {
            RING_GAP - RING_LINE / 2
        } else {
            0
        };
        let chips = if self.reactions.is_empty() {
            0
        } else {
            RING_GAP
        };
        (ring.max(chips), ring)
    }

    /// Its outer side, then its inner side: mine keep to the trailing side.
    fn sides(&self) -> (Edges, Edges) {
        if self.outbound {
            (Edges::Leading, Edges::Trailing)
        } else {
            (Edges::Trailing, Edges::Leading)
        }
    }
}

/// What a card shows: the channel an invitation is to, or the node a
/// contact introduces, and which of the two it is.
#[derive(Clone)]
struct Card {
    name: SharedText,
    avatar: AvatarStyle,
    kind: &'static str,
}

/// A card's own item, first in its message's actions menu.
#[derive(Clone)]
enum CardItem {
    /// Join the channel it invites to.
    Join(MenuText),
    /// Show the node it introduces.
    Show(MenuText),
}

/// A bubble, ringed while it is focused, with its reactions as chips over
/// its outer top corner: both outside it, in the room around it, of which
/// it holds what [`Look::held`] says.
///
/// Built from its data each time it is drawn ([`Lazy`]): kept in the
/// render trees, every bubble's would outweigh the rest of the screen.
fn bubble_look(m: &'static Metrics, look: &Look) -> impl View<Rgb565, ()> + use<> {
    let gap = RING_GAP as i32;
    let (corner, out) = if look.outbound {
        (Alignment::TopLeading, -gap)
    } else {
        (Alignment::TopTrailing, gap)
    };
    let (held_corner, held_rest) = look.held();
    let (outer, inner) = look.sides();
    body_view(m, look)
        .overlay(
            Alignment::Center,
            look.ringed.then(|| {
                GeometryReader::new(move |size: Size| {
                    RoundedRectangle::new(BUBBLE_RADIUS + RING_GAP as u16)
                        .stroked(RING_LINE)
                        .foreground_color(theme::ACCENT)
                        .frame_sized(size.width + 2 * RING_GAP, size.height + 2 * RING_GAP)
                        .offset(-gap, -gap)
                })
            }),
        )
        // Over the ring, so a chip cuts it as it cuts the bubble.
        .overlay(
            corner,
            (!look.reactions.is_empty())
                .then(|| chips(m, &look.reactions, look.outbound, look.open).offset(out, -gap)),
        )
        .padding(Edges::Top, held_corner)
        .padding(outer, held_corner)
        .padding(Edges::Bottom, held_rest)
        .padding(inner, held_rest)
}

/// A message's text, under the quote of what it answers and before the
/// dots for parts still to come; or an invitation, which is its card
/// alone: its text is only the channel's link.
fn body_view(m: &'static Metrics, look: &Look) -> impl View<Rgb565, ()> + use<> {
    let Look {
        outbound,
        open,
        forward_secret,
        ..
    } = *look;
    let mut corners = CornerRadii::equal(BUBBLE_RADIUS);
    let (fill, color) = if outbound {
        corners.bottom_right = TAIL_RADIUS;
        let fill = if open {
            theme::OUTBOUND_OPEN
        } else if forward_secret {
            theme::OUTBOUND_SECRET
        } else {
            theme::OUTBOUND
        };
        (fill, Rgb565::WHITE)
    } else {
        corners.bottom_left = TAIL_RADIUS;
        (theme::INBOUND, theme::TEXT)
    };
    // Parts still to come go after the text: amber once one will not.
    let to_come = look.to_come.map(|lost| {
        if lost {
            theme::AMBER
        } else {
            theme::TEXT_TERTIARY
        }
    });
    let quote_colors = match (outbound, forward_secret) {
        (true, true) => (
            theme::QUOTE_BAR_SECRET,
            theme::QUOTE_NAME_SECRET,
            theme::QUOTE_TEXT_SECRET,
        ),
        (true, false) => (
            theme::QUOTE_BAR_MINE,
            theme::QUOTE_NAME_MINE,
            theme::QUOTE_TEXT_MINE,
        ),
        (false, _) => (theme::ACCENT, theme::ACCENT, theme::TEXT_SECONDARY),
    };
    VStack::new((
        look.card.is_none().then(|| {
            VStack::new((
                look.reply
                    .as_ref()
                    .map(|reply| quoted(m, reply, quote_colors)),
                HStack::new((
                    Text::new(look.text.clone(), &font::REGULAR)
                        .with_font_size(m.body)
                        .foreground_color(color),
                    to_come.map(|color| to_come_dots(m, color)),
                ))
                .with_spacing(4)
                .with_alignment(VerticalAlignment::Bottom)
                .hint_background_color(fill),
            ))
            .with_spacing(0)
            .with_alignment(HorizontalAlignment::Leading)
            .padding(Edges::Horizontal, BUBBLE_PAD_X)
            .padding(Edges::Vertical, BUBBLE_PAD_Y)
            .background_color(fill, RoundedRectangle::with_radii(corners))
        }),
        look.card
            .as_ref()
            .map(|card| link_card(m, card, fill, color, corners)),
    ))
}

/// Where the parts still to come will go, after a message's text: three
/// dots at the middle of its last line.
fn to_come_dots(m: &'static Metrics, color: Rgb565) -> impl View<Rgb565, ()> + use<> {
    let dot = Circle.foreground_color(color).frame_sized(4, 4);
    HStack::new((dot.clone(), dot.clone(), dot))
        .with_spacing(3)
        .padding(Edges::Bottom, body_line(m) / 2 - 4)
}

/// A reply's quote, at the top of its bubble.
const QUOTED: u32 = 38;

/// Whom and what a reply answers, behind a bar, as the quote over the
/// composer shows a draft's: in its bar's, the name's, and the text's
/// `colors`, which in my bubbles are tints of the bubble's.
fn quoted(
    m: &'static Metrics,
    reply: &Quote,
    (bar, name, text): (Rgb565, Rgb565, Rgb565),
) -> impl View<Rgb565, ()> + use<> {
    let line = |face| {
        move |s| {
            Text::new(s, face)
                .with_font_size(m.small)
                .with_line_limit(1)
        }
    };
    HStack::new((
        RoundedRectangle::new(1)
            .foreground_color(bar)
            .frame_sized(3, QUOTED - 6),
        VStack::new((
            reply
                .name
                .clone()
                .map(|who| line(&font::BOLD)(who).foreground_color(name)),
            reply.name.is_none().then(|| {
                Text::new("You", &font::BOLD)
                    .with_font_size(m.small)
                    .foreground_color(name)
            }),
            line(&font::REGULAR)(reply.text.clone()).foreground_color(text),
        ))
        .with_spacing(0)
        .with_alignment(HorizontalAlignment::Leading),
    ))
    .with_spacing(7)
    .frame()
    .with_height(QUOTED)
}

/// A card, and its avatar.
const CARD_WIDTH: u32 = 300;
const CARD_HEIGHT: u32 = 64;
const CARD_AVATAR: u32 = 44;

/// The channel an invitation is to, or the node a contact introduces, in a
/// card that a press can take: a link inside text could not be focused.
fn link_card(
    m: &'static Metrics,
    card: &Card,
    fill: Rgb565,
    color: Rgb565,
    corners: CornerRadii<u16>,
) -> impl View<Rgb565, ()> + use<> {
    HStack::new((
        super::avatar::view(&card.avatar, CARD_AVATAR),
        VStack::new((
            Text::new(card.name.clone(), &font::BOLD)
                .with_font_size(m.body)
                .with_line_limit(1)
                .foreground_color(color),
            Text::new(card.kind, &font::REGULAR)
                .with_font_size(m.secondary)
                .with_line_limit(1)
                .foreground_color(theme::TEXT_SECONDARY),
        ))
        .with_spacing(0)
        .with_alignment(HorizontalAlignment::Leading),
        Spacer::default(),
        Image::new(&icon::CHEVRON)
            .as_template()
            .foreground_color(theme::TEXT_TERTIARY),
    ))
    .with_spacing(10)
    .hint_background_color(fill)
    .padding(Edges::Leading, 10)
    .padding(Edges::Trailing, 12)
    .frame()
    .with_width(CARD_WIDTH.min(bubble_max(m) - 2 * BUBBLE_PAD_X))
    .with_height(CARD_HEIGHT)
    .background_color(fill, RoundedRectangle::with_radii(corners))
}

/// A reaction chip's diameter, the background ring that sets it off, and how
/// far apart chips overlap.
const CHIP: u32 = 28;
const CHIP_HALO: u32 = 2;
const CHIP_STEP: i32 = 21;
/// How far a chip's center sits above the bubble's top edge.
const CHIP_RISE: u32 = 6;
/// The count on a chip shared by several people.
const BADGE: u32 = 18;

/// Room above a bubble for its chips, and for a count when there is one.
fn chip_reserve(reactions: &[Reacted]) -> u32 {
    if reactions.is_empty() {
        return 0;
    }
    let counted = reactions.iter().any(|r| r.count > 1);
    CHIP_RISE + CHIP / 2 + CHIP_HALO + if counted { 6 } else { 0 }
}

/// A bubble's reactions as round chips over its outer top corner, like a
/// hand of cards: mine frontmost at the corner, with one dot trail falling
/// outside the bubble. Placed from the corner outward and inward: offsets
/// here are from the corner of the ring around the bubble.
fn chips(
    m: &'static Metrics,
    reactions: &Reactions,
    outbound: bool,
    open: bool,
) -> impl View<Rgb565, ()> + use<> {
    // Mine takes the color of my bubbles.
    let (mine_fill, mine_pad) = if open {
        (theme::OUTBOUND_OPEN, icon::Pad::MineOpen)
    } else {
        (theme::OUTBOUND, icon::Pad::Mine)
    };
    // Toward the outside of the bubble: left on a sent message.
    let out: i32 = if outbound { -1 } else { 1 };
    let ring = RING_GAP as i32;
    // How far an element's outer edge reaches beyond the corner, as an
    // offset from the side the cluster is aligned to.
    let edge = move |beyond: i32| out * (beyond - ring);
    let top = move |above_bubble: i32| ring + above_bubble;
    let halo = (CHIP + 2 * CHIP_HALO) as i32;
    // Mine at the corner, then others inward, drawn back to front.
    let mut order: Vec<Reacted, { Reaction::ALL.len() }> = Vec::new();
    for r in reactions.iter().filter(|r| r.mine) {
        _ = order.push(*r);
    }
    for r in reactions.iter().filter(|r| !r.mine) {
        _ = order.push(*r);
    }
    let count = order.len();
    let front = order.first().map_or(theme::CHIP_THEIRS, |r| {
        if r.mine {
            mine_fill
        } else {
            theme::CHIP_THEIRS
        }
    });
    // The `k`th chip drawn: the innermost first, mine at the corner last.
    let chip = move |k: usize| {
        let place = count.checked_sub(1 + k)?;
        order.get(place).map(|r| {
            let inward = CHIP_STEP * place as i32;
            let (fill, pad) = if r.mine {
                (mine_fill, mine_pad)
            } else {
                (theme::CHIP_THEIRS, icon::Pad::Theirs)
            };
            let number = (r.count > 1).then(|| {
                let mut n: heapless::String<4> = heapless::String::new();
                _ = core::fmt::write(&mut n, format_args!("{}", r.count));
                ZStack::new((
                    Circle.foreground_color(theme::BACKGROUND),
                    Text::new(n, &font::BOLD)
                        .with_font_size(m.small)
                        .with_line_limit(1)
                        .foreground_color(theme::TEXT),
                ))
                .frame_sized(BADGE, BADGE)
                .offset(
                    edge(BADGE as i32 / 2 + 11 - inward),
                    top(-(CHIP_RISE as i32) - 11 - BADGE as i32 / 2),
                )
            });
            ZStack::new((
                ZStack::new((
                    Circle.foreground_color(theme::BACKGROUND),
                    Circle.foreground_color(fill).frame_sized(CHIP, CHIP),
                    Image::new(icon::reaction(r.reaction, pad)),
                ))
                .frame_sized(halo as u32, halo as u32)
                .offset(edge(halo / 2 - inward), top(-(CHIP_RISE as i32) - halo / 2)),
                number,
            ))
            .with_alignment(if outbound {
                Alignment::TopLeading
            } else {
                Alignment::TopTrailing
            })
        })
    };
    // The dot trail, from the corner chip outward and down.
    let dot = move |distance: i32, radius: u32, color: Rgb565| {
        let size = 2 * radius;
        Circle
            .foreground_color(color)
            .frame_sized(size, size)
            .offset(
                edge(distance + radius as i32),
                top(distance - CHIP_RISE as i32 - radius as i32),
            )
    };
    ZStack::new((
        dot(15, 6, theme::BACKGROUND),
        dot(15, 4, front),
        dot(21, 4, theme::BACKGROUND),
        dot(21, 2, front),
        chip(0),
        chip(1),
        chip(2),
        chip(3),
        chip(4),
        chip(5),
    ))
    .with_alignment(if outbound {
        Alignment::TopLeading
    } else {
        Alignment::TopTrailing
    })
}

/// What the line under a message says: that it was changed or came late,
/// and, when asked, how its delivery went.
#[derive(Clone, Copy)]
struct Caption {
    edited: bool,
    status: Option<&'static str>,
    color: Rgb565,
}

fn caption(message: &Message, delivery: bool) -> Option<Caption> {
    let mut color = theme::TEXT_TERTIARY;
    let status = match message.direction {
        Direction::Inbound if message.late => Some("Received late"),
        Direction::Outbound if delivery => Some(match message.delivery {
            Delivery::Sending => "Sending",
            Delivery::Sent => "Sent",
            Delivery::Delivered => "Delivered",
            Delivery::Unconfirmed => {
                color = theme::AMBER;
                "Unconfirmed"
            }
        }),
        _ => None,
    };
    (message.edited || status.is_some()).then_some(Caption {
        edited: message.edited,
        status,
        color,
    })
}

fn caption_line(
    m: &'static Metrics,
    caption: Caption,
    outbound: bool,
) -> impl View<Rgb565, ()> + use<> {
    let mut text: heapless::String<40> = heapless::String::new();
    if caption.edited {
        _ = text.push_str("Edited");
    }
    if let Some(status) = caption.status {
        if !text.is_empty() {
            _ = text.push_str(" \u{B7} ");
        }
        _ = text.push_str(status);
    }
    Text::new(text, &font::SEMIBOLD)
        .with_font_size(m.small)
        .with_line_limit(1)
        .foreground_color(caption.color)
        .frame()
        .with_height(STATUS_LINE)
        .flex_infinite_width(if outbound {
            HorizontalAlignment::Trailing
        } else {
            HorizontalAlignment::Leading
        })
}

/// What stands in the place of a message that is not there: the dots of
/// one on its way again, or a line saying it is gone.
#[derive(Clone, Copy)]
enum StandIn {
    Coming,
    Gone(&'static str),
}

/// The width of the bubble that holds a message's place while it comes
/// again.
const COMING_WIDTH: u32 = 62;

fn stand_in_view(
    m: &'static Metrics,
    stand_in: StandIn,
    outbound: bool,
) -> impl View<Rgb565, ()> + use<> {
    let side = if outbound {
        HorizontalAlignment::Trailing
    } else {
        HorizontalAlignment::Leading
    };
    let coming = matches!(stand_in, StandIn::Coming).then(|| {
        let mut corners = CornerRadii::equal(BUBBLE_RADIUS);
        if outbound {
            corners.bottom_right = TAIL_RADIUS;
        } else {
            corners.bottom_left = TAIL_RADIUS;
        }
        let dot = |color| Circle.foreground_color(color).frame_sized(8, 8);
        HStack::new((
            dot(theme::TEXT_SECONDARY),
            dot(theme::TEXT_TERTIARY),
            dot(theme::GAP_DOT),
        ))
        .with_spacing(6)
        .frame_sized(COMING_WIDTH, body_line(m) + 2 * BUBBLE_PAD_Y)
        .background_color(
            if outbound {
                theme::OUTBOUND
            } else {
                theme::INBOUND
            },
            RoundedRectangle::with_radii(corners),
        )
    });
    let gone = match stand_in {
        StandIn::Gone(text) => Some(
            Text::new(text, &font::REGULAR)
                .with_font_size(m.secondary)
                .with_line_limit(1)
                .foreground_color(theme::TEXT_TERTIARY)
                .frame()
                .with_height(STATUS_LINE)
                .padding(Edges::Horizontal, 4),
        ),
        StandIn::Coming => None,
    };
    VStack::new((coming, gone))
        .padding(Edges::Horizontal, SIDE)
        .flex_infinite_width(side)
}

/// A dot for each part of a message arriving in parts: filled once it
/// came, hollow while it is awaited, amber when it will not come.
fn part_dots(parts: Parts) -> impl View<Rgb565, ()> + use<> {
    let count = usize::from(parts.count).min(PART_INDICES.len());
    ForEach::<{ PART_INDICES.len() }>::new_horizontal(&PART_INDICES[..count], move |&i| {
        let bit = 1u16 << i;
        let (filled, color) = if parts.lost & bit != 0 {
            (false, theme::AMBER)
        } else if parts.received & bit != 0 {
            (true, theme::TEXT_SECONDARY)
        } else {
            (false, theme::TEXT_TERTIARY)
        };
        ZStack::new((
            filled.then(|| Circle.foreground_color(color).frame_sized(9, 9)),
            (!filled).then(|| Circle.stroked(2).foreground_color(color).frame_sized(8, 8)),
        ))
        .frame_sized(9, 9)
    })
    .with_spacing(4)
    .frame()
    .with_height(STATUS_LINE)
}

static PART_INDICES: [u16; 16] = {
    let mut a = [0; 16];
    let mut i = 0;
    while i < 16 {
        a[i] = i as u16;
        i += 1;
    }
    a
};

/// When the conversation picked up again after a lull: the local day and
/// time of the message after it.
#[derive(Clone, Copy)]
struct Times {
    /// Now, in Unix seconds, when the clock is known.
    now: Option<u32>,
    zone: Rule,
    hour24: bool,
    /// Messages older than those shown may be kept.
    older: bool,
}

/// How long a lull runs before the conversation says when it picked up
/// again: an hour, as on iOS.
const LULL: u32 = 60 * 60;

/// The day and the time over the message `i`, when a lull went before it,
/// or when it is the first there is.
fn separator(messages: &Messages, i: usize, times: Times) -> Option<Stamp> {
    let time = messages[i].time?;
    let lull = match messages[..i].iter().rev().find_map(|m| m.time) {
        Some(before) => time.saturating_sub(before) >= LULL,
        None => !times.older,
    };
    if !lull {
        return None;
    }
    // Each in the offset the zone kept then: a message from before a
    // change of daylight time keeps the time it was sent at.
    let local = |time: u32| Local::at(time, times.zone.offset_at(i64::from(time)));
    Some(Stamp {
        at: local(time),
        today: times.now.map(|now| local(now).day),
        hour24: times.hour24,
    })
}

/// When a lull ended, in local time, and today when the clock is known.
#[derive(Clone, Copy)]
struct Stamp {
    at: Local,
    today: Option<i32>,
    hour24: bool,
}

/// A stamp's day: Today, Yesterday, a weekday within the week, or a date.
fn day_label(stamp: &Stamp) -> heapless::String<16> {
    let mut label = heapless::String::new();
    let day = stamp.at.day;
    match stamp.today.map(|today| today - day) {
        Some(0) => _ = label.push_str("Today"),
        Some(1) => _ = label.push_str("Yesterday"),
        // Inside the last week a weekday places a message better than a
        // date does.
        Some(2..=6) => _ = label.push_str(WEEKDAYS[(day + 4).rem_euclid(7) as usize]),
        _ => {
            let (year, month, date) = civil(i64::from(day));
            _ = core::fmt::write(
                &mut label,
                format_args!("{} {date}", MONTHS[month as usize - 1]),
            );
            if stamp
                .today
                .map(|today| civil(i64::from(today)))
                .is_none_or(|(this_year, ..)| this_year != year)
            {
                _ = core::fmt::write(&mut label, format_args!(", {year}"));
            }
        }
    }
    label
}

/// How far the message after a separator stands below it.
const GAP_SEPARATOR: u32 = 6;

fn separator_line(m: &'static Metrics, stamp: &Stamp) -> impl View<Rgb565, ()> + use<> {
    let clock = stamp.at.time(stamp.hour24);
    HStack::new((
        Text::new(day_label(stamp), &font::BOLD)
            .with_font_size(m.small)
            .foreground_color(theme::TEXT_TERTIARY),
        Text::new(clock, &font::REGULAR)
            .with_font_size(m.small)
            .foreground_color(theme::TEXT_TERTIARY),
    ))
    .with_spacing(4)
    .frame()
    .with_height(STATUS_LINE)
}

/// When sending returns, while airtime is spent.
fn airtime_line(m: &'static Metrics, wait: u16) -> impl View<Rgb565, State> + use<> {
    let mut text: heapless::String<40> = heapless::String::new();
    _ = core::fmt::write(
        &mut text,
        format_args!(
            "Airtime limit \u{B7} Send in {}:{:02}",
            wait / 60,
            wait % 60
        ),
    );
    label::<40>(&text, &font::BOLD, m.small, theme::AMBER)
        .frame()
        .with_height(STATUS_LINE)
        .flex_infinite_width(HorizontalAlignment::Trailing)
        .padding(Edges::Trailing, SIDE)
}

/// The composer, or the line it folds to while you read.
/// `tone` is the field's fill and ring while it is edited.
fn composer(
    m: &'static Metrics,
    chat: ChatId,
    draft: &Draft,
    folded: bool,
    tone: (Rgb565, Rgb565),
    placeholder: &Placeholder,
) -> impl View<Rgb565, State> + use<> {
    buoyant::match_view!(folded, {
        true => folded_bar(m, draft, placeholder.clone()),
        false => field(m, chat, draft, tone, placeholder.clone()),
    })
}

fn field(
    m: &'static Metrics,
    chat: ChatId,
    draft: &Draft,
    tone: (Rgb565, Rgb565),
    placeholder: Placeholder,
) -> impl View<Rgb565, State> + use<> {
    let empty = draft.is_empty();
    TextField::new(draft, &font::REGULAR, move |s: &mut State| {
        s.draft_mut(chat)
    })
    .with_font_size(m.body)
    .with_max_lines(3)
    .on_submit(move |s: &mut State| s.send(chat))
    .on_active(State::field_active)
    .with_label(move |status: TextFieldStatus, area| {
        field_look(m, status, area, tone, empty.then_some(&placeholder))
    })
    .focus_key(keys::COMPOSER)
    .padding(Edges::Horizontal, SIDE)
    .padding(Edges::Vertical, COMPOSER_INSET)
}

fn field_look(
    m: &'static Metrics,
    status: TextFieldStatus,
    area: TextArea<'static, DraftText, PrerenderedFont>,
    (active_fill, active_ring): (Rgb565, Rgb565),
    placeholder: Option<&Placeholder>,
) -> impl View<Rgb565, State> + use<> {
    let (fill, line_width) = if status.is_active() {
        (active_fill, 2)
    } else {
        (theme::FIELD, 1)
    };
    let ring = if status.is_active() {
        active_ring
    } else if status.is_focused() {
        theme::ACCENT
    } else {
        theme::MENU_LINE
    };
    area.colors(AreaColors {
        caret: Some(active_ring),
        scroll_bar: Some((theme::MENU_LINE, theme::TEXT_SECONDARY)),
    })
    .foreground_color(theme::TEXT)
    .hint_background_color(fill)
    .overlay(
        Alignment::Leading,
        placeholder
            .filter(|_| !status.is_active())
            .map(|placeholder| {
                label::<48>(placeholder, &font::REGULAR, m.body, theme::TEXT_TERTIARY)
                    .padding(Edges::Leading, 4)
            }),
    )
    .padding(Edges::Horizontal, 12)
    .padding(Edges::Vertical, 2)
    .background(
        Alignment::Center,
        ZStack::new((
            RoundedRectangle::new(FIELD_RADIUS).foreground_color(fill),
            RoundedRectangle::new(FIELD_RADIUS)
                .stroked(line_width)
                .foreground_color(ring),
        )),
    )
}

/// The composer folded to one dim line: the draft, or where one would go.
fn folded_bar(
    m: &'static Metrics,
    draft: &Draft,
    placeholder: Placeholder,
) -> impl View<Rgb565, State> + use<> {
    let text = (!draft.is_empty()).then(|| draft.storage().clone());
    // Focusable, so turning past the newest message reaches the composer.
    Button::new(
        |_: &mut State| {},
        move |_| {
            HStack::new((
                Image::new(&icon::PENCIL)
                    .as_template()
                    .foreground_color(theme::TEXT_TERTIARY),
                text.clone()
                    .map(|text| super::line(text, &font::REGULAR, m.small, theme::TEXT_SECONDARY)),
                text.is_none().then(|| {
                    label::<48>(&placeholder, &font::REGULAR, m.small, theme::TEXT_TERTIARY)
                }),
            ))
            .with_spacing(4)
            .padding(Edges::Leading, 8)
            .flex_infinite_width(HorizontalAlignment::Leading)
            .frame()
            .with_height(BAR)
            .background_color(theme::CHROME, Rectangle)
            .overlay(
                Alignment::Top,
                Rectangle
                    .foreground_color(theme::LINE)
                    .frame()
                    .with_height(1),
            )
        },
    )
    .focus_key(keys::COMPOSER)
}

/// The quote above the composer while the draft is a reply.
const QUOTE: u32 = 42;

/// Who and what the draft replies to.
fn quote(
    m: &'static Metrics,
    message: &Message,
    chat_name: &str,
) -> impl View<Rgb565, State> + use<> {
    let mut title: heapless::String<48> = heapless::String::new();
    let whom = match (message.direction, &message.sender) {
        (Direction::Outbound, _) => "yourself",
        (Direction::Inbound, Some(sender)) => sender.name.as_str(),
        (Direction::Inbound, None) => chat_name,
    };
    _ = core::fmt::write(&mut title, format_args!("Replying to {whom}"));
    let text = message.text.clone();
    HStack::new((
        RoundedRectangle::new(2)
            .foreground_color(theme::ACCENT)
            .frame_sized(3, QUOTE - 6),
        VStack::new((
            label::<48>(&title, &font::BOLD, m.small, theme::ACCENT),
            super::line(text, &font::REGULAR, m.secondary, theme::TEXT_SECONDARY),
        ))
        .with_spacing(0)
        .with_alignment(HorizontalAlignment::Leading),
    ))
    .with_spacing(9)
    .padding(Edges::Leading, 12)
    .padding(Edges::Trailing, SIDE)
    .flex_infinite_width(HorizontalAlignment::Leading)
    .frame()
    .with_height(QUOTE)
}

/// The actions menu's width, and its palette's row.
const MENU_WIDTH: u32 = 236;
const PALETTE: u32 = 44;
const PAD: u32 = 34;
/// A menu item, and its focused look inside it.
const ITEM: u32 = 32;
const ITEM_INSET: u32 = 5;

/// What pressing a message gives: reactions first, then Reply and Details.
fn actions_menu(
    m: &'static Metrics,
    mine: Option<Reaction>,
    member: bool,
    card: Option<CardItem>,
) -> impl View<Rgb565, State> + use<> {
    let has_card = card.is_some();
    let pad = |reaction: Reaction| {
        Button::new(
            move |s: &mut State| s.react_from_actions(reaction),
            move |button: ButtonState| {
                let ring = if button.is_focused() {
                    Some(theme::ACCENT)
                } else if mine == Some(reaction) {
                    Some(theme::TEXT_TERTIARY)
                } else {
                    None
                };
                ZStack::new((
                    Circle.foreground_color(theme::REACTION_PAD),
                    Image::new(icon::reaction(reaction, icon::Pad::Palette)),
                    ring.map(|color| Circle.stroked(2).foreground_color(color)),
                ))
                .frame_sized(PAD, PAD)
            },
        )
        .focus_key(keys::reaction(reaction))
    };
    let [heart, up, down, laugh, exclaim, question] = Reaction::ALL;
    let content = VStack::new((
        HStack::new((
            pad(heart),
            pad(up),
            pad(down),
            pad(laugh),
            pad(exclaim),
            pad(question),
        ))
        .with_spacing(3)
        .padding(Edges::Leading, 8)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(PALETTE),
        Rectangle
            .foreground_color(theme::MENU_LINE)
            .frame()
            .with_height(1),
        // A card is for what it offers, first.
        card.map(|item| {
            let (text, key, action): (_, _, fn(&mut State)) = match item {
                CardItem::Join(text) => (text, keys::JOIN, State::join_from_actions),
                CardItem::Show(text) => {
                    (text, keys::VIEW_CONTACT, State::view_contact_from_actions)
                }
            };
            menu_item(m, text, key, action)
        })
        .padding(Edges::Top, 2),
        menu_item(
            m,
            menu_text("Reply"),
            keys::REPLY,
            State::reply_from_actions,
        )
        .padding(Edges::Top, if has_card { 0 } else { 2 }),
        member.then(|| {
            menu_item(
                m,
                menu_text("View member"),
                keys::VIEW_MEMBER,
                State::view_member_from_actions,
            )
        }),
        menu_item(
            m,
            menu_text("Details"),
            keys::DETAILS,
            State::details_from_actions,
        ),
    ))
    .with_spacing(0);
    menu_frame(m, content)
}

/// What pressing an unconfirmed message gives: Retry, Details, and Delete.
#[inline(never)]
fn unconfirmed_menu(m: &'static Metrics) -> impl View<Rgb565, State> + use<> {
    menu_frame(
        m,
        VStack::new((
            menu_item(
                m,
                menu_text("Retry"),
                keys::RETRY,
                State::retry_from_actions,
            )
            .padding(Edges::Top, 6),
            menu_item(
                m,
                menu_text("Details"),
                keys::DETAILS,
                State::details_from_actions,
            ),
            danger_item(
                m,
                menu_text("Delete"),
                keys::DELETE_MESSAGE,
                State::ask_delete_message,
            ),
        ))
        .with_spacing(0),
    )
}

/// A message's menu around `content`, at the top of the screen beside the
/// history. Backspace closes it, and typing closes it and goes to the
/// composer.
fn menu_frame<V: View<Rgb565, State>>(
    m: &'static Metrics,
    content: V,
) -> impl View<Rgb565, State> + use<V> {
    content
        .padding(Edges::Bottom, 6)
        .frame()
        .with_width(MENU_WIDTH)
        .background(
            Alignment::Center,
            ZStack::new((
                RoundedRectangle::new(12)
                    .foreground_color(Rgb565::BLACK)
                    .offset(1, 3),
                RoundedRectangle::new(12).foreground_color(theme::MENU),
                RoundedRectangle::new(12)
                    .stroked(1)
                    .foreground_color(theme::MENU_LINE),
            )),
        )
        .padding(Edges::Top, m.header + 6)
        .padding(Edges::Trailing, SIDE)
        .flex_infinite_width(HorizontalAlignment::Trailing)
        .flex_infinite_height(VerticalAlignment::Top)
        .on_key(|key, s: &mut State| match key {
            Key::Backspace => {
                s.close_actions();
                KeyResponse::Handled
            }
            Key::Character(_) | Key::Enter => {
                s.close_actions();
                s.focus().request(keys::COMPOSER);
                KeyResponse::Redirect
            }
            _ => KeyResponse::Ignored,
        })
}

/// A fixed action's label.
fn menu_text(text: &str) -> MenuText {
    MenuText::try_from(text).unwrap_or_default()
}

/// One of the menu's actions.
fn menu_item(
    m: &'static Metrics,
    text: MenuText,
    key: buoyant::focus::FocusKey,
    action: fn(&mut State),
) -> impl View<Rgb565, State> + use<> {
    item_in(m, text, key, action, theme::TEXT)
}

/// One of the menu's actions that cannot be taken back, in red.
fn danger_item(
    m: &'static Metrics,
    text: MenuText,
    key: buoyant::focus::FocusKey,
    action: fn(&mut State),
) -> impl View<Rgb565, State> + use<> {
    item_in(m, text, key, action, theme::RED)
}

fn item_in(
    m: &'static Metrics,
    text: MenuText,
    key: buoyant::focus::FocusKey,
    action: fn(&mut State),
    color: Rgb565,
) -> impl View<Rgb565, State> + use<> {
    Button::new(action, move |button: ButtonState| {
        let focused = button.is_focused();
        let face = if focused { &font::BOLD } else { &font::REGULAR };
        label::<40>(&text, face, m.body, color)
            .hint_background_color(if focused { theme::FOCUS } else { theme::MENU })
            .padding(Edges::Leading, 11)
            .flex_infinite_width(HorizontalAlignment::Leading)
            .frame()
            .with_height(ITEM - 2)
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
            .padding(Edges::Horizontal, ITEM_INSET)
            .padding(Edges::Bottom, 2)
    })
    .focus_key(key)
}

/// A channel member's avatar beside their messages. Built from its style
/// each time it is drawn ([`Lazy`]): kept in the render trees, one for every
/// run would outweigh the messages themselves.
fn member_avatar(style: &AvatarStyle) -> impl View<Rgb565, ()> + use<> {
    super::avatar::view(style, MEMBER_AVATAR)
}
