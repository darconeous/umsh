//! The route editor and a router's Neighbors, drawn by one view: a header
//! over a list of rows, each a button drawn from a description of it, and
//! what opens over the editor.
//!
//! Each kind of screen costs flash for every view type in it, compiled into
//! every pass the interface makes over its tree. Both screens are a list of
//! rows that each draw themselves, so they share one tree: what differs is
//! what each row says, which is drawn by [`Lazy`] outside the tree. Which
//! row is where is the navigation's ([`RouteDraft::row`],
//! [`listing_row`]), so that a press and the row drawn always agree.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::{BoundaryBehavior, FocusKey, Role};
use buoyant::match_view;
use buoyant::view::Lazy;
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::conversation::titled;
use super::neighbors::{self, Caption, NEIGHBOR, NeighborLook, TextLook};
use super::path::{self, NODE};
use super::route_edit::{self, Pinged, Value};
use crate::avatar::AvatarStyle;
use crate::board::Metrics;
use crate::model::{Listing, ListingAsk, MAX_LISTED, MAX_PATH, Node, PingView, Repeater, State};
use crate::nav::{Adjust, EditRow, ListRow, RouteDraft, Screen, keys, listing_row, listing_rows};
use crate::theme;

/// The most rows either screen has: the editor's with every hop.
const ROWS: usize = MAX_PATH + 6;
const _: () = assert!(MAX_LISTED + 4 <= ROWS);

static INDICES: [usize; ROWS] = {
    let mut a = [0; ROWS];
    let mut i = 0;
    while i < ROWS {
        a[i] = i;
        i += 1;
    }
    a
};

/// The route editor or the Neighbors shown, while one is.
// Out of line, as every page of `peer_or_channel` is.
#[inline(never)]
pub fn view(state: &State) -> Option<impl View<Rgb565, State> + use<>> {
    let m = state.metrics();
    let node = state.node;
    let (title, about, source, over, step) = match state.screen() {
        Screen::Route {
            peer,
            edit: Some(draft),
            ..
        } => {
            let summary = state.peer(*peer)?;
            let pinged = if draft.pinged {
                match node.ping_view(*peer) {
                    Some(PingView::Reply(reply)) if reply.flooded => Pinged::Flooded,
                    Some(PingView::Reply(reply)) => Pinged::Reply(reply.round_trip_ms),
                    Some(PingView::NoReply) => Pinged::NoReply,
                    Some(PingView::Waiting) | None => Pinged::Waiting,
                }
            } else {
                Pinged::Not
            };
            let mut name: String<32> = String::new();
            _ = name.push_str(umsh_grapheme::cut(summary.name.as_str(), 32));
            (
                "Edit route",
                name.clone(),
                Source::Edit {
                    draft: *draft,
                    avatar: summary.avatar.clone(),
                    name,
                    pinged,
                    adjusting: state.adjusting_route(),
                },
                draft.over,
                NODE,
            )
        }
        Screen::Neighbors { router, .. } => {
            let mut name: String<32> = String::new();
            if let Some(member) = node.known_member(router) {
                _ = name.push_str(&member.sender.name);
            }
            (
                "Neighbors",
                name,
                Source::Listing {
                    router: router.clone(),
                    listing: node.listing(router),
                    identifying: state.identifying(),
                    phase: state.spinner_phase(),
                },
                None,
                NEIGHBOR,
            )
        }
        _ => return None,
    };
    let count = source.count().min(ROWS);
    let mut keys = [keys::sheet(0); ROWS];
    for (i, key) in keys.iter_mut().enumerate().take(count) {
        *key = source.key(i);
    }
    Some(
        VStack::new((
            titled(m, title, theme::TEXT, None, &about),
            super::list(
                ForEach::<ROWS>::new_vertical(&INDICES[..count], move |&i| {
                    let (row, focusable) = source.row(node, m, i);
                    Button::new(
                        move |s: &mut State| s.press_sheet(i),
                        move |button: ButtonState| {
                            Lazy::new(
                                Look {
                                    row: row.clone(),
                                    focused: button.is_focused(),
                                    m,
                                },
                                look,
                            )
                        },
                    )
                    // A row that says something, rather than doing it,
                    // is passed over.
                    .with_role(if focusable {
                        Role::Button
                    } else {
                        Role::Pointer
                    })
                })
                .keyed(move |&i| keys[i])
                .with_spacing(0),
            )
            .with_scroll_step(step),
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
        .popover(over.as_ref(), move |over| route_edit::over_view(m, *over))
        // A tap outside closes it, as Backspace does.
        .on_blur(|s: &mut State| {
            s.close_route_over();
            Dismissal::Dismiss
        }),
    )
}

/// What the sheet lists the rows of.
#[derive(Clone)]
enum Source {
    /// A route being chosen to the peer named `name`.
    Edit {
        draft: RouteDraft,
        avatar: AvatarStyle,
        name: String<32>,
        pinged: Pinged,
        adjusting: Option<Adjust>,
    },
    /// What the router at `router` reports hearing.
    Listing {
        router: String<44>,
        listing: Option<Listing>,
        /// The bare hints asked who they are, still waited for.
        identifying: Vec<[u8; 2], MAX_PATH>,
        phase: u8,
    },
}

impl Source {
    fn count(&self) -> usize {
        match self {
            Self::Edit { draft, .. } => draft.rows(),
            Self::Listing { listing, .. } => listing_rows(listing.as_ref()),
        }
    }

    /// The row at `index`'s key: a row that does something keeps its own,
    /// which the navigation asks focus for by.
    fn key(&self, index: usize) -> FocusKey {
        match self {
            Self::Edit { draft, .. } => match draft.row(index) {
                Some(EditRow::Hop(hop)) => keys::path(hop),
                Some(EditRow::Flood) => keys::ROUTE_FLOOD,
                Some(EditRow::Ping) => keys::ROUTE_PING_ALONG,
                Some(EditRow::Hold) => keys::ROUTE_HOLD,
                Some(EditRow::Save) => keys::ROUTE_SAVE,
                Some(EditRow::You | EditRow::Peer) | None => keys::sheet(index),
            },
            Self::Listing { listing, .. } => match listing_row(listing.as_ref(), index) {
                Some(ListRow::Neighbor(at)) => keys::neighbor(at),
                Some(ListRow::More) => keys::NEIGHBORS_MORE,
                Some(ListRow::Refresh) => keys::NEIGHBORS_REFRESH,
                Some(ListRow::Read | ListRow::Said) | None => keys::sheet(index),
            },
        }
    }

    /// The row at `index`, and whether focus lands on it.
    fn row(&self, node: &'static dyn Node, m: &'static Metrics, index: usize) -> (Row, bool) {
        match self {
            Self::Edit {
                draft,
                avatar,
                name,
                pinged,
                adjusting,
            } => {
                let setting = |label, value, active, accent| Row::Setting {
                    look: route_edit::Look {
                        label,
                        value,
                        active,
                        focused: false,
                        accent,
                        m,
                    },
                    on_rail: false,
                };
                match draft.row(index) {
                    Some(EditRow::Hop(hop)) => (
                        Row::Hop {
                            // Named as it is laid out, so that the tree
                            // holds no repeater.
                            repeater: draft.hints().get(hop).and_then(|&hint| node.repeater(hint)),
                            lifted: draft.lifted.is_some_and(|(now, _)| usize::from(now) == hop),
                        },
                        true,
                    ),
                    Some(EditRow::Flood) => (
                        Row::Setting {
                            look: route_edit::Look {
                                // Past no repeater, the flood starts here.
                                label: if draft.hints().is_empty() {
                                    "Flood"
                                } else {
                                    "Then flood"
                                },
                                value: Value::Flood(draft.flood),
                                active: *adjusting == Some(Adjust::Flood),
                                focused: false,
                                accent: false,
                                m,
                            },
                            on_rail: true,
                        },
                        true,
                    ),
                    Some(EditRow::Peer) => (
                        Row::Peer {
                            avatar: avatar.clone(),
                            name: name.clone(),
                            flooding: draft.flood > 0,
                        },
                        false,
                    ),
                    Some(EditRow::Ping) => (
                        setting("Ping along route", Value::Ping(*pinged), false, false),
                        true,
                    ),
                    Some(EditRow::Hold) => (
                        setting(
                            "Hold for",
                            Value::Hold(draft.hold),
                            *adjusting == Some(Adjust::Hold),
                            false,
                        ),
                        true,
                    ),
                    Some(EditRow::Save) => (setting("Save", Value::None, false, true), true),
                    Some(EditRow::You) | None => (Row::You, false),
                }
            }
            Self::Listing {
                router,
                listing,
                identifying,
                phase,
            } => {
                let text = |label, count, busy| {
                    Row::Text(TextLook {
                        label,
                        count,
                        busy,
                        phase: *phase,
                        focused: false,
                        m,
                    })
                };
                let asking = listing.and_then(|listing| listing.asking);
                match listing_row(listing.as_ref(), index) {
                    Some(ListRow::Read) => (
                        Row::Caption(match listing.and_then(|listing| listing.read_ms_ago) {
                            Some(ms) => Caption::Read(neighbors::read_text(ms)),
                            None => Caption::Note("Not read", None, theme::TEXT_TERTIARY),
                        }),
                        false,
                    ),
                    Some(ListRow::Neighbor(at)) => match node.listed(router, at) {
                        Some(listed) => (
                            Row::Neighbor(NeighborLook {
                                known: listed.address.is_some(),
                                waiting: listed.address.is_none()
                                    && identifying.contains(&listed.hint),
                                name: listed.name,
                                avatar: listed.avatar,
                                signal: listed.signal,
                                heard_min: listed.heard_min,
                                distance_m: listed.distance_m,
                                phase: *phase,
                                focused: false,
                                m,
                            }),
                            true,
                        ),
                        None => (Row::You, false),
                    },
                    Some(ListRow::Said) => (
                        Row::Caption(if listing.is_some_and(|listing| listing.no_answer) {
                            Caption::Note(
                                "No answer",
                                Some("Out of reach, or it keeps no neighbor list"),
                                theme::AMBER,
                            )
                        } else {
                            Caption::Note("None", None, theme::TEXT_TERTIARY)
                        }),
                        false,
                    ),
                    Some(ListRow::More) => (
                        text(
                            "Load more",
                            listing.map(|listing| (listing.count, listing.total)),
                            asking == Some(ListingAsk::More),
                        ),
                        true,
                    ),
                    Some(ListRow::Refresh) => {
                        (text("Refresh", None, asking == Some(ListingAsk::Top)), true)
                    }
                    None => (Row::You, false),
                }
            }
        }
    }
}

/// What a row of the sheet draws.
#[derive(Clone)]
enum Row {
    /// This device, where a route starts.
    You,
    /// A hop of the route: the node it most plausibly is, and whether it
    /// rides the wheel.
    Hop {
        repeater: Option<Repeater>,
        lifted: bool,
    },
    /// A row of the editor past the hops, on the rail or under the path.
    Setting {
        look: route_edit::Look,
        on_rail: bool,
    },
    /// The peer, where a route ends.
    Peer {
        avatar: AvatarStyle,
        name: String<32>,
        flooding: bool,
    },
    Neighbor(NeighborLook),
    Caption(Caption),
    /// Load more or Refresh.
    Text(TextLook),
}

/// A row, and whether it has focus.
#[derive(Clone)]
struct Look {
    row: Row,
    focused: bool,
    m: &'static Metrics,
}

/// A row's look. Built each time it is drawn ([`Lazy`]), so that every
/// kind of row is one type in the tree.
fn look(look: &Look) -> impl View<Rgb565, ()> + use<> {
    let (focused, m) = (look.focused, look.m);
    match_view!(&look.row, {
        Row::You => path::you_look(&m),
        Row::Hop { repeater, lifted } => {
            route_edit::hop_look(&(repeater.clone(), focused, *lifted, m))
        },
        Row::Setting { look, on_rail } => route_edit::row_look(&(
            route_edit::Look { focused, ..*look },
            *on_rail,
        )),
        Row::Peer {
            avatar,
            name,
            flooding,
        } => path::end_look(&(avatar.clone(), name.clone(), false, *flooding, m)),
        Row::Neighbor(neighbor) => neighbors::neighbor_look(&NeighborLook {
            focused,
            ..neighbor.clone()
        }),
        Row::Caption(said) => neighbors::caption_look(&(said.clone(), m)),
        Row::Text(text) => neighbors::text_look(&TextLook { focused, ..*text }),
    })
}
