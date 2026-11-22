//! The route editor, a router's Neighbors, and Add hop, drawn by one view:
//! a header over a list of rows, each a button drawn from a description of
//! it, and what opens over the editor. Add hop's field, while text is
//! typed, is its first row.
//!
//! Each kind of screen costs flash for every view type in it, compiled into
//! every pass the interface makes over its tree. Both screens are a list of
//! rows that each draw themselves, so they share one tree: what differs is
//! what each row says, which is drawn by [`Lazy`] outside the tree. Which
//! row is where is the navigation's ([`RouteDraft::row`],
//! [`listing_row`], [`PickRows`]), so that a press and the row drawn always
//! agree.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::{BoundaryBehavior, FocusKey, Role};
use buoyant::match_view;
use buoyant::view::Lazy;
use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::conversation::titled;
use super::neighbors::{self, Caption, End, FieldLook, NEIGHBOR, NeighborLook, NodeLook, TextLook};
use super::path::{self, NODE};
use super::route_edit::{self, Pinged, Value};
use crate::avatar::AvatarStyle;
use crate::board::Metrics;
use crate::model::{Listing, ListingAsk, MAX_PATH, Node, PingView, Repeater, State};
use crate::nav::{
    Adjust, EditRow, ListRow, PickRow, PickRows, RouteDraft, SHEET_ROWS, Screen, keys, listing_row,
    listing_rows,
};
use crate::theme;

const ROWS: usize = SHEET_ROWS;

static INDICES: [usize; ROWS] = {
    let mut a = [0; ROWS];
    let mut i = 0;
    while i < ROWS {
        a[i] = i;
        i += 1;
    }
    a
};

/// The route editor, Neighbors, or Add hop shown, while one is.
// Out of line, as every page of `peer_or_channel` is.
#[inline(never)]
pub fn view(state: &State) -> Option<impl View<Rgb565, State> + use<>> {
    let m = state.metrics();
    let node = state.node;
    let mut title: String<16> = String::new();
    let (about, source, over, step) = match state.screen() {
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
            _ = title.push_str("Edit route");
            (
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
        Screen::Neighbors {
            router,
            pick: Some(pick),
            ..
        } => {
            let rows = state.pick_rows()?;
            let hops = state.pick_draft()?.hints();
            let last = hops.last().and_then(|&hint| node.repeater(hint));
            let last = last
                .as_ref()
                .map(|last| umsh_grapheme::cut(last.name.as_str(), 22));
            _ = core::fmt::write(&mut title, format_args!("Add hop {}", hops.len() + 1));
            let mut about: String<32> = String::new();
            let mut heard: String<32> = String::new();
            match last {
                Some(last) => {
                    _ = core::fmt::write(&mut about, format_args!("after {last}"));
                    _ = core::fmt::write(&mut heard, format_args!("Heard by {last}"));
                }
                None => _ = heard.push_str("Heard here"),
            }
            (
                about,
                Source::Pick {
                    router: router.clone(),
                    find: pick.find.clone(),
                    rows,
                    heard,
                    typing: state.screen().focus().current() == Some(keys::PICK_FIELD),
                    phase: state.spinner_phase(),
                },
                None,
                NEIGHBOR,
            )
        }
        Screen::Neighbors { router, .. } => {
            let mut name: String<32> = String::new();
            if let Some(member) = node.known_member(router) {
                _ = name.push_str(&member.sender.name);
            }
            _ = title.push_str("Neighbors");
            (
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
            titled(m, &title, theme::TEXT, None, &about),
            super::list(
                ForEach::<ROWS>::new_vertical(&INDICES[..count], move |&i| {
                    let (row, focusable) = source.row(node, m, i);
                    let key = source.key(i);
                    Button::new(
                        move |s: &mut State| s.press_sheet(i, key),
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
            // Add hop narrows by what is typed.
            Key::Character(c)
                if (c.is_alphanumeric() || matches!(c, ' ' | '.' | '\'' | '-'))
                    && s.find_hop(c) =>
            {
                KeyResponse::Handled
            }
            Key::Backspace => {
                if !s.unfind_hop() {
                    s.back();
                }
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
#[allow(
    clippy::large_enum_variant,
    reason = "built once per drawing of the sheet; there is no allocator to box it"
)]
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
    /// Add hop: what the last hop of the route being edited reports
    /// hearing, as `heard` labels it, and the rest it offers.
    Pick {
        router: String<44>,
        /// What is typed, which the field at the top shows.
        find: String<16>,
        rows: PickRows,
        heard: String<32>,
        /// The field has focus.
        typing: bool,
        phase: u8,
    },
}

impl Source {
    fn count(&self) -> usize {
        match self {
            Self::Edit { draft, .. } => draft.rows(),
            Self::Listing { listing, .. } => listing_rows(listing.as_ref()),
            Self::Pick { rows, .. } => rows.len(),
        }
    }

    /// The row at `index`'s key: a row that does something keeps its own,
    /// which the navigation asks focus for by.
    fn key(&self, index: usize) -> FocusKey {
        match self {
            Self::Edit { draft, .. } => match draft.row(index) {
                Some(EditRow::Hop(hop)) => keys::path(hop),
                Some(EditRow::Add) => keys::ROUTE_ADD,
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
            Self::Pick { rows, .. } => rows.key(index).0,
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
                    Some(EditRow::Add) => (
                        Row::Setting {
                            look: route_edit::Look {
                                label: "Add hop",
                                value: Value::Add,
                                active: false,
                                focused: false,
                                accent: true,
                                m,
                            },
                            on_rail: true,
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
                            Some(ms) => Caption::Label(label(&neighbors::read_text(ms)), None),
                            None => Caption::Note("Not read", None, theme::TEXT_TERTIARY),
                        }),
                        false,
                    ),
                    Some(ListRow::Neighbor(at)) => match node.listed(router, at) {
                        Some(listed) => (
                            Row::Neighbor(NeighborLook {
                                end: match (
                                    listed.address.is_some(),
                                    identifying.contains(&listed.hint),
                                ) {
                                    (true, _) => End::Open,
                                    (false, false) => End::Lookup,
                                    (false, true) => End::Asking,
                                },
                                name: listed.name,
                                avatar: listed.avatar,
                                signal: listed.signal,
                                heard_min: listed.heard_min,
                                distance_m: listed.distance_m,
                                phase: *phase,
                                tint: false,
                                focused: false,
                                m,
                            }),
                            true,
                        ),
                        None => (Row::You, false),
                    },
                    Some(ListRow::Said) => (Row::Caption(said(listing.as_ref())), false),
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
            Self::Pick {
                router,
                find,
                rows,
                heard,
                typing,
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
                let listing = rows.listing;
                let asking = listing.and_then(|listing| listing.asking);
                // What Enter in the field adds: the top row past it.
                let tint = *typing && rows.top() == Some(index);
                let node_row = |name: &str, avatar: AvatarStyle, about, age, hint, in_path| {
                    Row::Node(NodeLook {
                        name: String::try_from(umsh_grapheme::cut(name, 24)).unwrap_or_default(),
                        avatar,
                        about,
                        age,
                        hint,
                        in_path,
                        tint,
                        focused: false,
                        m,
                    })
                };
                let row = match rows.row(index) {
                    Some(PickRow::Field) => (
                        Row::Field(FieldLook {
                            text: find.clone(),
                            found: rows.found.unwrap_or(0),
                            m,
                        }),
                        true,
                    ),
                    Some(PickRow::Heard) => (
                        Row::Caption(Caption::Label(
                            heard.clone(),
                            Some(match listing.and_then(|listing| listing.read_ms_ago) {
                                Some(ms) => neighbors::read_text(ms),
                                None => String::try_from("Not read").unwrap_or_default(),
                            }),
                        )),
                        false,
                    ),
                    Some(PickRow::Neighbor(at)) => match node.listed(router, usize::from(at)) {
                        Some(listed) => (
                            Row::Neighbor(NeighborLook {
                                end: if rows.peer_at == Some(at) {
                                    End::Finish
                                } else if rows.in_path(index) {
                                    End::InPath
                                } else {
                                    End::Nothing
                                },
                                name: listed.name,
                                avatar: listed.avatar,
                                signal: listed.signal,
                                heard_min: listed.heard_min,
                                distance_m: listed.distance_m,
                                phase: *phase,
                                tint,
                                focused: false,
                                m,
                            }),
                            true,
                        ),
                        None => (Row::You, false),
                    },
                    Some(PickRow::Said) => (Row::Caption(said(listing.as_ref())), false),
                    Some(PickRow::More) => (
                        text(
                            "Load more",
                            listing.map(|listing| (listing.count, listing.total)),
                            asking == Some(ListingAsk::More),
                        ),
                        true,
                    ),
                    Some(PickRow::Refresh) => {
                        (text("Refresh", None, asking == Some(ListingAsk::Top)), true)
                    }
                    Some(PickRow::Known) => (
                        Row::Caption(Caption::Label(label("Known repeaters"), None)),
                        false,
                    ),
                    Some(PickRow::KnownAt(at, _)) => match node.known_repeater(usize::from(at)) {
                        Some(known) => (
                            node_row(
                                &known.name,
                                known.avatar,
                                String::new(),
                                known.age,
                                false,
                                rows.in_path(index),
                            ),
                            true,
                        ),
                        None => (Row::You, false),
                    },
                    Some(PickRow::Hints) => (
                        Row::Caption(Caption::Label(
                            label(if rows.hints.len() > 1 {
                                "Router hints"
                            } else {
                                "Router hint"
                            }),
                            None,
                        )),
                        false,
                    ),
                    Some(PickRow::Hint(at)) => {
                        let Some(read) = rows.hints.get(usize::from(at)) else {
                            return (Row::You, false);
                        };
                        let Some(repeater) = node.repeater(read.hint) else {
                            return (Row::You, false);
                        };
                        let known = repeater.address.is_some();
                        let [high, low] = read.hint;
                        let mut about: String<24> = String::new();
                        _ = if rows.hints.len() > 1 {
                            let how = if read.hex { "Hex" } else { "Prefix" };
                            core::fmt::write(
                                &mut about,
                                format_args!("{how} \u{B7} {high:02X}{low:02X}"),
                            )
                        } else if known {
                            core::fmt::write(&mut about, format_args!("{high:02X}{low:02X}"))
                        } else {
                            core::fmt::write(
                                &mut about,
                                format_args!("{high:02X}{low:02X} \u{B7} Unknown node"),
                            )
                        };
                        (
                            node_row(
                                &repeater.name,
                                repeater.avatar.clone(),
                                about,
                                String::new(),
                                !known,
                                rows.in_path(index),
                            ),
                            true,
                        )
                    }
                    None => (Row::You, false),
                };
                (row.0, rows.key(index).1)
            }
        }
    }
}

/// A label's text.
fn label(text: &str) -> String<32> {
    String::try_from(text).unwrap_or_default()
}

/// What a listing says in place of its rows: that the router did not
/// answer, or that it listed nobody.
fn said(listing: Option<&Listing>) -> Caption {
    if listing.is_some_and(|listing| listing.no_answer) {
        Caption::Note(
            "No answer",
            Some("Out of reach, or it keeps no neighbor list"),
            theme::AMBER,
        )
    } else {
        Caption::Note("None", None, theme::TEXT_TERTIARY)
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
    /// A known repeater, or a router hint typed text fixes.
    Node(NodeLook),
    /// Add hop's field, while text is typed.
    Field(FieldLook),
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
        Row::Node(row) => neighbors::node_look(&NodeLook {
            focused,
            ..row.clone()
        }),
        Row::Field(field) => neighbors::field_look(field),
        Row::Caption(said) => neighbors::caption_look(&(said.clone(), m)),
        Row::Text(text) => neighbors::text_look(&TextLook { focused, ..*text }),
    })
}
