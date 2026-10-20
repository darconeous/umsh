//! First run: what to call this node, its radio profile, and its time
//! zone. The name may be left empty, and peers then see the bare hint; the
//! profile is needed before the radio sends.

use buoyant::focus::BoundaryBehavior;
use buoyant::match_view;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::add_peer::field_look;
use super::label;
use super::member::detail_head;
use super::setting::{End, row};
use crate::board::Metrics;
use crate::model::State;
use crate::nav::{NameText, SetupPage, keys};
use crate::{font, theme};

const TOP: u32 = 6;
const LABEL: u32 = 22;
const INSET: u32 = 8;
/// The field's text: the screen less the field's inset and padding.
const fn text_width(m: &Metrics) -> u32 {
    m.width - 2 * INSET - 24
}
const CARET: u32 = 3;
const NOTE: u32 = 26;
const ROW: u32 = 36;

pub fn view(state: &State, page: &SetupPage) -> impl View<Rgb565, State> + use<> {
    match_view!(page, {
        SetupPage::Name { text } => name(state, text),
        SetupPage::Profile => super::profile::view(state, "Radio profile"),
        SetupPage::Zone { find } => super::clock::zone_list(state, find, "Time zone"),
    })
}

/// The welcome, and what to call this node.
fn name(state: &State, text: &NameText) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let address = state.node.address();
    let mut about: String<48> = String::new();
    _ = core::fmt::write(
        &mut about,
        format_args!("This device is {}", address.get(..4).unwrap_or("")),
    );
    VStack::new((
        detail_head(m, &state.node.avatar(), "Welcome to UMSH", &about, false),
        label::<24>(
            "What to call you",
            &font::BOLD,
            m.small,
            theme::TEXT_SECONDARY,
        )
        .padding(Edges::Leading, 10)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(LABEL),
        TextField::new(text, &font::REGULAR, State::name_text_mut)
            .with_font_size(m.body)
            .with_max_lines(1)
            .with_caret_width(CARET)
            .on_submit(State::continue_setup)
            .on_active(State::field_active)
            .with_label(|status, area| field_look(status, area, text_width(m)))
            .focus_key(keys::NAME_FIELD)
            .padding(Edges::Horizontal, INSET),
        label::<32>(
            "Nearby nodes see this name.",
            &font::MEDIUM,
            m.small,
            theme::TEXT_TERTIARY,
        )
        .padding(Edges::Leading, 10)
        .flex_infinite_width(HorizontalAlignment::Leading)
        .frame()
        .with_height(NOTE),
        row(
            m,
            "Continue",
            keys::CONTINUE,
            State::continue_setup,
            End::Chevron,
            false,
            ROW,
        ),
    ))
    .with_spacing(0)
    .padding(Edges::Top, TOP)
    // Nothing comes before it, so Backspace only ever edits the name.
    .bound_focus(BoundaryBehavior::Stop)
}
