//! The radio profiles the radio can be set to, one to a row. Pressing one
//! sets it; Backspace goes back. First run and Device › Radio › Profile
//! both show this list.

use buoyant::event::{Key, KeyResponse};
use buoyant::focus::BoundaryBehavior;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::Vec;

use super::conversation::header;
use super::setting::{End, row};
use crate::model::State;
use crate::nav::keys;

const ROW: u32 = 36;
/// The most rows the list holds at once. A longer list holds those around
/// the focused one, so the rows either side of it are always there to move
/// to.
const WINDOW: usize = 12;

/// Indices `ForEach` can hold without borrowing the state.
static INDICES: [usize; WINDOW] = {
    let mut a = [0; WINDOW];
    let mut i = 0;
    while i < WINDOW {
        a[i] = i;
        i += 1;
    }
    a
};

/// Where the rows the list holds start, among `count`, for the row at
/// `focused` to sit in their middle.
fn window(focused: usize, count: usize) -> usize {
    focused
        .saturating_sub(WINDOW / 2)
        .min(count.saturating_sub(WINDOW))
}

/// The list under `title`.
pub fn view(state: &State, title: &'static str) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let focus = state.screen().focus();
    let focused = focus
        .current()
        .or(focus.pending())
        .and_then(keys::profile_of)
        .unwrap_or(0);
    let count = state.node.profile_count();
    let start = window(focused, count);
    let names: Vec<&'static str, WINDOW> = (start..count)
        .map_while(|index| state.node.profile(index))
        .take(WINDOW)
        .collect();
    VStack::new((
        header(m, title, None, None),
        super::list(
            ForEach::<WINDOW>::new_vertical(&INDICES[..names.len()], move |&i| {
                let index = start + i;
                row(
                    m,
                    names[i],
                    keys::profile(index),
                    move |s: &mut State| s.choose_profile(index),
                    End::Nothing,
                    false,
                    ROW,
                )
            })
            .keyed(move |&i| keys::profile(start + i)),
        )
        .with_scroll_step(ROW),
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

#[cfg(test)]
mod tests {
    use super::{WINDOW, window};

    #[test]
    fn the_window_keeps_rows_either_side_of_focus() {
        // A short list is held whole.
        assert_eq!(window(5, 8), 0);
        assert_eq!(window(0, 22), 0);
        // Further down, the focused row sits mid-window...
        let start = window(10, 22);
        assert!(start < 10 && 10 < start + WINDOW - 1);
        // ...until the end of the list holds it.
        assert_eq!(window(21, 22), 22 - WINDOW);
    }
}
