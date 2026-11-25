//! The bundled typefaces: M PLUS 1 for text and M PLUS Code Latin for
//! addresses, each at the weights and pixel sizes the screens use.
//!
//! A view names the size it wants with `with_font_size`; the nearest
//! rasterized size is drawn.

use buoyant::font::PrerenderedFont;
use buoyant::font::prerendered::{CharRun, Face, GlyphEntry};

use crate::typeface::Typeface;

include!(concat!(env!("OUT_DIR"), "/fonts.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::{Board, Metrics};

    /// The face `face` resolves `size` to is one `sizes` keeps, so that a
    /// board built with only its own faces draws as this build does.
    fn kept(face: &Typeface, size: u32, sizes: &[u16]) -> bool {
        sizes.contains(&face.face(size).size)
    }

    #[test]
    fn faces_cover_requests() {
        let text = |m: &Metrics| [m.small, m.secondary, m.body, m.title];
        for (i, board) in [&Board::PAGER, &Board::TDECK].into_iter().enumerate() {
            for &(face, pager, tdeck) in BOARD_SIZES {
                let sizes = [pager, tdeck][i];
                if core::ptr::eq(face, &CLOCK) || core::ptr::eq(face, &CODE) {
                    continue;
                }
                for size in text(&board.metrics) {
                    assert!(kept(face, size, sizes), "board {i}: {size} px in {sizes:?}");
                }
            }
            let bold = BOARD_SIZES
                .iter()
                .find(|s| core::ptr::eq(s.0, &BOLD))
                .unwrap();
            for store in umsh_emoji::STORES {
                let badge = u32::from(store.size) * 11 / 20;
                assert!(kept(&BOLD, badge, [bold.1, bold.2][i]), "badge {badge} px");
            }
        }
    }
}
