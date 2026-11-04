//! The status strip: device name, time, and the few indicators worth a
//! permanent place.

use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::indicators::{Indicator, Indicators, Mask};
use super::{advance, label};
use crate::board::Metrics;
use crate::icon::Ink;
use crate::keyboard::Latch;
use crate::model::{Bluetooth, Gnss, State, StatusStrip, Wifi};
use crate::{font, icon, theme};

/// An icon and the columns it inks.
type Glyph = (&'static Mask, Ink);

/// The icon `NAME`, with its ink.
macro_rules! glyph {
    ($name:ident) => {
        (&icon::$name, icon::ink::$name)
    };
}

/// The strip; on first run, the battery alone, there being no name or
/// time yet to show. The battery shows only where its charge is known.
/// Shift's and Alt's states come first among the indicators, in the
/// keyboard's order. The time is the local time, while
/// the clock is known; the lock screen leaves it out to show it larger.
/// The time gives way to the indicators where they would reach it.
pub fn view(
    m: &'static Metrics,
    s: &StatusStrip,
    setup: bool,
    latches: (Latch, Latch),
    time: Option<String<8>>,
) -> impl View<Rgb565, State> + use<> {
    let shown = !setup;
    let row = indicators(s, shown, latches);
    let time = time.filter(|time| shown && clears(m, time, &row));
    ZStack::new((
        HStack::new((
            shown.then(|| {
                label::<24>(
                    &s.device_name,
                    &font::SEMIBOLD,
                    m.small,
                    theme::TEXT_SECONDARY,
                )
            }),
            Spacer::default(),
            row,
        ))
        .with_spacing(GAP)
        .padding(Edges::Horizontal, PADDING),
        time.map(|time| label::<8>(&time, &font::BOLD, m.small, theme::TEXT)),
    ))
    .frame()
    .with_height(m.strip)
    .background_color(theme::CHROME, Rectangle)
}

/// Between the strip's edges and what it shows.
const PADDING: u32 = 8;
/// Between the name, the time, and the indicators.
const GAP: u32 = 3;

/// What the strip shows at its right, left to right.
fn indicators(s: &StatusStrip, shown: bool, (shift, alt): (Latch, Latch)) -> Indicators {
    let mut row = Indicators::default();
    if let Some(glyph) = latched(alt, glyph!(ALT_ONCE), glyph!(ALT_LOCK)) {
        row.icon(glyph, theme::ALT);
    }
    if let Some(glyph) = latched(shift, glyph!(SHIFT_ONCE), glyph!(SHIFT_LOCK)) {
        row.icon(glyph, theme::TEXT);
    }
    if shown {
        if s.silent {
            row.icon(glyph!(BELL_SLASH), theme::TEXT_SECONDARY);
        }
        if let Some(wifi) = s.wifi {
            let glyph = match wifi {
                Wifi::Disconnected => glyph!(WIFI_LOST),
                Wifi::Joining => glyph!(WIFI_JOINING),
                Wifi::Connected => glyph!(WIFI),
            };
            row.icon(glyph, theme::TEXT_SECONDARY);
        }
        // The rune, flanked while a phone is connected, and in the accent
        // color while a pairing window is open.
        if let Some(bluetooth) = s.bluetooth {
            let (glyph, color) = match bluetooth {
                Bluetooth::Waiting => (glyph!(BLUETOOTH), theme::TEXT_SECONDARY),
                Bluetooth::Connected => (glyph!(BLUETOOTH_LINKED), theme::TEXT_SECONDARY),
                Bluetooth::Pairing => (glyph!(BLUETOOTH), theme::ACCENT),
            };
            row.icon(glyph, color);
        }
        if s.companion {
            row.icon(glyph!(COMPANION), theme::GREEN);
        }
        if let Some(gnss) = s.gnss {
            let glyph = match gnss {
                Gnss::Searching => glyph!(GNSS_SEARCHING),
                Gnss::Fixed => glyph!(GNSS),
            };
            row.icon(glyph, theme::TEXT_SECONDARY);
        }
    }
    if s.charging {
        row.icon(glyph!(BOLT), theme::TEXT_SECONDARY);
    }
    // Only a charge that can be told: charging without one shows the bolt
    // alone.
    if let Some(percent) = s.battery_percent {
        row.push(Indicator::Battery {
            percent,
            low: s.battery_low,
        });
    }
    row
}

/// Whether `time`, centered on the strip, ends short of where `row`
/// begins.
fn clears(m: &Metrics, time: &str, row: &Indicators) -> bool {
    let reach = (m.width + advance(time, &font::BOLD, m.small)) / 2 + GAP;
    reach + row.width() + PADDING <= m.width
}

/// A modifier's icon: armed for one key, or locked.
fn latched(latch: Latch, once: Glyph, locked: Glyph) -> Option<Glyph> {
    match latch {
        Latch::Off => None,
        Latch::Once => Some(once),
        Latch::Locked => Some(locked),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::Board;

    fn crowded() -> StatusStrip {
        StatusStrip {
            silent: true,
            wifi: Some(Wifi::Joining),
            bluetooth: Some(Bluetooth::Pairing),
            companion: true,
            gnss: Some(Gnss::Searching),
            charging: true,
            battery_percent: Some(20),
            ..StatusStrip::default()
        }
    }

    #[test]
    fn the_time_gives_way_to_a_row_that_would_reach_it() {
        let row = indicators(&crowded(), true, (Latch::Once, Latch::Locked));
        assert!(!clears(&Board::TDECK.metrics, "14:32", &row));
        assert!(clears(&Board::PAGER.metrics, "14:32", &row));
    }

    #[test]
    fn the_time_stays_beside_a_short_row() {
        let strip = StatusStrip {
            battery_percent: Some(80),
            ..StatusStrip::default()
        };
        let row = indicators(&strip, true, (Latch::Off, Latch::Off));
        assert!(clears(&Board::TDECK.metrics, "14:32", &row));
    }
}
