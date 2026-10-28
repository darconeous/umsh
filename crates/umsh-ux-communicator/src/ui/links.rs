//! Bluetooth and GNSS: each one's switch, and what it is doing while on.

use buoyant::view::popover::Dismissal;
use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::setting::{End, card, choice, page, readout, row};
use crate::board::Metrics;
use crate::model::{Fix, GnssReading, State};
use crate::nav::keys;
use crate::theme;

const ROW: u32 = 36;
/// Clear pairings' confirmation.
const CONFIRM_WIDTH: u32 = 220;

/// Bluetooth's switch; while it is on, whether a phone is connected, how
/// many are paired, and pairing.
pub fn bluetooth(state: &State, confirm: bool) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let on = state.node.bluetooth_enabled().unwrap_or(false);
    let reading = state.links.bluetooth;
    let mut paired: String<8> = String::new();
    if let Some(count) = reading.paired {
        _ = core::fmt::write(&mut paired, format_args!("{count}"));
    }
    let mut pin: String<8> = String::new();
    if let Some(code) = reading.pin.filter(|_| reading.pairing) {
        _ = core::fmt::write(&mut pin, format_args!("{code:06}"));
    }
    let shows_pairing = reading.paired.is_some();
    page(
        m,
        "Bluetooth",
        VStack::new((
            row(
                m,
                "Bluetooth",
                keys::BLUETOOTH_ENABLED,
                State::toggle_bluetooth,
                End::Switch(on),
                false,
                ROW,
            ),
            on.then(|| {
                VStack::new((
                    readout(
                        m,
                        "Phone",
                        if reading.connected {
                            "Connected"
                        } else {
                            "Not connected"
                        },
                        ROW,
                    ),
                    shows_pairing.then(|| readout(m, "Paired phones", &paired, ROW)),
                    shows_pairing.then(|| {
                        row(
                            m,
                            "Pairing mode",
                            keys::PAIRING,
                            State::toggle_pairing,
                            End::Switch(reading.pairing),
                            false,
                            ROW,
                        )
                    }),
                    (!pin.is_empty()).then(|| readout(m, "PIN", &pin, ROW)),
                    shows_pairing.then(|| {
                        row(
                            m,
                            "Clear pairings",
                            keys::CLEAR_PAIRINGS,
                            State::ask_clear_pairings,
                            End::Nothing,
                            true,
                            ROW,
                        )
                    }),
                ))
                .with_spacing(0)
            }),
        ))
        .with_spacing(0),
    )
    .popover(confirm.then_some(()).as_ref(), |()| clear_confirmation(m))
    // A tap outside is Cancel.
    .on_blur(|s: &mut State| {
        s.cancel_clear_pairings();
        Dismissal::Dismiss
    })
}

/// Clear pairings, confirmed, or Cancel, which is focused.
// Out of line, as `setting::row` is, against the Xtensa back end's failure.
#[inline(never)]
fn clear_confirmation(m: &'static Metrics) -> impl View<Rgb565, State> + use<> {
    let text = |text: &str| String::try_from(text).unwrap_or_default();
    card(
        m,
        VStack::new((
            choice(
                m,
                text("Clear pairings"),
                keys::CLEAR_PAIRINGS_CONFIRM,
                State::clear_pairings,
                theme::RED,
                None,
            ),
            choice(
                m,
                text("Cancel"),
                keys::CLEAR_PAIRINGS_CANCEL,
                State::cancel_clear_pairings,
                theme::TEXT,
                None,
            ),
        ))
        .with_spacing(0),
        CONFIRM_WIDTH,
        HorizontalAlignment::Center,
        State::cancel_clear_pairings,
    )
}

/// The GNSS receiver's switch and, once known, its name; while it is on,
/// its fix, where it is, and the satellites it uses.
pub fn gnss(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let on = state.node.gnss_enabled().unwrap_or(false);
    let reading = state.links.gnss;
    let texts = GnssTexts::of(&reading);
    page(
        m,
        "GNSS",
        VStack::new((
            row(
                m,
                "GNSS",
                keys::GNSS_ENABLED,
                State::toggle_gnss,
                End::Switch(on),
                false,
                ROW,
            ),
            reading
                .receiver
                .map(|receiver| readout(m, "Receiver", receiver, ROW)),
            on.then(|| {
                VStack::new((
                    readout(
                        m,
                        "Fix",
                        match reading.fix {
                            Fix::None => "Searching",
                            Fix::TwoD => "2D",
                            Fix::ThreeD => "3D",
                        },
                        ROW,
                    ),
                    texts
                        .position
                        .map(|position| readout(m, "Position", &position, ROW)),
                    texts
                        .altitude
                        .map(|altitude| readout(m, "Altitude", &altitude, ROW)),
                    readout(m, "Satellites", &texts.satellites, ROW),
                ))
                .with_spacing(0)
            }),
        ))
        .with_spacing(0),
    )
}

/// A reading's values, as its rows show them.
struct GnssTexts {
    position: Option<String<32>>,
    altitude: Option<String<16>>,
    satellites: String<16>,
}

impl GnssTexts {
    fn of(reading: &GnssReading) -> Self {
        let position = reading.position.map(|(latitude, longitude)| {
            let mut text = String::new();
            push_degrees(&mut text, latitude);
            _ = text.push_str(", ");
            push_degrees(&mut text, longitude);
            text
        });
        let altitude = reading.altitude.map(|meters| {
            let mut text = String::new();
            let minus = if meters < 0 { "\u{2212}" } else { "" };
            _ = core::fmt::write(
                &mut text,
                format_args!("{minus}{} m", meters.unsigned_abs()),
            );
            text
        });
        let mut satellites = String::new();
        _ = match reading.in_view {
            Some(seen) => {
                core::fmt::write(&mut satellites, format_args!("{} of {seen}", reading.used))
            }
            None => core::fmt::write(&mut satellites, format_args!("{}", reading.used)),
        };
        Self {
            position,
            altitude,
            satellites,
        }
    }
}

/// `micro` millionths of a degree, to five places: about a meter.
fn push_degrees(text: &mut String<32>, micro: i32) {
    let minus = if micro < 0 { "\u{2212}" } else { "" };
    let tenths_of_micro = (micro.unsigned_abs() + 5) / 10;
    _ = core::fmt::write(
        text,
        format_args!(
            "{minus}{}.{:05}",
            tenths_of_micro / 100_000,
            tenths_of_micro % 100_000
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn degrees(micro: i32) -> String<32> {
        let mut text = String::new();
        push_degrees(&mut text, micro);
        text
    }

    #[test]
    fn degrees_round_to_five_places() {
        assert_eq!(degrees(46_852_454), "46.85245");
        assert_eq!(degrees(46_852_456), "46.85246");
        assert_eq!(degrees(-121_760_550), "\u{2212}121.76055");
        assert_eq!(degrees(5), "0.00001");
        assert_eq!(degrees(0), "0.00000");
    }
}
