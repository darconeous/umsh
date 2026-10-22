//! Battery: its charge, what external power is doing, and the cell's
//! voltage, each where the board reads it.

use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::setting::{End, page, row};
use crate::model::{Charge, State};
use crate::nav::keys;

const ROW: u32 = 36;

pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let reading = state.battery;
    let percent = reading.percent.map(percent_text);
    let voltage = reading.millivolts.map(volts);
    page(
        m,
        "Battery",
        VStack::new((
            percent.map(|percent| {
                row(
                    m,
                    "Level",
                    keys::BATTERY_LEVEL,
                    |_| {},
                    End::value(&percent),
                    false,
                    ROW,
                )
            }),
            reading.charge.map(|charge| {
                row(
                    m,
                    "Status",
                    keys::BATTERY_CHARGE,
                    |_| {},
                    End::value(match charge {
                        Charge::Discharging => "On battery",
                        Charge::Charging => "Charging",
                        Charge::Charged => "Charged",
                        Charge::NotCharging => "Not charging",
                    }),
                    false,
                    ROW,
                )
            }),
            voltage.map(|voltage| {
                row(
                    m,
                    "Voltage",
                    keys::BATTERY_VOLTAGE,
                    |_| {},
                    End::value(&voltage),
                    false,
                    ROW,
                )
            }),
        ))
        .with_spacing(0),
    )
}

/// A charge, as the Device list and the Battery screen give it.
pub(super) fn percent_text(percent: u8) -> String<8> {
    let mut text = String::new();
    _ = core::fmt::write(&mut text, format_args!("{percent}%"));
    text
}

/// `millivolts`, in volts to two places.
fn volts(millivolts: u16) -> String<12> {
    let centivolts = (u32::from(millivolts) + 5) / 10;
    let mut text = String::new();
    _ = core::fmt::write(
        &mut text,
        format_args!("{}.{:02} V", centivolts / 100, centivolts % 100),
    );
    text
}

#[cfg(test)]
mod tests {
    use super::volts;

    #[test]
    fn volts_round_to_two_places() {
        assert_eq!(volts(3_921), "3.92 V");
        assert_eq!(volts(3_925), "3.93 V");
        assert_eq!(volts(4_200), "4.20 V");
    }
}
