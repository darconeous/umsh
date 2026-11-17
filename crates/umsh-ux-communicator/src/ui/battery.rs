//! Battery: its charge, what external power is doing, the cell's voltage,
//! and what a fuel gauge adds, each where the board reads it.

use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;

use super::setting::{page, readout};
use super::statistics::{Value, grouped};
use crate::model::{BatteryReading, Charge, State};

const ROW: u32 = 36;

/// Every readout the screen can show, in order; its place here names its
/// row.
const NAMES: [&str; 11] = [
    "Level",
    "Status",
    "Voltage",
    "Current",
    "Remaining",
    "Capacity",
    "Health",
    "Cycles",
    "Time left",
    "Time to full",
    "Temperature",
];

/// Indices `ForEach` can hold without borrowing the state.
static INDICES: [usize; NAMES.len()] = {
    let mut a = [0; NAMES.len()];
    let mut i = 0;
    while i < a.len() {
        a[i] = i;
        i += 1;
    }
    a
};

/// The places in [`NAMES`] shown, and how many there are.
type Shown = ([u8; NAMES.len()], usize);

pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    // Only the reading and which rows it fills are held; each row's text
    // is written as the row is built.
    let reading = state.battery;
    let (places, count) = shown(&reading);
    page(
        m,
        "Battery",
        ForEach::<{ NAMES.len() }>::new_vertical(&INDICES[..count], move |&i| {
            let place = usize::from(places[i]);
            readout(m, NAMES[place], &text(&reading, place), ROW)
        }),
    )
}

/// The rows `reading` has a value for, in order.
fn shown(reading: &BatteryReading) -> Shown {
    let mut places = [0; NAMES.len()];
    let mut count = 0;
    for place in 0..NAMES.len() {
        if !text(reading, place).is_empty() {
            places[count] = place as u8;
            count += 1;
        }
    }
    (places, count)
}

/// The value of row `place`, or empty where `reading` has none.
fn text(reading: &BatteryReading, place: usize) -> Value {
    let mut text = Value::new();
    let gauge = reading.gauge.unwrap_or_default();
    let charge = reading.charge;
    let mut put = |args: core::fmt::Arguments<'_>| _ = core::fmt::write(&mut text, args);
    match place {
        0 => {
            if let Some(percent) = reading.percent {
                put(format_args!("{percent}%"));
            }
        }
        1 => {
            if let Some(charge) = charge {
                put(format_args!(
                    "{}",
                    match charge {
                        Charge::Discharging => "On battery",
                        Charge::Charging => "Charging",
                        Charge::Charged => "Charged",
                        Charge::NotCharging => "Not charging",
                    }
                ));
            }
        }
        2 => {
            if let Some(millivolts) = reading.millivolts {
                let centivolts = (u32::from(millivolts) + 5) / 10;
                put(format_args!(
                    "{}.{:02} V",
                    centivolts / 100,
                    centivolts % 100
                ));
            }
        }
        3 => {
            if let Some(ma) = gauge.current_ma {
                put(format_args!("{ma} mA"));
            }
        }
        4 | 5 => {
            let mah = if place == 4 {
                gauge.remaining_mah
            } else {
                gauge.full_mah
            };
            if let Some(mah) = mah {
                put(format_args!("{} mAh", grouped(u32::from(mah))));
            }
        }
        6 => {
            if let Some(percent) = gauge.health_percent {
                put(format_args!("{percent}%"));
            }
        }
        7 => {
            if let Some(cycles) = gauge.cycles {
                put(format_args!("{}", grouped(u32::from(cycles))));
            }
        }
        // Each only while it is the way the charge is going.
        8 => {
            if let Some(minutes) = gauge
                .minutes_to_empty
                .filter(|_| charge == Some(Charge::Discharging))
            {
                duration(&mut put, minutes);
            }
        }
        9 => {
            if let Some(minutes) = gauge
                .minutes_to_full
                .filter(|_| charge == Some(Charge::Charging))
            {
                duration(&mut put, minutes);
            }
        }
        10 => {
            if let Some(dk) = gauge.temperature_dk {
                // Tenths of a kelvin to tenths of a degree, 273.15 K being 0 °C.
                let tenths = i32::from(dk) - 2_732;
                let sign = if tenths < 0 { "-" } else { "" };
                let tenths = tenths.unsigned_abs();
                put(format_args!("{sign}{}.{} °C", tenths / 10, tenths % 10));
            }
        }
        _ => {}
    }
    text
}

/// `minutes`, in its two largest units.
fn duration(put: &mut impl FnMut(core::fmt::Arguments<'_>), minutes: u16) {
    let (days, hours, minutes) = (minutes / 1_440, minutes / 60 % 24, minutes % 60);
    if days > 0 {
        put(format_args!("{days}d {hours}h"));
    } else if hours > 0 {
        put(format_args!("{hours}h {minutes}m"));
    } else {
        put(format_args!("{minutes}m"));
    }
}

/// A charge, as the Device list gives it.
pub(super) fn percent_text(percent: u8) -> String<8> {
    let mut text = String::new();
    _ = core::fmt::write(&mut text, format_args!("{percent}%"));
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GaugeReading;

    fn names(reading: &BatteryReading) -> heapless::Vec<&'static str, 11> {
        let (places, count) = shown(reading);
        places[..count]
            .iter()
            .map(|&place| NAMES[usize::from(place)])
            .collect()
    }

    fn row(reading: &BatteryReading, name: &str) -> Value {
        text(reading, NAMES.iter().position(|n| *n == name).unwrap())
    }

    #[test]
    fn volts_round_to_two_places() {
        for (mv, expected) in [(3_921, "3.92 V"), (3_925, "3.93 V"), (4_200, "4.20 V")] {
            let reading = BatteryReading {
                millivolts: Some(mv),
                ..BatteryReading::default()
            };
            assert_eq!(row(&reading, "Voltage"), expected);
        }
    }

    #[test]
    fn a_board_without_a_gauge_shows_what_it_reads() {
        let reading = BatteryReading {
            percent: Some(64),
            charge: Some(Charge::Discharging),
            millivolts: Some(3_812),
            gauge: None,
        };
        assert_eq!(names(&reading), ["Level", "Status", "Voltage"]);
    }

    #[test]
    fn gauge_rows_follow_the_charge() {
        let gauge = GaugeReading {
            current_ma: Some(-148),
            remaining_mah: Some(1_206),
            full_mah: Some(1_884),
            health_percent: Some(96),
            cycles: Some(37),
            minutes_to_empty: Some(489),
            minutes_to_full: Some(75),
            temperature_dk: None,
        };
        let mut reading = BatteryReading {
            percent: Some(64),
            charge: Some(Charge::Discharging),
            millivolts: Some(3_812),
            gauge: Some(gauge),
        };
        assert_eq!(
            names(&reading),
            [
                "Level",
                "Status",
                "Voltage",
                "Current",
                "Remaining",
                "Capacity",
                "Health",
                "Cycles",
                "Time left"
            ]
        );
        assert_eq!(row(&reading, "Current"), "-148 mA");
        assert_eq!(row(&reading, "Remaining"), "1,206 mAh");
        assert_eq!(row(&reading, "Health"), "96%");
        assert_eq!(row(&reading, "Time left"), "8h 9m");

        reading.charge = Some(Charge::Charging);
        let shown = names(&reading);
        assert!(!shown.contains(&"Time left"));
        assert_eq!(row(&reading, "Time to full"), "1h 15m");

        reading.charge = Some(Charge::Charged);
        let shown = names(&reading);
        assert!(!shown.contains(&"Time left") && !shown.contains(&"Time to full"));
    }

    #[test]
    fn durations_and_temperatures_read_naturally() {
        let mut reading = BatteryReading {
            charge: Some(Charge::Discharging),
            gauge: Some(GaugeReading {
                minutes_to_empty: Some(45),
                temperature_dk: Some(2_981),
                ..GaugeReading::default()
            }),
            ..BatteryReading::default()
        };
        assert_eq!(row(&reading, "Time left"), "45m");
        assert_eq!(row(&reading, "Temperature"), "24.9 °C");
        reading.gauge = Some(GaugeReading {
            minutes_to_empty: Some(3 * 1_440 + 125),
            temperature_dk: Some(2_682),
            ..GaugeReading::default()
        });
        assert_eq!(row(&reading, "Time left"), "3d 2h");
        assert_eq!(row(&reading, "Temperature"), "-5.0 °C");
    }
}
