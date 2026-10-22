//! Statistics: how long the device has run, the airtime it has spent, and
//! the traffic it has counted, each where the device keeps it. They are
//! read again every few seconds while shown.

use buoyant::view::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use heapless::{String, Vec};

use super::setting::{page, readout};
use crate::model::{State, Statistics};

const ROW: u32 = 36;

/// A readout's value.
type Value = String<20>;

/// Every readout the screen can show, in order; its place here names its
/// row.
const NAMES: [&str; 15] = [
    "Uptime",
    "Airtime",
    "Packets sent",
    "Channel busy",
    "Packets heard",
    "Bad CRC",
    "Not UMSH",
    "For this node",
    "Forwarded",
    "Forwards dropped",
    "Forwards canceled",
    "MeshCore seen",
    "MeshCore routed",
    "MeshCore flooded",
    "MeshCore declined",
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

pub fn view(state: &State) -> impl View<Rgb565, State> + use<> {
    let m = state.metrics();
    let shown = readouts(&state.node.statistics(), state.node.radio().airtime);
    page(
        m,
        "Statistics",
        ForEach::<{ NAMES.len() }>::new_vertical(&INDICES[..shown.len()], move |&i| {
            let (place, value) = &shown[i];
            readout(m, NAMES[*place], value, ROW)
        }),
    )
}

/// The readouts to show, each with its place in [`NAMES`]: Uptime always,
/// empty until it is known, and the airtime, as `airtime` percent of the
/// hour; then each counter the device keeps.
fn readouts(stats: &Statistics, airtime: u8) -> Vec<(usize, Value), { NAMES.len() }> {
    let mut shown = Vec::new();
    _ = shown.push((0, stats.uptime.map(uptime).unwrap_or_default()));
    let mut spent = Value::new();
    _ = core::fmt::write(&mut spent, format_args!("{airtime}% this hour"));
    _ = shown.push((1, spent));
    let counters = [
        stats.sent,
        stats.channel_busy,
        stats.heard,
        stats.bad_crc,
        stats.other,
        stats.accepted,
        stats.forwarded,
        stats.forward_dropped,
        stats.forward_cancelled,
        stats.meshcore_seen,
        stats.meshcore_routed,
        stats.meshcore_flooded,
        stats.meshcore_declined,
    ];
    for (place, count) in (2..).zip(counters) {
        if let Some(count) = count {
            _ = shown.push((place, grouped(count)));
        }
    }
    shown
}

/// `count`, its thousands set apart by commas.
fn grouped(count: u32) -> Value {
    let mut digits: String<10> = String::new();
    _ = core::fmt::write(&mut digits, format_args!("{count}"));
    let mut text = Value::new();
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            _ = text.push(',');
        }
        _ = text.push(digit);
    }
    text
}

/// `seconds` of running, in its two largest units.
fn uptime(seconds: u32) -> Value {
    let (days, hours) = (seconds / 86_400, seconds / 3_600 % 24);
    let (minutes, seconds) = (seconds / 60 % 60, seconds % 60);
    let mut text = Value::new();
    _ = if days > 0 {
        core::fmt::write(&mut text, format_args!("{days}d {hours}h"))
    } else if hours > 0 {
        core::fmt::write(&mut text, format_args!("{hours}h {minutes}m"))
    } else if minutes > 0 {
        core::fmt::write(&mut text, format_args!("{minutes}m {seconds}s"))
    } else {
        core::fmt::write(&mut text, format_args!("{seconds}s"))
    };
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_are_grouped_by_thousands() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(3_906), "3,906");
        assert_eq!(grouped(u32::MAX), "4,294,967,295");
    }

    #[test]
    fn uptime_reads_in_its_two_largest_units() {
        assert_eq!(uptime(45), "45s");
        assert_eq!(uptime(125), "2m 5s");
        assert_eq!(uptime(3 * 3_600 + 12 * 60), "3h 12m");
        assert_eq!(uptime(93_784), "1d 2h");
    }

    #[test]
    fn only_kept_counters_are_shown_after_uptime_and_airtime() {
        let stats = Statistics {
            sent: Some(412),
            forwarded: Some(1_630),
            ..Statistics::default()
        };
        let places: Vec<usize, 15> = readouts(&stats, 3).iter().map(|(p, _)| *p).collect();
        assert_eq!(places, [0, 1, 2, 8]);
    }
}
