//! Property and metadata value grammars.
//!
//! Round trips compare decoded values, never bytes: several of these accept
//! forms they do not write.

use umsh_ulcp::battery::BatteryStatus;
use umsh_ulcp::battery_gauge_config::Config;
use umsh_ulcp::battery_gauge_telemetry::Telemetry;
use umsh_ulcp::i2c::{BusInfo, DeviceInfo, ScanRequest, TransferRequest};
use umsh_ulcp::ip::{V4Address, V4Config, V6Config, V6Item};
use umsh_ulcp::items::{self, Filter, PeerKeyEntry};
use umsh_ulcp::wifi::{ApClient, ApConfig, ApStatus, Link, NetworkEntry, ScanResult};
use umsh_ulcp::{Announcement, BufferedRxMeta, DfuMode, RxMeta, TxMeta, bridge, pui, sint, uint};

const SCRATCH: usize = 1024;

macro_rules! round_trip {
    ($ty:ty, $input:expr) => {{
        if let Ok(first) = <$ty>::decode($input) {
            let mut out = [0u8; SCRATCH];
            if let Ok(len) = first.encode(&mut out) {
                let second = <$ty>::decode(&out[..len]).expect("an encoded value decodes");
                assert!(first == second, "changed by a round trip");
            }
        }
    }};
}

/// [`round_trip`] for an item, whose `encode` adds the length prefix its
/// `decode` does not take.
macro_rules! round_trip_item {
    ($ty:ty, $input:expr) => {{
        if let Ok(first) = <$ty>::decode($input) {
            let mut out = [0u8; SCRATCH];
            if let Ok(len) = first.encode(&mut out) {
                let item = items::prefixed_items(&out[..len])
                    .next()
                    .expect("one item")
                    .expect("a well-formed item");
                let second = <$ty>::decode(item).expect("an encoded value decodes");
                assert!(first == second, "changed by a round trip");
            }
        }
    }};
}

fn integers(input: &[u8]) {
    if let Ok((value, used)) = pui::decode(input) {
        assert!((1..=input.len()).contains(&used));
        let mut out = [0u8; 8];
        let len = pui::encode(value, &mut out).expect("a decoded value encodes");
        assert_eq!(pui::decode(&out[..len]), Ok((value, len)));
    }
    let _ = sint::decode(input);
    let _ = uint::decode(input);
}

fn requests(input: &[u8]) {
    if let Ok(request) = TransferRequest::parse(input) {
        let _ = request.shape();
        let _ = request.ops().count();
    }
    let _ = ScanRequest::parse(input);
    let _ = Announcement::parse(input);
    let _ = DfuMode::parse(input);
    if let Ok(text) = core::str::from_utf8(input) {
        let _ = bridge::valid_host(text);
    }
    let _ = items::prefixed_items(input).count();
    let _ = items::fixed_items::<4>(input).map(Iterator::count);
}

pub fn run(data: &[u8]) {
    let Some((&kind, input)) = data.split_first() else {
        return;
    };
    match kind % 22 {
        0 => round_trip!(TxMeta, input),
        1 => round_trip!(RxMeta, input),
        2 => round_trip!(BufferedRxMeta, input),
        3 => round_trip!(PeerKeyEntry, input),
        4 => round_trip!(Filter, input),
        5 => round_trip!(NetworkEntry<'_>, input),
        6 => round_trip!(ScanResult<'_>, input),
        7 => round_trip!(Link, input),
        8 => round_trip!(ApStatus, input),
        9 => round_trip!(ApConfig<'_>, input),
        10 => round_trip!(ApClient, input),
        11 => round_trip!(V4Config, input),
        12 => round_trip!(V6Config, input),
        13 => round_trip!(V4Address, input),
        14 => round_trip!(V6Item, input),
        15 => round_trip!(Config, input),
        16 => round_trip!(Telemetry, input),
        17 => round_trip_item!(BusInfo<'_>, input),
        18 => round_trip_item!(DeviceInfo<'_>, input),
        19 => {
            let _ = BatteryStatus::decode(input);
        }
        20 => integers(input),
        _ => requests(input),
    }
}
