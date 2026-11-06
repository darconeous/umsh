//! What arrives over IP: bearer datagrams, DNS-SD TXT records, and frames a
//! bridge hub relays.

use umsh_bridge_client::tunnel::Frame;
use umsh_lan_bearer::txt::Advertisement;
use umsh_lan_bearer::{Datagram, MAX_FRAME, classify};

use crate::script::Fields;

fn datagram(input: &[u8]) {
    if classify(input) != Datagram::Malformed {
        assert!(!input.is_empty() && input.len() <= MAX_FRAME);
    }
}

fn advertisement(input: &[u8]) {
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    let pairs: Vec<(&str, &str)> = text
        .split('\n')
        .filter_map(|line| line.split_once('='))
        .collect();
    let lookup = |key: &str| {
        pairs
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| *value)
    };
    let Ok(advertisement) = Advertisement::parse(lookup) else {
        return;
    };
    // What it says of itself, it reads back.
    let mut properties = Vec::new();
    advertisement.for_each_property(|key, value| properties.push((key, value.to_owned())));
    let lookup = |key: &str| {
        properties
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.as_str())
    };
    assert_eq!(Advertisement::parse(lookup).as_ref(), Ok(&advertisement));
}

fn tunnel(mut fields: Fields<'_>) {
    let now_ms = u64::from(fields.u32());
    let max_payload = usize::from(fields.u8());
    if let Some(frame) = Frame::parse(fields.rest(), now_ms, max_payload) {
        assert!(frame.data().len() <= max_payload);
        let _ = frame.stale(now_ms + u64::from(fields.u16()));
    }
}

pub fn run(data: &[u8]) {
    let Some((&kind, input)) = data.split_first() else {
        return;
    };
    match kind % 3 {
        0 => datagram(input),
        1 => advertisement(input),
        _ => tunnel(Fields::new(input)),
    }
}
