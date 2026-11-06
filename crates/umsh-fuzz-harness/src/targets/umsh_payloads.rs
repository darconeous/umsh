//! The application payloads behind a frame's payload type.

use umsh_core::options::OptionDecoder;
use umsh_node::NodeIdentityPayload;
use umsh_node::location::NodeLocation;
use umsh_node::mac_command::{
    self, IdentityRequestFilters, MacCommand, PeerRepeatersRequestView, PeerRepeatersResponseView,
};
use umsh_node::meet::MeetMessage;

fn mac_command(input: &[u8]) {
    let Ok(command) = mac_command::parse(input) else {
        return;
    };
    match command {
        MacCommand::IdentityRequest { options, .. } => {
            let filters = IdentityRequestFilters::new(options);
            let _ = filters.nonce();
            let _ = filters.hint_filtered();
            let _ = filters.hint_names_one_node();
        }
        MacCommand::PeerRepeatersRequest { options } => {
            let view = PeerRepeatersRequestView::new(options);
            let _ = (view.nonce(), view.cursor());
        }
        MacCommand::PeerRepeatersResponse { body } => {
            let view = PeerRepeatersResponseView::new(body);
            let _ = (view.nonce(), view.cursor(), view.total());
            // Walks forward or stops: a body this size has this many
            // entries at most.
            let mut entries = 0;
            for entry in view.entries() {
                entries += 1;
                assert!(entries <= body.len() + 1, "entries never ended");
                let _ = (entry.hint(), entry.name(), entry.rssi_snr());
                let _ = (entry.last_heard_min(), entry.location());
                let _ = entry.regions().count();
            }
        }
        _ => {}
    }
    let mut out = [0u8; 1024];
    if let Ok(len) = mac_command::encode(&command, &mut out) {
        assert_eq!(mac_command::parse(&out[..len]), Ok(command));
    }
}

fn identity(input: &[u8]) {
    let Ok(identity) = NodeIdentityPayload::from_bytes(input) else {
        return;
    };
    let mut out = [0u8; 1024];
    let Ok(len) = identity.encode(&mut out) else {
        return;
    };
    let again = NodeIdentityPayload::from_bytes(&out[..len]).expect("an encoded identity parses");
    assert_eq!(identity.role, again.role);
    assert_eq!(identity.capabilities, again.capabilities);
    assert_eq!(identity.signature, again.signature);
}

fn location(input: &[u8]) {
    let location = NodeLocation::from_bytes(input);
    let _ = location.precision();
    let _ = location.bounds();
    let _ = location.to_string();
    let again = NodeLocation::from_bytes(location.as_bytes());
    assert_eq!(location, again);
    let _ = location.clamped(input.first().copied().unwrap_or(0));
}

fn meet(input: &[u8]) {
    if let Ok(message) = MeetMessage::parse(input) {
        // `encode` writes a whole payload, payload-type byte first.
        let bytes = message.encode();
        assert_eq!(MeetMessage::parse(&bytes[1..]), Ok(message));
    }
}

fn chat_room(input: &[u8]) {
    if let Ok(action) = umsh_chat_room::parse(input) {
        let mut out = [0u8; 1024];
        if let Ok(len) = umsh_chat_room::encode(&action, &mut out) {
            assert_eq!(umsh_chat_room::parse(&out[..len]).ok(), Some(action));
        }
    }
    // A login is options after its action byte, in the encoding core owns.
    if let Some((_, options)) = input.split_first() {
        let mut decoder = OptionDecoder::new(options);
        while let Some(Ok(_)) = decoder.next() {}
    }
}

pub fn run(data: &[u8]) {
    let Some((&kind, input)) = data.split_first() else {
        return;
    };
    match kind % 5 {
        0 => mac_command(input),
        1 => identity(input),
        2 => location(input),
        3 => meet(input),
        _ => chat_room(input),
    }
}
