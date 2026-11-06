//! The node-management envelope and its fragment framing.

use umsh_node_mgmt::envelope::Envelope;
use umsh_node_mgmt::fragment;

pub fn run(data: &[u8]) {
    let offset = fragment::trailing_offset(data);
    if let Some(offset) = offset {
        assert!(offset <= data.len());
    }
    assert!(fragment::trailing(data).len() <= data.len());

    let Ok(envelope) = Envelope::parse(data) else {
        return;
    };
    let mut out = [0u8; 1024];
    if let Ok(len) = envelope.encode(&mut out) {
        assert_eq!(
            Envelope::parse(&out[..len]).expect("an encoded envelope parses"),
            envelope
        );
    }
}
