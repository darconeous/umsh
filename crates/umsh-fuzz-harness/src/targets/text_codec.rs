//! The text message codec and its contextual validation.

use umsh_text::codec;
use umsh_text::validate::{DirectChannelProfile, validate};

use super::text_engine::envelope;

pub fn run(data: &[u8]) {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    let Ok((message, info)) = codec::parse_with_info(payload) else {
        return;
    };
    let _ = validate(&DirectChannelProfile, &envelope(selector), &message, &info);

    // `encode` is stricter than `parse`, so what it refuses proves nothing.
    let mut out = [0u8; 1024];
    if let Ok(len) = codec::encode(&message, &mut out) {
        let again = codec::parse(&out[..len]).expect("an encoded message parses");
        assert_eq!(message.message_type, again.message_type);
        assert_eq!(message.sequence, again.sequence);
        assert_eq!(message.regarding, again.regarding);
        assert_eq!(message.body, again.body);
    }
}
