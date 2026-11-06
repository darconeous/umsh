//! The frame parser, everything a successful parse reports, and the AAD
//! built from it.

use umsh_core::{BlindAddr, PacketHeader, ParsedOptions, SourceAddrRef, feed_aad};

/// Every range a successful parse reports lies inside the frame, and fields
/// that follow the options end before the MIC.
pub fn assert_ranges_sane(header: &PacketHeader, len: usize) {
    for range in [&header.options_range, &header.body_range, &header.mic_range] {
        assert!(range.start <= range.end, "inverted range {range:?}");
        assert!(range.end <= len, "range {range:?} past frame of {len}");
    }
    assert!(header.total_len <= len);
    let trailer = header.mic_range.start;
    match header.source {
        SourceAddrRef::FullKeyAt { offset } => assert!(offset + 32 <= trailer),
        SourceAddrRef::Encrypted { offset, len } => assert!(offset + len <= trailer),
        SourceAddrRef::Hint(_) | SourceAddrRef::None => {}
    }
}

/// The frame's AAD, with `blind` standing in for a blind unicast's block.
pub fn aad(header: &PacketHeader, frame: &[u8], blind: Option<&BlindAddr>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    feed_aad(header, frame, blind, |bytes| out.extend_from_slice(bytes)).ok()?;
    Some(out)
}

pub fn run(data: &[u8]) {
    let Ok(header) = PacketHeader::parse(data) else {
        return;
    };
    assert_ranges_sane(&header, data.len());

    // A frame cut to the length its parse reports is the same frame.
    let exact = PacketHeader::parse(&data[..header.total_len]).expect("cut to its own length");
    assert_eq!(exact.body_range, header.body_range);
    assert_eq!(exact.mic_range, header.mic_range);
    assert_eq!(exact.options_range, header.options_range);

    if let Ok(options) = ParsedOptions::extract(data, header.options_range.clone()) {
        let _ = options.trace(data);
        let _ = options.refuses_delivery();
    }
    let blind = header
        .blind_addr_range()
        .and_then(|range| BlindAddr::from_plaintext(&data[range]));
    let _ = aad(&header, data, blind.as_ref());
}
