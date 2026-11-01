//! Rendering one captured radio frame: the decode summary, the options
//! that are present, and a hex dump grouped and tinted by field.

use std::fmt::Write as _;
use std::ops::Range;

use hamaddr::HamAddr;
use umsh::core::options::{OptionDecoder, TraceForm, TraceRef};
use umsh::core::{
    FRAME_SIGNATURE_OPTION_LEN, OptionNumber, PacketHeader, PacketType, PayloadType, PublicKey,
    RegionCode, RouterHint, SourceAddrRef,
};

use crate::output::styled;

/// A header field, used both to color its bytes in the hex dump and to color
/// the decoded value that came out of those bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Fcf,
    FloodHops,
    Dst,
    Src,
    Channel,
    SecInfo,
    Options,
    /// Ciphertext covering the addresses of a blind unicast or an encrypted
    /// multicast, which cannot be attributed to `Dst`/`Src` without the key.
    EncAddr,
    Body,
    /// A MAC ack's correlation handle: the first four bytes of the acked
    /// packet's MIC. Public, and not an authenticator.
    AckMic,
    /// A MAC ack's keyed authenticator, which only the original sender can
    /// verify.
    AckTag,
    /// The frame's Ed25519 signature: before the MIC on a secured frame, or
    /// inside the Frame Signature option on a broadcast. With `E` set it is
    /// ciphertext, but it is the same bytes either way.
    Signature,
    Mic,
}

impl Field {
    /// SGR parameters for this field. Deliberately limited to the 16 basic
    /// colors so the output survives minimal terminals.
    fn sgr(self) -> &'static str {
        match self {
            Self::Fcf => "1;97",
            Self::FloodHops => "93",
            Self::Dst => "91",
            Self::Src => "92",
            Self::Channel => "95",
            Self::SecInfo => "33",
            Self::Options => "96",
            Self::EncAddr => "94",
            Self::Body => "37",
            Self::AckMic => "36",
            Self::AckTag => "35",
            Self::Signature => "32",
            Self::Mic => "90",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Fcf => "fcf",
            Self::FloodHops => "hops",
            Self::Dst => "dst",
            Self::Src => "src",
            Self::Channel => "channel",
            Self::SecInfo => "secinfo",
            Self::Options => "options",
            Self::EncAddr => "enc-addr",
            Self::Body => "body",
            Self::AckMic => "ack-mic",
            Self::AckTag => "ack-tag",
            Self::Signature => "sig",
            Self::Mic => "mic",
        }
    }
}

const LEGEND: [Field; 13] = [
    Field::Fcf,
    Field::FloodHops,
    Field::Dst,
    Field::Src,
    Field::Channel,
    Field::SecInfo,
    Field::Options,
    Field::EncAddr,
    Field::Body,
    Field::AckMic,
    Field::AckTag,
    Field::Signature,
    Field::Mic,
];

/// Bold white on red. Encryption is the norm, so nothing marks it; it is
/// cleartext that has to be impossible to scroll past.
const UNENCRYPTED_SGR: &str = "1;97;41";

/// Wrap `text` in this field's color, or return it unchanged when the output
/// is not colorized.
fn tint(text: &str, field: Field, color: bool) -> String {
    styled(text, field.sgr(), color)
}

pub fn print_legend() {
    let chips: Vec<String> = LEGEND
        .iter()
        .map(|field| tint(field.label(), *field, true))
        .collect();
    println!("fields: {}", chips.join("  "));
}

pub fn should_display(packet: &[u8], umsh_only: bool) -> bool {
    !umsh_only || PacketHeader::parse(packet).is_ok()
}

/// Attribute every byte of `packet` to the field it belongs to.
///
/// The layout is reconstructed from the landmarks `PacketHeader` already
/// computed (options, body, and MIC ranges plus the SECINFO length), so it
/// stays in step with the parser rather than re-deriving the wire format.
fn field_map(header: &PacketHeader, len: usize) -> Vec<Option<Field>> {
    fn paint(map: &mut [Option<Field>], range: Range<usize>, field: Field) {
        if let Some(slice) = map.get_mut(range) {
            slice.fill(Some(field));
        }
    }

    let mut map = vec![None; len];
    paint(&mut map, 0..1, Field::Fcf);
    let mut cursor = 1;
    if header.flood_hops.is_some() {
        paint(&mut map, 1..2, Field::FloodHops);
        cursor = 2;
    }

    let options = header.options_range.clone();
    // Painted before the addressing fields: an encrypted multicast places its
    // ciphertext source at the head of the body range, and must win.
    paint(&mut map, header.body_range.clone(), Field::Body);
    paint(&mut map, options.clone(), Field::Options);
    paint(&mut map, header.mic_range.clone(), Field::Mic);
    // Over the option block too: a broadcast's signature is the tail of its
    // Frame Signature option, and the signature is what a reader wants to
    // see tinted.
    if let Some(signature) = header.signature() {
        paint(&mut map, signature.range.clone(), Field::Signature);
    }

    let sec_len = header.sec_info.map_or(0, |sec| sec.wire_len());
    let sec_start = options.start.saturating_sub(sec_len);
    match header.packet_type() {
        PacketType::Broadcast => paint(&mut map, cursor..options.start, Field::Src),
        // A MAC ack has no addressing, and no MIC of its own: its two fixed
        // fields are body. `PacketHeader` reports the same range as both
        // `body_range` and `mic_range`, so split it here.
        PacketType::MacAck => {
            let ack = header.body_range.start;
            paint(&mut map, ack..ack + 4, Field::AckMic);
            paint(&mut map, ack + 4..ack + 8, Field::AckTag);
        }
        PacketType::Reserved5 => {}
        PacketType::Unicast | PacketType::UnicastAckReq => {
            paint(&mut map, cursor..cursor + 3, Field::Dst);
            paint(&mut map, cursor + 3..sec_start, Field::Src);
            paint(&mut map, sec_start..options.start, Field::SecInfo);
        }
        PacketType::Multicast => {
            paint(&mut map, cursor..cursor + 2, Field::Channel);
            paint(&mut map, cursor + 2..options.start, Field::SecInfo);
            match header.source {
                SourceAddrRef::Encrypted { offset, len } => {
                    paint(&mut map, offset..offset + len, Field::EncAddr)
                }
                _ => paint(&mut map, options.end..header.body_range.start, Field::Src),
            }
        }
        PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {
            paint(&mut map, cursor..cursor + 2, Field::Channel);
            paint(&mut map, cursor + 2..options.start, Field::SecInfo);
            if matches!(header.source, SourceAddrRef::Encrypted { .. }) {
                paint(
                    &mut map,
                    options.end..header.body_range.start,
                    Field::EncAddr,
                );
            } else {
                paint(&mut map, options.end..options.end + 3, Field::Dst);
                paint(
                    &mut map,
                    options.end + 3..header.body_range.start,
                    Field::Src,
                );
            }
        }
    }
    map
}

/// Render the hex dump, grouped by field.
///
/// Colorized output needs no separators—the color change marks each field
/// boundary—so the bytes run together and stay compact. Without color the
/// same grouping is spelled with spaces between fields.
fn print_hex(packet: &[u8], map: &[Option<Field>], color: bool) {
    for line in hex_lines(packet, map, color) {
        println!("  {line}");
    }
}

/// Visible hex columns per line, chosen so a full-size LoRa frame wraps but a
/// typical one stays on a single line.
const HEX_WIDTH: usize = 96;

fn hex_lines(packet: &[u8], map: &[Option<Field>], color: bool) -> Vec<String> {
    let field_at = |index: usize| map.get(index).copied().flatten();

    // Split the frame into lines that fit the width budget. Each byte costs
    // two columns, plus one for the space that separates fields when the
    // output is not colorized.
    let mut spans: Vec<Range<usize>> = Vec::new();
    let mut start = 0;
    let mut col = 0;
    for index in 0..packet.len() {
        let separated = !color && index > start && field_at(index) != field_at(index - 1);
        let cost = 2 + usize::from(separated);
        if index > start && col + cost > HEX_WIDTH {
            spans.push(start..index);
            start = index;
            col = 2;
        } else {
            col += cost;
        }
    }
    if start < packet.len() {
        spans.push(start..packet.len());
    }

    spans
        .into_iter()
        .map(|span| {
            let mut line = String::new();
            let mut index = span.start;
            while index < span.end {
                let field = field_at(index);
                let mut run = index;
                while run < span.end && field_at(run) == field {
                    run += 1;
                }
                if !color && index != span.start {
                    line.push(' ');
                }
                let mut hex = String::new();
                for byte in &packet[index..run] {
                    let _ = write!(hex, "{byte:02x}");
                }
                match field {
                    Some(field) => line.push_str(&tint(&hex, field, color)),
                    None => line.push_str(&hex),
                }
                index = run;
            }
            line
        })
        .collect()
}

/// Print the decode summary, the present options, and the hex dump.
pub fn print_frame(packet: &[u8], color: bool) {
    let header = match PacketHeader::parse(packet) {
        Ok(header) => header,
        Err(error) => {
            println!("  not a UMSH packet ({error:?})");
            print_hex(packet, &vec![None; packet.len()], color);
            return;
        }
    };

    println!("  {}", summary_line(packet, &header, color));
    if let Some(line) = options_line(packet, &header, color) {
        println!("  {line}");
    }
    print_hex(packet, &field_map(&header, packet.len()), color);
}

/// Build the one-line decode summary: what it is, who it is between, and the
/// security and framing state that applies to it.
fn summary_line(packet: &[u8], header: &PacketHeader, color: bool) -> String {
    let mut chips: Vec<String> = Vec::new();
    let packet_type = header.packet_type();
    let type_text = format!("{packet_type:?}");
    chips.push(if color {
        format!("\x1b[1m{type_text}\x1b[0m")
    } else {
        type_text
    });

    // A destination hint names a node; a multicast or an encrypted blind
    // unicast is addressed by channel instead, so the channel stands in as
    // the destination and only appears separately when both are present.
    let dst = match (header.dst, header.channel) {
        (Some(hint), _) => Some(tint(&hint.to_string(), Field::Dst, color)),
        (None, Some(channel)) => Some(tint(
            &format!("ch:{:02x}{:02x}", channel.0[0], channel.0[1]),
            Field::Channel,
            color,
        )),
        (None, None) if packet_type == PacketType::Broadcast => Some("*".to_owned()),
        (None, None) => None,
    };
    let src = source_text(packet, header).map(|text| tint(&text, Field::Src, color));
    match (src, dst) {
        (Some(src), Some(dst)) => chips.push(format!("{src} → {dst}")),
        (Some(src), None) => chips.push(src),
        (None, Some(dst)) => chips.push(format!("→ {dst}")),
        (None, None) => {}
    }
    if header.dst.is_some()
        && let Some(channel) = header.channel
    {
        chips.push(tint(
            &format!("ch:{:02x}{:02x}", channel.0[0], channel.0[1]),
            Field::Channel,
            color,
        ));
    }

    // Rendered `remaining:accumulated`, matching the order of the two
    // nibbles in the FHOPS byte itself. `FHOPS_REM` is the flood-forwarding
    // budget still to spend and `FHOPS_ACC` the flood hops already
    // traversed; neither is a time-to-live nor a total hop count, since a
    // source-routed hop moves neither nibble.
    if let Some(hops) = header.flood_hops {
        chips.push(tint(
            &format!("fhops={}:{}", hops.remaining(), hops.accumulated()),
            Field::FloodHops,
            color,
        ));
    }

    let encrypted = header
        .sec_info
        .is_some_and(|security| security.scf.encrypted());
    if let Some(security) = header.sec_info {
        // Spelled `fcnt` rather than `ctr`, which would read as the AES-CTR
        // half of the packet's own encryption.
        chips.push(tint(
            &format!("fcnt={}", security.frame_counter),
            Field::SecInfo,
            color,
        ));
        if let Some(salt) = security.salt {
            chips.push(tint(&format!("salt={salt:#06x}"), Field::SecInfo, color));
        }
        if security.scf.signed() {
            chips.push(tint("signed", Field::SecInfo, color));
        }
        // Encrypted is the expected case and says nothing; a secured packet
        // type carrying cleartext is the anomaly worth shouting about.
        if !encrypted {
            chips.push(styled("UNENC", UNENCRYPTED_SGR, color));
        }
    }
    // `ack_requested()` is derived purely from the packet type, which is
    // already the first chip on the line, so it gets no chip of its own.

    // A MAC ack's whole content is its two fixed fields, so show them rather
    // than a length: the ack MIC correlates the ack with the packet it
    // acknowledges, and the ack tag is what actually authenticates it.
    if packet_type == PacketType::MacAck {
        let ack = header.body_range.start;
        match packet.get(ack..ack + 8) {
            Some(fields) => {
                chips.push(tint(
                    &format!("ack_mic={}", hex_text(&fields[..4])),
                    Field::AckMic,
                    color,
                ));
                chips.push(tint(
                    &format!("ack_tag={}", hex_text(&fields[4..])),
                    Field::AckTag,
                    color,
                ));
            }
            None => chips.push("<truncated ack>".to_owned()),
        }
        return chips.join("  ");
    }

    // Lengths carry their unit so they cannot be read as the field's value.
    if header.is_beacon() {
        chips.push("beacon".to_owned());
    } else {
        chips.push(tint(
            &format!("body={}B", header.body_range.len()),
            Field::Body,
            color,
        ));
    }
    // The payload type is the first body byte, and is only readable in the
    // clear.
    if !encrypted
        && let Some(payload) = packet
            .get(header.body_range.start)
            .and_then(|byte| PayloadType::from_byte(*byte))
    {
        chips.push(tint(&format!("{payload:?}"), Field::Body, color));
    }
    if !header.mic_range.is_empty() {
        chips.push(tint(
            &format!("mic={}B", header.mic_range.len()),
            Field::Mic,
            color,
        ));
    }
    chips.join("  ")
}

/// Render the source address: a hint, a full key, or an acknowledgement that
/// it is sealed.
fn source_text(packet: &[u8], header: &PacketHeader) -> Option<String> {
    match header.source {
        SourceAddrRef::Hint(hint) => Some(hint.to_string()),
        SourceAddrRef::FullKeyAt { offset } => Some(packet.get(offset..offset + 32).map_or_else(
            || "<truncated>".to_owned(),
            |bytes| {
                let mut key = [0u8; 32];
                key.copy_from_slice(bytes);
                PublicKey(key).to_string()
            },
        )),
        SourceAddrRef::Encrypted { .. } => Some("<enc>".to_owned()),
        SourceAddrRef::None => None,
    }
}

/// Render the options that are actually present, decoding each one's value.
///
/// This walks the option block directly rather than going through
/// `ParsedOptions`, so options that the MAC has no use for—callsigns, and
/// anything unrecognized—still show up in a capture.
fn options_line(packet: &[u8], header: &PacketHeader, color: bool) -> Option<String> {
    let range = header.options_range.clone();
    if range.is_empty() {
        return None;
    }

    let mut chips: Vec<String> = Vec::new();
    for entry in OptionDecoder::new(&packet[range]) {
        let (number, value) = match entry {
            Ok(entry) => entry,
            Err(error) => {
                chips.push(format!("<decode error: {error:?}>"));
                break;
            }
        };
        chips.push(option_chip(number, value));
    }
    if chips.is_empty() {
        return None;
    }
    Some(format!(
        "{}  {}",
        tint("opts", Field::Options, color),
        chips
            .iter()
            .map(|chip| tint(chip, Field::Options, color))
            .collect::<Vec<_>>()
            .join("  "),
    ))
}

fn option_chip(number: u16, value: &[u8]) -> String {
    match OptionNumber::from(number) {
        OptionNumber::FrameSignature if value.len() == FRAME_SIGNATURE_OPTION_LEN => format!(
            "fsig=ctr:{},sig:{}",
            u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
            signature_text(&value[4..]),
        ),
        OptionNumber::Trace => format!("trace=[{}]", trace_text(value)),
        OptionNumber::SourceRoute => format!("route=[{}]", route_text(value)),
        OptionNumber::RegionCode if value.len() == 2 => {
            format!("region={}", RegionCode::from_bytes([value[0], value[1]]))
        }
        // A zero-length threshold selects the receiver's default, which the
        // frame itself does not name.
        OptionNumber::MinRssi if value.is_empty() => "min-rssi=default".to_owned(),
        OptionNumber::MinRssi if value.len() == 1 => format!("min-rssi={}", -i16::from(value[0])),
        OptionNumber::MinSnr if value.is_empty() => "min-snr=default".to_owned(),
        OptionNumber::MinSnr if value.len() == 1 => format!("min-snr={}", value[0] as i8),
        OptionNumber::RouteRetry if value.is_empty() => "retry".to_owned(),
        OptionNumber::RouteRetry => format!("retry={}", hex_text(value)),
        OptionNumber::OperatorCallsign => format!("op={}", callsign_text(value)),
        OptionNumber::StationCallsign => format!("via={}", callsign_text(value)),
        OptionNumber::Fence => "fence".to_owned(),
        // Either an unknown option or a known one carrying a malformed value.
        // A critical option is marked with the class it is critical in:
        // `f` for a repeater that must not forward the frame, `d` for an
        // endpoint that must not deliver it. The classes are independent.
        other => format!("opt{number}{}={}", criticality_text(other), hex_text(value)),
    }
}

/// `[f]`, `[d]`, or `[fd]`; empty for an option that is not critical.
fn criticality_text(option: OptionNumber) -> String {
    let forwarding = if option.is_forwarding_critical() {
        "f"
    } else {
        ""
    };
    let delivery = if option.is_delivery_critical() {
        "d"
    } else {
        ""
    };
    if forwarding.is_empty() && delivery.is_empty() {
        String::new()
    } else {
        format!("[{forwarding}{delivery}]")
    }
}

/// A signature's leading and trailing bytes, which is enough to tell two
/// apart; the whole value is in the hex dump.
fn signature_text(signature: &[u8]) -> String {
    match (signature.get(..4), signature.len().checked_sub(2)) {
        (Some(head), Some(tail)) => format!(
            "{}…{}",
            crate::output::hex(head),
            crate::output::hex(&signature[tail..])
        ),
        _ => hex_text(signature),
    }
}

/// Render a route option as its list of router hints.
fn route_text(value: &[u8]) -> String {
    if !value.len().is_multiple_of(2) {
        return hex_text(value);
    }
    value
        .chunks_exact(2)
        .map(|hint| RouterHint([hint[0], hint[1]]).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// A trace's hops, most recent first. The form shows in the entries: the
/// signal form tags every hop with `@` and its RSSI (`@p2p` for a
/// point-to-point link), the `0xFE` hints-only form lists bare hints, and a
/// leading `…` marks the `0xFF` truncated form, whose older hops are gone.
fn trace_text(value: &[u8]) -> String {
    let Some(trace) = TraceRef::parse(value) else {
        return hex_text(value);
    };
    let hops = trace
        .entries()
        .map(|entry| match entry.signal {
            Some(signal) => match signal.rssi_dbm() {
                Some(rssi) => format!("{}@{rssi}", entry.hint),
                None => format!("{}@p2p", entry.hint),
            },
            None => entry.hint.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",");
    match trace.form() {
        TraceForm::Signal | TraceForm::HintsOnly => hops,
        TraceForm::Truncated => format!("…{hops}"),
    }
}

fn callsign_text(value: &[u8]) -> String {
    HamAddr::try_from_slice(value).map_or_else(|_| hex_text(value), |addr| addr.to_string())
}

fn hex_text(value: &[u8]) -> String {
    if value.is_empty() {
        return "-".to_owned();
    }
    crate::output::hex(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Packet #559 from a live capture, with its options re-encoded for
    /// today's numbering: a source-routed encrypted unicast with one
    /// source-route hop, an empty Trace option, and flood hops still to
    /// spend.
    const SOURCE_ROUTED_UNICAST: [u8; 44] = [
        0xd1, 0x50, 0xb7, 0xa6, 0x26, 0x45, 0xfe, 0xb2, 0xe0, 0xdf, 0x45, 0xb6, 0xa0, 0x32, 0xef,
        0x24, 0x40, 0xff, 0xa2, 0x41, 0x4a, 0x15, 0xf0, 0x7c, 0x55, 0x21, 0x51, 0xd6, 0x7d, 0xe6,
        0x29, 0xbb, 0xf3, 0xa0, 0xee, 0x37, 0x93, 0xa4, 0x22, 0x20, 0x9a, 0x49, 0x8f, 0x72,
    ];

    /// Packet #560: the same frame after a repeater consumed the source
    /// route and added itself to the trace (shown here in the hints-only
    /// form).
    const FORWARDED_UNICAST: [u8; 45] = [
        0xd1, 0x41, 0xb7, 0xa6, 0x26, 0x45, 0xfe, 0xb2, 0xe0, 0xdf, 0x45, 0xb6, 0xa0, 0x30, 0x43,
        0xfe, 0xef, 0x24, 0xff, 0xa2, 0x41, 0x4a, 0x15, 0xf0, 0x7c, 0x55, 0x21, 0x51, 0xd6, 0x7d,
        0xe6, 0x29, 0xbb, 0xf3, 0xa0, 0xee, 0x37, 0x93, 0xa4, 0x22, 0x20, 0x9a, 0x49, 0x8f, 0x72,
    ];

    /// Packet #110 from a live capture: a MAC ack with a flood-hop field and
    /// an empty options block.
    const MAC_ACK: [u8; 10] = [0xc9, 0x10, 0x8c, 0xb6, 0x8f, 0x5d, 0x97, 0x00, 0xed, 0xe7];

    /// Packet #109 from a live capture: a forwarded ack-requested unicast
    /// whose source route was consumed by the repeater that carried it.
    const UNICAST_ACK_REQ: [u8; 40] = [
        0xd9, 0x41, 0x1e, 0x9d, 0xb8, 0x45, 0xfe, 0xb2, 0xe0, 0xdf, 0x45, 0xb6, 0xa7, 0x30, 0xff,
        0x94, 0x21, 0xd3, 0x18, 0x09, 0x2e, 0x78, 0xd6, 0x47, 0x8c, 0xb6, 0x8f, 0x5d, 0x0d, 0xcd,
        0xe2, 0x26, 0x8f, 0xf2, 0x9a, 0x60, 0x75, 0xbd, 0x1b, 0x41,
    ];

    #[test]
    fn umsh_only_suppresses_foreign_frames_but_not_valid_umsh() {
        let valid_umsh_beacon = [0xc0, 0xa1, 0xb2, 0x03];
        let foreign_frame = [0x15, 0x02, 0x69, 0x26];
        assert!(should_display(&valid_umsh_beacon, true));
        assert!(!should_display(&foreign_frame, true));
        assert!(should_display(&foreign_frame, false));
    }

    #[test]
    fn summary_reports_addressing_security_and_framing() {
        let header = PacketHeader::parse(&SOURCE_ROUTED_UNICAST).unwrap();
        let summary = summary_line(&SOURCE_ROUTED_UNICAST, &header, false);
        assert_eq!(
            summary,
            "Unicast  5iEP → DMt*  fhops=5:0  fcnt=3745887904  body=10B  mic=16B",
        );
        // No `Some(..)`, and absent fields say nothing at all.
        assert!(!summary.contains("Some"));
        assert!(!summary.contains("None"));

        // One flood hop later: the repeater spent a hop from the remaining
        // budget and added it to the accumulated count. Neither nibble is a
        // total, so both are shown, in the order they appear in the byte.
        let forwarded = PacketHeader::parse(&FORWARDED_UNICAST).unwrap();
        assert!(summary_line(&FORWARDED_UNICAST, &forwarded, false).contains("fhops=4:1"),);
    }

    #[test]
    fn ack_request_is_stated_once_by_the_packet_type() {
        let header = PacketHeader::parse(&UNICAST_ACK_REQ).unwrap();
        assert!(header.ack_requested());
        let summary = summary_line(&UNICAST_ACK_REQ, &header, false);
        assert_eq!(
            summary,
            "UnicastAckReq  5iEP → 34Wi  fhops=4:1  fcnt=3745887911  body=9B  mic=16B",
        );
        // The type name already carries it; nothing repeats it.
        assert_eq!(summary.matches("Ack").count(), 1);
        assert!(!summary.contains("ack-req"));

        // A repeater that consumed the final hint leaves the emptied option
        // behind for provenance, and the capture must still show it.
        assert_eq!(
            options_line(&UNICAST_ACK_REQ, &header, false).unwrap(),
            "opts  route=[]",
        );
    }

    #[test]
    fn mac_ack_reports_its_two_body_fields_not_a_trailer() {
        let header = PacketHeader::parse(&MAC_ACK).unwrap();
        assert_eq!(header.packet_type(), PacketType::MacAck);
        assert_eq!(
            summary_line(&MAC_ACK, &header, false),
            "MacAck  fhops=1:0  ack_mic=8cb68f5d  ack_tag=9700ede7",
        );

        // The two fields are body, and a MAC ack has no MIC of its own—
        // even though `PacketHeader` reports the same range as `mic_range`.
        let map = field_map(&header, MAC_ACK.len());
        assert_eq!(map[0], Some(Field::Fcf));
        assert_eq!(map[1], Some(Field::FloodHops));
        for index in 2..6 {
            assert_eq!(map[index], Some(Field::AckMic), "byte {index}");
        }
        for index in 6..10 {
            assert_eq!(map[index], Some(Field::AckTag), "byte {index}");
        }
        assert!(
            !map.contains(&Some(Field::Mic)),
            "a MAC ack carries no MIC of its own",
        );

        assert_eq!(
            hex_lines(&MAC_ACK, &map, false),
            vec!["c9 10 8cb68f5d 9700ede7"],
        );
    }

    /// MAC acks with and without a static option show their two fields.
    #[test]
    fn mac_ack_shows_its_mic_and_tag() {
        let bare = [0xc8, 0xaa, 0x17, 0x13, 0x06, 0xd2, 0xfb, 0x63, 0xbd];
        let header = PacketHeader::parse(&bare).unwrap();
        assert_eq!(
            summary_line(&bare, &header, false),
            "MacAck  ack_mic=aa171306  ack_tag=d2fb63bd",
        );

        let callsign = [
            0xc8, 0x44, 0x5b, 0xbb, 0x08, 0x2c, 0xaa, 0x17, 0x13, 0x06, 0xa8, 0x78, 0xbe, 0x6e,
        ];
        let header = PacketHeader::parse(&callsign).unwrap();
        assert_eq!(
            summary_line(&callsign, &header, false),
            "MacAck  ack_mic=aa171306  ack_tag=a878be6e",
        );
        assert_eq!(
            options_line(&callsign, &header, false).unwrap(),
            "opts  op=N0CALL",
        );
    }

    #[test]
    fn cleartext_is_flagged_loudly_and_encryption_is_silent() {
        // Encryption is the expected case, so it adds nothing to the line.
        let header = PacketHeader::parse(&SOURCE_ROUTED_UNICAST).unwrap();
        assert!(!summary_line(&SOURCE_ROUTED_UNICAST, &header, false).contains("UNENC"));

        // Clearing the SCF encrypted bit leaves a secured packet type
        // carrying cleartext, which must be impossible to miss.
        let mut cleartext = SOURCE_ROUTED_UNICAST;
        cleartext[8] &= 0x7f;
        let header = PacketHeader::parse(&cleartext).unwrap();
        assert!(!header.sec_info.unwrap().scf.encrypted());

        let plain = summary_line(&cleartext, &header, false);
        assert!(plain.contains("UNENC"), "{plain}");

        // Colorized, it is bold white on a red background.
        let colored = summary_line(&cleartext, &header, true);
        assert!(colored.contains("\x1b[1;97;41mUNENC\x1b[0m"), "{colored}");
    }

    #[test]
    fn options_line_lists_only_present_options_with_decoded_routes() {
        let header = PacketHeader::parse(&SOURCE_ROUTED_UNICAST).unwrap();
        let line = options_line(&SOURCE_ROUTED_UNICAST, &header, false).unwrap();
        // The trace is present but still empty; the source route names the
        // next hop rather than a byte range.
        assert_eq!(line, "opts  route=[H6*]  trace=[]");
        for absent in ["region", "min-rssi", "min-snr", "retry"] {
            assert!(!line.contains(absent), "{absent} should not be listed");
        }

        let forwarded = PacketHeader::parse(&FORWARDED_UNICAST).unwrap();
        let line = options_line(&FORWARDED_UNICAST, &forwarded, false).unwrap();
        assert_eq!(line, "opts  route=[]  trace=[H6*]");
    }

    #[test]
    fn option_chips_decode_each_known_option() {
        assert_eq!(option_chip(11, &[0x78, 0x53]), "region=SJC");
        assert_eq!(option_chip(5, &[130]), "min-rssi=-130");
        assert_eq!(option_chip(5, &[]), "min-rssi=default");
        assert_eq!(option_chip(9, &[0xfd]), "min-snr=-3");
        assert_eq!(option_chip(6, &[]), "retry");
        assert_eq!(
            option_chip(
                4,
                HamAddr::try_from_callsign("KJ6QOH")
                    .unwrap()
                    .as_trimmed_slice()
            ),
            "op=KJ6QOH",
        );
        assert_eq!(
            option_chip(
                15,
                HamAddr::try_from_callsign("KZ2X")
                    .unwrap()
                    .as_trimmed_slice()
            ),
            "via=KZ2X",
        );
        assert_eq!(option_chip(7, &[0xff, 0xef, 0x24]), "trace=[…H6*]");
        // Unknown options survive, and the critical ones are marked.
        assert_eq!(option_chip(20, &[0xaa, 0xbb]), "opt20=aabb");
        assert_eq!(option_chip(21, &[0xaa]), "opt21[f]=aa");
    }

    /// The two criticality classes are separate: bit 0 for forwarding, and
    /// bits 2 and 3 set on a static option for delivery.
    #[test]
    fn unknown_options_show_each_criticality_class() {
        assert_eq!(option_chip(12, &[0xaa]), "opt12[d]=aa");
        assert_eq!(option_chip(1, &[0xaa]), "opt1[f]=aa");
        assert_eq!(option_chip(13, &[0xaa]), "opt13[fd]=aa");
        // Dynamic options (bit 1) are never delivery-critical.
        assert_eq!(option_chip(14, &[0xaa]), "opt14=aa");
        assert_eq!(option_chip(20, &[0xaa]), "opt20=aa");
    }

    #[test]
    fn trace_shows_each_of_its_three_forms() {
        // Signal form: a 4-byte record per hop; RSSI byte 0x5a is -90 dBm.
        assert_eq!(option_chip(7, &[0xef, 0x24, 0x5a, 0x10]), "trace=[H6*@-90]");
        // A point-to-point hop measured nothing.
        assert_eq!(option_chip(7, &[0xef, 0x24, 0x00, 0x00]), "trace=[H6*@p2p]");
        // Hints-only form (0xFE), then truncated (0xFF).
        assert_eq!(option_chip(7, &[0xfe, 0xef, 0x24]), "trace=[H6*]");
        assert_eq!(option_chip(7, &[0xff, 0xef, 0x24]), "trace=[…H6*]");
    }

    /// Example 12 of the test vectors: a signed, unencrypted multicast.
    const SIGNED_MULTICAST: [u8; 126] = [
        0xe4, 0xb0, 0x8d, 0x68, 0x00, 0x00, 0x00, 0x0c, 0xff, 0xed, 0x54, 0xa5, 0x9f, 0xb1, 0xac,
        0x3a, 0x51, 0x23, 0x93, 0x51, 0x36, 0x29, 0x41, 0xb8, 0x68, 0xe8, 0x5a, 0x60, 0xe3, 0xd7,
        0xb2, 0x48, 0x5d, 0x82, 0x88, 0x21, 0xdc, 0x7a, 0x69, 0xc2, 0x79, 0x03, 0x48, 0x65, 0x6c,
        0x70, 0x64, 0x60, 0xe7, 0x36, 0xcf, 0x31, 0x6b, 0xb3, 0x2f, 0x43, 0x8c, 0xa2, 0x81, 0xde,
        0x0d, 0xe0, 0x2c, 0x3b, 0xbe, 0xb7, 0xa6, 0xcb, 0x19, 0x5a, 0x5c, 0x60, 0x55, 0xbd, 0x46,
        0xa9, 0xf5, 0xe7, 0x53, 0x2c, 0x96, 0xae, 0xf7, 0xcc, 0xe8, 0x06, 0xc7, 0xf4, 0xfc, 0x46,
        0x2c, 0xd9, 0xb8, 0x61, 0xcc, 0x60, 0xd4, 0x47, 0x65, 0xf6, 0x6e, 0x4e, 0x3a, 0x5d, 0xdb,
        0x10, 0x91, 0x3d, 0x6d, 0x05, 0x59, 0x96, 0x7a, 0x9d, 0x75, 0xd9, 0xfc, 0xdc, 0xaa, 0x9f,
        0xad, 0x4c, 0x50, 0x3b, 0x2e, 0x47,
    ];

    /// Example 14: a signed broadcast, whose signature is the tail of its
    /// Frame Signature option.
    const SIGNED_BROADCAST: [u8; 106] = [
        0xc4, 0xed, 0x54, 0xa5, 0x9f, 0xb1, 0xac, 0x3a, 0x51, 0x23, 0x93, 0x51, 0x36, 0x29, 0x41,
        0xb8, 0x68, 0xe8, 0x5a, 0x60, 0xe3, 0xd7, 0xb2, 0x48, 0x5d, 0x82, 0x88, 0x21, 0xdc, 0x7a,
        0x69, 0xc2, 0x79, 0x0d, 0x37, 0x00, 0x00, 0x00, 0x0e, 0x03, 0x79, 0xa8, 0xfa, 0x3a, 0xb8,
        0x6e, 0x4f, 0x59, 0xc7, 0x6f, 0x0e, 0xe6, 0x5c, 0x76, 0x6b, 0xd2, 0xf1, 0x03, 0x38, 0x0e,
        0x62, 0xd9, 0xad, 0x4e, 0xe8, 0x66, 0xe5, 0x89, 0xb3, 0x56, 0xc0, 0x54, 0xac, 0xf8, 0x50,
        0xaf, 0xd6, 0x9a, 0xdd, 0xb7, 0xa3, 0x8b, 0x7c, 0x18, 0xe8, 0x77, 0xa6, 0xaa, 0x55, 0x84,
        0x68, 0xf7, 0x01, 0x2f, 0xe0, 0x91, 0x24, 0x4e, 0x6b, 0x89, 0x52, 0xbe, 0x0c, 0xff, 0x48,
        0x69,
    ];

    #[test]
    fn a_signed_secured_frame_shows_a_chip_and_paints_its_signature() {
        let header = PacketHeader::parse(&SIGNED_MULTICAST).unwrap();
        let summary = summary_line(&SIGNED_MULTICAST, &header, false);
        assert!(summary.contains("fcnt=12  signed"), "{summary}");

        let map = field_map(&header, SIGNED_MULTICAST.len());
        let signature = header.signature().unwrap().range.clone();
        assert_eq!(signature.len(), 64);
        for index in signature.clone() {
            assert_eq!(map[index], Some(Field::Signature), "byte {index}");
        }
        // The payload before it and the MIC after it keep their own fields.
        assert_eq!(map[signature.start - 1], Some(Field::Body));
        assert_eq!(map[signature.end], Some(Field::Mic));
        assert!(map.iter().all(Option::is_some), "every byte is attributed");
    }

    #[test]
    fn a_signed_broadcast_shows_option_0_and_paints_the_signature_in_it() {
        let header = PacketHeader::parse(&SIGNED_BROADCAST).unwrap();
        assert_eq!(
            options_line(&SIGNED_BROADCAST, &header, false).unwrap(),
            "opts  fsig=ctr:14,sig:0379a8fa…be0c",
        );
        // A broadcast has no SECINFO, so no `signed` chip: the option says it.
        assert!(!summary_line(&SIGNED_BROADCAST, &header, false).contains("signed"));

        let map = field_map(&header, SIGNED_BROADCAST.len());
        let signature = header.signature().unwrap();
        assert_eq!(signature.counter, 14);
        for index in signature.range.clone() {
            assert_eq!(map[index], Some(Field::Signature), "byte {index}");
        }
        // The counter ahead of the signature is still part of the option.
        assert_eq!(map[signature.range.start - 1], Some(Field::Options));
        assert_eq!(map[signature.range.end], Some(Field::Options));
    }

    #[test]
    fn a_built_signed_unicast_with_unknown_options_is_marked_by_class() {
        use umsh::core::NodeHint;
        use umsh::core::PacketBuilder;

        let mut buf = [0u8; 256];
        let frame = PacketBuilder::new(&mut buf)
            .unicast(NodeHint([0xc3, 0xd4, 0x25]))
            .source_hint(NodeHint([0xa1, 0xb2, 0x03]))
            .frame_counter(42)
            .signed()
            .option(OptionNumber::Unknown(1), &[0x02])
            .option(OptionNumber::Unknown(12), &[0x01])
            .payload(b"hi")
            .build()
            .unwrap()
            .as_bytes()
            .to_vec();
        let header = PacketHeader::parse(&frame).unwrap();
        assert_eq!(
            options_line(&frame, &header, false).unwrap(),
            "opts  opt1[f]=02  opt12[d]=01  fence",
        );
        assert!(summary_line(&frame, &header, false).contains("signed"));
    }

    #[test]
    fn field_map_attributes_every_byte_of_a_unicast() {
        let header = PacketHeader::parse(&SOURCE_ROUTED_UNICAST).unwrap();
        let map = field_map(&header, SOURCE_ROUTED_UNICAST.len());
        let expected = [
            (0..1, Field::Fcf),
            (1..2, Field::FloodHops),
            (2..5, Field::Dst),
            (5..8, Field::Src),
            (8..13, Field::SecInfo),
            (13..18, Field::Options),
            (18..28, Field::Body),
            (28..44, Field::Mic),
        ];
        for (range, field) in expected {
            for index in range.clone() {
                assert_eq!(map[index], Some(field), "byte {index} of {range:?}");
            }
        }
        assert!(map.iter().all(Option::is_some), "every byte is attributed");
    }

    #[test]
    fn hex_dump_groups_by_field_and_drops_spaces_when_colorized() {
        let header = PacketHeader::parse(&SOURCE_ROUTED_UNICAST).unwrap();
        let map = field_map(&header, SOURCE_ROUTED_UNICAST.len());

        // Uncolored output separates fields with spaces.
        let plain = hex_lines(&SOURCE_ROUTED_UNICAST, &map, false);
        assert_eq!(
            plain,
            vec![
                "d1 50 b7a626 45feb2 e0df45b6a0 32ef2440ff \
                 a2414a15f07c552151d6 7de629bbf3a0ee3793a422209a498f72",
            ],
        );

        // Colorized output needs no separators: the color change is the
        // boundary. Stripping the escapes recovers a bare hex string.
        let colored = hex_lines(&SOURCE_ROUTED_UNICAST, &map, true);
        assert_eq!(colored.len(), 1);
        assert!(colored[0].contains("\x1b["));
        assert_eq!(
            strip_ansi(&colored[0]),
            SOURCE_ROUTED_UNICAST
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
    }

    #[test]
    fn hex_dump_wraps_a_full_size_frame_without_losing_bytes() {
        let packet = [0x5au8; 200];
        let map = vec![Some(Field::Body); packet.len()];
        let lines = hex_lines(&packet, &map, true);
        assert!(lines.len() > 1, "a 200-byte frame must wrap");
        for line in &lines {
            assert!(strip_ansi(line).len() <= HEX_WIDTH, "line exceeds budget");
        }
        let rejoined: String = lines.iter().map(|line| strip_ansi(line)).collect();
        assert_eq!(rejoined, "5a".repeat(packet.len()));
    }

    #[test]
    fn non_umsh_frames_still_dump_their_bytes() {
        let foreign = [0x15, 0x02, 0x69, 0x26];
        let map = vec![None; foreign.len()];
        assert_eq!(hex_lines(&foreign, &map, false), vec!["15026926"]);
    }

    fn strip_ansi(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                for skip in chars.by_ref() {
                    if skip == 'm' {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn beacons_and_foreign_frames_render_without_a_security_header() {
        let beacon = [0xc0, 0xa1, 0xb2, 0x03];
        let header = PacketHeader::parse(&beacon).unwrap();
        assert_eq!(
            summary_line(&beacon, &header, false),
            "Broadcast  BtC5 → *  beacon",
        );
        assert!(options_line(&beacon, &header, false).is_none());

        assert!(PacketHeader::parse(&[0x15, 0x02, 0x69, 0x26]).is_err());
    }
}
