//! Node messaging metadata (`STR_NODE_MSG`).
//!
//! A `CMD_STR_SEND` on the stream hands the device a UMSH payload and a
//! destination; a `CMD_STR_RECV` hands a link a payload the device's node
//! received. Both carry the payload as `DATA` and a fixed prefix of kind,
//! flags, and addresses as metadata, followed by options in the
//! `CMD_PROP_MULTI_SET` entry form. As with `CMD_ANNOUNCE`, a send option
//! the device does not recognize is an error rather than something to
//! ignore: the link asked for something specific. A receiver of `Recv`
//! metadata ignores options it does not know.

use crate::frame::{Cmd, FrameWriter, MultiEntries, TID_UNSOLICITED, WriteError};
use crate::ids::{MAX_ANNOUNCE_FLOOD_HOPS, stream};
use crate::items::CHANNEL_IDENTIFIER_LEN;
use crate::status::Status;

/// Length of a public key in `TX_PEER` and `RX_SRC`.
pub const KEY_LEN: usize = 32;
/// Length of a node hint in `RX_SRC`.
pub const HINT_LEN: usize = 3;
/// Length of one router hint in a source route or trace.
pub const ROUTER_HINT_LEN: usize = 2;
/// Most router hints a source route or trace carries.
pub const MAX_ROUTE_HINTS: usize = 15;
/// Largest flood budget a send may ask for.
pub const MAX_FLOOD_HOPS: u8 = MAX_ANNOUNCE_FLOOD_HOPS;

/// `TX_FLAGS` bits.
pub mod tx_flag {
    /// Request an acknowledgment. Unicast and blind unicast only.
    pub const ACK: u8 = 0x01;
    /// Carry the device's full public key as the source.
    pub const FULL_SOURCE: u8 = 0x02;
    /// Carry a frame signature.
    pub const SIGNED: u8 = 0x04;
    /// Every flag defined; the rest are reserved and zero.
    pub const ALL: u8 = ACK | FULL_SOURCE | SIGNED;
}

/// `TX_OPTIONS` option numbers.
pub mod tx_opt {
    /// `TX_OPT_FLOOD_HOPS`: UINT8, 0 to 15.
    pub const FLOOD_HOPS: u32 = 1;
    /// `TX_OPT_SOURCE_ROUTE`: 1 to 15 router hints, next repeater first.
    pub const SOURCE_ROUTE: u32 = 2;
    /// `TX_OPT_TX_POWER`: INT8, dBm.
    pub const TX_POWER: u32 = 3;
}

/// `RX_FLAGS` bits.
pub mod rx_flag {
    /// `RX_SRC` is the sender's public key, not its hint.
    pub const SRC_KEY: u8 = 0x01;
    /// The sender is authenticated, by a pairwise MIC or a signature.
    pub const SENDER_AUTH: u8 = 0x02;
    /// The device acknowledged the message.
    pub const ACKED: u8 = 0x04;
    /// Unacknowledged messages were discarded since the last delivery.
    pub const GAP: u8 = 0x08;
    /// Delivered before, over a link whose session then ended.
    pub const REDELIVERED: u8 = 0x10;
}

/// `RX_OPTIONS` option numbers.
pub mod rx_opt {
    /// `RX_OPT_RSSI`: UINT8, the negated RSSI in dBm.
    pub const RSSI: u32 = 1;
    /// `RX_OPT_SNR`: INT16, centibels.
    pub const SNR: u32 = 2;
    /// `RX_OPT_TRACE`: the router hints of a complete trace, nearest
    /// repeater first.
    pub const TRACE: u32 = 3;
}

/// How a message is addressed: `TX_KIND` and `RX_KIND`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Unicast = 0,
    Broadcast = 1,
    BlindUnicast = 2,
    Multicast = 3,
}

impl Kind {
    /// The wire code for this kind.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Strict conversion from a decoded wire code.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Unicast),
            1 => Some(Self::Broadcast),
            2 => Some(Self::BlindUnicast),
            3 => Some(Self::Multicast),
            _ => None,
        }
    }

    /// Whether the metadata carries a channel identifier (kind bit 1).
    pub const fn has_channel(self) -> bool {
        self.code() & 0x02 != 0
    }

    /// Whether the message has one destination (kind bit 0 clear): a send
    /// names it, and only such a message can be acknowledged.
    pub const fn has_peer(self) -> bool {
        self.code() & 0x01 == 0
    }
}

/// Why node messaging metadata could not be honored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeMsgError {
    /// An unknown kind or flag, a flag the kind does not allow, an
    /// unrecognized or repeated option, or a value of the wrong length or
    /// out of range.
    Invalid,
    /// The metadata is cut short, or its entry list is malformed.
    Parse,
}

impl NodeMsgError {
    /// The status a device answers with.
    pub const fn status(self) -> Status {
        match self {
            Self::Invalid => Status::INVALID_ARGUMENT,
            Self::Parse => Status::PARSE_ERROR,
        }
    }
}

/// Split `len` octets off the front of `rest`.
fn take<'a>(rest: &mut &'a [u8], len: usize) -> Result<&'a [u8], NodeMsgError> {
    if rest.len() < len {
        return Err(NodeMsgError::Parse);
    }
    let (head, tail) = rest.split_at(len);
    *rest = tail;
    Ok(head)
}

fn take_array<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], NodeMsgError> {
    let bytes = take(rest, N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(bytes);
    Ok(array)
}

/// Whether `hints` is a well-formed source route or trace.
const fn valid_route(hints: &[u8]) -> bool {
    !hints.is_empty()
        && hints.len().is_multiple_of(ROUTER_HINT_LEN)
        && hints.len() <= MAX_ROUTE_HINTS * ROUTER_HINT_LEN
}

/// Parsed `Send` metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendMeta<'a> {
    pub kind: Kind,
    /// Request an acknowledgment.
    pub ack: bool,
    /// Carry the full public key as the source.
    pub full_source: bool,
    /// Carry a frame signature.
    pub signed: bool,
    /// The full channel identifier, for a kind with a channel.
    pub channel: Option<[u8; CHANNEL_IDENTIFIER_LEN]>,
    /// The destination's public key, for a kind with one destination.
    pub peer: Option<[u8; KEY_LEN]>,
    /// The flood budget, when given.
    pub flood_hops: Option<u8>,
    /// The router hints of a source route, next repeater first.
    pub source_route: Option<&'a [u8]>,
    /// The transmit power in dBm, when given.
    pub tx_power: Option<i8>,
}

impl<'a> SendMeta<'a> {
    /// A send of `kind` with no flags and no options. The addresses the
    /// kind calls for start out absent and must be filled in.
    pub const fn new(kind: Kind) -> Self {
        Self {
            kind,
            ack: false,
            full_source: false,
            signed: false,
            channel: None,
            peer: None,
            flood_hops: None,
            source_route: None,
            tx_power: None,
        }
    }

    /// The `TX_FLAGS` octet.
    pub const fn flags(&self) -> u8 {
        (if self.ack { tx_flag::ACK } else { 0 })
            | (if self.full_source {
                tx_flag::FULL_SOURCE
            } else {
                0
            })
            | (if self.signed { tx_flag::SIGNED } else { 0 })
    }

    /// Decode `Send` metadata.
    pub fn parse(metadata: &'a [u8]) -> Result<Self, NodeMsgError> {
        let mut rest = metadata;
        let [kind, flags] = take_array::<2>(&mut rest)?;
        let kind = Kind::from_code(kind).ok_or(NodeMsgError::Invalid)?;
        if flags & !tx_flag::ALL != 0 || (flags & tx_flag::ACK != 0 && !kind.has_peer()) {
            return Err(NodeMsgError::Invalid);
        }
        let mut meta = Self::new(kind);
        meta.ack = flags & tx_flag::ACK != 0;
        meta.full_source = flags & tx_flag::FULL_SOURCE != 0;
        meta.signed = flags & tx_flag::SIGNED != 0;
        if kind.has_channel() {
            meta.channel = Some(take_array(&mut rest)?);
        }
        if kind.has_peer() {
            meta.peer = Some(take_array(&mut rest)?);
        }

        let mut seen = 0u32;
        for entry in MultiEntries::new(rest) {
            let entry = entry.map_err(|_| NodeMsgError::Parse)?;
            let bit = match entry.key {
                tx_opt::FLOOD_HOPS | tx_opt::SOURCE_ROUTE | tx_opt::TX_POWER => 1u32 << entry.key,
                _ => return Err(NodeMsgError::Invalid),
            };
            if seen & bit != 0 {
                return Err(NodeMsgError::Invalid);
            }
            seen |= bit;
            match (entry.key, entry.value) {
                (tx_opt::FLOOD_HOPS, &[hops]) if hops <= MAX_FLOOD_HOPS => {
                    meta.flood_hops = Some(hops);
                }
                (tx_opt::SOURCE_ROUTE, hints) if valid_route(hints) => {
                    meta.source_route = Some(hints);
                }
                (tx_opt::TX_POWER, &[power]) => meta.tx_power = Some(power as i8),
                _ => return Err(NodeMsgError::Invalid),
            }
        }
        Ok(meta)
    }

    /// Append this metadata to a frame, after its `DATA`.
    ///
    /// The addresses written are the ones the kind calls for; a missing
    /// one is written as zeros, which no device holds a key for.
    pub fn write(&self, writer: &mut FrameWriter<'_>) -> Result<(), WriteError> {
        writer.write_u8(self.kind.code())?;
        writer.write_u8(self.flags())?;
        if self.kind.has_channel() {
            writer.write_bytes(&self.channel.unwrap_or_default())?;
        }
        if self.kind.has_peer() {
            writer.write_bytes(&self.peer.unwrap_or([0; KEY_LEN]))?;
        }
        if let Some(hops) = self.flood_hops {
            writer.write_entry(tx_opt::FLOOD_HOPS, &[hops])?;
        }
        if let Some(route) = self.source_route {
            writer.write_entry(tx_opt::SOURCE_ROUTE, route)?;
        }
        if let Some(power) = self.tx_power {
            writer.write_entry(tx_opt::TX_POWER, &[power as u8])?;
        }
        Ok(())
    }
}

/// The sender of a received message, as `RX_SRC` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The sender's public key.
    Key([u8; KEY_LEN]),
    /// The sender's node hint, for a multicast or broadcast message from
    /// a sender the device does not know.
    Hint([u8; HINT_LEN]),
}

/// `Recv` metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvMeta<'a> {
    pub kind: Kind,
    pub source: Source,
    /// The full channel identifier, for a kind with a channel.
    pub channel: Option<[u8; CHANNEL_IDENTIFIER_LEN]>,
    /// The sender is authenticated.
    pub sender_auth: bool,
    /// The device acknowledged the message.
    pub acked: bool,
    /// Unacknowledged messages were discarded since the last delivery.
    pub gap: bool,
    /// Delivered before, over a link whose session then ended.
    pub redelivered: bool,
    /// RSSI in dBm.
    pub rssi_dbm: Option<i16>,
    /// SNR in centibels.
    pub snr_cb: Option<i16>,
    /// The router hints of a complete trace, nearest repeater first.
    pub trace: Option<&'a [u8]>,
}

impl<'a> RecvMeta<'a> {
    /// The most octets `Recv` metadata occupies: kind and flags, a
    /// channel, a key, and every option at its largest.
    pub const MAX_LEN: usize = 2
        + CHANNEL_IDENTIFIER_LEN
        + KEY_LEN
        + (2 + 1)
        + (2 + 2)
        + (2 + MAX_ROUTE_HINTS * ROUTER_HINT_LEN);

    /// The `RX_FLAGS` octet.
    pub const fn flags(&self) -> u8 {
        (if matches!(self.source, Source::Key(_)) {
            rx_flag::SRC_KEY
        } else {
            0
        }) | (if self.sender_auth {
            rx_flag::SENDER_AUTH
        } else {
            0
        }) | (if self.acked { rx_flag::ACKED } else { 0 })
            | (if self.gap { rx_flag::GAP } else { 0 })
            | (if self.redelivered {
                rx_flag::REDELIVERED
            } else {
                0
            })
    }

    /// Append this metadata to a frame, after its `DATA`.
    ///
    /// A trace that is not a well-formed route is left out, so what the
    /// link copies into a reply is always a route it may send.
    pub fn write(&self, writer: &mut FrameWriter<'_>) -> Result<(), WriteError> {
        writer.write_u8(self.kind.code())?;
        writer.write_u8(self.flags())?;
        if self.kind.has_channel() {
            writer.write_bytes(&self.channel.unwrap_or_default())?;
        }
        match &self.source {
            Source::Key(key) => writer.write_bytes(key)?,
            Source::Hint(hint) => writer.write_bytes(hint)?,
        }
        if let Some(rssi) = self.rssi_dbm {
            let octet = rssi.saturating_neg().clamp(0, 254) as u8;
            writer.write_entry(rx_opt::RSSI, &[octet])?;
        }
        if let Some(snr) = self.snr_cb {
            writer.write_entry(rx_opt::SNR, &snr.to_le_bytes())?;
        }
        if let Some(trace) = self.trace.filter(|trace| valid_route(trace)) {
            writer.write_entry(rx_opt::TRACE, trace)?;
        }
        Ok(())
    }

    /// Decode `Recv` metadata. Unknown flags and options are ignored, and
    /// a known option whose value is misshaped is left out.
    pub fn parse(metadata: &'a [u8]) -> Result<Self, NodeMsgError> {
        let mut rest = metadata;
        let [kind, flags] = take_array::<2>(&mut rest)?;
        let kind = Kind::from_code(kind).ok_or(NodeMsgError::Invalid)?;
        let channel = if kind.has_channel() {
            Some(take_array(&mut rest)?)
        } else {
            None
        };
        let source = if flags & rx_flag::SRC_KEY != 0 {
            Source::Key(take_array(&mut rest)?)
        } else {
            Source::Hint(take_array(&mut rest)?)
        };
        let mut meta = Self {
            kind,
            source,
            channel,
            sender_auth: flags & rx_flag::SENDER_AUTH != 0,
            acked: flags & rx_flag::ACKED != 0,
            gap: flags & rx_flag::GAP != 0,
            redelivered: flags & rx_flag::REDELIVERED != 0,
            rssi_dbm: None,
            snr_cb: None,
            trace: None,
        };
        for entry in MultiEntries::new(rest) {
            let entry = entry.map_err(|_| NodeMsgError::Parse)?;
            match (entry.key, entry.value) {
                // As in `STR_PHY_RAW`, each has a value that says the
                // radio does not report it.
                (rx_opt::RSSI, &[rssi]) => {
                    meta.rssi_dbm = (rssi != 0xFF).then(|| -i16::from(rssi));
                }
                (rx_opt::SNR, &[lo, hi]) => {
                    let snr = i16::from_le_bytes([lo, hi]);
                    meta.snr_cb = (snr != i16::MIN).then_some(snr);
                }
                (rx_opt::TRACE, hints) if valid_route(hints) => meta.trace = Some(hints),
                _ => {}
            }
        }
        Ok(meta)
    }
}

/// Encode a `CMD_STR_SEND` on `STR_NODE_MSG`: `data` is the payload, type
/// octet first.
pub fn send_frame(
    buf: &mut [u8],
    tid: u8,
    data: &[u8],
    meta: &SendMeta<'_>,
) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, tid, Cmd::StrSend)?;
    stream_head(&mut writer, data)?;
    meta.write(&mut writer)?;
    Ok(writer.finish())
}

/// Encode a `CMD_STR_RECV` on `STR_NODE_MSG`: `data` is the payload, type
/// octet first.
pub fn recv_frame(buf: &mut [u8], data: &[u8], meta: &RecvMeta<'_>) -> Result<usize, WriteError> {
    let mut writer = FrameWriter::new(buf, TID_UNSOLICITED, Cmd::StrRecv)?;
    stream_head(&mut writer, data)?;
    meta.write(&mut writer)?;
    Ok(writer.finish())
}

fn stream_head(writer: &mut FrameWriter<'_>, data: &[u8]) -> Result<(), WriteError> {
    let len = u16::try_from(data.len()).map_err(|_| WriteError::ValueTooLarge)?;
    writer.write_pui(stream::NODE_MSG)?;
    writer.write_u16_le(len)?;
    writer.write_bytes(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{self, FRAME_IN_MAX, FRAME_OUT_MAX, Frame, StreamPayload};

    fn send_frame(buf: &mut [u8], data: &[u8], meta: &SendMeta<'_>) -> Result<usize, WriteError> {
        super::send_frame(buf, 1, data, meta)
    }

    fn parse_send(buf: &[u8]) -> Result<SendMeta<'_>, NodeMsgError> {
        let frame = Frame::parse(buf).unwrap();
        let payload = StreamPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.stream, stream::NODE_MSG);
        SendMeta::parse(payload.metadata)
    }

    const ROUTE: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

    #[test]
    fn every_kind_carries_the_addresses_it_calls_for() {
        let mut unicast = SendMeta::new(Kind::Unicast);
        unicast.peer = Some([0xAA; KEY_LEN]);
        unicast.ack = true;
        let mut broadcast = SendMeta::new(Kind::Broadcast);
        broadcast.signed = true;
        broadcast.full_source = true;
        let mut blind = SendMeta::new(Kind::BlindUnicast);
        blind.channel = Some([0xCC; CHANNEL_IDENTIFIER_LEN]);
        blind.peer = Some([0xAA; KEY_LEN]);
        blind.ack = true;
        let mut multicast = SendMeta::new(Kind::Multicast);
        multicast.channel = Some([0xCC; CHANNEL_IDENTIFIER_LEN]);
        multicast.flood_hops = Some(0);
        multicast.source_route = Some(&ROUTE);
        multicast.tx_power = Some(-3);

        for (meta, meta_len) in [(unicast, 34), (broadcast, 2), (blind, 50), (multicast, 30)] {
            let mut buf = [0u8; 128];
            let len = send_frame(&mut buf, &[3, 0xFF, b'h'], &meta).unwrap();
            let frame = Frame::parse(&buf[..len]).unwrap();
            let payload = StreamPayload::parse(frame.payload).unwrap();
            assert_eq!(payload.data, &[3, 0xFF, b'h']);
            assert_eq!(payload.metadata.len(), meta_len, "{:?}", meta.kind);
            assert_eq!(parse_send(&buf[..len]), Ok(meta));
        }
    }

    #[test]
    fn the_smallest_send_is_kind_and_flags() {
        assert_eq!(SendMeta::parse(&[1, 0]), Ok(SendMeta::new(Kind::Broadcast)));
        assert_eq!(SendMeta::parse(&[]), Err(NodeMsgError::Parse));
        assert_eq!(SendMeta::parse(&[1]), Err(NodeMsgError::Parse));
        // A unicast cut short of its key.
        assert_eq!(SendMeta::parse(&[0, 0, 1, 2, 3]), Err(NodeMsgError::Parse));
    }

    #[test]
    fn a_send_the_device_cannot_honor_is_refused() {
        let cases: [&[u8]; 4] = [
            // An unknown kind.
            &[4, 0],
            // A reserved flag.
            &[1, 0x08],
            // An acknowledged broadcast.
            &[1, tx_flag::ACK],
            // An acknowledged multicast.
            &[
                3,
                tx_flag::ACK,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        ];
        for metadata in cases {
            assert_eq!(
                SendMeta::parse(metadata),
                Err(NodeMsgError::Invalid),
                "{metadata:?}"
            );
        }
    }

    #[test]
    fn unknown_repeated_and_misshaped_options_are_refused() {
        let options: [&[(u32, &[u8])]; 8] = [
            &[(9, &[0])],
            &[(tx_opt::FLOOD_HOPS, &[1]), (tx_opt::FLOOD_HOPS, &[2])],
            &[(tx_opt::FLOOD_HOPS, &[MAX_FLOOD_HOPS + 1])],
            &[(tx_opt::FLOOD_HOPS, &[])],
            &[(tx_opt::SOURCE_ROUTE, &[])],
            &[(tx_opt::SOURCE_ROUTE, &[1, 2, 3])],
            &[(tx_opt::SOURCE_ROUTE, &[0; 2 * (MAX_ROUTE_HINTS + 1)])],
            &[(tx_opt::TX_POWER, &[1, 2])],
        ];
        for entries in options {
            let mut buf = [0u8; 64];
            let mut writer = FrameWriter::new(&mut buf, 0, Cmd::StrSend).unwrap();
            writer.write_u8(Kind::Broadcast.code()).unwrap();
            writer.write_u8(0).unwrap();
            for (key, value) in entries {
                writer.write_entry(*key, value).unwrap();
            }
            let len = writer.finish();
            assert_eq!(
                SendMeta::parse(&buf[2..len]),
                Err(NodeMsgError::Invalid),
                "{entries:?}"
            );
        }
        // An entry claiming four octets with two present.
        assert_eq!(
            SendMeta::parse(&[1, 0, 4, tx_opt::FLOOD_HOPS as u8, 1]),
            Err(NodeMsgError::Parse)
        );
    }

    #[test]
    fn a_received_message_round_trips() {
        let metas = [
            RecvMeta {
                kind: Kind::Unicast,
                source: Source::Key([0xAA; KEY_LEN]),
                channel: None,
                sender_auth: true,
                acked: true,
                gap: false,
                redelivered: true,
                rssi_dbm: Some(-91),
                snr_cb: Some(-53),
                trace: Some(&ROUTE),
            },
            RecvMeta {
                kind: Kind::Multicast,
                source: Source::Hint([1, 2, 3]),
                channel: Some([0xCC; CHANNEL_IDENTIFIER_LEN]),
                sender_auth: false,
                acked: false,
                gap: true,
                redelivered: false,
                rssi_dbm: None,
                snr_cb: None,
                trace: None,
            },
        ];
        for meta in metas {
            let mut buf = [0u8; 160];
            let len = recv_frame(&mut buf, &[0x80, 1, 2], &meta).unwrap();
            let frame = Frame::parse(&buf[..len]).unwrap();
            assert_eq!(frame.command(), Some(Cmd::StrRecv));
            let payload = StreamPayload::parse(frame.payload).unwrap();
            assert_eq!(RecvMeta::parse(payload.metadata), Ok(meta));
        }
    }

    #[test]
    fn a_receiver_ignores_what_it_does_not_know() {
        let mut buf = [0u8; 64];
        let mut writer = FrameWriter::new(&mut buf, 0, Cmd::StrRecv).unwrap();
        writer.write_u8(Kind::Broadcast.code()).unwrap();
        writer.write_u8(0x80).unwrap();
        writer.write_bytes(&[1, 2, 3]).unwrap();
        writer.write_entry(9, &[0; 5]).unwrap();
        writer.write_entry(rx_opt::TRACE, &[1, 2, 3]).unwrap();
        writer.write_entry(rx_opt::RSSI, &[80]).unwrap();
        let len = writer.finish();
        let meta = RecvMeta::parse(&buf[2..len]).unwrap();
        assert_eq!(meta.source, Source::Hint([1, 2, 3]));
        assert_eq!(meta.rssi_dbm, Some(-80));
        assert_eq!(meta.trace, None);
    }

    /// The largest message each kind can carry fits a ULCP frame in either
    /// direction, with every metadata field at its largest. A payload
    /// fills what the UMSH frame leaves it: 255 octets less the kind's
    /// smallest overhead (`umsh-core`'s builder: broadcast 5, unicast 29,
    /// multicast 28, blind unicast 31). A route or trace costs at least
    /// one octet more on the air than in the metadata less one, a flood
    /// budget one octet on the air, and a transmit power nothing; the
    /// payload is charged for the difference by not shrinking it at all.
    #[test]
    fn the_largest_messages_fit_a_frame() {
        const LORA_MAX: usize = 255;
        let route = [0x5A; MAX_ROUTE_HINTS * ROUTER_HINT_LEN];
        for (kind, overhead) in [
            (Kind::Broadcast, 5),
            (Kind::Unicast, 29),
            (Kind::Multicast, 28),
            (Kind::BlindUnicast, 31),
        ] {
            let data = [0xA5; LORA_MAX];
            let data = &data[..LORA_MAX - overhead];

            let mut send = SendMeta::new(kind);
            send.channel = kind.has_channel().then_some([0xCC; CHANNEL_IDENTIFIER_LEN]);
            send.peer = kind.has_peer().then_some([0xAA; KEY_LEN]);
            send.flood_hops = Some(MAX_FLOOD_HOPS);
            send.tx_power = Some(22);
            let mut buf = [0u8; FRAME_IN_MAX];
            let len = send_frame(&mut buf, data, &send).unwrap();
            // The route takes room from the payload on the air.
            let routed = &data[..data.len() - (route.len() + 1)];
            send.source_route = Some(&route);
            let routed_len = send_frame(&mut buf, routed, &send).unwrap();
            assert!(len.max(routed_len) <= FRAME_IN_MAX, "{kind:?}");

            let mut recv = RecvMeta {
                kind,
                source: Source::Key([0xAA; KEY_LEN]),
                channel: kind.has_channel().then_some([0xCC; CHANNEL_IDENTIFIER_LEN]),
                sender_auth: true,
                acked: true,
                gap: true,
                redelivered: true,
                rssi_dbm: Some(-120),
                snr_cb: Some(-200),
                trace: None,
            };
            let mut buf = [0u8; FRAME_OUT_MAX];
            let len = recv_frame(&mut buf, data, &recv).unwrap();
            assert!(len <= FRAME_OUT_MAX, "{kind:?}");
            recv.trace = Some(&route);
            let len = recv_frame(&mut buf, routed, &recv).unwrap();
            assert!(len <= FRAME_OUT_MAX, "{kind:?}");
        }
    }

    #[test]
    fn errors_carry_the_status_the_device_answers() {
        assert_eq!(NodeMsgError::Invalid.status(), Status::INVALID_ARGUMENT);
        assert_eq!(NodeMsgError::Parse.status(), Status::PARSE_ERROR);
        // The frame helpers agree with the hand-built frames above.
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        let len = frame::str_recv(&mut a, stream::NODE_MSG, &[1], &[1, 0, 1, 2, 3]).unwrap();
        let meta = RecvMeta {
            kind: Kind::Broadcast,
            source: Source::Hint([1, 2, 3]),
            channel: None,
            sender_auth: false,
            acked: false,
            gap: false,
            redelivered: false,
            rssi_dbm: None,
            snr_cb: None,
            trace: None,
        };
        assert_eq!(recv_frame(&mut b, &[1], &meta), Ok(len));
        assert_eq!(a[..len], b[..len]);
    }

    /// The values that say a radio reports no RSSI or SNR read as none,
    /// as they do in `STR_PHY_RAW`.
    #[test]
    fn unsupported_signal_values_read_as_absent() {
        let metadata = [
            Kind::Broadcast as u8,
            0,
            1,
            2,
            3,
            // Each entry: the length of what follows it, the option, the
            // value.
            2,
            rx_opt::RSSI as u8,
            0xFF,
            3,
            rx_opt::SNR as u8,
            0x00,
            0x80,
        ];
        let meta = RecvMeta::parse(&metadata).unwrap();
        assert_eq!(meta.source, Source::Hint([1, 2, 3]));
        assert_eq!((meta.rssi_dbm, meta.snr_cb), (None, None));
    }
}
