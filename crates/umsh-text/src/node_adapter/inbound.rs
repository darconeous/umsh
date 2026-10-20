//! Received frames to engine sources, with the channel display rules.

use alloc::vec::Vec;

use umsh_core::{ChannelKey, NodeHint, PayloadType, PublicKey, RouterHint};
use umsh_node::{PacketFamily, ReceivedPacketRef};

use crate::chat::{ChannelRegistry, TextSource};

/// The protocol's two well-known channels, which carry rules of their own
/// (`multicast-channels.md` §Default Channels).
///
/// Held by key, so a received frame is recognized by the key that
/// authenticated it, with no derivation per frame.
#[derive(Clone, Copy)]
pub struct WellKnownChannels {
    pub public: ChannelKey,
    pub emergency: ChannelKey,
}

impl WellKnownChannels {
    /// The canonical name of the `public` channel.
    pub const PUBLIC_NAME: &str = "public";
    /// The canonical name of the `EMERGENCY` channel, after case folding.
    pub const EMERGENCY_NAME: &str = "emergency";

    /// Derive both keys from their canonical names, rather than writing them
    /// down as literals that could drift from the derivation every other
    /// named channel goes through.
    #[cfg(feature = "software-crypto")]
    pub fn derive() -> Self {
        let key = |name| {
            *umsh_node::Channel::named(name)
                .expect("well-known channel names are short ASCII")
                .key()
        };
        Self {
            public: key(Self::PUBLIC_NAME),
            emergency: key(Self::EMERGENCY_NAME),
        }
    }

    pub fn is_public(&self, key: &ChannelKey) -> bool {
        key.0 == self.public.0
    }

    pub fn is_emergency(&self, key: &ChannelKey) -> bool {
        key.0 == self.emergency.0
    }

    /// Whether `key` is one of the two.
    pub fn contains(&self, key: &ChannelKey) -> bool {
        self.is_public(key) || self.is_emergency(key)
    }
}

/// Radio observations for a received frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RxSummary {
    pub rssi_dbm: Option<i16>,
    pub snr_centibels: Option<i16>,
    pub lqi: Option<u8>,
    /// Radio links the frame crossed to get here, counting the final one
    /// into this device. Absent for a frame source-routed without a trace
    /// route, whose hops nobody recorded.
    pub hop_count: Option<u8>,
    /// Intermediate-router hints in trace-route order: nearest us first,
    /// which is usable directly as a source route back.
    pub route_hints: Vec<RouterHint>,
    pub source_authenticated: bool,
    /// It came under a session with forward secrecy.
    pub forward_secret: bool,
    /// Seconds the frame spent queued on the radio before delivery; zero
    /// for a live reception.
    pub buffered_age_s: u32,
}

impl RxSummary {
    pub fn from_packet(packet: &ReceivedPacketRef<'_>) -> Self {
        Self {
            rssi_dbm: packet.rssi(),
            snr_centibels: packet.snr().map(|snr| snr.as_centibels()),
            lqi: packet.lqi().map(|lqi| lqi.get()),
            hop_count: packet.hop_count(),
            route_hints: packet.trace_route_hints().collect(),
            source_authenticated: packet.source_authenticated(),
            forward_secret: packet.forward_secret(),
            buffered_age_s: packet.rx().buffered_age_s(),
        }
    }
}

/// A text frame copied out of a receive callback.
///
/// The callback runs inside the node's pump, where the chat facade is not
/// at hand, so the channel is held by the key that authenticated the frame
/// until [`InboundText::source`] resolves it against the facade's channels.
#[derive(Clone)]
pub struct InboundText {
    origin: Origin,
    /// The text payload, without the payload-type byte.
    pub payload: Vec<u8>,
    pub received_at_ms: Option<u64>,
    pub rx: RxSummary,
}

#[derive(Clone, Copy)]
enum Origin {
    Direct {
        peer: PublicKey,
    },
    ChannelGroup {
        channel: ChannelKey,
        hint: NodeHint,
        full_key: Option<PublicKey>,
    },
    ChannelDirect {
        channel: ChannelKey,
        peer: PublicKey,
    },
}

impl InboundText {
    /// The key of the channel it came on, for a channel frame: one the node
    /// holds, since the key authenticated the frame.
    pub fn channel_key(&self) -> Option<ChannelKey> {
        match self.origin {
            Origin::Direct { .. } => None,
            Origin::ChannelGroup { channel, .. } | Origin::ChannelDirect { channel, .. } => {
                Some(channel)
            }
        }
    }

    /// Who sent it, with its channel named by tag. `None` when `channels`
    /// does not hold the channel—one the session has left.
    pub fn source(&self, channels: &ChannelRegistry) -> Option<TextSource> {
        Some(match self.origin {
            Origin::Direct { peer } => TextSource::Direct { peer },
            Origin::ChannelGroup {
                channel,
                hint,
                full_key,
            } => TextSource::ChannelGroup {
                channel: channels.tag_for(&channel)?,
                hint,
                full_key,
            },
            Origin::ChannelDirect { channel, peer } => TextSource::ChannelDirect {
                channel: channels.tag_for(&channel)?,
                peer,
            },
        })
    }
}

/// What a received frame is to a chat session.
#[derive(Clone)]
pub enum Inbound {
    /// A text message to feed the facade.
    Text(InboundText),
    /// Our own multicast, relayed back to us. It is the message we already
    /// have, not a second one, but it is evidence: something received our
    /// frame and forwarded it, the only reachability signal a multicast ever
    /// produces.
    Echo { hop_count: Option<u8> },
    /// A text frame the channel rules say must not be shown.
    Refused(Refusal),
}

/// Why a text frame was refused (`multicast-channels.md` §Default Channels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `EMERGENCY` chat must be readable by every node in range.
    EncryptedEmergency,
    /// `EMERGENCY` chat must name its sender by full key.
    AnonymousEmergency,
    /// `public` chat is shown only with its sender's full key.
    AnonymousPublic,
}

/// Classify a received frame for a chat session whose identity is
/// `local_key`.
///
/// `None` for anything that is not a text frame a chat session holds: another
/// payload type, a unicast or blind unicast without its sender's key, a
/// multicast without a claimed hint, or another packet family.
///
/// The checks on the well-known channels live here, at the chat layer, rather
/// than under the MAC: the requirements are about chat messages, and the MAC
/// is deliberately incurious about what it carries. A frame that fails one is
/// refused rather than shown unmarked—a message the reader would act on in an
/// emergency must not arrive with its origin or its reach in question.
/// `EMERGENCY` chat must also be signed, but the text-message format has no
/// signature yet, so that requirement is neither sent nor checked.
pub fn inbound_text(
    packet: &ReceivedPacketRef<'_>,
    local_key: &PublicKey,
    well_known: &WellKnownChannels,
) -> Option<Inbound> {
    if packet.payload_type() != PayloadType::TextMessage {
        return None;
    }
    let family = packet.packet_family();
    // Every group send carries our full source address, so a repeater's copy
    // arrives naming us. Scoped to multicast, because a directed frame naming
    // us is not an echo: a unicast reaches a receive handler only when it also
    // named a local identity as its destination, which makes it a message we
    // addressed to ourselves. That belongs in the transcript like any other.
    if family == PacketFamily::Multicast && packet.from_key() == Some(*local_key) {
        return Some(Inbound::Echo {
            hop_count: packet.hop_count(),
        });
    }
    let channel = packet.channel().map(|channel| *channel.key());
    if let Some(key) = &channel {
        if well_known.is_emergency(key) {
            if packet.encrypted() {
                return Some(Inbound::Refused(Refusal::EncryptedEmergency));
            }
            if !packet.has_full_source() || packet.from_key().is_none() {
                return Some(Inbound::Refused(Refusal::AnonymousEmergency));
            }
        } else if well_known.is_public(key)
            && family == PacketFamily::Multicast
            && !packet.has_full_source()
        {
            return Some(Inbound::Refused(Refusal::AnonymousPublic));
        }
    }
    let origin = match (family, channel) {
        (PacketFamily::Unicast, _) => Origin::Direct {
            peer: packet.from_key()?,
        },
        // Membership is what the channel MIC authenticates; the hint is the
        // only sender identity a multicast frame must carry.
        (PacketFamily::Multicast, Some(channel)) => Origin::ChannelGroup {
            channel,
            hint: packet.from_hint()?,
            full_key: packet.from_key(),
        },
        // Without a full key there is nobody to attribute the message to, and
        // nobody to answer a repair request to.
        (PacketFamily::BlindUnicast, Some(channel)) => Origin::ChannelDirect {
            channel,
            peer: packet.from_key()?,
        },
        _ => return None,
    };
    Some(Inbound::Text(InboundText {
        origin,
        payload: packet.payload().to_vec(),
        received_at_ms: packet.received_at_ms(),
        rx: RxSummary::from_packet(packet),
    }))
}
