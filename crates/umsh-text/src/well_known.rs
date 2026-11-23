//! The protocol's two well-known channels, and the rules they carry
//! (UEP-0021 Default Groups).

use umsh_core::{ChannelKey, PacketType, PayloadType};

use crate::MessageType;

/// Why a text message on a well-known channel is not accepted or displayed
/// (UEP-0021). Such a message holds no position in its sender's stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Blind unicast on a well-known channel carries only repair requests
    /// for its group conversation; a one-to-one conversation is a unicast.
    BlindUnicast,
    /// `EMERGENCY` chat must be readable by every node in range.
    EncryptedEmergency,
    /// `EMERGENCY` chat must name its sender by full key.
    AnonymousEmergency,
    /// `EMERGENCY` chat must be signed by the key it names.
    UnsignedEmergency,
    /// `public` chat is shown only with its sender's full key.
    AnonymousPublic,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::BlindUnicast => "a well-known-channel text frame: blind unicast",
            Self::EncryptedEmergency => "an emergency-channel text frame: encrypted",
            Self::AnonymousEmergency => {
                "an emergency-channel text frame: missing its full source key"
            }
            Self::UnsignedEmergency => "an emergency-channel text frame: not signed by its sender",
            Self::AnonymousPublic => "a public-channel text frame: missing its full source key",
        })
    }
}

/// What the well-known channels' admission rules read of a received
/// channel frame ([`WellKnownChannels::refusal`]).
#[derive(Clone, Copy, Debug)]
pub struct ChannelFrame<'a> {
    pub packet_type: PacketType,
    /// The SCF's `E` bit.
    pub encrypted: bool,
    /// The FCF's `S` bit: the source is a full key, not a node hint.
    pub full_source: bool,
    /// A frame signature verified against the source key. Read only for a
    /// multicast text message on `EMERGENCY`, the one frame that must carry
    /// one, so a caller may leave it `false` without verifying anywhere
    /// else.
    pub signed: bool,
    /// The application payload, with its payload-type byte.
    pub payload: &'a [u8],
}

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
    pub const EMERGENCY_NAME: &str = crate::emergency::CHANNEL_NAME;

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

    /// Why a text message received on the channel `channel_key` names is
    /// not accepted or displayed, or `None` when it may be, or when the
    /// frame is not a text message on a well-known channel (UEP-0021):
    ///
    /// - On either, a text message by blind unicast is refused unless it is
    ///   a Message Resend Request carrying Group Resend.
    /// - On `EMERGENCY`, one that is encrypted, whose source is a node hint,
    ///   or that arrives by multicast without a verified signature.
    /// - On `public`, one by multicast whose source is a node hint.
    ///
    /// `channel_key` is the key that authenticated the frame, compared in
    /// full, as for [`Self::frame_signature_required`].
    pub fn refusal(&self, channel_key: &ChannelKey, frame: &ChannelFrame<'_>) -> Option<Refusal> {
        let body = text_body(frame.payload)?;
        let emergency = self.is_emergency(channel_key);
        if !emergency && !self.is_public(channel_key) {
            return None;
        }
        let multicast = match frame.packet_type {
            PacketType::Multicast => true,
            PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => false,
            _ => return None,
        };
        if !multicast && !is_group_resend_request(body) {
            return Some(Refusal::BlindUnicast);
        }
        if emergency {
            if frame.encrypted {
                return Some(Refusal::EncryptedEmergency);
            }
            if !frame.full_source {
                return Some(Refusal::AnonymousEmergency);
            }
            if multicast && !frame.signed {
                return Some(Refusal::UnsignedEmergency);
            }
        } else if multicast && !frame.full_source {
            return Some(Refusal::AnonymousPublic);
        }
        None
    }

    /// Whether `payload`, with its payload-type byte, may go by blind
    /// unicast on the channel `channel_key` names: anything but a text
    /// message, which on a well-known channel goes only as a Message Resend
    /// Request carrying Group Resend (UEP-0021).
    pub fn blind_unicast_permitted(&self, channel_key: &ChannelKey, payload: &[u8]) -> bool {
        !self.contains(channel_key) || text_body(payload).is_none_or(is_group_resend_request)
    }

    /// Whether a frame must carry a verified frame signature to be shown:
    /// text-protocol traffic multicast on `EMERGENCY`, whose readers act on
    /// who sent it. That is chat, resend responses and Message Unavailable
    /// alike.
    ///
    /// `channel_key` is the key that authenticated the frame, compared in
    /// full: a channel that only shares `EMERGENCY`'s identifier is another
    /// channel. `payload` is the application payload with its payload-type
    /// byte. A blind unicast never needs one, since its pairwise MIC already
    /// names the sender.
    pub fn frame_signature_required(
        &self,
        packet_type: PacketType,
        channel_key: Option<&ChannelKey>,
        payload: &[u8],
    ) -> bool {
        packet_type == PacketType::Multicast
            && channel_key.is_some_and(|key| self.is_emergency(key))
            && payload
                .first()
                .is_some_and(|&byte| PayloadType::from_byte(byte) == Some(PayloadType::TextMessage))
    }
}

/// The body of a text message, after its payload-type byte; `None` for any
/// other payload.
fn text_body(payload: &[u8]) -> Option<&[u8]> {
    let (&payload_type, body) = payload.split_first()?;
    (PayloadType::from_byte(payload_type) == Some(PayloadType::TextMessage)).then_some(body)
}

/// Whether a text message body is a Message Resend Request for its sender's
/// group conversation. One that cannot be decoded is not.
fn is_group_resend_request(body: &[u8]) -> bool {
    crate::codec::parse(body).is_ok_and(|message| {
        message.message_type == MessageType::ResendRequest && message.channel_group_resend
    })
}

#[cfg(test)]
mod tests {
    use super::{ChannelFrame, Refusal, WellKnownChannels};
    use umsh_core::{ChannelKey, PacketType, PayloadType};

    const PUBLIC: ChannelKey = ChannelKey([1; 32]);
    const EMERGENCY: ChannelKey = ChannelKey([2; 32]);

    fn well_known() -> WellKnownChannels {
        WellKnownChannels {
            public: PUBLIC,
            emergency: EMERGENCY,
        }
    }

    /// A text payload, with its payload-type byte.
    const TEXT: &[u8] = b"\x03\xFFFire on the ridge";

    #[test]
    fn emergency_text_multicast_needs_a_signature() {
        let payload = TEXT;
        assert!(well_known().frame_signature_required(
            PacketType::Multicast,
            Some(&EMERGENCY),
            payload
        ));
    }

    #[test]
    fn other_channels_and_families_do_not() {
        let well_known = well_known();
        let payload = TEXT;
        assert!(!well_known.frame_signature_required(
            PacketType::Multicast,
            Some(&PUBLIC),
            payload
        ));
        for packet_type in [
            PacketType::BlindUnicast,
            PacketType::BlindUnicastAckReq,
            PacketType::Unicast,
            PacketType::Broadcast,
        ] {
            assert!(
                !well_known.frame_signature_required(packet_type, Some(&EMERGENCY), payload),
                "{packet_type:?}"
            );
        }
        assert!(!well_known.frame_signature_required(PacketType::Multicast, None, payload));
    }

    #[test]
    fn a_key_sharing_the_identifier_is_not_emergency() {
        // Only the full key is compared, so any other key, whatever its
        // identifier, is another channel.
        let mut colliding = EMERGENCY;
        colliding.0[31] ^= 1;
        assert!(!well_known().frame_signature_required(
            PacketType::Multicast,
            Some(&colliding),
            TEXT
        ));
    }

    #[test]
    fn only_text_protocol_traffic() {
        let well_known = well_known();
        for payload in [
            &[][..],
            &[PayloadType::NodeIdentity as u8, 0][..],
            &[0xEE, 1, 2][..],
        ] {
            assert!(
                !well_known.frame_signature_required(
                    PacketType::Multicast,
                    Some(&EMERGENCY),
                    payload
                ),
                "{payload:?}"
            );
        }
    }

    /// A Message Resend Request with Group Resend, with its payload-type
    /// byte: Message Type 2, Message Sequence 5, Group Resend.
    const GROUP_RESEND: &[u8] = b"\x03\x01\x02\x21\x05\x60";

    fn frame(packet_type: PacketType, payload: &[u8]) -> ChannelFrame<'_> {
        ChannelFrame {
            packet_type,
            encrypted: false,
            full_source: true,
            signed: true,
            payload,
        }
    }

    #[test]
    fn group_resend_fixture_decodes() {
        let message = crate::codec::parse(&GROUP_RESEND[1..]).unwrap();
        assert_eq!(message.message_type, crate::MessageType::ResendRequest);
        assert!(message.channel_group_resend);
    }

    #[test]
    fn admission_on_the_well_known_channels() {
        let well_known = well_known();
        let multicast = frame(PacketType::Multicast, TEXT);
        for key in [PUBLIC, EMERGENCY] {
            assert_eq!(well_known.refusal(&key, &multicast), None);
            for packet_type in [PacketType::BlindUnicast, PacketType::BlindUnicastAckReq] {
                assert_eq!(
                    well_known.refusal(&key, &frame(packet_type, TEXT)),
                    Some(Refusal::BlindUnicast)
                );
                assert_eq!(
                    well_known.refusal(&key, &frame(packet_type, GROUP_RESEND)),
                    None
                );
            }
        }
        let hint = ChannelFrame {
            full_source: false,
            ..multicast
        };
        assert_eq!(
            well_known.refusal(&PUBLIC, &hint),
            Some(Refusal::AnonymousPublic)
        );
        assert_eq!(
            well_known.refusal(&EMERGENCY, &hint),
            Some(Refusal::AnonymousEmergency)
        );
        let encrypted = ChannelFrame {
            encrypted: true,
            ..multicast
        };
        assert_eq!(well_known.refusal(&PUBLIC, &encrypted), None);
        assert_eq!(
            well_known.refusal(&EMERGENCY, &encrypted),
            Some(Refusal::EncryptedEmergency)
        );
        let unsigned = ChannelFrame {
            signed: false,
            ..multicast
        };
        assert_eq!(well_known.refusal(&PUBLIC, &unsigned), None);
        assert_eq!(
            well_known.refusal(&EMERGENCY, &unsigned),
            Some(Refusal::UnsignedEmergency)
        );
        // A blind unicast needs no signature.
        let resend = ChannelFrame {
            signed: false,
            ..frame(PacketType::BlindUnicast, GROUP_RESEND)
        };
        assert_eq!(well_known.refusal(&EMERGENCY, &resend), None);
    }

    #[test]
    fn other_channels_and_payloads_are_not_judged() {
        let well_known = well_known();
        let anything = ChannelFrame {
            encrypted: true,
            full_source: false,
            signed: false,
            ..frame(PacketType::BlindUnicast, TEXT)
        };
        assert_eq!(well_known.refusal(&ChannelKey([3; 32]), &anything), None);
        let identity = [PayloadType::NodeIdentity as u8, 0];
        let not_text = ChannelFrame {
            payload: &identity,
            ..anything
        };
        assert_eq!(well_known.refusal(&EMERGENCY, &not_text), None);
    }

    #[test]
    fn only_group_resend_requests_go_by_blind_unicast() {
        let well_known = well_known();
        for key in [PUBLIC, EMERGENCY] {
            assert!(!well_known.blind_unicast_permitted(&key, TEXT));
            assert!(well_known.blind_unicast_permitted(&key, GROUP_RESEND));
            assert!(
                well_known.blind_unicast_permitted(&key, &[PayloadType::NodeIdentity as u8, 0])
            );
        }
        assert!(well_known.blind_unicast_permitted(&ChannelKey([3; 32]), TEXT));
    }
}
