//! The protocol's two well-known channels, and the rules they carry
//! (`multicast-channels.md` §Default Channels).

use umsh_core::{ChannelKey, PacketType, PayloadType};

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

#[cfg(test)]
mod tests {
    use super::WellKnownChannels;
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
}
