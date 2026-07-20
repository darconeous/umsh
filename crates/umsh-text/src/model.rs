//! Wire-level model types for text messages.

use umsh_core::{ChannelId, NodeHint, PublicKey};

use crate::ParseError;

/// Text-message option numbers defined by the base specification.
pub mod option {
    pub const MESSAGE_TYPE: u16 = 0;
    pub const SENDER_HANDLE: u16 = 1;
    pub const MESSAGE_SEQUENCE: u16 = 2;
    pub const SEQUENCE_RESET: u16 = 3;
    pub const REGARDING: u16 = 4;
    pub const EDITING: u16 = 5;
    pub const BACKGROUND_COLOR: u16 = 6;
    pub const TEXT_COLOR: u16 = 7;
    pub const CHANNEL_GROUP_RESEND: u16 = 8;

    /// First option number outside the base text-message range.
    ///
    /// Options at or above this number are preserved as extension options for
    /// profile-specific validation (for example the chat-room Timestamp
    /// Received and Sender Sequence options).
    pub const EXTENSION_BASE: u16 = 9;
}

/// Maximum body bytes carried by a single fragment.
pub const FRAGMENT_BODY_MAX: usize = 160;

/// Maximum fragment count of a fragmented message (wire maximum).
pub const FRAGMENT_COUNT_MAX: u8 = 10;

/// Maximum reassembled body size of a fragmented message.
pub const REASSEMBLED_BODY_MAX: usize = FRAGMENT_BODY_MAX * FRAGMENT_COUNT_MAX as usize;

/// Text-message rendering/control type.
///
/// The type space is open: the base specification defines values 0–3, and
/// extensions (such as chat-room system events) define more. Unrecognized
/// values are preserved rather than rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Basic,
    Status,
    ResendRequest,
    MessageUnavailable,
    /// A message type outside the base range, preserved for profile-specific
    /// validation. Never constructed with values 0–3.
    Extension(u8),
}

impl MessageType {
    pub fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Basic,
            1 => Self::Status,
            2 => Self::ResendRequest,
            3 => Self::MessageUnavailable,
            other => Self::Extension(other),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Self::Basic => 0,
            Self::Status => 1,
            Self::ResendRequest => 2,
            Self::MessageUnavailable => 3,
            Self::Extension(value) => value,
        }
    }

    /// True for the control types that are not displayable content.
    pub fn is_control(self) -> bool {
        matches!(self, Self::ResendRequest | Self::MessageUnavailable)
    }
}

/// Fragment position carried by the 3-byte Message Sequence form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fragment {
    pub index: u8,
    pub count: u8,
}

/// Message Sequence option value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MessageSequence {
    pub message_id: u8,
    pub fragment: Option<Fragment>,
}

impl MessageSequence {
    pub fn unfragmented(message_id: u8) -> Self {
        Self {
            message_id,
            fragment: None,
        }
    }
}

/// Regarding option value: a reference to a previously sent message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regarding {
    /// 1-byte form used in one-to-one conversations and rooms.
    Unicast { message_id: u8 },
    /// 4-byte form used in channel-group conversations.
    Multicast {
        message_id: u8,
        source_prefix: NodeHint,
    },
}

impl Regarding {
    pub fn message_id(&self) -> u8 {
        match self {
            Self::Unicast { message_id } => *message_id,
            Self::Multicast { message_id, .. } => *message_id,
        }
    }
}

/// Zero-copy view over the extension options of a decoded text message.
///
/// Extension options are every option numbered at or above
/// [`option::EXTENSION_BASE`]. Because CoAP-style options are ordered by
/// number, they form a contiguous suffix of the option block, retained here
/// verbatim together with the option number in effect where the suffix begins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ExtensionOptions<'a> {
    pub(crate) base_number: u16,
    pub(crate) data: &'a [u8],
}

impl<'a> ExtensionOptions<'a> {
    /// A view containing no extension options.
    pub const fn empty() -> Self {
        Self {
            base_number: 0,
            data: &[],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Iterate over `(option number, value)` pairs.
    pub fn iter(&self) -> ExtensionOptionsIter<'a> {
        ExtensionOptionsIter {
            decoder: umsh_core::options::OptionDecoder::new(self.data),
            base_number: self.base_number,
        }
    }
}

pub struct ExtensionOptionsIter<'a> {
    decoder: umsh_core::options::OptionDecoder<'a>,
    base_number: u16,
}

impl<'a> Iterator for ExtensionOptionsIter<'a> {
    type Item = Result<(u16, &'a [u8]), ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.decoder.next()?;
        Some(
            item.map(|(delta_number, value)| (delta_number + self.base_number, value))
                .map_err(ParseError::from),
        )
    }
}

/// Borrowed decoded text message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextMessage<'a> {
    pub message_type: MessageType,
    pub sender_handle: Option<&'a str>,
    pub sequence: Option<MessageSequence>,
    pub sequence_reset: bool,
    pub regarding: Option<Regarding>,
    pub editing: Option<u8>,
    pub bg_color: Option<[u8; 3]>,
    pub text_color: Option<[u8; 3]>,
    pub channel_group_resend: bool,
    /// Options outside the base range, preserved verbatim for
    /// profile-specific validation.
    pub extensions: ExtensionOptions<'a>,
    /// Raw message body bytes.
    ///
    /// For unfragmented messages and complete reassembly this is UTF-8, but a
    /// single fragment of a fragmented message may end mid-code-point, so the
    /// codec exposes bytes; body text is validated where completeness is
    /// known.
    pub body: &'a [u8],
}

impl<'a> TextMessage<'a> {
    /// A basic text message with the given body and no options.
    pub fn basic(body: &'a str) -> Self {
        Self {
            message_type: MessageType::Basic,
            sender_handle: None,
            sequence: None,
            sequence_reset: false,
            regarding: None,
            editing: None,
            bg_color: None,
            text_color: None,
            channel_group_resend: false,
            extensions: ExtensionOptions::empty(),
            body: body.as_bytes(),
        }
    }

    /// The body as UTF-8 text, when valid.
    pub fn body_str(&self) -> Result<&'a str, ParseError> {
        core::str::from_utf8(self.body).map_err(|_| ParseError::InvalidUtf8)
    }
}

/// Identity of a conversation, independent of transport handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConversationKey {
    /// One-to-one unicast conversation with an authenticated peer.
    Direct { peer: PublicKey },
    /// The shared group conversation of a multicast channel.
    ChannelGroup { channel: ChannelId },
    /// One-to-one blind-unicast conversation over a channel key.
    ChannelDirect { channel: ChannelId, peer: PublicKey },
    /// Conversation with a chat-room node (reserved for the room adapter).
    Room { room: PublicKey },
}

impl ConversationKey {
    /// True when message references use the 4-byte multicast Regarding form.
    pub fn uses_multicast_references(&self) -> bool {
        matches!(self, Self::ChannelGroup { .. })
    }
}

/// The sender identity of a stream, as authenticated (or merely claimed) on
/// the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SenderScope {
    /// The local node.
    Local,
    /// An individually authenticated peer (unicast or blind-unicast).
    Peer(PublicKey),
    /// A multicast channel member identified only by its claimed source hint;
    /// the channel MIC authenticates membership, not this identity.
    ClaimedMember(NodeHint),
}

impl SenderScope {
    /// The 3-byte hint used for multicast Regarding references, when known.
    pub fn hint(&self) -> Option<NodeHint> {
        match self {
            Self::Local => None,
            Self::Peer(key) => Some(NodeHint([key.0[0], key.0[1], key.0[2]])),
            Self::ClaimedMember(hint) => Some(*hint),
        }
    }
}

/// A typed wire reference to a message, with explicit identity domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireRef {
    /// A reference scoped to a particular sender's stream in a conversation.
    SenderScoped { sender: SenderScope, message_id: u8 },
    /// A reference in a room's canonical numbering domain.
    RoomCanonical { message_id: u8 },
}
