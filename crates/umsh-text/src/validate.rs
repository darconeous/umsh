//! Semantic validation of decoded text messages in conversation context.
//!
//! The codec guarantees only syntactic validity. This layer applies the rules
//! that depend on how a message arrived and which conversation it belongs to,
//! selected by a [`TextProfile`].

use crate::ParseError;
use crate::codec::ParseInfo;
use crate::model::{
    ConversationKey, ExtensionOptions, MessageSequence, MessageType, Regarding, SenderScope,
    TextMessage, option,
};

/// How a MAC-validated packet arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryPath {
    /// Individually addressed and pairwise authenticated.
    Unicast,
    /// Channel-addressed with a single logical destination.
    BlindUnicast,
    /// Channel-addressed group delivery.
    Multicast,
}

/// MAC-validated context for one received text payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub path: DeliveryPath,
    pub conversation: ConversationKey,
    pub sender: SenderScope,
}

/// Why a syntactically valid message was rejected in context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidateError {
    /// Propagated syntactic error (UTF-8 of a complete body, extension
    /// decoding).
    Parse(ParseError),
    /// A resend request arrived via multicast or broadcast.
    ResendRequestPath,
    /// A resend request did not carry a Message Sequence option.
    ResendRequestMissingSequence,
    /// The Channel Group Resend flag appeared on a resend request that did
    /// not arrive by blind-unicast.
    ChannelGroupResendPath,
    /// A Message Unavailable response did not carry a Message Sequence
    /// option.
    UnavailableMissingSequence,
    /// The Regarding option width does not match the conversation type.
    RegardingWidth,
    /// The message type is not recognized by the selected profile.
    UnrecognizedMessageType(u8),
    /// A recognized extension option was duplicated in a role where
    /// duplication is unresolvable.
    DuplicateExtensionOption(u16),
    /// A recognized extension option had an invalid value.
    InvalidExtensionOption(u16),
}

impl From<ParseError> for ValidateError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

/// Treatment of a duplicated recognized option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuplicateTreatment {
    /// Identity, sequencing, or reference semantics: duplication is fatal.
    Fatal,
    /// Presentation: first occurrence wins, later ones are diagnostics.
    FirstWins,
    /// Zero-length flag: duplicates are idempotent.
    Idempotent,
}

/// Profile contract selecting which message types and extension options a
/// deployment recognizes.
///
/// Profiles are static implementations; `umsh-chat-room` implements the room
/// profiles on top of this contract.
pub trait TextProfile {
    /// Whether a non-control message type is recognized as displayable
    /// content in this profile.
    fn recognizes_content_type(&self, message_type: MessageType) -> bool;

    /// Duplicate treatment for a recognized extension option, or `None` when
    /// the option is unrecognized (and therefore ignorable).
    fn extension_treatment(&self, number: u16) -> Option<DuplicateTreatment>;
}

/// Base profile for direct and channel conversations: base message types
/// only, no recognized extension options.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectChannelProfile;

impl TextProfile for DirectChannelProfile {
    fn recognizes_content_type(&self, message_type: MessageType) -> bool {
        matches!(message_type, MessageType::Basic | MessageType::Status)
    }

    fn extension_treatment(&self, _number: u16) -> Option<DuplicateTreatment> {
        None
    }
}

/// Non-fatal observations recorded during validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidationNotes {
    /// Presentation options that were duplicated (first occurrence kept).
    pub repeated_presentation_mask: u16,
    /// A continuation fragment carried message-level metadata options, which
    /// were ignored.
    pub ignored_continuation_metadata: bool,
    /// A Channel Group Resend flag appeared on a non-request message and was
    /// ignored.
    pub ignored_channel_group_resend: bool,
}

/// A displayable content message after contextual validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentMessage<'a> {
    pub message_type: MessageType,
    pub sender_handle: Option<&'a str>,
    pub sequence: Option<MessageSequence>,
    pub sequence_reset: bool,
    pub regarding: Option<Regarding>,
    pub editing: Option<u8>,
    pub bg_color: Option<[u8; 3]>,
    pub text_color: Option<[u8; 3]>,
    pub extensions: ExtensionOptions<'a>,
    /// Raw body bytes; guaranteed UTF-8 when the message is unfragmented.
    pub body: &'a [u8],
}

/// A validated received text payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Validated<'a> {
    Content(ContentMessage<'a>),
    /// A request to resend one frame from the selected archive stream.
    ResendRequest {
        sequence: MessageSequence,
        channel_group: bool,
    },
    /// The named frame is not available for resend.
    Unavailable {
        sequence: MessageSequence,
    },
}

/// Validate a decoded message in its conversation context.
pub fn validate<'a>(
    profile: &dyn TextProfile,
    envelope: &Envelope,
    message: &TextMessage<'a>,
    info: &ParseInfo,
) -> Result<(Validated<'a>, ValidationNotes), ValidateError> {
    let mut notes = ValidationNotes {
        repeated_presentation_mask: info.repeated_presentation_mask,
        ..ValidationNotes::default()
    };

    match message.message_type {
        MessageType::ResendRequest => {
            if !matches!(
                envelope.path,
                DeliveryPath::Unicast | DeliveryPath::BlindUnicast
            ) {
                return Err(ValidateError::ResendRequestPath);
            }
            let sequence = message
                .sequence
                .ok_or(ValidateError::ResendRequestMissingSequence)?;
            if message.channel_group_resend && envelope.path != DeliveryPath::BlindUnicast {
                return Err(ValidateError::ChannelGroupResendPath);
            }
            // All other options and the body are ignored once the required
            // fields validate.
            return Ok((
                Validated::ResendRequest {
                    sequence,
                    channel_group: message.channel_group_resend,
                },
                notes,
            ));
        }
        MessageType::MessageUnavailable => {
            let sequence = message
                .sequence
                .ok_or(ValidateError::UnavailableMissingSequence)?;
            if message.channel_group_resend {
                notes.ignored_channel_group_resend = true;
            }
            return Ok((Validated::Unavailable { sequence }, notes));
        }
        other => {
            if !profile.recognizes_content_type(other) {
                return Err(ValidateError::UnrecognizedMessageType(other.to_byte()));
            }
        }
    }

    if let Some(regarding) = message.regarding {
        let multicast_form = matches!(regarding, Regarding::Multicast { .. });
        if multicast_form != envelope.conversation.uses_multicast_references() {
            return Err(ValidateError::RegardingWidth);
        }
    }

    validate_extensions(profile, &message.extensions, &mut notes)?;

    let mut content = ContentMessage {
        message_type: message.message_type,
        sender_handle: message.sender_handle,
        sequence: message.sequence,
        sequence_reset: message.sequence_reset,
        regarding: message.regarding,
        editing: message.editing,
        bg_color: message.bg_color,
        text_color: message.text_color,
        extensions: message.extensions,
        body: message.body,
    };

    if message.channel_group_resend {
        notes.ignored_channel_group_resend = true;
    }

    let fragmented = message.sequence.and_then(|sequence| sequence.fragment);
    let is_continuation = fragmented.is_some_and(|fragment| fragment.index > 0);
    if is_continuation {
        // Continuation fragments carry only sequence metadata; message-level
        // metadata belongs to fragment zero and must be ignored here.
        let metadata_mask = (1 << option::MESSAGE_TYPE)
            | (1 << option::SENDER_HANDLE)
            | (1 << option::SEQUENCE_RESET)
            | (1 << option::REGARDING)
            | (1 << option::EDITING)
            | (1 << option::BACKGROUND_COLOR)
            | (1 << option::TEXT_COLOR);
        if info.seen_mask & metadata_mask != 0 || !message.extensions.is_empty() {
            notes.ignored_continuation_metadata = true;
        }
        content.message_type = MessageType::Basic;
        content.sender_handle = None;
        content.sequence_reset = false;
        content.regarding = None;
        content.editing = None;
        content.bg_color = None;
        content.text_color = None;
        content.extensions = ExtensionOptions::empty();
    } else if fragmented.is_none() {
        // Unfragmented content bodies must be complete UTF-8. Fragment bodies
        // (including fragment zero) are validated only after reassembly.
        core::str::from_utf8(message.body).map_err(|_| ParseError::InvalidUtf8)?;
    }

    Ok((Validated::Content(content), notes))
}

fn validate_extensions(
    profile: &dyn TextProfile,
    extensions: &ExtensionOptions<'_>,
    notes: &mut ValidationNotes,
) -> Result<(), ValidateError> {
    // Recognized extension options are singletons; track the ones seen in a
    // small fixed window relative to the extension base.
    let mut seen: u64 = 0;
    for item in extensions.iter() {
        let (number, _value) = item.map_err(ValidateError::Parse)?;
        let Some(treatment) = profile.extension_treatment(number) else {
            continue;
        };
        let bit_index = number - option::EXTENSION_BASE;
        if bit_index >= 64 {
            continue;
        }
        let bit = 1u64 << bit_index;
        if seen & bit != 0 {
            match treatment {
                DuplicateTreatment::Fatal => {
                    return Err(ValidateError::DuplicateExtensionOption(number));
                }
                DuplicateTreatment::FirstWins => {
                    notes.repeated_presentation_mask |= 1 << (number.min(15));
                }
                DuplicateTreatment::Idempotent => {}
            }
        }
        seen |= bit;
    }
    Ok(())
}
