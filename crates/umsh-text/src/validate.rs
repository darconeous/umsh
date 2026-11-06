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
    /// A base option the message depends on could not be decoded.
    UndecodableOption(u16),
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
    /// Presentation options whose values could not be decoded and were
    /// dropped.
    pub dropped_presentation_mask: u16,
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
    /// Raw body bytes, which may not be valid UTF-8: the engine renders them
    /// lossily rather than lose the message.
    pub body: &'a [u8],
    /// A basic message that says it is a reply, in a Regarding this receiver
    /// could not interpret: a reply to an unknown message.
    pub unknown_regarding: bool,
    /// The message says it is an edit, in an Editing this receiver could not
    /// interpret: it stands as a message, the edit of something unknown.
    pub unknown_editing: bool,
    /// Why this receiver cannot present the message, when it cannot. The
    /// message still occupies its position in the sender's sequence.
    pub undisplayable: Option<ValidateError>,
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
        dropped_presentation_mask: info.undecodable_mask & PRESENTATION_MASK,
        ..ValidationNotes::default()
    };
    let fragmented = message.sequence.and_then(|sequence| sequence.fragment);
    let is_continuation = fragmented.is_some_and(|fragment| fragment.index > 0);

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
        _ => {}
    }

    // A message this receiver cannot present is still accounted for in the
    // sender's sequence, so its position is not repaired as a gap.
    // Continuations carry no message-level metadata of their own.
    let reading = if is_continuation {
        Reading::of_continuation(message)
    } else {
        Reading::of(profile, envelope, message, info, fragmented.is_some())
    };

    validate_extensions(profile, &message.extensions, &mut notes)?;

    let mut content = ContentMessage {
        message_type: reading.message_type,
        sender_handle: message.sender_handle,
        sequence: message.sequence,
        sequence_reset: message.sequence_reset,
        regarding: reading.regarding,
        editing: message.editing,
        bg_color: message.bg_color,
        text_color: message.text_color,
        extensions: message.extensions,
        body: message.body,
        unknown_regarding: reading.unknown_regarding,
        unknown_editing: reading.unknown_editing,
        undisplayable: reading.undisplayable,
    };

    if message.channel_group_resend {
        notes.ignored_channel_group_resend = true;
    }

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
    }

    Ok((Validated::Content(content), notes))
}

/// Base presentation options, which a message is complete without.
const PRESENTATION_MASK: u16 =
    (1 << option::SENDER_HANDLE) | (1 << option::BACKGROUND_COLOR) | (1 << option::TEXT_COLOR);

/// What a message-leading frame can be presented as, given what this
/// receiver could interpret of it.
///
/// Its sender sees it delivered, so a message with a body is always shown:
/// what could not be interpreted costs only its own meaning. A reaction is
/// the one exception, as without its target it has nowhere to go.
struct Reading {
    message_type: MessageType,
    regarding: Option<Regarding>,
    unknown_regarding: bool,
    unknown_editing: bool,
    undisplayable: Option<ValidateError>,
}

impl Reading {
    /// A continuation fragment, whose metadata belongs to fragment zero.
    fn of_continuation(message: &TextMessage<'_>) -> Self {
        Self {
            message_type: message.message_type,
            regarding: message.regarding,
            unknown_regarding: false,
            unknown_editing: false,
            undisplayable: None,
        }
    }

    fn of(
        profile: &dyn TextProfile,
        envelope: &Envelope,
        message: &TextMessage<'_>,
        info: &ParseInfo,
        fragmented: bool,
    ) -> Self {
        let type_reason = if info.undecodable(option::MESSAGE_TYPE) {
            Some(ValidateError::UndecodableOption(option::MESSAGE_TYPE))
        } else if !profile.recognizes_content_type(message.message_type) {
            Some(ValidateError::UnrecognizedMessageType(
                message.message_type.to_byte(),
            ))
        } else {
            None
        };
        let regarding_reason = if info.undecodable(option::REGARDING) {
            Some(ValidateError::UndecodableOption(option::REGARDING))
        } else {
            message
                .regarding
                .is_some_and(|regarding| !fits(regarding, &envelope.conversation))
                .then_some(ValidateError::RegardingWidth)
        };
        let editing_reason = info
            .undecodable(option::EDITING)
            .then_some(ValidateError::UndecodableOption(option::EDITING));

        let message_type = if type_reason.is_some() {
            MessageType::Basic
        } else {
            message.message_type
        };
        let reaction_lost = message_type == MessageType::Status && regarding_reason.is_some();
        // Later fragments may carry a body this one does not.
        let bodiless = message.body.is_empty() && !fragmented;
        let undisplayable = type_reason
            .or(regarding_reason)
            .or(editing_reason)
            .filter(|_| bodiless || reaction_lost);
        Self {
            message_type,
            regarding: if regarding_reason.is_some() {
                None
            } else {
                message.regarding
            },
            unknown_regarding: regarding_reason.is_some() && message_type == MessageType::Basic,
            unknown_editing: editing_reason.is_some(),
            undisplayable,
        }
    }
}

/// Whether a Regarding's form is one `conversation` uses.
fn fits(regarding: Regarding, conversation: &ConversationKey) -> bool {
    match regarding {
        Regarding::Multicast { .. } => conversation.uses_multicast_references(),
        Regarding::Own { .. } => conversation.is_one_to_one(),
        Regarding::Unicast { .. } => !conversation.uses_multicast_references(),
    }
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
