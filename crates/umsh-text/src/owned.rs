//! Allocated convenience types (feature `alloc`).
//!
//! The borrowed [`TextMessage`] is the canonical representation; these types
//! exist for callers that want to hold messages beyond the life of a receive
//! buffer.

use alloc::string::String;
use alloc::vec::Vec;

use crate::model::{ExtensionOptions, MessageSequence, MessageType, Regarding, TextMessage};

/// Owned copy of a message's extension-option block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnedExtensionOptions {
    base_number: u16,
    data: Vec<u8>,
}

impl OwnedExtensionOptions {
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn as_borrowed(&self) -> ExtensionOptions<'_> {
        ExtensionOptions {
            base_number: self.base_number,
            data: &self.data,
        }
    }
}

impl From<ExtensionOptions<'_>> for OwnedExtensionOptions {
    fn from(value: ExtensionOptions<'_>) -> Self {
        Self {
            base_number: value.base_number,
            data: value.data.into(),
        }
    }
}

/// Owned counterpart of [`TextMessage`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedTextMessage {
    pub message_type: MessageType,
    pub sender_handle: Option<String>,
    pub sequence: Option<MessageSequence>,
    pub sequence_reset: bool,
    pub regarding: Option<Regarding>,
    pub editing: Option<u8>,
    pub bg_color: Option<[u8; 3]>,
    pub text_color: Option<[u8; 3]>,
    pub channel_group_resend: bool,
    pub extensions: OwnedExtensionOptions,
    pub body: Vec<u8>,
}

impl OwnedTextMessage {
    /// A basic text message with the given body and no options.
    pub fn basic(body: impl Into<String>) -> Self {
        Self::from(TextMessage::basic(&body.into()))
    }

    pub fn as_borrowed(&self) -> TextMessage<'_> {
        TextMessage {
            message_type: self.message_type,
            sender_handle: self.sender_handle.as_deref(),
            sequence: self.sequence,
            sequence_reset: self.sequence_reset,
            regarding: self.regarding,
            editing: self.editing,
            bg_color: self.bg_color,
            text_color: self.text_color,
            channel_group_resend: self.channel_group_resend,
            extensions: self.extensions.as_borrowed(),
            body: &self.body,
        }
    }

    /// The body as UTF-8 text, when valid.
    pub fn body_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.body).ok()
    }
}

impl From<TextMessage<'_>> for OwnedTextMessage {
    fn from(value: TextMessage<'_>) -> Self {
        Self {
            message_type: value.message_type,
            sender_handle: value.sender_handle.map(String::from),
            sequence: value.sequence,
            sequence_reset: value.sequence_reset,
            regarding: value.regarding,
            editing: value.editing,
            bg_color: value.bg_color,
            text_color: value.text_color,
            channel_group_resend: value.channel_group_resend,
            extensions: value.extensions.into(),
            body: value.body.into(),
        }
    }
}
