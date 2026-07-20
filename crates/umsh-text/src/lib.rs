#![allow(async_fn_in_trait)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Text-message support for UMSH.
//!
//! This crate implements the stateful text-message protocol once, for use by
//! both mobile applications and embedded pagers:
//!
//! - [`codec`]: exact wire bytes — borrowed decoding and encoding, with
//!   extension options preserved for profile-specific validation. Works
//!   without `alloc`.
//! - [`validate`]: semantic validation of a decoded message in conversation
//!   context, selected by a [`validate::TextProfile`].
//! - [`engine`]: a deterministic sans-I/O reducer owning sequence
//!   allocation, deduplication, fragmentation, reassembly, and bounded
//!   repair. It receives commands and emits effects and events; platform
//!   code owns presentation, storage, and transports.
//! - Node-layer convenience wrappers (feature `node`) for chat-style
//!   applications built directly on `umsh-node`.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(all(feature = "std", not(feature = "alloc")))]
compile_error!("feature `std` requires feature `alloc`");

pub mod codec;
mod error;
pub mod model;
pub mod validate;

pub mod engine;

#[cfg(feature = "alloc")]
mod owned;

#[cfg(feature = "node")]
mod node_adapter;

pub use error::{EncodeError, ParseError, TextSendError};
pub use model::{
    ConversationKey, ExtensionOptions, FRAGMENT_BODY_MAX, FRAGMENT_COUNT_MAX, Fragment,
    MessageSequence, MessageType, REASSEMBLED_BODY_MAX, Regarding, SenderScope, TextMessage,
    WireRef,
};

pub use codec::{ParseInfo, encode as encode_text_message, parse as parse_text_message};

#[cfg(feature = "alloc")]
pub use owned::{OwnedExtensionOptions, OwnedTextMessage};

#[cfg(feature = "node")]
pub use node_adapter::{TextReceiveIssue, UnicastTextChatWrapper, parse_text_payload};

#[cfg(all(feature = "node", feature = "software-crypto"))]
pub use node_adapter::MulticastTextChatWrapper;

/// Namespace for raw text-message codec functions.
pub mod text_message {
    pub use crate::codec::{encode, parse, parse_with_info};
}
