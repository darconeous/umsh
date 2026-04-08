//! Umbrella crate that re-exports the UMSH workspace surface.
//!
//! In addition to re-exporting the core protocol crates, this crate defines the
//! [`Platform`] trait and optional runtime adapters for Tokio and Embassy.
//!
//! # Where to start
//!
//! Most applications should begin with:
//!
//! - [`node::Host`] to drive the shared MAC/runtime loop
//! - [`node::LocalNode`] as the per-identity send surface
//! - [`node::PeerConnection`] for peer-scoped interactions
//! - payload-level wrappers such as [`text::UnicastTextChatWrapper`] when they want
//!   app-specific convenience on top of raw packet callbacks
//!
//! Lower layers remain available when you need them:
//!
//! - [`mac`] for packet- and radio-facing coordinator control
//! - [`core`] for protocol types and packet parsing/building
//! - [`crypto`] and [`hal`] for platform integrations
//!
//! The intended receive boundary is low-level: node callbacks work with
//! [`node::ReceivedPacketRef`], and higher-level helpers live above that boundary rather than
//! inside the node core.

#[cfg(feature = "chat-rooms")]
pub use umsh_chat_room as chat_room;
pub use umsh_core as core;
pub use umsh_crypto as crypto;
pub use umsh_hal as hal;
pub use umsh_mac as mac;
pub use umsh_mac::Platform;
pub use umsh_node as node;
pub use umsh_text as text;
pub use umsh_uri as uri;

#[cfg(feature = "embassy-support")]
pub mod embassy_support;

#[cfg(feature = "software-crypto")]
pub mod test_vectors;

#[cfg(feature = "tokio-support")]
pub mod tokio_support;

pub mod prelude {
    //! Curated re-exports for the most common umbrella-crate entry points.
    //!
    //! This prelude intentionally favors the application-facing path:
    //! `Host -> LocalNode -> PeerConnection -> payload wrapper`.
    //!
    //! Lower-level MAC coordinator types remain available from [`crate::mac`], but are not
    //! pulled into the prelude by default.

    pub use crate::Platform;

    pub use umsh_core::{ChannelId, ChannelKey, PayloadType, PublicKey};
    pub use umsh_mac::{LocalIdentityId, PacketFamily, RouteHops, SendOptions};
    pub use umsh_node::{
        Capabilities, ChannelInfoRef, CommandId, Host, HostError, LocalNode, MacCommand, NodeError,
        NodeIdentityPayload, NodeRole, OwnedMacCommand, OwnedNodeIdentityPayload, PeerConnection,
        ReceivedPacketRef, RxMetadata, SendProgressTicket, SendToken, Snr, Subscription, Transport,
    };
    pub use umsh_text::{
        MessageSequence, MessageType, OwnedTextMessage, Regarding, TextMessage,
        UnicastTextChatWrapper,
    };

    #[cfg(feature = "software-crypto")]
    pub use umsh_node::{BoundChannel, Channel};

    #[cfg(feature = "software-crypto")]
    pub use umsh_text::MulticastTextChatWrapper;

    #[cfg(feature = "software-crypto")]
    pub use umsh_node::PfsStatus;
}
