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
//! - payload-level wrappers such as [`node::UnicastTextChatWrapper`] when they want
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

pub use umsh_app as app;
pub use umsh_core as core;
pub use umsh_crypto as crypto;
pub use umsh_hal as hal;
pub use umsh_mac as mac;
pub use umsh_mac::Platform;
pub use umsh_node as node;

#[cfg(feature = "embassy-support")]
pub mod embassy_support;

#[cfg(feature = "software-crypto")]
pub mod test_vectors;

#[cfg(feature = "tokio-support")]
pub mod tokio_support;

pub mod prelude {
    //! Curated re-exports for the most common umbrella-crate entry points.
    //!
    //! This prelude favors the current application-facing surface:
    //! `Host -> LocalNode -> PeerConnection -> payload wrapper`.

    pub use crate::Platform;

    pub use umsh_app::{MacCommand, NodeIdentityPayload, PayloadType, TextMessage};
    pub use umsh_core::{ChannelId, ChannelKey, PublicKey};
    pub use umsh_mac::{
        LocalIdentityId, Mac, MacEventRef, MacHandle, OperatingPolicy, PacketFamily,
        RepeaterConfig, RouteHops, SendOptions, SendReceipt,
    };
    pub use umsh_node::{
        ChannelInfoRef, Host, HostError, LocalNode, MacBackend, MacBackendError, NodeError,
        PeerConnection, ReceivedPacketRef, SendProgressTicket, SendToken, Subscription,
        Transport, UnicastTextChatWrapper,
    };

    #[cfg(feature = "software-crypto")]
    pub use umsh_node::{BoundChannel, Channel, MulticastTextChatWrapper};

    #[cfg(feature = "software-crypto")]
    pub use umsh_node::{PfsSession, PfsSessionManager, PfsState, PfsStatus};
}
