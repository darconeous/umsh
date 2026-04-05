//! Umbrella crate that re-exports the UMSH workspace surface.
//!
//! In addition to re-exporting the core protocol crates, this crate defines the
//! [`Platform`] trait and optional runtime adapters for Tokio and Embassy.

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

    pub use crate::Platform;

    pub use umsh_app::{MacCommand, NodeIdentityPayload, PayloadRef, PayloadType, TextMessage};
    pub use umsh_core::{ChannelId, ChannelKey, PublicKey};
    pub use umsh_mac::{
        LocalIdentityId, Mac, MacEventRef, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions,
        SendReceipt,
    };
    pub use umsh_node::{
        EventSink, LocalNode, MacBackend, MacBackendError, NodeError, NodeEvent, NodeRuntime,
        PeerConnection, SendProgressTicket, SendToken, Transport,
    };

    #[cfg(feature = "software-crypto")]
    pub use umsh_node::{BoundChannel, Channel};

    #[cfg(feature = "software-crypto")]
    pub use umsh_node::{PfsSession, PfsSessionManager, PfsState};
}
