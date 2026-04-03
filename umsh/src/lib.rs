//! Umbrella crate that re-exports the current UMSH workspace surface.

use embedded_hal_async::delay::DelayNs;

pub use umsh_core as core;
pub use umsh_crypto as crypto;
pub use umsh_hal as hal;
pub use umsh_mac as mac;
pub use umsh_app as app;
pub use umsh_node as node;

pub trait Platform {
    type Identity: umsh_crypto::NodeIdentity;
    type Aes: umsh_crypto::AesProvider;
    type Sha: umsh_crypto::Sha256Provider;
    type Radio: umsh_hal::Radio;
    type Delay: DelayNs;
    type Clock: umsh_hal::Clock;
    type Rng: umsh_hal::Rng;
    type CounterStore: umsh_hal::CounterStore;
    type KeyValueStore: umsh_hal::KeyValueStore;
}

#[cfg(feature = "software-crypto")]
pub mod test_vectors;

pub mod prelude {
    //! Convenience re-exports for the full public surface of the umbrella crate.

    pub use umsh_core::*;
    pub use umsh_crypto::*;
    pub use umsh_hal::*;
    pub use umsh_mac::*;
    pub use umsh_app::{
        format_channel_key_uri, format_channel_name_uri, format_channel_name_uri_with_params,
        format_node_uri, parse_payload, parse_umsh_uri, split_payload_type, Capabilities,
        ChannelKeyUri, ChannelNameUri, ChannelParams, CommandId, Fragment, MacCommand,
        MessageSequence, MessageType, NodeIdentityPayload, NodeRole, NodeUri, PayloadRef,
        PayloadType, Regarding, TextMessage, UmshUri,
    };
    pub use umsh_node::{
        DeferredAction, Endpoint, EndpointConfig, EndpointEvent, EventAction, NodeMac,
        NodeMacError, OwnedMacCommand, OwnedNodeIdentityPayload, OwnedTextMessage,
        UiAcceptancePolicy,
    };

    #[cfg(feature = "software-crypto")]
    pub use umsh_node::{PfsSession, PfsSessionManager, PfsState};

    #[cfg(feature = "std")]
    pub use umsh_app::{EncodeError as AppEncodeError, ParseError as AppParseError};

    #[cfg(feature = "chat-rooms")]
    pub use umsh_app::{ChatAction, LoginParams, RoomInfo};
}
