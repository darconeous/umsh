#![cfg_attr(not(feature = "std"), no_std)]

//! UMSH MAC-layer coordinator and supporting state types.
//!
//! This crate owns the radio-facing protocol logic: secure packet processing,
//! repeater forwarding, duplicate suppression, replay windows, ACK handling,
//! route learning, and send queuing.

use embedded_hal_async::delay::DelayNs;

pub(crate) const RECENT_MIC_CAPACITY: usize = 8;
pub(crate) const REPLAY_BACKTRACK_SLOTS: u32 = 8;
pub(crate) const REPLAY_STALE_MS: u64 = 5 * 60 * 1000;
pub(crate) const MAX_SOURCE_ROUTE_HOPS: usize = 15;
pub(crate) const MAX_RESEND_FRAME_LEN: usize = 256;
pub(crate) const DEFAULT_DUP_CACHE_SIZE: usize = 64;
pub(crate) const MAX_FORWARD_RETRIES: u8 = 3;
pub(crate) const MAX_CAD_ATTEMPTS: u8 = 5;

/// Error returned when a fixed-capacity MAC data structure is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityError;

/// Bundle of platform-specific associated types used by the higher layers.
pub trait Platform {
    /// Local identity implementation.
    type Identity: umsh_crypto::NodeIdentity;
    /// AES provider implementation.
    type Aes: umsh_crypto::AesProvider;
    /// SHA/HMAC provider implementation.
    type Sha: umsh_crypto::Sha256Provider;
    /// Radio implementation.
    type Radio: umsh_hal::Radio;
    /// Async delay implementation.
    type Delay: DelayNs;
    /// Monotonic clock implementation.
    type Clock: umsh_hal::Clock;
    /// Random-number generator implementation.
    type Rng: rand::CryptoRng;
    /// Persistent frame-counter store implementation.
    type CounterStore: umsh_hal::CounterStore;
    /// General-purpose persistent key-value store implementation.
    type KeyValueStore: umsh_hal::KeyValueStore;
}

mod cache;
mod coordinator;
mod handle;
mod peers;
mod send;

pub use cache::{DupCacheKey, DuplicateCache, RecentMic, ReplayVerdict, ReplayWindow};
pub use coordinator::{
    AmateurRadioMode, ChannelPolicy, CounterPersistenceError, IdentitySlot, LocalIdentity,
    LocalIdentityId, Mac, MacError, OperatingPolicy, RepeaterConfig, SendError,
};
pub use handle::{MacHandle, MacHandleError};
pub use peers::{
    CachedRoute, ChannelState, ChannelTable, HintReplayState, PeerCryptoMap, PeerCryptoState,
    PeerId, PeerInfo, PeerRegistry,
};
pub use send::{
    AckState, MacEventRef, PendingAck, PendingAckError, QueuedTx, ResendRecord, SendOptions,
    SendReceipt, TxPriority, TxQueue,
};

#[cfg(feature = "std")]
pub mod test_support;

#[cfg(test)]
mod tests;
