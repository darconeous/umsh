#![cfg_attr(not(feature = "std"), no_std)]

pub(crate) const RECENT_MIC_CAPACITY: usize = 8;
pub(crate) const REPLAY_BACKTRACK_SLOTS: u32 = 8;
pub(crate) const REPLAY_STALE_MS: u64 = 5 * 60 * 1000;
pub(crate) const MAX_SOURCE_ROUTE_HOPS: usize = 15;
pub(crate) const MAX_RESEND_FRAME_LEN: usize = 256;
pub(crate) const DEFAULT_DUP_CACHE_SIZE: usize = 64;
pub(crate) const MAX_FORWARD_RETRIES: u8 = 3;
pub(crate) const MAX_CAD_ATTEMPTS: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityError;

mod cache;
mod coordinator;
mod handle;
mod peers;
mod send;

pub use cache::{DupCacheKey, DuplicateCache, RecentMic, ReplayVerdict, ReplayWindow};
pub use coordinator::{
    AmateurRadioMode, ChannelPolicy, IdentitySlot, LocalIdentity, LocalIdentityId, Mac, MacError,
    OperatingPolicy, RepeaterConfig, SendError,
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

#[cfg(test)]
mod tests;