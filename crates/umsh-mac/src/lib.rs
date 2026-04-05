#![cfg_attr(not(feature = "std"), no_std)]

//! UMSH MAC-layer coordinator and supporting state types.
//!
//! This crate is the central runtime for the UMSH mesh protocol. It owns every piece of
//! radio-facing state and drives the full MAC lifecycle: receiving and authenticating
//! inbound frames, forwarding eligible frames as a repeater, issuing and verifying transport
//! ACKs, retransmitting unacknowledged sends, suppressing duplicates, enforcing replay
//! windows, managing frame-counter persistence, and servicing the outbound transmit queue.
//!
//! The crate is `no_std` compatible. All data structures are backed by
//! [`heapless`](https://docs.rs/heapless) fixed-capacity collections; capacity is controlled
//! by const-generic parameters on [`Mac`] so the compiler enforces sizing at build time with
//! zero heap allocation.
//!
//! # Architecture overview
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │  Application / upper layers                                    │
//! │  queue_broadcast / queue_unicast / queue_multicast / …         │
//! └──────────────────────────┬─────────────────────────────────────┘
//!                            │  SendOptions  →  SendReceipt
//!                            ▼
//! ┌────────────────────────────────────────────────────────────────┐
//! │  Mac<P>  (coordinator.rs)                                      │
//! │                                                                │
//! │  ┌─────────────────┐  ┌────────────────┐  ┌────────────────┐  │
//! │  │ IdentitySlot[N] │  │ PeerRegistry   │  │ ChannelTable   │  │
//! │  │  frame counters │  │  public keys   │  │  channel keys  │  │
//! │  │  pending ACKs   │  │  cached routes │  │  derived keys  │  │
//! │  │  pairwise keys  │  └────────────────┘  └────────────────┘  │
//! │  └─────────────────┘                                           │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │ TxQueue  (priority-ordered outbound frame buffer)        │  │
//! │  └──────────────────────────────────────────────────────────┘  │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │ DuplicateCache  │  ReplayWindow (per peer, per identity) │  │
//! │  └──────────────────────────────────────────────────────────┘  │
//! └──────────────────────────┬─────────────────────────────────────┘
//!                            │  async next_event()
//!                            ▼
//! ┌────────────────────────────────────────────────────────────────┐
//! │  Platform  (umsh-hal + umsh-crypto)                            │
//! │  Radio · Clock · Rng · Aes/Sha · CounterStore · KeyValueStore  │
//! └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules and key types
//!
//! ## [`coordinator`] — the top-level state machine
//!
//! [`Mac<P>`] is the single top-level type. Create one with [`Mac::new`], register
//! identities and peers, then drive it with `mac.next_event(&mut callbacks).await` in a
//! loop. Everything else in this crate exists to support `Mac`.
//!
//! Supporting types in this module:
//!
//! - [`LocalIdentityId`] — opaque slot index returned when registering a local keypair.
//! - [`LocalIdentity`] — either a long-term platform identity or an ephemeral software
//!   identity for PFS sessions.
//! - [`IdentitySlot`] — per-identity runtime state: keys, frame counter, pending ACKs.
//! - [`OperatingPolicy`] — transmission-time rules for the local node (amateur-radio mode,
//!   operator callsign, per-channel overrides).
//! - [`RepeaterConfig`] — controls whether and how inbound frames are forwarded.
//! - [`AmateurRadioMode`] — shared enum governing encryption and identification requirements
//!   under ham-radio law.
//! - [`ChannelPolicy`] — per-channel overrides within an [`OperatingPolicy`].
//! - [`SendError`], [`MacError`], [`CounterPersistenceError`] — error types for queuing,
//!   runtime event processing, and frame-counter store operations respectively.
//!
//! ## [`send`] — outbound transmission types
//!
//! - [`SendOptions`] — high-level parameters for a single send: MIC size, encryption,
//!   flood hops, ACK request, source route, salt, etc.
//! - [`SendReceipt`] — opaque token returned for ACK-requested sends; matched against
//!   inbound MAC ACKs to confirm delivery.
//! - [`TxQueue`] — priority-ordered, fixed-capacity queue of sealed frames waiting for
//!   radio transmission.
//! - [`QueuedTx`] — one entry in the transmit queue; includes frame bytes, priority,
//!   not-before timestamp, and CAD retry count.
//! - [`TxPriority`] — priority classes from highest (`ImmediateAck`) to lowest
//!   (`Application`).
//! - [`AckState`] — two-phase ACK lifecycle: `AwaitingForward` (listening for a repeater
//!   echo) followed by `AwaitingAck` (waiting for the destination's MAC ACK).
//! - [`PendingAck`] — full tracking record for one in-flight ACK-requested send, stored
//!   in the identity slot until delivery is confirmed or the deadline expires.
//! - [`ResendRecord`] — verbatim sealed frame bytes retained for retransmission without
//!   re-sealing.
//!
//! ## [`cache`] — duplicate suppression and replay protection
//!
//! - [`DuplicateCache`] — a fixed-size FIFO ring that records recently-seen
//!   [`DupCacheKey`] values. Before forwarding or delivering any received frame, the
//!   coordinator checks this cache; matching entries are silently dropped. Prevents
//!   re-delivery of frames that echoed back via multiple repeater paths.
//! - [`DupCacheKey`] — keyed on the truncated MIC for authenticated packets (unforgeable
//!   and compact) or a 32-bit hash of the frame body for unauthenticated ones (broadcast).
//! - [`ReplayWindow`] — per-peer, per-identity sliding window over frame counters. Rejects
//!   exact counter replays and frames older than the backtrack window, while tolerating
//!   a small amount of out-of-order delivery. Backed by a [`RecentMic`] ring for
//!   backward-window disambiguation.
//! - [`ReplayVerdict`] — outcome of a replay check: `Accept`, `Duplicate`, or `Replay`.
//!
//! ## [`peers`] — remote peer and channel registries
//!
//! - [`PeerRegistry`] — a flat list of [`PeerInfo`] records (public key + last-seen time +
//!   cached route). Looked up by hint or full key when matching inbound packets and routing
//!   outbound sends.
//! - [`PeerId`] — opaque index into the peer registry.
//! - [`CachedRoute`] — either an explicit source route or a flood-distance estimate,
//!   learned from successfully received packets and used to route future sends without
//!   flooding.
//! - [`PeerCryptoMap`] — per-identity map from [`PeerId`] to [`PeerCryptoState`]
//!   (established pairwise keys + replay window). One map per [`IdentitySlot`].
//! - [`ChannelTable`] — flat list of registered multicast channels. Each entry stores the
//!   raw channel key, the derived `k_enc`/`k_mic` keys (precomputed at registration time),
//!   and the 2-byte channel ID (also precomputed). Looked up by channel ID when
//!   authenticating inbound multicast and blind-unicast frames.
//!
//! ## [`handle`] — shared-ownership coordinator access
//!
//! - [`MacHandle`] — a `Copy`-able, lifetime-bounded reference to a `RefCell<Mac<P>>`.
//!   Designed for multi-task environments (e.g., `tokio` or RTOS task pairs) where one
//!   task runs the `next_event` loop while another enqueues sends or updates configuration
//!   without holding a long-lived mutable borrow.
//!
//! # Platform trait
//!
//! [`Platform`] is the single integration point. Implement it once per deployment target to
//! supply concrete driver types for all hardware abstractions:
//!
//! ```rust,ignore
//! struct MyPlatform;
//!
//! impl umsh_mac::Platform for MyPlatform {
//!     type Identity = MyHsmIdentity;
//!     type Aes      = MyAesDriver;
//!     type Sha      = MyShaDriver;
//!     type Radio    = MySx1262Driver;
//!     type Delay    = MyDelay;
//!     type Clock    = MyMonotonicClock;
//!     type Rng      = MyTrng;
//!     type CounterStore = MyFlashStore;
//!     type KeyValueStore = MyNvmStore;
//! }
//! ```
//!
//! The `umsh` workspace crate provides a `std`/`tokio`-backed implementation
//! (`tokio_support::StdPlatform`) suitable for desktop development and testing.
//!
//! # Frame-counter persistence
//!
//! UMSH uses a monotonic frame counter (not a timestamp) for replay protection. Because the
//! counter must never reuse a value, it must be committed to non-volatile storage before the
//! corresponding value is used on-air, or after a power cycle the counter could reset to a
//! previously-seen value, allowing old ciphertexts to replay. The coordinator manages this
//! automatically:
//!
//! 1. On startup, call [`Mac::load_persisted_counter`] for each long-term identity to read
//!    the last-committed boundary from the [`umsh_hal::CounterStore`] and set the live
//!    counter to the next safe starting point.
//! 2. At runtime, the coordinator schedules a persist whenever the live counter crosses a
//!    block boundary (every [`COUNTER_PERSIST_BLOCK_SIZE`] frames, default 128). While a
//!    persist is pending, sends will eventually block with [`SendError::CounterPersistenceLag`]
//!    if the store is not flushed in time.
//! 3. The application calls [`Mac::service_counter_persistence`] (typically from the
//!    `next_event` callback or a background task) to drain the pending write queue.
//!
//! # `no_std` usage
//!
//! Enable `default-features = false` in `Cargo.toml`. The crate compiles without the
//! standard library. All capacity limits are compile-time const generics. The `std` feature
//! enables [`test_support`], which provides software-backed driver stubs for unit testing.

use embedded_hal_async::delay::DelayNs;

pub(crate) const RECENT_MIC_CAPACITY: usize = 8;
pub(crate) const REPLAY_BACKTRACK_SLOTS: u32 = 8;
pub(crate) const REPLAY_STALE_MS: u64 = 5 * 60 * 1000;
pub(crate) const MAX_SOURCE_ROUTE_HOPS: usize = 15;
pub(crate) const MAX_RESEND_FRAME_LEN: usize = 256;
pub(crate) const DEFAULT_DUP_CACHE_SIZE: usize = 64;
pub(crate) const MAX_FORWARD_RETRIES: u8 = 3;
pub(crate) const MAX_CAD_ATTEMPTS: u8 = 5;

/// Default identity-slot capacity for the common `Mac<P>` configuration.
pub const DEFAULT_IDENTITIES: usize = 4;
/// Default remote-peer capacity for the common `Mac<P>` configuration.
pub const DEFAULT_PEERS: usize = 16;
/// Default shared-channel capacity for the common `Mac<P>` configuration.
pub const DEFAULT_CHANNELS: usize = 8;
/// Default pending-ACK capacity for the common `Mac<P>` configuration.
pub const DEFAULT_ACKS: usize = 16;
/// Default transmit-queue depth for the common `Mac<P>` configuration.
pub const DEFAULT_TX: usize = 16;
/// Default frame-buffer capacity for the common `Mac<P>` configuration.
pub const DEFAULT_FRAME: usize = MAX_RESEND_FRAME_LEN;
/// Default duplicate-cache capacity for the common `Mac<P>` configuration.
pub const DEFAULT_DUP: usize = DEFAULT_DUP_CACHE_SIZE;

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
