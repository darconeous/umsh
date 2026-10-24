#![cfg_attr(not(test), no_std)]

//! A communicator's durable chat state.
//!
//! - [`ChatStore`]: what a back end keeps—chats, messages, the resend
//!   archive, outbound checkpoints, peers, and channels—and the order it
//!   commits them in.
//! - [`Batch`]: one commit's worth of the text engine's outputs, in the
//!   order the store writes them.
//! - [`MemoryStore`]: the store worked on in memory, alone for tests, or
//!   over a [`Durable`] layer that keeps its records.
//! - [`FlashMapStore`] (feature `flash`): the store kept in a
//!   `sequential-storage` map on flash.
//! - [`conformance`]: the suite every back end passes, power cut between
//!   each step of the commit order included.
//! - [`CommunicatorNode`] (feature `node`): the node behind the interface,
//!   with the device's [`settings`] reached through its own ULCP session
//!   and its chats fed by the device node through [`task`].
//!
//! Device settings and security state are not stored here: the device
//! keeps the first, and the second stays with the MAC.

extern crate alloc;

mod batch;
#[cfg(feature = "node")]
mod chat;
mod durable;
#[cfg(feature = "flash")]
mod flash;
mod ids;
#[cfg(feature = "software-crypto")]
mod meet;
mod memory;
#[cfg(feature = "node")]
mod node;
mod reaction;
mod record;
#[cfg(feature = "node")]
pub mod settings;
mod store;
#[cfg(feature = "node")]
pub mod task;
mod wire;

#[cfg(any(test, feature = "conformance"))]
pub mod conformance;

pub use batch::{Batch, Change, CommitStep, Committed, Subject};
pub use durable::{Durable, Volatile};
#[cfg(feature = "flash")]
pub use flash::{FlashMap, FlashMapStore, RamFlash, RamFlashError, claim_partition};
pub use ids::{ChatId, MessageId, PeerId};
pub use memory::{MemoryStore, Quota};
pub use reaction::{CLUSTER_MAX, Cluster, REACTIONS, Reacted, Reaction, Reactions};
pub use record::{
    BODY_MAX, BuiltinChannel, ChannelAccess, ChannelChange, ChannelRecord, ChatChange, ChatRecord,
    Delivery, IDENTITY_MAX, LinkInfo, MessageFlags, MessageMeta, MessageRecord, NAME_MAX, Name,
    PeerChange, PeerFilter, PeerRecord, ROUTE_MAX, ReactorRecord, StoreError, Usage, WireAlias,
};
pub use store::ChatStore;

#[cfg(feature = "node")]
pub use chat::ChannelCrypto;
#[cfg(feature = "node")]
pub use node::{Clock, CommunicatorNode};
#[cfg(feature = "node")]
pub use umsh_text::chat::Seeds;
#[cfg(feature = "node")]
pub use umsh_text::node_adapter::WellKnownChannels;
