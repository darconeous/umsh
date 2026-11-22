//! Reactions: emotes about a message, folded into it.
//!
//! The vocabulary is the text protocol's (`umsh_text::reaction`). The store
//! keeps the latest from each sender inside the target, and counts them by
//! reaction when the message is read.

use alloc::vec::Vec;

pub use umsh_text::reaction::{CLUSTER_MAX, Cluster, Reaction};

/// The most kinds of reaction a message counts.
pub const REACTIONS: usize = 8;

/// Everyone who reacted to a message one way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reacted {
    pub reaction: Reaction,
    pub count: u16,
    /// One of them is this node.
    pub mine: bool,
    /// This node's went under a session with forward secrecy.
    pub forward_secret: bool,
}

/// A message's reactions, one entry per reaction, in the order each first
/// appeared: at most [`REACTIONS`]. Kept on the heap, as a record holds
/// none until it is read.
pub type Reactions = Vec<Reacted>;
