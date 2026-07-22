//! Built-in responder for the [Identity Request](crate::mac_command) MAC command.
//!
//! When enabled on a [`LocalNode`](crate::LocalNode), the node answers a
//! matching Identity Request with a **targeted authenticated unicast** carrying
//! its own [`NodeIdentityPayload`], echoing any request `NONCE` into identity
//! option 5. Responses are never signed and never fall back to broadcast: the
//! pairwise MIC, frame counter, and echoed nonce already make the reply
//! authentic and fresh, and a request whose source cannot be resolved to a key
//! is simply dropped by the MAC before the responder ever runs.
//!
//! The application supplies a [`NodeIdentityProfile`] (its role, capabilities,
//! and descriptive fields) and, optionally, a respond **policy** — a
//! registerable discriminator that inspects the [`IdentityRequestContext`] and
//! decides whether, and how, to answer (e.g. "known peers only", "only on a
//! given channel", "repeater → always"). No signing key is required.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use umsh_core::{ChannelId, NodeHint, PayloadType, PublicKey};
use umsh_mac::{PacketFamily, Snr};

use crate::identity::{NodeCapabilities, NodeIdentityPayload, NodeRole};
use crate::location::NodeLocation;
use crate::mac_command::IdentityRequestFilters;

/// This node's own identity, used to answer Identity Requests.
///
/// Holds descriptive fields only — **no signing key**. Config-like fields
/// (`role`, `capabilities`, `name`, `supported_regions`) are typically set once
/// at bring-up; live fields (`location`, `altitude_m`) can be refreshed at any
/// time via [`LocalNode::update_identity_profile`](crate::LocalNode::update_identity_profile),
/// e.g. from a GPS task.
#[derive(Clone, Debug)]
pub struct NodeIdentityProfile {
    /// This node's public key. Its [hint](PublicKey::hint) is matched against a
    /// request's `FILTER_NODE_HINT`; the key itself reaches the requester via
    /// the reply's MAC source address, not the identity payload.
    pub public_key: PublicKey,
    pub role: NodeRole,
    pub capabilities: NodeCapabilities,
    pub name: Option<String>,
    pub location: Option<NodeLocation>,
    pub altitude_m: Option<i32>,
    pub supported_regions: Option<Vec<u8>>,
}

impl NodeIdentityProfile {
    /// Create a minimal profile (role + capabilities), no descriptive options.
    pub fn new(public_key: PublicKey, role: NodeRole, capabilities: NodeCapabilities) -> Self {
        Self {
            public_key,
            role,
            capabilities,
            name: None,
            location: None,
            altitude_m: None,
            supported_regions: None,
        }
    }

    /// Set the display name (builder style).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the geographic location (builder style).
    pub fn with_location(mut self, location: NodeLocation) -> Self {
        self.location = Some(location);
        self
    }

    /// This node's hint, derived from its public key.
    pub fn hint(&self) -> NodeHint {
        self.public_key.hint()
    }

    /// Build the (unsigned) identity payload for a response, stamping `nonce`
    /// into option 5.
    fn to_payload(&self, nonce: Option<u32>) -> NodeIdentityPayload {
        NodeIdentityPayload {
            role: self.role,
            capabilities: self.capabilities,
            name: self.name.clone(),
            location: self.location,
            altitude_m: self.altitude_m,
            timestamp: None,
            supported_regions: self.supported_regions.clone(),
            nonce,
            signature: None,
        }
    }
}

/// Reception context for an incoming Identity Request, handed to the respond
/// policy so it can decide whether — and how — to answer.
///
/// The request has already passed the filter gate (its `FILTER_*` options
/// select this node) and its source has already been resolved to a key, so the
/// policy only governs the "do I want to answer *this sender*?" decision.
pub struct IdentityRequestContext<'a> {
    /// Resolved sender key. Always present: an unresolvable source is dropped
    /// before the policy runs.
    pub from_key: PublicKey,
    /// Sender hint, when the frame carried one.
    pub from_hint: Option<NodeHint>,
    /// Whether the request frame was authenticated (pairwise or channel MIC).
    pub source_authenticated: bool,
    /// Whether the request carried the sender's full 32-byte key.
    pub has_full_source: bool,
    /// The channel the request arrived on, if any (`None` for plain
    /// broadcast/unicast).
    pub channel: Option<ChannelId>,
    /// Coarse packet family (Unicast / Broadcast / Multicast / BlindUnicast).
    pub family: PacketFamily,
    /// The request's filter/option block, for policies that inspect it further.
    pub filters: IdentityRequestFilters<'a>,
    /// Received signal strength of the request, if measured.
    pub rssi: Option<i16>,
    /// Signal-to-noise ratio of the request, if measured.
    pub snr: Option<Snr>,
}

/// A respond policy's verdict for one Identity Request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespondDecision {
    /// Do not answer this request.
    Ignore,
    /// Answer with an authenticated unicast identity response.
    Respond {
        /// Include our full 32-byte key in the reply's source address, so a
        /// requester that only had our hint can authenticate the reply without
        /// a prior key exchange. Set `false` only when the requester already
        /// holds our key.
        full_source: bool,
    },
}

/// A registerable respond policy: given the request context, decide the verdict.
pub type RespondPolicy = dyn FnMut(&IdentityRequestContext<'_>) -> RespondDecision;

/// The default respond policy: answer every request that reached the policy.
///
/// Includes our full source key unless the request was authenticated to us
/// (an authenticated pairwise request implies the sender already holds our
/// key). The blind-unicast-over-channel case, where a channel-authenticated
/// sender may still lack our key, is a known edge a custom policy can override.
pub fn default_respond_policy(ctx: &IdentityRequestContext<'_>) -> RespondDecision {
    RespondDecision::Respond {
        full_source: !ctx.source_authenticated,
    }
}

/// Installed responder state: the profile plus the active policy.
pub(crate) struct IdentityResponder {
    pub(crate) profile: NodeIdentityProfile,
    pub(crate) policy: Box<RespondPolicy>,
}

/// A resolved plan to answer one Identity Request, produced synchronously while
/// the node state is borrowed and executed later by the async pump.
pub(crate) struct IdentityResponsePlan {
    /// Destination (the requester).
    pub(crate) to: PublicKey,
    /// Whether the reply should carry our full source key.
    pub(crate) full_source: bool,
    /// The framed reply payload: `PayloadType::NodeIdentity` + encoded identity.
    pub(crate) framed: Vec<u8>,
}

impl IdentityResponder {
    /// Evaluate an incoming request against the profile and policy.
    ///
    /// Returns `Some(plan)` when the node should answer: the request's filters
    /// select this node **and** the policy returns `Respond`. Returns `None`
    /// otherwise (not selected, policy said `Ignore`, or the reply could not be
    /// encoded).
    pub(crate) fn evaluate(
        &mut self,
        ctx: &IdentityRequestContext<'_>,
    ) -> Option<IdentityResponsePlan> {
        // Filter gate: does this request target a node like us?
        let our_hint = self.profile.hint();
        if !ctx
            .filters
            .selects(self.profile.role, self.profile.capabilities, &our_hint)
            .unwrap_or(false)
        {
            return None;
        }

        // Policy gate: do we want to answer this particular sender?
        let full_source = match (self.policy)(ctx) {
            RespondDecision::Ignore => return None,
            RespondDecision::Respond { full_source } => full_source,
        };

        // Build the framed reply, echoing the request nonce into option 5.
        let nonce = ctx.filters.nonce().ok().flatten();
        let payload = self.profile.to_payload(nonce);
        let mut buf = [0u8; 192];
        buf[0] = PayloadType::NodeIdentity as u8;
        let len = 1 + payload.encode(&mut buf[1..]).ok()?;
        Some(IdentityResponsePlan {
            to: ctx.from_key,
            full_source,
            framed: Vec::from(&buf[..len]),
        })
    }
}
