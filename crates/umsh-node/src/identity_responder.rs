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

use heapless::Deque;
use umsh_core::{ChannelId, NodeHint, PayloadType, PublicKey, RouterHint};
use umsh_mac::{PacketFamily, RouteHops, Snr};

use crate::identity::{NodeCapabilities, NodeIdentityPayload, NodeRole};
use crate::location::NodeLocation;
use crate::mac_command::IdentityRequestFilters;

/// The narrowest and widest random hold applied to a reply to a
/// broadcast/multicast solicitation, per the Identity Request
/// flood-management rules. Every node the solicitation selected is answering
/// the same frame, so the hold spreads the replies across the window instead
/// of piling them onto one another.
///
/// A solicitation narrowed to a single node is exempt: there is no crowd to
/// spread, and holding the one reply would only make the answer late. See
/// [`IdentityRequestFilters::hint_names_one_node`].
pub(crate) const RESPONSE_MIN_DELAY_MS: u16 = 500;
pub(crate) const RESPONSE_MAX_DELAY_MS: u16 = 30_000;

/// How long one answered solicitation suppresses further replies to it.
///
/// A solicitation reaches a node once per path it travels, and the copies do
/// not arrive together: a repeater carrying the second copy holds it for its
/// own contention delay first. The window must also outlive the reply's own
/// random hold, since a duplicate landing while the first reply still sits in
/// the transmit queue is the case that queues a second one — so it is derived
/// from that hold rather than chosen independently.
///
/// An immediate reply is covered by the same window with room to spare, and
/// keeping one window for both cases costs nothing: it suppresses repeats of a
/// solicitation, and a requester wanting a fresh answer inside it asks with a
/// fresh nonce.
const SOLICITATION_SUPPRESSION_MS: u64 = RESPONSE_MAX_DELAY_MS as u64 * 2;

/// How many recently answered solicitations are remembered at once.
///
/// One entry per distinct solicitation, so this is how many separate
/// questions a node can be holding answers to at once. Overflow evicts the
/// oldest, which can then be answered twice — the pre-existing behavior
/// rather than a new failure.
const ANSWERED_CAPACITY: usize = 8;

/// One solicitation this node has already answered.
struct AnsweredSolicitation {
    /// The requester, by hint rather than full key: enough to tell two
    /// askers apart, and a collision costs one suppressed reply rather than
    /// anything worse.
    requester: NodeHint,
    /// The request's `NONCE`, when it carried one. This is what makes the
    /// entry name a *solicitation* and not merely a peer — a requester that
    /// wants another answer inside the window asks with a fresh nonce, which
    /// is what the nonce is for. A request that carries none cannot be told
    /// apart from a repeat of itself, so within the window it is treated as
    /// one.
    nonce: Option<u32>,
    answered_at_ms: u64,
}

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
    /// The regions this node floods for, in their string form. Trailing
    /// entries are dropped from an advertisement that would not otherwise
    /// fit (node-identity.md § Supported Regions).
    pub supported_regions: Option<Vec<String>>,
    /// Where identity option 3 comes from: the current Unix time, or
    /// `None` on a node that does not know what time it is.
    ///
    /// A source rather than a value, because option 3 dates the *payload*
    /// and every payload is built fresh — a stored number would be the
    /// time some earlier payload was built. It lives here so that the one
    /// canonical builder stamps every framing identically; a node with no
    /// clock keeps the default and simply omits the option.
    pub clock: fn() -> Option<u32>,
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
            clock: || None,
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

    /// Build the (unsigned) identity payload this node advertises,
    /// stamping `nonce` into option 5.
    ///
    /// The one canonical builder, deliberately shared by both framings of
    /// a node identity: the Identity Request reply, which carries a
    /// request nonce and is authenticated by the enclosing unicast, and
    /// the standalone signed blob, which carries no nonce and is
    /// authenticated by a detached signature. They are different objects
    /// on the wire and the same statement about the node; the difference
    /// must not be able to drift into the contents.
    pub fn to_payload(&self, nonce: Option<u32>) -> NodeIdentityPayload {
        NodeIdentityPayload {
            role: self.role,
            capabilities: self.capabilities,
            name: self.name.clone(),
            location: self.location,
            altitude_m: self.altitude_m,
            // Option 3 dates this payload, so it is read now rather than
            // carried: the freshness marker exists to stop a captured
            // identity being presented indefinitely, and a stamp copied
            // from an earlier build would be exactly that capture.
            timestamp: (self.clock)(),
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
    /// The request's accumulated trace route, as packed option bytes, or
    /// `None` when the request carried no trace-route option at all.
    ///
    /// Repeaters prepend their hint when forwarding, so this reads
    /// front-to-back as the path *back* to the requester and needs no
    /// reversal. It is the only route home a broadcast solicitation offers:
    /// broadcast reception registers no route with the MAC.
    ///
    /// Presence is kept distinct from emptiness because the two say different
    /// things: an empty option is a request that reached us without passing a
    /// repeater, while no option is a requester that asked for no path to be
    /// recorded. The reply mirrors the option the request carried, so it is
    /// the presence — not the hop count — that decides.
    pub trace_route: Option<&'a [u8]>,
    /// The request's accumulated trace signal, as packed option bytes, or
    /// `None` when the request carried no trace-signal option.
    ///
    /// Paired with the trace route entry for entry, and mirrored onto the
    /// reply on the same terms.
    pub trace_signal: Option<&'a [u8]>,
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

/// A respond policy that answers nothing.
///
/// Lets a node keep a live profile while declining to be discovered. The
/// profile is what unsolicited advertisements are built from, so silencing
/// the responder this way — rather than by uninstalling it — is what keeps
/// the two behaviors independent.
pub fn never_respond_policy(_ctx: &IdentityRequestContext<'_>) -> RespondDecision {
    RespondDecision::Ignore
}

/// Installed responder state: the profile, the active policy, and the record
/// of what has already been answered.
pub(crate) struct IdentityResponder {
    pub(crate) profile: NodeIdentityProfile,
    pub(crate) policy: Box<RespondPolicy>,
    /// Insertion-ordered, so the oldest entry is always at the front and
    /// expiry prunes from that end without a scan.
    answered: Deque<AnsweredSolicitation, ANSWERED_CAPACITY>,
}

impl IdentityResponder {
    pub(crate) fn new(profile: NodeIdentityProfile, policy: Box<RespondPolicy>) -> Self {
        Self {
            profile,
            policy,
            answered: Deque::new(),
        }
    }
}

/// A resolved plan to answer one Identity Request, produced synchronously while
/// the node state is borrowed and executed later by the async pump.
pub(crate) struct IdentityResponsePlan {
    /// Destination (the requester).
    pub(crate) to: PublicKey,
    /// Whether the reply should carry our full source key.
    pub(crate) full_source: bool,
    /// Whether the reply must be held for a random delay before transmit.
    ///
    /// Set for a broadcast/multicast solicitation that more than one node may
    /// satisfy, where every selected node answers the same frame and undelayed
    /// replies would collide on the channel. A request narrowed to a single
    /// node has no crowd to spread and is answered immediately.
    pub(crate) delayed: bool,
    /// Whether the reply must carry no flood hop count field at all.
    /// Set for a solicitation that no `FILTER_NODE_HINT` narrowed: such a
    /// request was confined to the requester's neighbours on the way in, and
    /// its reply stays there too rather than being flooded back.
    pub(crate) no_flood: bool,
    /// Routers to steer the reply back through, in send order; empty when the
    /// request arrived with no trace to follow.
    ///
    /// A steered solicitation is the case this exists for: the requester is
    /// several hops away, the reply carries no flood budget, and broadcast
    /// reception left the MAC with no cached route to them. The trace the
    /// request accumulated on the way in is the path home.
    pub(crate) route: Vec<RouterHint>,
    /// Whether the reply asks the repeaters that carry it to record
    /// themselves, mirroring the trace-route option the request arrived with.
    ///
    /// The request's trace taught this node a path home and taught the
    /// requester nothing (beacons.md § Path Discovery, bidirectional
    /// establishment): a broadcast solicitation registers no route with the
    /// requester's MAC, and the reply's own source route reaches it with every
    /// hint consumed, so without a trace the requester ends the exchange still
    /// holding no route back. The MAC's own discovery floor does not cover
    /// this: it reads a source route as a path already known, which is true of
    /// a cached route and not of one handed back from a stranger's trace.
    ///
    /// A reply no repeater may carry records nothing either way — the MAC
    /// drops the request on an unrepeatable frame rather than spending an
    /// option header on it — so a genuinely direct answer stays bare.
    pub(crate) trace_route: bool,
    /// Whether the reply also asks for per-hop signal quality, mirroring the
    /// request's trace-signal option on the same terms.
    pub(crate) trace_signal: bool,
    /// The channel to answer on, set when the request arrived as a blind
    /// unicast; `None` sends a plain unicast.
    ///
    /// A blind request hid both endpoints behind the channel, and a reply sent
    /// in the clear would name them. A multicast or broadcast solicitation
    /// carries a channel too but is answered by targeted unicast, which is what
    /// keeps one solicitation from drawing a crowd of channel-wide replies.
    pub(crate) channel: Option<ChannelId>,
    /// The framed reply payload: `PayloadType::NodeIdentity` + encoded identity.
    pub(crate) framed: Vec<u8>,
}

impl IdentityResponder {
    /// Evaluate an incoming request against the profile and policy.
    ///
    /// Returns `Some(plan)` when the node should answer: the request's filters
    /// select this node, the solicitation has not already been answered,
    /// **and** the policy returns `Respond`. Returns `None` otherwise (not
    /// selected, already answered, policy said `Ignore`, or the reply could
    /// not be encoded).
    pub(crate) fn evaluate(
        &mut self,
        ctx: &IdentityRequestContext<'_>,
        now_ms: u64,
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

        // Freshness gate: one reply per solicitation, however many copies of
        // it arrive. A plain broadcast request carries no frame counter, so
        // nothing below the node layer can recognize a second copy of one;
        // the echoed nonce is the only thing that names the question.
        let nonce = ctx.filters.nonce().ok().flatten();
        let requester = ctx.from_key.hint();
        self.expire_answered(now_ms);
        if self.already_answered(&requester, nonce) {
            return None;
        }

        // Policy gate: do we want to answer this particular sender?
        let full_source = match (self.policy)(ctx) {
            RespondDecision::Ignore => return None,
            RespondDecision::Respond { full_source } => full_source,
        };

        // Build the framed reply, echoing the request nonce into option 5.
        let payload = self.profile.to_payload(nonce);
        let mut buf = [0u8; 192];
        buf[0] = PayloadType::NodeIdentity as u8;
        let len = 1 + payload.encode_fitting(&mut buf[1..]).ok()?;
        let solicitation = matches!(
            ctx.family,
            crate::PacketFamily::Broadcast | crate::PacketFamily::Multicast
        );
        // Recorded only now that there is a reply to send: a request the
        // policy declined or the encoder could not frame was never answered,
        // and must not suppress a later attempt that would succeed.
        self.record_answered(requester, nonce, now_ms);
        // Repeaters prepend as they forward, so the accumulated trace already
        // reads as the path back and is copied verbatim rather than reversed.
        let route = RouteHops::new(ctx.trace_route.unwrap_or(&[])).collect::<Vec<_>>();
        Some(IdentityResponsePlan {
            to: ctx.from_key,
            full_source,
            delayed: solicitation && !ctx.filters.hint_names_one_node(),
            no_flood: solicitation && !ctx.filters.hint_filtered(),
            route,
            // A response mirrors the trace options its request carried,
            // whatever form the response takes; the MAC does the same for a
            // MAC ack and an Echo Response.
            trace_route: ctx.trace_route.is_some(),
            trace_signal: ctx.trace_signal.is_some(),
            channel: match ctx.family {
                PacketFamily::BlindUnicast => ctx.channel,
                _ => None,
            },
            framed: Vec::from(&buf[..len]),
        })
    }

    fn already_answered(&self, requester: &NodeHint, nonce: Option<u32>) -> bool {
        self.answered
            .iter()
            .any(|entry| entry.requester == *requester && entry.nonce == nonce)
    }

    /// Drop every entry older than the suppression window.
    ///
    /// A clock that has gone backwards leaves an entry looking younger than
    /// it is, never older, so suppression can only be held slightly too long
    /// — never released early, which is the direction that would let the
    /// duplicate replies back.
    fn expire_answered(&mut self, now_ms: u64) {
        while let Some(entry) = self.answered.front() {
            if now_ms.saturating_sub(entry.answered_at_ms) < SOLICITATION_SUPPRESSION_MS {
                return;
            }
            let _ = self.answered.pop_front();
        }
    }

    fn record_answered(&mut self, requester: NodeHint, nonce: Option<u32>, now_ms: u64) {
        if self.answered.is_full() {
            let _ = self.answered.pop_front();
        }
        let _ = self.answered.push_back(AnsweredSolicitation {
            requester,
            nonce,
            answered_at_ms: now_ms,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::location::NodeLocation;

    /// A profile's position reaches the wire, and every payload built
    /// from it is dated when it was built rather than carrying a stamp
    /// from some earlier one.
    #[test]
    fn a_profile_position_reaches_the_wire_dated_at_build_time() {
        let mut profile = NodeIdentityProfile::new(
            PublicKey([9; 32]),
            NodeRole::Tracker,
            NodeCapabilities::empty(),
        );
        let here = NodeLocation::from_e7(377_749_000, -1_224_194_000, 5);
        profile.location = Some(here);
        profile.altitude_m = Some(-17);
        profile.clock = || Some(1_785_000_000);

        let payload = profile.to_payload(None);
        let mut buf = [0u8; 192];
        let len = payload.encode(&mut buf).expect("encode");
        let decoded = NodeIdentityPayload::from_bytes(&buf[..len]).expect("decode");

        assert_eq!(decoded.location, Some(here));
        assert_eq!(decoded.altitude_m, Some(-17));
        assert_eq!(decoded.timestamp, Some(1_785_000_000));
    }

    /// A node that does not know what time it is omits option 3 rather
    /// than inventing a date for the payload.
    #[test]
    fn a_clockless_node_omits_the_timestamp() {
        let profile = NodeIdentityProfile::new(
            PublicKey([9; 32]),
            NodeRole::Tracker,
            NodeCapabilities::empty(),
        );
        assert_eq!(profile.to_payload(None).timestamp, None);
    }
}
