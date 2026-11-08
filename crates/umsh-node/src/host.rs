use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use umsh_mac::{LocalIdentityId, SendOptions};

use crate::dispatch::EventDispatcher;
use crate::identity_responder::IdentityResponsePlan;
use crate::mac::MacBackend;
#[cfg(feature = "software-crypto")]
use crate::node::PfsLifecycle;
use crate::node::{LocalNode, LocalNodeState, NodeMembership};
use crate::receive::ReceivedPacketRef;
use crate::{NodeIdentityPayload, OwnedMacCommand, mac_command};
use umsh_core::{PayloadType, PublicKey};

/// Error returned when a [`Host`] cannot make progress.
///
/// Wraps the underlying MAC runtime failure.
#[derive(Debug)]
pub enum HostError<E> {
    Mac(E),
}

/// Multi-identity orchestration layer for the node API.
///
/// `Host` owns the shared MAC run loop and routes inbound events to the correct
/// [`LocalNode`], including ephemeral PFS identities that belong to a long-term node.
/// Applications typically:
///
/// 1. construct a `Host` from a shared [`MacHandle`](umsh_mac::MacHandle)
/// 2. register one or more [`LocalNode`]s with [`add_node`](Self::add_node)
/// 3. attach callbacks to nodes / peers / wrappers
/// 4. drive it with [`run`](Self::run)
///
/// # The pump is never cancelled
///
/// [`run`](Self::run) is the node's data pump. Run it as its own task, or as a sibling future
/// polled alongside the rest of the application, for as long as the node is up. Everything
/// else talks to the node through [`LocalNode`] and the handles made from it; a send through
/// one wakes the pump. Never race the pump as a losing `select!` arm or put it under a
/// timeout: a cycle in progress holds work in its own future—a frame just received, the
/// requests it carried, the replies they are owed—and dropping the future loses that work.
/// Dropping the pump is stopping the node, the way a power cut is.
///
/// The pump needs nothing from its caller between cycles. The deadlines the node layer keeps
/// (pings and forward-secrecy requests nobody answers, sessions that lapse) are wake sources
/// of the MAC's own, through [`MacBackend::wake_by`].
///
/// # Callback re-entrancy
///
/// Receive and control callbacks (`on_receive`, `on_text`, `on_ack_received`, …) are invoked
/// synchronously from inside the pump while the coordinator borrow is held. A callback
/// therefore MUST NOT call back into the MAC—it cannot `await` a `send`, and a blocking or
/// re-entrant borrow of the coordinator would deadlock. Keep callbacks short and
/// side-effect-free with respect to the MAC: record what you need (e.g. push to a queue or
/// set a flag) and perform any follow-up sends from your own task.
///
/// The node is not borrowed while its callbacks run, so a callback may subscribe or
/// unsubscribe, itself included. One added during an event first hears the next event, and
/// one removed during an event hears no more of it.
pub struct Host<M: MacBackend> {
    mac: M,
    dispatcher: Rc<RefCell<EventDispatcher>>,
    nodes: Vec<(LocalIdentityId, LocalNode<M>)>,
    pfs_control_options: SendOptions,
}

impl<M: MacBackend> Host<M> {
    /// Create a host around a shared MAC backend.
    pub fn new(mac: M) -> Self {
        Self {
            mac,
            dispatcher: Rc::new(RefCell::new(EventDispatcher::new())),
            nodes: Vec::new(),
            pfs_control_options: SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(5),
        }
    }

    /// Return a clone of the underlying shared MAC backend.
    pub fn mac(&self) -> M {
        self.mac.clone()
    }

    /// Borrow the send options used for node-managed PFS control messages.
    pub fn pfs_control_options(&self) -> &SendOptions {
        &self.pfs_control_options
    }

    /// Replace the send options used for node-managed PFS control messages.
    pub fn set_pfs_control_options(&mut self, options: SendOptions) {
        self.pfs_control_options = options;
    }

    /// Create and register a [`LocalNode`] for an already-registered local identity.
    ///
    /// The returned handle is cheap to clone and becomes the application-facing entry point
    /// for sending traffic and attaching callbacks for that identity.
    pub fn add_node(&mut self, identity_id: LocalIdentityId) -> LocalNode<M> {
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(
            identity_id,
            self.mac.clone(),
            self.dispatcher.clone(),
            membership,
            state,
        );
        self.nodes.push((identity_id, node.clone()));
        node
    }

    /// Look up a previously added node by identity id.
    pub fn node(&self, identity_id: LocalIdentityId) -> Option<LocalNode<M>> {
        self.nodes
            .iter()
            .find(|(id, _)| *id == identity_id)
            .map(|(_, node)| node.clone())
    }

    #[cfg(feature = "software-crypto")]
    fn route_node(&self, identity_id: LocalIdentityId) -> Option<LocalNode<M>> {
        if let Some(node) = self.node(identity_id) {
            return Some(node);
        }
        self.nodes
            .iter()
            .find(|(_, node)| node.owns_ephemeral_identity(identity_id))
            .map(|(_, node)| node.clone())
    }

    /// Drive the shared MAC until one wake cycle completes.
    ///
    /// This is a single wake-driven step, not a non-blocking poll. It waits until the MAC has
    /// meaningful work to do (radio activity or a protocol deadline), dispatches any resulting
    /// callbacks, services PFS command handling, and then returns.
    ///
    /// Not cancel-safe, and not meant to be: only [`run_with`](Self::run_with) calls it, and
    /// this crate's tests, through [`step`](Self::step).
    async fn pump_once(&mut self) -> Result<(), HostError<M::RunError>> {
        // The wait below may last indefinitely, so this is no time to stamp
        // what it delivers by: each frame carries the time the MAC received
        // it, and this stands in only for a backend that stamps none.
        let wait_began_ms = self.mac.now_ms().await;
        let pending_pfs = Rc::new(RefCell::new(Vec::<PfsCommand>::new()));
        let pending_pfs_ref = pending_pfs.clone();
        let pending_identity = Rc::new(RefCell::new(
            Vec::<(LocalNode<M>, IdentityResponsePlan)>::new(),
        ));
        let pending_identity_ref = pending_identity.clone();
        let pending_peer_repeaters = Rc::new(RefCell::new(Vec::<PeerRepeaterRequest<M>>::new()));
        let pending_peer_repeaters_ref = pending_peer_repeaters.clone();
        let pending_mobility = Rc::new(RefCell::new(Vec::<(umsh_core::PublicKey, bool)>::new()));
        let pending_mobility_ref = pending_mobility.clone();
        #[cfg(feature = "software-crypto")]
        let undelivered_pfs = Rc::new(RefCell::new(Vec::<(LocalNode<M>, PublicKey)>::new()));
        #[cfg(feature = "software-crypto")]
        let undelivered_pfs_ref = undelivered_pfs.clone();
        // Traffic for a retired session, answered once the event is done.
        let retired_heard = Rc::new(RefCell::new(
            Vec::<(LocalNode<M>, umsh_core::PublicKey)>::new(),
        ));
        let retired_heard_ref = retired_heard.clone();
        let dispatcher = self.dispatcher.clone();
        let nodes = self.nodes.clone();
        self.mac
            .next_event(move |identity_id, event| {
                dispatcher
                    .borrow_mut()
                    .dispatch_ticket_state(identity_id, &event);
                let Some(node) = route_node(&nodes, identity_id) else {
                    return;
                };
                match event {
                    umsh_mac::MacEventRef::Received(packet) => {
                        if !meet_admits(&node, identity_id, &packet) {
                            return;
                        }
                        // A frame under a session this node answered is the
                        // peer's word that it holds the session too.
                        #[cfg(feature = "software-crypto")]
                        if packet.sender_authenticated()
                            && let Some(from) = packet.from_key()
                            && let Some(peer) = node.note_pfs_frame(identity_id, &from)
                        {
                            node.dispatch_pfs_established(peer);
                        }
                        let _ = node.dispatch_received_packet(&packet);
                        if packet.payload_type() == umsh_core::PayloadType::Meet {
                            return;
                        }
                        if packet.packet_type() == umsh_core::PacketType::Broadcast
                            && packet.payload().is_empty()
                        {
                            if let Some(from_hint) = packet.from_hint() {
                                node.dispatch_beacon(from_hint, packet.from_key());
                            }
                        } else if let Some(from) = packet.from_key() {
                            dispatch_payload_callbacks(
                                &node,
                                &packet,
                                from,
                                &pending_pfs_ref,
                                &pending_identity_ref,
                                &pending_peer_repeaters_ref,
                                &pending_mobility_ref,
                                packet.received_at_ms().unwrap_or(wait_began_ms),
                            );
                        }
                    }
                    umsh_mac::MacEventRef::AckReceived { peer, receipt, .. } => {
                        let token = crate::SendToken::new(identity_id, receipt);
                        #[cfg(feature = "software-crypto")]
                        {
                            node.settle_pfs_close(token, true);
                            node.note_pfs_delivery(identity_id, true);
                        }
                        node.dispatch_ack_received(peer, token);
                    }
                    umsh_mac::MacEventRef::AckTimeout { peer, receipt } => {
                        let token = crate::SendToken::new(identity_id, receipt);
                        #[cfg(feature = "software-crypto")]
                        {
                            node.settle_pfs_close(token, false);
                            if let Some(session) = node.note_pfs_delivery(identity_id, false) {
                                undelivered_pfs_ref
                                    .borrow_mut()
                                    .push((node.clone(), session));
                            }
                        }
                        node.dispatch_ack_timeout(peer, token);
                    }
                    umsh_mac::MacEventRef::Transmitted { wire_bytes, .. } => {
                        node.dispatch_transmitted(wire_bytes);
                    }
                    umsh_mac::MacEventRef::Forwarded { .. } => {}
                    // Ticket resolution (failed + finished) is handled by
                    // dispatch_ticket_state above; there is no peer to
                    // notify since the frame never aired.
                    #[cfg_attr(not(feature = "software-crypto"), allow(unused_variables))]
                    umsh_mac::MacEventRef::TxAbandoned {
                        identity_id,
                        receipt,
                    } =>
                    {
                        #[cfg(feature = "software-crypto")]
                        if let Some(receipt) = receipt {
                            node.settle_pfs_close(
                                crate::SendToken::new(identity_id, receipt),
                                false,
                            );
                        }
                    }
                    umsh_mac::MacEventRef::RetiredAddressHeard { address } => {
                        retired_heard_ref.borrow_mut().push((node, address));
                    }
                }
            })
            .await
            .map_err(HostError::Mac)?;

        let queued: Vec<PfsCommand> = pending_pfs.borrow_mut().drain(..).collect();
        // Forward secrecy needs the software crypto back end; without it, a
        // peer's request goes unanswered.
        #[cfg(feature = "software-crypto")]
        for (identity_id, from, carriage, command) in queued {
            self.handle_pfs_command(identity_id, from, carriage, command)
                .await;
        }
        #[cfg(not(feature = "software-crypto"))]
        drop(queued);

        // Sessions whose sends kept going undelivered: the peer most
        // likely no longer holds its half.
        #[cfg(feature = "software-crypto")]
        {
            let undelivered: Vec<(LocalNode<M>, PublicKey)> =
                undelivered_pfs.borrow_mut().drain(..).collect();
            for (node, session) in undelivered {
                if let Some(peer) = node
                    .end_undelivered_pfs(&session, &self.pfs_control_options)
                    .await
                {
                    node.dispatch_pfs_ended(peer);
                }
            }
        }

        let heard: Vec<(LocalNode<M>, umsh_core::PublicKey)> =
            retired_heard.borrow_mut().drain(..).collect();
        #[cfg(feature = "software-crypto")]
        for (node, address) in heard {
            node.close_retired_pfs(&address, &self.pfs_control_options)
                .await;
        }
        #[cfg(not(feature = "software-crypto"))]
        drop(heard);

        let identity_replies: Vec<(LocalNode<M>, IdentityResponsePlan)> =
            pending_identity.borrow_mut().drain(..).collect();
        for (node, plan) in identity_replies {
            node.send_identity_response(plan).await;
        }

        let peer_repeater_requests: Vec<PeerRepeaterRequest<M>> =
            pending_peer_repeaters.borrow_mut().drain(..).collect();
        for (node, from, channel, request) in peer_repeater_requests {
            node.answer_peer_repeaters_request(from, channel, &request)
                .await;
        }

        let mobility: Vec<(umsh_core::PublicKey, bool)> =
            pending_mobility.borrow_mut().drain(..).collect();
        for (peer, mobile) in mobility {
            self.mac.set_peer_mobile(&peer, mobile).await;
        }

        self.service_protocol_timeouts().await;

        Ok(())
    }

    /// Fire the node-layer deadlines that have come, then ask the MAC to wake
    /// the pump by the earliest of those still ahead.
    ///
    /// Ping and PFS request timeouts have to fire even when the remote peer
    /// sends nothing at all, and a quiet radio wakes no one; the request
    /// makes the next deadline one of the MAC's own wake sources. A deadline
    /// set outside the pump asks for its own wake as it is set.
    async fn service_protocol_timeouts(&mut self) {
        let now_ms = self.mac.now_ms().await;
        service_node_timeouts(&self.nodes, now_ms).await;
        let next = self
            .nodes
            .iter()
            .filter_map(|(_, node)| node.next_deadline_ms())
            .min();
        if let Some(deadline_ms) = next {
            self.mac.wake_by(deadline_ms).await;
        }
    }

    /// One wake cycle, run to completion, for tests that script the MAC's
    /// events and check what each cycle did.
    #[cfg(test)]
    pub(crate) async fn step(&mut self) -> Result<(), HostError<M::RunError>> {
        self.pump_once().await
    }

    /// Run the node's data pump until the MAC fails.
    ///
    /// This is the one driver of a `Host`, and it is never cancelled; see
    /// [the type's documentation](Self#the-pump-is-never-cancelled). It
    /// returns only with the MAC's error.
    pub async fn run(&mut self) -> Result<(), HostError<M::RunError>> {
        self.run_with(async || {}).await
    }

    /// [`run`](Self::run), awaiting `after_cycle` each time a wake cycle
    /// completes.
    ///
    /// The hook runs inside the pump, at the one moment it is known to have
    /// just finished something and to hold no borrow of the coordinator:
    /// the place to republish what a cycle changes, such as the MAC's
    /// tallies. The next cycle waits for it, so keep it short.
    pub async fn run_with(
        &mut self,
        mut after_cycle: impl AsyncFnMut(),
    ) -> Result<(), HostError<M::RunError>> {
        // Deadlines set before the pump started ask for their wake here.
        self.service_protocol_timeouts().await;
        loop {
            self.pump_once().await?;
            after_cycle().await;
        }
    }

    #[cfg(feature = "software-crypto")]
    async fn handle_pfs_command(
        &mut self,
        identity_id: LocalIdentityId,
        from: PublicKey,
        carriage: PfsCarriage,
        command: OwnedMacCommand,
    ) {
        let Some(node) = self.route_node(identity_id) else {
            return;
        };

        match node
            .handle_pfs_command(&from, carriage, &command, &self.pfs_control_options)
            .await
        {
            Ok(Some(PfsLifecycle::Established(peer))) => node.dispatch_pfs_established(peer),
            Ok(Some(PfsLifecycle::Ended(peer))) => node.dispatch_pfs_ended(peer),
            Ok(Some(PfsLifecycle::Answered(_)) | None) => {}
            // Previously the error was dropped here, so a failed negotiation
            // (e.g. no ephemeral identity slot) left both sides silently stuck.
            // Surface it so applications can report the failure.
            Err(err) => node.dispatch_pfs_failed(from, err.pfs_failure()),
        }
        node.dispatch_pfs_records_changed();
    }
}

async fn service_node_timeouts<M: MacBackend>(
    nodes: &[(LocalIdentityId, LocalNode<M>)],
    now_ms: u64,
) {
    #[cfg(feature = "software-crypto")]
    for (_, node) in nodes {
        if let Ok(expired) = node.expire_pfs_sessions().await {
            for peer in expired {
                node.dispatch_pfs_ended(peer);
            }
        }
        // A retired session whose peer acknowledged its close has ended at
        // both ends; one past its lifetime just goes.
        for peer in node.settle_retired_pfs().await {
            node.dispatch_pfs_ended(peer);
        }
        // Abandon sent PFS requests that were never answered, so the
        // requester reports a timeout instead of sitting in `Requested`.
        for peer in node.expire_pfs_requests(now_ms) {
            node.dispatch_pfs_failed(peer, crate::node::PfsFailure::Timeout);
        }
        node.dispatch_pfs_records_changed();
    }

    for (_, node) in nodes {
        node.expire_pings(now_ms);
    }
}

fn route_node<M: MacBackend>(
    nodes: &[(LocalIdentityId, LocalNode<M>)],
    identity_id: LocalIdentityId,
) -> Option<LocalNode<M>> {
    let node = nodes
        .iter()
        .find(|(id, _)| *id == identity_id)
        .map(|(_, node)| node.clone());
    // An ephemeral identity answers for the node that made it.
    #[cfg(feature = "software-crypto")]
    let node = node.or_else(|| {
        nodes
            .iter()
            .find(|(_, node)| node.owns_ephemeral_identity(identity_id))
            .map(|(_, node)| node.clone())
    });
    node
}

/// Whether a received frame may reach the node at all, as far as contact
/// exchange (app-meet.md) is concerned.
///
/// A session identity takes Meet unicasts and nothing else: it must never
/// answer as the long-term node, so no identity response, forward secrecy,
/// or application payload goes through it. A Meet unicast reaches only a
/// session identity, and a Hello, being a broadcast, reaches the long-term
/// one. Meet frames that pass go to the node's receive handlers only.
fn meet_admits<M: MacBackend>(
    node: &LocalNode<M>,
    identity_id: LocalIdentityId,
    packet: &ReceivedPacketRef<'_>,
) -> bool {
    #[cfg(feature = "software-crypto")]
    let to_session = node.meet_identity() == Some(identity_id);
    #[cfg(not(feature = "software-crypto"))]
    let to_session = {
        let _ = (node, identity_id);
        false
    };
    let meet = packet.payload_type() == umsh_core::PayloadType::Meet;
    if !to_session && !meet {
        return true;
    }
    let unicast = packet.packet_type() != umsh_core::PacketType::Broadcast;
    meet && to_session == unicast
}

/// Whether an identity payload's claims are its sender's own: a signature
/// that verifies, or none on a frame whose sender authenticated. A channel
/// MIC alone never vouches for them: any member of the channel could have
/// written the payload.
#[cfg(feature = "software-crypto")]
pub fn identity_is_trustworthy(
    packet: &ReceivedPacketRef<'_>,
    from: &umsh_core::PublicKey,
    identity: &NodeIdentityPayload,
) -> bool {
    match identity.signature_state(from, packet.payload()) {
        crate::IdentitySignature::Valid => true,
        crate::IdentitySignature::Unsigned => packet.sender_authenticated(),
        crate::IdentitySignature::Invalid => false,
    }
}

/// Without the crypto to check a signature, only an unsigned payload on a
/// frame whose sender authenticated can be trusted.
#[cfg(not(feature = "software-crypto"))]
pub fn identity_is_trustworthy(
    packet: &ReceivedPacketRef<'_>,
    _from: &umsh_core::PublicKey,
    identity: &NodeIdentityPayload,
) -> bool {
    identity.signature.is_none() && packet.sender_authenticated()
}

/// Whether the frame carrying an identity shows that its owner is a direct
/// neighbor of this node, one hop away, on the air now.
///
/// Only an identity heard from its owner directly places the owner in this
/// node's repeater neighborhood: one that arrived forwarded says nothing
/// about whether the owner is a neighbor, one replayed from a device's
/// queue was heard minutes ago, and a copy of what this stack's own antenna
/// just sent came from nobody else. A host attached over a point-to-point
/// link is a neighbor with no radio between it and this node, so its
/// advertisement counts and carries no measurement.
///
/// The frame must also authenticate its sender, which for every such
/// frame means it passed replay detection: a verified frame signature, or
/// a unicast MIC. An embedded identity signature is not enough. It carries
/// no freshness, so an identity captured anywhere verifies wherever and
/// whenever it is put back on the air; it says who the node is, and is
/// believed as that, but not that the node is in range.
pub fn identity_heard_directly(packet: &ReceivedPacketRef<'_>) -> bool {
    packet.sender_authenticated()
        && packet.hop_count() == Some(1)
        && packet.rx().buffered_age_s() == 0
        && packet.rx().origin() != umsh_hal::RxOrigin::LocalTx
}

/// What a trusted identity that a frame carried may do to the details
/// already kept of its node.
///
/// Replay detection accepts a frame a little behind its sender's newest, so
/// an older advertisement delivered late must not roll newer details back.
/// Only a frame that authenticated its sender and advanced that sender's
/// established baseline speaks for the node as it is now.
///
/// This covers identities authenticated by their frame: advertisements and
/// identity responses. An identity imported by the user, from a QR code or
/// a contact exchange, applies as it always has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityUpdate {
    /// Replace what is kept.
    Replace,
    /// Keep a node not yet known, and fill in what is missing of one that
    /// is, but replace nothing.
    Fill,
}

impl IdentityUpdate {
    /// What the identity `packet` carried may do.
    pub fn of(packet: &ReceivedPacketRef<'_>) -> Self {
        if packet.sender_authenticated() && packet.in_order() {
            Self::Replace
        } else {
            Self::Fill
        }
    }
}

/// How an inbound PFS command arrived. The pump records it whether or not
/// forward secrecy is built in, so it lives here rather than in the PFS
/// module.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PfsCarriage {
    /// The channel a blind unicast arrived on: an answer follows it back.
    pub(crate) channel: Option<umsh_core::ChannelKey>,
    /// The frame counter it was sent under.
    pub(crate) counter: Option<u32>,
}

/// Work a pump cycle's synchronous dispatch leaves for after it returns.
type Deferred<T> = Rc<RefCell<Vec<T>>>;
/// A MAC command answered by the PFS machinery: identity, sender, how it
/// arrived, and the command.
type PfsCommand = (LocalIdentityId, PublicKey, PfsCarriage, OwnedMacCommand);
/// A Peer Repeaters Request to answer: the node asked, who asked, the channel
/// it arrived on, and the request's body.
type PeerRepeaterRequest<M> = (
    LocalNode<M>,
    umsh_core::PublicKey,
    Option<umsh_core::ChannelKey>,
    Vec<u8>,
);

#[allow(
    clippy::too_many_arguments,
    reason = "the deferred-work queues of one pump cycle"
)]
fn dispatch_payload_callbacks<M: MacBackend>(
    node: &LocalNode<M>,
    packet: &ReceivedPacketRef<'_>,
    from: umsh_core::PublicKey,
    pending_pfs: &Deferred<PfsCommand>,
    pending_identity: &Deferred<(LocalNode<M>, IdentityResponsePlan)>,
    pending_peer_repeaters: &Deferred<PeerRepeaterRequest<M>>,
    pending_mobility: &Deferred<(umsh_core::PublicKey, bool)>,
    received_at_ms: u64,
) {
    if packet.payload_type() == PayloadType::NodeIdentity {
        if let Ok(identity) = NodeIdentityPayload::from_bytes(packet.payload()) {
            let trusted = identity_is_trustworthy(packet, &from, &identity);
            let update = IdentityUpdate::of(packet);
            // Whether the node moves decides whether a route to it keeps a
            // flood hop of slack. That holds however the advertisement got
            // here, so long as the claim is the node's own. The MAC keeps
            // no "unknown", only "not mobile", so an identity that may only
            // fill can raise the flag but never lower it.
            let mobile = identity
                .capabilities
                .contains(crate::NodeCapabilities::MOBILE);
            if trusted && (mobile || update == IdentityUpdate::Replace) {
                pending_mobility.borrow_mut().push((from, mobile));
            }
            // Recorded before the callback so an observer that asks for the
            // peer-repeater listing from inside it sees this identity in it.
            if trusted && identity_heard_directly(packet) {
                node.observe_peer_identity(
                    from,
                    &identity,
                    update,
                    packet.rssi().zip(packet.snr()),
                    received_at_ms,
                );
            }
            node.dispatch_node_discovered(from, identity.name.as_deref());
        }
        return;
    }

    if packet.payload_type() == PayloadType::MacCommand
        && let Ok(command) = mac_command::parse(packet.payload())
    {
        // A MAC command is addressed to one node. A command that arrives by
        // multicast or broadcast is ignored unless its own definition gives
        // rules for that carriage (mac-commands.md), and today the Identity
        // Request is the only one that does. Anything else is dropped here,
        // before observers see it.
        let addressed_to_one_node = matches!(
            packet.packet_family(),
            umsh_mac::PacketFamily::Unicast | umsh_mac::PacketFamily::BlindUnicast
        );
        if !addressed_to_one_node
            && !matches!(command, mac_command::MacCommand::IdentityRequest { .. })
        {
            return;
        }
        // The carriage this request arrived on, which is the carriage its
        // response owes it back. `Some` only for a blind unicast: a plain
        // unicast is answered in kind, and the identity responder decides
        // for itself how to answer a multicast or broadcast solicitation.
        let reply_channel = matches!(packet.packet_family(), umsh_mac::PacketFamily::BlindUnicast)
            .then(|| packet.channel().map(|c| *c.key))
            .flatten();
        // Match borrowed variants before converting to owned.
        if let mac_command::MacCommand::EchoResponse { data } = command {
            node.match_pong(from, data, packet, received_at_ms);
        }
        // Identity Request: let the built-in responder (if enabled) build a
        // reply plan now, while the reception context is live; the async
        // pump sends it after this synchronous dispatch returns.
        if let mac_command::MacCommand::IdentityRequest { options } = command
            && let Some(plan) =
                node.evaluate_identity_request(packet, from, options, received_at_ms)
        {
            pending_identity.borrow_mut().push((node.clone(), plan));
        }
        // Peer Repeaters Request: the answer needs the MAC's transmitter
        // observations, which only an async borrow reaches, so it is
        // built by the pump after this synchronous dispatch returns.
        if let mac_command::MacCommand::PeerRepeatersRequest { options } = command
            && node.peer_repeaters_responder_enabled()
        {
            pending_peer_repeaters.borrow_mut().push((
                node.clone(),
                from,
                reply_channel,
                Vec::from(options),
            ));
        }
        let owned = OwnedMacCommand::from(command);
        node.dispatch_mac_command(from, &owned);
        if matches!(
            owned,
            OwnedMacCommand::PfsSessionRequest { .. }
                | OwnedMacCommand::PfsSessionResponse { .. }
                | OwnedMacCommand::EndPfsSession
        ) {
            let carriage = PfsCarriage {
                channel: reply_channel,
                counter: packet.header().sec_info.map(|info| info.frame_counter),
            };
            pending_pfs
                .borrow_mut()
                .push((node.identity_id(), from, carriage, owned));
        }
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use umsh_core::{
        ChannelId, ChannelKey, Fcf, PacketHeader, PacketType, ParsedOptions, PayloadType, PublicKey,
    };

    use super::{IdentityUpdate, identity_heard_directly, identity_is_trustworthy};
    use crate::identity::tests::signed_payload;
    use crate::location::NodeLocation;
    use crate::receive::{ChannelInfoRef, ReceivedPacketRef, RxAcceptance, SignatureStatus};
    use crate::{NodeCapabilities, NodeIdentityPayload, NodeRole, PeerRepeaterTable};

    const CHANNEL: ChannelKey = ChannelKey([0x5A; 32]);

    /// A frame of `packet_type` from `from` carrying the identity
    /// `payload`, as the MAC would deliver it: a unicast or multicast MIC
    /// authenticates its source, a broadcast has none.
    fn identity_frame(
        packet_type: PacketType,
        from: PublicKey,
        payload: &[u8],
        signature: SignatureStatus,
        acceptance: Option<RxAcceptance>,
    ) -> ReceivedPacketRef<'static> {
        let mut bytes = Vec::from([PayloadType::NodeIdentity as u8]);
        bytes.extend_from_slice(payload);
        let wire: &'static [u8] = alloc::boxed::Box::leak(bytes.into_boxed_slice());
        let multicast = packet_type == PacketType::Multicast;
        let channel_id = ChannelId([0x12, 0x34]);
        let header = PacketHeader {
            fcf: Fcf::new(packet_type, true, false),
            options_range: 0..0,
            flood_hops: None,
            dst: None,
            channel: multicast.then_some(channel_id),
            source: umsh_core::SourceAddrRef::Hint(from.hint()),
            sec_info: None,
            signature: None,
            body_range: 0..wire.len(),
            mic_range: wire.len()..wire.len(),
            total_len: wire.len(),
        };
        ReceivedPacketRef::new(
            wire,
            wire,
            header,
            ParsedOptions::default(),
            Some(from),
            Some(from.hint()),
            packet_type != PacketType::Broadcast,
            multicast.then_some(ChannelInfoRef {
                id: channel_id,
                key: &CHANNEL,
            }),
            umsh_mac::RxMetadata::default(),
        )
        .with_signature(signature)
        .with_acceptance(acceptance)
    }

    /// A signed broadcast advertisement, as the MAC judged it.
    fn signed_advert(
        from: PublicKey,
        payload: &[u8],
        acceptance: RxAcceptance,
    ) -> ReceivedPacketRef<'static> {
        identity_frame(
            PacketType::Broadcast,
            from,
            payload,
            SignatureStatus::Verified,
            Some(acceptance),
        )
    }

    fn trusted(packet: &ReceivedPacketRef<'_>, from: &PublicKey) -> bool {
        let identity = NodeIdentityPayload::from_bytes(packet.payload()).unwrap();
        identity_is_trustworthy(packet, from, &identity)
    }

    /// What the receive path does with an identity off the air: drop it
    /// unless trusted and heard directly, then keep it as its frame allows.
    fn hear(table: &mut PeerRepeaterTable, packet: &ReceivedPacketRef<'_>, now_ms: u64) {
        let from = packet.from_key().unwrap();
        let identity = NodeIdentityPayload::from_bytes(packet.payload()).unwrap();
        if identity_is_trustworthy(packet, &from, &identity) && identity_heard_directly(packet) {
            table.observe_identity(&from, &identity, IdentityUpdate::of(packet), None, now_ms);
        }
    }

    fn repeater(name: Option<&str>, location: Option<NodeLocation>) -> Vec<u8> {
        let identity = NodeIdentityPayload {
            role: NodeRole::Repeater,
            capabilities: NodeCapabilities::REPEATER,
            name: name.map(String::from),
            location,
            altitude_m: None,
            timestamp: None,
            supported_regions: None,
            nonce: None,
            signature: None,
        };
        let mut buf = [0u8; 128];
        let len = identity.encode(&mut buf).unwrap();
        buf[..len].to_vec()
    }

    fn kept(table: &PeerRepeaterTable) -> (Option<String>, Option<NodeLocation>) {
        let record = table.iter().next().expect("the repeater is listed");
        (record.name.clone(), record.location)
    }

    fn here() -> NodeLocation {
        NodeLocation::from_lat_lon(37.0, -122.0, 4)
    }

    const PEER: PublicKey = PublicKey([0x31; 32]);

    #[test]
    fn a_signed_advertisement_is_trusted_however_it_arrived() {
        let (key, payload) = signed_payload(0x31, NodeCapabilities::MOBILE);
        let unsigned_frame = identity_frame(
            PacketType::Broadcast,
            key,
            &payload,
            SignatureStatus::Unsigned,
            None,
        );
        assert!(trusted(&unsigned_frame, &key));
    }

    #[test]
    fn a_signature_that_fails_is_never_trusted() {
        let (_, payload) = signed_payload(0x31, NodeCapabilities::MOBILE);
        let impostor = PublicKey([0x55; 32]);
        let frame = identity_frame(
            PacketType::Broadcast,
            impostor,
            &payload,
            SignatureStatus::Verified,
            Some(RxAcceptance::Advanced),
        );
        assert!(!trusted(&frame, &impostor));
    }

    /// An unsigned bundle is trusted on its frame's signature.
    #[test]
    fn an_advertisement_is_trusted_on_its_frame_signature() {
        let payload = repeater(Some("Ridge"), None);
        let advert = signed_advert(PEER, &payload, RxAcceptance::Advanced);
        assert!(trusted(&advert, &PEER));
        let on_channel = identity_frame(
            PacketType::Multicast,
            PEER,
            &payload,
            SignatureStatus::Verified,
            Some(RxAcceptance::FirstContact),
        );
        assert!(trusted(&on_channel, &PEER));
    }

    /// A channel MIC proves only that the sender holds the channel key, so
    /// a channel-borne identity whose frame signature is missing or failed
    /// could have been written by any member.
    #[test]
    fn a_channel_borne_identity_needs_its_frame_signature() {
        let payload = repeater(Some("Ridge"), None);
        for signature in [SignatureStatus::Unsigned, SignatureStatus::NotVerified] {
            let frame = identity_frame(PacketType::Multicast, PEER, &payload, signature, None);
            assert!(frame.source_authenticated());
            assert!(!trusted(&frame, &PEER), "{signature:?}");
        }
        let broadcast = identity_frame(
            PacketType::Broadcast,
            PEER,
            &payload,
            SignatureStatus::Unsigned,
            None,
        );
        assert!(!trusted(&broadcast, &PEER));
    }

    /// A pairwise MIC authenticates its sender, so an identity response
    /// needs no signature of its own.
    #[test]
    fn an_identity_response_is_trusted_on_its_pairwise_mic() {
        let payload = repeater(Some("Ridge"), None);
        for packet_type in [PacketType::Unicast, PacketType::BlindUnicast] {
            let frame = identity_frame(
                packet_type,
                PEER,
                &payload,
                SignatureStatus::Unsigned,
                Some(RxAcceptance::Advanced),
            );
            assert!(trusted(&frame, &PEER));
        }
    }

    /// Only an authenticated frame that advanced its sender's baseline may
    /// replace what is kept.
    #[test]
    fn only_an_authenticated_frame_in_order_replaces() {
        let payload = repeater(Some("Ridge"), None);
        let update = |packet_type, signature, acceptance| {
            IdentityUpdate::of(&identity_frame(
                packet_type,
                PEER,
                &payload,
                signature,
                acceptance,
            ))
        };
        use IdentityUpdate::{Fill, Replace};
        use PacketType::{Broadcast, Multicast, Unicast};
        use RxAcceptance::{Advanced, Backfilled, FirstContact};
        use SignatureStatus::{NotVerified, Unsigned, Verified};
        assert_eq!(update(Broadcast, Verified, Some(Advanced)), Replace);
        assert_eq!(update(Multicast, Verified, Some(Advanced)), Replace);
        assert_eq!(update(Unicast, Unsigned, Some(Advanced)), Replace);
        assert_eq!(update(Broadcast, Verified, Some(FirstContact)), Fill);
        assert_eq!(update(Broadcast, Verified, Some(Backfilled)), Fill);
        assert_eq!(update(Unicast, Unsigned, Some(Backfilled)), Fill);
        assert_eq!(update(Multicast, NotVerified, None), Fill);
        assert_eq!(update(Broadcast, Unsigned, None), Fill);
    }

    /// Advertisement 102 is applied, then the never-seen 101 arrives in the
    /// backward window: it fills what 102 lacked and replaces nothing.
    #[test]
    fn a_reordered_advertisement_only_fills() {
        let mut table = PeerRepeaterTable::new();
        hear(
            &mut table,
            &signed_advert(PEER, &repeater(Some("Old"), None), RxAcceptance::Advanced),
            100,
        );
        hear(
            &mut table,
            &signed_advert(PEER, &repeater(Some("Ridge"), None), RxAcceptance::Advanced),
            102,
        );
        hear(
            &mut table,
            &signed_advert(
                PEER,
                &repeater(Some("Old"), Some(here())),
                RxAcceptance::Backfilled,
            ),
            101,
        );
        assert_eq!(kept(&table), (Some(String::from("Ridge")), Some(here())));
    }

    /// The same sequence over identity responses, whose pairwise traffic
    /// can arrive through the backward window too.
    #[test]
    fn a_reordered_identity_response_only_fills() {
        let response = |payload: &[u8], acceptance| {
            identity_frame(
                PacketType::Unicast,
                PEER,
                payload,
                SignatureStatus::Unsigned,
                Some(acceptance),
            )
        };
        let mut table = PeerRepeaterTable::new();
        hear(
            &mut table,
            &response(&repeater(Some("Old"), None), RxAcceptance::Advanced),
            100,
        );
        hear(
            &mut table,
            &response(&repeater(Some("Ridge"), None), RxAcceptance::Advanced),
            102,
        );
        hear(
            &mut table,
            &response(
                &repeater(Some("Old"), Some(here())),
                RxAcceptance::Backfilled,
            ),
            101,
        );
        assert_eq!(kept(&table), (Some(String::from("Ridge")), Some(here())));
    }

    /// A new signer's first advertisement lists it, but cannot say it is
    /// the newest; the next one, ahead of the baseline the first set, can.
    #[test]
    fn a_first_contact_fills_and_the_next_advertisement_replaces() {
        let mut table = PeerRepeaterTable::new();
        hear(
            &mut table,
            &signed_advert(
                PEER,
                &repeater(Some("Ridge"), None),
                RxAcceptance::FirstContact,
            ),
            1,
        );
        assert_eq!(kept(&table), (Some(String::from("Ridge")), None));
        hear(
            &mut table,
            &signed_advert(
                PEER,
                &repeater(None, Some(here())),
                RxAcceptance::FirstContact,
            ),
            2,
        );
        assert_eq!(
            kept(&table),
            (Some(String::from("Ridge")), Some(here())),
            "a second first contact, as after the receiver restarts, still only fills"
        );
        hear(
            &mut table,
            &signed_advert(
                PEER,
                &repeater(Some("Summit"), None),
                RxAcceptance::Advanced,
            ),
            3,
        );
        assert_eq!(kept(&table), (Some(String::from("Summit")), None));
    }

    /// A baseline restored from storage counts as established, so after a
    /// restart a peer's first advertisement ahead of it replaces.
    #[test]
    fn after_a_restart_an_advertisement_ahead_of_the_restored_baseline_replaces() {
        let mut table = PeerRepeaterTable::new();
        hear(
            &mut table,
            &signed_advert(
                PEER,
                &repeater(Some("Ridge"), Some(here())),
                RxAcceptance::Advanced,
            ),
            1,
        );
        hear(
            &mut table,
            &signed_advert(
                PEER,
                &repeater(Some("Summit"), None),
                RxAcceptance::Advanced,
            ),
            2,
        );
        assert_eq!(kept(&table), (Some(String::from("Summit")), None));
    }

    /// A standalone-signed identity says who its node is wherever it is
    /// presented, and is believed as that. Put back on the air in a frame
    /// that authenticates nobody—a replay, for all a receiver can tell—it
    /// is no evidence that its node is in range, and lists no neighbor.
    #[test]
    fn a_replayed_signed_identity_does_not_make_its_signer_a_neighbor() {
        let (key, payload) = signed_payload(0x31, NodeCapabilities::REPEATER);
        let mut table = PeerRepeaterTable::new();
        for replayed in [
            identity_frame(
                PacketType::Broadcast,
                key,
                &payload,
                SignatureStatus::Unsigned,
                None,
            ),
            // A channel MIC says only that the sender holds the channel key.
            identity_frame(
                PacketType::Multicast,
                key,
                &payload,
                SignatureStatus::Unsigned,
                None,
            ),
        ] {
            assert!(trusted(&replayed, &key), "the identity itself is believed");
            assert!(!identity_heard_directly(&replayed));
            hear(&mut table, &replayed, 1);
        }
        assert!(table.is_empty());

        // The node's own advertisement, whose frame signature passed replay
        // detection, does place it.
        hear(
            &mut table,
            &signed_advert(key, &payload, RxAcceptance::Advanced),
            2,
        );
        assert_eq!(table.len(), 1);
    }

    /// An untrusted identity changes nothing, not even what is missing.
    #[test]
    fn an_untrusted_identity_is_not_kept() {
        let mut table = PeerRepeaterTable::new();
        let forged = identity_frame(
            PacketType::Multicast,
            PEER,
            &repeater(Some("Forged"), None),
            SignatureStatus::NotVerified,
            None,
        );
        hear(&mut table, &forged, 1);
        assert!(table.is_empty());
    }
}
