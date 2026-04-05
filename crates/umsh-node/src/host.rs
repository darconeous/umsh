use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use umsh_app::{PayloadType, identity_payload, mac_command};
use umsh_mac::{LocalIdentityId, MacError, MacHandle, MacHandleError, Platform, SendOptions};

use crate::dispatch::EventDispatcher;
use crate::node::{LocalNode, LocalNodeState, NodeMembership, PfsLifecycle};
use crate::owned::OwnedMacCommand;
use crate::receive::ReceivedPacketRef;

/// Error returned when a [`Host`] cannot make progress.
///
/// `Busy` means some other caller already holds the underlying shared
/// [`MacHandle`](umsh_mac::MacHandle) borrow. `Mac` wraps the underlying runtime failure.
#[derive(Debug)]
pub enum HostError<E> {
    Busy,
    Mac(E),
}

impl<E> From<MacHandleError<E>> for HostError<E> {
    fn from(value: MacHandleError<E>) -> Self {
        match value {
            MacHandleError::Busy => Self::Busy,
            MacHandleError::Inner(inner) => Self::Mac(inner),
        }
    }
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
/// 4. drive progress with [`run`](Self::run) or [`pump_once`](Self::pump_once)
///
/// `run()` is the preferred long-lived driver. `pump_once()` exists for callers that need to
/// multiplex UMSH progress with other async work using `select!`.
pub struct Host<
    'a,
    P: Platform,
    const IDENTITIES: usize,
    const PEERS: usize,
    const CHANNELS: usize,
    const ACKS: usize,
    const TX: usize,
    const FRAME: usize,
    const DUP: usize,
> {
    mac: MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>,
    dispatcher: Rc<RefCell<EventDispatcher>>,
    nodes: Vec<(LocalIdentityId, LocalNode<MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>)>,
    pfs_control_options: SendOptions,
}

impl<
        'a,
        P: Platform,
        const IDENTITIES: usize,
        const PEERS: usize,
        const CHANNELS: usize,
        const ACKS: usize,
        const TX: usize,
        const FRAME: usize,
        const DUP: usize,
    > Host<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>
{
    /// Create a host around a shared MAC handle.
    pub fn new(
        mac: MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>,
    ) -> Self {
        Self {
            mac,
            dispatcher: Rc::new(RefCell::new(EventDispatcher::new())),
            nodes: Vec::new(),
            pfs_control_options: SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(5),
        }
    }

    /// Return the underlying shared MAC handle.
    pub fn mac(
        &self,
    ) -> MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP> {
        self.mac
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
    pub fn add_node(
        &mut self,
        identity_id: LocalIdentityId,
    ) -> LocalNode<MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>> {
        let membership = Rc::new(RefCell::new(NodeMembership::new()));
        let state = Rc::new(RefCell::new(LocalNodeState::new()));
        let node = LocalNode::new(
            identity_id,
            self.mac,
            self.dispatcher.clone(),
            membership,
            state,
        );
        self.nodes.push((identity_id, node.clone()));
        node
    }

    /// Look up a previously added node by identity id.
    pub fn node(
        &self,
        identity_id: LocalIdentityId,
    ) -> Option<LocalNode<MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>> {
        self.nodes
            .iter()
            .find(|(id, _)| *id == identity_id)
            .map(|(_, node)| node.clone())
    }

    fn route_node(
        &self,
        identity_id: LocalIdentityId,
    ) -> Option<LocalNode<MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>> {
        if let Some(node) = self.node(identity_id) {
            return Some(node);
        }

        #[cfg(feature = "software-crypto")]
        {
            return self
                .nodes
                .iter()
                .find(|(_, node)| node.owns_ephemeral_identity(identity_id))
                .map(|(_, node)| node.clone());
        }

        #[cfg(not(feature = "software-crypto"))]
        {
            None
        }
    }

    /// Drive the shared MAC until one wake cycle completes.
    ///
    /// This is a single wake-driven step, not a non-blocking poll. It waits until the MAC has
    /// meaningful work to do (radio activity or a protocol deadline), dispatches any resulting
    /// callbacks, services PFS command handling, and then returns.
    ///
    /// Use this when you need to multiplex UMSH progress with other async sources using
    /// `select!`. If UMSH owns the task, prefer [`run`](Self::run).
    pub async fn pump_once(
        &mut self,
    ) -> Result<(), HostError<MacError<<P::Radio as umsh_hal::Radio>::Error>>> {
        let pending_pfs =
            Rc::new(RefCell::new(Vec::<(LocalIdentityId, umsh_core::PublicKey, OwnedMacCommand)>::new()));
        let pending_pfs_ref = pending_pfs.clone();
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
                        let _ = node.dispatch_received_packet(&packet);
                        if packet.packet_type() == umsh_core::PacketType::Broadcast
                            && packet.payload().is_empty()
                        {
                            if let Some(from_hint) = packet.from_hint() {
                                node.dispatch_beacon(from_hint, packet.from_key());
                            }
                        } else if let Some(from) = packet.from_key() {
                            dispatch_payload_callbacks(&node, &packet, from, &pending_pfs_ref);
                        }
                    }
                    umsh_mac::MacEventRef::AckReceived { peer, receipt } => {
                        node.dispatch_ack_received(
                            peer,
                            crate::SendToken::new(identity_id, receipt),
                        );
                    }
                    umsh_mac::MacEventRef::AckTimeout { peer, receipt } => {
                        node.dispatch_ack_timeout(
                            peer,
                            crate::SendToken::new(identity_id, receipt),
                        );
                    }
                    umsh_mac::MacEventRef::Transmitted { .. }
                    | umsh_mac::MacEventRef::Forwarded { .. } => {}
                }
            })
            .await?;

        let queued: Vec<(LocalIdentityId, umsh_core::PublicKey, OwnedMacCommand)> =
            pending_pfs.borrow_mut().drain(..).collect();
        for (identity_id, from, command) in queued {
            self.handle_pfs_command(identity_id, from, command).await;
        }

        #[cfg(feature = "software-crypto")]
        for (_, node) in &self.nodes {
            if let Ok(expired) = node.expire_pfs_sessions() {
                for peer in expired {
                    node.dispatch_pfs_ended(peer);
                }
            }
        }

        Ok(())
    }

    /// Run the shared MAC/Host loop forever.
    ///
    /// This is the preferred long-lived driver for node-based applications. It keeps the
    /// runtime wake policy inside the MAC/Host stack rather than requiring callers to write
    /// poll/sleep loops themselves.
    pub async fn run(
        &mut self,
    ) -> Result<(), HostError<MacError<<P::Radio as umsh_hal::Radio>::Error>>> {
        loop {
            self.pump_once().await?;
        }
    }

    async fn handle_pfs_command(
        &mut self,
        identity_id: LocalIdentityId,
        from: umsh_core::PublicKey,
        command: OwnedMacCommand,
    ) {
        let Some(node) = self.route_node(identity_id) else {
            return;
        };

        if let Ok(Some(lifecycle)) = node
            .handle_pfs_command(&from, &command, &self.pfs_control_options)
            .await
        {
            match lifecycle {
                PfsLifecycle::Established(peer) => node.dispatch_pfs_established(peer),
                PfsLifecycle::Ended(peer) => node.dispatch_pfs_ended(peer),
            }
        }
    }
}

fn route_node<
    'a,
    P: Platform,
    const IDENTITIES: usize,
    const PEERS: usize,
    const CHANNELS: usize,
    const ACKS: usize,
    const TX: usize,
    const FRAME: usize,
    const DUP: usize,
>(
    nodes: &[(LocalIdentityId, LocalNode<MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>)],
    identity_id: LocalIdentityId,
) -> Option<LocalNode<MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>> {
    nodes
        .iter()
        .find(|(id, _)| *id == identity_id)
        .map(|(_, node)| node.clone())
        .or_else(|| {
            nodes.iter()
                .find(|(_, node)| node.owns_ephemeral_identity(identity_id))
                .map(|(_, node)| node.clone())
        })
}

fn dispatch_payload_callbacks<
    'a,
    P: Platform,
    const IDENTITIES: usize,
    const PEERS: usize,
    const CHANNELS: usize,
    const ACKS: usize,
    const TX: usize,
    const FRAME: usize,
    const DUP: usize,
>(
    node: &LocalNode<MacHandle<'a, P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>>,
    packet: &ReceivedPacketRef<'_>,
    from: umsh_core::PublicKey,
    pending_pfs: &Rc<RefCell<Vec<(LocalIdentityId, umsh_core::PublicKey, OwnedMacCommand)>>>,
) {
    if packet.payload_type() == PayloadType::NodeIdentity {
        if let Ok(identity) = identity_payload::parse(packet.payload()) {
            if let Ok(owned) = crate::OwnedNodeIdentityPayload::try_from(identity) {
                node.dispatch_node_discovered(from, owned.name.as_deref());
            }
        }
        return;
    }

    if packet.payload_type() == PayloadType::MacCommand {
        if let Ok(command) = mac_command::parse(packet.payload()) {
            let owned = OwnedMacCommand::from(command);
            node.dispatch_mac_command(from, &owned);
            if matches!(
                owned,
                OwnedMacCommand::PfsSessionRequest { .. }
                    | OwnedMacCommand::PfsSessionResponse { .. }
                    | OwnedMacCommand::EndPfsSession
            ) {
                pending_pfs.borrow_mut().push((node.identity_id(), from, owned));
            }
        }
    }
}
