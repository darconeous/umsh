use alloc::boxed::Box;
use alloc::rc::{Rc, Weak};
use alloc::vec::Vec;
use core::cell::RefCell;

use umsh_core::{ChannelId, ChannelKey, PacketType, PublicKey};
use umsh_app::{parse_payload, PayloadRef};
use umsh_mac::{LocalIdentityId, MacEventRef};

use crate::events::NodeEvent;
use crate::node::NodeMembership;
use crate::owned::{OwnedMacCommand, OwnedNodeIdentityPayload, OwnedTextMessage};
use crate::ticket::{SendToken, TicketState};

/// Trait for delivering node events to consumers.
///
/// Executor-specific adapters (tokio broadcast, embassy Signal, simple VecDeque,
/// etc.) implement this trait. The core dispatcher is executor-agnostic.
pub trait EventSink {
    /// Deliver a single event.
    fn send_event(&mut self, event: NodeEvent);
}

/// Per-node sink entry in the dispatcher.
struct NodeSinkEntry {
    identity_id: LocalIdentityId,
    membership: Rc<RefCell<NodeMembership>>,
    sink: Box<dyn EventSink>,
}

/// Dispatches MAC events to registered tickets and node sinks.
///
/// Each registered ticket entry carries:
/// - The `SendToken` for matching
/// - A `Weak<RefCell<TicketState>>` (drops automatically when ticket is dropped)
///
/// Each registered node sink carries:
/// - The node's `LocalIdentityId` (for routing identity-scoped events)
/// - The node's shared `Rc<RefCell<NodeMembership>>` (for channel-membership filtering)
/// - The node's `EventSink` instance
///
/// Uses `Vec` instead of `HashMap` — the number of in-flight tickets is small
/// (bounded by TX queue depth, typically 16), so linear scan is fine and avoids
/// the `std` dependency on `HashMap`.
pub(crate) struct EventDispatcher {
    /// SendToken → weak ref to ticket state.
    ticket_states: Vec<(SendToken, Weak<RefCell<TicketState>>)>,
    /// Per-node sink registrations.
    node_sinks: Vec<NodeSinkEntry>,
}

impl EventDispatcher {
    /// Create a new empty dispatcher.
    pub fn new() -> Self {
        Self {
            ticket_states: Vec::new(),
            node_sinks: Vec::new(),
        }
    }

    /// Register a new ticket. Returns the strong `Rc` (caller keeps it alive
    /// via `SendProgressTicket`).
    ///
    /// If `non_ack` is true, the ticket will be marked finished as soon as
    /// the `Transmitted` event fires (no ACK to wait for).
    pub fn register_ticket(&mut self, token: SendToken, non_ack: bool) -> Rc<RefCell<TicketState>> {
        let state = Rc::new(RefCell::new(TicketState {
            non_ack,
            ..TicketState::default()
        }));
        self.ticket_states.push((token, Rc::downgrade(&state)));
        state
    }

    /// Register a node sink for event delivery.
    pub fn register_node(
        &mut self,
        identity_id: LocalIdentityId,
        membership: Rc<RefCell<NodeMembership>>,
        sink: Box<dyn EventSink>,
    ) {
        self.node_sinks.push(NodeSinkEntry {
            identity_id,
            membership,
            sink,
        });
    }

    /// Called synchronously from the MAC event callback.
    ///
    /// Updates ticket state fields, then converts data events to `NodeEvent`
    /// and delivers them to registered node sinks (filtered by identity and
    /// channel membership).
    pub fn dispatch_ticket_state(
        &mut self,
        identity_id: LocalIdentityId,
        event: &MacEventRef<'_>,
    ) {
        // Phase 1: Update ticket state for send-tracking events.
        match *event {
            MacEventRef::Transmitted {
                identity_id: tx_id,
                receipt,
            } => {
                if let Some(receipt) = receipt {
                    let token = SendToken::new(tx_id, receipt);
                    self.update_ticket(&token, |state| {
                        state.transmitted = true;
                        if state.non_ack {
                            state.finished = true;
                        }
                    });
                }
            }
            MacEventRef::Forwarded {
                identity_id: fwd_id,
                receipt,
                ..
            } => {
                let token = SendToken::new(fwd_id, receipt);
                self.update_ticket(&token, |state| {
                    state.repeated = true;
                });
            }
            MacEventRef::AckReceived { receipt, .. } => {
                let token = SendToken::new(identity_id, receipt);
                self.update_ticket(&token, |state| {
                    state.acked = true;
                    state.finished = true;
                });
            }
            MacEventRef::AckTimeout { receipt, .. } => {
                let token = SendToken::new(identity_id, receipt);
                self.update_ticket(&token, |state| {
                    state.failed = true;
                    state.finished = true;
                });
            }
            _ => {}
        }

        // Phase 2: Convert data events to NodeEvent and deliver to sinks.
        if self.node_sinks.is_empty() {
            return;
        }
        if let Some(node_event) = Self::mac_event_to_node_event(identity_id, event) {
            // Extract the channel key for membership filtering.
            // Using the full ChannelKey (not the 2-byte ChannelId) prevents
            // event leakage between channels that collide on the derived ID.
            let channel_key = mac_event_channel_key(event);
            for entry in &mut self.node_sinks {
                if entry.identity_id != identity_id {
                    continue;
                }
                // For channel-scoped events, check membership by full key.
                if let Some(key) = &channel_key {
                    let membership = entry.membership.borrow();
                    if !membership.has_channel_key(key) {
                        continue;
                    }
                }
                entry.sink.send_event(node_event.clone());
            }
        }
    }

    /// Convert a MAC event to a NodeEvent, if applicable.
    fn mac_event_to_node_event(
        identity_id: LocalIdentityId,
        event: &MacEventRef<'_>,
    ) -> Option<NodeEvent> {
        match *event {
            MacEventRef::Unicast { from, payload, .. } => {
                Self::parse_data_payload(from, None, PacketType::Unicast, payload)
            }
            MacEventRef::Multicast { from, channel_id, channel_key, payload, .. } => {
                Self::parse_data_payload(from, Some((channel_id, channel_key)), PacketType::Multicast, payload)
            }
            MacEventRef::BlindUnicast { from, channel_id, channel_key, payload, .. } => {
                Self::parse_data_payload(from, Some((channel_id, channel_key)), PacketType::BlindUnicast, payload)
            }
            MacEventRef::Broadcast { from_hint, from_key, payload } => {
                if payload.is_empty() {
                    return Some(NodeEvent::BeaconReceived { from_hint, from_key });
                }
                match from_key {
                    Some(from) => Self::parse_data_payload(from, None, PacketType::Broadcast, payload),
                    None => Some(NodeEvent::BeaconReceived { from_hint, from_key }),
                }
            }
            MacEventRef::AckReceived { peer, receipt } => {
                let token = SendToken::new(identity_id, receipt);
                Some(NodeEvent::AckReceived { peer, token })
            }
            MacEventRef::AckTimeout { peer, receipt } => {
                let token = SendToken::new(identity_id, receipt);
                Some(NodeEvent::AckTimeout { peer, token })
            }
            // Transmitted/Forwarded are ticket-only events, not surfaced as NodeEvent.
            MacEventRef::Transmitted { .. } | MacEventRef::Forwarded { .. } => None,
        }
    }

    /// Parse a data payload into a NodeEvent.
    fn parse_data_payload(
        from: PublicKey,
        channel: Option<(ChannelId, ChannelKey)>,
        packet_type: PacketType,
        payload: &[u8],
    ) -> Option<NodeEvent> {
        let parsed = parse_payload(packet_type, payload).ok()?;
        match parsed {
            PayloadRef::TextMessage(message) => {
                let owned = OwnedTextMessage::try_from(message).ok()?;
                Some(match channel {
                    Some((channel_id, channel_key)) => NodeEvent::ChannelTextReceived {
                        from,
                        channel_id,
                        channel_key,
                        body: owned.body,
                    },
                    None => NodeEvent::TextReceived {
                        from,
                        body: owned.body,
                    },
                })
            }
            PayloadRef::NodeIdentity(identity) => {
                let owned = OwnedNodeIdentityPayload::try_from(identity).ok()?;
                Some(NodeEvent::NodeDiscovered {
                    key: from,
                    name: owned.name,
                })
            }
            PayloadRef::MacCommand(command) => {
                let owned = OwnedMacCommand::from(command);
                Some(NodeEvent::MacCommandReceived {
                    from,
                    command: owned,
                })
            }
            _ => None,
        }
    }

    /// Update a ticket's state if it's still alive. Cleans up dead entries.
    fn update_ticket(&mut self, token: &SendToken, f: impl FnOnce(&mut TicketState)) {
        // Find and update the matching ticket.
        if let Some(pos) = self.ticket_states.iter().position(|(t, _)| t == token) {
            let (_, weak) = &self.ticket_states[pos];
            if let Some(rc) = weak.upgrade() {
                f(&mut rc.borrow_mut());
            } else {
                // Weak is dead — remove entry.
                self.ticket_states.swap_remove(pos);
            }
        }

        // Opportunistically clean up other dead entries.
        self.ticket_states.retain(|(_, weak)| weak.strong_count() > 0);
    }
}

/// Extract the channel key from a channel-scoped MAC event, if any.
///
/// Uses the full `ChannelKey` from the MAC event (not the 2-byte `ChannelId`)
/// to prevent event delivery to nodes that have joined a different channel
/// that happens to collide on the derived ID.
fn mac_event_channel_key(event: &MacEventRef<'_>) -> Option<ChannelKey> {
    match *event {
        MacEventRef::Multicast { channel_key, .. } => Some(channel_key),
        MacEventRef::BlindUnicast { channel_key, .. } => Some(channel_key),
        _ => None,
    }
}
