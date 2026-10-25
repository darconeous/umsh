//! Engine transmissions to `LocalNode` sends, and their delivery back to the
//! engine.

use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;

use umsh_core::{ChannelKey, ChannelTag, PayloadType, PublicKey};
use umsh_mac::{ECHO_WATCH_MS, SendOptions, SendReceipt};
#[cfg(feature = "software-crypto")]
use umsh_node::{BoundChannel, Transport};
use umsh_node::{LocalNode, MacBackend, SendProgressTicket};

use crate::chat::{ChannelRegistry, ChatFacade, Outbound, Repeats, TransmitUpdate};
use crate::engine::sequence::MessageHandle;
use crate::engine::{Destination, Transmission};
use crate::node_adapter::WellKnownChannels;
use crate::validate::TextProfile;

/// The flood-hop ceiling the protocol fixes for `public` and `EMERGENCY`.
pub const WELL_KNOWN_CHANNEL_MAX_FLOOD_HOPS: u8 = 10;

/// How long an in-flight transmission may go unresolved before it is called
/// out. Longer than any ordinary acknowledgment wait, so this fires on
/// trouble rather than on a slow link.
pub const TRANSMISSION_STALL_MS: u64 = 60_000;

/// What a send needs to know beyond the frame itself.
#[derive(Clone, Copy)]
pub struct TransmitPolicy {
    /// Ceiling on how far a send travels when nothing narrower applies. Zero
    /// sends no flood at all.
    pub default_flood_hops: u8,
    pub well_known: WellKnownChannels,
}

/// Spend `hops` on `options`: a budget for a flood, or no flood at all for
/// zero.
pub fn with_flood_reach(options: SendOptions, hops: u8) -> SendOptions {
    if hops == 0 {
        options.no_flood()
    } else {
        options.with_flood_hops(hops)
    }
}

/// How far traffic on a channel may travel: the ceiling the user registered
/// for it, otherwise `default_hops`—and never past the ceiling the protocol
/// fixes for the well-known `public` and `EMERGENCY` channels.
pub fn channel_reach(
    channels: &ChannelRegistry,
    well_known: &WellKnownChannels,
    channel: &ChannelTag,
    default_hops: u8,
) -> u8 {
    let asked = channels.max_flood_hops(channel).unwrap_or(default_hops);
    match channels.key(channel) {
        Some(key) if well_known.contains(&key) => asked.min(WELL_KNOWN_CHANNEL_MAX_FLOOD_HOPS),
        _ => asked,
    }
}

/// Bind a held channel, so it can be sent over.
///
/// Looked up per send rather than cached: leaving and rejoining a channel
/// invalidates the binding, and the registry is the one place that knows.
#[cfg(feature = "software-crypto")]
pub fn bound_channel<M: MacBackend>(
    node: &LocalNode<M>,
    channels: &ChannelRegistry,
    channel: &ChannelTag,
) -> Option<BoundChannel<M>> {
    let key = channels.key(channel)?;
    node.bound_channel(&umsh_node::Channel::private(key, ""))
}

/// A transmission that has stayed in flight past [`TRANSMISSION_STALL_MS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stall {
    pub transmission_id: u32,
    pub waited_ms: u64,
    /// Window slots in use, of `window`.
    pub occupied: usize,
    pub window: usize,
    /// Transmissions waiting behind the window.
    pub pending: usize,
}

/// The chat transmit queue.
///
/// Frames go to the node through a bounded window, so a message larger than
/// the window waits here rather than in the MAC's own queue. A frame leaves
/// the window when nothing more can happen to it: acknowledged or failed, or
/// transmitted when no acknowledgment will follow.
pub struct TransmitQueue {
    window: usize,
    pending: VecDeque<Queued>,
    in_flight: Vec<InFlight>,
    /// Sent frames that will never be acknowledged, still listened to for
    /// repeaters carrying them. They take no room in the window.
    watching: Vec<Watching>,
    /// Peers that have acknowledged a frame since the last one failed:
    /// they know our key.
    pipeline_ready: BTreeSet<[u8; 32]>,
}

struct Queued {
    session_id: u64,
    transmission: Transmission,
}

struct InFlight {
    session_id: u64,
    transmission_id: u32,
    /// The peer whose first-contact pipeline this send gates on. Channel
    /// sends have no such peer: multicast is unaddressed and blind unicast
    /// carries no acknowledgment to confirm with.
    gate_peer: Option<PublicKey>,
    ticket: SendProgressTicket,
    sent_reported: bool,
    /// No acknowledgment will ever arrive, so transmission is the terminal
    /// success state rather than a step toward one.
    non_ack: bool,
    /// When this entry entered the window, and whether it has already been
    /// reported as overdue. A frame that never resolves holds a slot; a full
    /// window of them stops chat entirely, which from the outside looks like
    /// messages hanging on "Sending" for no reason.
    queued_at_ms: u64,
    stall_reported: bool,
    /// Whether repeaters heard carrying this frame are worth reporting:
    /// it carries a message of ours, to a peer or a whole channel.
    reports_repeats: bool,
    /// The message and fragment the frame carries, taken when it is sent:
    /// the engine lets go of a frame it expects no acknowledgment for.
    frame: Option<(MessageHandle, Option<u8>)>,
    /// The tally revision last reported.
    repeats_reported: u32,
}

struct Watching {
    session_id: u64,
    frame: (MessageHandle, Option<u8>),
    ticket: SendProgressTicket,
    repeats_reported: u32,
    until_ms: u64,
}

/// Report `ticket`'s repeaters for `frame` if they changed since
/// `reported`.
fn report_repeats<P, const SLOTS: usize, const PAGES: usize>(
    chat: &mut ChatFacade<P, SLOTS, PAGES>,
    session_id: u64,
    frame: (MessageHandle, Option<u8>),
    ticket: &SendProgressTicket,
    reported: &mut u32,
) where
    P: TextProfile + Clone,
{
    let tally = ticket.repeats();
    if tally.revision == *reported {
        return;
    }
    *reported = tally.revision;
    chat.transmit_repeats(
        session_id,
        Repeats {
            handle: frame.0,
            fragment: frame.1,
            repeaters: tally.repeaters.iter().copied().collect(),
            anonymous: tally.anonymous,
        },
    );
}

impl TransmitQueue {
    /// A queue keeping at most `window` frames in flight, aligned with the
    /// MAC's transmit queue.
    pub fn new(window: usize) -> Self {
        Self {
            window: window.max(1),
            pending: VecDeque::new(),
            in_flight: Vec::new(),
            watching: Vec::new(),
            pipeline_ready: BTreeSet::new(),
        }
    }

    pub fn enqueue(&mut self, outbound: Outbound) {
        let session_id = outbound.session_id();
        self.pending.extend(
            outbound
                .into_transmissions()
                .into_iter()
                .map(|transmission| Queued {
                    session_id,
                    transmission,
                }),
        );
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    /// Hand waiting frames to the node while the window has room. Returns
    /// how many were sent: each is an authenticated send that advanced the
    /// frame counter. It is [`TransmitQueue::depart`], [`transmit`], and
    /// [`TransmitQueue::departed`] in a loop, for a caller that holds the
    /// facade across the sends.
    pub async fn pump<M, P, const SLOTS: usize, const PAGES: usize>(
        &mut self,
        node: &LocalNode<M>,
        chat: &mut ChatFacade<P, SLOTS, PAGES>,
        policy: &TransmitPolicy,
        now_ms: u64,
    ) -> usize
    where
        M: MacBackend,
        P: TextProfile + Clone,
    {
        let mut sent_count = 0;
        while let Some(next) = self.depart(chat.channels(), policy) {
            let departure = match next {
                Ok(departure) => departure,
                Err(undeliverable) => {
                    undeliverable.fail(chat, now_ms);
                    continue;
                }
            };
            let sent = transmit(node, &departure).await;
            match self.departed(departure, sent, now_ms) {
                Departed::Sent => sent_count += 1,
                Departed::Failed(undeliverable) => undeliverable.fail(chat, now_ms),
                Departed::Busy => break,
            }
        }
        sent_count
    }

    /// The next frame the window has room for, with where it goes resolved
    /// against `channels`. `None` when nothing may leave now.
    ///
    /// - A unicast asks for an acknowledgment, and a peer gets one frame in
    ///   flight until its first is acknowledged: first contact may need
    ///   counter synchronization. Until then it names us by full key, since
    ///   a peer that has not registered us cannot read a frame that names
    ///   us by hint.
    /// - A channel multicast carries the full source key, so a member who
    ///   misses a fragment can address a resend request to us.
    /// - A channel-direct frame is a blind unicast, registering the peer on
    ///   the way out.
    /// - `EMERGENCY` goes out unencrypted, so any node in range can read it.
    ///
    /// A frame on a channel no longer held comes back undeliverable.
    pub fn depart(
        &mut self,
        channels: &ChannelRegistry,
        policy: &TransmitPolicy,
    ) -> Option<Result<Departure, Undeliverable>> {
        if self.in_flight.len() >= self.window {
            return None;
        }
        let queued = self.pending.pop_front()?;
        let transmission = &queued.transmission;
        let gate_peer = match transmission.destination {
            Destination::Peer(peer) => Some(peer),
            Destination::Channel(_) | Destination::ChannelPeer { .. } => None,
        };
        if let Some(peer) = gate_peer
            && !self.pipeline_ready.contains(&peer.0)
            && self
                .in_flight
                .iter()
                .any(|entry| entry.gate_peer == Some(peer))
        {
            self.pending.push_front(queued);
            return None;
        }
        let route = match transmission.destination {
            Destination::Peer(peer) => {
                let options = with_flood_reach(SendOptions::default(), policy.default_flood_hops)
                    .with_ack_requested(true);
                let options = if self.pipeline_ready.contains(&peer.0) {
                    options
                } else {
                    options.with_full_source()
                };
                Route::Peer { peer, options }
            }
            Destination::Channel(channel) => {
                let Some(key) = channels.key(&channel) else {
                    return Some(Err(Undeliverable::of(&queued)));
                };
                let options = channel_options(channels, policy, &channel, &key);
                Route::Channel { key, options }
            }
            // A repair request; the engine owns retrying it, so no
            // acknowledgment is asked for. Repairs carry the same message
            // the multicast did, so they are held to the same rules.
            Destination::ChannelPeer { channel, peer } => {
                let Some(key) = channels.key(&channel) else {
                    return Some(Err(Undeliverable::of(&queued)));
                };
                let options = channel_options(channels, policy, &channel, &key);
                Route::ChannelPeer { key, peer, options }
            }
        };
        let mut payload = Vec::with_capacity(transmission.payload.len() + 1);
        payload.push(PayloadType::TextMessage as u8);
        payload.extend_from_slice(transmission.payload.as_slice());
        Some(Ok(Departure {
            queued,
            gate_peer,
            route,
            payload,
            forward_secret: None,
        }))
    }

    /// What became of a departure's send. A frame the node refused for
    /// now—with a registered peer and an engine-bounded payload, its queues
    /// are full—goes back to the head of the queue, to wait for tickets to
    /// advance.
    pub fn departed(&mut self, departure: Departure, sent: Sent, now_ms: u64) -> Departed {
        let ticket = match sent {
            Sent::Ticket(ticket) => ticket,
            Sent::Unsendable => return Departed::Failed(Undeliverable::of(&departure.queued)),
            Sent::Busy => {
                self.pending.push_front(departure.queued);
                return Departed::Busy;
            }
        };
        let transmission = &departure.queued.transmission;
        // A repair goes to one member, and the multicast it repairs has
        // already had its repeaters counted.
        let reports_repeats = transmission.message.is_some()
            && matches!(
                transmission.destination,
                Destination::Peer(_) | Destination::Channel(_)
            );
        self.in_flight.push(InFlight {
            session_id: departure.queued.session_id,
            transmission_id: transmission.transmission_id,
            gate_peer: departure.gate_peer,
            ticket,
            sent_reported: false,
            non_ack: departure.gate_peer.is_none(),
            queued_at_ms: now_ms,
            stall_reported: false,
            reports_repeats,
            frame: None,
            repeats_reported: 0,
        });
        Departed::Sent
    }

    /// Report what the tickets say to the engine: transmitted, repeated,
    /// acknowledged, or failed. Returns the frames newly found overdue.
    pub fn service<P, const SLOTS: usize, const PAGES: usize>(
        &mut self,
        chat: &mut ChatFacade<P, SLOTS, PAGES>,
        now_ms: u64,
    ) -> Vec<Stall>
    where
        P: TextProfile + Clone,
    {
        let occupied = self.in_flight.len();
        let pending = self.pending.len();
        let mut stalls = Vec::new();
        let mut index = 0;
        while index < self.in_flight.len() {
            let entry = &mut self.in_flight[index];
            // Checked before the state transitions below, so an entry about
            // to retire this pass is not accused on its way out.
            let waited_ms = now_ms.saturating_sub(entry.queued_at_ms);
            if !entry.stall_reported
                && !entry.ticket.was_transmitted()
                && waited_ms >= TRANSMISSION_STALL_MS
            {
                entry.stall_reported = true;
                stalls.push(Stall {
                    transmission_id: entry.transmission_id,
                    waited_ms,
                    occupied,
                    window: self.window,
                    pending,
                });
            }
            if entry.ticket.was_transmitted() && !entry.sent_reported {
                entry.sent_reported = true;
                if entry.reports_repeats {
                    entry.frame = chat.in_flight_frame(entry.session_id, entry.transmission_id);
                }
                chat.transmit_update(
                    entry.session_id,
                    entry.transmission_id,
                    TransmitUpdate::Sent,
                    now_ms,
                );
            }
            if let Some(frame) = entry.frame {
                report_repeats(
                    chat,
                    entry.session_id,
                    frame,
                    &entry.ticket,
                    &mut entry.repeats_reported,
                );
            }
            let entry = &self.in_flight[index];
            if entry.non_ack && entry.sent_reported {
                // Nothing further can happen to this one but repeats, which
                // it is listened to for outside the window; retiring it here
                // is what keeps channel sends from accumulating in flight.
                let entry = self.in_flight.swap_remove(index);
                if let Some(frame) = entry.frame {
                    self.watching.push(Watching {
                        session_id: entry.session_id,
                        frame,
                        ticket: entry.ticket,
                        repeats_reported: entry.repeats_reported,
                        until_ms: now_ms.saturating_add(ECHO_WATCH_MS),
                    });
                }
            } else if entry.ticket.was_acked() {
                if let Some(peer) = entry.gate_peer {
                    self.pipeline_ready.insert(peer.0);
                }
                chat.transmit_update(
                    entry.session_id,
                    entry.transmission_id,
                    TransmitUpdate::Acked {
                        via_flood: entry.ticket.was_acked_via_route_retry(),
                    },
                    now_ms,
                );
                self.in_flight.swap_remove(index);
            } else if entry.ticket.has_failed() {
                // Perhaps it no longer knows us: the next frame introduces
                // us again.
                if let Some(peer) = entry.gate_peer {
                    self.pipeline_ready.remove(&peer.0);
                }
                chat.transmit_update(
                    entry.session_id,
                    entry.transmission_id,
                    TransmitUpdate::Failed,
                    now_ms,
                );
                self.in_flight.swap_remove(index);
            } else {
                index += 1;
            }
        }
        self.watching.retain_mut(|watching| {
            report_repeats(
                chat,
                watching.session_id,
                watching.frame,
                &watching.ticket,
                &mut watching.repeats_reported,
            );
            now_ms < watching.until_ms
        });
        stalls
    }

    /// Fail every frame the queue holds, waiting or in flight. Returns the
    /// receipts of in-flight sends still awaiting an acknowledgment, for the
    /// caller to cancel at the MAC.
    pub fn fail_all<P, const SLOTS: usize, const PAGES: usize>(
        &mut self,
        chat: &mut ChatFacade<P, SLOTS, PAGES>,
        now_ms: u64,
    ) -> Vec<SendReceipt>
    where
        P: TextProfile + Clone,
    {
        for queued in self.pending.drain(..) {
            chat.transmit_update(
                queued.session_id,
                queued.transmission.transmission_id,
                TransmitUpdate::Failed,
                now_ms,
            );
        }
        self.watching.clear();
        let mut receipts = Vec::new();
        for entry in self.in_flight.drain(..) {
            if let Some(receipt) = entry.ticket.receipt() {
                receipts.push(receipt);
            }
            chat.transmit_update(
                entry.session_id,
                entry.transmission_id,
                TransmitUpdate::Failed,
                now_ms,
            );
        }
        receipts
    }
}

/// A frame let go by [`TransmitQueue::depart`], with where it goes, until
/// [`TransmitQueue::departed`] is told how its send went.
pub struct Departure {
    queued: Queued,
    gate_peer: Option<PublicKey>,
    route: Route,
    /// The frame, with its payload-type byte.
    payload: Vec<u8>,
    /// Whether a frame to a peer goes under a session with forward secrecy
    /// or never does; `None` leaves it to whether one is held.
    forward_secret: Option<bool>,
}

impl Departure {
    /// The frame's payload, after its payload-type byte.
    pub fn payload(&self) -> &[u8] {
        self.payload.get(1..).unwrap_or_default()
    }

    /// The message of ours the frame carries, when its delivery is
    /// tracked.
    pub fn message(&self) -> Option<MessageHandle> {
        self.queued.transmission.message
    }

    /// Sends the frame, when it goes to a peer, under the session with
    /// forward secrecy held with them, failing without one; or, without
    /// `forward_secret`, never under one.
    pub fn require_forward_secrecy(&mut self, forward_secret: bool) {
        self.forward_secret = Some(forward_secret);
    }

    /// What [`Departure::require_forward_secrecy`] holds the frame to.
    pub fn forward_secrecy(&self) -> Option<bool> {
        self.forward_secret
    }

    /// The peer the frame is addressed to, when it goes to one alone.
    pub fn peer(&self) -> Option<PublicKey> {
        match self.route {
            Route::Peer { peer, .. } => Some(peer),
            Route::Channel { .. } | Route::ChannelPeer { .. } => None,
        }
    }
}

enum Route {
    Peer {
        peer: PublicKey,
        options: SendOptions,
    },
    Channel {
        key: ChannelKey,
        options: SendOptions,
    },
    ChannelPeer {
        key: ChannelKey,
        peer: PublicKey,
        options: SendOptions,
    },
}

/// How a send went.
pub enum Sent {
    Ticket(SendProgressTicket),
    /// Nothing will make this frame sendable; fail it.
    Unsendable,
    /// The node refused it for now; try again later.
    Busy,
}

/// What [`TransmitQueue::departed`] made of a send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Departed {
    /// It is in flight.
    Sent,
    /// It will never go: fail it.
    Failed(Undeliverable),
    /// The node is full for now: send nothing more until a ticket
    /// advances.
    Busy,
}

/// A frame that will not go out: an unregistrable peer, a channel no
/// longer held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Undeliverable {
    pub session_id: u64,
    pub transmission_id: u32,
}

impl Undeliverable {
    fn of(queued: &Queued) -> Self {
        Self {
            session_id: queued.session_id,
            transmission_id: queued.transmission.transmission_id,
        }
    }

    /// Tells the facade the frame failed.
    pub fn fail<P, const SLOTS: usize, const PAGES: usize>(
        self,
        chat: &mut ChatFacade<P, SLOTS, PAGES>,
        now_ms: u64,
    ) where
        P: TextProfile + Clone,
    {
        chat.transmit_update(
            self.session_id,
            self.transmission_id,
            TransmitUpdate::Failed,
            now_ms,
        );
    }
}

/// Sends a departed frame. Needs only the node, so a caller may hold
/// nothing else across it.
pub async fn transmit<M: MacBackend>(node: &LocalNode<M>, departure: &Departure) -> Sent {
    let payload = &departure.payload[..];
    match &departure.route {
        Route::Peer { peer, options } => {
            let Ok(connection) = node.peer(*peer).await else {
                return Sent::Unsendable;
            };
            match departure.forward_secret {
                None => connection.send(payload, options).await.into(),
                Some(forward_secret) => {
                    send_with_secrecy(node, peer, payload, options, forward_secret).await
                }
            }
        }
        Route::Channel { key, options } => send_on_channel(node, key, None, payload, options).await,
        Route::ChannelPeer { key, peer, options } => {
            send_on_channel(node, key, Some(peer), payload, options).await
        }
    }
}

/// A unicast to `peer` under a session with forward secrecy, or never
/// under one. One meant to go under a session that is no longer held
/// cannot go: it never goes without.
#[cfg(feature = "software-crypto")]
async fn send_with_secrecy<M: MacBackend>(
    node: &LocalNode<M>,
    peer: &PublicKey,
    payload: &[u8],
    options: &SendOptions,
    forward_secret: bool,
) -> Sent {
    match node
        .send_with_secrecy(peer, payload, options, forward_secret)
        .await
    {
        Ok(ticket) => Sent::Ticket(ticket),
        Err(umsh_node::NodeError::PfsSessionMissing) => Sent::Unsendable,
        Err(_) => Sent::Busy,
    }
}

/// Forward secrecy is the software crypto back end's alone: a frame meant
/// to go under it cannot go.
#[cfg(not(feature = "software-crypto"))]
async fn send_with_secrecy<M: MacBackend>(
    node: &LocalNode<M>,
    peer: &PublicKey,
    payload: &[u8],
    options: &SendOptions,
    forward_secret: bool,
) -> Sent {
    if forward_secret {
        return Sent::Unsendable;
    }
    umsh_node::Transport::send(node, peer, payload, options)
        .await
        .into()
}

/// A multicast on the channel `key` names, or with `peer` a blind unicast
/// to one member.
#[cfg(feature = "software-crypto")]
async fn send_on_channel<M: MacBackend>(
    node: &LocalNode<M>,
    key: &ChannelKey,
    peer: Option<&PublicKey>,
    payload: &[u8],
    options: &SendOptions,
) -> Sent {
    let Some(bound) = node.bound_channel(&umsh_node::Channel::private(*key, "")) else {
        return Sent::Unsendable;
    };
    let Some(peer) = peer else {
        return bound.send_all(payload, options).await.into();
    };
    // The MAC will only address a registered peer, and a channel member is
    // not one: nothing about being in a channel together registers anybody.
    // Registering on the way out spends a peer slot only on the members we
    // have to ask something of.
    if node.peer(*peer).await.is_err() {
        return Sent::Unsendable;
    }
    bound.send(peer, payload, options).await.into()
}

/// Channels are sealed by the software crypto back end alone.
#[cfg(not(feature = "software-crypto"))]
async fn send_on_channel<M: MacBackend>(
    _node: &LocalNode<M>,
    _key: &ChannelKey,
    _peer: Option<&PublicKey>,
    _payload: &[u8],
    _options: &SendOptions,
) -> Sent {
    Sent::Unsendable
}

impl<E> From<Result<SendProgressTicket, E>> for Sent {
    fn from(result: Result<SendProgressTicket, E>) -> Self {
        match result {
            Ok(ticket) => Sent::Ticket(ticket),
            Err(_) => Sent::Busy,
        }
    }
}

/// Options for a frame on a channel: as far as the channel reaches, naming
/// us by full key, and on `EMERGENCY` unencrypted.
///
/// An emergency message only members can read is not an emergency message.
/// The full source key keeps it attributable without encryption. An
/// unencrypted blind unicast still names its channel, which is what a
/// repeater decides to forward on. The spec also asks `EMERGENCY` chat to be
/// signed, but the text-message format has no signature yet, so none is sent.
fn channel_options(
    channels: &ChannelRegistry,
    policy: &TransmitPolicy,
    channel: &ChannelTag,
    key: &ChannelKey,
) -> SendOptions {
    let reach = channel_reach(
        channels,
        &policy.well_known,
        channel,
        policy.default_flood_hops,
    );
    let options = with_flood_reach(SendOptions::default(), reach).with_full_source();
    if policy.well_known.is_emergency(key) {
        options.unencrypted()
    } else {
        options
    }
}
