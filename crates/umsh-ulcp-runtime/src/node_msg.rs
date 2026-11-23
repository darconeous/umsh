//! Node messaging: UMSH payloads a link sends and receives through the
//! device's own node (`STR_NODE_MSG`).
//!
//! Three pieces, in the `admin_responder` pattern:
//!
//! - **Receiving.** [`tap`], on the node's receive path, keeps every
//!   message of a claimed payload type in the [`Inbox`], and the driver
//!   hands the oldest waiting one to whichever link receives (the attached
//!   host if it listens, otherwise the device's own interface) as a
//!   `CMD_STR_RECV`. The MAC asks [`admits`] before it acknowledges a
//!   claimed message, so an acknowledgment means the device kept it.
//! - **Sending.** The driver hands each staged send to [`SENDS`], and
//!   [`node_msg_loop`] gives it to the node and reports its outcome back to
//!   the driver as [`InEvent::NodeMsgResult`].
//! - **Waking the driver.** A delivery waits for a link that can take
//!   it. [`node_msg_loop`] tells the driver when a message arrives, and
//!   asks it to try again a little later when it found the link full.
//!
//! The claimed types are mirrored here from the session, since the
//! receive tap and the MAC's admission predicate cannot borrow it.

use core::cell::RefCell;
use core::future::poll_fn;
use core::task::Poll;

use embassy_futures::select::{Either3, select3};
use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, RawMutex};
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use umsh_core::{ChannelKey, PublicKey, RouterHint};
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
use umsh_hal::CounterStore;
use umsh_mac::{SendDestination, SendError, SendOptions, TxAbandonReason};
use umsh_node::{MacBackendError, NodeError, PacketFamily, ReceivedPacketRef, SendProgressTicket};
use umsh_ulcp::Status;
use umsh_ulcp::frame::WriteError;
use umsh_ulcp::items::CHANNEL_IDENTIFIER_LEN;
use umsh_ulcp::node_msg::{self, Kind, MAX_ROUTE_HINTS, ROUTER_HINT_LEN, RecvMeta, Source};
use umsh_ulcp_device::{
    Binding, MAX_NODE_MSG_TYPES, NODE_MSG_PAYLOAD_MAX, NODE_MSG_SENDS, NodeMsgRequest,
};

use crate::device_node::DeviceNode;
use crate::driver::{InEvent, InputChannel};
use crate::log::debug_log;

/// Messages the device holds for a link.
pub const INBOX_SLOTS: usize = 4;

/// The payload types the device node acts on itself, which a link may not
/// claim: a claim would let a link that stopped reading stop the device
/// acting on them too.
pub const RESERVED_TYPES: &[u8] = &[
    umsh_core::PayloadType::MacCommand as u8,
    umsh_core::PayloadType::NodeManagementRequest as u8,
];

/// Node messaging as the device node offers it.
pub const CONFIG: umsh_ulcp_device::NodeMsgConfig = umsh_ulcp_device::NodeMsgConfig {
    reserved_types: RESERVED_TYPES,
};

/// One received message of a claimed type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: Kind,
    pub source: Source,
    /// The full channel identifier, for a kind with a channel.
    pub channel: Option<[u8; CHANNEL_IDENTIFIER_LEN]>,
    /// The sender is authenticated, pairwise or by signature.
    pub sender_auth: bool,
    /// The device acknowledged it. Such a message is never discarded for
    /// room.
    pub acked: bool,
    pub rssi_dbm: Option<i16>,
    pub snr_cb: Option<i16>,
    /// The router hints of a complete trace, nearest repeater first.
    pub trace: heapless::Vec<u8, { MAX_ROUTE_HINTS * ROUTER_HINT_LEN }>,
    /// The payload, type octet first.
    pub payload: heapless::Vec<u8, NODE_MSG_PAYLOAD_MAX>,
}

impl Message {
    /// Encode this message as a `CMD_STR_RECV` into `out`.
    pub fn encode(
        &self,
        redelivered: bool,
        gap: bool,
        out: &mut [u8],
    ) -> Result<usize, WriteError> {
        let meta = RecvMeta {
            kind: self.kind,
            source: self.source,
            channel: self.channel,
            sender_auth: self.sender_auth,
            acked: self.acked,
            gap,
            redelivered,
            rssi_dbm: self.rssi_dbm,
            snr_cb: self.snr_cb,
            trace: (!self.trace.is_empty()).then_some(&self.trace[..]),
        };
        node_msg::recv_frame(out, &self.payload, &meta)
    }
}

/// Where a held message stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// Not yet taken by a link.
    Waiting,
    /// Taken by `Binding`'s link. Kept until its room is needed, in case
    /// that link's session starts over before it has the message.
    Delivered(Binding),
    /// Taken by `Binding`'s link, whose session then started over: owed
    /// to that link again, flagged. Room all the same, as any message
    /// that was delivered is.
    Again(Binding),
}

impl Held {
    /// Whether a link has taken the message, which makes its slot room.
    fn was_delivered(self) -> bool {
        !matches!(self, Self::Waiting)
    }
}

#[derive(Clone, Debug)]
struct Slot {
    /// Arrival order: delivery and reuse both go oldest first.
    seq: u32,
    held: Held,
    message: Message,
}

/// The messages the device holds for links (spec §Pushback, §Redelivery).
///
/// Room is a free slot, a message a link has taken, or an unacknowledged
/// one no link has: the first two are replaced freely, and the third is
/// displaced, with the gap reported. An acknowledged message no link has
/// taken is never displaced, which is why the MAC asks
/// [`Inbox::has_room_for_acked`] before it acknowledges.
pub struct Inbox {
    slots: [Option<Slot>; INBOX_SLOTS],
    next_seq: u32,
    /// Unacknowledged messages were discarded since the last delivery.
    gap: bool,
}

/// A message waiting for delivery, as [`Inbox::next`] reports it.
pub struct Waiting<'a> {
    pub seq: u32,
    pub message: &'a Message,
    pub redelivered: bool,
    pub gap: bool,
}

impl Default for Inbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Inbox {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; INBOX_SLOTS],
            next_seq: 0,
            gap: false,
        }
    }

    /// The slot a new message may take: a free one, then the oldest one a
    /// link has taken, then, if `displace` allows, the oldest
    /// unacknowledged one still waiting.
    fn room(&self, displace: bool) -> Option<usize> {
        if let Some(index) = self.slots.iter().position(Option::is_none) {
            return Some(index);
        }
        let oldest = |want: &dyn Fn(&Slot) -> bool| {
            self.slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.as_ref().map(|slot| (index, slot)))
                .filter(|(_, slot)| want(slot))
                .min_by_key(|(_, slot)| slot.seq)
                .map(|(index, _)| index)
        };
        oldest(&|slot| slot.held.was_delivered()).or_else(|| {
            displace
                .then(|| oldest(&|slot| slot.held == Held::Waiting && !slot.message.acked))
                .flatten()
        })
    }

    /// Whether an acknowledged message would be kept: what the MAC asks
    /// before it acknowledges one.
    pub fn has_room_for_acked(&self) -> bool {
        self.room(true).is_some()
    }

    /// Keep `message`. False when it was discarded: an unacknowledged
    /// message with no room, or an acknowledged one the MAC should not
    /// have accepted.
    pub fn store(&mut self, message: Message) -> bool {
        // An unacknowledged message takes only free or delivered room; an
        // acknowledged one may displace an unacknowledged one.
        let Some(index) = self.room(message.acked) else {
            self.gap = true;
            return false;
        };
        if self.slots[index]
            .as_ref()
            .is_some_and(|slot| slot.held == Held::Waiting)
        {
            self.gap = true;
        }
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        self.slots[index] = Some(Slot {
            seq,
            held: Held::Waiting,
            message,
        });
        true
    }

    /// The oldest message `link` is to be handed: one no link has taken,
    /// or one owed to `link` again.
    pub fn next(&self, link: Binding) -> Option<Waiting<'_>> {
        self.slots
            .iter()
            .flatten()
            .filter_map(|slot| match slot.held {
                Held::Waiting => Some((slot, false)),
                Held::Again(owed) if owed == link => Some((slot, true)),
                Held::Again(_) | Held::Delivered(_) => None,
            })
            .min_by_key(|(slot, _)| slot.seq)
            .map(|(slot, redelivered)| Waiting {
                seq: slot.seq,
                message: &slot.message,
                redelivered,
                gap: self.gap,
            })
    }

    /// `link` took message `seq`, with whatever gap [`Inbox::next`]
    /// reported.
    pub fn delivered(&mut self, seq: u32, link: Binding) {
        if let Some(slot) = self.slots.iter_mut().flatten().find(|slot| slot.seq == seq) {
            slot.held = Held::Delivered(link);
            self.gap = false;
        }
    }

    /// `link`'s session started over: what it was handed may not have
    /// reached it, so it is owed to that link again, flagged. Returns
    /// whether anything is.
    pub fn redeliver(&mut self, link: Binding) -> bool {
        let mut any = false;
        for slot in self.slots.iter_mut().flatten() {
            if slot.held == Held::Delivered(link) {
                slot.held = Held::Again(link);
                any = true;
            }
        }
        any
    }
}

/// The messages held for links.
pub static INBOX: BlockingMutex<CriticalSectionRawMutex, RefCell<Inbox>> =
    BlockingMutex::new(RefCell::new(Inbox::new()));

/// The mirrored `PROP_NODE_MSG_TYPES`.
static CLAIMS: BlockingMutex<
    CriticalSectionRawMutex,
    RefCell<heapless::Vec<u8, MAX_NODE_MSG_TYPES>>,
> = BlockingMutex::new(RefCell::new(heapless::Vec::new()));

/// Whether `payload_type` is claimed.
pub fn claimed(payload_type: u8) -> bool {
    CLAIMS.lock(|claims| claims.borrow().contains(&payload_type))
}

/// Republish the claimed types.
pub fn publish_claims(types: impl IntoIterator<Item = u8>) {
    CLAIMS.lock(|claims| {
        let mut claims = claims.borrow_mut();
        claims.clear();
        for payload_type in types {
            let _ = claims.push(payload_type);
        }
    });
}

/// The MAC's admission predicate: whether an acknowledgment-requesting
/// message of `payload_type` may be accepted and acknowledged. Only a
/// claimed type with no room is refused; everything else is the device's
/// own business, and its pushback is not this one.
pub fn admits(payload_type: u8) -> bool {
    !claimed(payload_type) || INBOX.lock(|inbox| inbox.borrow().has_room_for_acked())
}

/// Keep `packet` for a link, when its payload type is claimed. Called
/// from the node's receive path for every packet addressed to the device
/// identity, to one of its channels, or broadcast.
pub fn tap(packet: &ReceivedPacketRef<'_>) {
    let payload = packet.payload_bytes();
    let Some(&payload_type) = payload.first() else {
        return;
    };
    if !claimed(payload_type) {
        return;
    }
    let kind = match packet.packet_family() {
        PacketFamily::Unicast => Kind::Unicast,
        PacketFamily::Broadcast => Kind::Broadcast,
        PacketFamily::BlindUnicast => Kind::BlindUnicast,
        PacketFamily::Multicast => Kind::Multicast,
        PacketFamily::MacAck | PacketFamily::Reserved => return,
    };
    let source = match (packet.from_key(), packet.from_hint()) {
        (Some(key), _) => Source::Key(key.0),
        (None, Some(hint)) => Source::Hint(hint.0),
        (None, None) => return,
    };
    let channel = packet
        .channel()
        .filter(|_| kind.has_channel())
        .map(|channel| {
            CryptoEngine::new(SoftwareAes, SoftwareSha256)
                .derive_channel_tag(channel.key())
                .0
        });
    let mut trace = heapless::Vec::new();
    if let Some(hints) = packet.trace().and_then(|trace| trace.complete_hints()) {
        for hint in hints {
            if trace.extend_from_slice(&hint.0).is_err() {
                trace.clear();
                break;
            }
        }
    }
    let Ok(payload) = heapless::Vec::from_slice(payload) else {
        return;
    };
    let message = Message {
        kind,
        source,
        channel,
        sender_auth: packet.sender_authenticated(),
        // The tap sees only what was accepted for this node, so a request
        // for an acknowledgment was answered.
        acked: packet.ack_requested(),
        rssi_dbm: packet.rssi(),
        snr_cb: packet.snr().map(|snr| snr.as_centibels()),
        trace,
        payload,
    };
    if INBOX.lock(|inbox| inbox.borrow_mut().store(message)) {
        ARRIVED.signal(());
    } else {
        debug_log(format_args!(
            "node-msg: inbox full, type {payload_type} discarded"
        ));
    }
}

/// A message is waiting for a link.
static ARRIVED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// The driver found the receiving link with no room for a waiting
/// message.
static FULL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// How long after finding the receiving link full the driver tries it
/// again. Its queue drains as the link reads, which tells nobody, and
/// waiting on the queue itself would contend with the driver's own sends
/// for its one sender waker.
const FULL_RETRY: Duration = Duration::from_millis(250);

/// The driver could not hand a waiting message to the link that receives.
pub fn link_full() {
    FULL.signal(());
}

/// Sends staged by the session, waiting for [`node_msg_loop`].
pub static SENDS: Channel<CriticalSectionRawMutex, NodeMsgRequest, 2> = Channel::new();

/// The status a send that never reached the MAC's queue answers with.
fn refusal<E>(error: &NodeError<E>) -> Status
where
    E: umsh_node::MacBackend<SendError = SendError>,
{
    match error {
        NodeError::Mac(MacBackendError::Send(error)) => match error {
            SendError::QueueFull | SendError::PendingAckFull | SendError::CounterPersistenceLag => {
                Status::BUSY
            }
            SendError::ChannelMissing => Status::CHANNEL_NOT_FOUND,
            SendError::PeerMissing => Status::NOMEM,
            SendError::SigningUnsupported => Status::UNIMPLEMENTED,
            SendError::Build(_) => Status::INVALID_ARGUMENT,
            SendError::IdentityMissing => Status::INVALID_STATE,
            _ => Status::FAILURE,
        },
        NodeError::Mac(MacBackendError::InvalidPublicKey) => Status::INVALID_ARGUMENT,
        _ => Status::FAILURE,
    }
}

/// The status a finished send answers with (spec §Sending).
fn outcome(ticket: &SendProgressTicket, ack: bool) -> Status {
    match ticket.abandon_reason() {
        Some(TxAbandonReason::ChannelBusy) => Status::CCA_FAILURE,
        Some(TxAbandonReason::DutyLimit) => Status::DUTY_LIMIT,
        Some(_) => Status::FAILURE,
        None if ticket.was_acked() => Status::OK,
        None if !ticket.was_transmitted() => Status::FAILURE,
        None if ack => Status::NO_ACK,
        None if ticket.has_failed() => Status::FAILURE,
        None => Status::OK,
    }
}

/// The options `request` asks for, or the status a request the MAC
/// cannot express is refused with.
fn send_options(request: &NodeMsgRequest) -> Result<SendOptions, Status> {
    let mut options = SendOptions::default()
        .with_ack_requested(request.ack)
        .with_power_dbm(request.tx_power_dbm);
    options.track_transmission = true;
    options.full_source = request.full_source;
    options.signed = request.signed;
    match request.flood_hops {
        Some(0) => options.flood_hops = None,
        Some(hops) => options.flood_hops = Some(hops),
        None => {}
    }
    if !request.source_route.is_empty() {
        let mut route = heapless::Vec::new();
        for hint in request.source_route.chunks_exact(ROUTER_HINT_LEN) {
            route
                .push(RouterHint([hint[0], hint[1]]))
                .map_err(|_| Status::INVALID_ARGUMENT)?;
        }
        options.source_route = Some(route);
    }
    Ok(options)
}

/// Hand `request` to the node: the ticket that follows it, or the status
/// it was refused with.
async fn start<CS: CounterStore + 'static>(
    node: &DeviceNode<CS>,
    request: &NodeMsgRequest,
) -> Result<SendProgressTicket, Status> {
    if !crate::device_node::node_active() {
        return Err(Status::INVALID_STATE);
    }
    let options = send_options(request)?;
    let peer = request.peer.map(PublicKey);
    let channel = request.channel_key.map(ChannelKey);
    let destination = match (request.kind, &peer, &channel) {
        (Kind::Broadcast, _, _) => SendDestination::Broadcast,
        (Kind::Unicast, Some(peer), _) => SendDestination::Unicast(peer),
        (Kind::Multicast, _, Some(channel)) => SendDestination::Multicast(channel),
        (Kind::BlindUnicast, Some(peer), Some(channel)) => {
            SendDestination::BlindUnicast { peer, channel }
        }
        _ => return Err(Status::INVALID_ARGUMENT),
    };
    // Refused here rather than left to the builder, so a payload too long
    // for the send as asked always reads as the link's mistake. Ahead of
    // the peer slot, which a send that cannot go out should not take.
    let capacity = node
        .payload_capacity(destination, &options)
        .await
        .map_err(|error| refusal(&error))?;
    if request.payload.len() > capacity {
        return Err(Status::INVALID_ARGUMENT);
    }
    if let Some(peer) = &peer
        && !node.ensure_transient_peer(peer).await
    {
        // No slot, or no such key: only the first is the device's.
        return Err(if umsh_crypto::is_valid_ed25519_public_key(peer) {
            Status::NOMEM
        } else {
            Status::INVALID_ARGUMENT
        });
    }
    node.send_to(destination, &request.payload, &options)
        .await
        .map_err(|error| refusal(&error))
}

/// `PROP_NODE_MSG_MTU`: the longest payload a send of every kind takes
/// with nothing asked of it but an acknowledgment where one is allowed.
async fn mtu<CS: CounterStore + 'static>(node: &DeviceNode<CS>) -> u16 {
    // A stranger and a channel the device need not hold: what is measured
    // is the frame, which is the same for every peer and channel.
    let peer = PublicKey([0; 32]);
    let channel = ChannelKey([0; 32]);
    let plain = SendOptions::default();
    let acked = SendOptions::default().with_ack_requested(true);
    let mut smallest = NODE_MSG_PAYLOAD_MAX;
    for (destination, options) in [
        (SendDestination::Broadcast, &plain),
        (SendDestination::Multicast(&channel), &plain),
        (SendDestination::Unicast(&peer), &acked),
        (
            SendDestination::BlindUnicast {
                peer: &peer,
                channel: &channel,
            },
            &acked,
        ),
    ] {
        match node.payload_capacity(destination, options).await {
            Ok(capacity) => smallest = smallest.min(capacity),
            Err(_) => return 0,
        }
    }
    u16::try_from(smallest).unwrap_or(u16::MAX)
}

/// What woke [`node_msg_loop`] besides a send.
enum Wake {
    /// A message arrived, or a link found full may have room by now.
    Deliver,
    /// The driver found the receiving link full.
    Full,
}

/// Run node messaging for the device node: sends from [`SENDS`], their
/// outcomes, and the driver's wake-ups. Never returns.
pub async fn node_msg_loop<CS: CounterStore + 'static, M: RawMutex + 'static>(
    node: DeviceNode<CS>,
    input: &'static InputChannel<M>,
) {
    input.send(InEvent::NodeMsgMtu(mtu(&node).await)).await;
    // Sends on the air or waiting for their acknowledgment.
    let mut in_flight: heapless::Vec<(u16, bool, SendProgressTicket), NODE_MSG_SENDS> =
        heapless::Vec::new();
    // When to have the driver try a full link again.
    let mut retry_at: Option<Instant> = None;
    loop {
        let has_room = !in_flight.is_full();
        let next_send = async {
            if has_room {
                SENDS.receive().await
            } else {
                core::future::pending().await
            }
        };
        let finished = poll_fn(|cx| {
            match in_flight
                .iter()
                .position(|(_, _, ticket)| ticket.poll_finished(cx).is_ready())
            {
                Some(index) => Poll::Ready(index),
                None => Poll::Pending,
            }
        });
        let wake = async {
            let retry = async {
                match retry_at {
                    Some(at) => Timer::at(at).await,
                    None => core::future::pending().await,
                }
            };
            match select3(ARRIVED.wait(), FULL.wait(), retry).await {
                Either3::Second(()) => Wake::Full,
                Either3::First(()) | Either3::Third(()) => Wake::Deliver,
            }
        };
        // Resolved in its own statement, so the futures borrowing
        // `in_flight` are gone before the arms change it.
        let event = select3(next_send, finished, wake).await;
        match event {
            Either3::First(request) => match start(&node, &request).await {
                Ok(ticket) => {
                    // Room was checked before the request was taken.
                    let _ = in_flight.push((request.id, request.ack, ticket));
                }
                Err(status) => {
                    input
                        .send(InEvent::NodeMsgResult {
                            id: request.id,
                            status,
                        })
                        .await;
                }
            },
            Either3::Second(index) => {
                let (id, ack, ticket) = in_flight.swap_remove(index);
                let status = outcome(&ticket, ack);
                input.send(InEvent::NodeMsgResult { id, status }).await;
            }
            Either3::Third(Wake::Full) => {
                retry_at.get_or_insert_with(|| Instant::now() + FULL_RETRY);
            }
            Either3::Third(Wake::Deliver) => {
                retry_at = None;
                input.send(InEvent::NodeMsgPending).await;
            }
        }
    }
}

/// Held by every test that touches [`INBOX`] or the claims, which are one
/// per process.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn message(acked: bool, body: u8) -> Message {
        Message {
            kind: Kind::Unicast,
            source: Source::Key([0xAA; 32]),
            channel: None,
            sender_auth: true,
            acked,
            rssi_dbm: Some(-80),
            snr_cb: Some(40),
            trace: heapless::Vec::new(),
            payload: heapless::Vec::from_slice(&[3, body]).unwrap(),
        }
    }

    fn take(inbox: &mut Inbox, link: Binding) -> Option<(u8, bool, bool)> {
        let waiting = inbox.next(link)?;
        let seen = (waiting.message.payload[1], waiting.redelivered, waiting.gap);
        let seq = waiting.seq;
        inbox.delivered(seq, link);
        Some(seen)
    }

    #[test]
    fn messages_go_out_oldest_first_once() {
        let mut inbox = Inbox::new();
        assert!(inbox.store(message(true, 1)));
        assert!(inbox.store(message(false, 2)));
        assert_eq!(take(&mut inbox, Binding::Local), Some((1, false, false)));
        assert_eq!(take(&mut inbox, Binding::Local), Some((2, false, false)));
        assert_eq!(take(&mut inbox, Binding::Local), None);
    }

    /// A full inbox of acknowledged messages refuses the next one, which
    /// the MAC then neither acknowledges nor keeps; an unacknowledged one
    /// is discarded, and the next delivery says so.
    #[test]
    fn a_full_inbox_never_displaces_an_acknowledged_message() {
        let mut inbox = Inbox::new();
        for body in 0..INBOX_SLOTS as u8 {
            assert!(inbox.store(message(true, body)));
        }
        assert!(!inbox.has_room_for_acked());
        assert!(!inbox.store(message(false, 9)));
        assert_eq!(take(&mut inbox, Binding::Local), Some((0, false, true)));
        // The gap went out with that delivery.
        assert_eq!(take(&mut inbox, Binding::Local), Some((1, false, false)));
    }

    #[test]
    fn an_acknowledged_message_displaces_an_unacknowledged_one() {
        let mut inbox = Inbox::new();
        assert!(inbox.store(message(false, 0)));
        for body in 1..INBOX_SLOTS as u8 {
            assert!(inbox.store(message(true, body)));
        }
        assert!(inbox.has_room_for_acked());
        assert!(inbox.store(message(true, 9)));
        assert!(!inbox.has_room_for_acked());
        let bodies: Vec<_> = core::iter::from_fn(|| take(&mut inbox, Binding::Local)).collect();
        assert_eq!(
            bodies,
            [
                (1, false, true),
                (2, false, false),
                (3, false, false),
                (9, false, false)
            ]
        );
    }

    /// A delivered message counts as room, and is the first replaced.
    #[test]
    fn a_delivered_message_is_room() {
        let mut inbox = Inbox::new();
        for body in 0..INBOX_SLOTS as u8 {
            inbox.store(message(true, body));
        }
        take(&mut inbox, Binding::Local);
        assert!(inbox.has_room_for_acked());
        assert!(inbox.store(message(false, 9)));
        // Nothing waiting was displaced, so no gap.
        let bodies: Vec<_> = core::iter::from_fn(|| take(&mut inbox, Binding::Local)).collect();
        assert_eq!(
            bodies,
            [
                (1, false, false),
                (2, false, false),
                (3, false, false),
                (9, false, false)
            ]
        );
    }

    #[test]
    fn a_link_that_starts_over_is_handed_its_messages_again() {
        let mut inbox = Inbox::new();
        inbox.store(message(true, 1));
        inbox.store(message(true, 2));
        inbox.store(message(true, 3));
        take(&mut inbox, Binding::Local);
        take(&mut inbox, Binding::Device);
        // The device interface starting over is not the host's: what it
        // was handed is owed to it, and to nobody else.
        assert!(inbox.redeliver(Binding::Device));
        assert_eq!(take(&mut inbox, Binding::Local), Some((3, false, false)));
        assert_eq!(take(&mut inbox, Binding::Local), None);
        assert_eq!(take(&mut inbox, Binding::Device), Some((2, true, false)));
        assert!(inbox.redeliver(Binding::Local));
        let bodies: Vec<_> = core::iter::from_fn(|| take(&mut inbox, Binding::Local)).collect();
        assert_eq!(bodies, [(1, true, false), (3, true, false)]);
    }

    /// A message owed to a link again was delivered once, so it is still
    /// room: a link that never comes back for it does not hold up the
    /// messages after it.
    #[test]
    fn a_message_owed_again_is_room() {
        let mut inbox = Inbox::new();
        for body in 0..INBOX_SLOTS as u8 {
            inbox.store(message(true, body));
            take(&mut inbox, Binding::Local);
        }
        assert!(inbox.redeliver(Binding::Local));
        assert!(inbox.has_room_for_acked());
        assert!(inbox.store(message(true, 9)));
        // The oldest went, and nothing undelivered did, so no gap.
        let bodies: Vec<_> = core::iter::from_fn(|| take(&mut inbox, Binding::Local)).collect();
        assert_eq!(
            bodies,
            [
                (1, true, false),
                (2, true, false),
                (3, true, false),
                (9, false, false)
            ]
        );
    }

    #[test]
    fn admission_refuses_only_a_claimed_type_with_no_room() {
        let _alone = TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        publish_claims([3]);
        INBOX.lock(|inbox| {
            let mut inbox = inbox.borrow_mut();
            *inbox = Inbox::new();
            for body in 0..INBOX_SLOTS as u8 {
                inbox.store(message(true, body));
            }
        });
        assert!(!admits(3));
        assert!(admits(4));
        publish_claims([]);
        assert!(admits(3));
    }

    #[test]
    fn a_message_encodes_as_a_receipt() {
        let mut out = [0u8; 300];
        let mut held = message(true, 7);
        held.trace = heapless::Vec::from_slice(&[1, 2]).unwrap();
        let len = held.encode(true, false, &mut out).unwrap();
        let frame = umsh_ulcp::Frame::parse(&out[..len]).unwrap();
        let payload = umsh_ulcp::frame::StreamPayload::parse(frame.payload).unwrap();
        assert_eq!(payload.data, [3, 7]);
        let meta = RecvMeta::parse(payload.metadata).unwrap();
        assert!(meta.redelivered && meta.acked && !meta.gap);
        assert_eq!(meta.trace, Some(&[1, 2][..]));
    }
}
