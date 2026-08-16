//! The device's answer to Node Management Requests.
//!
//! This is the seam between the mesh and the ULCP session. The node's
//! receive path taps arriving Node Management Request payloads,
//! [`admit`] decides whether the sender is entitled to be heard at all,
//! and [`responder_loop`] runs each admitted exchange: the
//! [`DeviceEngine`] reads the envelope, the session — reached through the
//! driver's event loop, since it belongs to that task — serves the frame
//! inside, and the engine wraps the answer and retains it against a
//! retransmission.
//!
//! Two things are deliberately not here. The session's property surface
//! is unchanged, because an administrative exchange runs through the same
//! dispatch as the local link (`Session::handle_admin_frame`). And no
//! part of the exchange holds a borrow across an await: the request
//! crosses to the driver as bytes and the response comes back as bytes.

use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, RawMutex};
use embassy_sync::channel::Channel;
use embassy_time::Instant;

use umsh_core::{PayloadType, PublicKey};
use umsh_hal::CounterStore;
use umsh_mac::SendOptions;
use umsh_node::{PacketFamily, ReceivedPacketRef, Transport};
use umsh_node_mgmt::device::{DeviceEngine, Dispatch, Ingress};
use umsh_node_mgmt::fragment::{continuable, produce};
use umsh_ulcp_device::{MAX_DEV_ADMINS, MULTI_MAX};

use crate::device_node::{DeviceNode, NodeMutex};
use crate::driver::{ADMIN_REPLY, AdminFrame, DevDomainSnapshot, InEvent, InputChannel};
use crate::log::debug_log;

/// What one secure unicast frame spends before its application payload
/// begins, itemized against the packet format:
///
/// ```text
///   1  FCF
///   3  destination node hint
///   3  source node hint
///   5  SECINFO: SCF and the frame counter
///  32  a source route of up to 15 router hints, with its option header
///   3  region code
///   1  trace route
///   1  end-of-options marker
///   8  MIC
///   1  payload type
///  --
///  58
/// ```
///
/// Taken as 75 to leave room for an option this list does not yet know
/// about. The asymmetry is deliberate: over-reserving costs a slightly
/// smaller fragment and one more exchange, while under-reserving costs a
/// response that cannot be sent at all — which an administrator cannot
/// tell from a lost packet.
///
/// A full 32-octet source key is not reserved for. A response goes to an
/// administrator, which is by definition a registered peer, so the hint
/// form always suffices.
const FRAME_RESERVE: usize = 75;

/// The largest Node Management payload this device produces.
///
/// Also the size of each retained response, since a retained entry holds
/// a complete payload.
pub const ADMIN_PAYLOAD_MAX: usize = umsh_radio_loraphy::MAX_PAYLOAD - FRAME_RESERVE;

/// A payload that cannot hold an envelope plus a frame is not a budget,
/// it is a bug in the reserve above.
const _: () = assert!(
    ADMIN_PAYLOAD_MAX > umsh_node_mgmt::envelope::OVERHEAD_MAX + 32,
    "FRAME_RESERVE leaves no room for a Node Management exchange"
);

/// An administrator cannot ask what a device's budget is, so it assumes
/// the smallest one a device is allowed to have. A device below that
/// would silently drop requests it is required to answer.
const _: () = assert!(
    ADMIN_PAYLOAD_MAX >= umsh_node_mgmt::PAYLOAD_MAX,
    "this radio's payload is smaller than an administrator assumes"
);

/// One admitted request on its way to the responder.
struct Request {
    from: [u8; 32],
    payload: heapless::Vec<u8, ADMIN_PAYLOAD_MAX>,
}

/// Admitted requests, from the node's receive callback to the responder
/// task.
///
/// One slot. An administrator may not have more than one exchange
/// outstanding, and the responder serves one at a time, so a second
/// arrival while one is in flight is either a different administrator or
/// a retransmission — and both are better served by being asked again
/// than by being queued behind an exchange that may take several radio
/// round trips.
static REQUESTS: Channel<NodeMutex, Request, 1> = Channel::new();

/// The mirrored `PROP_DEV_ADMINS`, and the device-domain generation it
/// was taken at.
///
/// Mirrored rather than read from the session because authorization
/// happens in the node's receive callback, which cannot borrow the
/// session and cannot await. An empty list disables node management
/// entirely, which is the post-reset default.
static ADMINS: BlockingMutex<
    CriticalSectionRawMutex,
    RefCell<heapless::Vec<[u8; 32], MAX_DEV_ADMINS>>,
> = BlockingMutex::new(RefCell::new(heapless::Vec::new()));

/// The device-domain generation the mirror was taken at, as the cursor
/// generation.
static GENERATION: AtomicU32 = AtomicU32::new(0);

/// Requests dropped before reaching the engine, by reason.
static UNAUTHORIZED: AtomicU32 = AtomicU32::new(0);
static NOT_UNICAST: AtomicU32 = AtomicU32::new(0);
static OVERSIZE: AtomicU32 = AtomicU32::new(0);
static BUSY: AtomicU32 = AtomicU32::new(0);
static RESPONSES_DROPPED: AtomicU32 = AtomicU32::new(0);

/// What the binding refused, for a device that has to explain itself
/// without having answered anybody.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdminCounters {
    /// Requests from a node that is not a listed administrator, or whose
    /// source the MAC could not authenticate.
    pub unauthorized: u32,
    /// Requests that arrived by multicast or broadcast.
    pub not_unicast: u32,
    /// Requests larger than this device's payload ceiling.
    pub oversize: u32,
    /// Requests that arrived while another exchange was in flight.
    pub busy: u32,
    /// Response payloads, which a device never solicits.
    pub responses_dropped: u32,
}

/// What the binding has refused since boot.
pub fn counters() -> AdminCounters {
    AdminCounters {
        unauthorized: UNAUTHORIZED.load(Ordering::Relaxed),
        not_unicast: NOT_UNICAST.load(Ordering::Relaxed),
        oversize: OVERSIZE.load(Ordering::Relaxed),
        busy: BUSY.load(Ordering::Relaxed),
        responses_dropped: RESPONSES_DROPPED.load(Ordering::Relaxed),
    }
}

/// Republish the administrator list from a device-domain snapshot. Called
/// by the device-domain sync loop on every snapshot, so a key added over
/// either binding takes effect without a reboot.
pub fn publish_dev_domain(snapshot: &DevDomainSnapshot) {
    ADMINS.lock(|cell| {
        let mut admins = cell.borrow_mut();
        admins.clear();
        for key in snapshot.admins.iter() {
            let _ = admins.push(*key);
        }
    });
    GENERATION.store(snapshot.version, Ordering::Relaxed);
}

fn is_admin(key: &[u8; 32]) -> bool {
    ADMINS.lock(|cell| cell.borrow().iter().any(|listed| listed == key))
}

/// Decide whether an arriving packet is a Node Management Request this
/// device will act on, and queue it if so.
///
/// Registered as a receive handler at bring-up; returns `false` always,
/// so the packet still reaches every other observer. Everything refused
/// is refused silently — an unlisted sender learns nothing about whether
/// the device is manageable, not even that it declined to say.
pub fn admit(packet: &ReceivedPacketRef<'_>) {
    match packet.payload_type() {
        PayloadType::NodeManagementRequest => {}
        // A device never solicits anything, so a response addressed to it
        // is either misdirected or an attempt to confuse it.
        PayloadType::NodeManagementResponse => {
            RESPONSES_DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        _ => return,
    }
    if !matches!(
        packet.packet_family(),
        PacketFamily::Unicast | PacketFamily::BlindUnicast
    ) {
        NOT_UNICAST.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // Both conditions matter and neither implies the other: an
    // unauthenticated source could claim any key, and an authenticated
    // one that is not listed is simply not an administrator here.
    let Some(from) = packet.from_key().filter(|_| packet.source_authenticated()) else {
        UNAUTHORIZED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if !is_admin(&from.0) {
        UNAUTHORIZED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut payload = heapless::Vec::new();
    if payload.extend_from_slice(packet.payload()).is_err() {
        // Larger than this device can answer within. Dropped rather than
        // truncated: a truncated envelope would be answered
        // STATUS_PARSE_ERROR, which is a worse explanation than silence.
        OVERSIZE.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if REQUESTS
        .try_send(Request {
            from: from.0,
            payload,
        })
        .is_err()
    {
        BUSY.fetch_add(1, Ordering::Relaxed);
    }
}

/// Serve admitted Node Management exchanges forever.
///
/// `nonce` is drawn once per boot from the platform's cryptographic RNG.
/// It is what stops a cursor issued before a reboot from being honored
/// after one, when the device-domain generation has started over.
pub async fn responder_loop<CS: CounterStore + 'static, M: RawMutex + 'static>(
    node: DeviceNode<CS>,
    input: &'static InputChannel<M>,
    nonce: u16,
) {
    let mut engine: DeviceEngine<ADMIN_PAYLOAD_MAX> = DeviceEngine::new(nonce);
    let mut out = [0u8; ADMIN_PAYLOAD_MAX];
    let mut cut = [0u8; ADMIN_PAYLOAD_MAX];
    loop {
        let request = REQUESTS.receive().await;
        let generation = GENERATION.load(Ordering::Relaxed) as u16;
        let now_ms = Instant::now().as_millis();
        let len = match engine.begin(
            &request.from,
            &request.payload,
            generation,
            now_ms,
            &mut out,
        ) {
            Ingress::Drop(reason) => {
                debug_log(format_args!("admin: dropped {reason:?}"));
                continue;
            }
            Ingress::Respond { len } => Some(len),
            Ingress::Dispatch(dispatch) => {
                let reply = serve(input, &dispatch).await;
                let produced = produce(&reply, &dispatch, &mut cut);
                match engine.complete(produced, &mut out) {
                    Ok(len) => len,
                    Err(error) => {
                        // Nothing goes out. The administrator retransmits,
                        // and gets here again — which is the honest
                        // outcome for a reply this device cannot carry.
                        debug_log(format_args!("admin: reply REFUSED {error:?}"));
                        continue;
                    }
                }
            }
        };
        // A reset-class command is answered by no payload at all; its
        // delivery was confirmed by the MAC acknowledgment of the request.
        let Some(len) = len else { continue };
        respond(&node, &request.from, &out[..len]).await;
    }
}

/// Hand one frame to the session and wait for its answer.
///
/// The session belongs to the driver's task, so the exchange crosses the
/// event loop. It always answers — an empty reply is the answer for a
/// reset — so this never has to time out.
async fn serve<M: RawMutex + 'static>(
    input: &'static InputChannel<M>,
    dispatch: &Dispatch<'_>,
) -> AdminFrame {
    let mut frame = AdminFrame::new();
    if frame.extend_from_slice(dispatch.frame).is_err() {
        // The frame came out of a payload smaller than this buffer.
        debug_assert!(
            false,
            "admin request frame exceeds the driver's frame buffer"
        );
        return AdminFrame::new();
    }
    // A read may be continued with a cursor, so let the session build the
    // whole answer and cut it down here. Everything else — a write
    // sequence above all — is measured against what actually fits,
    // because there is no continuing it: the binding's rule is that an
    // entry whose reply would not fit is not executed at all.
    let reply_budget = match dispatch.command() {
        Some(cmd) if continuable(cmd) => MULTI_MAX,
        _ => dispatch.budget,
    };
    input
        .send(InEvent::Admin {
            frame,
            reply_budget,
        })
        .await;
    ADMIN_REPLY.receive().await
}

/// Send one response payload back to the administrator.
///
/// No acknowledgment is requested. The administrator's token retry is the
/// reliability layer for this binding, and it covers a lost response and
/// a lost request alike — an ack would only tell the device something it
/// has no use for.
async fn respond<CS: CounterStore + 'static>(node: &DeviceNode<CS>, to: &[u8; 32], payload: &[u8]) {
    let mut wire = heapless::Vec::<u8, { ADMIN_PAYLOAD_MAX + 1 }>::new();
    if wire
        .push(PayloadType::NodeManagementResponse as u8)
        .is_err()
        || wire.extend_from_slice(payload).is_err()
    {
        debug_assert!(false, "admin response exceeds ADMIN_PAYLOAD_MAX");
        return;
    }
    if node
        .send(&PublicKey(*to), &wire, &SendOptions::default())
        .await
        .is_err()
    {
        debug_log(format_args!(
            "admin: response to {:02x}{:02x}.. FAILED",
            to[0], to[1]
        ));
    }
}
