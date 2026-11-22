//! The board-agnostic half of a LAN bearer: what a radio does with a
//! datagram from the group before its node sees it.
//!
//! The socket, the group membership, and the DNS-SD responder are the
//! board's, because they are its network stack's. Everything that decides
//! about a datagram is here, where it can be tested on a host:
//!
//! - **Validation.** One UMSH frame per datagram, no header. Empty and
//!   oversized datagrams, and ones whose version bits name no protocol,
//!   are dropped and counted. MeshCore v1 frames are recognized and left
//!   alone: this node does not carry them across the LAN.
//! - **The ingress limit.** A token bucket over the datagrams handed to
//!   the node, so a busy LAN cannot spend the radio's airtime faster than
//!   the operator allows. The duty ceiling still applies behind it.
//! - **The hand-off.** A [`BridgePort`] the radio multiplexer drains into
//!   the node as [`RxOrigin::Bearer`](umsh_hal::RxOrigin), and into the
//!   ULCP session, which hears the LAN as the device does.
//! - **The egress.** Every UMSH frame the radio puts on the air, as the
//!   multiplexer reports it, queued for the board's socket task. The LAN
//!   works as backhaul does: whether a frame is carried is the node's
//!   ordinary forwarding decision, and the LAN sees what came of it.
//!
//! Spec: `docs/protocol-legacy/src/lan-bearer.md`.

use core::cell::RefCell;
use core::task::{Context, Poll};

use embassy_sync::blocking_mutex::{Mutex, raw::RawMutex};
use embassy_sync::waitqueue::WakerRegistration;
use heapless::{Deque, Vec};
use umsh_lan_bearer::Datagram;
use umsh_radio_loraphy::MAX_PAYLOAD;
use umsh_ulcp::stats::{Counter, StatsLedger};

use crate::radio_mux::BridgePort;

// The device's default (what PROP_LAN_BEARER_GROUP reports after a reset)
// and the transport's must be the same group.
const _: () = {
    let [a, b, c, d] = umsh_ulcp::lan::DEFAULT_GROUP;
    let [e, f, g, h] = umsh_lan_bearer::DEFAULT_GROUP;
    assert!(a == e && b == f && c == g && d == h);
    assert!(umsh_ulcp::lan::DEFAULT_PORT == umsh_lan_bearer::DEFAULT_PORT);
};

/// Datagrams waiting for the multiplexer. The node drains them as fast as
/// it receives anything; a few absorb a burst while it is busy.
const QUEUE: usize = 4;

/// Transmitted frames waiting for the socket task, which sends each at
/// once; a few absorb a burst while it is busy.
const OUTGOING: usize = 4;

/// What became of one datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Handed toward the node.
    Accepted,
    /// The bearer is not running.
    Inactive,
    /// Empty, oversized, or of an unknown protocol version.
    Malformed,
    /// A MeshCore v1 frame, which this node does not carry across the
    /// LAN.
    Foreign,
    /// Over the ingress limit.
    Limited,
    /// The queue toward the node was full.
    Overflow,
}

/// What a datagram is, judged by its first octet alone—as a radio judges
/// a reception, before parsing anything.
pub fn classify(datagram: &[u8]) -> Verdict {
    match umsh_lan_bearer::classify(datagram) {
        Datagram::Umsh => Verdict::Accepted,
        Datagram::MeshCoreV1 => Verdict::Foreign,
        Datagram::Malformed => Verdict::Malformed,
    }
}

/// The ingress limit: a bucket of datagrams, refilled continuously at the
/// configured rate.
///
/// The bucket holds a tenth of a minute's allowance, and never less than
/// one datagram, so a quiet LAN can deliver a short burst and a busy one
/// is held to the rate.
#[derive(Clone, Copy, Debug)]
pub struct IngressLimit {
    per_minute: u16,
    /// Tokens in thousandths of a datagram, so a slow rate still refills
    /// between datagrams.
    milli_tokens: u64,
    last_ms: u64,
}

impl IngressLimit {
    pub const fn new(per_minute: u16, now_ms: u64) -> Self {
        let mut limit = Self {
            per_minute,
            milli_tokens: 0,
            last_ms: now_ms,
        };
        limit.milli_tokens = limit.capacity_milli();
        limit
    }

    const fn capacity_milli(&self) -> u64 {
        let per_minute = self.per_minute as u64;
        let tenth = per_minute / 10;
        (if tenth == 0 { 1 } else { tenth }) * 1000
    }

    /// Take one datagram's token, if the bucket has one.
    pub fn admit(&mut self, now_ms: u64) -> bool {
        let per_minute = u64::from(self.per_minute.max(1));
        let elapsed_ms = now_ms.saturating_sub(self.last_ms);
        // per_minute datagrams per 60,000 ms is per_minute milli-tokens
        // per 60 ms. Time is consumed only as far as it earned whole
        // milli-tokens, so frequent calls lose nothing to rounding.
        let refill = elapsed_ms.saturating_mul(per_minute) / 60;
        self.last_ms = self.last_ms.saturating_add(refill * 60 / per_minute);
        self.milli_tokens = self.milli_tokens.saturating_add(refill);
        if self.milli_tokens >= self.capacity_milli() {
            self.milli_tokens = self.capacity_milli();
            self.last_ms = now_ms;
        }
        if self.milli_tokens >= 1000 {
            self.milli_tokens -= 1000;
            true
        } else {
            false
        }
    }
}

struct State {
    active: bool,
    limit: IngressLimit,
    queue: Deque<Vec<u8, MAX_PAYLOAD>, QUEUE>,
    waker: WakerRegistration,
    outgoing: Deque<Vec<u8, MAX_PAYLOAD>, OUTGOING>,
    outgoing_waker: WakerRegistration,
}

/// The LAN bearer's port into the radio multiplexer.
///
/// A board keeps one in a `static`, offers it every datagram its socket
/// receives, and attaches it to the multiplexer with
/// [`RxOrigin::Bearer`](umsh_hal::RxOrigin) as its origin.
pub struct LanPort<M: RawMutex> {
    state: Mutex<M, RefCell<State>>,
    stats: Option<&'static StatsLedger>,
}

impl<M: RawMutex> LanPort<M> {
    pub const fn new(stats: Option<&'static StatsLedger>) -> Self {
        Self {
            state: Mutex::new(RefCell::new(State {
                active: false,
                limit: IngressLimit::new(umsh_ulcp::lan::DEFAULT_INGRESS_LIMIT, 0),
                queue: Deque::new(),
                waker: WakerRegistration::new(),
                outgoing: Deque::new(),
                outgoing_waker: WakerRegistration::new(),
            })),
            stats,
        }
    }

    /// Start or stop accepting datagrams, at `per_minute`. Stopping drops
    /// whatever was waiting in either direction: frames from before the
    /// bearer went away are not worth carrying when it comes back.
    pub fn configure(&self, active: bool, per_minute: u16, now_ms: u64) {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if !active {
                state.queue.clear();
                state.outgoing.clear();
            }
            if active && (!state.active || state.limit.per_minute != per_minute) {
                state.limit = IngressLimit::new(per_minute, now_ms);
            }
            state.active = active;
        });
    }

    /// Judge one datagram from the group and, if it passes, queue it for
    /// the node.
    pub fn offer(&self, datagram: &[u8], now_ms: u64) -> Verdict {
        let verdict = self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if !state.active {
                return Verdict::Inactive;
            }
            match classify(datagram) {
                Verdict::Accepted => {}
                other => return other,
            }
            if !state.limit.admit(now_ms) {
                return Verdict::Limited;
            }
            let frame = Vec::from_slice(datagram).expect("classified as fitting");
            if state.queue.push_back(frame).is_err() {
                return Verdict::Overflow;
            }
            state.waker.wake();
            Verdict::Accepted
        });
        if let Some(stats) = self.stats {
            match verdict {
                Verdict::Accepted => stats.bump(Counter::LanRx),
                Verdict::Limited | Verdict::Overflow => stats.bump(Counter::LanRxLimited),
                Verdict::Malformed => stats.bump(Counter::LanRxMalformed),
                Verdict::Inactive | Verdict::Foreign => {}
            }
        }
        verdict
    }
}

impl<M: RawMutex> LanPort<M> {
    /// Wait for the next frame to send to the group.
    pub async fn outgoing(&self) -> Vec<u8, MAX_PAYLOAD> {
        core::future::poll_fn(|cx| {
            self.state.lock(|cell| {
                let mut state = cell.borrow_mut();
                state.outgoing_waker.register(cx.waker());
                match state.outgoing.pop_front() {
                    Some(frame) => Poll::Ready(frame),
                    None => Poll::Pending,
                }
            })
        })
        .await
    }
}

impl<M: RawMutex> BridgePort for LanPort<M> {
    /// Queue a frame the radio put on the air for the group. A MeshCore
    /// frame is left off, as one from the group is.
    fn transmitted(&self, data: &[u8]) {
        if classify(data) != Verdict::Accepted {
            return;
        }
        let outcome = self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if !state.active {
                return None;
            }
            let frame = Vec::from_slice(data).expect("classified as fitting");
            // The oldest goes first: the newest frame is the one a
            // neighbor on the LAN is still waiting for.
            let dropped = state.outgoing.is_full() && state.outgoing.pop_front().is_some();
            let _ = state.outgoing.push_back(frame);
            state.outgoing_waker.wake();
            Some(dropped)
        });
        if let (Some(stats), Some(dropped)) = (self.stats, outcome) {
            stats.bump(Counter::LanExported);
            if dropped {
                stats.bump(Counter::LanExportDropped);
            }
        }
    }

    fn poll_receive(&self, cx: &mut Context<'_>) -> Poll<Vec<u8, MAX_PAYLOAD>> {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.waker.register(cx.waker());
            match state.queue.pop_front() {
                Some(frame) => Poll::Ready(frame),
                None => Poll::Pending,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    const UMSH: u8 = 0b1100_0000;

    #[test]
    fn datagrams_are_judged_by_their_first_octet() {
        assert_eq!(classify(&[]), Verdict::Malformed);
        assert_eq!(classify(&[UMSH, 1, 2]), Verdict::Accepted);
        assert_eq!(classify(&[0b0000_0000, 1]), Verdict::Foreign);
        assert_eq!(classify(&[0b0100_0000, 1]), Verdict::Malformed);
        assert_eq!(classify(&[UMSH; MAX_PAYLOAD + 1]), Verdict::Malformed);
        assert_eq!(classify(&[UMSH; MAX_PAYLOAD]), Verdict::Accepted);
    }

    #[test]
    fn the_ingress_limit_allows_a_burst_then_the_rate() {
        // 60 a minute: a burst of six, then one a second.
        let mut limit = IngressLimit::new(60, 0);
        for _ in 0..6 {
            assert!(limit.admit(0));
        }
        assert!(!limit.admit(0));
        assert!(!limit.admit(999));
        assert!(limit.admit(1_000));
        assert!(!limit.admit(1_000));
        // A long quiet spell refills no more than the bucket holds.
        for _ in 0..6 {
            assert!(limit.admit(600_000));
        }
        assert!(!limit.admit(600_000));
    }

    #[test]
    fn a_slow_limit_still_admits_one() {
        let mut limit = IngressLimit::new(1, 0);
        assert!(limit.admit(0));
        assert!(!limit.admit(59_999));
        assert!(limit.admit(60_000));
    }

    #[test]
    fn the_port_counts_and_queues_what_it_accepts() {
        static STATS: StatsLedger = StatsLedger::new();
        let port = LanPort::<NoopRawMutex>::new(Some(&STATS));
        assert_eq!(port.offer(&[UMSH, 1], 0), Verdict::Inactive);
        port.configure(true, 10, 0);
        assert_eq!(port.offer(&[UMSH, 1], 0), Verdict::Accepted);
        assert_eq!(port.offer(&[UMSH, 2], 0), Verdict::Limited);
        assert_eq!(port.offer(&[0x40], 0), Verdict::Malformed);
        assert_eq!(port.offer(&[0x00], 0), Verdict::Foreign);
        assert_eq!(STATS.get(Counter::LanRx), 1);
        assert_eq!(STATS.get(Counter::LanRxLimited), 1);
        assert_eq!(STATS.get(Counter::LanRxMalformed), 1);

        let waker = core::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        match port.poll_receive(&mut cx) {
            Poll::Ready(frame) => assert_eq!(frame.as_slice(), &[UMSH, 1]),
            Poll::Pending => panic!("the accepted datagram was not queued"),
        }
        assert!(port.poll_receive(&mut cx).is_pending());

        port.offer(&[UMSH, 3], 60_000);
        port.configure(false, 10, 60_000);
        assert!(port.poll_receive(&mut cx).is_pending(), "stopping drops it");
    }

    /// What the radio sends goes to the group while the bearer runs, oldest
    /// first, newest kept when it overflows; MeshCore stays off the LAN.
    #[test]
    fn transmitted_frames_queue_for_the_group() {
        let port = LanPort::<NoopRawMutex>::new(None);
        let next = || embassy_futures::block_on(port.outgoing());
        port.transmitted(&[UMSH, 0]);
        port.configure(true, 60, 0);
        port.transmitted(&[0b0000_0000, 1]);
        for tag in 1..=OUTGOING as u8 + 1 {
            port.transmitted(&[UMSH, tag]);
        }
        for tag in 2..=OUTGOING as u8 + 1 {
            assert_eq!(next().as_slice(), &[UMSH, tag]);
        }
        port.transmitted(&[UMSH, 9]);
        port.configure(false, 60, 0);
        port.configure(true, 60, 0);
        port.transmitted(&[UMSH, 10]);
        assert_eq!(next().as_slice(), &[UMSH, 10], "stopping drops what waited");
    }
}
