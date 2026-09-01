//! Radio multiplexer: shares the one physical radio among multiple clients.
//!
//! Today the clients are the ULCP session and the device node. The
//! physical radio's [`Channels`] bundle has a single `tx_done` signal, so
//! completion attribution breaks the moment two clients transmit. The mux
//! owns the real bundle and gives every client a private virtual
//! [`Channels`] of the same type:
//!
//! - **TX**: requests are granted one at a time (round-robin under
//!   contention) and forwarded to the real TX queue; the real `tx_done`
//!   result is routed to the granting client's own `tx_done`, so each
//!   client sees exactly the completions for its own requests. Once the
//!   frame is on the air every *other* client receives a copy of it,
//!   marked [`RxOrigin::LocalTx`]. A radio cannot hear itself, but the
//!   clients share one antenna, and a client that never learns what the
//!   antenna beside it emitted cannot talk to it at all.
//! - **RX**: every received frame is fanned out to every client. Dual
//!   delivery is what the ULCP spec requires — frames addressed
//!   to the device identity are processed by the device itself *and*
//!   independently offered to host receive filtering. A client whose RX
//!   queue is full loses that frame (the same drop policy the radio
//!   runner applies to the real queue) without stalling the others.
//!
//! RX fan-out continues while a transmit is in flight; only the grant of
//! the *next* TX waits for the previous completion. The runner-side
//! controls (`DeviceControl`: settings, RSSI sampling) are single-owner
//! device-domain state and bypass the mux entirely.
//!
//! # Backhaul mode
//!
//! [`MuxMode::set_backhaul`] moves the session client off the shared
//! medium and onto a point-to-point link with the rest of the clients:
//!
//! - Receptions off the air go to the medium clients only.
//! - A session transmit never reaches the radio. It is handed to the
//!   medium clients as [`RxOrigin::Backhaul`], which the MAC treats as a
//!   frame heard from a neighbor and may therefore repeat.
//! - Medium transmits are unchanged, so the session still sees everything
//!   the device puts on the air.
//!
//! The device's own repeater then carries traffic in both directions
//! between the attached host and the mesh, which is what a bridge needs:
//! its forwarding rules, duplicate suppression, and hop accounting all
//! apply to the tunneled traffic instead of being reimplemented above it.

use core::future::poll_fn;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Poll;

use embassy_futures::select::{Either3, select3};
use embassy_sync::blocking_mutex::raw::RawMutex;
use umsh_core::{Fcf, UMSH_VERSION};
use umsh_hal::{RxInfo, RxOrigin, Snr, TxError};
use umsh_radio_loraphy::{Channels, MAX_PAYLOAD, RxFrame, TxRequest};
use umsh_ulcp::stats::{Counter, StatsLedger};

/// Index in `clients` of the ULCP session's virtual bundle.
///
/// Backhaul mode is defined in terms of "the session" and "the medium",
/// so the mux has to know which client is which. Every board wires the
/// session first.
const SESSION: usize = 0;

/// How the mux is routing, written by whoever handles
/// [`Effect::ApplyBackhaul`](umsh_ulcp_device::Effect) and read by the
/// mux as each frame is routed.
pub struct MuxMode(AtomicBool);

impl MuxMode {
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Put the session client on a point-to-point link with the medium
    /// clients, or return it to the shared medium.
    pub fn set_backhaul(&self, enabled: bool) {
        self.0.store(enabled, Ordering::Relaxed);
    }

    /// Whether backhaul mode is in effect.
    pub fn backhaul(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for MuxMode {
    fn default() -> Self {
        Self::new()
    }
}

/// The mode cell every board's mux and session driver share.
pub static MUX_MODE: MuxMode = MuxMode::new();

/// Run the multiplexer over the real radio `Channels` bundle.
///
/// `real` must be the bundle served by the radio runner, and the mux must
/// be that bundle's only client. Each entry in `clients` is one virtual
/// bundle, owned (RX-drained and TX-fed) by exactly one radio client.
/// `clients[0]` must be the ULCP session; the rest are on the medium.
///
/// # Counting
///
/// This is the only place on a device where every frame that reaches the
/// air, and every frame that comes off it, passes exactly once no matter
/// which client owns it — the ULCP session transmits straight to the
/// radio and never touches the device node's MAC — so `stats` is
/// tallied here rather than anywhere further up. A board with no ledger
/// passes `None`.
pub async fn radio_mux<M, const RX: usize, const TX: usize>(
    real: &'static Channels<M, RX, TX>,
    clients: &'static [&'static Channels<M, RX, TX>],
    mode: &'static MuxMode,
    stats: Option<&'static StatsLedger>,
) -> !
where
    M: RawMutex,
{
    // The transmit currently at the radio, if any. The frame bytes are
    // kept because `tx_done` reports only a result, and the copy owed to
    // the other clients can only be sent once the radio confirms the
    // frame actually went out.
    let mut in_flight: Option<InFlight> = None;
    // Where the next contended TX scan starts, so one busy client cannot
    // starve the others.
    let mut arbitration_start: usize = 0;

    loop {
        // Only wait for a TX completion while one is outstanding, so a
        // spurious tx_done can never be attributed to anyone.
        let tx_done = async {
            match in_flight {
                Some(_) => real.tx_done.wait().await,
                None => core::future::pending().await,
            }
        };
        // Only grant a new transmit while the radio is free; queued
        // requests keep waiting in their client's virtual TX queue.
        let next_tx = async {
            match in_flight {
                None => receive_any_tx(clients, arbitration_start).await,
                Some(_) => core::future::pending().await,
            }
        };

        match select3(real.rx.receive(), tx_done, next_tx).await {
            Either3::First(frame) => {
                // Counted before delivery, because who hears it is a
                // routing question and this one is about the antenna.
                note_reception(stats, &frame.data);
                // In backhaul mode the session is not on the medium, so
                // it hears nothing off the air.
                let skip = mode.backhaul().then_some(SESSION);
                deliver(clients, skip, &frame.data, frame.info);
            }
            Either3::Second(result) => {
                let Some(sent) = in_flight.take() else {
                    continue;
                };
                let aired = result.is_ok();
                if let Some(stats) = stats {
                    // Every completion the radio reports arrives here, and
                    // only frames that went to the radio have one — see
                    // the backhaul branch below, which answers its own.
                    match &result {
                        Ok(()) => stats.bump(Counter::TxPackets),
                        Err(TxError::CadTimeout) => stats.bump(Counter::TxChannelBusy),
                        Err(_) => {}
                    }
                }
                clients[sent.owner].tx_done.signal(result);
                if aired {
                    deliver(
                        clients,
                        Some(sent.owner),
                        &sent.data,
                        unmeasured(sent.data.len(), RxOrigin::LocalTx),
                    );
                }
            }
            Either3::Third((who, request)) => {
                // Drop any stale latched completion (e.g. from an earlier
                // transmit whose requester was cancelled before consuming
                // it) so the client can only observe this request's
                // result. `try_take` leaves a registered waiter intact,
                // unlike `reset`, which would silently drop its waker.
                let _ = clients[who].tx_done.try_take();
                arbitration_start = (who + 1) % clients.len();

                if who == SESSION && mode.backhaul() {
                    // The session's link is point to point: the frame
                    // goes to the medium clients and nowhere else.
                    //
                    // Nothing is counted on this path, and the early
                    // return is what keeps it that way: the completion it
                    // signals below is synthesized here, never seen by the
                    // radio, so it cannot reach the arm above. A frame
                    // that never reached the air is not a transmission,
                    // and the busy verdict this branch invents to report a
                    // backed-up tunnel is not a busy channel. If this
                    // early return ever goes away, the counting above has
                    // to grow a guard.
                    let delivered = deliver(
                        clients,
                        Some(SESSION),
                        &request.data,
                        unmeasured(request.data.len(), RxOrigin::Backhaul),
                    );
                    // A full receive queue means the far side is behind,
                    // and this frame is gone. Reporting it as a busy
                    // channel is both true of the link and the one
                    // outcome the sender already knows how to retry.
                    clients[SESSION].tx_done.signal(if delivered {
                        Ok(())
                    } else {
                        Err(TxError::CadTimeout)
                    });
                    continue;
                }

                let data = request.data.clone();
                real.tx.send(request).await;
                in_flight = Some(InFlight { owner: who, data });
            }
        }
    }
}

/// A transmit handed to the radio, held until its completion is known.
struct InFlight {
    owner: usize,
    data: heapless::Vec<u8, MAX_PAYLOAD>,
}

/// Tally one reception off the air, split by whether it is ours.
///
/// The test is the frame-control field alone — the protocol version and
/// the reserved bit — not a header parse. The MAC walks the header
/// anyway a moment later, and this runs in the path every client shares.
///
/// It is a test of provenance, not of health: a truncated or damaged
/// UMSH frame still counts as UMSH, which is right. What went wrong with
/// a frame of ours shows up in the CRC tally and in the gap between
/// receptions and the ones the node acted on. What lands in
/// `RxNonUmsh` is somebody else's traffic on the same sync word.
fn note_reception(stats: Option<&'static StatsLedger>, data: &[u8]) {
    let Some(stats) = stats else {
        return;
    };
    let ours = match data.first() {
        Some(&first) => {
            let fcf = Fcf(first);
            fcf.version() == UMSH_VERSION && fcf.reserved_valid()
        }
        // A zero-length reception is not a packet of anyone's, and the
        // radio should never hand one up; count it with the foreign
        // traffic rather than inventing a third bucket for it.
        None => false,
    };
    stats.bump(if ours {
        Counter::RxPackets
    } else {
        Counter::RxNonUmsh
    });
}

/// Metadata for a frame that reached a client without being received:
/// there is nothing to report but the length and where it came from.
fn unmeasured(len: usize, origin: RxOrigin) -> RxInfo {
    RxInfo {
        len,
        rssi: 0,
        snr: Snr::from_centibels(0),
        lqi: None,
        origin,
    }
}

/// Copy `data` into every client's receive queue except `skip`, returning
/// whether every intended recipient accepted it. A client whose queue is
/// full loses the frame rather than stalling the others.
fn deliver<M, const RX: usize, const TX: usize>(
    clients: &[&Channels<M, RX, TX>],
    skip: Option<usize>,
    data: &heapless::Vec<u8, MAX_PAYLOAD>,
    info: RxInfo,
) -> bool
where
    M: RawMutex,
{
    let mut delivered = true;
    for (index, client) in clients.iter().enumerate() {
        if Some(index) == skip {
            continue;
        }
        let copy = RxFrame {
            data: data.clone(),
            info,
        };
        if client.rx.try_send(copy).is_ok() {
            client.rx_waker.wake();
        } else {
            delivered = false;
        }
    }
    delivered
}

/// Wait for a TX request from any client, scanning from `start` so
/// arbitration round-robins instead of always favoring client 0.
async fn receive_any_tx<M, const RX: usize, const TX: usize>(
    clients: &[&Channels<M, RX, TX>],
    start: usize,
) -> (usize, TxRequest)
where
    M: RawMutex,
{
    poll_fn(move |cx| {
        // Register with every queue before scanning: a send racing in
        // behind an empty scan must still wake this future.
        for client in clients {
            let _ = client.tx.poll_ready_to_receive(cx);
        }
        for offset in 0..clients.len() {
            let index = (start + offset) % clients.len();
            if let Ok(request) = clients[index].tx.try_receive() {
                return Poll::Ready((index, request));
            }
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::Future;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Waker};
    use embassy_futures::select::{Either, select};
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use lora_phy::mod_params::RadioError;
    use std::sync::Arc;
    use umsh_hal::CadPolicy;

    type TestCh = Channels<NoopRawMutex, 4, 2>;

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
    }

    fn channels() -> &'static TestCh {
        Box::leak(Box::new(Channels::new()))
    }

    /// Drive the mux and a test scenario concurrently until the scenario
    /// completes. Each run gets its own mode cell, so tests sharing a
    /// process cannot see each other's routing.
    fn run<F: Future>(
        real: &'static TestCh,
        clients: &'static [&'static TestCh],
        scenario: F,
    ) -> F::Output {
        run_with_mode(real, clients, mode(), scenario)
    }

    fn run_with_mode<F: Future>(
        real: &'static TestCh,
        clients: &'static [&'static TestCh],
        mode: &'static MuxMode,
        scenario: F,
    ) -> F::Output {
        drive(real, clients, mode, None, scenario)
    }

    /// Drive the mux with a ledger attached, so a scenario can read back
    /// what it counted.
    fn run_with_stats<F: Future>(
        real: &'static TestCh,
        clients: &'static [&'static TestCh],
        mode: &'static MuxMode,
        stats: &'static StatsLedger,
        scenario: F,
    ) -> F::Output {
        drive(real, clients, mode, Some(stats), scenario)
    }

    fn drive<F: Future>(
        real: &'static TestCh,
        clients: &'static [&'static TestCh],
        mode: &'static MuxMode,
        stats: Option<&'static StatsLedger>,
        scenario: F,
    ) -> F::Output {
        block_on(async {
            match select(radio_mux(real, clients, mode, stats), scenario).await {
                Either::First(_) => unreachable!("mux never returns"),
                Either::Second(output) => output,
            }
        })
    }

    fn ledger() -> &'static StatsLedger {
        Box::leak(Box::new(StatsLedger::new()))
    }

    fn mode() -> &'static MuxMode {
        Box::leak(Box::new(MuxMode::new()))
    }

    fn backhaul_mode() -> &'static MuxMode {
        let mode = mode();
        mode.set_backhaul(true);
        mode
    }

    fn rx_frame(tag: u8) -> RxFrame {
        let mut data = heapless::Vec::new();
        data.push(tag).unwrap();
        RxFrame {
            data,
            info: RxInfo {
                len: 1,
                rssi: -40,
                snr: Snr::from_decibels(5),
                lqi: None,
                origin: RxOrigin::Air,
            },
        }
    }

    fn tx_request(tag: u8) -> TxRequest {
        let mut data = heapless::Vec::new();
        data.push(tag).unwrap();
        TxRequest {
            data,
            power_dbm: None,
            cad: CadPolicy::Skip,
        }
    }

    #[test]
    fn tx_completions_route_to_the_requesting_client() {
        let real = channels();
        let a = channels();
        let b = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([a, b]));

        run(real, clients, async {
            a.tx.send(tx_request(0xA1)).await;
            b.tx.send(tx_request(0xB1)).await;

            // Client A queued first from a fresh mux, so its request is
            // granted first; B's stays held until A's completion.
            let granted = real.tx.receive().await;
            assert_eq!(granted.data.as_slice(), &[0xA1]);
            assert!(
                real.tx.try_receive().is_err(),
                "B granted while A in flight"
            );

            real.tx_done
                .signal(Err(TxError::Io(RadioError::TransmitTimeout)));
            assert!(a.tx_done.wait().await.is_err());
            assert!(b.tx_done.try_take().is_none(), "completion leaked to B");

            let granted = real.tx.receive().await;
            assert_eq!(granted.data.as_slice(), &[0xB1]);
            real.tx_done.signal(Ok(()));
            assert!(b.tx_done.wait().await.is_ok());
            assert!(a.tx_done.try_take().is_none(), "completion leaked to A");
        });
    }

    #[test]
    fn tx_grants_round_robin_under_contention() {
        let real = channels();
        let a = channels();
        let b = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([a, b]));

        run(real, clients, async {
            a.tx.send(tx_request(0xA1)).await;
            a.tx.send(tx_request(0xA2)).await;
            b.tx.send(tx_request(0xB1)).await;

            // A1 goes first; B1 must beat A2 even though A queued earlier.
            let mut order = std::vec::Vec::new();
            for _ in 0..3 {
                let granted = real.tx.receive().await;
                order.push(granted.data[0]);
                real.tx_done.signal(Ok(()));
                // Consume the routed completion so the next wait is clean.
                let owner = if order.last() == Some(&0xB1) { b } else { a };
                assert!(owner.tx_done.wait().await.is_ok());
            }
            assert_eq!(order, [0xA1, 0xB1, 0xA2]);
        });
    }

    #[test]
    fn rx_fans_out_to_every_client() {
        let real = channels();
        let a = channels();
        let b = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([a, b]));

        struct CountingWake(AtomicUsize);
        impl std::task::Wake for CountingWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        run(real, clients, async {
            // Client B consumes frames the way LoraphyRadio does: via
            // rx_waker, not the channel's own waitlist.
            let wakes = Arc::new(CountingWake(AtomicUsize::new(0)));
            b.rx_waker.register(&Waker::from(wakes.clone()));

            real.rx.send(rx_frame(0x11)).await;

            let got_a = a.rx.receive().await;
            assert_eq!(got_a.data.as_slice(), &[0x11]);
            assert_eq!(got_a.info.rssi, -40);
            let got_b = b.rx.receive().await;
            assert_eq!(got_b.data.as_slice(), &[0x11]);
            assert!(wakes.0.load(Ordering::SeqCst) > 0, "rx_waker not woken");
        });
    }

    #[test]
    fn rx_overflow_drops_only_the_full_client() {
        let real = channels();
        let a = channels();
        let b = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([a, b]));

        run(real, clients, async {
            // Nobody drains A, so it saturates at its queue depth of 4;
            // B keeps receiving every frame with the mux never stalling.
            for tag in 0..6u8 {
                real.rx.send(rx_frame(tag)).await;
                let got = b.rx.receive().await;
                assert_eq!(got.data.as_slice(), &[tag]);
            }
            for expected in 0..4u8 {
                let got = a.rx.try_receive().expect("frame dropped early");
                assert_eq!(got.data.as_slice(), &[expected]);
            }
            assert!(a.rx.try_receive().is_err(), "overflow frame not dropped");
        });
    }

    #[test]
    fn rx_continues_while_tx_in_flight() {
        let real = channels();
        let a = channels();
        let b = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([a, b]));

        run(real, clients, async {
            a.tx.send(tx_request(0xA1)).await;
            let granted = real.tx.receive().await;
            assert_eq!(granted.data.as_slice(), &[0xA1]);

            // No completion yet — fan-out must not be blocked behind it.
            real.rx.send(rx_frame(0x22)).await;
            assert_eq!(b.rx.receive().await.data.as_slice(), &[0x22]);
            assert_eq!(a.rx.receive().await.data.as_slice(), &[0x22]);

            real.tx_done.signal(Ok(()));
            assert!(a.tx_done.wait().await.is_ok());
        });
    }

    #[test]
    fn a_transmit_reaches_every_other_client() {
        let real = channels();
        let a = channels();
        let b = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([a, b]));

        run(real, clients, async {
            a.tx.send(tx_request(0xA1)).await;
            assert_eq!(real.tx.receive().await.data.as_slice(), &[0xA1]);
            real.tx_done.signal(Ok(()));
            assert!(a.tx_done.wait().await.is_ok());

            let copy = b.rx.receive().await;
            assert_eq!(copy.data.as_slice(), &[0xA1]);
            assert_eq!(copy.info.origin, RxOrigin::LocalTx);
            assert!(!copy.info.origin.is_measured());
            assert!(
                a.rx.try_receive().is_err(),
                "a transmitter must not hear itself"
            );
        });
    }

    #[test]
    fn an_abandoned_transmit_reaches_nobody() {
        let real = channels();
        let a = channels();
        let b = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([a, b]));

        run(real, clients, async {
            a.tx.send(tx_request(0xA1)).await;
            assert_eq!(real.tx.receive().await.data.as_slice(), &[0xA1]);
            // CAD found the channel busy, so the frame never went out.
            real.tx_done.signal(Err(TxError::CadTimeout));
            assert!(a.tx_done.wait().await.is_err());

            assert!(
                b.rx.try_receive().is_err(),
                "a frame that never aired was copied anyway"
            );
        });
    }

    #[test]
    fn backhaul_keeps_the_session_off_the_air() {
        let real = channels();
        let session = channels();
        let node = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([session, node]));

        run_with_mode(real, clients, backhaul_mode(), async {
            // The session's frame goes to the node, not to the radio.
            session.tx.send(tx_request(0x51)).await;
            let handed = node.rx.receive().await;
            assert_eq!(handed.data.as_slice(), &[0x51]);
            assert_eq!(handed.info.origin, RxOrigin::Backhaul);
            assert!(
                real.tx.try_receive().is_err(),
                "backhaul frame reached the radio"
            );
            assert!(
                session.tx_done.wait().await.is_ok(),
                "a delivered frame must complete"
            );

            // Receptions belong to the medium, which the session left.
            real.rx.send(rx_frame(0x22)).await;
            assert_eq!(node.rx.receive().await.data.as_slice(), &[0x22]);
            assert!(
                session.rx.try_receive().is_err(),
                "session heard the air in backhaul mode"
            );

            // What the node transmits still reaches the session, which is
            // how the host sees anything at all from here.
            node.tx.send(tx_request(0x77)).await;
            assert_eq!(real.tx.receive().await.data.as_slice(), &[0x77]);
            real.tx_done.signal(Ok(()));
            assert!(node.tx_done.wait().await.is_ok());
            let copy = session.rx.receive().await;
            assert_eq!(copy.data.as_slice(), &[0x77]);
            assert_eq!(copy.info.origin, RxOrigin::LocalTx);
        });
    }

    #[test]
    fn a_backlogged_backhaul_reports_a_busy_channel() {
        let real = channels();
        let session = channels();
        let node = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([session, node]));

        run_with_mode(real, clients, backhaul_mode(), async {
            // Nobody drains the node, so its queue fills at depth 4.
            for tag in 0..4u8 {
                session.tx.send(tx_request(tag)).await;
                assert!(session.tx_done.wait().await.is_ok());
            }
            session.tx.send(tx_request(0xFF)).await;
            // The frame is gone rather than queued, and saying so lets
            // the sender retry instead of counting it as delivered.
            assert!(matches!(
                session.tx_done.wait().await,
                Err(TxError::CadTimeout)
            ));
        });
    }

    #[test]
    fn stale_latched_completion_is_cleared_at_grant() {
        let real = channels();
        let a = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([a]));

        run(real, clients, async {
            // A previous requester abandoned its completion.
            a.tx_done
                .signal(Err(TxError::Io(RadioError::TransmitTimeout)));

            a.tx.send(tx_request(0xA1)).await;
            let granted = real.tx.receive().await;
            assert_eq!(granted.data.as_slice(), &[0xA1]);
            // The grant cleared the stale result; only the real outcome
            // of this transmit can reach the client now.
            assert!(a.tx_done.try_take().is_none(), "stale completion survived");

            real.tx_done.signal(Ok(()));
            assert!(a.tx_done.wait().await.is_ok());
        });
    }

    /// A frame whose first octet carries the UMSH version and a clear
    /// reserved bit.
    fn umsh_rx_frame(tag: u8) -> RxFrame {
        let mut frame = rx_frame(Fcf::new(umsh_core::PacketType::Broadcast, false, false).0);
        frame.data.push(tag).unwrap();
        frame.info.len = frame.data.len();
        frame
    }

    #[test]
    fn counts_transmits_at_the_radio_and_receptions_off_the_air() {
        let real = channels();
        let session = channels();
        let node = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([session, node]));
        let stats = ledger();

        run_with_stats(real, clients, mode(), stats, async {
            // A session transmit — the traffic the device node's MAC
            // never sees, and the reason counting happens here.
            session.tx.send(tx_request(0xA1)).await;
            let _ = real.tx.receive().await;
            real.tx_done.signal(Ok(()));
            assert!(session.tx_done.wait().await.is_ok());
            // Its own client is skipped, but the other one gets a copy;
            // that copy is not a reception and must not be counted.
            assert_eq!(node.rx.receive().await.info.origin, RxOrigin::LocalTx);

            // A busy channel is an attempt, not a transmission.
            node.tx.send(tx_request(0xB1)).await;
            let _ = real.tx.receive().await;
            real.tx_done.signal(Err(TxError::CadTimeout));
            assert!(node.tx_done.wait().await.is_err());

            // A radio fault is neither.
            node.tx.send(tx_request(0xB2)).await;
            let _ = real.tx.receive().await;
            real.tx_done
                .signal(Err(TxError::Io(RadioError::TransmitTimeout)));
            assert!(node.tx_done.wait().await.is_err());

            real.rx.send(umsh_rx_frame(0x01)).await;
            let _ = session.rx.receive().await;
            let _ = node.rx.receive().await;
            // 0x00 is version 0, not ours.
            real.rx.send(rx_frame(0x00)).await;
            let _ = session.rx.receive().await;
            let _ = node.rx.receive().await;

            assert_eq!(stats.get(Counter::TxPackets), 1);
            assert_eq!(stats.get(Counter::TxChannelBusy), 1);
            assert_eq!(stats.get(Counter::RxPackets), 1);
            assert_eq!(stats.get(Counter::RxNonUmsh), 1);
        });
    }

    /// In backhaul mode a session frame is handed to the medium clients
    /// and never reaches the radio, so it is not a transmission — and the
    /// busy verdict the mux invents to report a backed-up tunnel is not a
    /// busy channel either.
    #[test]
    fn counts_nothing_for_a_frame_that_never_reached_the_air() {
        let real = channels();
        let session = channels();
        let node = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([session, node]));
        let stats = ledger();

        run_with_stats(real, clients, backhaul_mode(), stats, async {
            session.tx.send(tx_request(0x51)).await;
            let _ = node.rx.receive().await;
            assert!(session.tx_done.wait().await.is_ok());

            // Now fill the node's queue so the next one is refused.
            for tag in 0..4u8 {
                session.tx.send(tx_request(tag)).await;
                assert!(session.tx_done.wait().await.is_ok());
            }
            session.tx.send(tx_request(0xFF)).await;
            assert!(matches!(
                session.tx_done.wait().await,
                Err(TxError::CadTimeout)
            ));

            assert_eq!(stats.get(Counter::TxPackets), 0);
            assert_eq!(stats.get(Counter::TxChannelBusy), 0);
            assert_eq!(stats.get(Counter::RxPackets), 0);
        });
    }
}
