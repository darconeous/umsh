//! Radio multiplexer: shares the one physical radio among multiple clients.
//!
//! Today the only client is the companion session; the device node joins
//! as a second client per `docs/companion-device-node-plan.md`. The
//! physical radio's [`Channels`] bundle has a single `tx_done` signal, so
//! completion attribution breaks the moment two clients transmit. The mux
//! owns the real bundle and gives every client a private virtual
//! [`Channels`] of the same type:
//!
//! - **TX**: requests are granted one at a time (round-robin under
//!   contention) and forwarded to the real TX queue; the real `tx_done`
//!   result is routed to the granting client's own `tx_done`, so each
//!   client sees exactly the completions for its own requests.
//! - **RX**: every received frame is fanned out to every client. Dual
//!   delivery is what the companion-radio spec requires — frames addressed
//!   to the device identity are processed by the NCP itself *and*
//!   independently offered to host receive filtering. A client whose RX
//!   queue is full loses that frame (the same drop policy the radio
//!   runner applies to the real queue) without stalling the others.
//!
//! RX fan-out continues while a transmit is in flight; only the grant of
//! the *next* TX waits for the previous completion. The runner-side
//! controls (`NcpControl`: settings, RSSI sampling) are single-owner
//! device-domain state and bypass the mux entirely.

use core::future::poll_fn;
use core::task::Poll;

use embassy_futures::select::{Either3, select3};
use embassy_sync::blocking_mutex::raw::RawMutex;
use umsh_radio_loraphy::{Channels, RxFrame, TxRequest};

/// Run the multiplexer over the real radio `Channels` bundle.
///
/// `real` must be the bundle served by the radio runner, and the mux must
/// be that bundle's only client. Each entry in `clients` is one virtual
/// bundle, owned (RX-drained and TX-fed) by exactly one radio client.
pub async fn radio_mux<M, const RX: usize, const TX: usize>(
    real: &'static Channels<M, RX, TX>,
    clients: &'static [&'static Channels<M, RX, TX>],
) -> !
where
    M: RawMutex,
{
    // Index into `clients` of the transmit currently at the radio, if any.
    let mut in_flight: Option<usize> = None;
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
                for client in clients {
                    let copy = RxFrame {
                        data: frame.data.clone(),
                        info: frame.info,
                    };
                    if client.rx.try_send(copy).is_ok() {
                        client.rx_waker.wake();
                    }
                }
            }
            Either3::Second(result) => {
                if let Some(owner) = in_flight.take() {
                    clients[owner].tx_done.signal(result);
                }
            }
            Either3::Third((who, request)) => {
                // Drop any stale latched completion (e.g. from an earlier
                // transmit whose requester was cancelled before consuming
                // it) so the client can only observe this request's
                // result. `try_take` leaves a registered waiter intact,
                // unlike `reset`, which would silently drop its waker.
                let _ = clients[who].tx_done.try_take();
                real.tx.send(request).await;
                in_flight = Some(who);
                arbitration_start = (who + 1) % clients.len();
            }
        }
    }
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
    use umsh_hal::{RxInfo, Snr};

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
    /// completes.
    fn run<F: Future>(
        real: &'static TestCh,
        clients: &'static [&'static TestCh],
        scenario: F,
    ) -> F::Output {
        block_on(async {
            match select(radio_mux(real, clients), scenario).await {
                Either::First(_) => unreachable!("mux never returns"),
                Either::Second(output) => output,
            }
        })
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
            },
        }
    }

    fn tx_request(tag: u8) -> TxRequest {
        let mut data = heapless::Vec::new();
        data.push(tag).unwrap();
        TxRequest {
            data,
            power_dbm: None,
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
            assert!(real.tx.try_receive().is_err(), "B granted while A in flight");

            real.tx_done.signal(Err(RadioError::TransmitTimeout));
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
    fn stale_latched_completion_is_cleared_at_grant() {
        let real = channels();
        let a = channels();
        let clients: &'static [&'static TestCh] = Box::leak(Box::new([a]));

        run(real, clients, async {
            // A previous requester abandoned its completion.
            a.tx_done.signal(Err(RadioError::TransmitTimeout));

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
}
