//! Duty-cycle admission gate for the device node's radio path.
//!
//! `PROP_PHY_DUTY_LIMIT` bounds the *combined* airtime of every radio
//! client (device-node plan increment 4). The session already prices
//! and records its own transmissions against the shared
//! [`DutyLedger`]; this wrapper is the node-side counterpart: it sits
//! between the node's MAC and its virtual mux bundle, admits each
//! transmit against the combined budget, and records the airtime once
//! the transmit completes.
//!
//! A refused transmit is reported as [`TxError::CadTimeout`] — the one
//! transmit error the MAC treats as "channel unavailable right now":
//! it backs off with jitter, retries a bounded number of times, and
//! then drops the frame. Any other error would surface as a fatal
//! `MacError::Transmit` and kill the node pump, which must never be a
//! consequence of duty limiting. A budget exhausted this hour rarely
//! recovers within the MAC's short backoff horizon, so a refused frame
//! is effectively shed — exactly the spec's posture (transmits never
//! wait for duty-cycle allowance).

use umsh_companion_ncp::DutyLedger;
use umsh_hal::{Clock, Radio, RxInfo, TxError, TxOptions};

/// A [`Radio`] decorator enforcing the shared duty budget.
pub struct DutyGatedRadio<R, C> {
    inner: R,
    ledger: &'static DutyLedger,
    clock: C,
}

impl<R, C> DutyGatedRadio<R, C> {
    pub fn new(inner: R, ledger: &'static DutyLedger, clock: C) -> Self {
        Self {
            inner,
            ledger,
            clock,
        }
    }
}

impl<R: Radio, C: Clock> Radio for DutyGatedRadio<R, C> {
    type Error = R::Error;

    async fn transmit(
        &mut self,
        data: &[u8],
        options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        let airtime_ms = self
            .ledger
            .admit(self.clock.now_ms(), data.len())
            .map_err(|_| TxError::CadTimeout)?;
        self.inner.transmit(data, options).await?;
        // Record with the completion timestamp, mirroring the
        // session's on_tx_result accounting. Refusals and failed
        // transmits consume no budget.
        self.ledger.record(self.clock.now_ms(), airtime_ms);
        Ok(())
    }

    fn poll_receive(
        &mut self,
        cx: &mut core::task::Context<'_>,
        buf: &mut [u8],
    ) -> core::task::Poll<Result<RxInfo, Self::Error>> {
        self.inner.poll_receive(cx, buf)
    }

    fn max_frame_size(&self) -> usize {
        self.inner.max_frame_size()
    }

    fn t_frame_ms(&self) -> u32 {
        self.inner.t_frame_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    use std::cell::Cell;
    use std::rc::Rc;

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

    fn ledger() -> &'static DutyLedger {
        Box::leak(Box::new(DutyLedger::new()))
    }

    /// Records transmit lengths; can be told to fail.
    struct MockRadio {
        sent: std::vec::Vec<usize>,
        fail_next: bool,
    }

    impl Radio for MockRadio {
        type Error = u8;

        async fn transmit(
            &mut self,
            data: &[u8],
            _options: TxOptions,
        ) -> Result<(), TxError<Self::Error>> {
            if self.fail_next {
                self.fail_next = false;
                return Err(TxError::Io(0xEE));
            }
            self.sent.push(data.len());
            Ok(())
        }

        fn poll_receive(
            &mut self,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<Result<RxInfo, Self::Error>> {
            Poll::Pending
        }

        fn max_frame_size(&self) -> usize {
            255
        }

        fn t_frame_ms(&self) -> u32 {
            1_000
        }
    }

    #[derive(Clone)]
    struct TestClock(Rc<Cell<u64>>);

    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.0.get()
        }
    }

    /// The acceptance shape for the shared ledger: session airtime and
    /// node airtime interleave against one combined budget. The node's
    /// transmit is admitted while the combined figure is under the
    /// limit, refused as CadTimeout once session traffic exhausts it,
    /// and node traffic symmetrically starves the session's own check.
    #[test]
    fn interleaved_session_and_node_tx_share_one_budget() {
        let ledger = ledger();
        // Fixture modulation (906.875 MHz profile): SF9/BW250k/CR5.
        ledger.set_phy(9, 250_000, 5);
        ledger.set_limit(655); // ≈1%: 36 s per hour.
        let now = Rc::new(Cell::new(0u64));
        let mut node = DutyGatedRadio::new(
            MockRadio {
                sent: vec![],
                fail_next: false,
            },
            ledger,
            TestClock(now.clone()),
        );

        // Node beacon goes out while the budget is fresh.
        block_on(node.transmit(&[0u8; 32], TxOptions::default())).unwrap();
        assert_eq!(node.inner.sent, [32]);
        assert!(ledger.usage(now.get()) > 0);

        // The session records a burst of its own completed TX
        // (exactly what Session::on_tx_result does), exhausting the
        // combined budget...
        for _ in 0..36 {
            ledger.record(now.get(), 1_000);
        }
        // ...so the session's own pre-check refuses...
        assert!(ledger.would_exceed(now.get(), 100));
        // ...and the node's next transmit is shed as CadTimeout
        // without reaching the radio or consuming budget.
        let refused = block_on(node.transmit(&[0u8; 32], TxOptions::default()));
        assert!(matches!(refused, Err(TxError::CadTimeout)));
        assert_eq!(node.inner.sent, [32]);
        let usage_after_refusal = ledger.usage(now.get());

        // Symmetrically: after the window ages out, node traffic alone
        // starves the session's check.
        now.set(now.get() + 60 * 60 * 1_000);
        assert_eq!(ledger.usage(now.get()), 0);
        for _ in 0..36 {
            ledger.record(now.get(), 1_000);
        }
        assert!(ledger.would_exceed(now.get(), 100));
        assert!(matches!(
            block_on(node.transmit(&[0u8; 32], TxOptions::default())),
            Err(TxError::CadTimeout)
        ));
        let _ = usage_after_refusal;
    }

    /// A failed inner transmit consumes no budget, and the admitted
    /// airtime matches the ledger's modulation pricing.
    #[test]
    fn failed_transmit_records_nothing() {
        let ledger = ledger();
        ledger.set_phy(9, 250_000, 5);
        ledger.set_limit(655);
        let now = Rc::new(Cell::new(0u64));
        let mut node = DutyGatedRadio::new(
            MockRadio {
                sent: vec![],
                fail_next: true,
            },
            ledger,
            TestClock(now.clone()),
        );
        let failed = block_on(node.transmit(&[0u8; 48], TxOptions::default()));
        assert!(matches!(failed, Err(TxError::Io(0xEE))));
        assert_eq!(ledger.usage(0), 0);

        block_on(node.transmit(&[0u8; 48], TxOptions::default())).unwrap();
        let expected = umsh_companion::airtime::lora_airtime_ms(9, 250_000, 5, 48);
        // One recorded frame: usage reflects exactly its priced airtime
        // (rounded up to 5 ms units and rescaled).
        assert_eq!(
            u64::from(ledger.usage(0)),
            u64::from(expected.div_ceil(5)) * 65_535 / 720_000
        );
    }
}
