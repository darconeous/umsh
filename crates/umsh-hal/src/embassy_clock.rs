//! `embassy-time`-backed [`Clock`](crate::Clock).
//!
//! This is the single shared implementation used by both host (arch-std) and
//! embedded targets. The concrete `embassy-time` driver is provided by the
//! binary, not this wrapper, so the same zero-sized clock works everywhere the
//! global driver is installed.

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll};

use embassy_time::{Instant, Timer};

/// Monotonic [`Clock`](crate::Clock) backed by the global `embassy-time` driver.
///
/// Zero-sized: shares the global driver. Clone freely.
#[derive(Clone, Copy, Default, Debug)]
pub struct EmbassyClock;

impl crate::Clock for EmbassyClock {
    fn now_ms(&self) -> u64 {
        Instant::now().as_millis()
    }

    fn poll_delay_until(&self, cx: &mut Context<'_>, deadline_ms: u64) -> Poll<()> {
        let target = Instant::from_millis(deadline_ms);
        if Instant::now() >= target {
            return Poll::Ready(());
        }
        // Poll a freshly-pinned timer once to register `cx.waker()` with
        // embassy's global timer queue. The waker registration outlives the
        // future itself, so dropping the timer here is safe.
        let mut timer = pin!(Timer::at(target));
        timer.as_mut().poll(cx)
    }
}
