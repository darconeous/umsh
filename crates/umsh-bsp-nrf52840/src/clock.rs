//! Embassy-time-backed monotonic clock implementing [`umsh_hal::Clock`].
//!
//! Every nRF52840 firmware in this tree drives the MAC's timing layer with
//! embassy's `embassy-time` integration on RTC1 (see the `time-driver-rtc1`
//! feature on the `embassy-nrf` dep). This wrapper translates that into the
//! `umsh-hal` [`Clock`](umsh_hal::Clock) shape — millisecond-resolution
//! monotonic time plus an async deadline-poll for `next_event`-style waits.
//!
//! Use [`EmbassyClock`] as `Platform::Clock` on any nRF52840 board that
//! uses embassy-time. Construct with `EmbassyClock`; no peripheral handle
//! needed (the underlying timer driver is owned by the embassy runtime,
//! not this wrapper).

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll};

use embassy_time::{Instant, Timer};

/// Embassy-time-backed monotonic clock implementing [`umsh_hal::Clock`].
///
/// Zero-sized: shares the global embassy-time driver. Clone freely.
#[derive(Clone, Copy, Default, Debug)]
pub struct EmbassyClock;

impl umsh_hal::Clock for EmbassyClock {
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
