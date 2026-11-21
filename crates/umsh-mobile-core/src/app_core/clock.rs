//! The core's two times, which tests replace.
//!
//! Wall time dates what is stored and follows the user's clock: claims,
//! holds, advertisement timestamps. Monotonic time paces the schedules and
//! throttles. It never jumps when the time is set, and it keeps counting
//! while the phone sleeps, which tokio's `Instant` does not.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A future the clock resolves.
pub(crate) type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The core's clock.
pub(crate) trait Clock: Send + Sync {
    /// Unix milliseconds.
    fn now_ms(&self) -> i64;

    /// Milliseconds on a clock that only moves forward and counts sleep.
    /// Its origin means nothing.
    fn monotonic_ms(&self) -> i64;

    /// Resolve once [`monotonic_ms`](Self::monotonic_ms) has reached
    /// `deadline_ms`.
    fn sleep_until(&self, deadline_ms: i64) -> Sleep;
}

/// The longest tokio sleeps at a time before the monotonic clock is read
/// again: tokio's timer stops while the phone sleeps, so a long sleep
/// would end late by however long the phone slept.
const SLEEP_SLICE: Duration = Duration::from_secs(60);

pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
            })
    }

    fn monotonic_ms(&self) -> i64 {
        // Darwin's raw clock (Swift's continuous clock) and Linux's boot
        // time both count sleep; Linux's plain monotonic clock does not.
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        const CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC_RAW;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        const CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;
        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "android"
        )))]
        const CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;

        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `now` is a valid, writable timespec, and `CLOCK` a clock
        // the platform defines.
        let status = unsafe { libc::clock_gettime(CLOCK, &raw mut now) };
        if status != 0 {
            return 0;
        }
        // Both fields are 32 bits on 32-bit Android, where the conversion is
        // not the identity it is here.
        #[allow(clippy::useless_conversion)]
        let (seconds, nanoseconds) = (i64::from(now.tv_sec), i64::from(now.tv_nsec));
        seconds
            .saturating_mul(1000)
            .saturating_add(nanoseconds / 1_000_000)
    }

    fn sleep_until(&self, deadline_ms: i64) -> Sleep {
        Box::pin(async move {
            loop {
                let remaining = deadline_ms.saturating_sub(SystemClock.monotonic_ms());
                let Ok(remaining) = u64::try_from(remaining) else {
                    return;
                };
                if remaining == 0 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(remaining).min(SLEEP_SLICE)).await;
            }
        })
    }
}

/// A clock tests move by hand. Sleepers wake when it is advanced past
/// their deadline.
#[cfg(test)]
pub(crate) mod manual {
    use std::sync::atomic::{AtomicI64, Ordering};

    use tokio::sync::watch;

    use super::{Clock, Sleep};

    pub(crate) struct ManualClock {
        wall: AtomicI64,
        monotonic: watch::Sender<i64>,
    }

    impl ManualClock {
        pub(crate) fn new(wall_ms: i64) -> Self {
            Self {
                wall: AtomicI64::new(wall_ms),
                monotonic: watch::Sender::new(0),
            }
        }

        /// Move both times forward.
        pub(crate) fn advance(&self, by_ms: i64) {
            self.wall.fetch_add(by_ms, Ordering::SeqCst);
            self.monotonic.send_modify(|now| *now += by_ms);
        }

        /// Set the wall time alone, as a user changing the clock does.
        pub(crate) fn set_wall(&self, wall_ms: i64) {
            self.wall.store(wall_ms, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now_ms(&self) -> i64 {
            self.wall.load(Ordering::SeqCst)
        }

        fn monotonic_ms(&self) -> i64 {
            *self.monotonic.borrow()
        }

        fn sleep_until(&self, deadline_ms: i64) -> Sleep {
            let mut now = self.monotonic.subscribe();
            Box::pin(async move {
                // The sender lives as long as the clock, which outlives
                // every sleeper in a test.
                let _ = now.wait_for(|now| *now >= deadline_ms).await;
            })
        }
    }
}
