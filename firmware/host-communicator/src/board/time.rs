//! The time driver behind `embassy-time`, as a board's timer peripheral
//! would be: ticks counted from the process start, and one thread that
//! sleeps until the earliest timer anyone is waiting on and wakes it.
//!
//! Defined here, in the binary, rather than through `embassy-time/std`:
//! a feature on `embassy-time` unifies across every crate built with this
//! one, and would hand a time driver to crates that register their own.

use std::sync::{Condvar, Mutex, OnceLock};
use std::task::Waker;
use std::time::{Duration, Instant};

use embassy_time_driver::{Driver, TICK_HZ};
use embassy_time_queue_utils::queue_generic::ConstGenericQueue;

/// More timers than the device ever has armed at once: one per task that
/// waits on the clock.
const TIMERS: usize = 128;

struct HostTime {
    queue: Mutex<ConstGenericQueue<TIMERS>>,
    alarm: Condvar,
    sleeper: OnceLock<()>,
}

embassy_time_driver::time_driver_impl!(static DRIVER: HostTime = HostTime {
    queue: Mutex::new(ConstGenericQueue::new()),
    alarm: Condvar::new(),
    sleeper: OnceLock::new(),
});

/// When the clock started: the device's boot.
fn origin() -> Instant {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    *ORIGIN.get_or_init(Instant::now)
}

fn ticks(since: Duration) -> u64 {
    (since.as_nanos() * u128::from(TICK_HZ) / 1_000_000_000) as u64
}

fn duration(ticks: u64) -> Duration {
    Duration::from_nanos((u128::from(ticks) * 1_000_000_000 / u128::from(TICK_HZ)) as u64)
}

impl HostTime {
    /// Wakes each timer as it falls due, sleeping between them.
    fn sleep(&'static self) {
        let mut queue = self.queue.lock().unwrap();
        loop {
            let now = self.now();
            let next = queue.next_expiration(now);
            queue = if next == u64::MAX {
                self.alarm.wait(queue).unwrap()
            } else {
                self.alarm
                    .wait_timeout(queue, duration(next.saturating_sub(now)))
                    .unwrap()
                    .0
            };
        }
    }
}

impl Driver for HostTime {
    fn now(&self) -> u64 {
        ticks(origin().elapsed())
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        DRIVER.sleeper.get_or_init(|| {
            std::thread::Builder::new()
                .name("embassy-time".into())
                .spawn(|| DRIVER.sleep())
                .expect("the time driver's thread");
        });
        if self.queue.lock().unwrap().schedule_wake(at, waker) {
            self.alarm.notify_one();
        }
    }
}

/// Starts the clock now: the device boots.
pub fn start() {
    origin();
}
