//! A time driver for the host tests.
//!
//! On a device the driver is the board's timer; here it is the process
//! clock. `gnss`'s tests only need instants to exist so that offering a
//! fix to the wall clock links; `i2c`'s deadline tests need them to
//! advance, so the clock is real time in `embassy-time` ticks. Nothing
//! schedules a wake: `embassy_futures::block_on` polls until it is told
//! the future is ready, so a timer that reports itself expired on the
//! next poll is enough.

use core::task::Waker;
use std::sync::OnceLock;
use std::time::Instant;

struct Stub;

impl embassy_time_driver::Driver for Stub {
    fn now(&self) -> u64 {
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        let elapsed = EPOCH.get_or_init(Instant::now).elapsed();
        (elapsed.as_nanos() * u128::from(embassy_time_driver::TICK_HZ) / 1_000_000_000) as u64
    }

    fn schedule_wake(&self, _at: u64, _waker: &Waker) {}
}

embassy_time_driver::time_driver_impl!(static DRIVER: Stub = Stub);
