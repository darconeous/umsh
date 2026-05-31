//! Power control glue for the T-Echo: the [`SHUTDOWN_SIGNAL`] static and a
//! [`PowerSignaler`] that bridges the CLI's `umsh_hal::PowerControl` trait
//! into board-level power events.
//!
//! See `umsh-bsp-t1000e::power` for the design rationale — the shape is
//! identical here. The board-specific teardown sequence lives in the
//! firmware's `shutdown_task`, which awaits [`SHUTDOWN_SIGNAL`].

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;

/// Single-consumer shutdown trigger. The firmware's `shutdown_task` is the
/// only consumer.
pub static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

/// `umsh_hal::PowerControl` implementation for the T-Echo.
///
/// - `request_power_off` raises [`SHUTDOWN_SIGNAL`].
/// - `request_reboot` triggers an ARM Cortex-M `SYSRESETREQ` with no
///   flushing or teardown.
pub struct PowerSignaler;

impl umsh_hal::PowerControl for PowerSignaler {
    fn request_power_off(&self) {
        SHUTDOWN_SIGNAL.signal(());
    }

    fn request_reboot(&self) {
        cortex_m::peripheral::SCB::sys_reset();
    }
}
