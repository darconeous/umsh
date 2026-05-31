//! Power control glue for the Wio Tracker L1: a [`PowerSignaler`] that
//! bridges the CLI's `umsh_hal::PowerControl` trait into board-level power
//! events.
//!
//! Unlike the T1000-E and T-Echo BSPs, this one does not export a
//! `SHUTDOWN_SIGNAL` — the L1 has a mechanical power switch, and no
//! controlled-shutdown sequence has been wired up yet, so
//! `request_power_off` is a no-op. There is no architectural reason a
//! Wio L1 firmware *couldn't* drive a System OFF teardown (the user has
//! explicitly noted this is fine); when someone wants that, mirror the
//! T1000-E/T-Echo pattern and add a `SHUTDOWN_SIGNAL` here plus a
//! firmware-side `shutdown_task`.

/// `umsh_hal::PowerControl` implementation for the Wio Tracker L1.
///
/// - `request_power_off` is a **no-op** for now. The board has a
///   mechanical power switch, and no soft-poweroff teardown has been
///   wired up. `/poweroff` from the CLI will print "powering off" and
///   do nothing visible.
/// - `request_reboot` triggers an ARM Cortex-M `SYSRESETREQ` with no
///   flushing or teardown.
pub struct PowerSignaler;

impl umsh_hal::PowerControl for PowerSignaler {
    fn request_power_off(&self) {
        // TODO: wire a SHUTDOWN_SIGNAL + shutdown_task analogous to the
        // T1000-E / T-Echo BSPs once a soft-poweroff sequence is needed.
    }

    fn request_reboot(&self) {
        cortex_m::peripheral::SCB::sys_reset();
    }
}
