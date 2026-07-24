//! Power control glue for the SenseCAP Solar Node: a [`PowerSignaler`]
//! that bridges the CLI's `umsh_hal::PowerControl` trait into board-level
//! power events.
//!
//! **Phase 1 stub.** For bringup this mirrors the Wio Tracker L1 BSP:
//! `request_power_off` is a no-op and `request_reboot` triggers a plain
//! `SYSRESETREQ`. There is no battery monitor, `SHUTDOWN_SIGNAL`, or
//! System OFF teardown here yet.
//!
//! Unlike the Wio Tracker (mechanical power switch, no soft-poweroff
//! ever needed) this board *does* need a real power story: it is a
//! solar-autonomous outdoor node with nobody present to push a button,
//! so the low-battery path must work unattended. Phase 6 replaces this
//! stub with the T1000-E/T-Echo-style `SHUTDOWN_SIGNAL` + `shutdown_task`
//! plus low-battery System OFF and LPCOMP solar-recovery wake. See
//! `docs/firmware-plan-sensecap-solar-node-p1-pro.md` Phase 6.

/// `umsh_hal::PowerControl` implementation for the SenseCAP Solar Node.
///
/// - `request_power_off` is a **no-op** for now (Phase 6 wires the real
///   System OFF teardown). `/poweroff` from the CLI will do nothing
///   visible.
/// - `request_reboot` triggers an ARM Cortex-M `SYSRESETREQ` with no
///   flushing or teardown.
pub struct PowerSignaler;

impl umsh_hal::PowerControl for PowerSignaler {
    fn request_power_off(&self) {
        // TODO (Phase 6): raise a SHUTDOWN_SIGNAL and run the board's
        // System OFF teardown (radio sleep, GNSS off, LEDs off, divider
        // gate disconnected, button-wake armed), analogous to the
        // T1000-E / T-Echo BSPs.
    }

    fn request_reboot(&self) {
        cortex_m::peripheral::SCB::sys_reset();
    }
}
