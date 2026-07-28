//! The runtime's debug-log seam.
//!
//! Shared code needs to emit the same diagnostic lines the firmwares
//! already print, but each board owns its own sink: the nRF images
//! multiplex a USB-serial debug channel, the ESP32 image writes to its
//! UART. Rather than thread a logger through every signature — most of
//! which are `static`-backed tasks with no place to put one — a board
//! installs its sink once at boot and the shared modules call
//! [`debug_log`] freely.
//!
//! Before [`set_debug_log`] runs, logging is a no-op. That is the
//! correct behavior for the earliest boot code, which runs before the
//! transport that would carry a log line exists.

use core::fmt::Arguments;
use core::sync::atomic::{AtomicPtr, Ordering};

type Sink = fn(Arguments);

/// The installed sink, held as a raw code pointer.
///
/// Deliberately not a critical-section mutex. [`debug_log`] is called from
/// the device node's per-packet receive tap, on the same boards whose BLE
/// controller is the entire reason for the `node-thread-mode-mutex`
/// feature — taking a critical section once per received packet is exactly
/// the cost that feature exists to keep out of the radio path, and it
/// would be paid even when the board's sink discards the line.
///
/// A plain pointer slot is sufficient here: it is written once at boot and
/// only read afterwards, and there is no data behind the pointer to
/// publish, so relaxed ordering has nothing weaker to expose.
static SINK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the board's debug-log sink. Call once, as early in boot as
/// the sink itself is usable; a later call replaces the previous sink.
pub fn set_debug_log(sink: Sink) {
    SINK.store(sink as *mut (), Ordering::Relaxed);
}

/// Emit one debug line through the board's sink, or drop it if no sink
/// is installed yet.
pub fn debug_log(args: Arguments) {
    let sink = SINK.load(Ordering::Relaxed);
    if sink.is_null() {
        return;
    }
    // SAFETY: the slot is null or a `Sink` stored by `set_debug_log`, and
    // function pointers carry no lifetime to outlive.
    let sink: Sink = unsafe { core::mem::transmute::<*mut (), Sink>(sink) };
    sink(args);
}
