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

use core::cell::Cell;
use core::fmt::Arguments;

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

type Sink = fn(Arguments);

/// Installed once at boot. A critical-section mutex rather than an
/// atomic function pointer: this is written exactly once and read from
/// every context including interrupt-adjacent ones, so the cheapest
/// *safe* option wins over the fastest one.
static SINK: Mutex<CriticalSectionRawMutex, Cell<Option<Sink>>> = Mutex::new(Cell::new(None));

/// Install the board's debug-log sink. Call once, as early in boot as
/// the sink itself is usable; a later call replaces the previous sink.
pub fn set_debug_log(sink: Sink) {
    SINK.lock(|cell| cell.set(Some(sink)));
}

/// Emit one debug line through the board's sink, or drop it if no sink
/// is installed yet.
pub fn debug_log(args: Arguments) {
    if let Some(sink) = SINK.lock(|cell| cell.get()) {
        sink(args);
    }
}
