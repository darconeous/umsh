//! Shared T1000-E LED requests.

use core::sync::atomic::{AtomicBool, Ordering};

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;
use umsh_ux_tracker::led::LedSequence;

static ATTENTION_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Wakes the LED task when persistent attention changes.
pub static INDICATOR_CHANGED: Signal<ThreadModeRawMutex, ()> = Signal::new();

/// One-shot action-confirmation request. Latest request wins.
pub static LED_SEQUENCE_SIGNAL: Signal<ThreadModeRawMutex, LedSequence> = Signal::new();

pub fn attention_requested() -> bool {
    ATTENTION_REQUESTED.load(Ordering::Acquire)
}

pub fn request_attention() {
    if !ATTENTION_REQUESTED.swap(true, Ordering::AcqRel) {
        INDICATOR_CHANGED.signal(());
    }
}

pub fn clear_attention() {
    if ATTENTION_REQUESTED.swap(false, Ordering::AcqRel) {
        INDICATOR_CHANGED.signal(());
    }
}
