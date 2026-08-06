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

/// Whether the LED must currently be held dark.
///
/// The green LED is beside the ambient light sensor and its light
/// reaches it directly, so an illuminance reading taken while the LED is
/// lit measures the LED. Worse, the indicator is usually *blinking*, so
/// each reading catches a different part of the blink and the answer
/// swings wildly between polls — noise that no amount of oversampling or
/// flicker rejection can touch, because it is real light.
///
/// The light sampler in [`crate::power`] raises this for the duration of
/// a measurement. It outranks everything the LED engine wants to show:
/// the reading takes about 60 ms and the indicator is not carrying
/// information anyone can read in that time.
static LED_BLANKED: AtomicBool = AtomicBool::new(false);

/// Wakes the LED task when [`blank_requested`] changes. Separate from
/// [`INDICATOR_CHANGED`] because this one is latency-critical: the
/// sampler waits on the acknowledgement before it starts integrating.
pub static LED_BLANK_CHANGED: Signal<ThreadModeRawMutex, ()> = Signal::new();

/// Raised by the LED task once it has actually driven the LED off.
static LED_BLANK_CONFIRMED: Signal<ThreadModeRawMutex, ()> = Signal::new();

/// Whether the LED task must hold the LED dark. Checked by the task that
/// owns the LED, immediately before each duty write.
pub fn blank_requested() -> bool {
    LED_BLANKED.load(Ordering::Acquire)
}

/// Called by the LED task **after** writing a zero duty, to tell the
/// sampler the LED is off and it may begin.
pub fn confirm_blanked() {
    LED_BLANK_CONFIRMED.signal(());
}

/// Ask for the LED to be held dark. Paired with [`release_blank`].
pub(crate) fn request_blank() {
    LED_BLANK_CONFIRMED.reset();
    LED_BLANKED.store(true, Ordering::Release);
    LED_BLANK_CHANGED.signal(());
}

/// Wait until the LED task confirms the LED is off.
///
/// Callers **must** bound this: a board whose LED task is not running
/// would otherwise stall the caller indefinitely, and the caller here is
/// the loop that guards the cell.
pub(crate) async fn wait_blanked() {
    LED_BLANK_CONFIRMED.wait().await;
}

/// Return the LED to the indicator engine.
pub(crate) fn release_blank() {
    LED_BLANKED.store(false, Ordering::Release);
    LED_BLANK_CHANGED.signal(());
}

/// Locate-alert (`PROP_ALERT`) edges for the buzzer task: `true` starts
/// the alert melody, `false` stops it.
///
/// The authoritative flag lives in the firmware, which owns the session
/// and drives both the buzzer and the LED from it; this signal is only
/// how the edge reaches the buzzer task.
pub static BUZZER_ALERT_SET: Signal<ThreadModeRawMutex, bool> = Signal::new();
