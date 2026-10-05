//! Timing samples for the entropy pool.
//!
//! When an interrupt from outside the chip lands against the CPU's cycle
//! counter is not something an observer off the board can know to the
//! cycle: a frame's arrival and a finger on a button are both
//! asynchronous to an 80 MHz clock. [`sample`] records that instant at
//! the places such events arrive, and [`take`] hands the accumulated
//! samples to the pool.
//!
//! This is not a randomness source. Nothing draws from it: the samples
//! only ever go into the pool's hash, alongside a hardware harvest, and
//! hash mixing means input worth nothing costs nothing.

use core::sync::atomic::{AtomicU32, Ordering};

const SLOTS: usize = 8;

static SAMPLES: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];
static NEXT: AtomicU32 = AtomicU32::new(0);

/// Record that something asynchronous to the CPU has just happened.
pub fn sample() {
    let count = esp_hal::xtensa_lx::timer::get_cycle_count();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    // A slot folds in every sample it is handed, so wrapping around
    // discards nothing; the rotation keeps one lap from lining up with
    // the next.
    SAMPLES[n as usize % SLOTS].fetch_xor(
        count.rotate_left(n / SLOTS as u32 % u32::BITS),
        Ordering::Relaxed,
    );
}

/// Hand over what has accumulated and start again.
pub fn take() -> [u8; SLOTS * 4] {
    let mut out = [0u8; SLOTS * 4];
    for (slot, bytes) in SAMPLES.iter().zip(out.chunks_exact_mut(4)) {
        bytes.copy_from_slice(&slot.swap(0, Ordering::Relaxed).to_le_bytes());
    }
    out
}
