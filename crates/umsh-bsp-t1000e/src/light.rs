//! Ambient light sensing for the T1000-E.
//!
//! The sensor sits on P0.29 (AIN5) behind two enables: the shared sensor
//! 3.3 V rail (P1.06) and a sensor-enable line (P0.04), both active-high.
//! It is a phototransistor loaded to ground, so the node voltage rises
//! with illuminance from a small dark offset and rails once the load
//! resistor saturates — the transfer function is a straight line between
//! those two ends.
//!
//! The SAADC and the sensor rail are owned by
//! [`run_battery_monitor`](crate::power::run_battery_monitor); this module
//! is the request side of that ownership, plus the pure conversion, which
//! is host-testable and therefore deliberately not gated on the target.
//!
//! The light channel runs at **14-bit** resolution with hardware
//! oversampling, which is why the counts here are four times the
//! 12-bit-scale numbers the vendor driver works in. Full scale is 3.6 V
//! (`Gain1_6` against the 0.6 V internal reference), so one count is
//! `3600 / 16384 ≈ 0.2197` mV.

// ─── Calibration ─────────────────────────────────────────────────────
//
// Bench measurements, 2026-08-06, against a reference lux meter. Readings
// are averaged raw counts at 14-bit (see [`crate::power`] for how they
// are taken):
//
// | Raw counts | Meter      | Note            |
// |------------|------------|-----------------|
// | 0.2        | darkness   | the dark offset |
// | 8965.086   | 185 lux    | the fit below   |
// | 13478.391  | flashlight | the hard rail   |
//
// The response is linear across the usable range — verified against the
// meter after fitting — so one slope through the origin describes it.
//
// The substantive correction to what was inherited from Seeed: **this
// sensor has essentially no dark current.** 0.2 counts is 44 µV. Seeed's
// 80 mV floor — 364 counts at this resolution — is a software noise
// guard, not a property of the part, and subtracting it was discarding
// the entire bottom of the range, which is precisely the region an
// indicator-brightness policy works in.

/// Raw count at zero illuminance, subtracted before scaling.
///
/// Measured: full darkness reads 0.2 counts, so there is nothing to
/// subtract. Left at zero rather than rounded to 1 so the bottom of the
/// range is not clipped; a covered sensor reports about 4 mlux, which is
/// an honest noise floor and far below anything meaningful.
pub const DARK_OFFSET_RAW: u32 = 0;

/// Raw count above which the reading is clamped: 12288, which is 2.7 V
/// and three-quarters of full scale.
///
/// A judgement call rather than a measurement, and deliberately not
/// either of the two numbers it sits between:
///
/// - A bright flashlight drives the node to **13478** counts (2.96 V of a
///   3.3 V rail) and no further. That is the hard rail, where the reading
///   stops responding to light altogether; sitting the clamp right on it
///   leaves no margin for part-to-part or temperature variation in where
///   it lands.
/// - Seeed clamps at **11287** (2.48 V), which is arbitrary and throws
///   away range the part demonstrably has.
///
/// Between them, 2.7 V keeps a margin below the rail while retaining most
/// of the range. Everything above it reports the same clamped maximum,
/// which is the honest answer for a sensor that can no longer tell those
/// levels apart.
pub const SATURATION_RAW: u32 = 12_288;

/// Millilux per count above [`DARK_OFFSET_RAW`], as the fraction
/// `SLOPE_MLUX_NUM / SLOPE_MLUX_DEN` — **20.636 mlux per count**.
///
/// Fitted through the origin from the 185 lux point:
/// `185000 / 8965.086 = 20.636`.
///
/// A fraction rather than a whole number of millilux because rounding the
/// slope to an integer would discard a percent or two of the answer —
/// more than the sub-count resolution the sampling in [`crate::power`]
/// exists to buy.
pub const SLOPE_MLUX_NUM: u32 = 20_636;
pub const SLOPE_MLUX_DEN: u32 = 1_000;

/// Convert an accumulated run of SAADC counts on AIN5 to millilux.
///
/// Takes the **sum** and the number of conversions in it rather than a
/// pre-computed mean, because the mean of a run of counts is fractional
/// and a mean rounded to whole counts throws that away. Both divisions —
/// by the conversion count and by the slope's denominator — are therefore
/// done last, against the scaled sum.
///
/// Clamped at both ends: below the dark offset the sensor is reporting
/// its own leakage, above saturation it is reporting the load resistor.
pub fn millilux_from_sum(sum: u32, conversions: u32) -> u32 {
    if conversions == 0 {
        return 0;
    }
    let conversions = u64::from(conversions);
    let floor = conversions * u64::from(DARK_OFFSET_RAW);
    let ceiling = conversions * u64::from(SATURATION_RAW);
    let sum = u64::from(sum).min(ceiling);
    if sum <= floor {
        return 0;
    }
    let scaled =
        (sum - floor) * u64::from(SLOPE_MLUX_NUM) / (u64::from(SLOPE_MLUX_DEN) * conversions);
    scaled.min(u64::from(u32::MAX)) as u32
}

/// The largest value this board can report — the reading at
/// [`SATURATION_RAW`], about 253 lux.
///
/// A ceiling, not a measurement: everything from a bright room to direct
/// sunlight lands on it. The part is a dark-end instrument, and at the
/// dark end it is a good one — one count is 21 mlux, so full moonlight
/// (~300 mlux) sits about 15 counts up with a 4 mlux noise floor beneath
/// it. Anything wanting a daylight figure needs a different sensor.
pub const MAX_REPORTABLE_MLUX: u32 =
    (SATURATION_RAW - DARK_OFFSET_RAW) * SLOPE_MLUX_NUM / SLOPE_MLUX_DEN;

/// Convert one SAADC count on AIN5 to millilux — [`millilux_from_sum`]
/// for a single conversion.
pub fn raw_to_millilux(raw: u16) -> u32 {
    millilux_from_sum(u32::from(raw), 1)
}

#[cfg(target_os = "none")]
mod sampling {
    use core::sync::atomic::{AtomicU32, Ordering};

    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::signal::Signal;

    /// Wakes the battery monitor to take a light measurement now (see
    /// [`sample_illuminance`]).
    pub(crate) static LIGHT_SAMPLE_REQUEST: Signal<ThreadModeRawMutex, ()> = Signal::new();
    pub(crate) static LIGHT_SAMPLE_REPLY: Signal<ThreadModeRawMutex, u32> = Signal::new();

    /// The most recent measurement, however it was triggered, in
    /// millilux. `u32::MAX` until one exists — that cannot be a reading,
    /// because the conversion tops out at
    /// [`MAX_REPORTABLE_MLUX`](super::MAX_REPORTABLE_MLUX).
    static AMBIENT_MILLILUX: AtomicU32 = AtomicU32::new(u32::MAX);

    /// The most recent illuminance measurement in millilux, whoever asked
    /// for it; `None` until the first one completes.
    ///
    /// This is the consumer side of [`request_sample`], but every
    /// measurement lands here — an on-demand [`sample_illuminance`] for a
    /// protocol read refreshes it too.
    pub fn ambient_millilux() -> Option<u32> {
        match AMBIENT_MILLILUX.load(Ordering::Acquire) {
            u32::MAX => None,
            millilux => Some(millilux),
        }
    }

    /// Record a completed measurement. Called by the sampler in
    /// [`crate::power`] for every measurement it takes.
    pub(crate) fn publish_ambient(millilux: u32) {
        AMBIENT_MILLILUX.store(millilux, Ordering::Release);
    }

    /// Ask for a measurement without waiting for it: the result appears
    /// in [`ambient_millilux`] once taken. For callers that must not
    /// block on the monitor — the LED task requests from inside the
    /// select loop that also answers the sampler's blanking handshake.
    ///
    /// The request latches, so duplicates coalesce, and the reply signal
    /// is left alone: [`sample_illuminance`] resets it before waiting, so
    /// an unconsumed reply from this path cannot satisfy a later
    /// on-demand read.
    pub fn request_sample() {
        LIGHT_SAMPLE_REQUEST.signal(());
    }

    /// Ask [`run_battery_monitor`](crate::power::run_battery_monitor) —
    /// the sole SAADC and sensor-rail owner — for a fresh illuminance
    /// measurement in millilux and wait for it.
    ///
    /// Single-consumer, like the monitor itself. Never completes once the
    /// monitor has exited for critical-battery shutdown, so callers must
    /// apply their own timeout.
    pub async fn sample_illuminance() -> u32 {
        LIGHT_SAMPLE_REPLY.reset();
        LIGHT_SAMPLE_REQUEST.signal(());
        LIGHT_SAMPLE_REPLY.wait().await
    }
}

#[cfg(target_os = "none")]
pub(crate) use sampling::{LIGHT_SAMPLE_REPLY, LIGHT_SAMPLE_REQUEST, publish_ambient};
#[cfg(target_os = "none")]
pub use sampling::{ambient_millilux, request_sample, sample_illuminance};

#[cfg(test)]
mod tests {
    use super::*;

    /// Millilux for a whole number of counts above dark, whatever the
    /// constants currently are.
    fn at_counts(counts: u32) -> u32 {
        counts * SLOPE_MLUX_NUM / SLOPE_MLUX_DEN
    }

    #[test]
    fn saturates_at_the_ceiling() {
        let ceiling = raw_to_millilux(SATURATION_RAW as u16);
        assert_eq!(raw_to_millilux(SATURATION_RAW as u16 + 1), ceiling);
        assert_eq!(raw_to_millilux(u16::MAX), ceiling);
        assert_eq!(ceiling, MAX_REPORTABLE_MLUX);
        // The clamp survives averaging: a run entirely past saturation
        // reports the ceiling, not an extrapolation.
        assert_eq!(millilux_from_sum(u32::MAX, 23), ceiling);
    }

    /// Whatever the constants are set to, the conversion must never
    /// overflow or wrap — the sum of a full run at full scale is the
    /// worst case the sampler can hand it.
    #[test]
    fn a_full_scale_run_does_not_overflow() {
        let full_run = 23 * 16_383;
        let millilux = millilux_from_sum(full_run, 23);
        assert_eq!(millilux, MAX_REPORTABLE_MLUX);
        assert!(millilux < u32::MAX);
    }

    /// The whole point of summing rather than pre-averaging: a run whose
    /// mean falls between two counts must land between the two millilux
    /// values, not on one of them.
    #[test]
    fn the_average_keeps_resolution_below_one_count() {
        let base = DARK_OFFSET_RAW + 100;
        // Twenty conversions at `base`, three at `base + 1` — a mean of
        // 100.13 counts above dark, which whole counts cannot express.
        let sum = 20 * base + 3 * (base + 1);
        let averaged = millilux_from_sum(sum, 23);
        assert!(averaged > at_counts(100));
        assert!(averaged < at_counts(101));
    }

    /// A conversion count of zero is a caller bug, not a panic.
    #[test]
    fn an_empty_run_reads_zero() {
        assert_eq!(millilux_from_sum(10_000, 0), 0);
    }
}
