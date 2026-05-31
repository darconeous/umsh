//! Power control glue for the T1000-E: the [`SHUTDOWN_SIGNAL`] static, a
//! [`PowerSignaler`] that bridges the CLI's `umsh_hal::PowerControl`
//! trait into board-level power events, and the [`run_battery_monitor`]
//! task that triggers a protective shutdown on low VBAT.
//!
//! The BSP owns these because the *signaling* shape is uniform — fire a
//! signal for soft-poweroff, hit `SYSRESETREQ` for reboot. The actual
//! board-specific teardown sequence lives in [`crate::shutdown::run`],
//! which awaits [`SHUTDOWN_SIGNAL`].

use embassy_nrf::gpio::Output;
use embassy_nrf::saadc::Saadc;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Timer};

/// Single-consumer shutdown trigger. Fired by [`PowerSignaler::request_power_off`]
/// (via the CLI `/poweroff` command) and by any firmware-local source that wants
/// to drive the shutdown sequence (e.g. button long-press, low-battery cutoff).
///
/// The firmware's `shutdown_task` is the only consumer.
pub static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

/// `umsh_hal::PowerControl` implementation for the T1000-E.
///
/// - `request_power_off` raises [`SHUTDOWN_SIGNAL`] so the firmware's
///   `shutdown_task` can run its board-specific teardown sequence.
/// - `request_reboot` triggers an ARM Cortex-M `SYSRESETREQ` directly.
///   Deliberately performs no flushing or teardown — that would mask
///   persistence and state-recovery bugs we want the `/reboot` command
///   to surface.
pub struct PowerSignaler;

impl umsh_hal::PowerControl for PowerSignaler {
    fn request_power_off(&self) {
        SHUTDOWN_SIGNAL.signal(());
    }

    fn request_reboot(&self) {
        cortex_m::peripheral::SCB::sys_reset();
    }
}

/// Monitors battery voltage via the nRF52840 SAADC (P0.02 = AIN0, 2:1 divider).
///
/// The sensor rail (P1.06) must be enabled during sampling — it gates the
/// analog path to the battery divider. The rail is dropped immediately after
/// the read to minimise the power overhead.
///
/// Voltage math (12-bit, GAIN1_6, 0.6 V INTERNAL reference):
///   full-scale input = 0.6 V / (1/6) = 3.6 V → 4096 LSB
///   with 2:1 divider: VBAT_mV = raw × 2 × 3600 / 4096 = raw × 1.758 mV
///
/// 3.1 V low threshold → raw ≈ 1764. Ten consecutive under-threshold
/// samples trigger a protective shutdown via [`SHUTDOWN_SIGNAL`].
///
/// Wrap in `#[embassy_executor::task]` in the firmware binary so the
/// linker sees a concrete monomorphisation.
pub async fn run_battery_monitor(mut saadc: Saadc<'static, 1>, mut sensor_rail: Output<'static>) {
    const LOW_RAW: i16 = 1764; // ~3.1 V VBAT
    const CONSECUTIVE_NEEDED: u8 = 10;
    const SAMPLE_INTERVAL: Duration = Duration::from_secs(30);

    let mut low_count: u8 = 0;

    loop {
        Timer::after(SAMPLE_INTERVAL).await;

        // Gate the sensor rail, settle, sample, then drop the rail.
        sensor_rail.set_high();
        Timer::after(Duration::from_millis(5)).await;
        let mut buf = [0i16; 1];
        saadc.sample(&mut buf).await;
        sensor_rail.set_low();

        let raw = buf[0].max(0);
        if raw < LOW_RAW {
            low_count = low_count.saturating_add(1);
            if low_count >= CONSECUTIVE_NEEDED {
                // Cell protection: force shutdown before the battery
                // reaches the deep-discharge knee.
                SHUTDOWN_SIGNAL.signal(());
                return;
            }
        } else {
            low_count = 0;
        }
    }
}
