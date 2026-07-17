//! Power control glue for the T1000-E: the [`SHUTDOWN_SIGNAL`] static, a
//! [`PowerSignaler`] that bridges the CLI's `umsh_hal::PowerControl`
//! trait into board-level power events, and the [`run_battery_monitor`]
//! task that triggers a protective shutdown on low VBAT.
//!
//! The BSP owns these because the *signaling* shape is uniform — fire a
//! signal for soft-poweroff, hit `SYSRESETREQ` for reboot. The actual
//! board-specific teardown sequence lives in [`crate::shutdown::run`],
//! which awaits [`SHUTDOWN_SIGNAL`].

use core::sync::atomic::{AtomicU8, Ordering};

use embassy_futures::select::{Either3, select3};
use embassy_nrf::gpio::{Input, Output};
use embassy_nrf::saadc::Saadc;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Timer};
use umsh_ux_tracker::battery::{BatteryState, BatteryThresholds, classify};

/// Single-consumer shutdown trigger. Fired by [`PowerSignaler::request_power_off`]
/// (via the CLI `/poweroff` command) and by any firmware-local source that wants
/// to drive the shutdown sequence (e.g. button long-press, low-battery cutoff).
///
/// The firmware's `shutdown_task` is the only consumer.
pub static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

/// Current mutually exclusive user-facing battery mode.
static BATTERY_STATE: AtomicU8 = AtomicU8::new(BatteryState::BatteryOnly as u8);

/// Wakes the LED policy whenever the battery mode changes.
pub static BATTERY_STATE_CHANGED: Signal<ThreadModeRawMutex, BatteryState> = Signal::new();

pub fn battery_state() -> BatteryState {
    BatteryState::from_u8(BATTERY_STATE.load(Ordering::Acquire))
}

fn publish_battery_state(state: BatteryState) {
    let previous = BATTERY_STATE.swap(state as u8, Ordering::AcqRel);
    if previous != state as u8 {
        BATTERY_STATE_CHANGED.signal(state);
    }
}

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
        crate::preferences::set_asleep(true);
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
pub async fn run_battery_monitor(
    mut saadc: Saadc<'static, 1>,
    mut sensor_rail: Output<'static>,
    mut external_power: Input<'static>,
    mut charge_active: Input<'static>,
) {
    const CONSECUTIVE_NEEDED: u8 = 10;
    const SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
    const EDGE_DEBOUNCE: Duration = Duration::from_millis(20);

    let mut low_count: u8 = 0;

    loop {
        // Gate the sensor rail, settle, sample, then drop the rail.
        sensor_rail.set_high();
        Timer::after(Duration::from_millis(5)).await;
        let mut buf = [0i16; 1];
        saadc.sample(&mut buf).await;
        sensor_rail.set_low();

        let raw = u32::from(buf[0].max(0) as u16);
        let battery_mv = ((raw * 7_200) / 4_096).min(u32::from(u16::MAX)) as u16;
        let state = classify(
            battery_mv,
            external_power.is_high(),
            charge_active.is_low(),
            BatteryThresholds::default(),
        );
        publish_battery_state(state);

        if matches!(
            state,
            BatteryState::BatteryCharging | BatteryState::BatteryCharged
        ) {
            crate::preferences::set_battery_critical(false);
        }

        if state == BatteryState::BatteryCritical {
            low_count = low_count.saturating_add(1);
            if low_count >= CONSECUTIVE_NEEDED {
                // Cell protection: force shutdown before the battery
                // reaches the deep-discharge knee.
                crate::preferences::set_battery_critical(true);
                SHUTDOWN_SIGNAL.signal(());
                return;
            }
        } else {
            low_count = 0;
        }

        match select3(
            Timer::after(SAMPLE_INTERVAL),
            external_power.wait_for_any_edge(),
            charge_active.wait_for_any_edge(),
        )
        .await
        {
            Either3::First(()) => {}
            Either3::Second(()) | Either3::Third(()) => Timer::after(EDGE_DEBOUNCE).await,
        }
    }
}
