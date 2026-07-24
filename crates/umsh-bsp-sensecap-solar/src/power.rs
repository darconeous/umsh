//! Power control + battery monitoring for the SenseCAP Solar Node.
//!
//! Two pieces:
//!
//! - [`PowerSignaler`] — the CLI's `umsh_hal::PowerControl` bridge.
//!   **Phase 1 stub**: `request_power_off` is a no-op; `request_reboot`
//!   is a plain `SYSRESETREQ`. Phase 6 replaces this with the real
//!   System OFF teardown + LPCOMP solar-recovery wake.
//! - The battery monitor ([`run_battery_monitor`], [`sample_battery`],
//!   [`BatterySample`], [`battery_state`]) — ported from the T1000-E BSP
//!   with this board's wiring, so the companion-NCP's `CAP_BATTERY`
//!   snapshot path is board-agnostic.
//!
//! ## ⚠️ Provisional, UNCALIBRATED voltage curve (Phase 2-min)
//!
//! Per the user's decision to skip bench calibration for now, the
//! millivolt conversion below is a **good guess**, not a fitted curve.
//! It assumes the SAADC is configured exactly as on the T1000-E (12-bit,
//! `GAIN1_6`, 0.6 V internal reference → 3.6 V full scale) and applies a
//! provisional divider multiplier of **3.15** — the midpoint of the
//! MeshCore (3.0) and Meshtastic (3.3) formulas, which disagree by ~21%.
//! Absolute voltages and the derived UX classification may be off until
//! a real calibration (plan Phase 2) replaces [`DIVIDER_MICRO`]. The
//! protective low-battery shutdown stays **disarmed (count-only)** until
//! Phase 6 establishes the calibrated shutdown/recovery pair.

/// `umsh_hal::PowerControl` implementation for the SenseCAP Solar Node.
///
/// - `request_power_off` is a **no-op** for now (Phase 6 wires the real
///   System OFF teardown).
/// - `request_reboot` triggers an ARM Cortex-M `SYSRESETREQ`.
pub struct PowerSignaler;

impl umsh_hal::PowerControl for PowerSignaler {
    fn request_power_off(&self) {
        // TODO (Phase 6): raise a SHUTDOWN_SIGNAL and run the board's
        // System OFF teardown (radio sleep, GNSS off, LEDs off, divider
        // gate disconnected, PWR-button + LPCOMP wake armed).
    }

    fn request_reboot(&self) {
        cortex_m::peripheral::SCB::sys_reset();
    }
}

#[cfg(target_os = "none")]
pub use monitor::*;

#[cfg(target_os = "none")]
mod monitor {
    use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

    use embassy_nrf::gpio::Output;
    use embassy_nrf::pac;
    use embassy_nrf::saadc::Saadc;
    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::signal::Signal;
    use embassy_time::{Duration, Timer};
    use umsh_ux_tracker::battery::{
        BatteryState, BatteryThresholds, LevelEstimator, LevelSample, classify,
    };

    /// Provisional VBAT scaling, in microvolts-per-LSB × 4096, chosen so
    /// integer math stays exact: `battery_mv = raw * DIVIDER_MICRO / 4096`.
    ///
    /// Derivation (all a GUESS — see module docs):
    ///   Vadc_mV   = raw * 3600 / 4096            (12-bit, GAIN1_6, 0.6 V ref)
    ///   VBAT_mV   = Vadc_mV * 3.15               (provisional divider mult)
    ///           = raw * (3600 * 3.15) / 4096 = raw * 11340 / 4096
    const DIVIDER_MICRO: u32 = 11_340;

    /// Current mutually exclusive user-facing battery mode.
    static BATTERY_STATE: AtomicU8 = AtomicU8::new(BatteryState::BatteryOnly as u8);

    /// Wakes any LED policy whenever the battery mode changes.
    pub static BATTERY_STATE_CHANGED: Signal<ThreadModeRawMutex, BatteryState> = Signal::new();

    pub fn battery_state() -> BatteryState {
        BatteryState::from_u8(BATTERY_STATE.load(Ordering::Acquire))
    }

    /// Whether the nRF USB regulator currently detects VBUS. This is the
    /// only external-power signal on this board — the CN3165 charger
    /// exposes nothing to the MCU (its red/green/yellow LEDs are
    /// hardware-driven).
    pub fn usb_power_present() -> bool {
        pac::POWER.usbregstatus().read().vbusdetect()
    }

    fn publish_battery_state(state: BatteryState) {
        let previous = BATTERY_STATE.swap(state as u8, Ordering::AcqRel);
        if previous != state as u8 {
            BATTERY_STATE_CHANGED.signal(state);
        }
    }

    /// One serviced battery measurement.
    #[derive(Clone, Copy, Debug)]
    pub struct BatterySample {
        pub battery_mv: u16,
        pub state: BatteryState,
        /// `Some` from the monitor's first sample onward.
        pub level_percent: Option<u8>,
    }

    /// Millisecond timestamp of the most recent externally reported load;
    /// `u32::MAX` sentinel = never.
    static LAST_LOAD_MS: AtomicU32 = AtomicU32::new(u32::MAX);

    /// Tell the battery monitor a significant transient load just ran (a
    /// radio transmission), so nearby voltage samples are treated as
    /// sagged rather than resting OCV by the level estimator.
    pub fn note_external_load() {
        LAST_LOAD_MS.store(
            embassy_time::Instant::now().as_millis() as u32,
            Ordering::Release,
        );
    }

    static BATTERY_SAMPLE_REQUEST: Signal<ThreadModeRawMutex, ()> = Signal::new();
    static BATTERY_SAMPLE_REPLY: Signal<ThreadModeRawMutex, BatterySample> = Signal::new();

    /// Ask [`run_battery_monitor`] — the sole SAADC and divider-gate owner
    /// — for a fresh measurement and wait for it. Single-consumer. Never
    /// completes once the monitor has exited; callers should apply a
    /// timeout.
    pub async fn sample_battery() -> BatterySample {
        BATTERY_SAMPLE_REPLY.reset();
        BATTERY_SAMPLE_REQUEST.signal(());
        BATTERY_SAMPLE_REPLY.wait().await
    }

    /// Monitors battery voltage via the SAADC on AIN7 / P0.31, gating the
    /// resistor divider with `divider_gate` (P0.14, **active-low**: driven
    /// LOW to connect the divider for a reading, HIGH to disconnect it and
    /// stop the quiescent draw).
    ///
    /// Unlike the T1000-E monitor this one owns no charge-detect or
    /// external-power GPIO (the CN3165 exposes nothing); external power is
    /// inferred solely from `POWER.usbregstatus`. The consecutive-low
    /// counter is kept but **takes no action** (log/count-only) until
    /// Phase 6 arms a calibrated protective shutdown.
    ///
    /// Wrap in `#[embassy_executor::task]` in the firmware binary so the
    /// linker sees a concrete monomorphisation.
    pub async fn run_battery_monitor(mut saadc: Saadc<'static, 1>, mut divider_gate: Output<'static>) {
        const CONSECUTIVE_NEEDED: u8 = 10;
        const SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
        // Active-low divider gate: HIGH = disconnected (idle, no draw).
        divider_gate.set_high();

        let mut low_count: u8 = 0;
        let mut reply_pending = false;
        let mut estimator = LevelEstimator::new();
        let mut previous_sample_ms = embassy_time::Instant::now().as_millis() as u32;

        loop {
            // Connect the divider (gate LOW), settle ≥10 ms, sample, then
            // disconnect (gate HIGH) to drop the divider's quiescent draw.
            divider_gate.set_low();
            Timer::after(Duration::from_millis(10)).await;
            let mut buf = [0i16; 1];
            saadc.sample(&mut buf).await;
            divider_gate.set_high();

            let raw = u32::from(buf[0].max(0) as u16);
            let battery_mv = ((raw * DIVIDER_MICRO) / 4_096).min(u32::from(u16::MAX)) as u16;

            let usb = usb_power_present();
            // No charge-detect pin: use VBUS presence as a coarse "charging"
            // proxy (provisional). classify() still separates charged vs
            // charging vs discharging from voltage + these flags.
            let state = classify(battery_mv, usb, usb, BatteryThresholds::default());
            publish_battery_state(state);

            // Feed the level estimator; a load since the previous iteration
            // marks this voltage as potentially sagged.
            let now_ms = embassy_time::Instant::now().as_millis() as u32;
            let load_ms = LAST_LOAD_MS.load(Ordering::Acquire);
            let load_since_last =
                load_ms != u32::MAX && load_ms.wrapping_sub(previous_sample_ms) < u32::MAX / 2;
            previous_sample_ms = now_ms;
            estimator.sample(LevelSample {
                battery_mv,
                state,
                load_since_last,
                now_ms,
            });

            if reply_pending || BATTERY_SAMPLE_REQUEST.try_take().is_some() {
                reply_pending = false;
                BATTERY_SAMPLE_REPLY.signal(BatterySample {
                    battery_mv,
                    state,
                    level_percent: estimator.level(),
                });
            }

            // Count-only for now: no protective shutdown until Phase 6
            // arms a calibrated threshold/recovery pair.
            if state == BatteryState::BatteryCritical {
                low_count = low_count.saturating_add(1);
                let _ = low_count >= CONSECUTIVE_NEEDED;
            } else {
                low_count = 0;
            }

            match embassy_futures::select::select(
                Timer::after(SAMPLE_INTERVAL),
                BATTERY_SAMPLE_REQUEST.wait(),
            )
            .await
            {
                embassy_futures::select::Either::First(()) => {}
                // An on-demand request: sample immediately from the top.
                embassy_futures::select::Either::Second(()) => reply_pending = true,
            }
        }
    }
}
