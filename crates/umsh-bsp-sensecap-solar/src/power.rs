//! Power control + battery monitoring for the SenseCAP Solar Node.
//!
//! Two pieces:
//!
//! - [`PowerSignaler`] — the CLI's `umsh_hal::PowerControl` bridge.
//!   `request_power_off` raises [`SHUTDOWN_SIGNAL`] for the teardown in
//!   [`crate::shutdown`]; `request_reboot` is a plain `SYSRESETREQ`.
//! - The battery monitor ([`run_battery_monitor`], [`sample_battery`],
//!   [`BatterySample`], [`battery_state`]) — ported from the T1000-E BSP
//!   with this board's wiring, so the device's `CAP_BATTERY`
//!   snapshot path is board-agnostic.
//!
//! ## Voltage reading (MeshCore method, nominal — uncalibrated)
//!
//! Reads AIN7/P0.31 through the on-board 1 MΩ / 512 kΩ resistor bridge,
//! matching MeshCore's `SenseCapSolarBoard::getBattMilliVolts`. Our SAADC
//! is `embassy-nrf`'s default single-ended config: 12-bit, `Gain1_6`,
//! 0.6 V internal reference → **3.6 V full scale** at the pin. The divider
//! ratio is `(1M + 512k) / 512k = 2.953` (MeshCore rounds this to 3.0):
//!
//! ```text
//! Vpin_mV = raw * 3600 / 4096            (12-bit, Gain1_6, 0.6 V ref)
//! VBAT_mV = Vpin_mV * 1512 / 512         (1M/512k bridge, = ×2.953)
//!         = raw * (3600 * 1512 / 512) / 4096 = raw * 10631 / 4096
//! ```
//!
//! This is the *nominal* network value, not a fitted calibration —
//! resistor tolerance (±1 %) dominates the residual error. Good enough
//! for the protective low-battery cutoff; a bench calibration (plan
//! Phase 2) can still replace [`DIVIDER_MICRO`] with a fitted slope.

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;
use umsh_bsp_nrf52840::system_off::ShutdownReason;

/// Single-consumer power-off trigger. Fired by the dedicated PWR-button
/// state machine (hold-to-off), the low-battery protective cutoff in
/// [`run_battery_monitor`], and [`PowerSignaler::request_power_off`]. The
/// firmware's sensecap shutdown task ([`crate::shutdown::run`]) is the
/// only consumer; it runs the System OFF teardown and arms PWR wake.
///
/// The [`ShutdownReason`] carried here splits that teardown in two: a
/// requested power-off disconnects the divider and waits for a button,
/// while the low-battery cutoff leaves the divider live and arms LPCOMP so
/// the panel can bring the node back unattended. See [`crate::shutdown`].
pub static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ShutdownReason> = Signal::new();

/// `umsh_hal::PowerControl` implementation for the SenseCAP Solar Node.
///
/// - `request_power_off` raises [`SHUTDOWN_SIGNAL`] so the firmware's
///   sensecap shutdown task runs the System OFF teardown.
/// - `request_reboot` triggers an ARM Cortex-M `SYSRESETREQ`.
pub struct PowerSignaler;

impl umsh_hal::PowerControl for PowerSignaler {
    fn request_power_off(&self) {
        SHUTDOWN_SIGNAL.signal(ShutdownReason::Requested);
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
    use embassy_sync::watch::Watch;
    use embassy_time::{Duration, Timer};
    use umsh_ux_tracker::battery::{
        BatteryState, BatteryThresholds, ChargeClass, LevelEstimator, LevelSample, charge_class,
        classify, load_recent,
    };

    /// VBAT scaling, chosen so integer math stays exact:
    /// `battery_mv = raw * DIVIDER_MICRO / 4096`.
    ///
    /// Nominal 1M/512k-bridge value (see module docs), not a fitted
    /// calibration:
    ///   Vadc_mV = raw * 3600 / 4096              (12-bit, Gain1_6, 0.6 V ref)
    ///   VBAT_mV = Vadc_mV * 1512 / 512           (×2.953 divider)
    ///          = raw * (3600 * 1512 / 512) / 4096 = raw * 10631 / 4096
    const DIVIDER_MICRO: u32 = 10_631;

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

    /// Battery measurements worth announcing to a remote observer, for
    /// `PROP_BATTERY` asynchronous updates. Multi-receiver, and filtered
    /// on charge class plus level rather than the five-way presentation
    /// classification — see the T1000-E BSP's equivalent for the
    /// reasoning, which is identical.
    pub static BATTERY_ANNOUNCE: Watch<
        ThreadModeRawMutex,
        BatterySample,
        BATTERY_ANNOUNCE_RECEIVERS,
    > = Watch::new();

    /// Receivers of [`BATTERY_ANNOUNCE`]: the ULCP session driver.
    pub const BATTERY_ANNOUNCE_RECEIVERS: usize = 1;

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
    /// inferred solely from `POWER.usbregstatus`. `CONSECUTIVE_NEEDED`
    /// samples below the critical threshold (≈3.1 V, sustained ~5 min,
    /// only ever reached off-USB since `classify` reports Charging while
    /// external power is present) fire [`SHUTDOWN_SIGNAL`] for a protective
    /// System OFF — the unattended-node counterpart of the PWR button.
    /// That signal carries `ShutdownReason::BatteryCritical`, which is what
    /// makes the teardown leave the divider connected and arm LPCOMP: an
    /// unattended node that runs its cell down comes back by itself once
    /// the panel has refilled it past roughly 3.65 V.
    ///
    /// Wrap in `#[embassy_executor::task]` in the firmware binary so the
    /// linker sees a concrete monomorphisation.
    pub async fn run_battery_monitor(
        mut saadc: Saadc<'static, 1>,
        mut divider_gate: Output<'static>,
    ) {
        const CONSECUTIVE_NEEDED: u8 = 10;
        /// Normal cadence. Nothing is learned by reading the divider
        /// faster: the pack discharges over days and the level estimator
        /// quantizes to 5 %. External-power changes do not wait for it —
        /// [`VBUS_POLL_INTERVAL`] catches those.
        const SAMPLE_INTERVAL: Duration = Duration::from_secs(300);
        /// Cadence while the pack reads Low or Critical, so the protective
        /// cutoff (`CONSECUTIVE_NEEDED` consecutive critical samples) keeps
        /// its intended ~5-minute latency instead of scaling with the
        /// normal interval.
        const LOW_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
        /// How often VBUS is checked between voltage samples.
        ///
        /// This board has no charger-status GPIO — external power is
        /// `POWER.usbregstatus` only — and the `POWER` USB interrupts are
        /// unavailable to this firmware (MPSL owns the shared CLOCK_POWER
        /// vector; enabling them is the post-DFU watchdog freeze). So the
        /// charge-state edge has to be polled. It costs one register read,
        /// with no divider gating and no SAADC, which is why it can run
        /// far more often than the voltage sample.
        const VBUS_POLL_INTERVAL: Duration = Duration::from_secs(5);
        // Active-low divider gate: HIGH = disconnected (idle, no draw).
        divider_gate.set_high();

        let mut low_count: u8 = 0;
        let mut reply_pending = false;
        let mut estimator = LevelEstimator::new();
        let announce = BATTERY_ANNOUNCE.sender();
        // Last announced (charge class, level); `None` until the first
        // sample, which always announces.
        let mut announced: Option<(ChargeClass, Option<u8>)> = None;

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
            // No charge-detect pin: VBUS presence stands in for "charging"
            // (provisional). Passing it as both flags means Charged is
            // unreachable on this board — with external power the state is
            // always Charging — so a remote observer sees charging start
            // and stop but never charge *completion*. Distinguishing it
            // would mean inferring termination from voltage, i.e.
            // inventing charger state the hardware does not report.
            let state = classify(battery_mv, usb, usb, BatteryThresholds::default());
            publish_battery_state(state);

            // Feed the level estimator; a load within the sag window marks
            // this voltage as potentially sagged rather than resting.
            let now_ms = embassy_time::Instant::now().as_millis() as u32;
            let last_load_ms = match LAST_LOAD_MS.load(Ordering::Acquire) {
                u32::MAX => None,
                timestamp => Some(timestamp),
            };
            estimator.sample(LevelSample {
                battery_mv,
                state,
                load_recent: load_recent(now_ms, last_load_ms),
                now_ms,
            });

            let sample = BatterySample {
                battery_mv,
                state,
                level_percent: estimator.level(),
            };

            if reply_pending || BATTERY_SAMPLE_REQUEST.try_take().is_some() {
                reply_pending = false;
                BATTERY_SAMPLE_REPLY.signal(sample);
            }

            // Announce when the fields a remote observer acts on moved.
            // On-demand reads pass through here too, so a GET that reveals
            // a change rebaselines rather than leaving a duplicate
            // publication behind it.
            let key = (charge_class(state), sample.level_percent);
            if announced != Some(key) {
                announced = Some(key);
                announce.send(sample);
            }

            // Protective cell cutoff: sustained critical voltage while on
            // battery drives a System OFF so the pack is not deep-discharged
            // when nobody is present. `!usb` is belt-and-suspenders — a
            // Critical classification already implies no external power.
            if state == BatteryState::BatteryCritical && !usb {
                low_count = low_count.saturating_add(1);
                if low_count >= CONSECUTIVE_NEEDED {
                    super::SHUTDOWN_SIGNAL.signal(super::ShutdownReason::BatteryCritical);
                    return;
                }
            } else {
                low_count = 0;
            }

            // A pack already reading Low or Critical is watched closely;
            // the cutoff's latency depends on it.
            let interval = if matches!(
                state,
                BatteryState::BatteryLow | BatteryState::BatteryCritical
            ) {
                LOW_SAMPLE_INTERVAL
            } else {
                SAMPLE_INTERVAL
            };
            // Watch VBUS between voltage samples so plugging or unplugging
            // is reflected within seconds instead of within `interval`.
            // Returns as soon as it disagrees with this iteration's
            // reading, and the loop re-samples from the top.
            let vbus_changed = async {
                loop {
                    Timer::after(VBUS_POLL_INTERVAL).await;
                    if usb_power_present() != usb {
                        return;
                    }
                }
            };
            match embassy_futures::select::select3(
                Timer::after(interval),
                BATTERY_SAMPLE_REQUEST.wait(),
                vbus_changed,
            )
            .await
            {
                embassy_futures::select::Either3::First(()) => {}
                // An on-demand request: sample immediately from the top.
                embassy_futures::select::Either3::Second(()) => reply_pending = true,
                // External power appeared or vanished: re-sample now so
                // the charge-state change is published promptly.
                embassy_futures::select::Either3::Third(()) => {}
            }
        }
    }
}
