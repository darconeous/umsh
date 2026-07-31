//! Power control + battery monitoring for the T-Echo.
//!
//! Two pieces:
//!
//! - [`PowerSignaler`] and the [`SHUTDOWN_SIGNAL`] static, which bridge
//!   the CLI's `umsh_hal::PowerControl` trait into board-level power
//!   events. See `umsh-bsp-t1000e::power` for the design rationale — the
//!   shape is identical here. The board-specific teardown sequence lives
//!   in the firmware's `shutdown_task`, which awaits [`SHUTDOWN_SIGNAL`].
//! - The battery monitor ([`run_battery_monitor`], [`sample_battery`],
//!   [`BatterySample`], [`battery_state`]) — the same shape as the
//!   SenseCAP Solar and T-1000E monitors with this board's wiring, so the
//!   device's `CAP_BATTERY` snapshot path stays board-agnostic.
//!
//! ## Voltage reading (nominal — uncalibrated)
//!
//! Reads AIN2/P0.04 through the on-board 150 kΩ / 150 kΩ divider. Our
//! SAADC is `embassy-nrf`'s default single-ended config: 12-bit,
//! `Gain1_6`, 0.6 V internal reference → **3.6 V full scale** at the pin.
//! The divider halves VBAT, so the compensation factor is 2.0 (this is the
//! factor Meshtastic's T-Echo variant and MeshCore's `TechoBoard` both
//! use; MeshCore's `variant.h` also carries a 4.90× macro, which
//! contradicts its own board file and is treated as stale):
//!
//! ```text
//! Vpin_mV = raw * 3600 / 4096            (12-bit, Gain1_6, 0.6 V ref)
//! VBAT_mV = Vpin_mV * 2                  (150k/150k divider)
//!         = raw * 7200 / 4096
//! ```
//!
//! Note this differs from the `2.0 * 3000 / 4096` formula quoted in
//! `docs/hardware/lilygo-techo-hardware.md`: that figure comes from Arduino-side
//! firmware running the SAADC at a 3.0 V full scale, not the 3.6 V our
//! configuration produces. The divider ratio is the same; only the
//! reference term changes.
//!
//! This is the *nominal* network value, not a fitted calibration —
//! resistor tolerance dominates the residual error. Good enough for the
//! protective low-battery cutoff; a bench calibration can replace
//! [`DIVIDER_MICRO`] with a fitted slope.
//!
//! Unlike the SenseCAP Solar and T-1000E boards, the T-Echo's divider has
//! **no gate pin** — the 300 kΩ leg is hard-wired across the pack and
//! draws ~12 µA continuously. There is nothing for firmware to switch, so
//! the monitor loop has no settle step.
//!
//! LilyGO's own README warns that this ADC reads high while USB is
//! plugged in. That does not affect the reported *state* (external power
//! is detected independently, see [`usb_power_present`]), but a voltage
//! sampled on USB should not be read as a resting cell voltage — which is
//! also why the level estimator gates on rest.

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;

/// Single-consumer shutdown trigger, raised by
/// [`PowerSignaler::request_power_off`] and by the protective low-battery
/// cutoff in [`run_battery_monitor`]. The firmware's `shutdown_task` is
/// the only consumer; it also has its own button-driven trigger and waits
/// on both.
pub static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

/// `umsh_hal::PowerControl` implementation for the T-Echo.
///
/// - `request_power_off` raises [`SHUTDOWN_SIGNAL`].
/// - `request_reboot` triggers an ARM Cortex-M `SYSRESETREQ` with no
///   flushing or teardown.
pub struct PowerSignaler;

impl umsh_hal::PowerControl for PowerSignaler {
    fn request_power_off(&self) {
        SHUTDOWN_SIGNAL.signal(());
    }

    fn request_reboot(&self) {
        cortex_m::peripheral::SCB::sys_reset();
    }
}

#[cfg(all(target_os = "none", feature = "battery"))]
pub use monitor::*;

#[cfg(all(target_os = "none", feature = "battery"))]
mod monitor {
    use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

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
    /// Nominal 150k/150k-divider value (see module docs), not a fitted
    /// calibration:
    ///   Vadc_mV = raw * 3600 / 4096              (12-bit, Gain1_6, 0.6 V ref)
    ///   VBAT_mV = Vadc_mV * 2                    (×2.0 divider compensation)
    ///          = raw * 7200 / 4096
    const DIVIDER_MICRO: u32 = 7_200;

    /// Current mutually exclusive user-facing battery mode.
    static BATTERY_STATE: AtomicU8 = AtomicU8::new(BatteryState::BatteryOnly as u8);

    /// Wakes any display or LED policy whenever the battery mode changes.
    pub static BATTERY_STATE_CHANGED: Signal<ThreadModeRawMutex, BatteryState> = Signal::new();

    pub fn battery_state() -> BatteryState {
        BatteryState::from_u8(BATTERY_STATE.load(Ordering::Acquire))
    }

    /// Whether the nRF USB regulator currently detects VBUS. This is the
    /// only external-power signal on this board — the charger's status LED
    /// is hardware-driven and invisible to the MCU.
    ///
    /// Read straight from `POWER.usbregstatus`, which reflects the true
    /// VBUS pin state regardless of the `SoftwareVbusDetect` the USB stack
    /// is configured with.
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
    /// classification — see the T-1000E BSP's equivalent for the
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

    /// Ask [`run_battery_monitor`] — the sole SAADC owner — for a fresh
    /// measurement and wait for it. Single-consumer. Never completes once
    /// the monitor has exited; callers should apply a timeout.
    pub async fn sample_battery() -> BatterySample {
        BATTERY_SAMPLE_REPLY.reset();
        BATTERY_SAMPLE_REQUEST.signal(());
        BATTERY_SAMPLE_REPLY.wait().await
    }

    /// Monitors battery voltage via the SAADC on AIN2 / P0.04.
    ///
    /// Owns no divider gate (the T-Echo's is hard-wired) and no
    /// charge-detect GPIO (the charger exposes none); external power is
    /// inferred solely from `POWER.usbregstatus`. `CONSECUTIVE_NEEDED`
    /// samples below the critical threshold (≈3.1 V, sustained ~5 min,
    /// only ever reached off-USB since `classify` reports Charging while
    /// external power is present) fire [`super::SHUTDOWN_SIGNAL`] for a
    /// protective System OFF — nothing in the T-Echo's documented hardware
    /// proves an MCU-independent undervoltage lockout, so this is the only
    /// deep-discharge protection we can count on.
    ///
    /// Wrap in `#[embassy_executor::task]` in the firmware binary so the
    /// linker sees a concrete monomorphisation.
    pub async fn run_battery_monitor(mut saadc: Saadc<'static, 1>) {
        const CONSECUTIVE_NEEDED: u8 = 10;
        /// Normal cadence. Nothing is learned by reading faster: the pack
        /// discharges over days and the level estimator quantizes to 5 %.
        /// External-power changes do not wait for it —
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
        /// charge-state edge has to be polled. It costs one register read
        /// and no SAADC, which is why it can run far more often than the
        /// voltage sample.
        const VBUS_POLL_INTERVAL: Duration = Duration::from_secs(5);

        let mut low_count: u8 = 0;
        let mut reply_pending = false;
        let mut estimator = LevelEstimator::new();
        let announce = BATTERY_ANNOUNCE.sender();
        // Last announced (charge class, level); `None` until the first
        // sample, which always announces.
        let mut announced: Option<(ChargeClass, Option<u8>)> = None;

        loop {
            let mut buf = [0i16; 1];
            saadc.sample(&mut buf).await;

            let raw = u32::from(buf[0].max(0) as u16);
            let battery_mv = ((raw * DIVIDER_MICRO) / 4_096).min(u32::from(u16::MAX)) as u16;

            let usb = usb_power_present();
            // No charge-detect pin: VBUS presence stands in for "charging".
            // Passing it as both flags means Charged is unreachable on this
            // board — with external power the state is always Charging — so
            // a remote observer sees charging start and stop but never
            // charge *completion*. Distinguishing it would mean inferring
            // termination from a voltage LilyGO already warns is unreliable
            // while USB is attached.
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
            // in a drawer. `!usb` is belt-and-suspenders — a Critical
            // classification already implies no external power.
            if state == BatteryState::BatteryCritical && !usb {
                low_count = low_count.saturating_add(1);
                if low_count >= CONSECUTIVE_NEEDED {
                    super::SHUTDOWN_SIGNAL.signal(());
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
