//! Power control + battery monitoring for the Wio Tracker L1.
//!
//! Two pieces:
//!
//! - [`PowerSignaler`] and the [`SHUTDOWN_SIGNAL`] static, which bridge
//!   the CLI's `umsh_hal::PowerControl` trait into board-level power
//!   events. See `umsh-bsp-t1000e::power` for the design rationale — the
//!   shape is identical here. The board-specific teardown sequence lives
//!   in the firmware's shutdown task, which awaits [`SHUTDOWN_SIGNAL`].
//! - The battery monitor ([`run_battery_monitor`], [`sample_battery`],
//!   [`BatterySample`], [`battery_state`]) — the same shape as the
//!   SenseCAP Solar, T-1000E, and T-Echo monitors with this board's
//!   wiring, so the device's `CAP_BATTERY` snapshot path stays
//!   board-agnostic.
//!
//! This board has a mechanical power switch, so a System OFF teardown is
//! a convenience (and a way to stop the protective cutoff from
//! deep-discharging the pack) rather than the only way to stop the
//! battery draining. That does not change any of the code here; it only
//! lowers the stakes if the teardown is ever wrong.
//!
//! ## Voltage reading (nominal — uncalibrated)
//!
//! Reads AIN7/P0.31 through the on-board half-voltage divider. Our SAADC
//! is `embassy-nrf`'s default single-ended config: 12-bit, `Gain1_6`,
//! 0.6 V internal reference → **3.6 V full scale** at the pin. The
//! divider halves VBAT, so the compensation factor is 2.0 (Meshtastic's
//! variant declares exactly this: `ADC_MULTIPLIER = 2.0`,
//! `AREF_VOLTAGE = 3.6`):
//!
//! ```text
//! Vpin_mV = raw * 3600 / 4096            (12-bit, Gain1_6, 0.6 V ref)
//! VBAT_mV = Vpin_mV * 2                  (half-voltage divider)
//!         = raw * 7200 / 4096
//! ```
//!
//! Unlike the T-Echo's hard-wired bridge, this divider is **gated** by
//! P0.04 (`BAT_READ` / `VBAT_ENABLE`), and unlike the SenseCAP Solar's
//! gate it is **active-high**: Meshtastic drives it HIGH to enable the
//! measurement path. The monitor therefore raises it, settles, samples,
//! and drops it again.
//!
//! This is the *nominal* network value, not a fitted calibration —
//! resistor tolerance dominates the residual error. Good enough for the
//! protective low-battery cutoff; a bench calibration can replace
//! [`DIVIDER_MICRO`] with a fitted slope.

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;

/// Single-consumer shutdown trigger, raised by
/// [`PowerSignaler::request_power_off`], by the nav button's four-second
/// hold, and by the protective low-battery cutoff in
/// [`run_battery_monitor`]. The firmware's shutdown task is the only
/// consumer.
pub static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

/// `umsh_hal::PowerControl` implementation for the Wio Tracker L1.
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

#[cfg(feature = "battery")]
pub use monitor::*;

#[cfg(feature = "battery")]
mod monitor {
    use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, Ordering};

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
    /// Nominal half-divider value (see module docs), not a fitted
    /// calibration:
    ///   Vadc_mV = raw * 3600 / 4096              (12-bit, Gain1_6, 0.6 V ref)
    ///   VBAT_mV = Vadc_mV * 2                    (half-voltage divider)
    ///          = raw * 7200 / 4096
    const DIVIDER_MICRO: u32 = 7_200;

    /// How long the gated divider needs to settle after P0.04 goes high
    /// before the sample is trustworthy. Same allowance the SenseCAP
    /// monitor makes for its own gate.
    const DIVIDER_SETTLE: Duration = Duration::from_millis(10);

    /// Current mutually exclusive user-facing battery mode.
    static BATTERY_STATE: AtomicU8 = AtomicU8::new(BatteryState::BatteryOnly as u8);

    /// Wakes any LED policy whenever the battery mode changes.
    pub static BATTERY_STATE_CHANGED: Signal<ThreadModeRawMutex, BatteryState> = Signal::new();

    pub fn battery_state() -> BatteryState {
        BatteryState::from_u8(BATTERY_STATE.load(Ordering::Acquire))
    }

    /// Most recent measured pack voltage, 0 before the first sample.
    static BATTERY_MV: AtomicU16 = AtomicU16::new(0);
    /// Most recent estimated charge level, 0xFF before the estimator has
    /// seen a resting sample.
    static BATTERY_LEVEL: AtomicU8 = AtomicU8::new(u8::MAX);

    /// The last measured pack voltage in millivolts, or `None` before the
    /// monitor's first sample.
    ///
    /// This board is the first nRF tracker with an emissive panel that
    /// renders the battery, and its display task wants the reading
    /// without joining [`BATTERY_ANNOUNCE`] (a single-consumer budget
    /// already spent on the ULCP driver). Two relaxed atomic loads are
    /// cheaper than another `Watch` receiver.
    pub fn battery_millivolts() -> Option<u16> {
        match BATTERY_MV.load(Ordering::Acquire) {
            0 => None,
            mv => Some(mv),
        }
    }

    /// The last estimated charge level in percent, or `None` until the
    /// level estimator has had a resting sample to work from.
    pub fn battery_level() -> Option<u8> {
        match BATTERY_LEVEL.load(Ordering::Acquire) {
            u8::MAX => None,
            level => Some(level),
        }
    }

    /// Raised when the charge class or estimated level moves — the two
    /// things the on-screen indicator draws.
    ///
    /// This is a *redraw* prompt, never a wake: a battery sample the user
    /// did not ask for must not light this board's emissive panel, or a
    /// tracker in a drawer would glow every five minutes forever.
    pub static BATTERY_UI_CHANGED: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Whether the nRF USB regulator currently detects VBUS.
    ///
    /// The board's charger exposes no status line to the MCU, so this is
    /// the only external-power signal available.
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
    /// `PROP_BATTERY` asynchronous updates. Filtered on charge class plus
    /// level rather than the five-way presentation classification — see
    /// the T1000-E BSP's equivalent for the reasoning, which is identical.
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
    /// resistor divider with `divider_gate` (P0.04, **active-high**:
    /// driven HIGH to connect the divider for a reading, LOW to
    /// disconnect it and stop the quiescent draw).
    ///
    /// External power is inferred solely from `POWER.usbregstatus`.
    /// `CONSECUTIVE_NEEDED` samples below the critical threshold (≈3.1 V,
    /// sustained ~5 min, only ever reached off-USB since `classify`
    /// reports Charging while external power is present) fire
    /// [`SHUTDOWN_SIGNAL`] for a protective System OFF.
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
        /// The `POWER` USB interrupts are unavailable to this firmware
        /// (MPSL owns the shared CLOCK_POWER vector; enabling them is the
        /// post-DFU watchdog freeze), so the charge-state edge has to be
        /// polled. It costs one register read, with no divider gating and
        /// no SAADC, which is why it can run far more often than the
        /// voltage sample.
        const VBUS_POLL_INTERVAL: Duration = Duration::from_secs(5);
        // Active-high divider gate: LOW = disconnected (idle, no draw).
        divider_gate.set_low();

        let mut low_count: u8 = 0;
        let mut reply_pending = false;
        let mut estimator = LevelEstimator::new();
        let announce = BATTERY_ANNOUNCE.sender();
        // Last announced (charge class, level); `None` until the first
        // sample, which always announces.
        let mut announced: Option<(ChargeClass, Option<u8>)> = None;

        loop {
            // Connect the divider (gate HIGH), settle, sample, then
            // disconnect (gate LOW) to drop the divider's quiescent draw.
            divider_gate.set_high();
            Timer::after(DIVIDER_SETTLE).await;
            let mut buf = [0i16; 1];
            saadc.sample(&mut buf).await;
            divider_gate.set_low();

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

            // Published for the display task, which reads rather than
            // subscribes. A measured pack never reads 0 mV, so the
            // "no sample yet" sentinel cannot collide with a real value.
            BATTERY_MV.store(sample.battery_mv, Ordering::Release);
            BATTERY_LEVEL.store(sample.level_percent.unwrap_or(u8::MAX), Ordering::Release);

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
                // The same two fields are what the panel draws.
                BATTERY_UI_CHANGED.signal(());
            }

            // Protective cell cutoff: sustained critical voltage while on
            // battery drives a System OFF so the pack is not deep-discharged
            // when nobody is present. `!usb` is belt-and-suspenders — a
            // Critical classification already implies no external power.
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
