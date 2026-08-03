//! Power control + battery monitoring for the XIAO nRF52840 + Wio-SX1262
//! Kit.
//!
//! Two pieces:
//!
//! - [`PowerSignaler`] — the `umsh_hal::PowerControl` bridge, raising
//!   [`SHUTDOWN_SIGNAL`] for the headless System OFF teardown in
//!   [`crate::shutdown`].
//! - The battery monitor ([`run_battery_monitor`], [`sample_battery`],
//!   [`BatterySample`], [`battery_state`]) — the same shape as the other
//!   nRF52840 boards' monitors with this board's wiring, so the device's
//!   `CAP_BATTERY` snapshot path stays board-agnostic.
//!
//! ## Voltage reading (schematic-derived, nominal — uncalibrated)
//!
//! Reads AIN7/`P0.31` through the XIAO's 1 MΩ / 510 kΩ bridge. Our SAADC
//! is `embassy-nrf`'s default single-ended config: 12-bit, `Gain1_6`,
//! 0.6 V internal reference → **3.6 V full scale** at the pin:
//!
//! ```text
//! Vpin_mV = raw * 3600 / 4096            (12-bit, Gain1_6, 0.6 V ref)
//! VBAT_mV = Vpin_mV * 1510 / 510         (1M/510k bridge, = ×2.9608)
//!         = raw * (3600 * 1510 / 510) / 4096 = raw * 10659 / 4096
//! ```
//!
//! The resistor values are printed on the Seeed schematic and Meshtastic's
//! variant agrees (`R17=1M, R18=510k`). Both upstream firmwares round the
//! ratio to 3.0 and so read about 1.3 % high; we do not. This is still the
//! *nominal* network value rather than a fitted calibration — 1 % resistor
//! tolerance dominates the residual — so a bench calibration can replace
//! [`DIVIDER_MICRO`] with a fitted slope before it is trusted for a
//! protective cutoff.
//!
//! Note the SenseCAP Solar BSP uses `10_631` for what is physically the
//! same network, having inherited MeshCore's "1M, 512k" comment. The
//! difference is +0.26 %, well inside tolerance, so that board is not
//! wrong — just worth revisiting if it is ever bench-calibrated.
//!
//! ## The `P0.14` rule
//!
//! **`P0.14` is driven LOW at all times and never released.** It is the
//! divider's low side, not a gate, and this is a hardware rule rather
//! than a power policy. For a 4.2 V cell at VDD = 3.3 V:
//!
//! | `P0.14` state       | V at `P0.31` | Current | Verdict |
//! |---------------------|-------------:|--------:|---------|
//! | driven LOW          |       1.42 V |  2.8 µA | safe; the intended state |
//! | driven HIGH         |       3.60 V |  0.6 µA | exactly at the `VDD + 0.3` absolute maximum |
//! | disconnected input  |       4.2 V  |  0.3 µA | **worst** — well past absolute maximum |
//!
//! High-Z is the intuitive "disconnect" and it is the wrong answer: with
//! no path through the 510 kΩ leg the tap floats to the full cell voltage
//! and is held down only by `P0.31`'s ESD diode. Seeed's own wiki says to
//! keep the pin low and to avoid raising it during charging.
//!
//! So this monitor, unlike the SenseCAP Solar and Wio Tracker L1 ones,
//! **owns no gate and performs no settle step**: the divider is live
//! continuously and its ~2.8 µA is the documented price of the design.
//! The shipping Meshtastic build for this board drives `P0.14` high after
//! every read, which is precisely the state Seeed warns against; it is
//! not a reference implementation for this path.

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;

/// Single-consumer power-off trigger. The firmware's shutdown task
/// ([`crate::shutdown::run`]) is the only consumer.
///
/// In the shipping device image this has exactly **one** producer: the
/// low-battery protective cutoff in [`run_battery_monitor`]. The other
/// boards in this family also raise it from a button hold, and this one
/// has no button; there is no ULCP or BLE power-off command in that
/// firmware either. So an unattended flat pack is the only thing that
/// powers this board down on its own — which is fine, because that is
/// also the only case where powering down is worth the trip (see
/// [`crate::shutdown`] for how hard it is to come back).
pub static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

/// `umsh_hal::PowerControl` implementation for the XIAO nRF52840 kit.
///
/// Provided for the CLI firmware's `PowerControl` bridge, which is what
/// consumes this trait; the ULCP device image does not use it. Wiring a
/// remote power-off command to it would work, but think first — see
/// [`crate::shutdown`] on why System OFF is close to one-way here.
///
/// - `request_power_off` raises [`SHUTDOWN_SIGNAL`].
/// - `request_reboot` triggers an ARM Cortex-M `SYSRESETREQ`.
pub struct PowerSignaler;

impl umsh_hal::PowerControl for PowerSignaler {
    fn request_power_off(&self) {
        SHUTDOWN_SIGNAL.signal(());
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

    use embassy_nrf::gpio::{Input, Output};
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
    /// Nominal 1M/510k-bridge value (see module docs), not a fitted
    /// calibration:
    ///   Vadc_mV = raw * 3600 / 4096              (12-bit, Gain1_6, 0.6 V ref)
    ///   VBAT_mV = Vadc_mV * 1510 / 510           (×2.9608 divider)
    ///          = raw * (3600 * 1510 / 510) / 4096 = raw * 10659 / 4096
    const DIVIDER_MICRO: u32 = 10_659;

    /// Current mutually exclusive user-facing battery mode.
    static BATTERY_STATE: AtomicU8 = AtomicU8::new(BatteryState::BatteryOnly as u8);

    /// Wakes any LED policy whenever the battery mode changes.
    pub static BATTERY_STATE_CHANGED: Signal<ThreadModeRawMutex, BatteryState> = Signal::new();

    pub fn battery_state() -> BatteryState {
        BatteryState::from_u8(BATTERY_STATE.load(Ordering::Acquire))
    }

    /// Whether the nRF USB regulator currently detects VBUS.
    ///
    /// Together with the BQ25100's `~CHG` line this board can tell
    /// "charging" from "charge complete" — VBUS present with `~CHG`
    /// released means the charger terminated. `~CHG` alone cannot: it is
    /// high both when the pack is full and when there is no input power.
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

    /// Ask [`run_battery_monitor`] — the sole SAADC owner — for a fresh
    /// measurement and wait for it. Single-consumer. Never completes once
    /// the monitor has exited; callers should apply a timeout.
    pub async fn sample_battery() -> BatterySample {
        BATTERY_SAMPLE_REPLY.reset();
        BATTERY_SAMPLE_REQUEST.signal(());
        BATTERY_SAMPLE_REPLY.wait().await
    }

    /// Monitors battery voltage via the SAADC on AIN7 / `P0.31`.
    ///
    /// Takes ownership of three pins for the life of the program:
    ///
    /// - `divider_low` — `P0.14`, the divider's low side. Driven LOW here
    ///   and **never raised or released**; see the module docs for why
    ///   both alternatives are worse. There is no settle step because
    ///   there is nothing to switch.
    /// - `charge_status_n` — `P0.17`, the BQ25100's open-drain `~CHG`,
    ///   LOW while charging. Input only: it shares a node with the red
    ///   charge LED and driving it fights both.
    /// - `charge_current_hi` — `P0.13` (`HICHG`), held at the level the
    ///   caller chose (LOW = 100 mA, HIGH = 50 mA). The monitor only
    ///   keeps it alive; dropping the `Output` would return the pin to a
    ///   disconnected input, which the BQ25100 reads as 50 mA.
    ///
    /// `CONSECUTIVE_NEEDED` samples below the critical threshold (≈3.1 V,
    /// sustained ~5 min, only ever reached off-USB since `classify`
    /// reports a charge state while external power is present) fire
    /// [`super::SHUTDOWN_SIGNAL`] for a protective System OFF. On this
    /// board that matters more than most: there is no power switch and no
    /// way to cut any rail, so firmware discipline is the *only*
    /// deep-discharge protection.
    ///
    /// Wrap in `#[embassy_executor::task]` in the firmware binary so the
    /// linker sees a concrete monomorphisation.
    pub async fn run_battery_monitor(
        mut saadc: Saadc<'static, 1>,
        mut divider_low: Output<'static>,
        charge_status_n: Input<'static>,
        _charge_current_hi: Output<'static>,
    ) {
        const CONSECUTIVE_NEEDED: u8 = 10;
        /// Normal cadence. Nothing is learned by reading faster: the pack
        /// discharges over days and the level estimator quantizes to 5 %.
        /// Charge-state changes do not wait for it —
        /// [`CHARGE_POLL_INTERVAL`] catches those.
        const SAMPLE_INTERVAL: Duration = Duration::from_secs(300);
        /// Cadence while the pack reads Low or Critical, so the protective
        /// cutoff (`CONSECUTIVE_NEEDED` consecutive critical samples) keeps
        /// its intended ~5-minute latency instead of scaling with the
        /// normal interval.
        const LOW_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
        /// How often VBUS and `~CHG` are checked between voltage samples.
        ///
        /// The `POWER` USB interrupts are unavailable to this firmware
        /// (MPSL owns the shared CLOCK_POWER vector; enabling them is the
        /// post-DFU watchdog freeze), and `~CHG` would need a GPIOTE
        /// channel to watch asynchronously, so both edges are polled. It
        /// costs one register read and one pin read, with no SAADC, which
        /// is why it can run far more often than the voltage sample.
        const CHARGE_POLL_INTERVAL: Duration = Duration::from_secs(5);

        // The divider's low side. Driven LOW for the life of the program:
        // this is the reading path, not a gate. Raising it puts P0.31 at
        // its absolute maximum and releasing it puts P0.31 past it.
        divider_low.set_low();

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
            // Unlike the other boards in this family, the charger reports
            // its own state: BQ25100 `~CHG` is LOW while charging and
            // released once charging terminates. With VBUS as the
            // external-power flag, BatteryCharged is genuinely reachable
            // here — a remote observer sees charge completion, not just
            // charge start and stop.
            let charging = charge_status_n.is_low();
            let state = classify(battery_mv, usb, charging, BatteryThresholds::default());
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
            // Watch VBUS and `~CHG` between voltage samples so plugging,
            // unplugging, and charge termination are reflected within
            // seconds instead of within `interval`. Returns as soon as
            // either disagrees with this iteration's reading, and the loop
            // re-samples from the top.
            let charge_changed = async {
                loop {
                    Timer::after(CHARGE_POLL_INTERVAL).await;
                    if usb_power_present() != usb || charge_status_n.is_low() != charging {
                        return;
                    }
                }
            };
            match embassy_futures::select::select3(
                Timer::after(interval),
                BATTERY_SAMPLE_REQUEST.wait(),
                charge_changed,
            )
            .await
            {
                embassy_futures::select::Either3::First(()) => {}
                // An on-demand request: sample immediately from the top.
                embassy_futures::select::Either3::Second(()) => reply_pending = true,
                // External power or charge state moved: re-sample now so
                // the change is published promptly.
                embassy_futures::select::Either3::Third(()) => {}
            }
        }
    }
}
