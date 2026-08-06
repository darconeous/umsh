//! Power control glue for the T1000-E: the [`SHUTDOWN_SIGNAL`] static, a
//! [`PowerSignaler`] that bridges the CLI's `umsh_hal::PowerControl`
//! trait into board-level power events, and the [`run_battery_monitor`]
//! task that triggers a protective shutdown on low VBAT.
//!
//! The BSP owns these because the *signaling* shape is uniform — fire a
//! signal for soft-poweroff, hit `SYSRESETREQ` for reboot. The actual
//! board-specific teardown sequence lives in [`crate::shutdown::run`],
//! which awaits [`SHUTDOWN_SIGNAL`].

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use embassy_futures::select::{Either, Either4, select, select4};
use embassy_nrf::gpio::{Input, Output};
use embassy_nrf::interrupt::typelevel::{Binding, SAADC as SaadcIrq};
use embassy_nrf::saadc::{
    ChannelConfig, Config as SaadcConfig, InterruptHandler as SaadcInterruptHandler, Oversample,
    Resolution, Saadc, Time as SaadcTime,
};
use embassy_nrf::{Peri, pac, peripherals};
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;
use embassy_sync::watch::Watch;
use embassy_time::{Duration, Timer};
use umsh_ux_tracker::battery::{
    BatteryState, BatteryThresholds, ChargeClass, LevelEstimator, LevelSample, charge_class,
    classify, load_recent,
};

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

/// Whether the nRF USB regulator currently detects VBUS. On the T1000-E this
/// is the authoritative indication that the magnetic USB cable is supplying
/// external power. P0.05 is still useful as a wake/status hint, but hardware
/// validation showed that it may remain asserted after cable removal.
pub fn usb_power_present() -> bool {
    pac::POWER.usbregstatus().read().vbusdetect()
}

fn publish_battery_state(state: BatteryState) {
    let previous = BATTERY_STATE.swap(state as u8, Ordering::AcqRel);
    if previous != state as u8 {
        BATTERY_STATE_CHANGED.signal(state);
    }
}

/// One serviced battery measurement: the raw millivolt reading, the
/// five-way UX classification derived from it in the same iteration,
/// and the level estimator's current state of charge.
#[derive(Clone, Copy, Debug)]
pub struct BatterySample {
    pub battery_mv: u16,
    pub state: BatteryState,
    /// `Some` from the monitor's first sample onward.
    pub level_percent: Option<u8>,
}

/// Battery measurements the monitor considers worth announcing to a
/// remote observer, for `PROP_BATTERY` asynchronous updates.
///
/// Multi-receiver, unlike [`BATTERY_STATE_CHANGED`], and filtered on a
/// different question: that signal tracks the five-way *presentation*
/// classification for the LED, while this one fires when the reported
/// **charge class** or **level** moves — the two fields a remote observer
/// can act on. Voltage rides along on whichever sample triggered the
/// publication but never triggers one itself: it moves by a few
/// millivolts on every reading, so it would make every sample an event.
///
/// The level needs no threshold of its own: [`LevelEstimator`] already
/// quantizes to five-point steps, so "the level changed" is exactly "the
/// level moved by 5 %".
pub static BATTERY_ANNOUNCE: Watch<ThreadModeRawMutex, BatterySample, BATTERY_ANNOUNCE_RECEIVERS> =
    Watch::new();

/// Receivers of [`BATTERY_ANNOUNCE`]: the ULCP session driver. A `Watch`
/// (rather than a second `Signal`) both admits more than one and survives
/// the driver's select dropping the future on every other iteration.
pub const BATTERY_ANNOUNCE_RECEIVERS: usize = 1;

/// Millisecond timestamp of the most recent externally reported load
/// (see [`note_external_load`]); `u32::MAX` sentinel = never.
static LAST_LOAD_MS: AtomicU32 = AtomicU32::new(u32::MAX);

/// Tell the battery monitor a significant transient load just ran (a
/// radio transmission is the canonical case), so nearby voltage
/// samples are treated as sagged rather than as resting OCV by the
/// level estimator. Cheap; call per event.
pub fn note_external_load() {
    LAST_LOAD_MS.store(
        embassy_time::Instant::now().as_millis() as u32,
        Ordering::Release,
    );
}

/// Wakes the monitor to take a measurement now (see [`sample_battery`]).
static BATTERY_SAMPLE_REQUEST: Signal<ThreadModeRawMutex, ()> = Signal::new();
static BATTERY_SAMPLE_REPLY: Signal<ThreadModeRawMutex, BatterySample> = Signal::new();

/// Ask [`run_battery_monitor`] — the sole SAADC and sensor-rail owner —
/// for a fresh measurement and wait for it. The monitor services the
/// request by running its normal gated sample/classify/publish iteration
/// early, so protocol reads share the exact policy of the periodic scan.
///
/// Single-consumer, like the monitor itself. Never completes once the
/// monitor has exited for critical-battery shutdown; callers that can
/// outlive shutdown should apply their own timeout.
pub async fn sample_battery() -> BatterySample {
    BATTERY_SAMPLE_REPLY.reset();
    BATTERY_SAMPLE_REQUEST.signal(());
    BATTERY_SAMPLE_REPLY.wait().await
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

/// Monitors battery voltage via the nRF52840 SAADC (P0.02 = AIN0, 2:1 divider),
/// and serves on-demand ambient light readings from P0.29 (AIN5).
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
/// This task is the sole owner of the SAADC and of both sensor enables, so
/// the light sensor is served here rather than by a competing task. It
/// takes the peripheral and the two pins rather than a built `Saadc`, and
/// constructs a **single-channel** converter for each measurement: the
/// nRF52 SAADC's hardware oversampling is only available when one channel
/// is enabled, and it is by far the most effective noise tool on the part.
/// Enabling both at once would also put the converter in scan mode, where
/// the high-impedance light input shares a sample-and-hold with the
/// battery divider. Neither measurement is ever wanted at the same instant
/// as the other, so there is nothing to trade away.
///
/// The battery policy is unaffected: its converter is configured exactly
/// as it was before the light sensor existed, and light requests never
/// feed the level estimator, the announce filter, or the critical-battery
/// cutoff.
///
/// Generic over the interrupt binding so the BSP can build converters
/// itself; wrap in `#[embassy_executor::task]` in the firmware binary,
/// which names `Irqs` concretely, so the linker sees one monomorphisation.
// A flat list of hardware handles, one per pin the monitor owns, matching
// every other board's power task. Bundling them in a struct would move the
// same seven fields somewhere else and break that symmetry.
#[allow(clippy::too_many_arguments)]
pub async fn run_battery_monitor<I>(
    mut saadc: Peri<'static, peripherals::SAADC>,
    irq: I,
    mut battery_pin: Peri<'static, peripherals::P0_02>,
    mut light_pin: Peri<'static, peripherals::P0_29>,
    mut sensor_rail: Output<'static>,
    mut sensor_enable: Output<'static>,
    mut external_power: Input<'static>,
    mut charge_active: Input<'static>,
) where
    I: Binding<SaadcIrq, SaadcInterruptHandler> + Copy + 'static,
{
    const CONSECUTIVE_NEEDED: u8 = 10;
    /// Normal cadence. The cell discharges over days and the level
    /// estimator quantizes to 5 %, so nothing is learned by sampling the
    /// SAADC faster than this; the charge-state edges are interrupts and
    /// do not wait for it.
    const SAMPLE_INTERVAL: Duration = Duration::from_secs(300);
    /// Cadence while the cell is Low or Critical. The protective cutoff
    /// counts [`CONSECUTIVE_NEEDED`] consecutive critical samples, so its
    /// latency is a multiple of the interval in force — at the normal
    /// cadence that would be most of an hour of deep-discharge exposure.
    /// Sampling faster once the voltage is already alarming keeps the
    /// cutoff at its intended ~5 minutes without paying for it in the
    /// other 99 % of the battery's life.
    const LOW_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
    const EDGE_DEBOUNCE: Duration = Duration::from_millis(20);

    let mut low_count: u8 = 0;
    let mut reply_pending = false;
    let mut estimator = LevelEstimator::new();
    let announce = BATTERY_ANNOUNCE.sender();
    // Last announced (charge class, level); `None` until the first
    // sample, which always announces.
    let mut announced: Option<(ChargeClass, Option<u8>)> = None;

    loop {
        // Gate the sensor rail, settle, sample, then drop the rail. The
        // light-sensor enable stays low: the battery divider does not need
        // it.
        sensor_rail.set_high();
        Timer::after(Duration::from_millis(5)).await;
        let raw = {
            let mut converter = Saadc::new(
                saadc.reborrow(),
                irq,
                SaadcConfig::default(),
                [ChannelConfig::single_ended(battery_pin.reborrow())],
            );
            let mut buf = [0i16; 1];
            converter.sample(&mut buf).await;
            u32::from(buf[0].max(0) as u16)
        };
        sensor_rail.set_low();

        let battery_mv = ((raw * 7_200) / 4_096).min(u32::from(u16::MAX)) as u16;
        let state = classify(
            battery_mv,
            usb_power_present(),
            charge_active.is_low(),
            BatteryThresholds::default(),
        );
        publish_battery_state(state);

        // Feed the level estimator. A load within the sag window marks
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

        // Service an on-demand measurement request with this iteration's
        // sample. A request landing mid-iteration shares the sample that
        // was just taken rather than queueing a second rail cycle.
        if reply_pending || BATTERY_SAMPLE_REQUEST.try_take().is_some() {
            reply_pending = false;
            BATTERY_SAMPLE_REPLY.signal(sample);
        }

        // Announce the sample when the fields a remote observer acts on
        // have moved. On-demand reads go through this path too, so a
        // GET that reveals a change also rebaselines and does not leave
        // a duplicate publication queued behind it.
        let key = (charge_class(state), sample.level_percent);
        if announced != Some(key) {
            announced = Some(key);
            announce.send(sample);
        }

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

        // A cell already reading Low or Critical is watched closely; the
        // cutoff's latency depends on it.
        let interval = if matches!(
            state,
            BatteryState::BatteryLow | BatteryState::BatteryCritical
        ) {
            LOW_SAMPLE_INTERVAL
        } else {
            SAMPLE_INTERVAL
        };
        // Wait for the next battery iteration. Light requests are serviced
        // inside this wait and do not end it: they have their own enable,
        // settle and averaging, and must not pull a battery sample forward
        // — the estimator, the announce filter and the critical-battery
        // cutoff all count iterations.
        let mut deadline = Timer::after(interval);
        loop {
            match select(
                select4(
                    &mut deadline,
                    external_power.wait_for_any_edge(),
                    charge_active.wait_for_any_edge(),
                    BATTERY_SAMPLE_REQUEST.wait(),
                ),
                crate::light::LIGHT_SAMPLE_REQUEST.wait(),
            )
            .await
            {
                Either::First(Either4::First(())) => {}
                Either::First(Either4::Second(())) | Either::First(Either4::Third(())) => {
                    Timer::after(EDGE_DEBOUNCE).await
                }
                // An on-demand request: sample immediately and reply from
                // the top of the loop.
                Either::First(Either4::Fourth(())) => reply_pending = true,
                Either::Second(()) => {
                    let millilux = sample_light(
                        &mut saadc,
                        irq,
                        &mut light_pin,
                        &mut sensor_rail,
                        &mut sensor_enable,
                    )
                    .await;
                    crate::light::LIGHT_SAMPLE_REPLY.signal(millilux);
                    continue;
                }
            }
            break;
        }
    }
}

/// Points taken per reading. Two of them are discarded, so this is two
/// more than the number that end up in the average.
const LIGHT_POINTS: u32 = 25;

/// Spacing between points. Chosen with [`LIGHT_POINTS`] so the reading
/// spans exactly 50 ms — see [`sample_light`].
const LIGHT_POINT_SPACING: Duration = Duration::from_millis(2);

/// Hardware conversions accumulated and averaged by the SAADC itself for
/// each point. Available only because the light converter enables a
/// single channel; the `BURST` bit embassy sets alongside it makes one
/// `sample` call run the whole 32-conversion accumulation internally.
///
/// At the 40 µs acquisition time below this is ~1.3 ms of continuous
/// integration per point, comfortably inside [`LIGHT_POINT_SPACING`].
const LIGHT_OVERSAMPLE: Oversample = Oversample::Over32x;

/// One ambient light measurement, in millilux.
///
/// Raises both enables, settles, then takes [`LIGHT_POINTS`] points
/// spaced [`LIGHT_POINT_SPACING`] apart before dropping the enables
/// again — 800 hardware conversions in total.
///
/// Three separate things make the raw reading noisy, and each needs its
/// own treatment:
///
/// **Converter noise.** Answered in hardware by [`LIGHT_OVERSAMPLE`] and
/// by 14-bit resolution, which puts the quantization step four times
/// below the 12-bit one the vendor driver works in.
///
/// **Mains flicker.** Artificial light is not steady; it pulses at twice
/// the mains frequency, so a reading taken in under a millisecond
/// measures wherever in that cycle it happened to land and varies wildly
/// between reads. The points are therefore spread over 50 ms, which is a
/// whole number of half-cycles at both 50 Hz (5) and 60 Hz (6) — the
/// flicker integrates away for either mains, rather than aliasing. No
/// amount of oversampling inside a single point can do this; the window
/// has to be wide.
///
/// **Outliers.** The single largest and single smallest points are
/// dropped before averaging, so one disturbed point — a shadow crossing
/// the sensor, a transient on the shared rail — moves the result by
/// nothing instead of by a twenty-fifth of its excursion.
///
/// The kept points are handed to
/// [`millilux_from_sum`](crate::light::millilux_from_sum) as a sum rather
/// than a mean, so the sub-count resolution all of the above buys is not
/// rounded away in the last step.
///
/// Before any of that, the **LED is held dark** for the whole
/// measurement — see [`blank_requested`](crate::indicator::blank_requested).
/// It sits beside the sensor and its light reaches it, so a reading taken
/// while it is lit measures the indicator; because the indicator usually
/// blinks, successive readings catch different parts of the blink and
/// disagree by more than every other source here combined. That is real
/// light falling on the sensor, so no amount of filtering addresses it.
async fn sample_light<I>(
    saadc: &mut Peri<'static, peripherals::SAADC>,
    irq: I,
    light_pin: &mut Peri<'static, peripherals::P0_29>,
    sensor_rail: &mut Output<'static>,
    sensor_enable: &mut Output<'static>,
) -> u32
where
    I: Binding<SaadcIrq, SaadcInterruptHandler> + Copy + 'static,
{
    /// Settle time after raising the enables, from the vendor driver.
    const LIGHT_SETTLE: Duration = Duration::from_millis(10);
    /// How long to wait for the LED task to confirm the LED is off. A
    /// task wake and one duty write; generous by orders of magnitude.
    /// Bounded rather than open-ended because this runs inside the loop
    /// that guards the cell — a firmware with no LED task must give a
    /// polluted reading, never a stalled battery monitor.
    const LED_BLANK_TIMEOUT: Duration = Duration::from_millis(20);

    crate::indicator::request_blank();
    let _ = embassy_time::with_timeout(LED_BLANK_TIMEOUT, crate::indicator::wait_blanked()).await;

    sensor_rail.set_high();
    sensor_enable.set_high();
    Timer::after(LIGHT_SETTLE).await;

    // The light channel needs the long acquisition time: the default
    // 10 µs is rated for a source impedance around 100 kΩ and the
    // phototransistor node sits above that, so a shorter window leaves
    // the sample-and-hold short of the true voltage.
    let mut channel = ChannelConfig::single_ended(light_pin.reborrow());
    channel.time = SaadcTime::_40US;
    let mut converter = Saadc::new(
        saadc.reborrow(),
        irq,
        {
            let mut config = SaadcConfig::default();
            config.resolution = Resolution::_14bit;
            config.oversample = LIGHT_OVERSAMPLE;
            config
        },
        [channel],
    );

    let mut total: u32 = 0;
    let mut lowest = u32::MAX;
    let mut highest = 0;
    for index in 0..LIGHT_POINTS {
        if index > 0 {
            Timer::after(LIGHT_POINT_SPACING).await;
        }
        let mut buf = [0i16; 1];
        converter.sample(&mut buf).await;
        let raw = u32::from(buf[0].max(0) as u16);
        total += raw;
        lowest = lowest.min(raw);
        highest = highest.max(raw);
    }
    drop(converter);

    sensor_enable.set_low();
    sensor_rail.set_low();
    crate::indicator::release_blank();

    crate::light::millilux_from_sum(total - lowest - highest, LIGHT_POINTS - 2)
}
