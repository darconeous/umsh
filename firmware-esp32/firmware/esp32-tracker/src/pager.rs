//! Pager wiring and input capture. Only encoder ISR code reads A/B during use.
use super::*;
use core::cell::RefCell;
use esp_hal::gpio::Io;
use esp_hal::peripherals;
use esp_hal::ram;
use umsh_pager_peripherals::{
    input::{Debounce, KeyEvent, Keyboard, Quadrature},
    power::{Battery, Expander, LowBattery},
};
use umsh_ulcp::battery_diagnostics::{
    Fields as BatteryFieldsRequested, Sample as BatterySample, Value as BatteryValue,
};
use umsh_ulcp::i2c::{BusInfo, DeviceInfo, ScanRequest, TransferRequest};
use umsh_ulcp_runtime::i2c::{self as bus_access, Reservation};

#[cfg(feature = "motion-qualification")]
#[path = "pager_motion_qualification.rs"]
pub mod motion_qualification;

#[cfg(not(feature = "motion-qualification"))]
#[path = "pager_motion.rs"]
pub mod motion;

static I2C_BUS: StaticCell<board::I2cBus> = StaticCell::new();
static EXPANDER: StaticCell<board::SharedExpander> = StaticCell::new();
static SPI_BUS: StaticCell<board::SpiBus> = StaticCell::new();
static GROUP_REQUEST: Signal<CriticalSectionRawMutex, (u32, BatteryFieldsRequested)> =
    Signal::new();
static GROUP_REPLY: Signal<CriticalSectionRawMutex, (u32, BatterySample)> = Signal::new();
static GROUP_LOCK: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());
static GROUP_GENERATION: AtomicU32 = AtomicU32::new(0);
static GAUGE_REPORT: critical_section::Mutex<RefCell<Option<heapless::String<192>>>> =
    critical_section::Mutex::new(RefCell::new(None));

// ─── Raw bus access for the host ─────────────────────────────────────────

/// The clock `power_up` configures the bus for.
const BUS_SPEED_KHZ: u16 = 400;

/// The bus a host may drive through `CMD_I2C_TRANSFER`: the one every
/// peripheral on this board hangs off. The limits are the session's
/// ceilings; esp-hal chunks long operations through its FIFO itself.
pub const I2C_BUSES: &[BusInfo<'static>] = &[BusInfo {
    bus: 0,
    speed_khz: BUS_SPEED_KHZ,
    max_data: umsh_ulcp_device::I2C_DATA_MAX as u16,
    max_ops: umsh_ulcp_device::I2C_MAX_OPS as u8,
    name: "I2C0 SDA GPIO3 SCL GPIO2",
}];

/// What is on the bus, so a host can annotate a scan and think twice
/// before writing to the charger. The audio codec and the haptic driver
/// are here because they answer a scan, not because anything in this
/// firmware drives them.
pub const I2C_DEVICES: &[DeviceInfo<'static>] = &[
    DeviceInfo {
        bus: 0,
        addr: 0x18,
        name: "ES8311 audio codec",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x20,
        name: "XL9555 I/O expander (power domains)",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x28,
        name: "BHI260AP motion sensor",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x34,
        name: "TCA8418 keyboard controller",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x51,
        name: "PCF85063 real-time clock",
    },
    DeviceInfo {
        bus: 0,
        addr: GAUGE_ADDRESS,
        name: "BQ27220 battery gauge",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x5A,
        name: "DRV2605 haptic driver",
    },
    DeviceInfo {
        bus: 0,
        addr: 0x6B,
        name: "BQ25896 charger",
    },
];

const GAUGE_ADDRESS: u8 = 0x55;

/// How long a host transfer waits for the bus before answering
/// `STATUS_BUSY`. The battery, keyboard, motion, and RTC tasks hold it
/// for one transaction at a time, so a wait this long means something
/// is wrong rather than merely busy.
const BUS_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// The gauge, while one of its multi-transaction procedures runs. The
/// bus mutex is released between the procedure's transactions, and a
/// host transfer landing in that gap would run inside an unsealed
/// gauge; the guarded transfer refuses the address instead.
static GAUGE_PROCEDURE: Reservation = Reservation::new();

/// `DeviceEnv::i2c_transfer` for this board: the shared bus under a
/// bounded wait, the gauge reservation, and a deadline scaled to the
/// transfer. Dropping esp-hal's transaction future on the deadline
/// resets the controller, which is what makes the deadline safe.
pub async fn host_transfer(
    bus: &'static board::I2cBus,
    request: TransferRequest<'_>,
    out: &mut [u8],
) -> Result<usize, Status> {
    if request.bus != I2C_BUSES[0].bus {
        return Err(Status::ITEM_NOT_FOUND);
    }
    let deadline = bus_access::transfer_deadline(request.shape(), BUS_SPEED_KHZ);
    bus_access::guarded_transfer(
        bus,
        &GAUGE_PROCEDURE,
        BUS_LOCK_TIMEOUT,
        deadline,
        request,
        out,
    )
    .await
}

/// `DeviceEnv::i2c_scan` for this board.
pub async fn host_scan(
    bus: &'static board::I2cBus,
    request: ScanRequest,
    out: &mut [u8],
) -> Result<usize, Status> {
    if request.bus != I2C_BUSES[0].bus {
        return Err(Status::ITEM_NOT_FOUND);
    }
    let deadline = bus_access::scan_deadline(&request, BUS_SPEED_KHZ);
    bus_access::guarded_scan(
        bus,
        &GAUGE_PROCEDURE,
        BUS_LOCK_TIMEOUT,
        deadline,
        request,
        out,
    )
    .await
}

pub fn take_gauge_report() -> Option<heapless::String<192>> {
    critical_section::with(|cs| GAUGE_REPORT.borrow(cs).borrow_mut().take())
}

pub async fn sample_battery_group(fields: BatteryFieldsRequested) -> BatterySample {
    let _guard = GROUP_LOCK.lock().await;
    let generation = GROUP_GENERATION.fetch_add(1, Ordering::Relaxed);
    GROUP_REPLY.reset();
    GROUP_REQUEST.signal((generation, fields));
    let timeout = if fields.contains(umsh_ulcp::ids::prop::BATTERY_GAUGE_CONFIG) {
        30
    } else {
        2
    };
    // Timeout only abandons the reply; the battery owner finishes access cleanup.
    with_timeout(Duration::from_secs(timeout), async {
        loop {
            let (returned, sample) = GROUP_REPLY.wait().await;
            if returned == generation {
                return sample;
            }
        }
    })
    .await
    .unwrap_or_default()
}

fn screen_battery(sample: &BatterySample) -> Option<screen::BatteryDiagnostics> {
    use umsh_ulcp::{battery_diagnostics::VoltageRequest, ids::prop};
    let unsigned = |key| match sample.get(key).ok()?? {
        BatteryValue::Unsigned(v) => u16::try_from(v).ok(),
        _ => None,
    };
    Some(screen::BatteryDiagnostics {
        current_ma: match sample.get(prop::BATTERY_CURRENT).ok()?? {
            BatteryValue::Current(v) => i16::try_from(v).ok()?,
            _ => return None,
        },
        remaining_mah: unsigned(prop::BATTERY_REMAINING_CAPACITY)?,
        full_mah: unsigned(prop::BATTERY_FULL_CAPACITY)?,
        design_mah: unsigned(prop::BATTERY_DESIGN_CAPACITY)?,
        charging_mv: match sample.get(prop::BATTERY_CHARGE_VOLTAGE_REQUEST).ok()?? {
            BatteryValue::Voltage(VoltageRequest::Maximum) => u16::MAX,
            BatteryValue::Voltage(VoltageRequest::Millivolts(v)) => u16::try_from(v).ok()?,
            _ => return None,
        },
        status: unsigned(prop::BATTERY_GAUGE_STATUS)?,
        operation: unsigned(prop::BATTERY_GAUGE_OPERATION_STATUS)?,
        usb: match sample.get(prop::BATTERY_EXT_POWER_PRESENT).ok()?? {
            BatteryValue::Bool(v) => v,
            _ => return None,
        },
    })
}
pub static BATTERY_DETAILS_ACTIVE: AtomicBool = AtomicBool::new(false);
static BATTERY_DETAILS: critical_section::Mutex<RefCell<Option<screen::BatteryDiagnostics>>> =
    critical_section::Mutex::new(RefCell::new(None));

pub fn battery_diagnostics() -> Option<screen::BatteryDiagnostics> {
    critical_section::with(|cs| *BATTERY_DETAILS.borrow(cs).borrow())
}
#[repr(C, align(4))]
struct Stripe([u8; umsh_pager_peripherals::display::STRIPE_BYTES]);
static STRIPE: StaticCell<Stripe> = StaticCell::new();

pub async fn power_up(
    i2c: peripherals::I2C0<'static>,
    sda: peripherals::GPIO3<'static>,
    scl: peripherals::GPIO2<'static>,
    rtc: &mut Rtc<'static>,
) -> (&'static board::I2cBus, &'static board::SharedExpander) {
    let bus = I2C_BUS.init(Mutex::new(
        I2c::new(
            i2c,
            I2cConfig::default().with_frequency(Rate::from_khz(400)),
        )
        .unwrap()
        .with_sda(sda)
        .with_scl(scl)
        .into_async(),
    ));
    let mut expander = Expander::new(I2cDevice::new(bus));
    println!("pager: configuring XL9555 power domains");
    expander
        .init(&mut Delay)
        .await
        .expect("Pager XL9555 power initialization");
    let mut battery = Battery::new(I2cDevice::new(bus));
    println!("pager: configuring battery telemetry");
    battery
        .start_telemetry()
        .await
        .expect("Pager battery telemetry initialization");
    struct GaugeDelay<'a>(&'a mut Rtc<'static>);
    impl embedded_hal_async::delay::DelayNs for GaugeDelay<'_> {
        async fn delay_ns(&mut self, ns: u32) {
            self.0.rwdt.feed();
            Timer::after(Duration::from_nanos(u64::from(ns))).await;
        }
    }
    // Read the actual provisioned gauge profile; never enter CFGUPDATE or
    // overwrite capacity/taper/learning parameters. Restore access before proceeding.
    let config = {
        let _held = GAUGE_PROCEDURE.hold(GAUGE_ADDRESS);
        battery.inspect_configuration(&mut GaugeDelay(rtc)).await
    };
    let mut report = heapless::String::new();
    match config {
        Ok(config) => {
            let taper = config.taper_current_ma();
            match battery.limit_termination(taper).await {
                Ok(limit) => {
                    let _ = write!(
                        report,
                        "pager termination: taper={taper} mA cutoff={}->{} mA watchdog_disabled={}\r\n",
                        limit.before_ma, limit.after_ma, limit.watchdog_disabled
                    );
                }
                Err(error) => {
                    let _ = write!(
                        report,
                        "pager termination: FAILED taper={taper} mA {error:?}\r\n"
                    );
                }
            }
        }
        Err(error) => {
            let _ = write!(report, "pager termination: FAILED gauge read {error:?}\r\n");
        }
    }
    println!("{}", report.trim_end());
    critical_section::with(|cs| *GAUGE_REPORT.borrow(cs).borrow_mut() = Some(report));
    if let Ok(gauge) = battery.diagnostics().await {
        println!("pager: gauge readings: {gauge:?}");
    }
    if let Ok(reading) = battery.read().await {
        VBUS_PRESENT.store(reading.vbus, Ordering::Release);
    }
    println!("pager: I2C power domains and battery telemetry ready");
    (bus, EXPANDER.init(Mutex::new(expander)))
}

pub fn spi_bus(
    spi: peripherals::SPI2<'static>,
    dma: peripherals::DMA_CH0<'static>,
    sck: peripherals::GPIO35<'static>,
    mosi: peripherals::GPIO34<'static>,
    miso: peripherals::GPIO33<'static>,
) -> &'static board::SpiBus {
    // DMA sends a complete stripe without one CPU interrupt per 64-byte FIFO.
    // Copy buffers and descriptors are internal; framebuffer history is PSRAM.
    let rx = esp_hal::dma_rx_buffer!(256).unwrap();
    // Pixel stripes transfer directly from the aligned internal scratch space.
    // Only flash/PSRAM command or radio slices need the copy buffer.
    let tx = esp_hal::dma_tx_buffer!(256).unwrap();
    SPI_BUS.init(Mutex::new(
        Spi::new(
            spi,
            SpiConfig::default()
                .with_frequency(Rate::from_mhz(16))
                .with_mode(Mode::_0),
        )
        .unwrap()
        .with_sck(sck)
        .with_mosi(mosi)
        .with_miso(miso)
        .with_dma(dma)
        .with_buffers(rx, tx)
        .into_async(),
    ))
}
pub fn display(
    bus: &'static board::SpiBus,
    cs: Output<'static>,
    dc: peripherals::GPIO37<'static>,
    bl: peripherals::GPIO42<'static>,
    kb: peripherals::GPIO46<'static>,
) -> Display {
    let spi = board::SpiHandle::new(
        bus,
        cs,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(40))
            .with_mode(Mode::_0),
    );
    Display::new(
        spi,
        Output::new(dc, Level::High, OutputConfig::default()),
        Output::new(bl, Level::Low, OutputConfig::default()),
        Output::new(kb, Level::Low, OutputConfig::default()),
        external::display_frame(),
        external::display_frame(),
        &mut STRIPE
            .init_with(|| Stripe([0; umsh_pager_peripherals::display::STRIPE_BYTES]))
            .0,
    )
}

#[path = "pager_input.rs"]
pub mod input;

#[embassy_executor::task]
pub async fn battery_task(bus: &'static board::I2cBus) {
    let mut battery = Battery::new(I2cDevice::new(bus));
    let announce = BATTERY_ANNOUNCE.sender();
    let mut previous = None;
    let mut low = LowBattery::default();
    let mut next_tick = Instant::now();
    let mut next_acquisition = Instant::now();
    loop {
        let event = select3(
            Timer::at(next_tick),
            BATTERY_REQUEST.wait(),
            GROUP_REQUEST.wait(),
        )
        .await;
        let requested = matches!(event, Either3::Second(()));
        let group = match event {
            Either3::Third(request) => Some(request),
            _ => None,
        };
        let periodic = Instant::now() >= next_tick;
        if periodic {
            next_tick = Instant::now() + Duration::from_secs(1);
        }
        let fields = group
            .map(|(_, fields)| fields)
            .unwrap_or(
                BatteryFieldsRequested::SNAPSHOT.union(BatteryFieldsRequested::for_key(
                    umsh_ulcp::ids::prop::BATTERY_EXT_POWER_PRESENT,
                )),
            )
            .union(if periodic {
                BatteryFieldsRequested::ALL
            } else {
                BatteryFieldsRequested::NONE
            });
        struct SampleDelay;
        impl embedded_hal_async::delay::DelayNs for SampleDelay {
            async fn delay_ns(&mut self, ns: u32) {
                Timer::after(Duration::from_nanos(ns.into())).await;
            }
        }
        // TI limits complete standard-command polling to twice per second.
        // Host requests and the periodic UI/safety pass share this limit.
        Timer::at(next_acquisition).await;
        next_acquisition = Instant::now() + Duration::from_millis(500);
        let input_locks = input::locks_active();
        let mut sample = battery.sample(fields, &mut SampleDelay).await;
        if fields.contains(umsh_ulcp::ids::prop::BATTERY_GAUGE_CONFIG) {
            let inspected = {
                let _held = GAUGE_PROCEDURE.hold(GAUGE_ADDRESS);
                battery.inspect_configuration(&mut SampleDelay).await
            };
            sample.gauge_config = inspected.map_err(|error| {
                let mut report = heapless::String::new();
                let _ = write!(report, "pager gauge-config: {error:?}\r\n");
                critical_section::with(|cs| *GAUGE_REPORT.borrow(cs).borrow_mut() = Some(report));
                umsh_ulcp::Status::FAILURE
            });
        }
        if periodic {
            input::power_sample(
                match sample.get(umsh_ulcp::ids::prop::BATTERY_CURRENT) {
                    Ok(Some(BatteryValue::Current(v))) => Some(v),
                    _ => None,
                },
                !matches!(
                    sample.get(umsh_ulcp::ids::prop::BATTERY_EXT_POWER_PRESENT),
                    Ok(Some(BatteryValue::Bool(false)))
                ),
                input_locks,
            );
        }
        if let Some((generation, _)) = group {
            GROUP_REPLY.signal((generation, sample));
            // Host diagnostics do not wake the screen or advance its cadence.
            if !periodic {
                continue;
            }
        }
        let reading = sample.snapshot.map(|snapshot| board_battery::Reading {
            voltage_mv: snapshot.voltage_mv,
            percent: snapshot.level_percent,
            charge: snapshot.charge_state.map(|state| match state {
                umsh_ulcp::battery::BatteryChargeState::Charging => board_battery::Charge::Charging,
                umsh_ulcp::battery::BatteryChargeState::Discharging => {
                    board_battery::Charge::Discharging
                }
                umsh_ulcp::battery::BatteryChargeState::Charged => board_battery::Charge::Charged,
            }),
            vbus: matches!(
                sample.get(umsh_ulcp::ids::prop::BATTERY_EXT_POWER_PRESENT),
                Ok(Some(BatteryValue::Bool(true)))
            ),
        });
        if periodic {
            let details = screen_battery(&sample);
            critical_section::with(|cs| *BATTERY_DETAILS.borrow(cs).borrow_mut() = details);
        }
        match reading {
            Ok(reading) => {
                BATTERY_MV.store(reading.voltage_mv.unwrap_or(0), Ordering::Release);
                BATTERY_LEVEL.store(reading.percent.unwrap_or(0xff), Ordering::Release);
                BATTERY_CHARGE.store(
                    match reading.charge {
                        None => 0,
                        Some(board_battery::Charge::Discharging) => 1,
                        Some(board_battery::Charge::Charging) => 2,
                        Some(board_battery::Charge::Charged) => 3,
                    },
                    Ordering::Release,
                );
                if VBUS_PRESENT.swap(reading.vbus, Ordering::AcqRel) != reading.vbus {
                    VBUS_EDGE.signal(());
                }
                if requested {
                    BATTERY_REPLY.signal(reading);
                }
                let state = (reading.percent, reading.charge, reading.vbus);
                if previous.is_none_or(|old: (Option<u8>, Option<board_battery::Charge>, bool)| {
                    old.1 != state.1
                        || old.2 != state.2
                        || match (old.0, state.0) {
                            (Some(a), Some(b)) => a.abs_diff(b) >= BATTERY_LEVEL_STEP,
                            (a, b) => a != b,
                        }
                }) {
                    previous = Some(state);
                    announce.send(reading);
                    BATTERY_UI_CHANGED.signal(());
                }
                if periodic && low.sample(Some(&reading)) {
                    SHUTDOWN_REQUEST.signal(());
                }
            }
            Err(_) => {
                if periodic {
                    low.sample(None);
                }
                BATTERY_MV.store(0, Ordering::Release);
                BATTERY_LEVEL.store(0xff, Ordering::Release);
                BATTERY_CHARGE.store(0, Ordering::Release);
                BATTERY_UI_CHANGED.signal(());
                let unknown = board_battery::Reading {
                    voltage_mv: None,
                    percent: None,
                    charge: None,
                    vbus: VBUS_PRESENT.load(Ordering::Acquire),
                };
                if requested {
                    BATTERY_REPLY.signal(unknown);
                }
                if previous.take().is_some() {
                    announce.send(unknown);
                    debug_log(format_args!("pager: battery telemetry unavailable"));
                }
            }
        }
        // Refresh diagnostics without waking the display or extending attention.
        // Ordinary pages retain their existing announcement cadence.
        if periodic && BATTERY_DETAILS_ACTIVE.load(Ordering::Acquire) {
            BATTERY_UI_CHANGED.signal(());
        }
    }
}

#[embassy_executor::task]
pub async fn heartbeat_task(
    mut rtc: Rtc<'static>,
    mut sleep: esp_rtos::sleep::DeepSleep,
    expander: &'static board::SharedExpander,
    bus: &'static board::I2cBus,
) -> ! {
    loop {
        rtc.rwdt.feed();
        if with_timeout(Duration::from_secs(2), SHUTDOWN_REQUEST.wait())
            .await
            .is_ok()
        {
            break;
        }
    }
    input::shutdown().await;
    #[cfg(not(feature = "motion-qualification"))]
    {
        rtc.rwdt.feed();
        motion::SERVICE.shutdown();
        let _ = with_timeout(Duration::from_secs(7), motion::SERVICE.stopped.wait()).await;
        rtc.rwdt.feed();
    }
    DEVICE_CTL.shutdown();
    DISPLAY_SHUTDOWN_DONE.reset();
    DISPLAY_SHUTDOWN.signal(());
    let _ = with_timeout(Duration::from_secs(2), DISPLAY_SHUTDOWN_DONE.wait()).await;
    // Journal writes are synchronous on this executor; no flash operation can
    // be suspended halfway here. MAC counters are persisted before transmission.
    // Inputs are reborrowed only for the terminal shutdown path; never driven.
    let boot = Input::new(
        unsafe { peripherals::GPIO0::steal() },
        InputConfig::default().with_pull(Pull::Up),
    );
    let press = Input::new(
        unsafe { peripherals::GPIO7::steal() },
        InputConfig::default().with_pull(Pull::Up),
    );
    while boot.is_low() || press.is_low() {
        rtc.rwdt.feed();
        Timer::after_millis(50).await;
    }
    Timer::after_millis(50).await;
    rtc.rwdt.feed();
    // Do not race a radio SPI transfer when cutting its supply. A wedged
    // runner leaves the watchdog armed so the device can recover by resetting.
    DEVICE_CTL.wait_shutdown().await;
    let _ = expander.lock().await.shutdown().await;
    let mut battery = Battery::new(I2cDevice::new(bus));
    let _ = battery.sleep().await;
    // Final power command: on battery this cuts SYS, including the ESP32 and
    // its GPIO wake circuitry. QON (the dedicated power key) restores power.
    // USB can keep SYS alive, so retain the existing deep-sleep fallback below.
    for attempt in 1..=3 {
        rtc.rwdt.feed();
        if battery.power_off().await.is_ok() {
            break;
        }
        debug_log(format_args!(
            "pager: battery disconnect failed (attempt {attempt}/3)"
        ));
    }
    // Terminal ownership transfer: no further await lets the peripheral tasks
    // run after their outputs are disconnected. Avoid back-power through SPI,
    // UART, or IRQ pull-ups after the switched domains go down.
    unsafe {
        for pin in [
            peripherals::GPIO35::steal().into(),
            peripherals::GPIO34::steal().into(),
            peripherals::GPIO33::steal().into(),
            peripherals::GPIO36::steal().into(),
            peripherals::GPIO38::steal().into(),
            peripherals::GPIO37::steal().into(),
            peripherals::GPIO47::steal().into(),
            peripherals::GPIO14::steal().into(),
            peripherals::GPIO48::steal().into(),
            peripherals::GPIO4::steal().into(),
            peripherals::GPIO12::steal().into(),
            peripherals::GPIO21::steal().into(),
            peripherals::GPIO39::steal().into(),
            peripherals::GPIO6::steal().into(),
            peripherals::GPIO40::steal().into(),
            peripherals::GPIO41::steal().into(),
        ] {
            let pin: esp_hal::gpio::AnyPin<'static> = pin;
            core::mem::forget(Input::new(pin, InputConfig::default()));
        }
        core::mem::forget(Output::new(
            peripherals::GPIO42::steal(),
            Level::Low,
            OutputConfig::default(),
        ));
        core::mem::forget(Output::new(
            peripherals::GPIO46::steal(),
            Level::Low,
            OutputConfig::default(),
        ));
    }
    rtc.rwdt.disable();
    // On ESP32-S3 EXT1's low setting is ANY_LOW: either button wakes it.
    let mut boot_pin = unsafe { peripherals::GPIO0::steal() };
    let mut press_pin = unsafe { peripherals::GPIO7::steal() };
    let mut pins: [&mut dyn esp_hal::gpio::RtcPin; 2] = [&mut boot_pin, &mut press_pin];
    let wake = esp_hal::rtc_cntl::sleep::Ext1WakeupSource::new(&mut pins, Level::Low);
    sleep.deep_sleep(&[&wake]);
}
