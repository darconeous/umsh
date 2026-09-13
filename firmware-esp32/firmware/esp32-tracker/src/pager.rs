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

static I2C_BUS: StaticCell<board::I2cBus> = StaticCell::new();
static EXPANDER: StaticCell<board::SharedExpander> = StaticCell::new();
static SPI_BUS: StaticCell<board::SpiBus> = StaticCell::new();
#[repr(C, align(4))]
struct Stripe([u8; umsh_pager_peripherals::display::STRIPE_BYTES]);
static STRIPE: StaticCell<Stripe> = StaticCell::new();

pub async fn power_up(
    i2c: peripherals::I2C0<'static>,
    sda: peripherals::GPIO3<'static>,
    scl: peripherals::GPIO2<'static>,
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
        .init()
        .await
        .expect("Pager charger profile initialization");
    if let Ok(reading) = battery.read().await {
        VBUS_PRESENT.store(reading.vbus, Ordering::Release);
    }
    println!("pager: I2C power domains and charger configured");
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

struct Encoder {
    a: Input<'static>,
    b: Input<'static>,
    decoder: Quadrature,
}
static ENCODER: critical_section::Mutex<RefCell<Option<Encoder>>> =
    critical_section::Mutex::new(RefCell::new(None));
#[derive(Clone, Copy)]
struct Navigation {
    input: UiInput,
    splash: bool,
    faded: bool,
}
static NAVIGATION: Channel<CriticalSectionRawMutex, Navigation, 64> = Channel::new();
static INPUT_OVERFLOW: AtomicBool = AtomicBool::new(false);

#[inline(always)]
fn capture(input: UiInput) {
    let event = Navigation {
        input,
        splash: BOOT_SPLASH_ACTIVE.load(Ordering::Acquire),
        faded: SCREEN_FADED.load(Ordering::Acquire),
    };
    if NAVIGATION.try_send(event).is_err() {
        INPUT_OVERFLOW.store(true, Ordering::Release);
    }
}

pub fn init_encoder(
    io: peripherals::IO_MUX<'static>,
    a: peripherals::GPIO40<'static>,
    b: peripherals::GPIO41<'static>,
) {
    let mut io = Io::new(io);
    io.set_interrupt_handler(encoder_interrupt);
    let config = InputConfig::default().with_pull(Pull::Up);
    let mut a = Input::new(a, config);
    let mut b = Input::new(b, config);
    critical_section::with(|cs| {
        let decoder = Quadrature::new((u8::from(a.is_high()) << 1) | u8::from(b.is_high()));
        a.clear_interrupt();
        b.clear_interrupt();
        a.listen(Event::AnyEdge);
        b.listen(Event::AnyEdge);
        ENCODER
            .borrow_ref_mut(cs)
            .replace(Encoder { a, b, decoder });
    });
}

#[esp_hal::handler]
#[ram]
fn encoder_interrupt() {
    critical_section::with(|cs| {
        let mut encoder = ENCODER.borrow_ref_mut(cs);
        let Some(e) = encoder.as_mut() else {
            return;
        };
        if !(e.a.is_interrupt_set() || e.b.is_interrupt_set()) {
            return;
        }
        e.a.clear_interrupt();
        e.b.clear_interrupt();
        let ab = (u8::from(e.a.is_high()) << 1) | u8::from(e.b.is_high());
        match e.decoder.transition(ab) {
            // Pager's physical forward rotation follows the negative A/B cycle.
            1 => capture(UiInput::Backward),
            -1 => capture(UiInput::Forward),
            _ => {}
        }
    });
}

/// Button debounce samples do not decode the encoder. All A/B transitions are
/// consumed in the ISR, including while this task awaits an I2C transaction.
#[embassy_executor::task]
pub async fn input_task(
    press: peripherals::GPIO7<'static>,
    boot: peripherals::GPIO0<'static>,
    irq: peripherals::GPIO6<'static>,
    bus: &'static board::I2cBus,
) {
    let config = InputConfig::default().with_pull(Pull::Up);
    let press = Input::new(press, config);
    let boot = Input::new(boot, config);
    let irq = Input::new(irq, config);
    let mut button = Debounce::new(press.is_low());
    let mut power = Debounce::new(boot.is_low());
    let mut power_since = None;
    let mut keyboard = Keyboard::new(I2cDevice::new(bus));
    let mut keyboard_ok = keyboard.init().await.is_ok();
    let mut retry_at = Instant::now() + Duration::from_secs(1);
    let mut press_gate = (false, false);
    let mut was_pressed = press.is_low();
    loop {
        let now = Instant::now();
        let raw_press = press.is_low();
        if raw_press && !was_pressed {
            press_gate = (
                BOOT_SPLASH_ACTIVE.load(Ordering::Acquire),
                SCREEN_FADED.load(Ordering::Acquire),
            );
            UI_WAKE.signal(());
        }
        was_pressed = raw_press;
        if button.sample(raw_press, now.as_millis()) == Some(true) {
            let event = Navigation {
                input: UiInput::Select,
                splash: press_gate.0,
                faded: press_gate.1,
            };
            if NAVIGATION.try_send(event).is_err() {
                INPUT_OVERFLOW.store(true, Ordering::Release);
            }
        }
        match power.sample(boot.is_low(), now.as_millis()) {
            Some(true) => power_since = Some(now),
            Some(false) => power_since = None,
            _ => {}
        }
        if power_since.is_some_and(|at| now.duration_since(at) >= Duration::from_secs(4)) {
            power_since = None;
            SHUTDOWN_REQUEST.signal(());
        }
        if !keyboard_ok && now >= retry_at {
            keyboard_ok = keyboard.init().await.is_ok();
            retry_at = now + Duration::from_secs(1);
            if !keyboard_ok {
                debug_log(format_args!("pager: keyboard unavailable"));
            }
        }
        if keyboard_ok && irq.is_low() {
            // Bounded drain keeps an IRQ storm from starving push-button handling.
            for _ in 0..16 {
                match keyboard.next().await {
                    Ok(Some(KeyEvent::BackPress)) => capture(UiInput::Back),
                    Ok(Some(KeyEvent::Overflow)) => {
                        INPUT_OVERFLOW.store(true, Ordering::Release);
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        keyboard_ok = false;
                        retry_at = now + Duration::from_secs(1);
                        break;
                    }
                }
            }
        }
        if INPUT_OVERFLOW.swap(false, Ordering::AcqRel) {
            NAVIGATION.clear();
            UI_INPUT_CH.clear();
            debug_log(format_args!(
                "pager: input queue overflow; pending navigation discarded"
            ));
        }
        while !UI_INPUT_CH.is_full() {
            let Ok(event) = NAVIGATION.try_receive() else {
                break;
            };
            UI_WAKE.signal(());
            if event.splash {
                UI_SPLASH_DISMISS.signal(());
            } else if !event.faded {
                let _ = UI_INPUT_CH.try_send(event.input);
            }
        }
        Timer::after_millis(2).await;
    }
}

#[embassy_executor::task]
pub async fn battery_task(bus: &'static board::I2cBus) {
    let mut battery = Battery::new(I2cDevice::new(bus));
    let announce = BATTERY_ANNOUNCE.sender();
    let mut previous = None;
    let mut low = LowBattery::default();
    let mut next_tick = Instant::now();
    loop {
        let requested = matches!(
            select(Timer::at(next_tick), BATTERY_REQUEST.wait()).await,
            Either::Second(())
        );
        let periodic = Instant::now() >= next_tick;
        if periodic {
            next_tick = Instant::now() + Duration::from_secs(1);
        }
        match battery.read().await {
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
    DEVICE_CTL.shutdown();
    DISPLAY_SHUTDOWN_DONE.reset();
    DISPLAY_SHUTDOWN.signal(());
    let _ = with_timeout(Duration::from_secs(2), DISPLAY_SHUTDOWN_DONE.wait()).await;
    // Journal writes are synchronous on this executor; no flash operation can
    // be suspended halfway here. MAC counters are persisted before transmission.
    critical_section::with(|cs| {
        if let Some(e) = ENCODER.borrow_ref_mut(cs).as_mut() {
            e.a.unlisten();
            e.b.unlisten();
        }
    });
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
    let _ = Battery::new(I2cDevice::new(bus)).sleep().await;
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
