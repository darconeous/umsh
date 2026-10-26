//! T-Deck wiring: the peripheral rail, the shared buses, the panel, and
//! the way down. Every part on the rail—the radio, the keyboard, the
//! trackball, the backlight, the I²C pull-ups—comes up with GPIO10 and
//! goes down with it.
use super::*;
use esp_hal::peripherals;

static I2C_BUS: StaticCell<board::I2cBus> = StaticCell::new();
static SPI_BUS: StaticCell<board::SpiBus> = StaticCell::new();

/// Raises the peripheral rail, first of all: nothing on it answers until
/// it is up. The pin is driven high for the life of the board; shutdown
/// takes it back.
pub fn rail_up(enable: peripherals::GPIO10<'static>) {
    core::mem::forget(Output::new(enable, Level::High, OutputConfig::default()));
    // The rail's inrush can sag the supply; let it settle before anything
    // else draws from it. Async timers are not running yet.
    esp_hal::delay::Delay::new().delay_millis(100);
}

/// The I²C bus: the keyboard's controller, the touch panel, and the
/// microphone's ADC. The keyboard's side runs at 100 kHz.
pub fn i2c_bus(
    i2c: peripherals::I2C0<'static>,
    sda: peripherals::GPIO18<'static>,
    scl: peripherals::GPIO8<'static>,
) -> &'static board::I2cBus {
    I2C_BUS.init(Mutex::new(
        I2c::new(
            i2c,
            I2cConfig::default().with_frequency(Rate::from_khz(100)),
        )
        .unwrap()
        .with_sda(sda)
        .with_scl(scl)
        .into_async(),
    ))
}

pub fn spi_bus(
    spi: peripherals::SPI2<'static>,
    dma: peripherals::DMA_CH0<'static>,
    sck: peripherals::GPIO40<'static>,
    mosi: peripherals::GPIO41<'static>,
    miso: peripherals::GPIO38<'static>,
) -> &'static board::SpiBus {
    // DMA sends a complete stripe without one CPU interrupt per 64-byte FIFO.
    let rx = esp_hal::dma_rx_buffer!(256).unwrap();
    let tx = esp_hal::dma_tx_buffer!(256).unwrap();
    // The panel is readable, so MISO is driven by more than the radio; a
    // pull-up keeps it defined between them.
    let miso = Input::new(miso, InputConfig::default().with_pull(Pull::Up));
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

#[repr(C, align(4))]
struct Stripe([u8; board::display::STRIPE_BYTES]);
static STRIPE: StaticCell<Stripe> = StaticCell::new();

pub fn display(
    bus: &'static board::SpiBus,
    cs: Output<'static>,
    dc: peripherals::GPIO11<'static>,
    lights: board::display::BootBacklights,
) -> board::display::Display {
    // The write clock every T-Deck source runs the ST7789 at.
    let spi = board::SpiHandle::new(
        bus,
        cs,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(40))
            .with_mode(Mode::_0),
    );
    board::display::Display::new(
        spi,
        Output::new(dc, Level::High, OutputConfig::default()),
        lights,
        external::display_frame(),
        &mut STRIPE
            .init_with(|| Stripe([0; board::display::STRIPE_BYTES]))
            .0,
    )
}

#[path = "tdeck_input.rs"]
pub mod input;

#[path = "tdeck_sound.rs"]
pub mod sound;

/// The RWDT feed, and the shutdown sequence: the farewell, the capture
/// tasks stopped, the radio asleep, the rail down, and deep sleep until
/// the trackball is pressed. The slide switch is the only hard off.
#[embassy_executor::task]
pub async fn heartbeat_task(mut rtc: Rtc<'static>, mut sleep: esp_rtos::sleep::DeepSleep) -> ! {
    let cause = loop {
        rtc.rwdt.feed();
        if let Ok(cause) = with_timeout(Duration::from_secs(2), SHUTDOWN_REQUEST.wait()).await {
            break cause;
        }
    };
    debug_log(format_args!("shutdown: {cause:?}"));
    ui::begin_farewell(cause);
    sound::shutdown().await;
    crate::input_gate::shutdown().await;
    DEVICE_CTL.shutdown();
    ui::end_farewell().await;
    settle_saved_state().await;
    // The press is reborrowed only for the terminal shutdown path; never
    // driven. Arming the wake under a held press would wake at once.
    let press = Input::new(
        unsafe { peripherals::GPIO0::steal() },
        InputConfig::default().with_pull(Pull::Up),
    );
    while press.is_low() {
        rtc.rwdt.feed();
        Timer::after_millis(50).await;
    }
    Timer::after_millis(50).await;
    rtc.rwdt.feed();
    // Do not race a radio SPI transfer when cutting its supply. A wedged
    // runner leaves the watchdog armed so the device can recover by resetting.
    DEVICE_CTL.wait_shutdown().await;
    // Terminal ownership transfer: no further await lets the peripheral
    // tasks run after the rail is cut. Every pin into a part on the rail
    // floats, so nothing back-powers it through a bus or a pull-up.
    unsafe {
        for pin in [
            peripherals::GPIO40::steal().into(),
            peripherals::GPIO41::steal().into(),
            peripherals::GPIO38::steal().into(),
            peripherals::GPIO9::steal().into(),
            peripherals::GPIO17::steal().into(),
            peripherals::GPIO13::steal().into(),
            peripherals::GPIO45::steal().into(),
            peripherals::GPIO39::steal().into(),
            peripherals::GPIO18::steal().into(),
            peripherals::GPIO8::steal().into(),
            peripherals::GPIO3::steal().into(),
            peripherals::GPIO2::steal().into(),
            peripherals::GPIO15::steal().into(),
            peripherals::GPIO1::steal().into(),
            // The speaker amplifier's I2S lines.
            peripherals::GPIO7::steal().into(),
            peripherals::GPIO5::steal().into(),
            peripherals::GPIO6::steal().into(),
        ] {
            let pin: esp_hal::gpio::AnyPin<'static> = pin;
            core::mem::forget(Input::new(pin, InputConfig::default()));
        }
        core::mem::forget(Output::new(
            peripherals::GPIO42::steal(),
            Level::Low,
            OutputConfig::default(),
        ));
        // The rail's own pull-down holds it off through deep sleep.
        core::mem::forget(Output::new(
            peripherals::GPIO10::steal(),
            Level::Low,
            OutputConfig::default(),
        ));
    }
    rtc.rwdt.disable();
    // The press has its own pull-up, off the rail, and is an RTC GPIO.
    let mut press = Input::new(
        unsafe { peripherals::GPIO0::steal() },
        InputConfig::default().with_pull(Pull::Up),
    );
    press
        .apply_wakeup_config(&esp_hal::gpio::WakeupConfig::default().with_low_power_path(true))
        .expect("GPIO0 supports low-power wake");
    press.listen(Event::LowLevel);
    sleep.deep_sleep();
}
