//! Phase 1 bringup for the Heltec WiFi LoRa 32 V2: board I/O.
//!
//! On top of the Phase 0 floor (embassy on esp-rtos, UART0 banner, RWDT,
//! panic capture) this exercises the whole board-I/O surface:
//!
//! - `Vext` power domain as the single shared handle gating the OLED and
//!   the battery divider.
//! - SSD1306 over I²C with the full Vext-up → reset-pulse → init
//!   sequence, drawn via `embedded-graphics`.
//! - PRG button through `umsh_ux_tracker::button::ButtonFsm`; status LED
//!   through `umsh_ux_tracker::led::LedEngine` (heartbeat + one-shots).
//! - Battery sampling on GPIO13/ADC2 with
//!   `umsh_ux_tracker::battery` classification.
//!
//! Controls: single-click resamples the battery and confirms on the LED;
//! double-click plays the location-advert blink; a 3 s hold power-cycles
//! `Vext` and re-initializes the display (the Phase 1 exit-criteria
//! round-trip); quad-click panics, exercising the Phase 0
//! capture → reset → report-on-next-boot path.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rtc_cntl::{Rtc, RwdtStage};
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use umsh_bsp_heltec_lora32_v2::battery::BatterySampler;
use umsh_bsp_heltec_lora32_v2::display::{self, Display, DisplayConfigAsync as _};
use umsh_bsp_heltec_lora32_v2::vext::Vext;
use umsh_ux_tracker::battery::{BatteryState, BatteryThresholds, classify, soc_from_ocv};
use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm, ButtonTimings};
use umsh_ux_tracker::led::{LedEngine, LedSequence, LedTimings};

esp_bootloader_esp_idf::esp_app_desc!();

const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);
/// Periodic battery resample + redraw cadence.
const REFRESH_PERIOD: Duration = Duration::from_secs(30);
/// How long Vext stays off during the long-press round-trip test.
const VEXT_OFF_DWELL: Duration = Duration::from_secs(2);

static BUTTON_EVENTS: Channel<CriticalSectionRawMutex, ButtonEvent, 4> = Channel::new();
static LED_PLAY: Signal<CriticalSectionRawMutex, LedSequence> = Signal::new();

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    let mut rtc = Rtc::new(peripherals.RTC_TIMER);
    rtc.rwdt.set_timeout(RwdtStage::Stage0, WDT_TIMEOUT);
    rtc.rwdt.enable();

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let software_interrupt = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, software_interrupt.software_interrupt0);

    println!(
        "{} {} on {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        umsh_bsp_heltec_lora32_v2::BOARD_NAME,
    );

    let mut panic_buf = [0u8; umsh_bsp_esp32::panic_capture::MSG_CAPACITY];
    if let Some(msg) = umsh_bsp_esp32::panic_capture::take_panic_message(&mut panic_buf) {
        println!("previous boot panicked: {msg}");
    }

    let led = Output::new(peripherals.GPIO25, Level::Low, OutputConfig::default());
    spawner.spawn(led_task(led, rtc).unwrap());

    let button = Input::new(
        peripherals.GPIO0,
        InputConfig::default().with_pull(Pull::None),
    );
    spawner.spawn(button_task(button).unwrap());

    // Battery before anything radio-shaped ever exists: ADC2 claiming
    // panics once a radio controller owns it.
    let mut battery = BatterySampler::new(peripherals.ADC2, peripherals.GPIO13);

    let mut vext = Vext::new(peripherals.GPIO21);
    let mut oled_reset = Output::new(peripherals.GPIO16, Level::High, OutputConfig::default());
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(400)),
    )
    .unwrap()
    .with_sda(peripherals.GPIO4)
    .with_scl(peripherals.GPIO15)
    .into_async();
    let mut display = display::new_display(i2c);

    vext.enable().await;
    display::reset(&mut oled_reset).await;
    match display.init().await {
        Ok(()) => println!("oled: initialized"),
        Err(e) => println!("oled: init failed: {e:?}"),
    }

    let mut ui = UiState::default();
    ui.battery_mv = battery.sample_mv(&mut vext).await;
    redraw(&mut display, &ui).await;
    println!("battery: {} mV", ui.battery_mv);

    loop {
        match select(BUTTON_EVENTS.receive(), Timer::after(REFRESH_PERIOD)).await {
            Either::First(ButtonEvent::Single) => {
                LED_PLAY.signal(LedSequence::ActionConfirm);
                ui.clicks = ui.clicks.wrapping_add(1);
                ui.battery_mv = battery.sample_mv(&mut vext).await;
                redraw(&mut display, &ui).await;
                println!("battery: {} mV", ui.battery_mv);
            }
            Either::First(ButtonEvent::Double) => {
                LED_PLAY.signal(LedSequence::LocationAdvert);
            }
            Either::First(ButtonEvent::Long) => {
                // Phase 1 exit criterion: a full Vext power cycle must
                // come back with a working display via reset + re-init.
                println!("vext: power cycling");
                vext.disable();
                Timer::after(VEXT_OFF_DWELL).await;
                vext.enable().await;
                display::reset(&mut oled_reset).await;
                match display.init().await {
                    Ok(()) => println!("vext: display re-initialized"),
                    Err(e) => println!("vext: display re-init failed: {e:?}"),
                }
                ui.vext_cycles = ui.vext_cycles.wrapping_add(1);
                ui.battery_mv = battery.sample_mv(&mut vext).await;
                redraw(&mut display, &ui).await;
            }
            Either::First(ButtonEvent::Quad) => {
                panic!("quad-click (panic-capture test hook)");
            }
            Either::First(ButtonEvent::Triple | ButtonEvent::VeryLong) => {}
            Either::Second(()) => {
                ui.battery_mv = battery.sample_mv(&mut vext).await;
                redraw(&mut display, &ui).await;
            }
        }
    }
}

#[derive(Default)]
struct UiState {
    battery_mv: u16,
    vext_cycles: u32,
    clicks: u32,
}

async fn redraw(display: &mut Display, ui: &UiState) {
    // No charger-status or VBUS-sense signal exists on this board (the
    // charge LED is charger-driven), so classification runs in
    // battery-only terms.
    let state = classify(ui.battery_mv, false, false, BatteryThresholds::default());
    let soc = soc_from_ocv(ui.battery_mv);

    display.clear_buffer();
    let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);
    let mut line: heapless::String<24> = heapless::String::new();
    let _ = write!(line, "{}", env!("CARGO_PKG_NAME"));
    draw_line(display, &line, 0, style);

    line.clear();
    let _ = write!(line, "batt {} mV  {soc}%", ui.battery_mv);
    draw_line(display, &line, 1, style);

    line.clear();
    let _ = write!(line, "state {}", state_name(state));
    draw_line(display, &line, 2, style);

    line.clear();
    let _ = write!(line, "vext cycles {}", ui.vext_cycles);
    draw_line(display, &line, 3, style);

    line.clear();
    let _ = write!(line, "clicks {}", ui.clicks);
    draw_line(display, &line, 4, style);

    if let Err(e) = display.flush().await {
        println!("oled: flush failed: {e:?}");
    }
}

fn draw_line(display: &mut Display, text: &str, row: i32, style: MonoTextStyle<'_, BinaryColor>) {
    // FONT_6X10 baseline: 10 px rows with a 2 px top margin.
    let _ = Text::new(text, Point::new(0, 10 + row * 12), style).draw(display);
}

fn state_name(state: BatteryState) -> &'static str {
    match state {
        BatteryState::BatteryOnly => "ok",
        BatteryState::BatteryLow => "low",
        BatteryState::BatteryCritical => "critical",
        BatteryState::BatteryCharging => "charging",
        BatteryState::BatteryCharged => "charged",
    }
}

/// Drives the status LED from the UX engine's heartbeat plus one-shot
/// sequences signalled by the UI task, and pets the RWDT — this task
/// starving is exactly the condition the watchdog exists to catch.
#[embassy_executor::task]
async fn led_task(mut led: Output<'static>, mut rtc: Rtc<'static>) {
    let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
    loop {
        rtc.rwdt.feed();
        let decision = engine.tick(Instant::now().as_millis());
        led.set_level(if decision.on { Level::High } else { Level::Low });
        match select(
            LED_PLAY.wait(),
            Timer::at(Instant::from_millis(decision.next_deadline_ms)),
        )
        .await
        {
            Either::First(sequence) => engine.play(sequence, Instant::now().as_millis()),
            Either::Second(()) => {}
        }
    }
}

/// Resolves the PRG button (GPIO0, active low, external pull-up) through
/// the shared gesture FSM and forwards recognized events to the UI task.
#[embassy_executor::task]
async fn button_task(mut button: Input<'static>) {
    const DEBOUNCE: Duration = Duration::from_millis(10);
    let mut fsm = ButtonFsm::new(ButtonTimings::default());
    let mut pressed = button.is_low();
    loop {
        let event = {
            let now_ms = Instant::now().as_millis();
            let edge_fut = async {
                if pressed {
                    button.wait_for_high().await;
                    Timer::after(DEBOUNCE).await;
                    ButtonEdge::Release
                } else {
                    button.wait_for_low().await;
                    Timer::after(DEBOUNCE).await;
                    ButtonEdge::Press
                }
            };
            let deadline = fsm.next_deadline().unwrap_or(now_ms.saturating_add(60_000));
            match select(edge_fut, Timer::at(Instant::from_millis(deadline))).await {
                Either::First(edge) => {
                    pressed = matches!(edge, ButtonEdge::Press);
                    fsm.on_edge(edge, Instant::now().as_millis())
                }
                Either::Second(()) => fsm.poll(Instant::now().as_millis()),
            }
        };
        if let Some(event) = event {
            println!("button: {event:?}");
            BUTTON_EVENTS.send(event).await;
        }
    }
}
