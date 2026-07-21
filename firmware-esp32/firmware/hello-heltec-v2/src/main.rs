//! Phase 0 bringup for the Heltec WiFi LoRa 32 V2.
//!
//! Embassy executor, heartbeat blink on the status LED (GPIO25), version
//! banner on UART0 (shared with the CP2102 USB bridge), and the RWDT armed
//! and petted from the heartbeat loop — same watchdog posture as the nRF
//! boards (long timeout, pet from the task that must stay alive).

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rtc_cntl::{Rtc, RwdtStage};
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;

esp_bootloader_esp_idf::esp_app_desc!();

const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);
const HEARTBEAT_PERIOD: Duration = Duration::from_millis(500);

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
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

    let mut led = Output::new(peripherals.GPIO25, Level::Low, OutputConfig::default());
    // PRG button, active low, external pull-up. Deliberate test hook: pressing
    // it panics, exercising the capture -> reset -> report-on-next-boot path.
    let button = Input::new(
        peripherals.GPIO0,
        InputConfig::default().with_pull(Pull::None),
    );
    loop {
        led.toggle();
        rtc.rwdt.feed();
        if button.is_low() {
            panic!("PRG button pressed (panic-capture test hook)");
        }
        Timer::after(HEARTBEAT_PERIOD).await;
    }
}
