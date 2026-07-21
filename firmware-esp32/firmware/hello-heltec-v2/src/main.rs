//! Phase 1+2 bringup for the Heltec WiFi LoRa 32 V2: board I/O and the
//! SX1276 on the air.
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
//! - SX1276 via `lora-phy` + the `umsh-radio-loraphy` runner:
//!   `RegVersion` probe on boot (shown on OLED), then continuous RX with
//!   MeshCore US parameters, counting received frames on screen.
//!
//! Controls: single-click resamples the battery and confirms on the LED;
//! double-click plays the location-advert blink; triple-click transmits
//! a test frame; a 3 s hold power-cycles `Vext` and re-initializes the
//! display (the Phase 1 exit-criteria round-trip); quad-click panics,
//! exercising the Phase 0 capture → reset → report-on-next-boot path.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use embassy_executor::Spawner;
use embassy_futures::select::{Either, Either3, select, select3};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Delay, Duration, Instant, Timer};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rtc_cntl::{Rtc, RwdtStage};
use esp_hal::spi::Mode;
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use lora_phy::mod_params::{ModulationParams, PacketParams, RadioError};
use lora_phy::mod_traits::IrqState;
use lora_phy::{LoRa, RxMode};
use umsh_bsp_heltec_lora32_v2::battery::BatterySampler;
use umsh_bsp_heltec_lora32_v2::display::{self, Display, DisplayConfigAsync as _};
use umsh_bsp_heltec_lora32_v2::radio::{self, Radio, RadioSpi};
use umsh_bsp_heltec_lora32_v2::vext::Vext;
use umsh_hal::{RxInfo, Snr};
use umsh_radio_loraphy::{Channels, RxFrame, TxRequest};
use umsh_ux_tracker::battery::{BatteryState, BatteryThresholds, classify, soc_from_ocv};
use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm, ButtonTimings};
use umsh_ux_tracker::led::{LedEngine, LedSequence, LedTimings};

esp_bootloader_esp_idf::esp_app_desc!();

const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);
/// Periodic battery resample + redraw cadence.
const REFRESH_PERIOD: Duration = Duration::from_secs(30);
/// How long Vext stays off during the long-press round-trip test.
const VEXT_OFF_DWELL: Duration = Duration::from_secs(2);
/// Bring-up TX power. PA_BOOST floor — deliberately low until the RF
/// path is proven.
const TX_POWER_DBM: i32 = 2;

static BUTTON_EVENTS: Channel<CriticalSectionRawMutex, ButtonEvent, 4> = Channel::new();
static LED_PLAY: Signal<CriticalSectionRawMutex, LedSequence> = Signal::new();
static RADIO_CH: Channels<CriticalSectionRawMutex, 4, 2> = Channels::new();

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
    // panics once a radio controller owns it. (The SX1276 is on SPI and
    // doesn't touch ADC2 — this ordering guards against the Phase 4 BLE
    // controller, not the LoRa chip.)
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

    // ── SX1276 ───────────────────────────────────────────────────────────
    // SPI bus: SCK=GPIO5, MOSI=GPIO27, MISO=GPIO19, NSS=GPIO18 as
    // managed CS. SX1276 datasheet caps SCK at 10 MHz; Mode 0.
    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(8))
            .with_mode(Mode::_0),
    )
    .unwrap()
    .with_sck(peripherals.GPIO5)
    .with_mosi(peripherals.GPIO27)
    .with_miso(peripherals.GPIO19)
    .into_async();
    let radio_cs = Output::new(peripherals.GPIO18, Level::High, OutputConfig::default());
    let mut radio_spi = ExclusiveDevice::new(spi, radio_cs, Delay).unwrap();
    let mut radio_reset = Output::new(peripherals.GPIO14, Level::High, OutputConfig::default());

    match radio::probe_version(&mut radio_spi, &mut radio_reset).await {
        Ok(v) => {
            println!("radio: RegVersion {v:#04x}");
            ui.radio_version = Some(v);
        }
        Err(e) => println!("radio: version probe failed: {e:?}"),
    }
    if ui.radio_version == Some(radio::EXPECTED_VERSION) {
        let dio0 = Input::new(
            peripherals.GPIO26,
            InputConfig::default().with_pull(Pull::None),
        );
        match init_radio(radio_spi, radio_reset, dio0).await {
            Ok((mut lora, mdltn, rx_pkt, tx_pkt)) => {
                if let Err(e) = dump_radio_state(&mut lora, &mdltn, &rx_pkt).await {
                    println!("radio: state dump failed: {e:?}");
                }
                spawner.spawn(radio_task(lora, mdltn, rx_pkt, tx_pkt).unwrap());
                ui.radio_ok = true;
                println!("radio: RX (MeshCore US params, private sync word)");
            }
            Err(e) => println!("radio: init failed: {e:?}"),
        }
    } else {
        println!("radio: not an SX1276, radio disabled");
    }

    ui.battery_mv = battery.sample_mv(&mut vext).await;
    redraw(&mut display, &ui).await;
    println!("battery: {} mV", ui.battery_mv);

    loop {
        match select3(
            BUTTON_EVENTS.receive(),
            RADIO_CH.rx.receive(),
            Timer::after(REFRESH_PERIOD),
        )
        .await
        {
            Either3::First(ButtonEvent::Single) => {
                LED_PLAY.signal(LedSequence::ActionConfirm);
                ui.battery_mv = battery.sample_mv(&mut vext).await;
                redraw(&mut display, &ui).await;
                println!("battery: {} mV", ui.battery_mv);
            }
            Either3::First(ButtonEvent::Double) => {
                LED_PLAY.signal(LedSequence::LocationAdvert);
            }
            Either3::First(ButtonEvent::Triple) => {
                if ui.radio_ok {
                    let mut data: heapless::Vec<u8, { umsh_radio_loraphy::MAX_PAYLOAD }> =
                        heapless::Vec::new();
                    let _ = data.extend_from_slice(b"heltec-v2 phase2 tx test");
                    RADIO_CH
                        .tx
                        .send(TxRequest {
                            data,
                            power_dbm: None,
                        })
                        .await;
                    match RADIO_CH.tx_done.wait().await {
                        Ok(()) => {
                            ui.tx_count = ui.tx_count.wrapping_add(1);
                            println!("radio: tx ok");
                        }
                        Err(e) => println!("radio: tx failed: {e:?}"),
                    }
                    redraw(&mut display, &ui).await;
                }
            }
            Either3::First(ButtonEvent::Long) => {
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
            Either3::First(ButtonEvent::Quad) => {
                panic!("quad-click (panic-capture test hook)");
            }
            Either3::First(ButtonEvent::VeryLong) => {}
            Either3::Second(frame) => {
                ui.rx_count = ui.rx_count.wrapping_add(1);
                ui.last_rssi = Some(frame.info.rssi);
                println!(
                    "radio: rx {} bytes rssi {} snr {}",
                    frame.info.len,
                    frame.info.rssi,
                    frame.info.snr.as_decibels(),
                );
                redraw(&mut display, &ui).await;
            }
            Either3::Third(()) => {
                ui.battery_mv = battery.sample_mv(&mut vext).await;
                redraw(&mut display, &ui).await;
            }
        }
    }
}

/// Bring-up diagnostic: run one full `prepare_for_rx` + `start_rx`
/// cycle (identical to the runner's) and dump every LoRa-page register
/// so the chip's live RX configuration can be compared against a
/// known-good RadioLib/MeshCore node. The runner re-prepares RX when it
/// takes over, so this leaves no lasting state behind.
async fn dump_radio_state(
    lora: &mut Radio,
    mdltn: &ModulationParams,
    rx_pkt: &PacketParams,
) -> Result<(), RadioError> {
    lora.prepare_for_rx(RxMode::Continuous, mdltn, rx_pkt).await?;
    lora.start_rx().await?;
    Timer::after_millis(5).await;

    println!("radio: register dump (live RX state):");
    let kind = lora.radio_kind_mut();
    // Skip 0x00 (RegFifo — reading it disturbs the FIFO pointer).
    for base in (0x01u8..=0x42).step_by(8) {
        let mut line: heapless::String<64> = heapless::String::new();
        let _ = write!(line, "  0x{base:02x}:");
        for addr in base..(base + 8).min(0x43) {
            let val = kind.read_register_raw(addr).await?;
            let _ = write!(line, " {val:02x}");
        }
        println!("{}", line.as_str());
    }
    Ok(())
}

/// Bring the SX1276 up through lora-phy and build the MeshCore US
/// parameter set. `false` in `LoRa::new` selects the private sync word
/// (0x12 — the byte the SX126x boards expand to 0x1424).
async fn init_radio(
    spi: RadioSpi,
    reset: Output<'static>,
    dio0: Input<'static>,
) -> Result<(Radio, ModulationParams, PacketParams, PacketParams), RadioError> {
    let kind = radio::new_radio_kind(spi, reset, dio0)?;
    let mut lora = LoRa::new(kind, false, Delay).await?;
    let (mdltn, rx_pkt, tx_pkt) = umsh_radio_loraphy::meshcore_us_params(&mut lora)?;
    Ok((lora, mdltn, rx_pkt, tx_pkt))
}

#[derive(Default)]
struct UiState {
    battery_mv: u16,
    vext_cycles: u32,
    radio_version: Option<u8>,
    radio_ok: bool,
    rx_count: u32,
    tx_count: u32,
    last_rssi: Option<i16>,
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
    let _ = write!(line, "{}  vx {}", state_name(state), ui.vext_cycles);
    draw_line(display, &line, 2, style);

    line.clear();
    match (ui.radio_version, ui.radio_ok) {
        (Some(v), true) => {
            let _ = write!(line, "sx1276 v{v:02x} ok");
        }
        (Some(v), false) => {
            let _ = write!(line, "sx1276 v{v:02x} FAIL");
        }
        (None, _) => {
            let _ = write!(line, "sx1276 no spi");
        }
    }
    draw_line(display, &line, 3, style);

    line.clear();
    let _ = write!(line, "rx {} tx {}", ui.rx_count, ui.tx_count);
    if let Some(rssi) = ui.last_rssi {
        let _ = write!(line, " {rssi}");
    }
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

/// Read the SX1276's frequency-error indicator for the last received
/// packet and convert to Hz (positive = the remote carrier is above our
/// local tuning). Datasheet §4.1.5: FreqError = FEI × 2²⁴ / FXOSC ×
/// BW/500 kHz — at BW 62.5 that reduces to FEI × 65536 / 10⁶.
async fn read_freq_error_hz(lora: &mut Radio) -> i32 {
    let kind = lora.radio_kind_mut();
    let msb = kind.read_register_raw(0x28).await.unwrap_or(0);
    let mid = kind.read_register_raw(0x29).await.unwrap_or(0);
    let lsb = kind.read_register_raw(0x2a).await.unwrap_or(0);
    let mut fei = (((msb as u32 & 0x0f) << 16) | ((mid as u32) << 8) | lsb as u32) as i32;
    if msb & 0x08 != 0 {
        fei -= 1 << 20; // sign-extend the 20-bit value
    }
    ((fei as i64 * 65_536) / 1_000_000) as i32
}

/// Diagnostic stand-in for `umsh_radio_loraphy::runner`: the identical
/// RX/TX state machine and cancellation discipline (only `wait_for_irq`
/// and the TX-channel receive are cancel-safe), plus a raw FEI read on
/// every completed frame so carrier offset between the transmitter and
/// this board's crystal is measured, not guessed. Swap back to the
/// shared runner once the RF path is proven.
#[embassy_executor::task]
async fn radio_task(
    mut lora: Radio,
    mdltn: ModulationParams,
    rx_pkt: PacketParams,
    mut tx_pkt: PacketParams,
) -> ! {
    let mut rx_buf = [0u8; umsh_radio_loraphy::MAX_PAYLOAD];

    'outer: loop {
        if lora
            .prepare_for_rx(RxMode::Continuous, &mdltn, &rx_pkt)
            .await
            .is_err()
        {
            continue;
        }
        if lora.start_rx().await.is_err() {
            continue;
        }

        loop {
            match select3(
                lora.wait_for_irq(),
                RADIO_CH.tx.receive(),
                Timer::after_secs(2),
            )
            .await
            {
                Either3::Third(()) => {
                    // Noise-floor diagnostic: instantaneous RSSI while
                    // no packet is in flight. BW 62.5 kHz thermal floor
                    // is ≈ −125 dBm; a reading tens of dB above that
                    // means the front end is being jammed or the
                    // antenna path is broken.
                    let raw = lora.radio_kind_mut().read_register_raw(0x1b).await;
                    if let Ok(raw) = raw {
                        println!("radio: noise floor {} dBm", -157 + raw as i16);
                    }
                    continue;
                }
                Either3::First(Ok(())) => {
                    // process_irq_event is NOT cancel-safe — run to
                    // completion, then clear latched flags.
                    let irq_result = lora.process_irq_event().await;
                    let _ = lora.clear_irq_status().await;

                    match irq_result {
                        Ok(Some(IrqState::Done)) => {
                            if let Ok((len, status)) =
                                lora.get_rx_result(&rx_pkt, &mut rx_buf).await
                            {
                                let freq_err = read_freq_error_hz(&mut lora).await;
                                println!("radio: freq error {freq_err} Hz");
                                let mut data: heapless::Vec<
                                    u8,
                                    { umsh_radio_loraphy::MAX_PAYLOAD },
                                > = heapless::Vec::new();
                                let _ = data.extend_from_slice(&rx_buf[..len as usize]);
                                let info = RxInfo {
                                    len: len as usize,
                                    rssi: status.rssi,
                                    snr: Snr::from_decibels(status.snr as i8),
                                    lqi: None,
                                };
                                if RADIO_CH.rx.try_send(RxFrame { data, info }).is_ok() {
                                    RADIO_CH.rx_waker.wake();
                                }
                            }
                            continue 'outer;
                        }
                        Ok(_) => continue,
                        Err(_) => continue 'outer,
                    }
                }
                Either3::First(Err(_)) => continue 'outer,
                Either3::Second(tx_req) => {
                    // TX is also NOT cancel-safe — run to completion.
                    let power = tx_req.power_dbm.unwrap_or(TX_POWER_DBM);
                    let result = async {
                        lora.prepare_for_tx(&mdltn, &mut tx_pkt, power, &tx_req.data)
                            .await?;
                        lora.tx().await
                    }
                    .await;
                    RADIO_CH.tx_done.signal(result);
                    continue 'outer;
                }
            }
        }
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
