//! Phase 1+2 bringup for the Heltec WiFi LoRa 32 V3: board I/O and the
//! SX1262 on the air, on top of the Phase 0 safety floor (embassy on
//! esp-rtos, UART0 banner, RWDT, panic capture).
//!
//! - `Vext` power domain (GPIO36, active low inside the BSP) gating the
//!   OLED.
//! - SSD1306 over I²C (SDA=17/SCL=18, reset GPIO21) with the full
//!   Vext-up → reset-pulse → init sequence, drawn via
//!   `embedded-graphics`.
//! - PRG button (GPIO0) through `umsh_ux_tracker::button::ButtonFsm`;
//!   status LED (GPIO35) through `umsh_ux_tracker::led::LedEngine`.
//! - Battery sampling on GPIO1/ADC1 (curve-fitted calibration, GPIO37
//!   gate) with `umsh_ux_tracker::battery` classification.
//! - SX1262 via `lora-phy` + the shared `umsh-radio-loraphy` runner
//!   (the driver path proven on the T-Echo): continuous RX with
//!   MeshCore US parameters, counting received frames on screen.
//!
//! Controls: single-click resamples the battery and confirms on the
//! LED; double-click plays the location-advert blink; triple-click
//! transmits a test frame (attach the U.FL antenna first); a 3 s hold
//! power-cycles `Vext` and re-initializes the display (the Phase 1
//! exit-criteria round-trip); quad-click panics, exercising the Phase 0
//! capture → reset → report-on-next-boot path; a 10 s very-long hold
//! busy-loops the LED task, exercising RWDT starvation → hardware
//! reset.

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
use lora_phy::LoRa;
use lora_phy::mod_params::{ModulationParams, PacketParams};
use esp_radio::ble::controller::BleConnector;
use static_cell::StaticCell;
use umsh_bsp_esp32::flash_store;
use umsh_bsp_esp32::rng::EspCryptoRng;
use umsh_crypto::NodeIdentity as _;
use umsh_crypto::software::SoftwareIdentity;
use umsh_bsp_heltec_lora32_v3::battery::BatterySampler;
use umsh_bsp_heltec_lora32_v3::display::{self, Display, DisplayConfigAsync as _};
use umsh_bsp_heltec_lora32_v3::radio::{self, Radio};
use umsh_bsp_heltec_lora32_v3::vext::Vext;
use umsh_hal::KeyValueStore as _;
use umsh_radio_loraphy::{Channels, TxRequest};
use umsh_ux_tracker::battery::{BatteryState, BatteryThresholds, classify, soc_from_ocv};
use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm, ButtonTimings};
use umsh_ux_tracker::led::{LedEngine, LedSequence, LedTimings};

esp_bootloader_esp_idf::esp_app_desc!();

const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);
/// Periodic battery resample + redraw cadence.
const REFRESH_PERIOD: Duration = Duration::from_secs(30);
/// How long Vext stays off during the long-press round-trip test.
const VEXT_OFF_DWELL: Duration = Duration::from_secs(2);
/// Bring-up TX power. Deliberately low until the RF path is proven; the
/// MeshCore 22 dBm default is a ceiling, not a starting point.
const TX_POWER_DBM: i32 = 2;

static BUTTON_EVENTS: Channel<CriticalSectionRawMutex, ButtonEvent, 4> = Channel::new();
static LED_PLAY: Signal<CriticalSectionRawMutex, LedSequence> = Signal::new();
static RADIO_CH: Channels<CriticalSectionRawMutex, 4, 2> = Channels::new();
/// Set by the UI task to make the LED task busy-loop (RWDT starvation
/// test hook).
static STARVE_WDT: Signal<CriticalSectionRawMutex, ()> = Signal::new();

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
        umsh_bsp_heltec_lora32_v3::BOARD_NAME,
    );

    // The MAC/crypto stack allocates; sized to match the BLE spike.
    esp_alloc::heap_allocator!(size: 72 * 1024);

    let mut panic_buf = [0u8; umsh_bsp_esp32::panic_capture::MSG_CAPACITY];
    if let Some(msg) = umsh_bsp_esp32::panic_capture::take_panic_message(&mut panic_buf) {
        println!("previous boot panicked: {msg}");
    }

    // ── RF entropy source ────────────────────────────────────────────────
    // The ESP32 TRNG is only a true noise source while the RF subsystem is
    // clocked, and it degrades to pseudo-random *silently* otherwise. The
    // ADC entropy source is unusable on this board — it would claim ADC1,
    // which the battery sampler owns — so the BLE controller is what makes
    // the RNG trustworthy.
    //
    // Binding this by name rather than `_` is load-bearing: `BleConnector`
    // runs `ble_deinit` on drop, which takes the entropy with it, and a
    // bare `_` pattern would drop it immediately.
    let _ble = match BleConnector::new(peripherals.BT, Default::default()) {
        Ok(connector) => {
            println!("ble: controller up (RF entropy source)");
            Some(connector)
        }
        Err(e) => {
            println!("ble: init failed: {e:?} — crypto RNG unavailable");
            None
        }
    };

    // ── Flash storage ────────────────────────────────────────────────────
    // Resolves the `umsh` data partition from the on-flash partition
    // table (see firmware-esp32/partitions-umsh.csv). A board flashed
    // with the espflash default table has no such partition and lands in
    // `PartitionNotFound` — that is the expected failure, not a hang.
    let storage: Option<&'static flash_store::EspStorage> =
        match flash_store::new_storage(peripherals.FLASH) {
            Ok(storage) => {
                static STORAGE: StaticCell<flash_store::EspStorage> = StaticCell::new();
                Some(STORAGE.init(storage))
            }
            Err(e) => {
                println!("storage: init failed: {e:?}");
                None
            }
        };

    let mut boot_count: Option<u32> = None;
    let mut identity_hint: Option<heapless::String<8>> = None;
    if let Some(storage) = storage {
        boot_count = Some(bump_boot_count(flash_store::EspKeyValueStore::new(storage)).await);
        identity_hint = load_or_create_identity(storage).await;
    }

    let led = Output::new(peripherals.GPIO35, Level::Low, OutputConfig::default());
    spawner.spawn(led_task(led, rtc).unwrap());

    let button = Input::new(
        peripherals.GPIO0,
        InputConfig::default().with_pull(Pull::None),
    );
    spawner.spawn(button_task(button).unwrap());

    // Battery gate is GPIO37, independent of Vext, and ADC1 has no
    // radio-ownership constraint — construction order is free here.
    let mut battery = BatterySampler::new(peripherals.ADC1, peripherals.GPIO1, peripherals.GPIO37);

    let mut vext = Vext::new(peripherals.GPIO36);
    let mut oled_reset = Output::new(peripherals.GPIO21, Level::High, OutputConfig::default());
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(400)),
    )
    .unwrap()
    .with_sda(peripherals.GPIO17)
    .with_scl(peripherals.GPIO18)
    .into_async();
    let mut display = display::new_display(i2c);

    vext.enable().await;
    display::reset(&mut oled_reset).await;
    match display.init().await {
        Ok(()) => println!("oled: initialized"),
        Err(e) => println!("oled: init failed: {e:?}"),
    }

    let mut ui = UiState {
        boot_count,
        identity_hint,
        ..UiState::default()
    };

    // ── SX1262 ───────────────────────────────────────────────────────────
    // SPI bus: SCK=GPIO9, MOSI=GPIO10, MISO=GPIO11, NSS=GPIO8 as managed
    // CS. SX1262 datasheet caps SCK at 16 MHz; Mode 0.
    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(16))
            .with_mode(Mode::_0),
    )
    .unwrap()
    .with_sck(peripherals.GPIO9)
    .with_mosi(peripherals.GPIO10)
    .with_miso(peripherals.GPIO11)
    .into_async();
    let radio_cs = Output::new(peripherals.GPIO8, Level::High, OutputConfig::default());
    let radio_spi = ExclusiveDevice::new(spi, radio_cs, Delay).unwrap();
    let radio_reset = Output::new(peripherals.GPIO12, Level::High, OutputConfig::default());
    let radio_dio1 = Input::new(
        peripherals.GPIO14,
        InputConfig::default().with_pull(Pull::None),
    );
    let radio_busy = Input::new(
        peripherals.GPIO13,
        InputConfig::default().with_pull(Pull::None),
    );

    match init_radio(radio_spi, radio_reset, radio_dio1, radio_busy).await {
        Ok((lora, mdltn, rx_pkt, tx_pkt)) => {
            spawner.spawn(radio_task(lora, mdltn, rx_pkt, tx_pkt).unwrap());
            ui.radio_ok = true;
            println!("radio: RX (MeshCore US params, private sync word)");
        }
        Err(e) => println!("radio: init failed: {e:?}"),
    }

    ui.battery_mv = battery.sample_mv().await;
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
                ui.battery_mv = battery.sample_mv().await;
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
                    let _ = data.extend_from_slice(b"heltec-v3 phase2 tx test");
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
                ui.battery_mv = battery.sample_mv().await;
                redraw(&mut display, &ui).await;
            }
            Either3::First(ButtonEvent::Quad) => {
                panic!("quad-click (panic-capture test hook)");
            }
            Either3::First(ButtonEvent::VeryLong) => {
                println!("starving RWDT (very-long hold); expect a hardware reset");
                STARVE_WDT.signal(());
            }
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
                ui.battery_mv = battery.sample_mv().await;
                redraw(&mut display, &ui).await;
            }
        }
    }
}

/// Bring the SX1262 up through lora-phy and build the MeshCore US
/// parameter set. `false` in `LoRa::new` selects the private sync word
/// (0x12, expanded to 0x14/0x24 by the sx126x driver).
async fn init_radio(
    spi: radio::RadioSpi,
    reset: Output<'static>,
    dio1: Input<'static>,
    busy: Input<'static>,
) -> Result<
    (Radio, ModulationParams, PacketParams, PacketParams),
    lora_phy::mod_params::RadioError,
> {
    let kind = radio::new_radio_kind(spi, reset, dio1, busy)?;
    let mut lora = LoRa::new(kind, false, Delay).await?;
    let (mdltn, rx_pkt, tx_pkt) = umsh_radio_loraphy::meshcore_us_params(&mut lora)?;
    Ok((lora, mdltn, rx_pkt, tx_pkt))
}

/// The shared `umsh-radio-loraphy` runner, monomorphised for this
/// board's radio types.
#[embassy_executor::task]
async fn radio_task(
    lora: Radio,
    mdltn: ModulationParams,
    rx_pkt: PacketParams,
    tx_pkt: PacketParams,
) -> ! {
    umsh_radio_loraphy::runner(lora, &RADIO_CH, mdltn, rx_pkt, tx_pkt, TX_POWER_DBM).await
}

/// Key holding the persistent boot counter.
const BOOT_COUNT_KEY: &[u8] = b"hello.boots";

/// Read, increment, and persist the boot counter.
///
/// This is the Phase 3 storage proof: a value that survives a power
/// cycle demonstrates that the partition lookup, the `sequential-storage`
/// map, and the flash write path all work end to end. Returns the new
/// count (1 on a freshly erased region).
async fn bump_boot_count(kv: flash_store::EspKeyValueStore) -> u32 {
    let mut buf = [0u8; 4];
    let previous = match kv.load(BOOT_COUNT_KEY, &mut buf).await {
        Ok(Some(4)) => u32::from_le_bytes(buf),
        // Absent (first boot after erase) or an unexpected length — start over.
        Ok(_) => 0,
        Err(e) => {
            println!("storage: boot-count load failed: {e:?}");
            0
        }
    };
    let next = previous.wrapping_add(1);
    match kv.store(BOOT_COUNT_KEY, &next.to_le_bytes()).await {
        Ok(()) => println!("storage: boot {next} (previous {previous})"),
        Err(e) => println!("storage: boot-count store failed: {e:?}"),
    }
    next
}

/// Load the long-term Ed25519 identity, generating and persisting one on
/// first boot. Returns the node hint for display.
///
/// There is deliberately no PRNG fallback. If the RF entropy source is
/// missing we refuse to generate a key rather than mint a predictable
/// long-term identity — the same posture the nRF firmware takes, and the
/// reason `EspCryptoRng::new` is fallible in the first place.
async fn load_or_create_identity(
    storage: &'static flash_store::EspStorage,
) -> Option<heapless::String<8>> {
    let sk = match storage.load_sk().await {
        Ok(Some(sk)) => sk,
        Ok(None) => {
            let mut rng = match EspCryptoRng::new() {
                Ok(rng) => rng,
                Err(e) => {
                    println!("identity: no RF entropy ({e:?}) — refusing to generate a key");
                    return None;
                }
            };
            let mut sk = [0u8; 32];
            rng.fill_bytes(&mut sk);
            if let Err(e) = storage.store_sk(&sk).await {
                println!("identity: persist failed: {e:?}");
                return None;
            }
            println!("identity: generated a new key on first boot");
            sk
        }
        Err(e) => {
            println!("identity: load failed: {e:?}");
            return None;
        }
    };

    let identity = SoftwareIdentity::from_secret_bytes(&sk);
    let hint = identity.hint();
    let mut rendered: heapless::String<8> = heapless::String::new();
    let _ = write!(rendered, "{hint}");
    println!("identity: {rendered} (pk {:02x?})", &identity.public_key().0);
    Some(rendered)
}

#[derive(Default)]
struct UiState {
    battery_mv: u16,
    vext_cycles: u32,
    radio_ok: bool,
    rx_count: u32,
    tx_count: u32,
    last_rssi: Option<i16>,
    /// Persisted boot counter; `None` when storage failed to initialize.
    boot_count: Option<u32>,
    /// Rendered node hint for the persisted identity; `None` when no
    /// identity could be loaded or generated.
    identity_hint: Option<heapless::String<8>>,
}

async fn redraw(display: &mut Display, ui: &UiState) {
    // No charger-status or VBUS-sense signal exists on this board (the
    // charge LED is charger-driven, §9.4), so classification runs in
    // battery-only terms.
    let state = classify(ui.battery_mv, false, false, BatteryThresholds::default());
    let soc = soc_from_ocv(ui.battery_mv);

    display.clear_buffer();
    let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);
    let mut line: heapless::String<24> = heapless::String::new();
    match &ui.identity_hint {
        Some(hint) => {
            let _ = write!(line, "id {hint}");
        }
        None => {
            let _ = write!(line, "id --");
        }
    }
    if let Some(n) = ui.boot_count {
        let _ = write!(line, "  b{n}");
    }
    draw_line(display, &line, 0, style);

    line.clear();
    let _ = write!(line, "batt {} mV  {soc}%", ui.battery_mv);
    draw_line(display, &line, 1, style);

    line.clear();
    let _ = write!(line, "{}  vx {}", state_name(state), ui.vext_cycles);
    draw_line(display, &line, 2, style);

    line.clear();
    if ui.radio_ok {
        let _ = write!(line, "sx1262 ok");
    } else {
        let _ = write!(line, "sx1262 FAIL");
    }
    if ui.boot_count.is_none() {
        let _ = write!(line, "  nvFAIL");
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

/// Drives the status LED from the UX engine's heartbeat plus one-shot
/// sequences signalled by the UI task, and pets the RWDT.
#[embassy_executor::task]
async fn led_task(mut led: Output<'static>, mut rtc: Rtc<'static>) {
    let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
    loop {
        if STARVE_WDT.try_take().is_some() {
            // Deliberately starve the watchdog without yielding.
            #[allow(clippy::empty_loop)]
            loop {}
        }
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
    // Default timings leave `very_long_press` unset and `VeryLong` can
    // never fire; arm it for the RWDT-starvation test hook.
    let mut fsm = ButtonFsm::new(ButtonTimings {
        very_long_press: Some(core::time::Duration::from_secs(10)),
        ..ButtonTimings::default()
    });
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
