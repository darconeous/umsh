//! Phase 3 companion firmware for the Heltec WiFi LoRa 32 V3: the full
//! UMSH MAC on the SX1262, driven by an interactive `umsh-cli` session on
//! UART0.
//!
//! This is the CLI-parity counterpart to `companion-cli-wio-tracker-l1`.
//! The task layout and the reasons behind it are the same; only the
//! transport differs (UART0/CP2102 rather than USB-CDC), so the nRF
//! firmware's USB flow-control machinery collapses into a simpler drain
//! loop. `hello-heltec-v3` remains the bringup/diagnostic binary with the
//! button gestures and the panic/RWDT test hooks — this one is the
//! functional node.
//!
//! Task layout (steady state):
//! - `main`:        boot sequencing, then parks on the display loop
//! - `led_task`:    heartbeat LED and RWDT feed
//! - `radio_task`:  owns `lora_phy::LoRa`, runs the RX/TX state machine
//! - `mac_task`:    `Host::run` — the MAC pump, independent of the CLI
//! - `cli_task`:    `CliSession::run` over UART0
//! - `output_task`: owns the UART TX half, drains `OUTPUT_CH`
//!
//! Keeping the MAC pump out of the CLI task is deliberate and was learned
//! on the nRF side: with them fused, the coordinator had no registered
//! keys until a terminal attached, so inbound secure frames were dropped
//! on a headless node.
//!
//! ## Boot order is constrained
//!
//! The BLE controller comes up first and stays up. It is not used as a
//! transport here — it is the RF entropy source without which
//! `EspCryptoRng` refuses to exist (see `umsh_bsp_esp32::rng`). Storage
//! and the identity follow, because the MAC needs both.

#![no_std]
#![no_main]

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Delay, Duration, Instant, Timer};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_hal::Async;
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rtc_cntl::{Rtc, RwdtStage};
use esp_hal::spi::Mode;
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::uart::{Config as UartConfig, Uart, UartRx, UartTx};
use esp_println::println;
use esp_radio::ble::controller::BleConnector;
use lora_phy::LoRa;
use lora_phy::mod_params::{Bandwidth, ModulationParams, PacketParams, SpreadingFactor};
use static_cell::StaticCell;
use umsh_bsp_esp32::flash_store::{
    self, EspChannelStore, EspCounterStore, EspPeerStore, EspStorage,
};
use umsh_bsp_esp32::rng::EspCryptoRng;
use umsh_bsp_heltec_lora32_v3::battery::BatterySampler;
use umsh_bsp_heltec_lora32_v3::display::{self, Display, DisplayConfigAsync as _};
use umsh_bsp_heltec_lora32_v3::platform::{HeltecV3Mac, HeltecV3Platform};
use umsh_bsp_heltec_lora32_v3::radio::{self, Radio};
use umsh_bsp_heltec_lora32_v3::vext::Vext;
use umsh_core::{ChannelKey, PayloadType, PublicKey};
use umsh_crypto::{
    CryptoEngine, NodeIdentity as _,
    software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
};
use umsh_hal::EmbassyClock;
use umsh_mac::{LocalIdentityId, MacHandle, OperatingPolicy, RepeaterConfig};
use umsh_node::{Channel, Host, LocalNode};
use umsh_radio_loraphy::Channels;
use umsh_sync::AsyncRefCell;
use umsh_ux_tracker::battery::{BatteryState, BatteryThresholds, classify, soc_from_ocv};
use umsh_ux_tracker::led::{LedEngine, LedTimings};

mod cli_io;

esp_bootloader_esp_idf::esp_app_desc!();

const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);
/// Battery resample + OLED redraw cadence.
const REFRESH_PERIOD: Duration = Duration::from_secs(30);
/// Bringup TX power, matching `hello-heltec-v3`. The MeshCore 22 dBm
/// default is a ceiling, not a starting point.
const TX_POWER_DBM: i32 = 2;

/// MAC capacities, mirrored from [`HeltecV3Mac`]. Repeating them is
/// unavoidable: `MacHandle` is generic over the same const parameters and
/// there is no way to project them out of the `Mac` alias.
type V3Handle = MacHandle<'static, HeltecV3Platform, 2, 8, 4, 4, 8, 255, 32>;
type V3Host = Host<V3Handle>;
type V3Node = LocalNode<V3Handle>;

static RADIO_CH: Channels<CriticalSectionRawMutex, 4, 2> = Channels::new();
static MAC_CELL: StaticCell<AsyncRefCell<HeltecV3Mac>> = StaticCell::new();
static STORAGE: StaticCell<EspStorage> = StaticCell::new();

/// Frames delivered to the local node, for the OLED. The CLI keeps its own
/// richer statistics; this is only the at-a-glance number.
static RX_COUNT: AtomicU32 = AtomicU32::new(0);

/// Relay from the synchronous `on_receive` callback to the async
/// [`identity_persist_task`]. Carries (pk, payload, len).
static IDENTITY_SIGNAL: Signal<CriticalSectionRawMutex, ([u8; 32], [u8; 256], usize)> =
    Signal::new();

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

    // umsh-cli, umsh-node, and umsh-sync all use `alloc`.
    esp_alloc::heap_allocator!(size: 72 * 1024);

    let mut panic_buf = [0u8; umsh_bsp_esp32::panic_capture::MSG_CAPACITY];
    let previous_panic = umsh_bsp_esp32::panic_capture::take_panic_message(&mut panic_buf)
        .map(|msg| {
            println!("previous boot panicked: {msg}");
            // Copied out char-by-char: the capture buffer is borrowed from
            // the stack and the message may be longer than the CLI banner
            // slot, so truncation has to stay on a char boundary.
            let mut owned: heapless::String<128> = heapless::String::new();
            for c in msg.chars() {
                if owned.push(c).is_err() {
                    break;
                }
            }
            owned
        });

    // ── RF entropy source ────────────────────────────────────────────────
    // Bound by name, not `_`: `BleConnector` runs `ble_deinit` on drop,
    // which takes the entropy source with it, and a bare `_` pattern drops
    // it immediately. Without this the TRNG degrades to pseudo-random
    // *silently*, which is why `EspCryptoRng` is fallible at all.
    let _ble = match BleConnector::new(peripherals.BT, Default::default()) {
        Ok(connector) => {
            println!("ble: controller up (RF entropy source)");
            connector
        }
        Err(e) => panic!("ble init failed ({e:?}) — no trustworthy RNG"),
    };

    // ── Flash storage ────────────────────────────────────────────────────
    // Resolved by label from the on-flash partition table. A board flashed
    // without `--partition-table firmware-esp32/partitions-umsh.csv` has no
    // `umsh` partition and lands here — the panic names the cause instead
    // of failing later as an unexplained identity loss.
    let storage: &'static EspStorage = STORAGE.init(
        flash_store::new_storage(peripherals.FLASH)
            .unwrap_or_else(|e| panic!("storage init failed: {e:?}")),
    );

    // ── Identity ─────────────────────────────────────────────────────────
    // Loaded from flash on later boots, TRNG-generated on the first. There
    // is deliberately no PRNG fallback: a predictable long-term key is
    // worse than refusing to start.
    let mut rng = EspCryptoRng::new().unwrap_or_else(|e| panic!("crypto rng unavailable: {e:?}"));
    let sk_bytes: [u8; 32] = match storage.load_sk().await {
        Ok(Some(sk)) => sk,
        Ok(None) => {
            let mut sk = [0u8; 32];
            rng.fill_bytes(&mut sk);
            storage
                .store_sk(&sk)
                .await
                .unwrap_or_else(|e| panic!("identity persist failed: {e:?}"));
            println!("identity: generated a new key on first boot");
            sk
        }
        Err(e) => panic!("identity load failed: {e:?}"),
    };
    let identity = SoftwareIdentity::from_secret_bytes(&sk_bytes);
    let local_key = *identity.public_key();
    let mut identity_hint: heapless::String<8> = heapless::String::new();
    let _ = write!(identity_hint, "{}", identity.hint());
    println!("identity: {identity_hint}");

    // ── LED + RWDT ───────────────────────────────────────────────────────
    let led = Output::new(peripherals.GPIO35, Level::Low, OutputConfig::default());
    spawner.spawn(led_task(led, rtc).unwrap());

    // ── SX1262 ───────────────────────────────────────────────────────────
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

    let (lora, mdltn, rx_pkt, tx_pkt) =
        init_radio(radio_spi, radio_reset, radio_dio1, radio_busy)
            .await
            .unwrap_or_else(|e| panic!("radio init failed: {e:?}"));
    // Worst-case airtime hint for the MAC scheduler. Stated in the same
    // terms as `meshcore_us_params` builds them.
    let t_frame_ms = umsh_radio_loraphy::airtime_ms(
        SpreadingFactor::_7,
        Bandwidth::_62KHz,
        umsh_radio_loraphy::MAX_PAYLOAD,
    );
    spawner.spawn(radio_task(lora, mdltn, rx_pkt, tx_pkt).unwrap());

    // ── MAC coordinator ──────────────────────────────────────────────────
    // Built in place: the `Mac` is tens of kilobytes and `StaticCell::init`
    // would transit it through the stack once per move in the chain. Keep
    // this a single expression.
    let mac_cell: &'static AsyncRefCell<HeltecV3Mac> = MAC_CELL.init_with(|| {
        AsyncRefCell::new(HeltecV3Mac::new(
            umsh_radio_loraphy::LoraphyRadio::new(&RADIO_CH, t_frame_ms),
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
            EmbassyClock,
            rng,
            EspCounterStore::new(storage),
            RepeaterConfig::default(),
            OperatingPolicy::default(),
        ))
    });

    let identity_id = mac_cell
        .try_borrow_mut()
        .expect("mac cell is unshared during bring-up")
        .add_identity(identity)
        .unwrap_or_else(|_| panic!("identity slot"));
    // Seed the TX frame counter from the persisted boundary so secured
    // sends can never reuse counter space from a previous boot.
    MacHandle::new(mac_cell)
        .load_persisted_counter(identity_id)
        .await
        .unwrap_or_else(|e| panic!("tx counter load failed: {e:?}"));

    // ── Host, node, and persisted peers/channels ─────────────────────────
    // Registered here rather than from the CLI task so a headless node can
    // authenticate inbound secure frames without a terminal attached.
    let mut host: V3Host = Host::new(MacHandle::new(mac_cell));
    let node = host.add_node(identity_id);
    {
        let mut peers: heapless::Vec<([u8; 32], Option<heapless::String<16>>), 8> =
            heapless::Vec::new();
        let _ = storage.load_all_peers(&mut peers).await;
        let mut channels: heapless::Vec<(heapless::String<16>, [u8; 32]), 4> = heapless::Vec::new();
        let _ = storage.load_all_channels(&mut channels).await;
        for (pk, _alias) in peers.iter() {
            let _ = node.peer(PublicKey(*pk)).await;
        }
        for (name, key_bytes) in channels.iter() {
            let channel = Channel::private(ChannelKey(*key_bytes), name.as_str());
            let _ = node.join(&channel).await;
        }
        println!("restored {} peers, {} channels", peers.len(), channels.len());
    }
    // RX counter boundaries land on registered peers, so this must follow
    // peer registration.
    MacHandle::new(mac_cell)
        .load_all_persisted_rx_counters()
        .await
        .ok();

    // ── UART0 CLI ────────────────────────────────────────────────────────
    // Same pins the CP2102 bridge and `esp-println` use. Boot diagnostics
    // above interleave cleanly; steady-state `println!` would corrupt the
    // interactive line editing, so the firmware goes quiet from here.
    // Claiming UART0 resets the TX FIFO, which truncates whatever
    // `esp-println` left in flight — observed on hardware as a boot line
    // cut mid-word. `esp-println` exposes no flush, so drain by time: 20 ms
    // clears a 64-byte FIFO at 115200 baud roughly four times over.
    Timer::after(Duration::from_millis(20)).await;
    let uart = Uart::new(peripherals.UART0, UartConfig::default())
        .unwrap()
        .with_rx(peripherals.GPIO44)
        .with_tx(peripherals.GPIO43)
        .into_async();
    let (uart_rx, uart_tx) = uart.split();

    spawner.spawn(output_task(uart_tx).unwrap());
    spawner.spawn(identity_persist_task(storage).unwrap());
    spawner.spawn(mac_task(host, identity_id).unwrap());
    spawner.spawn(cli_task(node, local_key, storage, uart_rx, previous_panic).unwrap());

    // ── OLED ─────────────────────────────────────────────────────────────
    let mut battery =
        BatterySampler::new(peripherals.ADC1, peripherals.GPIO1, peripherals.GPIO37);
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
    let display_ok = display.init().await.is_ok();

    loop {
        let battery_mv = battery.sample_mv().await;
        if display_ok {
            redraw(&mut display, &identity_hint, battery_mv).await;
        }
        Timer::after(REFRESH_PERIOD).await;
    }
}

/// Bring the SX1262 up through lora-phy and build the MeshCore US
/// parameter set. `false` in `LoRa::new` selects the private sync word.
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

#[embassy_executor::task]
async fn radio_task(
    lora: Radio,
    mdltn: ModulationParams,
    rx_pkt: PacketParams,
    tx_pkt: PacketParams,
) -> ! {
    umsh_radio_loraphy::runner(lora, &RADIO_CH, mdltn, rx_pkt, tx_pkt, TX_POWER_DBM).await
}

/// Drives the MAC coordinator. Independent of the CLI so radio RX/TX and
/// the MAC pump (including ping auto-replies) keep running whether or not
/// a terminal is attached.
#[embassy_executor::task]
async fn mac_task(mut host: V3Host, identity_id: LocalIdentityId) {
    let sub_node = host.node(identity_id).expect("node just added");
    // Returns `false` throughout: this subscription observes, it does not
    // consume — the CLI's own subscriptions still see every packet.
    let _sub = sub_node.on_receive(|pkt| {
        RX_COUNT.fetch_add(1, Ordering::Relaxed);
        if pkt.payload_type() != PayloadType::NodeIdentity {
            return false;
        }
        let Some(from) = pkt.from_key() else {
            return false;
        };
        let raw = pkt.payload();
        let len = raw.len().min(256);
        let mut buf = [0u8; 256];
        buf[..len].copy_from_slice(&raw[..len]);
        IDENTITY_SIGNAL.signal((from.0, buf, len));
        false
    });

    let _ = host.run().await;
    panic!("host exited");
}

/// Persists `NodeIdentityPayload` bytes for peers already known to
/// storage. Unknown senders are ignored — receiving an identity is not
/// grounds for adding a peer.
#[embassy_executor::task]
async fn identity_persist_task(storage: &'static EspStorage) {
    loop {
        let (pk, payload, len) = IDENTITY_SIGNAL.wait().await;
        if storage.peer_exists(&pk).await.unwrap_or(false) {
            let _ = storage.update_peer_identity(&pk, &payload[..len]).await;
        }
    }
}

/// Owns the UART TX half and serves `OUTPUT_CH`.
#[embassy_executor::task]
async fn output_task(mut tx: UartTx<'static, Async>) -> ! {
    cli_io::drain_to_uart(&mut tx).await
}

/// Runs the `CliSession` over UART0.
#[embassy_executor::task]
async fn cli_task(
    node: V3Node,
    local_key: PublicKey,
    storage: &'static EspStorage,
    rx: UartRx<'static, Async>,
    previous_panic: Option<heapless::String<128>>,
) {
    use umsh_cli::CliSession;
    use umsh_cli::io::CliOutput as _;
    use umsh_cli::logger::NullLogger;

    let mut input = cli_io::UartInput::new(rx);
    let mut out = cli_io::UartOutput::new();

    let _ = out.write_line("").await;
    let _ = out.write_line("UMSH CLI (Heltec WiFi LoRa 32 V3)").await;
    let _ = out.write_line("type /help for commands").await;
    if let Some(msg) = previous_panic {
        let _ = out.write_line("[PREV PANIC]:").await;
        let _ = out.write_line(&msg).await;
    }

    let mut cli: CliSession<_, _, _, _, _, _, 4, 4, 2, 8, 128> = CliSession::new(
        node,
        local_key,
        out,
        NullLogger::new(),
        EspPeerStore::new(storage),
        EspChannelStore::new(storage),
        umsh_hal::NoPowerControl,
    );

    // `run` loads peers/channels from storage into the CLI display tables
    // and re-registers them with the MAC (idempotent) before looping.
    let _ = cli.run(&mut input).await;
    panic!("cli exited");
}

/// Heartbeat LED plus the RWDT feed. Sharing one task keeps the watchdog
/// tied to something visibly alive: if the LED stops, the reset follows.
#[embassy_executor::task]
async fn led_task(mut led: Output<'static>, mut rtc: Rtc<'static>) -> ! {
    let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
    loop {
        rtc.rwdt.feed();
        let decision = engine.tick(Instant::now().as_millis());
        led.set_level(if decision.on { Level::High } else { Level::Low });
        Timer::at(Instant::from_millis(decision.next_deadline_ms)).await;
    }
}

async fn redraw(display: &mut Display, hint: &str, battery_mv: u16) {
    // No charger-status or VBUS-sense signal exists on this board (the
    // charge LED is charger-driven), so classification is battery-only.
    let state = classify(battery_mv, false, false, BatteryThresholds::default());
    let soc = soc_from_ocv(battery_mv);

    display.clear_buffer();
    let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);
    let mut line: heapless::String<24> = heapless::String::new();

    let _ = write!(line, "id {hint}");
    draw_line(display, &line, 0, style);

    line.clear();
    let _ = write!(line, "batt {battery_mv} mV  {soc}%");
    draw_line(display, &line, 1, style);

    line.clear();
    let _ = write!(line, "{}", state_name(state));
    draw_line(display, &line, 2, style);

    line.clear();
    let _ = write!(line, "rx {}", RX_COUNT.load(Ordering::Relaxed));
    draw_line(display, &line, 3, style);

    line.clear();
    let _ = write!(line, "cli on uart0");
    draw_line(display, &line, 4, style);

    let _ = display.flush().await;
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

fn draw_line(display: &mut Display, text: &str, row: i32, style: MonoTextStyle<'_, BinaryColor>) {
    // FONT_6X10 baseline: 10 px rows with a 2 px top margin. Only rows
    // 0..=4 fit in the 64 px panel.
    let _ = Text::new(text, Point::new(0, 10 + row * 12), style).draw(display);
}
