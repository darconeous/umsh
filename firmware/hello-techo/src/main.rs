// LilyGO T-Echo bringup firmware.
//
// Boot sequence:
//   1. Bring up the peripheral rail (P0.12 HIGH).
//   2. Arm the watchdog (8 s timeout, petted by the heartbeat task).
//   3. Spawn the display task — initial boot screen ("UMSH bringup" + git
//      short SHA + "RX: 0") plus subsequent count-update refreshes.
//   4. Initialize the SX1262 LoRa radio (MeshCore US settings) and spawn
//      the radio runner task.
//   5. Spawn the packet handler task (drains the radio RX channel, updates
//      the count, queues print lines).
//   6. Run USB-CDC echo + heartbeat LED + USB stack concurrently.
//
// Task layout (steady state):
//   - main():               joins usb.run / run_echo / heartbeat
//   - display_task:         renders the e-paper on count changes
//   - radio_runner_task:    owns lora_phy::LoRa, RX/TX state machine
//   - packet_handler_task:  drains radio RX, updates count, queues prints
//
// Safety primitives inherited from the BSP (see umsh-bsp-nrf52840):
//   * Panic capture into reserved RAM, dumped over USB on the next boot.
//   * 1200-baud touchless reset and Ctrl-C × 3 + "dfu" escape to bootloader
//     (baked into CdcAcmRescue).
//   * Watchdog.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {
    // Host placeholder. This binary only runs on the embedded target.
}

// The #[panic_handler] must live in the binary crate.
#[cfg(target_os = "none")]
mod panic;

// Low-level SSD1681 / GDEH0154D67 driver, used by display_task below.
// Sibling of mod firmware so it can live at src/display.rs without
// awkward #[path] gymnastics.
#[cfg(target_os = "none")]
mod display;

// lora-phy 3.x unconditionally depends on defmt. Provide a zero-overhead
// no-op global logger so this binary links without any debug transport.
// All defmt log calls compile out in release mode; this just provides the
// required linker symbols.
#[cfg(target_os = "none")]
mod defmt_logger {
    #[defmt::global_logger]
    struct Logger;
    unsafe impl defmt::Logger for Logger {
        fn acquire() {}
        unsafe fn flush() {}
        unsafe fn release() {}
        unsafe fn write(_: &[u8]) {}
    }
    defmt::timestamp!("{=u32}", 0u32);
}

#[cfg(target_os = "none")]
mod firmware {
    use core::sync::atomic::{AtomicU32, Ordering};

    use super::display;

    use embassy_executor::Spawner;
    use embassy_futures::join::join3;
    use embassy_futures::select::{select, Either};
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
    use embassy_nrf::peripherals;
    use embassy_nrf::spim::{Config as SpimConfig, Frequency, Spim};
    use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
    use embassy_nrf::usb::Driver;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::channel::Channel;
    use embassy_sync::signal::Signal;
    use embassy_time::{Delay, Duration, Instant, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, Sender, State};
    use embassy_usb::{Builder, Config};
    use embedded_hal_bus::spi::ExclusiveDevice;
    use lora_phy::iv::GenericSx126xInterfaceVariant;
    use lora_phy::mod_params::{ModulationParams, PacketParams};
    use lora_phy::sx126x::{Config as LoraConfig, Sx126x, Sx1262, TcxoCtrlVoltage};
    use lora_phy::LoRa;
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_ux_tracker::led::{LedEngine, LedTimings};

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
        // SPIM2 → e-paper SPI bus. embassy-nrf names this interrupt SPI2.
        SPI2        => embassy_nrf::spim::InterruptHandler<peripherals::SPI2>;
        // SPIM1 → SX1262 LoRa SPI bus. embassy-nrf names this peripheral
        // TWISPI1 (it's the shared TWIM1/SPIM1 block on nRF52840).
        TWISPI1     => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI1>;
    });

    // ─── Configuration constants ─────────────────────────────────────────────

    /// Display refresh throttle: do not refresh more than once per this
    /// interval. Each full refresh is ~2 s of panel flashing, so spamming
    /// updates would be both ugly and bad for the panel.
    const DISPLAY_THROTTLE: Duration = Duration::from_secs(5);

    /// FONT_10X20 character width in pixels — used for centering text.
    const FONT_W: i32 = 10;

    /// Vertical positions of the three boot-screen text lines, in pixels.
    const TITLE_Y: i32 =  70;
    const SHA_Y:   i32 = 100;
    const COUNT_Y: i32 = 130;

    /// Bound on the per-packet print line. Worst case: ~30 byte header +
    /// 2 × 255 bytes of hex-encoded payload + CRLF = ~542 bytes; 640 leaves
    /// headroom.
    const PRINT_LINE_CAP: usize = 640;

    /// Per-frame TX power in dBm. SX1262 PA range is roughly -9..+22.
    /// 14 dBm is the conservative bringup default.
    const TX_POWER_DBM: i32 = 14;

    // ─── Concrete types for the radio task ───────────────────────────────────
    //
    // `#[embassy_executor::task]` requires concrete types in the task
    // signature, so we name them once here.

    type RadioSpiBus = ExclusiveDevice<Spim<'static>, Output<'static>, Delay>;
    type RadioIv     = GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>;
    type RadioKind   = Sx126x<RadioSpiBus, RadioIv, Sx1262>;
    type LoraRadio   = LoRa<RadioKind, Delay>;

    // ─── Static shared state ─────────────────────────────────────────────────

    /// Channels shared between the radio runner and Sx1262Radio / packet
    /// handler. Capacity: 4 inbound frames, 2 pending TX requests.
    type RadioCh = umsh_radio_sx126x::Channels<ThreadModeRawMutex, 4, 2>;
    static RADIO_CH: RadioCh = RadioCh::new();

    /// Running count of received packets, monotonically incremented by
    /// `packet_handler_task` once per received frame.
    static PACKET_COUNT: AtomicU32 = AtomicU32::new(0);

    /// Fires whenever the count changes. The display task wakes on this
    /// signal and reads the current `PACKET_COUNT` to render. Coalesces:
    /// rapid bursts produce one refresh per throttle window, not one per
    /// packet.
    static DISPLAY_COUNT_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Pre-formatted per-packet print lines waiting to be drained to USB
    /// by `run_echo`. If USB isn't draining (no serial connection), the
    /// queue fills and subsequent lines are dropped silently — the count
    /// still increments and the display still updates.
    type PrintLine = heapless::String<PRINT_LINE_CAP>;
    static PRINT_CH: Channel<ThreadModeRawMutex, PrintLine, 2> = Channel::new();

    // ─── Tasks ───────────────────────────────────────────────────────────────

    /// Owns the `lora_phy::LoRa` instance. Switches between continuous RX
    /// and TX as TX requests arrive on `RADIO_CH.tx`.
    #[embassy_executor::task]
    async fn radio_runner_task(
        lora: LoraRadio,
        mdltn: ModulationParams,
        rx_pkt: PacketParams,
        tx_pkt: PacketParams,
    ) {
        umsh_radio_sx126x::runner(lora, &RADIO_CH, mdltn, rx_pkt, tx_pkt, TX_POWER_DBM).await;
    }

    /// Always-on consumer of `RADIO_CH.rx`. Runs independently of USB so
    /// the counter and display update even without a serial connection.
    ///
    /// For each received frame: increments PACKET_COUNT, signals the
    /// display, formats a print line, and pushes it to PRINT_CH (drop if
    /// full).
    #[embassy_executor::task]
    async fn packet_handler_task() {
        use core::fmt::Write as _;

        loop {
            let frame = RADIO_CH.rx.receive().await;

            PACKET_COUNT.fetch_add(1, Ordering::Relaxed);
            DISPLAY_COUNT_SIGNAL.signal(());

            let mut line: PrintLine = heapless::String::new();
            let snr_db = frame.info.snr.as_centibels() / 10;
            let _ = write!(
                line,
                "\r\n[RX] rssi={} snr={} len={} data=",
                frame.info.rssi, snr_db, frame.info.len,
            );
            for &b in &frame.data[..frame.info.len.min(frame.data.len())] {
                let _ = write!(line, "{:02x}", b);
            }
            let _ = line.push_str("\r\n");
            let _ = PRINT_CH.try_send(line);
        }
    }

    /// Owns the e-paper SPI bus and pins. Renders the boot screen on
    /// startup, then waits for `DISPLAY_COUNT_SIGNAL` and re-renders with
    /// the latest count.
    ///
    /// Full refresh (with flashing) per update; partial refresh on this
    /// panel requires RED-RAM previous-frame tracking which is a separate
    /// change. `DISPLAY_THROTTLE` caps the visible refresh rate.
    #[embassy_executor::task]
    async fn display_task(
        mut spi:  Spim<'static>,
        mut cs:   Output<'static>,
        mut dc:   Output<'static>,
        mut rst:  Output<'static>,
        mut busy: Input<'static>,
    ) {
        use core::fmt::Write as _;
        use embedded_graphics::geometry::Point;
        use embedded_graphics::mono_font::ascii::FONT_10X20;
        use embedded_graphics::mono_font::MonoTextStyle;
        use embedded_graphics::pixelcolor::BinaryColor;
        use embedded_graphics::text::{Baseline, Text};
        use embedded_graphics::Drawable;
        use heapless::String;

        let sha   = env!("GIT_SHORT_SHA");
        let style = MonoTextStyle::new(&FONT_10X20, BinaryColor::On);

        // Fill `buf` with a frame containing the boot text and the supplied count.
        let mut buf = [0xFFu8; display::BUF_SIZE];
        let render = |buf: &mut [u8; display::BUF_SIZE], count: u32| {
            buf.fill(0xFF);  // all-white background
            let mut fb = display::EpdFb(buf);

            // Center each line by its glyph count.
            let center_x = |text: &str| (display::WIDTH as i32 - text.len() as i32 * FONT_W) / 2;

            let title = "UMSH bringup";
            let _ = Text::with_baseline(title, Point::new(center_x(title), TITLE_Y), style, Baseline::Top).draw(&mut fb);
            let _ = Text::with_baseline(sha,   Point::new(center_x(sha),   SHA_Y),   style, Baseline::Top).draw(&mut fb);

            let mut count_str: String<16> = String::new();
            let _ = write!(count_str, "RX: {}", count);
            let _ = Text::with_baseline(&count_str, Point::new(center_x(&count_str), COUNT_Y), style, Baseline::Top).draw(&mut fb);
        };

        // Initial boot screen (count = 0).
        render(&mut buf, 0);
        display::init(&mut spi, &mut cs, &mut dc, &mut rst, &mut busy).await;
        display::render(&mut spi, &mut cs, &mut dc, &mut busy, &buf).await;

        // Update loop. We deliberately do NOT reset the signal after the
        // throttle: any packet that fired during render+throttle stays
        // pending, so the next iteration starts immediately with the
        // newest count. Throttle still caps the refresh rate.
        loop {
            DISPLAY_COUNT_SIGNAL.wait().await;
            let count = PACKET_COUNT.load(Ordering::Relaxed);
            render(&mut buf, count);
            display::render(&mut spi, &mut cs, &mut dc, &mut busy, &buf).await;
            Timer::after(DISPLAY_THROTTLE).await;
        }
    }

    // ─── Main ────────────────────────────────────────────────────────────────

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

        // Peripheral power enable (P0.12). Must be high before display, LoRa,
        // or GNSS is addressed, including on battery power.
        let _peripheral_power = Output::new(p.P0_12, Level::High, OutputDrive::Standard);

        // WDT: 8 s timeout, petted by the heartbeat task every ~2 s.
        let mut wdt_config = WdtConfig::default();
        wdt_config.timeout_ticks = 32768 * 8;
        let (_wdt, [wdt_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, wdt_config).unwrap_or_else(|_| panic!("wdt"));

        // Pick up any panic message left by the previous boot.
        let mut prev_panic_buf = [0u8; 256];
        let prev_panic_len = {
            let mut slot = PanicSlot::new(super::panic::panic_region());
            if let Some(msg) = slot.read() {
                let n = msg.len().min(prev_panic_buf.len());
                prev_panic_buf[..n].copy_from_slice(&msg[..n]);
                slot.clear();
                n
            } else {
                0
            }
        };

        // ── E-paper display task ──────────────────────────────────────────────
        // P1.11 is the e-paper backlight on this module; drive it LOW
        // explicitly so leakage / external pullups can't turn it on.
        let _backlight = Output::new(p.P1_11, Level::Low, OutputDrive::Standard);
        {
            let mut cfg = SpimConfig::default();
            cfg.frequency = Frequency::M4;
            let disp_spi  = Spim::new(p.SPI2, Irqs, p.P0_31, p.P1_07, p.P0_29, cfg);
            let disp_cs   = Output::new(p.P0_30, Level::High, OutputDrive::Standard);
            let disp_dc   = Output::new(p.P0_28, Level::Low,  OutputDrive::Standard);
            let disp_rst  = Output::new(p.P0_02, Level::High, OutputDrive::Standard);
            let disp_busy = Input::new(p.P0_03, Pull::None);
            spawner.spawn(display_task(disp_spi, disp_cs, disp_dc, disp_rst, disp_busy).unwrap());
        }

        // ── SX1262 LoRa radio ────────────────────────────────────────────────
        // Pin assignment (T-Echo hardware, firmware-confirmed):
        //   SPI bus: SCK=P0.19, MOSI=P0.22, MISO=P0.23 (TWISPI1)
        //   CS=P0.24, RST=P0.25, BUSY=P0.17, DIO1=P0.20
        //   DIO2: internal RF switch (lora-phy sends SetDIO2AsRfSwitchCtrl).
        //   DIO3: 1.8 V TCXO (lora-phy sends SetDIO3AsTcxoCtrl).
        {
            let mut cfg = SpimConfig::default();
            // SX1262 datasheet §8.2: max SCK = 16 MHz, Mode 0 (CPOL=0, CPHA=0).
            cfg.frequency = Frequency::M16;
            let radio_bus = Spim::new(
                p.TWISPI1, Irqs,
                p.P0_19,  // SCK
                p.P0_23,  // MISO
                p.P0_22,  // MOSI
                cfg,
            );
            let radio_cs  = Output::new(p.P0_24, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();

            let radio_rst  = Output::new(p.P0_25, Level::High, OutputDrive::Standard);
            let radio_dio1 = Input::new(p.P0_20, Pull::None);
            let radio_busy = Input::new(p.P0_17, Pull::None);

            let iv = GenericSx126xInterfaceVariant::new(
                radio_rst,
                radio_dio1,
                radio_busy,
                None,   // rf_switch_rx: DIO2 wired internally on the T-Echo module
                None,   // rf_switch_tx: same
            ).unwrap();

            let lora_config = LoraConfig {
                chip: Sx1262,
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8),  // DIO3 → 1.8 V TCXO
                use_dcdc: true,   // T-Echo SX1262 module has DC-DC converter
                rx_boost: true,   // boosted LNA gain per MeshCore SX126X_RX_BOOSTED_GAIN=1
            };

            // enable_public_network=false → sync word 0x1424 (private),
            // matching MeshCore's RADIOLIB_SX126X_SYNC_WORD_PRIVATE = 0x12.
            let mut lora = LoRa::new(Sx126x::new(radio_spi, iv, lora_config), false, Delay)
                .await
                .unwrap_or_else(|_| panic!("radio init"));

            let (mdltn, rx_pkt, tx_pkt) = umsh_radio_sx126x::meshcore_us_params(&mut lora)
                .unwrap_or_else(|_| panic!("radio params"));

            spawner.spawn(radio_runner_task(lora, mdltn, rx_pkt, tx_pkt).unwrap());
        }

        // Drains RADIO_CH.rx, updates the count, signals the display, queues
        // print lines for USB. Runs independent of USB so the counter updates
        // even with no serial connected.
        spawner.spawn(packet_handler_task().unwrap());

        // ── USB stack + steady-state services ────────────────────────────────
        let led    = Output::new(p.P0_14, Level::High, OutputDrive::Standard);
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        let mut config = Config::new(0x16c0, 0x27dd);
        config.manufacturer      = Some("UMSH");
        config.product           = Some("T-Echo Bringup");
        config.serial_number     = Some("hello-techo");
        config.max_power         = 100;
        config.max_packet_size_0 = 64;

        static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static BOS_DESC:    StaticCell<[u8; 256]> = StaticCell::new();
        static MSOS_DESC:   StaticCell<[u8; 0]>   = StaticCell::new();
        static CONTROL_BUF: StaticCell<[u8; 64]>  = StaticCell::new();
        static STATE:       StaticCell<State>     = StaticCell::new();

        let mut builder = Builder::new(
            driver,
            config,
            CONFIG_DESC.init([0; 256]),
            BOS_DESC.init([0; 256]),
            MSOS_DESC.init([0; 0]),
            CONTROL_BUF.init([0; 64]),
        );

        let class = CdcAcmClass::new(&mut builder, STATE.init(State::new()), 64);
        let mut usb = builder.build();

        let (tx, raw_rx, ctrl) = class.split_with_control();
        let rx = CdcAcmRescue::new(raw_rx, ctrl);

        join3(
            usb.run(),
            run_echo(tx, rx, &prev_panic_buf[..prev_panic_len]),
            heartbeat(led, wdt_handle),
        ).await;
    }

    // ─── Heartbeat + WDT pet ─────────────────────────────────────────────────

    async fn heartbeat(mut led: Output<'static>, mut wdt: WatchdogHandle) -> ! {
        let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
        loop {
            wdt.pet();
            let decision = engine.tick(Instant::now().as_millis());
            // P0.14 is active-low: set_low() = LED on.
            if decision.on { led.set_low() } else { led.set_high() }
            Timer::at(Instant::from_millis(decision.next_deadline_ms)).await;
        }
    }

    // ─── USB-CDC: echo input, drain queued radio print lines ─────────────────
    //
    // 1200-baud touchless reset and Ctrl-C × 3 + "dfu" escape are baked into
    // CdcAcmRescue::read_packet and fire automatically on every read.
    //
    // Selects between (a) bytes from the host (echoed back) and (b) lines
    // from PRINT_CH (forwarded to host). Lines arrive pre-formatted from
    // packet_handler_task.

    async fn run_echo<'d, D: embassy_usb::driver::Driver<'d>>(
        mut tx: Sender<'d, D>,
        mut rx: CdcAcmRescue<'d, D>,
        prev_panic: &[u8],
    ) -> ! {
        let mut usb_buf = [0u8; 64];

        loop {
            rx.wait_connection().await;

            let _ = tx.write_packet(b"\r\nUMSH hello-techo ready.\r\n").await;
            let _ = tx.write_packet(b"Listening: MeshCore US 910.525MHz SF7 BW62.5\r\n").await;

            if !prev_panic.is_empty() {
                let _ = tx.write_packet(b"\r\n[PREV PANIC]: ").await;
                for chunk in prev_panic.chunks(64) {
                    if tx.write_packet(chunk).await.is_err() {
                        break;
                    }
                }
                let _ = tx.write_packet(b"\r\n").await;
            }

            'session: loop {
                match select(rx.read_packet(&mut usb_buf), PRINT_CH.receive()).await {
                    Either::First(Ok(0)) | Either::First(Err(_)) => break 'session,
                    Either::First(Ok(n)) => {
                        if tx.write_packet(&usb_buf[..n]).await.is_err() {
                            break 'session;
                        }
                    }
                    Either::Second(line) => {
                        for chunk in line.as_bytes().chunks(64) {
                            if tx.write_packet(chunk).await.is_err() {
                                break 'session;
                            }
                        }
                    }
                }
            }
        }
    }
}
