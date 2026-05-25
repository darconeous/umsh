// Seeed Wio Tracker L1 / L1 Pro bringup firmware (Phase 3).
//
// Boot sequence:
//   1. Arm the watchdog (8 s timeout, petted by the heartbeat task).
//   2. Read any panic message left by the previous boot.
//   3. Initialize the SH1106 OLED and spawn the display task.
//   4. Initialize the SX1262 LoRa radio (MeshCore US settings) with
//      the Wio Tracker's pin map and spawn the radio runner task.
//      RXEN (P1.08) is passed as rf_switch_rx to lora-phy, which drives
//      it HIGH in RX and LOW in TX automatically.
//   5. Spawn the packet handler task (raw RX counter + USB log).
//   6. Run USB-CDC echo + heartbeat LED + USB stack concurrently.
//
// Task layout (steady state):
//   - main():              joins usb.run / run_echo / heartbeat
//   - display_task:        renders the OLED on boot and count-change signals
//   - radio_runner_task:   owns lora_phy::LoRa, RX/TX state machine
//   - packet_handler_task: counts received frames, logs to USB, signals display
//
// Radio pin map (Wio Tracker L1 hardware reconstruction):
//   SPI:  SCK=P0.30, MISO=P0.03, MOSI=P0.28  (TWISPI1)
//   CS=P1.14, RST=P1.07, BUSY=P1.10, DIO1=P0.07
//   RXEN=P1.08 (external RX enable; passed to lora-phy as rf_switch_rx)
//   DIO2: internal RF switch (lora-phy SetDIO2AsRfSwitchCtrl, same as T-Echo)
//   DIO3: 1.8 V TCXO

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod panic;

#[cfg(target_os = "none")]
mod display;

// lora-phy 3.x unconditionally depends on defmt. Provide a no-op global
// logger so this binary links without any debug transport.
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
    use embassy_futures::select::{Either, select};
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
    use embassy_nrf::peripherals;
    use embassy_nrf::spim::{Config as SpimConfig, Frequency, Spim};
    use embassy_nrf::twim::{self, Config as TwimConfig, Twim};
    use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
    use embassy_nrf::usb::Driver;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::channel::Channel;
    use embassy_sync::signal::Signal;
    use embassy_time::{Delay, Instant, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, Sender, State};
    use embassy_usb::{Builder, Config};
    use embedded_hal_bus::spi::ExclusiveDevice;
    use lora_phy::iv::GenericSx126xInterfaceVariant;
    use lora_phy::mod_params::{Bandwidth, ModulationParams, PacketParams, SpreadingFactor};
    use lora_phy::sx126x::{Config as LoraConfig, Sx126x, Sx1262, TcxoCtrlVoltage};
    use lora_phy::LoRa;
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_ux_tracker::led::{LedEngine, LedTimings};

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
        // TWIM0/SPIM0 shared block → I²C for the SH1106 OLED.
        TWISPI0     => embassy_nrf::twim::InterruptHandler<peripherals::TWISPI0>;
        // TWIM1/SPIM1 shared block → SPI for the SX1262 LoRa radio.
        TWISPI1     => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI1>;
    });

    // ─── Configuration ───────────────────────────────────────────────────────

    const TX_POWER_DBM: i32 = 14;
    const PRINT_LINE_CAP: usize = 128;

    // ─── Concrete types ───────────────────────────────────────────────────────

    type RadioSpiBus = ExclusiveDevice<Spim<'static>, Output<'static>, Delay>;
    type RadioIv     = GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>;
    type RadioKind   = Sx126x<RadioSpiBus, RadioIv, Sx1262>;
    type LoraRadio   = LoRa<RadioKind, Delay>;

    // ─── Shared state ────────────────────────────────────────────────────────

    type RadioCh = umsh_radio_sx126x::Channels<ThreadModeRawMutex, 4, 2>;
    static RADIO_CH: RadioCh = RadioCh::new();

    static PACKET_COUNT: AtomicU32 = AtomicU32::new(0);
    static DISPLAY_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    type PrintLine = heapless::String<PRINT_LINE_CAP>;
    static PRINT_CH: Channel<ThreadModeRawMutex, PrintLine, 2> = Channel::new();

    // ─── Tasks ───────────────────────────────────────────────────────────────

    #[embassy_executor::task]
    async fn display_task(i2c: Twim<'static>) {
        use embedded_graphics::geometry::Point;
        use embedded_graphics::mono_font::ascii::FONT_6X10;
        use embedded_graphics::mono_font::MonoTextStyle;
        use embedded_graphics::pixelcolor::BinaryColor;
        use embedded_graphics::text::{Baseline, Text};
        use embedded_graphics::Drawable;
        use heapless::String;

        let mut oled = display::Sh1106::new(i2c);
        oled.init().await;

        let sha   = env!("GIT_SHORT_SHA");
        let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);

        let render = |fb: &mut display::Sh1106Fb, count: u32| {
            fb.clear();
            let _ = Text::with_baseline("UMSH bringup", Point::new(0, 0),  style, Baseline::Top).draw(fb);
            let _ = Text::with_baseline(sha,             Point::new(0, 16), style, Baseline::Top).draw(fb);
            let mut s: String<16> = String::new();
            let _ = core::fmt::write(&mut s, format_args!("RX: {}", count));
            let _ = Text::with_baseline(&s, Point::new(0, 32), style, Baseline::Top).draw(fb);
        };

        let mut fb = display::Sh1106Fb::new();
        render(&mut fb, 0);
        oled.flush(&fb).await;

        loop {
            DISPLAY_SIGNAL.wait().await;
            let count = PACKET_COUNT.load(Ordering::Relaxed);
            render(&mut fb, count);
            oled.flush(&fb).await;
        }
    }

    #[embassy_executor::task]
    async fn radio_runner_task(
        lora:   LoraRadio,
        mdltn:  ModulationParams,
        rx_pkt: PacketParams,
        tx_pkt: PacketParams,
    ) {
        umsh_radio_sx126x::runner(lora, &RADIO_CH, mdltn, rx_pkt, tx_pkt, TX_POWER_DBM).await;
    }

    #[embassy_executor::task]
    async fn packet_handler_task() {
        use core::fmt::Write as _;
        loop {
            let frame = RADIO_CH.rx.receive().await;
            PACKET_COUNT.fetch_add(1, Ordering::Relaxed);
            DISPLAY_SIGNAL.signal(());
            let mut line: PrintLine = heapless::String::new();
            let _ = write!(
                line,
                "\r\n[RX] rssi={} snr={} len={}\r\n",
                frame.info.rssi,
                frame.info.snr.as_centibels() / 10,
                frame.info.len,
            );
            let _ = PRINT_CH.try_send(line);
        }
    }

    // ─── Main ────────────────────────────────────────────────────────────────

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

        let mut wdt_config = WdtConfig::default();
        wdt_config.timeout_ticks = 32768 * 8;
        let (_wdt, [wdt_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, wdt_config).unwrap_or_else(|_| panic!("wdt"));

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

        // ── SH1106 OLED (TWIM0, SDA=P0.06, SCL=P0.05) ───────────────────────
        {
            static TWIM0_BUF: StaticCell<[u8; 256]> = StaticCell::new();
            let mut twim_cfg = TwimConfig::default();
            twim_cfg.frequency = twim::Frequency::K400;
            let i2c = Twim::new(
                p.TWISPI0, Irqs, p.P0_06, p.P0_05,
                twim_cfg, TWIM0_BUF.init([0; 256]),
            );
            spawner.spawn(display_task(i2c).unwrap());
        }

        // ── SX1262 LoRa radio (TWISPI1, MeshCore US settings) ────────────────
        // Pin map (Wio Tracker L1 hardware reconstruction):
        //   SPI: SCK=P0.30, MISO=P0.03, MOSI=P0.28 (TWISPI1)
        //   CS=P1.14, RST=P1.07, BUSY=P1.10, DIO1=P0.07
        //   RXEN=P1.08 passed as rf_switch_rx; lora-phy drives it HIGH in
        //   RX and LOW before TX, which is the correct polarity for an RX
        //   enable / LNA enable line. Drive LOW at boot so it is never
        //   asserted during radio init / calibration.
        //   DIO2: internal RF switch (lora-phy SetDIO2AsRfSwitchCtrl).
        //   DIO3: 1.8 V TCXO.
        let t_frame_ms = umsh_radio_sx126x::airtime_ms(
            SpreadingFactor::_7,
            Bandwidth::_62KHz,
            umsh_radio_sx126x::MAX_PAYLOAD,
        );
        {
            let mut spi_cfg = SpimConfig::default();
            spi_cfg.frequency = Frequency::M16;
            let radio_bus = Spim::new(
                p.TWISPI1, Irqs,
                p.P0_30,  // SCK
                p.P0_03,  // MISO
                p.P0_28,  // MOSI
                spi_cfg,
            );
            let radio_cs  = Output::new(p.P1_14, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();

            let radio_rst  = Output::new(p.P1_07, Level::High, OutputDrive::Standard);
            let radio_dio1 = Input::new(p.P0_07, Pull::None);
            let radio_busy = Input::new(p.P1_10, Pull::None);
            // RXEN: drive LOW at boot (safe during init/calibration), then
            // hand ownership to lora-phy as rf_switch_rx.
            let radio_rxen = Output::new(p.P1_08, Level::Low, OutputDrive::Standard);

            let iv = GenericSx126xInterfaceVariant::new(
                radio_rst,
                radio_dio1,
                radio_busy,
                Some(radio_rxen), // rf_switch_rx: lora-phy drives HIGH in RX, LOW in TX
                None,             // rf_switch_tx: no separate TX enable on Wio Tracker
            ).unwrap();

            let lora_config = LoraConfig {
                chip: Sx1262,
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8),
                use_dcdc: true,
                rx_boost: true,
            };

            let mut lora = LoRa::new(Sx126x::new(radio_spi, iv, lora_config), false, Delay)
                .await
                .unwrap_or_else(|_| panic!("radio init"));

            let (mdltn, rx_pkt, tx_pkt) = umsh_radio_sx126x::meshcore_us_params(&mut lora)
                .unwrap_or_else(|_| panic!("radio params"));

            spawner.spawn(radio_runner_task(lora, mdltn, rx_pkt, tx_pkt).unwrap());
        }

        let _ = t_frame_ms; // will be used in Phase 4 for Sx1262Radio airtime calc
        spawner.spawn(packet_handler_task().unwrap());

        // ── USB stack + steady-state services ────────────────────────────────
        let led    = Output::new(p.P1_01, Level::Low, OutputDrive::Standard);
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        let mut config = Config::new(0x2886, 0x1667);
        config.manufacturer      = Some("UMSH");
        config.product           = Some("Seeed Wio Tracker L1 Bringup");
        config.serial_number     = Some("hello-wio-tracker-l1");
        config.max_power         = 100;
        config.max_packet_size_0 = 64;

        static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static BOS_DESC:    StaticCell<[u8; 256]> = StaticCell::new();
        static MSOS_DESC:   StaticCell<[u8; 0]>   = StaticCell::new();
        static CONTROL_BUF: StaticCell<[u8; 64]>  = StaticCell::new();
        static STATE:       StaticCell<State>      = StaticCell::new();

        let mut builder = Builder::new(
            driver, config,
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

    // ─── Heartbeat ────────────────────────────────────────────────────────────

    async fn heartbeat(mut led: Output<'static>, mut wdt: WatchdogHandle) -> ! {
        let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
        loop {
            wdt.pet();
            let decision = engine.tick(Instant::now().as_millis());
            if decision.on { led.set_high() } else { led.set_low() }
            Timer::at(Instant::from_millis(decision.next_deadline_ms)).await;
        }
    }

    // ─── USB-CDC echo + radio log drain ───────────────────────────────────────

    async fn run_echo<'d, D: embassy_usb::driver::Driver<'d>>(
        mut tx: Sender<'d, D>,
        mut rx: CdcAcmRescue<'d, D>,
        prev_panic: &[u8],
    ) -> ! {
        let mut usb_buf = [0u8; 64];

        loop {
            rx.wait_connection().await;

            let _ = tx.write_packet(b"\r\nUMSH hello-wio-tracker-l1 ready.\r\n").await;
            let _ = tx.write_packet(b"Phase 3: listening MeshCore US 910.525MHz SF7 BW62.5\r\n").await;

            if !prev_panic.is_empty() {
                let _ = tx.write_packet(b"\r\n[PREV PANIC]: ").await;
                for chunk in prev_panic.chunks(64) {
                    if tx.write_packet(chunk).await.is_err() { break; }
                }
                let _ = tx.write_packet(b"\r\n").await;
            }

            'session: loop {
                match select(rx.read_packet(&mut usb_buf), PRINT_CH.receive()).await {
                    Either::First(Ok(0)) | Either::First(Err(_)) => break 'session,
                    Either::First(Ok(n)) => {
                        if tx.write_packet(&usb_buf[..n]).await.is_err() { break 'session; }
                    }
                    Either::Second(line) => {
                        for chunk in line.as_bytes().chunks(64) {
                            if tx.write_packet(chunk).await.is_err() { break 'session; }
                        }
                    }
                }
            }
        }
    }
}
