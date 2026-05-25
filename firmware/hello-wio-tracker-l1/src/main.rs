// Seeed Wio Tracker L1 / L1 Pro bringup firmware (Phase 2).
//
// Boot sequence:
//   1. Arm the watchdog (8 s timeout, petted by the heartbeat task).
//   2. Read any panic message left by the previous boot.
//   3. Initialize the SH1106 OLED (TWIM0, SDA=P0.06, SCL=P0.05) and
//      spawn the display task — shows boot screen immediately.
//   4. Run USB-CDC echo + heartbeat LED + USB stack concurrently.
//
// Task layout:
//   - main():         joins usb.run / run_echo / heartbeat
//   - display_task:   renders the OLED on boot and on count-change signals
//
// Safety primitives inherited from the BSP (umsh-bsp-nrf52840):
//   * Panic capture into reserved RAM, dumped over USB on the next boot.
//   * 1200-baud touchless reset and Ctrl-C × 3 + "dfu" escape to
//     bootloader (baked into CdcAcmRescue).
//   * Watchdog.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod panic;

#[cfg(target_os = "none")]
mod display;

#[cfg(target_os = "none")]
mod firmware {
    use core::sync::atomic::{AtomicU32, Ordering};

    use super::display;

    use embassy_executor::Spawner;
    use embassy_futures::join::join3;
    use embassy_futures::select::{Either, select};
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Level, Output, OutputDrive};
    use embassy_nrf::peripherals;
    use embassy_nrf::twim::{self, Config as TwimConfig, Twim};
    use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
    use embassy_nrf::usb::Driver;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::signal::Signal;
    use embassy_time::{Instant, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, Sender, State};
    use embassy_usb::{Builder, Config};
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_ux_tracker::led::{LedEngine, LedTimings};

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
        // TWIM0 / SPIM0 shared peripheral block. Embassy-nrf names it TWISPI0.
        TWISPI0     => embassy_nrf::twim::InterruptHandler<peripherals::TWISPI0>;
    });

    // ─── Shared state ────────────────────────────────────────────────────────

    /// Count of UMSH-authenticated packets (incremented in Phase 4).
    /// Wired up here so the display task can render "MAC: N" from day one.
    static PACKET_COUNT: AtomicU32 = AtomicU32::new(0);

    /// Fires whenever the MAC delivers a new authenticated packet, or on any
    /// other event that should refresh the display. Coalesces rapid bursts.
    static DISPLAY_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    // ─── Display task ─────────────────────────────────────────────────────────

    #[embassy_executor::task]
    async fn display_task(i2c: Twim<'static>) {
        use core::fmt::Write as _;
        use embedded_graphics::mono_font::ascii::FONT_6X10;
        use embedded_graphics::mono_font::MonoTextStyle;
        use embedded_graphics::pixelcolor::BinaryColor;
        use embedded_graphics::text::{Baseline, Text};
        use embedded_graphics::Drawable;
        use embedded_graphics::geometry::Point;
        use heapless::String;

        let mut oled = display::Sh1106::new(i2c);
        oled.init().await;

        let sha   = env!("GIT_SHORT_SHA");
        let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);

        let render = |fb: &mut display::Sh1106Fb, count: u32| {
            fb.clear();
            let _ = Text::with_baseline("UMSH bringup", Point::new(0, 0),  style, Baseline::Top).draw(fb);
            let _ = Text::with_baseline(sha,             Point::new(0, 16), style, Baseline::Top).draw(fb);
            let mut count_str: String<16> = String::new();
            let _ = write!(count_str, "MAC: {}", count);
            let _ = Text::with_baseline(&count_str,      Point::new(0, 32), style, Baseline::Top).draw(fb);
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

    // ─── Main ────────────────────────────────────────────────────────────────

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

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

        // ── SH1106 OLED display ───────────────────────────────────────────────
        // TWIM0 on SDA=P0.06, SCL=P0.05 (I²C address 0x3D).
        // embassy-nrf names the TWIM0/SPIM0 shared block TWISPI0.
        // Twim::new requires a static DMA scratch buffer; 256 B covers our
        // largest page write (1 control + 128 data = 129 B).
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
            if decision.on { led.set_high() } else { led.set_low() }
            Timer::at(Instant::from_millis(decision.next_deadline_ms)).await;
        }
    }

    // ─── USB-CDC echo ─────────────────────────────────────────────────────────

    async fn run_echo<'d, D: embassy_usb::driver::Driver<'d>>(
        mut tx: Sender<'d, D>,
        mut rx: CdcAcmRescue<'d, D>,
        prev_panic: &[u8],
    ) -> ! {
        let mut usb_buf = [0u8; 64];

        loop {
            rx.wait_connection().await;

            let _ = tx.write_packet(b"\r\nUMSH hello-wio-tracker-l1 ready.\r\n").await;
            let _ = tx.write_packet(b"Phase 2: SH1106 OLED display active.\r\n").await;

            if !prev_panic.is_empty() {
                let _ = tx.write_packet(b"\r\n[PREV PANIC]: ").await;
                for chunk in prev_panic.chunks(64) {
                    if tx.write_packet(chunk).await.is_err() { break; }
                }
                let _ = tx.write_packet(b"\r\n").await;
            }

            'session: loop {
                match select(rx.read_packet(&mut usb_buf), core::future::pending::<()>()).await {
                    Either::First(Ok(0)) | Either::First(Err(_)) => break 'session,
                    Either::First(Ok(n)) => {
                        if tx.write_packet(&usb_buf[..n]).await.is_err() { break 'session; }
                    }
                    Either::Second(()) => unreachable!(),
                }
            }
        }
    }
}
