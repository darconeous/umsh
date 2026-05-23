// LilyGO T-Echo bringup firmware.
//
// Boot sequence:
//   1. Bring up peripheral rail (P0.12 HIGH).
//   2. Arm the watchdog (8 s timeout, petted by the heartbeat task).
//   3. Render the e-paper boot screen — "UMSH bringup" + git short SHA —
//      and put the panel in deep sleep.
//   4. Run USB-CDC echo and the heartbeat LED concurrently for the rest
//      of the session.
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

#[cfg(target_os = "none")]
mod firmware {
    use embassy_executor::Spawner;
    use embassy_futures::join::join3;
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Level, Output, OutputDrive};
    use embassy_nrf::peripherals;
    use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
    use embassy_nrf::usb::Driver;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_time::{Instant, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, Sender, State};
    use embassy_usb::{Builder, Config};
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_ux_tracker::led::{LedEngine, LedTimings};

    bind_interrupts!(struct Irqs {
        USBD                    => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER             => embassy_nrf::usb::vbus_detect::InterruptHandler;
        SPI2                    => embassy_nrf::spim::InterruptHandler<peripherals::SPI2>;
    });

    // ─── E-paper (SSD1681 / GDEH0154D67) ──────────────────────────────────
    //
    // Init sequence matches GxEPD2_154_D67 byte-for-byte. Three things that
    // cost us a session to find:
    //   - Cmd 0x01 third byte must be 0x00 (GD=0). 0x01 mirrors the panel.
    //   - Cmd 0x11 (data entry) must be 0x03 (X+, Y+). 0x01 walks the wrong
    //     direction off the first row.
    //   - No pre-RAM load cycle. Activating with 0xB1 before writing RAM
    //     ends in "disable clock" and silently kills subsequent 0x24 data.
    //     The only activation is the post-RAM 0xF7 refresh.
    mod display {
        use embassy_nrf::gpio::{Input, Output};
        use embassy_nrf::spim::Spim;
        use embassy_time::{Duration, Timer};
        use embedded_graphics::draw_target::DrawTarget;
        use embedded_graphics::geometry::{OriginDimensions, Point, Size};
        use embedded_graphics::pixelcolor::BinaryColor;
        use embedded_graphics::prelude::Pixel;

        pub const WIDTH:  usize = 200;
        pub const HEIGHT: usize = 200;
        pub const BYTES_PER_ROW: usize = WIDTH / 8;
        pub const BUF_SIZE: usize = BYTES_PER_ROW * HEIGHT;

        /// Hardware-reset, software-reset, and load all SSD1681 control
        /// registers. After this returns the panel is ready to accept RAM
        /// writes via `render()`.
        pub async fn init(
            spi:  &mut Spim<'_>,
            cs:   &mut Output<'_>,
            dc:   &mut Output<'_>,
            rst:  &mut Output<'_>,
            busy: &mut Input<'_>,
        ) {
            Timer::after(Duration::from_millis(10)).await;
            rst.set_low();
            Timer::after(Duration::from_millis(10)).await;
            rst.set_high();
            wait_idle(busy).await;

            cmd(spi, cs, dc, 0x12, &[]).await;          // SW reset
            wait_idle(busy).await;

            cmd(spi, cs, dc, 0x01, &[0xC7, 0x00, 0x00]).await;        // driver output: MUX=199
            cmd(spi, cs, dc, 0x3C, &[0x05]).await;                    // border = VSS
            cmd(spi, cs, dc, 0x18, &[0x80]).await;                    // built-in temp sensor
            cmd(spi, cs, dc, 0x11, &[0x03]).await;                    // data entry: X+, Y+
            cmd(spi, cs, dc, 0x44, &[0x00, 0x18]).await;              // X window 0..24
            cmd(spi, cs, dc, 0x45, &[0x00, 0x00, 0xC7, 0x00]).await;  // Y window 0..199
        }

        /// Write `pixels` into both B/W RAM and RED RAM, trigger a full
        /// refresh, and wait for the panel to complete (~2 s).
        ///
        /// RED RAM is cleared with the same buffer because Meshtastic (or
        /// any prior firmware) may have left content in it that would
        /// otherwise combine with our B/W frame.
        pub async fn render(
            spi:    &mut Spim<'_>,
            cs:     &mut Output<'_>,
            dc:     &mut Output<'_>,
            busy:   &mut Input<'_>,
            pixels: &[u8],
        ) {
            cmd(spi, cs, dc, 0x4E, &[0x00]).await;
            cmd(spi, cs, dc, 0x4F, &[0x00, 0x00]).await;
            write_ram(spi, cs, dc, 0x24, pixels).await;
            cmd(spi, cs, dc, 0x4E, &[0x00]).await;
            cmd(spi, cs, dc, 0x4F, &[0x00, 0x00]).await;
            write_ram(spi, cs, dc, 0x26, pixels).await;
            cmd(spi, cs, dc, 0x22, &[0xF7]).await;
            cmd(spi, cs, dc, 0x20, &[]).await;
            wait_idle(busy).await;
        }

        /// Deep Sleep Mode 1: lowest power, RAM retained, hardware reset
        /// required to wake. Use this once the boot frame is on the glass.
        pub async fn sleep(spi: &mut Spim<'_>, cs: &mut Output<'_>, dc: &mut Output<'_>) {
            cmd(spi, cs, dc, 0x10, &[0x01]).await;
        }

        /// Wait, suspended via GPIOTE, until BUSY goes low (panel idle).
        async fn wait_idle(busy: &mut Input<'_>) {
            busy.wait_for_low().await;
        }

        /// Send one SSD1681 command byte plus optional small data payload.
        /// All buffers are copied to the stack first — nRF52840 EasyDMA can
        /// only read SRAM, and `&[...]` literals in release builds may live
        /// in flash.
        async fn cmd(
            spi:     &mut Spim<'_>,
            cs:      &mut Output<'_>,
            dc:      &mut Output<'_>,
            command: u8,
            data:    &[u8],
        ) {
            let cmd_buf = [command];
            let mut data_buf = [0u8; 8];
            let n = data.len().min(data_buf.len());
            data_buf[..n].copy_from_slice(&data[..n]);

            cs.set_low();
            dc.set_low();
            let _ = spi.write(&cmd_buf).await;
            if n > 0 {
                dc.set_high();
                let _ = spi.write(&data_buf[..n]).await;
            }
            cs.set_high();
        }

        /// Write a large pixel payload to the addressed RAM (`cmd_byte` =
        /// 0x24 for B/W, 0x26 for RED). Single DMA burst — SPIM2's TXD
        /// MAXCNT comfortably covers 5000 bytes despite the misleading
        /// 8-bit-only rumor for SPIM0/1.
        async fn write_ram(
            spi: &mut Spim<'_>,
            cs:  &mut Output<'_>,
            dc:  &mut Output<'_>,
            cmd_byte: u8,
            pixels: &[u8],
        ) {
            let cmd_buf = [cmd_byte];
            cs.set_low();
            dc.set_low();
            let _ = spi.write(&cmd_buf).await;
            dc.set_high();
            let _ = spi.write(pixels).await;
            cs.set_high();
        }

        /// `embedded-graphics::DrawTarget` over a packed-MSB B/W frame buffer.
        ///
        /// Layout: bit 7 of byte 0 is pixel (0,0). 1 = white paper, 0 = black
        /// ink. `BinaryColor::On` is treated as ink (clears the bit), which
        /// matches the e-paper convention used by `epd-waveshare` and friends.
        pub struct EpdFb<'a>(pub &'a mut [u8]);

        impl DrawTarget for EpdFb<'_> {
            type Color = BinaryColor;
            type Error = core::convert::Infallible;

            fn draw_iter<I>(&mut self, pixels: I) -> Result<(), core::convert::Infallible>
            where
                I: IntoIterator<Item = Pixel<BinaryColor>>,
            {
                for Pixel(Point { x, y }, color) in pixels {
                    if (0..WIDTH as i32).contains(&x) && (0..HEIGHT as i32).contains(&y) {
                        // T-Echo mounts the panel 90° CCW from the chip's
                        // natural scan order. GxEPD2 corrects this with
                        // rotation-3: swap axes, then flip the new y.
                        // chip_x = logical_y,  chip_y = (HEIGHT-1) - logical_x
                        let cx = y as usize;
                        let cy = HEIGHT - 1 - x as usize;
                        let idx = cy * BYTES_PER_ROW + cx / 8;
                        let bit = 7 - (cx % 8);
                        if color.is_on() {
                            self.0[idx] &= !(1 << bit);
                        } else {
                            self.0[idx] |=  1 << bit;
                        }
                    }
                }
                Ok(())
            }
        }

        impl OriginDimensions for EpdFb<'_> {
            fn size(&self) -> Size { Size::new(WIDTH as u32, HEIGHT as u32) }
        }
    }

    // ─── Main ─────────────────────────────────────────────────────────────

    #[embassy_executor::main]
    async fn main(_spawner: Spawner) {
        use embassy_nrf::gpio::{Input, Pull};
        use embassy_nrf::spim::{Config as SpimConfig, Frequency, Spim};
        use embedded_graphics::geometry::Point;
        use embedded_graphics::mono_font::ascii::FONT_10X20;
        use embedded_graphics::mono_font::MonoTextStyle;
        use embedded_graphics::pixelcolor::BinaryColor;
        use embedded_graphics::text::{Baseline, Text};
        use embedded_graphics::Drawable;

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

        // ── E-paper boot screen ───────────────────────────────────────────
        // Runs synchronously before USB so the ~2-second refresh doesn't
        // drop the host connection mid-handshake.
        //
        // P1.11 is the e-paper backlight on this module; we drive it LOW
        // explicitly so leakage / external pullups can't turn it on.
        let _backlight = Output::new(p.P1_11, Level::Low, OutputDrive::Standard);
        {
            let mut spi_config = SpimConfig::default();
            spi_config.frequency = Frequency::M4;
            let mut spi = Spim::new(p.SPI2, Irqs, p.P0_31, p.P1_07, p.P0_29, spi_config);
            let mut cs   = Output::new(p.P0_30, Level::High, OutputDrive::Standard);
            let mut dc   = Output::new(p.P0_28, Level::Low,  OutputDrive::Standard);
            let mut rst  = Output::new(p.P0_02, Level::High, OutputDrive::Standard);
            let mut busy = Input::new(p.P0_03, Pull::None);

            // White frame, draw black text on top.
            let mut buf = [0xFFu8; display::BUF_SIZE];
            {
                let mut fb = display::EpdFb(&mut buf);
                let style = MonoTextStyle::new(&FONT_10X20, BinaryColor::On);
                let title = "UMSH bringup";
                let sha   = env!("GIT_SHORT_SHA");
                // FONT_10X20 is 10 px wide per glyph.
                let title_x = (display::WIDTH as i32 - title.len() as i32 * 10) / 2;
                let sha_x   = (display::WIDTH as i32 - sha.len()   as i32 * 10) / 2;
                let _ = Text::with_baseline(title, Point::new(title_x, 80),  style, Baseline::Top).draw(&mut fb);
                let _ = Text::with_baseline(sha,   Point::new(sha_x,   110), style, Baseline::Top).draw(&mut fb);
            }

            display::init(&mut spi, &mut cs, &mut dc, &mut rst, &mut busy).await;
            display::render(&mut spi, &mut cs, &mut dc, &mut busy, &buf).await;
            display::sleep(&mut spi, &mut cs, &mut dc).await;
        }

        // ── Steady-state services ────────────────────────────────────────
        let led    = Output::new(p.P0_14, Level::High, OutputDrive::Standard);
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        let mut config = Config::new(0x16c0, 0x27dd);
        config.manufacturer     = Some("UMSH");
        config.product          = Some("T-Echo Bringup");
        config.serial_number    = Some("hello-techo");
        config.max_power        = 100;
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

    // ─── Heartbeat + WDT pet ──────────────────────────────────────────────

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

    // ─── USB-CDC echo ─────────────────────────────────────────────────────
    //
    // 1200-baud touchless reset and Ctrl-C × 3 + "dfu" escape are baked
    // into CdcAcmRescue::read_packet and fire automatically on every read.

    async fn run_echo<'d, D: embassy_usb::driver::Driver<'d>>(
        mut tx: Sender<'d, D>,
        mut rx: CdcAcmRescue<'d, D>,
        prev_panic: &[u8],
    ) -> ! {
        let mut buf = [0u8; 64];

        loop {
            rx.wait_connection().await;

            let _ = tx
                .write_packet(b"\r\nUMSH hello-techo: USB-CDC echo ready.\r\n")
                .await;

            if !prev_panic.is_empty() {
                let _ = tx.write_packet(b"\r\n[PREV PANIC]: ").await;
                for chunk in prev_panic.chunks(64) {
                    if tx.write_packet(chunk).await.is_err() {
                        break;
                    }
                }
                let _ = tx.write_packet(b"\r\n").await;
            }

            'echo: loop {
                match rx.read_packet(&mut buf).await {
                    Ok(0) | Err(_) => break 'echo,
                    Ok(n) => {
                        if tx.write_packet(&buf[..n]).await.is_err() {
                            break 'echo;
                        }
                    }
                }
            }
        }
    }
}
