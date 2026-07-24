// SenseCAP Solar Node P1 / P1-Pro bringup firmware — Phase 1.
//
// This is the *stripped* first-boot binary (see
// docs/firmware-plan-sensecap-solar-node-p1-pro.md, Phase 1). Its job is
// to prove the board comes up safely and to identify the LEDs / buttons
// whose colors and polarities the hardware reconstruction left open. It
// deliberately does NOT bring up the OLED (there is none), the SX1262
// radio (Phase 3), or the MAC / CLI (Phase 4 parity).
//
// What it does:
//   1. Initialize embassy-nrf, arm the 8 s watchdog.
//   2. Read + clear any panic message left by the previous boot.
//   3. Drive the board into a safe state:
//        - RADIO_RXEN (P0.05) LOW  — safety contract: RXEN low before any
//          radio work and until lora-phy owns it (no radio here yet).
//        - GNSS_ENABLE (P1.05) LOW — hold the L76K powered down.
//        - GNSS_RESET candidate (P1.03) is NEVER driven — left untouched.
//        - Battery-divider gate (P0.14) is NOT touched in Phase 1; the
//          gate polarity is verified in Phase 2 before we drive it.
//   4. Bring up USB-CDC with the CdcAcmRescue escape hatch + panic replay.
//   5. Blink LED_B (P0.19, the blue "breathing" LED) as a heartbeat, and
//      run an interactive GPIO/button identification session over CDC.
//
// Confirmed on hardware 2026-07-23:
//   - LED_A (P0.15) = white, active-high; LED_B (P0.19) = blue, active-high.
//   - USER_BUTTON (P1.01) and the "PWR" button (P1.07) are both active-low
//     on internal pull-ups (LOW pressed, HIGH released). PWR is a soft
//     momentary button — pressing it does not cut the MCU rail.
//
// Identification session (single-char commands, echoed back as reports):
//   '1'  toggle LED_A (P0.15) — the white user LED
//   '?'  help + current LED_A / button states
//   USER_BUTTON (P1.01) and PWR (P1.07) edges auto-report.
//
// The LED_B heartbeat runs in its own task (umsh_ux_tracker::led::LedEngine,
// a 20 ms pulse every 4 s), decoupled from the CDC RX loop so terminal
// activity can never affect its cadence. The watchdog is petted from that
// same heartbeat loop, exactly as on the other nRF52840 boards.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod panic;

#[cfg(target_os = "none")]
mod defmt_logger {
    // The BSP's Platform bundle transitively links lora-phy, which pulls
    // in defmt 0.3 and requires a global logger to link. This firmware
    // has no debug transport, so the logger is a no-op.
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
    use embassy_executor::Spawner;
    use embassy_futures::join::join;
    use embassy_futures::select::{Either3, select3};
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
    use embassy_nrf::peripherals;
    use embassy_nrf::usb::Driver;
    use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
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
    });

    // ─── Concrete USB driver type aliases ────────────────────────────────────
    type SolarUsbDriver = Driver<'static, HardwareVbusDetect>;
    type SolarSender = Sender<'static, SolarUsbDriver>;
    type SolarRescue = CdcAcmRescue<'static, SolarUsbDriver>;

    // ─── CDC output helper ───────────────────────────────────────────────────

    /// Write a line (with trailing CRLF) to the CDC sender in <=64-byte
    /// USB packets. Best-effort — drops on a closed endpoint.
    async fn write_line(tx: &mut SolarSender, s: &str) {
        for chunk in s.as_bytes().chunks(64) {
            let _ = tx.write_packet(chunk).await;
        }
        let _ = tx.write_packet(b"\r\n").await;
    }

    const HELP: &str = "\
SenseCAP Solar Node bringup (Phase 1) — GPIO identification\r
  1  toggle LED_A (P0.15, white user LED)\r
  ?  this help + current pin states\r
LED_B (P0.19, blue) blinks as the heartbeat.\r
USER_BUTTON (P1.01) and PWR (P1.07) edges auto-report.";

    /// Interactive GPIO/button identification over CDC. Owns LED_A, both
    /// buttons, and the CDC RX/TX endpoints. LED_B belongs to the
    /// independent heartbeat task.
    #[embassy_executor::task]
    async fn ident_task(
        mut tx: SolarSender,
        mut rx: SolarRescue,
        mut led_a: Output<'static>,
        mut btn1: Input<'static>,
        mut btn2: Input<'static>,
        prev_panic_buf: &'static [u8; 256],
        prev_panic_len: usize,
    ) {
        // Wait for the host to open the CDC port before writing the banner —
        // otherwise the writes silently vanish into a closed IN endpoint.
        rx.wait_connection().await;

        let sha = env!("GIT_SHORT_SHA");
        write_line(&mut tx, "").await;
        write_line(&mut tx, "UMSH SenseCAP Solar Node bringup (Phase 1)").await;
        write_line(&mut tx, sha).await;
        if prev_panic_len > 0 {
            write_line(&mut tx, "[PREV PANIC]:").await;
            if let Ok(s) = core::str::from_utf8(&prev_panic_buf[..prev_panic_len]) {
                write_line(&mut tx, s).await;
            }
        }
        write_line(&mut tx, HELP).await;

        let mut a_level = false; // LED_A assumed active-high (confirmed)
        led_a.set_low();

        let mut pkt = [0u8; 64];
        loop {
            // Re-arm on every iteration so a host re-attach is transparent and
            // a disconnected port doesn't busy-loop on read_packet returning 0.
            rx.wait_connection().await;

            match select3(
                rx.read_packet(&mut pkt),
                btn1.wait_for_any_edge(),
                btn2.wait_for_any_edge(),
            )
            .await
            {
                // CDC command bytes.
                Either3::First(res) => {
                    let n = match res {
                        Ok(0) | Err(_) => continue, // disconnect → re-arm at top
                        Ok(n) => n,
                    };
                    for &b in &pkt[..n] {
                        match b {
                            b'1' => {
                                a_level = !a_level;
                                if a_level {
                                    led_a.set_high();
                                } else {
                                    led_a.set_low();
                                }
                                report(&mut tx, "LED_A (P0.15)", a_level).await;
                            }
                            b'?' => {
                                write_line(&mut tx, HELP).await;
                                report(&mut tx, "LED_A (P0.15)", a_level).await;
                                report_button(&mut tx, "USER_BUTTON (P1.01)", &btn1).await;
                                report_button(&mut tx, "PWR         (P1.07)", &btn2).await;
                            }
                            b'\r' | b'\n' => {}
                            _ => {} // ignore other bytes
                        }
                    }
                }

                // Button edges: report the settled level. Pull-up inputs, so
                // LOW == pressed (active-low, confirmed).
                Either3::Second(()) => {
                    report_button(&mut tx, "USER_BUTTON (P1.01)", &btn1).await;
                }
                Either3::Third(()) => {
                    report_button(&mut tx, "PWR         (P1.07)", &btn2).await;
                }
            }
        }
    }

    async fn report(tx: &mut SolarSender, name: &str, level: bool) {
        write_line(tx, name).await;
        write_line(tx, if level { "  -> HIGH" } else { "  -> LOW" }).await;
    }

    async fn report_button(tx: &mut SolarSender, name: &str, btn: &Input<'static>) {
        write_line(tx, name).await;
        // Pull-up input: released == HIGH, pressed == LOW (active-low, confirmed).
        write_line(
            tx,
            if btn.is_low() {
                "  = LOW  (pressed)"
            } else {
                "  = HIGH (released)"
            },
        )
        .await;
    }

    // ─── Heartbeat (LED_B) + watchdog ────────────────────────────────────────

    /// Blinks LED_B (P0.19, blue "breathing" LED) via the shared LedEngine
    /// and pets the watchdog on the same schedule. Isolated from the CDC RX
    /// loop so terminal traffic can't perturb its cadence. Matches the
    /// heartbeat structure used on the other nRF52840 boards.
    async fn heartbeat(mut led_b: Output<'static>, mut wdt: WatchdogHandle) -> ! {
        let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
        loop {
            wdt.pet();
            let decision = engine.tick(Instant::now().as_millis());
            if decision.on {
                led_b.set_high();
            } else {
                led_b.set_low();
            }
            Timer::at(Instant::from_millis(decision.next_deadline_ms)).await;
        }
    }

    // ─── Main ────────────────────────────────────────────────────────────────

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

        let mut wdt_config = WdtConfig::default();
        wdt_config.timeout_ticks = 32768 * 8; // 8 s
        let (_wdt, [wdt_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, wdt_config).unwrap_or_else(|_| panic!("wdt"));

        // ── Board safe state ──────────────────────────────────────────────────
        // Held live for the lifetime of `main` (which never returns). RXEN low
        // per the safety contract; GNSS held powered down. The GNSS reset
        // candidate (P1.03) and battery-divider gate (P0.14) are deliberately
        // left untouched in Phase 1.
        let _radio_rxen = Output::new(p.P0_05, Level::Low, OutputDrive::Standard);
        let _gnss_enable = Output::new(p.P1_05, Level::Low, OutputDrive::Standard);

        // ── Previous-boot panic message ───────────────────────────────────────
        static PREV_PANIC_BUF: StaticCell<[u8; 256]> = StaticCell::new();
        let mut prev_panic_tmp = [0u8; 256];
        let prev_panic_len = {
            let mut slot = PanicSlot::new(super::panic::panic_region());
            if let Some(msg) = slot.read() {
                let n = msg.len().min(prev_panic_tmp.len());
                prev_panic_tmp[..n].copy_from_slice(&msg[..n]);
                slot.clear();
                n
            } else {
                0
            }
        };
        let prev_panic_buf: &'static [u8; 256] = PREV_PANIC_BUF.init(prev_panic_tmp);

        // ── User LEDs + buttons ───────────────────────────────────────────────
        let led_a = Output::new(p.P0_15, Level::Low, OutputDrive::Standard);
        let led_b = Output::new(p.P0_19, Level::Low, OutputDrive::Standard);
        let btn1 = Input::new(p.P1_01, Pull::Up);
        let btn2 = Input::new(p.P1_07, Pull::Up);

        // ── USB-CDC stack ─────────────────────────────────────────────────────
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        // USB IDs per the plan: VID 0x2886 / PID 0x0059 (Seeed XIAO family).
        let mut config = Config::new(0x2886, 0x0059);
        config.manufacturer = Some("UMSH");
        config.product = Some("SenseCAP Solar Node Bringup");
        config.serial_number = Some("companion-cli-sensecap-solar");
        config.max_power = 100;
        config.max_packet_size_0 = 64;

        static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static MSOS_DESC: StaticCell<[u8; 0]> = StaticCell::new();
        static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
        static STATE: StaticCell<State> = StaticCell::new();

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

        spawner
            .spawn(
                ident_task(tx, rx, led_a, btn1, btn2, prev_panic_buf, prev_panic_len).unwrap(),
            );

        join(usb.run(), heartbeat(led_b, wdt_handle)).await;
    }
}
