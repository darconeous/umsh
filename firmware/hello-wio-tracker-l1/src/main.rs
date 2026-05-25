// Seeed Wio Tracker L1 / L1 Pro bringup firmware (Phase 1).
//
// Boot sequence:
//   1. Arm the watchdog (8 s timeout, petted by the heartbeat task).
//   2. Read any panic message left by the previous boot.
//   3. Run USB-CDC echo + heartbeat LED + USB stack concurrently.
//
// Task layout:
//   - main():     joins usb.run / run_echo / heartbeat
//
// Safety primitives inherited from the BSP (umsh-bsp-nrf52840):
//   * Panic capture into reserved RAM, dumped over USB on the next boot.
//   * 1200-baud touchless reset and Ctrl-C × 3 + "dfu" escape to
//     bootloader (baked into CdcAcmRescue).
//   * Watchdog.
//
// What's intentionally absent compared to hello-techo at the same phase:
//   * No PIN_POWER_EN — the Wio Tracker has no equivalent board-wide
//     peripheral-power switch. Peripherals are always powered while
//     the board is on (which the physical power switch controls).
//
// Hardware notes:
//   * User LED (D11 / P1.01) is active-high (T-Echo's blue LED on
//     P0.14 was active-low). `set_high()` lights it.
//   * USB VID:PID is the Seeed-assigned 0x2886:0x1667. The CDC port
//     enumerates as "Seeed Wio Tracker L1 Bringup".

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
    use embassy_futures::select::{Either, select};
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
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
    });

    // ─── Main ────────────────────────────────────────────────────────────────

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        let _ = spawner; // unused in Phase 1; no spawned tasks yet
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

        // ── USB stack + steady-state services ────────────────────────────────
        // User LED on D11 / P1.01 (active-high). Start LOW so the LED is
        // off until the heartbeat engine begins.
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
            // P1.01 is active-high: set_high() = LED on.
            if decision.on { led.set_high() } else { led.set_low() }
            Timer::at(Instant::from_millis(decision.next_deadline_ms)).await;
        }
    }

    // ─── USB-CDC echo ───────────────────────────────────────────────────────
    //
    // 1200-baud touchless reset and Ctrl-C × 3 + "dfu" escape are baked
    // into CdcAcmRescue::read_packet and fire automatically on every read.

    async fn run_echo<'d, D: embassy_usb::driver::Driver<'d>>(
        mut tx: Sender<'d, D>,
        mut rx: CdcAcmRescue<'d, D>,
        prev_panic: &[u8],
    ) -> ! {
        let mut usb_buf = [0u8; 64];

        loop {
            rx.wait_connection().await;

            let _ = tx.write_packet(b"\r\nUMSH hello-wio-tracker-l1 ready.\r\n").await;
            let _ = tx.write_packet(b"Phase 1: USB-CDC echo + heartbeat + safety primitives.\r\n").await;

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
                // Phase 1 has no radio / MAC, so this is a pure echo loop
                // — no PRINT_CH receive side yet.
                match select(rx.read_packet(&mut usb_buf), core::future::pending::<()>()).await {
                    Either::First(Ok(0)) | Either::First(Err(_)) => break 'session,
                    Either::First(Ok(n)) => {
                        if tx.write_packet(&usb_buf[..n]).await.is_err() {
                            break 'session;
                        }
                    }
                    Either::Second(()) => unreachable!(),
                }
            }
        }
    }
}
