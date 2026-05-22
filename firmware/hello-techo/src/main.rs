// LilyGO T-Echo bringup firmware — Phase 2: safety primitives.
//
// Builds on Phase 1 (embassy 0.10 + USB-CDC echo + heartbeat LED).
//
// What this adds:
//
//   * WDT (8-second timeout). The heartbeat task pets it every ~2 s.
//     If firmware wedges, the device resets.
//
//   * Panic capture. A custom #[panic_handler] (in panic.rs) writes the
//     panic message to a .uninit RAM region (survives warm reset) and
//     triggers a system reset. On the next boot, the message is printed
//     over USB-CDC before any echo traffic.
//
//   * Touchless reset (1200-baud). When the host opens the CDC port at
//     1200 baud and drops DTR, the firmware calls enter_dfu_uf2()
//     (GPREGRET=0x57). The bootloader exposes both a CDC port and the
//     TECHOBOOT UF2 mass-storage drive, which the MeshCore web flasher,
//     adafruit-nrfutil, and direct UF2 copy all use.
//
//   * Escape-sequence DFU. Receiving Ctrl-C Ctrl-C Ctrl-C dfu\r in the
//     CDC data stream also calls enter_dfu_uf2(), independently of
//     the host baud setting, so a human at a terminal can always force DFU.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {
    // Host placeholder. This binary only runs on the embedded target.
}

// The #[panic_handler] must live in the binary crate. Everything else
// (SyncNoinit, SliceWriter, PanicSlot) lives in umsh-bsp-nrf52840.
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
    use embassy_time::{Duration, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, Sender, State};
    use embassy_usb::{Builder, Config};
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;

    bind_interrupts!(struct Irqs {
        USBD => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
    });

    // ─── Main ─────────────────────────────────────────────────────────────

    #[embassy_executor::main]
    async fn main(_spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

        // Peripheral power enable (P0.12). Must be high before any peripheral
        // (display, LoRa, GNSS) is addressed, including on battery power.
        let _peripheral_power = Output::new(p.P0_12, Level::High, OutputDrive::Standard);

        // WDT: 8-second timeout. The heartbeat task pets it every ~2 s.
        // Once started the WDT cannot be stopped; it survives soft resets.
        let mut wdt_config = WdtConfig::default();
        wdt_config.timeout_ticks = 32768 * 8;
        let (_wdt, [wdt_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, wdt_config).unwrap_or_else(|_| panic!("wdt"));

        // Check for a panic message left by the previous boot.
        // Read into a fixed stack buffer, then clear the slot so it only
        // appears once. The message is sent to the host after USB connects.
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

        // Blue LED on P0.14, active-low.
        let led = Output::new(p.P0_14, Level::High, OutputDrive::Standard);

        // USB driver backed by the hardware VBUS detector.
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        let mut config = Config::new(0x16c0, 0x27dd);
        config.manufacturer = Some("UMSH");
        config.product = Some("T-Echo Bringup");
        config.serial_number = Some("hello-techo");
        config.max_power = 100;
        config.max_packet_size_0 = 64;

        static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static MSOS_DESC: StaticCell<[u8; 0]> = StaticCell::new();
        static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
        static STATE: StaticCell<State> = StaticCell::new();

        let config_desc = CONFIG_DESC.init([0; 256]);
        let bos_desc = BOS_DESC.init([0; 256]);
        let msos_desc = MSOS_DESC.init([0; 0]);
        let control_buf = CONTROL_BUF.init([0; 64]);
        let state = STATE.init(State::new());

        let mut builder = Builder::new(
            driver,
            config,
            config_desc,
            bos_desc,
            msos_desc,
            control_buf,
        );

        let class = CdcAcmClass::new(&mut builder, state, 64);
        let mut usb = builder.build();

        // Split the class so the application sees only `tx` (raw Sender)
        // and `rx` (the rescue-protected wrapper). The rescue wrapper
        // owns the Receiver + ControlChanged internally, so the
        // application cannot bypass the 1200-baud touchless reset or
        // the magic escape-sequence DFU paths — they fire automatically
        // on every read.
        let (tx, raw_rx, ctrl) = class.split_with_control();
        let rx = CdcAcmRescue::new(raw_rx, ctrl);

        let usb_fut = usb.run();
        let echo_fut = run_echo(tx, rx, &prev_panic_buf[..prev_panic_len]);
        let blink_fut = heartbeat(led, wdt_handle);

        join3(usb_fut, echo_fut, blink_fut).await;
    }

    // ─── Heartbeat + WDT pet ──────────────────────────────────────────────

    async fn heartbeat(mut led: Output<'static>, mut wdt: WatchdogHandle) -> ! {
        loop {
            wdt.pet();
            led.set_low();
            Timer::after(Duration::from_millis(50)).await;
            led.set_high();
            Timer::after(Duration::from_millis(2000)).await;
        }
    }

    // ─── USB-CDC echo ─────────────────────────────────────────────────────
    //
    // Note: this looks like a plain CDC echo. The 1200-baud touchless reset
    // and the Ctrl-C-x3 + dfu escape sequence are NOT implemented here —
    // they are baked into CdcAcmRescue::read_packet and fire automatically
    // on every read, by construction. A future developer replacing this
    // with a real CLI does not need to (and cannot) re-implement them.

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
