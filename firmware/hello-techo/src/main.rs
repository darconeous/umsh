// LilyGO T-Echo bringup firmware — Phase 1: USB-CDC echo with
// concurrent heartbeat LED.
//
// Builds on the Phase 1 baseline (embassy 0.10 + executor 0.10 + time
// 0.5 with tick-hz-32_768 + cortex-m-rt set-vtor + PIN_POWER_EN high).
//
// What this does:
//
//   * Heartbeat task: blue LED (P0.14, active-low) blinks ~50 ms ON
//     every 2 s, forever. Visual proof the firmware is alive.
//
//   * USB-CDC echo task: enumerates as a USB CDC ACM serial device
//     (UMSH / T-Echo Bringup, VID 0x16c0, PID 0x27dd) and echoes
//     every byte received back to the host.
//
// Both run concurrently via embassy_futures::join.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {
    // Host placeholder. This binary only runs on the embedded target.
}

#[cfg(target_os = "none")]
mod firmware {
    use embassy_executor::Spawner;
    use embassy_futures::join::join3;
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Level, Output, OutputDrive};
    use embassy_nrf::peripherals;
    use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
    use embassy_nrf::usb::Driver;
    use embassy_time::{Duration, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
    use embassy_usb::{Builder, Config};
    use panic_halt as _;
    use static_cell::StaticCell;

    bind_interrupts!(struct Irqs {
        USBD => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
    });

    #[embassy_executor::main]
    async fn main(_spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

        // Peripheral power enable (P0.12).
        let _peripheral_power = Output::new(p.P0_12, Level::High, OutputDrive::Standard);

        // Blue LED on P0.14, active-low.
        let led = Output::new(p.P0_14, Level::High, OutputDrive::Standard);

        // USB driver. HardwareVbusDetect uses the nRF52's POWER block
        // to track VBUS so the device only enumerates while the host
        // is actually powering us.
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        // ─── USB descriptors / config ──────────────────────────────
        //
        // VID 0x16c0 / PID 0x27dd is the FOSS-friendly VOTI assignment
        // for CDC ACM devices. The Manufacturer + Product strings are
        // what shows up in `ioreg` / `lsusb` so we can tell at a
        // glance that this is our firmware.
        let mut config = Config::new(0x16c0, 0x27dd);
        config.manufacturer = Some("UMSH");
        config.product = Some("T-Echo Bringup");
        config.serial_number = Some("hello-techo");
        config.max_power = 100;
        config.max_packet_size_0 = 64;

        // embassy-usb's Builder takes &'static mut borrows of these
        // buffers. StaticCell is the standard embedded pattern for
        // turning a static into a one-shot &'static mut without
        // user-side unsafe.
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

        let mut class = CdcAcmClass::new(&mut builder, state, 64);
        let mut usb = builder.build();

        let usb_fut = usb.run();
        let echo_fut = echo(&mut class);
        let blink_fut = heartbeat(led);

        join3(usb_fut, echo_fut, blink_fut).await;
    }

    async fn heartbeat(mut led: Output<'static>) -> ! {
        loop {
            led.set_low();
            Timer::after(Duration::from_millis(50)).await;
            led.set_high();
            Timer::after(Duration::from_millis(2000)).await;
        }
    }

    async fn echo<'d, D: embassy_usb::driver::Driver<'d>>(
        class: &mut CdcAcmClass<'d, D>,
    ) -> ! {
        let mut buf = [0u8; 64];
        loop {
            class.wait_connection().await;
            let _ = class
                .write_packet(b"\r\nUMSH hello-techo: USB-CDC echo ready.\r\n")
                .await;
            loop {
                match class.read_packet(&mut buf).await {
                    Ok(n) if n == 0 => break,
                    Ok(n) => {
                        if class.write_packet(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}
