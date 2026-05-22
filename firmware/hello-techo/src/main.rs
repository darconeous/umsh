// LilyGO T-Echo bringup firmware — Phase 1: embassy + heartbeat LED.
//
// Foundational features we've nailed down in this build:
//
//   * embassy stack on current versions (embassy-nrf 0.10,
//     embassy-executor 0.10 + `embassy-time-driver` feature,
//     embassy-time 0.5 + `tick-hz-32_768`). Mixing 0.4 and 0.5
//     embassy-time pulled two copies of the time-base into the
//     binary and broke `Timer::after`; pinning everything to one
//     major series fixes it.
//
//   * cortex-m-rt with the `set-vtor` feature. The Adafruit nRF52
//     UF2 bootloader hands off to the app via the MBR, but VTOR is
//     not reliably pointing at *our* vector table on first
//     instruction. Without set-vtor the first interrupt that fires
//     (RTC1's compare match driving `Timer::after`) dispatches to
//     the wrong handler and the chip resets. With set-vtor enabled
//     cortex-m-rt fixes VTOR up at startup and interrupts go where
//     they should.
//
//   * PIN_POWER_EN (P0.12) driven high so the peripheral rail (LED,
//     e-paper, GNSS, LoRa, sensors) is energized on battery as well
//     as on VBUS. Without driving it explicitly, the LED only works
//     while USB is plugged in.
//
//   * LFCLK source = InternalRC. Reliable to start without a
//     32.768 kHz external crystal; the time driver only needs
//     low-rate clock accuracy that the RC easily provides for a
//     bringup firmware.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {
    // Host placeholder. This binary only runs on the embedded target.
}

#[cfg(target_os = "none")]
mod firmware {
    use embassy_executor::Spawner;
    use embassy_nrf::gpio::{Level, Output, OutputDrive};
    use embassy_time::{Duration, Timer};
    use panic_halt as _;

    #[embassy_executor::main]
    async fn main(_spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

        // Peripheral power enable (P0.12). High = peripherals powered;
        // schematic-equivalent to VBUS being present. Drive high before
        // anything else so the LED (and later e-paper / GNSS / LoRa)
        // works on battery too. Held for the lifetime of the binary
        // because we deliberately don't enter low-power modes yet.
        let _peripheral_power = Output::new(p.P0_12, Level::High, OutputDrive::Standard);

        // Blue LED on P0.14, active-low. Start off (high).
        let mut led = Output::new(p.P0_14, Level::High, OutputDrive::Standard);

        // 50 ms-on / 2 s-off heartbeat. Clearly visible, very low
        // duty cycle so it's friendly on the battery.
        loop {
            led.set_low();
            Timer::after(Duration::from_millis(50)).await;
            led.set_high();
            Timer::after(Duration::from_millis(2000)).await;
        }
    }
}
