// Seeed SenseCAP T1000-E companion-radio CLI firmware — Phase 2 bringup.
//
// Phase 1 established USB-CDC enumeration, WDT heartbeat, panic persistence,
// and every DFU rescue path. Phase 2 adds the user-facing power and DFU
// surfaces: a button task that recognises long-press (→ shutdown) and
// triple-tap (→ DFU), and a shutdown task that tri-states peripheral pins
// before entering System OFF so the button wake survives un-noised.
//
// Boot sequence:
//   1. Read button (P0.06); if held, enter serial DFU immediately.
//   2. Arm the watchdog (8 s timeout, petted by heartbeat).
//   3. Read any panic message left by the previous boot.
//   4. Set up USB-CDC with CdcAcmRescue (1200-baud touch + escape rescue).
//   5. Spawn output_task (drains OUTPUT_CH to the USB sender).
//   6. Spawn echo_task (waits for host connection, emits banner, echoes input).
//   7. Spawn button_task (long-press → SHUTDOWN_SIGNAL, triple-tap → DFU UF2).
//   8. Spawn shutdown_task (waits on SHUTDOWN_SIGNAL, performs ordered off).
//   9. Join usb.run / heartbeat in main.
//
// Task layout:
//   - main():         joins usb.run / heartbeat
//   - output_task:    owns USB Sender, drains OUTPUT_CH
//   - echo_task:      owns CdcAcmRescue; on each host connection emits banner
//                     then echoes inbound bytes back through OUTPUT_CH
//   - button_task:    owns P0.06 Input; runs ButtonFsm
//   - shutdown_task:  owns LED + button-pin metadata; performs System OFF
//
// DFU paths:
//   - Button held at boot     → enter_dfu_serial() before embassy starts
//   - 1200-baud touchless     → CdcAcmRescue → enter_dfu_uf2()
//   - Escape rescue           → CdcAcmRescue → enter_dfu_uf2()
//   - Triple-tap button       → button_task → enter_dfu_uf2()
//   - Hardware double-tap     → discrete RESET circuit + bootloader (no firmware action)
//
// Power-off paths:
//   - Long-press button (≥5 s) → button_task → SHUTDOWN_SIGNAL → shutdown_task
//   - Wake from System OFF      → button press (P0.06 DETECT-high)
//
// T1000-E pin notes:
//   LED:    P0.24  active-HIGH  (set_high = on)
//   Button: P0.06  active-HIGH  pull-down  (HIGH = pressed, WakeSense::High)
//   No peripheral power-enable rail (unlike T-Echo P0.12).
//
// Non-obvious gotcha learned during bringup:
//   `CdcAcmRescue::read_packet()` returns Ok(0) immediately when DTR is low.
//   Calling it in a tight loop without first awaiting `wait_connection()`
//   busy-loops the executor and starves heartbeat → WDT reboot.
//   Always call `wait_connection()` first, then loop on read_packet until
//   it returns Ok(0)/Err, then loop back to wait_connection.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod panic;

// lora-phy 3.x unconditionally depends on defmt. A zero-overhead no-op global
// logger satisfies the link without adding any debug transport — every log
// call compiles out at release. Same pattern as hello-techo.
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
    use embassy_executor::Spawner;
    use embassy_futures::join::join;
    use embassy_futures::select::{Either, select};
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
    use embassy_nrf::peripherals;
    use embassy_nrf::spim::{Config as SpimConfig, Frequency, Spim};
    use embassy_nrf::usb::Driver;
    use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::channel::Channel;
    use embassy_sync::signal::Signal;
    use embassy_time::{Delay, Duration, Instant, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, Sender, State};
    use embassy_usb::{Builder, Config};
    use embedded_hal_bus::spi::ExclusiveDevice;
    use lora_phy::LoRa;
    use lora_phy::iv::GenericLr1110InterfaceVariant;
    use lora_phy::lr1110::{
        Config as LoraConfig, Lr1110, RfSwitchConfig, TcxoCtrlVoltage,
        variant::Lr1110 as Lr1110Chip,
    };
    use lora_phy::mod_params::RxMode;
    use lora_phy::mod_traits::IrqState;
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::gpregret;
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_bsp_nrf52840::system_off::{
        Port, WakePin, WakeSense, drive_pin_low, power_off, tristate_pin,
    };
    use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm, ButtonTimings};
    use umsh_ux_tracker::led::{LedEngine, LedTimings};

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
        // The shared SPIM0/SPIS0/TWIM0/TWIS0 block on nRF52840 is named
        // "TWISPI0" in embassy-nrf, both as the peripheral and the interrupt.
        // We drive the LR1110 SPI on this peripheral.
        TWISPI0     => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI0>;
    });

    const OUTPUT_CAPACITY: usize = 8;
    const OUTPUT_LINE_MAX: usize = 128;

    type OutputLine = heapless::Vec<u8, OUTPUT_LINE_MAX>;
    static OUTPUT_CH: Channel<ThreadModeRawMutex, OutputLine, OUTPUT_CAPACITY> = Channel::new();

    /// Single-consumer shutdown trigger. Fired by `button_task` on a
    /// long-press and (eventually) by `/poweroff` once the CLI is wired.
    static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Fired by `echo_task` once `CdcAcmRescue::wait_connection()` returns
    /// (host opened the port, DTR is HIGH). `radio_task` awaits this before
    /// emitting any diagnostic line so messages aren't sent into a
    /// not-yet-enumerated endpoint and silently dropped by `output_task`.
    static USB_READY_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Debounce window applied between raw GPIO edges. The button line on
    /// P0.06 settles in well under this; 10 ms is the conventional safe
    /// floor.
    const DEBOUNCE: Duration = Duration::from_millis(10);

    async fn write_line(s: &str) {
        let mut v: OutputLine = heapless::Vec::new();
        let _ = v.extend_from_slice(s.as_bytes());
        let _ = v.extend_from_slice(b"\r\n");
        OUTPUT_CH.send(v).await;
    }

    type T1000eUsbDriver = Driver<'static, HardwareVbusDetect>;
    type T1000eSender = Sender<'static, T1000eUsbDriver>;
    type T1000eRescue = CdcAcmRescue<'static, T1000eUsbDriver>;

    #[embassy_executor::task]
    async fn output_task(mut tx: T1000eSender) {
        loop {
            let line = OUTPUT_CH.receive().await;
            for chunk in line.chunks(64) {
                let _ = tx.write_packet(chunk).await;
            }
            if !line.is_empty() && line.len() % 64 == 0 {
                let _ = tx.write_packet(&[]).await;
            }
        }
    }

    /// Echo + banner. Waits for the host to open the CDC port, prints the
    /// startup banner (including any captured previous-boot panic), then
    /// echoes inbound bytes until the port closes — and loops back.
    ///
    /// Banner runs on every reconnection so a user opening `screen` always
    /// sees it, not only on the boot directly after a power cycle.
    #[embassy_executor::task]
    async fn echo_task(
        mut rx: T1000eRescue,
        prev_panic_buf: &'static [u8; 256],
        prev_panic_len: usize,
    ) {
        let mut buf = [0u8; 64];
        loop {
            // CRITICAL: do not call read_packet() before wait_connection().
            // See gotcha note at the top of this file.
            rx.wait_connection().await;
            // Tell radio_task it's now safe to print its banner.
            USB_READY_SIGNAL.signal(());

            write_line("").await;
            write_line("UMSH T1000-E bringup -- Phase 2.5").await;
            write_line(concat!("sha: ", env!("GIT_SHORT_SHA"))).await;
            write_line("button: long-press = power off, triple-tap = DFU").await;
            write_line("radio: LR1110 RX-only @ 910.525 MHz (MeshCore US preset)").await;
            if prev_panic_len > 0 {
                write_line("[PREV PANIC]:").await;
                if let Ok(s) = core::str::from_utf8(&prev_panic_buf[..prev_panic_len]) {
                    write_line(s).await;
                }
            }

            loop {
                match rx.read_packet(&mut buf).await {
                    Ok(0) => break, // port closed → back to wait_connection
                    Ok(n) => {
                        let mut line: OutputLine = heapless::Vec::new();
                        let _ = line.extend_from_slice(&buf[..n]);
                        OUTPUT_CH.send(line).await;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    /// Resolves raw GPIO edges on the user button (P0.06, active-high,
    /// pull-down) into `ButtonFsm` events. `Long` raises `SHUTDOWN_SIGNAL`,
    /// `Triple` enters UF2 DFU directly (diverges via system reset).
    ///
    /// The task races three futures via nested `select`s:
    ///   * `wait_for_high/low` for the next debounced edge,
    ///   * a `Timer` to the FSM's next deadline (long-press / inter-click gap),
    ///   * a fallback long timer when the FSM is idle.
    #[embassy_executor::task]
    async fn button_task(mut button: Input<'static>) {
        let mut fsm = ButtonFsm::new(ButtonTimings::default());
        // Active-high, pull-down: pressed = HIGH.
        let mut pressed = button.is_high();
        loop {
            let event = {
                let now_ms = Instant::now().as_millis();
                let edge_fut = async {
                    if pressed {
                        button.wait_for_low().await;
                        Timer::after(DEBOUNCE).await;
                        ButtonEdge::Release
                    } else {
                        button.wait_for_high().await;
                        Timer::after(DEBOUNCE).await;
                        ButtonEdge::Press
                    }
                };
                let timeout_deadline_ms =
                    fsm.next_deadline().unwrap_or(now_ms.saturating_add(60_000));
                let timer_fut = Timer::at(Instant::from_millis(timeout_deadline_ms));
                match select(edge_fut, timer_fut).await {
                    Either::First(edge) => {
                        pressed = matches!(edge, ButtonEdge::Press);
                        fsm.on_edge(edge, Instant::now().as_millis())
                    }
                    Either::Second(()) => fsm.poll(Instant::now().as_millis()),
                }
            };

            match event {
                Some(ButtonEvent::Long) => {
                    // Wait for the user to release the button before
                    // signalling shutdown. If we fire immediately while the
                    // button is still held HIGH, shutdown_task will arm
                    // wake on SENSE=High on a pin that is already HIGH,
                    // and the chip wakes from System OFF on the very first
                    // DETECT check — observable as an "instant reboot" on
                    // long-press.
                    button.wait_for_low().await;
                    Timer::after(DEBOUNCE).await;
                    pressed = false;
                    // Reset the FSM since we consumed this press chord.
                    fsm = ButtonFsm::new(ButtonTimings::default());
                    SHUTDOWN_SIGNAL.signal(());
                }
                Some(ButtonEvent::Triple) => {
                    gpregret::enter_dfu_uf2();
                }
                _ => {}
            }
        }
    }

    /// Orchestrates the controlled power-off: tristate the GPIOs the
    /// firmware drove or sensed on so neither output leakage nor leftover
    /// SENSE bits keep current flowing or fire a spurious DETECT wake,
    /// then enter System OFF with the button armed as the wake source.
    ///
    /// `tristate_pin` writes PIN_CNF directly via PAC, so it works
    /// regardless of who in Embassy still "owns" the pin — by the time
    /// the CPU resumes from System OFF the firmware will have re-init
    /// everything from scratch anyway.
    ///
    /// Phase 2 only touches the LED (P0.24) and button (P0.06). Future
    /// phases must extend the tristate list as they bring up the radio,
    /// GNSS, sensors, and buzzer (see `docs/firmware-plan-t1000e.md`).
    #[embassy_executor::task]
    async fn shutdown_task() -> ! {
        SHUTDOWN_SIGNAL.wait().await;

        // button_task guarantees the user has released the button before
        // signalling us, so SENSE=High wake on P0.06 won't fire instantly.

        // (1) Hold the LR1110 in reset by driving its RESET pin LOW. While
        // held in reset the chip clocks stop, all internal state is lost,
        // and current draw collapses to the chip's reset-state minimum.
        // This is the cleanest low-power shutdown for the radio — better
        // than leaving the chip in standby/sleep, since reset stops the
        // chip from generating any DIO transitions that could wake us.
        //
        // P1.10 is the LR1110 RESET (active-low, per MeshCore variant.cpp
        // T1000-E). Drive LOW before tristating anything else.
        drive_pin_low(Port::P1, 10);
        // Tiny settle window for the chip to actually enter reset before
        // we cut its SPI and DIO lines. ~10 µs is plenty per the LR1110
        // datasheet, but we don't have access to await here so just spin.
        cortex_m::asm::delay(640); // ~10 µs @ 64 MHz

        // (2) Tristate everything else. Embassy's async GPIO `wait_for_*`
        // leaves PIN_CNF SENSE bits set on input pins that have an
        // in-flight wait when shutdown fires. Any such pin matching its
        // SENSE level at System OFF entry will fire DETECT immediately
        // and the chip "wakes" right away — observable as the device
        // rebooting on long-press instead of shutting down.
        //
        // `tristate_pin` writes PIN_CNF directly via PAC, so it works
        // regardless of which Embassy task still "owns" the pin.
        //
        // Button P0.06 is deliberately left alone — `power_off` configures
        // SENSE on it intentionally for wake.
        tristate_pin(Port::P0, 24); // LED
        // LR1110 SPI bus + control lines (Phase 2.5 radio init).
        tristate_pin(Port::P0, 11); // SPI SCK
        tristate_pin(Port::P0, 12); // SPI CS
        tristate_pin(Port::P0, 7); // LR1110 BUSY (embassy waits on this)
        tristate_pin(Port::P1, 1); // LR1110 DIO1/IRQ (embassy waits on this)
        tristate_pin(Port::P1, 8); // SPI MISO
        tristate_pin(Port::P1, 9); // SPI MOSI
        // NB: P1.10 (LR1110 RESET) intentionally NOT tristated — we want
        // to keep driving it LOW to hold the chip in reset.

        // Button is active-high with pull-down → wake on rising edge.
        power_off(&[WakePin {
            port: Port::P0,
            pin: 6,
            sense: WakeSense::High,
        }])
    }

    // ─── LR1110 radio ────────────────────────────────────────────────────────
    //
    // Concrete type aliases so the spawned task signature compiles.

    type RadioSpiBus = ExclusiveDevice<Spim<'static>, Output<'static>, Delay>;
    type RadioIv = GenericLr1110InterfaceVariant<Output<'static>, Input<'static>>;
    type RadioKind = Lr1110<RadioSpiBus, RadioIv, Lr1110Chip>;
    /// T1000-E RF-switch DIO table. Sourced from MeshCore's `t1000-e/target.cpp`:
    ///   STBY:   { LOW,  LOW,  LOW,  LOW  }
    ///   RX:     { HIGH, LOW,  LOW,  HIGH }
    ///   TX_LP:  { HIGH, HIGH, LOW,  HIGH }
    ///   TX_HP:  { LOW,  HIGH, LOW,  HIGH }
    ///   GNSS:   { LOW,  LOW,  HIGH, LOW  }
    /// Bit layout: DIO5=0x01, DIO6=0x02, DIO7=0x04, DIO8=0x08.
    const T1000E_RF_SWITCH: RfSwitchConfig = RfSwitchConfig {
        standby: 0x00,
        rx: 0x09,    // DIO5 + DIO8
        tx: 0x0B,    // DIO5 + DIO6 + DIO8
        tx_hp: 0x0A, // DIO6 + DIO8
        tx_hf: 0x00, // unused on LR1110 sub-GHz
        gnss: 0x04,  // DIO7
        wifi: 0x00,  // not used
    };

    /// Confirmed MeshCore US on-air parameters:
    ///   910.525 MHz / SF7 / BW62.5 kHz / CR4/5 / private sync 0x12 / CRC on
    /// Matches `umsh-radio-sx126x::meshcore_us_params`.
    const RX_FREQUENCY_HZ: u32 = 910_525_000;

    const LR1110_RX_BOOST: bool = true;

    fn radio_error_name(e: lora_phy::mod_params::RadioError) -> &'static str {
        use lora_phy::mod_params::RadioError;

        match e {
            RadioError::SPI => "SPI",
            RadioError::Reset => "Reset",
            RadioError::RfSwitchRx => "RfSwitchRx",
            RadioError::RfSwitchTx => "RfSwitchTx",
            RadioError::Busy => "Busy",
            RadioError::Irq => "Irq",
            RadioError::DIO1 => "DIO1",
            RadioError::InvalidConfiguration => "InvalidConfiguration",
            RadioError::InvalidRadioMode => "InvalidRadioMode",
            RadioError::OpError(_) => "OpError",
            RadioError::InvalidBaseAddress(_, _) => "InvalidBaseAddress",
            RadioError::PayloadSizeUnexpected(_) => "PayloadSizeUnexpected",
            RadioError::PayloadSizeMismatch(_, _) => "PayloadSizeMismatch",
            RadioError::UnavailableSpreadingFactor => "UnavailableSpreadingFactor",
            RadioError::UnavailableBandwidth => "UnavailableBandwidth",
            RadioError::InvalidBandwidthForFrequency => "InvalidBandwidthForFrequency",
            RadioError::InvalidSF6ExplicitHeaderRequest => "InvalidSF6ExplicitHeaderRequest",
            RadioError::InvalidOutputPowerForFrequency => "InvalidOutputPowerForFrequency",
            RadioError::TransmitTimeout => "TransmitTimeout",
            RadioError::ReceiveTimeout => "ReceiveTimeout",
            RadioError::HeaderError => "HeaderError",
            RadioError::CrcError => "CrcError",
            RadioError::DutyCycleUnsupported => "DutyCycleUnsupported",
            RadioError::RngUnsupported => "RngUnsupported",
        }
    }

    /// Phase 2.5 hello-LR1110: continuous RX with USB logging. No TX (those
    /// will require coordinating the radio with the rest of the system; here
    /// we only need to prove the chip enumerates and decodes packets).
    ///
    /// Defers all diagnostic output until USB_READY_SIGNAL fires so messages
    /// aren't emitted into a not-yet-enumerated endpoint (which would silently
    /// drop them — `output_task` ignores `EndpointError::Disabled`).
    /// Builds the radio params eagerly but reports the result only after the
    /// host is listening, so we can see exactly which step the radio reached.
    #[embassy_executor::task]
    async fn radio_task(radio: RadioKind) {
        use core::fmt::Write as _;
        use lora_phy::mod_params::{Bandwidth, CodingRate, RadioError, SpreadingFactor};

        USB_READY_SIGNAL.wait().await;
        write_line("[radio] bringing up LR1110 after USB connect").await;

        let mut lora = match LoRa::new(radio, false, Delay).await {
            Ok(lora) => lora,
            Err(_) => {
                write_line("[radio] LR1110 init FAILED").await;
                return;
            }
        };
        write_line("[radio] LR1110 init SUCCESS").await;

        let mdltn_result = lora.create_modulation_params(
            SpreadingFactor::_7,
            Bandwidth::_62KHz,
            CodingRate::_4_5,
            RX_FREQUENCY_HZ,
        );
        let mdltn = match mdltn_result {
            Ok(p) => p,
            Err(_) => {
                write_line("[radio] FAIL: create_modulation_params").await;
                return;
            }
        };
        write_line("[radio] modulation params created").await;

        let rx_pkt = match lora.create_rx_packet_params(
            16,    // match MeshCore/RadioLib LR1110 preamble length
            false, // false = explicit header
            255,   // max payload; match the known-good SX126x MeshCore helper
            true,  // CRC on
            false, // IQ normal
            &mdltn,
        ) {
            Ok(p) => p,
            Err(_) => {
                write_line("[radio] FAIL: create_rx_packet_params").await;
                return;
            }
        };
        write_line("[radio] RX packet params created").await;

        write_line("[radio] params built").await;

        write_line("[radio] Preparing for continuous rx mode...").await;
        if lora
            .prepare_for_rx(RxMode::Continuous, &mdltn, &rx_pkt)
            .await
            .is_err()
        {
            write_line("[radio] prepare_for_rx FAILED").await;
            return;
        }
        write_line("[radio] Starting RX mode...").await;
        if lora.start_rx().await.is_err() {
            write_line("[radio] start_rx FAILED").await;
            return;
        }
        write_line("[radio] RX mode started").await;
        write_line("[radio] entering RX loop").await;

        let mut buf = [0u8; 255];
        let mut rx_count: u32 = 0;
        let mut preamble_count: u32 = 0;
        let mut header_err_count: u32 = 0;
        let mut crc_err_count: u32 = 0;
        let mut last_counter_log = Instant::now();
        loop {
            if lora.wait_for_irq().await.is_err() {
                try_log_line("[radio] wait_for_irq FAIL");
                continue;
            }

            let irq_result = lora.process_irq_event().await;

            match irq_result {
                Ok(Some(IrqState::PreambleReceived)) => {
                    preamble_count = preamble_count.saturating_add(1);
                }
                Ok(Some(IrqState::Done)) => {
                    rx_count = rx_count.saturating_add(1);
                    match lora.get_rx_result(&rx_pkt, &mut buf).await {
                        Ok((n, status)) => {
                            let mut line: heapless::String<OUTPUT_LINE_MAX> =
                                heapless::String::new();
                            let _ = write!(
                                line,
                                "[rx] #{} len={} rssi={} snr={} hex=",
                                rx_count, n, status.rssi, status.snr,
                            );
                            // Reserve room for the CRLF that `try_log_line`
                            // appends. If we fill the line buffer completely,
                            // the newline extension fails and the next log
                            // line gets glued onto the packet hex.
                            let max_hex = OUTPUT_LINE_MAX
                                .saturating_sub(line.len() + 2)
                                / 2;
                            for b in &buf[..(n as usize).min(max_hex)] {
                                let _ = write!(line, "{:02x}", b);
                            }
                            try_log_line(&line);
                        }
                        Err(_) => try_log_line("[radio] get_rx_result FAIL after Done"),
                    }
                    let _ = lora.start_rx().await;
                }
                Ok(None) => {}
                Err(RadioError::HeaderError) => {
                    header_err_count = header_err_count.saturating_add(1);
                    let _ = lora.enter_standby().await;
                    let _ = lora
                        .prepare_for_rx(RxMode::Continuous, &mdltn, &rx_pkt)
                        .await;
                    let _ = lora.start_rx().await;
                }
                Err(RadioError::CrcError) => {
                    crc_err_count = crc_err_count.saturating_add(1);
                    let _ = lora.enter_standby().await;
                    let _ = lora
                        .prepare_for_rx(RxMode::Continuous, &mdltn, &rx_pkt)
                        .await;
                    let _ = lora.start_rx().await;
                }
                Err(e) => {
                    let mut line: heapless::String<OUTPUT_LINE_MAX> = heapless::String::new();
                    let _ = write!(line, "[radio] rx err: {}", radio_error_name(e));
                    try_log_line(&line);
                    let _ = lora.enter_standby().await;
                    let _ = lora
                        .prepare_for_rx(RxMode::Continuous, &mdltn, &rx_pkt)
                        .await;
                    let _ = lora.start_rx().await;
                }
            }

            let _ = lora.clear_irq_status().await;

            if last_counter_log.elapsed() >= Duration::from_secs(5) {
                if preamble_count != 0 {
                    let mut line: heapless::String<OUTPUT_LINE_MAX> = heapless::String::new();
                    let _ = write!(line, "[radio] preambles={}", preamble_count);
                    try_log_line(&line);
                    preamble_count = 0;
                }
                if header_err_count != 0 {
                    let mut line: heapless::String<OUTPUT_LINE_MAX> = heapless::String::new();
                    let _ = write!(line, "[radio] header_err={}", header_err_count);
                    try_log_line(&line);
                    header_err_count = 0;
                }
                if crc_err_count != 0 {
                    let mut line: heapless::String<OUTPUT_LINE_MAX> = heapless::String::new();
                    let _ = write!(line, "[radio] crc_err={}", crc_err_count);
                    try_log_line(&line);
                    crc_err_count = 0;
                }
                last_counter_log = Instant::now();
            }
        }
    }

    /// Non-blocking diagnostic line (try_send so a full OUTPUT_CH never blocks
    /// the radio task).
    fn try_log_line(s: &str) {
        let mut v: OutputLine = heapless::Vec::new();
        let _ = v.extend_from_slice(s.as_bytes());
        let _ = v.extend_from_slice(b"\r\n");
        let _ = OUTPUT_CH.try_send(v);
    }

    async fn heartbeat(mut led: Output<'static>, mut wdt: WatchdogHandle) -> ! {
        let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
        loop {
            wdt.pet();
            let decision = engine.tick(Instant::now().as_millis());
            // P0.24 active-HIGH.
            if decision.on {
                led.set_high()
            } else {
                led.set_low()
            }
            Timer::at(Instant::from_millis(decision.next_deadline_ms)).await;
        }
    }

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

        // Seize LR1110 RESET immediately at boot and hold the radio down until
        // we deliberately start bringup. The LR1110 is a separate chip and can
        // outlive nRF soft resets or watchdog resets; if a previous image left
        // it in a bad state (notably broken DCDC mode on this board), that
        // state can destabilize USB before we ever reach LoRa::new().
        //
        // Keeping RESET low here makes every boot start from a known-quiet
        // radio state and turns "persistent radio poison" into a testable
        // hypothesis instead of a mystery.
        let radio_rst = Output::new(p.P1_10, Level::Low, OutputDrive::Standard);

        // Button-held-at-boot DFU check (active-HIGH, pull-down). The same
        // `Input` is then handed to `button_task` for ongoing event
        // recognition (long-press, triple-tap), so the peripheral is
        // claimed exactly once.
        let button = Input::new(p.P0_06, Pull::Down);
        cortex_m::asm::delay(640_000); // ~10 ms settle
        if button.is_high() {
            umsh_bsp_nrf52840::gpregret::enter_dfu_serial();
        }

        let mut wdt_config = WdtConfig::default();
        wdt_config.timeout_ticks = 32768 * 8;
        let (_wdt, [wdt_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, wdt_config).unwrap_or_else(|_| panic!("wdt"));

        // Read any panic message left by the previous boot, then clear.
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

        let led = Output::new(p.P0_24, Level::Low, OutputDrive::Standard);

        // USB setup (Driver + Builder + class). NOT calling usb.run() yet —
        // we just want to see if the *setup* path itself hangs.
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        let mut config = Config::new(0x2886, 0x0057);
        config.manufacturer = Some("Seeed");
        config.product = Some("T1000-E Bringup");
        config.serial_number = Some("test");
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

        spawner.spawn(output_task(tx).unwrap());
        spawner.spawn(echo_task(rx, prev_panic_buf, prev_panic_len).unwrap());
        spawner.spawn(button_task(button).unwrap());
        spawner.spawn(shutdown_task().unwrap());
        // ── LR1110 LoRa radio (Phase 2.5: hello LR1110, RX only) ─────────────
        //
        // Pin map (firmware-confirmed against MeshCore variants/t1000-e):
        //   SPI bus: SCK=P0.11, MISO=P1.08, MOSI=P1.09 (TWISPI0)
        //   CS=P0.12, RST=P1.10, IRQ/DIO1=P1.01, BUSY=P0.07
        //   DIO3: 1.6 V TCXO control.
        //   DIO5-8: internal RF switch driven via SetDioAsRfSwitch (RfSwitchConfig).
        {
            let mut cfg = SpimConfig::default();
            // LR1110 SPI: max ~16 MHz, Mode 0. 8 MHz is safe on the nRF52840
            // pinout without trace-impedance worries.
            cfg.frequency = Frequency::M8;
            let radio_bus = Spim::new(
                p.TWISPI0, Irqs, p.P0_11, // SCK
                p.P1_08, // MISO
                p.P1_09, // MOSI
                cfg,
            );
            let radio_cs = Output::new(p.P0_12, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();

            // Pull::Down so a floating/un-driven pin reads as definite LOW;
            // the LR1110's IRQ output (DIO9/DIO11) is push-pull active-high
            // per datasheet, so this should not fight the chip when asserting.
            let radio_interrupt = Input::new(p.P1_01, Pull::Down);
            let radio_busy = Input::new(p.P0_07, Pull::None);

            let iv = RadioIv::new(
                radio_rst,
                radio_interrupt,
                radio_busy,
                None, // rf_switch_rx: not external — handled by internal DIO5-8
                None, // rf_switch_tx: same
            )
            .unwrap_or_else(|_| panic!("lr1110 iv"));

            let lora_config = LoraConfig {
                chip: Lr1110Chip::new(),
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V6), // 1.6 V TCXO on DIO3
                use_dcdc: false,
                rx_boost: LR1110_RX_BOOST,
                rf_switch: Some(T1000E_RF_SWITCH),
            };
            let radio = Lr1110::new(radio_spi, iv, lora_config);
            spawner.spawn(radio_task(radio).unwrap());
        }

        // Run USB + heartbeat together via join.
        join(usb.run(), heartbeat(led, wdt_handle)).await;
    }
}
