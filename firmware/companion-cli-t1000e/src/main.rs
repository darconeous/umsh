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

#[cfg(target_os = "none")]
mod firmware {
    use embassy_executor::Spawner;
    use embassy_futures::join::join;
    use embassy_futures::select::{select, Either};
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
    use embassy_nrf::peripherals;
    use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
    use embassy_nrf::usb::Driver;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::channel::Channel;
    use embassy_sync::signal::Signal;
    use embassy_time::{Duration, Instant, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, Sender, State};
    use embassy_usb::{Builder, Config};
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::gpregret;
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_bsp_nrf52840::system_off::{power_off, tristate_pin, Port, WakePin, WakeSense};
    use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm, ButtonTimings};
    use umsh_ux_tracker::led::{LedEngine, LedTimings};

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
    });

    const OUTPUT_CAPACITY: usize = 8;
    const OUTPUT_LINE_MAX: usize = 128;

    type OutputLine = heapless::Vec<u8, OUTPUT_LINE_MAX>;
    static OUTPUT_CH: Channel<ThreadModeRawMutex, OutputLine, OUTPUT_CAPACITY> = Channel::new();

    /// Single-consumer shutdown trigger. Fired by `button_task` on a
    /// long-press and (eventually) by `/poweroff` once the CLI is wired.
    static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

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
    type T1000eSender    = Sender<'static, T1000eUsbDriver>;
    type T1000eRescue    = CdcAcmRescue<'static, T1000eUsbDriver>;

    #[embassy_executor::task]
    async fn output_task(mut tx: T1000eSender) {
        loop {
            let line = OUTPUT_CH.receive().await;
            let _ = tx.write_packet(&line).await;
            if line.len() % 64 != 0 {
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

            write_line("").await;
            write_line("UMSH T1000-E bringup -- Phase 2").await;
            write_line(concat!("sha: ", env!("GIT_SHORT_SHA"))).await;
            write_line("button: long-press = power off, triple-tap = DFU").await;
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
                let timeout_deadline_ms = fsm
                    .next_deadline()
                    .unwrap_or(now_ms.saturating_add(60_000));
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

        tristate_pin(Port::P0, 24); // LED — kills heartbeat's drive into the LED
        // Button (P0.06) is configured for wake by `power_off`; do not
        // tristate it here, that would clear the wake configuration.

        // Button is active-high with pull-down → wake on rising edge.
        power_off(&[WakePin { port: Port::P0, pin: 6, sense: WakeSense::High }])
    }

    async fn heartbeat(mut led: Output<'static>, mut wdt: WatchdogHandle) -> ! {
        let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
        loop {
            wdt.pet();
            let decision = engine.tick(Instant::now().as_millis());
            // P0.24 active-HIGH.
            if decision.on { led.set_high() } else { led.set_low() }
            Timer::at(Instant::from_millis(decision.next_deadline_ms)).await;
        }
    }

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

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
        config.manufacturer      = Some("Seeed");
        config.product           = Some("T1000-E Bringup");
        config.serial_number     = Some("test");
        config.max_power         = 100;
        config.max_packet_size_0 = 64;

        static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
        static BOS_DESC:    StaticCell<[u8; 256]> = StaticCell::new();
        static MSOS_DESC:   StaticCell<[u8; 0]>   = StaticCell::new();
        static CONTROL_BUF: StaticCell<[u8; 64]>  = StaticCell::new();
        static STATE:       StaticCell<State>      = StaticCell::new();

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

        // Run USB + heartbeat together via join.
        join(usb.run(), heartbeat(led, wdt_handle)).await;
    }
}
