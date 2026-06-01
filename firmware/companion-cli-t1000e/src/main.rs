// Seeed SenseCAP T1000-E companion-radio CLI firmware — Phase 3 bringup.
//
// Phases 0-2 established: bootloader recon, USB-CDC, WDT, panic persist,
// DFU rescue paths, button FSM (long-press → shutdown, triple-tap → DFU),
// ordered System OFF with GPIO wake.
//
// Phase 2.5 proved the LR1110 radio receives MeshCore-US packets. The
// root fixes were in the lora-phy fork (read_buffer offset+length framing,
// calibration mask 0x3F, RadioLib-matching init sequence).
//
// Phase 3 wires CliSession over USB-CDC using the same MAC + radio_runner
// pattern as companion-cli-techo (T-Echo Phase 6). Changes from Phase 2.5:
//   - echo_task replaced by umsh_task (Host::run + CliSession::run)
//   - radio_task replaced by radio_runner_task (umsh_radio_loraphy::runner)
//   - output_task upgraded to cli_io::drain_to_sender (64-byte chunk drain)
//   - NVMC identity persistence (first-boot TRNG key generation)
//   - NVMC counter / peer / channel persistence
//   - PowerSignaler connects /poweroff CLI command to SHUTDOWN_SIGNAL
//
// Boot sequence:
//   1. Init heap allocator.
//   2. Hold LR1110 RESET low (keeps radio quiet during USB init).
//   3. Read button (P0.06); if held, enter serial DFU immediately.
//   4. Arm the watchdog (8 s timeout, petted by heartbeat).
//   5. Read any panic message left by the previous boot.
//   6. Init NVMC storage (64 KB at 0xE4000..0xF4000).
//   7. Load or TRNG-generate the local Ed25519 secret key.
//   8. Build Mac<T1000EPlatform> and load persisted TX counter.
//   9. Init LR1110 SPI + LoRa::new; derive MeshCore-US params.
//  10. Set up USB-CDC with CdcAcmRescue (1200-baud touch + escape rescue).
//  11. Spawn output_task, radio_runner_task, button_task, shutdown_task,
//      umsh_task.
//  12. Join usb.run / heartbeat in main.
//
// Task layout:
//   - main():              joins usb.run / heartbeat
//   - output_task:         owns USB Sender; drains cli_io::OUTPUT_CH
//   - radio_runner_task:   owns LoRa<LR1110>; loops continuous RX ↔ TX
//   - umsh_task:           host.run() + cli.run() via select; owns CdcInput
//   - button_task:         owns P0.06 Input; runs ButtonFsm
//   - shutdown_task:       awaits SHUTDOWN_SIGNAL; performs ordered System OFF
//   - heartbeat (inline):  LED + WDT pet; runs in join with usb.run
//
// T1000-E pin notes (all confirmed against MeshCore variants/t1000-e):
//   LED:    P0.24  active-HIGH  (set_high = on)
//   Button: P0.06  active-HIGH  pull-down  (HIGH = pressed, WakeSense::High)
//   LR1110: SCK=P0.11, CS=P0.12, MISO=P1.08, MOSI=P1.09, RST=P1.10
//           DIO1/IRQ=P1.01, BUSY=P0.07
//           DIO3: 1.6V TCXO control (set by lora-phy)
//           DIO5-8: internal RF switch (set via RfSwitchConfig)

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod panic;

#[cfg(target_os = "none")]
mod cli_io;

// lora-phy 3.x unconditionally depends on defmt. A zero-overhead no-op global
// logger satisfies the link without adding any debug transport — every log
// call compiles out at release. Same pattern as companion-cli-techo.
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

// Global heap allocator. umsh-sync (AsyncRefCell) and umsh-cli/node use alloc
// for Rc/RefCell/Vec. 8 KiB is generous; actual runtime allocation is minimal
// since all MAC state is in static arrays.
#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: embedded_alloc::Heap = embedded_alloc::Heap::empty();

#[cfg(target_os = "none")]
mod firmware {
    use core::mem::MaybeUninit;

    use embassy_executor::Spawner;
    use embassy_futures::join::join;
    use embassy_futures::select::{Either, select};
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
    use embassy_nrf::nvmc::Nvmc;
    use embassy_nrf::peripherals;
    use embassy_nrf::pwm::{Prescaler, SimpleConfig, SimplePwm};
    use embassy_nrf::saadc::{ChannelConfig, Config as SaadcConfig, Saadc};
    use embassy_nrf::spim::{Config as SpimConfig, Frequency, Spim};
    use embassy_nrf::usb::Driver;
    use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::signal::Signal;
    use embassy_time::{Delay, Duration, Instant, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, Sender, State};
    use embassy_usb::{Builder, Config};
    use embedded_hal_bus::spi::ExclusiveDevice;
    use lora_phy::LoRa;
    use lora_phy::iv::GenericLr1110InterfaceVariant;
    use lora_phy::lr1110::{
        Config as LoraConfig, Lr1110, TcxoCtrlVoltage, radio_kind_params::PaSelection,
        variant::Lr1110 as Lr1110Chip,
    };
    use lora_phy::mod_params::{
        Bandwidth, CodingRate, ModulationParams, PacketParams, SpreadingFactor,
    };
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::flash_store::{
        NvmcChannelStore, NvmcCounterStore, NvmcPeerStore, NvmcStorage,
    };
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_bsp_nrf52840::{EmbassyClock, Nrf52840Rng};
    use umsh_bsp_t1000e::{PowerSignaler, RF_SWITCH, SHUTDOWN_SIGNAL, T1000EMac, T1000EPlatform};
    use umsh_core::PublicKey;
    use umsh_crypto::{
        CryptoEngine, NodeIdentity,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    };
    use umsh_mac::{MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
    use umsh_node::{Host, LocalNode};
    use umsh_sync::AsyncRefCell;
    use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm, ButtonTimings};
    use umsh_ux_tracker::buzzer::melodies as buzzer_melodies;
    use umsh_ux_tracker::led::{LedEngine, LedTimings};

    use super::cli_io;

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
        // Shared SPIM0/TWIM0 block — named TWISPI0 in embassy-nrf.
        // LR1110 SPI is on this peripheral.
        TWISPI0     => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI0>;
        SAADC       => embassy_nrf::saadc::InterruptHandler;
    });

    // ─── Constants ───────────────────────────────────────────────────────────

    /// TX power for the LR1110 HP PA at max output (+22 dBm).
    const TX_POWER_DBM: i32 = 22;

    const DEBOUNCE: Duration = Duration::from_millis(10);

    // ─── Platform ─────────────────────────────────────────────────────────────
    //
    // `T1000EPlatform`, `T1000EMac`, the embassy-backed clock, the nRF52840
    // hardware-TRNG RNG, and the LR1110 RF-switch table all live in
    // `umsh-bsp-t1000e` (which composes the chip-level pieces from
    // `umsh-bsp-nrf52840`).

    // `T1000EMac` is re-exported from `umsh_bsp_t1000e`. `Host` and `LocalNode`
    // depend on `umsh-node` (alloc + software-crypto), which the BSP doesn't
    // pull in, so the firmware owns those two aliases.
    /// Host bound to the `'static` mac_cell. Owned by `mac_task`.
    type T1000EHost = Host<'static, T1000EPlatform, 2, 8, 4, 4, 8, 255, 32>;
    /// LocalNode handle. Cheap to clone — passed to `cli_task` and `beacon_task`.
    type T1000ENode = LocalNode<MacHandle<'static, T1000EPlatform, 2, 8, 4, 4, 8, 255, 32>>;

    // ─── Concrete radio types ─────────────────────────────────────────────────

    type RadioSpiBus = ExclusiveDevice<Spim<'static>, Output<'static>, Delay>;
    type RadioIv = GenericLr1110InterfaceVariant<Output<'static>, Input<'static>>;
    type RadioKindT = Lr1110<RadioSpiBus, RadioIv, Lr1110Chip>;
    type LoraRadio = LoRa<RadioKindT, Delay>;

    // ─── Static shared state ─────────────────────────────────────────────────

    /// Channels shared between radio_runner_task and LoraphyRadio / MAC.
    /// 4 inbound frames, 2 pending TX requests — same as T-Echo.
    type RadioCh = umsh_radio_loraphy::Channels<ThreadModeRawMutex, 4, 2>;
    static RADIO_CH: RadioCh = RadioCh::new();

    static MAC_CELL: StaticCell<AsyncRefCell<T1000EMac>> = StaticCell::new();
    static STORAGE: StaticCell<NvmcStorage> = StaticCell::new();

    // SHUTDOWN_SIGNAL and PowerSignaler now live in `umsh-bsp-t1000e::power`;
    // this firmware imports `SHUTDOWN_SIGNAL` for the long-press button source
    // and uses `umsh_bsp_t1000e::PowerSignaler` for the CLI's PowerControl.

    // BUZZER_SIGNAL now lives in `umsh_bsp_t1000e::buzzer` alongside the
    // buzzer runner; firmware code uses `umsh_bsp_t1000e::BUZZER_SIGNAL`.

    /// Button-driven beacon request. Single or Double presses both fire this
    /// so users get feedback no matter how the FSM classifies the press.
    static BEACON_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    // ─── USB types ────────────────────────────────────────────────────────────

    type T1000eUsbDriver = Driver<'static, HardwareVbusDetect>;
    type T1000eSender = Sender<'static, T1000eUsbDriver>;
    type T1000eRescue = CdcAcmRescue<'static, T1000eUsbDriver>;

    // ─── RF switch config ─────────────────────────────────────────────────────

    // `RF_SWITCH` and `PowerSignaler` are re-exported from `umsh_bsp_t1000e`.

    // ─── Tasks ───────────────────────────────────────────────────────────────

    /// Drains cli_io::OUTPUT_CH to the USB sender. Decoupling the sender from
    /// umsh_task lets RX keep flowing while TX awaits host IN polls.
    #[embassy_executor::task]
    async fn output_task(mut tx: T1000eSender) {
        cli_io::drain_to_sender(&mut tx).await;
    }

    /// Owns the `lora_phy::LoRa` instance. Switches between continuous RX
    /// and TX as TX requests arrive on `RADIO_CH.tx`.
    #[embassy_executor::task]
    async fn radio_runner_task(
        lora: LoraRadio,
        mdltn: ModulationParams,
        rx_pkt: PacketParams,
        tx_pkt: PacketParams,
    ) {
        umsh_radio_loraphy::runner(lora, &RADIO_CH, mdltn, rx_pkt, tx_pkt, TX_POWER_DBM).await;
    }

    /// Owns the piezo buzzer (PWM on P0.25 + power-enable on P1.05).
    /// Body lives in `umsh_bsp_t1000e::buzzer`; this shim is required so
    /// the embassy task macro sees concrete monomorphised types.
    #[embassy_executor::task]
    async fn buzzer_task(pwm: SimplePwm<'static>, enable: Output<'static>) {
        umsh_bsp_t1000e::buzzer::run(pwm, enable).await;
    }

    /// Drives the MAC coordinator. Independent of USB so radio RX/TX and
    /// the MAC pump keep running whether or not a host terminal is attached.
    #[embassy_executor::task]
    async fn mac_task(mut host: T1000EHost) {
        let _ = host.run().await;
        panic!("host exited");
    }

    /// Listens for button-driven beacon requests. Independent of USB so
    /// pressing the button broadcasts a beacon (and chirps) even when no
    /// host terminal is attached.
    #[embassy_executor::task]
    async fn beacon_task(beacon_node: T1000ENode) {
        use umsh_node::Transport as _;
        loop {
            BEACON_SIGNAL.wait().await;
            // Audible feedback first so the user hears the press even if
            // the MAC layer fails or stalls.
            umsh_bsp_t1000e::BUZZER_SIGNAL.signal(&buzzer_melodies::BEACON_ACK);
            let _ = beacon_node.send_all(&[], &SendOptions::default()).await;
        }
    }

    /// Runs the `CliSession` over USB-CDC. This is the only task that
    /// blocks on a host terminal connection — everything else (radio, MAC,
    /// button, buzzer, beacon) runs without it.
    #[embassy_executor::task]
    #[allow(clippy::too_many_arguments)]
    async fn cli_task(
        node: T1000ENode,
        local_key: PublicKey,
        storage: &'static NvmcStorage,
        peer_buf: heapless::Vec<([u8; 32], Option<heapless::String<16>>), 8>,
        ch_buf: heapless::Vec<(heapless::String<16>, [u8; 32]), 2>,
        rx: T1000eRescue,
        prev_panic_buf: &'static [u8; 256],
        prev_panic_len: usize,
    ) {
        use umsh_cli::CliSession;
        use umsh_cli::io::CliOutput;
        use umsh_cli::logger::NullLogger;

        let mut input = cli_io::CdcInput::new(rx);
        let mut out = cli_io::CdcOutput::new();

        // Peers and channels were already registered into the MAC at boot (see
        // `main`); `peer_buf`/`ch_buf` arrive here only to populate the CLI's
        // own display tables (aliases, channel names). The `register_*` calls
        // below re-hit the MAC, which is idempotent.

        // Wait for the host to open the CDC port before emitting the banner.
        input.wait_connection().await;

        let _ = out.write_line("").await;
        let _ = out.write_line("UMSH CLI (T1000-E)").await;
        let _ = out.write_line("type /help for commands").await;
        if prev_panic_len > 0 {
            let _ = out.write_line("[PREV PANIC]:").await;
            if let Ok(s) = core::str::from_utf8(&prev_panic_buf[..prev_panic_len]) {
                let _ = out.write_line(s).await;
            }
        }

        let peer_store = NvmcPeerStore::new(storage);
        let channel_store = NvmcChannelStore::new(storage);
        let mut cli: CliSession<_, _, _, _, _, _, 4, 4, 2, 8, 128> = CliSession::new(
            node,
            local_key,
            out,
            NullLogger::new(),
            peer_store,
            channel_store,
            PowerSignaler,
        );

        for (pk, alias) in peer_buf.iter() {
            let _ = cli.register_peer(PublicKey(*pk), alias.as_deref()).await;
        }
        for (name, key_bytes) in ch_buf.iter() {
            let _ = cli.register_channel(name.as_str(), *key_bytes).await;
        }

        let _ = cli.run(&mut input).await;
        panic!("cli exited");
    }

    /// Resolves raw GPIO edges on the user button (P0.06, active-high, pull-down)
    /// into `ButtonFsm` events. `Long` raises `SHUTDOWN_SIGNAL`,
    /// `Triple` enters UF2 DFU directly (diverges via system reset).
    #[embassy_executor::task]
    async fn button_task(mut button: Input<'static>) {
        let mut fsm = ButtonFsm::new(ButtonTimings::default());
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
                Some(ButtonEvent::Single) => {
                    BEACON_SIGNAL.signal(());
                }
                Some(ButtonEvent::Double) => {
                    umsh_bsp_t1000e::BUZZER_SILENCE_TOGGLE.signal(());
                }
                Some(ButtonEvent::Triple) => {
                    umsh_bsp_nrf52840::gpregret::enter_dfu_uf2();
                }
                Some(ButtonEvent::Quad) => {
                    // No action defined for Quad yet
                }
                Some(ButtonEvent::Long) => {
                    pressed = false;
                    fsm = ButtonFsm::new(ButtonTimings::default());
                    SHUTDOWN_SIGNAL.signal(());
                }
                _ => {}
            }
        }
    }

    /// Orchestrates controlled power-off (LR1110 reset + GPIO tristate +
    /// System OFF with button as wake). Body lives in
    /// `umsh_bsp_t1000e::shutdown`.
    #[embassy_executor::task]
    async fn shutdown_task() -> ! {
        umsh_bsp_t1000e::shutdown::run().await
    }

    /// Monitors battery voltage via SAADC and forces shutdown on low VBAT.
    /// Body lives in `umsh_bsp_t1000e::power`.
    #[embassy_executor::task]
    async fn power_task(saadc: Saadc<'static, 1>, sensor_rail: Output<'static>) {
        umsh_bsp_t1000e::power::run_battery_monitor(saadc, sensor_rail).await;
    }

    async fn heartbeat(mut led: Output<'static>, mut wdt: WatchdogHandle) -> ! {
        let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
        loop {
            wdt.pet();
            let decision = engine.tick(Instant::now().as_millis());
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
        // Init heap before any alloc-using code. 8 KiB is generous; runtime
        // alloc is near-zero since all MAC state lives in static arrays.
        {
            const HEAP_SIZE: usize = 8192;
            static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
            unsafe { crate::ALLOCATOR.init(core::ptr::addr_of!(HEAP) as usize, HEAP_SIZE) }
        }

        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

        // Seize LR1110 RESET immediately and hold it low. The LR1110 can
        // outlive nRF soft resets; if a previous image left it in a bad state
        // (e.g. broken DCDC on this board), holding RESET prevents that state
        // from destabilizing USB before LoRa::new() runs.
        let radio_rst = Output::new(p.P1_10, Level::Low, OutputDrive::Standard);

        // Button-held-at-boot DFU check (active-HIGH, pull-down).
        let button = Input::new(p.P0_06, Pull::Down);
        cortex_m::asm::delay(640_000); // ~10 ms settle
        if button.is_high() {
            umsh_bsp_nrf52840::gpregret::enter_dfu_serial();
        }

        // WDT: 8 s timeout, petted by heartbeat.
        let mut wdt_config = WdtConfig::default();
        wdt_config.timeout_ticks = 32768 * 8;
        let (_wdt, [wdt_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, wdt_config).unwrap_or_else(|_| panic!("wdt"));

        // Read any panic message left by the previous boot, then clear it.
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

        // ── Piezo buzzer ─────────────────────────────────────────────────────
        // P0.25 = PWM, P1.05 = power-enable for the buzzer driver chip.
        // Div16 prescaler gives a 1 MHz PWM clock — comfortably covers the
        // 1–2 kHz melody range with max_duty 500–1000.
        let buzzer_pwm = {
            let mut cfg = SimpleConfig::default();
            cfg.prescaler = Prescaler::Div16;
            SimplePwm::new_1ch(p.PWM0, p.P0_25, &cfg)
        };
        let buzzer_enable = Output::new(p.P1_05, Level::Low, OutputDrive::Standard);
        spawner.spawn(buzzer_task(buzzer_pwm, buzzer_enable).unwrap());
        // Boot chirp — independent of USB, so headless boots also signal life.
        umsh_bsp_t1000e::BUZZER_SIGNAL.signal(&buzzer_melodies::POWER_ON);

        // ── NVMC storage ─────────────────────────────────────────────────────
        // 64 KB at 0xE4000..0xF4000 (top of app window, per memory.x).
        let storage: &'static NvmcStorage = STORAGE.init(NvmcStorage::new(Nvmc::new(p.NVMC)));

        // ── Local identity ────────────────────────────────────────────────────
        // The hardware-TRNG RNG built here is the single RNG path for this
        // firmware — used for first-boot identity generation AND passed
        // ownership-by-value into `Mac::new` below as `Platform::Rng`.
        //
        // Load identity from flash on subsequent boots; TRNG-generate on
        // first boot. We do NOT fall back to any PRNG on failure — a
        // predictable long-term key is worse than panicking.
        let mut rng = Nrf52840Rng::new(p.RNG);
        let sk_bytes: [u8; 32] = match storage.load_sk().await {
            Ok(Some(sk)) => sk,
            Ok(None) => {
                let mut sk = [0u8; 32];
                rng.fill_bytes(&mut sk);
                storage
                    .store_sk(&sk)
                    .await
                    .unwrap_or_else(|_| panic!("identity persist"));
                sk
            }
            Err(_) => panic!("storage init failed"),
        };
        let identity = SoftwareIdentity::from_secret_bytes(&sk_bytes);
        let local_key = *identity.public_key();

        // ── LR1110 LoRa radio ─────────────────────────────────────────────────
        // Pin map (confirmed against MeshCore variants/t1000-e):
        //   SPI bus: SCK=P0.11, MISO=P1.08, MOSI=P1.09 (TWISPI0)
        //   CS=P0.12, RST=P1.10, IRQ/DIO1=P1.01, BUSY=P0.07
        //   DIO3: 1.6 V TCXO control (handled by lora-phy SetDIO3AsTCXOCtrl)
        //   DIO5-8: internal RF switch (handled by RfSwitchConfig via SetDioAsRfSwitch)
        let t_frame_ms = umsh_radio_loraphy::airtime_ms(
            SpreadingFactor::_7,
            Bandwidth::_62KHz,
            umsh_radio_loraphy::MAX_PAYLOAD,
        );
        {
            let mut cfg = SpimConfig::default();
            cfg.frequency = Frequency::M8;
            let radio_bus = Spim::new(
                p.TWISPI0, Irqs, p.P0_11, // SCK
                p.P1_08, // MISO
                p.P1_09, // MOSI
                cfg,
            );
            let radio_cs = Output::new(p.P0_12, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();

            // Pull::Down on DIO1: the LR1110's IRQ output is push-pull active-high,
            // so a pull-down prevents floating reads when IRQ is de-asserted.
            let radio_interrupt = Input::new(p.P1_01, Pull::Down);
            let radio_busy = Input::new(p.P0_07, Pull::None);

            let iv = GenericLr1110InterfaceVariant::new(
                radio_rst,
                radio_interrupt,
                radio_busy,
                None, // rf_switch_rx: not external — DIO5-8 handle it internally
                None, // rf_switch_tx: same
            )
            .unwrap_or_else(|_| panic!("lr1110 iv"));

            let lora_config = LoraConfig {
                // HP PA — SetTx will route through tx_hp (0x0A = DIO6+DIO8)
                // on our RF-switch table. Combined with TX_POWER_DBM=22 this
                // is the maximum output the chip + board can produce.
                chip: Lr1110Chip::with_pa(PaSelection::Hp),
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V6),
                use_dcdc: false, // T1000-E module has no external inductor for BST
                rx_boost: true,
                rf_switch: Some(RF_SWITCH),
            };

            // enable_public_network=false → private sync word 0x1424,
            // matching MeshCore's RADIOLIB_SX126X_SYNC_WORD_PRIVATE = 0x12.
            let mut lora = LoRa::new(Lr1110::new(radio_spi, iv, lora_config), false, Delay)
                .await
                .unwrap_or_else(|_| panic!("radio init"));

            // MeshCore-US on-air parameters tuned for LR1110.
            //
            // Phase 2.5 RX bringup proved that preamble_length=16 (matching
            // MeshCore's RadioLib TX preamble) reliably triggers
            // SyncWordHeaderValid → RxDone on the LR1110. The shared
            // `umsh_radio_loraphy::meshcore_us_params` helper uses 8 for RX,
            // which is fine for the SX1262 on T-Echo but loses packets on
            // LR1110. We pin both rx and tx to 16 here to match what worked
            // on real hardware.
            let mdltn = lora
                .create_modulation_params(
                    SpreadingFactor::_7,
                    Bandwidth::_62KHz,
                    CodingRate::_4_5,
                    910_525_000,
                )
                .unwrap_or_else(|_| panic!("modulation params"));
            let rx_pkt = lora
                .create_rx_packet_params(
                    16,    // preamble length: LR1110 needs 16 for MeshCore-US
                    false, // explicit header
                    255,   // max payload
                    true,  // CRC on
                    false, // IQ normal
                    &mdltn,
                )
                .unwrap_or_else(|_| panic!("rx packet params"));
            let tx_pkt = lora
                .create_tx_packet_params(
                    16,    // preamble length: matches MeshCore RadioLib
                    false, // explicit header
                    true,  // CRC on
                    false, // IQ normal
                    &mdltn,
                )
                .unwrap_or_else(|_| panic!("tx packet params"));

            spawner.spawn(radio_runner_task(lora, mdltn, rx_pkt, tx_pkt).unwrap());
        }

        // ── MAC coordinator ───────────────────────────────────────────────────
        let radio_handle = umsh_radio_loraphy::LoraphyRadio::new(&RADIO_CH, t_frame_ms);
        let crypto = CryptoEngine::new(SoftwareAes, SoftwareSha256);
        let mut mac = T1000EMac::new(
            radio_handle,
            crypto,
            EmbassyClock,
            rng,
            NvmcCounterStore::new(storage),
            RepeaterConfig::default(),
            OperatingPolicy::default(),
        );
        let identity_id = mac
            .add_identity(identity)
            .unwrap_or_else(|_| panic!("identity"));
        // Restore TX frame-counter boundary so the counter never rewinds.
        mac.load_persisted_counter(identity_id)
            .await
            .unwrap_or_else(|_| panic!("tx counter load"));
        let mac_cell: &'static AsyncRefCell<T1000EMac> = MAC_CELL.init(AsyncRefCell::new(mac));

        // ── USB stack ─────────────────────────────────────────────────────────
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        let mut config = Config::new(0x2886, 0x0057);
        config.manufacturer = Some("Seeed");
        config.product = Some("T1000-E UMSH CLI");
        config.serial_number = Some("umsh-t1000e");
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

        // ── Battery ADC ───────────────────────────────────────────────────────
        // P0.02 = AIN0 via 2:1 divider; sensor rail P1.06 gates the path.
        let sensor_rail = Output::new(p.P1_06, Level::Low, OutputDrive::Standard);
        let saadc = Saadc::new(
            p.SAADC,
            Irqs,
            SaadcConfig::default(), // 12-bit, no oversample
            [ChannelConfig::single_ended(p.P0_02)],
        );

        // ── Host + LocalNode ──────────────────────────────────────────────────
        // Build the Host and add the local identity's node here in main() so
        // we can clone the node for the beacon task before moving Host into
        // mac_task. The Host's internal node store and the cloned LocalNode
        // share Rc state, so events route correctly regardless of which task
        // holds which copy.
        let handle = MacHandle::new(mac_cell);
        let mut host: T1000EHost = Host::new(handle);
        let node = host.add_node(identity_id);
        let beacon_node = node.clone();

        // Load persisted peers and channels and register their keys into the
        // MAC *now*, at boot — independent of USB. This used to live in the CLI
        // task, which only registers after a host opens the CDC port; until
        // then the coordinator had no peer/channel keys, so it could not
        // authenticate inbound secure frames and silently dropped every ping
        // until a serial client attached. Aliases/names are carried along to
        // the CLI for display only; the MAC needs just the keys.
        let mut peer_buf: heapless::Vec<([u8; 32], Option<heapless::String<16>>), 8> =
            heapless::Vec::new();
        let _ = storage.load_all_peers(&mut peer_buf).await;
        let mut ch_buf: heapless::Vec<(heapless::String<16>, [u8; 32]), 2> = heapless::Vec::new();
        let _ = storage.load_all_channels(&mut ch_buf).await;
        for (pk, _alias) in peer_buf.iter() {
            let _ = node.peer(PublicKey(*pk)).await;
        }
        for (name, key_bytes) in ch_buf.iter() {
            let channel =
                umsh_node::Channel::private(umsh_core::ChannelKey(*key_bytes), name.as_str());
            let _ = node.join(&channel).await;
        }

        // Restore RX counter boundaries before the MAC starts processing
        // packets so the replay window starts above the last accepted frame.
        // Runs after the peer registration above so the persisted boundaries
        // actually land on registered peers.
        MacHandle::new(mac_cell)
            .load_all_persisted_rx_counters()
            .await
            .ok();

        spawner.spawn(output_task(tx).unwrap());
        spawner.spawn(button_task(button).unwrap());
        spawner.spawn(shutdown_task().unwrap());
        spawner.spawn(power_task(saadc, sensor_rail).unwrap());
        spawner.spawn(mac_task(host).unwrap());
        spawner.spawn(beacon_task(beacon_node).unwrap());
        spawner.spawn(
            cli_task(
                node, local_key, storage, peer_buf, ch_buf, rx, prev_panic_buf, prev_panic_len,
            )
            .unwrap(),
        );

        join(usb.run(), heartbeat(led, wdt_handle)).await;
    }
}
