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
// pattern as hello-techo (T-Echo Phase 6). Changes from Phase 2.5:
//   - echo_task replaced by umsh_task (Host::run + CliSession::run)
//   - radio_task replaced by radio_runner_task (umsh_radio_sx126x::runner)
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
    use embassy_nrf::pwm::{DutyCycle, Prescaler, SimpleConfig, SimplePwm};
    use embassy_nrf::rng::Rng;
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
        Config as LoraConfig, Lr1110, RfSwitchConfig, TcxoCtrlVoltage,
        variant::Lr1110 as Lr1110Chip,
    };
    use lora_phy::mod_params::{Bandwidth, ModulationParams, PacketParams, SpreadingFactor};
    use rand::{TryCryptoRng, TryRng};
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::flash_store::{
        NvmcChannelStore, NvmcCounterStore, NvmcKeyValueStore, NvmcPeerStore, NvmcStorage,
    };
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_bsp_nrf52840::system_off::{
        Port, WakePin, WakeSense, drive_pin_low, power_off, tristate_pin,
    };
    use umsh_crypto::{
        CryptoEngine, NodeIdentity,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    };
    use umsh_core::PublicKey;
    use umsh_mac::{LocalIdentityId, MacHandle, OperatingPolicy, Platform, RepeaterConfig};
    use umsh_node::Host;
    use umsh_sync::AsyncRefCell;
    use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm, ButtonTimings};
    use umsh_ux_tracker::buzzer::{BuzzerDecision, BuzzerEngine, Melody, melodies as buzzer_melodies};
    use umsh_ux_tracker::led::{LedEngine, LedTimings};

    use super::cli_io;

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
        // Shared SPIM0/TWIM0 block — named TWISPI0 in embassy-nrf.
        // LR1110 SPI is on this peripheral.
        TWISPI0     => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI0>;
        RNG         => embassy_nrf::rng::InterruptHandler<peripherals::RNG>;
    });

    // ─── Constants ───────────────────────────────────────────────────────────

    /// TX power for the LR1110 LP PA. Conservative bringup default;
    /// raise to 22 dBm for the HP PA once TX is validated.
    const TX_POWER_DBM: i32 = 14;

    const DEBOUNCE: Duration = Duration::from_millis(10);

    // ─── Platform: EmbassyClock ───────────────────────────────────────────────

    struct EmbassyClock;

    impl umsh_hal::Clock for EmbassyClock {
        fn now_ms(&self) -> u64 {
            Instant::now().as_millis()
        }

        fn poll_delay_until(
            &self,
            cx: &mut core::task::Context<'_>,
            deadline_ms: u64,
        ) -> core::task::Poll<()> {
            let target = Instant::from_millis(deadline_ms);
            if Instant::now() >= target {
                return core::task::Poll::Ready(());
            }
            let mut timer = core::pin::pin!(Timer::at(target));
            timer.as_mut().poll(cx)
        }
    }

    // ─── Platform: T1000ERng (FICR-seeded XorShift64) ────────────────────────
    //
    // NOT a cryptographic RNG — used only for MAC backoff randomization.
    // Identity key generation uses the nRF52840 hardware TRNG (Rng peripheral).

    struct T1000ERng {
        state: u64,
    }

    impl T1000ERng {
        fn from_ficr() -> Self {
            // FICR DEVICEID[0] at 0x10000060, DEVICEID[1] at 0x10000064.
            // Fixed addresses per nRF52840 Product Specification §5.1.3.
            // SAFETY: FICR is read-only, always-mapped.
            let lo = unsafe { core::ptr::read_volatile(0x1000_0060u32 as *const u32) } as u64;
            let hi = unsafe { core::ptr::read_volatile(0x1000_0064u32 as *const u32) } as u64;
            Self { state: ((hi << 32) | lo).max(1) }
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            x
        }
    }

    impl TryRng for T1000ERng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.next_u64() as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.next_u64())
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dest.chunks_mut(8) {
                let val = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&val[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for T1000ERng {}

    // ─── Platform: T1000EPlatform ─────────────────────────────────────────────

    struct T1000EPlatform;

    impl Platform for T1000EPlatform {
        type Identity      = SoftwareIdentity;
        type Aes           = SoftwareAes;
        type Sha           = SoftwareSha256;
        type Radio         = umsh_radio_sx126x::Sx1262Radio<ThreadModeRawMutex, 4, 2>;
        type Delay         = Delay;
        type Clock         = EmbassyClock;
        type Rng           = T1000ERng;
        type CounterStore  = NvmcCounterStore;
        type KeyValueStore = NvmcKeyValueStore;
    }

    /// Capacity: 1 identity, 8 peers, 4 channels, 4 pending ACKs,
    /// 8 TX queue slots, 255-byte frame, 32-entry dup cache.
    type T1000EMac = umsh_mac::Mac<T1000EPlatform, 1, 8, 4, 4, 8, 255, 32>;

    // ─── Concrete radio types ─────────────────────────────────────────────────

    type RadioSpiBus = ExclusiveDevice<Spim<'static>, Output<'static>, Delay>;
    type RadioIv     = GenericLr1110InterfaceVariant<Output<'static>, Input<'static>>;
    type RadioKindT  = Lr1110<RadioSpiBus, RadioIv, Lr1110Chip>;
    type LoraRadio   = LoRa<RadioKindT, Delay>;

    // ─── Static shared state ─────────────────────────────────────────────────

    /// Channels shared between radio_runner_task and Sx1262Radio / MAC.
    /// 4 inbound frames, 2 pending TX requests — same as T-Echo.
    type RadioCh = umsh_radio_sx126x::Channels<ThreadModeRawMutex, 4, 2>;
    static RADIO_CH: RadioCh = RadioCh::new();

    static MAC_CELL: StaticCell<AsyncRefCell<T1000EMac>> = StaticCell::new();
    static STORAGE:  StaticCell<NvmcStorage>              = StaticCell::new();

    /// Single-consumer shutdown trigger. Fired by `button_task` on long-press
    /// and by `PowerSignaler::request_power_off` from the CLI `/poweroff` command.
    static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Buzzer melody request. Latest signal wins — firing during a melody
    /// replaces it immediately. The buzzer task converts a `&'static Melody`
    /// into PWM tones via `BuzzerEngine`.
    static BUZZER_SIGNAL: Signal<ThreadModeRawMutex, &'static Melody> = Signal::new();

    // ─── USB types ────────────────────────────────────────────────────────────

    type T1000eUsbDriver = Driver<'static, HardwareVbusDetect>;
    type T1000eSender    = Sender<'static, T1000eUsbDriver>;
    type T1000eRescue    = CdcAcmRescue<'static, T1000eUsbDriver>;

    // ─── RF switch config ─────────────────────────────────────────────────────

    /// T1000-E RF-switch DIO table. Sourced from MeshCore's `t1000-e/target.cpp`:
    ///   STBY: LOW LOW LOW LOW   → 0x00
    ///   RX:   HIGH LOW LOW HIGH → DIO5+DIO8 = 0x09
    ///   TX:   HIGH HIGH LOW HIGH → DIO5+DIO6+DIO8 = 0x0B  (LP PA)
    ///   TX_HP: LOW HIGH LOW HIGH → DIO6+DIO8 = 0x0A  (HP PA)
    ///   GNSS: LOW LOW HIGH LOW  → DIO7 = 0x04
    const T1000E_RF_SWITCH: RfSwitchConfig = RfSwitchConfig {
        standby: 0x00,
        rx:      0x09,
        tx:      0x0B,
        tx_hp:   0x0A,
        tx_hf:   0x00,
        gnss:    0x04,
        wifi:    0x00,
    };

    // ─── PowerSignaler ────────────────────────────────────────────────────────

    /// Bridges the CLI `/poweroff` command to the shutdown task.
    struct PowerSignaler;

    impl umsh_hal::PowerControl for PowerSignaler {
        fn request_power_off(&self) {
            SHUTDOWN_SIGNAL.signal(());
        }
    }

    // ─── Tasks ───────────────────────────────────────────────────────────────

    /// Drains cli_io::OUTPUT_CH to the USB sender. Decoupling the sender from
    /// umsh_task lets RX keep flowing while TX awaits host IN polls.
    #[embassy_executor::task]
    async fn output_task(mut tx: T1000eSender) {
        cli_io::drain_to_sender(&mut tx).await;
    }

    /// Owns the LR1110 LoRa instance. Loops continuous RX ↔ TX as requests
    /// arrive from the MAC via RADIO_CH. umsh_radio_sx126x::runner is generic
    /// over RadioKind, so the LR1110 LoRa instance works directly.
    #[embassy_executor::task]
    async fn radio_runner_task(
        lora: LoraRadio,
        mdltn: ModulationParams,
        rx_pkt: PacketParams,
        tx_pkt: PacketParams,
    ) {
        umsh_radio_sx126x::runner(lora, &RADIO_CH, mdltn, rx_pkt, tx_pkt, TX_POWER_DBM).await;
    }

    /// Owns the piezo buzzer: PWM on P0.25 and power-enable on P1.05.
    /// Idle: PWM disabled, enable pin LOW (buzzer driver chip unpowered).
    /// On melody: enable HIGH, PWM emits a 50% duty square wave at the
    /// engine's current tone frequency, stepping through notes via
    /// `BuzzerEngine::tick`.
    ///
    /// Frequencies in the melodies are 1–2 kHz; with Prescaler::Div16
    /// the PWM clock is 1 MHz, giving max_duty 500–1000 — plenty of
    /// resolution at 50% duty.
    #[embassy_executor::task]
    async fn buzzer_task(mut pwm: SimplePwm<'static>, mut enable: Output<'static>) {
        let mut engine = BuzzerEngine::new();

        // Idle state: silent, unpowered.
        pwm.disable();
        enable.set_low();
        let mut driving = false;

        loop {
            match engine.tick(Instant::now().as_millis()) {
                BuzzerDecision::Tone { frequency_hz, next_deadline_ms } => {
                    // set_period recomputes max_duty for the given frequency,
                    // so the half-max read here is always the right 50% point.
                    pwm.set_period(frequency_hz as u32);
                    let half = pwm.max_duty() / 2;
                    pwm.set_duty(0, DutyCycle::normal(half));
                    if !driving {
                        enable.set_high();
                        pwm.enable();
                        driving = true;
                    }
                    // Wait for the note to end, or for a fresh play request
                    // to interrupt it.
                    match select(
                        BUZZER_SIGNAL.wait(),
                        Timer::at(Instant::from_millis(next_deadline_ms)),
                    )
                    .await
                    {
                        Either::First(melody) => {
                            engine.play(melody, Instant::now().as_millis());
                        }
                        Either::Second(()) => {}
                    }
                }
                BuzzerDecision::Silent => {
                    if driving {
                        pwm.disable();
                        enable.set_low();
                        driving = false;
                    }
                    let melody = BUZZER_SIGNAL.wait().await;
                    engine.play(melody, Instant::now().as_millis());
                }
            }
        }
    }

    /// Combined task: drives the MAC via `Host::run` and runs the `CliSession`
    /// concurrently via `select`. The shared `AsyncRefCell<Mac>` serialises
    /// MAC access between the host driver and the CLI's send-side calls.
    #[embassy_executor::task]
    async fn umsh_task(
        mac_cell: &'static AsyncRefCell<T1000EMac>,
        identity_id: LocalIdentityId,
        local_key: PublicKey,
        storage: &'static NvmcStorage,
        rx: T1000eRescue,
        prev_panic_buf: &'static [u8; 256],
        prev_panic_len: usize,
    ) {
        use umsh_cli::CliSession;
        use umsh_cli::io::CliOutput;
        use umsh_cli::logger::NullLogger;

        let handle = MacHandle::new(mac_cell);
        let mut host: Host<'_, T1000EPlatform, 1, 8, 4, 4, 8, 255, 32> = Host::new(handle);
        let node = host.add_node(identity_id);

        let mut input = cli_io::CdcInput::new(rx);
        let mut out   = cli_io::CdcOutput::new();

        // Pre-load persisted state before first connect so register_peer /
        // register_channel calls below don't block the CLI banner.
        let mut peer_buf: heapless::Vec<([u8; 32], Option<heapless::String<16>>), 8> =
            heapless::Vec::new();
        let _ = storage.load_all_peers(&mut peer_buf).await;
        let mut ch_buf: heapless::Vec<(heapless::String<16>, [u8; 32]), 2> =
            heapless::Vec::new();
        let _ = storage.load_all_channels(&mut ch_buf).await;

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

        let peer_store    = NvmcPeerStore::new(storage);
        let channel_store = NvmcChannelStore::new(storage);
        let mut cli: CliSession<_, _, _, _, _, _, 4, 4, 2, 8, 2, 128> = CliSession::new(
            node,
            local_key,
            out,
            NullLogger::new(),
            peer_store,
            channel_store,
            PowerSignaler,
        );

        // Re-register persisted peers and channels into the session tables.
        for (pk, alias) in peer_buf.iter() {
            let _ = cli.register_peer(PublicKey(*pk), alias.as_deref()).await;
        }
        // Restore RX counter boundaries so the replay window starts above
        // any frames accepted before the last reboot.
        MacHandle::new(mac_cell)
            .load_all_persisted_rx_counters()
            .await
            .ok();
        for (name, key_bytes) in ch_buf.iter() {
            let _ = cli.register_channel(name.as_str(), *key_bytes).await;
        }

        loop {
            match select(host.run(), cli.run(&mut input)).await {
                Either::First(_) => panic!("host exited"),
                Either::Second(_) => {}
            }
        }
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
                Some(ButtonEvent::Long) => {
                    // Wait for button release before signalling shutdown.
                    // If we fire while the button is still HIGH, shutdown_task
                    // arms SENSE=High on a pin that is already HIGH, causing an
                    // instant DETECT wake — observable as an immediate reboot.
                    button.wait_for_low().await;
                    Timer::after(DEBOUNCE).await;
                    pressed = false;
                    fsm = ButtonFsm::new(ButtonTimings::default());
                    SHUTDOWN_SIGNAL.signal(());
                }
                Some(ButtonEvent::Triple) => {
                    umsh_bsp_nrf52840::gpregret::enter_dfu_uf2();
                }
                _ => {}
            }
        }
    }

    /// Orchestrates the controlled power-off. Tristates peripheral GPIOs
    /// (clearing any embassy SENSE bits that would trigger instant DETECT wake),
    /// holds LR1110 in reset, then enters System OFF with the button armed as
    /// the wake source.
    #[embassy_executor::task]
    async fn shutdown_task() -> ! {
        SHUTDOWN_SIGNAL.wait().await;

        // Play the power-off chirp before tearing anything down. POWER_OFF
        // is 80+80+120 = 280 ms; wait 320 ms to let the final note finish
        // and the buzzer task return to its silent state.
        BUZZER_SIGNAL.signal(&buzzer_melodies::POWER_OFF);
        Timer::after(Duration::from_millis(320)).await;

        // Hold LR1110 in reset (active-low). Stops chip clocks and collapses
        // current draw to the reset-state minimum.
        drive_pin_low(Port::P1, 10);
        cortex_m::asm::delay(640); // ~10 µs @ 64 MHz

        // Tristate all peripheral signal pins. Embassy's async GPIO
        // `wait_for_*` leaves PIN_CNF SENSE bits set on in-flight waits;
        // any such pin matching its SENSE level at System OFF entry fires
        // DETECT and the chip wakes immediately (observable as a reboot).
        //
        // Button P0.06 is left alone — power_off configures it for wake.
        // P1.10 (LR1110 RESET) is left driving LOW intentionally.
        tristate_pin(Port::P0, 24); // LED
        tristate_pin(Port::P0, 25); // Buzzer PWM
        tristate_pin(Port::P1,  5); // Buzzer enable
        tristate_pin(Port::P0, 11); // SPI SCK
        tristate_pin(Port::P0, 12); // SPI CS
        tristate_pin(Port::P0,  7); // LR1110 BUSY
        tristate_pin(Port::P1,  1); // LR1110 DIO1/IRQ
        tristate_pin(Port::P1,  8); // SPI MISO
        tristate_pin(Port::P1,  9); // SPI MOSI

        // Button is active-high with pull-down → wake on rising edge.
        power_off(&[WakePin { port: Port::P0, pin: 6, sense: WakeSense::High }])
    }

    async fn heartbeat(mut led: Output<'static>, mut wdt: WatchdogHandle) -> ! {
        let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
        loop {
            wdt.pet();
            let decision = engine.tick(Instant::now().as_millis());
            if decision.on { led.set_high() } else { led.set_low() }
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
        BUZZER_SIGNAL.signal(&buzzer_melodies::POWER_ON);

        // ── NVMC storage ─────────────────────────────────────────────────────
        // 64 KB at 0xE4000..0xF4000 (top of app window, per memory.x).
        let storage: &'static NvmcStorage = STORAGE.init(NvmcStorage::new(Nvmc::new(p.NVMC)));

        // ── Local identity ────────────────────────────────────────────────────
        // Load from flash on subsequent boots; TRNG-generate on first boot.
        // We do NOT fall back to a FICR-seeded PRNG on failure — a predictable
        // long-term key is worse than panicking.
        let sk_bytes: [u8; 32] = match storage.load_sk().await {
            Ok(Some(sk)) => sk,
            Ok(None) => {
                let mut hw_rng = Rng::new(p.RNG, Irqs);
                hw_rng.set_bias_correction(true);
                let mut sk = [0u8; 32];
                hw_rng.fill_bytes(&mut sk).await;
                storage.store_sk(&sk).await.unwrap_or_else(|_| panic!("identity persist"));
                sk
            }
            Err(_) => panic!("storage init failed"),
        };
        let identity  = SoftwareIdentity::from_secret_bytes(&sk_bytes);
        let local_key = *identity.public_key();

        let rng = T1000ERng::from_ficr();

        // ── LR1110 LoRa radio ─────────────────────────────────────────────────
        // Pin map (confirmed against MeshCore variants/t1000-e):
        //   SPI bus: SCK=P0.11, MISO=P1.08, MOSI=P1.09 (TWISPI0)
        //   CS=P0.12, RST=P1.10, IRQ/DIO1=P1.01, BUSY=P0.07
        //   DIO3: 1.6 V TCXO control (handled by lora-phy SetDIO3AsTCXOCtrl)
        //   DIO5-8: internal RF switch (handled by RfSwitchConfig via SetDioAsRfSwitch)
        let t_frame_ms = umsh_radio_sx126x::airtime_ms(
            SpreadingFactor::_7,
            Bandwidth::_62KHz,
            umsh_radio_sx126x::MAX_PAYLOAD,
        );
        {
            let mut cfg = SpimConfig::default();
            cfg.frequency = Frequency::M8;
            let radio_bus = Spim::new(
                p.TWISPI0, Irqs,
                p.P0_11, // SCK
                p.P1_08, // MISO
                p.P1_09, // MOSI
                cfg,
            );
            let radio_cs  = Output::new(p.P0_12, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();

            // Pull::Down on DIO1: the LR1110's IRQ output is push-pull active-high,
            // so a pull-down prevents floating reads when IRQ is de-asserted.
            let radio_interrupt = Input::new(p.P1_01, Pull::Down);
            let radio_busy      = Input::new(p.P0_07, Pull::None);

            let iv = GenericLr1110InterfaceVariant::new(
                radio_rst,
                radio_interrupt,
                radio_busy,
                None, // rf_switch_rx: not external — DIO5-8 handle it internally
                None, // rf_switch_tx: same
            )
            .unwrap_or_else(|_| panic!("lr1110 iv"));

            let lora_config = LoraConfig {
                chip:      Lr1110Chip::new(),
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V6),
                use_dcdc:  false, // T1000-E module has no external inductor for BST
                rx_boost:  true,
                rf_switch: Some(T1000E_RF_SWITCH),
            };

            // enable_public_network=false → private sync word 0x1424,
            // matching MeshCore's RADIOLIB_SX126X_SYNC_WORD_PRIVATE = 0x12.
            let mut lora = LoRa::new(Lr1110::new(radio_spi, iv, lora_config), false, Delay)
                .await
                .unwrap_or_else(|_| panic!("radio init"));

            // meshcore_us_params: 910.525 MHz / SF7 / BW62.5 kHz / CR4/5 /
            // rx_preamble=8 / tx_preamble=16. Generic over RadioKind; works
            // with the LR1110 LoRa instance directly.
            let (mdltn, rx_pkt, tx_pkt) = umsh_radio_sx126x::meshcore_us_params(&mut lora)
                .unwrap_or_else(|_| panic!("radio params"));

            spawner.spawn(radio_runner_task(lora, mdltn, rx_pkt, tx_pkt).unwrap());
        }

        // ── MAC coordinator ───────────────────────────────────────────────────
        let radio_handle = umsh_radio_sx126x::Sx1262Radio::new(&RADIO_CH, t_frame_ms);
        let crypto       = CryptoEngine::new(SoftwareAes, SoftwareSha256);
        let mut mac      = T1000EMac::new(
            radio_handle,
            crypto,
            EmbassyClock,
            rng,
            NvmcCounterStore::new(storage),
            RepeaterConfig::default(),
            OperatingPolicy::default(),
        );
        let identity_id = mac.add_identity(identity).unwrap_or_else(|_| panic!("identity"));
        // Restore TX frame-counter boundary so the counter never rewinds.
        mac.load_persisted_counter(identity_id)
            .await
            .unwrap_or_else(|_| panic!("tx counter load"));
        let mac_cell: &'static AsyncRefCell<T1000EMac> =
            MAC_CELL.init(AsyncRefCell::new(mac));

        // ── USB stack ─────────────────────────────────────────────────────────
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        let mut config = Config::new(0x2886, 0x0057);
        config.manufacturer  = Some("Seeed");
        config.product       = Some("T1000-E UMSH CLI");
        config.serial_number = Some("umsh-t1000e");
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
        spawner.spawn(button_task(button).unwrap());
        spawner.spawn(shutdown_task().unwrap());
        spawner
            .spawn(
                umsh_task(
                    mac_cell,
                    identity_id,
                    local_key,
                    storage,
                    rx,
                    prev_panic_buf,
                    prev_panic_len,
                )
                .unwrap(),
            );

        join(usb.run(), heartbeat(led, wdt_handle)).await;
    }
}
