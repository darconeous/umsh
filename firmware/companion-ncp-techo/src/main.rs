// LilyGO T-Echo companion-radio NCP firmware.
//
// Exposes the SX1262 as a host-controlled PHY speaking the minimal
// companion-radio protocol (docs/protocol/src/companion-radio-minimal.md)
// with HDLC-Lite framing over USB-CDC. The UMSH MAC does not run here:
// the host owns it and drives this device through
// `umsh::companion_radio::CompanionRadio`.
//
// Protocol behavior lives in `umsh-companion-ncp::Session` (host-tested,
// no I/O); this binary is only glue:
//
// Task layout (steady state):
//   - main():            joins usb.run / heartbeat (LED + WDT pet)
//   - radio_task:        owns lora_phy::LoRa via umsh_radio_loraphy::ncp_runner;
//                        modulation/frequency/power are pushed at runtime
//                        through NCP_CTL as the host sets properties
//   - usb_in_task:       owns CdcAcmRescue; forwards packets and
//                        connect/disconnect edges into INPUT_CH (keeps
//                        read_packet out of any select, so cancel safety
//                        never depends on the USB driver)
//   - ncp_task:          owns the Session + HDLC decoder; sorts INPUT_CH,
//                        radio RX, and TX completions into session calls
//   - output_task:       owns the USB Sender, drains OUTPUT_CH
//   - button_task:       2 s hold on the user button fires SHUTDOWN_SIGNAL
//   - shutdown_task:     tri-states peripheral pins, drops the rail,
//                        enters System OFF
//
// CMD_RST is a protocol-level reset: session state returns to post-reset
// defaults and the radio is re-applied (disabled), but the MCU and the
// USB link stay up. Host attach also resets the session, silently — the
// reset notice is only emitted in response to CMD_RST so the host never
// sees an unsolicited reset it didn't ask for mid-handshake.
//
// Safety primitives inherited from the BSP (see umsh-bsp-nrf52840):
//   * Panic capture into reserved RAM (reported as STATUS_RESET_CRASH).
//   * 1200-baud touchless reset and Ctrl-C × 3 + "dfu" escape to
//     bootloader (baked into CdcAcmRescue).
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

// lora-phy 3.x unconditionally depends on defmt. Provide a zero-overhead
// no-op global logger so this binary links without any debug transport.
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
    use embassy_futures::select::{Either, Either3, select, select3};
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
    use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
    use embassy_usb::{Builder, Config};
    use embedded_hal_bus::spi::ExclusiveDevice;
    use lora_phy::LoRa;
    use lora_phy::iv::GenericSx126xInterfaceVariant;
    use lora_phy::sx126x::{Config as LoraConfig, Sx126x, Sx1262, TcxoCtrlVoltage};
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_bsp_nrf52840::system_off::{Port, WakePin, WakeSense, power_off, tristate_pin};
    use umsh_companion::{Status, hdlc};
    use umsh_companion_ncp::{Effect, RadioSettings, Session, SessionConfig, TxPower};
    use umsh_radio_loraphy::{
        MAX_PAYLOAD, NcpControl, NcpSettings, RxFrame, TxRequest, bandwidth_from_hz,
        coding_rate_from_denom, spreading_factor_from_u8,
    };
    use umsh_ux_tracker::led::{LedEngine, LedTimings};

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
        // SPIM1 → SX1262 LoRa SPI bus. embassy-nrf names this peripheral
        // TWISPI1 (it's the shared TWIM1/SPIM1 block on nRF52840).
        TWISPI1     => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI1>;
    });

    // ─── Configuration ───────────────────────────────────────────────────────

    /// SX1262 PA limits on this module.
    const MIN_TX_POWER_DBM: i8 = -9;
    const MAX_TX_POWER_DBM: i8 = 22;

    fn session_config() -> SessionConfig {
        SessionConfig {
            ncp_version: concat!("umsh-ncp-techo/0.1; ", env!("GIT_SHORT_SHA")),
            mtu: MAX_PAYLOAD as u16,
            // Fixed at build time: LoRa::new(.., false, ..) below sets the
            // private-network word 0x12 → SX126x registers 0x1424.
            sync_word: 0x1424,
            min_tx_power_dbm: MIN_TX_POWER_DBM,
            max_tx_power_dbm: MAX_TX_POWER_DBM,
            // SX1262 tunable range.
            freq_khz_min: 150_000,
            freq_khz_max: 960_000,
            // Post-reset defaults (PHY disabled until the host enables it);
            // RF values match the MeshCore-US bringup profile.
            defaults: RadioSettings {
                enabled: false,
                freq_khz: 910_525,
                bw_hz: 62_500,
                sf: 7,
                cr_denom: 5,
                tx_power_dbm: 14,
            },
            default_duty_limit: umsh_companion::ids::DUTY_LIMIT_DISABLED,
        }
    }

    // ─── Concrete types ──────────────────────────────────────────────────────

    type RadioSpiBus = ExclusiveDevice<Spim<'static>, Output<'static>, Delay>;
    type RadioIv = GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>;
    type RadioKind = Sx126x<RadioSpiBus, RadioIv, Sx1262>;
    type LoraRadio = LoRa<RadioKind, Delay>;

    type TechoUsbDriver = Driver<'static, HardwareVbusDetect>;
    type TechoSender = embassy_usb::class::cdc_acm::Sender<'static, TechoUsbDriver>;
    type TechoRescue = CdcAcmRescue<'static, TechoUsbDriver>;

    // ─── Static shared state ─────────────────────────────────────────────────

    /// Channels shared between the radio runner and the NCP session task.
    type RadioCh = umsh_radio_loraphy::Channels<ThreadModeRawMutex, 4, 2>;
    static RADIO_CH: RadioCh = RadioCh::new();

    /// Runtime radio settings pushed by the session to the runner.
    static NCP_CTL: NcpControl<ThreadModeRawMutex> = NcpControl::new();

    /// USB receive path: packets and connection edges from usb_in_task
    /// to ncp_task. A channel (rather than selecting on read_packet
    /// directly) keeps USB reads sequential and cancel-safety trivial.
    enum InEvent {
        Connected,
        Disconnected,
        Data(heapless::Vec<u8, 64>),
    }
    static INPUT_CH: Channel<ThreadModeRawMutex, InEvent, 8> = Channel::new();

    /// One USB CDC bulk packet in the output queue.
    type OutChunk = heapless::Vec<u8, 64>;
    static OUTPUT_CH: Channel<ThreadModeRawMutex, OutChunk, 16> = Channel::new();

    /// Fired by button_task on a 2 s hold; consumed by shutdown_task.
    static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    // ─── Outgoing frame staging ──────────────────────────────────────────────

    /// Largest companion frame the session emits (CMD_STR_RECV around a
    /// full-MTU payload), with HDLC escaping headroom.
    const WIRE_MAX: usize = hdlc::max_encoded_len(300);

    /// Collects frames emitted synchronously by the session, then
    /// flushes them to OUTPUT_CH asynchronously. The session emits at
    /// most one frame per call; two slots give headroom.
    struct Emitter {
        bufs: [[u8; WIRE_MAX]; 2],
        lens: [usize; 2],
        count: usize,
    }

    impl Emitter {
        const fn new() -> Self {
            Self {
                bufs: [[0; WIRE_MAX]; 2],
                lens: [0; 2],
                count: 0,
            }
        }

        /// HDLC-encode one companion frame into the next slot.
        ///
        /// The session is expected to emit at most `bufs.len()` frames per call
        /// and every frame is expected to fit `WIRE_MAX`. Both invariants are
        /// asserted in debug builds so a future session change that violates
        /// them is caught rather than silently dropping a response.
        fn push(&mut self, frame: &[u8]) {
            if self.count >= self.bufs.len() {
                debug_assert!(
                    false,
                    "Emitter overflow: session emitted more frames per call than staging slots"
                );
                return;
            }
            match hdlc::encode_frame(frame, &mut self.bufs[self.count]) {
                Ok(len) => {
                    self.lens[self.count] = len;
                    self.count += 1;
                }
                Err(_) => debug_assert!(false, "Emitter: HDLC encode failed (frame exceeds WIRE_MAX)"),
            }
        }

        /// Queue all staged frames for the USB output task.
        async fn flush(&mut self) {
            for index in 0..self.count {
                for chunk in self.bufs[index][..self.lens[index]].chunks(64) {
                    let mut packet: OutChunk = heapless::Vec::new();
                    let _ = packet.extend_from_slice(chunk);
                    OUTPUT_CH.send(packet).await;
                }
            }
            self.count = 0;
        }
    }

    /// Execute a radio side effect requested by the session.
    async fn apply_effect(session: &Session, effect: Option<Effect>) {
        match effect {
            Some(Effect::ApplyRadio(settings)) => {
                // The session validates values against the same discrete
                // sets these converters accept, so None here is
                // unreachable; bail out defensively rather than panic.
                let (Some(sf), Some(bw), Some(cr)) = (
                    spreading_factor_from_u8(settings.sf),
                    bandwidth_from_hz(settings.bw_hz),
                    coding_rate_from_denom(settings.cr_denom),
                ) else {
                    return;
                };
                NCP_CTL.apply(NcpSettings {
                    enabled: settings.enabled,
                    freq_hz: settings.freq_khz.saturating_mul(1_000),
                    sf,
                    bw,
                    cr,
                    power_dbm: i32::from(settings.tx_power_dbm),
                });
            }
            Some(Effect::StartTransmit) => {
                let mut data: heapless::Vec<u8, MAX_PAYLOAD> = heapless::Vec::new();
                let _ = data.extend_from_slice(session.tx_data());
                let power_dbm = match session.tx_power() {
                    TxPower::Default => None,
                    TxPower::Max => Some(i32::from(MAX_TX_POWER_DBM)),
                    TxPower::Dbm(dbm) => Some(i32::from(dbm)),
                };
                RADIO_CH.tx.send(TxRequest { data, power_dbm }).await;
            }
            // SampleRssi needs `&mut Session` + the emitter, so it is handled
            // inline in ncp_task rather than here.
            Some(Effect::SampleRssi { .. }) | None => {}
        }
    }

    // ─── Tasks ───────────────────────────────────────────────────────────────

    /// Owns the `lora_phy::LoRa` instance via the reconfigurable NCP
    /// runner. RX preamble 8 symbols, TX preamble 16 (MeshCore parity).
    #[embassy_executor::task]
    async fn radio_task(lora: LoraRadio) {
        umsh_radio_loraphy::ncp_runner(lora, &RADIO_CH, &NCP_CTL, 8, 16).await;
    }

    /// Owns the USB `Sender` and drains OUTPUT_CH.
    #[embassy_executor::task]
    async fn output_task(mut tx: TechoSender) {
        loop {
            let chunk = OUTPUT_CH.receive().await;
            let _ = tx.write_packet(&chunk).await;
        }
    }

    /// Owns the CDC receive half. Forwards packets and connection edges
    /// into INPUT_CH; `wait_connection` always precedes the read loop so
    /// a disconnected port never busy-loops.
    #[embassy_executor::task]
    async fn usb_in_task(mut rx: TechoRescue) {
        loop {
            rx.wait_connection().await;
            INPUT_CH.send(InEvent::Connected).await;
            loop {
                let mut packet = [0u8; 64];
                match rx.read_packet(&mut packet).await {
                    Ok(0) | Err(_) => break,
                    Ok(len) => {
                        let mut data: heapless::Vec<u8, 64> = heapless::Vec::new();
                        let _ = data.extend_from_slice(&packet[..len]);
                        INPUT_CH.send(InEvent::Data(data)).await;
                    }
                }
            }
            INPUT_CH.send(InEvent::Disconnected).await;
        }
    }

    /// Owns the protocol session and the HDLC decoder. Sorts host bytes,
    /// radio receptions, and transmit completions into session calls and
    /// executes the resulting radio effects.
    #[embassy_executor::task]
    async fn ncp_task(boot_reason: Status) {
        let mut session = Session::new(session_config());
        let mut decoder: hdlc::Decoder<300> = hdlc::Decoder::new();
        let mut emitter = Emitter::new();

        loop {
            // Only wait for a TX completion while one is outstanding,
            // so a spurious tx_done can never be consumed early.
            let tx_done = async {
                if session.has_pending_tx() {
                    RADIO_CH.tx_done.wait().await
                } else {
                    core::future::pending().await
                }
            };

            match select3(INPUT_CH.receive(), RADIO_CH.rx.receive(), tx_done).await {
                Either3::First(InEvent::Connected) => {
                    // Fresh protocol state for the new host session.
                    // Silent: the reset notice is only sent for CMD_RST,
                    // so the host never races a stray notice during its
                    // own reset handshake.
                    decoder.reset();
                    let effect = session.reset(boot_reason, &mut |_frame: &[u8]| {});
                    apply_effect(&session, Some(effect)).await;
                }
                Either3::First(InEvent::Disconnected) => {
                    decoder.reset();
                }
                Either3::First(InEvent::Data(data)) => {
                    for &byte in &data {
                        let Some(Ok(frame_bytes)) = decoder.push(byte) else {
                            continue;
                        };
                        let now_ms = Instant::now().as_millis();
                        let effect =
                            session.handle_frame(frame_bytes, now_ms, &mut |frame: &[u8]| {
                                emitter.push(frame)
                            });
                        emitter.flush().await;
                        match effect {
                            Some(Effect::SampleRssi { tid }) => {
                                // Round-trip to the radio runner for an
                                // instantaneous RSSI sample, then answer the
                                // deferred PROP_PHY_RSSI get.
                                NCP_CTL.request_rssi();
                                let sample = NCP_CTL.wait_rssi().await;
                                session.respond_rssi(tid, sample, &mut |frame: &[u8]| {
                                    emitter.push(frame)
                                });
                                emitter.flush().await;
                            }
                            other => apply_effect(&session, other).await,
                        }
                    }
                }
                Either3::Second(RxFrame { data, info }) => {
                    session.on_radio_rx(
                        &data,
                        info.rssi,
                        info.snr.as_centibels(),
                        info.lqi,
                        &mut |frame: &[u8]| emitter.push(frame),
                    );
                    emitter.flush().await;
                }
                Either3::Third(result) => {
                    let now_ms = Instant::now().as_millis();
                    session.on_tx_result(result.is_ok(), now_ms, &mut |frame: &[u8]| {
                        emitter.push(frame)
                    });
                    emitter.flush().await;
                }
            }
        }
    }

    /// Long-press watcher for the user button on P1.10 (active-low,
    /// pull-up). Two-second hold fires SHUTDOWN_SIGNAL.
    #[embassy_executor::task]
    async fn button_task(mut button: Input<'static>) {
        const HOLD: Duration = Duration::from_secs(2);
        loop {
            button.wait_for_low().await;
            match select(button.wait_for_high(), Timer::after(HOLD)).await {
                Either::First(()) => {
                    // Released before HOLD — no-op.
                }
                Either::Second(()) => {
                    SHUTDOWN_SIGNAL.signal(());
                    button.wait_for_high().await;
                }
            }
        }
    }

    /// Controlled power-off: tri-state peripheral signal pins, drop the
    /// peripheral rail, enter System OFF. No MAC counters or display
    /// handshake in this firmware. See companion-cli-techo for the
    /// rationale behind each tri-stated pin.
    #[embassy_executor::task]
    async fn shutdown_task(peripheral_power: Output<'static>) -> ! {
        SHUTDOWN_SIGNAL.wait().await;

        // E-paper SPI bus (SPIM2): SCK=P0.31, MOSI=P1.07, MISO=P0.29
        // E-paper control:         CS=P0.30, DC=P0.28, RST=P0.02, BUSY=P0.03
        // Radio SPI bus (TWISPI1): SCK=P0.19, MOSI=P0.22, MISO=P0.23
        // Radio control:           CS=P0.24, RST=P0.25, BUSY=P0.17, DIO1=P0.20
        // (E-paper pins are unconfigured in this firmware; tri-stating
        // them anyway is harmless and keeps the list identical to the
        // CLI firmware.)
        for (port, pin) in [
            (Port::P0, 31u8),
            (Port::P1, 7u8),
            (Port::P0, 29u8),
            (Port::P0, 30u8),
            (Port::P0, 28u8),
            (Port::P0, 2u8),
            (Port::P0, 3u8),
            (Port::P0, 19u8),
            (Port::P0, 22u8),
            (Port::P0, 23u8),
            (Port::P0, 24u8),
            (Port::P0, 25u8),
            (Port::P0, 17u8),
            (Port::P0, 20u8), // radio DIO1 ← has SENSE set by async radio wait
        ] {
            tristate_pin(port, pin);
        }

        drop(peripheral_power);

        // P1.10 is the side user button. Active-low, pull-up → DETECT-low wakes.
        power_off(&[WakePin {
            port: Port::P1,
            pin: 10,
            sense: WakeSense::Low,
        }])
    }

    // ─── Main ────────────────────────────────────────────────────────────────

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

        // Peripheral power enable (P0.12). Must be high before the LoRa
        // module is addressed. Ownership transfers to shutdown_task.
        let peripheral_power = Output::new(p.P0_12, Level::High, OutputDrive::Standard);

        // WDT: 8 s timeout, petted by the heartbeat task every ~2 s.
        let mut wdt_config = WdtConfig::default();
        wdt_config.timeout_ticks = 32768 * 8;
        let (_wdt, [wdt_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, wdt_config).unwrap_or_else(|_| panic!("wdt"));

        // A message in the panic slot means the last reset was a crash;
        // report that as the reset reason. The slot is cleared either way.
        let boot_reason = {
            let mut slot = PanicSlot::new(super::panic::panic_region());
            if slot.read().is_some() {
                slot.clear();
                Status::RESET_CRASH
            } else {
                Status::RESET_POWER_ON
            }
        };

        // ── SX1262 LoRa radio ────────────────────────────────────────────────
        // Pin assignment (T-Echo hardware, firmware-confirmed):
        //   SPI bus: SCK=P0.19, MOSI=P0.22, MISO=P0.23 (TWISPI1)
        //   CS=P0.24, RST=P0.25, BUSY=P0.17, DIO1=P0.20
        //   DIO2: internal RF switch; DIO3: 1.8 V TCXO.
        {
            let mut cfg = SpimConfig::default();
            // SX1262 datasheet §8.2: max SCK = 16 MHz, Mode 0.
            cfg.frequency = Frequency::M16;
            let radio_bus = Spim::new(
                p.TWISPI1, Irqs, p.P0_19, // SCK
                p.P0_23, // MISO
                p.P0_22, // MOSI
                cfg,
            );
            let radio_cs = Output::new(p.P0_24, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();

            let radio_rst = Output::new(p.P0_25, Level::High, OutputDrive::Standard);
            let radio_dio1 = Input::new(p.P0_20, Pull::None);
            let radio_busy = Input::new(p.P0_17, Pull::None);

            let iv = GenericSx126xInterfaceVariant::new(
                radio_rst, radio_dio1, radio_busy,
                None, // rf_switch_rx: DIO2 wired internally on the T-Echo module
                None, // rf_switch_tx: same
            )
            .unwrap();

            let lora_config = LoraConfig {
                chip: Sx1262,
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8), // DIO3 → 1.8 V TCXO
                use_dcdc: true,
                rx_boost: true,
            };

            // enable_public_network=false → sync word 0x1424 (private).
            // session_config().sync_word must match this choice.
            let lora = LoRa::new(Sx126x::new(radio_spi, iv, lora_config), false, Delay)
                .await
                .unwrap_or_else(|_| panic!("radio init"));

            spawner.spawn(radio_task(lora).unwrap());
        }

        // ── USB stack ────────────────────────────────────────────────────────
        let led = Output::new(p.P0_14, Level::High, OutputDrive::Standard);
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        let mut config = Config::new(0x16c0, 0x27dd);
        config.manufacturer = Some("UMSH");
        config.product = Some("T-Echo UMSH NCP");
        config.serial_number = Some("companion-ncp-techo");
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
        spawner.spawn(usb_in_task(rx).unwrap());
        spawner.spawn(ncp_task(boot_reason).unwrap());

        let button = Input::new(p.P1_10, Pull::Up);
        spawner.spawn(button_task(button).unwrap());
        spawner.spawn(shutdown_task(peripheral_power).unwrap());

        join(usb.run(), heartbeat(led, wdt_handle)).await;
    }

    // ─── Heartbeat + WDT pet ─────────────────────────────────────────────────

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
}
