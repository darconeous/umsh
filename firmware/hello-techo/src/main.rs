// LilyGO T-Echo bringup firmware with an interactive UMSH CLI on USB-CDC.
//
// Boot sequence:
//   1. Bring up the peripheral rail (P0.12 HIGH).
//   2. Arm the watchdog (8 s timeout, petted by the heartbeat task).
//   3. Spawn the display task — initial boot screen ("UMSH bringup" + git
//      short SHA + "MAC: 0") plus subsequent count-update refreshes.
//   4. Initialize the SX1262 LoRa radio (MeshCore US settings) and spawn
//      the radio runner task.
//   5. Build a `Mac<TechoPlatform>`, park it in a `'static AsyncRefCell`,
//      and spawn `umsh_task` which drives `Host::run` + `CliSession::run`
//      concurrently over the shared `MacHandle`.
//   6. Spawn `output_task` to own the USB `Sender` and drain `OUTPUT_CH`.
//   7. Join usb.run / heartbeat in main; the CLI runs in spawned tasks.
//
// Task layout (steady state):
//   - main():               joins usb.run / heartbeat
//   - display_task:         renders the e-paper on count changes
//   - radio_runner_task:    owns lora_phy::LoRa, RX/TX state machine
//   - umsh_task:            host.run() + cli.run(), shares the MAC via MacHandle
//   - output_task:          owns the USB Sender, drains OUTPUT_CH
//
// USB CDC flow control is preserved by the output_task / OUTPUT_CH split:
// nothing blocks CdcInput::read_packet on TX progress, so the host's bulk
// OUT NAK / retry mechanism handles backpressure correctly during pastes.
//
// Safety primitives inherited from the BSP (see umsh-bsp-nrf52840):
//   * Panic capture into reserved RAM, dumped over USB on the next boot.
//   * 1200-baud touchless reset and Ctrl-C × 3 + "dfu" escape to bootloader
//     (baked into CdcAcmRescue).
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

// Low-level SSD1681 / GDEH0154D67 driver, used by display_task below.
// Sibling of mod firmware so it can live at src/display.rs without
// awkward #[path] gymnastics.
#[cfg(target_os = "none")]
mod display;

#[cfg(target_os = "none")]
mod cli_io;

// lora-phy 3.x unconditionally depends on defmt. Provide a zero-overhead
// no-op global logger so this binary links without any debug transport.
// All defmt log calls compile out in release mode; this just provides the
// required linker symbols.
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

// Global heap allocator. umsh-mac → umsh-sync → alloc; a tiny static heap
// satisfies the linker. Actual runtime alloc usage is near-zero since we drive
// the MAC with `Mac::run` directly rather than through MacHandle.
#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: embedded_alloc::Heap = embedded_alloc::Heap::empty();

#[cfg(target_os = "none")]
mod firmware {
    use core::sync::atomic::{AtomicU32, Ordering};

    use super::display;

    use embassy_executor::Spawner;
    use embassy_futures::join::join;
    use embassy_futures::select::{Either, select};
    use embassy_nrf::bind_interrupts;
    use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
    use embassy_nrf::nvmc::Nvmc;
    use embassy_nrf::peripherals;
    use embassy_nrf::spim::{Config as SpimConfig, Frequency, Spim};
    use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
    use embassy_nrf::usb::Driver;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::signal::Signal;
    use embassy_time::{Delay, Duration, Instant, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
    use embassy_usb::{Builder, Config};
    use embedded_hal_bus::spi::ExclusiveDevice;
    use lora_phy::iv::GenericSx126xInterfaceVariant;
    use lora_phy::mod_params::{Bandwidth, ModulationParams, PacketParams, SpreadingFactor};
    use lora_phy::sx126x::{Config as LoraConfig, Sx126x, Sx1262, TcxoCtrlVoltage};
    use lora_phy::LoRa;
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::flash_store::{NvmcChannelStore, NvmcCounterStore, NvmcPeerStore, NvmcStorage};
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_bsp_nrf52840::system_off::{power_off, tristate_pin, Port, WakePin, WakeSense};
    use umsh_bsp_nrf52840::{EmbassyClock, Nrf52840Rng};
    use umsh_bsp_techo::{PowerSignaler, SHUTDOWN_SIGNAL, TechoMac, TechoPlatform};
    use umsh_crypto::{
        CryptoEngine, NodeIdentity,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    };
    use umsh_core::{ChannelKey, PayloadType, PublicKey};
    use umsh_mac::{LocalIdentityId, MacHandle, OperatingPolicy, RepeaterConfig};
    use umsh_node::{Channel, Host, LocalNode};
    use umsh_sync::AsyncRefCell;

    use super::cli_io;
    use umsh_ux_tracker::led::{LedEngine, LedTimings};

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        CLOCK_POWER => embassy_nrf::usb::vbus_detect::InterruptHandler;
        // SPIM2 → e-paper SPI bus. embassy-nrf names this interrupt SPI2.
        SPI2        => embassy_nrf::spim::InterruptHandler<peripherals::SPI2>;
        // SPIM1 → SX1262 LoRa SPI bus. embassy-nrf names this peripheral
        // TWISPI1 (it's the shared TWIM1/SPIM1 block on nRF52840).
        TWISPI1     => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI1>;
    });

    // ─── Configuration constants ─────────────────────────────────────────────

    /// Display refresh throttle: do not refresh more than once per this
    /// interval. Each full refresh is ~2 s of panel flashing, so spamming
    /// updates would be both ugly and bad for the panel.
    const DISPLAY_THROTTLE: Duration = Duration::from_secs(5);

    /// FONT_10X20 character width in pixels — used for centering text.
    const FONT_W: i32 = 10;

    /// Vertical positions of the three boot-screen text lines, in pixels.
    const TITLE_Y: i32 =  70;
    const SHA_Y:   i32 = 100;
    const COUNT_Y: i32 = 130;

    /// Per-frame TX power in dBm. SX1262 PA range is roughly -9..+22.
    /// 14 dBm is the conservative bringup default.
    const TX_POWER_DBM: i32 = 14;

    // ─── Concrete types for the radio task ───────────────────────────────────
    //
    // `#[embassy_executor::task]` requires concrete types in the task
    // signature, so we name them once here.

    type RadioSpiBus = ExclusiveDevice<Spim<'static>, Output<'static>, Delay>;
    type RadioIv     = GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>;
    type RadioKind   = Sx126x<RadioSpiBus, RadioIv, Sx1262>;
    type LoraRadio   = LoRa<RadioKind, Delay>;

    // Host/node aliases (need `umsh-node`, which the BSP doesn't pull in, so the
    // firmware owns them). The const params match `TechoMac`'s capacities.
    /// Host bound to the `'static` mac_cell. Owned by `mac_task`.
    type TechoHost = Host<'static, TechoPlatform, 2, 8, 4, 4, 8, 255, 32>;
    /// LocalNode handle. Cheap to clone — passed to `cli_task`.
    type TechoNode = LocalNode<MacHandle<'static, TechoPlatform, 2, 8, 4, 4, 8, 255, 32>>;

    // ─── Static shared state ─────────────────────────────────────────────────

    /// Channels shared between the radio runner and LoraphyRadio / MAC.
    /// Capacity: 4 inbound frames, 2 pending TX requests.
    type RadioCh = umsh_radio_loraphy::Channels<ThreadModeRawMutex, 4, 2>;
    static RADIO_CH: RadioCh = RadioCh::new();

    /// Count of UMSH-authenticated packets received by the MAC coordinator.
    /// Incremented in the mac_task on_event callback; read by display_task.
    static PACKET_COUNT: AtomicU32 = AtomicU32::new(0);

    /// Fires whenever the MAC delivers a new authenticated packet. The display
    /// task wakes on this signal and reads PACKET_COUNT to render. Coalesces:
    /// rapid bursts produce one refresh per throttle window, not one per packet.
    static DISPLAY_COUNT_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Shared MAC coordinator cell. Stored in a `StaticCell` so a `'static`
    /// reference can be handed to the spawned `umsh_task` (which builds
    /// `MacHandle` / `Host` / `CliSession` off of it).
    static MAC_CELL: StaticCell<AsyncRefCell<TechoMac>> = StaticCell::new();
    static STORAGE:  StaticCell<NvmcStorage>             = StaticCell::new();

    /// Relay from the sync `on_receive` callback to the async
    /// `identity_persist_task`. Carries (pk, payload_body, len).
    /// Only the most-recent identity per sender is retained; a newer
    /// over-the-air update simply overwrites an earlier un-drained one.
    static IDENTITY_SIGNAL: Signal<ThreadModeRawMutex, ([u8; 32], [u8; 256], usize)> =
        Signal::new();

    // ─── Shutdown signalling ─────────────────────────────────────────────────
    //
    // Three signals, each single-consumer:
    //   SHUTDOWN_SIGNAL          → shutdown_task   (fired by button_task and the
    //                                              `/poweroff` CLI command)
    //   DISPLAY_SHUTDOWN_SIGNAL  → display_task    (fired by shutdown_task,
    //                                              tells the display to render the
    //                                              final frame and sleep)
    //   DISPLAY_SHUTDOWN_DONE    → shutdown_task   (fired by display_task once
    //                                              the panel is asleep)

    // SHUTDOWN_SIGNAL and PowerSignaler live in `umsh-bsp-techo::power`;
    // the display-shutdown handshake stays firmware-local because it's
    // specific to this firmware's task layout.
    static DISPLAY_SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();
    static DISPLAY_SHUTDOWN_DONE: Signal<ThreadModeRawMutex, ()> = Signal::new();

    // ─── Platform types ───────────────────────────────────────────────────────
    //
    // `TechoPlatform`, `TechoMac`, the embassy-backed clock, and the
    // hardware-TRNG RNG live in `umsh-bsp-techo` (which composes the
    // chip-level pieces from `umsh-bsp-nrf52840`).

    // ─── Tasks ───────────────────────────────────────────────────────────────

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

    // ─── Concrete USB driver types ────────────────────────────────────────────
    // ('static lifetime, VbusDetect = HardwareVbusDetect.) Used by `umsh_task`
    // and `output_task`.
    type TechoUsbDriver = Driver<'static, HardwareVbusDetect>;
    type TechoSender    = embassy_usb::class::cdc_acm::Sender<'static, TechoUsbDriver>;
    type TechoRescue    = umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue<'static, TechoUsbDriver>;

    // ─── CliSession-backed combined task ─────────────────────────────────────

    /// Owns the USB `Sender` and drains `cli_io::OUTPUT_CH`. Decoupling the
    /// sender from `umsh_task` lets RX keep flowing while TX awaits host IN
    /// polls, so USB OUT NAKs handle backpressure correctly during pastes.
    #[embassy_executor::task]
    async fn output_task(mut tx: TechoSender) {
        cli_io::drain_to_sender(&mut tx).await;
    }

    /// Drains `IDENTITY_SIGNAL` and persists received `NodeIdentityPayload`
    /// bytes for known peers. Runs independently of the MAC/CLI task so that
    /// NVMC writes (which stall the CPU for ~85 ms) don't affect radio timing.
    #[embassy_executor::task]
    async fn identity_persist_task(storage: &'static NvmcStorage) {
        loop {
            let (pk, payload, len) = IDENTITY_SIGNAL.wait().await;
            if storage.peer_exists(&pk).await.unwrap_or(false) {
                let _ = storage.update_peer_identity(&pk, &payload[..len]).await;
            }
        }
    }

    /// Drives the MAC coordinator and owns the identity-relay subscription.
    /// Independent of USB so radio RX/TX and the MAC pump (including ping
    /// auto-replies) keep running whether or not a host terminal is attached.
    #[embassy_executor::task]
    async fn mac_task(mut host: TechoHost, identity_id: LocalIdentityId) {
        // Subscribe to raw packets so NodeIdentity payloads from known peers
        // can be relayed to identity_persist_task for durable storage.
        // The guard must remain live for the duration of the task.
        let sub_node = host.node(identity_id).expect("node just added");
        let _identity_sub = sub_node.on_receive(|pkt| {
            if pkt.payload_type() != PayloadType::NodeIdentity { return false; }
            let Some(from) = pkt.from_key() else { return false; };
            let raw = pkt.payload();
            let len = raw.len().min(256);
            let mut buf = [0u8; 256];
            buf[..len].copy_from_slice(&raw[..len]);
            IDENTITY_SIGNAL.signal((from.0, buf, len));
            false // don't consume — let other handlers see it too
        });

        let _ = host.run().await;
        panic!("host exited");
    }

    /// Runs the `CliSession` over USB-CDC. The only task that blocks on a host
    /// terminal connection — the radio, MAC pump, and identity relay all run
    /// without it. Peers/channels are already registered into the MAC at boot
    /// (see `main`); the buffers passed here only populate the CLI's own
    /// display tables.
    #[embassy_executor::task]
    #[allow(clippy::too_many_arguments)]
    async fn cli_task(
        node: TechoNode,
        local_key: PublicKey,
        storage: &'static NvmcStorage,
        peer_buf: heapless::Vec<([u8; 32], Option<heapless::String<16>>), 8>,
        ch_buf: heapless::Vec<(heapless::String<16>, [u8; 32]), 2>,
        rx: TechoRescue,
        prev_panic_buf: &'static [u8; 256],
        prev_panic_len: usize,
    ) {
        use umsh_cli::CliSession;
        use umsh_cli::io::CliOutput;
        use umsh_cli::logger::NullLogger;

        let mut input = cli_io::CdcInput::new(rx);
        let mut out = cli_io::CdcOutput::new();

        // Wait for the host to open the CDC port before writing the banner.
        input.wait_connection().await;

        let _ = out.write_line("").await;
        let _ = out.write_line("UMSH CLI (T-Echo)").await;
        let _ = out.write_line("type /help for commands").await;
        if prev_panic_len > 0 {
            let _ = out.write_line("[PREV PANIC]:").await;
            if let Ok(s) = core::str::from_utf8(&prev_panic_buf[..prev_panic_len]) {
                let _ = out.write_line(s).await;
            }
        }

        let peer_store    = NvmcPeerStore::new(storage);
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

        // Populate the CLI display tables (aliases, channel names). The MAC was
        // already registered at boot, so these re-registrations are idempotent.
        for (pk, alias) in peer_buf.iter() {
            let _ = cli.register_peer(PublicKey(*pk), alias.as_deref()).await;
        }
        for (name, key_bytes) in ch_buf.iter() {
            let _ = cli.register_channel(name.as_str(), *key_bytes).await;
        }

        let _ = cli.run(&mut input).await;
        panic!("cli exited");
    }

    /// Owns the e-paper SPI bus and pins. Renders the boot screen on
    /// startup, then waits for `DISPLAY_COUNT_SIGNAL` and re-renders with
    /// the latest count.
    ///
    /// Full refresh (with flashing) per update; partial refresh on this
    /// panel requires RED-RAM previous-frame tracking which is a separate
    /// change. `DISPLAY_THROTTLE` caps the visible refresh rate.
    #[embassy_executor::task]
    async fn display_task(
        mut spi:  Spim<'static>,
        mut cs:   Output<'static>,
        mut dc:   Output<'static>,
        mut rst:  Output<'static>,
        mut busy: Input<'static>,
    ) {
        use core::fmt::Write as _;
        use embedded_graphics::geometry::Point;
        use embedded_graphics::mono_font::ascii::FONT_10X20;
        use embedded_graphics::mono_font::MonoTextStyle;
        use embedded_graphics::pixelcolor::BinaryColor;
        use embedded_graphics::text::{Baseline, Text};
        use embedded_graphics::Drawable;
        use heapless::String;

        let sha   = env!("GIT_SHORT_SHA");
        let style = MonoTextStyle::new(&FONT_10X20, BinaryColor::On);

        // Fill `buf` with a frame containing the boot text and the supplied count.
        let mut buf = [0xFFu8; display::BUF_SIZE];
        let render = |buf: &mut [u8; display::BUF_SIZE], count: u32| {
            buf.fill(0xFF);  // all-white background
            let mut fb = display::EpdFb(buf);

            // Center each line by its glyph count.
            let center_x = |text: &str| (display::WIDTH as i32 - text.len() as i32 * FONT_W) / 2;

            let title = "UMSH bringup";
            let _ = Text::with_baseline(title, Point::new(center_x(title), TITLE_Y), style, Baseline::Top).draw(&mut fb);
            let _ = Text::with_baseline(sha,   Point::new(center_x(sha),   SHA_Y),   style, Baseline::Top).draw(&mut fb);

            let mut count_str: String<16> = String::new();
            let _ = write!(count_str, "MAC: {}", count);
            let _ = Text::with_baseline(&count_str, Point::new(center_x(&count_str), COUNT_Y), style, Baseline::Top).draw(&mut fb);
        };

        // Renders centred lines (one per slice element) onto an all-white frame.
        let render_lines = |buf: &mut [u8; display::BUF_SIZE], lines: &[(&str, i32)]| {
            buf.fill(0xFF);
            let mut fb = display::EpdFb(buf);
            for (text, y) in lines {
                let cx = (display::WIDTH as i32 - text.len() as i32 * FONT_W) / 2;
                let _ = Text::with_baseline(text, Point::new(cx, *y), style, Baseline::Top)
                    .draw(&mut fb);
            }
        };

        // Initial boot screen (count = 0).
        render(&mut buf, 0);
        display::init(&mut spi, &mut cs, &mut dc, &mut rst, &mut busy).await;
        display::render(&mut spi, &mut cs, &mut dc, &mut busy, &buf).await;

        // Update loop. Races count updates against the shutdown signal.
        // We deliberately do NOT reset DISPLAY_COUNT_SIGNAL after the
        // throttle: any packet that fired during render+throttle stays
        // pending, so the next iteration starts immediately with the
        // newest count. Throttle still caps the refresh rate.
        loop {
            match select(DISPLAY_COUNT_SIGNAL.wait(), DISPLAY_SHUTDOWN_SIGNAL.wait()).await {
                Either::First(()) => {
                    let count = PACKET_COUNT.load(Ordering::Relaxed);
                    render(&mut buf, count);
                    display::render(&mut spi, &mut cs, &mut dc, &mut busy, &buf).await;
                    Timer::after(DISPLAY_THROTTLE).await;
                }
                Either::Second(()) => {
                    // Final frame, then deep sleep (RAM-retaining; the panel
                    // wakes via hardware reset on the next boot).
                    render_lines(&mut buf, &[("Powered off", 100)]);
                    display::render(&mut spi, &mut cs, &mut dc, &mut busy, &buf).await;
                    display::sleep(&mut spi, &mut cs, &mut dc).await;
                    DISPLAY_SHUTDOWN_DONE.signal(());
                    // Park forever; the shutdown task will System OFF shortly.
                    core::future::pending::<()>().await;
                }
            }
        }
    }

    /// Long-press watcher for the user button on P1.10 (active-low, pull-up).
    /// Two-second hold fires [`SHUTDOWN_SIGNAL`]. Releases before 2 s are
    /// ignored — there's no short-press action defined yet.
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
                    // Wait for release so we don't keep re-triggering.
                    button.wait_for_high().await;
                }
            }
        }
    }

    /// Orchestrates the controlled power-off:
    ///   1. tell the display to render the final frame and sleep,
    ///   2. flush any pending TX frame-counter reservations (RX counters are
    ///      drained on every `next_event` in the parallel host task),
    ///   3. wait for the display task to acknowledge (cap at 5 s),
    ///   4. drop the peripheral power rail (P0.12) so LoRa / sensors / GNSS
    ///      lose power before the chip parks,
    ///   5. configure user-button DETECT-low and enter System OFF.
    ///
    /// Diverges via [`power_off`].
    #[embassy_executor::task]
    async fn shutdown_task(
        mac_cell: &'static AsyncRefCell<TechoMac>,
        peripheral_power: Output<'static>,
    ) -> ! {
        SHUTDOWN_SIGNAL.wait().await;

        DISPLAY_SHUTDOWN_SIGNAL.signal(());

        let handle = MacHandle::new(mac_cell);
        let _ = handle.service_counter_persistence().await;

        let _ = select(
            DISPLAY_SHUTDOWN_DONE.wait(),
            Timer::after(Duration::from_secs(5)),
        )
        .await;

        // Tri-state all peripheral signal pins before cutting power.
        //
        // Two reasons:
        //   1. Output pins driving into an unpowered peripheral leak current
        //      through ESD diodes back onto its unpowered VCC rail.
        //   2. Input pins with PIN_CNF SENSE configured by embassy's async
        //      GPIO layer (e.g. radio DIO1 / BUSY mid-wait) will fire DETECT
        //      and immediately wake the chip from System OFF.
        //
        // tristate_pin() writes PIN_CNF = 0x02 (DIR=input, INPUT=disconnect,
        // PULL=none, DRIVE=0, SENSE=disabled) — clearing any SENSE bits.
        //
        // E-paper SPI bus (SPIM2): SCK=P0.31, MOSI=P1.07, MISO=P0.29
        // E-paper control:         CS=P0.30, DC=P0.28, RST=P0.02, BUSY=P0.03
        // Radio SPI bus (TWISPI1): SCK=P0.19, MOSI=P0.22, MISO=P0.23
        // Radio control:           CS=P0.24, RST=P0.25, BUSY=P0.17, DIO1=P0.20
        for (port, pin) in [
            (Port::P0, 31u8), // e-paper SCK
            (Port::P1,  7u8), // e-paper MOSI
            (Port::P0, 29u8), // e-paper MISO
            (Port::P0, 30u8), // e-paper CS
            (Port::P0, 28u8), // e-paper DC
            (Port::P0,  2u8), // e-paper RST
            (Port::P0,  3u8), // e-paper BUSY
            (Port::P0, 19u8), // radio SCK
            (Port::P0, 22u8), // radio MOSI
            (Port::P0, 23u8), // radio MISO
            (Port::P0, 24u8), // radio CS
            (Port::P0, 25u8), // radio RST
            (Port::P0, 17u8), // radio BUSY
            (Port::P0, 20u8), // radio DIO1  ← has SENSE set by async radio wait
        ] {
            tristate_pin(port, pin);
        }

        // Drop the peripheral rail so the LoRa module, GNSS, sensors, and
        // e-paper bias generator all lose power before we enter System OFF.
        drop(peripheral_power);

        // P1.10 is the side user button. Active-low, pull-up → DETECT-low wakes.
        power_off(&[WakePin { port: Port::P1, pin: 10, sense: WakeSense::Low }])
    }

    // ─── Main ────────────────────────────────────────────────────────────────

    #[embassy_executor::main]
    async fn main(spawner: Spawner) {
        // Initialize the heap allocator before any alloc-using code runs.
        // 4 KiB is negligible on nRF52840 (256 KiB RAM); actual runtime
        // alloc usage is near-zero since we don't create a MacHandle.
        {
            use core::mem::MaybeUninit;
            const HEAP_SIZE: usize = 8192;
            static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
            unsafe { crate::ALLOCATOR.init(core::ptr::addr_of!(HEAP) as usize, HEAP_SIZE) }
        }

        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::default_config());

        // Peripheral power enable (P0.12). Must be high before display, LoRa,
        // or GNSS is addressed, including on battery power. Ownership is later
        // transferred to `shutdown_task` so it can drop the rail before entering
        // System OFF.
        let peripheral_power = Output::new(p.P0_12, Level::High, OutputDrive::Standard);

        // WDT: 8 s timeout, petted by the heartbeat task every ~2 s.
        let mut wdt_config = WdtConfig::default();
        wdt_config.timeout_ticks = 32768 * 8;
        let (_wdt, [wdt_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, wdt_config).unwrap_or_else(|_| panic!("wdt"));

        // Pick up any panic message left by the previous boot.
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

        // ── E-paper display task ──────────────────────────────────────────────
        // P1.11 is the e-paper backlight on this module; drive it LOW
        // explicitly so leakage / external pullups can't turn it on.
        let _backlight = Output::new(p.P1_11, Level::Low, OutputDrive::Standard);
        {
            let mut cfg = SpimConfig::default();
            cfg.frequency = Frequency::M4;
            let disp_spi  = Spim::new(p.SPI2, Irqs, p.P0_31, p.P1_07, p.P0_29, cfg);
            let disp_cs   = Output::new(p.P0_30, Level::High, OutputDrive::Standard);
            let disp_dc   = Output::new(p.P0_28, Level::Low,  OutputDrive::Standard);
            let disp_rst  = Output::new(p.P0_02, Level::High, OutputDrive::Standard);
            let disp_busy = Input::new(p.P0_03, Pull::None);
            spawner.spawn(display_task(disp_spi, disp_cs, disp_dc, disp_rst, disp_busy).unwrap());
        }

        // ── SX1262 LoRa radio ────────────────────────────────────────────────
        // Pin assignment (T-Echo hardware, firmware-confirmed):
        //   SPI bus: SCK=P0.19, MOSI=P0.22, MISO=P0.23 (TWISPI1)
        //   CS=P0.24, RST=P0.25, BUSY=P0.17, DIO1=P0.20
        //   DIO2: internal RF switch (lora-phy sends SetDIO2AsRfSwitchCtrl).
        //   DIO3: 1.8 V TCXO (lora-phy sends SetDIO3AsTcxoCtrl).
        let t_frame_ms = umsh_radio_loraphy::airtime_ms(
            SpreadingFactor::_7,
            Bandwidth::_62KHz,
            umsh_radio_loraphy::MAX_PAYLOAD,
        );
        {
            let mut cfg = SpimConfig::default();
            // SX1262 datasheet §8.2: max SCK = 16 MHz, Mode 0 (CPOL=0, CPHA=0).
            cfg.frequency = Frequency::M16;
            let radio_bus = Spim::new(
                p.TWISPI1, Irqs,
                p.P0_19,  // SCK
                p.P0_23,  // MISO
                p.P0_22,  // MOSI
                cfg,
            );
            let radio_cs  = Output::new(p.P0_24, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();

            let radio_rst  = Output::new(p.P0_25, Level::High, OutputDrive::Standard);
            let radio_dio1 = Input::new(p.P0_20, Pull::None);
            let radio_busy = Input::new(p.P0_17, Pull::None);

            let iv = GenericSx126xInterfaceVariant::new(
                radio_rst,
                radio_dio1,
                radio_busy,
                None,   // rf_switch_rx: DIO2 wired internally on the T-Echo module
                None,   // rf_switch_tx: same
            ).unwrap();

            let lora_config = LoraConfig {
                chip: Sx1262,
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8),  // DIO3 → 1.8 V TCXO
                use_dcdc: true,   // T-Echo SX1262 module has DC-DC converter
                rx_boost: true,   // boosted LNA gain per MeshCore SX126X_RX_BOOSTED_GAIN=1
            };

            // enable_public_network=false → sync word 0x1424 (private),
            // matching MeshCore's RADIOLIB_SX126X_SYNC_WORD_PRIVATE = 0x12.
            let mut lora = LoRa::new(Sx126x::new(radio_spi, iv, lora_config), false, Delay)
                .await
                .unwrap_or_else(|_| panic!("radio init"));

            let (mdltn, rx_pkt, tx_pkt) = umsh_radio_loraphy::meshcore_us_params(&mut lora)
                .unwrap_or_else(|_| panic!("radio params"));

            spawner.spawn(radio_runner_task(lora, mdltn, rx_pkt, tx_pkt).unwrap());
        }

        // ── NV storage ────────────────────────────────────────────────────────
        let storage: &'static NvmcStorage =
            STORAGE.init(NvmcStorage::new(Nvmc::new(p.NVMC)));

        // ── MAC coordinator ───────────────────────────────────────────────────
        // The hardware-TRNG RNG built here is the single RNG path for this
        // firmware — used for first-boot identity generation AND passed
        // ownership-by-value into `Mac::new` below as `Platform::Rng`.
        //
        // Load identity from flash on subsequent boots; TRNG-generate on
        // first boot. We do NOT fall back to any PRNG on failure — a
        // predictable long-term key is worse than refusing to start.
        let mut rng = Nrf52840Rng::new(p.RNG);
        let sk_bytes: [u8; 32] = match storage.load_sk().await {
            Ok(Some(sk)) => sk,
            Ok(None) => {
                let mut sk = [0u8; 32];
                rng.fill_bytes(&mut sk);
                storage.store_sk(&sk).await.unwrap_or_else(|_| panic!("identity persist"));
                sk
            }
            Err(_) => panic!("storage init failed"),
        };
        let identity  = SoftwareIdentity::from_secret_bytes(&sk_bytes);
        let local_key = *identity.public_key();

        let radio_handle = umsh_radio_loraphy::LoraphyRadio::new(&RADIO_CH, t_frame_ms);
        let crypto       = CryptoEngine::new(SoftwareAes, SoftwareSha256);
        let mut mac = TechoMac::new(
            radio_handle,
            crypto,
            EmbassyClock,
            rng,
            NvmcCounterStore::new(storage),
            RepeaterConfig::default(),
            OperatingPolicy::default(),
        );
        let identity_id = mac.add_identity(identity).unwrap_or_else(|_| panic!("identity"));
        // Restore the TX frame-counter boundary so the counter never rewinds.
        mac.load_persisted_counter(identity_id)
            .await
            .unwrap_or_else(|_| panic!("tx counter load"));
        let mac_cell: &'static AsyncRefCell<TechoMac> =
            MAC_CELL.init(AsyncRefCell::new(mac));

        // ── Host + node + boot-time peer/channel registration ─────────────────
        // Build the Host/node here so the MAC pump (`mac_task`) is independent
        // of USB, and register persisted peer/channel keys into the MAC now —
        // not from the CLI task, which only runs after a host opens the CDC
        // port. Without this the coordinator had no keys until a serial client
        // attached, so it couldn't authenticate inbound secure frames and
        // silently dropped every ping. Aliases/names ride along to the CLI for
        // display; the MAC needs only the keys.
        let handle = MacHandle::new(mac_cell);
        let mut host: TechoHost = Host::new(handle);
        let node = host.add_node(identity_id);

        let mut peer_buf: heapless::Vec<([u8; 32], Option<heapless::String<16>>), 8> =
            heapless::Vec::new();
        let _ = storage.load_all_peers(&mut peer_buf).await;
        let mut ch_buf: heapless::Vec<(heapless::String<16>, [u8; 32]), 2> = heapless::Vec::new();
        let _ = storage.load_all_channels(&mut ch_buf).await;
        for (pk, _alias) in peer_buf.iter() {
            let _ = node.peer(PublicKey(*pk)).await;
        }
        for (name, key_bytes) in ch_buf.iter() {
            let channel = Channel::private(ChannelKey(*key_bytes), name.as_str());
            let _ = node.join(&channel).await;
        }
        // Restore RX counter boundaries after peer registration so the persisted
        // boundaries land on registered peers.
        MacHandle::new(mac_cell)
            .load_all_persisted_rx_counters()
            .await
            .ok();

        // ── USB stack + steady-state services ────────────────────────────────
        let led    = Output::new(p.P0_14, Level::High, OutputDrive::Standard);
        let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

        let mut config = Config::new(0x16c0, 0x27dd);
        config.manufacturer      = Some("UMSH");
        config.product           = Some("T-Echo Bringup");
        config.serial_number     = Some("hello-techo");
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

        spawner.spawn(output_task(tx).unwrap());
        spawner.spawn(identity_persist_task(storage).unwrap());
        spawner.spawn(mac_task(host, identity_id).unwrap());
        spawner.spawn(
            cli_task(
                node, local_key, storage, peer_buf, ch_buf, rx, prev_panic_buf, prev_panic_len,
            )
            .unwrap(),
        );

        // User button (P1.10, active-low). Pull-up so DETECT can wake from
        // System OFF on the falling edge.
        let button = Input::new(p.P1_10, Pull::Up);
        spawner.spawn(button_task(button).unwrap());
        spawner.spawn(shutdown_task(mac_cell, peripheral_power).unwrap());

        join(
            usb.run(),
            heartbeat(led, wdt_handle),
        ).await;
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
