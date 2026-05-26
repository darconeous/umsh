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
    use embassy_nrf::rng::Rng;
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
    use rand::{TryCryptoRng, TryRng};
    use static_cell::StaticCell;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::flash_store::{NvmcChannelStore, NvmcCounterStore, NvmcKeyValueStore, NvmcPeerStore, NvmcStorage};
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    use umsh_crypto::{
        CryptoEngine, NodeIdentity,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    };
    use umsh_core::{PayloadType, PublicKey};
    use umsh_mac::{LocalIdentityId, MacHandle, OperatingPolicy, Platform, RepeaterConfig};
    use umsh_node::Host;
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
        RNG         => embassy_nrf::rng::InterruptHandler<peripherals::RNG>;
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

    // ─── Static shared state ─────────────────────────────────────────────────

    /// Channels shared between the radio runner and Sx1262Radio / MAC.
    /// Capacity: 4 inbound frames, 2 pending TX requests.
    type RadioCh = umsh_radio_sx126x::Channels<ThreadModeRawMutex, 4, 2>;
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

    // ─── Platform types ───────────────────────────────────────────────────────
    //
    // TechoPlatform bundles the concrete driver types for Mac<P>. All
    // implementations live here so the MAC type is fully concrete.

    /// Embassy monotonic clock implementing `umsh_hal::Clock`.
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
            // Poll a freshly-pinned timer once to register `cx.waker()` with
            // embassy's global timer queue. The waker registration outlives the
            // future itself, so dropping the timer here is safe.
            let mut timer = core::pin::pin!(Timer::at(target));
            timer.as_mut().poll(cx)
        }
    }

    /// XorShift64 PRNG seeded from the nRF52840 FICR device ID.
    ///
    /// The FICR DEVICEID registers hold a 64-bit unique identifier burned
    /// into the chip at the factory, giving different seeds per device. This
    /// is NOT a cryptographic RNG — it is sufficient for MAC backoff
    /// randomization in Phase 6 bringup. Replace with a proper CSPRNG
    /// (e.g. seeded from the hardware RNG peripheral) before deployment.
    struct TeChoRng {
        state: u64,
    }

    impl TeChoRng {
        fn from_ficr() -> Self {
            // FICR DEVICEID[0] at 0x10000060, DEVICEID[1] at 0x10000064.
            // Addresses are fixed per nRF52840 Product Specification §5.1.3.
            // SAFETY: FICR is a read-only, always-mapped peripheral region.
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

    impl TryRng for TeChoRng {
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

    impl TryCryptoRng for TeChoRng {}

    /// Platform bundle wiring the T-Echo hardware into `Mac<P>`.
    struct TechoPlatform;

    impl Platform for TechoPlatform {
        type Identity     = SoftwareIdentity;
        type Aes          = SoftwareAes;
        type Sha          = SoftwareSha256;
        type Radio        = umsh_radio_sx126x::Sx1262Radio<ThreadModeRawMutex, 4, 2>;
        type Delay        = Delay;
        type Clock        = EmbassyClock;
        type Rng          = TeChoRng;
        type CounterStore = NvmcCounterStore;
        type KeyValueStore = NvmcKeyValueStore;
    }

    /// Fully-typed MAC coordinator for the T-Echo.
    ///
    /// Capacity is deliberately minimal for Phase 6 bringup: 1 identity,
    /// 8 peers, 4 channels, 4 pending ACKs, 8 TX queue slots, 255-byte frame
    /// buffer, 32-entry dup cache. Total static footprint ≈ 6 KiB.
    type TechoMac = umsh_mac::Mac<TechoPlatform, 1, 8, 4, 4, 8, 255, 32>;

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
        umsh_radio_sx126x::runner(lora, &RADIO_CH, mdltn, rx_pkt, tx_pkt, TX_POWER_DBM).await;
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

    /// Combined task: drives the MAC via `Host::run` and runs the `CliSession`
    /// concurrently via `select`. The shared `AsyncRefCell<Mac>` (held via
    /// `MacHandle`) serialises MAC access between the host driver and the
    /// CLI's send-side calls.
    #[embassy_executor::task]
    async fn umsh_task(
        mac_cell: &'static AsyncRefCell<TechoMac>,
        identity_id: LocalIdentityId,
        local_key: PublicKey,
        storage: &'static NvmcStorage,
        rx: TechoRescue,
        prev_panic_buf: &'static [u8; 256],
        prev_panic_len: usize,
    ) {
        use umsh_cli::CliSession;
        use umsh_cli::io::CliOutput;
        use umsh_cli::logger::NullLogger;

        let handle = MacHandle::new(mac_cell);
        let mut host: Host<'_, TechoPlatform, 1, 8, 4, 4, 8, 255, 32> = Host::new(handle);
        let node = host.add_node(identity_id);

        let mut input = cli_io::CdcInput::new(rx);
        let mut out = cli_io::CdcOutput::new();

        // Load persisted peers and channels before `out` is moved into the CLI.
        let mut peer_buf: heapless::Vec<([u8; 32], Option<heapless::String<16>>), 8> =
            heapless::Vec::new();
        let _ = storage.load_all_peers(&mut peer_buf).await;
        let mut ch_buf: heapless::Vec<(heapless::String<16>, [u8; 32]), 2> =
            heapless::Vec::new();
        let _ = storage.load_all_channels(&mut ch_buf).await;

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
        let mut cli: CliSession<_, _, _, _, _, 4, 4, 2, 8, 2, 128> =
            CliSession::new(node, local_key, out, NullLogger::new(), peer_store, channel_store);

        // Re-register loaded peers and channels into the CLI session tables.
        for (pk, alias) in peer_buf.iter() {
            let key = PublicKey(*pk);
            let _ = cli.register_peer(key, alias.as_deref()).await;
        }
        // Load RX counter boundaries so the replay window starts above any
        // frames accepted before the last reboot.
        MacHandle::new(mac_cell)
            .load_all_persisted_rx_counters()
            .await
            .ok();
        for (name, key_bytes) in ch_buf.iter() {
            let _ = cli.register_channel(name.as_str(), *key_bytes).await;
        }

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

        loop {
            match select(host.run(), cli.run(&mut input)).await {
                Either::First(_) => panic!("host exited"),
                Either::Second(_) => {}
            }
        }
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

        // Initial boot screen (count = 0).
        render(&mut buf, 0);
        display::init(&mut spi, &mut cs, &mut dc, &mut rst, &mut busy).await;
        display::render(&mut spi, &mut cs, &mut dc, &mut busy, &buf).await;

        // Update loop. We deliberately do NOT reset the signal after the
        // throttle: any packet that fired during render+throttle stays
        // pending, so the next iteration starts immediately with the
        // newest count. Throttle still caps the refresh rate.
        loop {
            DISPLAY_COUNT_SIGNAL.wait().await;
            let count = PACKET_COUNT.load(Ordering::Relaxed);
            render(&mut buf, count);
            display::render(&mut spi, &mut cs, &mut dc, &mut busy, &buf).await;
            Timer::after(DISPLAY_THROTTLE).await;
        }
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
        // or GNSS is addressed, including on battery power.
        let _peripheral_power = Output::new(p.P0_12, Level::High, OutputDrive::Standard);

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
        let t_frame_ms = umsh_radio_sx126x::airtime_ms(
            SpreadingFactor::_7,
            Bandwidth::_62KHz,
            umsh_radio_sx126x::MAX_PAYLOAD,
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

            let (mdltn, rx_pkt, tx_pkt) = umsh_radio_sx126x::meshcore_us_params(&mut lora)
                .unwrap_or_else(|_| panic!("radio params"));

            spawner.spawn(radio_runner_task(lora, mdltn, rx_pkt, tx_pkt).unwrap());
        }

        // ── NV storage ────────────────────────────────────────────────────────
        let storage: &'static NvmcStorage =
            STORAGE.init(NvmcStorage::new(Nvmc::new(p.NVMC)));

        // ── MAC coordinator ───────────────────────────────────────────────────
        // Load the persisted identity key, or generate a fresh one from the
        // nRF52840 hardware TRNG (with bias correction) on first boot.
        // We do NOT fall back to a FICR-seeded PRNG on failure — a predictable
        // long-term key is worse than refusing to start.
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

        let rng = TeChoRng::from_ficr();

        let radio_handle = umsh_radio_sx126x::Sx1262Radio::new(&RADIO_CH, t_frame_ms);
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
        spawner.spawn(
            umsh_task(mac_cell, identity_id, local_key, storage, rx, prev_panic_buf, prev_panic_len)
                .unwrap()
        );

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
