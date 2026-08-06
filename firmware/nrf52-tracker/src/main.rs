// ULCP device firmware shared by the LilyGO T-Echo and Seeed
// SenseCAP T-1000E targets. Cargo features select the board-specific glue.
//
// Exposes the board's LoRa radio as a host-controlled PHY speaking the minimal
// ULCP protocol plus advertised full-profile extensions
// over USB-CDC/HDLC-Lite and encrypted+bonded BLE GATT/SAR. The host owns its
// own MAC and drives this device through `umsh::ulcp::UlcpDevice`;
// alongside that session, the **device node** (device_node.rs) runs a full
// on-board MAC/node stack for the device identity, sharing the radio through
// the mux.
//
// Protocol behavior lives in `umsh-ulcp-device::Session` (host-tested,
// no I/O); this binary is only glue:
//
// Task layout (steady state):
//   - main():            initializes MPSL/SDC and joins BLE, USB, heartbeat
//   - radio_task:        owns lora_phy::LoRa via umsh_radio_loraphy::device_runner;
//                        modulation/frequency/power are pushed at runtime
//                        through DEVICE_CTL as the host sets properties
//   - radio_mux_task:    multiplexes the physical radio across its clients
//                        (per-client TX completion routing, RX fan-out);
//                        the session is client A, the device node client B
//   - node_pump_task /   the device node: MAC pump + beacon requests for
//     node_beacon_task   the device identity (spawned only when a persisted
//                        identity exists; dormant otherwise)
//   - usb_in_task:       owns CdcAcmRescue + HDLC decoder; forwards frames and
//                        attach/detach edges into INPUT_CH (keeps
//                        read_packet out of any select, so cancel safety
//                        never depends on the USB driver)
//   - device_task:          hosts the shared ULCP driver
//                        (umsh_ulcp_runtime::driver): the Session
//                        select loop over INPUT_CH, radio RX, and TX
//                        completions, with board couplings via BoardDeviceEnv
//   - output_task:       owns the USB Sender + HDLC encoder, drains
//                        OUT_CH.wired
//   - ble_app:           advertising + encrypted/bond-gated GATT/SAR edges,
//                        pairing policy, generation-tagged OUT_CH.ble, and
//                        MPSL-coordinated PIN/bond persistence
//   - button_task:       resolves the side button into display-menu gestures
//   - display_task:      owns the e-paper BLE menu and its attention policy
//   - touch_task:        publishes the touch button's backlight demand
//   - backlight_task:    arbitrates backlight demand (locate alert wins)
//   - shutdown_task:     tri-states peripheral pins, drops the rail,
//                        enters System OFF
//
// CMD_RST is a protocol-level reset: all protocol state returns to
// post-reset values and the radio is re-applied (disabled), but the MCU
// and the USB link stay up. Host attach resets only session state
// (full-protocol semantics): the device domain — PHY configuration and
// enable state, device name, duty accounting — is untouched, and
// nothing is emitted; the reset notice is only sent for CMD_RST, so the
// host never sees an unsolicited reset it didn't ask for mid-handshake.
//
// Safety primitives inherited from the BSP (see umsh-bsp-nrf52840):
//   * Panic capture into reserved RAM (reported as STATUS_RESET_CRASH).
//   * 1200-baud touchless reset and Ctrl-C × 3 + "dfu" escape to
//     bootloader (baked into CdcAcmRescue).
//   * Watchdog.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
// The no-ble diagnostic image compiles the full BLE support source
// (pairing policy, bond store, GATT plumbing) with the call sites
// cfg'd out. Silence the resulting dead-code noise for that image
// only, so production builds keep full warning strength.
#![cfg_attr(feature = "no-ble", allow(dead_code, unused_imports))]

#[cfg(not(target_os = "none"))]
fn main() {
    // Host placeholder. This binary only runs on the embedded target.
}

// The device node's advertisement payloads use umsh-node's alloc-backed
// types (they draw from the same 8 KiB heap the node stack already
// uses).
extern crate alloc;

// Global heap allocator. The device node (umsh-sync's AsyncRefCell plus
// umsh-node's Rc-based plumbing) allocates a small bounded amount at
// bring-up; the ULCP session remains allocation-free. Initialized
// with an 8 KiB region at the top of main() — the same budget the CLI
// firmware's full stack runs in on identical hardware.
#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: embedded_alloc::Heap = embedded_alloc::Heap::empty();

// Board-agnostic leaf modules now live in `umsh-ulcp-runtime` (Phase 5
// extraction, increment A). Re-import them under their original names so the
// `super::<module>` paths inside `mod firmware` resolve unchanged. Gated to the
// firmware target because the host build compiles `mod firmware` out entirely.
#[cfg(target_os = "none")]
use umsh_ulcp_runtime::{ble_security, radio_mux, transport_policy};
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
mod ble_store;
#[cfg(target_os = "none")]
mod device_node;
mod proto_store;

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
    use super::ble_security::{PairingFailureClass, PairingRuntime, pairing_enabled};
    use super::ble_store::{self, Snapshot, StoredBond};
    use super::proto_store;
    use super::transport_policy::{Transport, generation_checked};
    #[cfg(feature = "ble-debug")]
    use core::fmt::Write as _;
    use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, Ordering};
    use embassy_executor::Spawner;
    use embassy_futures::join::join;
    use embassy_futures::select::{Either, Either3, select, select3};
    #[cfg(any(feature = "has-display", feature = "button-nav", feature = "t1000e"))]
    use embassy_futures::select::{Either4, select4};
    use embassy_nrf::bind_interrupts;
    #[cfg(feature = "cap-gnss")]
    use embassy_nrf::buffered_uarte::BufferedUarte;
    use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
    use embassy_nrf::mode::Async;
    use embassy_nrf::pac;
    use embassy_nrf::peripherals::{self, RNG};
    #[cfg(feature = "t1000e")]
    use embassy_nrf::pwm::DutyCycle;
    #[cfg(any(feature = "t1000e", feature = "cap-buzzer"))]
    use embassy_nrf::pwm::{Prescaler, SimpleConfig, SimplePwm};
    use embassy_nrf::rng;
    // The T-1000E is the one board whose converter is built in the BSP,
    // per measurement, because its battery and light channels want
    // different resolutions and oversampling. Every other board hands the
    // BSP a ready-made single-channel `Saadc` from here.
    #[cfg(feature = "t1000e")]
    use embassy_nrf::Peri;
    #[cfg(all(feature = "cap-battery-saadc", not(feature = "t1000e")))]
    use embassy_nrf::saadc::{ChannelConfig, Config as SaadcConfig, Saadc};
    use embassy_nrf::spim::{Config as SpimConfig, Frequency, Spim};
    #[cfg(feature = "cap-gnss")]
    use embassy_nrf::uarte::{Baudrate as UarteBaudrate, Config as UarteConfig};
    use embassy_nrf::usb::Driver;
    use embassy_nrf::usb::vbus_detect::SoftwareVbusDetect;
    use embassy_nrf::wdt::{Config as WdtConfig, Watchdog, WatchdogHandle};
    use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
    use embassy_sync::channel::Channel;
    use embassy_sync::mutex::Mutex;
    use embassy_sync::signal::Signal;
    use embassy_time::{Delay, Duration, Instant, Timer};
    use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
    use embassy_usb::{Builder, Config};
    use embedded_hal_bus::spi::ExclusiveDevice;
    use lora_phy::LoRa;
    #[cfg(feature = "t1000e")]
    use lora_phy::iv::GenericLr1110InterfaceVariant;
    #[cfg(not(feature = "t1000e"))]
    use lora_phy::iv::GenericSx126xInterfaceVariant;
    #[cfg(feature = "t1000e")]
    use lora_phy::lr1110::{
        Config as LoraConfig, Lr1110, TcxoCtrlVoltage, radio_kind_params::PaSelection,
        variant::Lr1110 as Lr1110Chip,
    };
    #[cfg(not(feature = "t1000e"))]
    use lora_phy::sx126x::{Config as LoraConfig, Sx126x, Sx1262, TcxoCtrlVoltage};
    use nrf_sdc::mpsl::{self, MultiprotocolServiceLayer};
    use nrf_sdc::{self as sdc};
    use static_cell::StaticCell;
    use trouble_host::gap;
    use trouble_host::prelude::*;
    use umsh_bsp_nrf52840::cdc_rescue::CdcAcmRescue;
    use umsh_bsp_nrf52840::panic_persist::PanicSlot;
    #[cfg(any(
        feature = "system-off-techo",
        feature = "system-off-wio",
        feature = "t1000e"
    ))]
    use umsh_bsp_nrf52840::system_off::Port;
    #[cfg(feature = "system-off-techo")]
    use umsh_bsp_nrf52840::system_off::drive_pin_high;
    #[cfg(any(
        feature = "t1000e",
        feature = "system-off-wio",
        feature = "system-off-techo"
    ))]
    use umsh_bsp_nrf52840::system_off::drive_pin_low;
    #[cfg(any(feature = "system-off-techo", feature = "system-off-wio"))]
    use umsh_bsp_nrf52840::system_off::{WakePin, WakeSense, power_off, tristate_pin};
    #[cfg(any(feature = "system-off-techo", feature = "system-off-wio"))]
    use umsh_bsp_nrf52840::system_off::{WakePull, connect_input, read_pin};
    #[cfg(feature = "t1000e")]
    use umsh_bsp_t1000e::RF_SWITCH;
    #[cfg(feature = "display-epd")]
    use umsh_bsp_techo::display;
    #[cfg(feature = "display-oled")]
    use umsh_bsp_wio_tracker_l1::display;
    // Board-selected battery BSP module, used only by the shared
    // `cap-battery-saadc` snapshot/load-hint code below.
    #[cfg(all(feature = "cap-battery-saadc", feature = "board-sensecap-solar"))]
    use umsh_bsp_sensecap_solar::power as board_power;
    #[cfg(all(feature = "cap-battery-saadc", feature = "t1000e"))]
    use umsh_bsp_t1000e::power as board_power;
    #[cfg(all(feature = "cap-battery-saadc", feature = "board-techo"))]
    use umsh_bsp_techo::power as board_power;
    #[cfg(all(feature = "cap-battery-saadc", feature = "board-wio-tracker-l1"))]
    use umsh_bsp_wio_tracker_l1::power as board_power;
    #[cfg(all(feature = "cap-battery-saadc", feature = "board-xiao-nrf52"))]
    use umsh_bsp_xiao_nrf52::power as board_power;
    // Board-selected GNSS power control. One board feature is active per
    // image, so this alias resolves to exactly one type and the pump's
    // task shim stays concrete — which is what `#[embassy_executor::task]`
    // requires, since a task function cannot be generic.
    #[cfg(all(feature = "cap-gnss", feature = "board-techo"))]
    type BoardGnss = umsh_bsp_techo::gnss::Gnss<'static>;
    #[cfg(all(feature = "cap-gnss", feature = "t1000e"))]
    type BoardGnss = umsh_bsp_t1000e::gnss::Gnss<'static>;
    #[cfg(all(feature = "cap-gnss", feature = "board-wio-tracker-l1"))]
    type BoardGnss = umsh_bsp_wio_tracker_l1::gnss::Gnss<'static>;
    #[cfg(all(feature = "cap-gnss", feature = "board-sensecap-solar"))]
    type BoardGnss = umsh_bsp_sensecap_solar::gnss::Gnss<'static>;
    /// The byte stream the pump reads.
    #[cfg(feature = "cap-gnss")]
    type GnssUart = BufferedUarte<'static>;
    use umsh_crypto::CryptoEngine;
    use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
    use umsh_ulcp::{Status, gatt, hdlc};
    #[cfg(feature = "cap-gnss")]
    use umsh_ulcp_device::GnssConfig;
    use umsh_ulcp_device::{
        AlertConfig, BatteryFields, MAX_DEVICE_NAME_LEN, RadioSettings, SessionConfig, TimeConfig,
    };

    /// The ULCP session instantiated with this firmware's crypto
    /// providers (software AES/SHA; Ed25519 comes in only through the
    /// device-identity provisioning path).
    // The physical radio remains single-flight, but the protocol session can
    // retain several host frames. This target-specific const generic avoids a
    // LoRa completion round trip between fragments without imposing the RAM
    // cost on smaller/default Session users.
    const ULCP_TX_QUEUE_CAPACITY: usize = 8;
    type Session = umsh_ulcp_device::Session<SoftwareAes, SoftwareSha256, ULCP_TX_QUEUE_CAPACITY>;

    /// Deterministic CSPRNG for device-identity generation, seeded from
    /// the hardware TRNG at boot: the RNG peripheral itself is owned by
    /// the SoftDevice Controller for the lifetime of the BLE stack.
    type IdentityRng = rand_chacha::ChaCha20Rng;
    use umsh_radio_loraphy::{DeviceControl, MAX_PAYLOAD};
    use umsh_ulcp_runtime::driver::{
        self, DeviceEnv, DeviceRuntime, InEvent, InputChannel, OutFrame, TransportChannels,
    };
    #[cfg(feature = "has-display")]
    use umsh_ux_display_tracker::attention::{
        Attention, AttentionConfig, DisplayKind, HoldReason, Transition,
    };
    #[cfg(feature = "button-nav")]
    use umsh_ux_display_tracker::gate::{Disposition, Gate, GateReason};
    use umsh_ux_display_tracker::menu::UiNotice;
    #[cfg(feature = "has-display")]
    use umsh_ux_display_tracker::menu::{MenuItems, UiEffect, UiInput, UiModel};
    #[cfg(feature = "has-display")]
    use umsh_ux_display_tracker::screen;
    #[cfg(any(feature = "button-nav", feature = "t1000e"))]
    use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm};
    // The display trackers take their timings from the shared class
    // policy; only the headless T-1000E still names its own.
    #[cfg(feature = "t1000e")]
    use umsh_ux_tracker::button::ButtonTimings;
    #[cfg(feature = "t1000e")]
    use umsh_ux_tracker::buzzer::melodies as buzzer_melodies;
    #[cfg(feature = "t1000e")]
    use umsh_ux_tracker::led::T1000eLedEngine;
    #[cfg(not(feature = "t1000e"))]
    use umsh_ux_tracker::led::{LedEngine, LedTimings};
    // The Solar P1's attention LED plays the same sequences from the
    // generic engine.
    #[cfg(any(feature = "t1000e", feature = "power-button"))]
    use umsh_ux_tracker::led::LedSequence;

    bind_interrupts!(struct Irqs {
        USBD        => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
        RNG         => rng::InterruptHandler<RNG>;
        EGU0_SWI0   => nrf_sdc::mpsl::LowPrioInterruptHandler;
        CLOCK_POWER => nrf_sdc::mpsl::ClockInterruptHandler;
        RADIO       => nrf_sdc::mpsl::HighPrioInterruptHandler;
        TIMER0      => nrf_sdc::mpsl::HighPrioInterruptHandler;
        RTC0        => nrf_sdc::mpsl::HighPrioInterruptHandler;
        // TWIM0/SPIM0 is the one peripheral this family uses two ways:
        // SPIM0 → LR1110 on the T-1000E, TWIM0 → SH1106 OLED on the Wio
        // Tracker L1. Both handlers cannot be bound at once — they claim
        // the same peripheral — so the board picks.
        TWISPI0     =>
            #[cfg(not(feature = "display-oled"))]
            embassy_nrf::spim::InterruptHandler<peripherals::TWISPI0>,
            #[cfg(feature = "display-oled")]
            embassy_nrf::twim::InterruptHandler<peripherals::TWISPI0>;
        // SPIM1 → SX1262 LoRa SPI bus. embassy-nrf names this peripheral
        // TWISPI1 (it's the shared TWIM1/SPIM1 block on nRF52840).
        TWISPI1     => embassy_nrf::spim::InterruptHandler<peripherals::TWISPI1>;
        // SPIM2 → SSD1681 e-paper SPI bus. embassy-nrf names this interrupt SPI2.
        SPI2        => embassy_nrf::spim::InterruptHandler<peripherals::SPI2>;
        SAADC       => embassy_nrf::saadc::InterruptHandler;
        // UARTE0 → the GNSS receiver, on every board that has one. Bound
        // unconditionally rather than per-board: an unused handler for a
        // peripheral nothing instantiates costs a vector-table entry and
        // saves a `cfg` fork in the one block that must stay readable.
        UARTE0      => embassy_nrf::buffered_uarte::InterruptHandler<peripherals::UARTE0>;
    });

    // ─── Configuration ───────────────────────────────────────────────────────

    /// SX1262 PA limits on this module.
    const MIN_TX_POWER_DBM: i8 = -9;
    const MAX_TX_POWER_DBM: i8 = 22;

    const BLE_CONNECTIONS_MAX: usize = 1;
    const BLE_L2CAP_CHANNELS_MAX: usize = 2;
    const BLE_L2CAP_TXQ: u8 = 3;
    const BLE_L2CAP_RXQ: u8 = 3;
    /// Nordic's SDC buffer configuration accepts 27..=251 octets.
    const SDC_PACKET_SIZE: u16 = 251;
    /// Largest value the ULCP characteristics accept.
    ///
    /// A client may write up to ATT_MTU-3 octets in one request, and the
    /// packet pool is configured for a 255-octet MTU, so anything smaller
    /// than 252 here is a size the peer is entitled to send and this device
    /// would refuse with an invalid-length error.
    const BLE_VALUE_MAX: usize = 252;
    #[cfg(feature = "board-techo")]
    const DEFAULT_DEVICE_NAME: &str = "UMSH T-Echo";
    #[cfg(feature = "t1000e")]
    const DEFAULT_DEVICE_NAME: &str = "UMSH T-1000E";
    // Board default + " XXXX" suffix must stay within trouble's 22-byte
    // GAP device-name limit; a longer name fails GATT-server construction
    // (the cause of the Solar P1 first-bringup boot loop).
    #[cfg(feature = "board-sensecap-solar")]
    const DEFAULT_DEVICE_NAME: &str = "UMSH Solar";
    #[cfg(feature = "board-wio-tracker-l1")]
    const DEFAULT_DEVICE_NAME: &str = "UMSH Wio L1";
    #[cfg(feature = "board-xiao-nrf52")]
    const DEFAULT_DEVICE_NAME: &str = "UMSH XIAO";

    /// The board default name plus a stable per-die suffix — the low 16
    /// bits of FICR DEVICEADDR, the same die-unique value the BLE
    /// identity address is built from — so factory-fresh radios are
    /// tellable apart in scan lists and on multi-board benches.
    fn default_device_name() -> &'static str {
        use core::fmt::Write as _;
        static NAME: embassy_sync::once_lock::OnceLock<heapless09::String<24>> =
            embassy_sync::once_lock::OnceLock::new();
        NAME.get_or_init(|| {
            let suffix = embassy_nrf::pac::FICR.deviceaddr(0).read() & 0xFFFF;
            let mut name = heapless09::String::new();
            let _ = write!(name, "{DEFAULT_DEVICE_NAME} {suffix:04X}");
            name
        })
        .as_str()
    }

    #[gatt_server]
    struct UlcpServer {
        ulcp: UlcpService,
    }

    #[gatt_service(uuid = "21eb6b15-0001-4ccf-92e4-a079171bec97")]
    struct UlcpService {
        #[characteristic(
            uuid = "21eb6b15-0002-4ccf-92e4-a079171bec97",
            write,
            write_without_response,
            permissions(write = encrypted)
        )]
        frame_in: heapless09::Vec<u8, BLE_VALUE_MAX>,
        #[characteristic(
            uuid = "21eb6b15-0003-4ccf-92e4-a079171bec97",
            notify,
            permissions(cccd = encrypted)
        )]
        frame_out: heapless09::Vec<u8, BLE_VALUE_MAX>,
    }

    /// `PROP_DEV_VERSION`: the board's firmware name and `git describe
    /// --always` (from the build script), nothing else. Boot
    /// diagnostics stay on the debug console.
    #[cfg(feature = "board-techo")]
    const DEV_VERSION: &str = concat!("umsh-techo ", env!("GIT_DESCRIBE"));
    #[cfg(feature = "t1000e")]
    const DEV_VERSION: &str = concat!("umsh-t1000e ", env!("GIT_DESCRIBE"));
    #[cfg(feature = "board-sensecap-solar")]
    const DEV_VERSION: &str = concat!("umsh-sensecap-solar ", env!("GIT_DESCRIBE"));
    #[cfg(feature = "board-wio-tracker-l1")]
    const DEV_VERSION: &str = concat!("umsh-wio-tracker-l1 ", env!("GIT_DESCRIBE"));
    #[cfg(feature = "board-xiao-nrf52")]
    const DEV_VERSION: &str = concat!("umsh-xiao-nrf52 ", env!("GIT_DESCRIBE"));

    fn session_config() -> SessionConfig {
        SessionConfig {
            dev_version: DEV_VERSION,
            default_device_name: default_device_name(),
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
            default_duty_limit: umsh_ulcp::ids::DUTY_LIMIT_DISABLED,
            duty: &DUTY_LEDGER,
            // Every board here is battery powered, and every one now has
            // a SAADC monitor reporting voltage, charge state, and the
            // rest-gated OCV level estimate.
            #[cfg(feature = "cap-battery-saadc")]
            battery: Some(BatteryFields {
                voltage: true,
                level: true,
                charge_state: true,
            }),
            #[cfg(not(feature = "cap-battery-saadc"))]
            battery: Some(BatteryFields::NONE),
            // Every board here can make itself conspicuous: the T-1000E
            // with its buzzer, the T-Echo and Solar P1 with their
            // indicator LEDs. `CAP_ALERT` says only that *something*
            // happens, so the difference stays a board matter.
            alert: Some(AlertConfig::DEFAULT),
            // Every board here keeps a wall clock. What it does *not*
            // claim is that the clock is set: a board with no receiver
            // and no battery-backed RTC simply reports that it does not
            // know what time it is until a host tells it.
            time: Some(TimeConfig),
            // The Solar P1 is the one board here that runs its receiver
            // by default. It is a fixed outdoor node with a panel rather
            // than a pocket tracker on a cell: the load it is worried
            // about is the one it can see coming, and a node that has to
            // be told to find itself after every reset is the worse
            // failure. Everywhere else the receiver waits to be asked.
            #[cfg(all(feature = "cap-gnss", feature = "board-sensecap-solar"))]
            gnss: Some(GnssConfig::ALWAYS_ON),
            #[cfg(all(feature = "cap-gnss", not(feature = "board-sensecap-solar")))]
            gnss: Some(GnssConfig::DEFAULT),
            #[cfg(not(feature = "cap-gnss"))]
            gnss: None,
            // The T-1000E is the one board here with an ambient light
            // sensor fitted.
            illuminance: cfg!(feature = "cap-illuminance"),
        }
    }

    /// The one duty ledger shared by every radio client (device-node
    /// plan increment 4): the session prices and records its own
    /// transmissions here, and the device node's radio path admits
    /// each transmit against the same combined budget (`duty_gate`),
    /// so `PROP_PHY_DUTY_LIMIT` bounds session + node airtime together
    /// and `PROP_PHY_DUTY_NOW` reports the combined figure.
    pub(crate) static DUTY_LEDGER: umsh_ulcp_device::DutyLedger =
        umsh_ulcp_device::DutyLedger::new();

    // ─── Concrete types ──────────────────────────────────────────────────────

    type RadioSpiBus = ExclusiveDevice<Spim<'static>, Output<'static>, Delay>;
    #[cfg(not(feature = "t1000e"))]
    type RadioIv = GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>;
    #[cfg(feature = "t1000e")]
    type RadioIv = GenericLr1110InterfaceVariant<Output<'static>, Input<'static>>;
    #[cfg(not(feature = "t1000e"))]
    type RadioKind = Sx126x<RadioSpiBus, RadioIv, Sx1262>;
    #[cfg(feature = "t1000e")]
    type RadioKind = Lr1110<RadioSpiBus, RadioIv, Lr1110Chip>;
    type LoraRadio = LoRa<RadioKind, Delay>;

    type DeviceUsbDriver = Driver<'static, &'static SoftwareVbusDetect>;
    type DeviceSender = embassy_usb::class::cdc_acm::Sender<'static, DeviceUsbDriver>;
    type DeviceRescue = CdcAcmRescue<'static, DeviceUsbDriver>;
    type BleStoreMutex = Mutex<ThreadModeRawMutex, BleStore>;
    /// The one MPSL-coordinated flash driver, shared between the BLE
    /// bond/PIN journal and the protocol snapshot journal.
    pub type SharedFlash = Mutex<ThreadModeRawMutex, JournalFlash>;

    /// Local wrapper carrying the `umsh-journal-store` trait impls for
    /// the MPSL-coordinated flash (both trait and driver are foreign
    /// since the journal extraction, so the impls need a local type).
    /// Derefs to the driver for the blocking read paths.
    pub struct JournalFlash(nrf_mpsl::Flash<'static>);

    impl core::ops::Deref for JournalFlash {
        type Target = nrf_mpsl::Flash<'static>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl core::ops::DerefMut for JournalFlash {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    struct BleStore {
        flash: &'static SharedFlash,
        snapshot: Snapshot,
        slot: Option<u32>,
    }

    impl ble_store::RecordWriter for JournalFlash {
        type Error = ();

        async fn write_record(&mut self, address: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            #[cfg(feature = "ble-store-fault-inject")]
            if BLE_STORE_FAULT_ARMED.load(Ordering::Acquire) {
                debug_log(format_args!(
                    "store fault-inject write address=0x{address:06x} len={}",
                    bytes.len(),
                ));
                return Err(());
            }
            self.write(address, bytes).await.map_err(|_| ())
        }
    }

    impl ble_store::PageEraser for JournalFlash {
        type Error = ();

        async fn erase_page(&mut self, start: u32, end: u32) -> Result<(), Self::Error> {
            #[cfg(feature = "ble-store-fault-inject")]
            if BLE_STORE_FAULT_ARMED.load(Ordering::Acquire) {
                debug_log(format_args!(
                    "store fault-inject erase start=0x{start:06x} end=0x{end:06x}",
                ));
                return Err(());
            }
            self.erase(start, end).await.map_err(|_| ())
        }
    }

    impl ble_store::RecordReader for JournalFlash {
        type Error = ();

        fn read_record(&mut self, address: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            self.read(address, bytes).map_err(|_| ())
        }
    }

    impl BleStore {
        async fn mount(shared: &'static SharedFlash) -> Self {
            let mut flash = shared.lock().await;
            let mut latest: Option<(u32, Snapshot)> = None;
            let mut read_failures = 0u8;
            let mut valid_records = 0u8;
            for page in [ble_store::PAGE0, ble_store::PAGE1] {
                let mut address = page;
                while address < page + ble_store::PAGE_SIZE {
                    let mut bytes = [0u8; ble_store::SLOT_SIZE];
                    if flash.read(address, &mut bytes).is_ok() {
                        if Snapshot::decode(&bytes).is_some() {
                            valid_records = valid_records.saturating_add(1);
                        }
                        latest = ble_store::consider_snapshot(latest, address, &bytes);
                    } else {
                        read_failures = read_failures.saturating_add(1);
                    }
                    address += ble_store::SLOT_SIZE as u32;
                }
            }
            let (slot, snapshot) = latest
                .map(|(slot, snapshot)| (Some(slot), snapshot))
                .unwrap_or((None, Snapshot::empty()));
            debug_log(format_args!(
                "store mount valid-records={} read-failures={} selected-slot={:?} generation={} bonds={} pin={} local-irk={}",
                valid_records,
                read_failures,
                slot,
                snapshot.generation,
                snapshot.bonds.len(),
                snapshot.pin.is_some(),
                snapshot.local_irk.is_some(),
            ));
            drop(flash);
            Self {
                flash: shared,
                snapshot,
                slot,
            }
        }

        fn snapshot(&self) -> &Snapshot {
            &self.snapshot
        }

        async fn persist(&mut self, mut snapshot: Snapshot) -> Result<(), ()> {
            snapshot.generation = self.snapshot.generation.wrapping_add(1);
            let mut flash = self.flash.lock().await;
            let target = umsh_ulcp_runtime::journal::journal_write_target(
                &mut *flash,
                self.slot,
                ble_store::PAGE0,
                ble_store::SLOT_SIZE,
            )
            .await?;

            let bytes = snapshot.encode();
            debug_log(format_args!(
                "store body-write begin generation={} target=0x{target:06x}",
                snapshot.generation
            ));
            match ble_store::write_committed_record(&mut *flash, target, &bytes).await {
                Ok(()) => debug_log(format_args!(
                    "store body-write=ok commit-write=ok target=0x{target:06x}"
                )),
                Err(ble_store::CommitError::Body(())) => {
                    debug_log(format_args!(
                        "store body-write=FAILED target=0x{target:06x}"
                    ));
                    return Err(());
                }
                Err(ble_store::CommitError::Commit(())) => {
                    debug_log(format_args!(
                        "store body-write=ok commit-write=FAILED target=0x{target:06x}"
                    ));
                    return Err(());
                }
            }
            self.snapshot = snapshot;
            self.slot = Some(target);
            debug_log(format_args!(
                "store commit generation={} slot=0x{:06x} bonds={} pin={} local_irk={}",
                self.snapshot.generation,
                target,
                self.snapshot.bonds.len(),
                self.snapshot.pin.is_some(),
                self.snapshot.local_irk.is_some(),
            ));
            Ok(())
        }

        async fn set_pin(&mut self, pin: Option<u32>) -> Result<(), ()> {
            let mut next = self.snapshot.clone();
            next.pin = pin;
            self.persist(next).await
        }

        async fn set_local_irk(&mut self, local_irk: [u8; 16]) -> Result<(), ()> {
            if self.snapshot.local_irk == Some(local_irk) {
                return Ok(());
            }
            let mut next = self.snapshot.clone();
            next.local_irk = Some(local_irk);
            self.persist(next).await
        }

        /// Persists `bond`, keeping the bond list LRU-ordered. Returns the
        /// evicted bond, if inserting a new one at `MAX_BONDS` capacity
        /// pushed out the least-recently-used entry.
        async fn add_bond(&mut self, bond: &BondInformation) -> Result<Option<StoredBond>, ()> {
            let stored = stored_bond(bond);
            let mut next = self.snapshot.clone();
            let outcome = ble_store::upsert_bond(&mut next.bonds, stored);
            let evicted = match outcome {
                ble_store::BondUpsert::Unchanged => return Ok(None),
                ble_store::BondUpsert::Updated => None,
                ble_store::BondUpsert::Inserted { evicted } => evicted,
            };
            self.persist(next).await?;
            Ok(evicted)
        }

        /// Moves the bond matching `address_kind`/`address` to the MRU end
        /// and persists it, if it isn't already there. Called on reconnect
        /// via an existing bond, so the LRU order reflects actual use
        /// rather than only pairing/re-pairing events.
        async fn touch_bond(&mut self, address_kind: u8, address: [u8; 6]) -> Result<bool, ()> {
            let mut next = self.snapshot.clone();
            if !ble_store::touch_bond(&mut next.bonds, address_kind, address) {
                return Ok(false);
            }
            self.persist(next).await?;
            Ok(true)
        }

        async fn clear_security(&mut self) -> Result<(), ()> {
            let mut next = Snapshot::empty();
            next.generation = self.snapshot.generation;
            next.local_irk = self.snapshot.local_irk;
            self.persist(next).await
        }
    }

    /// The stored protocol snapshot payload as read at boot.
    type BootSnapshot = umsh_ulcp_runtime::journal::BootPayload;

    /// This board's journal handle: the shared two-page rotating store
    /// bound to the MPSL-coordinated flash.
    type ProtoStore = umsh_ulcp_runtime::journal::ProtoStore<ThreadModeRawMutex, JournalFlash>;

    #[cfg(feature = "t1000e")]
    fn mapped_ux_preferences() -> Option<umsh_ux_tracker::state::UserPreferences> {
        let mut latest: Option<(u32, proto_store::Stored)> = None;
        for page in [
            proto_store::UX_PAGE0,
            proto_store::UX_PAGE0 + proto_store::PAGE_SIZE,
        ] {
            let mut address = page;
            while address < page + proto_store::PAGE_SIZE {
                let mut bytes = [0u8; proto_store::SLOT_SIZE];
                // Internal flash is memory mapped. This early read happens
                // before MPSL takes NVMC and never mutates flash.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        address as *const u8,
                        bytes.as_mut_ptr(),
                        bytes.len(),
                    );
                }
                latest = proto_store::consider_record(latest, address, &bytes);
                address += proto_store::SLOT_SIZE as u32;
            }
        }
        let (_, stored) = latest?;
        let proto_store::Record::Snapshot(payload) = stored.record else {
            return None;
        };
        let mut preferences =
            umsh_ux_tracker::state::UserPreferences::try_decode(*payload.first()?)?;
        // Critical shutdown is a live protective condition mirrored in the
        // retained register, not a durable user preference.
        preferences.battery_critical = false;
        Some(preferences)
    }

    /// Callers deliberately ignore the result: the preference is already
    /// applied in RAM and mirrored in GPREGRET2, so a failed journal write
    /// costs only durability across the next reset. There is no user-facing
    /// fault channel, and confirmation feedback reflects the applied state,
    /// not the flash commit.
    #[cfg(feature = "t1000e")]
    async fn persist_ux_preferences(
        store: &mut ProtoStore,
        mut preferences: umsh_ux_tracker::state::UserPreferences,
    ) -> Result<(), ()> {
        preferences.battery_critical = false;
        store.persist(&[preferences.encode()]).await
    }

    // ─── Device-node counter persistence (plan increment 4) ─────────────────

    // ─── Device-node counter persistence (plan increment 4) ─────────────────

    // ─── Device-node counter persistence ────────────────────────────────

    /// The device node's persisted frame counters, bound to this board's
    /// flash. The map, the journal handle, and the `CounterStore` impl
    /// are shared (`umsh_ulcp_runtime::node_counters`); only the flash
    /// type and the journal's page are this board's.
    pub type NodeCounters =
        umsh_ulcp_runtime::node_counters::NodeCounters<ThreadModeRawMutex, JournalFlash>;
    pub type NodeCountersMutex = umsh_ulcp_runtime::node_counters::NodeCountersMutex<
        ThreadModeRawMutex,
        ThreadModeRawMutex,
        JournalFlash,
    >;
    pub type NodeCounterStore = umsh_ulcp_runtime::node_counters::NodeCounterStore<
        ThreadModeRawMutex,
        ThreadModeRawMutex,
        JournalFlash,
    >;

    static NODE_COUNTERS_CELL: StaticCell<NodeCountersMutex> = StaticCell::new();

    /// Initialize the (still journal-less) counter state. Call exactly
    /// once, early in boot; the BLE image attaches the journal with
    /// [`mount_node_counters`] before the device node comes up.
    fn init_node_counters() -> &'static NodeCountersMutex {
        NODE_COUNTERS_CELL.init(Mutex::new(NodeCounters::new()))
    }

    /// Mount the counter journal and load the persisted map.
    async fn mount_node_counters(
        counters: &'static NodeCountersMutex,
        flash: &'static SharedFlash,
    ) {
        umsh_ulcp_runtime::node_counters::mount(counters, flash, proto_store::COUNTER_PAGE0).await
    }

    async fn prune_stale_tx_counters(counters: &'static NodeCountersMutex, public_key: &[u8; 32]) {
        umsh_ulcp_runtime::node_counters::prune_stale_tx(counters, public_key).await
    }

    async fn clear_node_counters(counters: &'static NodeCountersMutex) {
        umsh_ulcp_runtime::node_counters::clear(counters).await
    }

    fn stored_bond(bond: &BondInformation) -> StoredBond {
        let address = bond.identity.addr.to_bytes();
        StoredBond {
            address_kind: address[0],
            address: address[1..].try_into().unwrap(),
            irk: bond.identity.irk.map(IdentityResolvingKey::to_le_bytes),
            ltk: bond.ltk.to_le_bytes(),
            security_level: match bond.security_level {
                SecurityLevel::NoEncryption => 0,
                SecurityLevel::Encrypted => 1,
                SecurityLevel::EncryptedAuthenticated => 2,
            },
            is_bonded: bond.is_bonded,
        }
    }

    fn bond_identity_is_persistable(bond: &BondInformation) -> bool {
        let address = bond.identity.addr.to_bytes();
        let public = address[0] & 1 == 0;
        let random_static = address[1] & 0xc0 == 0xc0;
        public || random_static || bond.identity.irk.is_some()
    }

    fn trouble_bond(bond: &StoredBond) -> Option<BondInformation> {
        let mut raw = bond.address;
        raw.reverse();
        let identity = Identity {
            addr: Address::new(AddrKind::new(bond.address_kind), BdAddr::new(raw)),
            irk: bond.irk.and_then(IdentityResolvingKey::from_le_bytes),
        };
        let security_level = match bond.security_level {
            0 => SecurityLevel::NoEncryption,
            1 => SecurityLevel::Encrypted,
            2 => SecurityLevel::EncryptedAuthenticated,
            _ => return None,
        };
        Some(BondInformation::new(
            identity,
            LongTermKey::from_le_bytes(bond.ltk),
            security_level,
            bond.is_bonded,
        ))
    }

    fn ble_identity_address() -> Address {
        let low = embassy_nrf::pac::FICR.deviceaddr(0).read().to_le_bytes();
        let high = embassy_nrf::pac::FICR.deviceaddr(1).read().to_le_bytes();
        let mut address = [low[0], low[1], low[2], low[3], high[0], high[1]];
        address[5] |= 0xc0;
        Address::random(address)
    }

    // ─── Static shared state ─────────────────────────────────────────────────

    /// Channels shared between the radio runner and the radio mux, which
    /// is the runner's only client.
    type RadioCh = umsh_radio_loraphy::Channels<ThreadModeRawMutex, 4, 2>;
    static RADIO_CH: RadioCh = RadioCh::new();

    /// The session's virtual radio endpoint (mux client A). The device
    /// node's endpoint (client B) lives in `device_node::NODE_CH`.
    static SESSION_CH: RadioCh = RadioCh::new();
    static MUX_CLIENTS: [&RadioCh; 2] = [&SESSION_CH, &super::device_node::NODE_CH];

    /// Runtime radio settings pushed by the session to the runner.
    static DEVICE_CTL: DeviceControl<ThreadModeRawMutex> = DeviceControl::new();

    /// Framing-free receive path and connection edges into the shared
    /// ULCP driver (`InEvent`/`FrameBuf` and the queue types live there).
    static INPUT_CH: InputChannel<ThreadModeRawMutex> = InputChannel::new();
    type FrameBuf = driver::FrameBuf;
    const FRAME_IN_MAX: usize = driver::FRAME_IN_MAX;

    /// Outbound frame queues: `wired` drained by output_task (USB-CDC),
    /// `ble` by the GATT connection writer.
    static OUT_CH: TransportChannels<ThreadModeRawMutex> = TransportChannels::new();

    type DeviceName = heapless::Vec<u8, { MAX_DEVICE_NAME_LEN }>;
    static DEVICE_NAME: Mutex<ThreadModeRawMutex, DeviceName> = Mutex::new(DeviceName::new());

    /// Snapshot the live device name for the device node's
    /// advertisements. Falls back to the (FICR-suffixed) default until
    /// the session publishes a name at boot.
    pub(crate) async fn device_name_snapshot() -> DeviceName {
        let current = DEVICE_NAME.lock().await;
        if current.is_empty() {
            let mut name = DeviceName::new();
            let _ = name.extend_from_slice(default_device_name().as_bytes());
            name
        } else {
            current.clone()
        }
    }
    static DEVICE_NAME_CHANGED: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// The GAP Device Name value that clients may hold a stale copy of.
    ///
    /// Set when the device is renamed and cleared once a Service Changed
    /// indication has gone out. A rename that happens with no one connected
    /// is therefore announced to the next client instead of being lost.
    /// Known gap: a second bonded peer that is absent for the rename *and*
    /// for the connection that consumes this flag keeps its cached name
    /// until it reads the characteristic again. Closing that needs the
    /// pending-indication state to live per bond, in the bond store.
    static GATT_NAME_STALE: AtomicBool = AtomicBool::new(false);

    /// Whether a device name has been published since boot.
    ///
    /// The first publication is the saved name being restored as the radio
    /// configuration is applied, not a rename. Treating it as one would mark
    /// the database stale on every power cycle and make every bonded peer
    /// re-discover on its next connection.
    static DEVICE_NAME_PUBLISHED: AtomicBool = AtomicBool::new(false);

    /// GAP's own bound on the Device Name value, which is shorter than the
    /// ULCP device-name limit.
    type GapDeviceName = heapless09::Vec<u8, { gap::DEVICE_NAME_MAX_LENGTH }>;

    /// The platform battery source behind `Effect::SampleBattery`: one
    /// async sample operation per board profile, returning the fields
    /// that board's `SessionConfig::battery` advertises.
    ///
    /// T-1000E: a request/reply round trip into the BSP battery monitor
    /// — the sole SAADC and sensor-rail owner — which runs its normal
    /// gated sample/classify/publish iteration early and replies with
    /// the millivolt reading and UX classification. The timeout covers
    /// the monitor having exited for critical-battery shutdown.
    #[cfg(feature = "cap-battery-saadc")]
    async fn sample_battery_snapshot() -> Result<umsh_ulcp::battery::BatteryStatus, ()> {
        let sample =
            embassy_time::with_timeout(Duration::from_secs(2), board_power::sample_battery())
                .await
                .map_err(|_| ())?;
        battery_snapshot(sample)
    }

    /// Reduce one BSP battery sample to the protocol snapshot this board's
    /// `SessionConfig::battery` advertises.
    ///
    /// Shared by the on-demand read (`Effect::SampleBattery`) and the
    /// asynchronous publication (`DeviceEnv::battery_event`) so the two can
    /// never report the same measurement differently.
    #[cfg(feature = "cap-battery-saadc")]
    fn battery_snapshot(
        sample: board_power::BatterySample,
    ) -> Result<umsh_ulcp::battery::BatteryStatus, ()> {
        use umsh_ulcp::battery::{BatteryChargeState, BatteryStatus};
        use umsh_ux_tracker::battery::ChargeClass;
        // Low and critical are UX presentation policy, not charge states;
        // `charge_class` collapses all three unpowered classifications.
        let charge_state = match umsh_ux_tracker::battery::charge_class(sample.state) {
            ChargeClass::Charging => BatteryChargeState::Charging,
            ChargeClass::Charged => BatteryChargeState::Charged,
            ChargeClass::Discharging => BatteryChargeState::Discharging,
        };
        // The level is reported by its absence when the estimator has
        // none to give — before its first quiet sample, and for as long as
        // the pack is charging on a board whose charger reports no
        // completion. Voltage and charge state still mean something in
        // both cases, so the snapshot goes out carrying what it can.
        Ok(BatteryStatus {
            voltage_mv: Some(sample.battery_mv),
            level_percent: sample.level_percent,
            charge_state: Some(charge_state),
        })
    }

    /// T-Echo: `BatteryFields::NONE` means the session answers the empty
    /// value without emitting the effect, so this is unreachable; a
    /// failure keeps any future misrouting honest.
    #[cfg(not(feature = "cap-battery-saadc"))]
    async fn sample_battery_snapshot() -> Result<umsh_ulcp::battery::BatteryStatus, ()> {
        Err(())
    }

    /// The platform light source behind `Effect::SampleIlluminance`: a
    /// request/reply round trip into the same BSP monitor that owns the
    /// SAADC, which raises both sensor enables, settles, averages, and
    /// replies in millilux. The timeout covers the monitor having exited
    /// for critical-battery shutdown — a device on its way down reports
    /// no reading rather than hanging the transaction.
    #[cfg(feature = "cap-illuminance")]
    async fn sample_illuminance_millilux() -> Option<u32> {
        embassy_time::with_timeout(
            Duration::from_secs(2),
            umsh_bsp_t1000e::light::sample_illuminance(),
        )
        .await
        .ok()
    }

    /// Published session epoch, checked by each transport at framing edges.
    static SESSION_GEN: AtomicU32 = AtomicU32::new(0);

    /// Previous boot's last breadcrumb stage (temporary freeze
    /// diagnostics; surfaced in the version string as `crumb=N`).
    static PREV_BOOT_CRUMB: AtomicU8 = AtomicU8::new(0);
    /// Previous boot's heartbeat-iteration count (~50 ms each;
    /// surfaced as `beats=N`).
    static PREV_BOOT_BEATS: AtomicU16 = AtomicU16::new(0);
    /// Raw `RESETREAS` bits captured at this boot (surfaced as `rr=0x…`
    /// so a simultaneous LOCKUP+DOG cannot hide behind the DOG-first
    /// reset-reason mapping).
    static BOOT_RESETREAS: AtomicU32 = AtomicU32::new(0);
    /// Previous boot's watchdog-timeout capture (stacked PC/LR/xPSR of
    /// the code executing ~61 µs before the watchdog reset).
    static PREV_WDT_PC: AtomicU32 = AtomicU32::new(0);
    static PREV_WDT_LR: AtomicU32 = AtomicU32::new(0);
    static PREV_WDT_PSR: AtomicU32 = AtomicU32::new(0);
    /// Previous boot's PC-ring sample count (proves the 1 kHz sampler
    /// ran; surfaced as `rc=N`).
    static PREV_RING_COUNT: AtomicU16 = AtomicU16::new(0);

    /// RAM-only until BLE persistence lands. `u32::MAX` means unset.
    static PAIRING_PIN: AtomicU32 = AtomicU32::new(u32::MAX);
    static BLE_BONDS_AT_BOOT: AtomicU8 = AtomicU8::new(0);
    static BLE_BOND_COUNT: AtomicU8 = AtomicU8::new(0);

    /// How far the BLE link has got, for the status page. Nothing is
    /// connected until a GATT connection is accepted; "attached" means the
    /// client has subscribed to the ULCP notification characteristic and
    /// is therefore actually talking to us, not merely nearby.
    ///
    /// Same encoding as the Heltec V3's, so both families read the state
    /// out of their `ui_status` the same way.
    static BLE_LINK: AtomicU8 = AtomicU8::new(BLE_LINK_NONE);
    const BLE_LINK_NONE: u8 = 0;
    const BLE_LINK_CONNECTED: u8 = 1;
    const BLE_LINK_ATTACHED: u8 = 2;

    static PAIRING_MODE: AtomicBool = AtomicBool::new(true);
    static PAIRING_LOCKED_OUT: AtomicBool = AtomicBool::new(false);
    static PAIRING_FAILURES: AtomicU8 = AtomicU8::new(0);
    /// Set when the T-1000E user button is held through power-on. This is
    /// deliberately independent of bond count: physical presence opens one
    /// pairing window even when existing bonds are present.
    static FORCE_PAIRING_AT_BOOT: AtomicBool = AtomicBool::new(false);
    #[cfg(feature = "ble-store-fault-inject")]
    static BLE_STORE_FAULT_ARMED: AtomicBool = AtomicBool::new(false);
    static PAIRING_CONFIG_CH: Channel<ThreadModeRawMutex, Option<u32>, 1> = Channel::new();
    static PAIRING_CONFIG_ACK: Signal<ThreadModeRawMutex, bool> = Signal::new();
    static PAIRING_MODE_REQUEST: Signal<ThreadModeRawMutex, ()> = Signal::new();
    static PAIRING_TIMER_RESET: Signal<ThreadModeRawMutex, ()> = Signal::new();
    static BLE_WIPE_REQUEST: Signal<ThreadModeRawMutex, ()> = Signal::new();
    #[cfg(feature = "has-display")]
    static UI_INPUT_CH: Channel<ThreadModeRawMutex, UiInput, 8> = Channel::new();
    static UI_REFRESH: Signal<ThreadModeRawMutex, ()> = Signal::new();
    static UI_NOTICE: Signal<ThreadModeRawMutex, UiNotice> = Signal::new();
    #[cfg(feature = "has-display")]
    static DISPLAY_SHUTDOWN: Signal<ThreadModeRawMutex, ()> = Signal::new();
    #[cfg(feature = "has-display")]
    static DISPLAY_SHUTDOWN_DONE: Signal<ThreadModeRawMutex, ()> = Signal::new();
    /// 0 = normal heartbeat, 1 = pairing mode, 2 = BLE state wiped.
    static BLE_LED_MODE: AtomicU8 = AtomicU8::new(0);

    /// Whether a locate alert (`PROP_ALERT`) is running. The session is
    /// authoritative; this is its board-side mirror, read by the LED
    /// task to drive the blink and by the button task, which swallows
    /// the press that cancels an alert.
    static ALERT_ACTIVE: AtomicBool = AtomicBool::new(false);
    /// Wakes the LED task on a locate-alert edge.
    static ALERT_CHANGED: Signal<ThreadModeRawMutex, ()> = Signal::new();
    /// The same edge, for the display task. A `Signal` has one useful
    /// consumer, so each task that must react promptly gets its own.
    #[cfg(feature = "has-display")]
    static UI_ALERT_CHANGED: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Apply a `PROP_ALERT` transition to the board's indicators.
    ///
    /// Idempotent — the session emits the effect on every transition,
    /// including ones that change nothing.
    fn set_alert_indication(active: bool) {
        if ALERT_ACTIVE.swap(active, Ordering::AcqRel) == active {
            return;
        }
        ALERT_CHANGED.signal(());
        // Boards with a sounder make the noise too; on the others the
        // LED blink (plus whatever the panel shows) is the whole alert.
        #[cfg(feature = "t1000e")]
        umsh_bsp_t1000e::indicator::BUZZER_ALERT_SET.signal(active);
        #[cfg(feature = "cap-buzzer")]
        umsh_bsp_wio_tracker_l1::buzzer::BUZZER_ALERT_SET.signal(active);
        #[cfg(feature = "has-display")]
        UI_ALERT_CHANGED.signal(());
        #[cfg(feature = "display-epd")]
        BACKLIGHT_CHANGED.signal(());
    }

    /// Whether the capacitive touch button is currently held.
    ///
    /// The touch button and the locate alert both want the backlight, so
    /// neither drives the pin directly; they publish their demand here
    /// and [`backlight_task`] arbitrates.
    #[cfg(feature = "display-epd")]
    static BACKLIGHT_TOUCH: AtomicBool = AtomicBool::new(false);
    /// Wakes [`backlight_task`] when either demand changes.
    #[cfg(feature = "display-epd")]
    static BACKLIGHT_CHANGED: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Whether the emissive panel has lapsed dark.
    ///
    /// Published by the display task and read by the button task, which
    /// latches it on the press edge so the press that lights the panel is
    /// not also treated as navigation. Boards with a bistable panel never
    /// set it: they have nothing to wake.
    #[cfg(feature = "display-oled")]
    static SCREEN_OFF: AtomicBool = AtomicBool::new(false);
    /// Asks the emissive panel to come back on. Distinct from
    /// [`UI_REFRESH`], which changes what is drawn but must never light a
    /// panel the user did not touch.
    #[cfg(feature = "display-oled")]
    static UI_WAKE: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Whether a locate alert is running.
    fn alert_active() -> bool {
        ALERT_ACTIVE.load(Ordering::Acquire)
    }

    /// USB protocol attachment suppresses BLE advertising. The signal wakes a
    /// pending advertiser/connection so it can apply the atomic policy.
    static ADV_ALLOWED: AtomicBool = AtomicBool::new(true);
    static ADV_POLICY_CHANGED: Signal<ThreadModeRawMutex, ()> = Signal::new();

    #[cfg(feature = "ble-debug")]
    type DebugLine = heapless::String<192>;
    #[cfg(feature = "ble-debug")]
    // 128 deep so the whole boot window (including trouble-host's resolving-list
    // diagnostics) survives in the buffer until a serial reader attaches and
    // starts draining; the output task only drains after DTR. ble-debug only.
    static DEBUG_CH: Channel<ThreadModeRawMutex, DebugLine, 128> = Channel::new();
    #[cfg(feature = "ble-debug")]
    static DEBUG_DROPPED: AtomicU32 = AtomicU32::new(0);

    pub(crate) fn debug_log(args: core::fmt::Arguments<'_>) {
        #[cfg(feature = "ble-debug")]
        {
            let mut line = DebugLine::new();
            let dropped = DEBUG_DROPPED.swap(0, Ordering::AcqRel);
            if write!(line, "[{:>8} ms] ", Instant::now().as_millis()).is_err()
                || (dropped != 0 && write!(line, "[debug-dropped={dropped}] ").is_err())
                || line.write_fmt(args).is_err()
                || line.push_str("\r\n").is_err()
            {
                DEBUG_DROPPED.fetch_add(dropped.saturating_add(1), Ordering::AcqRel);
                return;
            }
            if DEBUG_CH.try_send(line).is_err() {
                DEBUG_DROPPED.fetch_add(dropped.saturating_add(1), Ordering::AcqRel);
            }
        }
        #[cfg(not(feature = "ble-debug"))]
        let _ = args;
    }

    /// Bridges the `log` facade used by foreign crates (notably
    /// trouble-host's resolving-list and SMP diagnostics) into the same
    /// USB-serial debug channel as [`debug_log`], inheriting its
    /// timestamping and drop accounting.
    #[cfg(feature = "ble-debug")]
    struct DebugChannelLogger;

    #[cfg(feature = "ble-debug")]
    impl log::Log for DebugChannelLogger {
        fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            debug_log(format_args!(
                "{} {}: {}",
                record.level(),
                record.target(),
                record.args(),
            ));
        }

        fn flush(&self) {}
    }

    #[cfg(feature = "ble-debug")]
    static DEBUG_LOGGER: DebugChannelLogger = DebugChannelLogger;

    /// Installs [`DebugChannelLogger`] as the global `log` sink. Idempotent:
    /// `set_logger` may only succeed once, so a repeat call is ignored. Level
    /// is capped at Debug to capture trouble-host's `[host] …` diagnostics
    /// and warnings without the per-packet Trace flood.
    #[cfg(feature = "ble-debug")]
    fn init_foreign_crate_logging() {
        let _ = log::set_logger(&DEBUG_LOGGER);
        log::set_max_level(log::LevelFilter::Debug);
    }

    #[cfg(feature = "ble-debug")]
    fn trouble_security_trace(event: SecurityTrace) {
        debug_log(format_args!(
            "smp {:?} opcode=0x{:02x} detail={:02x?}",
            event.direction,
            event.command,
            &event.detail[..usize::from(event.detail_len)],
        ));
    }

    #[cfg(feature = "ble-debug")]
    fn trouble_connection_trace(event: ConnectionTrace) {
        debug_log(format_args!("trouble connection {event:?}"));
    }

    #[cfg(feature = "ble-debug")]
    fn trouble_security_diagnostic_trace(event: SecurityDiagnosticTrace) {
        debug_log(format_args!("trouble security {event:?}"));
    }

    /// Fired by button_task on the power-off hold; consumed by the
    /// board's shutdown task, which also watches the BSP's own signal
    /// (the low-battery cutoff).
    #[cfg(any(feature = "system-off-techo", feature = "system-off-wio"))]
    static SHUTDOWN_SIGNAL: Signal<ThreadModeRawMutex, ()> = Signal::new();

    // ─── Outgoing frame limits ───────────────────────────────────────────────

    const WIRE_MAX: usize = hdlc::max_encoded_len(driver::FRAME_OUT_MAX);

    fn set_advertising_allowed(allowed: bool) {
        let previous = ADV_ALLOWED.swap(allowed, Ordering::AcqRel);
        debug_log(format_args!(
            "advertising policy set previous={} allowed={} changed={}",
            previous,
            allowed,
            previous != allowed,
        ));
        ADV_POLICY_CHANGED.signal(());
    }

    fn apply_pairing_gate<C: Controller, P: PacketPool>(stack: &Stack<'_, C, P>) {
        let pin_configured = PAIRING_PIN.load(Ordering::Acquire) != u32::MAX;
        let bonds = usize::from(BLE_BOND_COUNT.load(Ordering::Acquire));
        let enabled = pairing_enabled(
            PAIRING_MODE.load(Ordering::Acquire),
            pin_configured,
            PAIRING_LOCKED_OUT.load(Ordering::Acquire),
        );
        stack.set_pairing_enabled(enabled);
        debug_log(format_args!(
            "pairing gate enabled={} mode={} pin={} locked={} failures={} bonds={}/{}",
            enabled,
            PAIRING_MODE.load(Ordering::Acquire),
            pin_configured,
            PAIRING_LOCKED_OUT.load(Ordering::Acquire),
            PAIRING_FAILURES.load(Ordering::Acquire),
            bonds,
            ble_store::MAX_BONDS,
        ));
    }

    fn pairing_runtime() -> PairingRuntime {
        PairingRuntime {
            pairing_mode: PAIRING_MODE.load(Ordering::Acquire),
            failures: PAIRING_FAILURES.load(Ordering::Acquire),
            locked_out: PAIRING_LOCKED_OUT.load(Ordering::Acquire),
        }
    }

    fn publish_pairing_runtime(state: PairingRuntime) {
        PAIRING_MODE.store(state.pairing_mode, Ordering::Release);
        PAIRING_FAILURES.store(state.failures, Ordering::Release);
        PAIRING_LOCKED_OUT.store(state.locked_out, Ordering::Release);
        UI_REFRESH.signal(());
    }

    async fn persist_bond(
        store: &BleStoreMutex,
        bond: &BondInformation,
    ) -> Result<(usize, Option<StoredBond>), ()> {
        let mut store = store.lock().await;
        let evicted = store.add_bond(bond).await?;
        Ok((store.snapshot().bonds.len(), evicted))
    }

    /// Drops an LRU-evicted bond from the live trouble bond table so the
    /// evicted peer can't keep reconnecting as "bonded" this power cycle
    /// using stale in-RAM keys after being pushed out of durable storage.
    fn forget_evicted_bond<C: Controller, P: PacketPool>(
        stack: &Stack<'_, C, P>,
        evicted: Option<StoredBond>,
    ) {
        let Some(evicted) = evicted else {
            return;
        };
        let Some(evicted_info) = trouble_bond(&evicted) else {
            return;
        };
        match stack.remove_bond_information(evicted_info.identity) {
            Ok(()) => debug_log(format_args!("lru bond evict remove=ok")),
            Err(error) => debug_log(format_args!("lru bond evict remove=FAILED error={error:?}")),
        }
    }

    fn build_sdc<'d, const N: usize>(
        p: sdc::Peripherals<'d>,
        rng: &'d mut rng::Rng<Async>,
        mpsl: &'d MultiprotocolServiceLayer,
        mem: &'d mut sdc::Mem<N>,
    ) -> Result<sdc::SoftdeviceController<'d>, sdc::Error> {
        sdc::Builder::new()?
            .support_adv()
            .support_peripheral()
            // LE Privacy enables the controller resolving list and address
            // resolution. Without it, trouble-host's boot-time
            // LeSetAddrResolutionEnable / LeAddDeviceToResolvingList commands
            // fail as unsupported, the resolving list stays empty, and a
            // bonded central that reconnects with a rotated resolvable private
            // address (iOS rotates its RPA ~every 15 min) never resolves to
            // its bond — so the link never re-encrypts and wedges the single
            // peripheral slot as an unusable NoEncryption connection.
            .support_le_privacy()
            .peripheral_count(1)?
            .buffer_cfg(
                SDC_PACKET_SIZE,
                SDC_PACKET_SIZE,
                BLE_L2CAP_TXQ,
                BLE_L2CAP_RXQ,
            )?
            .build(p, rng, mpsl, mem)
    }

    /// Board environment for the shared ULCP driver
    /// (`umsh_ulcp_runtime::driver`): persistence, entropy, pairing,
    /// and indicator couplings. The former `cfg(feature = "t1000e")` forks
    /// inside the session loop live here as trait-method overrides; the
    /// T-Echo build keeps the driver's no-op defaults for the indicator
    /// and load hooks.
    struct BoardDeviceEnv {
        proto_store: ProtoStore,
        identity_store: ProtoStore,
        identity_rng: IdentityRng,
        node_counters: &'static NodeCountersMutex,
        /// Announce-worthy battery measurements from the BSP monitor, for
        /// unsolicited `PROP_BATTERY` publication. The monitor owns the
        /// cadence and the change policy; this only forwards.
        #[cfg(feature = "cap-battery-saadc")]
        battery: embassy_sync::watch::DynReceiver<'static, board_power::BatterySample>,
        /// Positioning changes worth publishing unasked. The runtime's
        /// GNSS sink owns the policy — a stationary receiver produces a
        /// fix a second and almost none of them are news — so this only
        /// forwards what it decided to raise.
        #[cfg(feature = "cap-gnss")]
        gnss_announce: umsh_ulcp_runtime::gnss::Announcer,
    }

    impl DeviceEnv for BoardDeviceEnv {
        async fn persist_snapshot(&mut self, bytes: &[u8]) -> Result<(), ()> {
            self.proto_store.persist(bytes).await
        }

        async fn clear_snapshot(&mut self) -> Result<(), ()> {
            self.proto_store.clear().await
        }

        async fn older_snapshot(&mut self, out: &mut [u8]) -> Option<usize> {
            self.proto_store.older_snapshot(out).await
        }

        async fn sign_identity(&mut self, out: &mut [u8]) -> Option<usize> {
            super::device_node::sign_identity_blob(out).await
        }

        /// A rejected snapshot on an unattended repeater reaches nobody
        /// over the protocol, so raise the board's local indication too.
        /// `fell_back` distinguishes "running on stale configuration"
        /// from "booted bare".
        fn report_snapshot_rejected(&mut self, fell_back: bool) {
            debug_log(format_args!(
                "proto-store snapshot rejected fell-back={fell_back}"
            ));
            #[cfg(feature = "t1000e")]
            umsh_bsp_t1000e::indicator::request_attention();
        }

        async fn persist_identity(&mut self, bytes: &[u8]) -> Result<(), ()> {
            self.identity_store.persist(bytes).await
        }

        async fn clear_identity(&mut self) -> Result<(), ()> {
            self.identity_store.clear().await
        }

        async fn clear_counters(&mut self) {
            clear_node_counters(self.node_counters).await;
        }

        fn fill_secret(&mut self, secret: &mut [u8; 32]) -> Result<(), ()> {
            // TRNG-seeded ChaCha20 CSPRNG (the RNG peripheral belongs to
            // the SDC at runtime); infallible once seeded.
            rand_core::RngCore::fill_bytes(&mut self.identity_rng, secret);
            Ok(())
        }

        async fn sample_battery(&mut self) -> Result<umsh_ulcp::battery::BatteryStatus, ()> {
            sample_battery_snapshot().await
        }

        #[cfg(feature = "cap-illuminance")]
        async fn sample_illuminance(&mut self) -> Option<u32> {
            sample_illuminance_millilux().await
        }

        /// Forward the monitor's announce-worthy samples. A sample that
        /// cannot be reduced to this board's advertised field set is
        /// skipped rather than published — the same fail-closed rule the
        /// on-demand read applies.
        ///
        /// `Watch::changed` is cancellation-safe (the receiver remembers
        /// which value it last observed), which this hook requires: the
        /// driver's select drops the future whenever another arm wins.
        #[cfg(feature = "cap-battery-saadc")]
        async fn battery_event(&mut self) -> umsh_ulcp::battery::BatteryStatus {
            loop {
                let sample = self.battery.changed().await;
                if let Ok(snapshot) = battery_snapshot(sample) {
                    return snapshot;
                }
            }
        }

        async fn read_time(&mut self) -> Option<u32> {
            umsh_hal::wall_clock::now()
        }

        /// A host wrote `PROP_TIME`. An operator outranks every other
        /// source, including a receiver whose time is being distrusted —
        /// distrusting the sky is precisely why somebody would set the
        /// clock by hand.
        ///
        /// The empty write is not a failure to parse: it is the host
        /// saying the device should go back to not knowing, which is what
        /// takes the clock off a board's display.
        async fn apply_time(&mut self, epoch: Option<u32>) {
            match epoch {
                Some(seconds) => {
                    umsh_hal::wall_clock::set_manual(seconds);
                }
                None => umsh_hal::wall_clock::clear(),
            }
            // The clock appearing or vanishing is a visible change the
            // user asked for, so redraw now rather than at whatever the
            // next event happens to be.
            UI_REFRESH.signal(());
        }

        /// The receiver's current view. Cached by the runtime rather than
        /// re-read from the receiver, because "what did it last say" is
        /// the only question a UART emitting one cycle a second can
        /// answer promptly.
        #[cfg(feature = "cap-gnss")]
        async fn sample_gnss(&mut self) -> Result<umsh_ulcp::gnss::GnssSnapshot, ()> {
            Ok(umsh_ulcp_runtime::gnss::snapshot())
        }

        /// Everything this board publishes unasked, on one select arm.
        ///
        /// The driver has exactly one, because a hook per property would
        /// need one `&mut self` borrow apiece. These are disjoint fields
        /// rather than three method calls, which is what makes selecting
        /// over them legal.
        #[cfg(feature = "cap-gnss")]
        async fn publish_event(&mut self) -> driver::PublishEvent {
            loop {
                #[cfg(feature = "cap-battery-saadc")]
                let event = select(self.battery.changed(), self.gnss_announce.changed()).await;
                #[cfg(not(feature = "cap-battery-saadc"))]
                let event = Either::Second(self.gnss_announce.changed().await) as Either<(), _>;

                match event {
                    #[cfg(feature = "cap-battery-saadc")]
                    Either::First(sample) => {
                        // A sample this board cannot reduce to its
                        // advertised field set is skipped rather than
                        // published — the same fail-closed rule the
                        // on-demand read applies.
                        if let Ok(snapshot) = battery_snapshot(sample) {
                            return driver::PublishEvent::Battery(snapshot);
                        }
                    }
                    #[cfg(not(feature = "cap-battery-saadc"))]
                    Either::First(()) => unreachable!("no battery source on this board"),
                    Either::Second(umsh_ulcp_runtime::gnss::Announce::Gnss(key, snapshot)) => {
                        return driver::PublishEvent::Gnss(key, snapshot);
                    }
                    Either::Second(umsh_ulcp_runtime::gnss::Announce::Time(epoch)) => {
                        return driver::PublishEvent::Time(epoch);
                    }
                }
            }
        }

        async fn apply_pairing_pin(&mut self, pin: Option<u32>) -> bool {
            PAIRING_CONFIG_CH.send(pin).await;
            PAIRING_CONFIG_ACK.wait().await
        }

        async fn factory_reset(&mut self) -> ! {
            // Erase the entire non-volatile storage region in one sweep.
            // Every persistent journal lives in this contiguous window
            // (see `ble_store` / memory.x): BLE bonds + pairing PIN + local
            // IRK, the saved provisioning snapshot, the device identity,
            // UX state, and the frame-counter boundaries. Wiping the flash
            // and rebooting is a complete factory reset — every subsystem
            // remounts from erased flash on boot, so no live in-RAM table
            // (BLE bonds included) has to be touched here.
            //
            // The full reserved region, not just the pages currently in
            // use, so a future journal added inside it is covered too.
            const NV_REGION_START: u32 = ble_store::PAGE0; // 0x000E_4000
            const NV_REGION_END: u32 = 0x000F_4000;
            debug_log(format_args!("FACTORY RESET: erasing NV region + reboot"));
            {
                let mut flash = self.proto_store.flash().lock().await;
                let mut page = NV_REGION_START;
                while page < NV_REGION_END {
                    // Best-effort: a page that fails to erase is superseded
                    // by the reboot's fresh mount anyway, and there is no
                    // host left to report to (the link drops on reset).
                    let _ = flash.erase(page, page + ble_store::PAGE_SIZE).await;
                    page += ble_store::PAGE_SIZE;
                }
            }
            // Discards all in-RAM state and remounts factory-fresh.
            cortex_m::peripheral::SCB::sys_reset()
        }

        fn set_advertising_allowed(&mut self, allowed: bool) {
            // ble-debug builds keep advertising open regardless of the
            // arbitration policy so the diagnostic console stays reachable.
            #[cfg(feature = "ble-debug")]
            let allowed = {
                let _ = allowed;
                true
            };
            set_advertising_allowed(allowed);
        }

        async fn publish_device_name(&mut self, name: &str) {
            let bytes = name.as_bytes();
            let mut current = DEVICE_NAME.lock().await;
            if current.as_slice() == bytes {
                return;
            }
            current.clear();
            if current.extend_from_slice(bytes).is_ok() {
                if DEVICE_NAME_PUBLISHED.swap(true, Ordering::AcqRel) {
                    GATT_NAME_STALE.store(true, Ordering::Release);
                }
                DEVICE_NAME_CHANGED.signal(());
                super::device_node::set_device_name(bytes);
            }
        }

        fn publish_dev_domain(&mut self, snapshot: driver::DevDomainSnapshot) {
            // The zone and the positioning policy ride the device-domain
            // mirror, so a host write, a boot restore, and a `CMD_RST`
            // all reach the clock and the receiver by the same path —
            // and neither needs anything to remember to push it.
            umsh_hal::wall_clock::set_tz(snapshot.tz_offset_min);
            #[cfg(feature = "cap-gnss")]
            umsh_ulcp_runtime::gnss::configure(
                snapshot.gnss_enabled,
                umsh_ulcp_runtime::gnss::Policy {
                    trust_time: snapshot.gnss_time_trust,
                    update_identity: snapshot.gnss_ident_update,
                    identity_precision: snapshot.gnss_ident_precision,
                },
            );
            super::device_node::DEV_SYNC.signal(snapshot);
        }

        #[cfg(feature = "t1000e")]
        fn request_attention(&mut self) {
            umsh_bsp_t1000e::indicator::request_attention();
        }

        #[cfg(feature = "t1000e")]
        fn clear_attention(&mut self) {
            umsh_bsp_t1000e::indicator::clear_attention();
        }

        #[cfg(feature = "cap-battery-saadc")]
        fn note_transmit_load(&mut self) {
            // Mark the load for the battery level estimator (the radio
            // runner transmits within milliseconds of this).
            board_power::note_external_load();
        }

        fn set_alert(&mut self, state: umsh_ulcp::alert::AlertState) {
            set_alert_indication(state.is_active());
        }

        #[cfg(all(feature = "cap-gnss", feature = "t1000e"))]
        fn gnss_switched(&mut self, enabled: bool) {
            // Two indications rather than one confirmation blink: the
            // gesture is a toggle, so "it worked" tells the operator
            // nothing they did not already know. Which way it went is
            // the only thing worth reporting, and the buzzer carries it
            // for a device still in a pocket.
            umsh_bsp_t1000e::indicator::LED_SEQUENCE_SIGNAL.signal(if enabled {
                LedSequence::GnssOn
            } else {
                LedSequence::GnssOff
            });
            umsh_bsp_t1000e::BUZZER_SIGNAL.signal(if enabled {
                &umsh_ux_tracker::buzzer::melodies::GNSS_ON
            } else {
                &umsh_ux_tracker::buzzer::melodies::GNSS_OFF
            });
        }

        fn trace(&mut self, args: core::fmt::Arguments<'_>) {
            debug_log(args);
        }
    }

    // ─── Tasks ───────────────────────────────────────────────────────────────

    #[embassy_executor::task]
    async fn mpsl_task(mpsl: &'static MultiprotocolServiceLayer<'static>) -> ! {
        mpsl.run().await
    }

    async fn ble_runner<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) -> ! {
        loop {
            match runner.run().await {
                Ok(()) => debug_log(format_args!("ble runner exited cleanly")),
                Err(error) => debug_log(format_args!("ble runner error={error:?}")),
            }
        }
    }

    /// How long a pairing window stays open before it closes itself.
    ///
    /// Boards that can *ask* for a window — a menu entry, or a
    /// hold-through-power-on gesture — get 30 s, because reopening one is
    /// cheap. A `boot-pairing-window` board has neither, so its only
    /// window is the automatic one at boot and it is deliberately shorter:
    /// it is open on every single boot rather than on request, so the
    /// exposure is recurring and the length is the only thing limiting it.
    #[cfg(not(feature = "boot-pairing-window"))]
    const PAIRING_WINDOW_SECS: u64 = 30;
    #[cfg(feature = "boot-pairing-window")]
    const PAIRING_WINDOW_SECS: u64 = 20;

    async fn pairing_timeout<C: Controller, P: PacketPool>(stack: &Stack<'_, C, P>) -> ! {
        loop {
            match select(
                Timer::after_secs(PAIRING_WINDOW_SECS),
                PAIRING_TIMER_RESET.wait(),
            )
            .await
            {
                Either::First(()) => {
                    debug_log(format_args!("pairing window expired"));
                    PAIRING_MODE.store(false, Ordering::Release);
                    BLE_LED_MODE.store(0, Ordering::Release);
                    UI_REFRESH.signal(());
                    apply_pairing_gate(stack);
                }
                Either::Second(()) => debug_log(format_args!("pairing timer reset")),
            }
        }
    }

    async fn pairing_config_task<C: Controller, P: PacketPool>(
        stack: &Stack<'_, C, P>,
        store: &BleStoreMutex,
    ) -> ! {
        loop {
            match select3(
                PAIRING_CONFIG_CH.receive(),
                PAIRING_MODE_REQUEST.wait(),
                BLE_WIPE_REQUEST.wait(),
            )
            .await
            {
                Either3::First(pin) => {
                    debug_log(format_args!(
                        "pin config begin configured={}",
                        pin.is_some()
                    ));
                    let persisted = match store.lock().await.set_pin(pin).await {
                        Ok(()) => {
                            debug_log(format_args!("pin config persist=ok"));
                            true
                        }
                        Err(()) => {
                            debug_log(format_args!("pin config persist=FAILED"));
                            false
                        }
                    };
                    let applied = if persisted {
                        match stack.set_fixed_passkey(pin) {
                            Ok(()) => {
                                debug_log(format_args!("pin config trouble-passkey=ok"));
                                true
                            }
                            Err(error) => {
                                debug_log(format_args!(
                                    "pin config trouble-passkey=FAILED error={error:?}"
                                ));
                                false
                            }
                        }
                    } else {
                        debug_log(format_args!("pin config trouble-passkey=skipped"));
                        false
                    };
                    let result = persisted && applied;
                    if result {
                        stack.set_io_capabilities(if pin.is_some() {
                            IoCapabilities::DisplayOnly
                        } else {
                            IoCapabilities::NoInputNoOutput
                        });
                        PAIRING_PIN.store(pin.unwrap_or(u32::MAX), Ordering::Release);
                        apply_pairing_gate(stack);
                    }
                    debug_log(format_args!(
                        "pin config requested={} persisted={} applied={}",
                        pin.is_some(),
                        persisted,
                        result,
                    ));
                    PAIRING_CONFIG_ACK.signal(result);
                }
                Either3::Second(()) => {
                    debug_log(format_args!("pairing mode requested"));
                    PAIRING_MODE.store(true, Ordering::Release);
                    BLE_LED_MODE.store(1, Ordering::Release);
                    let unavailable = PAIRING_LOCKED_OUT.load(Ordering::Acquire)
                        || usize::from(BLE_BOND_COUNT.load(Ordering::Acquire))
                            >= ble_store::MAX_BONDS;
                    UI_NOTICE.signal(if unavailable {
                        UiNotice::PairingUnavailable
                    } else {
                        UiNotice::PairingStarted
                    });
                    PAIRING_TIMER_RESET.signal(());
                    apply_pairing_gate(stack);
                }
                Either3::Third(()) => {
                    debug_log(format_args!("security wipe requested"));
                    if store.lock().await.clear_security().await.is_ok() {
                        debug_log(format_args!("security wipe flash=ok"));
                        BLE_BOND_COUNT.store(0, Ordering::Release);
                        let mut identities: heapless::Vec<Identity, { ble_store::MAX_BONDS }> =
                            heapless::Vec::new();
                        stack.with_bond_information(|bonds| {
                            for bond in bonds {
                                if identities.push(bond.identity).is_err() {
                                    debug_log(format_args!("security wipe identity-list=FULL"));
                                }
                            }
                        });
                        debug_log(format_args!(
                            "security wipe removing-bonds count={}",
                            identities.len()
                        ));
                        for identity in identities {
                            match stack.remove_bond_information(identity) {
                                Ok(()) => debug_log(format_args!("security wipe remove-bond=ok")),
                                Err(error) => debug_log(format_args!(
                                    "security wipe remove-bond=FAILED error={error:?}"
                                )),
                            }
                        }
                        match stack.set_fixed_passkey(None) {
                            Ok(()) => debug_log(format_args!("security wipe clear-passkey=ok")),
                            Err(error) => debug_log(format_args!(
                                "security wipe clear-passkey=FAILED error={error:?}"
                            )),
                        }
                        stack.set_io_capabilities(IoCapabilities::NoInputNoOutput);
                        PAIRING_PIN.store(u32::MAX, Ordering::Release);
                        PAIRING_FAILURES.store(0, Ordering::Release);
                        PAIRING_LOCKED_OUT.store(false, Ordering::Release);
                        PAIRING_MODE.store(true, Ordering::Release);
                        BLE_LED_MODE.store(2, Ordering::Release);
                        PAIRING_TIMER_RESET.signal(());
                        apply_pairing_gate(stack);
                        debug_log(format_args!("security wipe complete"));
                        UI_NOTICE.signal(UiNotice::BondsCleared);
                    } else {
                        debug_log(format_args!("security wipe flash=FAILED"));
                        UI_NOTICE.signal(UiNotice::ClearFailed);
                    }
                }
            }
        }
    }

    fn classify_pairing_failure(error: &trouble_host::Error) -> PairingFailureClass {
        match error {
            trouble_host::Error::Security(PairingFailedReason::ConfirmValueFailed) => {
                PairingFailureClass::ConfirmValue
            }
            trouble_host::Error::Security(PairingFailedReason::DHKeyCheckFailed) => {
                PairingFailureClass::DhKeyCheck
            }
            _ => PairingFailureClass::Other,
        }
    }

    async fn advertise<'values, 'server, C: Controller>(
        peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
        server: &'server UlcpServer<'values>,
    ) -> Result<GattConnection<'values, 'server, DefaultPacketPool>, BleHostError<C::Error>> {
        const SERVICE_UUID_LE: [u8; 16] = gatt::SERVICE_UUID.to_le_bytes();
        // The advertisement and the GAP characteristic must agree, and this
        // is the one place both are known to be about to matter.
        sync_gap_device_name(server).await;
        let name = {
            let configured = DEVICE_NAME.lock().await;
            if configured.is_empty() {
                DeviceName::from_slice(default_device_name().as_bytes()).expect("default name fits")
            } else {
                configured.clone()
            }
        };
        let adv_name_len = utf8_prefix_len(name.as_slice(), 8);
        let mut adv_data = [0u8; 31];
        let adv_len = AdStructure::encode_slice(
            &[
                AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                AdStructure::CompleteServiceUuids128(&[SERVICE_UUID_LE]),
                AdStructure::ShortenedLocalName(&name[..adv_name_len]),
            ],
            &mut adv_data,
        )?;
        let scan_name_len = utf8_prefix_len(name.as_slice(), 29);
        let scan_name = if scan_name_len == name.len() {
            AdStructure::CompleteLocalName(&name[..scan_name_len])
        } else {
            AdStructure::ShortenedLocalName(&name[..scan_name_len])
        };
        let mut scan_data = [0u8; 31];
        let scan_len = AdStructure::encode_slice(&[scan_name], &mut scan_data)?;
        debug_log(format_args!(
            "advertising start adv-bytes={} scan-bytes={}",
            adv_len, scan_len
        ));
        let advertiser = peripheral
            .advertise(
                &Default::default(),
                Advertisement::ConnectableScannableUndirected {
                    adv_data: &adv_data[..adv_len],
                    scan_data: &scan_data[..scan_len],
                },
            )
            .await?;
        debug_log(format_args!("advertising controller-active"));
        let raw_connection = advertiser.accept().await?;
        debug_log(format_args!("advertising raw-connection accepted"));
        let connection = raw_connection.with_attribute_server(server)?;
        debug_log(format_args!("advertising gatt-server attached"));
        Ok(connection)
    }

    fn utf8_prefix_len(bytes: &[u8], maximum: usize) -> usize {
        let text = core::str::from_utf8(bytes).expect("validated device name");
        let mut len = bytes.len().min(maximum);
        while !text.is_char_boundary(len) {
            len -= 1;
        }
        len
    }

    async fn send_ble_frame(
        server: &UlcpServer<'_>,
        conn: &GattConnection<'_, '_, DefaultPacketPool>,
        outbound: OutFrame,
    ) -> Result<(), trouble_host::Error> {
        if SESSION_GEN.load(Ordering::Acquire) != outbound.generation {
            debug_log(format_args!(
                "ble outbound dropped stale-generation frame-gen={} active-gen={}",
                outbound.generation,
                SESSION_GEN.load(Ordering::Acquire),
            ));
            return Ok(());
        }
        let segment_payload = usize::from(conn.raw().att_mtu())
            .saturating_sub(4)
            .clamp(1, BLE_VALUE_MAX - 1);
        let mut segments = generation_checked(
            gatt::segments(&outbound.frame, segment_payload),
            outbound.generation,
            || SESSION_GEN.load(Ordering::Acquire),
        );
        for segment in segments.by_ref() {
            let mut value: heapless09::Vec<u8, BLE_VALUE_MAX> = heapless09::Vec::new();
            value
                .push(segment.header())
                .map_err(|_| trouble_host::Error::InsufficientSpace)?;
            value
                .extend_from_slice(segment.payload())
                .map_err(|_| trouble_host::Error::InsufficientSpace)?;
            server.ulcp.frame_out.notify(conn, &value, false).await?;
        }
        if segments.stale() {
            debug_log(format_args!(
                "ble outbound segmentation stopped generation-changed"
            ));
        }
        Ok(())
    }

    /// A link-level signal the connection loop reacts to, other than a GATT
    /// event or an outbound frame.
    enum LinkSignal {
        AdvertisingPolicy,
        DeviceName,
    }

    /// The GAP Device Name value for `name`, truncated on a UTF-8 boundary.
    ///
    /// The characteristic is inline-stored and therefore shorter than the
    /// ULCP name limit; GAP gets a prefix rather than the full name, exactly
    /// as the advertisement does.
    fn gap_device_name(name: &[u8]) -> GapDeviceName {
        let len = utf8_prefix_len(name, gap::DEVICE_NAME_MAX_LENGTH);
        GapDeviceName::from_slice(&name[..len]).unwrap_or_default()
    }

    /// Publish the configured name on the GAP Device Name characteristic.
    ///
    /// Called before advertising and after a rename, so the value a client
    /// reads is the current name rather than whatever the device booted
    /// with.
    async fn sync_gap_device_name(server: &UlcpServer<'_>) {
        let Some(gap) = server.gap.as_ref() else {
            return;
        };
        let name = device_name_snapshot().await;
        if server
            .set(&gap.device_name, &gap_device_name(name.as_slice()))
            .is_err()
        {
            debug_log(format_args!("gap device-name update FAILED"));
        }
    }

    /// Tell a connected client that its cached attributes are stale.
    ///
    /// A bonded iOS client caches the GAP device name against the bond and
    /// will keep showing the old one — in Settings › Bluetooth and to every
    /// app on the phone — until a Service Changed indication makes it
    /// re-read. The indicated range covers the whole table, because the
    /// point is to invalidate a cache rather than to describe a structural
    /// change. Clients that never subscribed are skipped inside trouble.
    async fn announce_gatt_change(
        server: &UlcpServer<'_>,
        conn: &GattConnection<'_, '_, DefaultPacketPool>,
    ) {
        let Some(gap) = server.gap.as_ref() else {
            return;
        };
        // A client that has not subscribed cannot be told anything, and
        // `indicate` reports that case as success. Checking first keeps the
        // stale marker set so the next connection tries again.
        if !gap.service_changed.should_indicate(conn) {
            debug_log(format_args!("service-changed not subscribed; deferring"));
            return;
        }
        const WHOLE_TABLE: [u8; 4] = [0x01, 0x00, 0xFF, 0xFF];
        match gap
            .service_changed
            .indicate(conn, &WHOLE_TABLE, false)
            .await
        {
            Ok(()) => {
                GATT_NAME_STALE.store(false, Ordering::Release);
                debug_log(format_args!("service-changed indicated"));
            }
            Err(error) => debug_log(format_args!("service-changed indicate error={error:?}")),
        }
    }

    async fn gatt_connection<C: Controller, P: PacketPool>(
        stack: &Stack<'_, C, P>,
        store: &BleStoreMutex,
        server: &UlcpServer<'_>,
        conn: &GattConnection<'_, '_, DefaultPacketPool>,
    ) -> Result<(), trouble_host::Error> {
        match conn.raw().set_bondable(true) {
            Ok(()) => debug_log(format_args!("connection set-bondable=ok")),
            Err(error) => {
                debug_log(format_args!(
                    "connection set-bondable=FAILED error={error:?}"
                ));
                return Err(error);
            }
        }
        let peer = conn.raw().peer_identity();
        debug_log(format_args!(
            "connected peer={} kind={} irk={} table_match={} level={:?} mtu={}",
            peer.addr,
            peer.addr.to_bytes()[0],
            peer.irk.is_some(),
            conn.raw().is_bonded_peer(),
            conn.raw().security_level(),
            conn.raw().att_mtu(),
        ));
        let mut attached = false;
        BLE_LINK.store(BLE_LINK_CONNECTED, Ordering::Release);
        let mut reassembler: gatt::Reassembler<{ gatt::MAX_FRAME }> = gatt::Reassembler::new();

        // Reap a connection that never reaches encryption, so an unbonded or
        // unresolvable central — e.g. an iOS OS-level background reconnect that
        // presents an RPA we can't resolve — cannot squat the single peripheral
        // slot at NoEncryption and lock out the real client. A bonded reconnect
        // encrypts in ~0.3 s (see connect→Encrypted in the trace); 5 s leaves
        // ~2x headroom for a slow negotiated connection interval. A deliberate
        // pairing (the user pressed pair, then enters the PIN on the phone) gets
        // the full pairing-window grace instead.
        let grace = if PAIRING_MODE.load(Ordering::Acquire) {
            Duration::from_secs(40)
        } else {
            Duration::from_secs(5)
        };
        let mut encrypted = false;
        let mut deadline = core::pin::pin!(Timer::after(grace));

        loop {
            let event = {
                let grace_guard = async {
                    if encrypted {
                        core::future::pending::<()>().await
                    } else {
                        deadline.as_mut().await
                    }
                };
                // The two link-level signals share one arm so the GATT event
                // match below keeps its shape.
                let link_signal = async {
                    match select(ADV_POLICY_CHANGED.wait(), DEVICE_NAME_CHANGED.wait()).await {
                        Either::First(()) => LinkSignal::AdvertisingPolicy,
                        Either::Second(()) => LinkSignal::DeviceName,
                    }
                };
                match select(
                    select3(conn.next(), OUT_CH.ble.receive(), link_signal),
                    grace_guard,
                )
                .await
                {
                    Either::First(event) => event,
                    Either::Second(()) => {
                        debug_log(format_args!(
                            "unencrypted connection grace expired; disconnecting squatter"
                        ));
                        conn.raw().disconnect();
                        break;
                    }
                }
            };
            match event {
                Either3::First(GattConnectionEvent::Disconnected { reason }) => {
                    debug_log(format_args!("disconnected reason={reason:?}"));
                    break;
                }
                Either3::First(GattConnectionEvent::PairingComplete { bond, .. }) => {
                    debug_log(format_args!(
                        "pairing-complete bond={} table_match={}",
                        bond.is_some(),
                        conn.raw().is_bonded_peer(),
                    ));
                    if let Some(bond) = bond {
                        if !bond_identity_is_persistable(&bond) {
                            debug_log(format_args!("pairing bond identity=incomplete"));
                            match stack.remove_bond_information(bond.identity) {
                                Ok(()) => {
                                    debug_log(format_args!("pairing incomplete bond remove=ok"))
                                }
                                Err(error) => debug_log(format_args!(
                                    "pairing incomplete bond remove=FAILED error={error:?}"
                                )),
                            }
                            debug_log(format_args!(
                                "disconnect initiated by incomplete pairing identity"
                            ));
                            conn.raw().disconnect();
                            break;
                        }
                        let persisted_bonds = match persist_bond(store, &bond).await {
                            Ok((count, evicted)) => {
                                forget_evicted_bond(stack, evicted);
                                count
                            }
                            Err(()) => {
                                debug_log(format_args!("pairing bond persist=FAILED"));
                                match stack.remove_bond_information(bond.identity) {
                                    Ok(()) => debug_log(format_args!(
                                        "pairing unpersisted bond remove=ok"
                                    )),
                                    Err(error) => debug_log(format_args!(
                                        "pairing unpersisted bond remove=FAILED error={error:?}"
                                    )),
                                }
                                debug_log(format_args!(
                                    "disconnect initiated by pairing persistence failure"
                                ));
                                conn.raw().disconnect();
                                break;
                            }
                        };
                        BLE_BOND_COUNT.store(persisted_bonds as u8, Ordering::Release);
                        UI_REFRESH.signal(());
                        debug_log(format_args!(
                            "pairing bond persist=ok peer={} kind={} irk={} bonded={} level={:?}",
                            bond.identity.addr,
                            bond.identity.addr.to_bytes()[0],
                            bond.identity.irk.is_some(),
                            bond.is_bonded,
                            bond.security_level,
                        ));
                    }
                    // Trouble may report a successful peripheral pairing with
                    // bond=None and expose the completed bond at the first
                    // protected GATT edge. Pairing success still resets the
                    // failure counter and closes the window in that case.
                    publish_pairing_runtime(pairing_runtime().pairing_succeeded());
                    BLE_LED_MODE.store(0, Ordering::Release);
                    apply_pairing_gate(stack);
                }
                Either3::First(GattConnectionEvent::PassKeyDisplay(_)) => {
                    debug_log(format_args!("passkey display requested"));
                }
                Either3::First(GattConnectionEvent::PassKeyConfirm(_)) => {
                    debug_log(format_args!("passkey confirmation requested"));
                }
                Either3::First(GattConnectionEvent::PassKeyInput) => {
                    debug_log(format_args!("passkey input requested"));
                }
                Either3::First(GattConnectionEvent::BondLost) => {
                    debug_log(format_args!("bond lost event"));
                }
                Either3::First(GattConnectionEvent::OobRequest) => {
                    debug_log(format_args!("oob requested"));
                }
                Either3::First(GattConnectionEvent::Encrypted { bond, .. }) => {
                    debug_log(format_args!(
                        "encrypted event_bond={} table_match={} level={:?}",
                        bond.is_some(),
                        conn.raw().is_bonded_peer(),
                        conn.raw().security_level(),
                    ));
                    // Link is encrypted: this is not a squatter, so stop the
                    // unencrypted-connection reaper regardless of bond state.
                    encrypted = true;
                    if bond.is_some() || conn.raw().is_bonded_peer() {
                        let peer = conn.raw().peer_identity();
                        let raw = peer.addr.to_bytes();
                        let address: [u8; 6] = raw[1..].try_into().unwrap();
                        match store.lock().await.touch_bond(raw[0], address).await {
                            Ok(true) => debug_log(format_args!("bond lru touch=moved")),
                            Ok(false) => {}
                            Err(()) => debug_log(format_args!("bond lru touch=FAILED")),
                        }
                        publish_pairing_runtime(pairing_runtime().bonded_reconnect());
                        BLE_LED_MODE.store(0, Ordering::Release);
                        apply_pairing_gate(stack);
                    }
                    // A bonded client caches attributes across connections,
                    // so a rename it missed has to be announced now. Only a
                    // client that has subscribed to Service Changed — which
                    // it does after encrypting — can be told.
                    if GATT_NAME_STALE.load(Ordering::Acquire) {
                        announce_gatt_change(server, conn).await;
                    }
                }
                Either3::First(GattConnectionEvent::PairingFailed(error)) => {
                    debug_log(format_args!("pairing-failed error={error:?}"));
                    let failure = classify_pairing_failure(&error);
                    if failure.counts_toward_lockout() {
                        let before = pairing_runtime();
                        let after = before.record_failure(failure);
                        publish_pairing_runtime(after);
                        debug_log(format_args!(
                            "pairing authentication-failures={} locked={}",
                            after.failures, after.locked_out,
                        ));
                        if after.locked_out && !before.locked_out {
                            apply_pairing_gate(stack);
                        }
                    }
                }
                Either3::First(GattConnectionEvent::Gatt { event }) => {
                    match &event {
                        GattEvent::Read(read) => debug_log(format_args!(
                            "gatt read handle=0x{:04x} level={:?}",
                            read.handle(),
                            conn.raw().security_level(),
                        )),
                        GattEvent::Write(write) => debug_log(format_args!(
                            "gatt write handle=0x{:04x} level={:?}",
                            write.handle(),
                            conn.raw().security_level(),
                        )),
                        GattEvent::NotAllowed(event) => debug_log(format_args!(
                            "gatt not-allowed handle=0x{:04x} level={:?}",
                            event.handle(),
                            conn.raw().security_level(),
                        )),
                        GattEvent::Other(event) => debug_log(format_args!(
                            "gatt other handle={:?} level={:?}",
                            event.payload().handle(),
                            conn.raw().security_level(),
                        )),
                    }
                    let frame_in = matches!(&event, GattEvent::Write(write) if write.handle() == server.ulcp.frame_in.handle);
                    let cccd = matches!(&event, GattEvent::Write(write) if Some(write.handle()) == server.ulcp.frame_out.cccd_handle);
                    let protected = frame_in || cccd;
                    let bonded = conn.raw().is_bonded_peer();
                    let mut bond_persist_failed = false;
                    // PairingComplete is not guaranteed to carry the newly-created bond on
                    // every peripheral path.  The protected GATT edge is authoritative: if
                    // Trouble says this peer is bonded, find that exact live-table entry and
                    // make it durable before granting access.  add_bond is idempotent, so
                    // subsequent frames do not write flash.
                    let durable_bond = if protected && bonded {
                        let peer = conn.raw().peer_identity();
                        let bond = stack.with_bond_information(|bonds| {
                            bonds
                                .iter()
                                .find(|bond| bond.identity.match_identity(&peer))
                                .cloned()
                        });
                        match bond {
                            Some(bond) if !bond_identity_is_persistable(&bond) => {
                                debug_log(format_args!("protected bond identity=pending"));
                                false
                            }
                            Some(bond) => match persist_bond(store, &bond).await {
                                Ok((count, evicted)) => {
                                    debug_log(format_args!("protected bond persist=ok"));
                                    forget_evicted_bond(stack, evicted);
                                    BLE_BOND_COUNT.store(count as u8, Ordering::Release);
                                    UI_REFRESH.signal(());
                                    apply_pairing_gate(stack);
                                    true
                                }
                                Err(()) => {
                                    debug_log(format_args!("protected bond persist=FAILED"));
                                    bond_persist_failed = true;
                                    match stack.remove_bond_information(bond.identity) {
                                        Ok(()) => debug_log(format_args!(
                                            "protected unpersisted bond remove=ok"
                                        )),
                                        Err(error) => debug_log(format_args!(
                                            "protected unpersisted bond remove=FAILED error={error:?}"
                                        )),
                                    }
                                    false
                                }
                            },
                            None => {
                                debug_log(format_args!("protected bond lookup=missing"));
                                false
                            }
                        }
                    } else {
                        !protected
                    };
                    if protected {
                        let peer = conn.raw().peer_identity();
                        debug_log(format_args!(
                            "gatt protected={} bonded={} durable={} peer={} kind={} irk={} level={:?}",
                            if cccd { "cccd" } else { "frame-in" },
                            bonded,
                            durable_bond,
                            peer.addr,
                            peer.addr.to_bytes()[0],
                            peer.irk.is_some(),
                            conn.raw().security_level(),
                        ));
                    }
                    let mut inbound: heapless09::Vec<u8, BLE_VALUE_MAX> = heapless09::Vec::new();
                    if frame_in {
                        if let GattEvent::Write(write) = &event {
                            write.with_data(|_, data| {
                                if inbound.extend_from_slice(data).is_err() {
                                    debug_log(format_args!(
                                        "gatt frame-in staging=FAILED len={}",
                                        data.len()
                                    ));
                                }
                            });
                        }
                    }

                    let server_permission_denied = matches!(&event, GattEvent::NotAllowed(_));
                    let reply = if protected && !(bonded && durable_bond) {
                        debug_log(format_args!(
                            "gatt decision=reject insufficient-authentication"
                        ));
                        event.reject(AttErrorCode::INSUFFICIENT_AUTHENTICATION)
                    } else if server_permission_denied {
                        // `NotAllowedEvent::accept()` preserves and returns the
                        // attribute server's permission error; it does not grant
                        // the operation. Make that non-obvious Trouble API
                        // behavior explicit in the hardware trace.
                        debug_log(format_args!("gatt decision=return-server-permission-error"));
                        event.accept()
                    } else {
                        debug_log(format_args!("gatt decision=accept"));
                        event.accept()
                    }?;
                    reply.send().await;

                    if protected && bonded && !durable_bond && bond_persist_failed {
                        debug_log(format_args!(
                            "disconnect initiated by protected bond persistence failure"
                        ));
                        conn.raw().disconnect();
                        break;
                    }

                    if frame_in && bonded {
                        match reassembler.push(&inbound) {
                            Some(Ok(frame)) => {
                                let mut value: FrameBuf = heapless::Vec::new();
                                match value.extend_from_slice(frame) {
                                    Ok(()) => {
                                        debug_log(format_args!(
                                            "gatt frame-in complete len={}",
                                            frame.len()
                                        ));
                                        INPUT_CH.send(InEvent::Frame(Transport::Ble, value)).await;
                                    }
                                    Err(()) => debug_log(format_args!(
                                        "gatt frame-in complete staging=FAILED len={}",
                                        frame.len()
                                    )),
                                }
                            }
                            Some(Err(error)) => debug_log(format_args!(
                                "gatt frame-in decode=FAILED error={error:?} segment-len={}",
                                inbound.len()
                            )),
                            None => debug_log(format_args!(
                                "gatt frame-in segment accepted segment-len={} complete=false",
                                inbound.len()
                            )),
                        }
                    }
                    if cccd && bonded {
                        let subscribed = server.ulcp.frame_out.should_notify(conn);
                        match (attached, subscribed) {
                            (false, true) => {
                                debug_log(format_args!("cccd subscribed=true"));
                                attached = true;
                                BLE_LINK.store(BLE_LINK_ATTACHED, Ordering::Release);
                                UI_REFRESH.signal(());
                                INPUT_CH.send(InEvent::Attached(Transport::Ble)).await;
                            }
                            (true, false) => {
                                debug_log(format_args!("cccd subscribed=false"));
                                attached = false;
                                BLE_LINK.store(BLE_LINK_CONNECTED, Ordering::Release);
                                UI_REFRESH.signal(());
                                reassembler.reset();
                                INPUT_CH.send(InEvent::Detached(Transport::Ble)).await;
                            }
                            (false, false) => debug_log(format_args!(
                                "cccd state unchanged attached=false subscribed=false"
                            )),
                            (true, true) => debug_log(format_args!(
                                "cccd state unchanged attached=true subscribed=true"
                            )),
                        }
                    }
                }
                Either3::First(GattConnectionEvent::PhyUpdated { tx_phy, rx_phy }) => {
                    debug_log(format_args!(
                        "connection phy-updated tx={tx_phy:?} rx={rx_phy:?}"
                    ));
                }
                Either3::First(GattConnectionEvent::ConnectionParamsUpdated {
                    conn_interval,
                    peripheral_latency,
                    supervision_timeout,
                }) => {
                    debug_log(format_args!(
                        "connection params-updated interval-us={} latency={} timeout-us={}",
                        conn_interval.as_micros(),
                        peripheral_latency,
                        supervision_timeout.as_micros(),
                    ));
                }
                Either3::First(GattConnectionEvent::RequestConnectionParams(request)) => {
                    debug_log(format_args!(
                        "connection params-requested params={:?}",
                        request.params()
                    ));
                    match request.accept(None, stack).await {
                        Ok(()) => debug_log(format_args!("connection params-response=accepted")),
                        Err(error) => debug_log(format_args!(
                            "connection params-response=FAILED error={error:?}"
                        )),
                    }
                }
                Either3::First(GattConnectionEvent::DataLengthUpdated {
                    max_tx_octets,
                    max_tx_time,
                    max_rx_octets,
                    max_rx_time,
                }) => debug_log(format_args!(
                    "connection data-length tx-octets={} tx-time={} rx-octets={} rx-time={}",
                    max_tx_octets, max_tx_time, max_rx_octets, max_rx_time,
                )),
                Either3::First(GattConnectionEvent::FrameSpaceUpdated {
                    frame_space,
                    initiator,
                    phys,
                    spacing_types,
                }) => debug_log(format_args!(
                    "connection frame-space us={} initiator={initiator:?} phys={phys:?} spacing={spacing_types:?}",
                    frame_space.as_micros(),
                )),
                Either3::First(GattConnectionEvent::ConnectionRateChanged {
                    conn_interval,
                    subrate_factor,
                    peripheral_latency,
                    continuation_number,
                    supervision_timeout,
                }) => debug_log(format_args!(
                    "connection rate-changed interval-us={} subrate={} latency={} continuation={} timeout-us={}",
                    conn_interval.as_micros(),
                    subrate_factor,
                    peripheral_latency,
                    continuation_number,
                    supervision_timeout.as_micros(),
                )),
                Either3::Second(outbound) => {
                    if attached && conn.raw().is_bonded_peer() {
                        send_ble_frame(server, conn, outbound).await?;
                    } else {
                        debug_log(format_args!(
                            "ble outbound dropped attached={} bonded={} level={:?}",
                            attached,
                            conn.raw().is_bonded_peer(),
                            conn.raw().security_level(),
                        ));
                    }
                }
                Either3::Third(LinkSignal::AdvertisingPolicy) => {
                    if !ADV_ALLOWED.load(Ordering::Acquire) {
                        debug_log(format_args!(
                            "disconnect initiated by transport arbitration"
                        ));
                        conn.raw().disconnect();
                        break;
                    }
                }
                Either3::Third(LinkSignal::DeviceName) => {
                    sync_gap_device_name(server).await;
                    announce_gatt_change(server, conn).await;
                }
            }
        }
        BLE_LINK.store(BLE_LINK_NONE, Ordering::Release);
        UI_REFRESH.signal(());
        if attached {
            INPUT_CH.send(InEvent::Detached(Transport::Ble)).await;
        }
        Ok(())
    }

    async fn ble_peripheral<'values, C: Controller>(
        stack: &Stack<'_, C, DefaultPacketPool>,
        store: &BleStoreMutex,
        peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
        server: &UlcpServer<'values>,
    ) -> ! {
        loop {
            if !ADV_ALLOWED.load(Ordering::Acquire) {
                ADV_POLICY_CHANGED.wait().await;
                continue;
            }
            super::panic::breadcrumb_mark(12);
            match select3(
                advertise(peripheral, server),
                ADV_POLICY_CHANGED.wait(),
                DEVICE_NAME_CHANGED.wait(),
            )
            .await
            {
                Either3::First(Ok(connection)) => {
                    match gatt_connection(stack, store, server, &connection).await {
                        Ok(()) => debug_log(format_args!("gatt connection task ended ok")),
                        Err(error) => {
                            debug_log(format_args!("gatt connection task error={error:?}"))
                        }
                    }
                }
                Either3::First(Err(error)) => {
                    debug_log(format_args!("advertising error={error:?}"))
                }
                Either3::Second(()) => debug_log(format_args!("advertising policy changed")),
                Either3::Third(()) => debug_log(format_args!("advertising device name changed")),
            }
        }
    }

    /// Startup-failure containment: a misconfigured or failed BLE bring-up
    /// must degrade to a USB-only device, never a panic/reboot loop — a
    /// display-less field node that boot-loops is unrecoverable in place.
    /// Parks the BLE app forever; USB keeps running via the outer join.
    async fn ble_disabled_park(reason: &'static str) -> ! {
        loop {
            debug_log(format_args!("BLE DISABLED: {reason}"));
            Timer::after_secs(600).await;
        }
    }

    async fn ble_app<C: Controller>(controller: C, store: BleStore) -> ! {
        // Install the log→serial bridge before the host stack starts so
        // trouble-host's boot-time resolving-list diagnostics are captured.
        #[cfg(feature = "ble-debug")]
        init_foreign_crate_logging();
        super::panic::breadcrumb_mark(10);
        let mut resources: HostResources<
            _,
            DefaultPacketPool,
            BLE_CONNECTIONS_MAX,
            BLE_L2CAP_CHANNELS_MAX,
        > = HostResources::new();
        let initial = store.snapshot().clone();
        debug_log(format_args!(
            "ble boot identity={} bonds={} pin={} local_irk={} privacy=false",
            ble_identity_address(),
            initial.bonds.len(),
            initial.pin.is_some(),
            initial.local_irk.is_some(),
        ));
        for bond in &initial.bonds {
            debug_log(format_args!(
                "restored bond peer-kind={} peer={:02x?} irk={} bonded={} level={}",
                bond.address_kind,
                bond.address,
                bond.irk.is_some(),
                bond.is_bonded,
                bond.security_level,
            ));
        }
        PAIRING_PIN.store(initial.pin.unwrap_or(u32::MAX), Ordering::Release);
        BLE_BOND_COUNT.store(initial.bonds.len() as u8, Ordering::Release);
        // `boot-pairing-window` boards open a window on *every* boot,
        // bonded or not. They have no button and no menu, so this is the
        // only way to ever pair a second host — without it the first
        // bond would lock everyone else out permanently. Pressing RESET
        // is the physical-presence ceremony on those boards, standing in
        // for the button hold the others use; a configured PIN still
        // gates the pairing itself, and the failure lockout still applies.
        let initial_pairing_mode = initial.bonds.is_empty()
            || FORCE_PAIRING_AT_BOOT.load(Ordering::Acquire)
            || cfg!(feature = "boot-pairing-window");
        PAIRING_MODE.store(initial_pairing_mode, Ordering::Release);
        BLE_LED_MODE.store(u8::from(initial_pairing_mode), Ordering::Release);
        UI_REFRESH.signal(());
        let io_capabilities = if initial.pin.is_some() {
            IoCapabilities::DisplayOnly
        } else {
            IoCapabilities::NoInputNoOutput
        };
        let initial_pairing_enabled =
            pairing_enabled(initial_pairing_mode, initial.pin.is_some(), false);
        debug_log(format_args!(
            "ble stack configure io={io_capabilities:?} pairing-enabled={} fixed-passkey={}",
            initial_pairing_enabled,
            initial.pin.is_some(),
        ));
        let stack_builder = trouble_host::new(controller, &mut resources)
            .set_random_address(ble_identity_address())
            .set_io_capabilities(io_capabilities)
            .set_pairing_enabled(initial_pairing_enabled)
            .set_fixed_passkey(initial.pin);
        let stack = match stack_builder {
            Ok(builder) => {
                debug_log(format_args!("ble stack fixed-passkey configure=ok"));
                builder.build()
            }
            Err(error) => {
                debug_log(format_args!(
                    "ble stack fixed-passkey configure=FAILED error={error:?}"
                ));
                ble_disabled_park("invalid fixed passkey").await
            }
        };
        for (index, bond) in initial.bonds.iter().enumerate() {
            if let Some(bond) = trouble_bond(bond) {
                match stack.add_bond_information(bond) {
                    Ok(()) => debug_log(format_args!("restored bond index={index} add=ok")),
                    Err(error) => debug_log(format_args!(
                        "restored bond index={index} add=FAILED error={error:?}"
                    )),
                }
            } else {
                debug_log(format_args!("restored bond index={index} decode=FAILED"));
            }
        }
        let store = BleStoreMutex::new(store);
        let runner = stack.runner();
        let mut peripheral = stack.peripheral();
        let server_result = UlcpServer::new_with_config(GapConfig::Peripheral(PeripheralConfig {
            name: default_device_name(),
            appearance: &appearance::computer::GENERIC_COMPUTER,
        }));
        let server = match server_result {
            Ok(server) => {
                debug_log(format_args!("gatt server construction=ok"));
                server
            }
            Err(error) => {
                debug_log(format_args!(
                    "gatt server construction=FAILED error={error:?}"
                ));
                ble_disabled_park("gatt server construction failed").await
            }
        };

        super::panic::breadcrumb_mark(11);
        join(
            ble_runner(runner),
            join(
                pairing_timeout(&stack),
                join(
                    pairing_config_task(&stack, &store),
                    ble_peripheral(&stack, &store, &mut peripheral, &server),
                ),
            ),
        )
        .await;
        unreachable!()
    }

    /// Owns the `lora_phy::LoRa` instance via the reconfigurable device
    /// runner. RX preamble 8 symbols, TX preamble 16 (MeshCore parity).
    #[embassy_executor::task]
    async fn radio_task(lora: LoraRadio) {
        #[cfg(not(feature = "t1000e"))]
        const RX_PREAMBLE: u16 = 8;
        // Hardware bring-up established that the LR1110 misses MeshCore-US
        // traffic with an 8-symbol detector even though the SX1262 does not.
        #[cfg(feature = "t1000e")]
        const RX_PREAMBLE: u16 = 16;
        umsh_radio_loraphy::device_runner(lora, &RADIO_CH, &DEVICE_CTL, RX_PREAMBLE, 16).await;
    }

    /// Owns the real `RADIO_CH` bundle and multiplexes it across the
    /// virtual per-client bundles (see `radio_mux`): per-client TX
    /// completion routing plus RX fan-out to every client.
    #[embassy_executor::task]
    async fn radio_mux_task() {
        super::radio_mux::radio_mux(&RADIO_CH, &MUX_CLIENTS).await
    }

    /// Owns the USB `Sender`, HDLC-encodes frames, and writes USB packets.
    #[embassy_executor::task]
    async fn output_task(
        mut tx: DeviceSender,
        wdt_report: Option<&'static str>,
        panic_report: Option<&'static str>,
    ) {
        // Emit the previous boot's diagnostics (watchdog capture and/or
        // panic message) as ASCII to the first USB reader. HDLC hosts
        // resynchronize past it; humans read it with a serial terminal.
        // Wait for DTR — the OS CDC driver drains the IN endpoint even
        // with no process attached, so writing before a real opener
        // exists would discard the report into the void.
        if wdt_report.is_some() || panic_report.is_some() {
            while !tx.dtr() {
                Timer::after_millis(50).await;
            }
            Timer::after_millis(300).await;
            for report in [wdt_report, panic_report].into_iter().flatten() {
                for chunk in report.as_bytes().chunks(64) {
                    let _ = tx.write_packet(chunk).await;
                }
            }
        }
        loop {
            #[cfg(feature = "ble-debug")]
            let outbound = match select(OUT_CH.wired.receive(), DEBUG_CH.receive()).await {
                Either::First(outbound) => outbound,
                Either::Second(line) => {
                    for chunk in line.as_bytes().chunks(64) {
                        let _ = tx.write_packet(chunk).await;
                    }
                    continue;
                }
            };
            #[cfg(not(feature = "ble-debug"))]
            let outbound = OUT_CH.wired.receive().await;
            if SESSION_GEN.load(Ordering::Acquire) != outbound.generation {
                continue;
            }
            let mut wire = [0u8; WIRE_MAX];
            let Ok(len) = hdlc::encode_frame(&outbound.frame, &mut wire) else {
                continue;
            };
            for chunk in generation_checked(wire[..len].chunks(64), outbound.generation, || {
                SESSION_GEN.load(Ordering::Acquire)
            }) {
                let _ = tx.write_packet(chunk).await;
            }
        }
    }

    /// Owns the CDC receive half and HDLC decoder. Forwards frames and edges
    /// into INPUT_CH; `wait_connection` always precedes the read loop so
    /// a disconnected port never busy-loops.
    #[embassy_executor::task]
    async fn usb_in_task(mut rx: DeviceRescue) {
        loop {
            rx.wait_connection().await;
            debug_log(format_args!("usb debug attached"));
            let mut decoder: hdlc::Decoder<FRAME_IN_MAX> = hdlc::Decoder::new();
            let mut local_generation = SESSION_GEN.load(Ordering::Acquire);
            INPUT_CH.send(InEvent::Attached(Transport::Usb)).await;
            loop {
                let generation = SESSION_GEN.load(Ordering::Acquire);
                if generation != local_generation {
                    decoder.reset();
                    local_generation = generation;
                }
                let mut packet = [0u8; 64];
                match rx.read_packet(&mut packet).await {
                    Ok(0) | Err(_) => break,
                    Ok(len) => {
                        for &byte in &packet[..len] {
                            let Some(Ok(bytes)) = decoder.push(byte) else {
                                continue;
                            };
                            let mut frame = heapless::Vec::new();
                            let _ = frame.extend_from_slice(bytes);
                            INPUT_CH.send(InEvent::Frame(Transport::Usb, frame)).await;
                        }
                    }
                }
            }
            INPUT_CH.send(InEvent::Detached(Transport::Usb)).await;
        }
    }

    /// Owns the framing-free protocol session: hosts the shared ULCP
    /// driver (`umsh_ulcp_runtime::driver::run`) — host frames,
    /// radio receptions, transmit completions, and every session effect
    /// — over this board's channel wiring and [`BoardDeviceEnv`] couplings.
    #[embassy_executor::task]
    async fn device_task(
        boot_reason: Status,
        proto_store: ProtoStore,
        boot_snapshot: Option<BootSnapshot>,
        identity_store: ProtoStore,
        boot_identity: Option<[u8; 32]>,
        identity_rng: IdentityRng,
        node_counters: &'static NodeCountersMutex,
    ) {
        // The retained hardware reset cause answers the first
        // PROP_LAST_STATUS query; attach itself never modifies it.
        let session = Session::new(
            session_config(),
            boot_reason,
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
        );
        driver::run(
            session,
            boot_snapshot.as_deref(),
            boot_identity,
            DeviceRuntime {
                input: &INPUT_CH,
                radio: &SESSION_CH,
                ctl: &DEVICE_CTL,
                out: &OUT_CH,
                session_gen: &SESSION_GEN,
            },
            BoardDeviceEnv {
                proto_store,
                identity_store,
                identity_rng,
                node_counters,
                // The driver is the only receiver; the slot count is
                // sized for exactly that, so this cannot fail.
                #[cfg(feature = "cap-battery-saadc")]
                battery: board_power::BATTERY_ANNOUNCE
                    .dyn_receiver()
                    .expect("BATTERY_ANNOUNCE receiver slot"),
                #[cfg(feature = "cap-gnss")]
                gnss_announce: umsh_ulcp_runtime::gnss::announcer()
                    .expect("GNSS announcement receiver slot"),
            },
        )
        .await
    }

    /// Everything the shared renderer draws that is not menu state.
    ///
    /// The device name is passed in rather than read here: reading it is
    /// async and the model borrows it, so the display task snapshots it
    /// once per frame and lends it to this.
    #[cfg(feature = "has-display")]
    fn ui_status(name: &DeviceName) -> screen::StatusModel<'_> {
        screen::StatusModel {
            device_name: core::str::from_utf8(name).unwrap_or(DEFAULT_DEVICE_NAME),
            battery: ui_battery(),
            battery_mv: ui_battery_mv(),
            // A live host outranks discoverability: "somebody is talking
            // to me" is the fact worth a row, and advertising with nobody
            // there is the resting state the page no longer mentions.
            link: match BLE_LINK.load(Ordering::Acquire) {
                BLE_LINK_ATTACHED => screen::LinkState::Attached,
                BLE_LINK_CONNECTED => screen::LinkState::Connected,
                _ if ADV_ALLOWED.load(Ordering::Acquire) => screen::LinkState::Advertising,
                _ => screen::LinkState::OffWired,
            },
            stats: ui_stats(),
            bonds: BLE_BOND_COUNT.load(Ordering::Acquire),
            // Lockout outranks the window: while locked out there is no
            // window to describe.
            pairing: if PAIRING_LOCKED_OUT.load(Ordering::Acquire) {
                screen::PairingState::LockedOut
            } else if PAIRING_MODE.load(Ordering::Acquire) {
                screen::PairingState::Open {
                    pin: match PAIRING_PIN.load(Ordering::Acquire) {
                        u32::MAX => None,
                        pin => Some(pin),
                    },
                }
            } else {
                screen::PairingState::Closed
            },
            // `None` whenever the device does not know what time it is,
            // which the renderer draws as nothing at all. There is
            // deliberately no fallback here: a placeholder would be an
            // indication of the current time, and a device that does not
            // have one must not give any.
            clock: umsh_hal::wall_clock::local_hhmm()
                .map(|(hour, minute)| screen::ClockModel { hour, minute }),
        }
    }

    /// Radio activity for the stats page.
    ///
    /// Sampled when a frame is drawn rather than pushed: the counters move
    /// with every frame on the air, and waking a panel for each one would
    /// re-ink an e-paper display continuously to report numbers nobody is
    /// looking at.
    #[cfg(feature = "has-display")]
    fn ui_stats() -> screen::StatsModel {
        let counters = super::device_node::mac_counters();
        screen::StatsModel {
            tx_frames: counters.tx_frames,
            rx_frames: counters.rx_frames,
            rx_accepted: counters.rx_accepted,
            forwarded: counters.forwarded,
            tx_power_dbm: super::device_node::tx_power_dbm(),
            // The ledger's scale is 0-65535 for 0-100%; the page shows
            // tenths of a percent, which is the range a tracker lives in.
            duty_permille: (u32::from(DUTY_LEDGER.usage(Instant::now().as_millis())) * 1_000
                / 65_535) as u16,
        }
    }

    /// Cached battery reading for the indicator. Reads the monitor's
    /// published atomics rather than requesting a sample: the request path
    /// is single-consumer and already belongs to the ULCP driver.
    #[cfg(feature = "has-display")]
    fn ui_battery() -> screen::BatteryIndicator {
        #[cfg(feature = "cap-battery-saadc")]
        {
            screen::BatteryIndicator {
                level_percent: board_power::battery_level(),
                charge: Some(umsh_ux_tracker::battery::charge_class(
                    board_power::battery_state(),
                )),
            }
        }
        #[cfg(not(feature = "cap-battery-saadc"))]
        {
            screen::BatteryIndicator::UNKNOWN
        }
    }

    /// Completes when the charge class or level moves, so the panel can
    /// redraw its indicator. Never completes on a board built without the
    /// SAADC monitor, which keeps the display tasks' `select` shape the
    /// same either way.
    #[cfg(feature = "has-display")]
    async fn battery_ui_changed() {
        #[cfg(feature = "cap-battery-saadc")]
        board_power::BATTERY_UI_CHANGED.wait().await;
        #[cfg(not(feature = "cap-battery-saadc"))]
        core::future::pending::<()>().await
    }

    /// Drive the board's GNSS receiver.
    ///
    /// The whole of the per-board GNSS code: construct the UART and the
    /// board's power control, then hand both to the shared pump. An
    /// `#[embassy_executor::task]` cannot be generic, which is the only
    /// reason this shim exists at all — the loop it delegates to lives in
    /// `umsh_gnss::pump` and is common to both cargo workspaces.
    ///
    /// The receiver stays powered down until `PROP_GNSS_ENABLED` says
    /// otherwise, including on a board that has never been configured.
    #[cfg(feature = "cap-gnss")]
    #[embassy_executor::task]
    async fn gnss_task(
        #[allow(unused_mut)] mut uart: GnssUart,
        #[allow(unused_mut)] mut control: BoardGnss,
    ) {
        let Some(enable) = umsh_ulcp_runtime::gnss::EnableSource::new() else {
            debug_log(format_args!("gnss: enable receiver already taken"));
            return;
        };

        // On a board whose only surviving real-time clock lives inside the
        // receiver, read it back before the pump takes over — otherwise a
        // device that was switched off knowing the time boots not knowing
        // it, and the clock the backup domain was kept powered to preserve
        // is never actually consulted.
        //
        // Gated on trust and not on `PROP_GNSS_ENABLED`, because this is a
        // clock operation: a device with positioning switched off still
        // wants to know what time it is. Waiting for the device domain is
        // what makes the trust flag mean the saved setting rather than the
        // post-reset default.
        #[cfg(feature = "gnss-holds-the-clock")]
        {
            umsh_ulcp_runtime::gnss::wait_configured().await;
            if !umsh_hal::wall_clock::is_set() && umsh_ulcp_runtime::gnss::policy().trust_time {
                match umsh_gnss::pump::rtc_read_once(&mut uart, &mut control, embassy_time::Delay)
                    .await
                    .and_then(|at| at.to_unix())
                {
                    Some(epoch) => {
                        umsh_hal::wall_clock::apply(
                            epoch,
                            umsh_hal::wall_clock::TimeSource::GnssRtc,
                            true,
                        );
                        debug_log(format_args!("gnss: clock restored from receiver RTC"));
                    }
                    // What a receiver whose backup domain lost power looks
                    // like. The device simply does not know the time.
                    None => debug_log(format_args!("gnss: receiver RTC had no time")),
                }
            }
        }

        umsh_gnss::pump::run(
            uart,
            control,
            enable,
            umsh_ulcp_runtime::gnss::FixSink,
            embassy_time::Delay,
        )
        .await
    }

    /// Completes at the next minute boundary, so a clock row can advance.
    ///
    /// The display layer's standing rule is that panels redraw on events
    /// and never on a timer, because a timer on a bistable panel is a
    /// battery drain that reports nothing. A clock is the one thing that
    /// has to move on its own, so this is the sanctioned exception — and
    /// it is bounded to exactly the case that needs it. It never
    /// completes unless the panel is already awake (`awake`) *and* the
    /// device knows what time it is, so a sleeping panel is never woken
    /// by it and a device with no clock never arms it at all. A panel
    /// that was asleep catches up on its next event-driven redraw.
    #[cfg(feature = "has-display")]
    async fn clock_tick(awake: bool) {
        if !awake {
            core::future::pending::<()>().await;
        }
        match umsh_hal::wall_clock::millis_to_next_minute() {
            Some(millis) => Timer::after_millis(u64::from(millis)).await,
            None => core::future::pending().await,
        }
    }

    #[cfg(feature = "has-display")]
    fn ui_battery_mv() -> Option<u16> {
        #[cfg(feature = "cap-battery-saadc")]
        {
            board_power::battery_millivolts()
        }
        #[cfg(not(feature = "cap-battery-saadc"))]
        {
            None
        }
    }

    #[cfg(feature = "display-epd")]
    fn render_ui_frame(
        buf: &mut [u8; display::BUF_SIZE],
        model: &UiModel,
        status: &screen::StatusModel<'_>,
    ) {
        screen::render_frame(
            &mut display::EpdFb(buf),
            &screen::Layout::EPD_200X200,
            model,
            status,
        );
    }

    #[cfg(feature = "display-epd")]
    fn render_message_frame(
        buf: &mut [u8; display::BUF_SIZE],
        status: &screen::StatusModel<'_>,
        title: &str,
        detail: &str,
    ) {
        screen::render_message(
            &mut display::EpdFb(buf),
            &screen::Layout::EPD_200X200,
            status,
            title,
            detail,
        );
    }

    /// Everything this board's menu can do. Every display tracker in this
    /// family has a panel and a nav button, which between them cover the
    /// whole class vocabulary; a board with fewer affordances would
    /// return a narrower set and the menu would skip what it omits.
    #[cfg(feature = "has-display")]
    fn board_menu_items() -> MenuItems {
        MenuItems::all()
    }

    /// Owns the e-paper bus and renders the BLE menu. Input is serialized
    /// through the full-refresh cycle so Select can never activate an item the
    /// user has not yet seen on the panel.
    ///
    /// The panel is bistable, so attention lapsing never turns it off —
    /// it drops whatever the user was in the middle of and returns to
    /// the status page, so a press after walking away starts somewhere
    /// whose meaning is on screen.
    #[cfg(feature = "display-epd")]
    #[embassy_executor::task]
    async fn display_task(
        mut spi: Spim<'static>,
        mut cs: Output<'static>,
        mut dc: Output<'static>,
        mut rst: Output<'static>,
        mut busy: Input<'static>,
    ) {
        let mut model = UiModel::new(board_menu_items());
        let mut attention = Attention::new(
            DisplayKind::Persistent,
            AttentionConfig::PERSISTENT,
            Instant::now().as_millis(),
        );
        let mut shown = [0xff; display::BUF_SIZE];
        let mut next = [0xff; display::BUF_SIZE];
        {
            let name = device_name_snapshot().await;
            render_ui_frame(&mut next, &model, &ui_status(&name));
        }
        display::init(&mut spi, &mut cs, &mut dc, &mut rst, &mut busy).await;
        display::render(&mut spi, &mut cs, &mut dc, &mut busy, &next).await;
        shown.copy_from_slice(&next);

        // The panel borrows five peripherals mutably; a closure capturing
        // all of them would conflict with the `next` buffer it draws
        // into, so the push stays a macro.
        macro_rules! push {
            () => {
                display::render_partial(&mut spi, &mut cs, &mut dc, &mut busy, &mut shown, &next)
                    .await
            };
        }

        loop {
            // The name changes rarely but is needed by every frame this
            // pass might draw, including the message frames below, so it
            // is snapshotted once and lent out. The rest of the status is
            // rebuilt at each draw, since an effect handled below can
            // change it.
            let name = device_name_snapshot().await;

            // Both holds are edge-published by other tasks, but re-deriving
            // them here each pass is idempotent and cannot miss an edge.
            let now = Instant::now().as_millis();
            attention.set_hold(
                HoldReason::Pairing,
                PAIRING_MODE.load(Ordering::Acquire),
                now,
            );
            attention.set_hold(HoldReason::Alert, alert_active(), now);

            let lapse = async {
                match attention.next_deadline() {
                    Some(deadline) => Timer::at(Instant::from_millis(deadline)).await,
                    None => core::future::pending().await,
                }
            };

            // True unless the arm already pushed its own frame.
            let mut redraw = true;
            match select4(
                UI_INPUT_CH.receive(),
                select4(
                    UI_REFRESH.wait(),
                    UI_NOTICE.wait(),
                    UI_ALERT_CHANGED.wait(),
                    select(battery_ui_changed(), clock_tick(attention.accepts_redraw())),
                ),
                DISPLAY_SHUTDOWN.wait(),
                lapse,
            )
            .await
            {
                Either4::First(input) => {
                    debug_log(format_args!("ui input={input:?}"));
                    attention.wake(Instant::now().as_millis());
                    match model.apply(input) {
                        Some(UiEffect::CheckIn) => {
                            super::device_node::request_beacon(
                                super::device_node::BeaconTrigger::Button,
                            );
                            model.set_notice(UiNotice::CheckInRequested);
                        }
                        Some(UiEffect::StartPairing) => {
                            render_message_frame(
                                &mut next,
                                &ui_status(&name),
                                "Starting",
                                "pairing mode...",
                            );
                            push!();
                            redraw = false;
                            PAIRING_MODE_REQUEST.signal(());
                        }
                        Some(UiEffect::ClearBonds) => {
                            render_message_frame(
                                &mut next,
                                &ui_status(&name),
                                "Clearing",
                                "bonds + PIN...",
                            );
                            push!();
                            redraw = false;
                            BLE_WIPE_REQUEST.signal(());
                        }
                        None => {}
                    }
                }
                Either4::Second(refresh) => {
                    match refresh {
                        // The first three are consequences of something the
                        // user or their phone just did, so all of them
                        // count as attention.
                        Either4::First(()) => {
                            attention.wake(Instant::now().as_millis());
                            model.clear_notice();
                        }
                        Either4::Second(notice) => {
                            attention.wake(Instant::now().as_millis());
                            model.set_notice(notice);
                        }
                        Either4::Third(()) => {
                            attention.wake(Instant::now().as_millis());
                            if alert_active() {
                                render_message_frame(
                                    &mut next,
                                    &ui_status(&name),
                                    "Locate alert",
                                    "Press to stop",
                                );
                                push!();
                                redraw = false;
                            }
                        }
                        // A battery sample and a minute boundary are the
                        // two things here nobody asked for, so they
                        // redraw without counting as attention — waking
                        // on either would reset the lapse timer forever.
                        // The panel is bistable and already showing the
                        // old reading, so the redraw is a partial refresh
                        // of the indicator or the clock and little else.
                        Either4::Fourth(_) => {}
                    }
                }
                Either4::Third(()) => {
                    render_message_frame(&mut next, &ui_status(&name), "Sleeping", "Good night");
                    push!();
                    display::sleep(&mut spi, &mut cs, &mut dc).await;
                    DISPLAY_SHUTDOWN_DONE.signal(());
                    core::future::pending::<()>().await;
                }
                Either4::Fourth(()) => {
                    redraw = matches!(
                        attention.poll(Instant::now().as_millis()),
                        Some(Transition::Lapsed)
                    ) && !model.is_home();
                    if redraw {
                        model.go_home();
                    }
                }
            }

            if redraw {
                render_ui_frame(&mut next, &model, &ui_status(&name));
                push!();
            }
        }
    }

    /// Resolves the board's nav button (active-low, pull-up) into the
    /// display-tracker vocabulary: single advances, double selects, a
    /// 1–4 second hold released by the user goes back, and a continuing
    /// four-second hold always powers off.
    ///
    /// What a gesture means is decided by [`Gate`] at the press that
    /// starts it, not at the event that ends it, so a chord begun while
    /// something else owned the button is judged as a whole.
    #[cfg(feature = "button-nav")]
    #[embassy_executor::task]
    async fn button_task(mut button: Input<'static>) {
        const DEBOUNCE: Duration = Duration::from_millis(10);
        let mut fsm = ButtonFsm::new(umsh_ux_display_tracker::button_timings());
        let mut gate = Gate::new();
        let mut pressed = button.is_low();
        loop {
            let event = {
                let now_ms = Instant::now().as_millis();
                let edge_fut = async {
                    if pressed {
                        button.wait_for_high().await;
                        Timer::after(DEBOUNCE).await;
                        ButtonEdge::Release
                    } else {
                        button.wait_for_low().await;
                        Timer::after(DEBOUNCE).await;
                        ButtonEdge::Press
                    }
                };
                let deadline = fsm.next_deadline().unwrap_or(now_ms.saturating_add(60_000));
                match select(edge_fut, Timer::at(Instant::from_millis(deadline))).await {
                    Either::First(edge) => {
                        pressed = matches!(edge, ButtonEdge::Press);
                        if pressed {
                            // Read on the press edge, not at the last loop
                            // iteration: this task can park for a minute
                            // awaiting an edge, and both an alert starting
                            // and the panel lapsing dark happen during
                            // exactly such a park.
                            gate.set(GateReason::AlertActive, alert_active());
                            #[cfg(feature = "display-oled")]
                            gate.set(GateReason::ScreenOff, SCREEN_OFF.load(Ordering::Acquire));
                            gate.on_press();
                            // Wake on the press, not on the resolved
                            // gesture, so the panel is already lit while
                            // the user is still deciding what the press
                            // will become.
                            #[cfg(feature = "display-oled")]
                            UI_WAKE.signal(());
                        }
                        fsm.on_edge(edge, Instant::now().as_millis())
                    }
                    Either::Second(()) => fsm.poll(Instant::now().as_millis()),
                }
            };

            if let Some(event) = event {
                match gate.disposition(event) {
                    // Whoever found the radio meant to silence it, not to
                    // navigate its menus.
                    Disposition::CancelAlert => INPUT_CH.send(InEvent::CancelAlert).await,
                    Disposition::ConsumedByWake | Disposition::Discard => {}
                    Disposition::Deliver => {
                        let input = match event {
                            ButtonEvent::Single => Some(UiInput::Forward),
                            ButtonEvent::Double => Some(UiInput::Select),
                            ButtonEvent::Long => Some(UiInput::Backward),
                            ButtonEvent::VeryLong => {
                                pressed = false;
                                fsm = ButtonFsm::new(umsh_ux_display_tracker::button_timings());
                                SHUTDOWN_SIGNAL.signal(());
                                None
                            }
                            ButtonEvent::Triple | ButtonEvent::Quad => None,
                        };
                        if let Some(input) = input {
                            UI_INPUT_CH.send(input).await;
                        }
                    }
                }
            }

            gate.settle(fsm.next_deadline().is_none());
        }
    }

    /// The capacitive touch button remains dedicated to the unusual e-paper
    /// backlight. T-Echo defines P0.11 as active-low with a pull-up: illuminate
    /// on a debounced low level and turn it off on the corresponding release.
    ///
    /// Deliberately outside the attention and gate models: this is a
    /// plain momentary light for reading a bistable panel in the dark,
    /// not a navigation control, so holding it neither counts as
    /// activity nor consumes a gesture.
    #[cfg(feature = "display-epd")]
    #[embassy_executor::task]
    async fn touch_task(mut touch: Input<'static>) {
        const DEBOUNCE: Duration = Duration::from_millis(20);
        loop {
            touch.wait_for_low().await;
            Timer::after(DEBOUNCE).await;
            if !touch.is_low() {
                continue;
            }
            BACKLIGHT_TOUCH.store(true, Ordering::Release);
            BACKLIGHT_CHANGED.signal(());
            debug_log(format_args!("backlight touch=true"));
            touch.wait_for_high().await;
            Timer::after(DEBOUNCE).await;
            BACKLIGHT_TOUCH.store(false, Ordering::Release);
            BACKLIGHT_CHANGED.signal(());
            debug_log(format_args!("backlight touch=false"));
        }
    }

    /// Arbitrates the one bright output this board has.
    ///
    /// A locate alert outranks the touch button: the backlight is by far
    /// the most conspicuous thing on a T-Echo, and being conspicuous is
    /// the entire point of an alert. The indicator LED keeps its own
    /// alert blink — this adds a channel rather than moving one — and
    /// the touch button behaves exactly as before whenever no alert is
    /// running.
    ///
    /// The alert pattern is a double flash per second, which no other
    /// use of this pin resembles.
    #[cfg(feature = "display-epd")]
    #[embassy_executor::task]
    async fn backlight_task(mut backlight: Output<'static>) {
        const PERIOD_MS: u64 = 1_000;
        const STEP: Duration = Duration::from_millis(25);
        loop {
            if alert_active() {
                let phase = Instant::now().as_millis() % PERIOD_MS;
                backlight.set_level(if phase < 100 || (200..300).contains(&phase) {
                    Level::High
                } else {
                    Level::Low
                });
                // Poll rather than sleep to the next edge: the alert can
                // end at any moment and the pin must not be left lit.
                let _ = select(Timer::after(STEP), BACKLIGHT_CHANGED.wait()).await;
            } else {
                backlight.set_level(if BACKLIGHT_TOUCH.load(Ordering::Acquire) {
                    Level::High
                } else {
                    Level::Low
                });
                BACKLIGHT_CHANGED.wait().await;
            }
        }
    }

    #[cfg(feature = "display-oled")]
    fn render_oled_frame(
        fb: &mut display::Sh1106Fb,
        model: &UiModel,
        status: &screen::StatusModel<'_>,
    ) {
        screen::render_frame(fb, &screen::Layout::OLED_128X64, model, status);
    }

    #[cfg(feature = "display-oled")]
    fn render_oled_message(
        fb: &mut display::Sh1106Fb,
        status: &screen::StatusModel<'_>,
        title: &str,
        detail: &str,
    ) {
        screen::render_message(fb, &screen::Layout::OLED_128X64, status, title, detail);
    }

    /// Owns the SH1106 panel and the display attention policy.
    ///
    /// The panel is emissive, so attention lapsing actually turns it off:
    /// dimmed as a warning at 7 s, dark at 10 s. It stays lit for as long
    /// as a pairing window is open, because its PIN is the only place
    /// that number is shown, and for as long as a locate alert runs.
    #[cfg(feature = "display-oled")]
    #[embassy_executor::task]
    async fn oled_display_task(mut oled: display::Sh1106<'static>) {
        let mut model = UiModel::new(board_menu_items());
        let mut attention = Attention::new(
            DisplayKind::Emissive,
            AttentionConfig::EMISSIVE,
            Instant::now().as_millis(),
        );
        let mut fb = display::Sh1106Fb::new();
        oled.init().await;
        {
            let name = device_name_snapshot().await;
            render_oled_frame(&mut fb, &model, &ui_status(&name));
        }
        oled.flush(&fb).await;

        loop {
            // The name changes rarely but every frame this pass might draw
            // needs it, so it is snapshotted once and lent out; the rest of
            // the status is rebuilt at each draw.
            let name = device_name_snapshot().await;

            // Both holds are edge-published by other tasks, but re-deriving
            // them here each pass is idempotent and cannot miss an edge.
            let now = Instant::now().as_millis();
            attention.set_hold(
                HoldReason::Pairing,
                PAIRING_MODE.load(Ordering::Acquire),
                now,
            );
            attention.set_hold(HoldReason::Alert, alert_active(), now);
            SCREEN_OFF.store(attention.is_lapsed(), Ordering::Release);

            let lapse = async {
                match attention.next_deadline() {
                    Some(deadline) => Timer::at(Instant::from_millis(deadline)).await,
                    None => core::future::pending().await,
                }
            };

            let mut redraw = false;
            let mut alert_frame = false;
            let mut transition = None;
            match select4(
                UI_INPUT_CH.receive(),
                select4(
                    // All three are "content moved, redraw if the panel
                    // is already lit"; they differ only in what they do
                    // to the model, so they share an arm.
                    select3(
                        UI_REFRESH.wait(),
                        battery_ui_changed(),
                        clock_tick(attention.accepts_redraw()),
                    ),
                    UI_NOTICE.wait(),
                    UI_WAKE.wait(),
                    UI_ALERT_CHANGED.wait(),
                ),
                DISPLAY_SHUTDOWN.wait(),
                lapse,
            )
            .await
            {
                Either4::First(input) => {
                    debug_log(format_args!("ui input={input:?}"));
                    transition = attention.wake(Instant::now().as_millis());
                    redraw = true;
                    match model.apply(input) {
                        Some(UiEffect::CheckIn) => {
                            super::device_node::request_beacon(
                                super::device_node::BeaconTrigger::Button,
                            );
                            model.set_notice(UiNotice::CheckInRequested);
                        }
                        Some(UiEffect::StartPairing) => PAIRING_MODE_REQUEST.signal(()),
                        Some(UiEffect::ClearBonds) => BLE_WIPE_REQUEST.signal(()),
                        None => {}
                    }
                }
                Either4::Second(event) => match event {
                    // Content the user did not ask for: redraw if the
                    // panel is already lit, but never light it. That rule
                    // is what keeps a battery sample from waking a tracker
                    // in a drawer every few minutes.
                    Either4::First(Either3::First(())) => {
                        model.clear_notice();
                        redraw = true;
                    }
                    // A battery sample and a minute boundary both move
                    // content without touching the model.
                    Either4::First(Either3::Second(()) | Either3::Third(())) => redraw = true,
                    Either4::Second(notice) => {
                        model.set_notice(notice);
                        transition = attention.wake(Instant::now().as_millis());
                        redraw = true;
                    }
                    // A wake on its own changes no content — a lit panel
                    // is already showing the truth, and the events that do
                    // change something raise `UI_REFRESH` alongside this.
                    Either4::Third(()) => {
                        transition = attention.wake(Instant::now().as_millis());
                        redraw = transition.is_some();
                    }
                    // An alert takes the whole panel: being conspicuous is
                    // the point, and the hold above keeps it lit until the
                    // alert ends.
                    Either4::Fourth(()) => {
                        transition = attention.wake(Instant::now().as_millis());
                        redraw = true;
                        alert_frame = alert_active();
                    }
                },
                Either4::Third(()) => {
                    render_oled_message(
                        &mut fb,
                        &ui_status(&name),
                        "Powering off",
                        "press to wake",
                    );
                    oled.flush(&fb).await;
                    oled.set_contrast(display::CONTRAST_NORMAL).await;
                    oled.set_display_on(true).await;
                    Timer::after(Duration::from_millis(1_200)).await;
                    oled.set_display_on(false).await;
                    DISPLAY_SHUTDOWN_DONE.signal(());
                    core::future::pending::<()>().await;
                }
                Either4::Fourth(()) => transition = attention.poll(Instant::now().as_millis()),
            }

            match transition {
                Some(Transition::Lapsed) => {
                    // Waking always lands on the status page rather than
                    // on whatever was abandoned here.
                    model.go_home();
                    oled.set_display_on(false).await;
                    redraw = false;
                }
                Some(Transition::Dimmed) => {
                    oled.set_contrast(display::CONTRAST_DIM).await;
                    redraw = false;
                }
                Some(Transition::Woke) | None => {}
            }

            if redraw && attention.accepts_redraw() {
                let status = ui_status(&name);
                if alert_frame {
                    render_oled_message(&mut fb, &status, "Locate alert", "Press to stop");
                } else {
                    render_oled_frame(&mut fb, &model, &status);
                }
                oled.flush(&fb).await;
            }
            // Ordered after the redraw so the panel never lights on a
            // stale frame.
            if matches!(transition, Some(Transition::Woke)) {
                oled.set_contrast(display::CONTRAST_NORMAL).await;
                oled.set_display_on(true).await;
            }
        }
    }

    /// Wio Tracker L1 piezo driver. Kept as a task shim so the BSP's
    /// generic async runner is monomorphized in this binary.
    #[cfg(feature = "cap-buzzer")]
    #[embassy_executor::task]
    async fn wio_buzzer_task(pwm: SimplePwm<'static>) {
        umsh_bsp_wio_tracker_l1::buzzer::run(pwm).await;
    }

    /// T-1000E piezo driver. Kept as a task shim so the BSP's generic async
    /// runner is monomorphized in this binary.
    #[cfg(feature = "t1000e")]
    #[embassy_executor::task]
    async fn t1000e_buzzer_task(
        pwm: SimplePwm<'static>,
        enable: Output<'static>,
        initially_silenced: bool,
    ) {
        umsh_bsp_t1000e::buzzer::run(pwm, enable, initially_silenced).await;
    }

    /// Apply the T-1000E device profile: the unsupported single and quadruple
    /// slots remain inert, double-click toggles persisted Silence State,
    /// triple-click is reserved for unsupported GPS control, and the
    /// three-second long press enters persisted Sleep State. A startup-held press has already
    /// been consumed by the force-pairing ceremony, so it is ignored through
    /// its release instead of becoming an immediate shutdown.
    #[cfg(feature = "t1000e")]
    #[embassy_executor::task]
    async fn t1000e_button_task(
        mut button: Input<'static>,
        held_at_boot: bool,
        mut ux_store: ProtoStore,
    ) {
        const DEBOUNCE: Duration = Duration::from_millis(10);

        if held_at_boot {
            button.wait_for_low().await;
            Timer::after(DEBOUNCE).await;
        }

        let mut fsm = ButtonFsm::new(ButtonTimings::default());
        let mut pressed = false;
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
                let deadline = fsm.next_deadline().unwrap_or(now_ms.saturating_add(60_000));
                match select(edge_fut, Timer::at(Instant::from_millis(deadline))).await {
                    Either::First(edge) => {
                        pressed = matches!(edge, ButtonEdge::Press);
                        // A press means eyes on the LED and, likely, an
                        // environment that just changed — a device pulled
                        // from a pocket should not confirm at last
                        // minute's brightness. Re-evaluate ambient light
                        // now: the ~80 ms measurement completes well
                        // inside click recognition, so whatever
                        // confirmation follows renders at the fresh
                        // level, and at press-down the LED is almost
                        // certainly in a dark phase, so the sampler's
                        // blanking is invisible. User-initiated, so it
                        // deliberately bypasses the battery cadence.
                        if pressed {
                            umsh_bsp_t1000e::light::request_sample();
                        }
                        fsm.on_edge(edge, Instant::now().as_millis())
                    }
                    Either::Second(()) => fsm.poll(Instant::now().as_millis()),
                }
            };

            // Whoever found the beeping radio gets to silence it with
            // whatever they press first, and that press does nothing
            // else — fumbling for an alarm must not fire off a beacon or
            // flip the silence preference. The long press is the
            // exception the spec allows: powering the radio off is
            // deliberate enough to mean it, and it ends the alert anyway.
            if event.is_some() && alert_active() && !matches!(event, Some(ButtonEvent::Long)) {
                INPUT_CH.send(InEvent::CancelAlert).await;
                continue;
            }

            match event {
                Some(ButtonEvent::Single) => {
                    // Primary action: beacon from the device identity. The
                    // node task emits the confirmation (LED + melody) only
                    // when the MAC accepts the send; with no identity the
                    // node is dormant and the slot stays inert, with no
                    // false confirmation.
                    super::device_node::request_beacon(super::device_node::BeaconTrigger::Button);
                }
                Some(ButtonEvent::Double) => {
                    let preferences = umsh_bsp_t1000e::preferences::toggle_silent();
                    umsh_bsp_t1000e::BUZZER_SILENCE_SET.signal(preferences.silent);
                    umsh_bsp_t1000e::indicator::LED_SEQUENCE_SIGNAL
                        .signal(LedSequence::ActionConfirm);
                    let _ = persist_ux_preferences(&mut ux_store, preferences).await;
                }
                Some(ButtonEvent::Triple) => {
                    // The receiver switch, which the UX profile reserves
                    // this slot for. Routed through the ULCP session rather
                    // than straight at the pins, so the property, an
                    // attached host and the saved snapshot all see the same
                    // flip — poking the driver here would be undone by the
                    // next device-domain sync. A build with no receiver
                    // leaves the slot inert, confirmation included.
                    //
                    // Nothing is indicated here: the press does not know
                    // which way the switch went, and the session answers
                    // that through `gnss_switched`.
                    #[cfg(feature = "cap-gnss")]
                    INPUT_CH.send(InEvent::ToggleGnss).await;
                }
                Some(ButtonEvent::Long) => {
                    pressed = false;
                    fsm = ButtonFsm::new(ButtonTimings::default());
                    let preferences = umsh_bsp_t1000e::preferences::set_asleep(true);
                    let _ = persist_ux_preferences(&mut ux_store, preferences).await;
                    umsh_bsp_t1000e::SHUTDOWN_SIGNAL.signal(());
                }
                Some(ButtonEvent::Quad | ButtonEvent::VeryLong) | None => {}
            }
        }
    }

    #[cfg(feature = "t1000e")]
    #[embassy_executor::task]
    async fn t1000e_shutdown_task() -> ! {
        umsh_bsp_t1000e::shutdown::run().await
    }

    #[cfg(feature = "t1000e")]
    #[embassy_executor::task]
    async fn t1000e_power_task(
        saadc: Peri<'static, peripherals::SAADC>,
        battery_pin: Peri<'static, peripherals::P0_02>,
        light_pin: Peri<'static, peripherals::P0_29>,
        sensor_rail: Output<'static>,
        sensor_enable: Output<'static>,
        external_power: Input<'static>,
        charge_active: Input<'static>,
    ) {
        // The BSP builds a single-channel converter per measurement — the
        // battery's and the light sensor's configurations have nothing in
        // common — so it takes the peripheral and `Irqs` rather than a
        // built `Saadc`. This shim is where `Irqs` is named concretely.
        umsh_bsp_t1000e::power::run_battery_monitor(
            saadc,
            Irqs,
            battery_pin,
            light_pin,
            sensor_rail,
            sensor_enable,
            external_power,
            charge_active,
        )
        .await;
    }

    /// SenseCAP Solar battery monitor task: SAADC + active-low divider gate.
    /// No charge-detect / external-power GPIO (see BSP `power` module).
    #[cfg(feature = "board-sensecap-solar")]
    #[embassy_executor::task]
    async fn sensecap_power_task(saadc: Saadc<'static, 1>, divider_gate: Output<'static>) {
        umsh_bsp_sensecap_solar::power::run_battery_monitor(saadc, divider_gate).await;
    }

    /// XIAO nRF52840 kit battery monitor task: SAADC plus three held
    /// pins. The divider is **ungated** — P0.14 is its low side and is
    /// driven LOW for the life of the program, because both alternatives
    /// exceed P0.31's absolute maximum (see the BSP `power` module). The
    /// BQ25100 does report its own state, so unlike the other boards here
    /// this one distinguishes charging from charge-complete.
    #[cfg(feature = "board-xiao-nrf52")]
    #[embassy_executor::task]
    async fn xiao_power_task(
        saadc: Saadc<'static, 1>,
        divider_low: Output<'static>,
        charge_status_n: Input<'static>,
        charge_current_hi: Output<'static>,
    ) {
        umsh_bsp_xiao_nrf52::power::run_battery_monitor(
            saadc,
            divider_low,
            charge_status_n,
            charge_current_hi,
        )
        .await;
    }

    /// Headless System OFF for the XIAO nRF52840 kit. The sole producer
    /// is the BSP's protective low-battery cutoff: this board has no
    /// button to hold, and there is no remote power-off command in this
    /// firmware. Nothing is armed as a wake source either — there is
    /// nothing on the board to arm. See the BSP `shutdown` module.
    #[cfg(feature = "board-xiao-nrf52")]
    #[embassy_executor::task]
    async fn xiao_shutdown_task() -> ! {
        umsh_bsp_xiao_nrf52::shutdown::run().await
    }

    /// T-Echo battery monitor task: SAADC only. The divider is hard-wired
    /// (no gate) and the charger exposes no status pin, so external power
    /// comes from usbregstatus (see BSP `power` module).
    #[cfg(feature = "board-techo")]
    #[embassy_executor::task]
    async fn techo_power_task(saadc: Saadc<'static, 1>) {
        umsh_bsp_techo::power::run_battery_monitor(saadc).await;
    }

    /// Wio Tracker L1 battery monitor task: SAADC + **active-high**
    /// divider gate (P0.04 / `BAT_READ`). The charger exposes no status
    /// pin, so external power comes from usbregstatus (see BSP `power`
    /// module).
    #[cfg(feature = "board-wio-tracker-l1")]
    #[embassy_executor::task]
    async fn wio_power_task(saadc: Saadc<'static, 1>, divider_gate: Output<'static>) {
        umsh_bsp_wio_tracker_l1::power::run_battery_monitor(saadc, divider_gate).await;
    }

    /// Controlled power-off for the Wio Tracker L1: blank the OLED, hold
    /// the radio in reset, tri-state the peripheral signal pins, and
    /// enter System OFF with the nav button armed as the wake source.
    ///
    /// This board has a mechanical power switch, so System OFF is a
    /// convenience rather than the only way to stop the drain — but it is
    /// still what keeps the protective low-battery cutoff from letting an
    /// unattended pack deep-discharge with the switch left on.
    ///
    /// Unlike the T-Echo there is no board-wide peripheral rail to drop;
    /// the hardware reconstruction found no equivalent of that board's
    /// P0.12. So, like the SenseCAP Solar (the other rail-less SX1262
    /// board), the radio is parked by holding RST low — driven outputs
    /// keep their level through System OFF — and everything else is
    /// tri-stated.
    #[cfg(feature = "system-off-wio")]
    #[embassy_executor::task]
    async fn wio_shutdown_task() -> ! {
        // Two producers: the nav button's four-second hold (the local
        // signal) and the battery monitor's protective low-voltage cutoff
        // (the BSP's). Either one runs the same teardown.
        let _ = select(
            SHUTDOWN_SIGNAL.wait(),
            umsh_bsp_wio_tracker_l1::power::SHUTDOWN_SIGNAL.wait(),
        )
        .await;

        DISPLAY_SHUTDOWN.signal(());
        let _ = select(
            DISPLAY_SHUTDOWN_DONE.wait(),
            Timer::after(Duration::from_secs(5)),
        )
        .await;

        // The usual trigger is the nav button's four-second hold, which
        // means the button is often still down right now — and it is also
        // the wake pin. Arming DETECT-low while it is held would wake the
        // chip the instant it powers off, so wait for the release first
        // (plus a debounce margin), the same dance the SenseCAP Solar
        // does with its power button.
        connect_input(Port::P0, 8, WakePull::Up);
        while !read_pin(Port::P0, 8) {
            Timer::after(Duration::from_millis(50)).await;
        }
        Timer::after(Duration::from_millis(50)).await;

        // No switchable rail, so the SX1262 would otherwise keep whatever
        // mode it was in — typically continuous RX at milliamps — under a
        // System OFF that draws microamps. Holding RST (active-low) low
        // collapses it to its reset-state minimum.
        drive_pin_low(Port::P1, 7);
        // Battery divider gate is active-high: drive it LOW (disconnected)
        // rather than tri-stating, so the FET gate is pinned instead of
        // floating and the divider's quiescent draw is provably gone.
        drive_pin_low(Port::P0, 4);
        // The L76K GNSS shares the always-on rail, so System OFF does not
        // reach it: its standby line (active-high wake) is the only thing
        // that decides whether the board's floor is microamps or the tens
        // of milliamps an acquiring receiver draws. The BSP has driven it
        // since boot and the pump leaves it wherever `PROP_GNSS_ENABLED`
        // last put it, so this is only the belt to that suspenders — but
        // it has to happen here, while the module can still act on it.
        //
        // Deliberately *not* a full teardown: the module keeps its power
        // and its backup domain through System OFF, which is where this
        // board's clock comes from on the next boot. Asking it to sleep is
        // the whole intent; taking anything else away would cost the time.
        drive_pin_low(Port::P1, 9);
        // Three more control lines that drive real loads. Same argument as
        // the divider gate above: a tri-stated gate is not a gate that is
        // provably off, and driven levels are retained through System OFF.
        drive_pin_low(Port::P1, 8); // RXEN, active-high → LNA unbiased
        drive_pin_low(Port::P1, 1); // user LED, active-high
        drive_pin_low(Port::P1, 0); // piezo

        // OLED I²C (TWIM0):      SDA=P0.06, SCL=P0.05
        // Radio SPI (TWISPI1):   SCK=P0.30, MISO=P0.03, MOSI=P0.28
        // Radio control:         CS=P1.14, BUSY=P1.10, DIO1=P0.07
        //                        (RST, RXEN, LED, and piezo pinned above)
        // The display, radio, and battery tasks still own these pins;
        // direct PIN_CNF writes are deliberate here because every task is
        // about to lose its clock.
        for (port, pin) in [
            (Port::P0, 6u8),
            (Port::P0, 5u8),
            (Port::P0, 30u8),
            (Port::P0, 3u8),
            (Port::P0, 28u8),
            (Port::P1, 14u8),
            (Port::P1, 10u8),
            (Port::P0, 7u8), // radio DIO1 ← has SENSE set by async radio wait
        ] {
            tristate_pin(port, pin);
        }

        // P0.08 is the nav button. Active-low, pull-up → DETECT-low wakes.
        power_off(&[WakePin {
            port: Port::P0,
            pin: 8,
            sense: WakeSense::Low,
        }])
    }

    /// Dedicated power-button (P1.01, active-low) state machine for the
    /// Solar P1. This board has a button reserved for power, so — unlike the
    /// single-button boards that overload one button into a gesture FSM — it
    /// drives *nothing but power*: a hold past `HOLD_OFF` acknowledges on
    /// LED_A and requests System OFF, and a short press does nothing at all.
    /// Everything a user might otherwise want from a press is on USR; see
    /// [`sensecap_usr_button_task`]. Powering back on happens by pressing USR
    /// while in System OFF — a PWR press there reaches the bootloader instead.
    #[cfg(feature = "power-button")]
    #[embassy_executor::task]
    async fn sensecap_pwr_button_task(mut button: Input<'static>) {
        const HOLD_OFF: Duration = Duration::from_millis(1500);
        const DEBOUNCE: Duration = Duration::from_millis(20);

        // If PWR is still held when we boot, ignore it through release so the
        // press that started us is not misread as an immediate power-off hold.
        // (The force-pairing ceremony is on USR/P1.07, not this button, so it
        // never reaches here.)
        if button.is_low() {
            button.wait_for_high().await;
            Timer::after(DEBOUNCE).await;
        }

        loop {
            button.wait_for_low().await;
            Timer::after(DEBOUNCE).await;
            if button.is_high() {
                continue; // bounce
            }
            // Power off only if held past HOLD_OFF; release before that is a
            // short press, which this button deliberately ignores.
            match select(button.wait_for_high(), Timer::after(HOLD_OFF)).await {
                Either::First(()) => {}
                Either::Second(()) => {
                    // Hold accepted: acknowledge on LED_A and wait for the
                    // blinks to finish before tearing the board down, or the
                    // teardown would cut the acknowledgement it just asked
                    // for. Bounded, so a wedged indicator cannot block
                    // powering off.
                    ATTENTION_LED.signal(LedSequence::PowerOff);
                    let _ = select(
                        ATTENTION_LED_DONE.wait(),
                        Timer::after(Duration::from_millis(1500)),
                    )
                    .await;
                    umsh_bsp_sensecap_solar::power::SHUTDOWN_SIGNAL.signal(());
                    // The shutdown task waits for PWR release before arming
                    // wake; park here until it powers us off.
                    button.wait_for_high().await;
                }
            }
        }
    }

    /// The user button (USR / P1.07, active-low) on the Solar P1.
    ///
    /// This is the board's whole interactive surface while running — PWR
    /// does power and nothing else — so it carries the primary-action slot
    /// the UX profile describes: a press asks the device node to beacon,
    /// putting a signed identity (with its position, when the identity
    /// auto-update is on) on the air.
    ///
    /// Except while the locate alert is running, when the first press
    /// silences it and does nothing else. Whoever found the blinking radio
    /// gets to stop it with whatever they press; fumbling for it must not
    /// also fire off a beacon.
    ///
    /// No confirmation is emitted here. The node answers an accepted send
    /// through `NodeHooks::beacon_confirm`, so a board with no identity —
    /// where the node is dormant and the slot is genuinely inert — stays
    /// silent rather than acknowledging something that did not happen.
    #[cfg(feature = "power-button")]
    #[embassy_executor::task]
    async fn sensecap_usr_button_task(mut button: Input<'static>) {
        const DEBOUNCE: Duration = Duration::from_millis(20);

        // The press that woke the board from System OFF, or the one that
        // ran the force-pairing ceremony, is still down. Neither is a
        // beacon request.
        if button.is_low() {
            button.wait_for_high().await;
            Timer::after(DEBOUNCE).await;
        }

        loop {
            button.wait_for_low().await;
            Timer::after(DEBOUNCE).await;
            if button.is_high() {
                continue; // bounce
            }
            if alert_active() {
                INPUT_CH.send(InEvent::CancelAlert).await;
            } else {
                super::device_node::request_beacon(super::device_node::BeaconTrigger::Button);
            }
            // One action per press, however long it is held.
            button.wait_for_high().await;
            Timer::after(DEBOUNCE).await;
        }
    }

    /// One-shot sequences for LED_A, the Solar P1's attention indicator.
    #[cfg(feature = "power-button")]
    static ATTENTION_LED: Signal<ThreadModeRawMutex, LedSequence> = Signal::new();

    /// Fires when a requested sequence has finished playing, so a caller
    /// that is about to take the board down can let it finish.
    #[cfg(feature = "power-button")]
    static ATTENTION_LED_DONE: Signal<ThreadModeRawMutex, ()> = Signal::new();

    /// Confirm an accepted local action on LED_A. Reachable as a plain
    /// `fn()` because that is the shape `NodeHooks` takes.
    #[cfg(feature = "power-button")]
    pub fn confirm_attention_action() {
        ATTENTION_LED.signal(LedSequence::ActionConfirm);
    }

    /// Drives LED_A (P0.15, white, active-high) on the Solar P1.
    ///
    /// The board has two LEDs and gives them separate jobs. LED_B (blue) is
    /// the status light: heartbeat, BLE pairing blink — the "this thing is
    /// alive, here is its link state" story, which is worth glancing at and
    /// not worth looking up for. LED_A is the one meant to catch an eye
    /// across a field: the locate alert, and the short confirmations that
    /// answer a button press.
    ///
    /// It idles dark. A second heartbeat would only compete with the first.
    #[cfg(feature = "power-button")]
    #[embassy_executor::task]
    async fn sensecap_attention_led_task(mut led: Output<'static>) -> ! {
        let mut engine = LedEngine::attention_only(Instant::now().as_millis());
        loop {
            // On a board with no buzzer the blink is the entire alert, and
            // it outranks the confirmations inside the engine.
            if alert_active() {
                engine.start_alert(Instant::now().as_millis());
            } else {
                engine.stop_alert();
            }

            let decision = engine.tick(Instant::now().as_millis());
            if decision.on {
                led.set_high();
            } else {
                led.set_low();
            }
            // Nothing pending and nothing to show: report the sequence
            // finished, for whoever is waiting on it before powering off.
            if !decision.on && !engine.alert_active() {
                ATTENTION_LED_DONE.signal(());
            }

            match select3(
                Timer::at(Instant::from_millis(decision.next_deadline_ms)),
                ALERT_CHANGED.wait(),
                ATTENTION_LED.wait(),
            )
            .await
            {
                Either3::Third(sequence) => {
                    ATTENTION_LED_DONE.reset();
                    engine.play(sequence, Instant::now().as_millis());
                }
                Either3::First(()) | Either3::Second(()) => {}
            }
        }
    }

    #[cfg(feature = "power-button")]
    #[embassy_executor::task]
    async fn sensecap_shutdown_task() -> ! {
        umsh_bsp_sensecap_solar::shutdown::run().await
    }

    /// Controlled power-off: put the e-paper controller to sleep, tri-state
    /// peripheral signal pins, drop the rail, and enter System OFF.
    #[cfg(feature = "system-off-techo")]
    #[embassy_executor::task]
    async fn shutdown_task(peripheral_power: Output<'static>, power_enable: Output<'static>) -> ! {
        // Two producers on the T-Echo: the button's four-second hold (the
        // local signal) and the battery monitor's protective low-voltage
        // cutoff (the BSP's). Either one runs the same teardown.
        #[cfg(feature = "board-techo")]
        let _ = select(
            SHUTDOWN_SIGNAL.wait(),
            umsh_bsp_techo::power::SHUTDOWN_SIGNAL.wait(),
        )
        .await;
        #[cfg(not(feature = "board-techo"))]
        SHUTDOWN_SIGNAL.wait().await;

        DISPLAY_SHUTDOWN.signal(());
        let _ = select(
            DISPLAY_SHUTDOWN_DONE.wait(),
            Timer::after(Duration::from_secs(5)),
        )
        .await;

        // The usual trigger is the side button's four-second hold, which
        // means the button is often still down right now — and it is also
        // the wake pin. Arming DETECT-low while it is held would wake the
        // chip the instant it powers off, so wait for the release first
        // (plus a debounce margin), the same dance the SenseCAP Solar
        // does with its power button.
        connect_input(Port::P1, 10, WakePull::Up);
        while !read_pin(Port::P1, 10) {
            Timer::after(Duration::from_millis(50)).await;
        }
        Timer::after(Duration::from_millis(50)).await;

        // Nothing below this point awaits, so the heartbeat task cannot run
        // again and take the status LED back.
        //
        // The LED and the e-paper backlight are the two pins still driving a
        // load, and driven levels are retained through System OFF. Both are
        // pinned to their off state rather than tri-stated: their loads hang
        // off the always-on rail, where a floating pin is not provably dark.
        // The remaining RGB channel (P0.15) is never configured by this
        // firmware, so it sits at reset — a disconnected input that cannot
        // sink the LED. (P0.13, which the Meshtastic/MeshCore variant files
        // call the red channel, is PWR_EN per the schematic and is handled
        // with the rail below.)
        drive_pin_high(Port::P0, 14); // status LED, active-low → high is off
        drive_pin_low(Port::P1, 11); // e-paper backlight, active-high

        // The L76K GNSS. Dropping the rail below unpowers it on battery, but
        // not on USB: VBUS keeps VDD_POWR alive through a path PWR_EN does
        // not gate (hw-observed 2026-08-06), so this state must be correct
        // for a module that stays powered indefinitely, not just for one
        // about to lose its rail.
        //
        // Standby/WAKEUP (P1.02) is internally pulled up — floating means
        // awake — so it is driven low: a valid logic low into a powered
        // module (Standby, its proper low-power state) and no current into
        // an unpowered one. Reset (P1.05) is tri-stated, NOT driven: the
        // L76K hardware design has RESET_N internally pulled up ("leave
        // N/C if unused"), so released it idles high on a powered module —
        // holding it low instead pinned the powered module in reset, its
        // *worst* state, with the PPS pull-up faintly lighting the internal
        // blue LED as the tell. The UART line into the module (P1.08) is
        // driven low: low is a legal idle-adjacent level either way,
        // whereas its usual high idle would back-power a dead module.
        // P1.09 carries the module's output and is never driven by this
        // chip, so it is only released.
        drive_pin_low(Port::P1, 2);
        tristate_pin(Port::P1, 5);
        drive_pin_low(Port::P1, 8);
        tristate_pin(Port::P1, 9);

        // E-paper SPI bus (SPIM2): SCK=P0.31, MISO=P1.07, MOSI=P0.29
        // E-paper control:         CS=P0.30, DC=P0.28, RST=P0.02, BUSY=P0.03
        // Radio SPI bus (TWISPI1): SCK=P0.19, MOSI=P0.22, MISO=P0.23
        // Radio control:           CS=P0.24, RST=P0.25, BUSY=P0.17, DIO1=P0.20
        // The display and touch tasks still own these pins; direct PIN_CNF
        // writes are deliberate here because every task is about to lose power.
        for (port, pin) in [
            (Port::P0, 31u8),
            (Port::P1, 7u8),
            (Port::P0, 29u8),
            (Port::P0, 30u8),
            (Port::P0, 28u8),
            (Port::P0, 2u8),
            (Port::P0, 3u8),
            (Port::P0, 11u8), // touch input ← async wait may have set SENSE
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

        // The rail is switched by two pins, not one: per the schematic,
        // SX1262 = PWR_EN (P0.13), VDD_POWR = PWR_EN ∧ (PWR_ON (P0.12)
        // ∨ VBUS). PWR_EN is the master gate — and because VBUS stands in
        // for PWR_ON, it is the only input that keeps "off" off while the
        // board is on USB. (The Meshtastic/MeshCore variant files call
        // P0.13 the red LED channel; the schematic disagrees, and it was
        // the schematic that explained the off-state symptom: with PWR_EN
        // left floating, the rail only half-collapsed, and the L76K sat
        // browned-up with its PPS pull-up faintly lighting the internal
        // blue LED.)
        //
        // Dropping the `Output`s only hands the pins back to embassy,
        // which writes PIN_CNF = INPUT:Disconnect with no pull — floating,
        // the same trap. Pin both low so the LoRa module, GNSS, sensors,
        // and e-paper bias generator are provably unpowered rather than
        // left to a floating gate.
        drop(peripheral_power);
        drop(power_enable);
        drive_pin_low(Port::P0, 12);
        drive_pin_low(Port::P0, 13);

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
        // Temporary freeze diagnostics: recover the previous boot's last
        // breadcrumb stage, then mark progress through boot. Stage map:
        //  1 main entered            8 USB built, core tasks spawned
        //  2 embassy init done       9 chirp signaled / pre-join
        //  3 WDT armed              10 ble_app entered
        //  4 radio ready            11 trouble stack + GATT server built
        //  5 MPSL ready             12 advertising loop reached
        //  6 bond store ready       13 usb.run() first polled
        //  7 SDC built
        // Point the shared runtime's log seam at this board's debug
        // channel, before anything shared runs. `debug_log` itself
        // buffers until a transport is up, so installing it this early
        // costs nothing and means the journal mount lines are not lost.
        umsh_ulcp_runtime::log::set_debug_log(debug_log);

        // Re-power the GNSS backup domain as the very first thing this
        // image does, before embassy init and before any peripheral is
        // touched.
        //
        // nRF52840 System OFF retains driven pin levels *while it is off*,
        // but waking from it is a reset: GPIO returns to its disconnected
        // reset configuration, and stays there until something drives it
        // again. On this board that pin gates the only real-time clock
        // there is, so every millisecond between the reset and this write
        // is a millisecond the clock is running on whatever charge is left
        // on the rail. Asserting it in the normal peripheral-init block —
        // after the bootloader, embassy, the radio and the journal — is
        // far too late to expect it to survive.
        //
        // Whether it survives even from here is a question about the
        // bootloader's own startup time and the rail's capacitance, not
        // about this firmware. If it does not, the receiver comes back
        // reporting its own epoch, which `umsh-gnss` rejects, and the
        // device honestly reports that it does not know the time.
        #[cfg(all(feature = "gnss-holds-the-clock", feature = "t1000e"))]
        umsh_bsp_nrf52840::system_off::drive_pin_high(umsh_bsp_nrf52840::system_off::Port::P0, 8);

        let (previous_crumb, previous_beats) = super::panic::breadcrumb_take();
        PREV_BOOT_CRUMB.store(previous_crumb, Ordering::Release);
        PREV_BOOT_BEATS.store(previous_beats, Ordering::Release);
        let wdt_capture = super::panic::wdt_capture_take();
        let mut pc_ring = [0u32; super::panic::PC_RING_ENTRIES];
        let pc_ring_count = super::panic::pc_ring_take(&mut pc_ring);
        PREV_RING_COUNT.store(pc_ring_count as u16, Ordering::Release);
        super::panic::breadcrumb_mark(1);

        // Init heap before any alloc-using code (the device node's
        // bring-up allocates a small bounded amount). 8 KiB matches the
        // CLI firmware's budget for the same node stack.
        {
            use core::mem::MaybeUninit;
            const HEAP_SIZE: usize = 8192;
            static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
            unsafe { crate::ALLOCATOR.init(core::ptr::addr_of!(HEAP) as usize, HEAP_SIZE) }
        }

        // Crystal-less boards (XIAO-based SenseCAP Solar) run the LFCLK from
        // the internal RC oscillator; boards with a 32.768 kHz crystal use it.
        #[cfg(not(feature = "lfclk-rc"))]
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::ble_config());
        #[cfg(feature = "lfclk-rc")]
        let p = embassy_nrf::init(umsh_bsp_nrf52840::clocks::ble_config_lfrc());
        // GPIO state survives the soft reset/DFU handoff. Silence the T-1000E
        // piezo before any potentially lengthy radio, flash, or BLE work so a
        // retained PWM/enable state cannot sound until the buzzer task starts.
        #[cfg(feature = "t1000e")]
        {
            drive_pin_low(Port::P0, 25); // buzzer PWM input
            drive_pin_low(Port::P1, 5); // buzzer driver enable
        }
        super::panic::breadcrumb_mark(2);
        // RESETREAS survives reset. Capture and clear it before starting the
        // watchdog so a later host query can distinguish a watchdog reboot
        // from a cold start or an external reset.
        let hardware_reset_reasons = pac::POWER.resetreas().read();
        pac::POWER.resetreas().write(|reasons| reasons.0 = u32::MAX);
        BOOT_RESETREAS.store(hardware_reset_reasons.0, Ordering::Release);
        #[cfg(feature = "t1000e")]
        let t1000e_external_power = umsh_bsp_t1000e::power::usb_power_present();
        #[cfg(feature = "t1000e")]
        let t1000e_gpregret_state = umsh_bsp_t1000e::preferences::load_retained();
        #[cfg(feature = "t1000e")]
        let t1000e_retained_critical =
            t1000e_gpregret_state.is_some_and(|preferences| preferences.battery_critical);
        #[cfg(feature = "t1000e")]
        let mut t1000e_retained_state = mapped_ux_preferences().unwrap_or_default();
        #[cfg(feature = "t1000e")]
        {
            t1000e_retained_state.battery_critical = t1000e_retained_critical;
            umsh_bsp_t1000e::preferences::store(t1000e_retained_state);
        }
        #[cfg(feature = "t1000e")]
        if t1000e_retained_state.battery_critical && !t1000e_external_power {
            umsh_bsp_t1000e::shutdown::resume_persisted_sleep().await;
        }
        #[cfg(feature = "t1000e")]
        if t1000e_retained_state.battery_critical && t1000e_external_power {
            umsh_bsp_t1000e::preferences::set_battery_critical(false);
        }
        // RESETREAS.OFF alone proves a button wake: P0.06 is the only GPIO
        // DETECT source armed at System OFF entry (USB insertion wakes via
        // the native VBUS detector and sets its own reason bit). The pin
        // itself cannot be sampled this early — PIN_CNF resets to
        // input-disconnected, so the IN register reads 0 regardless of the
        // physical level.
        #[cfg(feature = "t1000e")]
        let t1000e_wake_requested = hardware_reset_reasons.off()
            || (hardware_reset_reasons.sreq()
                && t1000e_gpregret_state.is_some_and(|preferences| !preferences.asleep));
        #[cfg(feature = "t1000e")]
        let t1000e_wake_cleared_sleep = t1000e_wake_requested && t1000e_retained_state.asleep;
        #[cfg(feature = "t1000e")]
        if t1000e_wake_requested {
            umsh_bsp_t1000e::preferences::set_asleep(false);
        } else if umsh_bsp_t1000e::preferences::load().asleep {
            if t1000e_external_power {
                let mut led_config = SimpleConfig::default();
                led_config.prescaler = Prescaler::Div16;
                let led_pwm = SimplePwm::new_1ch(p.PWM1, p.P0_24, &led_config);
                let sleep_button = Input::new(p.P0_06, Pull::Down);
                let sleep_external_power = Input::new(p.P0_05, Pull::Down);
                let sleep_charge_active = Input::new(p.P1_03, Pull::Up);
                umsh_bsp_t1000e::shutdown::run_charging_sleep(
                    led_pwm,
                    sleep_button,
                    sleep_external_power,
                    sleep_charge_active,
                )
                .await;
            } else {
                umsh_bsp_t1000e::shutdown::resume_persisted_sleep().await;
            }
        }

        // Disarm POWER USB interrupt state inherited across the DFU
        // handoff. The bootloader's USB stack enables the POWER
        // USBDETECTED/USBREMOVED/USBPWRRDY interrupts, and POWER lives
        // in the always-on domain, so the enables survive the DFU
        // activation reset. MPSL later owns the shared CLOCK_POWER
        // vector but services only CLOCK events, so with VBUS present a
        // pending USB power event re-enters the handler forever,
        // starving thread mode until the watchdog fires — the post-DFU
        // first-boot freeze. This firmware never uses these interrupts
        // (USB runs on SoftwareVbusDetect precisely because MPSL owns
        // POWER), so clear the enables and any pending events before
        // MPSL takes the vector.
        pac::POWER.intenclr().write(|w| {
            w.set_usbdetected(true);
            w.set_usbremoved(true);
            w.set_usbpwrrdy(true);
        });
        pac::POWER.events_usbdetected().write_value(0);
        pac::POWER.events_usbremoved().write_value(0);
        pac::POWER.events_usbpwrrdy().write_value(0);

        // TEMPORARY freeze diagnostics: format the previous boot's
        // watchdog capture and PC-sample ring for the ASCII dump on the
        // first USB connect.
        let wdt_report: Option<&'static str> = (wdt_capture.is_some()
            || (pc_ring_count > 0 && hardware_reset_reasons.dog()))
        .then(|| {
            use core::fmt::Write as _;
            static REPORT: StaticCell<heapless09::String<2048>> = StaticCell::new();
            let report = REPORT.init(heapless09::String::new());
            let _ = write!(report, "\r\n=== WDT CAPTURE (previous boot) ===\r\n");
            if let Some(capture) = wdt_capture {
                PREV_WDT_PC.store(capture.pc, Ordering::Release);
                PREV_WDT_LR.store(capture.lr, Ordering::Release);
                PREV_WDT_PSR.store(capture.xpsr, Ordering::Release);
                let _ = write!(
                    report,
                    "pc={:#010x} lr={:#010x} psr={:#010x} exc={:#010x} sp={:#010x}\r\n",
                    capture.pc, capture.lr, capture.xpsr, capture.exc_return, capture.sp,
                );
                let _ = write!(
                    report,
                    "CLOCK hfstat={:#x} lfstat={:#x} inten={:#x} evhf={} evlf={} evdone={} evctto={} lfsrc={:#x}\r\n",
                    capture.clock[0],
                    capture.clock[1],
                    capture.clock[2],
                    capture.clock[3],
                    capture.clock[4],
                    capture.clock[5],
                    capture.clock[6],
                    capture.clock[7],
                );
                let _ = write!(report, "stack above frame:\r\n");
                for row in capture.stack.chunks(4) {
                    for word in row {
                        let _ = write!(report, "{word:#010x} ");
                    }
                    let _ = write!(report, "\r\n");
                }
            } else {
                let _ = write!(report, "no exception-frame capture (WDT IRQ shielded)\r\n");
            }
            let _ = write!(report, "pc ring ({pc_ring_count} samples, oldest first):\r\n");
            for row in pc_ring[..pc_ring_count].chunks(4) {
                for word in row {
                    let _ = write!(report, "{word:#010x} ");
                }
                let _ = write!(report, "\r\n");
            }
            let _ = write!(report, "=== END WDT CAPTURE ===\r\n");
            report.as_str()
        });
        #[cfg(feature = "ble-debug")]
        {
            set_security_trace_handler(Some(trouble_security_trace));
            set_security_diagnostic_trace_handler(Some(trouble_security_diagnostic_trace));
            set_connection_trace_handler(Some(trouble_connection_trace));
        }

        // Board power (schematic): SX1262 = PWR_EN (P0.13); VDD_POWR =
        // PWR_EN ∧ (PWR_ON (P0.12) ∨ VBUS). Both must be high before the
        // LoRa module is addressed. PWR_EN floating happens to work — its
        // reset state leaks enough to run the board, which is exactly how
        // the half-collapsed off-state rail went unnoticed — but the
        // radio's supply gate deserves a driven level, not a lucky float.
        // Ownership of both transfers to shutdown_task.
        #[cfg(feature = "system-off-techo")]
        let peripheral_power = Output::new(p.P0_12, Level::High, OutputDrive::Standard);
        #[cfg(feature = "system-off-techo")]
        let power_enable = Output::new(p.P0_13, Level::High, OutputDrive::Standard);

        // On T-1000E, seize LR1110 reset before any lengthy initialization.
        // The user button is active-high. Holding it through power-on is the
        // BLE spec's physical-presence ceremony; it must not invoke the
        // bootloader. The runtime task suppresses this same press until release.
        #[cfg(feature = "t1000e")]
        let radio_rst = Output::new(p.P1_10, Level::Low, OutputDrive::Standard);
        #[cfg(feature = "t1000e")]
        let mut button = Input::new(p.P0_06, Pull::Down);
        #[cfg(feature = "t1000e")]
        cortex_m::asm::delay(640_000);
        // A short press is how a powered-off T-1000E is started normally, so
        // the initial HIGH level alone cannot distinguish force pairing. Only
        // a press still held after one second is the deliberate ceremony.
        #[cfg(feature = "t1000e")]
        let force_pairing_at_boot = if button.is_high() {
            match select(button.wait_for_low(), Timer::after_secs(1)).await {
                Either::First(()) => false,
                Either::Second(()) => button.is_high(),
            }
        } else {
            false
        };
        #[cfg(feature = "t1000e")]
        FORCE_PAIRING_AT_BOOT.store(force_pairing_at_boot, Ordering::Release);

        // SenseCAP Solar: the same physical-presence ceremony, carried by the
        // secondary user button — enclosure "USR", P1.07, active-low.
        //
        // It cannot live on the power button (enclosure "PWR", P1.01): any
        // press of PWR while the node is in System OFF enters the stock
        // bootloader's DFU mode unconditionally — duration is irrelevant, a
        // bare tap does it — so that press never reaches this code. Escaping
        // that needs a different bootloader. The same fact makes USR the only
        // button that actually powers the node back on, which is what makes it
        // the natural carrier for a hold-through-power-on gesture.
        //
        // A wake press is how a powered-off node is started, so the level at
        // t=0 cannot distinguish the ceremony from an ordinary power-on — only
        // a press still held after one second is deliberate. The button is
        // claimed here rather than later because FORCE_PAIRING_AT_BOOT must be
        // set before the BLE store seeds PAIRING_MODE.
        #[cfg(feature = "power-button")]
        let mut usr_button = Input::new(p.P1_07, Pull::Up);
        #[cfg(feature = "power-button")]
        let mut pwr_led = Output::new(p.P0_15, Level::Low, OutputDrive::Standard);
        #[cfg(feature = "power-button")]
        cortex_m::asm::delay(640_000);
        #[cfg(feature = "power-button")]
        {
            let force_pairing_at_boot = if usr_button.is_low() {
                match select(usr_button.wait_for_high(), Timer::after_secs(1)).await {
                    Either::First(()) => false,
                    Either::Second(()) => usr_button.is_low(),
                }
            } else {
                false
            };
            FORCE_PAIRING_AT_BOOT.store(force_pairing_at_boot, Ordering::Release);
            // Acknowledge the accepted ceremony on LED_A (white, active-high)
            // the instant the threshold is crossed, while the user is still
            // holding. Without this the only feedback is the LED_B pairing
            // blink, which is indistinguishable from an unbonded node's — so a
            // gesture that silently missed looked identical to one that
            // worked. Two blinks, deliberately distinct from the three that
            // acknowledge hold-to-power-off. Runs before the WDT is armed.
            if force_pairing_at_boot {
                for _ in 0..2 {
                    pwr_led.set_high();
                    Timer::after_millis(120).await;
                    pwr_led.set_low();
                    Timer::after_millis(120).await;
                }
            }
        }

        // WDT: 8 s timeout, petted by the heartbeat task every ~2 s.
        let mut wdt_config = WdtConfig::default();
        wdt_config.timeout_ticks = 32768 * 8;
        let (mut wdt, [wdt_handle]) =
            Watchdog::try_new::<_, 1>(p.WDT, wdt_config).unwrap_or_else(|_| panic!("wdt"));
        // Freeze diagnostics: the TIMEOUT interrupt fires ~61 µs before
        // the watchdog reset; its handler (panic.rs `WDT`) records the
        // interrupted context's stacked PC/LR/xPSR into retained RAM.
        // Highest priority so it can preempt a storming lower-priority
        // handler; it runs only in the doomed final microseconds.
        wdt.enable_interrupt();
        unsafe {
            let mut peripherals = cortex_m::Peripherals::steal();
            peripherals
                .NVIC
                .set_priority(embassy_nrf::pac::Interrupt::WDT, 0);
            cortex_m::peripheral::NVIC::unmask(embassy_nrf::pac::Interrupt::WDT);
        }
        // Freeze diagnostics: 1 kHz PC sampler on TIMER2 (free on both
        // boards; MPSL owns TIMER0 only). Priority 1 — above the
        // thread-mode executor and MPSL's low-priority signal
        // processing, below MPSL's radio-critical priority 0.
        {
            let timer = pac::TIMER2;
            timer
                .mode()
                .write(|w| w.set_mode(pac::timer::vals::Mode::Timer));
            timer
                .bitmode()
                .write(|w| w.set_bitmode(pac::timer::vals::Bitmode::_32bit));
            timer.prescaler().write(|w| w.set_prescaler(4)); // 16 MHz / 2^4 = 1 MHz
            timer.cc(0).write_value(1_000); // 1 kHz sampling
            timer.shorts().write(|w| w.set_compare_clear(0, true));
            timer.intenset().write(|w| w.set_compare(0, true));
            timer.tasks_start().write_value(1);
            unsafe {
                let mut peripherals = cortex_m::Peripherals::steal();
                peripherals
                    .NVIC
                    .set_priority(embassy_nrf::pac::Interrupt::TIMER2, 1 << 5);
                cortex_m::peripheral::NVIC::unmask(embassy_nrf::pac::Interrupt::TIMER2);
            }
        }
        #[cfg(feature = "board-techo")]
        let led = Output::new(p.P0_14, Level::High, OutputDrive::Standard);
        // SenseCAP Solar: LED_B (P0.19, blue, active-high) is the heartbeat.
        #[cfg(feature = "board-sensecap-solar")]
        let led = Output::new(p.P0_19, Level::Low, OutputDrive::Standard);
        // Wio Tracker L1: the user LED (D11 / P1.01) is active-high.
        #[cfg(feature = "board-wio-tracker-l1")]
        let led = Output::new(p.P1_01, Level::Low, OutputDrive::Standard);
        // XIAO nRF52840: blue segment of the common-anode RGB LED (P0.06),
        // **active-low** — Level::High is off. Blue is the status colour
        // here (MeshCore's choice on this board); red stays free as a TX
        // indicator and green is the 10 kΩ leg, noticeably dimmer.
        #[cfg(feature = "board-xiao-nrf52")]
        let led = Output::new(p.P0_06, Level::High, OutputDrive::Standard);
        #[cfg(feature = "t1000e")]
        let led = {
            let mut config = SimpleConfig::default();
            config.prescaler = Prescaler::Div16;
            SimplePwm::new_1ch(p.PWM1, p.P0_24, &config)
        };
        // Service the watchdog throughout radio, persistence, MPSL, and BLE
        // initialization. Deferring this task until the final steady-state
        // join caused first-boot persistence to consume the entire watchdog
        // window and reset once before the device became usable.
        spawner.spawn(heartbeat(led, wdt_handle).unwrap());
        super::panic::breadcrumb_mark(3);

        // A message in the panic slot means the last reset was a crash;
        // report that as the reset reason and keep the message text for
        // the first-USB-reader dump. The slot is cleared either way.
        let mut panic_report: Option<&'static str> = None;
        let boot_reason = {
            let mut slot = PanicSlot::new(super::panic::panic_region());
            if let Some(message) = slot.read() {
                use core::fmt::Write as _;
                static PANIC_REPORT: StaticCell<heapless09::String<1100>> = StaticCell::new();
                let text = PANIC_REPORT.init(heapless09::String::new());
                let _ = write!(text, "\r\n=== PANIC (previous boot) ===\r\n");
                for byte in message.iter().take(1000) {
                    let c = *byte as char;
                    let _ = text.push(if c.is_ascii_graphic() || c == ' ' {
                        c
                    } else {
                        '.'
                    });
                }
                let _ = write!(text, "\r\n=== END PANIC ===\r\n");
                panic_report = Some(text.as_str());
                slot.clear();
                Status::RESET_CRASH
            } else if hardware_reset_reasons.dog() {
                Status::RESET_WATCHDOG
            } else if hardware_reset_reasons.lockup() {
                Status::RESET_CRASH
            } else if hardware_reset_reasons.resetpin() {
                Status::RESET_EXTERNAL
            } else if hardware_reset_reasons.sreq() {
                Status::RESET_SOFTWARE
            } else {
                Status::RESET_POWER_ON
            }
        };

        // ── SX1262 LoRa radio ────────────────────────────────────────────────
        // Pin assignment (T-Echo hardware, firmware-confirmed):
        //   SPI bus: SCK=P0.19, MOSI=P0.22, MISO=P0.23 (TWISPI1)
        //   CS=P0.24, RST=P0.25, BUSY=P0.17, DIO1=P0.20
        //   DIO2: internal RF switch; DIO3: 1.8 V TCXO.
        #[cfg(feature = "board-techo")]
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
            // Radio init failure degrades to a USB/BLE-only device (RF dead)
            // rather than a startup panic → reboot loop: a display-less
            // field node must stay reachable to diagnose.
            match LoRa::new(Sx126x::new(radio_spi, iv, lora_config), false, Delay).await {
                Ok(lora) => {
                    spawner.spawn(radio_task(lora).unwrap());
                }
                Err(error) => debug_log(format_args!("radio init FAILED (RF disabled): {error:?}")),
            }
        }

        // ── LR1110 LoRa radio (T-1000E) ─────────────────────────────────────
        #[cfg(feature = "t1000e")]
        {
            let mut cfg = SpimConfig::default();
            cfg.frequency = Frequency::M8;
            let radio_bus = Spim::new(p.TWISPI0, Irqs, p.P0_11, p.P1_08, p.P1_09, cfg);
            let radio_cs = Output::new(p.P0_12, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();
            let radio_interrupt = Input::new(p.P1_01, Pull::Down);
            let radio_busy = Input::new(p.P0_07, Pull::None);
            let iv = GenericLr1110InterfaceVariant::new(
                radio_rst,
                radio_interrupt,
                radio_busy,
                None,
                None,
            )
            .unwrap_or_else(|_| panic!("lr1110 iv"));
            let lora_config = LoraConfig {
                chip: Lr1110Chip::with_pa(PaSelection::Hp),
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V6),
                use_dcdc: false,
                rx_boost: true,
                rf_switch: Some(RF_SWITCH),
            };
            match LoRa::new(Lr1110::new(radio_spi, iv, lora_config), false, Delay).await {
                Ok(lora) => {
                    spawner.spawn(radio_task(lora).unwrap());
                }
                Err(error) => debug_log(format_args!("radio init FAILED (RF disabled): {error:?}")),
            }
        }

        // ── SX1262 LoRa radio (SenseCAP Solar Node, XIAO nRF52840 kit) ──────
        // Byte-for-byte the Wio Tracker L1 SX1262 bring-up on this pin map
        // (external RXEN, DIO2 internal RF switch, DIO3 1.8 V TCXO):
        //   SPI TWISPI1 @16MHz: SCK=P1.13, MISO=P1.14, MOSI=P1.15, CS=P0.04
        //   RST=P0.28, BUSY=P0.29, DIO1=P0.03, RXEN=P0.05 (rf_switch_rx)
        //
        // Two boards share this block verbatim, and not by coincidence:
        // both are XIAO-pinout carriers around the same Wio SX1262 module,
        // so the wiring is identical pin for pin. The XIAO kit's copy is
        // additionally schematic-confirmed (Wio-SX1262 for XIAO V1.0)
        // rather than reconstructed from vendor firmware.
        //
        // Two carrier details worth knowing here, both from that schematic:
        // RESET has a 10 kΩ pull-up, so a floating pin does *not* hold the
        // radio down — the explicit reset below is what does. RXEN has no
        // pull at all, which is why it is clamped at construction rather
        // than left to lora-phy's first transition.
        #[cfg(any(feature = "board-sensecap-solar", feature = "board-xiao-nrf52"))]
        {
            let mut cfg = SpimConfig::default();
            cfg.frequency = Frequency::M16;
            let radio_bus = Spim::new(
                p.TWISPI1, Irqs, p.P1_13, // SCK
                p.P1_14, // MISO
                p.P1_15, // MOSI
                cfg,
            );
            let radio_cs = Output::new(p.P0_04, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();

            let radio_rst = Output::new(p.P0_28, Level::High, OutputDrive::Standard);
            let radio_dio1 = Input::new(p.P0_03, Pull::None);
            let radio_busy = Input::new(p.P0_29, Pull::None);
            // RXEN clamped low at construction (safety contract) until
            // lora-phy drives it HIGH in RX / LOW in TX.
            let radio_rxen = Output::new(p.P0_05, Level::Low, OutputDrive::Standard);

            let iv = GenericSx126xInterfaceVariant::new(
                radio_rst,
                radio_dio1,
                radio_busy,
                Some(radio_rxen), // rf_switch_rx
                None,             // rf_switch_tx: none
            )
            .unwrap();

            let lora_config = LoraConfig {
                chip: Sx1262,
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8), // DIO3 → 1.8 V TCXO
                use_dcdc: true,
                rx_boost: true,
            };

            // Radio init failure degrades to a USB/BLE-only device (RF dead)
            // rather than a startup panic → reboot loop. The SX1262 bring-up
            // on these pins is hardware-proven on the SenseCAP Solar
            // (bidirectional RF, 2026-07-23); on the XIAO kit it is still
            // only schematic-confirmed, which is exactly the case this
            // degrade-instead-of-panic path exists for.
            match LoRa::new(Sx126x::new(radio_spi, iv, lora_config), false, Delay).await {
                Ok(lora) => {
                    spawner.spawn(radio_task(lora).unwrap());
                }
                Err(error) => debug_log(format_args!("radio init FAILED (RF disabled): {error:?}")),
            }
        }

        // ── SX1262 LoRa radio (Wio Tracker L1) ──────────────────────────────
        // The board the Solar P1 block above was itself ported from
        // (external RXEN, DIO2 internal RF switch, DIO3 1.8 V TCXO):
        //   SPI TWISPI1 @16MHz: SCK=P0.30, MISO=P0.03, MOSI=P0.28, CS=P1.14
        //   RST=P1.07, BUSY=P1.10, DIO1=P0.07, RXEN=P1.08 (rf_switch_rx)
        #[cfg(feature = "board-wio-tracker-l1")]
        {
            let mut cfg = SpimConfig::default();
            cfg.frequency = Frequency::M16;
            let radio_bus = Spim::new(
                p.TWISPI1, Irqs, p.P0_30, // SCK
                p.P0_03, // MISO
                p.P0_28, // MOSI
                cfg,
            );
            let radio_cs = Output::new(p.P1_14, Level::High, OutputDrive::Standard);
            let radio_spi = ExclusiveDevice::new(radio_bus, radio_cs, Delay).unwrap();

            let radio_rst = Output::new(p.P1_07, Level::High, OutputDrive::Standard);
            let radio_dio1 = Input::new(p.P0_07, Pull::None);
            let radio_busy = Input::new(p.P1_10, Pull::None);
            // RXEN clamped low at construction (safety contract). Holding
            // the external LNA biased through a +22 dBm transmit is the
            // one way firmware can damage this board.
            let radio_rxen = Output::new(p.P1_08, Level::Low, OutputDrive::Standard);

            let iv = GenericSx126xInterfaceVariant::new(
                radio_rst,
                radio_dio1,
                radio_busy,
                Some(radio_rxen), // rf_switch_rx
                None,             // rf_switch_tx: no separate TX enable pin
            )
            .unwrap();

            let lora_config = LoraConfig {
                chip: Sx1262,
                tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8), // DIO3 → 1.8 V TCXO
                use_dcdc: true,
                rx_boost: true,
            };

            // Radio init failure degrades to a USB/BLE-only device (RF dead)
            // rather than a startup panic → reboot loop.
            match LoRa::new(Sx126x::new(radio_spi, iv, lora_config), false, Delay).await {
                Ok(lora) => {
                    spawner.spawn(radio_task(lora).unwrap());
                }
                Err(error) => debug_log(format_args!("radio init FAILED (RF disabled): {error:?}")),
            }
        }

        // The mux is the radio runner's only client; the session (and,
        // later, the device node) transmit and receive through their
        // virtual bundles.
        spawner.spawn(radio_mux_task().unwrap());

        super::panic::breadcrumb_mark(4);

        // Device-node counter state exists in every image; the BLE
        // branch below attaches its journal once the shared flash is
        // up. Must precede device_task/bring_up, which hold references.
        let node_counters = init_node_counters();

        // ── MPSL + Nordic SoftDevice Controller ────────────────────────────
        // MPSL owns CLOCK/POWER, RADIO, RTC0, TIMER0, TEMP, and the listed
        // PPI channels. embassy-time remains on RTC1; LoRa remains on SPIM1.
        //
        // MPSL, the flash driver, and the protocol journals come up in
        // BOTH images: the flash driver needs only the MPSL timeslot
        // scheduler, not the BLE controller on top of it. The `no-ble`
        // diagnostic build skips just the SDC/Trouble construction
        // below; it is then a USB-only device with identical persistence
        // and clock configuration.
        let mut rng = rng::Rng::new(p.RNG, Irqs);
        // Everything this RNG feeds is key material — the device identity
        // secret, the CSPRNG seeds, the BLE local IRK — so take the
        // bias-corrected output. The nRF52840 TRNG is measurably biased
        // towards one bit value without it; correction costs roughly
        // 120 µs a byte instead of 40, which at a few 32-byte draws per
        // boot is not worth trading entropy quality for.
        rng.set_bias_correction(true);
        #[cfg(not(feature = "no-ble"))]
        let mut sdc_memory = sdc::Mem::<8192>::new();
        let mpsl = {
            let mpsl_peripherals = mpsl::Peripherals::new(
                p.RTC0, p.TIMER0, p.TEMP, p.PPI_CH19, p.PPI_CH30, p.PPI_CH31,
            );
            // Boards with a 32.768 kHz crystal use it (20 ppm); crystal-less
            // boards (XIAO-based SenseCAP Solar) run MPSL's LFCLK from the
            // internal RC oscillator, periodically calibrated against the HF
            // clock (rc_ctiv = 16 → every 4 s; rc_temp_ctiv = 2 → also on
            // ~0.5 °C drift). Must match the embassy `lfclk_source` above.
            #[cfg(not(feature = "lfclk-rc"))]
            let lfclk = mpsl::raw::mpsl_clock_lfclk_cfg_t {
                source: mpsl::raw::MPSL_CLOCK_LF_SRC_XTAL as u8,
                rc_ctiv: 0,
                rc_temp_ctiv: 0,
                accuracy_ppm: 20,
                skip_wait_lfclk_started: false,
            };
            #[cfg(feature = "lfclk-rc")]
            let lfclk = mpsl::raw::mpsl_clock_lfclk_cfg_t {
                source: mpsl::raw::MPSL_CLOCK_LF_SRC_RC as u8,
                rc_ctiv: 16,
                rc_temp_ctiv: 2,
                accuracy_ppm: 250,
                skip_wait_lfclk_started: false,
            };
            static MPSL: StaticCell<MultiprotocolServiceLayer> = StaticCell::new();
            static TIMESLOT_MEM: StaticCell<mpsl::SessionMem<1>> = StaticCell::new();
            let mpsl: &'static MultiprotocolServiceLayer = MPSL.init(
                MultiprotocolServiceLayer::with_timeslots(
                    mpsl_peripherals,
                    Irqs,
                    lfclk,
                    TIMESLOT_MEM.init(mpsl::SessionMem::new()),
                )
                .unwrap_or_else(|_| panic!("mpsl init")),
            );
            spawner.spawn(mpsl_task(mpsl).unwrap());
            mpsl
        };
        super::panic::breadcrumb_mark(5);
        static SHARED_FLASH: StaticCell<SharedFlash> = StaticCell::new();
        let flash = SHARED_FLASH.init(Mutex::new(JournalFlash(nrf_mpsl::Flash::take(
            mpsl, p.NVMC,
        ))));
        // Mount the protocol journals before the ULCP session starts: a
        // stored snapshot must be restored (and the PHY re-applied) and
        // the persisted device identity installed before the first host
        // command.
        let (proto_store, boot_snapshot) = ProtoStore::mount(flash, proto_store::PAGE0).await;
        let (mut identity_store, identity_payload) =
            ProtoStore::mount(flash, proto_store::IDENTITY_PAGE0).await;
        let (ux_store, _) = ProtoStore::mount(flash, proto_store::UX_PAGE0).await;
        mount_node_counters(node_counters, flash).await;
        #[cfg(feature = "t1000e")]
        let mut ux_store = ux_store;
        #[cfg(feature = "t1000e")]
        if t1000e_wake_cleared_sleep {
            let _ =
                persist_ux_preferences(&mut ux_store, umsh_bsp_t1000e::preferences::load()).await;
        }
        // Both halves of the persisted keypair: the public key seeds
        // the session's PROP_DEV_KEY surface, the secret brings up
        // the device node's MAC identity.
        //
        // A device identity always exists. When the journal is empty —
        // a factory-fresh board, or the boot that completes a factory
        // reset — one is generated here and persisted before anything
        // can observe its absence, so identity is never a commissioning
        // step the operator has to perform. Installing a *specific*
        // identity later (`PROP_DEV_PRIVATE_KEY`) stays available and is
        // recovery, not setup.
        //
        // The secret comes straight from the hardware TRNG, which
        // blocks until the peripheral has produced each byte and is
        // bias-corrected above. It is deliberately not drawn from the
        // ChaCha20 stream seeded below: that stream is fine, but there
        // is no reason to put a derivation between the noise source and
        // a key that outlives the device's configuration.
        let mut identity_keys = identity_payload
            .as_deref()
            .and_then(proto_store::decode_identity);
        if identity_keys.is_none() {
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret).await;
            let (public, record) = driver::device_identity_record(&secret);
            // A persist failure is not fatal: the device runs on this
            // key for the current boot and generates another next time.
            // Reporting it matters more than refusing to boot, because
            // the alternative is a radio that is silently inert.
            match identity_store.persist(&record).await {
                Ok(()) => debug_log(format_args!(
                    "device identity generated at first boot key={}",
                    umsh_core::PublicKey(public)
                )),
                Err(()) => debug_log(format_args!(
                    "device identity generated but persist=FAILED — volatile this boot"
                )),
            }
            identity_keys = Some((secret, public));
        }
        let boot_identity_keys = identity_keys;
        // A replaced identity leaves its TX boundary behind in the
        // counter journal; drop it so the map cannot silt up.
        if let Some((_, public)) = boot_identity_keys.as_ref() {
            prune_stale_tx_counters(node_counters, public).await;
        }
        // Seed the identity-generation and device-node CSPRNGs from the
        // TRNG; in the BLE image this must happen while the peripheral
        // is still ours — build_sdc below hands the RNG to the
        // SoftDevice Controller for its lifetime.
        let mut identity_seed = [0u8; 32];
        rng.fill_bytes(&mut identity_seed).await;
        let identity_rng = <IdentityRng as rand_core::SeedableRng>::from_seed(identity_seed);
        let mut node_seed = [0u8; 32];
        rng.fill_bytes(&mut node_seed).await;

        #[cfg(not(feature = "no-ble"))]
        let (controller, ble_store) = {
            let mut ble_store = BleStore::mount(flash).await;
            // Deliberate recovery image for hardware testing. This runs before the
            // Trouble host is constructed, so there is no live bond table to keep
            // in sync: the empty persisted snapshot becomes the host's initial
            // state below. Preserve the device's local IRK, matching the normal
            // security-wipe operation.
            #[cfg(feature = "ble-wipe-on-boot")]
            {
                debug_log(format_args!(
                    "ONE-TIME BLE WIPE begin bonds={} pin={}",
                    ble_store.snapshot().bonds.len(),
                    ble_store.snapshot().pin.is_some(),
                ));
                ble_store
                    .clear_security()
                    .await
                    .unwrap_or_else(|_| panic!("one-time ble wipe failed"));
                debug_log(format_args!(
                    "ONE-TIME BLE WIPE complete bonds={} pin={}",
                    ble_store.snapshot().bonds.len(),
                    ble_store.snapshot().pin.is_some(),
                ));
            }
            BLE_BONDS_AT_BOOT.store(ble_store.snapshot().bonds.len() as u8, Ordering::Release);
            BLE_BOND_COUNT.store(ble_store.snapshot().bonds.len() as u8, Ordering::Release);
            // See the matching seed in `ble_app` for why
            // `boot-pairing-window` boards force this true every boot.
            PAIRING_MODE.store(
                ble_store.snapshot().bonds.is_empty()
                    || FORCE_PAIRING_AT_BOOT.load(Ordering::Acquire)
                    || cfg!(feature = "boot-pairing-window"),
                Ordering::Release,
            );

            let sdc_peripherals = sdc::Peripherals::new(
                p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23, p.PPI_CH24,
                p.PPI_CH25, p.PPI_CH26, p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
            );
            if ble_store.snapshot().local_irk.is_none() {
                let mut local_irk = [0u8; 16];
                rng.fill_bytes(&mut local_irk).await;
                if local_irk == [0; 16] {
                    local_irk[0] = 1;
                }
                ble_store
                    .set_local_irk(local_irk)
                    .await
                    .unwrap_or_else(|_| panic!("local irk persist"));
            }
            #[cfg(feature = "ble-store-fault-inject")]
            {
                BLE_STORE_FAULT_ARMED.store(true, Ordering::Release);
                debug_log(format_args!(
                    "STORE FAULT INJECTION ARMED: all runtime writes and erases will fail"
                ));
            }
            super::panic::breadcrumb_mark(6);
            let controller = build_sdc(sdc_peripherals, &mut rng, mpsl, &mut sdc_memory)
                .unwrap_or_else(|_| panic!("sdc init"));
            super::panic::breadcrumb_mark(7);
            (controller, ble_store)
        };
        // The session surfaces only the public key; the secret stays with
        // the device node.
        let boot_identity = boot_identity_keys.map(|(_secret, public)| public);

        // ── USB stack ────────────────────────────────────────────────────────
        // HardwareVbusDetect cannot share POWER with MPSL. This tethered device
        // treats USB as present/ready; CDC connection state still supplies the
        // protocol attach/detach edges used by advertising arbitration.
        static VBUS: StaticCell<SoftwareVbusDetect> = StaticCell::new();
        let vbus = VBUS.init(SoftwareVbusDetect::new(true, true));
        let driver = Driver::new(p.USBD, Irqs, &*vbus);

        let mut config = Config::new(0x16c0, 0x27dd);
        config.manufacturer = Some("UMSH");
        #[cfg(feature = "board-techo")]
        {
            config.product = Some("T-Echo UMSH Radio");
            config.serial_number = Some("techo");
        }
        #[cfg(feature = "t1000e")]
        {
            config.product = Some("T-1000E UMSH Radio");
            config.serial_number = Some("t1000e");
        }
        #[cfg(feature = "board-sensecap-solar")]
        {
            config.product = Some("Solar Node UMSH Radio");
            config.serial_number = Some("sensecap-solar");
        }
        #[cfg(feature = "board-wio-tracker-l1")]
        {
            config.product = Some("Wio Tracker UMSH Radio");
            config.serial_number = Some("wio-tracker-l1");
        }
        #[cfg(feature = "board-xiao-nrf52")]
        {
            config.product = Some("XIAO nRF52 UMSH Radio");
            config.serial_number = Some("xiao-nrf52");
        }
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

        spawner.spawn(output_task(tx, wdt_report, panic_report).unwrap());
        spawner.spawn(usb_in_task(rx).unwrap());
        spawner.spawn(
            device_task(
                boot_reason,
                proto_store,
                boot_snapshot,
                identity_store,
                boot_identity,
                identity_rng,
                node_counters,
            )
            .unwrap(),
        );

        // ── Device node ─────────────────────────────────────────────────────
        // The device identity always exists by this point, so the full
        // MAC/node stack always comes up on mux client B; whether it
        // transmits is a matter of configuration (the PHY enable state
        // and the forwarding switch), not of whether a key was ever
        // provisioned. The airtime hint is the worst case at the
        // MeshCore-US default profile — the MAC scheduler only uses it as
        // a conservative bound.
        //
        // The one exception is a crash reboot: skip one boot of the
        // device node so the surviving boot stays reachable and prints
        // the previous panic over USB.
        let (identity_secret, _public) = boot_identity_keys
            .as_ref()
            .expect("a device identity is generated at boot when none is stored");
        if panic_report.is_none() {
            let t_frame_ms = umsh_radio_loraphy::airtime_ms(
                lora_phy::mod_params::SpreadingFactor::_7,
                lora_phy::mod_params::Bandwidth::_62KHz,
                umsh_radio_loraphy::MAX_PAYLOAD,
            );
            super::device_node::bring_up(
                spawner,
                identity_secret,
                node_seed,
                t_frame_ms,
                node_counters,
            )
            .await;
        }
        super::panic::breadcrumb_mark(8);

        // The touch button only asks for the e-paper backlight; a locate
        // alert can ask for it too, so the pin belongs to the arbiter
        // rather than to either caller. Menu input is exclusively the
        // side button below.
        #[cfg(feature = "board-techo")]
        {
            let touch = Input::new(p.P0_11, Pull::Up);
            let backlight = Output::new(p.P1_11, Level::Low, OutputDrive::Standard);
            spawner.spawn(touch_task(touch).unwrap());
            spawner.spawn(backlight_task(backlight).unwrap());

            let mut display_config = SpimConfig::default();
            display_config.frequency = Frequency::M4;
            let display_spi = Spim::new(p.SPI2, Irqs, p.P0_31, p.P1_07, p.P0_29, display_config);
            let display_cs = Output::new(p.P0_30, Level::High, OutputDrive::Standard);
            let display_dc = Output::new(p.P0_28, Level::Low, OutputDrive::Standard);
            let display_reset = Output::new(p.P0_02, Level::High, OutputDrive::Standard);
            let display_busy = Input::new(p.P0_03, Pull::None);
            spawner.spawn(
                display_task(
                    display_spi,
                    display_cs,
                    display_dc,
                    display_reset,
                    display_busy,
                )
                .unwrap(),
            );

            let button = Input::new(p.P1_10, Pull::Up);
            spawner.spawn(button_task(button).unwrap());
            spawner.spawn(shutdown_task(peripheral_power, power_enable).unwrap());

            // Quectel L76K on UARTE0. `BufferedUarte` rather than a plain
            // one because NMEA arrives as lines of unpredictable length:
            // a plain read would block until its buffer filled, holding a
            // complete sentence hostage to the start of the next one.
            //
            // TIMER1 and PPI 0/1 with group 0 are free — MPSL holds
            // TIMER0 and PPI 19/30/31, the softdevice controller holds
            // 17/18 and 20–29, and the freeze diagnostics hold TIMER2.
            let mut gnss_config = UarteConfig::default();
            gnss_config.baudrate = UarteBaudrate::Baud9600;
            static GNSS_RX: StaticCell<[u8; 256]> = StaticCell::new();
            static GNSS_TX: StaticCell<[u8; 16]> = StaticCell::new();
            let gnss_uart = BufferedUarte::new(
                p.UARTE0,
                p.TIMER1,
                p.PPI_CH0,
                p.PPI_CH1,
                p.PPI_GROUP0,
                // rxd, then txd. Measured, not taken from the variant
                // files: the module's TX — the line carrying NMEA — is
                // P1.09, the opposite of what the upstream pin names
                // suggest. See docs/hardware/lilygo-techo-hardware.md.
                p.P1_09,
                p.P1_08,
                Irqs,
                gnss_config,
                GNSS_RX.init([0; 256]),
                // Nothing is sent to this receiver: the L76K needs no
                // configuration to emit what UMSH reads. The buffer is
                // the smallest the driver will take.
                GNSS_TX.init([0; 16]),
            );
            spawner.spawn(gnss_task(gnss_uart, BoardGnss::new(p.P1_02, p.P1_05)).unwrap());
        }

        #[cfg(feature = "t1000e")]
        {
            let mut buzzer_config = SimpleConfig::default();
            buzzer_config.prescaler = Prescaler::Div16;
            let buzzer_pwm = SimplePwm::new_1ch(p.PWM0, p.P0_25, &buzzer_config);
            let buzzer_enable = Output::new(p.P1_05, Level::Low, OutputDrive::Standard);
            let initial_preferences = umsh_bsp_t1000e::preferences::load();
            spawner.spawn(
                t1000e_buzzer_task(buzzer_pwm, buzzer_enable, initial_preferences.silent).unwrap(),
            );
            // The normal power-on chirp is intentional. Early startup already
            // forced both buzzer pins low, so this is the first and only sound.
            umsh_bsp_t1000e::BUZZER_SIGNAL.signal(&buzzer_melodies::POWER_ON);

            let sensor_rail = Output::new(p.P1_06, Level::Low, OutputDrive::Standard);
            // The light sensor's own enable, downstream of the rail.
            let sensor_enable = Output::new(p.P0_04, Level::Low, OutputDrive::Standard);
            // AIN0 the battery divider, AIN5 the ambient light sensor. The
            // two are never wanted at the same instant and want opposite
            // converter configurations, so the BSP builds a single-channel
            // `Saadc` per measurement rather than scanning both.
            let external_power = Input::new(p.P0_05, Pull::Down);
            let charge_active = Input::new(p.P1_03, Pull::Up);
            spawner.spawn(
                t1000e_power_task(
                    p.SAADC,
                    p.P0_02,
                    p.P0_29,
                    sensor_rail,
                    sensor_enable,
                    external_power,
                    charge_active,
                )
                .unwrap(),
            );
            spawner.spawn(t1000e_button_task(button, force_pairing_at_boot, ux_store).unwrap());
            spawner.spawn(t1000e_shutdown_task().unwrap());

            // VRTC, main enable, sleep interrupt, reset, RTC interrupt,
            // and the stop line. All six matter: the receiver stays silent
            // if the last two are left floating.
            #[allow(unused_mut)]
            let mut gnss_control =
                BoardGnss::new(p.P0_08, p.P1_11, p.P1_12, p.P1_15, p.P0_15, p.P1_14);

            // Airoha AG3335 on UARTE0, at 115200 rather than the L76K
            // boards' 9600. `BufferedUarte` rather than a plain one because
            // NMEA arrives as lines of unpredictable length: a plain read
            // would block until its buffer filled, holding a complete
            // sentence hostage to the start of the next one.
            //
            // TIMER1 and PPI 0/1 with group 0 are free — MPSL holds TIMER0
            // and PPI 19/30/31, the softdevice controller holds 17/18 and
            // 20–29, and the freeze diagnostics hold TIMER2.
            let mut gnss_config = UarteConfig::default();
            gnss_config.baudrate = UarteBaudrate::Baud115200;
            // Twice the L76K boards' buffer. The same sentences arrive
            // twelve times faster here, and an overrun costs a whole fix
            // cycle rather than a sentence.
            static GNSS_RX: StaticCell<[u8; 512]> = StaticCell::new();
            // Big enough for the whole wake command in one pass, so
            // enabling the optional sentences is not several round trips.
            static GNSS_TX: StaticCell<[u8; 64]> = StaticCell::new();
            let gnss_uart = BufferedUarte::new(
                p.UARTE0,
                p.TIMER1,
                p.PPI_CH0,
                p.PPI_CH1,
                p.PPI_GROUP0,
                // rxd, then txd. Unlike the T-Echo, the upstream names here
                // agree with the electrical direction: `GPS_RX_PIN` is the
                // MCU's RX, and P0.14 carries NMEA. That is the same
                // reading of `GPS_RX_PIN` that turned out to be correct on
                // the T-Echo once its contradictory `PIN_SERIAL1_*` names
                // were discarded. See docs/hardware/t1000e-hardware.md.
                p.P0_14,
                p.P0_13,
                Irqs,
                gnss_config,
                GNSS_RX.init([0; 512]),
                // Used: the AG3335 persists its NMEA output selection, so
                // the BSP re-enables GSA and GSV on every wake. See
                // `umsh_bsp_t1000e::gnss`.
                GNSS_TX.init([0; 64]),
            );
            spawner.spawn(gnss_task(gnss_uart, gnss_control).unwrap());
        }

        // SenseCAP Solar battery monitor: SAADC on AIN7/P0.31, resistor
        // divider gated by P0.14 (active-low). Mirrors the T-1000E SAADC
        // configuration (12-bit, GAIN1_6, 0.6 V ref) so the BSP conversion
        // constant is comparable. No charge-detect / external-power GPIO
        // (the CN3165 exposes none); VBUS presence comes from usbregstatus.
        #[cfg(feature = "board-sensecap-solar")]
        {
            let saadc = Saadc::new(
                p.SAADC,
                Irqs,
                SaadcConfig::default(),
                [ChannelConfig::single_ended(p.P0_31)],
            );
            let divider_gate = Output::new(p.P0_14, Level::High, OutputDrive::Standard);
            spawner.spawn(sensecap_power_task(saadc, divider_gate).unwrap());

            // Quectel L76K on UARTE0, behind the one enable in this family
            // that really cuts the module's power — which on a solar node
            // is the whole point. `BufferedUarte` rather than a plain one
            // because NMEA arrives as lines of unpredictable length: a
            // plain read would block until its buffer filled, holding a
            // complete sentence hostage to the start of the next one.
            //
            // TIMER1 and PPI 0/1 with group 0 are free — MPSL holds
            // TIMER0 and PPI 19/30/31, the softdevice controller holds
            // 17/18 and 20–29, and the freeze diagnostics hold TIMER2.
            #[cfg(feature = "cap-gnss")]
            {
                let mut gnss_config = UarteConfig::default();
                gnss_config.baudrate = UarteBaudrate::Baud9600;
                static GNSS_RX: StaticCell<[u8; 256]> = StaticCell::new();
                static GNSS_TX: StaticCell<[u8; 16]> = StaticCell::new();
                let gnss_uart = BufferedUarte::new(
                    p.UARTE0,
                    p.TIMER1,
                    p.PPI_CH0,
                    p.PPI_CH1,
                    p.PPI_GROUP0,
                    // rxd, then txd. The `GPS_TX_PIN` / `GPS_RX_PIN` names
                    // on this board are the same trap as everywhere else in
                    // the family; measured, the module's output is P1.12 —
                    // the family rule that `GPS_RX_PIN` is the MCU's RX.
                    // See docs/hardware/sensecap-solar-node-p1-pro-hardware.md.
                    p.P1_12,
                    p.P1_11,
                    Irqs,
                    gnss_config,
                    GNSS_RX.init([0; 256]),
                    // Nothing is sent to this receiver: the L76K needs no
                    // configuration to emit what UMSH reads. The buffer is
                    // the smallest the driver will take.
                    GNSS_TX.init([0; 16]),
                );
                spawner.spawn(gnss_task(gnss_uart, BoardGnss::new(p.P1_05, p.P0_02)).unwrap());
            }
        }

        // XIAO nRF52840 kit peripherals. Same SAADC channel and the same
        // physical 1M/510k network as the SenseCAP Solar above, but the
        // low side is *not* a gate: P0.14 is created LOW and stays LOW
        // forever, because driving it high sits P0.31 exactly at its
        // VDD+0.3 absolute maximum and releasing it takes P0.31 to the
        // full cell voltage. Seeed's own wiki documents the rule; the
        // shipping Meshtastic build for this board violates it.
        //
        // The BQ25100 adds what the other boards here lack: HICHG (P0.13,
        // LOW = 100 mA) and ~CHG (P0.17, open-drain, LOW while charging).
        // ~CHG shares its node with the red charge LED, so it is an input
        // and nothing else. Both pins are handed to the monitor so they
        // stay asserted for the life of the program.
        //
        // No button task and no force-pairing ceremony: a stock kit has
        // no user button at all (the carrier's K1 footprint ships bare),
        // so this board is headless by construction. The shutdown task
        // still runs, but only the low-battery cutoff can reach it, and
        // it arms no wake source.
        #[cfg(feature = "board-xiao-nrf52")]
        {
            let saadc = Saadc::new(
                p.SAADC,
                Irqs,
                SaadcConfig::default(),
                [ChannelConfig::single_ended(p.P0_31)],
            );
            let divider_low = Output::new(p.P0_14, Level::Low, OutputDrive::Standard);
            let charge_status_n = Input::new(p.P0_17, Pull::None);
            // 100 mA. Sensible for anything above ~500 mAh, but it is a
            // 1C-plus rate for a small cell — the kit ships without one,
            // so the pack is whatever the user attached.
            let charge_current_hi = Output::new(p.P0_13, Level::Low, OutputDrive::Standard);
            spawner.spawn(
                xiao_power_task(saadc, divider_low, charge_status_n, charge_current_hi).unwrap(),
            );
            spawner.spawn(xiao_shutdown_task().unwrap());
        }

        // T-Echo battery monitor: SAADC on AIN2/P0.04. Same SAADC
        // configuration as the other two boards (12-bit, GAIN1_6, 0.6 V
        // ref), so only the BSP divider constant differs — this board's
        // 150k/150k bridge is hard-wired, with no gate pin to own.
        #[cfg(feature = "board-techo")]
        {
            let saadc = Saadc::new(
                p.SAADC,
                Irqs,
                SaadcConfig::default(),
                [ChannelConfig::single_ended(p.P0_04)],
            );
            spawner.spawn(techo_power_task(saadc).unwrap());
        }

        // Wio Tracker L1 peripherals: SH1106 OLED on TWIM0, nav button,
        // piezo, and the SAADC battery monitor on AIN7/P0.31 behind the
        // active-high divider gate on P0.04.
        #[cfg(feature = "board-wio-tracker-l1")]
        {
            // TWIM EasyDMA reads from SRAM, so the driver needs a static
            // scratch buffer; one frame page plus the control byte is the
            // largest transfer it makes.
            static TWIM_BUF: StaticCell<[u8; 256]> = StaticCell::new();
            let i2c = embassy_nrf::twim::Twim::new(
                p.TWISPI0,
                Irqs,
                p.P0_06, // SDA
                p.P0_05, // SCL
                embassy_nrf::twim::Config::default(),
                TWIM_BUF.init([0; 256]),
            );
            spawner.spawn(oled_display_task(display::Sh1106::new(i2c)).unwrap());

            let mut buzzer_config = SimpleConfig::default();
            buzzer_config.prescaler = Prescaler::Div16;
            let buzzer_pwm = SimplePwm::new_1ch(p.PWM0, p.P1_00, &buzzer_config);
            spawner.spawn(wio_buzzer_task(buzzer_pwm).unwrap());

            let saadc = Saadc::new(
                p.SAADC,
                Irqs,
                SaadcConfig::default(),
                [ChannelConfig::single_ended(p.P0_31)],
            );
            let divider_gate = Output::new(p.P0_04, Level::Low, OutputDrive::Standard);
            spawner.spawn(wio_power_task(saadc, divider_gate).unwrap());

            // D13 / P0.08, active-low with a pull-up (MeshCore configures
            // every button on this board as INPUT_PULLUP).
            let button = Input::new(p.P0_08, Pull::Up);
            spawner.spawn(button_task(button).unwrap());
            spawner.spawn(wio_shutdown_task().unwrap());

            // Quectel L76K on UARTE0. `BufferedUarte` rather than a plain
            // one because NMEA arrives as lines of unpredictable length:
            // a plain read would block until its buffer filled, holding a
            // complete sentence hostage to the start of the next one.
            //
            // TIMER1 and PPI 0/1 with group 0 are free — MPSL holds
            // TIMER0 and PPI 19/30/31, the softdevice controller holds
            // 17/18 and 20–29, and the freeze diagnostics hold TIMER2.
            #[cfg(feature = "cap-gnss")]
            {
                let mut gnss_config = UarteConfig::default();
                gnss_config.baudrate = UarteBaudrate::Baud9600;
                static GNSS_RX: StaticCell<[u8; 256]> = StaticCell::new();
                static GNSS_TX: StaticCell<[u8; 16]> = StaticCell::new();
                let gnss_uart = BufferedUarte::new(
                    p.UARTE0,
                    p.TIMER1,
                    p.PPI_CH0,
                    p.PPI_CH1,
                    p.PPI_GROUP0,
                    // rxd, then txd. The board notes contradict themselves
                    // about which of D6/D7 carries NMEA; measured, it is
                    // P0.26 — the family rule that `GPS_RX_PIN` is the
                    // MCU's RX, which now holds on all four boards. See
                    // docs/hardware/seeed-wio-tracker-l1-pro-hardware.md.
                    p.P0_26,
                    p.P0_27,
                    Irqs,
                    gnss_config,
                    GNSS_RX.init([0; 256]),
                    // Nothing is sent to this receiver: the L76K needs no
                    // configuration to emit what UMSH reads. The buffer is
                    // the smallest the driver will take.
                    GNSS_TX.init([0; 16]),
                );
                spawner.spawn(gnss_task(gnss_uart, BoardGnss::new(p.P1_09)).unwrap());
            }
        }

        // Dedicated power button (enclosure "PWR", P1.01) + System OFF
        // teardown. LED_A (P0.15, white) is the power-off acknowledgement
        // blinker, claimed early because the force-pairing ceremony also
        // blinks it; the heartbeat keeps LED_B (P0.19). P1.01 is the physical
        // power button (MeshCore's PIN_USER_BTN); P1.07 (enclosure "USR") is
        // the secondary user button and carries the force-pairing gesture.
        #[cfg(feature = "power-button")]
        {
            let pwr_button = Input::new(p.P1_01, Pull::Up);
            spawner.spawn(sensecap_pwr_button_task(pwr_button).unwrap());
            // LED_A passes from the boot ceremony to the task that owns it
            // for the rest of the run.
            spawner.spawn(sensecap_attention_led_task(pwr_led).unwrap());
            spawner.spawn(sensecap_usr_button_task(usr_button).unwrap());
            spawner.spawn(sensecap_shutdown_task().unwrap());
        }

        #[cfg(not(feature = "t1000e"))]
        drop(ux_store);

        super::panic::breadcrumb_mark(9);
        #[cfg(not(feature = "no-ble"))]
        join(ble_app(controller, ble_store), async {
            super::panic::breadcrumb_mark(13);
            usb.run().await
        })
        .await;
        #[cfg(feature = "no-ble")]
        {
            super::panic::breadcrumb_mark(13);
            usb.run().await;
        }
    }

    // ─── Heartbeat + WDT pet ─────────────────────────────────────────────────

    #[cfg(not(feature = "t1000e"))]
    #[embassy_executor::task]
    async fn heartbeat(mut led: Output<'static>, mut wdt: WatchdogHandle) -> ! {
        let mut engine = LedEngine::new(LedTimings::default(), Instant::now().as_millis());
        loop {
            wdt.pet();
            super::panic::breadcrumb_beat();
            // The locate alert outranks every other use of the LED,
            // including the pairing blink: someone is looking for this
            // board right now, and on a board with no buzzer the blink
            // is the entire alert.
            //
            // Not on the Solar P1, which has a second LED. There the alert
            // belongs on LED_A (white) alongside the other things meant to
            // be seen from a distance, and this one stays the status light
            // — see `sensecap_attention_led_task`.
            #[cfg(not(feature = "power-button"))]
            if alert_active() {
                engine.start_alert(Instant::now().as_millis());
            } else {
                engine.stop_alert();
            }
            // The pairing blink yields to the alert on a one-LED board,
            // where they would otherwise be fighting over the same pin. On
            // the Solar P1 they are on different LEDs and can both run.
            #[cfg(not(feature = "power-button"))]
            let alert_holds_the_led = alert_active();
            #[cfg(feature = "power-button")]
            let alert_holds_the_led = false;
            let ble_mode = BLE_LED_MODE.load(Ordering::Acquire);
            if ble_mode != 0 && !alert_holds_the_led {
                let phase = Instant::now().as_millis() % 2_000;
                let on = if ble_mode == 1 {
                    phase < 100 || (500..600).contains(&phase)
                } else {
                    phase < 100 || (200..300).contains(&phase) || (400..500).contains(&phase)
                };
                #[cfg(feature = "led-active-low")]
                if on {
                    led.set_low();
                } else {
                    led.set_high();
                }
                #[cfg(not(feature = "led-active-low"))]
                if on {
                    led.set_high();
                } else {
                    led.set_low();
                }
                Timer::after_millis(50).await;
                continue;
            }
            let decision = engine.tick(Instant::now().as_millis());
            // Active-low (T-Echo P0.14) inverts; active-high (Solar P1 LED_B
            // P0.19) drives directly.
            #[cfg(feature = "led-active-low")]
            if decision.on {
                led.set_low()
            } else {
                led.set_high()
            }
            #[cfg(not(feature = "led-active-low"))]
            if decision.on {
                led.set_high()
            } else {
                led.set_low()
            }
            // An alert edge must reach the LED without waiting out the
            // heartbeat's multi-second deadline. A `Signal` has one useful
            // consumer, so on the Solar P1 this arm is gone entirely and
            // `ALERT_CHANGED` belongs to the attention LED that shows the
            // alert — two waiters would leave whichever registered first
            // asleep through the edge.
            #[cfg(not(feature = "power-button"))]
            let _ = select(
                Timer::at(Instant::from_millis(decision.next_deadline_ms)),
                ALERT_CHANGED.wait(),
            )
            .await;
            #[cfg(feature = "power-button")]
            Timer::at(Instant::from_millis(decision.next_deadline_ms)).await;
        }
    }

    /// Ambient-sampling cadence for indicator dimming while on battery.
    /// Room light changes on the scale of minutes, and every sample
    /// cycles the sensor rail through 800 conversions, so once a minute
    /// is as often as the battery should pay for it.
    #[cfg(feature = "t1000e")]
    const AMBIENT_INTERVAL_BATTERY: Duration = Duration::from_secs(60);

    /// Cadence on external power, where the energy is free and the
    /// indicator can follow changing light closely.
    #[cfg(feature = "t1000e")]
    const AMBIENT_INTERVAL_EXTERNAL: Duration = Duration::from_secs(10);

    /// Written brightness (permille) at or below which the indicator is
    /// dark enough that the sampler's ~80 ms LED blackout is invisible.
    /// Wide enough that the charging breathe spends a comfortable window
    /// under it around each trough.
    #[cfg(feature = "t1000e")]
    const AMBIENT_NEAR_DARK_PERMILLE: u16 = 20;

    /// Request an ambient light sample when one is due and the duty just
    /// written is near-dark.
    ///
    /// The LED task drives the cadence because only it knows the
    /// animation phase: a request made at a dark phase lets the
    /// sampler's blanking handshake confirm against an LED that is
    /// already off, so the measurement never visibly interrupts what the
    /// indicator is showing — the charging breathe in particular. Every
    /// state has dark phases (heartbeat gap, breathing trough, blink
    /// gaps), so sampling is never starved for a window.
    ///
    /// Fire-and-forget: the result is read back from
    /// [`ambient_millilux`](umsh_bsp_t1000e::light::ambient_millilux)
    /// on a later iteration, so this task keeps servicing the blanking
    /// handshake while the measurement runs.
    #[cfg(feature = "t1000e")]
    fn maybe_request_ambient_sample(last_sample: &mut Option<Instant>, brightness_permille: u16) {
        if brightness_permille > AMBIENT_NEAR_DARK_PERMILLE {
            return;
        }
        // Evaluated against the current power source on every
        // opportunity, so an unplug can never carry the fast external
        // cadence onto the battery.
        let interval = if umsh_bsp_t1000e::power::usb_power_present() {
            AMBIENT_INTERVAL_EXTERNAL
        } else {
            AMBIENT_INTERVAL_BATTERY
        };
        if last_sample.is_none_or(|taken| taken.elapsed() >= interval) {
            *last_sample = Some(Instant::now());
            umsh_bsp_t1000e::light::request_sample();
        }
    }

    /// Write one LED duty, honouring the ambient-light blanking gate.
    ///
    /// Every duty write on this board goes through here so no future
    /// indicator state can accidentally light the LED during a
    /// measurement. The confirmation is raised **after** the write, so
    /// the sampler is told the LED is dark only once it actually is.
    #[cfg(feature = "t1000e")]
    fn write_led_duty(led: &mut SimplePwm<'static>, duty: u16) {
        let blanking = umsh_bsp_t1000e::indicator::blank_requested();
        let duty = if blanking { 0 } else { duty };
        led.set_duty(0, DutyCycle::inverted(duty));
        if blanking {
            umsh_bsp_t1000e::indicator::confirm_blanked();
        }
    }

    #[cfg(feature = "t1000e")]
    #[embassy_executor::task]
    async fn heartbeat(mut led: SimplePwm<'static>, mut wdt: WatchdogHandle) -> ! {
        led.set_period(1_000);
        led.enable();
        let mut engine = T1000eLedEngine::new(Instant::now().as_millis());
        // `None` at boot, so the first dark phase — within the first
        // heartbeat interval — takes the first reading.
        let mut last_ambient_sample: Option<Instant> = None;
        loop {
            wdt.pet();
            super::panic::breadcrumb_beat();
            let battery = umsh_bsp_t1000e::battery_state();
            engine.set_battery(battery);
            engine.set_attention(umsh_bsp_t1000e::indicator::attention_requested());
            engine.set_ambient_millilux(umsh_bsp_t1000e::light::ambient_millilux());
            // Outranks the pairing blink, the battery states, and the
            // one-shot sequences alike (see `T1000eLedEngine::tick`).
            if alert_active() {
                engine.start_alert(Instant::now().as_millis());
            } else {
                engine.stop_alert();
            }

            let ble_mode = BLE_LED_MODE.load(Ordering::Acquire);
            if ble_mode != 0
                && !alert_active()
                && matches!(
                    battery,
                    umsh_ux_tracker::battery::BatteryState::BatteryOnly
                        | umsh_ux_tracker::battery::BatteryState::BatteryCharged
                )
            {
                let phase = Instant::now().as_millis() % 2_000;
                let on = if ble_mode == 1 {
                    phase < 100 || (500..600).contains(&phase)
                } else {
                    phase < 100 || (200..300).contains(&phase) || (400..500).contains(&phase)
                };
                // This branch bypasses the engine, so it applies the
                // ambient dim itself — the connection blink dims with
                // the room like everything else.
                let brightness = if on {
                    umsh_ux_tracker::led::ambient_dim_permille(
                        umsh_bsp_t1000e::light::ambient_millilux(),
                    )
                } else {
                    0
                };
                let duty = ((u32::from(led.max_duty()) * u32::from(brightness)) / 1_000) as u16;
                write_led_duty(&mut led, duty);
                maybe_request_ambient_sample(&mut last_ambient_sample, brightness);
                match select(
                    Timer::after_millis(50),
                    umsh_bsp_t1000e::indicator::LED_BLANK_CHANGED.wait(),
                )
                .await
                {
                    Either::First(()) | Either::Second(()) => {}
                }
                continue;
            }

            let decision = engine.tick(Instant::now().as_millis());
            let duty =
                ((u32::from(led.max_duty()) * u32::from(decision.brightness)) / 1_000) as u16;
            write_led_duty(&mut led, duty);
            maybe_request_ambient_sample(&mut last_ambient_sample, decision.brightness);
            match select(
                select4(
                    select(
                        Timer::at(Instant::from_millis(decision.next_deadline_ms)),
                        ALERT_CHANGED.wait(),
                    ),
                    umsh_bsp_t1000e::BATTERY_STATE_CHANGED.wait(),
                    umsh_bsp_t1000e::indicator::INDICATOR_CHANGED.wait(),
                    umsh_bsp_t1000e::indicator::LED_SEQUENCE_SIGNAL.wait(),
                ),
                // An ambient light measurement wants the LED dark, and
                // wants it now — it waits on the confirmation below.
                umsh_bsp_t1000e::indicator::LED_BLANK_CHANGED.wait(),
            )
            .await
            {
                Either::First(Either4::First(_))
                | Either::First(Either4::Second(_))
                | Either::First(Either4::Third(()))
                | Either::Second(()) => {}
                Either::First(Either4::Fourth(sequence)) => {
                    engine.play(sequence, Instant::now().as_millis());
                }
            }
        }
    }
}
