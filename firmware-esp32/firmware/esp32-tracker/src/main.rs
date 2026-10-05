//! ULCP firmware for the ESP32 tracker boards (Heltec LoRa 32 V2/V3,
//! LILYGO T-Beam Supreme), selected by `board-*` features.
//!
//! The protocol brain is the shared board-agnostic driver
//! (`umsh_ulcp_runtime::driver`)—the same session loop the T-Echo
//! and T-1000E images run—behind each board's couplings:
//!
//! - **Wired transport**: HDLC-framed CRP on the board's serial port—
//!   UART0 behind a CP2102 bridge on the Heltecs, the native
//!   USB-Serial-JTAG peripheral where `wired-usb-serial-jtag` is on.
//!   Attachment is lazy: the first valid HDLC frame attaches. Native
//!   USB detaches when VBUS disappears; UART bridges cannot detect
//!   host disconnection. A board nobody serials into stays detached
//!   and autonomous.
//! - **BLE transport**: the `UlcpService` GATT shape over the
//!   esp-radio controller, with the same pairing/bonding lattice the
//!   Phase 4 spike hardware-proved (PIN on the OLED, lockout policy,
//!   durable bonds through `umsh_journal_store`). All of it is `ble.rs`.
//! - **Radio**: the board's LoRa modem behind `device_runner` +
//!   `radio_mux`; the session (client A) and the on-board device node
//!   (client B) share the physical radio and one duty ledger.
//! - **Persistence**: snapshot / identity / counter journals in the
//!   `umsh` partition tail (see `journals.rs`).
//!
//! On a `pmic-axp2101` board there is also **power**: everything
//! interesting sits behind an AXP2101 rail, battery telemetry is the
//! PMIC's own (with a real charge state), and power-off is a PMIC
//! operation rather than deep sleep—the POWER key brings the board
//! back with no firmware involved. `gnss` adds the shared `umsh_gnss`
//! pump on UART1, and `rtc-pcf8563` a hardware wall clock read at boot
//! and written back when a trusted source steps the time.
//!
//! ## Boot order is constrained
//!
//! On a `pmic-axp2101` board the PMU comes up before everything: until
//! its rails are configured, the radio, panel, and receiver are dark,
//! and probing them reports parts missing that are merely unpowered.
//! A radio brought up just for the purpose supplies hardware entropy
//! when the seed journal needs bootstrapping. Operational radios can
//! sleep or be disabled; the node uses CSPRNGs seeded from the persisted
//! pool, which `entropy.rs` keeps fed for as long as the board stays up.
//! Journals mount before the ULCP session starts so a stored snapshot
//! is restored (and the PHY re-applied) before the first host command.
//!
//! ## The console shares the wire, so it goes quiet
//!
//! `esp-println` shares the wired transport's port (UART0, or the
//! USB-Serial-JTAG peripheral). Boot diagnostics interleave cleanly
//! before the port is claimed; after that, nothing may `println!`. The
//! `debug-log` feature multiplexes diagnostic lines onto the wired
//! output stream as ASCII (HDLC hosts resynchronize past them),
//! mirroring the nRF image's ble-debug.

#![no_std]
#![no_main]
#![cfg_attr(
    all(feature = "wifi", feature = "debug-log"),
    feature(asm_experimental_arch)
)]

extern crate alloc;

use core::fmt::Write as _;
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
use core::sync::atomic::AtomicU8;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use embassy_embedded_hal::shared_bus::asynch::i2c::I2cDevice;

#[cfg(feature = "board-tbeam-supreme")]
mod bme280;
use embassy_executor::Spawner;
use embassy_futures::select::{Either, Either3, Either4, select, select3, select4};
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_sync::once_lock::OnceLock;
use embassy_sync::signal::Signal;
use embassy_sync::watch::Watch;
use embassy_time::{Delay, Duration, Instant, Timer, with_timeout};
#[cfg(not(feature = "board-tlora-pager"))]
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_hal::Async;
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Event, Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::rtc_cntl::{Rtc, RwdtStage, SocResetReason};
use esp_hal::spi::Mode;
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::uart::{Config as UartConfig, Uart};
#[cfg(not(feature = "wired-usb-serial-jtag"))]
use esp_hal::uart::{UartRx, UartTx};
#[cfg(feature = "wired-usb-serial-jtag")]
use esp_hal::usb::usb_serial_jtag::{UsbSerialJtag, UsbSerialJtagRx, UsbSerialJtagTx};
use esp_println::println;
use lora_phy::LoRa;
use static_cell::StaticCell;

use umsh_bsp_esp32::flash_store;
// The board BSP, under one name whatever the board. Every board-specific
// pin, peripheral, and radio type reaches this file through `board`.
#[cfg(feature = "board-heltec-v2")]
use umsh_bsp_heltec_lora32_v2 as board;
#[cfg(feature = "board-heltec-v3")]
use umsh_bsp_heltec_lora32_v3 as board;
#[cfg(feature = "board-tbeam-supreme")]
use umsh_bsp_tbeam_supreme as board;
#[cfg(feature = "board-tlora-pager")]
use umsh_bsp_tlora_pager as board;

#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
use board::battery as board_battery;
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
use board::battery::BatterySampler;
#[cfg(feature = "display-sh1106")]
use board::display;
#[cfg(any(feature = "display-sh1106", feature = "display-st7796"))]
use board::display::{Brightness, Display, brightness_from_permille};
// `DisplayConfigAsync` is the ssd1306 trait carrying `init()`.
#[cfg(not(any(feature = "display-sh1106", feature = "display-st7796")))]
use board::display::{
    self, Brightness, Display, DisplayConfigAsync as _, brightness_from_permille,
};
#[cfg(feature = "pmic-axp2101")]
use board::gnss::{PmuI2cDevice, SharedPmic};
#[cfg(feature = "pmic-axp2101")]
use board::power as board_power;
use board::radio as board_radio;
// Boards whose `Vext` also gates the battery divider share one rail
// between the display task and the sampler, so their handle is `Copy`
// rather than an owned pin; the API surface is otherwise identical.
// PMIC boards have no `Vext` at all—the panel's rail belongs to the
// AXP2101 and drops in the shutdown path instead.
#[cfg(feature = "board-tlora-pager")]
use board::I2cHandle as PmuI2cDevice;
#[cfg(not(any(
    feature = "vext-gates-battery",
    feature = "pmic-axp2101",
    feature = "board-tlora-pager"
)))]
use board::vext::Vext;
#[cfg(feature = "vext-gates-battery")]
use board::vext::VextHandle as Vext;
#[cfg(not(feature = "psram"))]
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
#[cfg(feature = "board-tlora-pager")]
use umsh_pager_peripherals::rtc::Pcf85063 as RtcChip;
#[cfg(feature = "pmic-axp2101")]
use umsh_pmic_axp2101::{Axp2101, ChargeDirection, ChargeState, IrqMask};
use umsh_radio_loraphy::{DeviceControl, MAX_PAYLOAD};
#[cfg(feature = "rtc-pcf8563")]
use umsh_rtc_pcf8563::Pcf8563 as RtcChip;
use umsh_ulcp::stats::{Counter, StatsLedger};
use umsh_ulcp::{Status, hdlc};
#[cfg(feature = "gnss")]
use umsh_ulcp_device::GnssConfig;
#[cfg(feature = "external-rtc")]
use umsh_ulcp_device::TimeConfig;
use umsh_ulcp_device::{BatteryFields, MAX_DEVICE_NAME_LEN, RadioSettings, SessionConfig};
use umsh_ulcp_runtime::driver::{
    self, DeviceEnv, DeviceRuntime, InEvent, InputChannel, Setting, TransportChannels,
};
use umsh_ulcp_runtime::{radio_mux, transport_policy};
use umsh_ux_display_tracker::attention::{
    Attention, AttentionConfig, DisplayKind, HoldReason, Transition,
};
#[cfg(not(feature = "board-tlora-pager"))]
use umsh_ux_display_tracker::gate::{Disposition, Gate, GateReason};
use umsh_ux_display_tracker::menu::MenuItem;
use umsh_ux_display_tracker::menu::{MenuItems, ToggleId, UiEffect, UiInput, UiModel, UiNotice};
use umsh_ux_display_tracker::screen;
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
use umsh_ux_tracker::battery::ChargeClass;
#[cfg(not(feature = "board-tlora-pager"))]
use umsh_ux_tracker::battery::soc_from_ocv;
#[cfg(not(feature = "board-tlora-pager"))]
use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm};

use transport_policy::{Transport, generation_checked};

// One facade, two bodies: the transport, or its absence.
#[cfg_attr(not(feature = "ble"), path = "ble_stub.rs")]
mod ble;
#[cfg(feature = "bridge-client")]
mod bridge;
mod device_node;
mod entropy;
#[cfg(feature = "psram")]
mod external;
#[cfg(feature = "wifi")]
mod ip;
mod journals;
#[cfg(feature = "board-tlora-pager")]
mod pager;
#[cfg(feature = "chip-esp32s3")]
mod temperature;
#[cfg(feature = "wifi")]
mod wifi;
#[cfg(all(feature = "wifi", feature = "debug-log"))]
mod wifi_memory;
#[cfg(all(feature = "wifi", not(feature = "chip-esp32s3")))]
compile_error!("WiFi requires an ESP32-S3 target");
#[cfg(all(feature = "wifi", feature = "ble", not(feature = "coex")))]
compile_error!("WiFi alongside Bluetooth needs the `coex` feature: build with `wifi,coex`");
// The chip's TRNG is true-random only while RF is live, so an image with
// no radio driver could never bootstrap its entropy pool.
#[cfg(not(any(feature = "wifi", feature = "ble")))]
compile_error!("enable `ble` or `wifi`: with neither radio there is no trusted entropy source");
#[cfg(all(
    feature = "psram",
    not(any(feature = "board-tbeam-supreme", feature = "board-tlora-pager"))
))]
compile_error!("PSRAM wiring is only defined for T-Beam Supreme and T-LoRa Pager");

#[cfg(feature = "wifi")]
type SnapshotStore = umsh_ulcp_runtime::wifi_journal::WifiStore<
    embassy_sync::blocking_mutex::raw::NoopRawMutex,
    journals::JournalFlash,
>;
#[cfg(feature = "wifi")]
type BootSnapshot = umsh_ulcp_runtime::wifi_journal::BootPayload;
#[cfg(not(feature = "wifi"))]
type SnapshotStore = journals::ProtoStore;
#[cfg(not(feature = "wifi"))]
type BootSnapshot = journals::BootPayload;

/// The session sizes its snapshots and the journal sizes its records
/// independently. This is where the two meet, so it is where a snapshot
/// growing past what a record can carry is caught.
const _: () = assert!(
    umsh_ulcp_device::SNAPSHOT_MAX <= SnapshotStore::MAX_PAYLOAD,
    "SNAPSHOT_MAX outgrew what a journal record can carry"
);

use journals::ProtoStore;

esp_bootloader_esp_idf::esp_app_desc!();

// ─── Configuration ───────────────────────────────────────────────────────

/// RWDT timeout. The PMIC board runs a longer leash: its heartbeat's
/// feed cadence is the ceiling on light-sleep residency (the RWDT runs
/// through light sleep and the feed is a timer wake), so the pair is
/// 20 s feeds under a 30 s timeout there, against the Heltecs' 4 s LED
/// blink under the original 8 s.
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);
#[cfg(feature = "pmic-axp2101")]
const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(30);
/// PMIC-board heartbeat cadence; see [`WDT_TIMEOUT`].
#[cfg(feature = "pmic-axp2101")]
const HEARTBEAT_FEED_SECS: u64 = 20;

/// SX1262 PA limits on this module.
#[cfg(feature = "radio-sx126x")]
const MIN_TX_POWER_DBM: i8 = -9;
#[cfg(feature = "radio-sx126x")]
const MAX_TX_POWER_DBM: i8 = 22;

/// SX1276 PA limits. The antenna is on the PA_BOOST port and the BSP
/// configures `tx_boost: true`, which is the [2, 20] dBm path in the
/// driver—the RFO path's [-4, 14] range is unreachable on this board.
/// Above 17 dBm the driver switches PA_DAC to its 20 dBm mode and raises
/// OCP to 240 mA, so the top of this range is duty-limited in practice.
#[cfg(feature = "radio-sx127x")]
const MIN_TX_POWER_DBM: i8 = 2;
#[cfg(feature = "radio-sx127x")]
const MAX_TX_POWER_DBM: i8 = 20;

#[cfg(feature = "board-heltec-v2")]
const DEFAULT_DEVICE_NAME: &str = "UMSH Heltec V2";
#[cfg(feature = "board-heltec-v3")]
const DEFAULT_DEVICE_NAME: &str = "UMSH Heltec V3";
#[cfg(feature = "board-tbeam-supreme")]
const DEFAULT_DEVICE_NAME: &str = "UMSH T-Beam";
#[cfg(feature = "board-tlora-pager")]
const DEFAULT_DEVICE_NAME: &str = "UMSH Pager";
#[cfg(feature = "board-tlora-pager")]
const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);

/// `PROP_DEV_VERSION`: the stack name and the release version from the
/// build script, in the `STACK-NAME/STACK-VERSION` form the spec
/// recommends. Which board it runs on is `PROP_DEV_MODEL`'s job.
const DEV_VERSION: &str = concat!("umsh/", env!("GIT_DESCRIBE"));

/// `PROP_DEV_MODEL`: the hardware this image was built for, matching the
/// board id used by the release manifest and `site/data/hardware.toml`
/// (`heltec-v2` / `heltec-v3` / `tbeam-supreme`).
const DEV_MODEL: &str = board::BOARD_NAME;

/// The board default name plus a stable per-die suffix—the low 16
/// bits of the factory eFuse MAC, the same die-unique value the BLE
/// identity address is built from—so factory-fresh radios are
/// tellable apart in scan lists and on multi-board benches.
fn default_device_name() -> &'static str {
    static NAME: OnceLock<heapless09::String<24>> = OnceLock::new();
    NAME.get_or_init(|| {
        let mac = base_mac_bytes();
        let suffix = u16::from_be_bytes([mac[4], mac[5]]);
        let mut name = heapless09::String::new();
        let _ = write!(name, "{DEFAULT_DEVICE_NAME} {suffix:04X}");
        name
    })
    .as_str()
}

/// The factory eFuse base MAC, as its six raw bytes.
fn base_mac_bytes() -> [u8; 6] {
    esp_hal::efuse::base_mac_address()
        .as_bytes()
        .try_into()
        .expect("EUI-48 base MAC")
}

const TX_PREAMBLE_SYMBOLS: u16 = 32;

fn session_config() -> SessionConfig {
    SessionConfig {
        dev_version: DEV_VERSION,
        dev_model: Some(DEV_MODEL),
        default_device_name: default_device_name(),
        mtu: MAX_PAYLOAD as u16,
        tx_preamble_symbols: TX_PREAMBLE_SYMBOLS,
        // Fixed at build time: LoRa::new(.., false, ..) below sets the
        // private-network word 0x12. `PROP_PHY_LORA_SW` is defined as
        // the 16-bit SX126x-style word whatever the silicon, so both
        // radio families report the same 0x1424 here.
        sync_word: umsh_ulcp::profiles::DEFAULT.sync_word,
        min_tx_power_dbm: MIN_TX_POWER_DBM,
        max_tx_power_dbm: MAX_TX_POWER_DBM,
        // Chip tunable range. Wider than any one module's matching
        // network—the operator is responsible for staying legal and
        // for what the antenna path can actually radiate.
        #[cfg(feature = "radio-sx126x")]
        freq_khz_min: 150_000,
        #[cfg(feature = "radio-sx126x")]
        freq_khz_max: 960_000,
        #[cfg(feature = "radio-sx127x")]
        freq_khz_min: 137_000,
        #[cfg(feature = "radio-sx127x")]
        freq_khz_max: 1_020_000,
        // Post-reset defaults: the vetted default profile, with the PHY
        // disabled until the host enables it.
        defaults: RadioSettings {
            enabled: false,
            freq_khz: umsh_ulcp::profiles::DEFAULT.freq_khz,
            bw_hz: umsh_ulcp::profiles::DEFAULT.bw_hz,
            sf: umsh_ulcp::profiles::DEFAULT.sf,
            cr_denom: umsh_ulcp::profiles::DEFAULT.cr_denom,
            tx_power_dbm: umsh_ulcp::profiles::DEFAULT_TX_POWER_DBM
                .clamp(MIN_TX_POWER_DBM, MAX_TX_POWER_DBM),
        },
        default_duty_limit: umsh_ulcp::profiles::DEFAULT.duty_limit,
        duty: &DUTY_LEDGER,
        battery_diagnostics: if cfg!(feature = "board-tlora-pager") {
            umsh_ulcp::battery_diagnostics::Fields::DIAGNOSTICS
                .union(umsh_ulcp::battery_diagnostics::Fields::GAUGE_CONFIG)
                .union(umsh_ulcp::battery_diagnostics::Fields::GAUGE_TELEMETRY)
        } else {
            Default::default()
        },
        // Battery-powered board with an ADC divider but no
        // charger-status signal (the charge LED is charger-driven), so
        // voltage and the OCV level estimate are reported and charge
        // state is not advertised.
        #[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
        battery: Some(BatteryFields {
            voltage: true,
            level: true,
            charge_state: false,
        }),
        // The AXP2101 measures its own battery terminal, runs a fuel
        // gauge, and knows which way current is flowing—the first
        // ESP32 board that can advertise all three fields.
        #[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
        battery: Some(BatteryFields {
            voltage: true,
            level: true,
            charge_state: true,
        }),
        #[cfg(feature = "board-tlora-pager")]
        alert: Some(umsh_ulcp_device::AlertConfig::DEFAULT),
        #[cfg(not(feature = "board-tlora-pager"))]
        alert: None,
        // No clock. A permanently-wired bench board reads the time from
        // the host it is wired to.
        #[cfg(not(feature = "external-rtc"))]
        time: None,
        // A hardware RTC holds the time across power-off and the
        // receiver can set it: `CAP_TIME` rests on a real clock.
        #[cfg(feature = "external-rtc")]
        time: Some(TimeConfig),
        #[cfg(not(feature = "gnss"))]
        gnss: None,
        // The receiver stays off until asked—a battery board, not a
        // fixed outdoor node.
        #[cfg(feature = "gnss")]
        gnss: Some(GnssConfig::DEFAULT),
        // No ambient light sensor.
        display_motion_wake: cfg!(all(
            feature = "board-tlora-pager",
            not(feature = "motion-qualification")
        )),
        illuminance: false,
        temperatures: cfg!(feature = "chip-esp32s3"),
        // The ESP32-S3 radio is always up on this board, but the
        // peripheral can be made unfindable: see `advertising_permitted`.
        // An image built without the transport claims none of it.
        ble: cfg!(feature = "ble"),
        // The bond journal and the pairing window are the same as the
        // nRF boards'; both commands reach the machinery the front-panel
        // menu already drives.
        ble_pairing: cfg!(feature = "ble"),
        ble_pin: cfg!(feature = "ble"),
        // The SoC restarts on command; see the `reboot` hook below.
        reboot: true,
        // A real MAC runs behind this session.
        mac_node: true,
        // These chips have the radio, but nothing here drives it yet:
        // the capability is a promise about the property surface, and
        // claiming it before there is a station to serve it would be a
        // device answering for hardware it is not using.
        #[cfg(feature = "wifi")]
        wifi: Some(wifi::CONFIG),
        #[cfg(feature = "wifi")]
        ip: Some(umsh_ulcp_device::net::IpConfig {
            manual_dns: false,
            ..umsh_ulcp_device::net::IpConfig::V4_ONLY
        }),
        #[cfg(not(feature = "wifi"))]
        wifi: None,
        #[cfg(not(feature = "wifi"))]
        ip: None,
        bridge_client: cfg!(feature = "bridge-client"),
        stats: Some(&STATS),
        #[cfg(feature = "ulcp-i2c")]
        i2c_buses: board::i2c::BUSES,
        #[cfg(not(feature = "ulcp-i2c"))]
        i2c_buses: &[],
        i2c_devices: &[],
    }
}

/// The one duty ledger shared by every radio client: the session prices
/// and records its own transmissions here, and the device node's radio
/// path admits each transmit against the same combined budget
/// (`duty_gate`), so `PROP_PHY_DUTY_LIMIT` bounds session + node
/// airtime together and `PROP_PHY_DUTY_NOW` reports the combined figure.
pub(crate) static DUTY_LEDGER: umsh_ulcp_device::DutyLedger = umsh_ulcp_device::DutyLedger::new();

// ─── Concrete types ──────────────────────────────────────────────────────

/// The ULCP session instantiated with this firmware's crypto providers
/// (software AES/SHA; Ed25519 comes in only through the device-identity
/// provisioning path). The TX queue capacity matches the nRF images:
/// the physical radio remains single-flight, but the protocol session
/// can retain several host frames so a LoRa completion round trip is
/// not imposed between fragments.
#[cfg(feature = "chip-esp32s3")]
const ULCP_TX_QUEUE_CAPACITY: usize = 8;
/// Halved on the classic ESP32: each staged frame is RAM the 128 KiB
/// `dram_seg` cannot spare, and the CP2102 link this depth was sized for
/// still gets four frames of pipelining.
#[cfg(feature = "chip-esp32")]
const ULCP_TX_QUEUE_CAPACITY: usize = 4;
type Session = umsh_ulcp_device::Session<SoftwareAes, SoftwareSha256, ULCP_TX_QUEUE_CAPACITY>;

/// The CSPRNG behind everything seeded from the entropy pool at boot:
/// ChaCha20, rekeyed whenever `entropy.rs` has a fresh harvest for it.
type IdentityRng = umsh_ulcp_runtime::reseed::ReseedingRng;

// ─── Static shared state ─────────────────────────────────────────────────

/// Channels shared between the radio runner and the radio mux, which
/// is the runner's only client.
type RadioCh = umsh_radio_loraphy::Channels<CriticalSectionRawMutex, 4, 2>;
static RADIO_CH: RadioCh = RadioCh::new();

/// The session's virtual radio endpoint (mux client A). The device
/// node's endpoint (client B) lives in `device_node::NODE_CH`.
static SESSION_CH: RadioCh = RadioCh::new();
static MUX_CLIENTS: [&RadioCh; 2] = [&SESSION_CH, &device_node::NODE_CH];

/// Runtime radio settings pushed by the session to the runner.
static DEVICE_CTL: DeviceControl<CriticalSectionRawMutex> = DeviceControl::new();

/// The one traffic ledger for the whole device.
///
/// The mux is where every real transmit and every off-air reception passes
/// exactly once, so that is where the air counters are kept—counting at
/// the MAC would miss everything the session sends, which on a
/// phone-attached tracker is most of it. The runner adds the CRC failures
/// it alone can see, and the node's pump mirrors the four figures only the
/// MAC knows.
pub(crate) static STATS: StatsLedger = StatsLedger::new();

/// Framing-free receive path and connection edges into the shared
/// ULCP driver (`InEvent`/`FrameBuf` and the queue types live there).
static INPUT_CH: InputChannel<CriticalSectionRawMutex> = InputChannel::new();
#[cfg(feature = "ble")]
type FrameBuf = driver::FrameBuf;
const FRAME_IN_MAX: usize = driver::FRAME_IN_MAX;

/// Outbound frame queues: `wired` drained by output_task (UART0), `ble`
/// by the GATT connection writer.
static OUT_CH: TransportChannels<CriticalSectionRawMutex> = TransportChannels::new();

/// Published session epoch, checked by each transport at framing edges.
static SESSION_GEN: AtomicU32 = AtomicU32::new(0);

type DeviceName = heapless::Vec<u8, { MAX_DEVICE_NAME_LEN }>;
static DEVICE_NAME: Mutex<CriticalSectionRawMutex, DeviceName> = Mutex::new(DeviceName::new());
static DEVICE_NAME_READY: AtomicBool = AtomicBool::new(false);

/// Snapshot the live device name for the device node's advertisements.
/// Falls back to the (eFuse-suffixed) default until the session
/// publishes a name at boot.
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

/// Heltec V2 only: arbitration for ADC2, which the classic ESP32 shares
/// exclusively between the radio and the battery divider. The battery
/// task holds this across a sample; the BLE supervisor holds it across
/// controller bring-up, so `Adc::new` and esp-radio init can never race
/// each other's claim. [`ADC2_RADIO_UP`] says which way the claim went.
#[cfg(feature = "board-heltec-v2")]
static ADC2_ARBITER: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());
#[cfg(feature = "board-heltec-v2")]
static ADC2_RADIO_UP: AtomicBool = AtomicBool::new(false);

/// Whether USB power is present, per the PMIC's last word (its IRQ
/// pokes an immediate re-read on plug/unplug, so this trails the cable
/// by milliseconds). Starts optimistic so the wired console exists
/// from the first instruction of a USB-powered boot; the first reading
/// corrects a battery boot.
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
static VBUS_PRESENT: AtomicBool = AtomicBool::new(true);
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
static VBUS_EDGE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// OLED redraw trigger for content that changed without the user asking
///—a battery sample, a bond count. Deliberately *not* a wake event:
/// the battery is sampled on a timer, so a redraw that woke the panel
/// would keep it lit forever.
static UI_REFRESH: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// How many frames the session is holding for an absent host, for the
/// status page to draw. This board has no sounder, so the count is the
/// whole indication.
static QUEUED_FRAMES: AtomicU16 = AtomicU16::new(0);
/// The user is here, or wants to be: a button press, a BLE link
/// transition. Restarts the display-attention timeout and relights a
/// panel that has gone dark.
static UI_WAKE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Motion has its own notification and never extends an active/dim timeout.
async fn motion_wake() {
    #[cfg(all(feature = "board-tlora-pager", not(feature = "motion-qualification")))]
    loop {
        let wake = pager::motion::SERVICE.display_wake.wait().await;
        if pager::motion::SERVICE.accept(wake, Instant::now().as_millis()) {
            return;
        }
    }
    #[cfg(any(not(feature = "board-tlora-pager"), feature = "motion-qualification"))]
    core::future::pending::<()>().await;
}
/// Resolved menu gestures, button task → display task.
static UI_INPUT_CH: Channel<CriticalSectionRawMutex, UiInput, 8> = Channel::new();
/// Latched at the first press, including before display initialization.
static BOOT_SPLASH_ACTIVE: AtomicBool = AtomicBool::new(true);
static UI_SPLASH_DISMISS: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// Result of a menu action, to be shown on the status page.
static UI_NOTICE: Signal<CriticalSectionRawMutex, UiNotice> = Signal::new();
/// Whether the panel has faded—dimming toward its floor, resting
/// there, or powered off. Published by the display task; read by the
/// button task, which gates a gesture on the state at the press that
/// began it, so a press that answers the fade brings the panel back and
/// goes no further.
static SCREEN_FADED: AtomicBool = AtomicBool::new(false);
/// The four-second power-off hold fired: button task → heartbeat task,
/// which owns the shutdown sequence (deep sleep through its `Rtc`, or
/// a PMIC power-off on `pmic-axp2101` boards).
static SHUTDOWN_REQUEST: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// Shutdown sequence → display task. Distinct from `SHUTDOWN_REQUEST`
/// so the two consumers cannot race for one signal: whichever awaited
/// first would consume it and leave the other waiting forever.
static DISPLAY_SHUTDOWN: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// The display task has rendered its farewell and powered the panel
/// down (dropping `Vext` where it owns the rail).
static DISPLAY_SHUTDOWN_DONE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// Last battery sample in millivolts (0 = never sampled). Display only.
static BATTERY_MV: AtomicU16 = AtomicU16::new(0);
/// Last battery level percent (0xFF = unknown). Display only.
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
static BATTERY_LEVEL: AtomicU8 = AtomicU8::new(0xFF);
/// Last charge classification: 0 unknown, 1 discharging, 2 charging,
/// 3 charged. Display only.
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
static BATTERY_CHARGE: AtomicU8 = AtomicU8::new(0);
/// Battery request/reply pair between the session env and the sampler
/// task, which owns the ADC (or the PMIC telemetry cadence).
static BATTERY_REQUEST: Signal<CriticalSectionRawMutex, ()> = Signal::new();
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
static BATTERY_REPLY: Signal<CriticalSectionRawMutex, u16> = Signal::new();
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
static BATTERY_REPLY: Signal<CriticalSectionRawMutex, board_battery::Reading> = Signal::new();
/// Readings worth announcing to a remote observer, for unsolicited
/// `PROP_BATTERY` publication. A `Watch` rather than a `Signal`: the
/// driver's select drops and re-creates the wait on every other
/// iteration, and a receiver must not lose an update to that.
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
static BATTERY_ANNOUNCE: Watch<CriticalSectionRawMutex, u16, 1> = Watch::new();
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
static BATTERY_ANNOUNCE: Watch<CriticalSectionRawMutex, board_battery::Reading, 1> = Watch::new();

// Keep Pager diagnostics compact enough to preserve the required stack reserve.
// Best-effort diagnostics may be truncated; sensing never depends on logging.
#[cfg(all(feature = "debug-log", feature = "board-tlora-pager"))]
const DEBUG_LINE_CAPACITY: usize = if cfg!(feature = "motion-qualification") {
    176
} else {
    64
};
#[cfg(all(feature = "debug-log", not(feature = "board-tlora-pager")))]
const DEBUG_LINE_CAPACITY: usize = 192;
#[cfg(feature = "debug-log")]
type DebugLine = heapless::String<DEBUG_LINE_CAPACITY>;
#[cfg(all(feature = "debug-log", feature = "board-tlora-pager"))]
const DEBUG_QUEUE_CAPACITY: usize = if cfg!(feature = "motion-qualification") {
    2
} else {
    1
};
#[cfg(all(feature = "debug-log", not(feature = "board-tlora-pager")))]
const DEBUG_QUEUE_CAPACITY: usize = 32;
#[cfg(feature = "debug-log")]
static DEBUG_CH: Channel<CriticalSectionRawMutex, DebugLine, DEBUG_QUEUE_CAPACITY> = Channel::new();
#[cfg(feature = "debug-log")]
static DEBUG_DROPPED: AtomicU32 = AtomicU32::new(0);

pub(crate) fn debug_log(args: core::fmt::Arguments<'_>) {
    #[cfg(feature = "debug-log")]
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
    #[cfg(not(feature = "debug-log"))]
    let _ = args;
}

// ─── Outgoing frame limits ───────────────────────────────────────────────

const WIRE_MAX: usize = hdlc::max_encoded_len(driver::FRAME_OUT_MAX);

// ─── Device-node counter persistence ─────────────────────────────────────

/// The device node's persisted frame counters, bound to this board's
/// flash. The map, the journal handle, and the `CounterStore` impl are
/// shared (`umsh_ulcp_runtime::node_counters`); only the mutex kinds,
/// the flash type, and the journal's page are this board's.
pub type NodeCounters =
    umsh_ulcp_runtime::node_counters::NodeCounters<NoopRawMutex, journals::JournalFlash>;
pub type NodeCountersMutex = umsh_ulcp_runtime::node_counters::NodeCountersMutex<
    CriticalSectionRawMutex,
    NoopRawMutex,
    journals::JournalFlash,
>;
pub type NodeCounterStore = umsh_ulcp_runtime::node_counters::NodeCounterStore<
    CriticalSectionRawMutex,
    NoopRawMutex,
    journals::JournalFlash,
>;

static NODE_COUNTERS_CELL: StaticCell<NodeCountersMutex> = StaticCell::new();

/// Initialize the (still journal-less) counter state. Call exactly
/// once, early in boot; the journal attaches with
/// [`mount_node_counters`] before the device node comes up.
fn init_node_counters() -> &'static NodeCountersMutex {
    NODE_COUNTERS_CELL.init(Mutex::new(NodeCounters::new()))
}

/// Mount the counter journal and load the persisted map.
async fn mount_node_counters(
    counters: &'static NodeCountersMutex,
    flash: &'static journals::SharedFlash,
    page0: u32,
) {
    umsh_ulcp_runtime::node_counters::mount(counters, flash, page0).await
}

async fn prune_stale_tx_counters(counters: &'static NodeCountersMutex, public_key: &[u8; 32]) {
    umsh_ulcp_runtime::node_counters::prune_stale_tx(counters, public_key).await
}

async fn clear_node_counters(counters: &'static NodeCountersMutex) {
    umsh_ulcp_runtime::node_counters::clear(counters).await
}

// ─── The PMU bus: PMIC + RTC ─────────────────────────────────────────────

/// The PMU I²C controller, shared by the AXP2101 and the PCF8563
/// through per-device `I2cDevice` handles.
#[cfg(feature = "pmic-axp2101")]
type PmuBus = Mutex<CriticalSectionRawMutex, I2c<'static, Async>>;
#[cfg(feature = "pmic-axp2101")]
static PMU_BUS: StaticCell<PmuBus> = StaticCell::new();

/// The one AXP2101, shared by the battery task, the PMU IRQ task, the
/// GNSS power control, and the shutdown path.
#[cfg(feature = "pmic-axp2101")]
static PMIC_CELL: StaticCell<SharedPmic> = StaticCell::new();

/// The PCF8563. Read once at boot, then handed to the session's
/// [`BoardDeviceEnv`]—the only thing that ever writes it back.
///
/// Deliberately not a global: esp-hal's `Async` peripherals are `!Send`
/// by design (they belong to the executor that drives them), so the
/// handle travels as a task argument rather than through a static.
#[cfg(feature = "external-rtc")]
type RtcMutex = Mutex<CriticalSectionRawMutex, RtcChip<PmuI2cDevice>>;
#[cfg(feature = "external-rtc")]
static RTC_CELL: StaticCell<RtcMutex> = StaticCell::new();

/// Write a stepped wall clock back to the RTC, so the time the board
/// wakes up with is the time it went down with. Best-effort: a refused
/// write costs the writeback, not the clock.
#[cfg(feature = "external-rtc")]
async fn rtc_writeback(rtc: &'static RtcMutex, epoch: u32) {
    if rtc.lock().await.write(epoch).await.is_err() {
        debug_log(format_args!("rtc: writeback FAILED"));
    }
}

// ─── Battery sampling ────────────────────────────────────────────────────

/// Smallest level movement worth announcing, in percentage points.
///
/// This board's level is a direct OCV-table lookup rather than the
/// quantized `LevelEstimator` output, so it drifts by a point or two on
/// every reading and needs an explicit threshold. Matched to the
/// estimator's five-point step so every board announces level movement at
/// the same granularity.
///
/// The estimator is deliberately not used here. It releases its
/// never-rise-while-discharging clamp only on a `Charging` or `Charged`
/// classification, and this board cannot produce either—the LGS4056H's
/// status output drives the orange LED and reaches no GPIO. Fed
/// perpetually-discharging samples the clamp would never lift, so a fully
/// recharged pack would keep reporting the level it bottomed out at until
/// the next reboot.
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
const BATTERY_LEVEL_STEP: u8 = 5;

/// Smallest level movement worth announcing, in percentage points.
///
/// Matched to the nRF estimator's five-point step so every board
/// announces level movement at the same granularity. The level itself
/// prefers the PMIC's fuel gauge and falls back to the OCV table while
/// the gauge is unlearned—which of the two should be primary
/// long-term is a hardware-validation question.
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
const BATTERY_LEVEL_STEP: u8 = 5;

/// Raised when the announced level moves, so the panel can redraw its
/// battery indicator.
///
/// A redraw prompt, never a wake: an unrequested sample must not light an
/// emissive panel, or a board left on a desk would glow every minute
/// forever.
static BATTERY_UI_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Owns the ADC divider. Samples on a slow cadence for the OLED and
/// immediately on session request (`Effect::SampleBattery`).
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
#[embassy_executor::task]
async fn battery_task(mut sampler: BatterySampler) {
    let announce = BATTERY_ANNOUNCE.sender();
    // Level last announced; `None` until the first sample, which always
    // announces.
    let mut announced: Option<u8> = None;
    loop {
        let requested = matches!(
            select(Timer::after_secs(60), BATTERY_REQUEST.wait()).await,
            Either::Second(())
        );
        // V2: ADC2 belongs to the radio while the BLE controller is up
        // (`Adc::new` would panic), so sampling waits for a BLE-off
        // window and the last reading is served in the meantime. Until
        // a first reading exists there is nothing to serve—skip, and
        // let an on-demand request time out rather than answer with a
        // made-up voltage.
        #[cfg(feature = "board-heltec-v2")]
        let sampled = {
            let _claim = ADC2_ARBITER.lock().await;
            if ADC2_RADIO_UP.load(Ordering::Acquire) {
                match BATTERY_MV.load(Ordering::Acquire) {
                    0 => None,
                    last => Some(last),
                }
            } else {
                Some(sampler.sample_mv().await)
            }
        };
        #[cfg(not(feature = "board-heltec-v2"))]
        let sampled = Some(sampler.sample_mv().await);
        let Some(mv) = sampled else {
            continue;
        };
        BATTERY_MV.store(mv, Ordering::Release);
        if requested {
            BATTERY_REPLY.signal(mv);
        }
        // Announce a level that has moved far enough to be worth a frame.
        // On-demand reads pass through here too, so a read that reveals a
        // move rebaselines rather than leaving a duplicate behind it.
        // There is no charge-state trigger on this board: the charge LED
        // is charger-driven and invisible to the MCU.
        let level = soc_from_ocv(mv);
        let moved = match announced {
            Some(previous) => level.abs_diff(previous) >= BATTERY_LEVEL_STEP,
            None => true,
        };
        if moved {
            announced = Some(level);
            announce.send(mv);
            // The same movement is what the on-screen indicator draws.
            BATTERY_UI_CHANGED.signal(());
        }
    }
}

/// The platform battery source behind `Effect::SampleBattery`: a
/// request/reply round trip into [`battery_task`], the sole ADC owner.
/// No charger-status signal exists on this board, so charge state is
/// never reported (and `SessionConfig::battery` does not advertise it).
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
async fn sample_battery_snapshot() -> Result<umsh_ulcp::battery::BatteryStatus, ()> {
    BATTERY_REPLY.reset();
    BATTERY_REQUEST.signal(());
    let mv = with_timeout(Duration::from_secs(2), BATTERY_REPLY.wait())
        .await
        .map_err(|_| ())?;
    Ok(battery_snapshot(mv))
}

/// Reduce one voltage reading to the protocol snapshot this board's
/// `SessionConfig::battery` advertises.
///
/// Shared by the on-demand read (`Effect::SampleBattery`) and the
/// asynchronous publication (`DeviceEnv::battery_event`) so the two can
/// never report the same reading differently.
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
fn battery_snapshot(mv: u16) -> umsh_ulcp::battery::BatteryStatus {
    umsh_ulcp::battery::BatteryStatus {
        voltage_mv: Some(mv),
        level_percent: Some(soc_from_ocv(mv)),
        charge_state: None,
    }
}

/// The level a reading supports: the PMIC gauge when it has learned the
/// pack, the OCV table while it has not, nothing without a cell.
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
fn battery_level(reading: &board_battery::Reading) -> Option<u8> {
    #[cfg(feature = "board-tlora-pager")]
    {
        reading.percent
    }
    #[cfg(not(feature = "board-tlora-pager"))]
    {
        reading
            .percent
            .or_else(|| reading.voltage_mv.map(soc_from_ocv))
    }
}

/// The `ChargeClass` a reading supports, or `None` when no cell is detected.
#[cfg(feature = "pmic-axp2101")]
fn battery_charge_class(reading: &board_battery::Reading) -> Option<ChargeClass> {
    let battery_mv = reading.voltage_mv?;
    if reading.vbus {
        match reading.direction {
            ChargeDirection::Charging => Some(ChargeClass::Charging),
            ChargeDirection::Standby
                if matches!(reading.state, ChargeState::Done) && battery_mv >= 4_100 =>
            {
                Some(ChargeClass::Charged)
            }
            ChargeDirection::Standby
            | ChargeDirection::Discharging
            | ChargeDirection::Unknown(_) => Some(ChargeClass::NotCharging),
        }
    } else {
        Some(ChargeClass::Discharging)
    }
}

#[cfg(feature = "board-tlora-pager")]
fn battery_charge_class(reading: &board_battery::Reading) -> Option<ChargeClass> {
    reading.charge.map(|charge| match charge {
        board_battery::Charge::Discharging => ChargeClass::Discharging,
        board_battery::Charge::Charging => ChargeClass::Charging,
        board_battery::Charge::Charged => ChargeClass::Charged,
        board_battery::Charge::NotCharging => ChargeClass::NotCharging,
    })
}

/// Owns the PMIC telemetry cadence. Samples on a slow cadence for the
/// OLED, immediately on session request (`Effect::SampleBattery`), and
/// on PMU events (VBUS/charger/battery edges poke [`BATTERY_REQUEST`]).
#[cfg(feature = "pmic-axp2101")]
#[embassy_executor::task]
async fn battery_task(pmic: &'static SharedPmic) {
    let announce = BATTERY_ANNOUNCE.sender();
    // What was last announced; `None` until the first good sample, which
    // always announces.
    let mut announced: Option<(Option<u8>, Option<ChargeClass>)> = None;
    loop {
        let requested = matches!(
            select(Timer::after_secs(60), BATTERY_REQUEST.wait()).await,
            Either::Second(())
        );
        let reading = match board_battery::read(&mut *pmic.lock().await).await {
            Ok(reading) => reading,
            // A refused bus leaves the last numbers standing; a pending
            // on-demand read times out on its own side.
            Err(_) => continue,
        };
        BATTERY_MV.store(reading.voltage_mv.unwrap_or(0), Ordering::Release);
        if VBUS_PRESENT.swap(reading.vbus, Ordering::AcqRel) != reading.vbus {
            // The wired-transport supervisor keys the USB-Serial-JTAG
            // driver's existence off this.
            VBUS_EDGE.signal(());
        }
        BATTERY_LEVEL.store(battery_level(&reading).unwrap_or(0xFF), Ordering::Release);
        BATTERY_CHARGE.store(
            match battery_charge_class(&reading) {
                None => 0,
                Some(ChargeClass::Discharging) => 1,
                Some(ChargeClass::Charging) => 2,
                Some(ChargeClass::Charged) => 3,
                Some(ChargeClass::NotCharging) => 4,
            },
            Ordering::Release,
        );
        if requested {
            BATTERY_REPLY.signal(reading);
        }
        // Announce a level that moved far enough to be worth a frame, and
        // every charge-class edge—plugging in is always news. On-demand
        // reads pass through here too, so a read that reveals a move
        // rebaselines rather than leaving a duplicate behind it.
        let level = battery_level(&reading);
        let charge = battery_charge_class(&reading);
        let moved = match announced {
            Some((previous_level, previous_charge)) => {
                charge != previous_charge
                    || match (level, previous_level) {
                        (Some(now), Some(previous)) => now.abs_diff(previous) >= BATTERY_LEVEL_STEP,
                        (now, previous) => now != previous,
                    }
            }
            None => true,
        };
        if moved {
            announced = Some((level, charge));
            announce.send(reading);
            // The same movement is what the on-screen indicator draws.
            BATTERY_UI_CHANGED.signal(());
        }
    }
}

/// The platform battery source behind `Effect::SampleBattery`: a
/// request/reply round trip into [`battery_task`], the sole owner of
/// the telemetry cadence.
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
async fn sample_battery_snapshot() -> Result<umsh_ulcp::battery::BatteryStatus, ()> {
    BATTERY_REPLY.reset();
    BATTERY_REQUEST.signal(());
    let reading = with_timeout(Duration::from_secs(2), BATTERY_REPLY.wait())
        .await
        .map_err(|_| ())?;
    Ok(battery_snapshot(&reading))
}

/// Reduce one reading to the protocol snapshot this board's
/// `SessionConfig::battery` advertises.
///
/// Shared by the on-demand read (`Effect::SampleBattery`) and the
/// asynchronous publication so the two can never report the same
/// reading differently.
#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
fn battery_snapshot(reading: &board_battery::Reading) -> umsh_ulcp::battery::BatteryStatus {
    umsh_ulcp::battery::BatteryStatus {
        voltage_mv: reading.voltage_mv,
        level_percent: battery_level(reading),
        charge_state: battery_charge_class(reading).map(|class| match class {
            ChargeClass::Discharging => umsh_ulcp::battery::BatteryChargeState::Discharging,
            ChargeClass::Charging => umsh_ulcp::battery::BatteryChargeState::Charging,
            ChargeClass::Charged => umsh_ulcp::battery::BatteryChargeState::Charged,
            ChargeClass::NotCharging => umsh_ulcp::battery::BatteryChargeState::NotCharging,
        }),
    }
}

// ─── PMU interrupt ───────────────────────────────────────────────────────

/// Serve the AXP2101's interrupt line (active low).
///
/// Power-key presses wake the panel—the POWER key is a PMIC input,
/// not a GPIO, so this is the only path a press reaches firmware by.
/// Supply and charger edges poke the battery task, whose announce
/// policy decides whether the change is worth a frame.
#[cfg(feature = "pmic-axp2101")]
#[embassy_executor::task]
async fn pmu_irq_task(pmic: &'static SharedPmic, mut irq: Input<'static>) {
    loop {
        // GPIO waits wake the chip from light sleep when the PMU asserts IRQ.
        irq.wait_for(Event::LowLevel).await;
        let taken = match pmic.lock().await.take_irqs().await {
            Ok(taken) => taken,
            Err(_) => {
                debug_log(format_args!("pmu irq: status read FAILED"));
                Timer::after_millis(250).await;
                continue;
            }
        };
        if taken.contains(IrqMask::POWER_KEY_SHORT) || taken.contains(IrqMask::POWER_KEY_LONG) {
            UI_WAKE.signal(());
        }
        if taken.contains(IrqMask::VBUS_INSERTED)
            || taken.contains(IrqMask::VBUS_REMOVED)
            || taken.contains(IrqMask::BATTERY_INSERTED)
            || taken.contains(IrqMask::BATTERY_REMOVED)
            || taken.contains(IrqMask::CHARGE_STARTED)
            || taken.contains(IrqMask::CHARGE_DONE)
        {
            BATTERY_REQUEST.signal(());
        }
        // The line is level-triggered: the AXP2101 holds it low until
        // every latched status bit is cleared, which is why this waits on
        // the level rather than an edge—a source latched between the
        // read and the write-back would otherwise be lost for good.
        //
        // The cost of that choice is that `wait_for_low` returns
        // immediately while the line is still down, so the service rate
        // has to be floored here or a source that re-latches as fast as
        // it is cleared becomes an unbounded I2C flood on the bus the
        // battery reads and the RTC share. Empty means the line is low
        // with nothing latched at all—noise, or a source this build
        // does not enable—and is worth backing off from much harder.
        Timer::after_millis(if taken.is_empty() { 50 } else { 2 }).await;
    }
}

// ─── Board environment for the shared ULCP driver ─────────────────────────

/// Persistence, entropy, pairing, and indicator couplings for
/// `umsh_ulcp_runtime::driver`. The attention/load hooks keep the
/// driver's no-op defaults—this board has no buzzer or battery-sag
/// estimator to feed.
struct BoardDeviceEnv {
    #[cfg(feature = "chip-esp32s3")]
    temperatures: &'static mut temperature::Sensors,
    proto_store: SnapshotStore,
    identity_store: ProtoStore,
    identity_rng: IdentityRng,
    node_counters: &'static NodeCountersMutex,
    /// Host-drivable buses; the BSP guards and routes each request.
    #[cfg(feature = "ulcp-i2c")]
    i2c: board::i2c::Buses,
    /// Announce-worthy readings from [`battery_task`], for unsolicited
    /// `PROP_BATTERY` publication.
    #[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
    battery: embassy_sync::watch::DynReceiver<'static, u16>,
    #[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
    battery: embassy_sync::watch::DynReceiver<'static, board_battery::Reading>,
    /// Positioning changes worth publishing unasked. The runtime's GNSS
    /// sink owns the policy—a stationary receiver produces a fix a
    /// second and almost none of them are news—so this only forwards
    /// what it decided to raise.
    #[cfg(feature = "gnss")]
    gnss_announce: umsh_ulcp_runtime::gnss::Announcer,
    /// The hardware clock, for writing a stepped time back. `None` when
    /// the chip did not answer at boot—the board still keeps time,
    /// it just will not survive a power-off.
    #[cfg(feature = "external-rtc")]
    rtc: Option<&'static RtcMutex>,
}

/// One battery reading as the session reports it, taking the reading by
/// value so callers need not know that the PMIC boards carry a struct
/// where the rest carry millivolts.
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
fn battery_reading_snapshot(mv: u16) -> umsh_ulcp::battery::BatteryStatus {
    battery_snapshot(mv)
}

#[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
fn battery_reading_snapshot(reading: board_battery::Reading) -> umsh_ulcp::battery::BatteryStatus {
    battery_snapshot(&reading)
}

impl BoardDeviceEnv {
    /// The publishable sources that depend on what is fitted, as one
    /// future.
    ///
    /// Split out of [`DeviceEnv::publish_event`] so the feature
    /// combinations live in one place instead of multiplying against the
    /// sources that are always present. Cancellation-safe: `Watch::changed`
    /// remembers which value the receiver last observed, and the driver's
    /// select drops this future whenever another arm wins.
    async fn sensor_event(&mut self) -> driver::PublishEvent {
        // Disjoint field borrows, not method calls: two `&mut self`
        // futures cannot coexist in one select.
        #[cfg(feature = "gnss")]
        let event = select(self.battery.changed(), self.gnss_announce.changed()).await;
        #[cfg(not(feature = "gnss"))]
        let event = Either::First(self.battery.changed().await) as Either<_, ()>;

        match event {
            Either::First(reading) => {
                driver::PublishEvent::Battery(battery_reading_snapshot(reading))
            }
            #[cfg(feature = "gnss")]
            Either::Second(umsh_ulcp_runtime::gnss::Announce::Gnss(key, snapshot)) => {
                driver::PublishEvent::Gnss(key, snapshot)
            }
            #[cfg(feature = "gnss")]
            Either::Second(umsh_ulcp_runtime::gnss::Announce::Time(epoch)) => {
                // A trusted receiver stepped the wall clock notably;
                // carry the step into the RTC so it survives power-off.
                // Sub-notable re-syncs never reach this arm, which is
                // what keeps the writeback off the every-second fix
                // cadence.
                #[cfg(feature = "external-rtc")]
                if let (Some(seconds), Some(rtc)) = (epoch, self.rtc) {
                    rtc_writeback(rtc, seconds).await;
                }
                driver::PublishEvent::Time(epoch)
            }
            #[cfg(feature = "gnss")]
            Either::Second(umsh_ulcp_runtime::gnss::Announce::IdentityFix(
                location,
                altitude_m,
            )) => driver::PublishEvent::IdentityFix(
                heapless::Vec::from_slice(location.as_bytes()).unwrap_or_default(),
                altitude_m,
            ),
            #[cfg(not(feature = "gnss"))]
            Either::Second(()) => unreachable!("no receiver on this board"),
        }
    }
}

impl DeviceEnv for BoardDeviceEnv {
    #[cfg(feature = "chip-esp32s3")]
    async fn sample_temperatures(&mut self, out: &mut [u16]) -> Result<usize, Status> {
        self.temperatures.sample(out).await
    }

    #[cfg(feature = "chip-esp32s3")]
    async fn read_temperature_names(&mut self, out: &mut [u8]) -> Result<usize, Status> {
        self.temperatures.read_names(out)
    }

    #[cfg(feature = "board-tlora-pager")]
    fn set_alert(&mut self, state: umsh_ulcp::alert::AlertState) {
        pager::alert::set(state.is_active());
    }
    #[cfg(feature = "bridge-client")]
    fn apply_bridge_config(
        &mut self,
        config: &umsh_ulcp_device::bridge::BridgeConfig,
        identity: Option<[u8; 32]>,
    ) {
        bridge::apply(config, identity);
    }
    #[cfg(feature = "wifi")]
    fn apply_network_config(&mut self, config: driver::NetworkConfig<'_>) {
        wifi::apply(config);
    }

    #[cfg(feature = "wifi")]
    fn wifi_selection_result(&mut self, result: Result<(), Status>) {
        if result.is_err() {
            UI_NOTICE.signal(UiNotice::NetworkUnavailable);
        }
    }

    #[cfg(feature = "wifi")]
    async fn set_wifi_scanning(&mut self, scanning: bool) -> Result<bool, Status> {
        Ok(wifi::scan(scanning))
    }

    #[cfg(feature = "wifi")]
    async fn read_network_table(&mut self, key: u32, out: &mut [u8]) -> Result<usize, Status> {
        wifi::read_table(key, out)
    }
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
        debug_log(format_args!(
            "identity request: node key present={}",
            device_node::node_key().is_some()
        ));
        device_node::sign_identity_blob(out).await
    }

    /// This board has no attention indicator, so the trace is the local
    /// report; the host-visible one is `PROP_SAVED`.
    fn report_snapshot_rejected(&mut self, fell_back: bool) {
        debug_log(format_args!(
            "proto-store snapshot rejected fell-back={fell_back}"
        ));
    }

    /// No sounder here, so the queued count on the status page carries
    /// the whole report and the notice's class and mute have nothing to
    /// steer.
    fn frame_queued(&mut self, notice: umsh_ulcp_device::QueuedNotice) {
        QUEUED_FRAMES.store(
            notice.depth.min(u16::MAX as usize) as u16,
            Ordering::Release,
        );
        UI_REFRESH.signal(());
    }

    fn queue_emptied(&mut self) {
        QUEUED_FRAMES.store(0, Ordering::Release);
        UI_REFRESH.signal(());
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
        // TRNG-seeded ChaCha20 CSPRNG (seeded while the RF subsystem
        // was known-live at boot); infallible once seeded.
        rand_core::RngCore::fill_bytes(&mut self.identity_rng, secret);
        Ok(())
    }

    async fn sample_battery(&mut self) -> Result<umsh_ulcp::battery::BatteryStatus, ()> {
        sample_battery_snapshot().await
    }
    #[cfg(feature = "board-tlora-pager")]
    async fn sample_battery_group(
        &mut self,
        fields: umsh_ulcp::battery_diagnostics::Fields,
    ) -> umsh_ulcp::battery_diagnostics::Sample {
        pager::sample_battery_group(fields).await
    }

    #[cfg(feature = "ulcp-i2c")]
    async fn i2c_transfer(
        &mut self,
        request: umsh_ulcp::i2c::TransferRequest<'_>,
        out: &mut [u8],
    ) -> Result<usize, Status> {
        self.i2c.transfer(request, out).await
    }

    #[cfg(feature = "ulcp-i2c")]
    async fn i2c_scan(
        &mut self,
        request: umsh_ulcp::i2c::ScanRequest,
        out: &mut [u8],
    ) -> Result<usize, Status> {
        self.i2c.scan(request, out).await
    }

    /// Publish the reading [`battery_task`] flagged, reduced the same way
    /// the on-demand read reduces it.
    #[cfg(not(feature = "gnss"))]
    async fn battery_event(&mut self) -> umsh_ulcp::battery::BatteryStatus {
        #[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
        {
            let mv = self.battery.changed().await;
            battery_snapshot(mv)
        }
        #[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
        {
            let reading = self.battery.changed().await;
            battery_snapshot(&reading)
        }
    }

    #[cfg(feature = "external-rtc")]
    async fn read_time(&mut self) -> Option<u32> {
        umsh_hal::wall_clock::now()
    }

    /// A host wrote `PROP_TIME`. An operator outranks every other
    /// source, and a manual set is worth persisting: it goes to the
    /// hardware RTC too, so the board wakes up with it.
    ///
    /// The empty write returns the wall clock to not knowing. The RTC
    /// keeps its time—"the host cleared the clock" is a statement
    /// about the running device, not an instruction to destroy the
    /// hardware clock's state—so the next boot restores from it.
    #[cfg(feature = "external-rtc")]
    async fn apply_time(&mut self, epoch: Option<u32>) {
        match epoch {
            Some(seconds) => {
                umsh_hal::wall_clock::set_manual(seconds);
                if let Some(rtc) = self.rtc {
                    rtc_writeback(rtc, seconds).await;
                }
            }
            None => umsh_hal::wall_clock::clear(),
        }
        // The clock appearing or vanishing is a visible change the user
        // asked for, so redraw now rather than at whatever the next
        // event happens to be.
        UI_REFRESH.signal(());
    }

    /// The receiver's current view. Cached by the runtime rather than
    /// re-read from the receiver, because "what did it last say" is the
    /// only question a UART emitting one cycle a second can answer
    /// promptly.
    #[cfg(feature = "gnss")]
    async fn sample_gnss(&mut self) -> Result<umsh_ulcp::gnss::GnssSnapshot, ()> {
        Ok(umsh_ulcp_runtime::gnss::snapshot())
    }

    /// Everything this board publishes unasked, on one select arm.
    ///
    /// The driver has exactly one, because a hook per property would
    /// need one `&mut self` borrow apiece. The Bluetooth transport's
    /// sources need no board hardware, so they ride here on every board,
    /// GNSS or not, while [`sensor_event`](Self::sensor_event) keeps the
    /// sources that do vary by board behind their own features.
    async fn publish_event(&mut self) -> driver::PublishEvent {
        let sensors = async {
            match select(self.sensor_event(), ble::event()).await {
                Either::First(event) | Either::Second(event) => event,
            }
        };
        #[cfg(feature = "wifi")]
        {
            #[cfg(feature = "bridge-client")]
            let events = async {
                match select(wifi::event(), bridge::event()).await {
                    Either::First(event) | Either::Second(event) => event,
                }
            };
            #[cfg(not(feature = "bridge-client"))]
            let events = wifi::event();
            match select(sensors, events).await {
                Either::First(event) | Either::Second(event) => event,
            }
        }
        #[cfg(not(feature = "wifi"))]
        sensors.await
    }

    async fn apply_pairing_pin(&mut self, pin: Option<u32>) -> bool {
        ble::apply_pairing_pin(pin).await
    }

    async fn clear_ble_bonds(&mut self, reply_over_ble: bool) -> bool {
        ble::clear_bonds(reply_over_ble).await
    }

    async fn set_ble_pairing(&mut self, open: bool) -> bool {
        ble::set_pairing(open).await
    }

    async fn factory_reset(&mut self) -> ! {
        // TODO: erase the runtime-discovered `umsh` partition span
        // (`partition.start..partition.end`)—all journals live there—
        // then esp32 reset. Unlike techo's hardcoded NV region, the span
        // is not currently held by `BoardDeviceEnv`, so this needs the
        // partition bounds threaded in first.
        todo!("Implement factory reset for esp32");
    }

    async fn reboot(&mut self) -> ! {
        // Settle the mesh first: air the MAC acknowledgment that answers
        // a mesh-commanded reboot, and force the frame counters to
        // flash. Without the flush, the boundary that admitted the
        // reboot command dies with the RAM it lives in, and the
        // administrator's retries are accepted again after boot—one
        // reboot per retry.
        device_node::quiesce_for_reboot().await;
        // A plain restart: every journal in the `umsh` partition stays
        // where it is and the board remounts from it on the way back up.
        debug_log(format_args!("REBOOT: restarting"));
        esp_hal::system::software_reset()
    }

    fn set_ble_enabled(&mut self, enabled: bool) {
        ble::set_enabled(enabled);
    }

    fn set_advertising_allowed(&mut self, allowed: bool) {
        ble::set_advertising_allowed(allowed);
    }

    async fn publish_device_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let mut current = DEVICE_NAME.lock().await;
        let was_ready = DEVICE_NAME_READY.swap(true, Ordering::AcqRel);
        if was_ready && current.as_slice() == bytes {
            return;
        }
        current.clear();
        if current.extend_from_slice(bytes).is_ok() {
            ble::device_name_changed();
            device_node::set_device_name(bytes);
            UI_REFRESH.signal(());
        }
    }

    fn boot_settings_ready(&mut self) {
        ble::boot_settings_ready();
    }

    fn publish_dev_domain(&mut self, snapshot: driver::DevDomainSnapshot) {
        // The zone and the positioning policy ride the device-domain
        // mirror, so a host write, a boot restore, and a `CMD_RST` all
        // reach the clock and the receiver by the same path—and
        // neither needs anything to remember to push it.
        #[cfg(feature = "external-rtc")]
        umsh_hal::wall_clock::set_tz(snapshot.tz_offset_min);
        #[cfg(feature = "gnss")]
        umsh_ulcp_runtime::gnss::configure(
            snapshot.gnss_enabled,
            umsh_ulcp_runtime::gnss::Policy {
                trust_time: snapshot.gnss_time_trust,
                update_identity: snapshot.gnss_ident_update,
                identity_precision: snapshot.gnss_ident_precision,
            },
        );
        #[cfg(all(feature = "board-tlora-pager", not(feature = "motion-qualification")))]
        pager::motion::SERVICE.request(
            umsh_motion::service::Consumer::Display,
            snapshot.display_motion_wake_enabled,
        );
        device_node::publish_snapshot(snapshot);
        // Every switch the settings menu shows is read back out of the
        // mirrors this call has just finished writing, so this is the one
        // place that can honestly say they moved. A host write, a boot
        // restore, a `CMD_RST` and a press on the panel all arrive here,
        // which is why none of them has to remember to raise it for
        // itself. `UI_REFRESH` never lights a dark panel—the press that
        // caused this already did.
        UI_REFRESH.signal(());
    }

    fn trace(&mut self, args: core::fmt::Arguments<'_>) {
        debug_log(args);
    }
}

// ─── Radio ───────────────────────────────────────────────────────────────

/// Owns the `lora_phy::LoRa` instance via the reconfigurable device
/// runner. TX uses MeshCore's 32-symbol SF7 preamble; the hardware-proven
/// 8-symbol SX1262 RX acquisition setting remains unchanged.
///
/// Continuous RX on every board. The SX1262 boards ran preamble duty
/// cycle for a time, but a counted bench campaign found an intrinsic
/// loss mode: the chip's raw preamble detector false-fires in sniff
/// mode and each false detection camps the demodulator, deaf to real
/// frames, until the host re-arms RX—a few percent of unretried
/// traffic lost, unfixable chip-side without breaking real detection.
/// See `docs/sx1262-rx-duty-cycle-findings.md` before reintroducing it.
#[embassy_executor::task]
async fn radio_task(lora: board_radio::Radio) {
    use umsh_radio_loraphy::RxStrategy;
    umsh_radio_loraphy::device_runner(
        lora,
        &RADIO_CH,
        &DEVICE_CTL,
        8,
        TX_PREAMBLE_SYMBOLS,
        RxStrategy::Continuous,
        Some(&STATS),
    )
    .await;
}

/// Owns the real `RADIO_CH` bundle and multiplexes it across the
/// virtual per-client bundles (see `radio_mux`): per-client TX
/// completion routing plus RX fan-out to every client.
#[embassy_executor::task]
async fn radio_mux_task() {
    #[cfg(feature = "bridge-client")]
    let attachment = Some(radio_mux::BridgeAttachment {
        node: 1,
        port: &bridge::PORT,
    });
    #[cfg(not(feature = "bridge-client"))]
    let attachment = None;
    radio_mux::radio_mux_with_bridge(
        &RADIO_CH,
        &MUX_CLIENTS,
        &radio_mux::MUX_MODE,
        Some(&STATS),
        attachment,
    )
    .await
}

// ─── GNSS ────────────────────────────────────────────────────────────────

/// Drive the board's GNSS receiver.
///
/// The whole of the per-board GNSS code: the UART and the board's power
/// control, handed to the shared pump. An `#[embassy_executor::task]`
/// cannot be generic, which is the only reason this shim exists at all
///—the loop it delegates to lives in `umsh_gnss::pump` and is common
/// to both cargo workspaces.
///
/// The receiver stays powered down until `PROP_GNSS_ENABLED` says
/// otherwise, including on a board that has never been configured. It
/// is never asked for the time: the PCF8563 is this board's clock, so
/// the receiver's own RTC is not consulted at boot.
#[cfg(feature = "gnss")]
#[cfg(feature = "board-tbeam-supreme")]
type GnssRxPin = esp_hal::peripherals::GPIO9<'static>;
#[cfg(feature = "board-tbeam-supreme")]
type GnssTxPin = esp_hal::peripherals::GPIO8<'static>;
#[cfg(feature = "board-tlora-pager")]
type GnssRxPin = esp_hal::peripherals::GPIO4<'static>;
#[cfg(feature = "board-tlora-pager")]
type GnssTxPin = esp_hal::peripherals::GPIO12<'static>;

#[cfg(feature = "gnss")]
#[embassy_executor::task]
async fn gnss_task(
    uart1: esp_hal::peripherals::UART1<'static>,
    rx: GnssRxPin,
    tx: GnssTxPin,
    control: board::gnss::Gnss,
) {
    let Some(enable) = umsh_ulcp_runtime::gnss::EnableSource::new() else {
        debug_log(format_args!("gnss: enable receiver already taken"));
        return;
    };
    let slot = core::cell::RefCell::new(GnssUartSlot {
        boot: Some((uart1, rx, tx)),
        open: None,
        parked: None,
    });
    umsh_gnss::pump::run(
        GnssPort { slot: &slot },
        GnssPower {
            inner: control,
            slot: &slot,
        },
        enable,
        umsh_ulcp_runtime::gnss::FixSink,
        Delay,
    )
    .await
}

/// The GNSS UART's active and sleep-compatible parked states.
///
/// `UartRx` holds a `WakeLock` for its entire lifetime, so a UART that
/// exists while the receiver is off is a light-sleep veto with nobody
/// on the other end. The pump's `Power` edges own the driver's
/// lifecycle instead: opened in `power_on`, RX dropped in `power_off`—
/// which also makes "GNSS enabled forbids sleep" true by construction,
/// exactly the right policy while NMEA is streaming (a light-sleeping
/// UART loses RX bytes).
#[cfg(feature = "gnss")]
struct GnssUartSlot {
    /// The real peripherals, consumed by the first open; later opens
    /// steal (see `open_port`).
    boot: Option<(esp_hal::peripherals::UART1<'static>, GnssRxPin, GnssTxPin)>,
    open: Option<Uart<'static, Async>>,
    /// The pinned HAL suspends every UART before light sleep. After the
    /// UART has been initialized, dropping its last clock guard leaves
    /// that suspend's register-update handshake waiting on a stopped clock.
    /// An idle, disconnected TX half retains the clocks but no WakeLock.
    parked: Option<esp_hal::uart::UartTx<'static, esp_hal::Blocking>>,
}

#[cfg(feature = "gnss")]
impl GnssUartSlot {
    fn open_port(&mut self) {
        if self.open.is_some() {
            return;
        }
        // Prevent sleep in the gap between retiring the parked clock owner
        // and constructing the next RX driver (which takes its own lock).
        let _transition = esp_hal::rtc_cntl::WakeLock::new();
        drop(self.parked.take());
        let (uart1, rx, tx) = self.boot.take().unwrap_or_else(|| {
            // SAFETY: the previous RX driver was dropped by `park_port`,
            // and its parked TX half was dropped immediately above,
            // and the slot (single-task, behind one `RefCell`) is the
            // sole place they are ever (re)constructed.
            unsafe {
                (
                    esp_hal::peripherals::UART1::steal(),
                    GnssRxPin::steal(),
                    GnssTxPin::steal(),
                )
            }
        });
        self.open = Some(
            Uart::new(uart1, UartConfig::default().with_baudrate(board::GNSS_BAUD))
                .unwrap()
                .with_rx(rx)
                .with_tx(tx)
                .into_async(),
        );
    }

    fn park_port(&mut self) {
        let Some(uart) = self.open.take() else {
            return;
        };
        // The pump has canceled its pending read before reaching here.
        // Leave async mode explicitly so its interrupt ownership flags and
        // CPU interrupt are retired before any driver clock is released.
        let (rx, tx) = uart
            .into_blocking()
            .with_rx(Level::High)
            .with_tx(esp_hal::gpio::NoPin)
            .split();
        self.parked = Some(tx);
        // Disconnecting the matrix leaves GPIO's output latch/pull state
        // intact. Float both lines so they cannot feed the disabled rail.
        // SAFETY: neither half is connected to these pins anymore, and
        // this single-task slot is their only owner across GNSS cycles.
        unsafe {
            drop(Input::new(GnssRxPin::steal(), InputConfig::default()));
            drop(Input::new(GnssTxPin::steal(), InputConfig::default()));
        }
        // Only RX holds the lifetime WakeLock. The parked TX never writes
        // and has no physical output connection into the unpowered receiver.
        drop(rx);
    }
}

/// The pump's `Read` half over the slot. The `RefMut` is held across
/// the read await, which is sound here because everything touching the
/// slot runs sequentially inside `gnss_task`: `power_off` can only
/// borrow after the pump has dropped the read future it was selecting
/// on.
#[cfg(feature = "gnss")]
struct GnssPort<'a> {
    slot: &'a core::cell::RefCell<GnssUartSlot>,
}

#[cfg(feature = "gnss")]
impl embedded_io_async::ErrorType for GnssPort<'_> {
    type Error = <Uart<'static, Async> as embedded_io_async::ErrorType>::Error;
}

#[cfg(feature = "gnss")]
impl embedded_io_async::Read for GnssPort<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut slot = self.slot.borrow_mut();
        let Some(uart) = slot.open.as_mut() else {
            // Powered down: the pump reads 0 as a closed stream and
            // backs off rather than spinning.
            return Ok(0);
        };
        embedded_io_async::Read::read(uart, buf).await
    }
}

/// The pump's `Power` half: the board's rail/wake sequencing wrapped
/// with the UART's lifecycle.
#[cfg(feature = "gnss")]
struct GnssPower<'a> {
    inner: board::gnss::Gnss,
    slot: &'a core::cell::RefCell<GnssUartSlot>,
}

#[cfg(feature = "gnss")]
impl umsh_gnss::pump::Power for GnssPower<'_> {
    async fn power_on(&mut self) {
        self.slot.borrow_mut().open_port();
        self.inner.power_on().await;
    }

    async fn power_off(&mut self) {
        self.inner.power_off().await;
        // After the receiver, retire RX and its wake lock while preserving
        // the clocks needed by the HAL's UART sleep handshake.
        self.slot.borrow_mut().park_port();
    }
}

// ─── Wired transport (UART0 or native USB-Serial-JTAG) ───────────────────

/// The wired port's halves, whichever peripheral carries them.
#[cfg(not(feature = "wired-usb-serial-jtag"))]
type WiredTx = UartTx<'static, Async>;
#[cfg(not(feature = "wired-usb-serial-jtag"))]
type WiredRx = UartRx<'static, Async>;
#[cfg(feature = "wired-usb-serial-jtag")]
type WiredTx = UsbSerialJtagTx<'static, Async>;
#[cfg(feature = "wired-usb-serial-jtag")]
type WiredRx = UsbSerialJtagRx<'static, Async>;

/// How long one wired write may sit in a FIFO nobody drains. The
/// USB-Serial-JTAG FIFO only empties while a host has the port open, so
/// an unplugged cable turns every write into a stall; bounding it keeps
/// the output queue draining (frames are dropped instead) and the
/// session alive. A UART drains unconditionally and never comes near
/// this bound.
const WIRED_WRITE_TIMEOUT: Duration = Duration::from_millis(500);

/// Write all of `bytes`, best-effort. Returns false when the host
/// stopped draining—the caller abandons the rest of the frame, since
/// half an HDLC frame is worth less than nothing.
async fn wired_write_all(tx: &mut WiredTx, bytes: &[u8]) -> bool {
    let mut sent = 0;
    while sent < bytes.len() {
        match with_timeout(
            WIRED_WRITE_TIMEOUT,
            embedded_io_async::Write::write(tx, &bytes[sent..]),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => sent += n,
            _ => return false,
        }
    }
    true
}

/// Owns the wired TX half, HDLC-encodes frames, and writes them out.
#[cfg(not(feature = "wired-usb-serial-jtag"))]
#[embassy_executor::task]
async fn output_task(mut tx: WiredTx, panic_report: Option<heapless::String<128>>) {
    output_pump(&mut tx, panic_report).await
}

/// The wired TX pump: HDLC-encode frames and write them out. Never
/// returns; on the USB-Serial-JTAG board the supervisor cancels it when
/// VBUS drops.
async fn output_pump(tx: &mut WiredTx, panic_report: Option<heapless::String<128>>) {
    // Emit the previous boot's panic message as ASCII. HDLC hosts
    // resynchronize past it; humans read it with a serial terminal.
    // There is no reader handshake to wait for—it lands in the bridge
    // (or the bounded write drops it with no host attached), which is
    // the correct behavior for a serial console.
    if let Some(report) = panic_report {
        let _ = wired_write_all(tx, b"[PREV PANIC]: ").await;
        let _ = wired_write_all(tx, report.as_bytes()).await;
        let _ = wired_write_all(tx, b"\r\n").await;
    }
    loop {
        #[cfg(feature = "debug-log")]
        let outbound = match select(OUT_CH.wired.receive(), DEBUG_CH.receive()).await {
            Either::First(outbound) => outbound,
            Either::Second(line) => {
                let _ = wired_write_all(tx, line.as_bytes()).await;
                continue;
            }
        };
        #[cfg(not(feature = "debug-log"))]
        let outbound = OUT_CH.wired.receive().await;
        if SESSION_GEN.load(Ordering::Acquire) != outbound.generation {
            continue;
        }
        #[cfg(feature = "board-tlora-pager")]
        if let Some(report) = pager::take_gauge_report() {
            let _ = wired_write_all(tx, report.as_bytes()).await;
        }
        #[cfg(feature = "board-tlora-pager")]
        if let Some(report) = pager::input::power_report() {
            if wired_write_all(tx, report.as_bytes()).await {
                pager::input::power_report_sent();
            }
        }
        let mut wire = [0u8; WIRE_MAX];
        let Ok(len) = hdlc::encode_frame(&outbound.frame, &mut wire) else {
            continue;
        };
        for chunk in generation_checked(wire[..len].chunks(64), outbound.generation, || {
            SESSION_GEN.load(Ordering::Acquire)
        }) {
            if !wired_write_all(tx, chunk).await {
                break;
            }
        }
    }
}

/// Owns the wired RX half and HDLC decoder, forwarding frames into
/// `INPUT_CH`. UART bridges cannot detect host disconnection, so their
/// wired attachment persists after the first valid HDLC frame. Native
/// USB instead uses the supervisor below to detach on VBUS loss. A board
/// nobody serials into stays detached and operates
/// autonomously (queueing and delegated acknowledgement). Displacement
/// by a BLE attach is observed as a foreign `SESSION_GEN` bump, which
/// re-arms the lazy attach, so a displaced serial host reclaims the
/// session with its next frame.
#[cfg(not(feature = "wired-usb-serial-jtag"))]
#[embassy_executor::task]
async fn uart_in_task(mut rx: WiredRx) {
    input_pump(&mut rx).await
}

/// The wired RX pump. Never returns; on the USB-Serial-JTAG board the
/// supervisor cancels it when VBUS drops, and the decoder state dies
/// with it—a torn frame cannot outlive the cable that carried it.
async fn input_pump(rx: &mut WiredRx) {
    let mut decoder: hdlc::Decoder<FRAME_IN_MAX> = hdlc::Decoder::new();
    let mut local_generation = SESSION_GEN.load(Ordering::Acquire);
    // True while this task's own lazy attach is still unprocessed: the
    // resulting single generation bump must not reset the decoder,
    // because the bytes in flight belong to the very session being
    // attached. Any other generation movement is a displacement and
    // resets as before.
    let mut own_attach_pending = false;
    // Local mirror of "we attached wired and were not displaced since";
    // suppresses duplicate attaches within one read batch (each attach
    // bumps the generation and would invalidate the previous command's
    // in-flight response).
    let mut wired_attached = false;
    loop {
        let generation = SESSION_GEN.load(Ordering::Acquire);
        if generation != local_generation {
            if own_attach_pending && generation == local_generation.wrapping_add(1) {
                own_attach_pending = false;
            } else {
                // Foreign session edge (BLE attach or a racing burst):
                // drop any half-decoded frame and re-arm lazy attach.
                decoder.reset();
                own_attach_pending = false;
                wired_attached = false;
            }
            local_generation = generation;
        }
        let mut packet = [0u8; 64];
        match embedded_io_async::Read::read(rx, &mut packet).await {
            Ok(0) => {}
            // A FIFO overflow or framing error costs the in-flight
            // frame, not the session: resynchronize on the next flag.
            Err(_) => decoder.reset(),
            Ok(len) => {
                for &byte in &packet[..len] {
                    let Some(Ok(bytes)) = decoder.push(byte) else {
                        continue;
                    };
                    // Covers both first-ever contact and reclaiming
                    // the session after a BLE displacement (which
                    // cleared the flag via the generation check above;
                    // a BLE *detach* bumps nothing, but then wired was
                    // not displaced and the flag is still accurate).
                    if !wired_attached {
                        wired_attached = true;
                        own_attach_pending = true;
                        INPUT_CH.send(InEvent::Attached(Transport::Usb)).await;
                    }
                    let mut frame = heapless::Vec::new();
                    let _ = frame.extend_from_slice(bytes);
                    INPUT_CH.send(InEvent::Frame(Transport::Usb, frame)).await;
                }
            }
        }
    }
}

/// Owns the USB-Serial-JTAG driver for exactly as long as USB power is
/// present.
///
/// Both halves of the driver hold a `WakeLock` for their entire
/// lifetime—the peripheral cannot receive across light sleep—so a
/// driver that exists on battery is a driver that forbids sleep
/// forever. Keying its existence off VBUS turns that lock into policy:
/// on USB power the transport is up and the board never sleeps (there
/// is nothing to save), on battery the transport does not exist and
/// its locks with it. Wired ULCP attach loses nothing—with no VBUS
/// there is no host on the other end of the pins.
#[cfg(feature = "wired-usb-serial-jtag")]
#[embassy_executor::task]
async fn wired_transport_task(
    usb: esp_hal::peripherals::USB_DEVICE<'static>,
    panic_report: Option<heapless::String<128>>,
) {
    let mut usb = Some(usb);
    let mut panic_report = panic_report;
    loop {
        if !VBUS_PRESENT.load(Ordering::Acquire) {
            VBUS_EDGE.wait().await;
            continue;
        }
        let device = usb.take().unwrap_or_else(|| {
            // SAFETY: the previous cycle's driver—the singleton's only
            // consumer—was dropped before this loop came back around,
            // and this task is the sole place the peripheral is ever
            // (re)constructed.
            unsafe { esp_hal::peripherals::USB_DEVICE::steal() }
        });
        let (mut rx, mut tx) = UsbSerialJtag::new(device).into_async().split();
        debug_log(format_args!("wired transport: up (VBUS)"));
        select3(
            output_pump(&mut tx, panic_report.take()),
            input_pump(&mut rx),
            async {
                loop {
                    VBUS_EDGE.wait().await;
                    if !VBUS_PRESENT.load(Ordering::Acquire) {
                        break;
                    }
                }
            },
        )
        .await;
        // Release the peripheral's wake locks before waiting for the
        // runtime. Detach must precede any new USB attach after replug;
        // the runtime ignores it if BLE already displaced this session.
        drop(rx);
        drop(tx);
        INPUT_CH.send(InEvent::Detached(Transport::Usb)).await;
        debug_log(format_args!("wired transport: down (no VBUS)"));
    }
}

// ─── ULCP session ────────────────────────────────────────────────────────

/// Keep the large protocol storage out of the async task's initializer.
/// Without PSRAM, constructing it as an async local can make LLVM copy
/// the entire session through a stack temporary while spawning the task.
#[cfg(all(feature = "wifi", not(feature = "psram")))]
#[inline(never)]
fn internal_session(config: SessionConfig, boot_reason: Status) -> &'static mut Session {
    static SESSION: StaticCell<Session> = StaticCell::new();
    SESSION.init_with(|| {
        Session::new(
            config,
            boot_reason,
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
        )
    })
}

/// Owns the framing-free protocol session: hosts the shared ULCP driver
/// (`umsh_ulcp_runtime::driver::run`)—host frames, radio
/// receptions, transmit completions, and every session effect—over
/// this board's channel wiring and [`BoardDeviceEnv`] couplings.
/// Pager needs a separate constructor to bound main's frame. On T-Beam, keep
/// it inlined: a separate constructor adds a ~9 KiB frame between main and the
/// ~18 KiB future initializer, overflowing the stack despite each frame fitting.
#[embassy_executor::task]
#[cfg_attr(feature = "board-tlora-pager", inline(never))]
async fn device_task(
    boot_reason: Status,
    proto_store: SnapshotStore,
    boot_snapshot: Option<BootSnapshot>,
    identity_store: ProtoStore,
    boot_identity: Option<[u8; 32]>,
    identity_rng: IdentityRng,
    node_counters: &'static NodeCountersMutex,
    #[cfg(feature = "external-rtc")] rtc: Option<&'static RtcMutex>,
    #[cfg(feature = "ulcp-i2c")] i2c: board::i2c::Buses,
    #[cfg(feature = "chip-esp32s3")] sens: esp_hal::peripherals::SENS<'static>,
    #[cfg(feature = "pmic-axp2101")] pmic: &'static SharedPmic,
) {
    // The retained hardware reset cause answers the first
    // PROP_LAST_STATUS query; attach itself never modifies it.
    let config = session_config();
    #[cfg(feature = "ulcp-i2c")]
    let config = SessionConfig {
        i2c_devices: i2c.devices(),
        ..config
    };
    #[cfg(not(any(feature = "psram", feature = "wifi")))]
    let mut session = Session::new(
        config,
        boot_reason,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
    );
    #[cfg(not(any(feature = "psram", feature = "wifi")))]
    let (session, snapshot_storage) = (&mut session, &mut [0; umsh_ulcp_device::SNAPSHOT_MAX]);
    #[cfg(all(feature = "wifi", not(feature = "psram")))]
    let (session, snapshot_storage) = {
        static SNAPSHOT: StaticCell<[u8; umsh_ulcp_device::SNAPSHOT_MAX]> = StaticCell::new();
        (
            internal_session(config, boot_reason),
            SNAPSHOT.init_with(|| [0; umsh_ulcp_device::SNAPSHOT_MAX]),
        )
    };
    #[cfg(feature = "psram")]
    let (session, snapshot_storage) =
        (external::session(config, boot_reason), external::snapshot());
    driver::run_with_storage(
        session,
        snapshot_storage,
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
            #[cfg(feature = "chip-esp32s3")]
            temperatures: temperature::sensors(
                umsh_bsp_esp32::temperature::TemperatureSensor::new(sens),
                #[cfg(feature = "pmic-axp2101")]
                pmic,
            ),
            proto_store,
            identity_store,
            identity_rng,
            node_counters,
            #[cfg(feature = "ulcp-i2c")]
            i2c,
            // The driver is the only receiver; the slot count is sized
            // for exactly that, so this cannot fail.
            battery: BATTERY_ANNOUNCE
                .dyn_receiver()
                .expect("BATTERY_ANNOUNCE receiver slot"),
            #[cfg(feature = "gnss")]
            gnss_announce: umsh_ulcp_runtime::gnss::announcer()
                .expect("GNSS announcement receiver slot"),
            #[cfg(feature = "external-rtc")]
            rtc,
        },
    )
    .await
}

// ─── UI: OLED, button, LED ───────────────────────────────────────────────

/// What this board's menu can do.
///
/// Everything the class defines—minus the receiver entries on a board
/// with no GNSS fitted, where both come out and the submenu that led to
/// them goes with them. Clearing bonds is a menu item rather than a
/// bare gesture because the confirmation page in front of it is what
/// makes it safe.
fn board_menu_items() -> MenuItems {
    #[allow(unused_mut)]
    let mut items = MenuItems::all();
    #[cfg(not(feature = "board-tlora-pager"))]
    {
        items = items.without(MenuItem::Battery);
    }
    #[cfg(not(feature = "gnss"))]
    {
        items = items
            .without(MenuItem::GnssToggle)
            .without(MenuItem::ShareLocation);
    }
    #[cfg(not(feature = "wifi"))]
    {
        items = items
            .without(MenuItem::WifiToggle)
            .without(MenuItem::WifiNetworks);
    }
    #[cfg(not(feature = "ble"))]
    {
        items = items
            .without(MenuItem::BluetoothToggle)
            .without(MenuItem::StartPairing)
            .without(MenuItem::ClearBonds);
    }
    #[cfg(any(not(feature = "board-tlora-pager"), feature = "motion-qualification"))]
    {
        items = items.without(MenuItem::MotionWake);
    }
    items
}

/// Which device-domain switch a menu toggle names.
const fn ulcp_setting(id: ToggleId) -> Setting {
    match id {
        ToggleId::Radio => Setting::Radio,
        ToggleId::Wifi => Setting::Wifi,
        ToggleId::Bluetooth => Setting::Bluetooth,
        ToggleId::Gnss => Setting::Gnss,
        ToggleId::MotionWake => Setting::MotionWake,
        ToggleId::ShareLocation => Setting::ShareLocation,
        ToggleId::Forwarding => Setting::Forwarding,
    }
}

/// Backing store for the identity page's two strings, which
/// [`screen::StatusModel`] only borrows.
#[derive(Default)]
struct IdentityText {
    hint: heapless::String<8>,
    address: heapless::String<{ umsh_core::base58::ENCODED_LEN }>,
}

impl IdentityText {
    /// The running node's address, or empty before bring-up.
    fn current() -> Self {
        use core::fmt::Write as _;
        let Some(key) = device_node::node_key() else {
            return Self::default();
        };
        let mut text = Self::default();
        let _ = write!(
            text.hint,
            "{}",
            umsh_core::NodeHint::from_public_key(&umsh_core::PublicKey(key))
        );
        for digit in umsh_core::base58::encode(&key) {
            let _ = text.address.push(digit as char);
        }
        text
    }

    fn model(&self) -> Option<screen::IdentityModel<'_>> {
        if self.address.is_empty() {
            return None;
        }
        Some(screen::IdentityModel {
            hint: &self.hint,
            address: &self.address,
        })
    }
}

/// Everything the shared renderer draws that is not menu state.
///
/// The device name is passed in rather than read here: reading it is
/// async and the model borrows it, so the display task snapshots it once
/// per frame and lends it to this.
fn ui_status<'a>(name: &'a DeviceName, identity: &'a IdentityText) -> screen::StatusModel<'a> {
    #[cfg(feature = "wifi")]
    let wifi = Some(wifi::ui_snapshot());
    #[cfg(not(feature = "wifi"))]
    let wifi: Option<umsh_ux_display_tracker::wifi::WifiMenu> = None;
    let mv = BATTERY_MV.load(Ordering::Acquire);
    // No charger telemetry reaches the MCU on the ADC boards, so their
    // indicator says nothing about charging rather than asserting the
    // pack is discharging; the PMIC boards know which way current flows,
    // and unknown (no cell, or before the first sample) draws nothing
    // rather than a guess.
    #[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
    let battery = screen::BatteryIndicator {
        level_percent: (mv != 0).then(|| soc_from_ocv(mv)),
        charge: None,
    };
    #[cfg(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))]
    let battery = {
        let level = BATTERY_LEVEL.load(Ordering::Acquire);
        screen::BatteryIndicator {
            level_percent: (level != 0xFF).then_some(level),
            charge: match BATTERY_CHARGE.load(Ordering::Acquire) {
                1 => Some(ChargeClass::Discharging),
                2 => Some(ChargeClass::Charging),
                3 => Some(ChargeClass::Charged),
                4 => Some(ChargeClass::NotCharging),
                _ => None,
            },
        }
    };
    let bluetooth = ble::panel();
    screen::StatusModel {
        wifi,
        pairing_highlight: (Instant::now().as_millis() / screen::PAIRING_BLINK_MS) % 2 == 0,
        firmware_version: env!("GIT_DESCRIBE"),
        device_name: core::str::from_utf8(name).unwrap_or(DEFAULT_DEVICE_NAME),
        // Boards with no receiver report nothing on both positioning
        // switches rather than a guess—and neither is on their menu.
        settings: screen::SettingsModel {
            radio: device_node::radio_enabled(),
            #[cfg(all(feature = "board-tlora-pager", not(feature = "motion-qualification")))]
            motion_wake: Some(pager::motion::SERVICE.control().display()),
            #[cfg(any(not(feature = "board-tlora-pager"), feature = "motion-qualification"))]
            motion_wake: None,
            wifi: wifi.map(|wifi| wifi.enabled),
            bluetooth: bluetooth.enabled,
            #[cfg(not(feature = "gnss"))]
            gnss: None,
            #[cfg(not(feature = "gnss"))]
            share_location: None,
            #[cfg(feature = "gnss")]
            gnss: Some(umsh_ulcp_runtime::gnss::enabled()),
            #[cfg(feature = "gnss")]
            share_location: Some(umsh_ulcp_runtime::gnss::policy().update_identity),
            forwarding: Some(device_node::repeater_enabled()),
        },
        identity: identity.model(),
        battery,
        battery_mv: (mv != 0).then_some(mv),
        #[cfg(feature = "board-tlora-pager")]
        battery_details: pager::battery_diagnostics(),
        #[cfg(not(feature = "board-tlora-pager"))]
        battery_details: None,
        queued: Some(QUEUED_FRAMES.load(Ordering::Acquire)),
        link: bluetooth.link,
        bonds: bluetooth.bonds,
        pairing: bluetooth.pairing,
        stats: ui_stats(),
        // Boards without `CAP_TIME` never know what time it is and must
        // not indicate one. On the rest, `None` whenever the device does
        // not know, which the renderer draws as nothing at all—there
        // is deliberately no fallback, because a placeholder would be an
        // indication of the current time.
        #[cfg(not(feature = "external-rtc"))]
        clock: None,
        #[cfg(feature = "external-rtc")]
        clock: umsh_hal::wall_clock::local_hhmm()
            .map(|(hour, minute)| screen::ClockModel { hour, minute }),
    }
}

/// Radio activity for the stats page.
///
/// Sampled when a frame is drawn rather than pushed: the counters move
/// with every frame on the air, and a redraw per frame would burn the
/// panel's power budget reporting numbers nobody is looking at.
fn ui_stats() -> screen::StatsModel {
    // The same ledger the host reads over ULCP, so a reset from the phone
    // clears this page too. `rx_frames` is everything the radio handed up,
    // UMSH or not, which is what the page has always meant.
    screen::StatsModel {
        tx_frames: STATS.get(Counter::TxPackets),
        rx_frames: STATS.get(Counter::RxPackets) + STATS.get(Counter::RxNonUmsh),
        rx_accepted: STATS.get(Counter::RxAccepted),
        forwarded: STATS.get(Counter::Forwarded),
        tx_power_dbm: device_node::tx_power_dbm(),
        // The ledger's scale is 0-65535 for 0-100%; the page shows tenths
        // of a percent, which is the range a tracker lives in.
        duty_permille: (u32::from(DUTY_LEDGER.usage(Instant::now().as_millis())) * 1_000 / 65_535)
            as u16,
    }
}

#[cfg(feature = "board-tlora-pager")]
const DISPLAY_LAYOUT: screen::Layout = screen::Layout::TFT_480X222;
#[cfg(not(feature = "board-tlora-pager"))]
const DISPLAY_LAYOUT: screen::Layout = screen::Layout::OLED_128X64;

/// Render the current page. Best-effort—a display error just leaves the
/// panel stale; it never blocks the protocol paths.
async fn render_frame(display: &mut Display, model: &UiModel, status: &screen::StatusModel<'_>) {
    screen::render_frame(display, &DISPLAY_LAYOUT, model, status);
    let _ = display.flush().await;
}

/// Center a short message, keeping the header so the battery stays
/// readable while the board is busy saying something else.
async fn render_message(
    display: &mut Display,
    status: &screen::StatusModel<'_>,
    title: &str,
    detail: &str,
) {
    screen::render_message(display, &DISPLAY_LAYOUT, status, title, detail);
    let _ = display.flush().await;
}

/// Redraw an awake panel at the next clock or pairing animation boundary.
/// A sleeping panel never arms a timer and catches up when woken.
async fn display_tick(awake: bool, pairing_delay: Option<u64>) {
    if !awake {
        core::future::pending::<()>().await;
    }
    let clock_delay = umsh_hal::wall_clock::millis_to_next_minute().map(u64::from);
    match clock_delay.into_iter().chain(pairing_delay).min() {
        Some(millis) => Timer::after_millis(millis).await,
        None => core::future::pending().await,
    }
}

/// Draw the boot-only artwork without needing journals, identity, or radio.
/// Return its original visible deadline so later ownership handoff cannot
/// blank the panel or restart the splash dwell.
async fn show_boot_splash(display: &mut Display) -> umsh_ux_display_tracker::boot::BootSplash {
    // Pager backlights provide immediate startup feedback, including while
    // the panel resets and its first frame is being drawn.
    #[cfg(not(feature = "board-tlora-pager"))]
    let _ = display.set_display_on(false).await;
    let _ = display.set_brightness(Brightness::NORMAL).await;
    let mut splash = umsh_ux_display_tracker::boot::BootSplash::new();
    screen::render_splash(display, &DISPLAY_LAYOUT, env!("GIT_DESCRIBE"));
    for attempt in 1..=3 {
        match display.flush().await {
            Ok(()) => {
                if display.set_display_on(true).await.is_ok() {
                    let now = Instant::now().as_millis();
                    splash.shown(now);
                    println!("display: boot logo visible at {now} ms (attempt {attempt})");
                    return splash;
                }
            }
            Err(error) => {
                debug_log(format_args!(
                    "display: boot splash transfer failed: {error:?}"
                ));
            }
        }
        Timer::after_millis(20).await;
    }
    // Never time a partially written frame as a successful splash.
    splash.dismiss();
    BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
    splash
}

/// Owns the OLED, the `Vext` rail that powers it (where one exists—
/// on a PMIC board the panel's rail drops in the shutdown path
/// instead), and the display attention policy.
///
/// The panel is emissive, so attention lapsing actually turns it off:
/// full brightness for 20 s, a second-long fall into the dim warning,
/// dark at 30 s. It stays lit for as long as a pairing window is open,
/// because its PIN is the only place that number is shown.
#[embassy_executor::task]
async fn display_task(
    mut display: Display,
    #[cfg(feature = "board-tlora-pager")] mut splash: umsh_ux_display_tracker::boot::BootSplash,
    #[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))] mut vext: Vext,
) {
    #[cfg(feature = "board-tlora-pager")]
    let pager_capture_epoch = pager::input::interactive().await;
    let mut model = UiModel::new(board_menu_items());
    #[cfg(not(feature = "board-tlora-pager"))]
    let mut splash = show_boot_splash(&mut display).await;
    if !splash.is_active() {
        render_frame(
            &mut display,
            &model,
            &ui_status(&device_name_snapshot().await, &IdentityText::current()),
        )
        .await;
        let _ = display.set_display_on(true).await;
    }
    let mut attention = Attention::new(
        DisplayKind::Emissive,
        AttentionConfig::EMISSIVE,
        Instant::now().as_millis(),
    );
    #[cfg(feature = "board-tlora-pager")]
    pager::input::shown(pager_capture_epoch);

    #[cfg(feature = "board-tlora-pager")]
    let mut was_alerting = false;

    loop {
        #[cfg(feature = "board-tlora-pager")]
        pager::set_battery_details_visible(
            attention.accepts_redraw()
                && !splash.is_active()
                && !pager::alert::active()
                && matches!(
                    model.page(),
                    umsh_ux_display_tracker::menu::Page::Detail(
                        MenuItem::BatteryCharge
                            | MenuItem::BatteryCapacity
                            | MenuItem::BatteryGauge
                    )
                ),
        );
        // The name changes rarely but every frame this pass might draw
        // needs it, so it is snapshotted once and lent out; the rest of
        // the status is rebuilt at each draw. The identity is rendered
        // the same way, and is empty until node bring-up runs.
        let name = device_name_snapshot().await;
        let identity = IdentityText::current();

        // Asserting the hold is itself a wake, and on a dark panel that
        // wake is the whole event: a pairing window a host opened has no
        // press behind it. So the transition is carried into this pass
        // rather than dropped. Dropping it leaves the policy believing the
        // panel is lit while the glass stays dark, and every later wake is
        // then a no-op against an already-active state—the panel cannot
        // be brought back at all until a lapse puts the two back in
        // agreement.
        let now = Instant::now().as_millis();
        let mut transition =
            attention.set_hold(HoldReason::Pairing, ble::pairing_window_open(), now);
        #[cfg(feature = "board-tlora-pager")]
        {
            let active = pager::alert::active();
            transition = attention
                .set_hold(HoldReason::Alert, active, now)
                .or(transition);
            if active && splash.dismiss() {
                BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
            }
            if was_alerting && !active {
                transition = attention.wake(now).or(transition);
            }
        }
        SCREEN_FADED.store(attention.is_faded(), Ordering::Release);

        // A panel about to be powered on needs a frame drawn into it
        // first, whether or not an arm below asks for one.
        let mut redraw = transition.is_some();

        let lapse = async {
            match splash.next_deadline().or_else(|| attention.next_deadline()) {
                // A hold pins the panel awake, so there is no deadline to
                // wait for—but a wake it just produced still has to be
                // applied. Falling through to the arm below is what gets
                // this pass to the power-on; blocking here would hold it
                // until some unrelated event arrived.
                None if transition.is_some() => {}
                Some(deadline) => Timer::at(Instant::from_millis(deadline)).await,
                None => core::future::pending().await,
            }
        };
        match select4(
            UI_INPUT_CH.receive(),
            select3(
                // All three are "content moved, redraw if the panel is
                // already lit"; they differ only in what they do to the
                // model, so they share an arm.
                select3(
                    UI_REFRESH.wait(),
                    BATTERY_UI_CHANGED.wait(),
                    display_tick(
                        attention.accepts_redraw(),
                        if splash.is_active() {
                            None
                        } else {
                            screen::pairing_animation_delay_ms(
                                &model,
                                &ui_status(&name, &identity),
                                Instant::now().as_millis(),
                            )
                        },
                    ),
                ),
                async {
                    #[cfg(feature = "board-tlora-pager")]
                    {
                        match select(UI_NOTICE.wait(), pager::alert::DISPLAY_CHANGED.wait()).await {
                            Either::First(notice) => Some(notice),
                            Either::Second(()) => None,
                        }
                    }
                    #[cfg(not(feature = "board-tlora-pager"))]
                    Some(UI_NOTICE.wait().await)
                },
                select(UI_WAKE.wait(), motion_wake()),
            ),
            DISPLAY_SHUTDOWN.wait(),
            select(UI_SPLASH_DISMISS.wait(), lapse),
        )
        .await
        {
            // Do not skip the rest of this pass: it may own the alert's
            // one-shot Woke transition and still need to light the panel.
            #[cfg(feature = "board-tlora-pager")]
            Either4::First(_) if pager::alert::active() => redraw = true,
            Either4::First(input) => {
                let now = Instant::now().as_millis();
                transition = attention.wake(now).or(transition);
                redraw = true;
                #[cfg(feature = "wifi")]
                let effect = model.apply_with_wifi(input, &wifi::ui_snapshot());
                #[cfg(not(feature = "wifi"))]
                let effect = model.apply(input);
                match effect {
                    Some(UiEffect::SelectWifiNetwork(name)) => {
                        #[cfg(feature = "wifi")]
                        {
                            let mut selected = umsh_ulcp_device::net::SelectedNetwork::default();
                            if selected.set(name.as_bytes()).is_ok() {
                                INPUT_CH.send(InEvent::SelectWifiNetwork(selected)).await;
                                redraw = false;
                            }
                        }
                        #[cfg(not(feature = "wifi"))]
                        {
                            let _ = name;
                            model.set_notice(UiNotice::NetworkUnavailable);
                        }
                    }
                    Some(UiEffect::CheckIn) => {
                        device_node::request_beacon(device_node::BeaconTrigger::Button);
                        model.set_notice(UiNotice::CheckInRequested);
                    }
                    Some(UiEffect::StartPairing) => ble::request_pairing(),
                    Some(UiEffect::ClearBonds) => ble::request_clear_bonds(),
                    Some(UiEffect::Toggle(id)) => {
                        // Applied by the ULCP session, so the property, an
                        // attached host and the saved snapshot all see the
                        // same flip.
                        //
                        // Which is also why the frame is *not* drawn here.
                        // The session runs in another task and has not
                        // moved the value yet, so a redraw on this pass
                        // would push the old state back onto the panel and
                        // call it fresh. The frame that shows the flip is
                        // the one `UI_REFRESH` will drive out of
                        // `publish_dev_domain`. Nothing else on screen
                        // needed this press: a notice only ever lives on
                        // the status page, and a toggle entry never does.
                        INPUT_CH.send(InEvent::Toggle(ulcp_setting(id))).await;
                        redraw = false;
                    }
                    None => {}
                }
            }
            Either4::Second(event) => match event {
                // Content the user did not ask for: redraw if the panel
                // is already lit, but never light it. That rule is what
                // keeps a battery sample from waking a board left on a
                // desk every minute.
                Either3::First(_) => redraw = true,
                Either3::Second(None) => redraw = true,
                Either3::Second(Some(notice)) => {
                    model.set_notice(notice);
                    transition = attention.wake(Instant::now().as_millis()).or(transition);
                    redraw = true;
                }
                // A wake on its own changes no content—a lit panel is
                // already showing the truth, and the events that do
                // change something raise `UI_REFRESH` alongside this.
                Either3::Third(Either::First(())) => {
                    transition = attention.wake(Instant::now().as_millis()).or(transition);
                    redraw = transition.is_some();
                }
                Either3::Third(Either::Second(())) => {
                    if attention.is_lapsed() {
                        transition = attention
                            .wake_from_motion(Instant::now().as_millis())
                            .or(transition);
                        redraw = transition.is_some();
                        debug_log(format_args!("motion: display wake"));
                    } else {
                        debug_log(format_args!(
                            "motion: consumed while {:?}",
                            attention.state()
                        ));
                    }
                }
            },
            Either4::Third(()) => {
                render_message(
                    &mut display,
                    &ui_status(&name, &identity),
                    "Powering off",
                    if cfg!(feature = "board-tlora-pager") {
                        ""
                    } else {
                        "hold to wake"
                    },
                )
                .await;
                let _ = display.set_display_on(true).await;
                Timer::after_millis(1_200).await;
                let _ = display.set_display_on(false).await;
                #[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
                vext.disable();
                DISPLAY_SHUTDOWN_DONE.signal(());
                core::future::pending::<()>().await;
            }
            Either4::Fourth(event) => {
                if matches!(event, Either::First(())) && splash.dismiss() {
                    redraw = true;
                } else {
                    transition = attention.poll(Instant::now().as_millis()).or(transition);
                }
            }
        }

        redraw |= splash.poll(Instant::now().as_millis());
        #[cfg(feature = "board-tlora-pager")]
        {
            let active = pager::alert::active();
            let now = Instant::now().as_millis();
            transition = attention
                .set_hold(HoldReason::Alert, active, now)
                .or(transition);
            if active {
                splash.dismiss();
                BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
            } else if was_alerting {
                transition = attention.wake(now).or(transition);
            }
        }
        #[cfg(feature = "board-tlora-pager")]
        let pager_capture_epoch = if matches!(transition, Some(Transition::Woke)) {
            Some(pager::input::interactive().await)
        } else {
            None
        };
        match transition {
            Some(Transition::Lapsed) => {
                // Waking always lands on the status page rather than on
                // whatever was abandoned here.
                model.go_home();
                #[cfg(feature = "board-tlora-pager")]
                let before_display_off = pager::input::activity();
                let off = display.set_display_on(false).await;
                #[cfg(feature = "board-tlora-pager")]
                if off.is_ok() {
                    pager::input::dark(before_display_off);
                }
                #[cfg(not(feature = "board-tlora-pager"))]
                let _ = off;
                redraw = false;
            }
            // One step of the fall, not the whole of it: the policy sends
            // one of these per ramp step and says where between the
            // panel's two contrasts to sit. Nothing is redrawn—a
            // contrast write leaves the framebuffer alone, which is what
            // makes a fade affordable on a panel that redraws only on
            // events.
            Some(Transition::Dimming) => {
                let _ = display
                    .set_brightness(brightness_from_permille(attention.brightness_permille()))
                    .await;
                redraw = false;
            }
            Some(Transition::Woke) | None => {}
        }

        #[cfg(feature = "board-tlora-pager")]
        {
            redraw |= pager::alert::active() || was_alerting;
        }
        if redraw && !splash.is_active() && attention.accepts_redraw() {
            let status = ui_status(&name, &identity);
            if let Some(wifi) = &status.wifi {
                model.refresh_wifi(wifi);
            }
            #[cfg(feature = "board-tlora-pager")]
            if pager::alert::active() {
                screen::render_message(
                    &mut display,
                    &DISPLAY_LAYOUT,
                    &status,
                    "Locate alert",
                    "Press any key to stop.",
                );
                if pager::alert::bright() {
                    display.invert();
                }
                let _ = display.flush().await;
            } else {
                render_frame(&mut display, &model, &status).await;
            }
            #[cfg(not(feature = "board-tlora-pager"))]
            render_frame(&mut display, &model, &status).await;
            if BOOT_SPLASH_ACTIVE.swap(false, Ordering::AcqRel) {
                let _ = attention.wake(Instant::now().as_millis());
            }
        }
        // Ordered after the redraw so the panel never lights on a stale
        // frame.
        if matches!(transition, Some(Transition::Woke)) {
            let _ = display.set_brightness(Brightness::NORMAL).await;
            let on = display.set_display_on(true).await;
            #[cfg(feature = "board-tlora-pager")]
            if on.is_ok() {
                pager::input::shown(pager_capture_epoch.unwrap());
            }
            #[cfg(not(feature = "board-tlora-pager"))]
            let _ = on;
        }
        #[cfg(feature = "board-tlora-pager")]
        {
            let active = pager::alert::active();
            if active || was_alerting {
                let _ = display
                    .set_brightness(if active && pager::alert::bright() {
                        Brightness::ALERT
                    } else {
                        Brightness::NORMAL
                    })
                    .await;
            }
            was_alerting = active;
        }
    }
}

/// PRG button (GPIO0, active low), resolved into the display-tracker
/// vocabulary: single advances the menu, double selects, a 1–4 second
/// hold released by the user goes back, and a continuing four-second
/// hold powers the board off.
///
/// A gesture that begins once the panel has started to fade only brings
/// it back to full: against a dark panel the user cannot have meant to
/// act on something they could not see, and against a fading one the
/// press is the answer to the fade's own question. The power-off hold is
/// the sole exception, since a device that has gone dark still has to be
/// switchable-off.
#[embassy_executor::task]
#[cfg(not(feature = "board-tlora-pager"))]
async fn button_task(mut button: Input<'static>) {
    const DEBOUNCE: Duration = Duration::from_millis(30);
    let mut fsm = ButtonFsm::new(umsh_ux_display_tracker::button_timings());
    let mut gate = Gate::new();
    let mut pressed = button.is_low();
    loop {
        let event = {
            let now_ms = Instant::now().as_millis();
            let edge_fut = async {
                if pressed {
                    // Held: a release cannot be slept through anyway
                    // (the hold itself keeps deadlines short), but the
                    // level wake keeps the story uniform.
                    button.wait_for(Event::HighLevel).await;
                    umsh_bsp_esp32::jitter::sample();
                    Timer::after(DEBOUNCE).await;
                    ButtonEdge::Release
                } else {
                    // Idle park, often for the 60 s floor: wake-enabled
                    // so a press wakes the chip from light sleep
                    // instead of the wait pinning it awake.
                    button.wait_for(Event::LowLevel).await;
                    // When a finger arrives is nothing the chip's clock
                    // could have predicted.
                    umsh_bsp_esp32::jitter::sample();
                    Timer::after(DEBOUNCE).await;
                    ButtonEdge::Press
                }
            };
            let deadline = fsm.next_deadline().unwrap_or(now_ms.saturating_add(60_000));
            match select(edge_fut, Timer::at(Instant::from_millis(deadline))).await {
                Either::First(edge) => {
                    pressed = matches!(edge, ButtonEdge::Press);
                    if pressed {
                        // Latch the pre-wake screen state, read on the
                        // press edge—this task can park for a minute
                        // awaiting an edge, and the panel lapses dark
                        // during exactly such a park. Then wake on the
                        // press, not on the resolved gesture, so the
                        // panel is already lit while the user is still
                        // deciding what the press will become.
                        gate.set(
                            GateReason::ScreenFaded,
                            SCREEN_FADED.load(Ordering::Acquire),
                        );
                        gate.set(
                            GateReason::BootSplash,
                            BOOT_SPLASH_ACTIVE.load(Ordering::Acquire),
                        );
                        gate.on_press();
                        UI_WAKE.signal(());
                    }
                    fsm.on_edge(edge, Instant::now().as_millis())
                }
                Either::Second(()) => fsm.poll(Instant::now().as_millis()),
            }
        };

        if let Some(event) = event {
            match gate.disposition(event) {
                Disposition::ConsumedByWake | Disposition::CancelAlert | Disposition::Discard => {}
                Disposition::DismissSplash => UI_SPLASH_DISMISS.signal(()),
                Disposition::Deliver => {
                    let input = match event {
                        ButtonEvent::Single => Some(UiInput::Forward),
                        ButtonEvent::Double => Some(UiInput::Select),
                        ButtonEvent::Long => Some(UiInput::Backward),
                        ButtonEvent::VeryLong => {
                            pressed = false;
                            fsm = ButtonFsm::new(umsh_ux_display_tracker::button_timings());
                            SHUTDOWN_REQUEST.signal(());
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

/// Heartbeat LED plus the RWDT feed. Sharing one task keeps the
/// watchdog tied to something visibly alive: if the LED stops, the
/// reset follows. Pairing mode switches to a fast blink.
///
/// It also owns the shutdown sequence, because it owns the `Rtc` that
/// deep sleep is entered through.
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
#[embassy_executor::task]
async fn heartbeat_task(
    mut led: Output<'static>,
    mut rtc: Rtc<'static>,
    mut deep_sleep: esp_rtos::sleep::DeepSleep,
) -> ! {
    loop {
        rtc.rwdt.feed();
        // The idle blink spends four seconds dark, so the shutdown hold
        // has to interrupt the wait rather than be noticed after it.
        let (on_ms, off_ms) = if ble::pairing_indicated() {
            (100, 300)
        } else {
            // Four seconds apart matches the nRF boards' heartbeat
            // (`LedTimings::default`). The pulse does not: the white LED
            // on both Heltec boards is far brighter than their status
            // LEDs, so it takes a bare flick to read as alive rather
            // than their 20 ms.
            //
            // Four seconds is also as slow as this loop may go—it
            // carries the `WDT_TIMEOUT` feed, and half of eight seconds
            // is the margin the watchdog has left for a late wake.
            (3, 4_000)
        };
        led.set_high();
        if with_timeout(Duration::from_millis(on_ms), SHUTDOWN_REQUEST.wait())
            .await
            .is_ok()
        {
            shutdown(&mut led, &mut rtc, &mut deep_sleep).await;
        }
        led.set_low();
        if with_timeout(Duration::from_millis(off_ms), SHUTDOWN_REQUEST.wait())
            .await
            .is_ok()
        {
            shutdown(&mut led, &mut rtc, &mut deep_sleep).await;
        }
    }
}

/// Quiesce the board and enter deep sleep, waking on the PRG button.
///
/// Ordering matters at every step:
///
/// - The radio goes to chip sleep first. It is powered from the board's
///   main rail rather than from `Vext`, so it survives deep sleep and
///   would otherwise sit in receive and dominate the sleeping current.
/// - The display task renders its farewell and drops `Vext` on its own,
///   since it owns both; a bounded wait keeps a wedged panel from
///   stranding a board the user has asked to turn off.
/// - The wake source is armed only after the button is released.
///   Arming it under a still-held button wakes the board immediately
///   from the very press that put it to sleep.
///
/// Counter persistence needs nothing here: `MacHandle::next_event`
/// flushes it as it goes, so there is no buffered state to lose.
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
async fn shutdown(
    led: &mut Output<'static>,
    rtc: &mut Rtc<'static>,
    deep_sleep: &mut esp_rtos::sleep::DeepSleep,
) -> ! {
    debug_log(format_args!("shutdown: power-off hold"));
    DEVICE_CTL.shutdown();
    DISPLAY_SHUTDOWN_DONE.reset();
    DISPLAY_SHUTDOWN.signal(());
    let _ = with_timeout(Duration::from_secs(2), DISPLAY_SHUTDOWN_DONE.wait()).await;
    led.set_low();

    // `button_task` owns GPIO0 for the life of the board. Temporarily
    // duplicate its input to await release; neither handle drives it.
    // After the final await, arm low-power wake and enter deep sleep
    // without letting another task change the pin configuration.
    {
        let button = Input::new(
            unsafe { esp_hal::peripherals::GPIO0::steal() },
            InputConfig::default().with_pull(Pull::Up),
        );
        // Feed the watchdog across the release wait: a user may lean on
        // the button for longer than the 8 s timeout, and rebooting the
        // board they just asked to switch off is the one outcome worse
        // than a slow shutdown.
        while button.is_low() {
            rtc.rwdt.feed();
            Timer::after_millis(50).await;
        }
        Timer::after_millis(50).await;
        rtc.rwdt.feed();
    }

    rtc.rwdt.disable();
    let mut wake = Input::new(
        unsafe { esp_hal::peripherals::GPIO0::steal() },
        InputConfig::default().with_pull(Pull::Up),
    );
    wake.apply_wakeup_config(&esp_hal::gpio::WakeupConfig::default().with_low_power_path(true))
        .expect("GPIO0 supports low-power wake");
    wake.listen(Event::LowLevel);
    deep_sleep.deep_sleep();
}

/// The RWDT feed, with no LED behind it—this board's only LEDs belong
/// to the PMIC's charger and the receiver's PPS output.
///
/// It also owns the shutdown sequence, because it owns the `Rtc` whose
/// watchdog has to keep getting fed across the button-release wait.
#[cfg(feature = "pmic-axp2101")]
#[embassy_executor::task]
async fn heartbeat_task(mut rtc: Rtc<'static>, pmic: &'static SharedPmic) -> ! {
    loop {
        rtc.rwdt.feed();
        // The feed cadence caps light-sleep residency (each feed is a
        // timer wake), so it runs as slow as the watchdog allows; the
        // shutdown signal still lands instantly through the timeout.
        if with_timeout(
            Duration::from_secs(HEARTBEAT_FEED_SECS),
            SHUTDOWN_REQUEST.wait(),
        )
        .await
        .is_ok()
        {
            shutdown(&mut rtc, pmic).await;
        }
    }
}

/// Quiesce the board and hand the power topology back to the PMIC—
/// "off" on this board is a PMIC power-off, not deep sleep, and the
/// POWER key brings it back with no firmware involved.
///
/// Ordering matters at every step:
///
/// - The radio goes to chip sleep first, so it stops transmitting
///   mid-frame before its rail is cut.
/// - The display task renders its farewell and switches the panel off;
///   a bounded wait keeps a wedged panel from stranding a board the
///   user has asked to turn off.
/// - The BOOT button must be released before the power-off: the PMIC
///   cuts DCDC1 while GPIO0 is held low, and a strapped-low GPIO0 at
///   the *next* power-on would drop the board into the ROM bootloader.
/// - The switched rails drop before the soft power-off so nothing is
///   back-powered through a peripheral bus during the down-ramp.
///
/// Counter persistence needs nothing here: `MacHandle::next_event`
/// flushes it as it goes, so there is no buffered state to lose. And if
/// the PMIC refuses the power-off, the abandoned RWDT resets the board
/// back to a running state—worse than off, better than wedged.
#[cfg(feature = "pmic-axp2101")]
async fn shutdown(rtc: &mut Rtc<'static>, pmic: &'static SharedPmic) -> ! {
    debug_log(format_args!("shutdown: power-off hold"));
    DEVICE_CTL.shutdown();
    DISPLAY_SHUTDOWN_DONE.reset();
    DISPLAY_SHUTDOWN.signal(());
    let _ = with_timeout(Duration::from_secs(2), DISPLAY_SHUTDOWN_DONE.wait()).await;

    // GPIO0 is stolen rather than handed over: `button_task` holds an
    // `Input` on it for the life of the board. Both uses are read-only,
    // nothing drives the pin, and this function never returns—so no
    // other task observes the duplicate.
    {
        let button = Input::new(
            unsafe { esp_hal::peripherals::GPIO0::steal() },
            InputConfig::default().with_pull(Pull::Up),
        );
        // Feed the watchdog across the release wait: a user may lean on
        // the button for longer than the 8 s timeout, and rebooting the
        // board they just asked to switch off is the one outcome worse
        // than a slow shutdown.
        while button.is_low() {
            rtc.rwdt.feed();
            Timer::after_millis(50).await;
        }
        Timer::after_millis(50).await;
        rtc.rwdt.feed();
    }

    {
        let mut pmic = pmic.lock().await;
        let _ = board_power::shutdown_rails(&mut pmic).await;
        let _ = pmic.power_off().await;
    }
    // Supply is dropping. If it somehow does not, stop feeding the RWDT
    // and let it reset the board to a known-running state.
    loop {
        Timer::after_secs(1).await;
    }
}

// ─── Boot ────────────────────────────────────────────────────────────────

/// Map the retained hardware reset cause (plus a captured panic
/// message) onto the CRP `PROP_LAST_STATUS` reset statuses.
fn boot_reason(panicked: bool) -> Status {
    if panicked {
        return Status::RESET_CRASH;
    }
    let reason = esp_hal::system::reset_reason();

    // The core and system timers are named the same on both parts. The
    // per-CPU ones are not: the dual-core classic ESP32 numbers them by
    // CPU (`Cpu0Sw`, `Cpu0RtcWdt`) and has no second CPU watchdog and no
    // super-watchdog, both of which the S3 does have.
    let watchdog = matches!(
        reason,
        Some(
            SocResetReason::CoreMwdt0
                | SocResetReason::CoreMwdt1
                | SocResetReason::CoreRtcWdt
                | SocResetReason::CpuMwdt0
                | SocResetReason::SysRtcWdt
        )
    );
    #[cfg(feature = "chip-esp32")]
    let watchdog = watchdog || matches!(reason, Some(SocResetReason::Cpu0RtcWdt));
    #[cfg(feature = "chip-esp32s3")]
    let watchdog = watchdog
        || matches!(
            reason,
            Some(
                SocResetReason::CpuMwdt1 | SocResetReason::CpuRtcWdt | SocResetReason::SysSuperWdt
            )
        );
    if watchdog {
        return Status::RESET_WATCHDOG;
    }

    #[cfg(feature = "chip-esp32")]
    let cpu_sw = matches!(reason, Some(SocResetReason::Cpu0Sw));
    #[cfg(feature = "chip-esp32s3")]
    let cpu_sw = matches!(reason, Some(SocResetReason::CpuSw));
    if cpu_sw
        || matches!(
            reason,
            Some(SocResetReason::CoreSw | SocResetReason::CoreDeepSleep)
        )
    {
        return Status::RESET_SOFTWARE;
    }

    Status::RESET_POWER_ON
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    // Point the shared runtime's log seam at this board's debug channel
    // before anything shared runs, so the journal mount lines are not
    // lost.
    umsh_ulcp_runtime::log::set_debug_log(debug_log);
    // 80 MHz, not `CpuClock::max()`: this workload is idle-dominated and
    // an idle `waiti` core still clocks its way through every wakeup, so
    // the frequency is a direct battery cost (Meshtastic parks its ESP32
    // targets at 80 MHz for the same reason). esp-radio's documented
    // floor is 80 MHz, and APB stays at 80 MHz either way so SPI/UART
    // timing is unchanged.
    let clocks = {
        #[allow(unused_mut)]
        let mut clocks = esp_hal::clock::ClockConfig::from(CpuClock::_80MHz);
        #[cfg(feature = "chip-esp32s3")]
        {
            // The main crystal supports BLE light sleep without requiring
            // a separate 32 kHz crystal on the board.
            clocks.ble_lp_clk = Some(esp_hal::clock::ll::BleLpClkConfig::Xtal);
        }
        clocks
    };
    let config = esp_hal::Config::default().with_cpu_clock(clocks);
    #[cfg_attr(not(feature = "entropy-sar-adc"), allow(unused_mut))]
    let mut peripherals = esp_hal::init(config);
    #[cfg(feature = "board-tlora-pager")]
    let pager_boot_lights =
        board::display::BootBacklights::new(peripherals.GPIO42, peripherals.GPIO46);
    #[cfg(feature = "board-tlora-pager")]
    let pager_boot_guard = esp_hal::rtc_cntl::WakeLock::new();
    #[cfg(all(feature = "wifi", feature = "debug-log"))]
    wifi_memory::init();
    // umsh-node and umsh-sync use `alloc`. The classic ESP32 has roughly
    // half the S3's data RAM and the BT controller takes a fixed bite out
    // of it before the application sees any, so its heap is smaller.
    #[cfg(all(feature = "chip-esp32s3", not(feature = "wifi")))]
    esp_alloc::heap_allocator!(size: 72 * 1024);
    #[cfg(feature = "wifi")]
    {
        // Both regions are internal RAM. The bootloader's former arena
        // becomes available before main, leaving the ordinary arena room
        // for the executor and stack.
        // The Heltec keeps its session internally; the Pager adds DMA state.
        // Their smaller heaps leave room for nested calls and interrupts.
        #[cfg(feature = "board-heltec-v3")]
        esp_alloc::heap_allocator!(size: 40 * 1024);
        // Leave room for sleep and audio DMA/task state while preserving the
        // checked 32 KiB nested-call reserve (82 KiB total internal heap).
        #[cfg(feature = "board-tlora-pager")]
        esp_alloc::heap_allocator!(size: 18 * 1024);
        #[cfg(not(any(feature = "board-heltec-v3", feature = "board-tlora-pager")))]
        // Keep the 20 KiB stack reserve and nested task construction headroom
        // with the upgraded radio/scheduler's internal static storage.
        esp_alloc::heap_allocator!(size: 44 * 1024);
        esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);
    }
    #[cfg(feature = "psram")]
    external::init(peripherals.PSRAM);
    // The classic ESP32's `dram_seg` is only 128 KiB once esp-hal reserves
    // the BT controller's 64 KiB, and the static side of this image does
    // not fit alongside a heap of any useful size. `dram2_seg` is the
    // ~96 KiB of DRAM past the ROM data and stack areas—unusable for
    // zero-initialized statics (NOLOAD, nothing clears it) but fine for
    // a heap arena, which is `MaybeUninit` by nature. Smaller than the
    // S3's 72 KiB deliberately: on the S3 the BLE controller allocates
    // from this heap, while here it lives in its own 64 KiB reservation,
    // so this heap only carries umsh-node/umsh-sync (8 KiB on the nRF
    // boards) plus esp-radio's residual allocations—and the device
    // node's ~32 KiB Mac arena shares the same 96 KiB region.
    #[cfg(feature = "chip-esp32")]
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 48 * 1024);

    let mut rtc = Rtc::new(peripherals.RTC_TIMER);
    rtc.rwdt.set_timeout(RwdtStage::Stage0, WDT_TIMEOUT);
    rtc.rwdt.enable();

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    // Automatic light sleep: when the scheduler runs out of ready
    // tasks, no `WakeLock` is held, and the next timer deadline is far
    // enough away, the idle hook enters light sleep until that deadline
    // (GPIO wake always armed) instead of spinning `waiti` at 80 MHz.
    // S3 BLE supplies a sleep veto and wake deadline between events.
    // Wired-transport and UART drivers retain their lifetime wake locks,
    // and GPIO level waits arm wake sources. Original ESP32 BLE still
    // holds a lock from controller initialization to deinitialization.
    // A board whose locks never all clear simply falls back to WFI.
    let sleep = esp_rtos::sleep::configure(peripherals.LPWR);
    esp_rtos::start_with_idle_hook(timg0.timer0, sleep.light_sleep_hook);

    println!(
        "{} {} on {}",
        env!("CARGO_PKG_NAME"),
        DEV_VERSION,
        board::BOARD_NAME,
    );

    let mut panic_buf = [0u8; umsh_bsp_esp32::panic_capture::MSG_CAPACITY];
    let panic_report =
        umsh_bsp_esp32::panic_capture::take_panic_message(&mut panic_buf).map(|msg| {
            println!("previous boot panicked: {msg}");
            // Copied out char-by-char: the capture buffer is borrowed from
            // the stack and the message may be longer than the report slot,
            // so truncation has to stay on a char boundary.
            let mut owned: heapless::String<128> = heapless::String::new();
            for c in msg.chars() {
                if owned.push(c).is_err() {
                    break;
                }
            }
            owned
        });
    let boot_reason = boot_reason(panic_report.is_some());

    // ── PMU first: nothing else is powered until its rails are up ────────
    // Hardware doc §5.3: the radio, panel, and receiver sit behind
    // AXP2101 rails, and probing them before this block reports parts
    // missing that are merely dark.
    #[cfg(feature = "pmic-axp2101")]
    let pmu_bus: &'static PmuBus = {
        let pmu_i2c = I2c::new(
            peripherals.I2C1,
            I2cConfig::default().with_frequency(Rate::from_khz(100)),
        )
        .unwrap()
        .with_sda(peripherals.GPIO42)
        .with_scl(peripherals.GPIO41)
        .into_async();
        PMU_BUS.init(Mutex::new(pmu_i2c))
    };
    #[cfg(feature = "pmic-axp2101")]
    let pmic: &'static SharedPmic = {
        let mut pmic = Axp2101::new(I2cDevice::new(pmu_bus));
        // The rail-settle cycle is for supplies that were genuinely
        // down; a warm restart's rails were under firmware control the
        // whole time.
        let cold_boot = boot_reason == Status::RESET_POWER_ON;
        board_power::bring_up(&mut pmic, &mut Delay, cold_boot)
            .await
            .unwrap_or_else(|e| panic!("pmu bring-up failed: {e:?}"));
        println!("pmu: rails up (cold_boot={cold_boot})");
        // Seed the VBUS mirror from a direct read, so a battery boot
        // does not spend its first minute pretending to have USB (the
        // optimistic initial value) while the battery task waits out
        // its first cadence.
        if let Ok(vbus) = pmic.vbus_present().await {
            VBUS_PRESENT.store(vbus, Ordering::Release);
        }
        PMIC_CELL.init(Mutex::new(pmic))
    };

    #[cfg(feature = "board-tlora-pager")]
    let (pmu_bus, expander, initial_battery) =
        pager::power_up(peripherals.I2C0, peripherals.GPIO3, peripherals.GPIO2).await;
    #[cfg(feature = "board-tlora-pager")]
    let (pager_panel_cs, radio_cs) = {
        // All four shared-SPI devices must be deselected before the first
        // panel command, including the not-yet-initialized LoRa modem.
        let sd = Output::new(peripherals.GPIO21, Level::High, OutputConfig::default());
        let nfc = Output::new(peripherals.GPIO39, Level::High, OutputConfig::default());
        core::mem::forget((sd, nfc));
        (
            Output::new(peripherals.GPIO38, Level::High, OutputConfig::default()),
            Output::new(peripherals.GPIO36, Level::High, OutputConfig::default()),
        )
    };
    #[cfg(feature = "board-tlora-pager")]
    let pager_spi = pager::spi_bus(
        peripherals.SPI2,
        peripherals.DMA_CH0,
        peripherals.GPIO35,
        peripherals.GPIO34,
        peripherals.GPIO33,
    );
    #[cfg(feature = "board-tlora-pager")]
    let pager_boot_display = {
        let mut panel = pager::display(
            pager_spi,
            pager_panel_cs,
            peripherals.GPIO37,
            pager_boot_lights,
        );
        if panel.init().await.is_ok() {
            let splash = show_boot_splash(&mut panel).await;
            Some((panel, splash))
        } else {
            let _ = panel.set_display_on(false).await;
            BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
            debug_log(format_args!("pager: display init failed"));
            None
        }
    };
    #[cfg(feature = "board-tlora-pager")]
    {
        pager::input::init_encoder(peripherals.IO_MUX, peripherals.GPIO40, peripherals.GPIO41);
        spawner.spawn(pager::input::coordinator().unwrap());
        spawner.spawn(pager::input::navigation_task().unwrap());
        let config = InputConfig::default().with_pull(Pull::Up);
        spawner.spawn(
            pager::input::button_task(Input::new(peripherals.GPIO7, config), false).unwrap(),
        );
        spawner
            .spawn(pager::input::button_task(Input::new(peripherals.GPIO0, config), true).unwrap());
        spawner.spawn(
            pager::input::keyboard_task(Input::new(peripherals.GPIO6, config), pmu_bus).unwrap(),
        );
        spawner.spawn(pager::battery_task(pmu_bus, initial_battery).unwrap());
        pager::alert::spawn(
            spawner,
            pmu_bus,
            expander,
            peripherals.I2S0,
            peripherals.DMA_CH1,
            peripherals.GPIO10,
            peripherals.GPIO11,
            peripherals.GPIO18,
            peripherals.GPIO45,
        );
        #[cfg(feature = "motion-qualification")]
        spawner.spawn(pager::motion_qualification::task(pmu_bus, peripherals.GPIO8).unwrap());
        #[cfg(not(feature = "motion-qualification"))]
        spawner.spawn(pager::motion::task(pmu_bus, peripherals.GPIO8).unwrap());
        spawner.spawn(pager::heartbeat_task(rtc, sleep.deep_sleep, expander, pmu_bus).unwrap());
    }

    // The hardware wall clock, read once before anything else competes
    // for the bus. `ExternalRtc` applies only while the clock is unset,
    // so a later GNSS fix or host write outranks it.
    #[cfg(feature = "external-rtc")]
    let wall_clock_rtc: Option<&'static RtcMutex> = {
        let mut rtc_chip = RtcChip::new(I2cDevice::new(pmu_bus));
        #[cfg(feature = "board-tlora-pager")]
        if rtc_chip.init().await.is_err() {
            println!("rtc: clock output configuration failed");
        }
        match rtc_chip.read().await {
            Ok(Some(epoch)) => {
                umsh_hal::wall_clock::apply(
                    epoch,
                    umsh_hal::wall_clock::TimeSource::ExternalRtc,
                    false,
                );
                println!("rtc: clock restored");
                Some(RTC_CELL.init(Mutex::new(rtc_chip)))
            }
            Ok(None) => {
                println!("rtc: no stored time");
                Some(RTC_CELL.init(Mutex::new(rtc_chip)))
            }
            // A chip that does not answer at boot is not going to answer
            // a writeback either; the board keeps time in RAM only.
            Err(_) => {
                println!("rtc: not responding");
                None
            }
        }
    };

    #[cfg(feature = "pmic-axp2101")]
    {
        let pmu_irq = Input::new(
            peripherals.GPIO40,
            InputConfig::default().with_pull(Pull::Up),
        );
        spawner.spawn(pmu_irq_task(pmic, pmu_irq).unwrap());
        spawner.spawn(heartbeat_task(rtc, pmic).unwrap());
    }

    #[cfg(feature = "board-heltec-v3")]
    let led = Output::new(peripherals.GPIO35, Level::Low, OutputConfig::default());
    #[cfg(feature = "board-heltec-v2")]
    let led = Output::new(peripherals.GPIO25, Level::Low, OutputConfig::default());
    // The Heltecs' power-off is deep sleep, entered through the same
    // `Sleep` handle whose idle hook was installed above—LPWR has one
    // owner now. A PMIC board powers off through the PMIC instead and
    // has no use for the deep-sleep half.
    #[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
    spawner.spawn(heartbeat_task(led, rtc, sleep.deep_sleep).unwrap());
    #[cfg(feature = "pmic-axp2101")]
    let _ = sleep;

    // ── Vext rail and battery ADC ────────────────────────────────────────
    // The classic ESP32 shares ADC2 exclusively between the battery
    // divider and the radio; the V2 sampler therefore claims the ADC
    // per sample under [`ADC2_ARBITER`] instead of holding it, so the
    // BLE supervisor can bring the controller up and down freely. The
    // V3's ADC1 is independent, and a PMIC board has no ADC at all—
    // its rails came up above, and the battery is read over the PMU
    // bus.
    #[cfg(feature = "board-heltec-v3")]
    let mut vext = Vext::new(peripherals.GPIO36);
    #[cfg(feature = "board-heltec-v2")]
    let mut vext = board::vext::init(peripherals.GPIO21);

    // The SAR ADC noise source borrows ADC1 and leaves the block reset,
    // so it is read before anything else is built on the unit.
    #[cfg(feature = "entropy-sar-adc")]
    let sar_adc_noise = entropy::sar_adc(peripherals.RNG.reborrow(), peripherals.ADC1.reborrow());
    #[cfg(not(feature = "entropy-sar-adc"))]
    let sar_adc_noise = None;

    #[cfg(feature = "board-heltec-v3")]
    let sampler = BatterySampler::new(peripherals.ADC1, peripherals.GPIO1, peripherals.GPIO37);
    #[cfg(feature = "board-heltec-v2")]
    let sampler = BatterySampler::new(peripherals.ADC2, peripherals.GPIO13, vext);

    // ── Flash: discover the `umsh` partition (never hardcoded) ───────────
    let (flash, partition) = flash_store::open_partition(peripherals.FLASH)
        .unwrap_or_else(|e| panic!("umsh partition not found: {e:?}"));
    println!(
        "storage: umsh partition 0x{:06x}..0x{:06x}",
        partition.start, partition.end,
    );
    static SHARED_FLASH: StaticCell<journals::SharedFlash> = StaticCell::new();
    let shared: &'static journals::SharedFlash = SHARED_FLASH.init(journals::shared(flash));

    // The radio peripherals: each is constructed into a controller by its
    // own supervisor, one lifecycle per enable cycle—and one of them is
    // borrowed briefly below if the entropy pool needs a hardware
    // bootstrap before any supervisor exists.
    #[cfg(feature = "ble")]
    let mut bt = peripherals.BT;
    #[cfg(feature = "wifi")]
    #[cfg_attr(feature = "ble", allow(unused_mut))]
    let mut wifi_radio = peripherals.WIFI;

    // ── Entropy pool: seeded from flash, healed by the TRNG ──────────────
    // A boot with a stored seed needs no hardware entropy to be safe. One
    // without—first boot, or the boot completing a factory reset—reads
    // the RF-gated TRNG through a radio brought up just for the draw,
    // never through an operational controller that may sleep. Neither
    // depends on a radio the operator has switched off: the switch
    // governs the transport, not this.
    let seed_store = journals::SeedStore::mount(shared, &partition).await;
    #[cfg(feature = "ble")]
    let boot_harvest = || ble::harvest_trng_once(&mut bt);
    #[cfg(not(feature = "ble"))]
    let boot_harvest = || wifi::harvest_trng_once(&mut wifi_radio);
    let mut entropy_service = entropy::boot(seed_store, sar_adc_noise, boot_harvest).await;
    let mut pool_draw = |label: &[u8], out: &mut [u8]| entropy_service.draw(label, out);

    // ── Journals: BLE security, snapshot, identity, node counters ────────
    // Mounted before the ULCP session starts: a stored snapshot must be
    // restored (and the PHY re-applied) and the persisted device
    // identity installed before the first host command.
    #[cfg(feature = "ble")]
    let ble_store_handle = ble::mount(shared, &partition, &mut pool_draw).await;
    let (proto_store, boot_snapshot) =
        SnapshotStore::mount(shared, journals::proto_page0(&partition)).await;
    let (mut identity_store, identity_payload) =
        ProtoStore::mount(shared, journals::identity_page0(&partition)).await;
    let node_counters = init_node_counters();
    mount_node_counters(node_counters, shared, journals::counter_page0(&partition)).await;

    // Both halves of the persisted keypair: the public key seeds the
    // session's PROP_DEV_KEY surface, the secret brings up the device
    // node's MAC identity.
    //
    // A device identity always exists. When the journal is empty—a
    // factory-fresh board, or the boot that completes a factory reset—
    // one is generated here and persisted before anything can observe
    // its absence, so identity is never a commissioning step the
    // operator has to perform.
    //
    // The draw comes from the entropy pool, whose no-seed bootstrap
    // path above ran on the RF-gated TRNG—so a first-boot identity is
    // true-random by construction, and a later regeneration inherits
    // the pool's ratcheted, TRNG-healed state.
    let mut identity_keys = identity_payload
        .as_deref()
        .and_then(umsh_journal_store::proto::decode_identity);
    if identity_keys.is_none() {
        let mut secret = [0u8; 32];
        pool_draw(b"device-identity", &mut secret);
        let (public, record) = driver::device_identity_record(&secret);
        // A persist failure is not fatal: the device runs on this key
        // for the current boot and generates another next time.
        match identity_store.persist(&record).await {
            Ok(()) => println!("device identity generated at first boot"),
            Err(()) => {
                println!("device identity generated but persist FAILED—volatile this boot")
            }
        }
        identity_keys = Some((secret, public));
    }
    let boot_identity_keys = identity_keys;
    // A replaced identity leaves its TX boundary behind in the counter
    // journal; drop it so the map cannot silt up.
    if let Some((_, public)) = boot_identity_keys.as_ref() {
        prune_stale_tx_counters(node_counters, public).await;
    }
    println!(
        "journals: snapshot={} identity={} bonds={}",
        boot_snapshot.is_some(),
        boot_identity_keys.is_some(),
        ble::panel().bonds,
    );

    // Seed the identity-generation and device-node CSPRNGs from the
    // entropy pool. Each also reads a reseed slot, which is how a harvest
    // taken later in this boot reaches it.
    let mut identity_seed = [0u8; 32];
    pool_draw(b"identity-rng", &mut identity_seed);
    let identity_rng = IdentityRng::new(identity_seed, &entropy::SESSION_RESEED);
    let mut node_seed = [0u8; 32];
    pool_draw(b"node-rng", &mut node_seed);
    // The Node Management cursor nonce, from the same cryptographic
    // source: it is what keeps a cursor issued before a reboot from being
    // honored after one.
    let mut admin_nonce = [0u8; 2];
    pool_draw(b"admin-nonce", &mut admin_nonce);
    let admin_nonce = u16::from_be_bytes(admin_nonce);
    #[cfg(feature = "wifi")]
    let network_seed = {
        let mut bytes = [0; 8];
        pool_draw(b"wifi-ip", &mut bytes);
        u64::from_le_bytes(bytes)
    };
    #[cfg(feature = "bridge-client")]
    let bridge_seed = {
        let mut seed = [0; 32];
        pool_draw(b"bridge-tls", &mut seed);
        seed
    };
    #[cfg(feature = "ble")]
    let ble_privacy_seed = {
        let mut seed = [0; 32];
        pool_draw(b"ble-privacy-rng", &mut seed);
        seed
    };
    drop(pool_draw);
    // Every boot-time draw is made; the pool now belongs to the service
    // that keeps it fed.
    spawner.spawn(entropy::task(entropy_service).unwrap());
    #[cfg(feature = "wifi")]
    #[cfg_attr(not(feature = "bridge-client"), allow(unused_variables))]
    let network_stack = {
        const SOCKETS: usize = if cfg!(feature = "bridge-client") {
            3
        } else {
            1
        };
        static RESOURCES: StaticCell<embassy_net::StackResources<SOCKETS>> = StaticCell::new();
        let interface = wifi::interface();
        let mac = interface.mac_address();
        let (stack, runner) = embassy_net::new(
            interface,
            embassy_net::Config::default(),
            RESOURCES.init_with(embassy_net::StackResources::new),
            network_seed,
        );
        spawner.spawn(ip::runner(runner).unwrap());
        spawner.spawn(wifi::task(wifi_radio, stack).unwrap());
        wifi::publish(driver::PublishEvent::WifiMac(mac)).await;
        stack
    };
    #[cfg(feature = "bridge-client")]
    {
        let (buffers, queues) = bridge::storage();
        bridge::PORT.init(queues);
        let seed = boot_identity_keys.as_ref().map(|keys| keys.0);
        spawner.spawn(bridge::task(network_stack, seed, bridge_seed, buffers).unwrap());
    }

    let boot_identity = boot_identity_keys.as_ref().map(|(_secret, public)| *public);

    // ── The LoRa modem behind the device runner + mux ────────────────────
    // SPI2 on every board; the pins, the control lines, and the
    // interface variant's arity are the board's. On a PMIC board the
    // radio's rail (ALDO3) settled during PMU bring-up, so the reset
    // that follows means something.
    #[cfg(feature = "board-heltec-v3")]
    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(16))
            .with_mode(Mode::_0),
    )
    .unwrap()
    .with_sck(peripherals.GPIO9)
    .with_mosi(peripherals.GPIO10)
    .with_miso(peripherals.GPIO11)
    .into_async();
    #[cfg(feature = "board-heltec-v2")]
    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(16))
            .with_mode(Mode::_0),
    )
    .unwrap()
    .with_sck(peripherals.GPIO5)
    .with_mosi(peripherals.GPIO27)
    .with_miso(peripherals.GPIO19)
    .into_async();
    #[cfg(feature = "board-tbeam-supreme")]
    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(16))
            .with_mode(Mode::_0),
    )
    .unwrap()
    .with_sck(peripherals.GPIO12)
    .with_mosi(peripherals.GPIO11)
    .with_miso(peripherals.GPIO13)
    .into_async();

    #[cfg(feature = "board-heltec-v3")]
    let radio_cs = Output::new(peripherals.GPIO8, Level::High, OutputConfig::default());
    #[cfg(feature = "board-heltec-v2")]
    let radio_cs = Output::new(peripherals.GPIO18, Level::High, OutputConfig::default());
    #[cfg(feature = "board-tbeam-supreme")]
    let radio_cs = Output::new(peripherals.GPIO10, Level::High, OutputConfig::default());
    #[cfg(not(feature = "board-tlora-pager"))]
    let radio_spi = ExclusiveDevice::new(spi, radio_cs, Delay).unwrap();
    #[cfg(feature = "board-tlora-pager")]
    let radio_spi = board::SpiHandle::new(
        pager_spi,
        radio_cs,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(16))
            .with_mode(Mode::_0),
    );

    #[cfg(feature = "board-heltec-v3")]
    let radio_reset = Output::new(peripherals.GPIO12, Level::High, OutputConfig::default());
    #[cfg(feature = "board-heltec-v2")]
    let radio_reset = Output::new(peripherals.GPIO14, Level::High, OutputConfig::default());
    #[cfg(feature = "board-tbeam-supreme")]
    let radio_reset = Output::new(peripherals.GPIO5, Level::High, OutputConfig::default());

    #[cfg(feature = "board-tlora-pager")]
    let radio_reset = Output::new(peripherals.GPIO47, Level::High, OutputConfig::default());
    #[cfg(feature = "board-tlora-pager")]
    let (radio_dio1, radio_busy) = (peripherals.GPIO14, peripherals.GPIO48);

    // SX126x: DIO1 carries the IRQs and BUSY gates every command.
    #[cfg(feature = "board-heltec-v3")]
    let (radio_dio1, radio_busy) = (peripherals.GPIO14, peripherals.GPIO13);
    #[cfg(feature = "board-tbeam-supreme")]
    let (radio_dio1, radio_busy) = (peripherals.GPIO1, peripherals.GPIO4);
    #[cfg(feature = "radio-sx126x")]
    let kind = {
        let radio_dio1 = Input::new(radio_dio1, InputConfig::default().with_pull(Pull::None));
        let radio_busy = Input::new(radio_busy, InputConfig::default().with_pull(Pull::None));
        board_radio::new_radio_kind(radio_spi, radio_reset, radio_dio1, radio_busy)
    }
    .unwrap_or_else(|e| panic!("radio init failed: {e:?}"));

    // SX127x: no BUSY line at all, and DIO0 alone carries every IRQ the
    // driver needs. DIO1/DIO2 are wired to input-only pins and unused.
    #[cfg(feature = "radio-sx127x")]
    let kind = {
        let radio_dio0 = Input::new(
            peripherals.GPIO26,
            InputConfig::default().with_pull(Pull::None),
        );
        board_radio::new_radio_kind(radio_spi, radio_reset, radio_dio0)
    }
    .unwrap_or_else(|e| panic!("radio init failed: {e:?}"));
    // `false` selects the private-network sync word (0x12 → 0x1424),
    // matching SessionConfig::sync_word above.
    let lora = LoRa::new(kind, false, Delay)
        .await
        .unwrap_or_else(|e| panic!("radio init failed: {e:?}"));
    spawner.spawn(radio_task(lora).unwrap());
    spawner.spawn(radio_mux_task().unwrap());

    // ── The wired transport ───────────────────────────────────────────────
    // The same port `esp-println` writes to: UART0 behind the CP2102
    // bridge, or the chip's native USB-Serial-JTAG where the USB-C
    // socket wires straight to the SoC. Claiming it resets the TX FIFO,
    // which truncates whatever `esp-println` left in flight; drain by
    // time (20 ms clears a 64-byte FIFO at 115200 baud roughly four
    // times over). The console goes quiet from here.
    Timer::after_millis(20).await;
    #[cfg(feature = "board-heltec-v3")]
    let uart = Uart::new(peripherals.UART0, UartConfig::default())
        .unwrap()
        .with_rx(peripherals.GPIO44)
        .with_tx(peripherals.GPIO43)
        .into_async();
    #[cfg(feature = "board-heltec-v2")]
    let uart = Uart::new(peripherals.UART0, UartConfig::default())
        .unwrap()
        .with_rx(peripherals.GPIO3)
        .with_tx(peripherals.GPIO1)
        .into_async();
    #[cfg(not(feature = "wired-usb-serial-jtag"))]
    {
        let (wired_rx, wired_tx) = uart.split();
        spawner.spawn(output_task(wired_tx, panic_report.clone()).unwrap());
        spawner.spawn(uart_in_task(wired_rx).unwrap());
    }
    // Pinless: the peripheral owns GPIO19/20 itself. The supervisor
    // constructs and drops the driver as USB power comes and goes.
    #[cfg(feature = "wired-usb-serial-jtag")]
    spawner.spawn(wired_transport_task(peripherals.USB_DEVICE, panic_report.clone()).unwrap());

    #[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
    vext.enable().await;

    // Construct shared buses before the session can accept host requests.
    #[cfg(feature = "board-heltec-v3")]
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(400)),
    )
    .unwrap()
    .with_sda(peripherals.GPIO17)
    .with_scl(peripherals.GPIO18)
    .into_async();
    #[cfg(feature = "board-heltec-v2")]
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(400)),
    )
    .unwrap()
    .with_sda(peripherals.GPIO4)
    .with_scl(peripherals.GPIO15)
    .into_async();
    #[cfg(feature = "board-tbeam-supreme")]
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(400)),
    )
    .unwrap()
    .with_sda(peripherals.GPIO17)
    .with_scl(peripherals.GPIO18)
    .into_async();

    #[cfg(not(feature = "board-tlora-pager"))]
    let display_bus: &'static board::I2cBus = {
        static DISPLAY_BUS: StaticCell<board::I2cBus> = StaticCell::new();
        DISPLAY_BUS.init(Mutex::new(i2c))
    };
    #[cfg(all(feature = "ulcp-i2c", feature = "board-tbeam-supreme"))]
    let (boot_oled, i2c_inventory) = {
        static INVENTORY: StaticCell<board::i2c::Inventory> = StaticCell::new();
        let inventory = INVENTORY.init_with(board::i2c::Inventory::new);
        let mut handle = I2cDevice::new(display_bus);
        // Bound startup even if a peripheral holds SCL. This HAL stops
        // the controller on cancellation; retain only completed probes.
        if embassy_time::with_timeout(Duration::from_millis(500), inventory.discover(&mut handle))
            .await
            .is_err()
        {
            debug_log(format_args!("i2c: startup discovery timed out"));
        }
        let oled = if let Some(addr) = inventory.panel_address() {
            let mut panel = display::new_display(handle, addr);
            match embassy_time::with_timeout(Duration::from_millis(200), panel.init()).await {
                Ok(Ok(())) => {
                    debug_log(format_args!("oled: sh1106 at 0x{addr:02x}"));
                    Some(panel)
                }
                _ => None,
            }
        } else {
            None
        };
        // PMIC bring-up already validated the chip ID; the RTC boot read
        // records presence even when its stored time is invalid.
        inventory.finish(oled.is_some(), true, wall_clock_rtc.is_some());
        (oled, &*inventory)
    };
    #[cfg(all(feature = "ulcp-i2c", feature = "board-tlora-pager"))]
    let host_buses = board::i2c::Buses { bus: pmu_bus };
    #[cfg(all(feature = "ulcp-i2c", feature = "pmic-axp2101"))]
    let host_buses = board::i2c::Buses {
        sensor: display_bus,
        pmu: pmu_bus,
        inventory: i2c_inventory,
    };
    #[cfg(all(
        feature = "ulcp-i2c",
        not(any(feature = "pmic-axp2101", feature = "board-tlora-pager"))
    ))]
    let host_buses = board::i2c::Buses { bus: display_bus };

    #[cfg(feature = "board-tbeam-supreme")]
    bme280::start(spawner, display_bus, pmu_bus).await;

    // ── The ULCP session ─────────────────────────────────────────────────
    spawner.spawn(
        device_task(
            boot_reason,
            proto_store,
            boot_snapshot,
            identity_store,
            boot_identity,
            identity_rng,
            node_counters,
            #[cfg(feature = "external-rtc")]
            wall_clock_rtc,
            #[cfg(feature = "ulcp-i2c")]
            host_buses,
            #[cfg(feature = "chip-esp32s3")]
            peripherals.SENS,
            #[cfg(feature = "pmic-axp2101")]
            pmic,
        )
        .unwrap(),
    );

    // ── Device node ──────────────────────────────────────────────────────
    // The device identity always exists by this point, so the full
    // MAC/node stack always comes up on mux client B; whether it
    // transmits is a matter of configuration, not of whether a key was
    // ever provisioned. A previous panic is reported independently; it
    // must not suppress the identity or mesh service on the next boot.
    let (identity_secret, _public) = boot_identity_keys
        .as_ref()
        .expect("a device identity is generated at boot when none is stored");
    debug_log(format_args!("node startup: spawning"));
    let t_frame_ms = umsh_radio_loraphy::airtime_ms(
        lora_phy::mod_params::SpreadingFactor::_7,
        lora_phy::mod_params::Bandwidth::_62KHz,
        umsh_radio_loraphy::MAX_PAYLOAD,
    );
    spawner.spawn(
        device_node::bring_up(
            spawner,
            *identity_secret,
            node_seed,
            t_frame_ms,
            node_counters,
            &INPUT_CH,
            admin_nonce,
        )
        .unwrap(),
    );

    // ── Battery, button ──────────────────────────────────────────────────
    // The sampler was constructed above, before the radio controller;
    // on a PMIC board the telemetry comes off the PMU bus instead.
    #[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
    spawner.spawn(battery_task(sampler).unwrap());
    #[cfg(feature = "pmic-axp2101")]
    spawner.spawn(battery_task(pmic).unwrap());
    #[cfg(not(feature = "board-tlora-pager"))]
    let button = Input::new(
        peripherals.GPIO0,
        InputConfig::default().with_pull(Pull::Up),
    );
    #[cfg(not(feature = "board-tlora-pager"))]
    spawner.spawn(button_task(button).unwrap());

    // ── GNSS: UART1 to the receiver, powered by the pump ─────────────────
    // The pump owns when the receiver runs (`PROP_GNSS_ENABLED`); the
    // BSP's `Power` impl owns how, and its rail starts off. This board's
    // clock lives in the PCF8563, so nothing reads the receiver's own
    // RTC at boot.
    #[cfg(feature = "board-tbeam-supreme")]
    {
        let gnss_wake = Output::new(peripherals.GPIO7, Level::Low, OutputConfig::default());
        spawner.spawn(
            gnss_task(
                peripherals.UART1,
                peripherals.GPIO9,
                peripherals.GPIO8,
                board::gnss::Gnss::new(pmic, gnss_wake),
            )
            .unwrap(),
        );
    }

    #[cfg(feature = "board-tlora-pager")]
    {
        spawner.spawn(
            gnss_task(
                peripherals.UART1,
                peripherals.GPIO4,
                peripherals.GPIO12,
                board::gnss::Gnss::new(expander),
            )
            .unwrap(),
        );
        if let Some((panel, splash)) = pager_boot_display {
            spawner.spawn(display_task(panel, splash).unwrap());
        }
    }

    // ── OLED, then hand the panel to its task ────────────────────────────
    // On a `Vext` board the panel and the rail that powers it move
    // together: the display task switches the panel off when attention
    // lapses and drops the rail entirely on the way into deep sleep. On
    // a PMIC board the panel's rail came up with the sensor rails and
    // drops in the shutdown path.
    #[cfg(not(any(feature = "display-sh1106", feature = "display-st7796")))]
    #[cfg(feature = "board-heltec-v3")]
    let mut oled_reset = Output::new(peripherals.GPIO21, Level::High, OutputConfig::default());
    #[cfg(not(any(feature = "display-sh1106", feature = "display-st7796")))]
    #[cfg(feature = "board-heltec-v2")]
    let mut oled_reset = Output::new(peripherals.GPIO16, Level::High, OutputConfig::default());

    #[cfg(not(any(feature = "display-sh1106", feature = "display-st7796")))]
    {
        let mut oled = display::new_display(I2cDevice::new(display_bus));
        display::reset(&mut oled_reset).await;
        if oled.init().await.is_ok() {
            spawner.spawn(display_task(oled, vext).unwrap());
        } else {
            BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
        }
    }
    // The SH1106's address is a population variable and there is no
    // reset pin—the rail is the reset, and it is already up. A panel
    // that does not answer leaves the board headless rather than
    // stopping the boot.
    #[cfg(all(feature = "display-sh1106", feature = "ulcp-i2c"))]
    {
        if let Some(oled) = boot_oled {
            spawner.spawn(display_task(oled).unwrap());
        } else {
            BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
            debug_log(format_args!("oled: no initialized panel"));
        }
    }
    #[cfg(all(feature = "display-sh1106", not(feature = "ulcp-i2c")))]
    {
        let mut i2c = I2cDevice::new(display_bus);
        match display::probe(&mut i2c).await {
            Some(addr) => {
                debug_log(format_args!("oled: sh1106 at 0x{addr:02x}"));
                let mut oled = display::new_display(i2c, addr);
                if oled.init().await.is_ok() {
                    spawner.spawn(display_task(oled).unwrap());
                } else {
                    BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
                }
            }
            None => {
                BOOT_SPLASH_ACTIVE.store(false, Ordering::Release);
                debug_log(format_args!("oled: no panel found"));
            }
        }
    }

    // ── BLE app: runs the pairing lattice + GATT transport forever ───────
    #[cfg(feature = "board-tlora-pager")]
    drop(pager_boot_guard);
    #[cfg(feature = "ble")]
    ble::run(bt, ble_privacy_seed, ble_store_handle).await;
    // With no supervisor to become, main still must not return: what it
    // built above stays alive only as long as it does.
    #[cfg(not(feature = "ble"))]
    core::future::pending::<()>().await;
}
