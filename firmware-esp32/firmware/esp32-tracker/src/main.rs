//! ULCP firmware for the ESP32 tracker boards (Heltec LoRa 32 V2/V3,
//! LILYGO T-Beam Supreme), selected by `board-*` features.
//!
//! The protocol brain is the shared board-agnostic driver
//! (`umsh_ulcp_runtime::driver`) — the same session loop the T-Echo
//! and T-1000E images run — behind each board's couplings:
//!
//! - **Wired transport**: HDLC-framed CRP on the board's serial port —
//!   UART0 behind a CP2102 bridge on the Heltecs, the native
//!   USB-Serial-JTAG peripheral where `wired-usb-serial-jtag` is on.
//!   Neither has usable connection state, so wired attachment is lazy
//!   and permanent: the first valid HDLC frame attaches, nothing ever
//!   detaches it (serial hosts are assumed present once they speak),
//!   and a board nobody serials into stays detached and autonomous.
//!   Real attach/detach edges exist only on BLE.
//! - **BLE transport**: the `UlcpService` GATT shape over the
//!   esp-radio controller, with the same pairing/bonding lattice the
//!   Phase 4 spike hardware-proved (PIN on the OLED, lockout policy,
//!   durable bonds through `umsh_journal_store`).
//! - **Radio**: the board's LoRa modem behind `device_runner` +
//!   `radio_mux`; the session (client A) and the on-board device node
//!   (client B) share the physical radio and one duty ledger.
//! - **Persistence**: snapshot / identity / counter journals in the
//!   `umsh` partition tail (see `ble_store.rs`).
//!
//! On a `pmic-axp2101` board there is also **power**: everything
//! interesting sits behind an AXP2101 rail, battery telemetry is the
//! PMIC's own (with a real charge state), and power-off is a PMIC
//! operation rather than deep sleep — the POWER key brings the board
//! back with no firmware involved. `gnss` adds the shared `umsh_gnss`
//! pump on UART1, and `rtc-pcf8563` a hardware wall clock read at boot
//! and written back when a trusted source steps the time.
//!
//! ## Boot order is constrained
//!
//! On a `pmic-axp2101` board the PMU comes up before everything: until
//! its rails are configured, the radio, panel, and receiver are dark,
//! and probing them reports parts missing that are merely unpowered.
//! The BLE controller is next (first, elsewhere) and stays up: it is
//! both a transport and the RF entropy source without which
//! `EspCryptoRng` refuses to exist (see `umsh_bsp_esp32::rng`).
//! Journals mount before the ULCP session starts so a stored snapshot
//! is restored (and the PHY re-applied) before the first host command.
//!
//! ## The console shares the wire, so it goes quiet
//!
//! `esp-println` shares the wired transport's port (UART0, or the
//! USB-Serial-JTAG peripheral). Boot diagnostics interleave cleanly
//! before the port is claimed; after that, nothing may `println!`. The
//! `ble-debug` feature multiplexes diagnostic lines onto the wired
//! output stream as ASCII (HDLC hosts resynchronize past them),
//! mirroring the nRF image's ble-debug.

#![no_std]
#![no_main]

extern crate alloc;

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, Ordering};

use bt_hci::controller::ExternalController;
#[cfg(feature = "pmic-axp2101")]
use embassy_embedded_hal::shared_bus::asynch::i2c::I2cDevice;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_futures::select::{Either, Either3, Either4, select, select3, select4};
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_sync::once_lock::OnceLock;
use embassy_sync::signal::Signal;
use embassy_sync::watch::Watch;
use embassy_time::{Delay, Duration, Instant, Timer, with_timeout};
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_hal::Async;
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::interrupt::software::SoftwareInterruptControl;
#[cfg(not(feature = "pmic-axp2101"))]
use esp_hal::rtc_cntl::sleep::{Ext0WakeupSource, LowPower};
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
use esp_radio::ble::controller::BleConnector;
use lora_phy::LoRa;
use static_cell::StaticCell;
use trouble_host::gap;
use trouble_host::prelude::*;

use umsh_bsp_esp32::flash_store;
use umsh_bsp_esp32::rng::EspCryptoRng;
// The board BSP, under one name whatever the board. Every board-specific
// pin, peripheral, and radio type reaches this file through `board`.
#[cfg(feature = "board-heltec-v2")]
use umsh_bsp_heltec_lora32_v2 as board;
#[cfg(feature = "board-heltec-v3")]
use umsh_bsp_heltec_lora32_v3 as board;
#[cfg(feature = "board-tbeam-supreme")]
use umsh_bsp_tbeam_supreme as board;

#[cfg(feature = "pmic-axp2101")]
use board::battery as board_battery;
#[cfg(not(feature = "pmic-axp2101"))]
use board::battery::BatterySampler;
#[cfg(feature = "display-sh1106")]
use board::display::{self, Brightness, Display};
// `DisplayConfigAsync` is the ssd1306 trait carrying `init()`.
#[cfg(not(feature = "display-sh1106"))]
use board::display::{self, Brightness, Display, DisplayConfigAsync as _};
#[cfg(feature = "pmic-axp2101")]
use board::gnss::{PmuI2cDevice, SharedPmic};
#[cfg(feature = "pmic-axp2101")]
use board::power as board_power;
use board::radio as board_radio;
// Boards whose `Vext` also gates the battery divider share one rail
// between the display task and the sampler, so their handle is `Copy`
// rather than an owned pin; the API surface is otherwise identical.
// PMIC boards have no `Vext` at all — the panel's rail belongs to the
// AXP2101 and drops in the shutdown path instead.
#[cfg(not(any(feature = "vext-gates-battery", feature = "pmic-axp2101")))]
use board::vext::Vext;
#[cfg(feature = "vext-gates-battery")]
use board::vext::VextHandle as Vext;
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
#[cfg(feature = "pmic-axp2101")]
use umsh_pmic_axp2101::{Axp2101, ChargeDirection, ChargeState, IrqMask};
use umsh_radio_loraphy::{DeviceControl, MAX_PAYLOAD};
#[cfg(feature = "rtc-pcf8563")]
use umsh_rtc_pcf8563::Pcf8563;
use umsh_ulcp::{Status, gatt, hdlc};
#[cfg(feature = "gnss")]
use umsh_ulcp_device::GnssConfig;
#[cfg(feature = "rtc-pcf8563")]
use umsh_ulcp_device::TimeConfig;
use umsh_ulcp_device::{BatteryFields, MAX_DEVICE_NAME_LEN, RadioSettings, SessionConfig};
use umsh_ulcp_runtime::ble_security::{PairingFailureClass, PairingRuntime, pairing_enabled};
use umsh_ulcp_runtime::driver::{
    self, DeviceEnv, DeviceRuntime, InEvent, InputChannel, OutFrame, Setting, TransportChannels,
};
use umsh_ulcp_runtime::{radio_mux, transport_policy};
use umsh_ux_display_tracker::attention::{
    Attention, AttentionConfig, DisplayKind, HoldReason, Transition,
};
use umsh_ux_display_tracker::gate::{Disposition, Gate, GateReason};
#[cfg(not(feature = "gnss"))]
use umsh_ux_display_tracker::menu::MenuItem;
use umsh_ux_display_tracker::menu::{MenuItems, ToggleId, UiEffect, UiInput, UiModel, UiNotice};
use umsh_ux_display_tracker::screen;
#[cfg(feature = "pmic-axp2101")]
use umsh_ux_tracker::battery::ChargeClass;
use umsh_ux_tracker::battery::soc_from_ocv;
use umsh_ux_tracker::button::{ButtonEdge, ButtonEvent, ButtonFsm};

use transport_policy::{Transport, generation_checked};

mod ble_store;
mod device_node;

use ble_store::{BleStore, ProtoStore, StoredBond, bond_identity_is_persistable, trouble_bond};

esp_bootloader_esp_idf::esp_app_desc!();

// ─── Configuration ───────────────────────────────────────────────────────

const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);

/// SX1262 PA limits on this module.
#[cfg(feature = "radio-sx126x")]
const MIN_TX_POWER_DBM: i8 = -9;
#[cfg(feature = "radio-sx126x")]
const MAX_TX_POWER_DBM: i8 = 22;

/// SX1276 PA limits. The antenna is on the PA_BOOST port and the BSP
/// configures `tx_boost: true`, which is the [2, 20] dBm path in the
/// driver — the RFO path's [-4, 14] range is unreachable on this board.
/// Above 17 dBm the driver switches PA_DAC to its 20 dBm mode and raises
/// OCP to 240 mA, so the top of this range is duty-limited in practice.
#[cfg(feature = "radio-sx127x")]
const MIN_TX_POWER_DBM: i8 = 2;
#[cfg(feature = "radio-sx127x")]
const MAX_TX_POWER_DBM: i8 = 20;

const BLE_CONNECTIONS_MAX: usize = 1;
const BLE_L2CAP_CHANNELS_MAX: usize = 2;
/// HCI command/event slot count for the external controller.
const HCI_SLOTS: usize = 4;

/// The one BLE controller this image builds, named so the GATT host's
/// resource block can be a `static` — a generic function cannot own one.
type BleController = ExternalController<BleConnector<'static>, HCI_SLOTS>;

/// The GATT host's resource block. Tens of kilobytes; see `ble_app`.
type BleResources =
    HostResources<BleController, DefaultPacketPool, BLE_CONNECTIONS_MAX, BLE_L2CAP_CHANNELS_MAX>;
/// Max GATT value payload the ULCP characteristics carry.
/// Largest value the ULCP characteristics accept.
///
/// A client may write up to ATT_MTU-3 octets in one request, and the
/// packet pool is configured for a 255-octet MTU, so anything smaller
/// than 252 here is a size the peer is entitled to send and this device
/// would refuse with an invalid-length error.
const BLE_VALUE_MAX: usize = 252;

#[cfg(feature = "board-heltec-v2")]
const DEFAULT_DEVICE_NAME: &str = "UMSH Heltec V2";
#[cfg(feature = "board-heltec-v3")]
const DEFAULT_DEVICE_NAME: &str = "UMSH Heltec V3";
#[cfg(feature = "board-tbeam-supreme")]
const DEFAULT_DEVICE_NAME: &str = "UMSH T-Beam";

/// `PROP_DEV_VERSION`: the stack name and the release version from the
/// build script, in the `STACK-NAME/STACK-VERSION` form the spec
/// recommends. Which board it runs on is `PROP_DEV_MODEL`'s job.
const DEV_VERSION: &str = concat!("umsh/", env!("GIT_DESCRIBE"));

/// `PROP_DEV_MODEL`: the hardware this image was built for, matching the
/// board id used by the release manifest and `site/data/hardware.toml`
/// (`heltec-v2` / `heltec-v3` / `tbeam-supreme`).
const DEV_MODEL: &str = board::BOARD_NAME;

/// The board default name plus a stable per-die suffix — the low 16
/// bits of the factory eFuse MAC, the same die-unique value the BLE
/// identity address is built from — so factory-fresh radios are
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

/// Stable random-static BLE identity address derived from the factory
/// eFuse MAC (top two bits forced to `11` per the random-static rule),
/// so a bonded peer reconnects to the same address across reboots.
fn ble_identity_address() -> Address {
    let mac = base_mac_bytes();
    let mut address = [mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]];
    address[5] |= 0xc0;
    Address::random(address)
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

fn session_config() -> SessionConfig {
    SessionConfig {
        dev_version: DEV_VERSION,
        dev_model: Some(DEV_MODEL),
        default_device_name: default_device_name(),
        mtu: MAX_PAYLOAD as u16,
        // Fixed at build time: LoRa::new(.., false, ..) below sets the
        // private-network word 0x12. `PROP_PHY_LORA_SW` is defined as
        // the 16-bit SX126x-style word whatever the silicon, so both
        // radio families report the same 0x1424 here.
        sync_word: 0x1424,
        min_tx_power_dbm: MIN_TX_POWER_DBM,
        max_tx_power_dbm: MAX_TX_POWER_DBM,
        // Chip tunable range. Wider than any one module's matching
        // network — the operator is responsible for staying legal and
        // for what the antenna path can actually radiate.
        #[cfg(feature = "radio-sx126x")]
        freq_khz_min: 150_000,
        #[cfg(feature = "radio-sx126x")]
        freq_khz_max: 960_000,
        #[cfg(feature = "radio-sx127x")]
        freq_khz_min: 137_000,
        #[cfg(feature = "radio-sx127x")]
        freq_khz_max: 1_020_000,
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
        // Battery-powered board with an ADC divider but no
        // charger-status signal (the charge LED is charger-driven), so
        // voltage and the OCV level estimate are reported and charge
        // state is not advertised.
        #[cfg(not(feature = "pmic-axp2101"))]
        battery: Some(BatteryFields {
            voltage: true,
            level: true,
            charge_state: false,
        }),
        // The AXP2101 measures its own battery terminal, runs a fuel
        // gauge, and knows which way current is flowing — the first
        // ESP32 board that can advertise all three fields.
        #[cfg(feature = "pmic-axp2101")]
        battery: Some(BatteryFields {
            voltage: true,
            level: true,
            charge_state: true,
        }),
        // No locate alert. The boards' only conspicuous output is the
        // OLED, and the permanent wired attach means a second host can
        // be present while the alert runs — neither is worth the wiring.
        alert: None,
        // No clock. A permanently-wired bench board reads the time from
        // the host it is wired to.
        #[cfg(not(feature = "rtc-pcf8563"))]
        time: None,
        // A hardware RTC holds the time across power-off and the
        // receiver can set it: `CAP_TIME` rests on a real clock.
        #[cfg(feature = "rtc-pcf8563")]
        time: Some(TimeConfig),
        #[cfg(not(feature = "gnss"))]
        gnss: None,
        // The receiver stays off until asked — a battery board, not a
        // fixed outdoor node.
        #[cfg(feature = "gnss")]
        gnss: Some(GnssConfig::DEFAULT),
        // No ambient light sensor.
        illuminance: false,
        // The ESP32-S3 radio is always up on this board, but the
        // peripheral can be made unfindable: see `advertising_permitted`.
        ble: true,
        // A real MAC runs behind this session.
        mac_node: true,
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

/// Deterministic CSPRNG for device-identity generation, seeded from the
/// RF-gated hardware TRNG at boot.
type IdentityRng = rand_chacha::ChaCha20Rng;

type BleStoreMutex = Mutex<CriticalSectionRawMutex, BleStore>;

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

/// Framing-free receive path and connection edges into the shared
/// ULCP driver (`InEvent`/`FrameBuf` and the queue types live there).
static INPUT_CH: InputChannel<CriticalSectionRawMutex> = InputChannel::new();
type FrameBuf = driver::FrameBuf;
const FRAME_IN_MAX: usize = driver::FRAME_IN_MAX;

/// Outbound frame queues: `wired` drained by output_task (UART0), `ble`
/// by the GATT connection writer.
static OUT_CH: TransportChannels<CriticalSectionRawMutex> = TransportChannels::new();

/// Published session epoch, checked by each transport at framing edges.
static SESSION_GEN: AtomicU32 = AtomicU32::new(0);

type DeviceName = heapless::Vec<u8, { MAX_DEVICE_NAME_LEN }>;
static DEVICE_NAME: Mutex<CriticalSectionRawMutex, DeviceName> = Mutex::new(DeviceName::new());
static DEVICE_NAME_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// The GAP Device Name value that clients may hold a stale copy of.
///
/// Set when the device is renamed and cleared once a Service Changed
/// indication has gone out, so a rename made with no one connected is
/// announced to the next client instead of being lost. Known gap: a second
/// bonded peer absent for both the rename and the connection that consumes
/// this flag keeps its cached name until it reads the characteristic again.
static GATT_NAME_STALE: AtomicBool = AtomicBool::new(false);

/// Whether a device name has been published since boot.
///
/// The first publication is the saved name being restored as the radio
/// configuration is applied, not a rename. Treating it as one would mark the
/// database stale on every power cycle and make every bonded peer
/// re-discover on its next connection.
static DEVICE_NAME_PUBLISHED: AtomicBool = AtomicBool::new(false);

/// GAP's own bound on the Device Name value, shorter than the ULCP limit.
type GapDeviceName = heapless09::Vec<u8, { gap::DEVICE_NAME_MAX_LENGTH }>;

/// A link-level signal the connection loop reacts to, other than a GATT
/// event or an outbound frame.
enum LinkSignal {
    AdvertisingPolicy,
    DeviceName,
}

/// The GAP Device Name value for `name`, truncated on a UTF-8 boundary.
fn gap_device_name(name: &[u8]) -> GapDeviceName {
    let len = utf8_prefix_len(name, gap::DEVICE_NAME_MAX_LENGTH);
    GapDeviceName::from_slice(&name[..len]).unwrap_or_default()
}

/// Publish the configured name on the GAP Device Name characteristic, so a
/// client reads the current name rather than the one the device booted with.
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
/// A bonded iOS client caches the GAP device name against the bond and keeps
/// showing the old one until a Service Changed indication makes it re-read.
/// The indicated range covers the whole table because the point is to
/// invalidate a cache, not to describe a structural change.
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

/// `u32::MAX` sentinel means "no PIN configured".
static PAIRING_PIN: AtomicU32 = AtomicU32::new(u32::MAX);
static BLE_BOND_COUNT: AtomicU8 = AtomicU8::new(0);
static PAIRING_MODE: AtomicBool = AtomicBool::new(true);
static PAIRING_LOCKED_OUT: AtomicBool = AtomicBool::new(false);
static PAIRING_FAILURES: AtomicU8 = AtomicU8::new(0);
static PAIRING_CONFIG_CH: Channel<CriticalSectionRawMutex, Option<u32>, 1> = Channel::new();
static PAIRING_CONFIG_ACK: Signal<CriticalSectionRawMutex, bool> = Signal::new();
static PAIRING_MODE_REQUEST: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static PAIRING_TIMER_RESET: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static BLE_WIPE_REQUEST: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Wired protocol attachment suppresses BLE advertising. The signal
/// wakes a pending advertiser/connection so it can apply the policy.
static ADV_ALLOWED: AtomicBool = AtomicBool::new(true);
/// `PROP_BLE_ENABLED`, mirrored from the session. True at boot, before
/// any restore, so a device that never reaches its saved state is still
/// reachable by the host that could fix it.
static BLE_ENABLED: AtomicBool = AtomicBool::new(true);
static ADV_POLICY_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// OLED redraw trigger for content that changed without the user asking
/// — a battery sample, a bond count. Deliberately *not* a wake event:
/// the battery is sampled on a timer, so a redraw that woke the panel
/// would keep it lit forever.
static UI_REFRESH: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// The user is here, or wants to be: a button press, a BLE link
/// transition. Restarts the display-attention timeout and relights a
/// panel that has gone dark.
static UI_WAKE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// Resolved menu gestures, button task → display task.
static UI_INPUT_CH: Channel<CriticalSectionRawMutex, UiInput, 8> = Channel::new();
/// Result of a menu action, to be shown on the status page.
static UI_NOTICE: Signal<CriticalSectionRawMutex, UiNotice> = Signal::new();
/// Whether the panel is currently powered off. Published by the display
/// task; read by the button task, which gates a gesture on the state at
/// the press that began it.
static SCREEN_OFF: AtomicBool = AtomicBool::new(false);
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
/// 0 = normal heartbeat, 1 = pairing mode (fast LED blink). On a board
/// with no firmware LED the state reaches the user through the panel's
/// pairing page instead.
static BLE_LED_MODE: AtomicU8 = AtomicU8::new(0);
/// 0 = idle/advertising, 1 = connected, 2 = attached. Display only.
static BLE_LINK: AtomicU8 = AtomicU8::new(0);
/// Last battery sample in millivolts (0 = never sampled). Display only.
static BATTERY_MV: AtomicU16 = AtomicU16::new(0);
/// Last battery level percent (0xFF = unknown). Display only.
#[cfg(feature = "pmic-axp2101")]
static BATTERY_LEVEL: AtomicU8 = AtomicU8::new(0xFF);
/// Last charge classification: 0 unknown, 1 discharging, 2 charging,
/// 3 charged. Display only.
#[cfg(feature = "pmic-axp2101")]
static BATTERY_CHARGE: AtomicU8 = AtomicU8::new(0);
/// Battery request/reply pair between the session env and the sampler
/// task, which owns the ADC (or the PMIC telemetry cadence).
static BATTERY_REQUEST: Signal<CriticalSectionRawMutex, ()> = Signal::new();
#[cfg(not(feature = "pmic-axp2101"))]
static BATTERY_REPLY: Signal<CriticalSectionRawMutex, u16> = Signal::new();
#[cfg(feature = "pmic-axp2101")]
static BATTERY_REPLY: Signal<CriticalSectionRawMutex, board_battery::Reading> = Signal::new();
/// Readings worth announcing to a remote observer, for unsolicited
/// `PROP_BATTERY` publication. A `Watch` rather than a `Signal`: the
/// driver's select drops and re-creates the wait on every other
/// iteration, and a receiver must not lose an update to that.
#[cfg(not(feature = "pmic-axp2101"))]
static BATTERY_ANNOUNCE: Watch<CriticalSectionRawMutex, u16, 1> = Watch::new();
#[cfg(feature = "pmic-axp2101")]
static BATTERY_ANNOUNCE: Watch<CriticalSectionRawMutex, board_battery::Reading, 1> = Watch::new();

#[cfg(feature = "ble-debug")]
type DebugLine = heapless::String<192>;
#[cfg(feature = "ble-debug")]
static DEBUG_CH: Channel<CriticalSectionRawMutex, DebugLine, 32> = Channel::new();
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

// ─── Outgoing frame limits ───────────────────────────────────────────────

const WIRE_MAX: usize = hdlc::max_encoded_len(driver::FRAME_OUT_MAX);

// ─── Device-node counter persistence ─────────────────────────────────────

/// The device node's persisted frame counters, bound to this board's
/// flash. The map, the journal handle, and the `CounterStore` impl are
/// shared (`umsh_ulcp_runtime::node_counters`); only the mutex kinds,
/// the flash type, and the journal's page are this board's.
pub type NodeCounters =
    umsh_ulcp_runtime::node_counters::NodeCounters<NoopRawMutex, ble_store::JournalFlash>;
pub type NodeCountersMutex = umsh_ulcp_runtime::node_counters::NodeCountersMutex<
    CriticalSectionRawMutex,
    NoopRawMutex,
    ble_store::JournalFlash,
>;
pub type NodeCounterStore = umsh_ulcp_runtime::node_counters::NodeCounterStore<
    CriticalSectionRawMutex,
    NoopRawMutex,
    ble_store::JournalFlash,
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
    flash: &'static ble_store::SharedFlash,
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
/// [`BoardDeviceEnv`] — the only thing that ever writes it back.
///
/// Deliberately not a global: esp-hal's `Async` peripherals are `!Send`
/// by design (they belong to the executor that drives them), so the
/// handle travels as a task argument rather than through a static.
#[cfg(feature = "rtc-pcf8563")]
type RtcMutex = Mutex<CriticalSectionRawMutex, Pcf8563<PmuI2cDevice>>;
#[cfg(feature = "rtc-pcf8563")]
static RTC_CELL: StaticCell<RtcMutex> = StaticCell::new();

/// Write a stepped wall clock back to the RTC, so the time the board
/// wakes up with is the time it went down with. Best-effort: a refused
/// write costs the writeback, not the clock.
#[cfg(feature = "rtc-pcf8563")]
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
/// classification, and this board cannot produce either — the LGS4056H's
/// status output drives the orange LED and reaches no GPIO. Fed
/// perpetually-discharging samples the clamp would never lift, so a fully
/// recharged pack would keep reporting the level it bottomed out at until
/// the next reboot.
#[cfg(not(feature = "pmic-axp2101"))]
const BATTERY_LEVEL_STEP: u8 = 5;

/// Smallest level movement worth announcing, in percentage points.
///
/// Matched to the nRF estimator's five-point step so every board
/// announces level movement at the same granularity. The level itself
/// prefers the PMIC's fuel gauge and falls back to the OCV table while
/// the gauge is unlearned — which of the two should be primary
/// long-term is a hardware-validation question.
#[cfg(feature = "pmic-axp2101")]
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
#[cfg(not(feature = "pmic-axp2101"))]
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
        let mv = sampler.sample_mv().await;
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
#[cfg(not(feature = "pmic-axp2101"))]
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
#[cfg(not(feature = "pmic-axp2101"))]
fn battery_snapshot(mv: u16) -> umsh_ulcp::battery::BatteryStatus {
    umsh_ulcp::battery::BatteryStatus {
        voltage_mv: Some(mv),
        level_percent: Some(soc_from_ocv(mv)),
        charge_state: None,
    }
}

/// The level a reading supports: the PMIC gauge when it has learned the
/// pack, the OCV table while it has not, nothing without a cell.
#[cfg(feature = "pmic-axp2101")]
fn battery_level(reading: &board_battery::Reading) -> Option<u8> {
    reading
        .percent
        .or_else(|| reading.voltage_mv.map(soc_from_ocv))
}

/// The `ChargeClass` a reading supports, or `None` when the PMIC cannot
/// say (no cell installed, or an unassigned status code).
#[cfg(feature = "pmic-axp2101")]
fn battery_charge_class(reading: &board_battery::Reading) -> Option<ChargeClass> {
    match reading.direction {
        ChargeDirection::Charging => Some(ChargeClass::Charging),
        ChargeDirection::Discharging => Some(ChargeClass::Discharging),
        ChargeDirection::Standby if matches!(reading.state, ChargeState::Done) => {
            Some(ChargeClass::Charged)
        }
        ChargeDirection::Standby | ChargeDirection::Unknown(_) => None,
    }
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
        BATTERY_LEVEL.store(battery_level(&reading).unwrap_or(0xFF), Ordering::Release);
        BATTERY_CHARGE.store(
            match battery_charge_class(&reading) {
                None => 0,
                Some(ChargeClass::Discharging) => 1,
                Some(ChargeClass::Charging) => 2,
                Some(ChargeClass::Charged) => 3,
            },
            Ordering::Release,
        );
        if requested {
            BATTERY_REPLY.signal(reading);
        }
        // Announce a level that moved far enough to be worth a frame, and
        // every charge-class edge — plugging in is always news. On-demand
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
#[cfg(feature = "pmic-axp2101")]
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
#[cfg(feature = "pmic-axp2101")]
fn battery_snapshot(reading: &board_battery::Reading) -> umsh_ulcp::battery::BatteryStatus {
    umsh_ulcp::battery::BatteryStatus {
        voltage_mv: reading.voltage_mv,
        level_percent: battery_level(reading),
        charge_state: battery_charge_class(reading).map(|class| match class {
            ChargeClass::Discharging => umsh_ulcp::battery::BatteryChargeState::Discharging,
            ChargeClass::Charging => umsh_ulcp::battery::BatteryChargeState::Charging,
            ChargeClass::Charged => umsh_ulcp::battery::BatteryChargeState::Charged,
        }),
    }
}

// ─── PMU interrupt ───────────────────────────────────────────────────────

/// Serve the AXP2101's interrupt line (active low).
///
/// Power-key presses wake the panel — the POWER key is a PMIC input,
/// not a GPIO, so this is the only path a press reaches firmware by.
/// Supply and charger edges poke the battery task, whose announce
/// policy decides whether the change is worth a frame.
#[cfg(feature = "pmic-axp2101")]
#[embassy_executor::task]
async fn pmu_irq_task(pmic: &'static SharedPmic, mut irq: Input<'static>) {
    loop {
        irq.wait_for_low().await;
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
        // the level rather than an edge — a source latched between the
        // read and the write-back would otherwise be lost for good.
        //
        // The cost of that choice is that `wait_for_low` returns
        // immediately while the line is still down, so the service rate
        // has to be floored here or a source that re-latches as fast as
        // it is cleared becomes an unbounded I2C flood on the bus the
        // battery reads and the RTC share. Empty means the line is low
        // with nothing latched at all — noise, or a source this build
        // does not enable — and is worth backing off from much harder.
        Timer::after_millis(if taken.is_empty() { 50 } else { 2 }).await;
    }
}

// ─── Pairing runtime plumbing (port of the nRF firmware's) ────────────────────

/// Whether the peripheral may be findable right now: transport
/// arbitration and the user's own `PROP_BLE_ENABLED`, both of which have
/// to agree.
fn advertising_permitted() -> bool {
    ADV_ALLOWED.load(Ordering::Acquire) && BLE_ENABLED.load(Ordering::Acquire)
}

/// Apply `PROP_BLE_ENABLED` by reusing the advertising-policy path, which
/// already stops the advertiser and drops a live connection. Bonds are
/// untouched, so the host reconnects without pairing again.
fn set_ble_enabled(enabled: bool) {
    if BLE_ENABLED.swap(enabled, Ordering::AcqRel) != enabled {
        debug_log(format_args!(
            "ble reachability {}",
            if enabled { "ON" } else { "off" }
        ));
        ADV_POLICY_CHANGED.signal(());
        UI_REFRESH.signal(());
    }
}

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

/// Drops an LRU-evicted bond from the live trouble bond table so the evicted
/// peer can't keep reconnecting as "bonded" this power cycle using stale
/// in-RAM keys after being pushed out of durable storage.
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

// ─── Board environment for the shared ULCP driver ─────────────────────────

/// Persistence, entropy, pairing, and indicator couplings for
/// `umsh_ulcp_runtime::driver`. The attention/load hooks keep the
/// driver's no-op defaults — this board has no buzzer or battery-sag
/// estimator to feed.
struct BoardDeviceEnv {
    proto_store: ProtoStore,
    identity_store: ProtoStore,
    identity_rng: IdentityRng,
    node_counters: &'static NodeCountersMutex,
    /// Announce-worthy readings from [`battery_task`], for unsolicited
    /// `PROP_BATTERY` publication.
    #[cfg(not(feature = "pmic-axp2101"))]
    battery: embassy_sync::watch::DynReceiver<'static, u16>,
    #[cfg(feature = "pmic-axp2101")]
    battery: embassy_sync::watch::DynReceiver<'static, board_battery::Reading>,
    /// Positioning changes worth publishing unasked. The runtime's GNSS
    /// sink owns the policy — a stationary receiver produces a fix a
    /// second and almost none of them are news — so this only forwards
    /// what it decided to raise.
    #[cfg(feature = "gnss")]
    gnss_announce: umsh_ulcp_runtime::gnss::Announcer,
    /// The hardware clock, for writing a stepped time back. `None` when
    /// the chip did not answer at boot — the board still keeps time,
    /// it just will not survive a power-off.
    #[cfg(feature = "rtc-pcf8563")]
    rtc: Option<&'static RtcMutex>,
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
        device_node::sign_identity_blob(out).await
    }

    /// This board has no attention indicator, so the trace is the local
    /// report; the host-visible one is `PROP_SAVED`.
    fn report_snapshot_rejected(&mut self, fell_back: bool) {
        debug_log(format_args!(
            "proto-store snapshot rejected fell-back={fell_back}"
        ));
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

    /// Publish the reading [`battery_task`] flagged, reduced the same way
    /// the on-demand read reduces it.
    #[cfg(not(feature = "gnss"))]
    async fn battery_event(&mut self) -> umsh_ulcp::battery::BatteryStatus {
        #[cfg(not(feature = "pmic-axp2101"))]
        {
            let mv = self.battery.changed().await;
            battery_snapshot(mv)
        }
        #[cfg(feature = "pmic-axp2101")]
        {
            let reading = self.battery.changed().await;
            battery_snapshot(&reading)
        }
    }

    #[cfg(feature = "rtc-pcf8563")]
    async fn read_time(&mut self) -> Option<u32> {
        umsh_hal::wall_clock::now()
    }

    /// A host wrote `PROP_TIME`. An operator outranks every other
    /// source, and a manual set is worth persisting: it goes to the
    /// hardware RTC too, so the board wakes up with it.
    ///
    /// The empty write returns the wall clock to not knowing. The RTC
    /// keeps its time — "the host cleared the clock" is a statement
    /// about the running device, not an instruction to destroy the
    /// hardware clock's state — so the next boot restores from it.
    #[cfg(feature = "rtc-pcf8563")]
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
    /// need one `&mut self` borrow apiece. These are disjoint fields
    /// rather than separate method calls, which is what makes selecting
    /// over them legal.
    #[cfg(feature = "gnss")]
    async fn publish_event(&mut self) -> driver::PublishEvent {
        match select(self.battery.changed(), self.gnss_announce.changed()).await {
            Either::First(reading) => driver::PublishEvent::Battery(battery_snapshot(&reading)),
            Either::Second(umsh_ulcp_runtime::gnss::Announce::Gnss(key, snapshot)) => {
                driver::PublishEvent::Gnss(key, snapshot)
            }
            Either::Second(umsh_ulcp_runtime::gnss::Announce::Time(epoch)) => {
                // A trusted receiver stepped the wall clock notably;
                // carry the step into the RTC so it survives power-off.
                // Sub-notable re-syncs never reach this arm, which is
                // what keeps the writeback off the every-second fix
                // cadence.
                #[cfg(feature = "rtc-pcf8563")]
                if let (Some(seconds), Some(rtc)) = (epoch, self.rtc) {
                    rtc_writeback(rtc, seconds).await;
                }
                driver::PublishEvent::Time(epoch)
            }
            Either::Second(umsh_ulcp_runtime::gnss::Announce::IdentityFix(
                location,
                altitude_m,
            )) => driver::PublishEvent::IdentityFix(
                heapless::Vec::from_slice(location.as_bytes()).unwrap_or_default(),
                altitude_m,
            ),
        }
    }

    async fn apply_pairing_pin(&mut self, pin: Option<u32>) -> bool {
        PAIRING_CONFIG_CH.send(pin).await;
        PAIRING_CONFIG_ACK.wait().await
    }

    async fn factory_reset(&mut self) -> ! {
        // TODO: erase the runtime-discovered `umsh` partition span
        // (`partition.start..partition.end`) — all journals live there —
        // then esp32 reset. Unlike techo's hardcoded NV region, the span
        // is not currently held by `BoardDeviceEnv`, so this needs the
        // partition bounds threaded in first.
        todo!("Implement factory reset for esp32");
    }

    fn set_ble_enabled(&mut self, enabled: bool) {
        set_ble_enabled(enabled);
    }

    fn set_advertising_allowed(&mut self, allowed: bool) {
        // ble-debug builds keep advertising open regardless of the
        // arbitration policy so the diagnostic path stays reachable.
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
            device_node::set_device_name(bytes);
            UI_REFRESH.signal(());
        }
    }

    fn publish_dev_domain(&mut self, snapshot: driver::DevDomainSnapshot) {
        // The zone and the positioning policy ride the device-domain
        // mirror, so a host write, a boot restore, and a `CMD_RST` all
        // reach the clock and the receiver by the same path — and
        // neither needs anything to remember to push it.
        #[cfg(feature = "rtc-pcf8563")]
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
        device_node::DEV_SYNC.signal(snapshot);
    }

    fn trace(&mut self, args: core::fmt::Arguments<'_>) {
        debug_log(args);
    }
}

// ─── BLE app layer (port of the nRF firmware's, esp-radio controller) ─────────

async fn ble_runner<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) -> ! {
    loop {
        match runner.run().await {
            Ok(()) => debug_log(format_args!("ble runner exited cleanly")),
            Err(error) => debug_log(format_args!("ble runner error={error:?}")),
        }
    }
}

async fn pairing_timeout<C: Controller, P: PacketPool>(stack: &Stack<'_, C, P>) -> ! {
    loop {
        match select(Timer::after_secs(30), PAIRING_TIMER_RESET.wait()).await {
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
                let persisted = store.lock().await.set_pin(pin).await.is_ok();
                let applied = if persisted {
                    stack.set_fixed_passkey(pin).is_ok()
                } else {
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
                    UI_REFRESH.signal(());
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
                    || usize::from(BLE_BOND_COUNT.load(Ordering::Acquire)) >= ble_store::MAX_BONDS;
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
                    BLE_BOND_COUNT.store(0, Ordering::Release);
                    let mut identities: heapless09::Vec<Identity, { ble_store::MAX_BONDS }> =
                        heapless09::Vec::new();
                    stack.with_bond_information(|bonds| {
                        for bond in bonds {
                            let _ = identities.push(bond.identity);
                        }
                    });
                    for identity in identities {
                        let _ = stack.remove_bond_information(identity);
                    }
                    let _ = stack.set_fixed_passkey(None);
                    stack.set_io_capabilities(IoCapabilities::NoInputNoOutput);
                    PAIRING_PIN.store(u32::MAX, Ordering::Release);
                    PAIRING_FAILURES.store(0, Ordering::Release);
                    PAIRING_LOCKED_OUT.store(false, Ordering::Release);
                    PAIRING_MODE.store(true, Ordering::Release);
                    BLE_LED_MODE.store(1, Ordering::Release);
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

/// Start advertising and return the accept handle. This future must
/// run to completion before racing any cancellation signal: dropping
/// `Peripheral::advertise` mid-configuration (before its internal
/// `LeSetAdvEnable(true)`) leaves trouble's `advertise_command_state`
/// in `Cancel` with nothing for the runner's disable arm to disable,
/// and every later `advertise()` then parks in `request()` forever —
/// observed as "configuring" with no "active" on the esp-radio
/// external controller. Cancellation belongs on the returned
/// [`Advertiser`] (dropping it is the designed clean-stop path).
async fn advertise<'values, 'server, C: Controller>(
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
) -> Result<Advertiser<'values, C, DefaultPacketPool>, BleHostError<C::Error>> {
    const SERVICE_UUID_LE: [u8; 16] = gatt::SERVICE_UUID.to_le_bytes();
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
    let advertiser = peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data[..adv_len],
                scan_data: &scan_data[..scan_len],
            },
        )
        .await?;
    debug_log(format_args!("advertise: active, awaiting connection"));
    Ok(advertiser)
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

async fn gatt_connection<C: Controller, P: PacketPool>(
    stack: &Stack<'_, C, P>,
    store: &BleStoreMutex,
    server: &UlcpServer<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
) -> Result<(), trouble_host::Error> {
    conn.raw().set_bondable(true)?;
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
    BLE_LINK.store(1, Ordering::Release);
    UI_REFRESH.signal(());
    UI_WAKE.signal(());
    let mut attached = false;
    let mut reassembler: gatt::Reassembler<{ gatt::MAX_FRAME }> = gatt::Reassembler::new();

    loop {
        // The two link-level signals share one arm so the GATT event match
        // below keeps its shape.
        let link_signal = async {
            match select(ADV_POLICY_CHANGED.wait(), DEVICE_NAME_CHANGED.wait()).await {
                Either::First(()) => LinkSignal::AdvertisingPolicy,
                Either::Second(()) => LinkSignal::DeviceName,
            }
        };
        match select3(conn.next(), OUT_CH.ble.receive(), link_signal).await {
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
                        let _ = stack.remove_bond_information(bond.identity);
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
                            let _ = stack.remove_bond_information(bond.identity);
                            conn.raw().disconnect();
                            break;
                        }
                    };
                    BLE_BOND_COUNT.store(persisted_bonds as u8, Ordering::Release);
                    UI_REFRESH.signal(());
                }
                // Trouble may report a successful peripheral pairing with
                // bond=None and expose the completed bond at the first
                // protected GATT edge. Pairing success still resets the
                // failure counter and closes the window in that case.
                publish_pairing_runtime(pairing_runtime().pairing_succeeded());
                BLE_LED_MODE.store(0, Ordering::Release);
                apply_pairing_gate(stack);
            }
            Either3::First(GattConnectionEvent::Encrypted { bond, .. }) => {
                debug_log(format_args!(
                    "encrypted event_bond={} table_match={} level={:?}",
                    bond.is_some(),
                    conn.raw().is_bonded_peer(),
                    conn.raw().security_level(),
                ));
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
                // A bonded client caches attributes across connections, so a
                // rename it missed has to be announced now.
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
                let frame_in = matches!(&event, GattEvent::Write(write) if write.handle() == server.ulcp.frame_in.handle);
                let cccd = matches!(&event, GattEvent::Write(write) if Some(write.handle()) == server.ulcp.frame_out.cccd_handle);
                let protected = frame_in || cccd;
                let bonded = conn.raw().is_bonded_peer();
                let mut bond_persist_failed = false;
                // PairingComplete is not guaranteed to carry the newly
                // created bond on every peripheral path. The protected
                // GATT edge is authoritative: if Trouble says this peer
                // is bonded, find that exact live-table entry and make
                // it durable before granting access. add_bond is
                // idempotent, so subsequent frames do not write flash.
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
                                forget_evicted_bond(stack, evicted);
                                BLE_BOND_COUNT.store(count as u8, Ordering::Release);
                                apply_pairing_gate(stack);
                                true
                            }
                            Err(()) => {
                                debug_log(format_args!("protected bond persist=FAILED"));
                                bond_persist_failed = true;
                                let _ = stack.remove_bond_information(bond.identity);
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
                    // `NotAllowedEvent::accept()` preserves and returns
                    // the attribute server's permission error; it does
                    // not grant the operation.
                    event.accept()
                } else {
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
                        None => {}
                    }
                }
                if cccd && bonded {
                    let subscribed = server.ulcp.frame_out.should_notify(conn);
                    match (attached, subscribed) {
                        (false, true) => {
                            debug_log(format_args!("cccd subscribed=true"));
                            attached = true;
                            BLE_LINK.store(2, Ordering::Release);
                            UI_REFRESH.signal(());
                            UI_WAKE.signal(());
                            INPUT_CH.send(InEvent::Attached(Transport::Ble)).await;
                        }
                        (true, false) => {
                            debug_log(format_args!("cccd subscribed=false"));
                            attached = false;
                            reassembler.reset();
                            BLE_LINK.store(1, Ordering::Release);
                            UI_REFRESH.signal(());
                            UI_WAKE.signal(());
                            INPUT_CH.send(InEvent::Detached(Transport::Ble)).await;
                        }
                        _ => {}
                    }
                }
            }
            Either3::First(GattConnectionEvent::RequestConnectionParams(request)) => {
                // trouble hands ownership of the request; dropping it
                // unanswered only logs — the central's parameter
                // renegotiation then stalls until a procedure/supervision
                // timeout drops the link. Answer it, as techo does.
                match request.accept(None, stack).await {
                    Ok(()) => debug_log(format_args!("connection params-response=accepted")),
                    Err(error) => debug_log(format_args!(
                        "connection params-response=FAILED error={error:?}"
                    )),
                }
            }
            Either3::First(_) => {}
            Either3::Second(outbound) => {
                if attached && conn.raw().is_bonded_peer() {
                    send_ble_frame(server, conn, outbound).await?;
                } else {
                    debug_log(format_args!(
                        "ble outbound dropped attached={} bonded={}",
                        attached,
                        conn.raw().is_bonded_peer(),
                    ));
                }
            }
            Either3::Third(LinkSignal::AdvertisingPolicy) => {
                if !advertising_permitted() {
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
    BLE_LINK.store(0, Ordering::Release);
    UI_REFRESH.signal(());
    UI_WAKE.signal(());
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
        if !advertising_permitted() {
            ADV_POLICY_CHANGED.wait().await;
            continue;
        }
        // The configuration phase runs unraced (see `advertise`); only
        // the connection wait may be cancelled, by dropping the
        // Advertiser — the runner then disables advertising cleanly and
        // the next loop iteration reconfigures with fresh name/policy.
        // The advertisement and the GAP characteristic must agree, and this
        // is the one place both are about to matter.
        sync_gap_device_name(server).await;
        let advertiser = match advertise(peripheral).await {
            Ok(advertiser) => advertiser,
            Err(error) => {
                debug_log(format_args!("advertising error={error:?}"));
                Timer::after_millis(500).await;
                continue;
            }
        };
        match select3(
            advertiser.accept(),
            ADV_POLICY_CHANGED.wait(),
            DEVICE_NAME_CHANGED.wait(),
        )
        .await
        {
            Either3::First(Ok(connection)) => {
                let connection = match connection.with_attribute_server(server) {
                    Ok(connection) => connection,
                    Err(error) => {
                        debug_log(format_args!("attribute server attach error={error:?}"));
                        continue;
                    }
                };
                match gatt_connection(stack, store, server, &connection).await {
                    Ok(()) => debug_log(format_args!("gatt connection task ended ok")),
                    Err(error) => debug_log(format_args!("gatt connection task error={error:?}")),
                }
            }
            Either3::First(Err(error)) => debug_log(format_args!("advertising error={error:?}")),
            Either3::Second(()) => debug_log(format_args!("advertising policy changed")),
            Either3::Third(()) => debug_log(format_args!("advertising device name changed")),
        }
    }
}

async fn ble_app(controller: BleController, store: BleStore) -> ! {
    // `HostResources` is tens of kilobytes, and `ble_app` is awaited
    // directly from `main` — so a stack-built one lands as a temporary in
    // main's poll frame, which is already the largest frame in the image.
    // The same rule the `Mac` arena follows applies here: build it
    // through `StaticCell::init_with`, never on the stack.
    static BLE_RESOURCES: StaticCell<BleResources> = StaticCell::new();
    let resources = BLE_RESOURCES.init_with(HostResources::new);
    let initial = store.snapshot().clone();
    debug_log(format_args!(
        "ble boot identity={} bonds={} pin={} local_irk={}",
        ble_identity_address(),
        initial.bonds.len(),
        initial.pin.is_some(),
        initial.local_irk.is_some(),
    ));
    PAIRING_PIN.store(initial.pin.unwrap_or(u32::MAX), Ordering::Release);
    BLE_BOND_COUNT.store(initial.bonds.len() as u8, Ordering::Release);
    let initial_pairing_mode = initial.bonds.is_empty();
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
    let stack = trouble_host::new(controller, resources)
        .set_random_address(ble_identity_address())
        .set_io_capabilities(io_capabilities)
        .set_pairing_enabled(initial_pairing_enabled)
        .set_fixed_passkey(initial.pin)
        .expect("invalid fixed passkey")
        .build();
    for (index, bond) in initial.bonds.iter().enumerate() {
        match trouble_bond(bond) {
            Some(bond) => match stack.add_bond_information(bond) {
                Ok(()) => debug_log(format_args!("restored bond index={index} add=ok")),
                Err(error) => debug_log(format_args!(
                    "restored bond index={index} add=FAILED error={error:?}"
                )),
            },
            None => debug_log(format_args!("restored bond index={index} decode=FAILED")),
        }
    }
    let store = BleStoreMutex::new(store);
    let runner = stack.runner();
    let mut peripheral = stack.peripheral();
    let server = UlcpServer::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: default_device_name(),
        appearance: &appearance::computer::GENERIC_COMPUTER,
    }))
    .unwrap_or_else(|_| panic!("gatt server construction failed"));

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

// ─── Radio ───────────────────────────────────────────────────────────────

/// Owns the `lora_phy::LoRa` instance via the reconfigurable device
/// runner. TX uses MeshCore's 32-symbol SF7 preamble; the hardware-proven
/// 8-symbol SX1262 RX acquisition setting remains unchanged.
#[embassy_executor::task]
async fn radio_task(lora: board_radio::Radio) {
    umsh_radio_loraphy::device_runner(lora, &RADIO_CH, &DEVICE_CTL, 8, 32).await;
}

/// Owns the real `RADIO_CH` bundle and multiplexes it across the
/// virtual per-client bundles (see `radio_mux`): per-client TX
/// completion routing plus RX fan-out to every client.
#[embassy_executor::task]
async fn radio_mux_task() {
    radio_mux::radio_mux(&RADIO_CH, &MUX_CLIENTS, &radio_mux::MUX_MODE).await
}

// ─── GNSS ────────────────────────────────────────────────────────────────

/// Drive the board's GNSS receiver.
///
/// The whole of the per-board GNSS code: the UART and the board's power
/// control, handed to the shared pump. An `#[embassy_executor::task]`
/// cannot be generic, which is the only reason this shim exists at all
/// — the loop it delegates to lives in `umsh_gnss::pump` and is common
/// to both cargo workspaces.
///
/// The receiver stays powered down until `PROP_GNSS_ENABLED` says
/// otherwise, including on a board that has never been configured. It
/// is never asked for the time: the PCF8563 is this board's clock, so
/// the receiver's own RTC is not consulted at boot.
#[cfg(feature = "gnss")]
#[embassy_executor::task]
async fn gnss_task(uart: Uart<'static, Async>, control: board::gnss::Gnss) {
    let Some(enable) = umsh_ulcp_runtime::gnss::EnableSource::new() else {
        debug_log(format_args!("gnss: enable receiver already taken"));
        return;
    };
    umsh_gnss::pump::run(
        uart,
        control,
        enable,
        umsh_ulcp_runtime::gnss::FixSink,
        Delay,
    )
    .await
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
/// stopped draining — the caller abandons the rest of the frame, since
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
#[embassy_executor::task]
async fn output_task(mut tx: WiredTx, panic_report: Option<heapless::String<128>>) {
    // Emit the previous boot's panic message as ASCII. HDLC hosts
    // resynchronize past it; humans read it with a serial terminal.
    // There is no reader handshake to wait for — it lands in the bridge
    // (or the bounded write drops it with no host attached), which is
    // the correct behavior for a serial console.
    if let Some(report) = panic_report {
        let _ = wired_write_all(&mut tx, b"[PREV PANIC]: ").await;
        let _ = wired_write_all(&mut tx, report.as_bytes()).await;
        let _ = wired_write_all(&mut tx, b"\r\n").await;
    }
    loop {
        #[cfg(feature = "ble-debug")]
        let outbound = match select(OUT_CH.wired.receive(), DEBUG_CH.receive()).await {
            Either::First(outbound) => outbound,
            Either::Second(line) => {
                let _ = wired_write_all(&mut tx, line.as_bytes()).await;
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
            if !wired_write_all(&mut tx, chunk).await {
                break;
            }
        }
    }
}

/// Owns the wired RX half and HDLC decoder, forwarding frames into
/// `INPUT_CH`. Neither peripheral exposes usable connection state, so
/// wired attachment is lazy and permanent: the first valid HDLC frame
/// attaches the wired transport, and no wired detach ever fires — a
/// serial host is assumed present for good once it has spoken. Detach
/// semantics exist only for BLE, whose link genuinely drops; a board
/// nobody serials into therefore stays detached and operates
/// autonomously (queueing and delegated acknowledgement). Displacement
/// by a BLE attach is observed as a foreign `SESSION_GEN` bump, which
/// re-arms the lazy attach, so a displaced serial host reclaims the
/// session with its next frame.
#[embassy_executor::task]
async fn uart_in_task(mut rx: WiredRx) {
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
        match embedded_io_async::Read::read(&mut rx, &mut packet).await {
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

// ─── ULCP session ────────────────────────────────────────────────────────

/// Owns the framing-free protocol session: hosts the shared ULCP driver
/// (`umsh_ulcp_runtime::driver::run`) — host frames, radio
/// receptions, transmit completions, and every session effect — over
/// this board's channel wiring and [`BoardDeviceEnv`] couplings.
#[embassy_executor::task]
async fn device_task(
    boot_reason: Status,
    proto_store: ProtoStore,
    boot_snapshot: Option<ble_store::BootPayload>,
    identity_store: ProtoStore,
    boot_identity: Option<[u8; 32]>,
    identity_rng: IdentityRng,
    node_counters: &'static NodeCountersMutex,
    #[cfg(feature = "rtc-pcf8563")] rtc: Option<&'static RtcMutex>,
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
            // The driver is the only receiver; the slot count is sized
            // for exactly that, so this cannot fail.
            battery: BATTERY_ANNOUNCE
                .dyn_receiver()
                .expect("BATTERY_ANNOUNCE receiver slot"),
            #[cfg(feature = "gnss")]
            gnss_announce: umsh_ulcp_runtime::gnss::announcer()
                .expect("GNSS announcement receiver slot"),
            #[cfg(feature = "rtc-pcf8563")]
            rtc,
        },
    )
    .await
}

// ─── UI: OLED, button, LED ───────────────────────────────────────────────

/// What this board's menu can do.
///
/// Everything the class defines — minus the receiver entries on a board
/// with no GNSS fitted, where both come out and the submenu that led to
/// them goes with them. Clearing bonds is a menu item rather than a
/// bare gesture because the confirmation page in front of it is what
/// makes it safe.
fn board_menu_items() -> MenuItems {
    #[cfg(feature = "gnss")]
    {
        MenuItems::all()
    }
    #[cfg(not(feature = "gnss"))]
    {
        MenuItems::all()
            .without(MenuItem::GnssToggle)
            .without(MenuItem::ShareLocation)
    }
}

/// Which device-domain switch a menu toggle names.
const fn ulcp_setting(id: ToggleId) -> Setting {
    match id {
        ToggleId::Bluetooth => Setting::Bluetooth,
        ToggleId::Gnss => Setting::Gnss,
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
    let mv = BATTERY_MV.load(Ordering::Acquire);
    // No charger telemetry reaches the MCU on the ADC boards, so their
    // indicator says nothing about charging rather than asserting the
    // pack is discharging; the PMIC boards know which way current flows,
    // and unknown (no cell, or before the first sample) draws nothing
    // rather than a guess.
    #[cfg(not(feature = "pmic-axp2101"))]
    let battery = screen::BatteryIndicator {
        level_percent: (mv != 0).then(|| soc_from_ocv(mv)),
        charge: None,
    };
    #[cfg(feature = "pmic-axp2101")]
    let battery = {
        let level = BATTERY_LEVEL.load(Ordering::Acquire);
        screen::BatteryIndicator {
            level_percent: (level != 0xFF).then_some(level),
            charge: match BATTERY_CHARGE.load(Ordering::Acquire) {
                1 => Some(ChargeClass::Discharging),
                2 => Some(ChargeClass::Charging),
                3 => Some(ChargeClass::Charged),
                _ => None,
            },
        }
    };
    screen::StatusModel {
        device_name: core::str::from_utf8(name).unwrap_or(DEFAULT_DEVICE_NAME),
        // Boards with no receiver report nothing on both positioning
        // switches rather than a guess — and neither is on their menu.
        settings: screen::SettingsModel {
            bluetooth: Some(BLE_ENABLED.load(Ordering::Acquire)),
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
        link: match BLE_LINK.load(Ordering::Acquire) {
            2 => screen::LinkState::Attached,
            1 => screen::LinkState::Connected,
            _ if advertising_permitted() => screen::LinkState::Advertising,
            _ => screen::LinkState::OffWired,
        },
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
        stats: ui_stats(),
        // Boards without `CAP_TIME` never know what time it is and must
        // not indicate one. On the rest, `None` whenever the device does
        // not know, which the renderer draws as nothing at all — there
        // is deliberately no fallback, because a placeholder would be an
        // indication of the current time.
        #[cfg(not(feature = "rtc-pcf8563"))]
        clock: None,
        #[cfg(feature = "rtc-pcf8563")]
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
    let counters = device_node::mac_counters();
    screen::StatsModel {
        tx_frames: counters.tx_frames,
        rx_frames: counters.rx_frames,
        rx_accepted: counters.rx_accepted,
        forwarded: counters.forwarded,
        tx_power_dbm: device_node::tx_power_dbm(),
        // The ledger's scale is 0-65535 for 0-100%; the page shows tenths
        // of a percent, which is the range a tracker lives in.
        duty_permille: (u32::from(DUTY_LEDGER.usage(Instant::now().as_millis())) * 1_000 / 65_535)
            as u16,
    }
}

/// Render the current page. Best-effort — a display error just leaves the
/// panel stale; it never blocks the protocol paths.
async fn render_frame(display: &mut Display, model: &UiModel, status: &screen::StatusModel<'_>) {
    screen::render_frame(display, &screen::Layout::OLED_128X64, model, status);
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
    screen::render_message(display, &screen::Layout::OLED_128X64, status, title, detail);
    let _ = display.flush().await;
}

/// Completes at the next minute boundary, so the clock row can advance.
///
/// The display layer's standing rule is that panels redraw on events
/// and never on a timer, because a timer on a panel nobody is watching
/// is a battery drain that reports nothing. A clock is the one thing
/// that has to move on its own, so this is the sanctioned exception —
/// bounded to exactly the case that needs it: it never completes unless
/// the panel is already awake *and* the device knows what time it is
/// (a clockless board never sets the wall clock, so this pends forever
/// there). A panel that was asleep catches up on its next event-driven
/// redraw.
async fn clock_tick(awake: bool) {
    if !awake {
        core::future::pending::<()>().await;
    }
    match umsh_hal::wall_clock::millis_to_next_minute() {
        Some(millis) => Timer::after_millis(u64::from(millis)).await,
        None => core::future::pending().await,
    }
}

/// Owns the OLED, the `Vext` rail that powers it (where one exists —
/// on a PMIC board the panel's rail drops in the shutdown path
/// instead), and the display attention policy.
///
/// The panel is emissive, so attention lapsing actually turns it off:
/// dimmed as a warning at 7 s, dark at 10 s. It stays lit for as long as
/// a pairing window is open, because its PIN is the only place that
/// number is shown.
#[embassy_executor::task]
async fn display_task(mut display: Display, #[cfg(not(feature = "pmic-axp2101"))] mut vext: Vext) {
    let mut model = UiModel::new(board_menu_items());
    let mut attention = Attention::new(
        DisplayKind::Emissive,
        AttentionConfig::EMISSIVE,
        Instant::now().as_millis(),
    );
    let _ = display.set_brightness(Brightness::NORMAL).await;
    {
        let name = device_name_snapshot().await;
        let identity = IdentityText::current();
        render_frame(&mut display, &model, &ui_status(&name, &identity)).await;
    }

    loop {
        // The name changes rarely but every frame this pass might draw
        // needs it, so it is snapshotted once and lent out; the rest of
        // the status is rebuilt at each draw. The identity is rendered
        // the same way, and is empty until node bring-up runs.
        let name = device_name_snapshot().await;
        let identity = IdentityText::current();

        let now = Instant::now().as_millis();
        attention.set_hold(
            HoldReason::Pairing,
            PAIRING_MODE.load(Ordering::Acquire),
            now,
        );
        SCREEN_OFF.store(attention.is_lapsed(), Ordering::Release);

        let lapse = async {
            match attention.next_deadline() {
                Some(deadline) => Timer::at(Instant::from_millis(deadline)).await,
                None => core::future::pending().await,
            }
        };

        let mut redraw = false;
        let mut transition = None;
        match select4(
            UI_INPUT_CH.receive(),
            select3(
                // All three are "content moved, redraw if the panel is
                // already lit"; they differ only in what they do to the
                // model, so they share an arm.
                select3(
                    UI_REFRESH.wait(),
                    BATTERY_UI_CHANGED.wait(),
                    clock_tick(attention.accepts_redraw()),
                ),
                UI_NOTICE.wait(),
                UI_WAKE.wait(),
            ),
            DISPLAY_SHUTDOWN.wait(),
            lapse,
        )
        .await
        {
            Either4::First(input) => {
                let now = Instant::now().as_millis();
                transition = attention.wake(now);
                redraw = true;
                match model.apply(input) {
                    Some(UiEffect::CheckIn) => {
                        device_node::request_beacon(device_node::BeaconTrigger::Button);
                        model.set_notice(UiNotice::CheckInRequested);
                    }
                    Some(UiEffect::StartPairing) => PAIRING_MODE_REQUEST.signal(()),
                    Some(UiEffect::ClearBonds) => BLE_WIPE_REQUEST.signal(()),
                    Some(UiEffect::Toggle(id)) => {
                        // Applied by the ULCP session, so the property, an
                        // attached host and the saved snapshot all see the
                        // same flip. The new state reaches the panel
                        // through `ui_status` on the redraw below, which
                        // is why the entry stays put.
                        INPUT_CH.send(InEvent::Toggle(ulcp_setting(id))).await;
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
                Either3::Second(notice) => {
                    model.set_notice(notice);
                    transition = attention.wake(Instant::now().as_millis());
                    redraw = true;
                }
                // A wake on its own changes no content — a lit panel is
                // already showing the truth, and the events that do
                // change something raise `UI_REFRESH` alongside this.
                Either3::Third(()) => {
                    transition = attention.wake(Instant::now().as_millis());
                    redraw = transition.is_some();
                }
            },
            Either4::Third(()) => {
                render_message(
                    &mut display,
                    &ui_status(&name, &identity),
                    "Powering off",
                    "hold to wake",
                )
                .await;
                let _ = display.set_display_on(true).await;
                Timer::after_millis(1_200).await;
                let _ = display.set_display_on(false).await;
                #[cfg(not(feature = "pmic-axp2101"))]
                vext.disable();
                DISPLAY_SHUTDOWN_DONE.signal(());
                core::future::pending::<()>().await;
            }
            Either4::Fourth(()) => transition = attention.poll(Instant::now().as_millis()),
        }

        match transition {
            Some(Transition::Lapsed) => {
                // Waking always lands on the status page rather than on
                // whatever was abandoned here.
                model.go_home();
                let _ = display.set_display_on(false).await;
                redraw = false;
            }
            Some(Transition::Dimmed) => {
                let _ = display.set_brightness(Brightness::DIM).await;
                redraw = false;
            }
            Some(Transition::Woke) | None => {}
        }

        if redraw && attention.accepts_redraw() {
            render_frame(&mut display, &model, &ui_status(&name, &identity)).await;
        }
        // Ordered after the redraw so the panel never lights on a stale
        // frame.
        if matches!(transition, Some(Transition::Woke)) {
            let _ = display.set_brightness(Brightness::NORMAL).await;
            let _ = display.set_display_on(true).await;
        }
    }
}

/// PRG button (GPIO0, active low), resolved into the display-tracker
/// vocabulary: single advances the menu, double selects, a 1–4 second
/// hold released by the user goes back, and a continuing four-second
/// hold powers the board off.
///
/// A gesture that begins against a dark panel only relights it: the user
/// cannot have meant to act on something they could not see. The
/// power-off hold is the sole exception, since a device that has gone
/// dark still has to be switchable-off.
#[embassy_executor::task]
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
                        // Latch the pre-wake screen state, read on the
                        // press edge — this task can park for a minute
                        // awaiting an edge, and the panel lapses dark
                        // during exactly such a park. Then wake on the
                        // press, not on the resolved gesture, so the
                        // panel is already lit while the user is still
                        // deciding what the press will become.
                        gate.set(GateReason::ScreenOff, SCREEN_OFF.load(Ordering::Acquire));
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
#[cfg(not(feature = "pmic-axp2101"))]
#[embassy_executor::task]
async fn heartbeat_task(
    mut led: Output<'static>,
    mut rtc: Rtc<'static>,
    mut low_power: LowPower<'static>,
) -> ! {
    loop {
        rtc.rwdt.feed();
        // The idle blink spends two seconds dark, so the shutdown hold
        // has to interrupt the wait rather than be noticed after it.
        let (on_ms, off_ms) = if BLE_LED_MODE.load(Ordering::Acquire) == 1 {
            (100, 300)
        } else {
            (40, 2_000)
        };
        led.set_high();
        if with_timeout(Duration::from_millis(on_ms), SHUTDOWN_REQUEST.wait())
            .await
            .is_ok()
        {
            shutdown(&mut led, &mut rtc, &mut low_power).await;
        }
        led.set_low();
        if with_timeout(Duration::from_millis(off_ms), SHUTDOWN_REQUEST.wait())
            .await
            .is_ok()
        {
            shutdown(&mut led, &mut rtc, &mut low_power).await;
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
#[cfg(not(feature = "pmic-axp2101"))]
async fn shutdown(
    led: &mut Output<'static>,
    rtc: &mut Rtc<'static>,
    low_power: &mut LowPower<'static>,
) -> ! {
    debug_log(format_args!("shutdown: power-off hold"));
    DEVICE_CTL.shutdown();
    DISPLAY_SHUTDOWN_DONE.reset();
    DISPLAY_SHUTDOWN.signal(());
    let _ = with_timeout(Duration::from_secs(2), DISPLAY_SHUTDOWN_DONE.wait()).await;
    led.set_low();

    // GPIO0 is stolen rather than handed over: `button_task` holds an
    // `Input` on it for the life of the board, and the wake source wants
    // the bare pin. Both uses are read-only, nothing drives the pin, and
    // `sleep_deep` never returns — so no other task observes the
    // duplicate.
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
    let wake = Ext0WakeupSource::new(unsafe { esp_hal::peripherals::GPIO0::steal() }, Level::Low);
    low_power.sleep_deep(&[&wake]);
}

/// The RWDT feed, with no LED behind it — this board's only LEDs belong
/// to the PMIC's charger and the receiver's PPS output.
///
/// It also owns the shutdown sequence, because it owns the `Rtc` whose
/// watchdog has to keep getting fed across the button-release wait.
#[cfg(feature = "pmic-axp2101")]
#[embassy_executor::task]
async fn heartbeat_task(mut rtc: Rtc<'static>, pmic: &'static SharedPmic) -> ! {
    loop {
        rtc.rwdt.feed();
        if with_timeout(Duration::from_secs(2), SHUTDOWN_REQUEST.wait())
            .await
            .is_ok()
        {
            shutdown(&mut rtc, pmic).await;
        }
    }
}

/// Quiesce the board and hand the power topology back to the PMIC —
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
/// back to a running state — worse than off, better than wedged.
#[cfg(feature = "pmic-axp2101")]
async fn shutdown(rtc: &mut Rtc<'static>, pmic: &'static SharedPmic) -> ! {
    debug_log(format_args!("shutdown: power-off hold"));
    DEVICE_CTL.shutdown();
    DISPLAY_SHUTDOWN_DONE.reset();
    DISPLAY_SHUTDOWN.signal(());
    let _ = with_timeout(Duration::from_secs(2), DISPLAY_SHUTDOWN_DONE.wait()).await;

    // GPIO0 is stolen rather than handed over: `button_task` holds an
    // `Input` on it for the life of the board. Both uses are read-only,
    // nothing drives the pin, and this function never returns — so no
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
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    // umsh-node and umsh-sync use `alloc`. The classic ESP32 has roughly
    // half the S3's data RAM and the BT controller takes a fixed bite out
    // of it before the application sees any, so its heap is smaller.
    #[cfg(feature = "chip-esp32s3")]
    esp_alloc::heap_allocator!(size: 72 * 1024);
    // The classic ESP32's `dram_seg` is only 128 KiB once esp-hal reserves
    // the BT controller's 64 KiB, and the static side of this image does
    // not fit alongside a heap of any useful size. `dram2_seg` is the
    // ~96 KiB of DRAM past the ROM data and stack areas — unusable for
    // zero-initialized statics (NOLOAD, nothing clears it) but fine for
    // a heap arena, which is `MaybeUninit` by nature. Smaller than the
    // S3's 72 KiB deliberately: on the S3 the BLE controller allocates
    // from this heap, while here it lives in its own 64 KiB reservation,
    // so this heap only carries umsh-node/umsh-sync (8 KiB on the nRF
    // boards) plus esp-radio's residual allocations — and the device
    // node's ~32 KiB Mac arena shares the same 96 KiB region.
    #[cfg(feature = "chip-esp32")]
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 48 * 1024);

    let mut rtc = Rtc::new(peripherals.RTC_TIMER);
    rtc.rwdt.set_timeout(RwdtStage::Stage0, WDT_TIMEOUT);
    rtc.rwdt.enable();

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

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
        PMIC_CELL.init(Mutex::new(pmic))
    };

    // The hardware wall clock, read once before anything else competes
    // for the bus. `ExternalRtc` applies only while the clock is unset,
    // so a later GNSS fix or host write outranks it.
    #[cfg(feature = "rtc-pcf8563")]
    let wall_clock_rtc: Option<&'static RtcMutex> = {
        let mut rtc_chip = Pcf8563::new(I2cDevice::new(pmu_bus));
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
    #[cfg(not(feature = "pmic-axp2101"))]
    let low_power = LowPower::new(peripherals.LPWR);
    #[cfg(not(feature = "pmic-axp2101"))]
    spawner.spawn(heartbeat_task(led, rtc, low_power).unwrap());

    // ── Vext rail and battery ADC, before the radio controller ───────────
    // Claim order matters on the classic ESP32: the battery divider sits
    // on an ADC2 channel, ADC2 is shared with the radio, and `Adc::new`
    // panics once the esp-radio controller has taken it. Claiming here
    // costs the boards with an independent ADC nothing — the rail starts
    // off and no conversion runs until the battery task asks for one.
    // A PMIC board has neither: its rails came up above, and the battery
    // is read over the PMU bus.
    #[cfg(feature = "board-heltec-v3")]
    let mut vext = Vext::new(peripherals.GPIO36);
    #[cfg(feature = "board-heltec-v2")]
    let mut vext = board::vext::init(peripherals.GPIO21);

    #[cfg(feature = "board-heltec-v3")]
    let sampler = BatterySampler::new(peripherals.ADC1, peripherals.GPIO1, peripherals.GPIO37);
    #[cfg(feature = "board-heltec-v2")]
    let sampler = BatterySampler::new(peripherals.ADC2, peripherals.GPIO13, vext);

    // ── BLE controller: transport AND the RF entropy source ──────────────
    let connector = BleConnector::new(peripherals.BT, Default::default())
        .unwrap_or_else(|e| panic!("ble init failed ({e:?}) — no trustworthy RNG"));
    let mut rng = EspCryptoRng::new().unwrap_or_else(|e| panic!("crypto rng unavailable: {e:?}"));
    let controller: ExternalController<_, HCI_SLOTS> = ExternalController::new(connector);

    // ── Flash: discover the `umsh` partition (never hardcoded) ───────────
    let (flash, partition) = flash_store::open_partition(peripherals.FLASH)
        .unwrap_or_else(|e| panic!("umsh partition not found: {e:?}"));
    println!(
        "storage: umsh partition 0x{:06x}..0x{:06x}",
        partition.start, partition.end,
    );
    static SHARED_FLASH: StaticCell<ble_store::SharedFlash> = StaticCell::new();
    let shared: &'static ble_store::SharedFlash = SHARED_FLASH.init(ble_store::shared(flash));

    // ── Journals: BLE security, snapshot, identity, node counters ────────
    // Mounted before the ULCP session starts: a stored snapshot must be
    // restored (and the PHY re-applied) and the persisted device
    // identity installed before the first host command.
    let mut ble_store_handle = BleStore::mount(shared, &partition).await;
    if ble_store_handle.snapshot().local_irk.is_none() {
        let mut local_irk = [0u8; 16];
        rng.fill_bytes(&mut local_irk);
        if local_irk == [0; 16] {
            local_irk[0] = 1;
        }
        ble_store_handle
            .set_local_irk(local_irk)
            .await
            .unwrap_or_else(|_| panic!("local irk persist failed"));
    }
    let (proto_store, boot_snapshot) =
        ProtoStore::mount(shared, ble_store::proto_page0(&partition)).await;
    let (mut identity_store, identity_payload) =
        ProtoStore::mount(shared, ble_store::identity_page0(&partition)).await;
    let node_counters = init_node_counters();
    mount_node_counters(node_counters, shared, ble_store::counter_page0(&partition)).await;

    // Both halves of the persisted keypair: the public key seeds the
    // session's PROP_DEV_KEY surface, the secret brings up the device
    // node's MAC identity.
    //
    // A device identity always exists. When the journal is empty — a
    // factory-fresh board, or the boot that completes a factory reset —
    // one is generated here and persisted before anything can observe
    // its absence, so identity is never a commissioning step the
    // operator has to perform.
    //
    // `rng` is `EspCryptoRng`, which cannot be constructed at all unless
    // the RF entropy source is live and panics if it goes away, so this
    // draw is true-random by construction rather than by convention. It
    // is deliberately taken directly rather than from the ChaCha20
    // stream seeded below.
    let mut identity_keys = identity_payload
        .as_deref()
        .and_then(umsh_journal_store::proto::decode_identity);
    if identity_keys.is_none() {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let (public, record) = driver::device_identity_record(&secret);
        // A persist failure is not fatal: the device runs on this key
        // for the current boot and generates another next time.
        match identity_store.persist(&record).await {
            Ok(()) => println!("device identity generated at first boot"),
            Err(()) => {
                println!("device identity generated but persist FAILED — volatile this boot")
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
        ble_store_handle.snapshot().bonds.len(),
    );

    // Seed the identity-generation and device-node CSPRNGs from the
    // TRNG while the RF subsystem is known-live.
    let mut identity_seed = [0u8; 32];
    rng.fill_bytes(&mut identity_seed);
    let identity_rng = <IdentityRng as rand_core::SeedableRng>::from_seed(identity_seed);
    let mut node_seed = [0u8; 32];
    rng.fill_bytes(&mut node_seed);
    // The Node Management cursor nonce, from the same cryptographic
    // source: it is what keeps a cursor issued before a reboot from being
    // honored after one.
    let mut admin_nonce = [0u8; 2];
    rng.fill_bytes(&mut admin_nonce);
    let admin_nonce = u16::from_be_bytes(admin_nonce);

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
    let radio_spi = ExclusiveDevice::new(spi, radio_cs, Delay).unwrap();

    #[cfg(feature = "board-heltec-v3")]
    let radio_reset = Output::new(peripherals.GPIO12, Level::High, OutputConfig::default());
    #[cfg(feature = "board-heltec-v2")]
    let radio_reset = Output::new(peripherals.GPIO14, Level::High, OutputConfig::default());
    #[cfg(feature = "board-tbeam-supreme")]
    let radio_reset = Output::new(peripherals.GPIO5, Level::High, OutputConfig::default());

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
    let (wired_rx, wired_tx) = uart.split();
    // Pinless: the peripheral owns GPIO19/20 itself.
    #[cfg(feature = "wired-usb-serial-jtag")]
    let (wired_rx, wired_tx) = UsbSerialJtag::new(peripherals.USB_DEVICE)
        .into_async()
        .split();
    spawner.spawn(output_task(wired_tx, panic_report.clone()).unwrap());
    spawner.spawn(uart_in_task(wired_rx).unwrap());

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
            #[cfg(feature = "rtc-pcf8563")]
            wall_clock_rtc,
        )
        .unwrap(),
    );

    // ── Device node ──────────────────────────────────────────────────────
    // The device identity always exists by this point, so the full
    // MAC/node stack always comes up on mux client B; whether it
    // transmits is a matter of configuration, not of whether a key was
    // ever provisioned. After a crash reboot, skip one boot of the node
    // so the surviving boot stays reachable and reports the panic.
    let (identity_secret, _public) = boot_identity_keys
        .as_ref()
        .expect("a device identity is generated at boot when none is stored");
    if panic_report.is_none() {
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
    }

    // ── Battery, button ──────────────────────────────────────────────────
    // The sampler was constructed above, before the radio controller;
    // on a PMIC board the telemetry comes off the PMU bus instead.
    #[cfg(not(feature = "pmic-axp2101"))]
    spawner.spawn(battery_task(sampler).unwrap());
    #[cfg(feature = "pmic-axp2101")]
    spawner.spawn(battery_task(pmic).unwrap());
    let button = Input::new(
        peripherals.GPIO0,
        InputConfig::default().with_pull(Pull::Up),
    );
    spawner.spawn(button_task(button).unwrap());

    // ── GNSS: UART1 to the receiver, powered by the pump ─────────────────
    // The pump owns when the receiver runs (`PROP_GNSS_ENABLED`); the
    // BSP's `Power` impl owns how, and its rail starts off. This board's
    // clock lives in the PCF8563, so nothing reads the receiver's own
    // RTC at boot.
    #[cfg(feature = "gnss")]
    {
        let gnss_uart = Uart::new(
            peripherals.UART1,
            UartConfig::default().with_baudrate(board::GNSS_BAUD),
        )
        .unwrap()
        .with_rx(peripherals.GPIO9)
        .with_tx(peripherals.GPIO8)
        .into_async();
        let gnss_wake = Output::new(peripherals.GPIO7, Level::Low, OutputConfig::default());
        spawner.spawn(gnss_task(gnss_uart, board::gnss::Gnss::new(pmic, gnss_wake)).unwrap());
    }

    // ── OLED, then hand the panel to its task ────────────────────────────
    // On a `Vext` board the panel and the rail that powers it move
    // together: the display task switches the panel off when attention
    // lapses and drops the rail entirely on the way into deep sleep. On
    // a PMIC board the panel's rail came up with the sensor rails and
    // drops in the shutdown path.
    #[cfg(not(feature = "display-sh1106"))]
    #[cfg(feature = "board-heltec-v3")]
    let mut oled_reset = Output::new(peripherals.GPIO21, Level::High, OutputConfig::default());
    #[cfg(not(feature = "display-sh1106"))]
    #[cfg(feature = "board-heltec-v2")]
    let mut oled_reset = Output::new(peripherals.GPIO16, Level::High, OutputConfig::default());

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

    #[cfg(not(feature = "display-sh1106"))]
    {
        let mut oled = display::new_display(i2c);
        vext.enable().await;
        display::reset(&mut oled_reset).await;
        if oled.init().await.is_ok() {
            spawner.spawn(display_task(oled, vext).unwrap());
        }
    }
    // The SH1106's address is a population variable and there is no
    // reset pin — the rail is the reset, and it is already up. A panel
    // that does not answer leaves the board headless rather than
    // stopping the boot.
    #[cfg(feature = "display-sh1106")]
    {
        let mut i2c = i2c;
        match display::probe(&mut i2c).await {
            Some(addr) => {
                debug_log(format_args!("oled: sh1106 at 0x{addr:02x}"));
                let mut oled = display::new_display(i2c, addr);
                if oled.init().await.is_ok() {
                    spawner.spawn(display_task(oled).unwrap());
                }
            }
            None => debug_log(format_args!("oled: no panel found")),
        }
    }

    // ── BLE app: runs the pairing lattice + GATT transport forever ───────
    ble_app(controller, ble_store_handle).await
}
