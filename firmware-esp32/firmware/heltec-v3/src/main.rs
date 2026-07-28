//! ULCP firmware for the Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262).
//!
//! The protocol brain is the shared board-agnostic driver
//! (`umsh_ulcp_runtime::driver`) — the same session loop the T-Echo
//! and T-1000E images run — behind this board's couplings:
//!
//! - **Wired transport**: HDLC-framed CRP on UART0 (the CP2102 bridge).
//!   UART has no connection state, so wired attachment is lazy and
//!   permanent: the first valid HDLC frame attaches, nothing ever
//!   detaches it (serial hosts are assumed present once they speak),
//!   and a board nobody serials into stays detached and autonomous.
//!   Real attach/detach edges exist only on BLE.
//! - **BLE transport**: the `UlcpService` GATT shape over the
//!   esp-radio controller, with the same pairing/bonding lattice the
//!   Phase 4 spike hardware-proved (PIN on the OLED, lockout policy,
//!   durable bonds through `umsh_journal_store`).
//! - **Radio**: the SX1262 behind `device_runner` + `radio_mux`; the
//!   session (client A) and the on-board device node (client B) share
//!   the physical radio and one duty ledger.
//! - **Persistence**: snapshot / identity / counter journals in the
//!   `umsh` partition tail (see `ble_store.rs`).
//!
//! ## Boot order is constrained
//!
//! The BLE controller comes up first and stays up: it is both a
//! transport and the RF entropy source without which `EspCryptoRng`
//! refuses to exist (see `umsh_bsp_esp32::rng`). Journals mount before
//! the ULCP session starts so a stored snapshot is restored (and the PHY
//! re-applied) before the first host command.
//!
//! ## UART0 is the wire, so the console goes quiet
//!
//! `esp-println` shares UART0 with the wired transport. Boot
//! diagnostics interleave cleanly before the UART is claimed; after
//! that, nothing may `println!`. The `ble-debug` feature multiplexes
//! diagnostic lines onto the UART0 output stream as ASCII (HDLC hosts
//! resynchronize past them), mirroring the nRF image's ble-debug.

#![no_std]
#![no_main]

extern crate alloc;

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, Ordering};

use bt_hci::controller::ExternalController;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_futures::select::{Either, Either3, select, select3};
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_sync::once_lock::OnceLock;
use embassy_sync::signal::Signal;
use embassy_time::{Delay, Duration, Instant, Timer, with_timeout};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_hal::Async;
use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rtc_cntl::{Rtc, RwdtStage, SocResetReason};
use esp_hal::spi::Mode;
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::uart::{Config as UartConfig, Uart, UartRx, UartTx};
use esp_println::println;
use esp_radio::ble::controller::BleConnector;
use lora_phy::LoRa;
use static_cell::StaticCell;
use trouble_host::gap;
use trouble_host::prelude::*;

use umsh_bsp_esp32::flash_store;
use umsh_bsp_esp32::rng::EspCryptoRng;
use umsh_bsp_heltec_lora32_v3::battery::BatterySampler;
use umsh_bsp_heltec_lora32_v3::display::{self, Display, DisplayConfigAsync as _};
use umsh_bsp_heltec_lora32_v3::radio as board_radio;
use umsh_bsp_heltec_lora32_v3::vext::Vext;
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
use umsh_radio_loraphy::{DeviceControl, MAX_PAYLOAD};
use umsh_ulcp::{Status, gatt, hdlc};
use umsh_ulcp_device::{BatteryFields, MAX_DEVICE_NAME_LEN, RadioSettings, SessionConfig};
use umsh_ulcp_runtime::ble_security::{PairingFailureClass, PairingRuntime, pairing_enabled};
use umsh_ulcp_runtime::driver::{
    self, DeviceEnv, DeviceRuntime, InEvent, InputChannel, OutFrame, TransportChannels,
};
use umsh_ulcp_runtime::{radio_mux, transport_policy};
use umsh_ux_tracker::battery::soc_from_ocv;

use transport_policy::{Transport, generation_checked};

mod ble_store;
mod device_node;

use ble_store::{BleStore, ProtoStore, StoredBond, bond_identity_is_persistable, trouble_bond};

esp_bootloader_esp_idf::esp_app_desc!();

// ─── Configuration ───────────────────────────────────────────────────────

const WDT_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(8);

/// SX1262 PA limits on this module.
const MIN_TX_POWER_DBM: i8 = -9;
const MAX_TX_POWER_DBM: i8 = 22;

const BLE_CONNECTIONS_MAX: usize = 1;
const BLE_L2CAP_CHANNELS_MAX: usize = 2;
/// HCI command/event slot count for the external controller.
const HCI_SLOTS: usize = 4;
/// Max GATT value payload the ULCP characteristics carry.
/// Largest value the ULCP characteristics accept.
///
/// A client may write up to ATT_MTU-3 octets in one request, and the
/// packet pool is configured for a 255-octet MTU, so anything smaller
/// than 252 here is a size the peer is entitled to send and this device
/// would refuse with an invalid-length error.
const BLE_VALUE_MAX: usize = 252;

const DEFAULT_DEVICE_NAME: &str = "UMSH Heltec V3";

/// `PROP_DEV_VERSION`: the board's firmware name and `git describe
/// --always` (from the build script), nothing else.
const DEV_VERSION: &str = concat!("umsh-heltec-v3 ", env!("GIT_DESCRIBE"));

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
        // Battery-powered board with an ADC divider but no
        // charger-status signal (the charge LED is charger-driven), so
        // voltage and the OCV level estimate are reported and charge
        // state is not advertised.
        battery: Some(BatteryFields {
            voltage: true,
            level: true,
            charge_state: false,
        }),
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
const ULCP_TX_QUEUE_CAPACITY: usize = 8;
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
static ADV_POLICY_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// OLED redraw trigger; the display task also refreshes periodically.
static UI_REFRESH: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// 0 = normal heartbeat, 1 = pairing mode (fast LED blink).
static BLE_LED_MODE: AtomicU8 = AtomicU8::new(0);
/// 0 = idle/advertising, 1 = connected, 2 = attached. Display only.
static BLE_LINK: AtomicU8 = AtomicU8::new(0);
/// Last battery sample in millivolts (0 = never sampled). Display only.
static BATTERY_MV: AtomicU16 = AtomicU16::new(0);
/// Battery request/reply pair between the session env and the sampler
/// task, which owns the ADC.
static BATTERY_REQUEST: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static BATTERY_REPLY: Signal<CriticalSectionRawMutex, u16> = Signal::new();

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

// ─── Battery sampling ────────────────────────────────────────────────────

/// Owns the ADC divider. Samples on a slow cadence for the OLED and
/// immediately on session request (`Effect::SampleBattery`).
#[embassy_executor::task]
async fn battery_task(mut sampler: BatterySampler) {
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
    }
}

/// The platform battery source behind `Effect::SampleBattery`: a
/// request/reply round trip into [`battery_task`], the sole ADC owner.
/// No charger-status signal exists on this board, so charge state is
/// never reported (and `SessionConfig::battery` does not advertise it).
async fn sample_battery_snapshot() -> Result<umsh_ulcp::battery::BatteryStatus, ()> {
    BATTERY_REPLY.reset();
    BATTERY_REQUEST.signal(());
    let mv = with_timeout(Duration::from_secs(2), BATTERY_REPLY.wait())
        .await
        .map_err(|_| ())?;
    Ok(umsh_ulcp::battery::BatteryStatus {
        voltage_mv: Some(mv),
        level_percent: Some(soc_from_ocv(mv)),
        charge_state: None,
    })
}

// ─── Pairing runtime plumbing (port of the nRF firmware's) ────────────────────

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
                UI_REFRESH.signal(());
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
                } else {
                    debug_log(format_args!("security wipe flash=FAILED"));
                }
                UI_REFRESH.signal(());
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
                            INPUT_CH.send(InEvent::Attached(Transport::Ble)).await;
                        }
                        (true, false) => {
                            debug_log(format_args!("cccd subscribed=false"));
                            attached = false;
                            reassembler.reset();
                            BLE_LINK.store(1, Ordering::Release);
                            UI_REFRESH.signal(());
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
    BLE_LINK.store(0, Ordering::Release);
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

async fn ble_app<C: Controller>(controller: C, store: BleStore) -> ! {
    let mut resources: HostResources<
        _,
        DefaultPacketPool,
        BLE_CONNECTIONS_MAX,
        BLE_L2CAP_CHANNELS_MAX,
    > = HostResources::new();
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
    let stack = trouble_host::new(controller, &mut resources)
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
/// runner. RX preamble 8 symbols, TX preamble 16 (MeshCore parity;
/// the SX1262 detects MeshCore-US traffic fine at 8 — hardware-proven
/// in Phase 2 on this board).
#[embassy_executor::task]
async fn radio_task(lora: board_radio::Radio) {
    umsh_radio_loraphy::device_runner(lora, &RADIO_CH, &DEVICE_CTL, 8, 16).await;
}

/// Owns the real `RADIO_CH` bundle and multiplexes it across the
/// virtual per-client bundles (see `radio_mux`): per-client TX
/// completion routing plus RX fan-out to every client.
#[embassy_executor::task]
async fn radio_mux_task() {
    radio_mux::radio_mux(&RADIO_CH, &MUX_CLIENTS).await
}

// ─── Wired transport (UART0) ─────────────────────────────────────────────

/// Write all of `bytes` to the UART, best-effort.
async fn uart_write_all(tx: &mut UartTx<'static, Async>, bytes: &[u8]) {
    let mut sent = 0;
    while sent < bytes.len() {
        match tx.write_async(&bytes[sent..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => sent += n,
        }
    }
}

/// Owns the UART TX half, HDLC-encodes frames, and writes them out.
#[embassy_executor::task]
async fn output_task(mut tx: UartTx<'static, Async>, panic_report: Option<heapless::String<128>>) {
    // Emit the previous boot's panic message as ASCII. HDLC hosts
    // resynchronize past it; humans read it with a serial terminal.
    // UART has no DTR, so this cannot wait for a reader — it lands in
    // the CP2102 and is lost if no terminal is attached, which is the
    // correct behaviour for a serial console.
    if let Some(report) = panic_report {
        uart_write_all(&mut tx, b"[PREV PANIC]: ").await;
        uart_write_all(&mut tx, report.as_bytes()).await;
        uart_write_all(&mut tx, b"\r\n").await;
    }
    loop {
        #[cfg(feature = "ble-debug")]
        let outbound = match select(OUT_CH.wired.receive(), DEBUG_CH.receive()).await {
            Either::First(outbound) => outbound,
            Either::Second(line) => {
                uart_write_all(&mut tx, line.as_bytes()).await;
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
            uart_write_all(&mut tx, chunk).await;
        }
    }
}

/// Owns the UART RX half and HDLC decoder, forwarding frames into
/// `INPUT_CH`. UART has no connection state, so wired attachment is
/// lazy and permanent: the first valid HDLC frame attaches the wired
/// transport, and no wired detach ever fires — a serial host is
/// assumed present for good once it has spoken. Detach semantics exist
/// only for BLE, whose link genuinely drops; a board nobody serials
/// into therefore stays detached and operates autonomously (queueing
/// and delegated acknowledgement). Displacement by a BLE attach is
/// observed as a foreign `SESSION_GEN` bump, which re-arms the lazy
/// attach, so a displaced serial host reclaims the session with its
/// next frame.
#[embassy_executor::task]
async fn uart_in_task(mut rx: UartRx<'static, Async>) {
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
        match rx.read_async(&mut packet).await {
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
        },
    )
    .await
}

// ─── UI: OLED, button, LED ───────────────────────────────────────────────

fn draw_line(display: &mut Display, text: &str, row: i32, style: MonoTextStyle<'_, BinaryColor>) {
    // FONT_6X10 baseline: rows 0..=4 fit in the 64 px panel.
    let _ = Text::new(text, Point::new(0, 10 + row * 12), style).draw(display);
}

/// Render the status screen. Best-effort — a display error just leaves
/// the panel stale; it never blocks the protocol paths.
async fn render_status(display: &mut Display) {
    let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);
    display.clear_buffer();

    let name = device_name_snapshot().await;
    draw_line(
        display,
        core::str::from_utf8(&name).unwrap_or(DEFAULT_DEVICE_NAME),
        0,
        style,
    );

    let mut line: heapless::String<24> = heapless::String::new();
    let pin = PAIRING_PIN.load(Ordering::Acquire);
    if PAIRING_MODE.load(Ordering::Acquire) && pin != u32::MAX {
        let _ = write!(line, "PIN {pin:06}");
    } else if PAIRING_MODE.load(Ordering::Acquire) {
        let _ = write!(line, "pairing (no PIN)");
    } else {
        let _ = write!(line, "paired");
    }
    draw_line(display, &line, 1, style);

    line.clear();
    let _ = write!(
        line,
        "bonds {}/{}{}",
        BLE_BOND_COUNT.load(Ordering::Acquire),
        ble_store::MAX_BONDS,
        if PAIRING_LOCKED_OUT.load(Ordering::Acquire) {
            " LOCK"
        } else {
            ""
        },
    );
    draw_line(display, &line, 2, style);

    line.clear();
    let _ = write!(
        line,
        "ble {}",
        match BLE_LINK.load(Ordering::Acquire) {
            2 => "attached",
            1 => "connected",
            _ if ADV_ALLOWED.load(Ordering::Acquire) => "advertising",
            _ => "off (wired)",
        }
    );
    draw_line(display, &line, 3, style);

    line.clear();
    let mv = BATTERY_MV.load(Ordering::Acquire);
    if mv == 0 {
        let _ = write!(line, "batt --");
    } else {
        let _ = write!(line, "batt {mv} mV {}%", soc_from_ocv(mv));
    }
    draw_line(display, &line, 4, style);

    let _ = display.flush().await;
}

#[embassy_executor::task]
async fn display_task(mut display: Display) {
    loop {
        render_status(&mut display).await;
        let _ = select(UI_REFRESH.wait(), Timer::after_secs(30)).await;
    }
}

/// PRG button (GPIO0, active low): a short press opens the pairing
/// window (or requests a device-node beacon when one is held ≥2 s).
/// Security wipes stay tool-driven (`umsh-ulcpctl`) — no
/// destructive gesture on a button this easy to lean on.
#[embassy_executor::task]
async fn button_task(mut button: Input<'static>) {
    loop {
        button.wait_for_low().await;
        Timer::after_millis(30).await;
        if button.is_high() {
            continue;
        }
        let pressed_at = Instant::now();
        button.wait_for_high().await;
        let held = pressed_at.elapsed();
        if held >= Duration::from_secs(2) {
            device_node::request_beacon(device_node::BeaconTrigger::Button);
        } else {
            PAIRING_MODE_REQUEST.signal(());
        }
        Timer::after_millis(30).await;
    }
}

/// Heartbeat LED plus the RWDT feed. Sharing one task keeps the
/// watchdog tied to something visibly alive: if the LED stops, the
/// reset follows. Pairing mode switches to a fast blink.
#[embassy_executor::task]
async fn heartbeat_task(mut led: Output<'static>, mut rtc: Rtc<'static>) -> ! {
    loop {
        rtc.rwdt.feed();
        if BLE_LED_MODE.load(Ordering::Acquire) == 1 {
            led.set_high();
            Timer::after_millis(100).await;
            led.set_low();
            Timer::after_millis(300).await;
        } else {
            led.set_high();
            Timer::after_millis(40).await;
            led.set_low();
            Timer::after_secs(2).await;
        }
    }
}

// ─── Boot ────────────────────────────────────────────────────────────────

/// Map the retained hardware reset cause (plus a captured panic
/// message) onto the CRP `PROP_LAST_STATUS` reset statuses.
fn boot_reason(panicked: bool) -> Status {
    if panicked {
        return Status::RESET_CRASH;
    }
    match esp_hal::system::reset_reason() {
        Some(
            SocResetReason::CoreMwdt0
            | SocResetReason::CoreMwdt1
            | SocResetReason::CoreRtcWdt
            | SocResetReason::CpuMwdt0
            | SocResetReason::CpuMwdt1
            | SocResetReason::CpuRtcWdt
            | SocResetReason::SysRtcWdt
            | SocResetReason::SysSuperWdt,
        ) => Status::RESET_WATCHDOG,
        Some(SocResetReason::CoreSw | SocResetReason::CpuSw | SocResetReason::CoreDeepSleep) => {
            Status::RESET_SOFTWARE
        }
        _ => Status::RESET_POWER_ON,
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    // Point the shared runtime's log seam at this board's debug channel
    // before anything shared runs, so the journal mount lines are not
    // lost.
    umsh_ulcp_runtime::log::set_debug_log(debug_log);
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    // umsh-node and umsh-sync use `alloc`.
    esp_alloc::heap_allocator!(size: 72 * 1024);

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
        umsh_bsp_heltec_lora32_v3::BOARD_NAME,
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

    let led = Output::new(peripherals.GPIO35, Level::Low, OutputConfig::default());
    spawner.spawn(heartbeat_task(led, rtc).unwrap());

    // ── BLE controller first: transport AND the RF entropy source ────────
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

    let boot_identity = boot_identity_keys.as_ref().map(|(_secret, public)| *public);

    // ── SX1262 behind the device runner + mux ────────────────────────────
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
    let radio_cs = Output::new(peripherals.GPIO8, Level::High, OutputConfig::default());
    let radio_spi = ExclusiveDevice::new(spi, radio_cs, Delay).unwrap();
    let radio_reset = Output::new(peripherals.GPIO12, Level::High, OutputConfig::default());
    let radio_dio1 = Input::new(
        peripherals.GPIO14,
        InputConfig::default().with_pull(Pull::None),
    );
    let radio_busy = Input::new(
        peripherals.GPIO13,
        InputConfig::default().with_pull(Pull::None),
    );
    let kind = board_radio::new_radio_kind(radio_spi, radio_reset, radio_dio1, radio_busy)
        .unwrap_or_else(|e| panic!("radio init failed: {e:?}"));
    // `false` selects the private-network sync word (0x12 → 0x1424),
    // matching SessionConfig::sync_word above.
    let lora = LoRa::new(kind, false, Delay)
        .await
        .unwrap_or_else(|e| panic!("radio init failed: {e:?}"));
    spawner.spawn(radio_task(lora).unwrap());
    spawner.spawn(radio_mux_task().unwrap());

    // ── UART0: the wired transport ────────────────────────────────────────
    // Same pins the CP2102 bridge and `esp-println` use. Claiming UART0
    // resets the TX FIFO, which truncates whatever `esp-println` left in
    // flight; drain by time (20 ms clears a 64-byte FIFO at 115200 baud
    // roughly four times over). The console goes quiet from here.
    Timer::after_millis(20).await;
    let uart = Uart::new(peripherals.UART0, UartConfig::default())
        .unwrap()
        .with_rx(peripherals.GPIO44)
        .with_tx(peripherals.GPIO43)
        .into_async();
    let (uart_rx, uart_tx) = uart.split();
    spawner.spawn(output_task(uart_tx, panic_report.clone()).unwrap());
    spawner.spawn(uart_in_task(uart_rx).unwrap());

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
        device_node::bring_up(
            spawner,
            identity_secret,
            node_seed,
            t_frame_ms,
            node_counters,
        )
        .await;
    }

    // ── Battery, button ──────────────────────────────────────────────────
    let sampler = BatterySampler::new(peripherals.ADC1, peripherals.GPIO1, peripherals.GPIO37);
    spawner.spawn(battery_task(sampler).unwrap());
    let button = Input::new(
        peripherals.GPIO0,
        InputConfig::default().with_pull(Pull::Up),
    );
    spawner.spawn(button_task(button).unwrap());

    // ── OLED (Vext up → reset → init), then hand the panel to its task ───
    let mut vext = Vext::new(peripherals.GPIO36);
    let mut oled_reset = Output::new(peripherals.GPIO21, Level::High, OutputConfig::default());
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(400)),
    )
    .unwrap()
    .with_sda(peripherals.GPIO17)
    .with_scl(peripherals.GPIO18)
    .into_async();
    let mut oled = display::new_display(i2c);
    vext.enable().await;
    display::reset(&mut oled_reset).await;
    if oled.init().await.is_ok() {
        spawner.spawn(display_task(oled).unwrap());
    }

    // ── BLE app: runs the pairing lattice + GATT transport forever ───────
    ble_app(controller, ble_store_handle).await
}
