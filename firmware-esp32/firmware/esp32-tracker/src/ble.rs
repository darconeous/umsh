//! The BLE transport: the `UlcpService` GATT shape over the esp-radio
//! controller, with the pairing and bonding lattice the nRF images run
//! and durable bonds through `umsh_journal_store`.
//!
//! The rest of the firmware reaches Bluetooth only through the functions
//! in the first section below. Everything after it is the transport's
//! own business.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use bt_hci::controller::ExternalController;
use embassy_futures::join::join;
use embassy_futures::select::{Either, Either3, select, select3};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_sync::watch::Watch;
use embassy_time::{Duration, Instant, Timer};
use esp_radio::ble::controller::BleConnector;
use static_cell::StaticCell;
use trouble_host::gap;
use trouble_host::prelude::*;
use umsh_bsp_esp32::rng::{EspCryptoRng, RngError as EntropyHarvestError};
use umsh_crypto::software::SoftwareSha256;
use umsh_ulcp::ble::BleLinkState;
use umsh_ulcp::gatt;
use umsh_ulcp_runtime::ble_controller::{self, ControllerState, Guarded, bt_hci};
use umsh_ulcp_runtime::ble_privacy;
use umsh_ulcp_runtime::ble_security::{PairingFailureClass, PairingRuntime, pairing_enabled};
use umsh_ulcp_runtime::driver::{self, InEvent, OutFrame};
use umsh_ulcp_runtime::transport_policy::{Transport, generation_checked};
use umsh_ux_display_tracker::menu::UiNotice;
use umsh_ux_display_tracker::screen;

use super::journals::SharedFlash;
use super::{
    DEVICE_NAME_READY, FrameBuf, INPUT_CH, IdentityRng, OUT_CH, SESSION_GEN, UI_NOTICE, UI_REFRESH,
    UI_WAKE, base_mac_bytes, debug_log, default_device_name, device_name_snapshot, entropy,
};

mod store;
use store::{BleStore, StoredBond, bond_identity_is_persistable, trouble_bond};

// ─── What the rest of the firmware sees ──────────────────────────────────

/// The mounted bond journal, held by `main` between [`mount`] and [`run`].
pub(crate) type Store = BleStore;

/// What the panel shows of this transport.
pub(crate) struct Panel {
    /// The operator's switch.
    pub enabled: Option<bool>,
    pub link: screen::LinkState,
    pub bonds: u8,
    pub pairing: screen::PairingState,
}

pub(crate) fn panel() -> Panel {
    Panel {
        enabled: Some(BLE_ENABLED.load(Ordering::Acquire)),
        link: match BleLinkState::from_code(BLE_LINK.load(Ordering::Acquire)) {
            Some(BleLinkState::Attached) => screen::LinkState::Attached,
            Some(BleLinkState::Connected) => screen::LinkState::Connected,
            _ if advertising_permitted() => screen::LinkState::Advertising,
            // The operator's own switch, not the wired-host suppression:
            // "off (wired)" on a device whose Bluetooth was turned off
            // reads as someone else's doing.
            _ if !BLE_ENABLED.load(Ordering::Acquire) => screen::LinkState::Disabled,
            _ => screen::LinkState::OffWired,
        },
        bonds: BLE_BOND_COUNT.load(Ordering::Acquire),
        // Bluetooth off outranks everything—a lockout on a transport
        // that is off is not a state anyone can act on—then lockout
        // outranks the window: while locked out there is no window to
        // describe.
        pairing: if !BLE_ENABLED.load(Ordering::Acquire) {
            screen::PairingState::Closed
        } else if PAIRING_LOCKED_OUT.load(Ordering::Acquire) {
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
    }
}

/// Whether the LED shows the pairing blink rather than the heartbeat.
#[cfg(not(any(feature = "pmic-axp2101", feature = "board-tlora-pager")))]
pub(crate) fn pairing_indicated() -> bool {
    BLE_LED_MODE.load(Ordering::Acquire) == 1
}

/// The menu's Start pairing. Fires and forgets; the notice is the answer.
pub(crate) fn request_pairing() {
    PAIRING_MODE_REQUEST.signal(true);
}

/// The menu's Clear bonds, likewise.
pub(crate) fn request_clear_bonds() {
    BLE_WIPE_REQUEST.signal(false);
}

/// The configured name moved; the advertiser and a live link follow it.
pub(crate) fn device_name_changed() {
    DEVICE_NAME_CHANGED.signal(());
}

/// The saved settings are in force, so the device may become findable.
pub(crate) fn boot_settings_ready() {
    debug_log(format_args!("boot settings ready; BLE startup permitted"));
    BOOT_SETTINGS_READY.sender().send(());
}

/// The next transport change to publish unasked: the bond count, the
/// link, or the pairing window. All three come off statics, so this needs
/// no board hardware. Cancel-safe—a signal keeps its value until an arm
/// that completes takes it.
pub(crate) async fn event() -> driver::PublishEvent {
    match select3(
        BLE_BOND_COUNT_CHANGED.wait(),
        BLE_LINK_CHANGED.wait(),
        BLE_PAIRING_CHANGED.wait(),
    )
    .await
    {
        Either3::First(count) => driver::PublishEvent::BleBondCount(count),
        Either3::Second(state) => driver::PublishEvent::BleLink(state),
        Either3::Third(open) => driver::PublishEvent::BlePairing(open),
    }
}

/// A `PROP_BLE_PAIRING_PIN` write.
pub(crate) async fn apply_pairing_pin(pin: Option<u32>) -> bool {
    PAIRING_CONFIG_CH.send(pin).await;
    PAIRING_CONFIG_ACK.wait().await
}

/// A `PROP_BLE_BOND_COUNT` write of zero.
pub(crate) async fn clear_bonds(reply_over_ble: bool) -> bool {
    // The menu fires this signal too and never waits, so an outcome
    // may already be sitting in the ack; clear it before asking or we
    // would answer with the menu's.
    BLE_WIPE_ACK.reset();
    BLE_WIPE_REQUEST.signal(reply_over_ble);
    BLE_WIPE_ACK.wait().await
}

/// A `PROP_BLE_PAIRING` write.
pub(crate) async fn set_pairing(open: bool) -> bool {
    if !BLE_ENABLED.load(Ordering::Acquire) {
        // Nothing can pair through a transport that is off, so a
        // window cannot open—and closing one is trivially done
        // without the stack's help, which matters on this family:
        // the task that would answer is torn down with the
        // controller, and waiting on it would hang the session.
        if !open {
            set_pairing_mode(false);
        }
        return !open;
    }
    PAIRING_MODE_ACK.reset();
    PAIRING_MODE_REQUEST.signal(open);
    PAIRING_MODE_ACK.wait().await
}

/// Mount the bond journal and seed everything that mirrors it.
///
/// The bond count, the pairing PIN, and the pairing window all come
/// off the journal, not the radio. A board that boots with
/// `PROP_BLE_ENABLED` cleared never brings the stack up, so state
/// seeded only inside `run_ble_stack` keeps its `static` initializer
/// instead: a count of zero on a device holding bonds, and—worse—a
/// pairing window stuck open, which held the panel awake forever and
/// announced "pairing" on a transport that is off. Seeded here, at
/// the mount, exactly as the nRF image seeds them.
pub(crate) async fn mount(
    shared: &'static SharedFlash,
    partition: &core::ops::Range<u32>,
    mut draw: impl FnMut(&[u8], &mut [u8]),
) -> Store {
    let mut store = BleStore::mount(shared, partition).await;
    if store.snapshot().privacy_migration_pending {
        let replacement_irk = loop {
            let mut irk = [0; 16];
            draw(b"ble-privacy-migration", &mut irk);
            if irk != [0; 16] && Some(irk) != store.snapshot().local_irk {
                break irk;
            }
        };
        match store.forget_hosts(replacement_irk).await {
            Ok(()) => debug_log(format_args!("BLE privacy migration complete; pair again")),
            Err(()) => debug_log(format_args!("BLE privacy migration failed; BLE blocked")),
        }
    }
    set_bond_count(store.snapshot().bonds.len() as u8);
    PAIRING_PIN.store(store.snapshot().pin.unwrap_or(u32::MAX), Ordering::Release);
    PAIRING_MODE.store(store.snapshot().bonds.is_empty(), Ordering::Release);
    BLE_PAIRING_CHANGED.signal(pairing_window_open());
    if !store.snapshot().privacy_migration_pending && store.snapshot().local_irk.is_none() {
        let mut local_irk = [0u8; 16];
        while local_irk == [0; 16] {
            draw(b"ble-local-irk", &mut local_irk);
        }
        store
            .set_local_irk(local_irk)
            .await
            .unwrap_or_else(|_| panic!("local irk persist failed"));
    }
    store
}

// ─── Configuration ───────────────────────────────────────────────────────

const BLE_CONNECTIONS_MAX: usize = 1;
const BLE_L2CAP_CHANNELS_MAX: usize = 2;
/// HCI command/event slot count for the external controller.
const HCI_SLOTS: usize = 4;

/// The one BLE controller this image builds, named so the GATT host's
/// resource block can be a `static`—a generic function cannot own one.
type BleController = Guarded<ExternalController<BleConnector<'static>, HCI_SLOTS>>;

/// The GATT host's resource block. Tens of kilobytes; see [`run`].
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

/// The same hardware, as the model identifier in pairing advertisements.
#[cfg(feature = "board-heltec-v2")]
const BLE_MODEL_ID: u16 = ble_privacy::model::HELTEC_LORA32_V2;
#[cfg(feature = "board-heltec-v3")]
const BLE_MODEL_ID: u16 = ble_privacy::model::HELTEC_LORA32_V3;
#[cfg(feature = "board-tbeam-supreme")]
const BLE_MODEL_ID: u16 = ble_privacy::model::LILYGO_T_BEAM_SUPREME;
#[cfg(feature = "board-tlora-pager")]
const BLE_MODEL_ID: u16 = ble_privacy::model::LILYGO_T_LORA_PAGER;

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

type BleStoreMutex = Mutex<CriticalSectionRawMutex, BleStore>;

// Retained readiness for each advertiser, independent of stack initialization.
static BOOT_SETTINGS_READY: Watch<CriticalSectionRawMutex, (), 1> = Watch::new();
static DEVICE_NAME_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

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
async fn sync_gap_device_name(server: &UlcpServer<'_>, store: &BleStoreMutex) {
    let Some(gap) = server.gap.as_ref() else {
        return;
    };
    let name = device_name_snapshot().await;
    if server
        .set(&gap.device_name, &gap_device_name(name.as_slice()))
        .is_err()
    {
        debug_log(format_args!("gap device-name update FAILED"));
        return;
    }
    // Boot publication must precede the baseline comparison: the temporary
    // hardware-default name must not look like a rename on every restart.
    if DEVICE_NAME_READY.load(Ordering::Acquire) {
        let hash = umsh_crypto::Sha256Provider::hash(&SoftwareSha256, &[name.as_slice()]);
        let _busy = BleConfigGuard::new();
        let mut store = store.lock().await;
        if !BLE_REKEY_PENDING.load(Ordering::Acquire)
            && store.observe_device_name(hash).await.is_err()
        {
            debug_log(format_args!("gap name-refresh persistence FAILED"));
        }
    }
}

/// Compatibility workaround for clients that cache the GAP name.
/// A name-value change is not a service-structure change, and iOS controls
/// when Settings refreshes. Only a retained bond with a pending rename is
/// indicated; confirmation clears that host's durable pending state.
async fn announce_gatt_change(
    server: &UlcpServer<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    store: &BleStoreMutex,
) -> bool {
    if BLE_REKEY_PENDING.load(Ordering::Acquire)
        || !DEVICE_NAME_READY.load(Ordering::Acquire)
        || !matches!(
            conn.raw().security_level(),
            Ok(SecurityLevel::Encrypted | SecurityLevel::EncryptedAuthenticated)
        )
        || !conn.raw().is_bonded_peer()
    {
        return false;
    }
    let hash = {
        let name = device_name_snapshot().await;
        umsh_crypto::Sha256Provider::hash(&SoftwareSha256, &[name.as_slice()])
    };
    let (bond, revision) = {
        let store = store.lock().await;
        let snapshot = store.snapshot();
        // A failed rename commit must be retried before acknowledging it.
        if snapshot.device_name_hash != Some(hash) {
            return false;
        }
        let peer = conn.raw().peer_identity();
        let Some(bond) = snapshot.bonds.iter().find(|bond| {
            trouble_bond(bond).is_some_and(|bond| bond.identity.match_identity(&peer))
        }) else {
            return false;
        };
        if !bond.name_refresh_pending {
            return true;
        }
        (*bond, snapshot.name_revision)
    };
    let Some(gap) = server.gap.as_ref() else {
        return false;
    };
    // A client that has not subscribed cannot be told anything, and
    // `indicate` reports that case as success. Checking first keeps the
    // connection eligible to retry after subscription.
    if !gap.service_changed.should_indicate(conn) {
        debug_log(format_args!("service-changed not subscribed; deferring"));
        return false;
    }
    const WHOLE_TABLE: [u8; 4] = [0x01, 0x00, 0xFF, 0xFF];
    match gap
        .service_changed
        .indicate(conn, &WHOLE_TABLE, false)
        .await
    {
        Ok(()) => {
            // indicate() waits for ATT confirmation, not just queue insertion.
            // Keep a concurrent rename or bond replacement eligible to retry.
            let current_hash = {
                let current = device_name_snapshot().await;
                umsh_crypto::Sha256Provider::hash(&SoftwareSha256, &[current.as_slice()])
            };
            if hash != current_hash {
                return false;
            }
            let _busy = BleConfigGuard::new();
            let mut store = store.lock().await;
            if BLE_REKEY_PENDING.load(Ordering::Acquire) {
                return false;
            }
            match store.acknowledge_device_name(&bond, revision).await {
                Ok(acknowledged) => acknowledged,
                Err(()) => {
                    debug_log(format_args!("gap name-refresh acknowledgement FAILED"));
                    false
                }
            }
        }
        Err(error) => {
            debug_log(format_args!("service-changed indicate error={error:?}"));
            false
        }
    }
}

/// `u32::MAX` sentinel means "no PIN configured".
static PAIRING_PIN: AtomicU32 = AtomicU32::new(u32::MAX);
/// How many bonds the journal holds. Seeded from the store at mount,
/// not from the BLE stack: the stack does not run at all on a board that
/// boots with `PROP_BLE_ENABLED` cleared, and the count has to be right
/// on one that does.
static BLE_BOND_COUNT: AtomicU8 = AtomicU8::new(0);
static PAIRING_MODE: AtomicBool = AtomicBool::new(true);
static PAIRING_LOCKED_OUT: AtomicBool = AtomicBool::new(false);
static PAIRING_FAILURES: AtomicU8 = AtomicU8::new(0);
static PAIRING_CONFIG_CH: Channel<CriticalSectionRawMutex, Option<u32>, 1> = Channel::new();
static PAIRING_CONFIG_ACK: Signal<CriticalSectionRawMutex, bool> = Signal::new();
static PAIRING_MODE_REQUEST: Signal<CriticalSectionRawMutex, bool> = Signal::new();
static PAIRING_TIMER_RESET: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static BLE_CONTROLLER_STATE: ControllerState = ControllerState::new();
static BLE_RESTART_PENDING: AtomicBool = AtomicBool::new(false);
static BLE_REKEY_PENDING: AtomicBool = AtomicBool::new(false);
static BLE_WIPE_WAITING_REPLY: AtomicBool = AtomicBool::new(false);
static BLE_STACK_FAULT: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static BLE_CONFIG_BUSY: AtomicU32 = AtomicU32::new(0);
static BLE_WIPE_REPLY_DEADLINE: Signal<CriticalSectionRawMutex, Instant> = Signal::new();
static BLE_PRIVACY_RNG: Mutex<CriticalSectionRawMutex, Option<IdentityRng>> = Mutex::new(None);
static PAIRING_DEADLINE: embassy_sync::blocking_mutex::Mutex<
    CriticalSectionRawMutex,
    core::cell::RefCell<ble_privacy::PairingDeadline>,
> = embassy_sync::blocking_mutex::Mutex::new(core::cell::RefCell::new(
    ble_privacy::PairingDeadline::new(),
));

struct BleConfigGuard;
impl BleConfigGuard {
    fn new() -> Self {
        BLE_CONFIG_BUSY.fetch_add(1, Ordering::AcqRel);
        Self
    }
}
impl Drop for BleConfigGuard {
    fn drop(&mut self) {
        BLE_CONFIG_BUSY.fetch_sub(1, Ordering::AcqRel);
    }
}

fn pairing_visibility_changed() {
    BLE_RESTART_PENDING.store(true, Ordering::Release);
    BLE_CONTROLLER_STATE.invalidate_advertising();
    ADV_POLICY_CHANGED.signal(());
}

async fn next_local_irk(store: &BleStoreMutex) -> [u8; 16] {
    let old = store.lock().await.snapshot().local_irk;
    let mut rng = BLE_PRIVACY_RNG.lock().await;
    let rng = rng.as_mut().expect("BLE privacy RNG initialized");
    loop {
        let mut irk = [0; 16];
        rand_core::RngCore::fill_bytes(rng, &mut irk);
        if irk != [0; 16] && Some(irk) != old {
            return irk;
        }
    }
}

async fn initialize_pairing_deadline() {
    PAIRING_DEADLINE.lock(|d| {
        if PAIRING_MODE.load(Ordering::Acquire) {
            d.borrow_mut().open(
                Instant::now().as_millis(),
                ble_privacy::pairing_window_ms(BLE_BOND_COUNT.load(Ordering::Acquire)),
            );
        }
    });
}
static BLE_WIPE_REQUEST: Signal<CriticalSectionRawMutex, bool> = Signal::new();
/// Outcomes for the two requests above, for a caller that has someone to
/// answer. The menu fires and forgets; a ULCP command waits, and resets
/// the signal first so it cannot read the menu's stale result.
static BLE_WIPE_ACK: Signal<CriticalSectionRawMutex, bool> = Signal::new();
static PAIRING_MODE_ACK: Signal<CriticalSectionRawMutex, bool> = Signal::new();
/// The bond count moved, carrying the new value to `publish_event` so
/// `PROP_BLE_BOND_COUNT` follows enrollment without polling.
static BLE_BOND_COUNT_CHANGED: Signal<CriticalSectionRawMutex, u8> = Signal::new();
/// The pairing window moved, carrying the new state to `publish_event`
/// so `PROP_BLE_PAIRING` follows the window without polling—including
/// the transitions nobody commanded (a timeout, the boot-time window)
/// and the boot seeding of the session's mirror.
static BLE_PAIRING_CHANGED: Signal<CriticalSectionRawMutex, bool> = Signal::new();
/// The BLE link moved, carrying the new state to `publish_event` so
/// `PROP_BLE_LINK` follows a host arriving or walking away without
/// polling.
static BLE_LINK_CHANGED: Signal<CriticalSectionRawMutex, BleLinkState> = Signal::new();

/// Wired protocol attachment suppresses BLE advertising. The signal
/// wakes a pending advertiser/connection so it can apply the policy.
static ADV_ALLOWED: AtomicBool = AtomicBool::new(true);
/// `PROP_BLE_ENABLED`, mirrored from the session. True at boot, before
/// any restore, so a device that never reaches its saved state is still
/// reachable by the host that could fix it.
static BLE_ENABLED: AtomicBool = AtomicBool::new(true);
static ADV_POLICY_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
/// Wakes the BLE supervisor on a `PROP_BLE_ENABLED` edge. Separate from
/// [`ADV_POLICY_CHANGED`] because embassy's `Signal` holds a single
/// waker—the advertiser loop and the supervisor cannot share one.
static BLE_LIFECYCLE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// 0 = normal heartbeat, 1 = pairing mode (fast LED blink). On a board
/// with no firmware LED the state reaches the user through the panel's
/// pairing page instead.
static BLE_LED_MODE: AtomicU8 = AtomicU8::new(0);
/// How far the BLE link has got, for the status page and for
/// `PROP_BLE_LINK`. Holds a [`BleLinkState`] code rather than an encoding
/// of its own: the panel and the property are two readings of one fact,
/// and the wire enumeration is the one place that fact is defined.
static BLE_LINK: AtomicU8 = AtomicU8::new(BleLinkState::None.code());

// ─── Pairing runtime plumbing (port of the nRF firmware's) ────────────────────

/// Whether the peripheral may be findable right now: transport
/// arbitration and the user's own `PROP_BLE_ENABLED`, both of which have
/// to agree.
fn advertising_permitted() -> bool {
    BOOT_SETTINGS_READY.try_get().is_some()
        && ADV_ALLOWED.load(Ordering::Acquire)
        && BLE_ENABLED.load(Ordering::Acquire)
        && !BLE_CONTROLLER_STATE.failed()
}

/// Whether a pairing window is genuinely open, for everything that shows
/// one: the status page and the attention hold that keeps the panel
/// awake while a PIN might need reading.
///
/// Gated on `PROP_BLE_ENABLED` because pairing mode is a property of the
/// running stack: nothing can pair through a transport that is off, and
/// a panel held awake for a window nobody can walk through is a battery
/// drain announcing a falsehood.
pub(crate) fn pairing_window_open() -> bool {
    BLE_ENABLED.load(Ordering::Acquire) && PAIRING_MODE.load(Ordering::Acquire)
}

/// Apply `PROP_BLE_ENABLED`. The advertising-policy signal stops the
/// advertiser and drops a live connection; the lifecycle signal then
/// has the supervisor tear the whole controller down (or bring it back
/// up). Bonds are untouched, so the host reconnects without pairing
/// again after a re-enable.
pub(crate) fn set_enabled(enabled: bool) {
    let window_was = pairing_window_open();
    if BLE_ENABLED.swap(enabled, Ordering::AcqRel) != enabled {
        debug_log(format_args!(
            "ble reachability {}",
            if enabled { "ON" } else { "off" }
        ));
        ADV_POLICY_CHANGED.signal(());
        BLE_LIFECYCLE.signal(());
        UI_REFRESH.signal(());
        // `PROP_BLE_PAIRING` reports the window through this gate, so
        // flipping the transport can move the property too.
        let window_now = pairing_window_open();
        if window_was != window_now {
            BLE_PAIRING_CHANGED.signal(window_now);
        }
    }
}

/// Record how many bonds the store now holds, waking anything that
/// reports it. Every write to the count goes through here so the
/// property, the status page and the atomic cannot drift apart.
fn set_bond_count(count: u8) {
    if BLE_BOND_COUNT.swap(count, Ordering::AcqRel) != count {
        BLE_BOND_COUNT_CHANGED.signal(count);
        UI_REFRESH.signal(());
    }
}

/// Move the pairing window, waking anything that reports it. What is
/// published is `pairing_window_open()`—the window as the property
/// defines it, gated on `PROP_BLE_ENABLED`—so the session's mirror
/// and the panel read the same fact.
fn set_pairing_mode(open: bool) {
    let previous = PAIRING_MODE.swap(open, Ordering::AcqRel);
    PAIRING_DEADLINE.lock(|d| {
        if open {
            d.borrow_mut().open(
                Instant::now().as_millis(),
                ble_privacy::pairing_window_ms(BLE_BOND_COUNT.load(Ordering::Acquire)),
            );
        } else {
            d.borrow_mut().close();
        }
    });
    PAIRING_TIMER_RESET.signal(());
    if previous != open {
        BLE_PAIRING_CHANGED.signal(pairing_window_open());
        pairing_visibility_changed();
        UI_REFRESH.signal(());
    }
}

/// Record how far the BLE link has got, waking anything that reports it.
/// Every write to the state goes through here for the same reason the
/// bond count does—the panel and `PROP_BLE_LINK` are two readings of
/// one fact and must not disagree.
///
/// The panel wake goes with it: on this family a connection arriving is
/// exactly the moment the screen should come back, and every site that
/// used to store the state raised both signals by hand.
fn set_ble_link(state: BleLinkState) {
    if BLE_LINK.swap(state.code(), Ordering::AcqRel) != state.code() {
        BLE_LINK_CHANGED.signal(state);
        UI_REFRESH.signal(());
        UI_WAKE.signal(());
    }
}

/// Apply the transport arbitration's view of whether to advertise.
pub(crate) fn set_advertising_allowed(allowed: bool) {
    // ble-debug builds keep advertising open regardless of the
    // arbitration policy so the diagnostic path stays reachable.
    #[cfg(feature = "ble-debug")]
    let allowed = {
        let _ = allowed;
        true
    };
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
    stack.set_pairing_enabled(enabled && !BLE_REKEY_PENDING.load(Ordering::Acquire));
    debug_log(format_args!(
        "pairing gate enabled={} mode={} pin={} locked={} failures={} bonds={}/{}",
        enabled,
        PAIRING_MODE.load(Ordering::Acquire),
        pin_configured,
        PAIRING_LOCKED_OUT.load(Ordering::Acquire),
        PAIRING_FAILURES.load(Ordering::Acquire),
        bonds,
        store::MAX_BONDS,
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
    PAIRING_FAILURES.store(state.failures, Ordering::Release);
    PAIRING_LOCKED_OUT.store(state.locked_out, Ordering::Release);
    if PAIRING_MODE.load(Ordering::Acquire) != state.pairing_mode {
        set_pairing_mode(state.pairing_mode);
    }
    UI_REFRESH.signal(());
}

async fn persist_bond(
    store: &BleStoreMutex,
    bond: &BondInformation,
) -> Result<(usize, Option<StoredBond>), ()> {
    let _busy = BleConfigGuard::new();
    let mut store = store.lock().await;
    if BLE_REKEY_PENDING.load(Ordering::Acquire) {
        return Err(());
    }
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

// ─── BLE app layer (port of the nRF firmware's, esp-radio controller) ─────────

async fn ble_runner<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) -> ! {
    match runner.run().await {
        Ok(()) => debug_log(format_args!("BLE runner stopped")),
        Err(error) => debug_log(format_args!(
            "BLE runner exited; requesting stack recovery: {error:?}"
        )),
    }
    BLE_CONTROLLER_STATE.runner_exited();
    BLE_STACK_FAULT.signal(());
    core::future::pending().await
}

async fn pairing_timeout<C: Controller, P: PacketPool>(stack: &Stack<'_, C, P>) -> ! {
    loop {
        let deadline = PAIRING_DEADLINE.lock(|d| d.borrow().at());
        let expires = async {
            if let Some(deadline) = deadline {
                Timer::at(Instant::from_millis(deadline)).await;
            } else {
                core::future::pending::<()>().await;
            }
        };
        if let Either::First(()) = select(expires, PAIRING_TIMER_RESET.wait()).await {
            set_pairing_mode(false);
            BLE_LED_MODE.store(0, Ordering::Release);
            UI_REFRESH.signal(());
            apply_pairing_gate(stack);
        }
    }
}

/// A pending change to the pairing configuration, from a ULCP host or
/// from the menu on the front of the device.
///
/// Each of these has a durable half in the bond journal, which is
/// mounted for the life of the board, and a live half on the BLE stack,
/// which exists only while `PROP_BLE_ENABLED` is set. So they are served
/// in two places—by [`pairing_config_task`] while the stack is up, and
/// by [`serve_pairing_request_offline`] while the supervisor is parked—
/// and never by both at once.
enum PairingRequest {
    /// A `PROP_BLE_PAIRING_PIN` write; `None` clears the PIN.
    Pin(Option<u32>),
    /// A `PROP_BLE_PAIRING` write, or the menu's Start pairing.
    Window(bool),
    /// A `PROP_BLE_BOND_COUNT` write of zero, or the menu's Clear bonds.
    Wipe(bool),
}

/// Wait for the next pairing request. Cancel-safe: nothing is taken from
/// the channel or the signals until one is ready, so the supervisor can
/// race this against a lifecycle edge and lose no request. A request
/// that arrives while neither server is listening—the moments either
/// side of a controller bring-up—waits latched until one is.
async fn next_pairing_request() -> PairingRequest {
    match select3(
        PAIRING_CONFIG_CH.receive(),
        PAIRING_MODE_REQUEST.wait(),
        BLE_WIPE_REQUEST.wait(),
    )
    .await
    {
        Either3::First(pin) => PairingRequest::Pin(pin),
        Either3::Second(open) => PairingRequest::Window(open),
        Either3::Third(reply) => PairingRequest::Wipe(reply),
    }
}

/// The durable half of a `PROP_BLE_PAIRING_PIN` write: the journal, and
/// the mirror everything else reads. A stack, when one exists, takes the
/// PIN from here at every bring-up.
async fn persist_pairing_pin(store: &BleStoreMutex, pin: Option<u32>) -> bool {
    if store.lock().await.set_pin(pin).await.is_err() {
        return false;
    }
    PAIRING_PIN.store(pin.unwrap_or(u32::MAX), Ordering::Release);
    UI_REFRESH.signal(());
    true
}

/// The durable half of forgetting every host: empty the security journal
/// and reset every mirror that describes it, including pairing mode—a
/// device that has forgotten every host it trusts and is not accepting
/// new ones is reachable by nothing.
///
/// Emptying a live stack's in-memory bond table is the other half, and
/// only the caller that has a stack can do it. A wipe performed with the
/// controller down needs no such half: the next bring-up builds the
/// stack's table from this journal.
async fn wipe_ble_security(store: &BleStoreMutex, reply_over_ble: bool) -> bool {
    let irk = next_local_irk(store).await;
    if store.lock().await.forget_hosts(irk).await.is_err() {
        debug_log(format_args!("security wipe flash=FAILED"));
        UI_NOTICE.signal(UiNotice::ClearFailed);
        return false;
    }
    BLE_WIPE_WAITING_REPLY.store(reply_over_ble, Ordering::Release);
    if reply_over_ble {
        BLE_WIPE_REPLY_DEADLINE.signal(Instant::now() + Duration::from_secs(10));
    }
    BLE_REKEY_PENDING.store(true, Ordering::Release);
    BLE_CONTROLLER_STATE.invalidate_advertising();
    BLE_RESTART_PENDING.store(true, Ordering::Release);
    set_bond_count(0);
    PAIRING_PIN.store(u32::MAX, Ordering::Release);
    PAIRING_FAILURES.store(0, Ordering::Release);
    PAIRING_LOCKED_OUT.store(false, Ordering::Release);
    set_pairing_mode(true);
    debug_log(format_args!("security wipe journal=ok"));
    UI_NOTICE.signal(UiNotice::BondsCleared);
    true
}

/// Serve pairing requests against the live stack, for one
/// `PROP_BLE_ENABLED` cycle.
async fn pairing_config_task<C: Controller, P: PacketPool>(
    stack: &Stack<'_, C, P>,
    store: &BleStoreMutex,
) -> ! {
    loop {
        let request = next_pairing_request().await;
        let _busy = BleConfigGuard::new();
        match request {
            PairingRequest::Pin(pin) => {
                debug_log(format_args!(
                    "pin config begin configured={}",
                    pin.is_some()
                ));
                let persisted = persist_pairing_pin(store, pin).await;
                let applied = persisted && stack.set_fixed_passkey(pin).is_ok();
                if applied {
                    stack.set_io_capabilities(if pin.is_some() {
                        IoCapabilities::DisplayOnly
                    } else {
                        IoCapabilities::NoInputNoOutput
                    });
                    apply_pairing_gate(stack);
                }
                debug_log(format_args!(
                    "pin config requested={} persisted={} applied={}",
                    pin.is_some(),
                    persisted,
                    applied,
                ));
                PAIRING_CONFIG_ACK.signal(applied);
            }
            PairingRequest::Window(false) => {
                debug_log(format_args!("pairing window closed on request"));
                set_pairing_mode(false);
                BLE_LED_MODE.store(0, Ordering::Release);
                UI_REFRESH.signal(());
                apply_pairing_gate(stack);
                // Closing always lands: there is no state the device can
                // be in where a window refuses to shut.
                PAIRING_MODE_ACK.signal(true);
            }
            PairingRequest::Window(true) => {
                debug_log(format_args!("pairing mode requested"));
                let locked_out = PAIRING_LOCKED_OUT.load(Ordering::Acquire);
                // A window that cannot be walked through is not a window:
                // while locked out nothing is opened and the caller is
                // told so rather than left waiting out a timeout—and
                // `PROP_BLE_PAIRING` never reports a window nothing can
                // use. A full store is not that case—enrollment at
                // capacity evicts rather than refuses, so it warns the
                // operator without failing the request.
                if !locked_out {
                    set_pairing_mode(true);
                    BLE_LED_MODE.store(1, Ordering::Release);
                    PAIRING_TIMER_RESET.signal(());
                }
                let unavailable = locked_out
                    || usize::from(BLE_BOND_COUNT.load(Ordering::Acquire)) >= store::MAX_BONDS;
                UI_NOTICE.signal(if unavailable {
                    UiNotice::PairingUnavailable
                } else {
                    UiNotice::PairingStarted
                });
                apply_pairing_gate(stack);
                PAIRING_MODE_ACK.signal(!locked_out);
            }
            PairingRequest::Wipe(reply_over_ble) => {
                debug_log(format_args!("security wipe requested"));
                let wiped = wipe_ble_security(store, reply_over_ble).await;
                if wiped {
                    let mut identities: heapless09::Vec<Identity, { store::MAX_BONDS }> =
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
                    BLE_LED_MODE.store(1, Ordering::Release);
                    PAIRING_TIMER_RESET.signal(());
                    apply_pairing_gate(stack);
                    debug_log(format_args!("security wipe complete"));
                }
                BLE_WIPE_ACK.signal(wiped);
                if wiped {
                    ADV_POLICY_CHANGED.signal(());
                }
            }
        }
    }
}

/// Serve one pairing request with the controller down.
///
/// Called only from the supervisor's parked branch, where
/// [`pairing_config_task`] does not exist, so the two never race for the
/// same request. Clearing bonds and writing the PIN are journal work and
/// complete here exactly as they would with a stack up; only the window
/// needs a live transport, and there is none.
///
/// The window requests that reach this are the menu's—a
/// `PROP_BLE_PAIRING` write never gets here, because
/// [`set_pairing`] answers it without the stack when
/// Bluetooth is off. Serving them anyway is what keeps a press on a
/// parked device from latching an open-window request into the next
/// bring-up.
async fn serve_pairing_request_offline(request: PairingRequest, store: &BleStoreMutex) {
    match request {
        PairingRequest::Pin(pin) => {
            let persisted = persist_pairing_pin(store, pin).await;
            debug_log(format_args!(
                "pin config with ble down requested={} persisted={}",
                pin.is_some(),
                persisted,
            ));
            PAIRING_CONFIG_ACK.signal(persisted);
        }
        PairingRequest::Window(open) => {
            debug_log(format_args!(
                "pairing window {open} requested with ble down"
            ));
            if open {
                // Nothing advertises, so nothing can walk through a
                // window: the operator is told rather than left watching
                // for a host that cannot arrive.
                UI_NOTICE.signal(UiNotice::PairingUnavailable);
            } else {
                set_pairing_mode(false);
            }
            PAIRING_MODE_ACK.signal(!open);
        }
        PairingRequest::Wipe(reply_over_ble) => {
            debug_log(format_args!("security wipe requested with ble down"));
            BLE_WIPE_ACK.signal(wipe_ble_security(store, reply_over_ble).await);
        }
    }
}

/// Start advertising and return the accept handle. This future must
/// run to completion before racing any cancellation signal: dropping
/// `Peripheral::advertise` mid-configuration (before its internal
/// `LeSetAdvEnable(true)`) leaves trouble's `advertise_command_state`
/// in `Cancel` with nothing for the runner's disable arm to disable,
/// and every later `advertise()` then parks in `request()` forever—
/// observed as "configuring" with no "active" on the esp-radio
/// external controller. Cancellation belongs on the returned
/// [`Advertiser`] (dropping it is the designed clean-stop path).
async fn advertise<'values, C: Controller>(
    stack: &Stack<'_, C, DefaultPacketPool>,
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
) -> Result<(Advertiser<'values, C, DefaultPacketPool>, Option<u64>), BleHostError<C::Error>> {
    if !BLE_CONTROLLER_STATE.wait_for_privacy().await {
        return Err(trouble_host::Error::InvalidValue.into());
    }
    let name = device_name_snapshot().await;
    let data = ble_privacy::advertisement(
        gatt::SERVICE_UUID.to_le_bytes(),
        &name,
        BLE_MODEL_ID,
        pairing_window_open(),
        Instant::now().as_millis(),
    );
    // Trouble skips this HCI command for an empty slice. Explicitly clear
    // the old scan response before installing a nameless advertisement.
    stack
        .command(bt_hci::cmd::le::LeSetScanResponseData::new(0, [0; 31]))
        .await?;
    peripheral
        .advertise(
            &AdvertisementParameters {
                interval_min: Duration::from_micros(data.interval_us),
                interval_max: Duration::from_micros(data.interval_us),
                ..Default::default()
            },
            Advertisement::ConnectableScannableUndirected {
                adv_data: &data.advertising[..data.advertising_len],
                scan_data: &data.scan_response[..data.scan_response_len],
            },
        )
        .await
        .map(|advertiser| (advertiser, data.refresh_at_ms))
}

fn utf8_prefix_len(bytes: &[u8], maximum: usize) -> usize {
    ble_privacy::utf8_prefix_len(bytes, maximum)
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
    let segments = generation_checked(
        gatt::segments(&outbound.frame, segment_payload),
        outbound.generation,
        || SESSION_GEN.load(Ordering::Acquire),
    );
    let mut segments = segments.peekable();
    while let Some(segment) = segments.next() {
        let mut value: heapless09::Vec<u8, BLE_VALUE_MAX> = heapless09::Vec::new();
        value
            .push(segment.header())
            .map_err(|_| trouble_host::Error::InsufficientSpace)?;
        value
            .extend_from_slice(segment.payload())
            .map_err(|_| trouble_host::Error::InsufficientSpace)?;
        BLE_CONTROLLER_STATE.notification(
            server.ulcp.frame_out.handle,
            outbound.finish_ble_wipe && segments.peek().is_none(),
        );
        server.ulcp.frame_out.notify(conn, &value, false).await?;
    }
    if SESSION_GEN.load(Ordering::Acquire) != outbound.generation {
        debug_log(format_args!(
            "ble outbound segmentation stopped generation-changed"
        ));
    }
    if outbound.finish_ble_wipe {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !BLE_CONTROLLER_STATE.fence_done()
            && !BLE_CONTROLLER_STATE.link_failed()
            && Instant::now() < deadline
        {
            Timer::after_millis(10).await;
        }
        let sent = BLE_CONTROLLER_STATE.fence_done();
        debug_log(format_args!(
            "bond-clear final reply controller-completed={sent}"
        ));
        BLE_WIPE_WAITING_REPLY.store(false, Ordering::Release);
        conn.raw().disconnect();
        ADV_POLICY_CHANGED.signal(());
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
    set_ble_link(BleLinkState::Connected);
    let mut attached = false;
    let mut name_announced = false;
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
                    set_bond_count(persisted_bonds as u8);
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
                sync_gap_device_name(server, store).await;
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
                    let _busy = BleConfigGuard::new();
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
                if !name_announced {
                    name_announced = announce_gatt_change(server, conn, store).await;
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
                if BLE_REKEY_PENDING.load(Ordering::Acquire) {
                    event
                        .reject(AttErrorCode::INSUFFICIENT_AUTHORISATION)?
                        .send()
                        .await;
                    continue;
                }
                let accesses_name = server.gap.as_ref().is_some_and(|gap| {
                    ble_controller::accesses_device_name(
                        event.payload().incoming(),
                        gap.device_name.handle,
                    )
                });
                let encrypted = matches!(
                    conn.raw().security_level(),
                    Ok(SecurityLevel::Encrypted | SecurityLevel::EncryptedAuthenticated)
                );
                let retained = if accesses_name && encrypted && conn.raw().is_bonded_peer() {
                    let peer = conn.raw().peer_identity();
                    store.lock().await.snapshot().bonds.iter().any(|bond| {
                        trouble_bond(bond).is_some_and(|bond| bond.identity.match_identity(&peer))
                    })
                } else {
                    false
                };
                if accesses_name
                    && !ble_privacy::name_visible(pairing_window_open(), encrypted, retained)
                {
                    event
                        .reject(AttErrorCode::INSUFFICIENT_AUTHENTICATION)?
                        .send()
                        .await;
                    continue;
                }

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
                                set_bond_count(count as u8);
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
                // The indication path checks its own retained bond only when
                // a name refresh is still outstanding on this connection.
                if !name_announced && encrypted && conn.raw().is_bonded_peer() {
                    name_announced = announce_gatt_change(server, conn, store).await;
                }

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
                            INPUT_CH.send(InEvent::Attached(Transport::Ble)).await;
                            // Publish only after enqueueing, so teardown knows
                            // whether the protocol session needs a detach.
                            set_ble_link(BleLinkState::Attached);
                        }
                        (true, false) => {
                            debug_log(format_args!("cccd subscribed=false"));
                            attached = false;
                            reassembler.reset();
                            INPUT_CH.send(InEvent::Detached(Transport::Ble)).await;
                            set_ble_link(BleLinkState::Connected);
                        }
                        _ => {}
                    }
                }
            }
            Either3::First(GattConnectionEvent::RequestConnectionParams(request)) => {
                // trouble hands ownership of the request; dropping it
                // unanswered only logs—the central's parameter
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
                if attached
                    && (conn.raw().is_bonded_peer()
                        || (outbound.finish_ble_wipe
                            && BLE_WIPE_WAITING_REPLY.load(Ordering::Acquire)))
                {
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
                if !advertising_permitted()
                    || (BLE_REKEY_PENDING.load(Ordering::Acquire)
                        && !BLE_WIPE_WAITING_REPLY.load(Ordering::Acquire))
                {
                    debug_log(format_args!(
                        "disconnect initiated by transport arbitration"
                    ));
                    conn.raw().disconnect();
                    break;
                }
            }
            Either3::Third(LinkSignal::DeviceName) => {
                sync_gap_device_name(server, store).await;
                name_announced = false;
                if matches!(
                    conn.raw().security_level(),
                    Ok(SecurityLevel::Encrypted | SecurityLevel::EncryptedAuthenticated)
                ) && conn.raw().is_bonded_peer()
                {
                    name_announced = announce_gatt_change(server, conn, store).await;
                }
            }
        }
    }
    // Stack teardown owns the final detach, including cancellation paths.
    Ok(())
}

async fn ble_peripheral<C: Controller>(
    stack: &Stack<'_, C, DefaultPacketPool>,
    store: &BleStoreMutex,
    peripheral: &mut Peripheral<'_, C, DefaultPacketPool>,
    server: &UlcpServer<'_>,
) {
    // Withhold on-air discovery, not controller/stack initialization. Retain
    // readiness across every internal stack rebuild.
    BOOT_SETTINGS_READY
        .receiver()
        .expect("one BLE advertiser")
        .get()
        .await;
    loop {
        if BLE_RESTART_PENDING.load(Ordering::Acquire) || BLE_CONTROLLER_STATE.failed() {
            return;
        }
        if !advertising_permitted() {
            match select(ADV_POLICY_CHANGED.wait(), entropy::overdue()).await {
                Either::First(()) => continue,
                // As below: nobody is connected, so the stack can go.
                Either::Second(()) => return,
            }
        }
        sync_gap_device_name(server, store).await;
        let (advertiser, refresh_at_ms) = match advertise(stack, peripheral).await {
            Ok(result) => result,
            Err(error) => {
                debug_log(format_args!("advertising error={error:?}"));
                Timer::after_millis(500).await;
                continue;
            }
        };
        // Check again after the uncancellable configuration phase. A pairing
        // transition during HCI setup must not leave the old payload active.
        if BLE_RESTART_PENDING.load(Ordering::Acquire) || !advertising_permitted() {
            drop(advertiser);
            continue;
        }
        match select3(
            advertiser.accept(),
            async {
                // Reconfigure only after advertise() has completed. A
                // boot deadline crossed during HCI setup fires immediately.
                let wake = select3(
                    ADV_POLICY_CHANGED.wait(),
                    async {
                        if let Some(deadline) = refresh_at_ms {
                            Timer::at(Instant::from_millis(deadline)).await;
                        } else {
                            core::future::pending::<()>().await;
                        }
                    },
                    entropy::overdue(),
                )
                .await;
                matches!(wake, Either3::Third(()))
            },
            DEVICE_NAME_CHANGED.wait(),
        )
        .await
        {
            Either3::First(Ok(connection)) => {
                match connection.with_attribute_server(server) {
                    Ok(connection) => {
                        let result =
                            select(gatt_connection(stack, store, server, &connection), async {
                                let deadline = BLE_WIPE_REPLY_DEADLINE.wait().await;
                                Timer::at(deadline).await;
                            })
                            .await;
                        if !matches!(result, Either::First(Ok(()))) {
                            debug_log(format_args!(
                                "BLE session ended before final response completed"
                            ));
                            BLE_WIPE_WAITING_REPLY.store(false, Ordering::Release);
                            connection.raw().disconnect();
                        }
                    }
                    Err(error) => debug_log(format_args!("attribute server error={error:?}")),
                }
                // Each stack serves at most one connection. Its next lifetime
                // gets a fresh RPA and a clean transmit-completion ledger.
                return;
            }
            Either3::First(Err(error)) => debug_log(format_args!("advertising error={error:?}")),
            // A harvest needs the controller to itself, and nobody is
            // connected: end this stack and let the supervisor take one
            // on its way to the next.
            Either3::Second(true) => return,
            Either3::Second(false) | Either3::Third(()) => {}
        }
    }
}

/// Bring the RF subsystem up just long enough for one TRNG draw, then
/// tear it back down.
///
/// Used for bootstrapping and the supervisor's harvests.
/// An initialized sleeping controller does not guarantee live RF noise;
/// the RNG owns a controller with modem sleep off for the entire draw.
/// The caller must arbitrate ADC2 on the original ESP32 once tasks run.
fn try_harvest_trng_once(
    bt: &mut esp_hal::peripherals::BT<'static>,
) -> Result<[u8; 32], EntropyHarvestError> {
    let mut rng = EspCryptoRng::new(bt.reborrow())?;
    let mut out = [0u8; 32];
    rng.fill_bytes(&mut out);
    drop(rng);
    Ok(out)
}

/// Boot cannot proceed with an empty/uncommitted seed and no trusted entropy.
pub(crate) fn harvest_trng_once(bt: &mut esp_hal::peripherals::BT<'static>) -> [u8; 32] {
    try_harvest_trng_once(bt)
        .unwrap_or_else(|e| panic!("entropy harvest failed ({e})—no trusted entropy source"))
}

/// One harvest for the entropy service, with the controller down.
async fn harvest_entropy(bt: &mut esp_hal::peripherals::BT<'static>) {
    let fresh = {
        #[cfg(feature = "board-heltec-v2")]
        let _adc2_claim = super::ADC2_ARBITER.lock().await;
        // The temporary controller drops before the ADC2 guard and
        // before any await or operational BLE construction.
        try_harvest_trng_once(bt)
    };
    match fresh {
        Ok(fresh) => entropy::offer(fresh),
        Err(error) => {
            debug_log(format_args!(
                "ble entropy harvest FAILED error={error}; retrying later"
            ));
            entropy::harvest_failed();
        }
    }
}

/// BLE supervisor: rebuild for enablement, pairing boundaries and disconnects.
///
/// While BLE is enabled this owns the whole trouble stack. When the
/// property goes false, [`run_ble_stack`] unwinds the peripheral,
/// runner, stack, controller, and connector. The server and journal
/// survive across cycles. The connector's drop deinitializes the btdm
/// controller and releases its PHY and wake-source ownership. On S3,
/// the pinned driver wakes a sleeping controller before teardown. Upstream
/// sleep hooks coordinate light sleep between events while enabled; the
/// original ESP32 retains its controller-lifetime wake lock. Re-enabling
/// builds a fresh stack over the same static `HostResources`, which
/// `trouble_host::new` rewrites field-by-field on every call.
///
/// Between stacks the controller is free, and the supervisor uses the gap
/// to harvest live RF entropy for [`entropy`] whenever one is due. With
/// Bluetooth switched off it still does, through a controller that never
/// advertises. An idle advertiser gives up its stack for an overdue
/// harvest; a connected host is never interrupted for one.
pub(crate) async fn run(
    bt: esp_hal::peripherals::BT<'static>,
    privacy_seed: [u8; 32],
    store: Store,
) -> ! {
    // `HostResources` is tens of kilobytes, and this is awaited
    // directly from `main`—so a stack-built one lands as a temporary in
    // main's poll frame, which is already the largest frame in the image.
    // The same rule the `Mac` arena follows applies here: build it
    // through `StaticCell::init_with`, never on the stack.
    static BLE_RESOURCES: StaticCell<BleResources> = StaticCell::new();
    let resources = BLE_RESOURCES.init_with(HostResources::new);
    *BLE_PRIVACY_RNG.lock().await =
        Some(IdentityRng::new(privacy_seed, &entropy::BLE_PRIVACY_RESEED));
    initialize_pairing_deadline().await;
    BLE_LED_MODE.store(u8::from(pairing_window_open()), Ordering::Release);
    UI_REFRESH.signal(());
    // The service macro allocates the large ULCP characteristics in
    // one-shot StaticCells. Keep the attribute server for the supervisor's
    // lifetime; rebuilding it on Bluetooth re-enable panics. Connections
    // borrow it only during each controller cycle.
    let server = UlcpServer::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: default_device_name(),
        appearance: &appearance::computer::GENERIC_COMPUTER,
    }))
    .unwrap_or_else(|_| panic!("gatt server construction failed"));
    let store = BleStoreMutex::new(store);
    let mut bt = Some(bt);
    let mut recovery = ble_privacy::RestartBackoff::default();
    loop {
        let mut device = bt.take().unwrap_or_else(|| {
            // SAFETY: the peripheral singleton was consumed by a
            // previous cycle's connector, which `run_ble_stack`
            // dropped before returning; this supervisor is the only
            // place the radio is ever (re)constructed, so exactly one
            // owner exists at any time.
            unsafe { esp_hal::peripherals::BT::steal() }
        });
        if entropy::harvest_due() {
            harvest_entropy(&mut device).await;
        }
        if !BLE_ENABLED.load(Ordering::Acquire) {
            bt = Some(device);
            BLE_LED_MODE.store(0, Ordering::Release);
            UI_REFRESH.signal(());
            debug_log(format_args!("ble supervisor: controller down"));
            // Parked, but not deaf. Bond clearing and PIN writes are
            // journal work, and a host still reaches them over the mesh
            // admin binding or a wired link—a command that waited here
            // for a stack-scoped task to answer would never be answered
            // at all. Serving happens outside the `select` so an enable
            // edge cannot cancel a flash write halfway. An overdue
            // harvest is taken at the top of the next pass.
            match select3(
                BLE_LIFECYCLE.wait(),
                next_pairing_request(),
                entropy::overdue(),
            )
            .await
            {
                Either3::First(()) | Either3::Third(()) => {}
                Either3::Second(request) => serve_pairing_request_offline(request, &store).await,
            }
            continue;
        }
        let connector = {
            // V2: exclude a mid-flight battery sample while esp-radio
            // claims ADC2 (see [`super::ADC2_ARBITER`]).
            #[cfg(feature = "board-heltec-v2")]
            let _adc2_claim = super::ADC2_ARBITER.lock().await;
            #[cfg(feature = "board-heltec-v2")]
            super::ADC2_RADIO_UP.store(true, Ordering::Release);
            BleConnector::new(
                device,
                esp_radio::ble::Config::default().with_modem_sleep(cfg!(feature = "chip-esp32s3")),
            )
        };
        let connector = match connector {
            Ok(connector) => connector,
            Err(error) => {
                #[cfg(feature = "board-heltec-v2")]
                super::ADC2_RADIO_UP.store(false, Ordering::Release);
                debug_log(format_args!("ble init FAILED error={error:?}; retrying"));
                Timer::after_secs(5).await;
                continue;
            }
        };
        let controller: BleController =
            Guarded::new(ExternalController::new(connector), &BLE_CONTROLLER_STATE);
        if PAIRING_DEADLINE.lock(|d| d.borrow().expired(Instant::now().as_millis())) {
            set_pairing_mode(false);
        }
        BLE_CONTROLLER_STATE.reset();
        BLE_STACK_FAULT.reset();
        BLE_WIPE_REPLY_DEADLINE.reset();
        BLE_RESTART_PENDING.store(false, Ordering::Release);
        BLE_REKEY_PENDING.store(false, Ordering::Release);
        BLE_WIPE_WAITING_REPLY.store(false, Ordering::Release);
        let started = Instant::now();
        run_ble_stack(controller, resources, &store, &server).await;
        // Everything up to and including the connector has dropped by
        // here; the radio's ADC2 claim went with it.
        #[cfg(feature = "board-heltec-v2")]
        super::ADC2_RADIO_UP.store(false, Ordering::Release);
        debug_log(format_args!("ble supervisor: stack torn down"));
        if BLE_CONTROLLER_STATE.needs_recovery() {
            let delay = recovery.after_exit(started.elapsed().as_millis());
            debug_log(format_args!("BLE stack recovery in {delay} ms"));
            Timer::after_millis(delay).await;
        } else {
            recovery.reset();
        }
        if BLE_CONTROLLER_STATE.failed() {
            debug_log(format_args!(
                "BLE privacy failed; toggle Bluetooth to retry"
            ));
            let mut disabled = !BLE_ENABLED.load(Ordering::Acquire);
            loop {
                match select3(
                    BLE_LIFECYCLE.wait(),
                    next_pairing_request(),
                    entropy::overdue(),
                )
                .await
                {
                    Either3::First(()) => {}
                    Either3::Second(request) => {
                        serve_pairing_request_offline(request, &store).await
                    }
                    Either3::Third(()) => {
                        // SAFETY: as at the top of the supervisor loop—
                        // the failed stack's connector has dropped.
                        let mut device = unsafe { esp_hal::peripherals::BT::steal() };
                        harvest_entropy(&mut device).await;
                    }
                }
                if !BLE_ENABLED.load(Ordering::Acquire) {
                    disabled = true;
                } else if disabled {
                    break;
                }
            }
        }
    }
}

/// One enable-cycle of the trouble stack. Returns—unwinding every
/// borrow of `resources`—when `PROP_BLE_ENABLED` goes false.
async fn run_ble_stack(
    controller: BleController,
    resources: &mut BleResources,
    store: &BleStoreMutex,
    server: &UlcpServer<'_>,
) {
    let initial = store.lock().await.snapshot().clone();
    if initial.privacy_migration_pending {
        debug_log(format_args!("BLE blocked: privacy migration not committed"));
        BLE_CONTROLLER_STATE.fail();
        return;
    }
    let Some(irk) = initial
        .local_irk
        .and_then(IdentityResolvingKey::from_le_bytes)
    else {
        BLE_CONTROLLER_STATE.fail();
        return;
    };
    PAIRING_PIN.store(initial.pin.unwrap_or(u32::MAX), Ordering::Release);
    set_bond_count(initial.bonds.len() as u8);
    let stack = trouble_host::new(controller, resources)
        .set_random_address(ble_identity_address())
        .enable_privacy(irk)
        .set_rpa_timeout(Duration::from_secs(ble_privacy::RPA_TIMEOUT_SECS))
        .set_io_capabilities(if initial.pin.is_some() {
            IoCapabilities::DisplayOnly
        } else {
            IoCapabilities::NoInputNoOutput
        })
        .set_pairing_enabled(pairing_enabled(
            PAIRING_MODE.load(Ordering::Acquire),
            initial.pin.is_some(),
            PAIRING_LOCKED_OUT.load(Ordering::Acquire),
        ))
        .set_fixed_passkey(initial.pin)
        .expect("valid persisted PIN")
        .build();
    for bond in &initial.bonds {
        if let Some(bond) = trouble_bond(bond) {
            if stack.add_bond_information(bond).is_err() {
                BLE_CONTROLLER_STATE.fail();
            }
        }
    }
    let runner = stack.runner();
    let mut peripheral = stack.peripheral();
    select3(
        async {
            ble_peripheral(&stack, store, &mut peripheral, server).await;
            while BLE_CONFIG_BUSY.load(Ordering::Acquire) != 0 {
                Timer::after_millis(10).await;
            }
        },
        join(
            ble_runner(runner),
            join(pairing_timeout(&stack), pairing_config_task(&stack, store)),
        ),
        async {
            select(BLE_STACK_FAULT.wait(), async {
                loop {
                    BLE_LIFECYCLE.wait().await;
                    if !BLE_ENABLED.load(Ordering::Acquire) {
                        break;
                    }
                }
            })
            .await;
            while BLE_CONFIG_BUSY.load(Ordering::Acquire) != 0 {
                Timer::after_millis(10).await;
            }
        },
    )
    .await;
    // This is the sole final-detach owner for both normal completion
    // and cancellation by a runner exit or a lifecycle transition.
    if BLE_LINK.load(Ordering::Acquire) == BleLinkState::Attached.code() {
        INPUT_CH.send(InEvent::Detached(Transport::Ble)).await;
    }
    set_ble_link(BleLinkState::None);
}
