//! Station ownership and the private ULCP-to-network boundary.
use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_futures::select::{Either3, select, select3};
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    channel::Channel,
    signal::Signal,
};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_radio::wifi::{
    AuthenticationMethod as Auth, AuthenticationMethodConfig as AuthConfig, Config,
    ConnectionError, ControllerConfig, DisconnectReason, Interface, PowerSaveMode, WifiController,
    ap::AccessPointInfo, scan::ScanConfig, sta::StationConfig,
};
use umsh_ulcp::{
    Status,
    ids::prop,
    ip,
    wifi::{Link, LinkReason, LinkState, NetworkEntry, ScanResult, SecurityMode},
};
use umsh_ulcp_device::NETWORK_TABLE_MAX;
use umsh_ulcp_device::known_networks::KnownNetworks;
use umsh_ulcp_device::net::{NetworkName as StationName, StationIntent};
use umsh_ulcp_device::station::{Chooser, Mode, Next};
use umsh_ulcp_runtime::driver::{self, NetworkConfig, PublishEvent};
use umsh_ux_display_tracker::wifi::{NetworkName, WifiMenu, WifiState};

const _: () = assert!(
    umsh_ulcp_device::known_networks::MAX_NETWORKS
        <= umsh_ux_display_tracker::wifi::MAX_SAVED_NETWORKS
);

static UI: Mutex<CriticalSectionRawMutex, RefCell<WifiMenu>> = Mutex::new(RefCell::new(WifiMenu {
    enabled: false,
    state: WifiState::Off,
    network: None,
    networks: [None; 4],
}));

#[cfg(feature = "display")]
pub fn ui_snapshot() -> WifiMenu {
    UI.lock(|cell| *cell.borrow())
}

pub const CONFIG: umsh_ulcp_device::net::WifiConfig = umsh_ulcp_device::net::WifiConfig {
    supported_modes: SecurityMode::Open.bit()
        | SecurityMode::Wpa.bit()
        | SecurityMode::Wpa2.bit()
        | SecurityMode::Wpa3.bit(),
    max_sae_password: 63,
    raw_keys: false,
    binary_ssids: false,
    ..umsh_ulcp_device::net::WifiConfig::STATION
};

// No Debug implementation: this value contains a credential.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Settings {
    enabled: bool,
    networks: KnownNetworks,
    intent: StationIntent,
    pub v4: ip::V4Config,
    pub hostname: heapless::String<63>,
}

/// The settings, and a count of their changes, so the task can tell a
/// change without copying the credentials out to compare them.
static SETTINGS: Mutex<CriticalSectionRawMutex, RefCell<(u32, Option<Settings>)>> =
    Mutex::new(RefCell::new((0, None)));
static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static SCAN_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static SCAN: Mutex<CriticalSectionRawMutex, RefCell<(bool, u32)>> =
    Mutex::new(RefCell::new((false, 0)));
/// A join is in flight. A scan would cancel it, so a host's is refused.
static CONNECTING: AtomicBool = AtomicBool::new(false);
static EVENTS: Channel<CriticalSectionRawMutex, (Option<u32>, PublishEvent), 4> = Channel::new();
type Item = heapless::Vec<u8, { umsh_ulcp::wifi::SCAN_RESULT_MAX_LEN }>;
/// The retained scan table, bounded by bytes as well as count so a whole
/// read fits one frame on the device's own settings link.
static RESULTS: Mutex<CriticalSectionRawMutex, RefCell<heapless::Vec<Item, 10>>> =
    Mutex::new(RefCell::new(heapless::Vec::new()));
const RESULTS_MAX_BYTES: usize = driver::FRAME_IN_MAX - 16;
static ADDRESSES: Mutex<CriticalSectionRawMutex, RefCell<heapless::Vec<u8, 16>>> =
    Mutex::new(RefCell::new(heapless::Vec::new()));
static RESOLVERS: Mutex<CriticalSectionRawMutex, RefCell<heapless::Vec<u8, 64>>> =
    Mutex::new(RefCell::new(heapless::Vec::new()));

pub fn apply(config: NetworkConfig<'_>) {
    UI.lock(|cell| {
        let mut ui = cell.borrow_mut();
        ui.enabled = config.wifi_enabled;
        ui.networks = [None; 4];
        for (slot, entry) in ui.networks.iter_mut().zip(
            config
                .known_networks
                .entries()
                .filter_map(|raw| NetworkEntry::decode(raw).ok()),
        ) {
            *slot = NetworkName::new(entry.ssid);
        }
        if !ui.enabled {
            ui.state = WifiState::Off;
            ui.network = None;
        } else if ui.state == WifiState::Off {
            ui.state = WifiState::Disconnected;
        }
    });
    let mut hostname = heapless::String::new();
    for byte in config.device_name.iter().copied() {
        let c = if byte.is_ascii_alphanumeric() {
            byte.to_ascii_lowercase() as char
        } else {
            '-'
        };
        if c == '-' && (hostname.is_empty() || hostname.ends_with('-')) {
            continue;
        }
        if hostname.push(c).is_err() {
            break;
        }
    }
    while hostname.ends_with('-') {
        hostname.pop();
    }
    if hostname.is_empty() {
        hostname.push_str("umsh").unwrap();
    }
    let next = Settings {
        enabled: config.wifi_enabled,
        networks: config.known_networks.clone(),
        intent: config.intent,
        v4: config.v4,
        hostname,
    };
    let changed = SETTINGS.lock(|cell| {
        let mut state = cell.borrow_mut();
        if state.1.as_ref() == Some(&next) {
            false
        } else {
            state.0 = state.0.wrapping_add(1);
            state.1 = Some(next);
            true
        }
    });
    if changed {
        CHANGED.signal(());
    }
}

/// The settings, if they changed since `seen`, with their count.
fn settings_since(seen: Option<u32>) -> Option<(u32, Settings)> {
    SETTINGS.lock(|cell| {
        let state = cell.borrow();
        match (seen == Some(state.0), &state.1) {
            (false, Some(settings)) => Some((state.0, settings.clone())),
            _ => None,
        }
    })
}

fn settings_generation() -> u32 {
    SETTINGS.lock(|cell| cell.borrow().0)
}

/// The station's DHCP host name, which is also its mDNS one.
#[cfg(feature = "lan-bearer")]
pub(super) fn hostname() -> Option<heapless::String<63>> {
    SETTINGS.lock(|cell| cell.borrow().1.as_ref().map(|s| s.hostname.clone()))
}
fn scan_state() -> (bool, u32) {
    SCAN.lock(|cell| *cell.borrow())
}

/// A host's scan request. A scan already running, the device's own
/// included, is the one it gets.
pub fn scan(request: bool) -> Result<bool, Status> {
    SCAN.lock(|cell| {
        let mut state = cell.borrow_mut();
        if state.0 == request {
            return Ok(request);
        }
        if request && CONNECTING.load(Ordering::Relaxed) {
            return Err(Status::BUSY);
        }
        state.0 = request;
        state.1 = state.1.wrapping_add(1);
        if request {
            RESULTS.lock(|cell| cell.borrow_mut().clear());
        }
        SCAN_CHANGED.signal(());
        Ok(request)
    })
}

/// Start a scan of the device's own, reported as a host's is. `None`
/// when one is already running.
fn begin_scan() -> Option<u32> {
    SCAN.lock(|cell| {
        let mut state = cell.borrow_mut();
        if state.0 {
            return None;
        }
        state.0 = true;
        state.1 = state.1.wrapping_add(1);
        RESULTS.lock(|cell| cell.borrow_mut().clear());
        Some(state.1)
    })
}

pub async fn event() -> PublishEvent {
    loop {
        let (generation, event) = EVENTS.receive().await;
        if generation.is_none_or(|generation| generation == scan_state().1) {
            return event;
        }
    }
}

pub(super) async fn publish(event: PublishEvent) {
    EVENTS.send((None, event)).await;
}

/// Show the station on the device's own screen.
fn show(chooser: &Chooser, link: &Link) {
    let named = match chooser.mode() {
        Mode::Hold(ssid) => NetworkName::new(ssid),
        Mode::Choose => chooser
            .naming()
            .and_then(|name| NetworkName::new(name.as_bytes())),
        Mode::Paused => None,
    };
    let changed = UI.lock(|cell| {
        let mut ui = cell.borrow_mut();
        let before = *ui;
        ui.network = named.filter(|_| ui.enabled);
        ui.state = match (ui.enabled, link.state) {
            (false, _) => WifiState::Off,
            (true, LinkState::Up) => WifiState::Connected,
            (true, LinkState::Connecting)
                if ui.network.is_some()
                    && matches!(
                        link.reason,
                        LinkReason::NotFound
                            | LinkReason::Auth
                            | LinkReason::Rejected
                            | LinkReason::Other
                    ) =>
            {
                WifiState::Failing
            }
            (true, LinkState::Connecting) if ui.network.is_some() => WifiState::Connecting,
            (true, LinkState::Connecting) => WifiState::Searching,
            (true, LinkState::Down) => WifiState::Disconnected,
        };
        *ui != before
    });
    if changed {
        super::UI_REFRESH.signal(());
    }
}

pub fn read_table(key: u32, out: &mut [u8]) -> Result<usize, Status> {
    match key {
        prop::WIFI_SCAN_RESULTS => RESULTS.lock(|cell| {
            let mut len = 0;
            for item in cell.borrow().iter() {
                len += umsh_ulcp::items::encode_prefixed_item(
                    item,
                    out.get_mut(len..).ok_or(Status::NOMEM)?,
                )
                .map_err(|_| Status::NOMEM)?;
            }
            Ok(len)
        }),
        prop::IPV4_ADDRESS => ADDRESSES.lock(|cell| copy(&cell.borrow(), out)),
        prop::IP_RESOLVERS => RESOLVERS.lock(|cell| copy(&cell.borrow(), out)),
        _ => Err(Status::PROP_NOT_FOUND),
    }
}

fn copy(value: &[u8], out: &mut [u8]) -> Result<usize, Status> {
    out.get_mut(..value.len())
        .ok_or(Status::NOMEM)?
        .copy_from_slice(value);
    Ok(value.len())
}

pub(super) async fn table(key: u32, bytes: &[u8]) {
    let changed = match key {
        prop::IPV4_ADDRESS => ADDRESSES.lock(|cell| {
            let mut old = cell.borrow_mut();
            if old.as_slice() == bytes {
                false
            } else {
                *old = heapless::Vec::from_slice(bytes).unwrap();
                true
            }
        }),
        prop::IP_RESOLVERS => RESOLVERS.lock(|cell| {
            let mut old = cell.borrow_mut();
            if old.as_slice() == bytes {
                false
            } else {
                *old = heapless::Vec::from_slice(bytes).unwrap();
                true
            }
        }),
        _ => return,
    };
    if changed {
        publish(PublishEvent::NetworkTableChanged(
            key,
            heapless::Vec::<u8, NETWORK_TABLE_MAX>::from_slice(bytes).unwrap(),
        ))
        .await;
    }
}

fn modes(auth: Option<Auth>) -> u16 {
    match auth {
        Some(Auth::None) => SecurityMode::Open.bit(),
        Some(Auth::Wpa) => SecurityMode::Wpa.bit(),
        Some(Auth::Wpa2Personal) => SecurityMode::Wpa2.bit(),
        Some(Auth::WpaWpa2Personal) => SecurityMode::Wpa.bit() | SecurityMode::Wpa2.bit(),
        Some(Auth::Wpa3Personal) => SecurityMode::Wpa3.bit(),
        Some(Auth::Wpa2Wpa3Personal) => SecurityMode::Wpa2.bit() | SecurityMode::Wpa3.bit(),
        Some(Auth::Owe) => SecurityMode::Owe.bit(),
        _ => 0,
    }
}

fn station(entry: NetworkEntry<'_>) -> Option<StationConfig> {
    CONFIG.validate_network(&entry).ok()?;
    // The upstream driver enforces an authentication threshold and
    // chooses APs by signal strength. Association needs no application scan.
    let password = core::str::from_utf8(entry.credential)
        .ok()?
        .try_into()
        .ok()?;
    let authentication = match entry.security {
        // The public configuration currently omits WPA3. set_station_config
        // raises its raw threshold before any connection attempt can start.
        SecurityMode::Wpa3 | SecurityMode::Wpa2 => AuthConfig::Wpa2Personal(password),
        SecurityMode::Wpa => AuthConfig::Wpa(password),
        SecurityMode::Open => AuthConfig::Open,
        _ => return None,
    };
    Some(
        StationConfig::default()
            .with_ssid(entry.ssid.try_into().ok()?)
            .with_authentication(authentication)
            .with_scan_method(esp_radio::wifi::sta::ScanMethod::AllChannels),
    )
}

/// Preserve the WPA3 minimum absent from esp-radio's public authentication enum.
///
/// This task exclusively owns the station controller and calls this only before
/// connect_async, after any previous attempt has been disconnected. Never connect
/// if either raw call fails: checking negotiated security afterward alone would
/// allow a WPA3-only credential to participate in a WPA2 exchange.
fn set_station_config(
    controller: &mut WifiController<'_>,
    config: StationConfig,
    security: SecurityMode,
) -> Result<(), ()> {
    controller
        .set_config(&Config::Station(config))
        .map_err(|_| ())?;
    if security == SecurityMode::Wpa3 {
        use esp_wifi_sys_esp32s3::include::{
            ESP_OK, esp_wifi_get_config, esp_wifi_set_config, wifi_auth_mode_t_WIFI_AUTH_WPA3_PSK,
            wifi_config_t, wifi_interface_t_WIFI_IF_STA,
        };
        // SAFETY: the controller above has initialized STA. The bindings are
        // the same upstream blob ABI used by esp-radio. Read-modify-write keeps
        // every other field, including credentials, as configured by esp-radio.
        unsafe {
            let mut raw: wifi_config_t = core::mem::zeroed();
            if esp_wifi_get_config(wifi_interface_t_WIFI_IF_STA, &mut raw) != ESP_OK as i32 {
                return Err(());
            }
            raw.sta.threshold.authmode = wifi_auth_mode_t_WIFI_AUTH_WPA3_PSK;
            if esp_wifi_set_config(wifi_interface_t_WIFI_IF_STA, &mut raw) != ESP_OK as i32 {
                return Err(());
            }
        }
    }
    Ok(())
}

async fn report_ap(ap: &AccessPointInfo, generation: u32) {
    if scan_state() != (true, generation) {
        return;
    }
    // Upstream exposes only a UTF-8 prefix. Never publish that prefix as
    // a different SSID when bytes are missing.
    let ssid = ap.ssid.as_str();
    if ssid.len() != ap.ssid.len() || ssid.as_bytes().contains(&0) {
        return;
    }
    let result = ScanResult {
        ssid: ssid.as_bytes(),
        bssid: ap.bssid,
        rssi_dbm: ap.signal_strength,
        frequency_mhz: 2407 + u16::from(ap.channel) * 5,
        modes: modes(ap.auth_method),
    };
    let mut bytes = [0; umsh_ulcp::wifi::SCAN_RESULT_MAX_LEN];
    let Ok(len) = result.encode(&mut bytes) else {
        return;
    };
    let item = Item::from_slice(&bytes[..len]).unwrap();
    RESULTS.lock(|cell| {
        let mut results = cell.borrow_mut();
        if let Some(index) = results
            .iter()
            .position(|raw| ScanResult::decode(raw).unwrap().bssid == ap.bssid)
        {
            results.remove(index);
        }
        let bytes = |results: &heapless::Vec<Item, 10>| {
            results.iter().map(|raw| 1 + raw.len()).sum::<usize>()
        };
        // The weakest go first, the new one included.
        while results.is_full() || bytes(&results) + 1 + item.len() > RESULTS_MAX_BYTES {
            match results.last() {
                Some(raw) if ScanResult::decode(raw).unwrap().rssi_dbm < ap.signal_strength => {
                    results.pop();
                }
                _ => return,
            }
        }
        results.push(item.clone()).unwrap();
        results.sort_unstable_by_key(|raw| {
            core::cmp::Reverse(ScanResult::decode(raw).unwrap().rssi_dbm)
        });
    });
    EVENTS
        .send((Some(generation), PublishEvent::WifiScanResult(item)))
        .await;
}

/// The station wakes for every DTIM beacon, which lets the chip light-sleep
/// between them. Downlink traffic waits at the access point for up to one
/// DTIM period.
const POWER_SAVE: PowerSaveMode = PowerSaveMode::Minimum;

/// How stale the cached `PROP_WIFI_RSSI` may get while associated. Each
/// refresh is a CPU wake, so this stays well above the DTIM period.
const RSSI_REFRESH: Duration = Duration::from_secs(30);

fn controller_config() -> ControllerConfig {
    ControllerConfig::default()
        .with_country_info(*b"US")
        .with_rx_queue_size(4)
        .with_tx_queue_size(4)
        .with_static_rx_buf_num(4)
        .with_dynamic_rx_buf_num(8)
        .with_dynamic_tx_buf_num(8)
        .with_rx_ba_win(4)
        .with_initial_config(Config::Station(
            StationConfig::default().with_authentication(AuthConfig::Open),
        ))
}

/// Read the TRNG while a controller is alive.
///
/// The chip's TRNG is true-random only while RF is live. A started
/// station that is not associated may idle its RF, so the PHY is held on
/// for the read. Nothing awaits in here: the reader is gone before the
/// controller can be.
fn harvest(_alive: &WifiController<'_>) -> Option<[u8; 32]> {
    let _phy = esp_phy::enable_phy();
    let trng = esp_hal::rng::Trng::try_new().ok()?;
    let mut fresh = [0u8; 32];
    trng.read(&mut fresh);
    Some(fresh)
}

/// Bring a controller up just long enough for one TRNG draw.
#[cfg(not(feature = "ble"))]
fn harvest_once(peripheral: &mut esp_hal::peripherals::WIFI<'static>) -> Option<[u8; 32]> {
    let controller = WifiController::new(peripheral.reborrow(), controller_config()).ok()?;
    harvest(&controller)
}

/// Boot cannot proceed with an empty/uncommitted seed and no trusted entropy.
#[cfg(not(feature = "ble"))]
pub fn harvest_trng_once(peripheral: &mut esp_hal::peripherals::WIFI<'static>) -> [u8; 32] {
    harvest_once(peripheral)
        .unwrap_or_else(|| panic!("entropy harvest failed—no trusted entropy source"))
}

fn offer_harvest(fresh: Option<[u8; 32]>) {
    match fresh {
        Some(fresh) => super::entropy::offer(fresh),
        None => {
            super::debug_log(format_args!("wifi entropy harvest FAILED; retrying later"));
            super::entropy::harvest_failed();
        }
    }
}

/// Keep entropy arriving while the controller is down.
///
/// Where Bluetooth is compiled in, its supervisor does this and Wi-Fi
/// stays dark when switched off. Without it this radio is the only one
/// there is, and comes up for one read when a harvest is overdue.
async fn harvest_while_parked(peripheral: &mut esp_hal::peripherals::WIFI<'static>) {
    #[cfg(not(feature = "ble"))]
    loop {
        super::entropy::overdue().await;
        offer_harvest(harvest_once(peripheral));
    }
    #[cfg(feature = "ble")]
    let _ = peripheral;
    #[cfg(feature = "ble")]
    core::future::pending::<()>().await;
}

/// What a failed join says about the network.
fn failure(error: &ConnectionError) -> LinkReason {
    let ConnectionError::Failed(info) = error else {
        return LinkReason::Other;
    };
    match info.reason {
        DisconnectReason::NoAccessPointFound | DisconnectReason::BeaconTimeout => {
            LinkReason::NotFound
        }
        DisconnectReason::AuthenticationFailed
        | DisconnectReason::AuthenticationExpired
        | DisconnectReason::FourWayHandshakeTimeout
        | DisconnectReason::HandshakeTimeout
        | DisconnectReason::MicFailure => LinkReason::Auth,
        _ => LinkReason::Rejected,
    }
}

/// Every channel, then each hidden network in `probe` by name, feeding
/// what is heard to the results and the chooser. Stops early when the
/// scan is cancelled or the settings change; the upstream scan future
/// does not stop the radio when dropped, so each bounded channel scan is
/// finished before that is checked.
async fn run_scan(
    controller: &mut WifiController<'_>,
    generation: u32,
    settings: u32,
    probe: &[heapless::Vec<u8, 32>],
    chooser: &mut Chooser,
) {
    let live = || scan_state() == (true, generation) && settings_generation() == settings;
    chooser.scan_started();
    let names = core::iter::once(None).chain(probe.iter().map(Some));
    'scan: for name in names {
        for channel in 1..=11 {
            if !live() {
                break 'scan;
            }
            let mut config = ScanConfig::default()
                .with_channel(channel)
                .with_show_hidden(true)
                .with_max(32);
            if let Some(name) = name {
                config = config.with_ssid(name.as_slice().try_into().expect("validated SSID"));
            }
            let Ok(aps) = controller.scan_async(&config).await else {
                break 'scan;
            };
            if settings_generation() != settings {
                break 'scan;
            }
            for ap in &aps {
                chooser.heard(ap.ssid.as_str().as_bytes(), ap.signal_strength);
                report_ap(ap, generation).await;
            }
            // Leave the shared antenna to Bluetooth between channels.
            Timer::after_millis(20).await;
        }
    }
    chooser.scan_finished(Instant::now().as_millis());
    if scan_state() == (true, generation) {
        SCAN.lock(|cell| cell.borrow_mut().0 = false);
        EVENTS
            .send((Some(generation), PublishEvent::WifiScanning(false)))
            .await;
    }
}

/// Join `entry`, unless the settings change or a scan is asked for first.
/// `None` when cancelled.
async fn join(
    controller: &mut WifiController<'_>,
    entry: NetworkEntry<'_>,
) -> Option<Result<(), LinkReason>> {
    let Some(config) = station(entry) else {
        return Some(Err(LinkReason::Rejected));
    };
    if set_station_config(controller, config, entry.security).is_err() {
        return Some(Err(LinkReason::Rejected));
    }
    super::debug_log(format_args!(
        "wifi: connection attempt (minimum={:?})",
        entry.security
    ));
    CONNECTING.store(true, Ordering::Relaxed);
    let outcome = select3(
        with_timeout(Duration::from_secs(20), controller.connect_async()),
        CHANGED.wait(),
        SCAN_CHANGED.wait(),
    )
    .await;
    CONNECTING.store(false, Ordering::Relaxed);
    let result = match outcome {
        Either3::First(Ok(Ok(info))) => {
            let negotiated = match info.authmode {
                Auth::None => Some(SecurityMode::Open),
                Auth::Wpa => Some(SecurityMode::Wpa),
                Auth::Wpa2Personal => Some(SecurityMode::Wpa2),
                Auth::Wpa3Personal => Some(SecurityMode::Wpa3),
                _ => None,
            };
            if negotiated.is_some_and(|mode| entry.security.permits(mode, entry.raw_key)) {
                super::debug_log(format_args!("wifi: connected ({:?})", negotiated));
                return Some(Ok(()));
            }
            Err(LinkReason::Rejected)
        }
        Either3::First(Ok(Err(error))) => Err(failure(&error)),
        Either3::First(Err(_)) => Err(LinkReason::Other),
        _ => {
            let _ = controller.disconnect_async().await;
            return None;
        }
    };
    let _ = controller.disconnect_async().await;
    Some(result)
}

#[embassy_executor::task]
pub async fn task(
    mut peripheral: esp_hal::peripherals::WIFI<'static>,
    stack: embassy_net::Stack<'static>,
) {
    let mut network = super::ip::network();
    loop {
        let Some((mut seen, mut current)) = settings_since(None) else {
            select(CHANGED.wait(), harvest_while_parked(&mut peripheral)).await;
            continue;
        };
        if !current.enabled && !scan_state().0 {
            super::ip::update(stack, &current, false).await;
            select3(
                CHANGED.wait(),
                SCAN_CHANGED.wait(),
                harvest_while_parked(&mut peripheral),
            )
            .await;
            continue;
        }
        let mut controller = match WifiController::new(peripheral.reborrow(), controller_config()) {
            Ok(controller) => controller,
            Err(_) => {
                Timer::after_secs(5).await;
                continue;
            }
        };
        if controller.set_power_saving(POWER_SAVE).is_err() {
            super::debug_log(format_args!("wifi: power save {:?} refused", POWER_SAVE));
            drop(controller);
            Timer::after_secs(5).await;
            continue;
        }
        // Remembers the last network joined only while the controller is
        // up; after that the strongest wins, as after a restart.
        let mut chooser = Chooser::default();
        let mut link: Option<(Link, u32)> = None;
        let mut named: Option<(StationName, u32)> = None;
        loop {
            #[cfg(feature = "debug-log")]
            super::memory_probe::sample();
            // The controller is up anyway, so a harvest costs nothing.
            if super::entropy::harvest_due() {
                offer_harvest(harvest(&controller));
            }
            // Signals describe changes since this snapshot. Discard an
            // already-observed wake before starting cancelable work.
            CHANGED.reset();
            SCAN_CHANGED.reset();
            if let Some((generation, next)) = settings_since(Some(seen)) {
                seen = generation;
                current = next;
            }
            let now = Instant::now().as_millis();
            if chooser.configure(current.enabled, current.intent, &current.networks, now) {
                let _ = controller.disconnect_async().await;
            }
            if !current.enabled && !scan_state().0 {
                break;
            }
            let connected = controller.is_connected();
            if !connected && chooser.associated().is_some() {
                chooser.lost();
            }
            let epoch = chooser.epoch();
            if let Some(naming) = chooser.naming() {
                if named != Some((naming, epoch)) {
                    named = Some((naming, epoch));
                    publish(PublishEvent::WifiNetwork {
                        ssid: naming,
                        hold_ended: false,
                        epoch,
                    })
                    .await;
                }
            }
            let association = connected
                .then(|| controller.ap_info().ok())
                .flatten()
                .map(|ap| umsh_ulcp::wifi::Association {
                    bssid: ap.bssid,
                    frequency_mhz: 2407 + u16::from(ap.channel) * 5,
                });
            let next_link = match association {
                Some(association) => Link {
                    state: LinkState::Up,
                    reason: LinkReason::None,
                    association: Some(association),
                },
                None => chooser.link_down(),
            };
            show(&chooser, &next_link);
            if link != Some((next_link, epoch)) {
                link = Some((next_link, epoch));
                publish(PublishEvent::WifiLink(next_link, epoch)).await;
            }
            // The update reads the stack itself, so only later changes count.
            network.try_changed();
            super::ip::update(stack, &current, connected).await;
            let hidden = || {
                current
                    .networks
                    .entries()
                    .filter_map(|raw| NetworkEntry::decode(raw).ok())
                    .filter(|entry| entry.hidden)
                    .map(|entry| heapless::Vec::<u8, 32>::from_slice(entry.ssid).unwrap())
                    .collect::<heapless::Vec<_, 4>>()
            };
            let (scanning, generation) = scan_state();
            if scanning {
                run_scan(&mut controller, generation, seen, &hidden(), &mut chooser).await;
                continue;
            }
            if connected {
                publish(PublishEvent::WifiRssi(
                    controller.rssi().ok().map(|r| r.clamp(-127, 0) as i8),
                ))
                .await;
                // A lease or a lost link reaches the IP tables through
                // `network`. The refresh timer also covers a disconnect
                // that lands between `is_connected` and the event
                // subscription.
                select3(
                    CHANGED.wait(),
                    SCAN_CHANGED.wait(),
                    select3(
                        controller.wait_for_disconnect_async(),
                        network.changed(),
                        Timer::after(RSSI_REFRESH),
                    ),
                )
                .await;
                continue;
            }
            match chooser.step(now) {
                Next::Join(name) => {
                    let Some(entry) = current.networks.get(name.as_bytes()) else {
                        continue;
                    };
                    match join(&mut controller, entry).await {
                        None => {}
                        Some(Ok(())) => chooser.joined(name.as_bytes()),
                        Some(Err(reason)) => {
                            super::debug_log(format_args!("wifi: join failed ({:?})", reason));
                            let now = Instant::now().as_millis();
                            if chooser.failed(name.as_bytes(), reason, now) {
                                publish(PublishEvent::WifiNetwork {
                                    ssid: StationName::default(),
                                    hold_ended: true,
                                    epoch,
                                })
                                .await;
                            }
                        }
                    }
                }
                Next::Scan { probe_hidden } => {
                    if let Some(generation) = begin_scan() {
                        EVENTS
                            .send((Some(generation), PublishEvent::WifiScanning(true)))
                            .await;
                        let probe = if probe_hidden {
                            hidden()
                        } else {
                            heapless::Vec::new()
                        };
                        run_scan(&mut controller, generation, seen, &probe, &mut chooser).await;
                    }
                }
                Next::Wait(until) => {
                    let until = async {
                        match until {
                            Some(at) => Timer::at(Instant::from_millis(at)).await,
                            None => core::future::pending().await,
                        }
                    };
                    select3(CHANGED.wait(), SCAN_CHANGED.wait(), until).await;
                }
            }
        }
        drop(controller);
        publish(PublishEvent::WifiLink(
            Default::default(),
            current.intent.epoch,
        ))
        .await;
        UI.lock(|cell| {
            let mut ui = cell.borrow_mut();
            ui.network = None;
            ui.state = WifiState::Off;
        });
        super::ip::update(stack, &current, false).await;
    }
}

pub fn interface() -> Interface {
    Interface::station()
}
