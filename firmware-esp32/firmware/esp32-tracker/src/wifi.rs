//! Station ownership and the private ULCP-to-network boundary.
use alloc::string::String;
use core::cell::RefCell;
use embassy_futures::select::{Either3, select, select3};
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    channel::Channel,
    signal::Signal,
};
use embassy_time::{Duration, Timer, with_timeout};
use esp_radio::wifi::{
    AuthenticationMethod as Auth, Config, ControllerConfig, Interface, WifiController,
    ap::AccessPointInfo, scan::ScanConfig, sta::StationConfig,
};
use umsh_ulcp::{
    Status,
    ids::prop,
    ip,
    wifi::{Link, LinkReason, LinkState, NetworkEntry, ScanResult, SecurityMode},
};
use umsh_ulcp_device::NETWORK_TABLE_MAX;
use umsh_ulcp_runtime::driver::{NetworkConfig, PublishEvent};

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
    entry: heapless::Vec<u8, { umsh_ulcp::wifi::NETWORK_ENTRY_MAX_LEN }>,
    hidden: heapless::Vec<heapless::Vec<u8, 32>, 4>,
    pub v4: ip::V4Config,
    pub hostname: heapless::String<63>,
}

static SETTINGS: Mutex<CriticalSectionRawMutex, RefCell<Option<Settings>>> =
    Mutex::new(RefCell::new(None));
static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static SCAN_CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static SCAN: Mutex<CriticalSectionRawMutex, RefCell<(bool, u32)>> =
    Mutex::new(RefCell::new((false, 0)));
static EVENTS: Channel<CriticalSectionRawMutex, (Option<u32>, PublishEvent), 4> = Channel::new();
type Item = heapless::Vec<u8, { umsh_ulcp::wifi::SCAN_RESULT_MAX_LEN }>;
static RESULTS: Mutex<CriticalSectionRawMutex, RefCell<heapless::Vec<Item, 10>>> =
    Mutex::new(RefCell::new(heapless::Vec::new()));
static ADDRESSES: Mutex<CriticalSectionRawMutex, RefCell<heapless::Vec<u8, 16>>> =
    Mutex::new(RefCell::new(heapless::Vec::new()));
static RESOLVERS: Mutex<CriticalSectionRawMutex, RefCell<heapless::Vec<u8, 64>>> =
    Mutex::new(RefCell::new(heapless::Vec::new()));

pub fn apply(config: NetworkConfig<'_>) {
    let mut entry = heapless::Vec::new();
    if let Some(selected) = config.known_networks.get(config.network) {
        let mut bytes = [0; umsh_ulcp::wifi::NETWORK_ENTRY_MAX_LEN];
        if let Ok(len) = selected.encode(&mut bytes) {
            entry.extend_from_slice(&bytes[..len]).unwrap();
        }
    }
    let hidden = config
        .known_networks
        .entries()
        .filter_map(|raw| {
            let entry = NetworkEntry::decode(raw).ok()?;
            entry
                .hidden
                .then(|| heapless::Vec::from_slice(entry.ssid).unwrap())
        })
        .collect();
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
        entry,
        hidden,
        v4: config.v4,
        hostname,
    };
    let changed = SETTINGS.lock(|cell| {
        let mut state = cell.borrow_mut();
        if state.as_ref() == Some(&next) {
            false
        } else {
            *state = Some(next);
            true
        }
    });
    if changed {
        CHANGED.signal(());
    }
}

fn settings() -> Option<Settings> {
    SETTINGS.lock(|cell| cell.borrow().clone())
}
fn scan_state() -> (bool, u32) {
    SCAN.lock(|cell| *cell.borrow())
}

pub fn scan(request: bool) -> bool {
    SCAN.lock(|cell| {
        let mut state = cell.borrow_mut();
        if state.0 != request {
            state.0 = request;
            state.1 = state.1.wrapping_add(1);
            if request {
                RESULTS.lock(|cell| cell.borrow_mut().clear());
            }
            SCAN_CHANGED.signal(());
        }
    });
    request
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
    let password = String::from(core::str::from_utf8(entry.credential).ok()?);
    Some(
        StationConfig::default()
            .with_ssid(entry.ssid)
            .with_password(password)
            .with_scan_method(esp_radio::wifi::sta::ScanMethod::AllChannels)
            .with_auth_method(match entry.security {
                SecurityMode::Wpa3 => Auth::Wpa3Personal,
                SecurityMode::Wpa2 => Auth::Wpa2Personal,
                SecurityMode::Wpa => Auth::Wpa,
                _ => Auth::None,
            }),
    )
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
        if results.is_full() {
            if ScanResult::decode(results.last().unwrap())
                .unwrap()
                .rssi_dbm
                >= ap.signal_strength
            {
                return;
            }
            results.pop();
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

#[embassy_executor::task]
pub async fn task(
    mut peripheral: esp_hal::peripherals::WIFI<'static>,
    stack: embassy_net::Stack<'static>,
) {
    let mut link = Link::default();
    loop {
        let Some(mut current) = settings() else {
            CHANGED.wait().await;
            continue;
        };
        if !current.enabled && !scan_state().0 {
            super::ip::update(stack, &current, false).await;
            select(CHANGED.wait(), SCAN_CHANGED.wait()).await;
            continue;
        }
        let config = ControllerConfig::default()
            .with_country_info(*b"US")
            .with_rx_queue_size(4)
            .with_tx_queue_size(4)
            .with_static_rx_buf_num(4)
            .with_dynamic_rx_buf_num(8)
            .with_dynamic_tx_buf_num(8)
            .with_rx_ba_win(4)
            .with_initial_config(Config::Station(
                StationConfig::default().with_auth_method(Auth::None),
            ));
        let mut controller = match WifiController::new(peripheral.reborrow(), config) {
            Ok(controller) => controller,
            Err(_) => {
                Timer::after_secs(5).await;
                continue;
            }
        };
        let mut active: Option<heapless::Vec<u8, { umsh_ulcp::wifi::NETWORK_ENTRY_MAX_LEN }>> =
            None;
        let mut backoff = 1;
        loop {
            #[cfg(feature = "ble-debug")]
            super::wifi_memory::sample();
            // Signals describe changes since this snapshot. Discard an
            // already-observed wake before starting cancelable work.
            CHANGED.reset();
            SCAN_CHANGED.reset();
            if let Some(next) = settings() {
                if current.entry != next.entry || current.enabled != next.enabled {
                    backoff = 1;
                    link.reason = LinkReason::None;
                }
                current = next;
            }
            if !current.enabled && !scan_state().0 {
                break;
            }
            if active
                .as_ref()
                .is_some_and(|entry| !current.enabled || *entry != current.entry)
            {
                let _ = controller.disconnect_async().await;
                active = None;
                backoff = 1;
            }
            let connected = controller.is_connected();
            let state = if connected {
                LinkState::Up
            } else if current.enabled && !current.entry.is_empty() {
                LinkState::Connecting
            } else {
                LinkState::Down
            };
            let association = if connected {
                controller
                    .ap_info()
                    .ok()
                    .map(|ap| umsh_ulcp::wifi::Association {
                        bssid: ap.bssid,
                        frequency_mhz: 2407 + u16::from(ap.channel) * 5,
                    })
            } else {
                None
            };
            let next_link = Link {
                state,
                reason: if state == LinkState::Connecting {
                    if link.state == LinkState::Up {
                        LinkReason::Lost
                    } else {
                        link.reason
                    }
                } else {
                    LinkReason::None
                },
                association,
            };
            if next_link != link {
                link = next_link;
                publish(PublishEvent::WifiLink(link)).await;
            }
            super::ip::update(stack, &current, connected).await;
            let (scanning, generation) = scan_state();
            if scanning {
                // The upstream scan future does not stop the radio when
                // dropped. Finish each bounded channel scan, then observe
                // cancellation before publishing or starting another one.
                for channel in 1..=11 {
                    let config = ScanConfig::default()
                        .with_channel(channel)
                        .with_show_hidden(true)
                        .with_max(32);
                    match controller.scan_async(&config).await {
                        Ok(aps) => {
                            if settings().as_ref() != Some(&current) {
                                break;
                            }
                            for ap in &aps {
                                report_ap(ap, generation).await;
                            }
                        }
                        _ => {
                            break;
                        }
                    }
                    if scan_state() != (true, generation) || settings().as_ref() != Some(&current) {
                        break;
                    }
                }
                for ssid in &current.hidden {
                    if scan_state() != (true, generation) || settings().as_ref() != Some(&current) {
                        break;
                    }
                    for channel in 1..=11 {
                        if scan_state() != (true, generation)
                            || settings().as_ref() != Some(&current)
                        {
                            break;
                        }
                        let config = ScanConfig::default()
                            .with_ssid(ssid.as_slice())
                            .with_channel(channel)
                            .with_show_hidden(true)
                            .with_max(32);
                        match controller.scan_async(&config).await {
                            Ok(aps) => {
                                if settings().as_ref() != Some(&current) {
                                    break;
                                }
                                for ap in &aps {
                                    report_ap(ap, generation).await;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                if scan_state() == (true, generation) {
                    SCAN.lock(|cell| cell.borrow_mut().0 = false);
                    EVENTS
                        .send((Some(generation), PublishEvent::WifiScanning(false)))
                        .await;
                }
                continue;
            }
            if connected {
                publish(PublishEvent::WifiRssi(
                    controller.rssi().ok().map(|r| r.clamp(-127, 0) as i8),
                ))
                .await;
                match select3(CHANGED.wait(), SCAN_CHANGED.wait(), Timer::after_secs(1)).await {
                    _ => {}
                }
                continue;
            }
            if current.enabled && !current.entry.is_empty() {
                let entry = NetworkEntry::decode(&current.entry).unwrap();
                if let Some(config) = station(entry) {
                    if controller.set_config(&Config::Station(config)).is_ok() {
                        active = Some(current.entry.clone());
                        super::debug_log(format_args!(
                            "wifi: connection attempt (minimum={:?})",
                            entry.security
                        ));
                        match select3(
                            with_timeout(Duration::from_secs(20), controller.connect_async()),
                            CHANGED.wait(),
                            SCAN_CHANGED.wait(),
                        )
                        .await
                        {
                            Either3::First(Ok(Ok(info))) => {
                                let negotiated = match info.authmode {
                                    Auth::None => Some(SecurityMode::Open),
                                    Auth::Wpa => Some(SecurityMode::Wpa),
                                    Auth::Wpa2Personal => Some(SecurityMode::Wpa2),
                                    Auth::Wpa3Personal => Some(SecurityMode::Wpa3),
                                    _ => None,
                                };
                                if negotiated
                                    .is_some_and(|mode| entry.security.permits(mode, entry.raw_key))
                                {
                                    super::debug_log(format_args!(
                                        "wifi: connected ({:?})",
                                        negotiated
                                    ));
                                    backoff = 1;
                                    continue;
                                }
                                let _ = controller.disconnect_async().await;
                                link.reason = LinkReason::Rejected;
                            }
                            Either3::First(_) => {
                                let _ = controller.disconnect_async().await;
                                link.reason = LinkReason::Auth;
                            }
                            _ => {
                                let _ = controller.disconnect_async().await;
                                continue;
                            }
                        }
                    }
                } else {
                    link.reason = LinkReason::Rejected;
                }
                publish(PublishEvent::WifiLink(link)).await;
            }
            if !current.entry.is_empty() {
                super::debug_log(format_args!(
                    "wifi: retry in {} s ({:?})",
                    backoff, link.reason
                ));
            }
            select3(
                CHANGED.wait(),
                SCAN_CHANGED.wait(),
                Timer::after(Duration::from_secs(backoff)),
            )
            .await;
            backoff = (backoff * 2).min(60);
        }
        drop(controller);
        link = Link::default();
        publish(PublishEvent::WifiLink(Default::default())).await;
        super::ip::update(stack, &current, false).await;
    }
}

pub fn interface() -> Interface {
    Interface::station()
}
