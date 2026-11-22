//! The managed-device engine's tests: against a scripted device
//! (`script`), and against the soft device behind a real radio driver.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use umsh_ulcp::ids::{cap, prop};
use umsh_ulcp::pui;

use super::MobileManagedDevice;
use super::records::{MobileManagedDeviceRecord, MobileManagementLink};
use crate::app_core::test_support::{Core, identity};
use crate::store::MobilePeerUpsertRecord;
use crate::ulcp::{
    UlcpDevicePropertiesRecord, UlcpManageCategory, UlcpTimeRecord, ulcp_dirty_writes,
};

mod administrative;
mod companion;
mod drafts;
mod engine;
mod keys;
mod pushes;
pub(in crate::app_core::manage) mod script;
mod setup;
mod setup_apply;
mod units;
mod wifi;

use script::ScriptedCarrier;

/// The phone's identity seed, and the managed device's.
const OWNER_SEED: u8 = 3;
const DEVICE_SEED: u8 = 0x22;

fn address_of(seed: u8) -> String {
    identity(seed).public_identity().canonical_address
}

/// `PROP_CAPS` holding `capabilities`.
fn capabilities(capabilities: &[u32]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for capability in capabilities {
        let mut bytes = [0; pui::MAX_LEN];
        let length = pui::encode(*capability, &mut bytes).unwrap();
        encoded.extend_from_slice(&bytes[..length]);
    }
    encoded
}

/// `property`'s octets for the value `record` holds, as a write encodes
/// them.
fn encoded(property: u32, record: &UlcpDevicePropertiesRecord) -> Vec<u8> {
    ulcp_dirty_writes(record.clone(), vec![property])
        .unwrap()
        .into_iter()
        .find(|write| write.property_id == property)
        .unwrap()
        .value
}

fn name(name: &str) -> Vec<u8> {
    encoded(
        prop::DEV_NAME,
        &UlcpDevicePropertiesRecord {
            device_name: Some(name.to_owned()),
            ..UlcpDevicePropertiesRecord::default()
        },
    )
}

fn time(epoch_seconds: u32) -> Vec<u8> {
    encoded(
        prop::TIME,
        &UlcpDevicePropertiesRecord {
            time: Some(UlcpTimeRecord {
                epoch_seconds: Some(epoch_seconds),
            }),
            ..UlcpDevicePropertiesRecord::default()
        },
    )
}

/// A device with a name, an identity, a clock, counters and temperature
/// sensors, answering several properties at a time.
fn device_values(version: &str) -> BTreeMap<u32, Vec<u8>> {
    let zero = encoded(
        prop::STAT_TX_PACKETS,
        &UlcpDevicePropertiesRecord::default(),
    );
    BTreeMap::from([
        (
            prop::CAPS,
            capabilities(&[
                cap::DEV_NAME,
                cap::IDENT,
                cap::ALERT,
                cap::TIME,
                cap::STATS,
                cap::REBOOT,
                cap::SAVE,
                cap::CMD_MULTI,
                cap::TEMPERATURE,
            ]),
        ),
        (prop::DEV_VERSION, version.as_bytes().to_vec()),
        (prop::DEV_MODEL, b"Soft".to_vec()),
        (prop::DEV_NAME, name("Tallac Ridge")),
        (prop::TIME, time(1_790_000_000)),
        (prop::UPTIME, zero.clone()),
        (prop::STAT_TX_PACKETS, zero.clone()),
        (prop::STAT_RX_PACKETS, zero),
        // Two sensors, one unavailable, with their names.
        (prop::TEMPERATURES, vec![0xa5, 0x0b, 0xff, 0xff]),
        (prop::TEMPERATURE_NAMES, b"\x03Die\x03Air".to_vec()),
    ])
}

/// A peer or administrator key.
fn key(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

/// One `PROP_WIFI_NETWORKS` entry in the reported form.
fn network(ssid: &[u8], security: u8, auto_join: bool) -> Vec<u8> {
    let flags = if auto_join {
        0
    } else {
        umsh_ulcp::wifi::FLAG_MANUAL
    };
    let mut entry = vec![flags, security, u8::try_from(ssid.len()).unwrap()];
    entry.extend_from_slice(ssid);
    entry
}

/// One scan result item.
fn heard(ssid: &[u8], bssid: u8, rssi_dbm: i8, modes: u16) -> Vec<u8> {
    let mut item = [0u8; umsh_ulcp::wifi::SCAN_RESULT_MAX_LEN];
    let length = umsh_ulcp::wifi::ScanResult {
        modes,
        frequency_mhz: 2437,
        rssi_dbm,
        bssid: [bssid; 6],
        ssid,
    }
    .encode(&mut item)
    .unwrap();
    item[..length].to_vec()
}

/// Items end to end, each with its length before it.
fn items(items: &[Vec<u8>]) -> Vec<u8> {
    let mut table = Vec::new();
    for item in items {
        let mut prefixed = vec![0; item.len() + 4];
        let length = umsh_ulcp::items::encode_prefixed_item(item, &mut prefixed).unwrap();
        table.extend_from_slice(&prefixed[..length]);
    }
    table
}

/// `device_values` with a Wi-Fi station, Bluetooth pairing and key
/// tables: this phone and one other administer it, one peer.
fn station_values() -> BTreeMap<u32, Vec<u8>> {
    let mut values = device_values("1.0");
    values.insert(
        prop::CAPS,
        capabilities(&[
            cap::DEV_NAME,
            cap::IDENT,
            cap::TIME,
            cap::SAVE,
            cap::CMD_MULTI,
            cap::DEV_IDENTITY,
            cap::ADMIN,
            cap::BLE,
            cap::WIFI_SCAN,
            cap::WIFI,
        ]),
    );
    values.extend([
        (
            prop::DEV_ADMINS,
            [script::PHONE_NODE_KEY.to_vec(), key(0xa1)].concat(),
        ),
        (prop::DEV_PEERS, key(0xb1)),
        (prop::BLE_ENABLED, vec![1]),
        (prop::BLE_BOND_COUNT, vec![2]),
        (prop::BLE_LINK, vec![0]),
        (prop::BLE_PAIRING, vec![0]),
        (prop::WIFI_SCANNING, vec![0]),
        (prop::WIFI_SCAN_RESULTS, Vec::new()),
        (prop::WIFI_ENABLED, vec![0]),
        (
            prop::WIFI_NETWORKS,
            items(&[network(b"Field Office", 2, true)]),
        ),
        (prop::WIFI_NETWORK, Vec::new()),
    ]);
    values
}

/// A core whose owner keeps a peer row for the scripted device, so its
/// cache is kept.
struct Bench {
    core: Core,
    owner: String,
    address: String,
    script: Arc<ScriptedCarrier>,
    device: Arc<MobileManagedDevice>,
}

impl Bench {
    async fn new(link: MobileManagementLink) -> Self {
        Self::with(link, true).await
    }

    /// `cached`, the device's cache is kept under its address.
    async fn with(link: MobileManagementLink, cached: bool) -> Self {
        let address = address_of(DEVICE_SEED);
        let script = ScriptedCarrier::new(cached.then(|| address.clone()), device_values("1.0"));
        Self::scripted(link, script).await
    }

    /// A device with a station, Bluetooth and key tables, its cache kept.
    async fn station(link: MobileManagementLink) -> Self {
        Self::station_with(link, Some(script::PHONE_NODE_KEY.to_vec()), false).await
    }

    async fn station_with(
        link: MobileManagementLink,
        phone_node_key: Option<Vec<u8>>,
        saves_table_edits: bool,
    ) -> Self {
        let script = ScriptedCarrier::configured(
            Some(address_of(DEVICE_SEED)),
            station_values(),
            phone_node_key,
            saves_table_edits,
        );
        Self::scripted(link, script).await
    }

    async fn scripted(link: MobileManagementLink, script: Arc<ScriptedCarrier>) -> Self {
        let core = Core::new();
        let owner = address_of(OWNER_SEED);
        let address = address_of(DEVICE_SEED);
        core.store
            .insert_identity(owner.clone(), owner.clone(), 1)
            .unwrap();
        core.store
            .upsert_peer(
                owner.clone(),
                address.clone(),
                MobilePeerUpsertRecord {
                    is_saved: true,
                    ..MobilePeerUpsertRecord::default()
                },
            )
            .unwrap();
        core.core.set_owner(Some(owner.clone())).unwrap();
        let device = core
            .core
            .manage_scripted(script.clone(), link)
            .await
            .unwrap();
        Self {
            core,
            owner,
            address,
            script,
            device,
        }
    }

    /// Another handle on the bench's device, or on a new one when the
    /// bench's has gone.
    async fn handle(&self, link: MobileManagementLink) -> Arc<MobileManagedDevice> {
        self.core
            .core
            .manage_scripted(self.script.clone(), link)
            .await
            .unwrap()
    }

    fn snapshot(&self) -> MobileManagedDeviceRecord {
        self.device.snapshot()
    }

    /// How many devices the worker manages.
    async fn registered(&self) -> usize {
        self.core
            .core
            .on_worker(|worker| async move { Ok(worker.managed.borrow().len()) })
            .await
            .unwrap()
    }

    /// Wait, in real time, until `done` holds of the device's snapshot.
    async fn until(&self, what: &str, done: impl Fn(&MobileManagedDeviceRecord) -> bool) {
        until(what, || done(&self.snapshot())).await;
    }

    /// Wait until the script has been asked `count` exchanges.
    async fn asked(&self, count: usize) {
        until("the device asked", || self.script.asked().len() >= count).await;
    }
}

/// Wait, in real time, until `done` holds.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "never: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn reading(
    record: &MobileManagedDeviceRecord,
    category: UlcpManageCategory,
) -> Option<&super::records::MobileCategoryReadingRecord> {
    record
        .readings
        .iter()
        .find(|reading| reading.category == category)
}
