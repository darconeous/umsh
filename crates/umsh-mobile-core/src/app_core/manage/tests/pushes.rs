//! What a device pushes, against a scripted device.

use umsh_ulcp::ids::prop;

use super::script::Call;
use super::{Bench, heard, items, name, reading};
use crate::app_core::manage::records::{MobileManagementLink, MobileManagementOutcome};
use crate::ulcp::{
    UlcpAlertState, UlcpManageCategory, UlcpPropertyPushKind, UlcpPropertyPushRecord,
};

const ADMINISTRATIVE: MobileManagementLink = MobileManagementLink::Administrative;

fn push(property_id: u32, value: Vec<u8>, kind: UlcpPropertyPushKind) -> UlcpPropertyPushRecord {
    UlcpPropertyPushRecord {
        property_id,
        value,
        kind,
    }
}

fn is(property_id: u32, value: Vec<u8>) -> UlcpPropertyPushRecord {
    push(property_id, value, UlcpPropertyPushKind::Is)
}

/// What the device shows as heard: names, strongest first, and whether
/// each is known.
fn heard_names(bench: &Bench) -> Vec<(Vec<u8>, i8, bool)> {
    bench
        .snapshot()
        .heard_networks
        .into_iter()
        .map(|heard| (heard.result.ssid, heard.result.rssi_dbm, heard.is_known))
        .collect()
}

#[tokio::test]
async fn a_scan_folds_by_access_point_and_groups_by_name() {
    let bench = Bench::station(ADMINISTRATIVE).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .load_category(UlcpManageCategory::Wifi)
        .await
        .unwrap();
    // A whole table, as a read answers or a scan's start clears it.
    bench.device.receive_pushes(
        vec![is(
            prop::WIFI_SCAN_RESULTS,
            items(&[heard(b"Field Office", 1, -70, 4), heard(b"", 2, -60, 0)]),
        )],
        0,
    );
    bench
        .until("the table", |snapshot| snapshot.heard_networks.len() == 2)
        .await;
    // One access point at a time while a scan runs.
    bench.device.receive_pushes(
        vec![
            push(
                prop::WIFI_SCAN_RESULTS,
                heard(b"Field Office", 3, -50, 4),
                UlcpPropertyPushKind::Inserted,
            ),
            push(
                prop::WIFI_SCAN_RESULTS,
                heard(b"Trailhead", 4, -80, 4),
                UlcpPropertyPushKind::Inserted,
            ),
            push(
                prop::WIFI_SCAN_RESULTS,
                heard(b"", 5, -40, 0),
                UlcpPropertyPushKind::Inserted,
            ),
            push(
                prop::WIFI_SCAN_RESULTS,
                vec![0xff],
                UlcpPropertyPushKind::Inserted,
            ),
        ],
        0,
    );
    bench
        .until("the inserts", |snapshot| snapshot.heard_networks.len() == 4)
        .await;
    // Named networks once, at their strongest; nameless ones each alone.
    assert_eq!(
        heard_names(&bench),
        vec![
            (Vec::new(), -40, false),
            (b"Field Office".to_vec(), -50, true),
            (Vec::new(), -60, false),
            (b"Trailhead".to_vec(), -80, false),
        ]
    );
    bench.device.receive_pushes(
        vec![push(
            prop::WIFI_SCAN_RESULTS,
            heard(b"Field Office", 3, -50, 4),
            UlcpPropertyPushKind::Removed,
        )],
        0,
    );
    bench
        .until("the removal", |snapshot| {
            snapshot
                .heard_networks
                .iter()
                .any(|heard| heard.result.rssi_dbm == -70)
        })
        .await;
    bench
        .device
        .receive_pushes(vec![is(prop::WIFI_SCAN_RESULTS, Vec::new())], 0);
    bench
        .until("cleared", |snapshot| snapshot.heard_networks.is_empty())
        .await;
    // Never a reading's value, and never cached.
    let snapshot = bench.snapshot();
    let wifi = reading(&snapshot, UlcpManageCategory::Wifi).unwrap();
    assert!(
        !wifi
            .values
            .iter()
            .any(|value| value.property_id == prop::WIFI_SCAN_RESULTS && !value.value.is_empty())
    );
}

#[tokio::test]
async fn a_push_folds_into_held_readings_and_is_kept_only_then() {
    let bench = Bench::station(ADMINISTRATIVE).await;
    bench.device.load_card().await.unwrap();
    let cached = || {
        bench
            .core
            .store
            .cached_properties(
                bench.owner.clone(),
                bench.address.clone(),
                vec![prop::DEV_NAME],
            )
            .unwrap()
            .get(&prop::DEV_NAME)
            .map(|cached| cached.value.clone())
    };
    // Nothing on screen holds the name yet.
    bench
        .device
        .receive_pushes(vec![is(prop::DEV_NAME, name("Unheld"))], 0);
    bench
        .device
        .receive_pushes(vec![is(prop::ALERT, vec![1])], 0);
    bench
        .until("the alert", |snapshot| {
            snapshot.alert != UlcpAlertState::None
        })
        .await;
    assert_eq!(cached(), None);

    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    bench.device.receive_pushes(
        vec![
            // An item notice says a table changed, not what it holds.
            push(
                prop::DEV_NAME,
                name("Notice"),
                UlcpPropertyPushKind::Inserted,
            ),
            is(prop::DEV_NAME, name("Ridge")),
        ],
        0,
    );
    bench
        .until("the pushed name", |snapshot| {
            reading(snapshot, UlcpManageCategory::Identity)
                .and_then(|reading| reading.properties.device_name.as_deref())
                == Some("Ridge")
        })
        .await;
    assert_eq!(cached(), Some(name("Ridge")));
}

#[tokio::test]
async fn lost_pushes_read_again_only_what_is_held() {
    let bench = Bench::station(ADMINISTRATIVE).await;
    bench.device.load_card().await.unwrap();
    for category in [UlcpManageCategory::Identity, UlcpManageCategory::Time] {
        assert_eq!(
            bench.device.refresh_category(category).await,
            Ok(MobileManagementOutcome::Done)
        );
    }
    bench.script.clear_asked();
    bench.device.receive_pushes(Vec::new(), 3);
    bench.asked(2).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let identity =
        crate::ulcp::ulcp_category_properties(UlcpManageCategory::Identity, caps(&bench)).unwrap();
    let time =
        crate::ulcp::ulcp_category_properties(UlcpManageCategory::Time, caps(&bench)).unwrap();
    assert_eq!(
        bench.script.asked(),
        vec![
            Call::Fetch {
                property_ids: identity,
                multi_hint: true
            },
            Call::Fetch {
                property_ids: time,
                multi_hint: true
            },
        ]
    );
}

/// How many reads the script has been asked.
fn fetches(bench: &Bench) -> usize {
    bench
        .script
        .asked()
        .iter()
        .filter(|call| matches!(call, Call::Fetch { .. }))
        .count()
}

#[tokio::test]
async fn lost_pushes_read_again_a_category_whose_read_is_running() {
    let bench = Bench::station(ADMINISTRATIVE).await;
    bench.device.load_card().await.unwrap();
    assert_eq!(
        bench
            .device
            .refresh_category(UlcpManageCategory::Identity)
            .await,
        Ok(MobileManagementOutcome::Done)
    );
    bench.script.clear_asked();
    bench.script.hold();
    let (running, ()) = tokio::join!(
        bench.device.refresh_category(UlcpManageCategory::Identity),
        async {
            bench.asked(1).await;
            // Its answer may predate what was lost.
            bench.device.receive_pushes(Vec::new(), 1);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            bench.script.unhold();
        }
    );
    assert_eq!(running, Ok(MobileManagementOutcome::Done));
    bench.asked(2).await;
    assert_eq!(fetches(&bench), 2);
}

#[tokio::test]
async fn a_retired_device_stops_reading_again() {
    let bench = Bench::station(ADMINISTRATIVE).await;
    bench.device.load_card().await.unwrap();
    for category in [UlcpManageCategory::Identity, UlcpManageCategory::Time] {
        assert_eq!(
            bench.device.refresh_category(category).await,
            Ok(MobileManagementOutcome::Done)
        );
    }
    bench.script.clear_asked();
    bench.script.hold();
    bench.device.receive_pushes(Vec::new(), 1);
    bench.asked(1).await;
    assert_eq!(bench.core.core.erase(false).await, Ok(()));
    bench.script.unhold();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(fetches(&bench), 1, "nothing read after the erase");
}

fn caps(bench: &Bench) -> Vec<u8> {
    bench.snapshot().card.unwrap().capabilities
}
