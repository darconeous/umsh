//! Wi-Fi, Bluetooth pairings and the mesh scan poll, against a scripted
//! device.

use std::future::Future;
use std::time::Duration;

use umsh_ulcp::Status;
use umsh_ulcp::ids::prop;

use super::script::Call;
use super::{Bench, heard, items, reading, until};
use crate::app_core::manage::records::{
    MobileManagementLink, MobileManagementOutcome, MobileManagementProblem as Problem,
    MobilePropertyState, MobileWifiOutcome, MobileWifiRefusal, MobileWifiStep,
};
use crate::app_core::manage::refusal::{Stop, classify};
use crate::ulcp::{UlcpDfuMode, UlcpManageCategory, ulcp_wifi_network_item};

const MESH: MobileManagementLink = MobileManagementLink::Mesh;
const COMPANION: MobileManagementLink = MobileManagementLink::Companion;

const FIELD_OFFICE: &[u8] = b"Field Office";
const WPA2: u8 = 2;
const WPA3: u8 = 3;

/// Open the bench's device and read its Wi-Fi.
async fn opened(bench: &Bench) {
    bench.device.load_card().await.unwrap();
    assert_eq!(
        bench
            .device
            .refresh_category(UlcpManageCategory::Wifi)
            .await,
        Ok(MobileManagementOutcome::Done)
    );
    bench.script.clear_asked();
}

fn writes(calls: &[Call]) -> Vec<Vec<(u32, Vec<u8>)>> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::Write(writes) => Some(writes.clone()),
            _ => None,
        })
        .collect()
}

fn wifi_fetches(bench: &Bench) -> usize {
    bench
        .script
        .asked()
        .iter()
        .filter(|call| matches!(call, Call::Fetch { .. }))
        .count()
}

fn item(ssid: &[u8], security: u8, auto_join: bool, credential: &[u8]) -> Vec<u8> {
    ulcp_wifi_network_item(
        ssid.to_vec(),
        security,
        false,
        auto_join,
        credential.to_vec(),
    )
    .unwrap()
}

/// Run `work` while the core's clock moves on a poll step at a time, as
/// long as `each` lets it.
async fn ticking<T>(bench: &Bench, work: impl Future<Output = T>, mut each: impl FnMut()) -> T {
    tokio::pin!(work);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        tokio::select! {
            out = &mut work => return out,
            () = tokio::time::sleep(Duration::from_millis(5)) => {
                assert!(tokio::time::Instant::now() < deadline, "never finished");
                each();
                bench.core.clock.advance(2_000);
            }
        }
    }
}

/// Wait until the scan's write went and its poll is waiting.
async fn polling(bench: &Bench) {
    until("the scan was asked for", || {
        !writes(&bench.script.asked()).is_empty()
    })
    .await;
    bench
        .until("the write ended", |snapshot| !snapshot.busy)
        .await;
    tokio::time::sleep(Duration::from_millis(20)).await;
}

// MARK: The scan

#[tokio::test]
async fn a_mesh_scan_is_followed_until_the_flag_clears() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let results = items(&[
        heard(FIELD_OFFICE, 1, -60, 4),
        heard(b"Trailhead", 2, -70, 4),
    ]);
    let outcome = ticking(&bench, bench.device.scan_networks(), || {
        if wifi_fetches(&bench) >= 1 {
            bench.script.set(prop::WIFI_SCANNING, vec![0]);
            bench.script.set(prop::WIFI_SCAN_RESULTS, results.clone());
        }
    })
    .await;
    assert_eq!(outcome, Ok(MobileManagementOutcome::Done));
    let asked = bench.script.asked();
    assert_eq!(writes(&asked), vec![vec![(prop::WIFI_SCANNING, vec![1])]]);
    assert!(wifi_fetches(&bench) >= 2);
    let heard: Vec<Vec<u8>> = bench
        .snapshot()
        .heard_networks
        .into_iter()
        .map(|heard| heard.result.ssid)
        .collect();
    assert_eq!(heard, vec![FIELD_OFFICE.to_vec(), b"Trailhead".to_vec()]);
    assert!(bench.snapshot().heard_networks[0].is_known);
}

#[tokio::test]
async fn the_poll_ends_on_a_flag_refused_or_left_out() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let (outcome, ()) = tokio::join!(
        ticking(&bench, bench.device.scan_networks(), || {}),
        async {
            until("the scan was asked for", || {
                !writes(&bench.script.asked()).is_empty()
            })
            .await;
            bench
                .script
                .refuse(prop::WIFI_SCANNING, Some(Status::PROP_NOT_FOUND.0));
        }
    );
    assert_eq!(outcome, Ok(MobileManagementOutcome::Done));
    assert!(wifi_fetches(&bench) < 20);
    bench.script.unrefuse(prop::WIFI_SCANNING);
    bench.script.clear_asked();

    let (outcome, ()) = tokio::join!(
        ticking(&bench, bench.device.scan_networks(), || {}),
        async {
            until("the scan was asked for", || {
                !writes(&bench.script.asked()).is_empty()
            })
            .await;
            bench.script.omit(prop::WIFI_SCANNING);
        }
    );
    assert_eq!(outcome, Ok(MobileManagementOutcome::Done));
    assert!(wifi_fetches(&bench) < 20);
}

#[tokio::test]
async fn the_poll_gives_up_after_twenty_reads() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let outcome = ticking(&bench, bench.device.scan_networks(), || {}).await;
    assert_eq!(outcome, Ok(MobileManagementOutcome::Done));
    assert_eq!(wifi_fetches(&bench), 20);
}

#[tokio::test]
async fn a_failed_read_ends_the_poll() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let (outcome, ()) = tokio::join!(bench.device.scan_networks(), async {
        polling(&bench).await;
        bench.script.fail_next(Stop::Problem(Problem::NoAnswer));
        bench.core.clock.advance(2_000);
    });
    assert_eq!(
        outcome,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::NoAnswer
        })
    );
    assert_eq!(bench.snapshot().problem, Some(Problem::NoAnswer));
}

#[tokio::test]
async fn a_cancel_ends_the_poll() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let (outcome, ()) = tokio::join!(bench.device.scan_networks(), async {
        polling(&bench).await;
        bench.device.cancel();
    });
    assert_eq!(outcome, Ok(MobileManagementOutcome::Cancelled));
    assert_eq!(wifi_fetches(&bench), 0);
}

#[tokio::test]
async fn a_second_scan_ends_the_first_and_follows_its_own() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let (first, second) = tokio::join!(bench.device.scan_networks(), async {
        polling(&bench).await;
        let second = bench.device.scan_networks();
        tokio::pin!(second);
        // The first answers once the second has begun.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while writes(&bench.script.asked()).len() < 2 {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::select! {
                _ = &mut second => panic!("the second scan ended early"),
                () = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
        bench.script.set(prop::WIFI_SCANNING, vec![0]);
        ticking(&bench, second, || {}).await
    });
    assert_eq!(first, Ok(MobileManagementOutcome::Cancelled));
    assert_eq!(second, Ok(MobileManagementOutcome::Done));
}

#[tokio::test]
async fn a_second_scan_ends_the_first_while_its_read_is_out() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let (first, second) = tokio::join!(bench.device.scan_networks(), async {
        polling(&bench).await;
        bench.script.hold();
        bench.core.clock.advance(2_000);
        until("the first scan's read", || wifi_fetches(&bench) == 1).await;
        // The device says the first scan finished, with a table.
        bench.script.set(prop::WIFI_SCANNING, vec![0]);
        bench.script.set(
            prop::WIFI_SCAN_RESULTS,
            items(&[heard(FIELD_OFFICE, 1, -60, 4)]),
        );
        // Something heard, so the second scan's start shows as it clears.
        bench.device.receive_pushes(
            vec![crate::ulcp::UlcpPropertyPushRecord {
                property_id: prop::WIFI_SCAN_RESULTS,
                value: items(&[heard(b"Trailhead", 2, -70, 4)]),
                kind: crate::ulcp::UlcpPropertyPushKind::Is,
            }],
            0,
        );
        bench
            .until("heard", |snapshot| !snapshot.heard_networks.is_empty())
            .await;
        let second = bench.device.scan_networks();
        tokio::pin!(second);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !bench.snapshot().heard_networks.is_empty() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::select! {
                _ = &mut second => panic!("the second scan ended early"),
                () = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
        bench.script.unhold();
        ticking(&bench, second, || {}).await
    });
    assert_eq!(first, Ok(MobileManagementOutcome::Cancelled));
    assert_eq!(second, Ok(MobileManagementOutcome::Done));
}

#[tokio::test]
async fn releasing_the_device_ends_the_poll() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let (outcome, ()) = tokio::join!(bench.device.scan_networks(), async {
        polling(&bench).await;
        bench.device.release();
    });
    assert_eq!(outcome, Ok(MobileManagementOutcome::Cancelled));
    assert_eq!(wifi_fetches(&bench), 0);
}

#[tokio::test]
async fn firmware_update_entry_ends_the_poll() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    bench.script.answer_dfu(Some(0));
    let (outcome, entered) = tokio::join!(bench.device.scan_networks(), async {
        polling(&bench).await;
        bench.device.enter_dfu(UlcpDfuMode::Default).await
    });
    assert_eq!(entered, Ok(MobileManagementOutcome::Done));
    assert_eq!(outcome, Ok(MobileManagementOutcome::Skipped));
    assert_eq!(wifi_fetches(&bench), 0);
}

#[tokio::test]
async fn a_link_that_pushes_is_not_polled() {
    let bench = Bench::station(COMPANION).await;
    opened(&bench).await;
    assert_eq!(
        bench.device.scan_networks().await,
        Ok(MobileManagementOutcome::Done)
    );
    assert_eq!(
        bench.script.asked(),
        vec![Call::Write(vec![(prop::WIFI_SCANNING, vec![1])])]
    );
}

/// Bug 15: the scan flag is live state, so a scan left mid-poll never
/// reopens from the cache as still scanning.
#[tokio::test]
async fn a_scan_left_mid_poll_reopens_without_the_flag() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let (outcome, ()) = tokio::join!(bench.device.scan_networks(), async {
        polling(&bench).await;
        bench.device.cancel();
    });
    assert_eq!(outcome, Ok(MobileManagementOutcome::Cancelled));
    bench.device.release();
    let reopened = bench.handle(MESH).await;
    assert_ne!(reopened.id(), bench.device.id());
    reopened.load_card().await.unwrap();
    reopened
        .load_category(UlcpManageCategory::Wifi)
        .await
        .unwrap();
    let snapshot = reopened.snapshot();
    let wifi = reading(&snapshot, UlcpManageCategory::Wifi).unwrap();
    assert!(!wifi.is_fresh, "from the cache");
    let scanning = wifi
        .states
        .iter()
        .find(|state| state.property_id == prop::WIFI_SCANNING)
        .unwrap();
    assert_eq!(scanning.state, MobilePropertyState::NotRead);
    assert_eq!(wifi.properties.wifi_scanning, None);
}

// MARK: Joining and the network table

#[tokio::test]
async fn a_join_stores_turns_on_selects_saves_and_reads_again() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    assert_eq!(
        bench
            .device
            .join_network(
                FIELD_OFFICE.to_vec(),
                WPA2,
                false,
                b"fieldwork".to_vec(),
                Some(0b1100)
            )
            .await,
        Ok(MobileWifiOutcome::Done)
    );
    let asked = bench.script.asked();
    assert_eq!(
        asked[..3],
        [
            Call::NetworkEdit {
                item: item(FIELD_OFFICE, WPA2, true, b"fieldwork"),
                present: true
            },
            Call::Write(vec![
                (prop::WIFI_ENABLED, vec![1]),
                (prop::WIFI_NETWORK, FIELD_OFFICE.to_vec()),
            ]),
            Call::Save,
        ]
    );
    assert!(matches!(asked[3], Call::Fetch { .. }), "Wi-Fi read again");
    assert_eq!(asked.len(), 4);

    // The station reads on now: no TurnOn.
    bench.script.clear_asked();
    bench
        .device
        .join_network(
            FIELD_OFFICE.to_vec(),
            WPA2,
            false,
            b"fieldwork".to_vec(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        writes(&bench.script.asked()),
        vec![vec![(prop::WIFI_NETWORK, FIELD_OFFICE.to_vec())]]
    );
}

#[tokio::test]
async fn an_unread_or_refused_station_is_turned_on() {
    // Unread.
    let bench = Bench::station(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.set(prop::WIFI_ENABLED, vec![1]);
    bench
        .device
        .join_network(FIELD_OFFICE.to_vec(), WPA3, false, b"x".to_vec(), None)
        .await
        .unwrap();
    assert_eq!(writes(&bench.script.asked())[0][0].0, prop::WIFI_ENABLED);

    // Refused when read.
    let bench = Bench::station(MESH).await;
    bench
        .script
        .refuse(prop::WIFI_ENABLED, Some(Status::PROP_NOT_FOUND.0));
    opened(&bench).await;
    bench.script.unrefuse(prop::WIFI_ENABLED);
    bench
        .device
        .join_network(FIELD_OFFICE.to_vec(), WPA3, false, b"x".to_vec(), None)
        .await
        .unwrap();
    assert_eq!(writes(&bench.script.asked())[0][0].0, prop::WIFI_ENABLED);
}

/// The store step's refusals, each with its own meaning; nothing is saved
/// and nothing read after a refusal.
#[tokio::test]
async fn a_refused_join_says_why_at_its_step() {
    let cases = [
        (Status::NOMEM, WPA2, Some(0b1100), MobileWifiRefusal::NoRoom),
        (
            Status::INVALID_ARGUMENT,
            WPA2,
            None,
            MobileWifiRefusal::CredentialRejected,
        ),
        // Bugs 3 and 4: the next mode the network offers, from the plan.
        (
            Status::UNIMPLEMENTED,
            WPA3,
            Some(0b1100),
            MobileWifiRefusal::SecurityUnsupported {
                tried: WPA3,
                weaker: Some(WPA2),
            },
        ),
        (
            Status::UNIMPLEMENTED,
            WPA3,
            Some(0b1000),
            MobileWifiRefusal::SecurityUnsupported {
                tried: WPA3,
                weaker: None,
            },
        ),
        (
            Status::BUSY,
            WPA2,
            None,
            MobileWifiRefusal::Other {
                step: MobileWifiStep::Store,
                refusal: classify(Some(Status::BUSY.0)),
            },
        ),
    ];
    for (status, security, offered, refusal) in cases {
        let bench = Bench::station(MESH).await;
        opened(&bench).await;
        bench.script.refuse_edit(status.0);
        assert_eq!(
            bench
                .device
                .join_network(
                    FIELD_OFFICE.to_vec(),
                    security,
                    false,
                    b"fieldwork".to_vec(),
                    offered
                )
                .await,
            Ok(MobileWifiOutcome::Refused { refusal }),
            "{status:?}"
        );
        assert_eq!(bench.script.asked().len(), 1, "only the store");
        assert_eq!(bench.snapshot().problem, None);
    }
}

#[tokio::test]
async fn a_join_refused_after_the_store_is_no_step_down() {
    for (property, step) in [
        (prop::WIFI_ENABLED, MobileWifiStep::TurnOn),
        (prop::WIFI_NETWORK, MobileWifiStep::Select),
    ] {
        let bench = Bench::station(MESH).await;
        opened(&bench).await;
        bench.script.refuse(property, Some(Status::UNIMPLEMENTED.0));
        assert_eq!(
            bench
                .device
                .join_network(
                    FIELD_OFFICE.to_vec(),
                    WPA3,
                    false,
                    b"fieldwork".to_vec(),
                    Some(0b1100)
                )
                .await,
            Ok(MobileWifiOutcome::Refused {
                refusal: MobileWifiRefusal::Other {
                    step,
                    refusal: classify(Some(Status::UNIMPLEMENTED.0)),
                }
            })
        );
        assert!(!bench.script.asked().contains(&Call::Save));
        assert_eq!(wifi_fetches(&bench), 0);
    }
}

#[tokio::test]
async fn a_network_this_app_cannot_build_is_not_sent() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    for (security, credential) in [(9, b"fieldwork".to_vec()), (WPA2, b"short".to_vec())] {
        assert_eq!(
            bench
                .device
                .join_network(FIELD_OFFICE.to_vec(), security, false, credential, None)
                .await,
            Ok(MobileWifiOutcome::Failed {
                problem: Problem::NotBuilt
            })
        );
    }
    assert!(bench.script.asked().is_empty());
    assert_eq!(bench.snapshot().problem, Some(Problem::NotBuilt));
}

#[tokio::test]
async fn an_update_stores_saves_and_reads_again() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    // An empty credential under the stored mode keeps the stored one.
    assert_eq!(
        bench
            .device
            .update_network(FIELD_OFFICE.to_vec(), WPA2, false, false, Vec::new())
            .await,
        Ok(MobileWifiOutcome::Done)
    );
    let asked = bench.script.asked();
    assert_eq!(
        asked[..2],
        [
            Call::NetworkEdit {
                item: item(FIELD_OFFICE, WPA2, false, b""),
                present: true
            },
            Call::Save
        ]
    );
    assert!(matches!(asked[2], Call::Fetch { .. }));

    for (status, refusal) in [
        (
            Status::UNIMPLEMENTED,
            MobileWifiRefusal::SecurityUnsupported {
                tried: WPA3,
                weaker: None,
            },
        ),
        (
            Status::INVALID_ARGUMENT,
            MobileWifiRefusal::CredentialRejected,
        ),
        (
            Status::NOMEM,
            MobileWifiRefusal::Other {
                step: MobileWifiStep::Store,
                refusal: classify(Some(Status::NOMEM.0)),
            },
        ),
    ] {
        bench.script.clear_asked();
        bench.script.refuse_edit(status.0);
        assert_eq!(
            bench
                .device
                .update_network(FIELD_OFFICE.to_vec(), WPA3, false, true, b"x".to_vec())
                .await,
            Ok(MobileWifiOutcome::Refused { refusal })
        );
        assert_eq!(bench.script.asked().len(), 1);
    }
}

#[tokio::test]
async fn auto_join_resends_the_stored_entry_without_its_credential() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    assert_eq!(
        bench
            .device
            .set_auto_join(FIELD_OFFICE.to_vec(), false)
            .await,
        Ok(MobileManagementOutcome::Done)
    );
    let asked = bench.script.asked();
    assert_eq!(
        asked[..2],
        [
            Call::NetworkEdit {
                item: item(FIELD_OFFICE, WPA2, false, b""),
                present: true
            },
            Call::Save
        ]
    );
    assert!(matches!(asked[2], Call::Fetch { .. }));

    bench.script.clear_asked();
    assert_eq!(
        bench
            .device
            .set_auto_join(b"Elsewhere".to_vec(), true)
            .await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::NotFound
        })
    );
    assert!(bench.script.asked().is_empty());
}

#[tokio::test]
async fn forgetting_removes_by_name_and_saves() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    assert_eq!(
        bench.device.forget_network(FIELD_OFFICE.to_vec()).await,
        Ok(MobileManagementOutcome::Done)
    );
    let asked = bench.script.asked();
    assert_eq!(
        asked[..2],
        [
            Call::NetworkEdit {
                item: FIELD_OFFICE.to_vec(),
                present: false
            },
            Call::Save
        ]
    );
    assert!(matches!(asked[2], Call::Fetch { .. }));

    bench.script.clear_asked();
    bench.script.refuse_edit(Status::BUSY.0);
    assert_eq!(
        bench.device.forget_network(FIELD_OFFICE.to_vec()).await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::Refused {
                refusal: classify(Some(Status::BUSY.0))
            }
        })
    );
    assert_eq!(bench.script.asked().len(), 1, "no save, no read");
}

#[tokio::test]
async fn joining_a_known_network_or_leaving_writes_and_folds_the_echo() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let network = || {
        reading(&bench.snapshot(), UlcpManageCategory::Wifi)
            .and_then(|reading| reading.properties.wifi_network.clone())
    };
    assert_eq!(
        bench.device.join_known_network(FIELD_OFFICE.to_vec()).await,
        Ok(MobileManagementOutcome::Done)
    );
    // Bug 13: a button's echo reaches the reading.
    assert_eq!(network(), Some(FIELD_OFFICE.to_vec()));
    assert_eq!(
        bench.device.disconnect_network().await,
        Ok(MobileManagementOutcome::Done)
    );
    assert_eq!(network(), Some(Vec::new()));
    assert_eq!(
        bench.script.asked(),
        vec![
            Call::Write(vec![(prop::WIFI_NETWORK, FIELD_OFFICE.to_vec())]),
            Call::Write(vec![(prop::WIFI_NETWORK, Vec::new())]),
        ],
        "nothing saved"
    );

    bench
        .script
        .refuse(prop::WIFI_NETWORK, Some(Status::INVALID_STATE.0));
    assert_eq!(
        bench.device.disconnect_network().await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::Refused {
                refusal: classify(Some(Status::INVALID_STATE.0))
            }
        })
    );
}

// MARK: Bluetooth pairings

#[tokio::test]
async fn cleared_pairings_read_as_no_bonds_and_pairing_open() {
    let bench = Bench::station(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Bluetooth)
        .await
        .unwrap();
    bench.script.clear_asked();
    // A device that clears its bonds and still reports the old count.
    bench.script.set(prop::BLE_BOND_COUNT, vec![2]);
    assert_eq!(
        bench.device.clear_bluetooth_pairings().await,
        Ok(MobileManagementOutcome::Done)
    );
    assert_eq!(
        bench.script.asked(),
        vec![Call::Write(vec![(prop::BLE_BOND_COUNT, vec![0])])]
    );
    let snapshot = bench.snapshot();
    let bluetooth = reading(&snapshot, UlcpManageCategory::Bluetooth).unwrap();
    assert_eq!(bluetooth.properties.ble_bond_count, Some(0));
    assert_eq!(bluetooth.properties.ble_pairing, Some(true));

    bench
        .script
        .refuse(prop::BLE_BOND_COUNT, Some(Status::PROP_NOT_FOUND.0));
    bench.script.set(prop::BLE_PAIRING, vec![0]);
    bench
        .device
        .refresh_category(UlcpManageCategory::Bluetooth)
        .await
        .unwrap();
    assert_eq!(
        bench.device.clear_bluetooth_pairings().await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::Refused {
                refusal: classify(Some(Status::PROP_NOT_FOUND.0))
            }
        })
    );
    let snapshot = bench.snapshot();
    let bluetooth = reading(&snapshot, UlcpManageCategory::Bluetooth).unwrap();
    assert_eq!(
        bluetooth.properties.ble_pairing,
        Some(false),
        "nothing folded"
    );
}
