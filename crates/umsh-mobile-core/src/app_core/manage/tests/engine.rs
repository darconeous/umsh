//! The engine's rules, against a scripted device.

use std::time::Duration;

use umsh_ulcp::Status;
use umsh_ulcp::ids::prop;

use super::script::Call;
use super::{Bench, device_values, name, reading, time, until};
use crate::app_core::MobileAppError;
use crate::app_core::clock::Clock;
use crate::app_core::manage::records::{
    MobileAnnouncementReach, MobileApplyOutcome, MobileApplyResult, MobileManagementLink,
    MobileManagementOutcome, MobileManagementProblem as Problem, MobilePropertyState,
    MobileRefusal, MobileRefusalReason, MobileTemperatureNames, MobileTemperatureValue,
};
use crate::app_core::manage::refusal::Stop;
use crate::mobile_mesh::MobileMeshResetScope;
use crate::ulcp::{
    MobileAnnouncementKind, UlcpAlertState, UlcpDevicePropertiesRecord, UlcpDfuMode,
    UlcpManageCategory,
};

const MESH: MobileManagementLink = MobileManagementLink::Mesh;
const COMPANION: MobileManagementLink = MobileManagementLink::Companion;

fn fetches(calls: &[Call]) -> Vec<Vec<u32>> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::Fetch { property_ids, .. } => Some(property_ids.clone()),
            _ => None,
        })
        .collect()
}

fn named(record: &UlcpDevicePropertiesRecord) -> Option<&str> {
    record.device_name.as_deref()
}

fn identity_named(bench: &Bench, name: &str) {
    let snapshot = bench.snapshot();
    let identity = reading(&snapshot, UlcpManageCategory::Identity).expect("an identity reading");
    assert_eq!(named(&identity.properties), Some(name));
}

// MARK: Handles and lifetime

#[tokio::test]
async fn two_handles_on_one_device_share_its_engine() {
    let bench = Bench::new(MESH).await;
    let second = bench.handle(MESH).await;
    assert_eq!(second.id(), bench.device.id());
    assert_eq!(
        bench.device.load_card().await,
        Ok(MobileManagementOutcome::Done)
    );
    assert_eq!(second.snapshot(), bench.snapshot());
    assert!(second.snapshot().card.is_some());
    assert_eq!(bench.registered().await, 1);
}

#[tokio::test]
async fn the_last_close_relinquishes_and_the_device_is_forgotten() {
    let bench = Bench::new(MESH).await;
    let second = bench.handle(MESH).await;
    second.release();
    second.release();
    assert_eq!(
        bench.device.load_card().await,
        Ok(MobileManagementOutcome::Done),
        "one close of two changes nothing"
    );
    assert_eq!(second.load_card().await, Err(MobileAppError::Stopped));
    assert_eq!(bench.registered().await, 1);
    bench.device.release();
    assert_eq!(bench.registered().await, 0);
    assert_eq!(bench.device.load_card().await, Err(MobileAppError::Stopped));
}

#[tokio::test]
async fn dropping_a_handle_closes_it() {
    let bench = Bench::new(MESH).await;
    let Bench {
        core,
        device,
        script,
        ..
    } = bench;
    drop(device);
    let registered = || async {
        core.core
            .on_worker(|worker| async move { Ok(worker.managed.borrow().len()) })
            .await
            .unwrap()
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while registered().await != 0 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    drop(script);
}

#[tokio::test]
async fn a_handle_outliving_its_core_answers_stopped() {
    let bench = Bench::new(MESH).await;
    let Bench { core, device, .. } = bench;
    let crate::app_core::test_support::Core {
        directory,
        core: app,
        ..
    } = core;
    drop(app);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match device.load_card().await {
            Err(MobileAppError::Stopped) => break,
            _ => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the core never stopped"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
    drop(device);
    drop(directory);
}

// MARK: The queue

#[tokio::test]
async fn the_queue_runs_reads_and_writes_in_order() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.clear_asked();
    bench.script.hold();
    let device = &bench.device;
    let (first, applied, second, ()) = tokio::join!(
        device.refresh_category(UlcpManageCategory::Identity),
        async {
            bench.asked(1).await;
            device
                .apply_properties(
                    UlcpManageCategory::Identity,
                    UlcpDevicePropertiesRecord {
                        device_name: Some("Ridge".to_owned()),
                        ..UlcpDevicePropertiesRecord::default()
                    },
                    vec![prop::DEV_NAME],
                    true,
                )
                .await
        },
        async {
            bench.until("two queued", |snapshot| snapshot.busy).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            device.refresh_category(UlcpManageCategory::Time).await
        },
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            bench.script.unhold();
        },
    );
    assert_eq!(first, Ok(MobileManagementOutcome::Done));
    assert_eq!(
        applied.map(|outcome| outcome.result),
        Ok(MobileApplyResult::Applied)
    );
    assert_eq!(second, Ok(MobileManagementOutcome::Done));
    let asked = bench.script.asked();
    assert!(matches!(asked[0], Call::Fetch { .. }));
    assert!(matches!(asked[1], Call::Write(_)));
    assert_eq!(asked[2], Call::Save);
    assert!(matches!(asked[3], Call::Fetch { .. }));
    assert!(!bench.snapshot().busy);
}

#[tokio::test]
async fn an_automatic_read_already_queued_is_not_asked_twice() {
    let bench = Bench::new(COMPANION).await;
    bench.script.hold();
    let (first, second, ()) = tokio::join!(
        bench.device.load_card(),
        async {
            bench.asked(1).await;
            bench.device.load_card().await
        },
        async {
            bench.asked(1).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            bench.script.unhold();
        },
    );
    assert_eq!(first, Ok(MobileManagementOutcome::Done));
    assert_eq!(second, Ok(MobileManagementOutcome::Done));
    assert_eq!(fetches(&bench.script.asked()).len(), 1);
}

#[tokio::test]
async fn cancel_ends_reads_and_writes_alike() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.clear_asked();
    bench.script.hold();
    let (read, write, ()) = tokio::join!(
        bench.device.refresh_category(UlcpManageCategory::Identity),
        async {
            bench.asked(1).await;
            bench
                .device
                .apply_properties(
                    UlcpManageCategory::Identity,
                    UlcpDevicePropertiesRecord::default(),
                    vec![prop::STAT_TX_PACKETS],
                    true,
                )
                .await
        },
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            bench.device.cancel();
        },
    );
    assert_eq!(read, Ok(MobileManagementOutcome::Cancelled));
    assert_eq!(
        write,
        Ok(MobileApplyOutcome {
            answered: false,
            result: MobileApplyResult::Cancelled
        })
    );
    assert_eq!(bench.script.asked().len(), 1, "the write was never sent");
    assert_eq!(bench.snapshot().problem, None);
    assert!(!bench.snapshot().busy);
}

#[tokio::test]
async fn relinquishing_cancels_reads_and_lets_a_write_finish() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    let watcher = bench.handle(MESH).await;
    bench.script.clear_asked();
    bench.script.hold();
    let (write, read, ()) = tokio::join!(
        bench.device.apply_properties(
            UlcpManageCategory::Identity,
            UlcpDevicePropertiesRecord {
                device_name: Some("Ridge".to_owned()),
                ..UlcpDevicePropertiesRecord::default()
            },
            vec![prop::DEV_NAME],
            true,
        ),
        async {
            bench.asked(1).await;
            watcher.refresh_category(UlcpManageCategory::Identity).await
        },
        async {
            bench.asked(1).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Every handle closes; the read waits behind the write.
            bench.device.release();
            watcher.release();
            tokio::time::sleep(Duration::from_millis(50)).await;
            bench.script.unhold();
        },
    );
    assert_eq!(
        write,
        Ok(MobileApplyOutcome {
            answered: true,
            result: MobileApplyResult::Applied
        })
    );
    assert_eq!(read, Ok(MobileManagementOutcome::Cancelled));
    let asked = bench.script.asked();
    assert!(matches!(asked[0], Call::Write(_)));
    assert_eq!(asked[1], Call::Save);
    assert_eq!(asked.len(), 2);
    assert_eq!(bench.registered().await, 0);
}

#[tokio::test]
async fn after_firmware_update_entry_nothing_runs() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.answer_dfu(Some(Status::OK.0));
    bench.script.clear_asked();
    bench.script.hold();
    let (dfu, read, ()) = tokio::join!(
        bench.device.enter_dfu(UlcpDfuMode::Default),
        async {
            bench.asked(1).await;
            bench
                .device
                .refresh_category(UlcpManageCategory::Identity)
                .await
        },
        async {
            bench.asked(1).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            bench.script.unhold();
        },
    );
    assert_eq!(dfu, Ok(MobileManagementOutcome::Done));
    assert_eq!(read, Ok(MobileManagementOutcome::Skipped));
    assert!(bench.snapshot().entered_dfu);
    assert_eq!(
        bench.device.restart().await,
        Ok(MobileManagementOutcome::Skipped)
    );
    assert_eq!(bench.script.asked().len(), 1);
}

#[tokio::test]
async fn a_problem_lasts_until_the_next_request() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.fail_next(Stop::Problem(Problem::NoAnswer));
    assert_eq!(
        bench
            .device
            .refresh_category(UlcpManageCategory::Identity)
            .await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::NoAnswer
        })
    );
    assert_eq!(bench.snapshot().problem, Some(Problem::NoAnswer));
    bench.device.dismiss_problem();
    bench
        .until("dismissed", |snapshot| snapshot.problem.is_none())
        .await;

    bench.script.fail_next(Stop::Problem(Problem::Unreachable));
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    assert_eq!(bench.snapshot().problem, Some(Problem::Unreachable));
    // Asking again clears it; a cancel sets none.
    bench.script.hold();
    let (read, ()) = tokio::join!(
        bench.device.refresh_category(UlcpManageCategory::Identity),
        async {
            bench
                .until("asked again", |snapshot| snapshot.problem.is_none())
                .await;
            bench.device.cancel();
        },
    );
    assert_eq!(read, Ok(MobileManagementOutcome::Cancelled));
    assert_eq!(bench.snapshot().problem, None);
}

#[tokio::test]
async fn a_dropped_call_still_runs_to_its_end() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.clear_asked();
    bench.script.hold();
    let call = bench.device.apply_properties(
        UlcpManageCategory::Identity,
        UlcpDevicePropertiesRecord {
            device_name: Some("Ridge".to_owned()),
            ..UlcpDevicePropertiesRecord::default()
        },
        vec![prop::DEV_NAME],
        true,
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), call)
            .await
            .is_err()
    );
    bench.script.unhold();
    until("written and saved", || bench.script.asked().len() == 2).await;
    assert_eq!(bench.script.value(prop::DEV_NAME), Some(name("Ridge")));
}

// MARK: Card and cache

#[tokio::test]
async fn over_the_mesh_a_second_open_asks_nothing() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .load_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    assert!(
        reading(&bench.snapshot(), UlcpManageCategory::Identity)
            .is_some_and(|reading| reading.as_of_ms.is_none()),
        "over the mesh a category waits for Refresh"
    );
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    assert_eq!(fetches(&bench.script.asked()).len(), 2);
    bench.device.release();
    assert_eq!(bench.registered().await, 0);

    bench.script.clear_asked();
    let reopened = bench.handle(MESH).await;
    assert_ne!(reopened.id(), bench.device.id());
    reopened.load_card().await.unwrap();
    reopened
        .load_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    assert_eq!(bench.script.asked(), Vec::<Call>::new());
    let snapshot = reopened.snapshot();
    assert_eq!(
        snapshot
            .card
            .as_ref()
            .and_then(|card| card.device_name.as_deref()),
        Some("Tallac Ridge")
    );
    assert!(!snapshot.card_is_fresh);
    let identity = reading(&snapshot, UlcpManageCategory::Identity).unwrap();
    assert_eq!(named(&identity.properties), Some("Tallac Ridge"));
    assert!(!identity.is_fresh);
    // A cache-built reading refused nothing, so it answers every id.
    assert_eq!(identity.answered, identity.property_ids);
}

#[tokio::test]
async fn off_the_mesh_the_cache_renders_then_refreshes_once() {
    let bench = Bench::new(COMPANION).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .load_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    assert_eq!(fetches(&bench.script.asked()).len(), 2);
    bench.device.load_card().await.unwrap();
    bench
        .device
        .load_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    assert_eq!(
        fetches(&bench.script.asked()).len(),
        2,
        "read once per lifetime"
    );
    let snapshot = bench.snapshot();
    assert!(snapshot.card_is_fresh);
    assert!(snapshot.refreshes_stale_readings);
    assert!(snapshot.offers_factory_reset);
}

#[tokio::test]
async fn a_storeless_device_always_asks_and_keeps_nothing() {
    let bench = Bench::with(MobileManagementLink::Administrative, false).await;
    bench.device.load_card().await.unwrap();
    bench.device.release();
    let reopened = bench.handle(MobileManagementLink::Administrative).await;
    reopened.load_card().await.unwrap();
    assert_eq!(fetches(&bench.script.asked()).len(), 2);
    assert_eq!(
        bench
            .core
            .store
            .management_card(bench.owner.clone(), bench.address.clone())
            .unwrap(),
        None
    );
    assert_eq!(reopened.snapshot().address, None);
}

#[tokio::test]
async fn new_firmware_drops_the_readings_and_the_cached_values() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .load_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
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
    };
    assert_eq!(cached().len(), 1);
    assert_eq!(
        cached()[&prop::DEV_NAME].fetched_at_ms,
        bench.core.clock.now_ms(),
        "stamped by the core's clock"
    );
    bench.script.set(prop::DEV_VERSION, b"2.0".to_vec());
    bench.device.refresh_card().await.unwrap();
    let snapshot = bench.snapshot();
    assert!(snapshot.readings.is_empty());
    assert_eq!(
        snapshot.card.and_then(|card| card.device_version),
        Some("2.0".to_owned())
    );
    assert!(cached().is_empty());
}

#[tokio::test]
async fn the_cache_is_dated_by_its_oldest_sample() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .load_category(UlcpManageCategory::Time)
        .await
        .unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Time)
        .await
        .unwrap();
    let first = bench.core.clock.now_ms();
    bench.core.clock.advance(60_000);
    bench.device.set_clock_now().await.unwrap();
    bench.device.release();

    let reopened = bench.handle(MESH).await;
    reopened.load_card().await.unwrap();
    reopened
        .load_category(UlcpManageCategory::Time)
        .await
        .unwrap();
    let snapshot = reopened.snapshot();
    let time = reading(&snapshot, UlcpManageCategory::Time).unwrap();
    assert_eq!(time.as_of_ms, Some(first));
    let sampled = |property| {
        time.values
            .iter()
            .find(|value| value.property_id == property)
            .map(|value| value.received_at_ms)
    };
    assert_eq!(sampled(prop::UPTIME), Some(first));
    assert_eq!(sampled(prop::TIME), Some(first + 60_000));
}

#[tokio::test]
async fn another_owner_retires_the_device() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .core
        .core
        .set_owner(Some(super::address_of(9)))
        .unwrap();
    assert_eq!(
        bench.device.load_card().await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::NoOwner
        })
    );
    let other = bench.handle(MESH).await;
    assert_ne!(
        other.id(),
        bench.device.id(),
        "a new owner gets a new device"
    );
}

// MARK: Readings

#[tokio::test]
async fn a_read_replaces_the_reading() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Time)
        .await
        .unwrap();
    bench
        .script
        .refuse(prop::TIME, Some(Status::INVALID_STATE.0));
    bench
        .device
        .refresh_category(UlcpManageCategory::Time)
        .await
        .unwrap();
    let snapshot = bench.snapshot();
    let time = reading(&snapshot, UlcpManageCategory::Time).unwrap();
    assert_eq!(time.properties.time, None);
    assert!(!time.answered.contains(&prop::TIME));
    let state = |property| {
        time.states
            .iter()
            .find(|state| state.property_id == property)
            .map(|state| state.state.clone())
    };
    assert_eq!(
        state(prop::TIME),
        Some(MobilePropertyState::Refused {
            refusal: MobileRefusal {
                reason: MobileRefusalReason::NotNow,
                status: Some(4)
            }
        })
    );
    assert_eq!(state(prop::UPTIME), Some(MobilePropertyState::Present));
    // Asked but never held: the device refuses with PROP_NOT_FOUND.
    assert!(matches!(
        state(prop::TZ_RULE),
        Some(MobilePropertyState::Refused { .. })
    ));
}

#[tokio::test]
async fn an_echo_keeps_the_other_samples_dated() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    let read_at = bench.core.clock.now_ms();
    bench.core.clock.advance(5_000);
    bench
        .device
        .apply_properties(
            UlcpManageCategory::Identity,
            UlcpDevicePropertiesRecord {
                device_name: Some("Ridge".to_owned()),
                ..UlcpDevicePropertiesRecord::default()
            },
            vec![prop::DEV_NAME],
            true,
        )
        .await
        .unwrap();
    identity_named(&bench, "Ridge");
    let snapshot = bench.snapshot();
    let identity = reading(&snapshot, UlcpManageCategory::Identity).unwrap();
    assert_eq!(identity.as_of_ms, Some(read_at + 5_000));
    for value in &identity.values {
        let expected = if value.property_id == prop::DEV_NAME {
            read_at + 5_000
        } else {
            read_at
        };
        assert_eq!(value.received_at_ms, expected, "{}", value.property_id);
    }
}

#[tokio::test]
async fn sensors_are_read_in_two_phases_and_keep_their_names() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.clear_asked();
    bench
        .device
        .refresh_category(UlcpManageCategory::Sensors)
        .await
        .unwrap();
    assert_eq!(
        fetches(&bench.script.asked()),
        vec![vec![prop::TEMPERATURES, prop::TEMPERATURE_NAMES]],
        "everything at once until the names are known"
    );
    let snapshot = bench.snapshot();
    let summary = reading(&snapshot, UlcpManageCategory::Sensors)
        .and_then(|reading| reading.temperatures.clone())
        .unwrap();
    assert_eq!(summary.names, MobileTemperatureNames::Known);
    assert_eq!(summary.failure, None);
    assert_eq!(summary.rows.len(), 2);
    assert_eq!(summary.rows[0].name.as_deref(), Some("Die"));
    assert_eq!(
        summary.rows[0].value,
        MobileTemperatureValue::Reading {
            tenths_kelvin: 2981
        }
    );
    assert_eq!(summary.rows[1].value, MobileTemperatureValue::Unavailable);

    // Names known and the inventory unchanged: the measurements alone,
    // and the names stay, with their first instant.
    bench.script.clear_asked();
    bench.core.clock.advance(1_000);
    bench
        .device
        .refresh_category(UlcpManageCategory::Sensors)
        .await
        .unwrap();
    assert_eq!(
        fetches(&bench.script.asked()),
        vec![vec![prop::TEMPERATURES]]
    );
    let snapshot = bench.snapshot();
    let sensors = reading(&snapshot, UlcpManageCategory::Sensors).unwrap();
    assert_eq!(
        sensors.properties.temperature_names,
        Some(vec!["Die".to_owned(), "Air".to_owned()])
    );

    // A third sensor appears: the names are asked again, and a shorter
    // names list is rejected while the known names stay.
    bench.script.clear_asked();
    bench
        .script
        .set(prop::TEMPERATURES, vec![0xa5, 0x0b, 0xff, 0xff, 0xa5, 0x0b]);
    bench
        .script
        .set(prop::TEMPERATURE_NAMES, b"\x03Die".to_vec());
    bench
        .device
        .refresh_category(UlcpManageCategory::Sensors)
        .await
        .unwrap();
    assert_eq!(
        fetches(&bench.script.asked()),
        vec![vec![prop::TEMPERATURES], vec![prop::TEMPERATURE_NAMES]]
    );
    let snapshot = bench.snapshot();
    let summary = reading(&snapshot, UlcpManageCategory::Sensors)
        .and_then(|reading| reading.temperatures.clone())
        .unwrap();
    assert_eq!(summary.names, MobileTemperatureNames::Incomplete);
    assert_eq!(summary.rows.len(), 3);
    assert_eq!(summary.rows[1].name.as_deref(), Some("Air"));
    assert_eq!(summary.rows[2].name, None);
}

#[tokio::test]
async fn a_failed_sensor_request_marks_its_own_properties() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Sensors)
        .await
        .unwrap();
    // A third sensor would have the names asked after the measurements,
    // but the measurements' request fails, so no count is read to grow and
    // the names are not asked again. Under the two-phase plan a failed
    // request is always the last one, so it never has a next to stop.
    bench
        .script
        .set(prop::TEMPERATURES, vec![0xa5, 0x0b, 0xff, 0xff, 0xa5, 0x0b]);
    bench.script.fail_next(Stop::Problem(Problem::NoAnswer));
    bench.script.clear_asked();
    bench.script.hold();
    let (outcome, ()) = tokio::join!(
        bench.device.refresh_category(UlcpManageCategory::Sensors),
        async {
            bench.asked(1).await;
            // The reset reading is out before the first answer: names
            // carried over, measurements cleared.
            let snapshot = bench.snapshot();
            let sensors = reading(&snapshot, UlcpManageCategory::Sensors).unwrap();
            assert!(sensors.properties.temperature_names.is_some());
            assert_eq!(sensors.properties.temperatures, None);
            bench.script.unhold();
        },
    );
    assert_eq!(outcome, Ok(MobileManagementOutcome::Done));
    let snapshot = bench.snapshot();
    let sensors = reading(&snapshot, UlcpManageCategory::Sensors).unwrap();
    let state = |property| {
        sensors
            .states
            .iter()
            .find(|state| state.property_id == property)
            .map(|state| state.state.clone())
    };
    assert_eq!(
        state(prop::TEMPERATURES),
        Some(MobilePropertyState::Failed {
            problem: Problem::NoAnswer
        })
    );
    // Not re-asked: the failed request read no count to grow.
    assert_eq!(fetches(&bench.script.asked()).len(), 1);
    assert_eq!(
        state(prop::TEMPERATURE_NAMES),
        Some(MobilePropertyState::Present)
    );
    assert_eq!(snapshot.problem, None, "a sensor failure is the row's");
}

#[tokio::test]
async fn a_sensor_the_answer_leaves_out_did_not_respond() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.omit(prop::TEMPERATURES);
    bench
        .device
        .refresh_category(UlcpManageCategory::Sensors)
        .await
        .unwrap();
    let snapshot = bench.snapshot();
    let sensors = reading(&snapshot, UlcpManageCategory::Sensors).unwrap();
    assert_eq!(
        sensors
            .temperatures
            .as_ref()
            .and_then(|summary| summary.failure.clone()),
        Some(MobilePropertyState::NoResponse)
    );
}

// MARK: Apply

#[tokio::test]
async fn apply_writes_only_what_is_dirty_and_saves() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    bench.script.clear_asked();
    let outcome = bench
        .device
        .apply_properties(
            UlcpManageCategory::Identity,
            UlcpDevicePropertiesRecord {
                device_name: Some("Ridge".to_owned()),
                ident_role: Some(4),
                ..UlcpDevicePropertiesRecord::default()
            },
            vec![prop::DEV_NAME],
            true,
        )
        .await;
    assert_eq!(
        outcome,
        Ok(MobileApplyOutcome {
            answered: true,
            result: MobileApplyResult::Applied
        })
    );
    assert_eq!(
        bench.script.asked(),
        vec![
            Call::Write(vec![(prop::DEV_NAME, name("Ridge"))]),
            Call::Save
        ]
    );
    identity_named(&bench, "Ridge");
    assert_eq!(
        bench
            .core
            .store
            .cached_properties(
                bench.owner.clone(),
                bench.address.clone(),
                vec![prop::DEV_NAME]
            )
            .unwrap()[&prop::DEV_NAME]
            .value,
        name("Ridge")
    );
}

#[tokio::test]
async fn a_refused_value_is_not_saved() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    bench
        .script
        .refuse(prop::IDENT_ROLE, Some(Status::INVALID_ARGUMENT.0));
    bench.script.clear_asked();
    let outcome = bench
        .device
        .apply_properties(
            UlcpManageCategory::Identity,
            UlcpDevicePropertiesRecord {
                device_name: Some("Ridge".to_owned()),
                ident_role: Some(4),
                ..UlcpDevicePropertiesRecord::default()
            },
            vec![prop::DEV_NAME, prop::IDENT_ROLE],
            true,
        )
        .await;
    assert_eq!(
        outcome,
        Ok(MobileApplyOutcome {
            answered: true,
            result: MobileApplyResult::Refused
        })
    );
    assert!(!bench.script.asked().contains(&Call::Save));
    let snapshot = bench.snapshot();
    assert_eq!(
        snapshot.problem,
        Some(Problem::NotAllApplied { saving: true })
    );
    let identity = reading(&snapshot, UlcpManageCategory::Identity).unwrap();
    assert_eq!(identity.refusals.len(), 1);
    assert_eq!(identity.refusals[0].property_id, prop::IDENT_ROLE);
    assert_eq!(
        identity.refusals[0].refusal.reason,
        MobileRefusalReason::OutOfRange
    );
    // The value taken is folded all the same.
    identity_named(&bench, "Ridge");
    // A read clears the refusals.
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    let snapshot = bench.snapshot();
    assert!(
        reading(&snapshot, UlcpManageCategory::Identity)
            .unwrap()
            .refusals
            .is_empty()
    );
}

#[tokio::test]
async fn an_apply_clears_only_the_refusals_of_what_it_writes() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    bench
        .script
        .refuse(prop::IDENT_ROLE, Some(Status::INVALID_ARGUMENT.0));
    let apply = |properties, dirty| {
        bench
            .device
            .apply_properties(UlcpManageCategory::Identity, properties, dirty, true)
    };
    let refused_ids = || {
        reading(&bench.snapshot(), UlcpManageCategory::Identity)
            .unwrap()
            .refusals
            .iter()
            .map(|row| row.property_id)
            .collect::<Vec<_>>()
    };
    apply(
        UlcpDevicePropertiesRecord {
            ident_role: Some(4),
            ..UlcpDevicePropertiesRecord::default()
        },
        vec![prop::IDENT_ROLE],
    )
    .await
    .unwrap();
    assert_eq!(refused_ids(), vec![prop::IDENT_ROLE]);
    // Another property applied: the role's refusal stands.
    let outcome = apply(
        UlcpDevicePropertiesRecord {
            device_name: Some("Ridge".to_owned()),
            ..UlcpDevicePropertiesRecord::default()
        },
        vec![prop::DEV_NAME],
    )
    .await
    .unwrap();
    assert_eq!(outcome.result, MobileApplyResult::Applied);
    assert_eq!(refused_ids(), vec![prop::IDENT_ROLE]);
    // The role written again and taken: its refusal goes.
    bench.script.unrefuse(prop::IDENT_ROLE);
    apply(
        UlcpDevicePropertiesRecord {
            ident_role: Some(4),
            ..UlcpDevicePropertiesRecord::default()
        },
        vec![prop::IDENT_ROLE],
    )
    .await
    .unwrap();
    assert!(refused_ids().is_empty());
}

#[tokio::test]
async fn a_failed_save_still_answered() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.refuse_save(Some(Status::INVALID_STATE.0));
    let outcome = bench
        .device
        .apply_properties(
            UlcpManageCategory::Identity,
            UlcpDevicePropertiesRecord {
                device_name: Some("Ridge".to_owned()),
                ..UlcpDevicePropertiesRecord::default()
            },
            vec![prop::DEV_NAME],
            true,
        )
        .await;
    let refused = Problem::Refused {
        refusal: MobileRefusal {
            reason: MobileRefusalReason::NotNow,
            status: Some(4),
        },
    };
    assert_eq!(
        outcome,
        Ok(MobileApplyOutcome {
            answered: true,
            result: MobileApplyResult::Failed {
                problem: refused.clone()
            }
        })
    );
    assert_eq!(bench.snapshot().problem, Some(refused));

    assert_eq!(
        bench
            .device
            .apply_properties(
                UlcpManageCategory::Identity,
                UlcpDevicePropertiesRecord::default(),
                Vec::new(),
                true
            )
            .await,
        Ok(MobileApplyOutcome {
            answered: true,
            result: MobileApplyResult::NothingToApply
        })
    );

    bench.script.fail_next(Stop::Problem(Problem::NoAnswer));
    assert_eq!(
        bench
            .device
            .apply_properties(
                UlcpManageCategory::Identity,
                UlcpDevicePropertiesRecord {
                    device_name: Some("Ridge".to_owned()),
                    ..UlcpDevicePropertiesRecord::default()
                },
                vec![prop::DEV_NAME],
                true,
            )
            .await,
        Ok(MobileApplyOutcome {
            answered: false,
            result: MobileApplyResult::Failed {
                problem: Problem::NoAnswer
            }
        })
    );
}

#[tokio::test]
async fn a_value_this_app_cannot_encode_is_not_built() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.clear_asked();
    assert_eq!(
        bench
            .device
            .apply_properties(
                UlcpManageCategory::Identity,
                UlcpDevicePropertiesRecord::default(),
                vec![prop::DEV_NAME],
                true,
            )
            .await,
        Ok(MobileApplyOutcome {
            answered: false,
            result: MobileApplyResult::Failed {
                problem: Problem::NotBuilt
            }
        })
    );
    assert!(bench.script.asked().is_empty());
}

#[tokio::test]
async fn the_clock_is_set_to_now_without_a_save() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.clear_asked();
    assert_eq!(
        bench.device.set_clock_now().await,
        Ok(MobileManagementOutcome::Done)
    );
    let now = u32::try_from(bench.core.clock.now_ms() / 1000).unwrap();
    assert_eq!(
        bench.script.asked(),
        vec![Call::Write(vec![(prop::TIME, time(now))])]
    );
}

#[tokio::test]
async fn reset_counters_zeroes_the_answered_ones_then_reads_them() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    assert_eq!(
        bench.device.reset_counters().await,
        Ok(MobileManagementOutcome::Done),
        "nothing read, nothing to reset"
    );
    assert!(fetches(&bench.script.asked()).len() == 1);
    bench
        .script
        .refuse(prop::STAT_RX_BAD_CRC, Some(Status::PROP_NOT_FOUND.0));
    bench
        .device
        .refresh_category(UlcpManageCategory::Statistics)
        .await
        .unwrap();
    let statistics = |bench: &Bench| {
        bench
            .snapshot()
            .readings
            .into_iter()
            .find(|reading| reading.category == UlcpManageCategory::Statistics)
            .unwrap()
    };
    assert!(
        statistics(&bench).can_reset_counters,
        "the gate is published"
    );
    bench.script.clear_asked();
    assert_eq!(
        bench.device.reset_counters().await,
        Ok(MobileManagementOutcome::Done)
    );
    let asked = bench.script.asked();
    let Call::Write(writes) = &asked[0] else {
        panic!("not a write: {asked:?}");
    };
    let written: Vec<u32> = writes.iter().map(|(property, _)| *property).collect();
    assert!(written.contains(&prop::STAT_TX_PACKETS));
    assert!(!written.contains(&prop::STAT_RX_BAD_CRC));
    assert!(!written.contains(&prop::UPTIME));
    assert!(
        matches!(asked[1], Call::Fetch { .. }),
        "read again: {asked:?}"
    );
    assert_eq!(asked.len(), 2, "never saved");

    bench.script.clear_asked();
    bench.script.fail_next(Stop::Problem(Problem::NoAnswer));
    assert_eq!(
        bench.device.reset_counters().await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::NoAnswer
        })
    );
    assert_eq!(bench.script.asked().len(), 1, "not read again unanswered");

    // A refused counter still has the accepted ones read again; the
    // refusal is the answer.
    bench
        .script
        .refuse(prop::STAT_TX_PACKETS, Some(Status::INVALID_ARGUMENT.0));
    bench.script.clear_asked();
    assert_eq!(
        bench.device.reset_counters().await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::NotAllApplied { saving: false }
        })
    );
    let asked = bench.script.asked();
    assert!(matches!(asked[0], Call::Write(_)), "{asked:?}");
    assert!(
        matches!(asked[1], Call::Fetch { .. }),
        "read again: {asked:?}"
    );
    assert_eq!(asked.len(), 2, "never saved");
}

// MARK: Actions

#[tokio::test]
async fn the_alert_is_the_echo_or_the_request() {
    let bench = Bench::new(COMPANION).await;
    bench
        .device
        .set_alert(UlcpAlertState::Locate)
        .await
        .unwrap();
    assert_eq!(bench.snapshot().alert, UlcpAlertState::Locate);

    let mesh = Bench::new(MESH).await;
    mesh.script.echo_alert();
    mesh.device.set_alert(UlcpAlertState::Locate).await.unwrap();
    assert_eq!(mesh.snapshot().alert, UlcpAlertState::Locate);
    assert_eq!(
        mesh.script.asked(),
        vec![Call::SetAlert(UlcpAlertState::Locate)]
    );
}

#[tokio::test]
async fn firmware_update_entry_answers_by_status() {
    for (status, expected) in [
        (Some(0), MobileManagementOutcome::Done),
        (
            Some(2),
            MobileManagementOutcome::Failed {
                problem: Problem::DfuUnsupported,
            },
        ),
        (
            Some(5),
            MobileManagementOutcome::Failed {
                problem: Problem::DfuUnsupported,
            },
        ),
        (
            Some(4),
            MobileManagementOutcome::Failed {
                problem: Problem::DfuRefused { status: 4 },
            },
        ),
        (
            None,
            MobileManagementOutcome::Failed {
                problem: Problem::DfuUnconfirmed,
            },
        ),
    ] {
        let bench = Bench::new(MESH).await;
        bench.script.answer_dfu(status);
        assert_eq!(
            bench.device.enter_dfu(UlcpDfuMode::Ble).await,
            Ok(expected.clone()),
            "{status:?}"
        );
        assert_eq!(
            bench.snapshot().entered_dfu,
            expected == MobileManagementOutcome::Done
        );
    }
    // A device on its way into its bootloader may not answer: an exchange
    // that heard nothing readable is unconfirmed; any other failure is
    // itself.
    for (failure, expected) in [
        (Problem::NoAnswer, Problem::DfuUnconfirmed),
        (Problem::Unreachable, Problem::DfuUnconfirmed),
        (Problem::Unreadable, Problem::DfuUnconfirmed),
        (Problem::NoRadio, Problem::NoRadio),
    ] {
        let bench = Bench::new(MESH).await;
        bench.script.answer_dfu(Some(0));
        bench.script.fail_next(Stop::Problem(failure.clone()));
        assert_eq!(
            bench.device.enter_dfu(UlcpDfuMode::Ble).await,
            Ok(MobileManagementOutcome::Failed { problem: expected }),
            "{failure:?}"
        );
        assert!(!bench.snapshot().entered_dfu);
    }
}

#[tokio::test]
async fn a_restart_drops_the_sensors() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Sensors)
        .await
        .unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Time)
        .await
        .unwrap();
    assert_eq!(
        bench.device.restart().await,
        Ok(MobileManagementOutcome::Done)
    );
    let snapshot = bench.snapshot();
    assert!(reading(&snapshot, UlcpManageCategory::Sensors).is_none());
    assert!(reading(&snapshot, UlcpManageCategory::Time).is_some());
    assert_eq!(
        bench.script.asked().last(),
        Some(&Call::Reset(MobileMeshResetScope::Reboot))
    );
}

#[tokio::test]
async fn an_announcement_reaches_as_far_as_asked() {
    let bench = Bench::new(MESH).await;
    for (reach, hops) in [
        (MobileAnnouncementReach::Nearby, 0),
        (MobileAnnouncementReach::Mesh, 5),
    ] {
        bench
            .device
            .announce(MobileAnnouncementKind::Beacon, reach)
            .await
            .unwrap();
        let Some(Call::Announce(request)) = bench.script.asked().last().cloned() else {
            panic!("no announcement");
        };
        assert_eq!(request.flood_hops, hops);
        assert_eq!(request.kind, MobileAnnouncementKind::Beacon);
        assert_eq!(request.full_source, None);
        assert_eq!(request.channel_identifier, None);
    }
}

#[tokio::test]
async fn a_factory_reset_forgets_the_cache_even_when_it_fails() {
    let bench = Bench::new(COMPANION).await;
    bench.device.load_card().await.unwrap();
    assert!(
        bench
            .core
            .store
            .management_card(bench.owner.clone(), bench.address.clone())
            .unwrap()
            .is_some()
    );
    bench.script.fail_next(Stop::Problem(Problem::NoAnswer));
    assert_eq!(
        bench.device.factory_reset().await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::NoAnswer
        })
    );
    assert_eq!(
        bench
            .core
            .store
            .management_card(bench.owner.clone(), bench.address.clone())
            .unwrap(),
        None
    );
    assert_eq!(bench.snapshot().card, None);

    let mesh = Bench::new(MESH).await;
    assert_eq!(
        mesh.device.factory_reset().await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::InvalidRequest
        })
    );
    assert!(mesh.script.asked().is_empty());
}

#[tokio::test]
async fn a_factory_reset_never_sent_keeps_the_cache() {
    let bench = Bench::new(COMPANION).await;
    bench.device.load_card().await.unwrap();
    bench.script.clear_asked();
    bench.script.hold();
    let (read, reset, ()) = tokio::join!(
        bench.device.refresh_category(UlcpManageCategory::Identity),
        async {
            bench.asked(1).await;
            bench.device.factory_reset().await
        },
        async {
            bench.asked(1).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            bench.device.cancel();
        },
    );
    assert_eq!(read, Ok(MobileManagementOutcome::Cancelled));
    assert_eq!(reset, Ok(MobileManagementOutcome::Cancelled));
    assert_eq!(bench.script.asked().len(), 1, "the reset was never sent");
    assert!(
        bench
            .core
            .store
            .management_card(bench.owner.clone(), bench.address.clone())
            .unwrap()
            .is_some()
    );
    assert!(bench.snapshot().card.is_some());
}

#[tokio::test]
async fn forgetting_the_cache_keeps_the_phone_key_and_freshness() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench
        .device
        .refresh_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    assert_eq!(
        bench.device.forget_cache().await,
        Ok(MobileManagementOutcome::Done)
    );
    let snapshot = bench.snapshot();
    assert_eq!(snapshot.card, None);
    assert!(snapshot.readings.is_empty());
    assert!(snapshot.card_is_fresh);
    assert_eq!(snapshot.phone_node_key, Some(vec![7; 32]));
    assert!(
        bench
            .core
            .store
            .cached_properties(
                bench.owner.clone(),
                bench.address.clone(),
                vec![prop::DEV_NAME]
            )
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn the_offered_categories_follow_the_card() {
    let bench = Bench::new(MESH).await;
    assert!(bench.snapshot().categories.is_empty());
    bench.device.load_card().await.unwrap();
    let categories: Vec<UlcpManageCategory> = bench
        .snapshot()
        .categories
        .iter()
        .map(|offered| offered.category)
        .collect();
    // In the suggested order, sensors before the radio, peers last.
    let order = |category| categories.iter().position(|held| *held == category);
    assert!(order(UlcpManageCategory::Sensors) < order(UlcpManageCategory::Statistics));
    assert!(order(UlcpManageCategory::Statistics) < order(UlcpManageCategory::Identity));
    assert!(order(UlcpManageCategory::Identity) < order(UlcpManageCategory::Time));
    assert!(order(UlcpManageCategory::Time).is_some());
    assert!(!categories.contains(&UlcpManageCategory::Power));
    for offered in bench.snapshot().categories {
        assert_eq!(
            Ok(offered.property_ids),
            crate::ulcp::ulcp_category_properties(
                offered.category,
                device_values("1.0")[&prop::CAPS].clone()
            )
        );
    }
}

#[tokio::test]
async fn every_change_is_named_in_the_core_changes() {
    let bench = Bench::new(MESH).await;
    bench.core.core.poll_changes();
    let before = bench.snapshot().revision;
    bench.device.load_card().await.unwrap();
    assert!(bench.snapshot().revision > before);
    let changes = bench.core.core.poll_changes();
    assert_eq!(changes.managed_devices, vec![bench.device.id()]);
}

#[tokio::test]
async fn an_erase_ends_what_is_queued_and_retires_the_device() {
    let bench = Bench::new(MESH).await;
    bench.device.load_card().await.unwrap();
    bench.script.hold();
    let (read, erased) = tokio::join!(
        bench.device.refresh_category(UlcpManageCategory::Identity),
        async {
            bench.asked(2).await;
            bench.core.core.erase(false).await
        },
    );
    assert_eq!(erased, Ok(()));
    assert_eq!(read, Err(MobileAppError::Busy));
    assert_eq!(
        bench.device.load_card().await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::NoOwner
        })
    );
    assert_eq!(
        bench.device.forget_cache().await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::NoOwner
        }),
        "a forget that never ran says so"
    );
}
