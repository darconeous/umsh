//! Key tables, against a scripted device.

use std::future::Future;
use std::time::Duration;

use umsh_ulcp::Status;
use umsh_ulcp::ids::prop;

use super::script::{Call, PHONE_NODE_KEY};
use super::{Bench, key, reading};
use crate::app_core::MobileAppError;
use crate::app_core::manage::records::{
    MobileKeyEntryRecord, MobileKeyTable, MobileKeyTableRecord, MobileManagementLink,
    MobileManagementOutcome, MobileManagementProblem as Problem, MobilePropertyState,
};
use crate::app_core::manage::refusal::classify;
use crate::ulcp::UlcpManageCategory;

const MESH: MobileManagementLink = MobileManagementLink::Mesh;
const COMPANION: MobileManagementLink = MobileManagementLink::Companion;

/// Open the bench's device and read its key tables.
async fn opened(bench: &Bench) {
    bench.device.load_card().await.unwrap();
    assert_eq!(
        bench
            .device
            .refresh_category(UlcpManageCategory::PeerNodes)
            .await,
        Ok(MobileManagementOutcome::Done)
    );
    bench.script.clear_asked();
}

fn edit(table: MobileKeyTable, byte: u8, present: bool) -> Call {
    Call::TableEdit {
        table,
        key: key(byte),
        present,
    }
}

#[tokio::test]
async fn the_tables_show_what_may_be_taken_out() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let snapshot = bench.snapshot();
    assert_eq!(
        snapshot.administrators,
        Some(MobileKeyTableRecord {
            entries: vec![
                MobileKeyEntryRecord {
                    key: PHONE_NODE_KEY.to_vec(),
                    is_this_phone: true,
                    removable: false,
                },
                MobileKeyEntryRecord {
                    key: key(0xa1),
                    is_this_phone: false,
                    removable: true,
                },
            ]
        })
    );
    assert_eq!(
        snapshot.peers,
        Some(MobileKeyTableRecord {
            entries: vec![MobileKeyEntryRecord {
                key: key(0xb1),
                is_this_phone: false,
                removable: true,
            }]
        })
    );
}

#[tokio::test]
async fn removals_go_first_and_the_mesh_saves_once() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    assert_eq!(
        bench
            .device
            .set_keys(MobileKeyTable::Peers, vec![key(0xc1), key(0xc2), key(0xc1)])
            .await,
        Ok(MobileManagementOutcome::Done)
    );
    assert_eq!(
        bench.script.asked(),
        vec![
            edit(MobileKeyTable::Peers, 0xb1, false),
            edit(MobileKeyTable::Peers, 0xc1, true),
            edit(MobileKeyTable::Peers, 0xc2, true),
            Call::Save,
        ]
    );
    // The table is what was asked, sorted, without reading it back.
    let expected = [key(0xc1), key(0xc2)].concat();
    let snapshot = bench.snapshot();
    let peers = reading(&snapshot, UlcpManageCategory::PeerNodes).unwrap();
    assert_eq!(
        peers.properties.dev_peer_keys,
        Some(vec![key(0xc1), key(0xc2)])
    );
    assert!(peers.is_fresh);
    assert_eq!(
        bench
            .core
            .store
            .cached_properties(
                bench.owner.clone(),
                bench.address.clone(),
                vec![prop::DEV_PEERS]
            )
            .unwrap()[&prop::DEV_PEERS]
            .value,
        expected
    );
}

#[tokio::test]
async fn a_local_link_saves_behind_each_edit_itself() {
    let bench = Bench::station_with(COMPANION, Some(PHONE_NODE_KEY.to_vec()), true).await;
    opened(&bench).await;
    assert_eq!(
        bench
            .device
            .set_keys(
                MobileKeyTable::Administrators,
                vec![PHONE_NODE_KEY.to_vec(), key(0xa2)],
            )
            .await,
        Ok(MobileManagementOutcome::Done)
    );
    assert_eq!(
        bench.script.asked(),
        vec![
            edit(MobileKeyTable::Administrators, 0xa1, false),
            edit(MobileKeyTable::Administrators, 0xa2, true),
        ],
        "no save follows"
    );
}

#[tokio::test]
async fn the_first_failed_edit_stops_the_rest() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let before = bench.snapshot();
    bench.script.refuse_edit(Status::NOMEM.0);
    assert_eq!(
        bench
            .device
            .set_keys(MobileKeyTable::Peers, vec![key(0xc1)])
            .await,
        Ok(MobileManagementOutcome::Failed {
            problem: Problem::Refused {
                refusal: classify(Some(Status::NOMEM.0))
            }
        })
    );
    assert_eq!(
        bench.script.asked(),
        vec![edit(MobileKeyTable::Peers, 0xb1, false)],
        "no addition, no save"
    );
    assert_eq!(
        reading(&bench.snapshot(), UlcpManageCategory::PeerNodes),
        reading(&before, UlcpManageCategory::PeerNodes),
        "nothing read back"
    );
}

#[tokio::test]
async fn equal_tables_are_done_before_the_guard() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let administrators = vec![key(0xa1), PHONE_NODE_KEY.to_vec()];
    assert_eq!(
        bench
            .device
            .set_keys(MobileKeyTable::Administrators, administrators)
            .await,
        Ok(MobileManagementOutcome::Done)
    );
    assert!(bench.script.asked().is_empty());
    assert_eq!(bench.snapshot().problem, None);
}

#[tokio::test]
async fn the_guard_keeps_this_phone_and_the_last_administrator() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    let refused = Ok(MobileManagementOutcome::Failed {
        problem: Problem::InvalidRequest,
    });
    assert_eq!(
        bench
            .device
            .set_keys(MobileKeyTable::Administrators, vec![key(0xa1)])
            .await,
        refused,
        "this phone's own entry"
    );
    assert_eq!(
        bench
            .device
            .set_keys(MobileKeyTable::Administrators, Vec::new())
            .await,
        refused,
        "every administrator"
    );
    assert!(bench.script.asked().is_empty(), "nothing sent");
    assert_eq!(bench.snapshot().problem, Some(Problem::InvalidRequest));
    // Peers have no such guard.
    assert_eq!(
        bench
            .device
            .set_keys(MobileKeyTable::Peers, Vec::new())
            .await,
        Ok(MobileManagementOutcome::Done)
    );
}

#[tokio::test]
async fn with_this_phones_key_unknown_the_guard_keeps_only_the_last() {
    let bench = Bench::station_with(MESH, None, false).await;
    opened(&bench).await;
    assert_eq!(
        bench
            .device
            .set_keys(MobileKeyTable::Administrators, vec![key(0xa1)])
            .await,
        Ok(MobileManagementOutcome::Done)
    );
    assert_eq!(
        bench.script.asked(),
        vec![
            Call::TableEdit {
                table: MobileKeyTable::Administrators,
                key: PHONE_NODE_KEY.to_vec(),
                present: false,
            },
            Call::Save,
        ]
    );
}

#[tokio::test]
async fn a_readback_with_no_reading_makes_one_with_the_categorys_ids() {
    let bench = Bench::station(MESH).await;
    bench.device.load_card().await.unwrap();
    assert!(reading(&bench.snapshot(), UlcpManageCategory::PeerNodes).is_none());
    // Unread, the table is empty: the key is an addition.
    assert_eq!(
        bench
            .device
            .set_keys(MobileKeyTable::Peers, vec![key(0xc1)])
            .await,
        Ok(MobileManagementOutcome::Done)
    );
    let snapshot = bench.snapshot();
    let peers = reading(&snapshot, UlcpManageCategory::PeerNodes).unwrap();
    assert_eq!(peers.property_ids, vec![prop::DEV_PEERS, prop::DEV_ADMINS]);
    assert_eq!(peers.answered, peers.property_ids);
    assert_eq!(
        peers
            .states
            .iter()
            .map(|state| state.state.clone())
            .collect::<Vec<_>>(),
        vec![MobilePropertyState::Present, MobilePropertyState::NotRead]
    );
    assert_eq!(
        snapshot.peers.map(|table| table.entries.len()),
        Some(1),
        "the table the screen shows"
    );
}

/// Run `first` and `second` behind a read the script holds, so both are
/// queued against the same reading before either runs.
async fn queued_behind_a_read<A, B>(
    bench: &Bench,
    first: A,
    second: B,
) -> (MobileManagementOutcome, MobileManagementOutcome)
where
    A: Future<Output = Result<MobileManagementOutcome, MobileAppError>>,
    B: Future<Output = Result<MobileManagementOutcome, MobileAppError>>,
{
    bench.script.hold();
    let (read, first, second, ()) = tokio::join!(
        bench.device.refresh_category(UlcpManageCategory::Identity),
        async {
            bench.asked(1).await;
            first.await
        },
        async {
            bench.asked(1).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            second.await
        },
        async {
            bench.asked(1).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            bench.script.unhold();
        },
    );
    assert_eq!(read, Ok(MobileManagementOutcome::Done));
    (first.unwrap(), second.unwrap())
}

#[tokio::test]
async fn edits_queued_together_all_take() {
    let bench = Bench::station(MESH).await;
    opened(&bench).await;
    // Each asked against the table as it read, [b1].
    let (first, second) = queued_behind_a_read(
        &bench,
        bench
            .device
            .set_keys(MobileKeyTable::Peers, vec![key(0xb1), key(0xc1)]),
        bench
            .device
            .set_keys(MobileKeyTable::Peers, vec![key(0xb1), key(0xc2)]),
    )
    .await;
    assert_eq!(first, MobileManagementOutcome::Done);
    assert_eq!(second, MobileManagementOutcome::Done);
    let asked = bench.script.asked();
    assert_eq!(
        asked[1..],
        [
            edit(MobileKeyTable::Peers, 0xc1, true),
            Call::Save,
            edit(MobileKeyTable::Peers, 0xc2, true),
            Call::Save,
        ],
        "the second does not take out what the first put in"
    );
    let expected = vec![key(0xb1), key(0xc1), key(0xc2)];
    let snapshot = bench.snapshot();
    let peers = reading(&snapshot, UlcpManageCategory::PeerNodes).unwrap();
    assert_eq!(peers.properties.dev_peer_keys, Some(expected.clone()));
    assert_eq!(
        bench
            .core
            .store
            .cached_properties(
                bench.owner.clone(),
                bench.address.clone(),
                vec![prop::DEV_PEERS]
            )
            .unwrap()[&prop::DEV_PEERS]
            .value,
        expected.concat()
    );
}

#[tokio::test]
async fn the_guard_judges_the_table_when_the_edit_runs() {
    // This phone's key unknown: only the last administrator is kept.
    let bench = Bench::station_with(COMPANION, None, true).await;
    opened(&bench).await;
    // Both asked against [phone, a1]; each alone leaves one.
    let (first, second) = queued_behind_a_read(
        &bench,
        bench
            .device
            .set_keys(MobileKeyTable::Administrators, vec![key(0xa1)]),
        bench.device.set_keys(
            MobileKeyTable::Administrators,
            vec![PHONE_NODE_KEY.to_vec()],
        ),
    )
    .await;
    assert_eq!(first, MobileManagementOutcome::Done);
    assert_eq!(
        second,
        MobileManagementOutcome::Failed {
            problem: Problem::InvalidRequest,
        },
        "it would take out the last"
    );
    assert_eq!(
        bench.script.asked()[1..],
        [Call::TableEdit {
            table: MobileKeyTable::Administrators,
            key: PHONE_NODE_KEY.to_vec(),
            present: false,
        }]
    );
    let snapshot = bench.snapshot();
    assert_eq!(
        reading(&snapshot, UlcpManageCategory::PeerNodes)
            .unwrap()
            .properties
            .dev_admin_keys,
        Some(vec![key(0xa1)])
    );
    assert_eq!(snapshot.problem, Some(Problem::InvalidRequest));
}
