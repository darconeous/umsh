//! A setup's Apply over a scripted device: the order of its exchanges,
//! what each failure answers, stops after the configuration was sent, the
//! setup's state across an apply, and the engine it shares with
//! management screens. The rules live in `manage/setup/apply.rs` and
//! `manage/setup/verify.rs`; each test states the rule it checks.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use umsh_ulcp::Status;
use umsh_ulcp::ids::{cap, prop};

use super::script::{Call, PHONE_NODE_KEY, ScriptedCarrier};
use super::setup::{Device, ZONE, companion};
use super::{key, until};
use crate::app_core::MobileAppError;
use crate::app_core::manage::MobileManagedDevice;
use crate::app_core::manage::Retired;
use crate::app_core::manage::records::{
    MobileKeyTable, MobileManagementLink, MobileManagementOutcome,
    MobileManagementProblem as Problem, MobileRefusal, MobileRefusalReason,
};
use crate::app_core::manage::refusal::Stop;
use crate::app_core::manage::setup::{
    MobileDeviceSetup, MobileSetupApplyOutcome, MobileSetupDraft, MobileSetupGoal,
    MobileSetupRadioParameter, MobileSetupResult, MobileSetupSetting, setup_set_radio_parameter,
};
use crate::app_core::test_support::Core;
use crate::ulcp::{UlcpDfuMode, UlcpManageCategory};

use MobileSetupGoal::{Repeater, Tracker};

type Applying = JoinHandle<Result<MobileSetupApplyOutcome, MobileAppError>>;

/// `Device::full()` with what a management screen's card reads.
fn device() -> Device {
    Device::full()
        .with(prop::DEV_VERSION, b"1.0".to_vec())
        .with(prop::DEV_MODEL, b"Soft".to_vec())
}

struct Bench {
    core: Core,
    script: Arc<ScriptedCarrier>,
    setup: Arc<MobileDeviceSetup>,
}

impl Bench {
    /// `goal` on `device`, its profile copied from the phone's radio.
    async fn new(goal: MobileSetupGoal, device: &Device) -> Self {
        let core = Core::new();
        let script =
            ScriptedCarrier::configured(None, device.values(), Some(PHONE_NODE_KEY.to_vec()), true);
        let setup = core
            .core
            .set_up_scripted(script.clone(), goal, Some(companion()), ZONE.to_owned())
            .await
            .unwrap();
        Self {
            core,
            script,
            setup,
        }
    }

    fn draft(&self) -> MobileSetupDraft {
        self.setup.draft().unwrap()
    }

    async fn apply(&self, draft: MobileSetupDraft) -> MobileSetupApplyOutcome {
        self.setup.apply(draft).await.unwrap()
    }

    /// Apply the built draft in a task of its own.
    fn spawn_apply(&self) -> Applying {
        let (setup, draft) = (self.setup.clone(), self.draft());
        tokio::spawn(async move { setup.apply(draft).await })
    }

    /// A management handle on the setup's engine.
    async fn handle(&self) -> Arc<MobileManagedDevice> {
        self.core
            .core
            .manage_scripted(self.script.clone(), MobileManagementLink::Administrative)
            .await
            .unwrap()
    }

    async fn asked(&self, count: usize) {
        until("the device asked", || self.script.asked().len() >= count).await;
    }

    /// Wait until the registered engines' queues hold `count` entries.
    async fn queued(&self, count: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let queued = self
                .core
                .core
                .on_worker(|worker| async move {
                    let engines = worker.managed.borrow().all();
                    Ok(engines
                        .iter()
                        .map(|engine| engine.queue_len())
                        .sum::<usize>())
                })
                .await
                .unwrap();
            if queued >= count {
                return;
            }
            assert!(tokio::time::Instant::now() < deadline, "never queued");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn registered(&self) -> usize {
        self.core
            .core
            .on_worker(|worker| async move { Ok(worker.managed.borrow().len()) })
            .await
            .unwrap()
    }
}

fn is_configure(call: &Call) -> bool {
    matches!(call, Call::Configure(_))
}

fn is_clock(call: &Call) -> bool {
    matches!(call, Call::Write(writes) if writes.len() == 1 && writes[0].0 == prop::TIME)
}

fn edit(key: Vec<u8>, present: bool) -> Call {
    Call::TableEdit {
        table: MobileKeyTable::Administrators,
        key,
        present,
    }
}

// MARK: Order

#[tokio::test]
async fn an_apply_configures_reads_back_edits_then_sets_the_clock() {
    // Configure, read back, edit the administrators (removals first, each
    // half in byte order), then set the clock.
    let bench = Bench::new(Repeater, &device()).await;
    let mut draft = bench.draft();
    draft = bench.setup.remove_administrator(draft, key(0xa1));
    draft = bench.setup.add_administrator(draft, key(0x01));
    let outcome = bench.apply(draft).await;
    assert_eq!(
        outcome.result,
        MobileSetupResult::Configured {
            clock_failed: false
        }
    );
    let asked = bench.script.asked();
    assert_eq!(asked.len(), 6, "{asked:?}");
    assert!(is_configure(&asked[0]));
    assert_eq!(asked[1], Call::ReadBack);
    assert_eq!(asked[2], edit(key(0xa1), false));
    assert_eq!(asked[3], edit(key(0x01), true));
    assert_eq!(asked[4], edit(PHONE_NODE_KEY.to_vec(), true));
    assert!(is_clock(&asked[5]), "no save after the edits");
    let mut held = vec![key(0x01), PHONE_NODE_KEY.to_vec()];
    held.sort();
    assert_eq!(outcome.draft.administrators.reported, held);
    assert_eq!(outcome.draft.administrators.value, held);
    assert_eq!(
        bench.setup.snapshot().last_result,
        Some(outcome.result.clone())
    );
    assert_eq!(bench.setup.snapshot().advertised_role, Some(1));
}

#[tokio::test]
async fn a_tracker_with_no_administrator_edit_makes_none() {
    let bench = Bench::new(Tracker, &device()).await;
    let outcome = bench.apply(bench.draft()).await;
    assert_eq!(
        outcome.result,
        MobileSetupResult::Configured {
            clock_failed: false
        }
    );
    let asked = bench.script.asked();
    assert_eq!(asked.len(), 3, "{asked:?}");
    assert!(is_configure(&asked[0]) && is_clock(&asked[2]));
    // The role the device now names (a tracker's), for Peers.
    assert_eq!(bench.setup.snapshot().advertised_role, Some(3));
}

// MARK: Failures

#[tokio::test]
async fn a_configuration_that_fails_is_not_applied_and_is_not_the_engines_problem() {
    // Each failure that is not a refusal, by problem.
    for problem in [
        Problem::NoAnswer,
        Problem::RadioBusy,
        Problem::Unreadable,
        Problem::NoRadio,
    ] {
        let bench = Bench::new(Tracker, &device()).await;
        let handle = bench.handle().await;
        // A failure the status bar shows, from before the apply.
        bench.script.fail_next(Stop::Problem(Problem::NoAnswer));
        assert!(matches!(
            handle.refresh_card().await,
            Ok(MobileManagementOutcome::Failed { .. })
        ));
        assert_eq!(handle.snapshot().problem, Some(Problem::NoAnswer));
        bench.script.clear_asked();

        bench.script.fail_next(Stop::Problem(problem.clone()));
        let outcome = bench.apply(bench.draft()).await;
        let expected = MobileSetupResult::NotApplied { problem };
        assert_eq!(outcome.result, expected);
        let asked = bench.script.asked();
        assert_eq!(asked.len(), 1, "no read-back, edits or clock: {asked:?}");
        assert_eq!(bench.setup.snapshot().last_result, Some(expected));
        assert!(!bench.setup.snapshot().applying);
        assert_eq!(
            handle.snapshot().problem,
            None,
            "asking again cleared it, and the setup's own failure is not set"
        );
    }
}

#[tokio::test]
async fn placeholders_stay_off_the_wire_once_the_device_answers() {
    // The attach could not read the time-trust policy, so Positioning
    // holds placeholders; the read-back, and every apply after it, can.
    let core = Core::new();
    let script =
        ScriptedCarrier::configured(None, device().values(), Some(PHONE_NODE_KEY.to_vec()), true);
    script.refuse(prop::GNSS_TIME_TRUST, Some(Status::PROP_NOT_FOUND.0));
    let setup = core
        .core
        .set_up_scripted(script.clone(), Tracker, Some(companion()), ZONE.to_owned())
        .await
        .unwrap();
    script.unrefuse(prop::GNSS_TIME_TRUST);
    let bench = Bench {
        core,
        script,
        setup,
    };
    for _ in 0..2 {
        let outcome = bench.apply(bench.draft()).await;
        assert!(
            matches!(outcome.result, MobileSetupResult::Configured { .. }),
            "{:?}",
            outcome.result
        );
    }
    for call in bench.script.asked() {
        if let Call::Configure(writes) = call {
            for (property, _) in writes {
                assert!(
                    ![
                        prop::GNSS_ENABLED,
                        prop::GNSS_IDENT_UPDATE,
                        prop::GNSS_IDENT_PRECISION,
                        prop::GNSS_TIME_TRUST,
                    ]
                    .contains(&property),
                    "{property}"
                );
            }
        }
    }
    assert_eq!(bench.script.value(prop::GNSS_ENABLED), Some(vec![1]));
}

#[tokio::test]
async fn a_read_back_that_fails_leaves_the_configuration_unverified() {
    let bench = Bench::new(Repeater, &device()).await;
    bench
        .script
        .fail_read_back(Stop::Problem(Problem::NoAnswer));
    let outcome = bench.apply(bench.draft()).await;
    assert_eq!(
        outcome.result,
        MobileSetupResult::NotVerified {
            problem: Problem::NoAnswer
        }
    );
    let asked = bench.script.asked();
    assert_eq!(asked.len(), 2, "no edits, no clock: {asked:?}");

    // A device that answers with no configuration is unreadable.
    let bench = Bench::new(Tracker, &device()).await;
    bench.script.answer_read_back_empty();
    assert_eq!(
        bench.apply(bench.draft()).await.result,
        MobileSetupResult::NotVerified {
            problem: Problem::Unreadable
        }
    );
}

#[tokio::test]
async fn an_administrator_edit_refused_stops_the_rest() {
    // A refused administrator edit stops the edits after it and the clock.
    let bench = Bench::new(Repeater, &device()).await;
    let draft = bench.setup.remove_administrator(bench.draft(), key(0xa1));
    bench.script.refuse_edit(Status::NOMEM.0);
    let outcome = bench.apply(draft).await;
    assert_eq!(
        outcome.result,
        MobileSetupResult::AdministratorsNotApplied {
            problem: Problem::Refused {
                refusal: MobileRefusal {
                    reason: MobileRefusalReason::TooLarge,
                    status: Some(Status::NOMEM.0),
                }
            }
        }
    );
    let asked = bench.script.asked();
    assert_eq!(
        asked.len(),
        3,
        "the addition and the clock not sent: {asked:?}"
    );
    assert_eq!(asked[2], edit(key(0xa1), false));
    assert_eq!(
        outcome.draft.administrators.reported,
        vec![key(0xa1)],
        "the list is not taken as applied"
    );
}

#[tokio::test]
async fn a_clock_the_device_refuses_is_reported_and_not_fatal() {
    let bench = Bench::new(Tracker, &device()).await;
    bench
        .script
        .refuse(prop::TIME, Some(Status::INVALID_STATE.0));
    assert_eq!(
        bench.apply(bench.draft()).await.result,
        MobileSetupResult::Configured { clock_failed: true }
    );

    // A device without a clock is not asked to set one.
    let bench = Bench::new(Tracker, &device().without(cap::TIME)).await;
    assert_eq!(
        bench.apply(bench.draft()).await.result,
        MobileSetupResult::Configured {
            clock_failed: false
        }
    );
    assert!(!bench.script.asked().iter().any(is_clock));
}

#[tokio::test]
async fn a_setting_reported_differently_outranks_the_clock() {
    // The clock is still set, and the mismatch wins.
    let bench = Bench::new(Tracker, &device()).await;
    bench
        .script
        .rewrite_on_configure(prop::PHY_LORA_SF, vec![11]);
    bench
        .script
        .refuse(prop::TIME, Some(Status::INVALID_STATE.0));
    assert_eq!(
        bench.apply(bench.draft()).await.result,
        MobileSetupResult::ReportedDifferently {
            setting: MobileSetupSetting::SpreadingFactor
        }
    );
    assert!(bench.script.asked().iter().any(is_clock));
}

// MARK: Stops

#[tokio::test]
async fn a_stop_after_the_configuration_was_sent_is_interrupted() {
    // During the configuration pass: the device may or may not keep it.
    let bench = Bench::new(Tracker, &device()).await;
    let handle = bench.handle().await;
    bench.script.hold();
    let applying = bench.spawn_apply();
    bench.asked(1).await;
    handle.cancel();
    let expected = MobileSetupResult::Interrupted { configured: false };
    assert_eq!(applying.await.unwrap().unwrap().result, expected);
    assert_eq!(bench.setup.snapshot().last_result, Some(expected));
    assert!(!bench.setup.snapshot().applying);

    // During the read-back: saved, but not checked.
    let bench = Bench::new(Tracker, &device()).await;
    let handle = bench.handle().await;
    bench.script.hold();
    let applying = bench.spawn_apply();
    bench.asked(1).await;
    bench.script.pass_one();
    bench.asked(2).await;
    handle.cancel();
    assert_eq!(
        applying.await.unwrap().unwrap().result,
        MobileSetupResult::Interrupted { configured: true }
    );

    // An erase retires the engine: still answered, as a value.
    let bench = Bench::new(Tracker, &device()).await;
    bench.script.hold();
    let applying = bench.spawn_apply();
    bench.asked(1).await;
    bench
        .core
        .core
        .on_worker(|worker| async move {
            worker.retire_managed(Retired::Erased);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        applying.await.unwrap(),
        Ok(MobileSetupApplyOutcome {
            result: MobileSetupResult::Interrupted { configured: false },
            draft: bench.draft(),
        })
    );
}

#[tokio::test]
async fn a_stop_before_anything_was_sent_is_cancelled() {
    let bench = Bench::new(Tracker, &device()).await;
    let handle = bench.handle().await;
    bench.script.hold();
    let writing = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.set_clock_now().await })
    };
    bench.asked(1).await;
    let applying = bench.spawn_apply();
    bench.queued(2).await;
    handle.cancel();
    assert_eq!(
        writing.await.unwrap(),
        Ok(MobileManagementOutcome::Cancelled)
    );
    assert_eq!(
        applying.await.unwrap().unwrap().result,
        MobileSetupResult::Cancelled
    );
    assert_eq!(bench.script.asked().len(), 1, "nothing of the apply sent");
    assert_eq!(
        bench.setup.snapshot().last_result,
        Some(MobileSetupResult::Cancelled)
    );
}

#[tokio::test]
async fn an_apply_on_an_engine_an_erase_retired_answers_busy() {
    // Retired before anything was sent: the retirement's error.
    let bench = Bench::new(Tracker, &device()).await;
    bench
        .core
        .core
        .on_worker(|worker| async move {
            worker.retire_managed(Retired::Erased);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        bench.setup.apply(bench.draft()).await,
        Err(MobileAppError::Busy)
    );
    assert!(bench.script.asked().is_empty(), "nothing sent");
    let snapshot = bench.setup.snapshot();
    assert_eq!(snapshot.last_result, None);
    assert!(!snapshot.applying);
}

// MARK: The setup's state

#[tokio::test]
async fn a_clamped_power_is_the_drafts_and_the_apply_stands_applied() {
    // The device clamps the power; that is not an edit.
    let bench = Bench::new(Tracker, &device()).await;
    bench
        .script
        .rewrite_on_configure(prop::PHY_TX_POWER, vec![20]);
    let draft =
        setup_set_radio_parameter(bench.draft(), MobileSetupRadioParameter::TransmitPower, 30);
    let outcome = bench.apply(draft).await;
    assert_eq!(
        outcome.result,
        MobileSetupResult::Configured {
            clock_failed: false
        }
    );
    assert_eq!(outcome.draft.radio.transmit_power_dbm.value, 20);
    let kept = bench.setup.draft().unwrap();
    assert_eq!(
        kept, outcome.draft,
        "a rebuilt screen gets the outcome's draft"
    );
    assert!(bench.setup.review(kept.clone()).unwrap().applied);
    let mut edited = kept;
    edited.name.text = "Somewhere Else".to_owned();
    assert!(!bench.setup.review(edited).unwrap().applied);
    assert_eq!(
        bench.setup.snapshot().reported.unwrap().transmit_power_dbm,
        20
    );
}

#[tokio::test]
async fn an_apply_outlives_a_release_and_a_dropped_caller() {
    // Released mid-apply: the apply still runs to its end and lands.
    let bench = Bench::new(Tracker, &device()).await;
    bench.script.hold();
    let applying = bench.spawn_apply();
    bench.asked(1).await;
    let clone = bench.setup.clone();
    bench.setup.release();
    bench.script.unhold();
    let expected = MobileSetupResult::Configured {
        clock_failed: false,
    };
    assert_eq!(applying.await.unwrap().unwrap().result, expected);
    assert_eq!(clone.snapshot().last_result, Some(expected.clone()));
    assert!(bench.script.asked()[1] == Call::ReadBack);
    assert_eq!(
        bench.registered().await,
        0,
        "the engine left once its queue emptied"
    );

    // The caller stops waiting: the result still lands.
    let bench = Bench::new(Tracker, &device()).await;
    bench.script.hold();
    let applying = bench.spawn_apply();
    bench.asked(1).await;
    applying.abort();
    let _ = applying.await;
    bench.script.unhold();
    until("the result landed", || {
        bench.setup.snapshot().last_result.is_some()
    })
    .await;
    assert_eq!(bench.setup.snapshot().last_result, Some(expected));
    assert!(!bench.setup.snapshot().applying);
}

#[tokio::test]
async fn only_the_sheets_own_administrator_edits_are_made() {
    // A key another screen added since the sheet was built stays.
    let bench = Bench::new(Repeater, &device()).await;
    bench
        .script
        .set(prop::DEV_ADMINS, [key(0xa1), key(0xc1)].concat());
    let outcome = bench.apply(bench.draft()).await;
    let mut held = vec![key(0xa1), key(0xc1), PHONE_NODE_KEY.to_vec()];
    held.sort();
    assert_eq!(outcome.draft.administrators.value, held);
    assert!(!bench.script.asked().contains(&edit(key(0xc1), false)));

    // A second apply diffs against the first's result: nothing to send.
    bench.script.clear_asked();
    let again = bench.apply(outcome.draft).await;
    assert!(matches!(again.result, MobileSetupResult::Configured { .. }));
    assert!(
        !bench
            .script
            .asked()
            .iter()
            .any(|call| matches!(call, Call::TableEdit { .. }))
    );
}

#[tokio::test]
async fn a_second_apply_waits_for_none() {
    let bench = Bench::new(Tracker, &device()).await;
    bench.script.hold();
    let applying = bench.spawn_apply();
    bench.asked(1).await;
    assert!(bench.setup.snapshot().applying);
    assert_eq!(
        bench.setup.apply(bench.draft()).await,
        Err(MobileAppError::InvalidRequest)
    );
    assert!(!bench.setup.review(bench.draft()).unwrap().can_apply);
    bench.script.unhold();
    applying.await.unwrap().unwrap();
    assert!(bench.setup.review(bench.draft()).unwrap().can_apply);
}

// MARK: The shared engine

#[tokio::test]
async fn a_setup_shares_its_engine_with_management() {
    let bench = Bench::new(Tracker, &device()).await;
    let handle = bench.handle().await;
    assert_eq!(bench.registered().await, 1, "one engine");

    // A management write queued first runs first.
    bench.script.hold();
    let writing = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.set_clock_now().await })
    };
    bench.asked(1).await;
    let applying = bench.spawn_apply();
    bench.script.unhold();
    writing.await.unwrap().unwrap();
    applying.await.unwrap().unwrap();
    let asked = bench.script.asked();
    assert!(is_clock(&asked[0]) && is_configure(&asked[1]), "{asked:?}");

    // An apply leaves the readings stale: the next load reads again.
    handle.load_card().await.unwrap();
    handle
        .load_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    bench.script.clear_asked();
    handle
        .load_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    assert!(bench.script.asked().is_empty(), "fresh: not read again");
    bench.apply(bench.draft()).await;
    assert!(!handle.snapshot().card_is_fresh);
    bench.script.clear_asked();
    handle
        .load_category(UlcpManageCategory::Identity)
        .await
        .unwrap();
    assert!(
        bench
            .script
            .asked()
            .iter()
            .any(|call| matches!(call, Call::Fetch { .. })),
        "stale: read again"
    );

    // Once the device entered firmware update, nothing more is sent.
    bench.script.answer_dfu(Some(Status::OK.0));
    assert_eq!(
        handle.enter_dfu(UlcpDfuMode::Default).await,
        Ok(MobileManagementOutcome::Done)
    );
    bench.script.clear_asked();
    assert_eq!(
        bench.apply(bench.draft()).await.result,
        MobileSetupResult::Skipped
    );
    assert!(bench.script.asked().is_empty());
}

// MARK: Lifecycle and misuse

#[tokio::test]
async fn a_released_setup_takes_nothing_more_and_lets_its_engine_go() {
    let bench = Bench::new(Tracker, &device()).await;
    bench.setup.release();
    bench.setup.release();
    assert_eq!(
        bench.setup.review(bench.draft()),
        Err(MobileAppError::Stopped)
    );
    assert_eq!(
        bench.setup.apply(bench.draft()).await,
        Err(MobileAppError::Stopped)
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while bench.registered().await != 0 {
        assert!(tokio::time::Instant::now() < deadline, "the engine stayed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn a_refused_device_has_no_draft_and_applies_nothing() {
    let bench = Bench::new(Repeater, &device().without(cap::REPEATER)).await;
    assert_eq!(bench.setup.draft(), None);
    let snapshot = bench.setup.snapshot();
    assert!(snapshot.refusal.is_some() && snapshot.sections.is_empty());
    let draft = Bench::new(Tracker, &device()).await.draft();
    assert_eq!(
        bench.setup.review(draft.clone()),
        Err(MobileAppError::InvalidRequest)
    );
    assert_eq!(
        bench.setup.apply(draft).await.unwrap().result,
        MobileSetupResult::Invalid
    );
    assert!(bench.script.asked().is_empty());
}

#[tokio::test]
async fn a_draft_review_refuses_is_not_sent() {
    // A draft review refuses is answered Invalid, and nothing is sent.
    let bench = Bench::new(Tracker, &device()).await;
    let mut draft = bench.draft();
    draft.radio.frequency_khz.value = 0;
    let outcome = bench.apply(draft.clone()).await;
    assert_eq!(outcome.result, MobileSetupResult::Invalid);
    assert_eq!(outcome.draft, draft);
    assert!(bench.script.asked().is_empty());
    assert_eq!(bench.setup.snapshot().last_result, None);
}

#[tokio::test]
async fn a_zone_rule_no_device_accepts_is_a_mistake() {
    let core = Core::new();
    let script = ScriptedCarrier::configured(None, device().values(), None, true);
    assert_eq!(
        core.core
            .set_up_scripted(script, Tracker, None, "Not a rule".to_owned())
            .await
            .err(),
        Some(MobileAppError::InvalidRequest)
    );
}
