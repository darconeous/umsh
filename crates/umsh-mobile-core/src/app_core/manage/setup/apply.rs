//! A setup's Apply on the device's engine: one queue entry that
//! configures the device, reads it back, edits its administrators, sets
//! its clock and checks what it reports.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use umsh_ulcp::ids::prop;

use super::records::MobileSetupResult;
use super::verify::first_mismatch;
use crate::app_core::manage::engine::{Ended, Engine, clock_now};
use crate::app_core::manage::keys::{KeyTableDiff, apply_key_table};
use crate::app_core::manage::records::MobileKeyTable;
use crate::app_core::manage::refusal::Stop;
use crate::app_core::worker::Worker;
use crate::ulcp::{
    UlcpDeviceConfigRecord, UlcpDevicePropertiesRecord, UlcpSyncRecord, ulcp_dirty_writes,
};

/// What Apply was asked to do, settled when it was tapped.
pub(super) struct Plan {
    /// The whole configuration.
    pub(super) record: UlcpDeviceConfigRecord,
    /// The writes the configuration makes: what the read-back is held to.
    pub(super) writes: Vec<(u32, Vec<u8>)>,
    /// What the read the setup was built on could not answer, where the
    /// configuration holds placeholders: never written, whatever the
    /// device answers by now.
    pub(super) unreadable: Vec<u32>,
    /// The administrator edits the sheet asked for, against the list it
    /// was built on; `None` asks for none.
    pub(super) administrators: Option<KeyTableDiff>,
    /// The list the sheet was built on, for a read-back that has none.
    pub(super) reported_administrators: Vec<Vec<u8>>,
    pub(super) sets_clock: bool,
}

/// How an apply ended, with what the device reported on the way.
pub(super) struct Applied {
    pub(super) result: MobileSetupResult,
    /// The read-back, once the device answered one.
    pub(super) read_back: Option<UlcpSyncRecord>,
    /// The administrator list the edits left, once they all took.
    pub(super) administrators: Option<Vec<Vec<u8>>>,
}

impl Applied {
    fn ended(result: MobileSetupResult) -> Self {
        Self {
            result,
            read_back: None,
            administrators: None,
        }
    }
}

impl Ended for Applied {
    fn from_stop(stop: Stop) -> Self {
        Self::ended(match stop {
            Stop::Cancelled => MobileSetupResult::Cancelled,
            Stop::Skipped => MobileSetupResult::Skipped,
            Stop::Problem(problem) => MobileSetupResult::NotApplied { problem },
        })
    }

    fn is_cancelled(&self) -> bool {
        self.result == MobileSetupResult::Cancelled
    }
}

/// Run `plan` as one entry on `engine`'s queue. Its failures are answered
/// as results, never as the engine's problem; only a stop before anything
/// was sent ends it as a stop. Once the configuration was sent, the
/// engine's readings no longer say what the device holds.
pub(super) async fn apply(worker: &Rc<Worker>, engine: &Rc<Engine>, plan: Plan) -> Applied {
    engine.note("set up a device");
    let sent = Rc::new(Cell::new(false));
    let read_back = Rc::new(RefCell::new(None));
    let administrators = Rc::new(RefCell::new(None));
    let result = {
        let (engine, worker) = (engine.clone(), worker.clone());
        let (sent, read_back, administrators) =
            (sent.clone(), read_back.clone(), administrators.clone());
        engine
            .clone()
            .run(&worker.clone(), true, None, move |operation| async move {
                sent.set(true);
                let carrier = &engine.carrier;
                match carrier
                    .configure_device(
                        &worker,
                        &operation,
                        plan.record.clone(),
                        plan.unreadable.clone(),
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(Stop::Problem(problem)) => {
                        return Ok(MobileSetupResult::NotApplied { problem });
                    }
                    // The pass runs on in the link's session: the device
                    // may hold the configuration, and may have saved it.
                    Err(Stop::Cancelled | Stop::Skipped) => {
                        return Ok(MobileSetupResult::Interrupted { configured: false });
                    }
                }
                let interrupted = MobileSetupResult::Interrupted { configured: true };
                let reported = match carrier.read_back(&worker, &operation).await {
                    Ok(reported) => reported,
                    Err(Stop::Problem(problem)) => {
                        return Ok(MobileSetupResult::NotVerified { problem });
                    }
                    Err(Stop::Cancelled | Stop::Skipped) => return Ok(interrupted),
                };
                *read_back.borrow_mut() = Some(reported.clone());
                if let Some(asked) = &plan.administrators {
                    // The sheet's own edits, made to the list as the device
                    // holds it now: an entry another screen added stays.
                    let current = reported
                        .dev_admin_keys
                        .clone()
                        .unwrap_or_else(|| plan.reported_administrators.clone());
                    let (edits, after) = asked.against(&current);
                    let edited = async {
                        apply_key_table(
                            carrier,
                            &worker,
                            &operation,
                            MobileKeyTable::Administrators,
                            &edits,
                        )
                        .await?;
                        if !edits.is_empty() && !carrier.saves_table_edits() {
                            carrier.save(&worker, &operation).await?;
                        }
                        Ok::<(), Stop>(())
                    };
                    match edited.await {
                        Ok(()) => *administrators.borrow_mut() = Some(after),
                        Err(Stop::Problem(problem)) => {
                            return Ok(MobileSetupResult::AdministratorsNotApplied { problem });
                        }
                        Err(Stop::Cancelled | Stop::Skipped) => return Ok(interrupted),
                    }
                }
                let mut clock_failed = false;
                if plan.sets_clock {
                    // Unsaved: a clock kept for later would be wrong by then.
                    let writes = ulcp_dirty_writes(
                        UlcpDevicePropertiesRecord {
                            time: Some(clock_now(&worker)),
                            ..UlcpDevicePropertiesRecord::default()
                        },
                        vec![prop::TIME],
                    );
                    clock_failed = match writes {
                        Ok(writes) => match carrier.write(&worker, &operation, writes).await {
                            Ok(answers) => answers.iter().any(|answer| answer.value.is_none()),
                            Err(Stop::Problem(_)) => true,
                            Err(Stop::Cancelled | Stop::Skipped) => return Ok(interrupted),
                        },
                        Err(_) => true,
                    };
                }
                Ok(
                    match first_mismatch(&plan.record, &reported, &plan.writes) {
                        Some(setting) => MobileSetupResult::ReportedDifferently { setting },
                        None => MobileSetupResult::Configured { clock_failed },
                    },
                )
            })
            .await
    };
    if sent.get() {
        engine.mark_stale(worker);
    }
    match result {
        Ok(result) => Applied {
            result,
            read_back: read_back.take(),
            administrators: administrators.take(),
        },
        Err(stop) => Applied::from_stop(stop),
    }
}
