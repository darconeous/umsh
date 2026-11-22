//! The core's worker: one thread, a current-thread runtime and a
//! `LocalSet`, where every command, the pipeline, the policy pass and the
//! schedules run as tasks over one [`Worker`].
//!
//! Commands from the object arrive as jobs. Wakes from the mesh session and
//! the radio driver arrive as flags raised from their threads; the pump
//! task takes them in order.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{Notify, mpsc, watch};

use super::channels::ChannelCache;
use super::clock::Clock;
use super::pipeline::PipelineState;
use super::policy::PolicyState;
use super::records::{MobileAppChangesRecord, MobileAppConfigRecord, MobileAppLifecycle};
use super::settings::Settings;
use super::waiters::Waiters;
use super::{MobileAppError, Shared};
use crate::MobileCounterStore;
use crate::mobile_mesh::{MobileMeshSession, MobileMeshWakeListener};
use crate::radio_driver::MobileRadioDriver;
use crate::secret_vault::SecretVault;
use crate::store::MobileAppStore;

/// Work the object hands its worker. It runs as its own task.
pub(super) type Job = Box<dyn FnOnce(Rc<Worker>) -> Pin<Box<dyn Future<Output = ()>>> + Send>;

/// What the session and the driver raise from their own threads.
#[derive(Default)]
pub(super) struct Signals {
    session: AtomicBool,
    driver: AtomicBool,
    wake: Notify,
}

impl Signals {
    fn raise(&self, flag: &AtomicBool) {
        flag.store(true, Ordering::SeqCst);
        self.wake.notify_one();
    }

    pub(super) fn raise_session(&self) {
        self.raise(&self.session);
    }

    pub(super) fn raise_driver(&self) {
        self.raise(&self.driver);
    }
}

/// The session's wake, taken in-process.
pub(super) struct SessionWake(pub(super) Arc<Signals>);

impl MobileMeshWakeListener for SessionWake {
    fn on_update_pending(&self) {
        self.0.raise_session();
    }
}

/// Everything the worker's tasks share. Only the worker's thread touches
/// it; `RefCell` borrows are never held across an await.
pub(super) struct Worker {
    pub(super) store: Arc<MobileAppStore>,
    pub(super) vault: Arc<dyn SecretVault>,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) shared: Arc<Shared>,
    pub(super) config: MobileAppConfigRecord,
    pub(super) signals: Arc<Signals>,
    /// Held by `start`, `erase`, `stop` and `use_radio`, so each runs whole
    /// and in turn.
    pub(super) transitions: tokio::sync::Mutex<()>,
    /// Commands still running.
    in_flight: Rc<watch::Sender<usize>>,
    /// Raised by `stop` when it is done; ends the worker.
    exit: Notify,
    pub(super) session: RefCell<Option<Arc<MobileMeshSession>>>,
    pub(super) counter_store: RefCell<Option<Arc<MobileCounterStore>>>,
    pub(super) driver: RefCell<Option<Arc<MobileRadioDriver>>>,
    pub(super) channels: RefCell<ChannelCache>,
    /// Held by `refresh_channels`, so two never interleave: a command's
    /// registration and its rollback, a removal, and the pass's each run
    /// whole.
    pub(super) channel_refresh: tokio::sync::Mutex<()>,
    pub(super) settings: RefCell<Settings>,
    pub(super) policy: RefCell<PolicyState>,
    pub(super) pipeline: RefCell<PipelineState>,
    pub(super) waiters: RefCell<Waiters>,
    /// Wakes the policy pass task.
    pub(super) policy_wake: Notify,
    /// Wakes the schedules to check whether one is due.
    pub(super) schedule_check: Notify,
    /// Raised when a revocation has no round left to run.
    pub(super) revocation_done: Notify,
    /// Sessions start on virtual time in tests that ask for it.
    #[cfg(test)]
    pub(super) virtual_time: bool,
    #[cfg(test)]
    pub(super) hooks: Arc<TestHooks>,
}

/// Where tests hold the worker up and watch what it pushed.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    /// When set, `start` takes a permit once it is starting, before it
    /// opens anything.
    pub(crate) start_gate: Option<tokio::sync::Semaphore>,
    /// Each name pushed to a session for its group messages, oldest first.
    pub(crate) pushed_names: std::sync::Mutex<Vec<String>>,
}

/// A command counted as running until it drops.
pub(super) struct InFlight(Rc<watch::Sender<usize>>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.send_modify(|count| *count -= 1);
    }
}

impl Worker {
    pub(super) fn lifecycle(&self) -> MobileAppLifecycle {
        self.shared.snapshot().lifecycle
    }

    /// Count a command as running, when the lifecycle takes commands. One
    /// made while starting waits for the start to end, as `stop` does.
    pub(super) async fn begin_command(&self) -> Result<InFlight, MobileAppError> {
        self.start_settled().await;
        match self.lifecycle() {
            MobileAppLifecycle::Running => {
                self.in_flight.send_modify(|count| *count += 1);
                Ok(InFlight(self.in_flight.clone()))
            }
            MobileAppLifecycle::Erasing | MobileAppLifecycle::Stopping => Err(MobileAppError::Busy),
            MobileAppLifecycle::Stopped => Err(MobileAppError::Stopped),
            MobileAppLifecycle::Idle
            | MobileAppLifecycle::Starting
            | MobileAppLifecycle::Failed { .. } => Err(MobileAppError::NotRunning),
        }
    }

    /// Wait out a start under way. `start` holds the transition lock from
    /// before it enters starting until it has left it, so once the lock is
    /// had the start has ended, run or failed.
    pub(super) async fn start_settled(&self) {
        if self.lifecycle() == MobileAppLifecycle::Starting {
            drop(self.transitions.lock().await);
        }
    }

    /// Wait until no command is running.
    pub(super) async fn commands_settled(&self) {
        let mut count = self.in_flight.subscribe();
        let _ = count.wait_for(|count| *count == 0).await;
    }

    /// End the worker once the running task returns.
    pub(super) fn finish(&self) {
        self.exit.notify_one();
    }

    pub(super) fn session(&self) -> Option<Arc<MobileMeshSession>> {
        self.session.borrow().clone()
    }

    pub(super) fn driver(&self) -> Option<Arc<MobileRadioDriver>> {
        self.driver.borrow().clone()
    }

    /// Raise `changes`: flags for what a write moved, which no snapshot
    /// field holds.
    pub(super) fn raise(&self, changes: MobileAppChangesRecord) {
        self.shared.publish(|_| changes);
    }

    /// The owner the core runs for, when one is set.
    pub(super) fn owner(&self) -> Option<String> {
        self.shared.snapshot().owner.clone()
    }

    /// Take what woke the pump, in order: the driver's states first, then
    /// the session's update. The session's waits while the core is not
    /// running, and is taken once it is.
    async fn pump(self: Rc<Self>) {
        loop {
            self.signals.wake.notified().await;
            if self.signals.driver.swap(false, Ordering::SeqCst) {
                self.take_driver_update();
            }
            if self.lifecycle() == MobileAppLifecycle::Running
                && self.signals.session.swap(false, Ordering::SeqCst)
            {
                self.take_session_update();
            }
            // A wake is a chance to send an announcement the phone slept
            // through.
            self.schedule_check.notify_waiters();
        }
    }
}

/// What the worker starts with.
pub(super) struct WorkerParts {
    pub(super) store: Arc<MobileAppStore>,
    pub(super) vault: Arc<dyn SecretVault>,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) shared: Arc<Shared>,
    pub(super) config: MobileAppConfigRecord,
    pub(super) signals: Arc<Signals>,
    #[cfg(test)]
    pub(super) virtual_time: bool,
    #[cfg(test)]
    pub(super) hooks: Arc<TestHooks>,
}

/// Run the worker until `stop` finishes it, or until the object is dropped,
/// which takes the identity down as `stop` does.
pub(super) fn run(
    parts: WorkerParts,
    mut jobs: mpsc::UnboundedReceiver<Job>,
    finished: &watch::Sender<bool>,
) {
    let shared = parts.shared.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build();
    if let Ok(runtime) = runtime {
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async move {
            let worker = Rc::new(Worker {
                store: parts.store,
                vault: parts.vault,
                clock: parts.clock,
                shared: parts.shared,
                config: parts.config,
                signals: parts.signals,
                transitions: tokio::sync::Mutex::new(()),
                in_flight: Rc::new(watch::Sender::new(0)),
                exit: Notify::new(),
                session: RefCell::new(None),
                counter_store: RefCell::new(None),
                driver: RefCell::new(None),
                channels: RefCell::new(ChannelCache::default()),
                channel_refresh: tokio::sync::Mutex::new(()),
                settings: RefCell::new(Settings::default()),
                policy: RefCell::new(PolicyState::default()),
                pipeline: RefCell::new(PipelineState::default()),
                waiters: RefCell::new(Waiters::default()),
                policy_wake: Notify::new(),
                schedule_check: Notify::new(),
                revocation_done: Notify::new(),
                #[cfg(test)]
                virtual_time: parts.virtual_time,
                #[cfg(test)]
                hooks: parts.hooks,
            });
            tokio::task::spawn_local(worker.clone().pump());
            tokio::task::spawn_local(worker.clone().run_policy());
            loop {
                tokio::select! {
                    biased;
                    () = worker.exit.notified() => break,
                    job = jobs.recv() => match job {
                        Some(job) => {
                            tokio::task::spawn_local(job(worker.clone()));
                        }
                        // The object is gone: take the identity down as
                        // `stop` does, without anyone to answer.
                        None => {
                            worker.stop().await;
                            break;
                        }
                    },
                }
            }
            worker.cancel_schedules();
        });
    }
    shared.enter(MobileAppLifecycle::Stopped);
    finished.send_replace(true);
}
