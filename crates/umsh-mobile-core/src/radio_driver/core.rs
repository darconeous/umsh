//! The driver's logic: a synchronous state machine. An event and the time
//! go in; effects come out, and the core names its next deadline. No
//! threads, no timers, no I/O, so every deadline and budget here is tested
//! with an explicit clock.
//!
//! Callers waiting on an operation hold the receiving end of a oneshot;
//! the core resolves the sending end. Everything else it wants done—link
//! calls, mesh session calls, publications—it returns as [`Effect`]s, in
//! the order they must happen.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Arc;

use tokio::sync::oneshot;

use super::{
    MobileRadioClockRecord, MobileRadioError, MobileRadioPhase, MobileRadioProblem,
    MobileRadioStateRecord, MobileRadioTransportPhase, MobileRadioTransportStateRecord,
};
use crate::ulcp::{
    UlcpLocalManagementEventRecord, UlcpOperationErrorRecord, UlcpOperationFailureKind,
    UlcpPropertyPushRecord, UlcpRawTransmitDisposition, UlcpRawTransmitResultRecord,
};
use crate::{
    MobileError, MobileMeshOutboundFrameRecord, MobileMeshRxRecord, MobileUlcpSession,
    UlcpHostOwnership, UlcpRadioSettingsRecord, UlcpReceivedFrameRecord, UlcpSessionPhase,
    UlcpSessionUpdateRecord, describe_ulcp_frame,
};

/// The length of a radio's device key: an Ed25519 public key.
const DEVICE_KEY_LENGTH: usize = 32;

/// Busy answers one raw transmit may get before it is given up.
pub(crate) const MAXIMUM_RAW_TRANSMIT_BUSY_RETRIES: u32 = 20;
/// How long a busy raw transmit waits before it is tried again.
pub(crate) const RAW_TRANSMIT_BUSY_RETRY_MS: u64 = 100;
/// Raw transmits handed to the radio at once.
///
/// The mobile MAC needs the radio's physical transmit completion before it
/// starts its ack clock. A larger window is unsafe until the radio itself
/// owns the inter-frame receive and ack window.
pub(crate) const MAXIMUM_RAW_TRANSMITS_IN_FLIGHT: usize = 1;
/// Budget for one frame's physical transmission, from handing it to the
/// radio to the radio saying what became of it.
///
/// Generous beside the worst legitimate case—a maximum-size frame at the
/// slowest spreading factor, after the radio's channel-activity backoff—
/// because expiring early fails a send that would have succeeded. It
/// exists because the MAC awaits this completion holding its coordinator:
/// a radio that takes a frame and never reports it would park every later
/// send behind it for as long as the link stays up. The deadline bounds
/// that to one frame, loudly.
pub(crate) const RAW_TRANSMIT_TIMEOUT_MS: u64 = 30_000;
/// How long a control exchange may go unanswered before the session is
/// judged stalled.
pub(crate) const CONTROL_DEADLINE_MS: u64 = 8_000;
/// How long a release waits for the radio to confirm it let go of this
/// phone's host key. The disconnect goes ahead either way.
pub(crate) const HOST_RELEASE_TIMEOUT_MS: u64 = 2_000;
/// Reconnects a fatal protocol fault is worth before the failure sticks.
///
/// Most such faults are one bad frame—a corrupted segment, an answer that
/// arrived after its transaction was retired—and the link comes back
/// clean. A radio whose firmware genuinely disagrees with this app fails
/// the same way every time, so the budget is small: reconnecting past it
/// only hides the disagreement behind more teardowns.
pub(crate) const FATAL_FAULT_RETRY_BUDGET: u8 = 2;
/// How long an attach must hold before a fault after it gets a fresh
/// budget. Below this the attach is part of the failure rather than proof
/// against it: a radio that attaches and at once faults would otherwise
/// refill its budget every cycle and never give up.
pub(crate) const FATAL_FAULT_BUDGET_REFILL_MS: u64 = 60_000;
/// Frames received before a mesh session exists, kept newest first for it.
/// What falls off is ordinary radio loss to the protocol's repair path.
pub(crate) const MAXIMUM_FRAMES_AWAITING_MESH_SESSION: usize = 32;
/// How long a mesh frame is worth transmitting, from when the driver took
/// it. The mesh session stops waiting for a frame's result after this
/// long and counts it failed, so sending it later would put on the air
/// what the MAC has already given up on.
pub(crate) const MESH_FRAME_LIFETIME_MS: u64 =
    crate::mobile_mesh::TRANSMIT_COMPLETION_TIMEOUT.as_millis() as u64;

/// The time an event happens at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Now {
    /// A monotonic clock, for deadlines. A wall-clock change must not
    /// decide whether a deadline passed.
    pub(crate) monotonic_ms: u64,
    /// Milliseconds since the Unix epoch, for stamping readings.
    pub(crate) wall_ms: u64,
}

/// Where a caller waits for an operation's outcome.
pub(crate) type Reply<T> = oneshot::Sender<Result<T, MobileRadioError>>;

/// One call into the ULCP session that starts an operation.
pub(crate) type SessionCall =
    Box<dyn FnOnce(&MobileUlcpSession) -> Result<UlcpSessionUpdateRecord, MobileError> + Send>;

/// Something that happened, for the core to act on.
pub(crate) enum Event {
    /// The transport carries no frames, and stands here.
    Transport(MobileRadioTransportStateRecord),
    /// The transport carries frames now. `bound_radio` says whether the
    /// radio on the other end is the one the app is bound to.
    LinkReady {
        bound_radio: bool,
    },
    /// One complete ULCP frame arrived.
    LinkReceived(Vec<u8>),
    /// Writes carrying these raw transmits failed while the link stayed
    /// up.
    LinkWritesFailed {
        raw_transaction_ids: Vec<u8>,
        problem: MobileRadioProblem,
    },
    /// The transport found the link unusable on its own account.
    LinkFault(MobileRadioProblem),
    /// The transport failed at something without losing the link.
    ReportProblem(MobileRadioProblem),
    /// A deliberate new attempt: the fault budget starts over.
    ResetRecoveryBudget,
    /// This phone's host key, once the identity is unlocked.
    HostKey(Option<[u8; 32]>),
    /// The mesh session is about to be replaced or removed.
    MeshSessionLeaving,
    /// A mesh session is in place.
    MeshSessionArrived,
    /// Frames the mesh session wants transmitted.
    MeshOutbound(Vec<MobileMeshOutboundFrameRecord>),
    Command(Command),
}

/// A request from the app.
pub(crate) enum Command {
    /// Read the radio's state anew. Joins a read already running.
    Refresh {
        call: SessionCall,
        reply: Reply<MobileRadioStateRecord>,
    },
    /// Change the radio's configuration; done when the radio confirms.
    Configure { call: SessionCall, reply: Reply<()> },
    /// Edit one of the radio's key tables, or its host domain.
    DeviceTable {
        requires_device_identity: bool,
        call: SessionCall,
        reply: Reply<()>,
    },
    /// Send a command the radio acts on without an exchange: done once
    /// sent. `abandon_binding` drops the app's binding to the radio
    /// afterwards, for a radio about to erase itself.
    Immediate {
        call: SessionCall,
        abandon_binding: bool,
        reply: Reply<()>,
    },
    /// One local management exchange, answered by the event that ends it.
    LocalManagement {
        dfu: bool,
        call: SessionCall,
        reply: Reply<UlcpLocalManagementEventRecord>,
    },
    /// Write this phone's host key into the radio.
    Claim { reply: Reply<()> },
    /// Clear this phone's host key from the radio before letting it go.
    ReleaseHost { reply: oneshot::Sender<()> },
}

/// What the core wants done, in order.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Effect {
    /// Queue one complete ULCP frame on the link.
    Send {
        frame: Vec<u8>,
        raw_transaction_id: Option<u8>,
    },
    /// Discard partly framed input and anything queued to send.
    ResetFraming,
    /// Tear the link down. `retry` says whether the core would spend a
    /// reconnect on it.
    Invalidate {
        retry: bool,
    },
    /// The radio attached: the transport may remember it.
    DidAttach,
    /// The bound radio reported its own name.
    DidReportName(String),
    /// The radio is erasing itself: drop the binding, keep the link.
    AbandonBinding,
    /// The radio confirmed DFU entry: stop reconnecting to it.
    DidEnterDfu,
    /// Hand a received frame to the mesh session.
    MeshReceive(MobileMeshRxRecord),
    /// Report a mesh frame's physical transmit result.
    MeshComplete {
        frame_id: u64,
        transmitted: bool,
    },
    /// Fail every frame the mesh session is waiting on.
    MeshFailOutbound,
    /// The longest frame's airtime at the radio's settings.
    MeshFrameTime(u32),
    /// The radio's state changed.
    State(Box<MobileRadioStateRecord>),
    Received(UlcpReceivedFrameRecord),
    Pushed(UlcpPropertyPushRecord),
    HostReleased(Vec<u8>),
    Diagnostic(String),
}

/// One mesh frame on its way to the radio.
#[derive(Clone, Debug)]
struct MeshFrame {
    id: u64,
    data: Vec<u8>,
    /// Transmit without the radio's channel-activity check: an immediate
    /// ack.
    nocca: bool,
    power_dbm: Option<i8>,
    /// Which mesh session the frame came from, so a completion never
    /// reaches the one that replaced it.
    session: u64,
    /// When the driver took the frame, for [`MESH_FRAME_LIFETIME_MS`].
    taken_at_ms: u64,
    busy_retries: u32,
}

impl MeshFrame {
    /// Whether the mesh session has stopped waiting on this frame.
    fn expired(&self, now: Now) -> bool {
        now.monotonic_ms.saturating_sub(self.taken_at_ms) >= MESH_FRAME_LIFETIME_MS
    }
}

/// What a transport's report says became of the teardown a fault asked
/// for.
enum Teardown {
    /// Still coming down: an offered reconnect may yet happen.
    Underway,
    /// Over, with nothing following it.
    Rested,
    /// The transport is bringing the link back.
    Reconnecting,
    /// The transport has a failure of its own to show instead.
    Superseded,
}

impl Teardown {
    fn of(report: &MobileRadioTransportStateRecord) -> Self {
        use MobileRadioTransportPhase as Phase;
        match report.phase {
            Phase::Disconnecting => Self::Underway,
            Phase::Idle => Self::Rested,
            // A failure the transport does not explain is the fault's own.
            Phase::Failed if report.problem.is_none() => Self::Rested,
            Phase::Failed | Phase::Unavailable => Self::Superseded,
            Phase::Scanning
            | Phase::Discovered
            | Phase::Connecting
            | Phase::Pairing
            | Phase::Attaching
            | Phase::Reconnecting
            | Phase::WaitingForRadio => Self::Reconnecting,
        }
    }
}

struct InFlight {
    frame: MeshFrame,
    deadline_ms: u64,
}

/// A fatal fault on its way to settling: the link has been invalidated,
/// and the transport's next report decides what the user sees.
struct Fault {
    problem: MobileRadioProblem,
    /// The core offered a reconnect, which it spends if the transport
    /// takes it.
    retry_offered: bool,
    /// The transport reported a resting state, so the failure stands
    /// until something new begins.
    settled: bool,
}

struct HostRelease {
    waiters: Vec<oneshot::Sender<()>>,
    /// The radio being released, announced when it confirms.
    device_key: Option<Vec<u8>>,
    deadline_ms: u64,
}

struct LocalManagement {
    reply: Reply<UlcpLocalManagementEventRecord>,
    dfu: bool,
}

/// Work an update asks for that itself applies an update. It runs once the
/// update that asked has been applied in full, and before the state is
/// published, so one update is never applied inside another.
enum Deferred {
    AutoEnable {
        generation: u64,
        settings: UlcpRadioSettingsRecord,
    },
    RestartForHostKey {
        generation: u64,
    },
    AutoClaim {
        generation: u64,
    },
    PumpRawTransmits {
        generation: u64,
    },
}

/// Why an update could not be applied.
enum ApplyError {
    LinkDown,
    DeviceKey,
    UnknownRawTransaction(u8),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LinkDown => formatter.write_str("the link is down"),
            Self::DeviceKey => formatter.write_str("a device key of the wrong length"),
            Self::UnknownRawTransaction(id) => {
                write!(
                    formatter,
                    "raw transmit result for unknown transaction {id}"
                )
            }
        }
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(cause) => write!(formatter, "{cause}"),
            Self::Apply(error) => write!(formatter, "{error}"),
        }
    }
}

impl ApplyError {
    fn for_caller(&self) -> MobileRadioError {
        match self {
            Self::LinkDown => MobileRadioError::RadioUnavailable,
            Self::DeviceKey | Self::UnknownRawTransaction(_) => {
                MobileRadioError::IncompatibleProtocol
            }
        }
    }
}

/// A session call that failed, or whose update could not be applied.
enum CallError {
    Session(MobileError),
    Apply(ApplyError),
}

impl CallError {
    fn for_caller(&self) -> MobileRadioError {
        match self {
            Self::Session(cause) => MobileRadioError::Refused { error: *cause },
            Self::Apply(error) => error.for_caller(),
        }
    }
}

pub(crate) struct DriverCore {
    session: Arc<MobileUlcpSession>,
    /// The state as it stands; published when it differs from `published`.
    state: MobileRadioStateRecord,
    published: MobileRadioStateRecord,
    /// The transport's latest report, for its name and identifier.
    transport: MobileRadioTransportStateRecord,
    link_up: bool,
    bound_radio: bool,
    /// Bumped whenever the link comes up or goes down. Deferred work
    /// carries the value it was armed under, so work armed against one
    /// link never acts on the next.
    generation: u64,
    host_key: Option<[u8; 32]>,
    fault_retries_remaining: u8,
    /// When the current attach began, for the budget refill.
    attached_at_ms: Option<u64>,
    fault: Option<Fault>,
    /// The name last reported to the transport, so it hears each once.
    reported_name: Option<String>,
    /// The generation `DidAttach` was last sent for.
    attach_announced: Option<u64>,

    refresh_in_progress: bool,
    refresh_waiters: Vec<Reply<MobileRadioStateRecord>>,
    configuration: Option<Reply<()>>,
    device_table: Option<Reply<()>>,
    local_management: Option<LocalManagement>,
    host_release: Option<HostRelease>,

    /// Each outstanding control transaction keeps the deadline it was
    /// given when first seen; unsolicited traffic and raw transmits
    /// cannot extend it.
    control_deadlines: BTreeMap<u8, u64>,

    /// Mesh frames taken while the radio could not carry them. They wait
    /// for the next attach, as they would have in the mesh session's own
    /// queue.
    backlog: VecDeque<MeshFrame>,
    /// Mesh frames for the radio as it is now.
    pending_raw: VecDeque<MeshFrame>,
    in_flight: BTreeMap<u8, InFlight>,
    /// Transactions the watchdog gave up on. A radio answering after the
    /// deadline is late, not wrong.
    abandoned_raw: HashSet<u8>,
    /// When a busy raw transmit is to be tried again, and under which
    /// generation.
    raw_retry: Option<(u64, u64)>,

    auto_enable_generation: Option<u64>,
    auto_claim_generation: Option<u64>,
    host_key_restart_generation: Option<u64>,

    /// Which mesh session is in place, when one is.
    mesh_session: Option<u64>,
    next_mesh_session: u64,
    frames_awaiting_mesh_session: VecDeque<MobileMeshRxRecord>,
    frame_time_ms: Option<u32>,

    deferred: VecDeque<Deferred>,
    effects: Vec<Effect>,
}

impl DriverCore {
    pub(crate) fn new(session: Arc<MobileUlcpSession>) -> Self {
        let state = MobileRadioStateRecord::idle();
        Self {
            session,
            transport: MobileRadioTransportStateRecord {
                phase: MobileRadioTransportPhase::Idle,
                name: None,
                link_id: None,
                problem: None,
            },
            published: state.clone(),
            state,
            link_up: false,
            bound_radio: false,
            generation: 0,
            host_key: None,
            fault_retries_remaining: FATAL_FAULT_RETRY_BUDGET,
            attached_at_ms: None,
            fault: None,
            reported_name: None,
            attach_announced: None,
            refresh_in_progress: false,
            refresh_waiters: Vec::new(),
            configuration: None,
            device_table: None,
            local_management: None,
            host_release: None,
            control_deadlines: BTreeMap::new(),
            backlog: VecDeque::new(),
            pending_raw: VecDeque::new(),
            in_flight: BTreeMap::new(),
            abandoned_raw: HashSet::new(),
            raw_retry: None,
            auto_enable_generation: None,
            auto_claim_generation: None,
            host_key_restart_generation: None,
            mesh_session: None,
            next_mesh_session: 0,
            frames_awaiting_mesh_session: VecDeque::new(),
            frame_time_ms: None,
            deferred: VecDeque::new(),
            effects: Vec::new(),
        }
    }

    pub(crate) fn state(&self) -> &MobileRadioStateRecord {
        &self.state
    }

    /// Act on one event.
    pub(crate) fn handle(&mut self, event: Event, now: Now) -> Vec<Effect> {
        match event {
            Event::Transport(report) => self.transport_changed(report),
            Event::LinkReady { bound_radio } => self.link_ready(bound_radio, now),
            Event::LinkReceived(frame) => self.link_received(frame, now),
            Event::LinkWritesFailed {
                raw_transaction_ids,
                problem,
            } => self.link_writes_failed(raw_transaction_ids, problem),
            Event::LinkFault(problem) => self.fatal(problem, now),
            Event::ReportProblem(problem) => self.state.problem = Some(problem),
            Event::ResetRecoveryBudget => self.fault_retries_remaining = FATAL_FAULT_RETRY_BUDGET,
            Event::HostKey(key) => self.set_host_key(key, now),
            Event::MeshSessionLeaving => self.mesh_session_leaving(),
            Event::MeshSessionArrived => self.mesh_session_arrived(),
            Event::MeshOutbound(frames) => self.mesh_outbound(frames, now),
            Event::Command(command) => self.command(command, now),
        }
        self.finish(now)
    }

    /// Act on every deadline that has passed by `now`.
    pub(crate) fn tick(&mut self, now: Now) -> Vec<Effect> {
        let at = now.monotonic_ms;
        if self
            .host_release
            .as_ref()
            .is_some_and(|release| release.deadline_ms <= at)
        {
            self.diagnose("release: the radio did not answer in time".to_owned());
            self.finish_host_release(false);
        }
        let expired: Vec<u8> = self
            .in_flight
            .iter()
            .filter(|(_, in_flight)| in_flight.deadline_ms <= at)
            .map(|(&id, _)| id)
            .collect();
        for transaction_id in expired {
            self.raw_transmit_timed_out(transaction_id, now);
        }
        if let Some((due, generation)) = self.raw_retry
            && due <= at
        {
            self.raw_retry = None;
            if generation == self.generation {
                self.pump_raw_transmits(now);
            }
        }
        if self
            .control_deadline()
            .is_some_and(|deadline| deadline <= at)
        {
            self.diagnose(format!(
                "ulcp: no response for {}s, parked at {:?} host {:?}",
                CONTROL_DEADLINE_MS / 1000,
                self.state.phase,
                self.state.host,
            ));
            self.finish_stranded_operations();
            self.fatal(MobileRadioProblem::SynchronizationStalled, now);
        }
        self.finish(now)
    }

    /// The earliest monotonic time at which `tick` has work.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        [
            self.control_deadline(),
            self.in_flight.values().map(|f| f.deadline_ms).min(),
            self.raw_retry.map(|(due, _)| due),
            self.host_release.as_ref().map(|r| r.deadline_ms),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn control_deadline(&self) -> Option<u64> {
        self.control_deadlines.values().copied().min()
    }

    /// Run deferred work, publish the state if it changed, and hand over
    /// the effects.
    fn finish(&mut self, now: Now) -> Vec<Effect> {
        while let Some(work) = self.deferred.pop_front() {
            self.run_deferred(work, now);
        }
        if self.published != self.state {
            self.published = self.state.clone();
            self.effects
                .push(Effect::State(Box::new(self.state.clone())));
        }
        std::mem::take(&mut self.effects)
    }

    fn diagnose(&mut self, line: String) {
        self.effects.push(Effect::Diagnostic(line));
    }

    // ------------------------------------------------------------------
    // Transport
    // ------------------------------------------------------------------

    /// The transport carries no frames, and says where it stands.
    ///
    /// A fault the core declared settles here. If the transport takes the
    /// reconnect the core offered, a retry is spent and the reconnect
    /// shows. If it comes to rest instead, the failure shows, and stands
    /// through the teardown until something new begins: the disconnect
    /// that follows a failure must not overwrite it.
    ///
    /// A transport can report a reconnect of its own before it hears that
    /// the core offered none: the invalidation trails whatever the
    /// transport had already queued. That reconnect is about to be called
    /// off, so the failure holds through it.
    fn transport_changed(&mut self, report: MobileRadioTransportStateRecord) {
        if self.link_up {
            self.link_up = false;
            self.retire_session();
        }
        let mut state = MobileRadioStateRecord::transport(&report);
        if let Some(mut fault) = self.fault.take() {
            let teardown = match Teardown::of(&report) {
                Teardown::Reconnecting if !fault.retry_offered && !fault.settled => {
                    Teardown::Underway
                }
                teardown => teardown,
            };
            match teardown {
                teardown @ (Teardown::Underway | Teardown::Rested) => {
                    fault.settled |= matches!(teardown, Teardown::Rested);
                    if fault.settled || !fault.retry_offered {
                        state.phase = MobileRadioPhase::Failed;
                        state.problem = Some(fault.problem.clone());
                    } else {
                        state.phase = MobileRadioPhase::Reconnecting;
                        state.problem = None;
                    }
                    state.name = state.name.or_else(|| self.state.name.clone());
                    self.fault = Some(fault);
                }
                Teardown::Reconnecting => self.spend_offered_retry(&fault),
                Teardown::Superseded => {}
            }
        }
        self.state = state;
        self.transport = report;
    }

    /// The link is coming back after `fault`: spend the reconnect the
    /// fault offered, unless the failure had already come to rest and this
    /// is a new attempt.
    fn spend_offered_retry(&mut self, fault: &Fault) {
        if fault.retry_offered && !fault.settled {
            self.fault_retries_remaining = self.fault_retries_remaining.saturating_sub(1);
            self.diagnose(format!(
                "fault: reconnecting; {} retries left",
                self.fault_retries_remaining
            ));
        }
    }

    /// The transport carries frames: start the ULCP session over it.
    fn link_ready(&mut self, bound_radio: bool, now: Now) {
        self.link_up = true;
        self.bound_radio = bound_radio;
        // A transport that came straight back without saying so still took
        // the reconnect. The budget must not depend on how it reports.
        if let Some(fault) = self.fault.take() {
            self.spend_offered_retry(&fault);
        }
        self.reported_name = None;
        self.generation = self.generation.wrapping_add(1);
        self.begin_synchronization(now);
    }

    /// One complete ULCP frame arrived.
    ///
    /// Consuming the frame and applying what it produced fail for unrelated
    /// reasons—a frame this session cannot read, against a value inside a
    /// frame it read fine—so they are reported apart.
    fn link_received(&mut self, frame: Vec<u8>, now: Now) {
        if !self.link_up {
            // Left over from a link the core already let go of.
            return;
        }
        let update = match self.session.consume(frame.clone()) {
            Ok(update) => update,
            Err(MobileError::UlcpUnexpectedCommand) => {
                // A well-formed command this session does not handle—an
                // unsolicited notification from newer firmware—is not a
                // broken link. Ignoring it costs at most one operation
                // that times out; tearing the link down costs the session.
                self.diagnose(format!(
                    "ulcp: ignoring unhandled command {}",
                    describe_ulcp_frame(frame)
                ));
                return;
            }
            Err(MobileError::UlcpUnexpectedFrame) => {
                // A well-formed frame with no place here: an answer to a
                // transaction nothing waits on, or a radio answering twice.
                // The session refuses it before touching any state, so
                // ignoring it orphans nothing, while closing the link would
                // turn a stray frame into a lost session.
                self.diagnose(format!(
                    "ulcp: ignoring frame nothing is waiting on {}",
                    describe_ulcp_frame(frame)
                ));
                return;
            }
            Err(cause) => {
                self.diagnose(format!(
                    "fatal: invalid frame cause={cause} frame=[{}]",
                    describe_ulcp_frame(frame)
                ));
                self.fatal(MobileRadioProblem::InvalidFrame, now);
                return;
            }
        };
        if let Err(error) = self.apply(update, now) {
            self.diagnose(format!(
                "fatal: unusable value cause={error} frame=[{}]",
                describe_ulcp_frame(frame)
            ));
            self.fatal(MobileRadioProblem::UnusableValue, now);
        }
    }

    /// Writes carrying these raw transmits failed while the link stayed up.
    /// Their tickets are released here: the MAC awaits each completion
    /// holding its coordinator, so one dropped ticket parks every later
    /// send.
    fn link_writes_failed(&mut self, transaction_ids: Vec<u8>, problem: MobileRadioProblem) {
        if !self.link_up {
            // Writes a teardown discarded: their frames were failed when
            // the link was let go.
            return;
        }
        self.pending_raw.clear();
        for transaction_id in &transaction_ids {
            self.in_flight.remove(transaction_id);
        }
        let _ = self.session.abandon_raw_transmits(transaction_ids);
        if self.mesh_session.is_some() {
            self.effects.push(Effect::MeshFailOutbound);
        }
        self.state.problem = Some(problem);
    }

    /// Tear the link down: its framing or session state can no longer be
    /// trusted. Ordinary status failures and rejected operations never come
    /// here.
    ///
    /// The teardown is not giving up. Most such faults are one bad frame,
    /// so while the budget lasts the core offers the transport a reconnect;
    /// whether one happens is the transport's to say.
    fn fatal(&mut self, problem: MobileRadioProblem, now: Now) {
        if !self.link_up && self.fault.as_ref().is_some_and(|fault| !fault.settled) {
            // The link is already being torn down for a fault; whatever
            // else went wrong with it is the same incident.
            self.diagnose(format!("fault while settling another: {problem:?}"));
            return;
        }
        if self
            .attached_at_ms
            .is_some_and(|at| now.monotonic_ms.saturating_sub(at) >= FATAL_FAULT_BUDGET_REFILL_MS)
        {
            // A fault after a session that held is a new incident.
            self.fault_retries_remaining = FATAL_FAULT_RETRY_BUDGET;
        }
        let retry = self.fault_retries_remaining > 0;
        self.diagnose(format!(
            "fatal ULCP fault: {problem:?}; retries left {}",
            self.fault_retries_remaining
        ));
        self.link_up = false;
        self.retire_session();
        // A retry shows as the reconnect it is: a failure the app is
        // about to undo would flash an error the user cannot act on.
        self.state.phase = if retry {
            MobileRadioPhase::Reconnecting
        } else {
            MobileRadioPhase::Failed
        };
        self.state.problem = (!retry).then(|| problem.clone());
        self.fault = Some(Fault {
            problem,
            retry_offered: retry,
            settled: false,
        });
        self.effects.push(Effect::Invalidate { retry });
    }

    /// End the ULCP session in progress, because the link went or because
    /// a new session is starting over it: release everything that was
    /// waiting on the radio and retire the generation, so work armed
    /// against this session cannot act on the next.
    fn retire_session(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        // The attach is over however it ended. Leaving the stamp would let
        // a fault in the next attach's handshake claim credit for how long
        // this one held.
        self.attached_at_ms = None;
        self.finish_pending_operations();
        // With the link gone there is nothing left to wait for.
        self.finish_host_release(false);
        let _ = self.session.reset();
        self.abandon_outstanding_mesh_frames();
        self.auto_enable_generation = None;
        self.auto_claim_generation = None;
        self.control_deadlines.clear();
        self.raw_retry = None;
        self.attach_announced = None;
    }

    fn begin_synchronization(&mut self, now: Now) {
        if !self.link_up {
            return;
        }
        // Whatever the transport was part-way through belongs to the
        // session being replaced, not the one starting here.
        self.retire_session();
        self.effects.push(Effect::ResetFraming);
        let host_key = self.host_key.map(|key| key.to_vec());
        let result = self
            .session
            .begin(host_key)
            .map_err(CallError::Session)
            .and_then(|update| self.apply(update, now).map_err(CallError::Apply));
        if let Err(error) = result {
            self.diagnose(format!("fatal: the session could not start: {error}"));
            self.fatal(MobileRadioProblem::SessionStartFailed, now);
        }
    }

    fn set_host_key(&mut self, key: Option<[u8; 32]>, now: Now) {
        let had_key = self.host_key.is_some();
        self.host_key = key;
        // A link can attach before the identity unlocks. The session then
        // finds no key and parks awaiting a host, with nothing to judge it
        // again. Start over now that the key exists; a radio with another
        // owner still parks.
        if key.is_some()
            && !had_key
            && self.link_up
            && self.state.phase == MobileRadioPhase::AwaitingHost
        {
            self.begin_synchronization(now);
        }
    }

    // ------------------------------------------------------------------
    // Applying the ULCP session's updates
    // ------------------------------------------------------------------

    /// Fold one update from the ULCP session into the state, and carry out
    /// what it asks, in the order its effects must happen.
    fn apply(&mut self, mut update: UlcpSessionUpdateRecord, now: Now) -> Result<(), ApplyError> {
        if !self.link_up {
            return Err(ApplyError::LinkDown);
        }
        self.fold_snapshot(&update, now)?;
        self.note_refusals(&update);
        let automatic = self.automatic_work(&update);
        if let Some(result) = update.raw_transmit_result.take() {
            self.finish_raw_transmit(result, now)?;
        }
        for received in std::mem::take(&mut update.received_frames) {
            self.deliver_received(received);
        }
        if let Some(event) = update.management_event.take() {
            let entered_dfu = self.local_management.as_ref().is_some_and(|m| m.dfu)
                && event.status_code == Some(0);
            self.finish_local_management(Ok(event));
            // The radio is leaving for its bootloader: nothing more is
            // asked of it, and the binding is not remembered again.
            if entered_dfu {
                return Ok(());
            }
        }
        for push in std::mem::take(&mut update.pushed_properties) {
            self.effects.push(Effect::Pushed(push));
        }

        let raw_transaction_id = match update.outbound_frames.len() {
            1 => update.raw_transmit_started_transaction_id,
            _ => None,
        };
        for frame in std::mem::take(&mut update.outbound_frames) {
            self.effects.push(Effect::Send {
                frame,
                raw_transaction_id,
            });
        }
        // A completed attach is the app's intent to stay bound to this
        // radio: the transport remembers it and arms reconnect.
        if update.snapshot.phase == UlcpSessionPhase::Attached
            && self.attach_announced != Some(self.generation)
        {
            self.attach_announced = Some(self.generation);
            self.effects.push(Effect::DidAttach);
        }
        self.deferred.extend(automatic);
        self.finish_waiters(&update);
        self.track_control_deadlines(&update, now);

        // Mesh frames wait out a control exchange: the session starts a
        // raw transmit only when nothing else is outstanding.
        if update.pending_control_transactions.is_empty() && !self.pending_raw.is_empty() {
            self.deferred.push_back(Deferred::PumpRawTransmits {
                generation: self.generation,
            });
        }
        Ok(())
    }

    /// Bring the state up to the session's snapshot: phase, host, name,
    /// key, and what the radio last read out.
    fn fold_snapshot(
        &mut self,
        update: &UlcpSessionUpdateRecord,
        now: Now,
    ) -> Result<(), ApplyError> {
        let snapshot = &update.snapshot;
        let previous_phase = self.state.phase;
        let previous_host = self.state.host;
        self.state.phase = match snapshot.phase {
            UlcpSessionPhase::Idle => MobileRadioPhase::Attaching,
            UlcpSessionPhase::Synchronizing => MobileRadioPhase::Synchronizing,
            UlcpSessionPhase::AwaitingHost => MobileRadioPhase::AwaitingHost,
            UlcpSessionPhase::Claiming => MobileRadioPhase::Provisioning,
            UlcpSessionPhase::Configuring => MobileRadioPhase::Configuring,
            UlcpSessionPhase::Attached => MobileRadioPhase::Attached,
            UlcpSessionPhase::Releasing => MobileRadioPhase::Disconnecting,
        };
        self.state.host = snapshot.host_ownership;
        if self.state.phase != previous_phase || self.state.host != previous_host {
            self.diagnose(format!(
                "ulcp: {previous_phase:?}→{:?} host {previous_host:?}→{:?} generation={} waiting={}",
                self.state.phase,
                self.state.host,
                snapshot.generation,
                update.waiting_for_responses,
            ));
        }
        if self.state.phase == MobileRadioPhase::Attached
            && previous_phase != MobileRadioPhase::Attached
        {
            // How long this attach holds says whether the next fault is a
            // new incident or the same one still going.
            self.attached_at_ms = Some(now.monotonic_ms);
            // Frames that waited out the link go now.
            self.pending_raw.extend(self.backlog.drain(..));
        }
        // The radio's own answer is the only authoritative name; the
        // transport's cached one does not follow a rename.
        if let Some(reported) = &snapshot.device_name
            && self.bound_radio
            && self.reported_name.as_ref() != Some(reported)
        {
            self.reported_name = Some(reported.clone());
            self.effects.push(Effect::DidReportName(reported.clone()));
        }
        if snapshot.device_name.is_some() {
            self.state.name.clone_from(&snapshot.device_name);
        } else if self.state.name.is_none() {
            self.state.name.clone_from(&self.transport.name);
        }
        if snapshot
            .device_key
            .as_ref()
            .is_some_and(|key| key.len() != DEVICE_KEY_LENGTH)
        {
            return Err(ApplyError::DeviceKey);
        }
        self.state.device_key.clone_from(&snapshot.device_key);
        // Present only on the update that carries a new reading. Absent
        // means no news: the previous reading and its time stand, rather
        // than a stale value being stamped as current.
        if let Some(battery) = &snapshot.battery {
            self.state.battery = Some(battery.clone());
            self.state.battery_read_at_ms = Some(now.wall_ms);
        }
        // Carried on every update: the radio ends an alert on its own, and
        // the control has to follow the radio, not what was last asked.
        self.state.alert = snapshot.alert;
        // Reported once, like battery: an epoch means nothing without the
        // instant it arrived.
        if let Some(time) = snapshot.time {
            self.state.clock = Some(MobileRadioClockRecord {
                epoch_seconds: time.epoch_seconds,
                read_at_ms: now.wall_ms,
            });
        }
        // Mirrored like the alert: a position is state.
        self.state.position.clone_from(&snapshot.gnss);
        if let Some(frame_ms) = snapshot
            .provisioning
            .as_ref()
            .and_then(|provisioning| provisioning.frame_time_ms)
            && self.frame_time_ms != Some(frame_ms)
        {
            self.frame_time_ms = Some(frame_ms);
            if self.mesh_session.is_some() {
                self.effects.push(Effect::MeshFrameTime(frame_ms));
            }
        }
        self.state.provisioning.clone_from(&snapshot.provisioning);
        // Any word from the radio clears the banner.
        self.state.problem = None;
        Ok(())
    }

    /// Show an operation the radio refused, or answered in a form the
    /// session could not use. Neither is a link fault. A device-table edit
    /// reports through its own caller instead: a full table is an answer
    /// for that screen, not a radio problem.
    fn note_refusals(&mut self, update: &UlcpSessionUpdateRecord) {
        if let Some(error) = &update.operation_error {
            self.diagnose(format!(
                "ulcp: operation rejected: {} {} ({})",
                error.operation, error.status_name, error.status_code
            ));
            if self.device_table.is_none() {
                self.state.problem = Some(MobileRadioProblem::OperationRejected {
                    operation: error.operation.clone(),
                    status_code: error.status_code,
                    status_name: error.status_name.clone(),
                });
            }
        }
        // The radio acted, and the two disagree about the reply's shape.
        if let Some(mismatch) = &update.mismatched_response {
            self.diagnose(format!(
                "ulcp: answer not understood: {} answered with property {:#x} command {}",
                mismatch.operation, mismatch.property_id, mismatch.command
            ));
            if self.device_table.is_none() {
                self.state.problem = Some(MobileRadioProblem::UnrecognizedAnswer);
            }
        }
    }

    /// What the driver does on its own account once the session settles,
    /// each at most once per session generation.
    fn automatic_work(&mut self, update: &UlcpSessionUpdateRecord) -> Vec<Deferred> {
        let snapshot = &update.snapshot;
        if update.waiting_for_responses {
            return Vec::new();
        }
        let generation = self.generation;
        let mut work = Vec::new();
        // An attach is meant to give a usable radio: turn the transmitter
        // on if the radio's own profile has it off.
        if snapshot.phase == UlcpSessionPhase::Attached
            && matches!(
                snapshot.host_ownership,
                UlcpHostOwnership::Ours | UlcpHostOwnership::Unsupported
            )
            && self.auto_enable_generation != Some(snapshot.generation)
            && let Some(provisioning) = &snapshot.provisioning
            && !provisioning.phy_enabled
        {
            self.auto_enable_generation = Some(snapshot.generation);
            work.push(Deferred::AutoEnable {
                generation,
                settings: UlcpRadioSettingsRecord {
                    device_name: provisioning
                        .supports_device_name
                        .then(|| snapshot.device_name.clone())
                        .flatten(),
                    phy_enabled: true,
                    frequency_khz: provisioning.frequency_khz,
                    transmit_power_dbm: provisioning.transmit_power_dbm,
                    bandwidth_hz: provisioning.bandwidth_hz,
                    spreading_factor: provisioning.spreading_factor,
                    coding_rate_denom: provisioning.coding_rate_denom,
                    duty_cycle_limit: provisioning.duty_cycle_limit,
                },
            });
        }
        if snapshot.phase != UlcpSessionPhase::AwaitingHost || self.host_key.is_none() {
            return work;
        }
        // The key arrived while the first synchronization was still in
        // flight, so the parked state is stale the moment it is reported.
        // `set_host_key` covers the opposite order.
        if snapshot.host_ownership == UlcpHostOwnership::LocalIdentityUnavailable
            && self.host_key_restart_generation != Some(snapshot.generation)
        {
            self.host_key_restart_generation = Some(snapshot.generation);
            work.push(Deferred::RestartForHostKey { generation });
        }
        // The host domain is volatile: a radio boots with no host key. A
        // radio bound in the app is the user's decision, so the phone takes
        // it, from another host too: the last claim wins. A refused claim
        // is not retried in a loop.
        if matches!(
            snapshot.host_ownership,
            UlcpHostOwnership::Unclaimed | UlcpHostOwnership::OtherHost
        ) && self.bound_radio
            && self.auto_claim_generation != Some(snapshot.generation)
        {
            self.auto_claim_generation = Some(snapshot.generation);
            work.push(Deferred::AutoClaim { generation });
        }
        work
    }

    /// The radio said what became of a raw transmit.
    fn finish_raw_transmit(
        &mut self,
        result: UlcpRawTransmitResultRecord,
        now: Now,
    ) -> Result<(), ApplyError> {
        let Some(mut in_flight) = self.in_flight.remove(&result.transaction_id) else {
            if !self.abandoned_raw.remove(&result.transaction_id) {
                return Err(ApplyError::UnknownRawTransaction(result.transaction_id));
            }
            // The watchdog already failed this frame. The radio is late,
            // not wrong: keep the link.
            self.diagnose(format!(
                "raw transmit answered after its deadline: transaction {} ({})",
                result.transaction_id, result.status_name
            ));
            return Ok(());
        };
        match result.disposition {
            UlcpRawTransmitDisposition::Sent => self.complete_mesh_frame(&in_flight.frame, true),
            UlcpRawTransmitDisposition::Retry
                if in_flight.frame.busy_retries < MAXIMUM_RAW_TRANSMIT_BUSY_RETRIES =>
            {
                in_flight.frame.busy_retries += 1;
                self.pending_raw.push_front(in_flight.frame);
                self.raw_retry = Some((
                    now.monotonic_ms + RAW_TRANSMIT_BUSY_RETRY_MS,
                    self.generation,
                ));
            }
            UlcpRawTransmitDisposition::Retry | UlcpRawTransmitDisposition::Rejected => {
                self.complete_mesh_frame(&in_flight.frame, false);
                self.diagnose(format!(
                    "raw transmit rejected: {} ({})",
                    result.status_name, result.status_code
                ));
                self.state.problem = Some(match result.disposition {
                    UlcpRawTransmitDisposition::Retry => MobileRadioProblem::RadioBusy,
                    _ => MobileRadioProblem::TransmissionRejected {
                        status_code: result.status_code,
                        status_name: result.status_name,
                    },
                });
            }
        }
        Ok(())
    }

    /// Hand a frame the radio received to the mesh session, and publish it.
    fn deliver_received(&mut self, received: UlcpReceivedFrameRecord) {
        let record = MobileMeshRxRecord {
            data: received.data.clone(),
            rssi_dbm: received.rssi_dbm,
            lqi: received.lqi,
            snr_cb: received.snr_cb,
            was_buffered: received.was_buffered,
            was_acknowledged: received.was_acknowledged,
            age_seconds: received.age_seconds,
        };
        if self.mesh_session.is_some() {
            self.effects.push(Effect::MeshReceive(record));
        } else {
            // A link can deliver frames before the app installs the mesh
            // session. Keep a bounded window, newest kept.
            self.frames_awaiting_mesh_session.push_back(record);
            while self.frames_awaiting_mesh_session.len() > MAXIMUM_FRAMES_AWAITING_MESH_SESSION {
                self.frames_awaiting_mesh_session.pop_front();
            }
        }
        self.effects.push(Effect::Received(received));
    }

    /// Answer the callers whose operation this update settles.
    fn finish_waiters(&mut self, update: &UlcpSessionUpdateRecord) {
        if update.waiting_for_responses {
            return;
        }
        let snapshot = &update.snapshot;
        if snapshot.phase == UlcpSessionPhase::Releasing {
            self.finish_host_release(snapshot.host_ownership == UlcpHostOwnership::Unclaimed);
        }
        if snapshot.phase != UlcpSessionPhase::Attached {
            return;
        }
        let mismatch = update
            .mismatched_response
            .as_ref()
            .map(|_| MobileRadioError::UnrecognizedAnswer);
        let rejection = update
            .operation_error
            .as_ref()
            .map(|error| MobileRadioError::OperationRejected {
                operation: error.operation.clone(),
                status_code: error.status_code,
                status_name: error.status_name.clone(),
            })
            .or_else(|| mismatch.clone());
        if self.refresh_in_progress {
            self.finish_refresh(rejection.clone().map_or(Ok(()), Err));
        }
        if let Some(reply) = self.configuration.take() {
            let _ = reply.send(rejection.map_or(Ok(()), Err));
        }
        if let Some(reply) = self.device_table.take() {
            let outcome = device_table_outcome(update.operation_error.as_ref()).or(mismatch);
            let _ = reply.send(outcome.map_or(Ok(()), Err));
        }
    }

    /// Keep one deadline per outstanding control transaction: the one it
    /// was given when first seen.
    fn track_control_deadlines(&mut self, update: &UlcpSessionUpdateRecord, now: Now) {
        if let Some(completed) = update.completed_control_transaction {
            self.control_deadlines.remove(&completed);
        }
        let pending = &update.pending_control_transactions;
        self.control_deadlines.retain(|id, _| pending.contains(id));
        for &id in pending {
            self.control_deadlines
                .entry(id)
                .or_insert(now.monotonic_ms + CONTROL_DEADLINE_MS);
        }
    }

    fn run_deferred(&mut self, work: Deferred, now: Now) {
        match work {
            Deferred::AutoEnable {
                generation,
                settings,
            } => {
                if generation != self.generation
                    || !self.link_up
                    || self.state.phase != MobileRadioPhase::Attached
                {
                    return;
                }
                let result = self
                    .session
                    .configure(settings)
                    .map_err(CallError::Session)
                    .and_then(|update| self.apply(update, now).map_err(CallError::Apply));
                if result.is_err() {
                    self.diagnose("could not enable the radio's transmitter".to_owned());
                    self.state.problem = Some(MobileRadioProblem::AutoEnableFailed);
                }
            }
            Deferred::RestartForHostKey { generation } => {
                if generation != self.generation
                    || !self.link_up
                    || self.host_key.is_none()
                    || self.state.phase != MobileRadioPhase::AwaitingHost
                {
                    return;
                }
                self.diagnose(
                    "radio parked without a phone identity that has since arrived; \
                     synchronizing again"
                        .to_owned(),
                );
                self.begin_synchronization(now);
            }
            Deferred::AutoClaim { generation } => {
                if generation != self.generation || !self.link_up {
                    return;
                }
                self.diagnose("bound radio awaiting a host; claiming".to_owned());
                // A refused claim reports through the state.
                let _ = self.claim(now);
            }
            Deferred::PumpRawTransmits { generation } => {
                if generation == self.generation {
                    self.pump_raw_transmits(now);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Raw transmits
    // ------------------------------------------------------------------

    fn mesh_outbound(&mut self, frames: Vec<MobileMeshOutboundFrameRecord>, now: Now) {
        let Some(session) = self.mesh_session else {
            return;
        };
        let ready = self.link_up && self.state.phase == MobileRadioPhase::Attached;
        if !ready {
            // Nothing drains the backlog while the radio is away, so what
            // has outlived its use goes here rather than piling up.
            let held = self.backlog.len();
            self.backlog.retain(|frame| !frame.expired(now));
            let discarded = held - self.backlog.len();
            if discarded > 0 {
                self.diagnose(format!(
                    "{discarded} mesh frames discarded: they waited {}s for the radio",
                    MESH_FRAME_LIFETIME_MS / 1000
                ));
            }
        }
        let queue = if ready {
            &mut self.pending_raw
        } else {
            &mut self.backlog
        };
        queue.extend(frames.into_iter().map(|frame| MeshFrame {
            id: frame.id,
            data: frame.data,
            nocca: frame.nocca,
            power_dbm: frame.power_dbm,
            session,
            taken_at_ms: now.monotonic_ms,
            busy_retries: 0,
        }));
        if ready {
            self.pump_raw_transmits(now);
        }
    }

    /// Start what the radio can take now, dropping a frame the session
    /// will not start rather than tearing anything down.
    fn pump_raw_transmits(&mut self, now: Now) {
        if !self.link_up || self.state.phase != MobileRadioPhase::Attached {
            return;
        }
        while let Err(error) = self.start_raw_transmits(now) {
            if !self.link_up {
                return;
            }
            // One unsendable frame; the link and session stay. Its ticket
            // fails, and later frames may still go.
            let Some(dropped) = self.pending_raw.pop_front() else {
                return;
            };
            self.diagnose(format!("raw transmit could not start: {error}"));
            self.complete_mesh_frame(&dropped, false);
            self.state.problem = Some(MobileRadioProblem::TransmissionUnsendable);
        }
    }

    fn start_raw_transmits(&mut self, now: Now) -> Result<(), CallError> {
        while self.in_flight.len() < MAXIMUM_RAW_TRANSMITS_IN_FLIGHT
            && self.raw_retry.is_none()
            && self.control_deadlines.is_empty()
            && let Some(frame) = self.pending_raw.pop_front()
        {
            if frame.expired(now) {
                // The mesh session has already counted it failed, so there
                // is no ticket left to fail.
                self.diagnose(format!(
                    "mesh frame {} discarded: it waited {}s for the radio",
                    frame.id,
                    MESH_FRAME_LIFETIME_MS / 1000
                ));
                continue;
            }
            // A frame that does not start goes back to the front, where
            // the caller finds it.
            let started = self
                .session
                .transmit_raw(frame.data.clone(), frame.nocca, frame.power_dbm)
                .and_then(|update| {
                    update
                        .raw_transmit_started_transaction_id
                        .filter(|id| !self.in_flight.contains_key(id))
                        .map(|id| (id, update))
                        .ok_or(MobileError::InvalidUlcpFrame)
                });
            let (transaction_id, update) = match started {
                Ok(started) => started,
                Err(cause) => {
                    self.pending_raw.push_front(frame);
                    return Err(CallError::Session(cause));
                }
            };
            // This transaction ID belongs to a live submission now,
            // whatever an earlier use of it was abandoned for.
            self.abandoned_raw.remove(&transaction_id);
            self.in_flight.insert(
                transaction_id,
                InFlight {
                    frame,
                    deadline_ms: now.monotonic_ms + RAW_TRANSMIT_TIMEOUT_MS,
                },
            );
            if let Err(error) = self.apply(update, now) {
                if let Some(in_flight) = self.in_flight.remove(&transaction_id) {
                    self.pending_raw.push_front(in_flight.frame);
                }
                return Err(CallError::Apply(error));
            }
        }
        Ok(())
    }

    /// Give up on a frame the radio took and never reported. The link is
    /// left alone; only this frame's ticket fails, which releases the MAC.
    fn raw_transmit_timed_out(&mut self, transaction_id: u8, now: Now) {
        let Some(in_flight) = self.in_flight.remove(&transaction_id) else {
            return;
        };
        self.diagnose(format!(
            "raw transmit timed out after {}s: transaction {transaction_id} mesh frame {} {} bytes",
            RAW_TRANSMIT_TIMEOUT_MS / 1000,
            in_flight.frame.id,
            in_flight.frame.data.len(),
        ));
        self.abandoned_raw.insert(transaction_id);
        self.complete_mesh_frame(&in_flight.frame, false);
        self.state.problem = Some(MobileRadioProblem::TransmissionUnreported);
        self.pump_raw_transmits(now);
    }

    fn complete_mesh_frame(&mut self, frame: &MeshFrame, transmitted: bool) {
        // A frame from a session since replaced has nobody to tell.
        if self.mesh_session == Some(frame.session) {
            self.effects.push(Effect::MeshComplete {
                frame_id: frame.id,
                transmitted,
            });
        }
    }

    /// Abandon every mesh frame in the radio's hands, queued or in flight,
    /// and fail the mesh session's tickets for them.
    ///
    /// The MAC awaits each ticket holding its coordinator, so a frame
    /// dropped without failing its ticket wedges the mesh session: every
    /// later send queues behind it. Any path that walks away from the
    /// frames it carried comes through here.
    fn abandon_outstanding_mesh_frames(&mut self) {
        // A restarted session issues transaction IDs from the start again,
        // so entries kept here would swallow a real protocol violation.
        self.abandoned_raw.clear();
        if self.pending_raw.is_empty() && self.in_flight.is_empty() {
            return;
        }
        self.diagnose(format!(
            "abandoning mesh frames: queued={} in flight={}",
            self.pending_raw.len(),
            self.in_flight.len()
        ));
        self.pending_raw.clear();
        self.in_flight.clear();
        if self.mesh_session.is_some() {
            self.effects.push(Effect::MeshFailOutbound);
        }
    }

    // ------------------------------------------------------------------
    // The mesh session
    // ------------------------------------------------------------------

    /// The mesh session is going: fail what the radio holds for it, while
    /// it is still there to be told.
    fn mesh_session_leaving(&mut self) {
        if self.mesh_session.take().is_none() {
            return;
        }
        // A frame still in flight stays there for the radio's answer, which
        // no longer reaches anyone.
        let held = self.backlog.len() + self.pending_raw.len() + self.in_flight.len();
        self.backlog.clear();
        self.pending_raw.clear();
        if held > 0 {
            self.effects.push(Effect::MeshFailOutbound);
        }
    }

    fn mesh_session_arrived(&mut self) {
        self.next_mesh_session = self.next_mesh_session.wrapping_add(1);
        self.mesh_session = Some(self.next_mesh_session);
        if let Some(frame_ms) = self.frame_time_ms {
            self.effects.push(Effect::MeshFrameTime(frame_ms));
        }
        for record in self.frames_awaiting_mesh_session.drain(..) {
            self.effects.push(Effect::MeshReceive(record));
        }
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    fn command(&mut self, command: Command, now: Now) {
        match command {
            Command::Refresh { call, reply } => self.refresh(call, reply, now),
            Command::Configure { call, reply } => self.configure(call, reply, now),
            Command::DeviceTable {
                requires_device_identity,
                call,
                reply,
            } => self.device_table(requires_device_identity, call, reply, now),
            Command::Immediate {
                call,
                abandon_binding,
                reply,
            } => {
                if !self.link_up {
                    let _ = reply.send(Err(MobileRadioError::RadioUnavailable));
                    return;
                }
                if let Err(error) = self.call(call, now) {
                    let _ = reply.send(Err(error.for_caller()));
                    return;
                }
                // After the update, which may announce the attach again:
                // dropping the binding last is what sticks. The link stays
                // up so the command reaches the radio.
                if abandon_binding {
                    self.effects.push(Effect::AbandonBinding);
                }
                let _ = reply.send(Ok(()));
            }
            Command::LocalManagement { dfu, call, reply } => {
                if !self.link_up || self.state.phase != MobileRadioPhase::Attached {
                    let _ = reply.send(Err(MobileRadioError::RadioUnavailable));
                    return;
                }
                if self.local_management.is_some() {
                    let _ = reply.send(Err(MobileRadioError::OperationInProgress));
                    return;
                }
                self.local_management = Some(LocalManagement { reply, dfu });
                // An exchange with nothing to ask completes inside the call.
                if let Err(error) = self.call(call, now) {
                    self.finish_local_management(Err(error.for_caller()));
                }
            }
            Command::Claim { reply } => {
                let _ = reply.send(self.claim(now));
            }
            Command::ReleaseHost { reply } => self.release_host(reply, now),
        }
    }

    fn call(&mut self, call: SessionCall, now: Now) -> Result<(), CallError> {
        let update = call(&self.session).map_err(CallError::Session)?;
        self.apply(update, now).map_err(CallError::Apply)
    }

    fn refresh(&mut self, call: SessionCall, reply: Reply<MobileRadioStateRecord>, now: Now) {
        if !self.link_up {
            let _ = reply.send(Err(MobileRadioError::RadioUnavailable));
            return;
        }
        if self.configuration.is_some() {
            let _ = reply.send(Err(MobileRadioError::OperationInProgress));
            return;
        }
        // A positioning read and a full refresh share their waiters: both
        // end on the same event, and a caller polling one joins the other
        // rather than starving it.
        self.refresh_waiters.push(reply);
        if self.refresh_in_progress {
            return;
        }
        self.refresh_in_progress = true;
        if let Err(error) = self.call(call, now) {
            self.finish_refresh(Err(error.for_caller()));
        }
    }

    fn configure(&mut self, call: SessionCall, reply: Reply<()>, now: Now) {
        if !self.link_up {
            let _ = reply.send(Err(MobileRadioError::RadioUnavailable));
            return;
        }
        if self.configuration.is_some() || self.refresh_in_progress {
            let _ = reply.send(Err(MobileRadioError::OperationInProgress));
            return;
        }
        self.configuration = Some(reply);
        if let Err(error) = self.call(call, now)
            && let Some(reply) = self.configuration.take()
        {
            let _ = reply.send(Err(error.for_caller()));
        }
    }

    /// One table edit at a time, resolved by the update that carries its
    /// outcome. The session wants an otherwise idle attach, so an edit
    /// racing another operation is refused rather than interleaved.
    fn device_table(
        &mut self,
        requires_device_identity: bool,
        call: SessionCall,
        reply: Reply<()>,
        now: Now,
    ) {
        if !self.link_up
            || self.state.phase != MobileRadioPhase::Attached
            || self.state.host != UlcpHostOwnership::Ours
        {
            let _ = reply.send(Err(MobileRadioError::RadioUnavailable));
            return;
        }
        if requires_device_identity
            && !self
                .state
                .provisioning
                .as_ref()
                .is_some_and(|provisioning| provisioning.supports_device_identity)
        {
            let _ = reply.send(Err(MobileRadioError::Unsupported));
            return;
        }
        if self.device_table.is_some() || self.configuration.is_some() || self.refresh_in_progress {
            let _ = reply.send(Err(MobileRadioError::OperationInProgress));
            return;
        }
        self.device_table = Some(reply);
        if let Err(error) = self.call(call, now)
            && let Some(reply) = self.device_table.take()
        {
            let _ = reply.send(Err(error.for_caller()));
        }
    }

    fn claim(&mut self, now: Now) -> Result<(), MobileRadioError> {
        let Some(host_key) = self.host_key.filter(|_| self.link_up) else {
            self.diagnose(format!(
                "claim: refused; link up={} host key={}",
                self.link_up,
                self.host_key.is_some()
            ));
            return Err(MobileRadioError::IdentityUnavailable);
        };
        if !matches!(
            self.state.host,
            UlcpHostOwnership::Unclaimed | UlcpHostOwnership::OtherHost
        ) {
            self.diagnose(format!(
                "claim: refused from host state {:?}",
                self.state.host
            ));
            return Err(MobileRadioError::TakeoverNotAllowed);
        }
        self.diagnose(format!(
            "claim: writing host key from host state {:?}",
            self.state.host
        ));
        self.call(
            Box::new(move |session| session.claim(host_key.to_vec())),
            now,
        )
        .map_err(|error| {
            self.state.problem = Some(MobileRadioProblem::ClaimFailed);
            error.for_caller()
        })
    }

    /// Hand the radio back before letting it go: clear this phone's host
    /// key, so the radio stops queueing for a phone that has left. Ends
    /// when the radio answers, the link goes, or the deadline passes.
    fn release_host(&mut self, reply: oneshot::Sender<()>, now: Now) {
        if let Some(release) = &mut self.host_release {
            release.waiters.push(reply);
            return;
        }
        if !self.link_up || self.state.host != UlcpHostOwnership::Ours {
            let _ = reply.send(());
            return;
        }
        self.host_release = Some(HostRelease {
            waiters: vec![reply],
            device_key: self.state.device_key.clone(),
            deadline_ms: now.monotonic_ms + HOST_RELEASE_TIMEOUT_MS,
        });
        self.diagnose("release: clearing the radio's host key".to_owned());
        if let Err(error) = self.call(Box::new(|session| session.release()), now) {
            self.diagnose(format!("release: not sent ({error})"));
            self.finish_host_release(false);
        }
    }

    // ------------------------------------------------------------------
    // Finishing waiters
    // ------------------------------------------------------------------

    fn finish_refresh(&mut self, outcome: Result<(), MobileRadioError>) {
        self.refresh_in_progress = false;
        for reply in self.refresh_waiters.drain(..) {
            let _ = reply.send(outcome.clone().map(|()| self.state.clone()));
        }
    }

    fn finish_local_management(
        &mut self,
        outcome: Result<UlcpLocalManagementEventRecord, MobileRadioError>,
    ) {
        let Some(management) = self.local_management.take() else {
            return;
        };
        if management.dfu
            && outcome
                .as_ref()
                .is_ok_and(|event| event.status_code == Some(0))
        {
            self.effects.push(Effect::DidEnterDfu);
        }
        let _ = management.reply.send(outcome);
    }

    /// End the wait for a release. `confirmed` is the radio saying it no
    /// longer holds this phone's key, which is announced.
    fn finish_host_release(&mut self, confirmed: bool) {
        let Some(release) = self.host_release.take() else {
            return;
        };
        if confirmed && let Some(key) = release.device_key {
            self.effects.push(Effect::HostReleased(key));
        }
        for waiter in release.waiters {
            let _ = waiter.send(());
        }
    }

    /// Release callers waiting on a control exchange the radio stopped
    /// answering. Timed out, not rejected: nobody knows whether the radio
    /// acted.
    fn finish_stranded_operations(&mut self) {
        if self.refresh_in_progress || !self.refresh_waiters.is_empty() {
            self.finish_refresh(Err(MobileRadioError::TimedOut));
        }
        if let Some(reply) = self.configuration.take() {
            let _ = reply.send(Err(MobileRadioError::TimedOut));
        }
        if let Some(reply) = self.device_table.take() {
            let _ = reply.send(Err(MobileRadioError::TimedOut));
        }
        self.finish_local_management(Err(MobileRadioError::TimedOut));
    }

    fn finish_pending_operations(&mut self) {
        if self.refresh_in_progress || !self.refresh_waiters.is_empty() {
            self.finish_refresh(Err(MobileRadioError::RadioUnavailable));
        }
        if let Some(reply) = self.configuration.take() {
            let _ = reply.send(Err(MobileRadioError::RadioUnavailable));
        }
        if let Some(reply) = self.device_table.take() {
            let _ = reply.send(Err(MobileRadioError::RadioUnavailable));
        }
        self.finish_local_management(Err(MobileRadioError::RadioUnavailable));
    }
}

/// A finished table edit's outcome for its caller. `ALREADY` and
/// `ITEM_NOT_FOUND` are successes: the radio holds, or lacks, the key as
/// asked. A failed chained save leaves the edit live, and the state's
/// `saved` reports persistence.
fn device_table_outcome(error: Option<&UlcpOperationErrorRecord>) -> Option<MobileRadioError> {
    let error = error?;
    match error.kind {
        UlcpOperationFailureKind::SaveFailed
        | UlcpOperationFailureKind::AlreadyApplied
        | UlcpOperationFailureKind::ItemMissing => None,
        UlcpOperationFailureKind::Capacity => Some(MobileRadioError::DeviceFull),
        UlcpOperationFailureKind::Rejected => Some(MobileRadioError::OperationRejected {
            operation: error.operation.clone(),
            status_code: error.status_code,
            status_name: error.status_name.clone(),
        }),
    }
}
