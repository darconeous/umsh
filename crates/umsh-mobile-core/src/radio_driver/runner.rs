//! The driver's thread, and the UniFFI object native code holds.
//!
//! One thread owns the core. It takes events and timer expiries in the
//! order they arrive and carries out every effect, so frames leave in the
//! order the core produced them and no lock ever covers a foreign call.
//! It is a thread of its own because a driver exists before the identity
//! unlocks: its mesh session arrives later, and can be replaced.

use std::sync::{Arc, Mutex, PoisonError, mpsc as std_mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::oneshot;

use super::core::{Command, DriverCore, Effect, Event, Now, RefreshKind, Reply, SessionCall};
use super::{
    MobileRadioDriverUpdateRecord, MobileRadioError, MobileRadioProblem, MobileRadioStateRecord,
    MobileRadioTransportStateRecord,
};
use crate::mobile_mesh::{
    HostPeerKeyEntryRecord, MeshOutboundListener, MobileMeshPropertyWriteRecord, UpdateListener,
    WakeSignal,
};
use crate::ulcp::{
    MobileAnnouncementRecord, UlcpAdvertSettingsRecord, UlcpDeviceConfigRecord,
    UlcpGnssSettingsRecord, UlcpItemMutationRecord, UlcpLocalManagementEventRecord,
};
use crate::{
    MobileMeshSession, MobileUlcpSession, UlcpAlertState, UlcpDfuMode, UlcpRadioSettingsRecord,
};

/// Property pushes kept for a platform that falls behind, newest kept.
/// Pushes are sparse and each is whole.
const PUSHES_KEPT: usize = 16;

/// The transport under a driver: one link carrying whole ULCP frames.
///
/// Every call is fire-and-forget: it is made on the driver's thread, and
/// the implementation hops to its own queue and returns. None reads native
/// state back. The driver holds the link until it is stopped
/// (`MobileRadioDriver::stop`).
#[uniffi::export(with_foreign)]
pub trait RadioLink: Send + Sync {
    /// Queue one complete ULCP frame. `raw_transaction_id` tags the write
    /// carrying a raw transmit, so a transport that learns of a write
    /// failure can fail that transmit alone
    /// (`MobileRadioDriver::link_writes_failed`).
    fn send(&self, frame: Vec<u8>, raw_transaction_id: Option<u8>);

    /// Discard partly framed input and anything queued to send: a session
    /// is starting, and nothing from the one before may merge into it.
    fn reset_framing(&self);

    /// Tear the transport down: the session behind it can no longer be
    /// trusted. With `retry`, the driver would spend a reconnect on this,
    /// and the transport takes its ordinary link-loss path if it can. The
    /// state it reports next decides what the user sees.
    fn invalidate(&self, retry: bool);

    /// The radio attached. Where the transport remembers which radio the
    /// app is bound to, this is when.
    fn did_attach(&self);

    /// The bound radio reported its own name, which outranks whatever the
    /// transport had cached.
    fn did_report_name(&self, name: String);

    /// The radio is erasing itself and will reboot. Drop the binding, but
    /// leave the link up: the command still has to reach the radio.
    fn abandon_binding(&self);

    /// The radio confirmed it is entering DFU. Stop reconnecting to it,
    /// and keep the binding.
    fn did_enter_dfu(&self);
}

/// Told that `MobileRadioDriver::poll_update` has something new.
///
/// Called on the driver's thread; implementations only schedule a drain on
/// their own executor and return. Calls are coalesced: one per
/// pending-to-drained cycle.
#[uniffi::export(with_foreign)]
pub trait MobileRadioDriverListener: Send + Sync {
    fn on_update_pending(&self);
}

impl UpdateListener for dyn MobileRadioDriverListener {
    fn update_pending(&self) {
        self.on_update_pending();
    }
}

enum Input {
    Event(Event),
    /// The mesh session has frames for the radio.
    MeshOutboundReady,
    UseMeshSession {
        session: Option<Arc<MobileMeshSession>>,
        done: oneshot::Sender<()>,
    },
    Stop,
}

/// What the thread publishes and native code reads.
struct Shared {
    state: Mutex<MobileRadioStateRecord>,
    update: Mutex<MobileRadioDriverUpdateRecord>,
    wake: WakeSignal<dyn MobileRadioDriverListener>,
}

impl Shared {
    /// Add what one round of effects published, and wake the listener.
    fn publish(&self, batch: MobileRadioDriverUpdateRecord) {
        if let Some(state) = &batch.state {
            self.state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone_from(state);
        }
        {
            let mut update = self.update.lock().unwrap_or_else(PoisonError::into_inner);
            if batch.state.is_some() {
                update.state = batch.state;
            }
            keep_newest(
                &mut update.pushed_properties,
                batch.pushed_properties,
                PUSHES_KEPT,
            );
            update.host_releases.extend(batch.host_releases);
        }
        self.wake.notify();
    }
}

/// Append `more`, then let go of the oldest values past `limit`.
fn keep_newest<T>(values: &mut Vec<T>, more: Vec<T>, limit: usize) {
    values.extend(more);
    if values.len() > limit {
        values.drain(..values.len() - limit);
    }
}

/// Tells the driver's thread that its mesh session has frames.
struct OutboundWake(std_mpsc::Sender<Input>);

impl MeshOutboundListener for OutboundWake {
    fn outbound_ready(&self) {
        let _ = self.0.send(Input::MeshOutboundReady);
    }
}

/// The radio driver for one transport.
#[derive(uniffi::Object)]
pub struct MobileRadioDriver {
    inputs: std_mpsc::Sender<Input>,
    shared: Arc<Shared>,
}

impl Drop for MobileRadioDriver {
    fn drop(&mut self) {
        self.stop();
    }
}

#[uniffi::export]
impl MobileRadioDriver {
    /// A driver for the phone's own radio over `link`. The link reports
    /// its state with `transport_changed` and `link_ready`.
    #[uniffi::constructor]
    pub fn new(link: Arc<dyn RadioLink>) -> Result<Arc<Self>, MobileRadioError> {
        Self::start(link, MobileUlcpSession::new())
    }

    /// A driver for a radio this phone administers but does not tether to.
    /// It never claims the radio, never turns its transmitter on, and never
    /// reconnects: a fault ends the session. `lazy_inspection` attaches
    /// without reading the radio whole, for a screen that reads what it
    /// shows (`MobileUlcpSession::administrative_lazy`).
    #[uniffi::constructor]
    pub fn administrative(
        link: Arc<dyn RadioLink>,
        lazy_inspection: bool,
    ) -> Result<Arc<Self>, MobileRadioError> {
        let session = if lazy_inspection {
            MobileUlcpSession::administrative_lazy()
        } else {
            MobileUlcpSession::administrative()
        };
        Self::start(link, session)
    }

    /// Register the listener told of new updates. If one is already
    /// waiting, it is told at once.
    pub fn set_listener(&self, listener: Arc<dyn MobileRadioDriverListener>) {
        self.shared.wake.set_listener(Some(listener));
    }

    pub fn clear_listener(&self) {
        self.shared.wake.set_listener(None);
    }

    /// Stop the driver for good. Its thread ends and lets go of the link
    /// and the mesh session; calls waiting on it, and any made afterwards,
    /// fail as stopped. Dropping the driver stops it too, but a platform
    /// that frees objects late should not leave a thread waiting on that.
    pub fn stop(&self) {
        let _ = self.inputs.send(Input::Stop);
    }

    /// Everything that changed since the last poll.
    pub fn poll_update(&self) -> MobileRadioDriverUpdateRecord {
        // Re-armed first, so anything published mid-drain wakes again.
        self.shared.wake.drained();
        std::mem::take(
            &mut *self
                .shared
                .update
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// The radio's state as last published.
    pub fn state(&self) -> MobileRadioStateRecord {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    // --- What the transport reports. None of these wait. ---

    /// The transport carries no frames, and stands here.
    pub fn transport_changed(&self, state: MobileRadioTransportStateRecord) {
        self.post(Event::Transport(state));
    }

    /// The transport carries frames now. `bound_radio` says whether the
    /// radio on the other end is the one the app is bound to; a transport
    /// that reaches exactly one radio always is.
    pub fn link_ready(&self, bound_radio: bool) {
        self.post(Event::LinkReady { bound_radio });
    }

    /// One complete ULCP frame arrived.
    pub fn link_received(&self, frame: Vec<u8>) {
        self.post(Event::LinkReceived(frame));
    }

    /// Writes carrying these raw transmits failed while the link stayed up.
    pub fn link_writes_failed(&self, raw_transaction_ids: Vec<u8>, problem: MobileRadioProblem) {
        self.post(Event::LinkWritesFailed {
            raw_transaction_ids,
            problem,
        });
    }

    /// The transport found the link unusable on its own account—an
    /// attach that never finished, an endpoint it cannot write. The driver
    /// treats it as any fatal fault, and invalidates the link.
    pub fn link_fault(&self, problem: MobileRadioProblem) {
        self.post(Event::LinkFault(problem));
    }

    /// The transport failed at something without losing the link.
    pub fn report_problem(&self, problem: MobileRadioProblem) {
        self.post(Event::ReportProblem(problem));
    }

    /// A deliberate new attempt, made by the user: the fault budget starts
    /// over. An automatic reconnect must not call this, or a failing radio
    /// would refill its budget forever.
    pub fn reset_recovery_budget(&self) {
        self.post(Event::ResetRecoveryBudget);
    }

    // --- What the app supplies. ---

    /// This phone's host key: its identity's public key, once unlocked.
    pub fn set_host_key(&self, host_key: Option<Vec<u8>>) -> Result<(), MobileRadioError> {
        let host_key = host_key
            .map(|key| key.try_into())
            .transpose()
            .map_err(|_| MobileRadioError::InvalidArgument)?;
        self.send(Event::HostKey(host_key))
    }

    /// The mesh session whose frames this radio carries, or none. Frames
    /// received while there is none are kept, a bounded few, for the next.
    pub async fn use_mesh_session(
        &self,
        session: Option<Arc<MobileMeshSession>>,
    ) -> Result<(), MobileRadioError> {
        let (done, finished) = oneshot::channel();
        self.inputs
            .send(Input::UseMeshSession { session, done })
            .map_err(|_| MobileRadioError::Stopped)?;
        finished.await.map_err(|_| MobileRadioError::Stopped)
    }

    // --- Operations on the radio. ---

    /// Wait for the attach to finish. Answers with the state once the
    /// session is attached with nothing outstanding; with the radio's
    /// refusal if it refused part of the attach; and with `LinkFailed` if
    /// the link comes to rest or fails first. Waits through the
    /// transport's connecting phases, so a caller may ask before the link
    /// is ready, once the transport has reported that it is connecting.
    ///
    /// A tethered radio can park short of attached, awaiting a host or a
    /// claim, with the link up. The wait then lasts until something moves
    /// it on or the link goes, so a caller that cannot wait that long
    /// brings its own deadline.
    pub async fn attached(&self) -> Result<MobileRadioStateRecord, MobileRadioError> {
        self.request(|reply| Command::Attached { reply }).await
    }

    /// Read the radio's state anew. Joins a full read already running or
    /// waiting.
    pub async fn refresh(&self) -> Result<MobileRadioStateRecord, MobileRadioError> {
        self.request(|reply| Command::Refresh {
            kind: RefreshKind::Full,
            call: Box::new(|session| session.refresh()),
            reply,
        })
        .await
    }

    /// Read the radio's positioning properties anew. Joins a positioning
    /// read already running or waiting.
    pub async fn refresh_positioning(&self) -> Result<MobileRadioStateRecord, MobileRadioError> {
        self.request(|reply| Command::Refresh {
            kind: RefreshKind::Positioning,
            call: Box::new(|session| session.refresh_positioning()),
            reply,
        })
        .await
    }

    pub async fn configure(
        &self,
        settings: UlcpRadioSettingsRecord,
    ) -> Result<(), MobileRadioError> {
        self.configuration(Box::new(move |session| session.configure(settings)))
            .await
    }

    /// Write a whole device configuration and have the radio save it.
    pub async fn configure_device(
        &self,
        configuration: UlcpDeviceConfigRecord,
    ) -> Result<(), MobileRadioError> {
        self.configuration(Box::new(move |session| {
            session.configure_device(configuration)
        }))
        .await
    }

    pub async fn configure_positioning(
        &self,
        gnss: Option<UlcpGnssSettingsRecord>,
        tz_rule: Option<String>,
        time_24h: Option<bool>,
    ) -> Result<(), MobileRadioError> {
        self.configuration(Box::new(move |session| {
            session.configure_positioning(gnss, tz_rule, time_24h)
        }))
        .await
    }

    pub async fn configure_advertising(
        &self,
        advert: Option<UlcpAdvertSettingsRecord>,
    ) -> Result<(), MobileRadioError> {
        self.configuration(Box::new(move |session| {
            session.configure_advertising(advert)
        }))
        .await
    }

    pub async fn insert_device_peer(&self, public_key: Vec<u8>) -> Result<(), MobileRadioError> {
        self.device_table(true, Box::new(move |s| s.insert_device_peer(public_key)))
            .await
    }

    pub async fn remove_device_peer(&self, public_key: Vec<u8>) -> Result<(), MobileRadioError> {
        self.device_table(true, Box::new(move |s| s.remove_device_peer(public_key)))
            .await
    }

    pub async fn insert_device_admin(&self, public_key: Vec<u8>) -> Result<(), MobileRadioError> {
        self.device_table(true, Box::new(move |s| s.insert_device_admin(public_key)))
            .await
    }

    pub async fn remove_device_admin(&self, public_key: Vec<u8>) -> Result<(), MobileRadioError> {
        self.device_table(true, Box::new(move |s| s.remove_device_admin(public_key)))
            .await
    }

    pub async fn insert_device_channel_key(
        &self,
        channel_key: Vec<u8>,
    ) -> Result<(), MobileRadioError> {
        self.device_table(
            true,
            Box::new(move |s| s.insert_device_channel_key(channel_key)),
        )
        .await
    }

    pub async fn remove_device_channel_key(
        &self,
        channel_key: Vec<u8>,
    ) -> Result<(), MobileRadioError> {
        self.device_table(
            true,
            Box::new(move |s| s.remove_device_channel_key(channel_key)),
        )
        .await
    }

    pub async fn reconcile_host_channel_keys(
        &self,
        keys: Vec<Vec<u8>>,
    ) -> Result<(), MobileRadioError> {
        self.device_table(
            false,
            Box::new(move |s| s.reconcile_host_channel_keys(keys)),
        )
        .await
    }

    pub async fn reconcile_host_peer_keys(
        &self,
        entries: Vec<HostPeerKeyEntryRecord>,
    ) -> Result<(), MobileRadioError> {
        self.device_table(
            false,
            Box::new(move |s| s.reconcile_host_peer_keys(entries)),
        )
        .await
    }

    pub async fn reconcile_host_destination_hints(
        &self,
        hints: Vec<Vec<u8>>,
    ) -> Result<(), MobileRadioError> {
        self.device_table(
            false,
            Box::new(move |s| s.reconcile_host_destination_hints(hints)),
        )
        .await
    }

    pub async fn reconcile_host_mutes(
        &self,
        channel_identifiers: Vec<Vec<u8>>,
        peer_keys: Vec<Vec<u8>>,
    ) -> Result<(), MobileRadioError> {
        self.device_table(
            false,
            Box::new(move |s| s.reconcile_host_mutes(channel_identifiers, peer_keys)),
        )
        .await
    }

    pub async fn set_host_auto_ack(&self, enabled: bool) -> Result<(), MobileRadioError> {
        self.device_table(false, Box::new(move |s| s.set_host_auto_ack(enabled)))
            .await
    }

    /// Ask the radio for the frames it queued while no host was attached.
    pub async fn drain_queue(&self) -> Result<(), MobileRadioError> {
        self.device_table(false, Box::new(|s| s.drain_queue()))
            .await
    }

    pub async fn set_alert(&self, state: UlcpAlertState) -> Result<(), MobileRadioError> {
        self.immediate(false, Box::new(move |s| s.set_alert(state)))
            .await
    }

    pub async fn set_time(&self, epoch_seconds: Option<u32>) -> Result<(), MobileRadioError> {
        self.immediate(false, Box::new(move |s| s.set_time(epoch_seconds)))
            .await
    }

    /// Erase the radio. It reboots blank and drops the link itself, so the
    /// binding goes and the link stays up long enough to carry the
    /// command.
    pub async fn factory_reset(&self) -> Result<(), MobileRadioError> {
        self.immediate(true, Box::new(|s| s.factory_reset())).await
    }

    /// Restart the radio. The binding stays: the radio coming back is the
    /// same radio, and reconnecting to it is the point.
    pub async fn reboot(&self) -> Result<(), MobileRadioError> {
        self.immediate(false, Box::new(|s| s.reboot())).await
    }

    pub async fn announce(
        &self,
        request: MobileAnnouncementRecord,
    ) -> Result<UlcpLocalManagementEventRecord, MobileRadioError> {
        self.local_management(false, Box::new(move |s| s.announce(request)))
            .await
    }

    /// Enter DFU. On the radio's confirmation the transport is told to
    /// stop reconnecting (`RadioLink::did_enter_dfu`).
    pub async fn enter_dfu(
        &self,
        mode: UlcpDfuMode,
    ) -> Result<UlcpLocalManagementEventRecord, MobileRadioError> {
        self.local_management(true, Box::new(move |s| s.enter_dfu(mode)))
            .await
    }

    /// Read named properties from the radio.
    pub async fn fetch_properties(
        &self,
        property_ids: Vec<u32>,
    ) -> Result<UlcpLocalManagementEventRecord, MobileRadioError> {
        self.local_management(
            false,
            Box::new(move |s| s.begin_property_fetch(property_ids)),
        )
        .await
    }

    /// Write properties to the radio, in the given order.
    pub async fn write_properties(
        &self,
        writes: Vec<MobileMeshPropertyWriteRecord>,
    ) -> Result<UlcpLocalManagementEventRecord, MobileRadioError> {
        self.local_management(false, Box::new(move |s| s.begin_property_writes(writes)))
            .await
    }

    /// Edit the items of one of the radio's tables.
    pub async fn edit_property_items(
        &self,
        property_id: u32,
        mutations: Vec<UlcpItemMutationRecord>,
    ) -> Result<UlcpLocalManagementEventRecord, MobileRadioError> {
        self.local_management(
            false,
            Box::new(move |s| s.begin_property_items(property_id, mutations)),
        )
        .await
    }

    /// Persist the radio's live configuration.
    pub async fn save(&self) -> Result<UlcpLocalManagementEventRecord, MobileRadioError> {
        self.local_management(false, Box::new(|s| s.begin_save()))
            .await
    }

    /// Write this phone's host key into the radio, replacing whatever host
    /// it had.
    pub async fn claim(&self) -> Result<(), MobileRadioError> {
        self.request(|reply| Command::Claim { reply }).await
    }

    /// Clear this phone's host key from the radio before letting it go, so
    /// it stops queueing for a phone that has left. Returns when the radio
    /// answers, the link goes, or two seconds pass; a radio holding another
    /// host's key, or none, has nothing to release.
    pub async fn release_host(&self) {
        let (reply, released) = oneshot::channel();
        if self
            .send(Event::Command(Command::ReleaseHost { reply }))
            .is_ok()
        {
            let _ = released.await;
        }
    }
}

impl MobileRadioDriver {
    fn start(
        link: Arc<dyn RadioLink>,
        session: Arc<MobileUlcpSession>,
    ) -> Result<Arc<Self>, MobileRadioError> {
        let (inputs, input_rx) = std_mpsc::channel();
        let core = DriverCore::new(session);
        let shared = Arc::new(Shared {
            state: Mutex::new(core.state().clone()),
            update: Mutex::new(MobileRadioDriverUpdateRecord::default()),
            wake: WakeSignal::new(),
        });
        let runner = Runner {
            core,
            link,
            mesh_session: None,
            outbound_wake: Arc::new(OutboundWake(inputs.clone())),
            shared: shared.clone(),
            epoch: Instant::now(),
        };
        std::thread::Builder::new()
            .name("umsh-radio-driver".to_owned())
            .spawn(move || runner.run(input_rx))
            .map_err(|_| MobileRadioError::Stopped)?;
        Ok(Arc::new(Self { inputs, shared }))
    }

    fn post(&self, event: Event) {
        let _ = self.send(event);
    }

    fn send(&self, event: Event) -> Result<(), MobileRadioError> {
        self.inputs
            .send(Input::Event(event))
            .map_err(|_| MobileRadioError::Stopped)
    }

    async fn request<T>(
        &self,
        command: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, MobileRadioError> {
        let (reply, outcome) = oneshot::channel();
        self.send(Event::Command(command(reply)))?;
        outcome.await.map_err(|_| MobileRadioError::Stopped)?
    }

    async fn configuration(&self, call: SessionCall) -> Result<(), MobileRadioError> {
        self.request(|reply| Command::Configure { call, reply })
            .await
    }

    async fn device_table(
        &self,
        requires_device_identity: bool,
        call: SessionCall,
    ) -> Result<(), MobileRadioError> {
        self.request(|reply| Command::DeviceTable {
            requires_device_identity,
            call,
            reply,
        })
        .await
    }

    async fn immediate(
        &self,
        abandon_binding: bool,
        call: SessionCall,
    ) -> Result<(), MobileRadioError> {
        self.request(|reply| Command::Immediate {
            call,
            abandon_binding,
            reply,
        })
        .await
    }

    async fn local_management(
        &self,
        dfu: bool,
        call: SessionCall,
    ) -> Result<UlcpLocalManagementEventRecord, MobileRadioError> {
        self.request(|reply| Command::LocalManagement { dfu, call, reply })
            .await
    }
}

struct Runner {
    core: DriverCore,
    link: Arc<dyn RadioLink>,
    mesh_session: Option<Arc<MobileMeshSession>>,
    /// This driver's place in a mesh session's outbound route.
    outbound_wake: Arc<dyn MeshOutboundListener>,
    shared: Arc<Shared>,
    /// Zero on the monotonic clock.
    epoch: Instant,
}

impl Runner {
    fn run(mut self, inputs: std_mpsc::Receiver<Input>) {
        loop {
            let input = match self.core.next_deadline() {
                None => match inputs.recv() {
                    Ok(input) => input,
                    Err(_) => break,
                },
                Some(deadline) => {
                    let wait = deadline.saturating_sub(self.now().monotonic_ms);
                    match inputs.recv_timeout(Duration::from_millis(wait)) {
                        Ok(input) => input,
                        Err(std_mpsc::RecvTimeoutError::Timeout) => {
                            let effects = self.core.tick(self.now());
                            self.execute(effects);
                            continue;
                        }
                        Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            };
            match input {
                Input::Event(event) => {
                    let effects = self.core.handle(event, self.now());
                    self.execute(effects);
                }
                Input::MeshOutboundReady => {
                    let frames = self
                        .mesh_session
                        .as_ref()
                        .map(|session| session.take_outbound_frames())
                        .unwrap_or_default();
                    if !frames.is_empty() {
                        let effects = self.core.handle(Event::MeshOutbound(frames), self.now());
                        self.execute(effects);
                    }
                }
                Input::UseMeshSession { session, done } => {
                    self.use_mesh_session(session);
                    let _ = done.send(());
                }
                Input::Stop => break,
            }
        }
        if let Some(session) = self.mesh_session.take() {
            session.stop_routing_outbound_to(&self.outbound_wake);
        }
    }

    fn use_mesh_session(&mut self, session: Option<Arc<MobileMeshSession>>) {
        if self.mesh_session.is_some() {
            // What the core fails for the old session reaches the old one.
            let effects = self.core.handle(Event::MeshSessionLeaving, self.now());
            self.execute(effects);
            if let Some(old) = self.mesh_session.take() {
                old.stop_routing_outbound_to(&self.outbound_wake);
            }
        }
        self.mesh_session = session;
        if let Some(session) = self.mesh_session.clone() {
            let effects = self.core.handle(Event::MeshSessionArrived, self.now());
            self.execute(effects);
            session.route_outbound_to(self.outbound_wake.clone());
        }
    }

    fn now(&self) -> Now {
        Now {
            monotonic_ms: u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX),
            wall_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| {
                    u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
                }),
        }
    }

    /// Carry out effects in order. Link and mesh calls are made as they
    /// come; what is for the platform is gathered and published once, so a
    /// round of effects wakes the listener once.
    fn execute(&mut self, effects: Vec<Effect>) {
        let mut batch = MobileRadioDriverUpdateRecord::default();
        for effect in effects {
            match effect {
                Effect::Send {
                    frame,
                    raw_transaction_id,
                } => self.link.send(frame, raw_transaction_id),
                Effect::ResetFraming => self.link.reset_framing(),
                Effect::Invalidate { retry } => self.link.invalidate(retry),
                Effect::DidAttach => self.link.did_attach(),
                Effect::DidReportName(name) => self.link.did_report_name(name),
                Effect::AbandonBinding => self.link.abandon_binding(),
                Effect::DidEnterDfu => self.link.did_enter_dfu(),
                Effect::MeshReceive(record) => {
                    if let Some(session) = &self.mesh_session
                        && let Err(error) = session.receive(record)
                    {
                        log::warn!(
                            target: self.core.log_target(),
                            "mesh session refused a frame: {error}"
                        );
                    }
                }
                Effect::MeshComplete {
                    frame_id,
                    transmitted,
                } => {
                    // A stale completion is a diagnostic, never a reason to
                    // disturb a healthy link.
                    if let Some(session) = &self.mesh_session
                        && let Err(error) = session.complete_outbound_frame(frame_id, transmitted)
                    {
                        log::warn!(
                            target: self.core.log_target(),
                            "could not complete mesh frame {frame_id}: {error}"
                        );
                    }
                }
                Effect::MeshFailOutbound => {
                    if let Some(session) = &self.mesh_session {
                        let _ = session.fail_outbound_transmissions();
                    }
                }
                Effect::MeshFrameTime(frame_ms) => {
                    if let Some(session) = &self.mesh_session {
                        session.set_frame_time_ms(frame_ms);
                    }
                }
                Effect::State(state) => batch.state = Some(*state),
                Effect::Pushed(push) => batch.pushed_properties.push(push),
                Effect::HostReleased(key) => batch.host_releases.push(key),
            }
        }
        if batch != MobileRadioDriverUpdateRecord::default() {
            self.shared.publish(batch);
        }
    }
}
