//! The host stack this tool becomes to reach a device over the mesh.
//!
//! Every other part of this tool speaks ULCP down the wire to the radio
//! it is attached to. Reaching a device across the room means borrowing
//! that radio and becoming a node: running a host MAC over the
//! attachment, and speaking the same ULCP grammar to the far end,
//! carried by the Node Management binding
//! (`docs/protocol/src/app-node-management.md`).
//!
//! Two identities are in play and it is worth keeping them apart. The
//! attached radio has its own device identity, which `identity` shows.
//! This tool has a separate, persistent administrator identity—
//! `admin-key` prints it—and a device is managed from here only once
//! that key is listed in its `PROP_DEV_ADMINS`, which `dev-admin add`
//! does over a bench link.

use std::collections::VecDeque;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rand::{Rng as _, rng};
use tokio::time::Instant;

use umsh::core::PublicKey;
use umsh::crypto::{
    CryptoEngine, NodeIdentity,
    software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
};
use umsh::mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig};
use umsh::node::{Host, LocalNode};
use umsh::node_mgmt::admin::{Failure, Outcome};
use umsh::node_mgmt::{NodeManager, Progress};
use umsh::tokio_support::{StdClock, TokioFileCounterStore, TokioFileKeyValueStore, TokioPlatform};
use umsh::ulcp::{UlcpDevice, UlcpDeviceConfig, UlcpError};
use umsh::ulcp_mesh::{
    DeliveredOutcome, MeshEndpoint, MeshFault, MeshFrameLink, MeshRequest, mesh_link,
};
use umsh::ulcp_wire::ids::prop;
use umsh_sync::AsyncRefCell;

use crate::App;
use crate::connection::{self, FrameTap, Recovered, Recovery, Relink, Session, SessionLink};
use crate::output::{field, note};

// ─── The host stack this tool becomes ────────────────────────────────────────

/// One identity—the administrator's. Channels and queues are sized for
/// a tool that talks to one device at a time and holds one exchange open
/// while it does.
///
/// Peers are sized for `discover` instead, which is the one command that
/// meets a crowd: every stranger that answers a solicitation is
/// auto-registered from the full key it sends, and the registry evicts
/// the least recently used once it is full. Four slots would have made a
/// discovery of any size report the last four nodes to speak. This is a
/// host tool with a host's memory.
const IDENTITIES: usize = 1;
const PEERS: usize = 32;
const CHANNELS: usize = 1;
const ACKS: usize = 8;
const TX: usize = 8;
const FRAME: usize = 256;
const DUP: usize = 32;

/// The radio this tool runs its MAC over: the attached device, whatever
/// transport it was attached over. One type, because the transport is
/// what recovery replaces, and only this type knows how.
pub type CtlRadio = UlcpDevice<SessionLink>;
pub type CtlPlatform = TokioPlatform<CtlRadio, TokioFileCounterStore, TokioFileKeyValueStore>;
pub type CtlMac = Mac<CtlPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
pub type CtlHandle<'a> =
    MacHandle<'a, CtlPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
pub type CtlHost<'a> = Host<CtlHandle<'a>>;

/// How long the whole operation may take before the tool gives up.
///
/// The exchange engine has its own attempt budget; this bounds the
/// continuation loop of a large read, where each fragment restarts that
/// budget.
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(180);

// ─── The administrator identity ──────────────────────────────────────────────

/// Load the administrator identity, generating one the first time.
///
/// The seed is a plain 32-byte file, written where the rest of this
/// tool's state lives.
pub fn admin_identity() -> Result<SoftwareIdentity> {
    let path = connection::admin_identity_path()
        .ok_or_else(|| anyhow!("no HOME directory to keep an administrator identity in"))?;
    load_or_create_identity(&path)
}

fn load_or_create_identity(path: &Path) -> Result<SoftwareIdentity> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let secret: [u8; 32] = bytes.try_into().map_err(|_| {
                anyhow!(
                    "{} is not a 32-byte identity seed; move it aside to start over",
                    path.display()
                )
            })?;
            Ok(SoftwareIdentity::from_secret_bytes(&secret))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let mut secret = [0u8; 32];
            rng().fill_bytes(&mut secret);
            std::fs::write(path, secret).with_context(|| format!("writing {}", path.display()))?;
            note("generated a new administrator identity");
            Ok(SoftwareIdentity::from_secret_bytes(&secret))
        }
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// `admin-key`: print the public key a device must list to be managed
/// from here.
pub fn show_admin_key() -> Result<()> {
    let identity = admin_identity()?;
    field("administrator", identity.public_key().to_string());
    if let Some(path) = connection::admin_identity_path() {
        field("identity", path.display());
    }
    note("a device lists this key under `dev-admin add` before it will answer");
    Ok(())
}

// ─── Bring-up ────────────────────────────────────────────────────────────────

/// The device's live PHY, as a radio configuration.
///
/// The host MAC paces itself on modeled airtime, and the attach this
/// tool uses deliberately leaves the radio's configuration alone, so the
/// defaults it carries may describe some other radio entirely. Read the
/// real ones before borrowing the link.
///
/// A radio whose PHY is switched off refuses every transmission, and it
/// does so far downstream—as an `INVALID_STATE` on the first frame the
/// MAC tries to send, long after the radio has been borrowed. Reading
/// the flag here turns that into an answer the caller can act on, while
/// it still has its attachment.
pub async fn adopt_phy(device: &mut CtlRadio) -> Result<UlcpDeviceConfig> {
    let keys = [
        prop::PHY_FREQ,
        prop::PHY_LORA_BW,
        prop::PHY_LORA_SF,
        prop::PHY_LORA_CR,
        prop::PHY_TX_POWER,
        prop::PHY_ENABLED,
    ];
    let answers = device.get_props(&keys).await?;
    let mut config = connection::attach_config();
    for (requested, answer) in keys.iter().zip(&answers) {
        let Ok((_, value)) = answer else { continue };
        match *requested {
            prop::PHY_ENABLED => {
                if value.first() == Some(&0) {
                    bail!("the radio's PHY is switched off; turn it on with `set phy-enabled on`");
                }
            }
            prop::PHY_FREQ => {
                if let Ok(bytes) = <[u8; 4]>::try_from(&value[..]) {
                    config.freq_khz = u32::from_le_bytes(bytes);
                }
            }
            prop::PHY_LORA_BW => {
                if let Ok(bytes) = <[u8; 4]>::try_from(&value[..]) {
                    config.bandwidth_hz = u32::from_le_bytes(bytes);
                }
            }
            prop::PHY_LORA_SF => {
                if let Some(&sf) = value.first() {
                    config.spreading_factor = sf;
                }
            }
            prop::PHY_LORA_CR => {
                if let Some(&cr) = value.first() {
                    config.coding_rate_denom = cr;
                }
            }
            prop::PHY_TX_POWER => {
                if let Some(&power) = value.first() {
                    config.tx_power_dbm = power as i8;
                }
            }
            _ => {}
        }
    }
    Ok(config)
}

/// This host owns the MAC and does its own filtering, so the radio's
/// provisioned receive filters must not gate delivery. The mode is
/// session-scoped and touches no provisioning—which is also why it is
/// asserted again after every reattach.
pub async fn prepare_radio(device: &mut CtlRadio) -> Result<()> {
    match device.set_prop(prop::MAC_PROMISCUOUS, &[1]).await {
        Ok(_) => Ok(()),
        Err(UlcpError::Status(status)) => {
            note(format!(
                "radio refused promiscuous mode ({status:?}); reception follows its own filtering"
            ));
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Open the frame-counter store the administrator identity persists to.
///
/// Separate from [`build_mac`] so a failure here happens before the
/// radio is consumed, leaving the caller its attachment to hand back.
pub fn counter_store() -> Result<TokioFileCounterStore> {
    let path = connection::admin_counter_path()
        .ok_or_else(|| anyhow!("no HOME directory to keep frame counters in"))?;
    TokioFileCounterStore::new(path)
        .map_err(|error| anyhow!("opening the counter store: {error:?}"))
}

/// What a node stack needs to know about the radio it runs over, beyond
/// the radio itself: how to reach it again, and whether to.
///
/// The session that lent the radio is described here rather than
/// carried—its device handle is inside the MAC for the duration—so the
/// stack can put a lost link back under that handle without the session
/// being any the wiser.
#[derive(Clone)]
pub struct StackContext {
    pub target: connection::Target,
    pub tap: FrameTap,
    pub label: String,
    /// The policy [`NodeStack::pump_until`] heals a lost link with, or
    /// `None` when the caller does its own healing (the mesh driver) or
    /// wants the failure (`--no-reconnect`).
    pub self_heal: Option<Recovery>,
}

impl StackContext {
    /// Describe `session`'s radio for a stack that is about to borrow it.
    fn for_session(session: &Session, self_heal: Option<Recovery>) -> Self {
        Self {
            target: session.target.clone(),
            tap: session.tap.clone(),
            label: session.label.clone(),
            self_heal,
        }
    }

    fn relink(&self) -> Relink<'_> {
        Relink {
            target: &self.target,
            tap: &self.tap,
            label: &self.label,
        }
    }
}

/// Something this tool runs as a node on its own radio.
///
/// `manage`, the messaging commands, and `discover` all want the same
/// preamble—read the device's PHY, take the attachment over, turn it
/// into a MAC—and the same guarantee afterwards, that the attachment
/// comes back whether the errand worked or not. That is
/// [`borrowing_the_radio`]; this is the part that differs.
pub trait RadioErrand {
    async fn run(
        self,
        mac: &AsyncRefCell<CtlMac>,
        identity: SoftwareIdentity,
        ctx: &StackContext,
    ) -> Result<()>;
}

/// Take the attachment over as this tool's radio, run `errand` on it,
/// and hand the attachment back.
///
/// This tool has one radio. A command that kept it on failure would
/// leave the session holding nothing, so the give-back is unconditional
///—every early return here happens before the link is consumed.
pub async fn borrowing_the_radio<E: RadioErrand>(app: &mut App, errand: E) -> Result<()> {
    let identity = admin_identity()?;
    // Read the device's own PHY before taking the link over, so the host
    // MAC paces itself the way the radio is actually configured.
    let config = adopt_phy(app.device()?).await?;

    let Some(session) = app.session.take() else {
        bail!("not attached—try `ble-scan` or `connect`");
    };
    let ctx = StackContext::for_session(&session, app.recovery.clone());
    let Session {
        device,
        target,
        label,
        tap,
    } = session;
    // Re-attaching is the only way to give the handle a configuration; it
    // costs a handful of property reads and no reconnect. The link is
    // consumed, so a failure here really does end the attachment.
    let mut device = UlcpDevice::attach_administrative(device.into_link(), config)
        .await
        .context("re-attaching the radio with its own PHY")?;
    if app.trace {
        connection::install_trace(&mut device);
    }
    prepare_radio(&mut device).await?;

    let (device, result) = match counter_store() {
        Ok(store) => {
            let mac = build_mac(device, store);
            let result = errand.run(&mac, identity, &ctx).await;
            (mac.into_inner().into_radio(), result)
        }
        Err(error) => (device, Err(error)),
    };
    app.session = Some(Session {
        device,
        target,
        label,
        tap,
    });
    result
}

/// Take the radio over as this tool's MAC.
pub fn build_mac(radio: CtlRadio, store: TokioFileCounterStore) -> AsyncRefCell<CtlMac> {
    AsyncRefCell::new(Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        StdClock::new(),
        rng(),
        store,
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    ))
}

/// The tool as a node: a host MAC over the borrowed radio, one local
/// node standing for the administrator identity, and the pump that keeps
/// both moving.
pub struct NodeStack<'a> {
    pub host: CtlHost<'a>,
    pub node: LocalNode<CtlHandle<'a>>,
    pub handle: CtlHandle<'a>,
    mac: &'a AsyncRefCell<CtlMac>,
    ctx: StackContext,
    /// How many times the link under the radio has been put back. A
    /// caller that had an exchange in flight compares this before and
    /// after to learn whether the exchange straddled a recovery.
    recoveries: u32,
    started: Instant,
}

impl<'a> NodeStack<'a> {
    /// Register `identity` on the borrowed MAC and stand a node up on it,
    /// returning the stack and the administrator's public key.
    pub async fn build(
        mac: &'a AsyncRefCell<CtlMac>,
        identity: SoftwareIdentity,
        ctx: &StackContext,
    ) -> Result<(Self, PublicKey)> {
        let handle = MacHandle::new(mac);
        let local_key = *identity.public_key();
        let identity_id = handle
            .add_identity(identity)
            .await
            .map_err(|error| anyhow!("registering the administrator identity: {error:?}"))?;
        // A frame counter that restarted at zero would be rejected as a
        // replay by every device that has heard this identity before.
        handle
            .load_persisted_counter(identity_id)
            .await
            .map_err(|error| anyhow!("loading persisted frame counters: {error:?}"))?;

        let mut host: CtlHost<'a> = Host::new(handle);
        let node = host.add_node(identity_id);
        Ok((
            Self {
                host,
                node,
                handle,
                mac,
                ctx: ctx.clone(),
                recoveries: 0,
                started: Instant::now(),
            },
            local_key,
        ))
    }

    /// When this stack came up. The exchange engine's deadlines are
    /// expressed against [`Self::now_ms`], which counts from here.
    pub fn started(&self) -> Instant {
        self.started
    }

    pub fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// How many times the link under the radio has been put back.
    pub fn recoveries(&self) -> u32 {
        self.recoveries
    }

    /// Whether the radio's transport has reported itself gone.
    pub async fn radio_link_lost(&self) -> bool {
        self.mac.borrow().await.radio().link_lost()
    }

    /// Put the link back under the radio, attempt after attempt, until
    /// it is back or `abort` resolves.
    ///
    /// The MAC and everything standing on it survive: identities,
    /// peers, routes, pending acknowledgments. Only the transport under
    /// the device handle is replaced, and the session-scoped state this
    /// host asserts on the radio is asserted again. The exclusive borrow
    /// is uncontended here—nothing is pumping while the radio is known
    /// to be gone.
    pub async fn recover(
        &mut self,
        policy: &Recovery,
        abort: impl Future<Output = ()>,
    ) -> Result<Recovered> {
        let mut mac = self.mac.borrow_mut().await;
        let radio = mac.radio_mut();
        let outcome = connection::recover_device(radio, &self.ctx.relink(), policy, abort).await?;
        if outcome == Recovered::Attached {
            prepare_radio(radio).await?;
            self.recoveries += 1;
        }
        Ok(outcome)
    }

    /// Drive the MAC until it has nothing to do or `deadline` arrives.
    ///
    /// A quiet radio produces no MAC wake, so the timeouts that retire an
    /// unanswered acknowledgment need their own nudge afterwards.
    ///
    /// A radio whose link has gone is put back here, when the stack was
    /// told to: the pump is where the loss is noticed, and the caller's
    /// own deadline loop simply comes round again once the link is back.
    /// Ctrl-C ends the wait, not the process.
    pub async fn pump_until(&mut self, deadline: Instant) -> Result<()> {
        let pumped = tokio::select! {
            result = self.host.pump_once() => result,
            _ = tokio::time::sleep_until(deadline) => Ok(()),
        };
        if let Err(error) = pumped {
            let policy = self.ctx.self_heal.clone();
            if let Some(policy) = policy
                && self.radio_link_lost().await
            {
                let interrupted = async {
                    let _ = tokio::signal::ctrl_c().await;
                };
                return match self.recover(&policy, interrupted).await? {
                    Recovered::Attached => Ok(()),
                    Recovered::Interrupted => bail!("reconnect interrupted"),
                };
            }
            bail!("the radio stopped answering: {error:?}");
        }
        self.host.service_protocol_timeouts().await;
        let _ = self.handle.service_counter_persistence().await;
        Ok(())
    }

    /// Carry one exchange to its end, pumping the host in between, giving
    /// up at `give_up`.
    ///
    /// An exchange that ends without an outcome—this tool ran out of
    /// patience, or the radio underneath went away—is abandoned, so the
    /// manager is free for the next one.
    pub async fn exchange(
        &mut self,
        manager: &mut NodeManager<CtlHandle<'a>>,
        request: &[u8],
        give_up: Instant,
    ) -> Result<Outcome> {
        manager
            .begin(request, self.now_ms())
            .map_err(|error| anyhow!("{error:?}"))?;
        let outcome = self.carry(manager, give_up).await;
        if outcome.is_err() {
            manager.abandon();
        }
        outcome
    }

    async fn carry(
        &mut self,
        manager: &mut NodeManager<CtlHandle<'a>>,
        give_up: Instant,
    ) -> Result<Outcome> {
        loop {
            if Instant::now() > give_up {
                bail!("gave up after {} s", OPERATION_TIMEOUT.as_secs());
            }
            let progress = manager
                .service(self.now_ms())
                .await
                .map_err(|error| anyhow!("sending to the device: {error:?}"))?;
            let deadline_ms = match progress {
                Progress::Done(outcome) => return Ok(outcome),
                Progress::Waiting { deadline_ms } => deadline_ms,
            };
            let wait = Duration::from_millis(deadline_ms.saturating_sub(self.now_ms()));
            self.pump_until(Instant::now() + wait).await?;
        }
    }
}

/// What a failed exchange means to somebody holding the tool.
pub fn describe(failure: Failure) -> anyhow::Error {
    match failure {
        Failure::TimedOut => anyhow!(
            "no answer—the device may be out of range, or this tool may not be one of its \
             administrators (`admin-key` prints the key it would have to list)"
        ),
        Failure::CursorInvalid => {
            anyhow!("the device's state changed mid-read; run the command again")
        }
        Failure::TooLarge => anyhow!("the answer is larger than this tool reassembles"),
        Failure::Malformed => anyhow!("the device's answer could not be read"),
        Failure::UnknownCriticalOption(number) => {
            anyhow!("the device's answer carries option {number}, which this tool does not know")
        }
    }
}

// ─── A persistent session over the mesh ──────────────────────────────────────

/// What a mesh session borrowed, and how to give it back.
///
/// The driver task owns the radio for as long as the session lasts; its
/// join handle is how the radio comes home, and the rest is what the
/// local session was called before it was lent out.
pub struct MeshHome {
    pub driver: tokio::task::JoinHandle<CtlRadio>,
    pub local_target: connection::Target,
    pub local_label: String,
    pub tap: connection::FrameTap,
}

/// Whether opening a session should say hello first.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Greeting {
    /// Ask the device its name, so the prompt is something a person
    /// recognizes and an unreachable node is reported now rather than by
    /// whatever they type first. One exchange.
    Named,
    /// Say nothing. The key is the label, and the command the caller
    /// came for is the first thing on the air.
    Silent,
}

/// Borrow the attached radio and open a ULCP session to `target` over the
/// mesh.
///
/// On success `app` is attached to the remote device and holds the
/// [`MeshHome`] that ends the session. On failure the local attachment is
/// restored, because a tool that loses your radio for mistyping a key is
/// not one you would use twice.
pub async fn open_remote(app: &mut App, target: PublicKey, greeting: Greeting) -> Result<()> {
    if app.mesh.is_some() {
        bail!("already on a mesh session—`disconnect` returns to the radio");
    }
    let identity = admin_identity()?;

    // Read the device's own PHY before taking the link over, and open the
    // counter store while there is still an attachment to hand back.
    let phy = adopt_phy(app.device()?).await?;
    let store = counter_store()?;

    let Some(session) = app.session.take() else {
        bail!("not attached—try `ble-scan` or `connect`");
    };
    // The driver heals the link itself, so the stack under it does not.
    let ctx = StackContext::for_session(&session, None);
    let recovery = app.recovery.clone();
    let connection::Session {
        device,
        target: local_target,
        label: local_label,
        tap,
    } = session;

    // Re-attaching is the only way to give the handle the configuration
    // the host MAC paces itself on. The link is consumed, so a failure
    // here really does end the attachment.
    let mut radio = UlcpDevice::attach_administrative(device.into_link(), phy.clone())
        .await
        .context("re-attaching the radio with its own PHY")?;
    if app.trace {
        connection::install_trace(&mut radio);
    }
    prepare_radio(&mut radio).await?;

    let (link, endpoint) = mesh_link();
    let driver = tokio::task::spawn_local(drive(
        radio, store, identity, target, endpoint, ctx, recovery,
    ));

    // From here the radio belongs to the driver, and the only way back to
    // it is through the join handle.
    let home = MeshHome {
        driver,
        local_target,
        local_label,
        tap,
    };
    match open_session(link, phy, target, greeting).await {
        Ok(session) => {
            app.session = Some(session);
            app.mesh = Some(home);
            Ok(())
        }
        Err(error) => {
            // The link is already dropped, so the driver is winding down;
            // wait for the radio and put the local session back.
            restore_local(app, home).await;
            Err(error)
        }
    }
}

/// Open the device handle at the far end of `link`.
///
/// Opening costs nothing on the air—the binding needs no session and
/// the device is told nothing—so the only exchange here is the name,
/// and only when one was asked for.
async fn open_session(
    link: MeshFrameLink,
    phy: UlcpDeviceConfig,
    target: PublicKey,
    greeting: Greeting,
) -> Result<connection::Session> {
    let tap = connection::new_tap();
    let session_link = SessionLink::new(connection::AnyLink::Mesh(link), tap.clone());
    let mut device = UlcpDevice::open_remote(session_link, connection::mesh_attach_config(phy));
    // A device that will not say its name is still perfectly usable; the
    // key it answers to will do as a label.
    let label = match greeting {
        Greeting::Silent => target.to_string(),
        Greeting::Named => {
            note("reaching the device over the mesh—an exchange can take a while");
            match device.device_name().await {
                Ok(name) if !name.is_empty() => name,
                Ok(_) => target.to_string(),
                Err(error) => {
                    return Err(
                        anyhow::Error::new(error).context("reaching the device over the mesh")
                    );
                }
            }
        }
    };
    Ok(connection::Session {
        device,
        target: connection::Target::Mesh { key: target.0 },
        label,
        tap,
    })
}

/// End a mesh session and put the local attachment back.
///
/// The session's device handle must already be dropped: that is what
/// closes the link and tells the driver to wind down.
pub async fn restore_local(app: &mut App, home: MeshHome) {
    let MeshHome {
        driver,
        local_target,
        local_label,
        tap,
    } = home;
    match driver.await {
        Ok(radio) => {
            app.session = Some(connection::Session {
                device: radio,
                target: local_target,
                label: local_label,
                tap,
            });
        }
        Err(error) => {
            // The driver panicked or was cancelled, and the radio went
            // with it. Say so rather than leaving a session that is not
            // attached to anything.
            note(format!(
                "the mesh session ended badly ({error}); the radio was not recovered"
            ));
        }
    }
}

/// The driver task: owns the borrowed radio for the life of the session,
/// carries every request the link hands it, and gives the radio back.
async fn drive(
    radio: CtlRadio,
    store: TokioFileCounterStore,
    identity: SoftwareIdentity,
    target: PublicKey,
    endpoint: MeshEndpoint,
    ctx: StackContext,
    recovery: Option<Recovery>,
) -> CtlRadio {
    let mac = build_mac(radio, store);
    serve(&mac, identity, target, endpoint, &ctx, recovery.as_ref()).await;
    mac.into_inner().into_radio()
}

/// One step of the driver loop: what the select settled on.
enum Step {
    /// A request to carry.
    Carry(MeshRequest),
    /// The MAC made progress on its own.
    Pumped,
    /// The MAC could not be pumped; whether that is the link is decided
    /// once the borrow is released.
    Failed(anyhow::Error),
    /// The link is gone; the session is over.
    Closed,
}

/// Whether an exchange that straddled a recovery deserves a second try.
///
/// The exchange engine's own retries absorb a short outage; a long one
/// ends the exchange with no outcome, or with a timeout that was really
/// the radio's absence. Either is worth one more try—except for a
/// reset-class request, which may already have been delivered and must
/// not be delivered twice.
fn should_rerun(recovered: bool, outcome: &Result<Outcome>, reset_class: bool) -> bool {
    recovered
        && !reset_class
        && match outcome {
            Err(_) | Ok(Outcome::Failed(Failure::TimedOut)) => true,
            Ok(_) => false,
        }
}

/// Everything the driver holds while serving a session, so carrying a
/// request reads the same wherever it happens.
struct Driver<'a> {
    stack: NodeStack<'a>,
    manager: NodeManager<CtlHandle<'a>>,
    routes: crate::routes::RouteCache,
}

impl Driver<'_> {
    /// Run one exchange, reporting whether a recovery happened under it.
    async fn attempt(&mut self, request: &MeshRequest) -> (bool, Result<Outcome>) {
        let before = self.stack.recoveries();
        let give_up = Instant::now() + OPERATION_TIMEOUT;
        let outcome = self
            .stack
            .exchange(&mut self.manager, request.frame(), give_up)
            .await;
        (self.stack.recoveries() != before, outcome)
    }

    /// Carry one request and hand its outcome back through `endpoint`.
    async fn carry(&mut self, endpoint: &mut MeshEndpoint, request: MeshRequest) {
        let (recovered, mut outcome) = self.attempt(&request).await;
        if should_rerun(recovered, &outcome, request.is_reset_class()) {
            outcome = self.attempt(&request).await.1;
        }
        match outcome {
            Ok(Outcome::Replied { .. }) => {
                let reply = self.manager.reply().to_vec();
                endpoint.deliver(&request, DeliveredOutcome::Replied(&reply));
            }
            Ok(Outcome::NoResponse) => endpoint.deliver(&request, DeliveredOutcome::NoResponse),
            Ok(Outcome::Failed(failure)) => {
                endpoint.deliver(&request, DeliveredOutcome::Failed(failure))
            }
            // This command could not be carried—it ran out of patience,
            // or the engine would not take it. The session survives: a
            // radio that has actually died fails the pump on the very
            // next turn of the loop, and that is dealt with there.
            Err(error) => endpoint.refuse(format!("{error:#}")),
        }
        // An exchange is where a route is learned, so this is where
        // there is something new to remember. Writing per exchange
        // rather than at the end also means the file is current while a
        // shell session is still open, which is what lets `routes`
        // report on one.
        self.routes.harvest(&self.stack.handle).await;
        if let Err(error) = self.routes.store() {
            crate::output::warn(format!("could not save learned routes: {error:#}"));
        }
    }
}

async fn serve(
    mac: &AsyncRefCell<CtlMac>,
    identity: SoftwareIdentity,
    target: PublicKey,
    mut endpoint: MeshEndpoint,
    ctx: &StackContext,
    recovery: Option<&Recovery>,
) {
    let (stack, _local_key) = match NodeStack::build(mac, identity, ctx).await {
        Ok(built) => built,
        Err(error) => return endpoint.fail(MeshFault::Radio(format!("{error:#}"))),
    };
    let peer = match stack.node.peer(target).await {
        Ok(peer) => peer,
        Err(error) => {
            return endpoint.fail(MeshFault::Radio(format!(
                "registering the device as a peer: {error:?}"
            )));
        }
    };
    // Whatever an earlier invocation learned about reaching this device,
    // put back before the first frame goes out. A wrong guess costs one
    // exchange and the MAC's own retry finds the path again; not
    // guessing costs a flood every time the tool is run.
    let routes = crate::routes::RouteCache::load();
    if let Some(record) = routes.get(&target) {
        peer.restore_route(record.route.clone()).await;
    }

    // The first token has only to be unpredictable; the manager keeps
    // every one after it distinct from all of its own.
    let mut seed = [0u8; 2];
    rng().fill_bytes(&mut seed);
    let manager = NodeManager::new(peer, u16::from_be_bytes(seed));
    let mut driver = Driver {
        stack,
        manager,
        routes,
    };

    let mut fatal = None;
    loop {
        // The arms only settle what happened. Everything that needs the
        // stack runs below, once the futures borrowing it are gone.
        let step = tokio::select! {
            request = endpoint.next() => match request {
                Some(request) => Step::Carry(request),
                None => Step::Closed,
            },
            result = driver.stack.host.pump_once() => match result {
                Ok(()) => Step::Pumped,
                Err(error) => Step::Failed(anyhow!("the radio stopped answering: {error:?}")),
            },
        };
        match step {
            Step::Closed => break,
            Step::Pumped => {
                driver.stack.host.service_protocol_timeouts().await;
                let _ = driver.stack.handle.service_counter_persistence().await;
            }
            Step::Failed(error) => {
                let Some(policy) = recovery else {
                    fatal = Some(MeshFault::Radio(format!("{error:#}")));
                    break;
                };
                if !driver.stack.radio_link_lost().await {
                    fatal = Some(MeshFault::Radio(format!("{error:#}")));
                    break;
                }
                // The session goes on while the link is put back: what
                // arrives meanwhile waits its turn, and the handle being
                // dropped—the user leaving—is what ends the wait.
                let mut deferred = VecDeque::new();
                let outcome = {
                    let closed = async {
                        while let Some(request) = endpoint.next().await {
                            deferred.push_back(request);
                        }
                    };
                    driver.stack.recover(policy, closed).await
                };
                match outcome {
                    Ok(Recovered::Attached) => {
                        for request in deferred {
                            driver.carry(&mut endpoint, request).await;
                        }
                    }
                    Ok(Recovered::Interrupted) => break,
                    Err(error) => {
                        fatal = Some(MeshFault::Radio(format!("{error:#}")));
                        break;
                    }
                }
            }
            Step::Carry(request) => driver.carry(&mut endpoint, request).await,
        }
    }
    let _ = driver.stack.handle.service_counter_persistence().await;
    driver.routes.harvest(&driver.stack.handle).await;
    if let Err(error) = driver.routes.store() {
        crate::output::warn(format!("could not save learned routes: {error:#}"));
    }
    if let Some(fault) = fatal {
        endpoint.fail(fault);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exchange_is_rerun_once_only_when_a_recovery_ate_it() {
        let lost: Result<Outcome> = Err(anyhow!("gave up"));
        let timed_out: Result<Outcome> = Ok(Outcome::Failed(Failure::TimedOut));
        let answered: Result<Outcome> = Ok(Outcome::NoResponse);
        let malformed: Result<Outcome> = Ok(Outcome::Failed(Failure::Malformed));

        assert!(should_rerun(true, &lost, false));
        assert!(should_rerun(true, &timed_out, false));
        // An exchange that reached an answer is not repeated.
        assert!(!should_rerun(true, &answered, false));
        // Nor one the device answered badly: that was not the link.
        assert!(!should_rerun(true, &malformed, false));
        // Nothing is repeated when the link never went away.
        assert!(!should_rerun(false, &lost, false));
        // A reset may already have landed; it is never sent twice.
        assert!(!should_rerun(true, &lost, true));
    }
}
