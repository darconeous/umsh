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
//! This tool has a separate, persistent administrator identity —
//! `admin-key` prints it — and a device is managed from here only once
//! that key is listed in its `PROP_DEV_ADMINS`, which `dev-admin add`
//! does over a bench link.

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
use umsh::hal::Radio;
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
use crate::connection::{self, SessionLink};
use crate::output::{field, note};

// ─── The host stack this tool becomes ────────────────────────────────────────

/// One identity — the administrator's. Peers, channels, and queues are
/// sized for a tool that talks to one device at a time and holds one
/// exchange open while it does.
const IDENTITIES: usize = 1;
const PEERS: usize = 4;
const CHANNELS: usize = 1;
const ACKS: usize = 8;
const TX: usize = 8;
const FRAME: usize = 256;
const DUP: usize = 32;

pub type CtlPlatform<R> = TokioPlatform<R, TokioFileCounterStore, TokioFileKeyValueStore>;
pub type CtlMac<R> = Mac<CtlPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
pub type CtlHandle<'a, R> =
    MacHandle<'a, CtlPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
pub type CtlHost<'a, R> = Host<CtlHandle<'a, R>>;

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
pub async fn adopt_phy(device: &mut UlcpDevice<SessionLink>) -> Result<UlcpDeviceConfig> {
    let keys = [
        prop::PHY_FREQ,
        prop::PHY_LORA_BW,
        prop::PHY_LORA_SF,
        prop::PHY_LORA_CR,
        prop::PHY_TX_POWER,
    ];
    let answers = device.get_props(&keys).await?;
    let mut config = connection::attach_config();
    for (requested, answer) in keys.iter().zip(&answers) {
        let Ok((_, value)) = answer else { continue };
        match *requested {
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
/// session-scoped and touches no provisioning.
pub async fn prepare_radio(device: &mut UlcpDevice<SessionLink>) -> Result<()> {
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

/// Take the radio over as this tool's MAC.
pub fn build_mac<R: Radio>(radio: R, store: TokioFileCounterStore) -> AsyncRefCell<CtlMac<R>> {
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
pub struct NodeStack<'a, R: Radio> {
    pub host: CtlHost<'a, R>,
    pub node: LocalNode<CtlHandle<'a, R>>,
    pub handle: CtlHandle<'a, R>,
    started: Instant,
}

impl<'a, R: Radio> NodeStack<'a, R>
where
    R::Error: core::fmt::Debug,
{
    /// Register `identity` on the borrowed MAC and stand a node up on it,
    /// returning the stack and the administrator's public key.
    pub async fn build(
        mac: &'a AsyncRefCell<CtlMac<R>>,
        identity: SoftwareIdentity,
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

        let mut host: CtlHost<'a, R> = Host::new(handle);
        let node = host.add_node(identity_id);
        Ok((
            Self {
                host,
                node,
                handle,
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

    /// Drive the MAC until it has nothing to do or `deadline` arrives.
    ///
    /// A quiet radio produces no MAC wake, so the timeouts that retire an
    /// unanswered acknowledgment need their own nudge afterwards.
    pub async fn pump_until(&mut self, deadline: Instant) -> Result<()> {
        tokio::select! {
            result = self.host.pump_once() => {
                result.map_err(|error| anyhow!("the radio stopped answering: {error:?}"))?;
            }
            _ = tokio::time::sleep_until(deadline) => {}
        }
        self.host.service_protocol_timeouts().await;
        let _ = self.handle.service_counter_persistence().await;
        Ok(())
    }

    /// Carry one exchange to its end, pumping the host in between, giving
    /// up at `give_up`.
    pub async fn exchange(
        &mut self,
        manager: &mut NodeManager<CtlHandle<'a, R>>,
        request: &[u8],
        give_up: Instant,
    ) -> Result<Outcome> {
        manager
            .begin(request, self.now_ms())
            .map_err(|error| anyhow!("{error:?}"))?;
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
            "no answer — the device may be out of range, or this tool may not be one of its \
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
    pub driver: tokio::task::JoinHandle<UlcpDevice<SessionLink>>,
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
        bail!("already on a mesh session — `disconnect` returns to the radio");
    }
    let identity = admin_identity()?;

    // Read the device's own PHY before taking the link over, and open the
    // counter store while there is still an attachment to hand back.
    let phy = adopt_phy(app.device()?).await?;
    let store = counter_store()?;

    let Some(session) = app.session.take() else {
        bail!("not attached — try `scan` or `connect`");
    };
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
    let driver = tokio::task::spawn_local(drive(radio, store, identity, target, endpoint));

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
/// Opening costs nothing on the air — the binding needs no session and
/// the device is told nothing — so the only exchange here is the name,
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
            note("reaching the device over the mesh — an exchange can take a while");
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
    radio: UlcpDevice<SessionLink>,
    store: TokioFileCounterStore,
    identity: SoftwareIdentity,
    target: PublicKey,
    endpoint: MeshEndpoint,
) -> UlcpDevice<SessionLink> {
    let mac = build_mac(radio, store);
    serve(&mac, identity, target, endpoint).await;
    mac.into_inner().into_radio()
}

/// One step of the driver loop: what the select settled on.
enum Step {
    /// A request to carry.
    Carry(MeshRequest),
    /// The MAC made progress on its own.
    Pumped,
    /// The link is gone; the session is over.
    Closed,
}

async fn serve<R: Radio>(
    mac: &AsyncRefCell<CtlMac<R>>,
    identity: SoftwareIdentity,
    target: PublicKey,
    mut endpoint: MeshEndpoint,
) where
    R::Error: core::fmt::Debug,
{
    let (mut stack, _local_key) = match NodeStack::build(mac, identity).await {
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
    // The first token has only to be unpredictable; the manager keeps
    // every one after it distinct from all of its own.
    let mut seed = [0u8; 2];
    rng().fill_bytes(&mut seed);
    let mut manager = NodeManager::new(peer, u16::from_be_bytes(seed));

    let mut fatal = None;
    loop {
        // The arms only settle what happened. Everything that needs the
        // stack runs below, once the futures borrowing it are gone.
        let step = tokio::select! {
            request = endpoint.next() => match request {
                Some(request) => Step::Carry(request),
                None => Step::Closed,
            },
            result = stack.host.pump_once() => match result {
                Ok(()) => Step::Pumped,
                Err(error) => {
                    fatal = Some(MeshFault::Radio(format!(
                        "the radio stopped answering: {error:?}"
                    )));
                    break;
                }
            },
        };
        match step {
            Step::Closed => break,
            Step::Pumped => {
                stack.host.service_protocol_timeouts().await;
                let _ = stack.handle.service_counter_persistence().await;
            }
            Step::Carry(request) => {
                let give_up = Instant::now() + OPERATION_TIMEOUT;
                match stack.exchange(&mut manager, request.frame(), give_up).await {
                    Ok(Outcome::Replied { .. }) => {
                        let reply = manager.reply().to_vec();
                        endpoint.deliver(&request, DeliveredOutcome::Replied(&reply));
                    }
                    Ok(Outcome::NoResponse) => {
                        endpoint.deliver(&request, DeliveredOutcome::NoResponse)
                    }
                    Ok(Outcome::Failed(failure)) => {
                        endpoint.deliver(&request, DeliveredOutcome::Failed(failure))
                    }
                    // This command could not be carried — it ran out of
                    // patience, or the engine would not take it. The
                    // session survives: a radio that has actually died
                    // fails the pump on the very next turn of this loop,
                    // and that is what ends things.
                    Err(error) => endpoint.refuse(format!("{error:#}")),
                }
            }
        }
    }
    let _ = stack.handle.service_counter_persistence().await;
    if let Some(fault) = fatal {
        endpoint.fail(fault);
    }
}
