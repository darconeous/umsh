//! `manage`: administering another device over the mesh.
//!
//! Every other command in this tool speaks ULCP down the wire to the
//! radio it is attached to. This one borrows that radio and becomes a
//! node: it runs a host MAC over the attachment, and speaks the same ULCP
//! grammar to a device across the room, carried by the Node Management
//! binding (`docs/protocol/src/app-node-management.md`).
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
use umsh::node::Host;
use umsh::node_mgmt::admin::{Failure, Outcome};
use umsh::node_mgmt::{NodeManager, Progress};
use umsh::tokio_support::{StdClock, TokioFileCounterStore, TokioFileKeyValueStore, TokioPlatform};
use umsh::ulcp::{UlcpDevice, UlcpDeviceConfig, UlcpError};
use umsh::ulcp_wire::ids::prop;
use umsh::ulcp_wire::{Status, capability_name, frame, property_name, reply};
use umsh_sync::AsyncRefCell;

use super::tables::TableOp;
use super::values::{AssignArg, BytesArg, KeyArg};
use crate::connection::{Session, SessionLink};
use crate::output::{field, hex, note, subfield};
use crate::{App, connection};

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

type CtlPlatform<R> = TokioPlatform<R, TokioFileCounterStore, TokioFileKeyValueStore>;
type CtlMac<R> = Mac<CtlPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
type CtlHandle<'a, R> =
    MacHandle<'a, CtlPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
type CtlHost<'a, R> = Host<CtlHandle<'a, R>>;

/// How long the whole operation may take before the tool gives up.
///
/// The exchange engine has its own attempt budget; this bounds the
/// continuation loop of a large read, where each fragment restarts that
/// budget.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(180);

// ─── Command surface ─────────────────────────────────────────────────────────

#[derive(Debug, clap::Subcommand)]
pub enum ManageOp {
    /// Read the device's capabilities and versions in one exchange.
    Info,

    /// Read one property.
    Get {
        #[arg(value_name = "PROP", value_parser = super::values::parse_u32)]
        key: u32,
    },

    /// Write one property.
    Set {
        #[arg(value_name = "PROP", value_parser = super::values::parse_u32)]
        key: u32,
        #[arg(value_name = "HEX")]
        value: BytesArg,
    },

    /// Add an entry to a table property.
    Insert {
        #[arg(value_name = "PROP", value_parser = super::values::parse_u32)]
        key: u32,
        #[arg(value_name = "HEX")]
        item: BytesArg,
    },

    /// Remove an entry from a table property.
    Remove {
        #[arg(value_name = "PROP", value_parser = super::values::parse_u32)]
        key: u32,
        #[arg(value_name = "HEX")]
        selector: BytesArg,
    },

    /// Read several properties in one exchange.
    GetMany {
        #[arg(value_name = "PROP", required = true, value_parser = super::values::parse_u32)]
        keys: Vec<u32>,
    },

    /// Write several properties, in order, in one exchange. A failure
    /// stops the sequence where it happened.
    SetMany {
        #[arg(value_name = "PROP=HEX", required = true)]
        entries: Vec<AssignArg>,
    },

    /// Persist the device's live state across reboots (CMD_SAVE).
    Save,

    /// Protocol reset (CMD_RST). Answered by no response: delivery is the
    /// acknowledgment.
    Reset,

    /// Nodes authorized to manage the device — including this tool.
    Admins {
        #[command(subcommand)]
        op: Option<TableOp>,
    },
}

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

/// Take the attachment over as this tool's radio, run `op` against
/// `target`, and hand the attachment back.
pub async fn run(app: &mut App, target: KeyArg, op: ManageOp) -> Result<()> {
    let identity = admin_identity()?;
    let no_save = app.no_save;

    // Read the device's own PHY before taking the link over: the host MAC
    // paces itself on modeled airtime, and the attach this tool uses
    // deliberately leaves the radio's configuration alone, so the
    // defaults it carries may describe some other radio entirely.
    let config = adopt_phy(app.device()?).await?;

    let Some(session) = app.session.take() else {
        bail!("not attached — try `scan` or `connect`");
    };
    let Session {
        device,
        target: attached,
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

    let (device, result) = manage(device, identity, PublicKey(target.0), op, no_save).await;
    app.session = Some(Session {
        device,
        target: attached,
        label,
        tap,
    });
    result
}

/// The device's live PHY, as a radio configuration.
async fn adopt_phy(device: &mut UlcpDevice<SessionLink>) -> Result<UlcpDeviceConfig> {
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
async fn prepare_radio(device: &mut UlcpDevice<SessionLink>) -> Result<()> {
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

/// Run one operation with the radio borrowed, and give the radio back
/// whether it succeeded or not.
async fn manage(
    radio: UlcpDevice<SessionLink>,
    identity: SoftwareIdentity,
    target: PublicKey,
    op: ManageOp,
    no_save: bool,
) -> (UlcpDevice<SessionLink>, Result<()>) {
    let counters = match connection::admin_counter_path() {
        Some(path) => path,
        None => {
            return (
                radio,
                Err(anyhow!("no HOME directory to keep frame counters in")),
            );
        }
    };
    let store = match TokioFileCounterStore::new(counters) {
        Ok(store) => store,
        Err(error) => return (radio, Err(anyhow!("opening the counter store: {error:?}"))),
    };

    let mac = AsyncRefCell::new(Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        StdClock::new(),
        rng(),
        store,
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    ));
    let result = operate(&mac, identity, target, op, no_save).await;
    (mac.into_inner().into_radio(), result)
}

async fn operate<R: Radio>(
    mac: &AsyncRefCell<CtlMac<R>>,
    identity: SoftwareIdentity,
    target: PublicKey,
    op: ManageOp,
    no_save: bool,
) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
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

    let mut host: CtlHost<'_, R> = Host::new(handle);
    let node = host.add_node(identity_id);
    let peer = node
        .peer(target)
        .await
        .map_err(|error| anyhow!("registering the device as a peer: {error:?}"))?;
    // The first token has only to be unpredictable; the engine keeps
    // every one after it distinct from the last.
    let mut seed = [0u8; 2];
    rng().fill_bytes(&mut seed);
    let manager = NodeManager::new(peer, u16::from_be_bytes(seed));

    field("administrator", local_key.to_string());
    field("device", target.to_string());

    let mut ctl = Ctl {
        host,
        manager,
        handle: &handle,
        started: Instant::now(),
    };
    let result = run_op(&mut ctl, op, no_save).await;
    let _ = handle.service_counter_persistence().await;
    result
}

/// The tool as a node, for the duration of one operation.
struct Ctl<'a, R: Radio> {
    host: CtlHost<'a, R>,
    manager: NodeManager<CtlHandle<'a, R>>,
    handle: &'a CtlHandle<'a, R>,
    started: Instant,
}

impl<'a, R: Radio> Ctl<'a, R>
where
    R::Error: core::fmt::Debug,
{
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Carry one exchange to its end, pumping the host in between.
    async fn exchange(&mut self, request: &[u8]) -> Result<Outcome> {
        self.manager
            .begin(request, self.now_ms())
            .map_err(|error| anyhow!("{error:?}"))?;
        loop {
            if self.started.elapsed() > OPERATION_TIMEOUT {
                bail!("gave up after {} s", OPERATION_TIMEOUT.as_secs());
            }
            let progress = self
                .manager
                .service(self.now_ms())
                .await
                .map_err(|error| anyhow!("sending to the device: {error:?}"))?;
            let deadline_ms = match progress {
                Progress::Done(outcome) => return Ok(outcome),
                Progress::Waiting { deadline_ms } => deadline_ms,
            };
            let wait = Duration::from_millis(deadline_ms.saturating_sub(self.now_ms()));
            tokio::select! {
                result = self.host.pump_once() => {
                    result.map_err(|error| anyhow!("the radio stopped answering: {error:?}"))?;
                }
                _ = tokio::time::sleep(wait) => {}
            }
            // A quiet radio produces no MAC wake, so the timeouts that
            // retire an unanswered acknowledgment need their own nudge.
            self.host.service_protocol_timeouts().await;
            let _ = self.handle.service_counter_persistence().await;
        }
    }

    /// Carry one exchange and insist on a reply frame.
    async fn reply(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        match self.exchange(request).await? {
            Outcome::Replied { .. } => Ok(self.manager.reply().to_vec()),
            Outcome::NoResponse => bail!("the device answered nothing where a reply was due"),
            Outcome::Failed(failure) => Err(describe(failure)),
        }
    }
}

/// What a failed exchange means to somebody holding the tool.
fn describe(failure: Failure) -> anyhow::Error {
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

// ─── Operations ──────────────────────────────────────────────────────────────

async fn run_op<R: Radio>(ctl: &mut Ctl<'_, R>, op: ManageOp, no_save: bool) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    match op {
        ManageOp::Info => info(ctl).await,
        ManageOp::Get { key } => {
            let reply = ctl
                .reply(&encode(|buf| frame::prop_get(buf, 0, key))?)
                .await?;
            report_value(key, &reply)
        }
        ManageOp::Set { key, value } => {
            let reply = ctl
                .reply(&encode(|buf| frame::prop_set(buf, 0, key, &value.0))?)
                .await?;
            report_value(key, &reply)?;
            save_if_asked(ctl, no_save).await
        }
        ManageOp::Insert { key, item } => {
            let reply = ctl
                .reply(&encode(|buf| frame::prop_insert(buf, 0, key, &item.0))?)
                .await?;
            report_value(key, &reply)?;
            save_if_asked(ctl, no_save).await
        }
        ManageOp::Remove { key, selector } => {
            let reply = ctl
                .reply(&encode(|buf| frame::prop_remove(buf, 0, key, &selector.0))?)
                .await?;
            report_value(key, &reply)?;
            save_if_asked(ctl, no_save).await
        }
        ManageOp::GetMany { keys } => {
            let reply = ctl
                .reply(&encode(|buf| frame::prop_multi_get(buf, 0, &keys))?)
                .await?;
            report_entries(&keys, &reply, "reissue the rest")
        }
        ManageOp::SetMany { entries } => {
            let keys: Vec<u32> = entries.iter().map(|entry| entry.0).collect();
            let borrowed: Vec<(u32, &[u8])> = entries
                .iter()
                .map(|entry| (entry.0, entry.1.as_slice()))
                .collect();
            let reply = ctl
                .reply(&encode(|buf| frame::prop_multi_set(buf, 0, &borrowed))?)
                .await?;
            report_entries(
                &keys,
                &reply,
                "the sequence stopped there; reissue the remainder",
            )?;
            save_if_asked(ctl, no_save).await
        }
        ManageOp::Save => {
            let reply = ctl.reply(&encode(|buf| frame::save(buf, 0))?).await?;
            report_value(prop::LAST_STATUS, &reply)
        }
        ManageOp::Reset => {
            match ctl.exchange(&encode(|buf| frame::reset(buf, 0))?).await? {
                Outcome::NoResponse => {
                    println!("reset delivered; the device answers a reset with nothing");
                    Ok(())
                }
                // `CMD_RESTORE` on a device with no snapshot resets
                // nothing and answers like any other command, so a reply
                // is not a protocol violation — it is an answer.
                Outcome::Replied { .. } => report_value(prop::LAST_STATUS, ctl.manager.reply()),
                Outcome::Failed(failure) => Err(describe(failure)),
            }
        }
        ManageOp::Admins { op } => admins(ctl, op.unwrap_or(TableOp::List), no_save).await,
    }
}

async fn info<R: Radio>(ctl: &mut Ctl<'_, R>) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    let keys = [
        prop::PROTOCOL_VERSION,
        prop::DEV_VERSION,
        prop::DEV_MODEL,
        prop::DEV_NAME,
        prop::DEV_KEY,
        prop::CAPS,
    ];
    let reply = ctl
        .reply(&encode(|buf| frame::prop_multi_get(buf, 0, &keys))?)
        .await?;
    for (key, answer) in zip_answers(&keys, &reply)? {
        match answer {
            Err(status) => field(&label(key), format!("{status:?}")),
            Ok(value) => match key {
                prop::CAPS => {
                    field("capabilities", format!("{} advertised", value.len()));
                    for &number in &value {
                        match capability_name(u32::from(number)) {
                            Some(name) => subfield(&format!("{number}"), name),
                            None => subfield(&format!("{number}"), "unnamed"),
                        }
                    }
                }
                prop::DEV_VERSION | prop::DEV_MODEL | prop::DEV_NAME => field(
                    &label(key),
                    String::from_utf8_lossy(&value)
                        .trim_end_matches('\0')
                        .to_owned(),
                ),
                prop::DEV_KEY => field(&label(key), hex(&value)),
                _ => field(&label(key), hex(&value)),
            },
        }
    }
    Ok(())
}

async fn admins<R: Radio>(ctl: &mut Ctl<'_, R>, op: TableOp, no_save: bool) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    match op {
        TableOp::List => {
            let reply = ctl
                .reply(&encode(|buf| frame::prop_get(buf, 0, prop::DEV_ADMINS))?)
                .await?;
            let value = value_of(prop::DEV_ADMINS, &reply)?;
            if value.is_empty() {
                println!("no administrators listed");
            } else if !value.len().is_multiple_of(32) {
                bail!("malformed administrator listing");
            } else {
                for key in value.chunks(32) {
                    println!("{}", hex(key));
                }
            }
            Ok(())
        }
        TableOp::Add { key } => {
            let reply = ctl
                .reply(&encode(|buf| {
                    frame::prop_insert(buf, 0, prop::DEV_ADMINS, &key.0)
                })?)
                .await?;
            let digest = value_of(prop::DEV_ADMINS, &reply)?;
            println!("administrator added (digest {})", hex(&digest));
            save_if_asked(ctl, no_save).await
        }
        TableOp::Remove { key } => {
            // Removing the administrator this tool is speaking as ends
            // the conversation, which is legitimate — handing a device
            // over is exactly this — but it should not be a surprise.
            if key.0 == ctl.manager.device().0 {
                note("that key is the device's own, not an administrator's");
            }
            let reply = ctl
                .reply(&encode(|buf| {
                    frame::prop_remove(buf, 0, prop::DEV_ADMINS, &key.0)
                })?)
                .await?;
            let digest = value_of(prop::DEV_ADMINS, &reply)?;
            println!("administrator removed (digest {})", hex(&digest));
            save_if_asked(ctl, no_save).await
        }
    }
}

/// Persist a mutation, matching what the local commands do.
async fn save_if_asked<R: Radio>(ctl: &mut Ctl<'_, R>, no_save: bool) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    if no_save {
        note("--no-save — changes are live only; `manage <KEY> save` persists them");
        return Ok(());
    }
    let reply = ctl.reply(&encode(|buf| frame::save(buf, 0))?).await?;
    match reply::status_of(&reply) {
        Some(Status::OK) | None => {
            println!("saved: changes persist across reboots");
            Ok(())
        }
        Some(status) => bail!("the device refused to save ({status:?})"),
    }
}

// ─── Frames in, values out ───────────────────────────────────────────────────

/// Build a request frame into a buffer large enough for anything the
/// binding carries.
fn encode(
    build: impl FnOnce(&mut [u8]) -> Result<usize, umsh::ulcp_wire::frame::WriteError>,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; umsh::node_mgmt::REQUEST_MAX];
    let len = build(&mut buf).map_err(|error| {
        anyhow!("the request does not fit one Node Management payload: {error:?}")
    })?;
    buf.truncate(len);
    Ok(buf)
}

fn label(key: u32) -> String {
    match property_name(key) {
        Some(name) => name.to_owned(),
        None => format!("prop {key}"),
    }
}

/// The value a single-property reply carries, or the status that stands
/// in its place.
fn value_of(requested: u32, reply: &[u8]) -> Result<Vec<u8>> {
    match reply::property(requested, reply)
        .map_err(|error| anyhow!("unreadable reply: {error:?}"))?
    {
        reply::Answer::Value(value) => Ok(value.to_vec()),
        reply::Answer::Refused(status) => bail!("the device refused: {status:?}"),
    }
}

fn report_value(requested: u32, reply: &[u8]) -> Result<()> {
    let value = value_of(requested, reply)?;
    field(&label(requested), hex(&value));
    Ok(())
}

/// One position of a `CMD_PROP_ARE`: the property that was asked for, and
/// either its value or the status that occupied the slot instead.
type Answer = (u32, Result<Vec<u8>, Status>);

/// Split a `CMD_PROP_ARE` into per-position outcomes, in the order asked
/// for.
fn zip_answers(keys: &[u32], reply: &[u8]) -> Result<Vec<Answer>> {
    let entries = reply::entries(keys, reply).map_err(|error| match error {
        // A device without `CAP_CMD_MULTI` answers the unrecognized
        // command with a plain status rather than an entry list.
        reply::EntriesError::NotEntries => match reply::status_of(reply) {
            Some(status) => anyhow!("the device refused the multi-property request: {status:?}"),
            None => anyhow!("the device answered a multi-property request with something else"),
        },
        reply::EntriesError::Unreadable(error) => anyhow!("unreadable reply: {error:?}"),
    })?;
    entries
        .map(|entry| {
            let (key, answer) = entry.map_err(|error| anyhow!("malformed entry: {error:?}"))?;
            Ok(match answer {
                reply::Answer::Value(value) => (key, Ok(value.to_vec())),
                reply::Answer::Refused(status) => (key, Err(status)),
            })
        })
        .collect()
}

fn report_entries(keys: &[u32], reply: &[u8], short_advice: &str) -> Result<()> {
    let answers = zip_answers(keys, reply)?;
    for (key, answer) in &answers {
        match answer {
            Ok(value) => field(&label(*key), hex(value)),
            Err(status) => field(&label(*key), format!("{status:?}")),
        }
    }
    if answers.len() < keys.len() {
        field(
            "short",
            format!(
                "{} of {} answered; {short_advice}",
                answers.len(),
                keys.len()
            ),
        );
    }
    Ok(())
}
