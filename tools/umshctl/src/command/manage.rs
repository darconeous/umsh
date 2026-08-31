//! `manage`: administering another device over the mesh.
//!
//! One Node Management exchange at a time against a device across the
//! room, carried over the borrowed radio by the host stack in
//! [`crate::mesh`] — which is also where the administrator identity these
//! exchanges are signed with lives.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use rand::{Rng as _, rng};
use tokio::time::Instant;

use umsh::core::PublicKey;
use umsh::crypto::software::SoftwareIdentity;
use umsh::hal::Radio;
use umsh::node_mgmt::NodeManager;
use umsh::node_mgmt::admin::Outcome;
use umsh::ulcp_wire::ids::prop;
use umsh::ulcp_wire::{Status, capability_name, frame, reply};
use umsh_sync::AsyncRefCell;

use super::lifecycle::PairState;
use super::props::PropArg;
use super::tables::TableOp;
use super::values::{AssignArg, BytesArg, KeyArg};
use crate::App;
use crate::connection::confirm;
use crate::mesh::{self, CtlHandle, CtlMac, NodeStack, OPERATION_TIMEOUT, describe};
use crate::output::{address, field, hex, note, subfield};

// ─── Command surface ─────────────────────────────────────────────────────────

#[derive(Debug, clap::Subcommand)]
pub enum ManageOp {
    /// Read the device's capabilities and versions in one exchange.
    Info,

    /// Read one property, by name or number.
    Get {
        #[arg(value_name = "PROP")]
        key: PropArg,
    },

    /// Write one property, by name or number.
    Set {
        #[arg(value_name = "PROP")]
        key: PropArg,
        #[arg(value_name = "VALUE")]
        value: String,
    },

    /// Add an entry to a table property.
    Insert {
        #[arg(value_name = "PROP")]
        key: PropArg,
        #[arg(value_name = "HEX")]
        item: BytesArg,
    },

    /// Remove an entry from a table property.
    Remove {
        #[arg(value_name = "PROP")]
        key: PropArg,
        #[arg(value_name = "HEX")]
        selector: BytesArg,
    },

    /// Read several properties in one exchange.
    GetMany {
        #[arg(value_name = "PROP", required = true)]
        keys: Vec<PropArg>,
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

    /// Restart the device (CMD_REBOOT), keeping everything it has
    /// persisted. Answered by no response: delivery is the
    /// acknowledgment, and a device that cannot restart says so.
    Reboot,

    /// Manage the device's Bluetooth bonds (CAP_BLE). Unlike the
    /// resets above these answer with a status: an administrator is
    /// addressing the device's node, not one of its Bluetooth hosts, so
    /// the link survives even a clear.
    Ble {
        #[command(subcommand)]
        op: BleOp,
    },

    /// Nodes authorized to manage the device — including this tool.
    Admins {
        #[command(subcommand)]
        op: Option<TableOp>,
    },
}

/// Bond management over the mesh.
#[derive(Debug, clap::Subcommand)]
pub enum BleOp {
    /// Open or close the pairing window.
    Pair {
        /// The window state to set.
        #[arg(value_enum, default_value_t = PairState::On)]
        state: PairState,
    },
    /// Forget every paired host, the pairing PIN, and the pairing
    /// lockout, then open a pairing window.
    Clear {
        /// Confirm the wipe. Required outside the REPL, which asks.
        #[arg(long)]
        yes: bool,
    },
}

// ─── Bring-up ────────────────────────────────────────────────────────────────

/// What the borrowed radio is being lent out for.
///
/// Administering a device and asking a repeater who its neighbors are are
/// different conversations — one is authorized node management, the other a
/// plain MAC command anyone may send — but both need this tool to stop being
/// a serial client and become a node on the mesh. That apparatus is what this
/// enum is here to share.
#[derive(Debug)]
pub enum Operation {
    Manage(ManageOp),
    /// Ask the target for the repeaters it knows of.
    PeerRepeaters,
    /// Measure the path to the target.
    Ping(super::ping::PingArgs),
}

/// One operation against one device, waiting for a radio to run on.
struct Errand {
    target: PublicKey,
    op: Operation,
    no_save: bool,
}

impl mesh::RadioErrand for Errand {
    async fn run<R: Radio>(
        self,
        mac: &AsyncRefCell<CtlMac<R>>,
        identity: SoftwareIdentity,
    ) -> Result<()>
    where
        R::Error: core::fmt::Debug,
    {
        operate(mac, identity, self.target, self.op, self.no_save).await
    }
}

/// Take the attachment over as this tool's radio, run `op` against
/// `target`, and hand the attachment back.
pub async fn run(app: &mut App, target: KeyArg, op: Operation) -> Result<()> {
    // Ask before borrowing the radio: a cancelled wipe should not have
    // cost an attach, and this is the last point where the terminal is
    // still ours.
    if let Operation::Manage(ManageOp::Ble {
        op: BleOp::Clear { yes: false },
    }) = &op
    {
        const WARNING: &str = "manage ble clear forgets every paired host, the pairing PIN, \
             and the pairing lockout on the target";
        if !app.interactive {
            bail!("{WARNING}; re-run with --yes to confirm");
        }
        println!("{WARNING}.");
        if !confirm("forget every paired host?")? {
            println!("cancelled");
            return Ok(());
        }
    }
    let errand = Errand {
        target: PublicKey(target.0),
        op,
        no_save: app.no_save,
    };
    mesh::borrowing_the_radio(app, errand).await
}

async fn operate<R: Radio>(
    mac: &AsyncRefCell<CtlMac<R>>,
    identity: SoftwareIdentity,
    target: PublicKey,
    op: Operation,
    no_save: bool,
) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    let (stack, local_key) = NodeStack::build(mac, identity).await?;
    let peer = stack
        .node
        .peer(target)
        .await
        .map_err(|error| anyhow!("registering the device as a peer: {error:?}"))?;
    // What an earlier invocation learned about reaching this node, put
    // back before the first frame. This is the path that matters most:
    // `manage` and `ping` are run from scripts, over and over, and each
    // one used to start by flooding for a route it had just been told.
    let mut routes = crate::routes::RouteCache::load();
    if let Some(record) = routes.get(&target) {
        peer.restore_route(record.route.clone()).await;
    }

    // The first token has only to be unpredictable; the manager keeps
    // every one after it distinct from all of its own, and the device
    // forgets this process's tokens long before another random seed
    // could land on them.
    let mut seed = [0u8; 2];
    rng().fill_bytes(&mut seed);
    let manager = NodeManager::new(peer, u16::from_be_bytes(seed));

    field("administrator", local_key.to_string());
    field(
        match op {
            Operation::Manage(_) => "device",
            Operation::PeerRepeaters => "repeater",
            Operation::Ping(_) => "target",
        },
        target.to_string(),
    );

    let mut ctl = Ctl {
        stack,
        target,
        manager,
    };
    let result = run_op(&mut ctl, op, no_save).await;
    let _ = ctl.stack.handle.service_counter_persistence().await;
    routes.harvest(&ctl.stack.handle).await;
    if let Err(error) = routes.store() {
        crate::output::warn(format!("could not save learned routes: {error:#}"));
    }
    result
}

/// The tool as a node, for the duration of one operation.
pub struct Ctl<'a, R: Radio> {
    pub(super) stack: NodeStack<'a, R>,
    pub(super) target: PublicKey,
    manager: NodeManager<CtlHandle<'a, R>>,
}

impl<'a, R: Radio> Ctl<'a, R>
where
    R::Error: core::fmt::Debug,
{
    /// Carry one exchange to its end, within what is left of the
    /// operation's budget.
    async fn exchange(&mut self, request: &[u8]) -> Result<Outcome> {
        let give_up = self.stack.started() + OPERATION_TIMEOUT;
        self.stack
            .exchange(&mut self.manager, request, give_up)
            .await
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

// ─── Operations ──────────────────────────────────────────────────────────────

async fn run_op<R: Radio>(ctl: &mut Ctl<'_, R>, op: Operation, no_save: bool) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    let op = match op {
        Operation::Manage(op) => op,
        Operation::PeerRepeaters => return peer_repeaters(ctl).await,
        // A ping is bounded by its own count, interval, and per-ping
        // timeout, so the exchange engine's deadline does not apply.
        Operation::Ping(args) => return super::ping::run(ctl, args).await,
    };
    match op {
        ManageOp::Info => info(ctl).await,
        ManageOp::Get { key } => {
            let reply = ctl
                .reply(&encode(|buf| frame::prop_get(buf, 0, key.0))?)
                .await?;
            report_value(key.0, &reply)
        }
        ManageOp::Set { key, value } => {
            let encoded = super::props::encode_value(key.0, &value)?;
            let reply = ctl
                .reply(&encode(|buf| frame::prop_set(buf, 0, key.0, &encoded))?)
                .await?;
            report_value(key.0, &reply)?;
            save_if_asked(ctl, no_save).await
        }
        ManageOp::Insert { key, item } => {
            let reply = ctl
                .reply(&encode(|buf| frame::prop_insert(buf, 0, key.0, &item.0))?)
                .await?;
            report_value(key.0, &reply)?;
            save_if_asked(ctl, no_save).await
        }
        ManageOp::Remove { key, selector } => {
            let reply = ctl
                .reply(&encode(|buf| {
                    frame::prop_remove(buf, 0, key.0, &selector.0)
                })?)
                .await?;
            report_value(key.0, &reply)?;
            save_if_asked(ctl, no_save).await
        }
        ManageOp::GetMany { keys } => {
            let numbers: Vec<u32> = keys.iter().map(|key| key.0).collect();
            let reply = ctl
                .reply(&encode(|buf| frame::prop_multi_get(buf, 0, &numbers))?)
                .await?;
            report_entries(&numbers, &reply, "reissue the rest")
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
        ManageOp::Reboot => {
            match ctl.exchange(&encode(|buf| frame::reboot(buf, 0))?).await? {
                Outcome::NoResponse => {
                    println!("reboot delivered; the device is restarting");
                    Ok(())
                }
                // The one answer this command produces: a device without
                // `CAP_REBOOT` saying it cannot restart itself.
                Outcome::Replied { .. } => report_value(prop::LAST_STATUS, ctl.manager.reply()),
                Outcome::Failed(failure) => Err(describe(failure)),
            }
        }
        ManageOp::Ble { op } => match op {
            // The window is a property, so opening and closing it is an
            // ordinary write the reply quotes back.
            BleOp::Pair { state } => {
                let open = state == PairState::On;
                let reply = ctl
                    .reply(&encode(|buf| {
                        frame::prop_set(buf, 0, prop::BLE_PAIRING, &[open as u8])
                    })?)
                    .await?;
                report_value(prop::BLE_PAIRING, &reply)
            }
            BleOp::Clear { .. } => {
                // Confirmed in `run`, before the radio was borrowed.
                let frame = encode(|buf| frame::ble_clear_bonds(buf, 0))?;
                match ctl.exchange(&frame).await? {
                    Outcome::Replied { .. } => report_value(prop::LAST_STATUS, ctl.manager.reply()),
                    Outcome::NoResponse => {
                        bail!("the device answered nothing; this command reports a status")
                    }
                    Outcome::Failed(failure) => Err(describe(failure)),
                }
            }
        },
        ManageOp::Admins { op } => admins(ctl, op.unwrap_or(TableOp::List), no_save).await,
    }
}

/// `peer-repeaters`: ask the target which repeaters it knows of.
///
/// Not node management — it is a plain MAC command any node may send, and
/// the target need not list this tool as an administrator. It reuses the
/// same borrowed radio because the tool still has to be a node to ask.
async fn peer_repeaters<R: Radio>(ctl: &mut Ctl<'_, R>) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    use umsh::node::OwnedMacCommand;
    use umsh::node::mac_command::PeerRepeatersResponseView;

    // Answers arrive asynchronously on the receive path, so they are
    // collected by a subscription and matched to the page that asked.
    let pages: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
    let sink = pages.clone();
    let target = ctl.target;
    let _subscription = ctl.stack.node.on_mac_command(move |from, command| {
        if from != target {
            return;
        }
        if let OwnedMacCommand::PeerRepeatersResponse { body } = command {
            sink.borrow_mut().push(body.clone());
        }
    });

    let peer = ctl
        .stack
        .node
        .peer(target)
        .await
        .map_err(|error| anyhow!("registering the repeater as a peer: {error:?}"))?;

    let mut seed = [0u8; 2];
    rng().fill_bytes(&mut seed);
    let mut nonce = u16::from_be_bytes(seed);
    let mut cursor: Option<Vec<u8>> = None;
    let mut listed = 0usize;
    let mut total: Option<u8> = None;

    loop {
        pages.borrow_mut().clear();
        peer.request_peer_repeaters(nonce, cursor.as_deref(), &Default::default())
            .await
            .map_err(|error| anyhow!("asking for the listing: {error:?}"))?;

        let deadline = Instant::now() + PEER_REPEATERS_PAGE_TIMEOUT;
        let body = loop {
            if let Some(body) = pages
                .borrow()
                .iter()
                .find(|body| PeerRepeatersResponseView::new(body).nonce() == Some(nonce))
                .cloned()
            {
                break Some(body);
            }
            if Instant::now() >= deadline {
                break None;
            }
            ctl.stack.pump_until(deadline).await?;
        };

        let Some(body) = body else {
            if listed == 0 {
                bail!(
                    "no answer — the repeater may be out of range, or may not answer peer-repeater \
                     requests"
                );
            }
            note("the listing stopped part way; run the command again to start over");
            break;
        };

        let view = PeerRepeatersResponseView::new(&body);
        total = total.or_else(|| view.total());
        for entry in view.entries() {
            print_peer_repeater(&entry);
            listed += 1;
        }
        match view.cursor() {
            Some(next) => cursor = Some(next.to_vec()),
            None => break,
        }
        // A fresh nonce per page, so a late copy of the previous answer
        // cannot be mistaken for this one.
        nonce = nonce.wrapping_add(1);
    }

    match total {
        Some(total) if usize::from(total) != listed => {
            note(format!("listed {listed} of {total} peer repeaters"))
        }
        _ if listed == 0 => note("the repeater knows of no peers"),
        _ => {}
    }
    Ok(())
}

/// How long one page may take before the tool gives up on it.
const PEER_REPEATERS_PAGE_TIMEOUT: Duration = Duration::from_secs(30);

fn print_peer_repeater(entry: &umsh::node::mac_command::PeerRepeaterEntryView<'_>) {
    let Some(hint) = entry.hint() else {
        // An entry that names nobody is not an entry; the responder is
        // still describing a real neighborhood around it.
        return;
    };
    field(
        "peer",
        match entry.name() {
            Some(name) => format!("{} ({name})", hex(hint)),
            None => hex(hint),
        },
    );
    if let Some((rssi, snr)) = entry.rssi_snr() {
        subfield("signal", format!("{rssi} dBm, {snr}"));
    }
    if let Some(minutes) = entry.last_heard_min() {
        subfield("last heard", format!("{minutes} min ago"));
    }
    if let Some(location) = entry.location() {
        let (lat, lon) = location.center();
        subfield("location", format!("{lat:.4}, {lon:.4}"));
    }
    let regions: Vec<String> = entry
        .regions()
        .map(|code| umsh::core::RegionCode::from_bytes(code).to_string())
        .collect();
    if !regions.is_empty() {
        subfield("regions", regions.join(", "));
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
                prop::DEV_KEY => field(&label(key), address(&value)),
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
                    println!("{}", address(key));
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
            println!("administrator added (digest {})", address(&digest));
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
            println!("administrator removed (digest {})", address(&digest));
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
    super::props::spell(key)
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
    field(
        &label(requested),
        super::props::format_value(requested, &value),
    );
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
            Ok(value) => field(&label(*key), super::props::format_value(*key, value)),
            Err(status) => field(&label(*key), format!("refused: {status:?}")),
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
