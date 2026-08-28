//! `send` and `listen`: text messages to and from this tool's own
//! identity.
//!
//! The tool already becomes a node on the mesh to administer a device;
//! these do the same thing for the oldest reason there is to have a
//! mesh. Both borrow the attached radio, so they need a local
//! attachment — a mesh session has already lent that radio out.
//!
//! The identity is the administrator identity `admin-key` prints, so a
//! message from this tool arrives from the same key a device authorizes
//! for management.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use tokio::time::Instant;

use umsh::core::{PayloadType, PublicKey};
use umsh::crypto::software::SoftwareIdentity;
use umsh::hal::Radio;
use umsh::mac::{MacCounters, SendOptions};
use umsh::node::{ReceivedPacketRef, SendProgressTicket};
use umsh::text::{TextMessage, UnicastTextChatWrapper};
use umsh_sync::AsyncRefCell;

use super::values::KeyArg;
use crate::App;
use crate::mesh::{self, CtlMac, NodeStack};
use crate::output::{field, note, subfield};
use crate::routes::RouteCache;

/// How far a message floods when no route to the peer is known.
///
/// The MAC clamps this to a cached route's own distance when it has one,
/// so this is the budget for a first message into an unmapped mesh.
const DISCOVERY_HOPS: u8 = 5;

#[derive(Debug, clap::Args)]
pub struct SendArgs {
    /// The node to send to, as its public key.
    #[arg(value_name = "KEY")]
    pub target: KeyArg,

    /// The message. Several words are joined with spaces.
    ///
    /// A message that begins with a dash goes after `--`, as anywhere
    /// else; the flags stay flags so `--timeout` still means what it
    /// says.
    #[arg(value_name = "TEXT", required = true)]
    pub text: Vec<String>,

    /// Give up waiting for the acknowledgment after this long.
    #[arg(long, short = 'W', default_value_t = 30, value_name = "SECS")]
    pub timeout: u64,

    /// Send without asking for an acknowledgment.
    ///
    /// Nothing comes back, so nothing says the message arrived — which
    /// is what you want for a message to somebody who is not listening
    /// yet, and never what you want otherwise.
    #[arg(long)]
    pub no_ack: bool,
}

#[derive(Debug, clap::Args)]
pub struct ListenArgs {
    /// Stop after this long. Without it, listens until interrupted.
    #[arg(long, short = 'W', value_name = "SECS")]
    pub timeout: Option<u64>,

    /// Also listen for this node, by public key. May be repeated.
    ///
    /// A unicast names its sender by a short hint, not by a whole key,
    /// so a message can only be read by somebody who already knows who
    /// might be sending. Every node this tool has a remembered route to
    /// is listened for without asking; this adds the ones it has not
    /// reached yet.
    #[arg(long = "from", value_name = "KEY")]
    pub from: Vec<KeyArg>,
}

/// What this command is being lent the radio for.
enum Errand {
    Send(SendArgs),
    Listen(ListenArgs),
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
        match &self {
            Errand::Send(args) => deliver(mac, identity, PublicKey(args.target.0), args).await,
            Errand::Listen(args) => receive(mac, identity, args).await,
        }
    }
}

/// `send`: one message, and what became of it.
pub async fn send(app: &mut App, args: SendArgs) -> Result<()> {
    mesh::borrowing_the_radio(app, Errand::Send(args)).await
}

/// `listen`: whatever arrives, until you stop it.
pub async fn listen(app: &mut App, args: ListenArgs) -> Result<()> {
    mesh::borrowing_the_radio(app, Errand::Listen(args)).await
}

async fn deliver<R: Radio>(
    mac: &AsyncRefCell<CtlMac<R>>,
    identity: SoftwareIdentity,
    target: PublicKey,
    args: &SendArgs,
) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    let text = args.text.join(" ");
    let (mut stack, local_key) = NodeStack::build(mac, identity).await?;
    let peer = stack
        .node
        .peer(target)
        .await
        .map_err(|error| anyhow!("registering the node as a peer: {error:?}"))?;

    // Whatever an earlier invocation learned about reaching this node.
    let mut routes = RouteCache::load();
    let known = routes.get(&target).is_some();
    if let Some(record) = routes.get(&target) {
        peer.restore_route(record.route.clone()).await;
    }

    field("from", local_key.to_string());
    field("to", target.to_string());
    if !known {
        note("no route known; this message floods to find one");
    }

    let options = SendOptions::default()
        .with_ack_requested(!args.no_ack)
        .with_flood_hops(DISCOVERY_HOPS);
    // What the radio had already sent, so the wait below can tell this
    // frame's transmission from any that came before it.
    let before = stack.handle.counters().await;
    let chat = UnicastTextChatWrapper::new(peer);
    let ticket = chat
        .send_text(&text, &options)
        .await
        .map_err(|error| anyhow!("sending: {error:?}"))?;

    let outcome = settle(&mut stack, &ticket, args, before).await;
    routes.harvest(&stack.handle).await;
    if let Err(error) = routes.store() {
        crate::output::warn(format!("could not save learned routes: {error:#}"));
    }
    let _ = stack.handle.service_counter_persistence().await;
    outcome
}

/// Pump the radio until the message is done, or until patience runs out.
///
/// "Done" means two different things. An acknowledged send is done when
/// the MAC says so — an ack arrived, or every retransmission timed out.
/// A send that asked for no acknowledgment has no receipt to track, so
/// its ticket is finished the moment it is issued, before the frame has
/// been anywhere near the radio; what finishes that one is the frame
/// actually going out, which the MAC's own transmit counters report.
async fn settle<R: Radio>(
    stack: &mut NodeStack<'_, R>,
    ticket: &SendProgressTicket,
    args: &SendArgs,
    before: MacCounters,
) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    let give_up = Instant::now() + Duration::from_secs(args.timeout);
    if args.no_ack {
        loop {
            let now = stack.handle.counters().await;
            if now.tx_abandoned > before.tx_abandoned {
                bail!("not sent: the channel stayed busy and the frame was abandoned");
            }
            if now.tx_frames > before.tx_frames {
                // Nothing was asked for and nothing comes back. That the
                // frame aired is the whole truth available.
                field("sent", "no acknowledgment was requested");
                return Ok(());
            }
            if Instant::now() >= give_up {
                bail!(
                    "the frame was still waiting to go out after {} s",
                    args.timeout
                );
            }
            stack.pump_until(give_up.min(Instant::now() + POLL)).await?;
        }
    }
    while !ticket.is_finished() {
        if Instant::now() >= give_up {
            bail!(
                "no acknowledgment after {} s; the message may still have arrived",
                args.timeout
            );
        }
        stack.pump_until(give_up.min(Instant::now() + POLL)).await?;
    }
    if ticket.was_acked() {
        field("delivered", "acknowledged by the far end");
        return Ok(());
    }
    if ticket.has_failed() {
        bail!("not delivered: every retransmission went unacknowledged");
    }
    bail!("the send finished without an acknowledgment or a failure")
}

/// How long a single pump waits before the deadline is checked again.
const POLL: Duration = Duration::from_millis(250);

async fn receive<R: Radio>(
    mac: &AsyncRefCell<CtlMac<R>>,
    identity: SoftwareIdentity,
    args: &ListenArgs,
) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    let (mut stack, local_key) = NodeStack::build(mac, identity).await?;
    field("listening as", local_key.to_string());

    // A unicast carries a short hint for its sender rather than a whole
    // key, so the receiver has to know in advance who might be calling.
    // The remembered routes are this tool's address book of everyone it
    // has reached; `--from` covers anyone it has not.
    let mut routes = RouteCache::load();
    let mut expected: Vec<PublicKey> = args.from.iter().map(|key| PublicKey(key.0)).collect();
    for (key, _) in routes.iter() {
        if !expected.contains(&key) {
            expected.push(key);
        }
    }
    for key in &expected {
        let peer = stack
            .node
            .peer(*key)
            .await
            .map_err(|error| anyhow!("registering {key} as a peer: {error:?}"))?;
        if let Some(record) = routes.get(key) {
            peer.restore_route(record.route.clone()).await;
        }
    }

    match expected.len() {
        0 => note("no nodes known to listen for; name one with --from"),
        1 => field("expecting", expected[0].to_string()),
        // `routes` prints the list itself; a count here keeps the
        // banner short without hiding that the set is not empty.
        count => field("expecting", format!("{count} known nodes")),
    }
    note(match args.timeout {
        Some(seconds) => format!("for {seconds} s, or until interrupted"),
        None => "until interrupted".to_string(),
    });

    // The subscription borrows nothing from the stack, so it can hold
    // its own counter and outlive each turn of the pump below.
    let _subscription = stack.node.on_receive(move |packet| show(packet));

    let deadline = args
        .timeout
        .map(|seconds| Instant::now() + Duration::from_secs(seconds));
    loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            break;
        }
        let next = deadline.unwrap_or_else(|| Instant::now() + POLL);
        tokio::select! {
            result = stack.pump_until(next.min(Instant::now() + POLL)) => result?,
            // Ctrl-C ends the command rather than the process, so the
            // shell gets its prompt back and the radio comes home.
            _ = tokio::signal::ctrl_c() => {
                println!();
                break;
            }
        }
    }

    // Every sender taught a route on the way in; keep them.
    routes.harvest(&stack.handle).await;
    if let Err(error) = routes.store() {
        crate::output::warn(format!("could not save learned routes: {error:#}"));
    }
    let _ = stack.handle.service_counter_persistence().await;
    Ok(())
}

/// Print one received packet, if it is a text message.
///
/// Returning false leaves the packet for any other handler: this one
/// claims only what it printed.
fn show(packet: &ReceivedPacketRef<'_>) -> bool {
    // The payload type rides in the MAC header, so the payload itself is
    // the text message from its first byte.
    if packet.payload_type() != PayloadType::TextMessage {
        return false;
    }
    let Ok(message) = umsh::text::parse_text_message(packet.payload()) else {
        return false;
    };
    let Ok(body) = message.body_str() else {
        return false;
    };
    field(
        "from",
        match packet.from_key() {
            Some(key) => key.to_string(),
            // A message whose sender is a hint rather than a key came in
            // unauthenticated; saying so is the point.
            None => "unknown sender".to_string(),
        },
    );
    if !packet.source_authenticated() {
        subfield("warning", "the sender is not authenticated");
    }
    if let Some(rssi) = packet.rssi() {
        subfield("signal", format!("{rssi} dBm"));
    }
    print_body(&message, body);
    true
}

fn print_body(message: &TextMessage<'_>, body: &str) {
    if let Some(handle) = message.sender_handle {
        subfield("handle", handle);
    }
    subfield("message", body);
}
