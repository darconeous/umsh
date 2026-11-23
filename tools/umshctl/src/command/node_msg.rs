//! `node-msg`: UMSH payloads sent and received through the attached
//! device's own node (`CAP_NODE_MSG`).
//!
//! Unlike `send` and `listen`, which make this tool a node of its own,
//! these speak as the device: its identity, its peers and channels, its
//! acknowledgments. Which payload types reach a listener is the device's
//! `node-msg-types` property, set with `set`/`get` like any other.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use tokio::time::Instant;

use umsh::core::{NodeHint, PayloadType, PublicKey};
use umsh::ulcp::{NodeMessage, UlcpError};
use umsh::ulcp_wire::Status;
use umsh::ulcp_wire::ids::prop;
use umsh::ulcp_wire::node_msg::{Kind, MAX_FLOOD_HOPS, SendMeta, Source};

use super::values::{BytesArg, ChannelIdentifierArg, KeyArg, RouteArg};
use crate::App;
use crate::output::{self, field, note, subfield};

#[derive(Debug, clap::Subcommand)]
pub enum NodeMsgOp {
    /// Send one payload as the device.
    ///
    /// The destination picks the kind: a key alone is a unicast, a
    /// channel alone a multicast, both a blind unicast, and neither a
    /// broadcast.
    Send(SendArgs),
    /// Print the messages the device delivers, until interrupted.
    ///
    /// Only the payload types listed in `node-msg-types` are delivered.
    Listen(ListenArgs),
}

#[derive(Debug, clap::Args)]
pub struct SendArgs {
    /// The destination node's public key.
    #[arg(long, value_name = "KEY")]
    pub to: Option<KeyArg>,

    /// One of the device's channels, as its identifier or its key.
    #[arg(long, value_name = "CHANNEL")]
    pub channel: Option<ChannelIdentifierArg>,

    /// The whole payload in hex, type octet first, in place of TEXT.
    #[arg(long, value_name = "HEX", conflicts_with = "text")]
    pub payload: Option<BytesArg>,

    /// A text message. Several words are joined with spaces.
    #[arg(value_name = "TEXT", required_unless_present = "payload")]
    pub text: Vec<String>,

    /// Send without asking for an acknowledgment.
    #[arg(long)]
    pub no_ack: bool,

    /// Carry the device's whole public key as the source.
    #[arg(long)]
    pub full_source: bool,

    /// Sign the frame.
    #[arg(long)]
    pub signed: bool,

    /// Flood budget, 0 for none.
    #[arg(long, value_name = "HOPS", value_parser = clap::value_parser!(u8).range(0..=MAX_FLOOD_HOPS as i64))]
    pub flood: Option<u8>,

    /// Repeaters to route through, nearest first: their hints or keys.
    #[arg(long, value_name = "HINT,...")]
    pub route: Option<RouteArg>,

    /// Transmit power in dBm for this send.
    #[arg(long, value_name = "DBM", allow_negative_numbers = true)]
    pub power: Option<i8>,

    /// Give up waiting for the outcome after this long.
    #[arg(long, short = 'W', default_value_t = 60, value_name = "SECS")]
    pub timeout: u64,
}

#[derive(Debug, clap::Args)]
pub struct ListenArgs {
    /// Stop after this long.
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,
}

pub async fn run(app: &mut App, op: NodeMsgOp) -> Result<()> {
    match op {
        NodeMsgOp::Send(args) => send(app, args).await,
        NodeMsgOp::Listen(args) => listen(app, args).await,
    }
}

async fn send(app: &mut App, args: SendArgs) -> Result<()> {
    let kind = match (&args.to, &args.channel) {
        (Some(_), None) => Kind::Unicast,
        (None, None) => Kind::Broadcast,
        (Some(_), Some(_)) => Kind::BlindUnicast,
        (None, Some(_)) => Kind::Multicast,
    };
    let data = match args.payload {
        Some(payload) => payload.0,
        None => {
            // A text message with no options: the type, the marker, the body.
            let mut data = vec![PayloadType::TextMessage as u8, 0xFF];
            data.extend_from_slice(args.text.join(" ").as_bytes());
            data
        }
    };
    if data.is_empty() {
        bail!("a payload needs at least its type octet");
    }
    let route: Option<Vec<u8>> = args
        .route
        .map(|route| route.0.iter().flat_map(|hint| hint.0).collect());
    let mut meta = SendMeta::new(kind);
    meta.ack = kind.has_peer() && !args.no_ack;
    meta.full_source = args.full_source;
    meta.signed = args.signed;
    meta.peer = args.to.map(|key| key.0);
    meta.channel = args.channel.map(|channel| channel.0);
    meta.flood_hops = args.flood;
    meta.source_route = route.as_deref();
    meta.tx_power = args.power;

    let device = app.device()?;
    let started = Instant::now();
    match device
        .node_msg_send(&data, &meta, Duration::from_secs(args.timeout))
        .await
    {
        Ok(()) if meta.ack => {
            field(
                "acknowledged",
                format!("{} ms", started.elapsed().as_millis()),
            );
            Ok(())
        }
        Ok(()) => {
            field("sent", format!("{} ms", started.elapsed().as_millis()));
            Ok(())
        }
        Err(UlcpError::Status(Status::NO_ACK)) => {
            bail!("sent, but no acknowledgment arrived")
        }
        Err(error) => Err(anyhow!(error)),
    }
}

async fn listen(app: &mut App, args: ListenArgs) -> Result<()> {
    let device = app.device()?;
    if device.is_remote() {
        bail!("node messages are delivered to a wired link, never over the mesh");
    }
    let claimed = device.get_prop(prop::NODE_MSG_TYPES).await?;
    // Listening is a host's to ask for. The device's own interface, an
    // application wired to the device, is refused it, and receives
    // whenever no host is listening.
    let listening = match device.set_prop(prop::NODE_MSG_LISTEN, &[1]).await {
        Ok(_) => true,
        Err(UlcpError::Status(Status::NOT_PERMITTED)) => {
            note("this is the device's own interface: it receives while no host listens");
            false
        }
        Err(error) => return Err(anyhow!(error)),
    };
    if claimed.is_empty() {
        note("no payload types are claimed; claim text with `set node-msg-types 03`");
    } else {
        let types: Vec<String> = claimed.iter().map(u8::to_string).collect();
        field("types", types.join(", "));
    }
    note(match args.timeout {
        Some(seconds) => format!("for {seconds} s, or until interrupted"),
        None => "until interrupted".to_string(),
    });
    let deadline = args
        .timeout
        .map(|seconds| Instant::now() + Duration::from_secs(seconds));
    let outcome = loop {
        let wait = match deadline {
            Some(deadline) if Instant::now() >= deadline => break Ok(()),
            Some(deadline) => deadline.saturating_duration_since(Instant::now()),
            None => Duration::from_secs(3600),
        };
        tokio::select! {
            received = device.receive_node_msg(wait) => match received {
                Ok(message) => show(&message),
                Err(UlcpError::Timeout) => {}
                Err(error) => break Err(anyhow!(error)),
            },
            // Ctrl-C ends the command rather than the process, so the
            // shell gets its prompt back and the listener is put away.
            _ = tokio::signal::ctrl_c() => {
                println!();
                break Ok(());
            }
        }
    };
    // Session state, but a REPL keeps its session: the next command
    // should not find messages it did not ask for.
    if outcome.is_ok() && listening {
        device.set_prop(prop::NODE_MSG_LISTEN, &[0]).await?;
    }
    outcome
}

/// Print one delivered message.
fn show(message: &NodeMessage) {
    field(
        "from",
        match message.source {
            Source::Key(key) => PublicKey(key).to_string(),
            Source::Hint(hint) => format!("{} (hint)", NodeHint(hint)),
        },
    );
    let kind = match message.kind {
        Kind::Unicast => "unicast",
        Kind::Broadcast => "broadcast",
        Kind::BlindUnicast => "blind unicast",
        Kind::Multicast => "multicast",
    };
    match message.channel {
        Some(channel) => subfield("kind", format!("{kind} on {}", output::hex(&channel))),
        None => subfield("kind", kind),
    }
    if !message.sender_auth {
        subfield("warning", "the sender is not authenticated");
    }
    if message.acked {
        subfield("acknowledged", "yes");
    }
    if message.redelivered {
        subfield("redelivered", "it may have been delivered already");
    }
    if message.gap {
        subfield("gap", "earlier messages were discarded");
    }
    if let Some(rssi) = message.rssi_dbm {
        subfield("rssi", format!("{rssi} dBm"));
    }
    if let Some(snr) = message.snr_cb {
        subfield("snr", format!("{:.1} dB", f32::from(snr) / 10.0));
    }
    if !message.trace.is_empty() {
        let hints: Vec<String> = message.trace.chunks(2).map(output::hex).collect();
        subfield("route back", hints.join(","));
    }
    let text = (message.data.first() == Some(&(PayloadType::TextMessage as u8)))
        .then(|| umsh::text::parse_text_message(&message.data[1..]).ok())
        .flatten()
        .and_then(|text| text.body_str().ok().map(str::to_string));
    match text {
        Some(body) => subfield("text", body),
        None => subfield("payload", output::hex(&message.data)),
    }
}
