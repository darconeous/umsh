//! `discover`: who else is out there.
//!
//! Two mechanisms wearing one command. Nodes advertise their identity on
//! their own schedule, so a radio that simply listens learns who is
//! nearby eventually; and a node may ask, with an Identity Request that
//! everyone in earshot answers. This asks once and then listens, which
//! is what makes the answer arrive in a minute rather than in an hour.
//!
//! The ask is a zero-hop broadcast with no flood budget: repeaters never
//! carry it, so it reaches exactly the nodes that can hear this radio.
//! Reaching further is what `--via` is for — it steers the question
//! through the routers on the way to a node this tool already knows how
//! to reach, and the answers come home along the trace the question
//! accumulated.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use tokio::time::Instant;

use umsh::core::{PayloadType, PublicKey, RouterHint};
use umsh::crypto::software::SoftwareIdentity;
use umsh::hal::Radio;
use umsh::mac::{CachedRoute, SendOptions};
use umsh::node::mac_command::IdentityRequestBuilder;
use umsh::node::{
    MacCommand, NodeCapabilities, NodeIdentityPayload, NodeRole, ReceivedPacketRef, Transport,
    mac_command,
};
use umsh_sync::AsyncRefCell;

use super::values::{HintPrefixArg, KeyArg};
use crate::App;
use crate::mesh::{self, CtlMac, NodeStack};
use crate::output::{field, note, subfield};
use crate::routes::{self, RouteCache};

/// How long a single pump waits before the deadline is checked again.
const POLL: Duration = Duration::from_millis(250);

/// Room for the request frame: an option block of a nonce and three
/// filters, and the payload type byte in front of it.
const REQUEST_FRAME: usize = 64;

#[derive(Debug, clap::Args)]
pub struct DiscoverArgs {
    /// How long to listen, in seconds.
    ///
    /// A node holds its answer for a random delay of up to thirty
    /// seconds so that everyone within earshot does not reply at once,
    /// so anything shorter than that hears only the eager.
    #[arg(long, short = 'W', default_value_t = 40, value_name = "SECS")]
    pub timeout: u64,

    /// Listen without asking: transmit nothing at all.
    ///
    /// What arrives is whatever nodes advertise on their own schedule,
    /// which is a much quieter way to learn the same thing, given time.
    #[arg(long)]
    pub passive: bool,

    /// Ask only nodes in this role to answer.
    #[arg(long, value_name = "ROLE")]
    pub role: Option<RoleFilter>,

    /// Ask only nodes with every one of these capabilities.
    #[arg(long, value_name = "CAP", value_delimiter = ',')]
    pub caps: Vec<CapFilter>,

    /// Ask only nodes whose hint starts with these bytes, as one to
    /// three hex octets.
    #[arg(long, value_name = "HEX")]
    pub hint: Option<HintPrefixArg>,

    /// Ask from this node's vantage rather than from here.
    ///
    /// The question is source-routed through the routers on the way to
    /// it, so what answers is what can hear *that* node. Needs a
    /// remembered source route — `routes` lists what there is.
    #[arg(long, value_name = "KEY")]
    pub via: Option<KeyArg>,
}

/// The roles a request can single out.
///
/// Deliberately not every [`NodeRole`]: `unspecified` is what a node
/// says when it declines to say, and filtering for it would ask the
/// least identifiable nodes to identify themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum RoleFilter {
    Repeater,
    Chat,
    Tracker,
    Sensor,
    Bridge,
    ChatRoom,
}

impl RoleFilter {
    fn role(self) -> NodeRole {
        match self {
            Self::Repeater => NodeRole::Repeater,
            Self::Chat => NodeRole::Chat,
            Self::Tracker => NodeRole::Tracker,
            Self::Sensor => NodeRole::Sensor,
            Self::Bridge => NodeRole::Bridge,
            Self::ChatRoom => NodeRole::ChatRoom,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum CapFilter {
    Repeater,
    Mobile,
    TextMessages,
    Telemetry,
    ChatRoom,
    Coap,
}

impl CapFilter {
    fn bit(self) -> NodeCapabilities {
        match self {
            Self::Repeater => NodeCapabilities::REPEATER,
            Self::Mobile => NodeCapabilities::MOBILE,
            Self::TextMessages => NodeCapabilities::TEXT_MESSAGES,
            Self::Telemetry => NodeCapabilities::TELEMETRY,
            Self::ChatRoom => NodeCapabilities::CHAT_ROOM,
            Self::Coap => NodeCapabilities::COAP,
        }
    }
}

/// `discover`: ask once, then listen.
pub async fn discover(app: &mut App, args: DiscoverArgs) -> Result<()> {
    mesh::borrowing_the_radio(app, args).await
}

impl mesh::RadioErrand for DiscoverArgs {
    async fn run<R: Radio>(
        self,
        mac: &AsyncRefCell<CtlMac<R>>,
        identity: SoftwareIdentity,
    ) -> Result<()>
    where
        R::Error: core::fmt::Debug,
    {
        explore(mac, identity, &self).await
    }
}

async fn explore<R: Radio>(
    mac: &AsyncRefCell<CtlMac<R>>,
    identity: SoftwareIdentity,
    args: &DiscoverArgs,
) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    let mut routes = RouteCache::load();
    // Resolve the vantage before standing anything up: a route this tool
    // cannot express is a mistake in the command line, not a failure
    // halfway through a discovery.
    let vantage = match &args.via {
        Some(key) => Some(steer_through(&routes, &PublicKey(key.0))?),
        None => None,
    };

    let (mut stack, local_key) = NodeStack::build(mac, identity).await?;
    // A stranger answers with its whole key in the source address,
    // having no reason to think this node has heard of it. Without this
    // the MAC has nowhere to put that key and drops the answer.
    stack.handle.set_auto_register_full_key_peers(true).await;

    field("listening as", local_key.to_string());

    let seen: Rc<RefCell<Vec<PublicKey>>> = Rc::new(RefCell::new(Vec::new()));
    let started = Instant::now();

    let nonce = if args.passive {
        note("listening only; nothing is transmitted");
        None
    } else {
        let nonce = ask(&mut stack, args, vantage.as_deref()).await?;
        field("asked", describe_ask(args));
        Some(nonce)
    };

    // An advertisement is addressed to everybody, so this only reads it —
    // returning false leaves it for anyone else who is listening.
    let sink = seen.clone();
    let _subscription = stack.node.on_receive(move |packet| {
        let Some(identity) = advertisement(packet) else {
            return false;
        };
        let Some(key) = packet.from_key() else {
            return false;
        };
        let mut seen = sink.borrow_mut();
        if seen.contains(&key) {
            return false;
        }
        seen.push(key);
        report(&key, &identity, packet, nonce, started);
        false
    });

    note(format!("listening for {} s", args.timeout));
    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    loop {
        if Instant::now() >= deadline {
            break;
        }
        tokio::select! {
            result = stack.pump_until(deadline.min(Instant::now() + POLL)) => result?,
            // Ctrl-C ends the command rather than the process, so the
            // shell gets its prompt back and the radio comes home.
            _ = tokio::signal::ctrl_c() => {
                println!();
                break;
            }
        }
    }

    let count = seen.borrow().len();
    match count {
        0 if args.passive => note("nothing advertised itself"),
        0 => note("nobody answered"),
        1 => field("heard", "1 node"),
        many => field("heard", format!("{many} nodes")),
    }

    // An answer that came back over a trace taught the MAC a way home.
    routes.harvest(&stack.handle).await;
    if let Err(error) = routes.store() {
        crate::output::warn(format!("could not save learned routes: {error:#}"));
    }
    let _ = stack.handle.service_counter_persistence().await;
    Ok(())
}

/// Broadcast one Identity Request, and return the nonce it carries so
/// the answers can be told from unsolicited advertisements.
async fn ask<R: Radio>(
    stack: &mut NodeStack<'_, R>,
    args: &DiscoverArgs,
    vantage: Option<&[RouterHint]>,
) -> Result<u32>
where
    R::Error: core::fmt::Debug,
{
    let mut bytes = [0u8; 4];
    stack.handle.fill_random(&mut bytes).await;
    let nonce = u32::from_be_bytes(bytes);
    let frame = request_frame(args, nonce)?;

    // Full source lets a stranger unicast an answer back.
    let mut send = SendOptions::default().with_full_source();
    if let Some(hops) = vantage {
        send = send
            .try_with_source_route(hops)
            .map_err(|_| anyhow!("that route is longer than a request can carry"))?
            // The trace the question accumulates is the answering
            // strangers' only path home: a broadcast teaches the MAC no
            // route, and the answer carries no flood budget.
            .with_trace_route();
    }
    // Last, always: a source route back-fills a flood budget from its
    // own length, and any flood budget at all makes the far end drop an
    // unhinted solicitation.
    let send = send.no_flood();

    stack
        .node
        .send_all(&frame, &send)
        .await
        .map_err(|error| anyhow!("asking: {error:?}"))?;
    Ok(nonce)
}

/// The Identity Request payload this ask sends, payload-type byte and
/// all.
fn request_frame(args: &DiscoverArgs, nonce: u32) -> Result<Vec<u8>> {
    // Options are emitted in ascending key order: nonce, hint, role,
    // capabilities. The builder does not sort them.
    let mut builder = IdentityRequestBuilder::new()
        .nonce(nonce)
        .map_err(|error| anyhow!("building the request: {error:?}"))?;
    if let Some(hint) = &args.hint {
        builder = builder
            .filter_hint_prefix(&hint.0)
            .map_err(|error| anyhow!("building the hint filter: {error:?}"))?;
    }
    if let Some(role) = args.role {
        builder = builder
            .filter_role(role.role())
            .map_err(|error| anyhow!("building the role filter: {error:?}"))?;
    }
    // A broadcast request must carry at least one filter option, so an
    // ask that names nothing carries a zero-bit capability filter, which
    // every node satisfies. A hint or a role has already narrowed it.
    let caps = args
        .caps
        .iter()
        .fold(NodeCapabilities::empty(), |bits, cap| bits | cap.bit());
    if !args.caps.is_empty() || (args.hint.is_none() && args.role.is_none()) {
        builder = builder
            .filter_caps(caps)
            .map_err(|error| anyhow!("building the capability filter: {error:?}"))?;
    }

    let options = builder.build();
    let command = MacCommand::IdentityRequest { options: &options };
    let mut frame = [0u8; REQUEST_FRAME];
    frame[0] = PayloadType::MacCommand as u8;
    let length = mac_command::encode(&command, &mut frame[1..])
        .map_err(|error| anyhow!("encoding the request: {error:?}"))?
        + 1;
    Ok(frame[..length].to_vec())
}

/// The router hints that steer a question through `peer` to whatever is
/// around it.
fn steer_through(routes: &RouteCache, peer: &PublicKey) -> Result<Vec<RouterHint>> {
    let Some(record) = routes.get(peer) else {
        bail!("no remembered route to {peer}; reach it once — `ping {peer}` — and try again");
    };
    match &record.route {
        CachedRoute::Source(hints) => Ok(hints.to_vec()),
        // A direct neighbor is reached with no routers in between, so
        // there is nothing to steer through: the question would go out
        // exactly as it does without --via.
        CachedRoute::Direct => bail!(
            "{peer} is a direct neighbor, so asking from its vantage is asking from here; drop --via"
        ),
        CachedRoute::Flood { .. } => bail!(
            "only a flood route to {peer} is remembered ({}); a vantage needs the routers named",
            routes::describe(&record.route)
        ),
    }
}

/// Read a packet as a node identity advertisement, if that is what it is.
fn advertisement(packet: &ReceivedPacketRef<'_>) -> Option<NodeIdentityPayload> {
    if packet.payload_type() != PayloadType::NodeIdentity {
        return None;
    }
    // The payload type rides in the MAC header, so the payload is the
    // identity from its first byte.
    NodeIdentityPayload::from_bytes(packet.payload()).ok()
}

/// Print one node, the first time it is heard.
fn report(
    key: &PublicKey,
    identity: &NodeIdentityPayload,
    packet: &ReceivedPacketRef<'_>,
    asked: Option<u32>,
    started: Instant,
) {
    println!("{key}");
    if let Some(name) = &identity.name {
        subfield("name", name);
    }
    subfield("role", role_name(identity.role));
    if !identity.capabilities.is_empty() {
        subfield("capabilities", capability_names(identity.capabilities));
    }
    if let Some(location) = &identity.location
        && !location.is_unspecified()
    {
        let (lat, lon) = location.center();
        subfield(
            "location",
            format!("{lat:.4}, {lon:.4} (±{} bytes)", location.precision()),
        );
    }
    if let Some(regions) = &identity.supported_regions
        && !regions.is_empty()
    {
        subfield("regions", regions.join(", "));
    }
    if let Some(rssi) = packet.rssi() {
        subfield("signal", format!("{rssi} dBm"));
    }
    if let Some(hops) = packet.hop_count() {
        subfield("hops", hops);
    }
    subfield(
        "heard",
        match (asked, identity.nonce) {
            (Some(mine), Some(theirs)) if mine == theirs => "an answer to this ask".to_string(),
            // Somebody else is discovering at the same time, and this
            // radio overheard the reply. Worth saying: it means the node
            // is there, but says nothing about whether it heard *us*.
            (_, Some(_)) => "an answer to somebody else's ask".to_string(),
            (_, None) => format!("advertised, {:.0?} in", started.elapsed()),
        },
    );
    if !packet.source_authenticated() {
        subfield("warning", "this identity is not authenticated");
    }
}

fn role_name(role: NodeRole) -> String {
    match role {
        NodeRole::Unspecified => "unspecified".to_string(),
        NodeRole::Repeater => "repeater".to_string(),
        NodeRole::Chat => "chat".to_string(),
        NodeRole::Tracker => "tracker".to_string(),
        NodeRole::Sensor => "sensor".to_string(),
        NodeRole::Bridge => "bridge".to_string(),
        NodeRole::ChatRoom => "chat room".to_string(),
        NodeRole::TemporarySession => "temporary session".to_string(),
        NodeRole::Unknown(code) => format!("role {code}"),
    }
}

fn capability_names(caps: NodeCapabilities) -> String {
    let named = [
        (NodeCapabilities::REPEATER, "repeater"),
        (NodeCapabilities::MOBILE, "mobile"),
        (NodeCapabilities::TEXT_MESSAGES, "text-messages"),
        (NodeCapabilities::TELEMETRY, "telemetry"),
        (NodeCapabilities::CHAT_ROOM, "chat-room"),
        (NodeCapabilities::COAP, "coap"),
    ];
    let mut out: Vec<&str> = named
        .iter()
        .filter(|(bit, _)| caps.contains(*bit))
        .map(|(_, name)| *name)
        .collect();
    let known = named
        .iter()
        .fold(NodeCapabilities::empty(), |bits, (bit, _)| bits | *bit);
    let rest = caps.bits() & !known.bits();
    let extra;
    if rest != 0 {
        extra = format!("0x{rest:02x}");
        out.push(&extra);
    }
    out.join(", ")
}

/// How the ask reads back, so the report says what was actually asked.
fn describe_ask(args: &DiscoverArgs) -> String {
    let mut parts = Vec::new();
    if let Some(hint) = &args.hint {
        parts.push(format!(
            "hint {}",
            hint.0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
    }
    if let Some(role) = args.role {
        parts.push(role_name(role.role()));
    }
    if !args.caps.is_empty() {
        parts.push(capability_names(
            args.caps
                .iter()
                .fold(NodeCapabilities::empty(), |bits, cap| bits | cap.bit()),
        ));
    }
    let who = if parts.is_empty() {
        "every node in earshot".to_string()
    } else {
        parts.join(", ")
    };
    match &args.via {
        Some(key) => format!("{who}, from the vantage of {key}", key = PublicKey(key.0)),
        None => who,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh::core::NodeHint;
    use umsh::node::mac_command::IdentityRequestFilters;

    /// The frame this command sends, read back the way a node that
    /// receives it reads it.
    fn filters_of(frame: &[u8]) -> (Option<u32>, Vec<u8>) {
        assert_eq!(frame[0], PayloadType::MacCommand as u8, "payload type");
        let MacCommand::IdentityRequest { options } =
            mac_command::parse(&frame[1..]).expect("parses as a MAC command")
        else {
            panic!("not an identity request");
        };
        let filters = IdentityRequestFilters::new(options);
        (filters.nonce().expect("a readable nonce"), options.to_vec())
    }

    fn bare() -> DiscoverArgs {
        DiscoverArgs {
            timeout: 40,
            passive: false,
            role: None,
            caps: Vec::new(),
            hint: None,
            via: None,
        }
    }

    #[test]
    fn an_unfiltered_ask_still_carries_a_filter_everyone_satisfies() {
        let frame = request_frame(&bare(), 0x0102_0304).unwrap();
        let (nonce, options) = filters_of(&frame);
        assert_eq!(nonce, Some(0x0102_0304));

        // A broadcast request with no filter option at all is dropped by
        // the far end, so an ask that names nobody asks for no
        // capabilities in particular — which every node has.
        let filters = IdentityRequestFilters::new(&options);
        assert!(!filters.hint_filtered());
        for role in [NodeRole::Repeater, NodeRole::Chat, NodeRole::Sensor] {
            assert!(
                filters
                    .selects(
                        role,
                        NodeCapabilities::empty(),
                        &NodeHint([0x11, 0x22, 0x33])
                    )
                    .unwrap(),
                "{role:?} should be selected by an unfiltered ask"
            );
        }
    }

    #[test]
    fn a_narrowed_ask_selects_only_what_it_named() {
        let args = DiscoverArgs {
            role: Some(RoleFilter::Repeater),
            caps: vec![CapFilter::Telemetry],
            hint: Some(HintPrefixArg(vec![0xa1])),
            ..bare()
        };
        let frame = request_frame(&args, 7).unwrap();
        let (nonce, options) = filters_of(&frame);
        assert_eq!(nonce, Some(7));
        let filters = IdentityRequestFilters::new(&options);
        assert!(filters.hint_filtered());

        let matching = NodeHint([0xa1, 0x22, 0x33]);
        let elsewhere = NodeHint([0xb0, 0x22, 0x33]);
        let telemetry = NodeCapabilities::TELEMETRY | NodeCapabilities::REPEATER;
        assert!(
            filters
                .selects(NodeRole::Repeater, telemetry, &matching)
                .unwrap()
        );
        // Every named filter has to hold: the wrong role, a missing
        // capability, or a hint outside the prefix each rule the node out.
        assert!(
            !filters
                .selects(NodeRole::Chat, telemetry, &matching)
                .unwrap()
        );
        assert!(
            !filters
                .selects(NodeRole::Repeater, NodeCapabilities::REPEATER, &matching)
                .unwrap()
        );
        assert!(
            !filters
                .selects(NodeRole::Repeater, telemetry, &elsewhere)
                .unwrap()
        );
    }

    #[test]
    fn capabilities_read_as_names_and_keep_what_they_do_not_know() {
        assert_eq!(
            capability_names(NodeCapabilities::REPEATER | NodeCapabilities::TEXT_MESSAGES),
            "repeater, text-messages"
        );
        assert_eq!(capability_names(NodeCapabilities::empty()), "");
        // A bit this build has no name for is still worth reporting.
        assert_eq!(
            capability_names(NodeCapabilities::from_bits_retain(0x81)),
            "repeater, 0x80"
        );
    }

    #[test]
    fn an_ask_says_who_it_is_for() {
        assert_eq!(describe_ask(&bare()), "every node in earshot");

        let narrowed = DiscoverArgs {
            role: Some(RoleFilter::Repeater),
            caps: vec![CapFilter::Telemetry],
            hint: Some(HintPrefixArg(vec![0xa1, 0xb2])),
            ..bare()
        };
        assert_eq!(describe_ask(&narrowed), "hint a1b2, repeater, telemetry");
    }

    #[test]
    fn a_vantage_needs_the_routers_named() {
        let mut routes = RouteCache::default();
        let peer = PublicKey([0x11; 32]);
        // Nothing remembered at all.
        assert!(steer_through(&routes, &peer).is_err());

        // A direct neighbor has no routers in between.
        routes.record(&peer, CachedRoute::Direct);
        assert!(steer_through(&routes, &peer).is_err());

        // A flood route names no routers either.
        routes.record(&peer, CachedRoute::flood(5, &[]).unwrap());
        assert!(steer_through(&routes, &peer).is_err());

        let hops = [RouterHint([0xa1, 0xb2]), RouterHint([0xc3, 0xd4])];
        routes.record(&peer, CachedRoute::source(&hops).unwrap());
        assert_eq!(steer_through(&routes, &peer).unwrap(), hops);
    }
}
