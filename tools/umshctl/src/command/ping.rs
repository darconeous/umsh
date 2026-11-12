//! `ping`: reachability and path quality, measured over the mesh.
//!
//! Like `manage` and `peer-repeaters` this borrows the attached radio and
//! becomes a node, but it needs no authorization from the far end: a ping
//! is a No-Op that asks for an acknowledgment, and every node's MAC
//! acknowledges it on its own. `--echo` sends an Echo Request instead and
//! times the Echo Response.
//! What a ping is for is measuring the path that real traffic will take, so
//! the flags here are the frame's own shape—MIC size, source form, flood
//! budget, an explicit route, the channel it rides—and they carry through
//! to the wire untouched.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};

use rand::{Rng as _, rng};
use tokio::time::Instant;
use umsh::core::PayloadType;
use umsh::mac::{MAX_FLOOD_HOPS, SendOptions};
use umsh::node::{CommandId, MacCommand, PongMetadata, ReceivedPacketRef, mac_command};

use super::manage::Ctl;
use super::values::{ChannelArg, KeyArg, MicArg, RegionCodeArg, RouteArg};
use crate::output::{field, note};

/// The default ping size: the bytes that follow the command.
///
/// Enough to be a real frame without paying for airtime nobody asked
/// about. With `--echo`, two of them are the nonce that matches a reply to
/// its request.
const DEFAULT_SIZE: u16 = 8;

/// The nonce an echo carries ahead of its filler.
const ECHO_NONCE_LEN: u16 = 2;

/// How long an echo is waited on when the caller names no wait. Nothing
/// acknowledges an Echo Request, so the MAC never says it has given up.
const ECHO_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, clap::Args)]
pub struct PingArgs {
    /// The node to ping, as its node public key.
    #[arg(value_name = "KEY")]
    pub target: KeyArg,

    /// How many pings to send.
    #[arg(short = 'c', long, value_name = "N", default_value_t = 1,
          value_parser = clap::value_parser!(u32).range(1..))]
    pub count: u32,

    /// Seconds to wait between one ping and the next.
    #[arg(short = 'i', long, value_name = "SECONDS", default_value_t = 3)]
    pub interval: u64,

    /// Seconds to wait for each reply. Without it a ping waits until the
    /// MAC gives up on it, which is after its retries and its Route Retry,
    /// and an `--echo` waits 30 seconds.
    #[arg(short = 'W', long, value_name = "SECONDS",
          value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout: Option<u64>,

    /// Bytes of filler after the command; with `--echo`, bytes of echo
    /// data, including the 2-byte nonce. The frame's own budget is the real
    /// ceiling, and an oversize ping is refused rather than shortened.
    #[arg(short = 's', long, value_name = "BYTES", default_value_t = DEFAULT_SIZE)]
    pub size: u16,

    /// Flood-hop ceiling (`FHOPS_REM`): repeater forwards the ping may spend,
    /// one less than the hops it can travel. `0` sends without a flood
    /// budget at all.
    #[arg(long, alias = "hops", value_name = "FLOOD_HOPS", value_parser = clap::value_parser!(u8).range(0..=MAX_FLOOD_HOPS as i64))]
    pub flood_hops: Option<u8>,

    /// Flood even where a route to the target is already cached.
    #[arg(long, conflicts_with = "route")]
    pub flood: bool,

    /// Steer the ping down an explicit route: a comma-separated list of
    /// repeaters, first repeater first, each four hex digits of its hint
    /// or a full node key.
    #[arg(long, value_name = "HINT,HINT")]
    pub route: Option<RouteArg>,

    /// Ping inside a channel, as a blind unicast—a channel name, or the
    /// 32 bytes of a private channel key. A target that has never been
    /// heard from cannot resolve a 3-byte source hint, so first contact on
    /// a channel wants `--full-source`.
    #[arg(long, value_name = "CHANNEL")]
    pub channel: Option<ChannelArg>,

    /// Send an Echo Request and time its Echo Response, instead of timing
    /// the acknowledgment of a No-Op. The echo data comes back whole, so
    /// the return leg is as large as the outbound one, and nothing retries
    /// an echo that goes unanswered.
    #[arg(long)]
    pub echo: bool,

    /// MIC size in bytes.
    #[arg(long, value_name = "BYTES", default_value = "8")]
    pub mic: MicArg,

    /// Stamp the ping with a region code.
    #[arg(long, value_name = "REGION")]
    pub region: Option<RegionCodeArg>,

    /// Carry the whole 32-byte source key rather than a 3-byte hint.
    #[arg(long)]
    pub full_source: bool,

    /// Randomize the SECINFO salt.
    #[arg(long)]
    pub salt: bool,

    /// Leave off the trace-route and trace-signal options, which are
    /// otherwise on: without them a reply that crossed repeaters names
    /// none of them and carries no per-hop signal. The RSSI and SNR on
    /// each line are this radio's own measurement of the reply and are
    /// unaffected. Unrelated to the global `--trace`, which prints frames
    /// on stderr.
    #[arg(long)]
    pub untraced: bool,
}

/// An echo sent and not yet answered: the nonce its response has to carry,
/// and when it was handed to the MAC.
#[derive(Clone, Copy)]
struct AwaitedEcho {
    nonce: [u8; ECHO_NONCE_LEN as usize],
    sent: Instant,
}

impl PingArgs {
    /// The frame shape these flags ask for.
    fn send_options(&self) -> Result<SendOptions> {
        let mut options = SendOptions::default().with_mic_size(self.mic.0);
        if !self.untraced {
            options = options.with_trace();
        }
        if let Some(route) = &self.route {
            options = options
                .try_with_source_route(&route.0)
                .map_err(|error| anyhow!("that source route is too long: {error:?}"))?;
        } else if self.flood {
            // An explicit empty route suppresses the cached one, which is
            // what forcing a flood means. The cache itself is left alone.
            options = options
                .try_with_source_route(&[])
                .map_err(|error| anyhow!("{error:?}"))?;
        }
        // After the route, which fills in a flood budget of its own when
        // none was set: an explicit `--flood-hops` is the one the caller
        // meant.
        options = match self.flood_hops {
            Some(0) => options.no_flood(),
            Some(flood_hops) => options.with_flood_hops(flood_hops),
            None => options,
        };
        if let Some(region) = self.region {
            options = options.with_region_code(region.0.to_bytes());
        }
        if self.full_source {
            options = options.with_full_source();
        }
        if self.salt {
            options = options.with_salt();
        }
        Ok(options)
    }
}

/// What one ping came back as.
enum Reply {
    /// It was answered, and this is how the answer arrived.
    Answer(PongMetadata),
    /// Nothing came back.
    Silence {
        /// How long the ping was waited on: until the MAC gave up on it,
        /// or the caller's own wait ran out first.
        after_ms: u64,
        /// What the MAC saw of the frame on its way out, which separates
        /// "nobody answered" from "it never left the antenna".
        progress: SendProgress,
    },
}

/// What the MAC observed of a frame it sent.
struct SendProgress {
    transmitted: bool,
    repeated: bool,
}

pub async fn run(ctl: &mut Ctl<'_>, args: PingArgs) -> Result<()> {
    let target = ctl.target;
    let options = args.send_options()?;
    if args.echo && args.size < ECHO_NONCE_LEN {
        bail!("an echo carries a {ECHO_NONCE_LEN}-byte nonce, so `--size` cannot be smaller");
    }

    // A blind unicast still needs the destination registered as a peer—
    // the channel conceals the pair, it does not stand in for knowing who
    // they are—and a channel-bound peer handle does not register one.
    // This is also what keeps a target whose firmware still answers off
    // the channel working: its plain unicast reply lands on a known peer.
    let peer = ctl
        .stack
        .node
        .peer(target)
        .await
        .map_err(|error| anyhow!("registering the target as a peer: {error:?}"))?;

    let bound = match &args.channel {
        Some(channel) => Some(
            ctl.stack
                .node
                .join(&channel.0)
                .await
                .map_err(|error| anyhow!("joining the channel: {error:?}"))?,
        ),
        None => None,
    };

    if let Some(channel) = &args.channel {
        field("channel", channel.0.name());
    }
    field("shape", describe_shape(&args, &options));

    // Answers arrive asynchronously on the receive path, so a subscription
    // collects them and the loop below waits for one to land.
    let pong: Rc<RefCell<Option<PongMetadata>>> = Rc::new(RefCell::new(None));
    let sink = pong.clone();
    let _pong_subscription = ctl.stack.node.on_pong_with_metadata(move |from, metadata| {
        if from == target {
            *sink.borrow_mut() = Some(metadata.clone());
        }
    });
    let expired = Rc::new(RefCell::new(false));
    let expiry = expired.clone();
    let _timeout_subscription = ctl.stack.node.on_ping_timeout(move |from| {
        if from == target {
            *expiry.borrow_mut() = true;
        }
    });
    // An Echo Response is an ordinary packet to the node, so `--echo`
    // picks its own answer out of what is received, by the nonce it echoes.
    let awaited: Rc<RefCell<Option<AwaitedEcho>>> = Rc::new(RefCell::new(None));
    let _echo_subscription = args.echo.then(|| {
        let sink = pong.clone();
        let awaited = awaited.clone();
        ctl.stack.node.on_receive(move |packet| {
            let Some(echo) = *awaited.borrow() else {
                return false;
            };
            if packet.from_key() == Some(target) && echoes(packet, &echo.nonce) {
                awaited.borrow_mut().take();
                *sink.borrow_mut() = Some(PongMetadata::from_path(
                    echo.sent.elapsed().as_millis() as u64,
                    packet.rx(),
                    packet.hop_count(),
                    packet.trace(),
                    false,
                ));
            }
            // Seen, not claimed: the node handles the packet as it would.
            false
        })
    });

    let mut sent = 0u32;
    let mut rtts: Vec<u64> = Vec::new();
    let mut result = Ok(());

    for seq in 1..=args.count {
        pong.borrow_mut().take();
        *expired.borrow_mut() = false;

        let waits = Waits {
            pong: &pong,
            expired: &expired,
            awaited: &awaited,
        };
        let reply = match one_ping(ctl, &peer, bound.as_ref(), &args, &options, waits).await {
            Ok(reply) => reply,
            Err(error) => {
                result = Err(error);
                break;
            }
        };
        sent += 1;
        report(seq, &reply);
        if let Reply::Answer(metadata) = &reply {
            rtts.push(metadata.round_trip_ms);
        }

        if seq < args.count {
            let until = Instant::now() + Duration::from_secs(args.interval);
            wait_until(ctl, Some(until), || false).await;
        }
    }

    if let Some(channel) = &args.channel {
        let _ = ctl.stack.node.leave(&channel.0).await;
    }
    result?;

    summarize(sent, &rtts);
    if rtts.is_empty() {
        if args.channel.is_some() && !args.full_source {
            note(
                "a node that has never heard this key cannot resolve its 3-byte hint inside a \
                 channel; try again with `--full-source`",
            );
        }
        bail!("no reply from {target} after {sent} ping(s)");
    }
    Ok(())
}

/// Where the answer to a ping shows up.
#[derive(Clone, Copy)]
struct Waits<'a> {
    /// The answer, once it lands.
    pong: &'a Rc<RefCell<Option<PongMetadata>>>,
    /// Set when the node gives up on a ping.
    expired: &'a Rc<RefCell<bool>>,
    /// The echo being waited on, for `--echo`.
    awaited: &'a Rc<RefCell<Option<AwaitedEcho>>>,
}

/// Send one ping and wait for how it ends.
async fn one_ping(
    ctl: &mut Ctl<'_>,
    peer: &umsh::node::PeerConnection<umsh::node::LocalNode<crate::mesh::CtlHandle<'_>>>,
    bound: Option<&umsh::node::BoundChannel<crate::mesh::CtlHandle<'_>>>,
    args: &PingArgs,
    options: &SendOptions,
    waits: Waits<'_>,
) -> Result<Reply> {
    let started = Instant::now();
    // The MAC ends a ping, acknowledged or given up on, so only a wait the
    // caller asked for cuts one short.
    let wait = args
        .timeout
        .map(Duration::from_secs)
        .or(args.echo.then_some(ECHO_WAIT));
    let deadline = wait.map(|wait| started + wait);

    let ticket = if args.echo {
        // The Echo Request asks for no acknowledgment: its Echo Response is
        // what comes back, and the MAC retries nothing.
        let mut nonce = [0u8; ECHO_NONCE_LEN as usize];
        rng().fill_bytes(&mut nonce);
        let mut payload = vec![0xA5u8; 2 + usize::from(args.size)];
        payload[0] = PayloadType::MacCommand as u8;
        payload[1] = CommandId::EchoRequest as u8;
        payload[2..2 + nonce.len()].copy_from_slice(&nonce);
        *waits.awaited.borrow_mut() = Some(AwaitedEcho {
            nonce,
            sent: started,
        });
        let options = options.clone().with_ack_requested(false);
        let sent = match bound {
            Some(bound) => bound.peer(ctl.target).send(&payload, &options).await,
            None => peer.send(&payload, &options).await,
        };
        if sent.is_err() {
            waits.awaited.borrow_mut().take();
        }
        sent.map_err(describe_send)?
    } else {
        // The acknowledgment is the answer, so the ticket follows the ping
        // out the way any acknowledged send's does.
        let padding = usize::from(args.size);
        match bound {
            Some(bound) => bound.peer(ctl.target).ping(padding, options).await,
            None => peer.ping(padding, options).await,
        }
        .map_err(describe_send)?
    };

    wait_until(ctl, deadline, || {
        waits.pong.borrow().is_some() || *waits.expired.borrow()
    })
    .await;
    waits.awaited.borrow_mut().take();

    Ok(match waits.pong.borrow_mut().take() {
        Some(metadata) => Reply::Answer(metadata),
        None => Reply::Silence {
            after_ms: started.elapsed().as_millis() as u64,
            progress: SendProgress {
                transmitted: ticket.was_transmitted(),
                repeated: ticket.was_repeated(),
            },
        },
    })
}

/// Whether `packet` is an Echo Response whose data begins with `nonce`.
fn echoes(packet: &ReceivedPacketRef<'_>, nonce: &[u8]) -> bool {
    packet.payload_type() == PayloadType::MacCommand
        && matches!(
            mac_command::parse(packet.payload()),
            Ok(MacCommand::EchoResponse { data }) if data.starts_with(nonce)
        )
}

/// Wait until `done`, or until `deadline` when there is one.
async fn wait_until(ctl: &Ctl<'_>, deadline: Option<Instant>, mut done: impl FnMut() -> bool) {
    while !done() {
        let now = Instant::now();
        if deadline.is_some_and(|deadline| now >= deadline) {
            break;
        }
        // With no deadline it is the pump's cycles that say when to look
        // again; the second only bounds a cycle that completed unnoticed.
        ctl.stack
            .wait_until(deadline.unwrap_or(now + Duration::from_secs(1)))
            .await;
    }
}

/// What went wrong on the way to the antenna, in the terms of the flag
/// that caused it.
fn describe_send(error: impl core::fmt::Debug) -> anyhow::Error {
    let rendered = format!("{error:?}");
    if rendered.contains("BufferTooSmall") {
        return anyhow!(
            "the ping does not fit in one frame; lower `--size`, or shorten the frame with a \
             smaller `--mic` or without `--full-source`"
        );
    }
    anyhow!("sending the ping: {rendered}")
}

/// The one-line summary of the frame shape being measured, so the numbers
/// below it can be read back later without the command line.
fn describe_shape(args: &PingArgs, options: &SendOptions) -> String {
    let mut parts = Vec::new();
    if args.echo {
        parts.push(format!("{} bytes echo", args.size));
    } else {
        parts.push(format!("{} bytes no-op, ack requested", args.size));
    }
    parts.push(format!("mic {}", options.mic_size.byte_len()));
    match &options.source_route {
        Some(route) if route.is_empty() => parts.push(String::from("forced flood")),
        Some(route) => parts.push(format!(
            "route {}",
            route
                .iter()
                .map(|hint| hint.to_string())
                .collect::<Vec<_>>()
                .join(" → ")
        )),
        None => {}
    }
    match options.flood_hops {
        Some(hops) => parts.push(format!("{hops} flood hops")),
        None => parts.push(String::from("no flood budget")),
    }
    if options.full_source {
        parts.push(String::from("full source"));
    }
    if !options.trace {
        parts.push(String::from("untraced"));
    }
    parts.join(", ")
}

/// One line per ping, in the order they were sent.
fn report(seq: u32, reply: &Reply) {
    match reply {
        Reply::Answer(metadata) => {
            let mut line = format!("seq {seq}: reply in {}", seconds(metadata.round_trip_ms));
            if let Some(hops) = metadata.hop_count {
                line.push_str(&format!(", {hops} hop{}", if hops == 1 { "" } else { "s" }));
            }
            // A trace that lost hops in transit names only the nearest; an
            // ellipsis stands for the rest.
            let mut path: Vec<String> = metadata
                .route_hints
                .iter()
                .map(|hint| hint.to_string())
                .collect();
            if metadata.trace_truncated {
                path.push("…".into());
            }
            if !path.is_empty() {
                line.push_str(&format!(" via {}", path.join(" → ")));
            }
            if let Some(rssi) = metadata.rssi_dbm {
                line.push_str(&format!(", {rssi} dBm"));
            }
            if let Some(snr) = metadata.snr_centibels {
                line.push_str(&format!(", snr {:.1} dB", f32::from(snr) / 10.0));
            }
            if metadata.via_route_retry {
                line.push_str(", after route retry");
            }
            println!("{line}");
        }
        Reply::Silence { after_ms, progress } => {
            let mut line = format!("seq {seq}: no reply after {}", seconds(*after_ms));
            let mut seen = Vec::new();
            if progress.transmitted {
                seen.push("transmitted");
            }
            if progress.repeated {
                seen.push("repeated");
            }
            if !seen.is_empty() {
                line.push_str(&format!(" ({})", seen.join(", ")));
            }
            println!("{line}");
        }
    }
}

/// Loss and round-trip spread over the whole run.
fn summarize(sent: u32, rtts: &[u64]) {
    if sent == 0 {
        return;
    }
    let replies = rtts.len() as u32;
    let loss = u64::from(sent - replies) * 100 / u64::from(sent);
    field("replies", format!("{replies} of {sent} ({loss}% loss)"));
    if let (Some(min), Some(max)) = (rtts.iter().min(), rtts.iter().max()) {
        let avg = rtts.iter().sum::<u64>() / rtts.len() as u64;
        // One unit for the three numbers, the way ping has always shown it.
        field(
            "rtt",
            format!(
                "min/avg/max {}/{}/{} s",
                bare_seconds(*min),
                bare_seconds(avg),
                bare_seconds(*max)
            ),
        );
    }
}

fn seconds(ms: u64) -> String {
    format!("{} s", bare_seconds(ms))
}

fn bare_seconds(ms: u64) -> String {
    format!("{:.2}", ms as f64 / 1000.0)
}
