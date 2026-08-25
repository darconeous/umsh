//! `ping`: reachability and path quality, measured over the mesh.
//!
//! Like `manage` and `peer-repeaters` this borrows the attached radio and
//! becomes a node, but it needs no authorization from the far end: an Echo
//! Request is a plain MAC command that every node's MAC answers on its own.
//! What a ping is for is measuring the path that real traffic will take, so
//! the flags here are the frame's own shape—MIC size, source form, flood
//! budget, an explicit route, the channel it rides—and they carry through
//! to the wire untouched.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};

use tokio::time::Instant;
use umsh::core::PayloadType;
use umsh::hal::Radio;
use umsh::mac::{MAX_FLOOD_HOPS, SendOptions};
use umsh::node::PongMetadata;

use super::manage::Ctl;
use super::values::{ChannelArg, KeyArg, MicArg, RegionCodeArg, RouteArg};
use crate::output::{field, note};

/// The default echo size, in bytes of echo data.
///
/// Two of them are the nonce that matches a reply to its request, so this
/// is a small ping with six bytes of filler—enough to be a real frame
/// without paying for airtime nobody asked about.
const DEFAULT_SIZE: u16 = 8;

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

    /// Seconds to wait for each reply.
    #[arg(short = 'W', long, value_name = "SECONDS", default_value_t = 30,
          value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout: u64,

    /// Bytes of echo data, including the 2-byte nonce. The frame's own
    /// budget is the real ceiling, and an oversize ping is refused rather
    /// than shortened.
    #[arg(short = 's', long, value_name = "BYTES", default_value_t = DEFAULT_SIZE,
          conflicts_with = "ack_only", value_parser = clap::value_parser!(u16).range(2..))]
    pub size: u16,

    /// Flood-hop ceiling. `0` sends without a flood budget at all.
    #[arg(long, value_name = "HOPS", value_parser = clap::value_parser!(u8).range(0..=MAX_FLOOD_HOPS as i64))]
    pub hops: Option<u8>,

    /// Flood even where a route to the target is already cached.
    #[arg(long, conflicts_with = "route")]
    pub flood: bool,

    /// Steer the ping down an explicit route: a comma-separated list of
    /// hops, first hop first, each four hex digits of a router hint or a
    /// full node key.
    #[arg(long, value_name = "HOP,HOP")]
    pub route: Option<RouteArg>,

    /// Ping inside a channel, as a blind unicast—a channel name, or the
    /// 32 bytes of a private channel key. A target that has never been
    /// heard from cannot resolve a 3-byte source hint, so first contact on
    /// a channel wants `--full-source`.
    #[arg(long, value_name = "CHANNEL")]
    pub channel: Option<ChannelArg>,

    /// Send a No-op MAC command asking for an acknowledgment, and time the
    /// ack instead of an echo. Measures the MAC's own round trip, with no
    /// application frame coming back.
    #[arg(long)]
    pub ack_only: bool,

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

impl PingArgs {
    /// The frame shape these flags ask for.
    fn send_options(&self) -> Result<SendOptions> {
        let mut options = SendOptions::default().with_mic_size(self.mic.0);
        if !self.untraced {
            options = options.with_trace_route().with_trace_signal();
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
        // After the route, which fills in a hop budget of its own when
        // none was set: an explicit `--hops` is the one the caller meant.
        options = match self.hops {
            Some(0) => options.no_flood(),
            Some(hops) => options.with_flood_hops(hops),
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
    Echo(PongMetadata),
    /// An ack-only ping, and how long the acknowledgment took.
    Acked(u64),
    /// Nothing came back.
    Silence {
        /// What the MAC saw of the frame on its way out, where it kept a
        /// receipt to see it by—which separates "nobody answered" from
        /// "it never left the antenna". An echo ping asks for no
        /// acknowledgment, so the MAC tracks nothing and there is nothing
        /// here to report.
        progress: Option<SendProgress>,
    },
}

/// What the MAC observed of an ack-tracked frame it sent.
struct SendProgress {
    transmitted: bool,
    repeated: bool,
}

pub async fn run<R: Radio>(ctl: &mut Ctl<'_, R>, args: PingArgs) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    let target = ctl.target;
    let options = args.send_options()?;

    // A blind unicast still needs the destination registered as a peer —
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

    // Replies arrive asynchronously on the receive path, so a subscription
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

    let mut sent = 0u32;
    let mut rtts: Vec<u64> = Vec::new();
    let mut result = Ok(());

    for seq in 1..=args.count {
        pong.borrow_mut().take();
        *expired.borrow_mut() = false;

        let reply =
            match one_ping(ctl, &peer, bound.as_ref(), &args, &options, &pong, &expired).await {
                Ok(reply) => reply,
                Err(error) => {
                    result = Err(error);
                    break;
                }
            };
        sent += 1;
        report(seq, &args, &reply);
        if let Some(rtt) = match &reply {
            Reply::Echo(metadata) => Some(metadata.round_trip_ms),
            Reply::Acked(rtt_ms) => Some(*rtt_ms),
            Reply::Silence { .. } => None,
        } {
            rtts.push(rtt);
        }

        if seq < args.count {
            let until = Instant::now() + Duration::from_secs(args.interval);
            pump_until(ctl, until, || false).await?;
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

/// Send one ping and wait out its deadline.
#[allow(clippy::too_many_arguments)]
async fn one_ping<R: Radio>(
    ctl: &mut Ctl<'_, R>,
    peer: &umsh::node::PeerConnection<umsh::node::LocalNode<crate::mesh::CtlHandle<'_, R>>>,
    bound: Option<&umsh::node::BoundChannel<crate::mesh::CtlHandle<'_, R>>>,
    args: &PingArgs,
    options: &SendOptions,
    pong: &Rc<RefCell<Option<PongMetadata>>>,
    expired: &Rc<RefCell<bool>>,
) -> Result<Reply>
where
    R::Error: core::fmt::Debug,
{
    let timeout = Duration::from_secs(args.timeout);
    let started = Instant::now();
    let deadline = started + timeout;

    if args.ack_only {
        // A No-op is one command byte and produces no reply frame; what is
        // being timed is the MAC acknowledgment it asks for.
        let payload = [
            PayloadType::MacCommand as u8,
            umsh::node::mac_command::CommandId::Noop as u8,
        ];
        let options = options.clone().with_ack_requested(true);
        let ticket = match bound {
            Some(bound) => bound.peer(ctl.target).send(&payload, &options).await,
            None => peer.send(&payload, &options).await,
        }
        .map_err(describe_send)?;
        pump_until(ctl, deadline, || ticket.is_finished()).await?;
        return Ok(if ticket.was_acked() {
            Reply::Acked(started.elapsed().as_millis() as u64)
        } else {
            Reply::Silence {
                progress: Some(SendProgress {
                    transmitted: ticket.was_transmitted(),
                    repeated: ticket.was_repeated(),
                }),
            }
        });
    }

    let extra = usize::from(args.size - 2);
    // The echo response is the acknowledgment, so `ping` asks for no MAC
    // ack and the MAC keeps no receipt to track the frame by; the ticket
    // exists only so the send's own failures surface.
    match bound {
        Some(bound) => {
            bound
                .peer(ctl.target)
                .ping(extra, options, timeout.as_millis() as u64)
                .await
        }
        None => peer.ping(extra, options, timeout.as_millis() as u64).await,
    }
    .map_err(describe_send)?;

    pump_until(ctl, deadline, || {
        pong.borrow().is_some() || *expired.borrow()
    })
    .await?;

    Ok(match pong.borrow_mut().take() {
        Some(metadata) => Reply::Echo(metadata),
        None => Reply::Silence { progress: None },
    })
}

/// Drive the host until `done` or the deadline, whichever comes first.
async fn pump_until<R: Radio>(
    ctl: &mut Ctl<'_, R>,
    deadline: Instant,
    mut done: impl FnMut() -> bool,
) -> Result<()>
where
    R::Error: core::fmt::Debug,
{
    while !done() && Instant::now() < deadline {
        // A quiet radio produces no MAC wake, so the deadlines that retire
        // an unanswered ping need their own nudge — which the pump does.
        ctl.stack.pump_until(deadline).await?;
    }
    Ok(())
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
    if args.ack_only {
        parts.push(String::from("no-op, ack requested"));
    } else {
        parts.push(format!("{} bytes echo", args.size));
    }
    parts.push(format!("mic {}", options.mic_size.byte_len()));
    match &options.source_route {
        Some(route) if route.is_empty() => parts.push(String::from("forced flood")),
        Some(route) => parts.push(format!(
            "route {}",
            route
                .iter()
                .map(|hop| hop.to_string())
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
    if !options.trace_route {
        parts.push(String::from("untraced"));
    }
    parts.join(", ")
}

/// One line per ping, in the order they were sent.
fn report(seq: u32, args: &PingArgs, reply: &Reply) {
    match reply {
        Reply::Echo(metadata) => {
            let mut line = format!("seq {seq}: reply in {}", seconds(metadata.round_trip_ms));
            if let Some(hops) = metadata.hop_count {
                line.push_str(&format!(", {hops} hop{}", if hops == 1 { "" } else { "s" }));
            }
            if !metadata.route_hints.is_empty() {
                line.push_str(&format!(
                    " via {}",
                    metadata
                        .route_hints
                        .iter()
                        .map(|hop| hop.to_string())
                        .collect::<Vec<_>>()
                        .join(" → ")
                ));
            }
            if let Some(rssi) = metadata.rssi_dbm {
                line.push_str(&format!(", {rssi} dBm"));
            }
            if let Some(snr) = metadata.snr_centibels {
                line.push_str(&format!(", snr {:.1} dB", f32::from(snr) / 10.0));
            }
            println!("{line}");
        }
        Reply::Acked(rtt_ms) => println!("seq {seq}: acked in {}", seconds(*rtt_ms)),
        Reply::Silence { progress } => {
            let what = if args.ack_only { "no ack" } else { "timeout" };
            let mut line = format!("seq {seq}: {what} after {} s", args.timeout);
            if let Some(progress) = progress {
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
