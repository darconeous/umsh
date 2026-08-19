//! The hub: one task that copies each arriving frame to every other
//! interface.
//!
//! The bridge carries frames between radios that cannot hear each other,
//! and that is all it does. Every participant's device runs in backhaul
//! mode, so the node behind each radio is a repeater whose point-to-point
//! neighbor is the participant — duplicate suppression, hop accounting,
//! trace prepending, and forwarding policy are that node's, applied to
//! bridged traffic as to anything else it hears. A packet crossing the
//! bridge is repeated twice: once by the device that heard it, whose
//! transmission is what the tunnel carries, and once by each device that
//! receives it on the far side.
//!
//! So the hub holds no duplicate cache, no hop accounting, and no notion
//! of what a packet is. It admits a frame against the arrival client's
//! rate limit and copies it out. The one exception is the exit clamp, an
//! operator's lever for a bridge spraying too far: it lowers the
//! remaining flood budget on the way through, and is off unless
//! configured.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;
use umsh_core::{FloodHops, PacketHeader};

use crate::iface::{Ingress, Interfaces};
use crate::policy::Policy;

/// How often the bridge says what it has been doing. Slow enough to
/// leave on in a deployment, frequent enough to see a problem develop.
const STATS_INTERVAL: Duration = Duration::from_secs(300);

pub struct Hub {
    interfaces: Arc<Interfaces>,
    policy: Policy,
    /// Ceiling applied to `FHOPS_REM` in passing. `None` leaves every
    /// frame exactly as it arrived.
    exit_clamp: Option<u8>,
    counters: Counters,
}

/// What happened to a frame, for logs and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The arrival client's rate limit is spent.
    RateLimited,
    /// Copied to this many interfaces. Zero when every other interface
    /// is down or excluded by an egress rule.
    Relayed(usize),
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Counters {
    pub received: u64,
    pub relayed: u64,
    pub rate_limited: u64,
    pub clamped: u64,
}

impl Hub {
    pub fn new(interfaces: Arc<Interfaces>, policy: Policy, exit_clamp: Option<u8>) -> Self {
        Self {
            interfaces,
            policy,
            exit_clamp,
            counters: Counters::default(),
        }
    }

    /// Drive the bridge: frames in, copies out.
    pub async fn run(mut self, mut ingress: mpsc::Receiver<Ingress>) {
        let mut report = tokio::time::interval(STATS_INTERVAL);
        report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        report.tick().await;

        loop {
            tokio::select! {
                biased;
                arrival = ingress.recv() => match arrival {
                    Some(mut arrival) => {
                        let verdict = self.relay(&mut arrival, Instant::now());
                        tracing::debug!(
                            iface = %self.interfaces.name(arrival.iface),
                            len = arrival.frame.data.len(),
                            ?verdict,
                        );
                    }
                    // Every interface task is gone, which cannot happen
                    // while the process is running.
                    None => return,
                },
                _ = report.tick() => self.report(),
            }
        }
    }

    /// Admit one frame and copy it to every interface allowed to carry
    /// it.
    pub fn relay(&mut self, arrival: &mut Ingress, now: Instant) -> Verdict {
        self.counters.received += 1;
        if !self.policy.admit(arrival.iface, now) {
            self.counters.rate_limited += 1;
            return Verdict::RateLimited;
        }

        if let Some(max) = self.exit_clamp
            && clamp_flood_hops(&mut arrival.frame.data, max)
        {
            self.counters.clamped += 1;
        }

        let mut sent = 0;
        for iface in &self.interfaces.all {
            if !iface.is_connected() || !self.policy.may_forward(arrival.iface, iface.id) {
                continue;
            }
            iface.send(arrival.frame.clone());
            sent += 1;
        }
        self.counters.relayed += 1;
        Verdict::Relayed(sent)
    }

    /// What the bridge has been doing, at an interval slow enough to
    /// leave in a running deployment's log.
    fn report(&self) {
        let counters = self.counters;
        tracing::info!(
            received = counters.received,
            relayed = counters.relayed,
            rate_limited = counters.rate_limited,
            clamped = counters.clamped,
            "bridge"
        );
        for iface in &self.interfaces.all {
            let (full, stale) = iface.egress.dropped();
            if full == 0 && stale == 0 {
                continue;
            }
            tracing::info!(
                iface = %iface.name,
                dropped_backpressure = full,
                dropped_stale = stale,
                "egress"
            );
        }
    }
}

/// Lower `FHOPS_REM` to `max`, reporting whether the frame changed.
///
/// The flood hop count is dynamic routing metadata, excluded from the
/// MIC, so rewriting it in passing keeps the packet authentic — the same
/// reason a repeater may decrement it. It is the byte after the FCF
/// whenever the FCF says it is present, so the rewrite is one byte and
/// the accumulated count is left alone.
///
/// A frame that carries no flood budget, or does not parse as a UMSH
/// packet at all, passes through untouched. The clamp is a limit on how
/// far traffic travels, not a filter: the hub does not decide what is
/// worth carrying.
fn clamp_flood_hops(frame: &mut [u8], max: u8) -> bool {
    let Ok(header) = PacketHeader::parse(frame) else {
        return false;
    };
    let Some(hops) = header.flood_hops else {
        return false;
    };
    if hops.remaining() <= max {
        return false;
    }
    let Some(clamped) = FloodHops::new(max, hops.accumulated()) else {
        return false;
    };
    frame[1] = clamped.0;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ServerConfig};
    use crate::iface::InterfaceId;
    use crate::tunnel::TunnelFrame;

    /// A pinned-client address the fixtures can use.
    fn address(seed: u8) -> String {
        use umsh_crypto::NodeIdentity as _;
        umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&[seed; 32])
            .public_key()
            .to_string()
    }

    /// A server with its own radio and two pinned clients, all up.
    fn hub(extra: &str, clamp: Option<u8>) -> (Arc<Interfaces>, Hub) {
        let text = format!(
            "[identity]\nkey_file = \"k\"\n[server]\n\
             [server.radio]\ntype = \"ble\"\n\
             [[server.clients]]\nname = \"cabin\"\naddress = \"{}\"\n{extra}\
             [[server.clients]]\nname = \"summit\"\naddress = \"{}\"\n",
            address(0xAA),
            address(0xBB)
        );
        let config: Config = toml::from_str(&text).unwrap();
        config.validate().unwrap();
        let server: ServerConfig = config.server.unwrap();
        let interfaces = Arc::new(Interfaces::build(&server));
        let policy = Policy::build(&server, &interfaces).unwrap();
        for iface in &interfaces.all {
            iface.set_connected(true);
        }
        let hub = Hub::new(interfaces.clone(), policy, clamp);
        (interfaces, hub)
    }

    /// A broadcast carrying a flood hop count, as a sender emits it.
    fn flood_frame(remaining: u8) -> Vec<u8> {
        use umsh_core::{NodeHint, PacketBuilder};
        let mut buf = [0u8; 255];
        PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(NodeHint([1, 2, 3]))
            .flood_hops(remaining)
            .payload(b"hello")
            .build()
            .unwrap()
            .to_vec()
    }

    /// A broadcast with no `FHOPS` field at all — what a sender emits
    /// when the frame must not be flooded onward.
    fn unfloodable_frame() -> Vec<u8> {
        use umsh_core::{NodeHint, PacketBuilder};
        let mut buf = [0u8; 255];
        PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(NodeHint([1, 2, 3]))
            .payload(b"hello")
            .build()
            .unwrap()
            .to_vec()
    }

    /// The flood hop counters a frame is carrying.
    fn hops(frame: &[u8]) -> FloodHops {
        PacketHeader::parse(frame)
            .expect("a frame the fixtures built")
            .flood_hops
            .expect("this fixture carries a hop count")
    }

    fn arrival(iface: InterfaceId, data: Vec<u8>) -> Ingress {
        Ingress {
            iface,
            frame: TunnelFrame::new(data, vec![0x00, 0x00, 0x00, 0x00]),
        }
    }

    /// Everything queued on an interface right now.
    fn drained(interfaces: &Interfaces, id: InterfaceId) -> Vec<TunnelFrame> {
        let queue = &interfaces.get(id).egress;
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut out = Vec::new();
        while let std::task::Poll::Ready(crate::tunnel::Dequeued::Frame(frame)) =
            queue.poll_pop(queue.generation(), &mut cx)
        {
            out.push(frame);
        }
        out
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_reaches_every_interface_but_the_one_it_came_from() {
        let (interfaces, mut hub) = hub("", None);
        let cabin = interfaces.by_client(0).unwrap().id;
        let radio = interfaces.radio.unwrap();
        let summit = interfaces.by_client(1).unwrap().id;

        let mut ingress = arrival(cabin, flood_frame(3));
        assert_eq!(hub.relay(&mut ingress, Instant::now()), Verdict::Relayed(2));

        assert_eq!(drained(&interfaces, radio).len(), 1);
        assert_eq!(drained(&interfaces, summit).len(), 1);
        assert!(drained(&interfaces, cabin).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn the_hub_carries_bytes_it_does_not_read() {
        let (interfaces, mut hub) = hub("", None);
        let cabin = interfaces.by_client(0).unwrap().id;
        let radio = interfaces.radio.unwrap();

        // Not a UMSH packet at all, with metadata of its own.
        let frame = TunnelFrame::new(vec![0xFF, 0xFE, 0xFD], vec![0x01, 0x02, 0x03, 0x04]);
        let mut ingress = Ingress {
            iface: cabin,
            frame: frame.clone(),
        };
        hub.relay(&mut ingress, Instant::now());

        assert_eq!(
            drained(&interfaces, radio),
            vec![frame],
            "body and metadata cross unchanged"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_egress_rule_narrows_the_fan_out() {
        let (interfaces, mut hub) = hub("allow_to = [\"radio\"]\n", None);
        let cabin = interfaces.by_client(0).unwrap().id;
        let summit = interfaces.by_client(1).unwrap().id;

        let mut ingress = arrival(cabin, flood_frame(3));
        assert_eq!(hub.relay(&mut ingress, Instant::now()), Verdict::Relayed(1));
        assert!(drained(&interfaces, summit).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_spent_rate_limit_stops_the_frame_at_the_hub() {
        let (interfaces, mut hub) = hub("max_frames_per_minute = 1\n", None);
        let cabin = interfaces.by_client(0).unwrap().id;
        let radio = interfaces.radio.unwrap();

        let mut first = arrival(cabin, flood_frame(3));
        assert_eq!(hub.relay(&mut first, Instant::now()), Verdict::Relayed(2));
        let mut second = arrival(cabin, flood_frame(3));
        assert_eq!(hub.relay(&mut second, Instant::now()), Verdict::RateLimited);
        assert_eq!(drained(&interfaces, radio).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_servers_own_radio_is_never_rate_limited() {
        let (interfaces, mut hub) = hub("max_frames_per_minute = 1\n", None);
        let radio = interfaces.radio.unwrap();
        for _ in 0..100 {
            let mut ingress = arrival(radio, flood_frame(3));
            assert!(matches!(
                hub.relay(&mut ingress, Instant::now()),
                Verdict::Relayed(_)
            ));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_clamp_the_flood_budget_crosses_untouched() {
        let (interfaces, mut hub) = hub("", None);
        let cabin = interfaces.by_client(0).unwrap().id;
        let radio = interfaces.radio.unwrap();

        let mut ingress = arrival(cabin, flood_frame(3));
        hub.relay(&mut ingress, Instant::now());
        let carried = drained(&interfaces, radio).remove(0);
        assert_eq!(carried.data, flood_frame(3));
    }

    #[tokio::test(start_paused = true)]
    async fn the_clamp_lowers_the_budget_and_leaves_the_rest_alone() {
        let (interfaces, mut hub) = hub("", Some(1));
        let cabin = interfaces.by_client(0).unwrap().id;
        let radio = interfaces.radio.unwrap();

        let sent = flood_frame(5);
        let mut ingress = arrival(cabin, sent.clone());
        hub.relay(&mut ingress, Instant::now());
        let carried = drained(&interfaces, radio).remove(0);

        assert_eq!(hops(&carried.data).remaining(), 1);
        assert_eq!(
            hops(&carried.data).accumulated(),
            hops(&sent).accumulated(),
            "the accumulated count is history, not budget"
        );
        assert_eq!(
            carried.data[2..],
            sent[2..],
            "nothing but the hop byte moved"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_clamp_of_zero_ends_the_flood_at_the_far_side() {
        let (interfaces, mut hub) = hub("", Some(0));
        let cabin = interfaces.by_client(0).unwrap().id;
        let radio = interfaces.radio.unwrap();

        let mut ingress = arrival(cabin, flood_frame(5));
        hub.relay(&mut ingress, Instant::now());
        let carried = drained(&interfaces, radio).remove(0);
        assert_eq!(hops(&carried.data).remaining(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_clamp_never_raises_a_budget_that_is_already_lower() {
        let (interfaces, mut hub) = hub("", Some(4));
        let cabin = interfaces.by_client(0).unwrap().id;
        let radio = interfaces.radio.unwrap();

        let mut ingress = arrival(cabin, flood_frame(1));
        hub.relay(&mut ingress, Instant::now());
        let carried = drained(&interfaces, radio).remove(0);
        assert_eq!(carried.data, flood_frame(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_with_no_flood_budget_is_not_given_one() {
        // The clamp is a ceiling, not a field the hub adds: a frame
        // deliberately sent unfloodable must stay that way.
        let (interfaces, mut hub) = hub("", Some(2));
        let cabin = interfaces.by_client(0).unwrap().id;
        let radio = interfaces.radio.unwrap();

        let mut ingress = arrival(cabin, unfloodable_frame());
        hub.relay(&mut ingress, Instant::now());
        let carried = drained(&interfaces, radio).remove(0);
        assert_eq!(carried.data, unfloodable_frame());
        assert!(
            PacketHeader::parse(&carried.data)
                .unwrap()
                .flood_hops
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_the_clamp_cannot_read_crosses_anyway() {
        let (interfaces, mut hub) = hub("", Some(1));
        let cabin = interfaces.by_client(0).unwrap().id;
        let radio = interfaces.radio.unwrap();

        let garbage = vec![0xFF, 0xEE, 0xDD];
        let mut ingress = arrival(cabin, garbage.clone());
        hub.relay(&mut ingress, Instant::now());
        assert_eq!(drained(&interfaces, radio).remove(0).data, garbage);
    }

    #[tokio::test(start_paused = true)]
    async fn an_interface_that_is_down_holds_nothing() {
        let (interfaces, mut hub) = hub("", None);
        let cabin = interfaces.by_client(0).unwrap().id;
        let summit = interfaces.by_client(1).unwrap().id;
        interfaces.get(summit).set_connected(false);

        let mut ingress = arrival(cabin, flood_frame(3));
        assert_eq!(
            hub.relay(&mut ingress, Instant::now()),
            Verdict::Relayed(1),
            "a down interface is not counted as a delivery"
        );
        assert!(drained(&interfaces, summit).is_empty());
    }
}
