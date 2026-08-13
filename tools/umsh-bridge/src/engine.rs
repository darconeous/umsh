//! The forwarding procedure, and the one duplicate cache the whole
//! bridge shares.
//!
//! The bridge is one virtual repeater whose radios happen to sit in
//! different places: it suppresses duplicates once, accounts for a hop
//! once, and records itself in a trace once, no matter how many
//! interfaces took part. That is why every decision is made here, in one
//! task, and clients relay bytes without an opinion.
//!
//! [`Engine::evaluate`] walks the [thirteen steps] in order, including
//! the one that is a no-op for a forwarding-only bridge, so the code and
//! the specification can be read side by side.
//!
//! [thirteen steps]: https://darconeous.github.io/umsh/docs/protocol/internet-bridging.html#forwarding-procedure

use std::collections::VecDeque;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;
use umsh_core::options::TraceSignalEntry;
use umsh_core::{NodeHint, PacketHeader, ParsedOptions, RouterHint, SourceAddrRef};
use umsh_mac::DupCacheKey;
use umsh_mac::forward_id::forwarding_dup_key_parsed;
use umsh_ulcp::meta::{RxMeta, TxMeta};

use crate::config::ServerConfig;
use crate::identity::BridgeIdentity;
use crate::iface::{Ingress, InterfaceId, Interfaces};
use crate::policy::Policy;
use crate::rewrite::{self, RewriteError, RewritePlan};
use crate::tunnel::TunnelFrame;

/// How long a duplicate key stays suppressed. The same hour the MAC
/// uses: long enough to collapse a burst of retransmissions of one
/// packet, short enough that a node re-announcing itself is heard again
/// well within the time anyone would wait for it.
const CACHE_TTL: Duration = Duration::from_millis(umsh_mac::DUP_CACHE_TTL_MS);

/// How many times a flood confirmation copy defers to an overheard
/// forwarding before giving up on it. Any overheard forwarding confirms
/// the previous hop just as well as ours would have.
const MAX_DEFERRALS: u8 = 3;

/// Largest frame the bridge will compose. A rewritten frame that would
/// exceed this is dropped at step 10, and one this large is already far
/// beyond what any LoRa PHY carries.
const MAX_FRAME_SIZE: usize = 255;

/// How often the bridge says what it has been doing. Slow enough to
/// leave on in a deployment, frequent enough to see a problem develop.
const STATS_INTERVAL: Duration = Duration::from_secs(300);

pub struct Engine {
    node_hint: NodeHint,
    router_hint: RouterHint,
    interfaces: std::sync::Arc<Interfaces>,
    policy: Policy,
    cache: DuplicateCache,
    pending: VecDeque<PendingConfirmation>,
    exit_clamp: u8,
    min_rssi: Option<i16>,
    min_snr_cb: Option<i16>,
    contention: Duration,
    counters: Counters,
}

/// What happened to a frame, for logs and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The frame did not parse as a UMSH packet at all.
    Unparseable,
    /// Step 1: already seen, and outside the re-confirmation window or
    /// on a different interface.
    Duplicate,
    /// Step 1 / Re-confirmation: a previous hop retrying, answered with
    /// another confirmation copy and nothing else.
    Reconfirmed,
    /// Step 2: the bridge is the source or the destination.
    Local,
    /// Step 4: an unknown critical option.
    UnknownCriticalOption,
    /// Step 5: policy declined it.
    Policy(&'static str),
    /// Step 6: the source route names someone else next.
    NotOurHop,
    /// Step 7: the frame carries no flood hop count, so it was never
    /// floodable to begin with.
    NotFloodable,
    /// Step 7: the flood budget is spent.
    HopsExhausted,
    /// Step 8: too weak to relay.
    TooWeak(&'static str),
    /// Step 10 or the rewrite: the frame cannot be composed.
    Undeliverable(RewriteError),
    /// Steps 11-13: accepted, and transmitted on this many interfaces
    /// (not counting the confirmation copy).
    Forwarded(usize),
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Counters {
    pub received: u64,
    pub forwarded: u64,
    pub duplicates: u64,
    pub reconfirmations: u64,
    pub dropped: u64,
}

impl Engine {
    pub fn new(
        identity: &BridgeIdentity,
        config: &ServerConfig,
        interfaces: std::sync::Arc<Interfaces>,
        policy: Policy,
    ) -> Self {
        Self {
            node_hint: identity.node_hint(),
            router_hint: identity.router_hint(),
            interfaces,
            policy,
            cache: DuplicateCache::new(config.forwarding.cache_entries).with_window(
                Duration::from_secs(config.forwarding.confirmation_window_secs),
            ),
            pending: VecDeque::new(),
            exit_clamp: config.forwarding.exit_clamp,
            min_rssi: config.forwarding.min_rssi,
            min_snr_cb: config
                .forwarding
                .min_snr
                .map(|snr| (snr * 10.0).round() as i16),
            contention: Duration::from_millis(config.forwarding.flood_contention_ms),
            counters: Counters::default(),
        }
    }

    /// Drive the bridge: frames in, transmissions out, deferred
    /// confirmation copies fired when their window elapses.
    pub async fn run(mut self, mut ingress: mpsc::Receiver<Ingress>) {
        let mut report = tokio::time::interval(STATS_INTERVAL);
        report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        report.tick().await;

        loop {
            let deadline = self.pending.iter().map(|pending| pending.at).min();
            tokio::select! {
                biased;
                arrival = ingress.recv() => match arrival {
                    Some(arrival) => {
                        let verdict = self.evaluate(&arrival, Instant::now());
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
                () = sleep_until(deadline) => self.fire_due(Instant::now()),
                _ = report.tick() => self.report(),
            }
        }
    }

    /// What the bridge has been doing, at an interval slow enough to
    /// leave in a running deployment's log.
    fn report(&self) {
        let counters = self.counters;
        tracing::info!(
            received = counters.received,
            forwarded = counters.forwarded,
            duplicates = counters.duplicates,
            reconfirmations = counters.reconfirmations,
            dropped = counters.dropped,
            cached = self.cache.entries.len(),
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

    /// One pass of the forwarding procedure, in specification order.
    pub fn evaluate(&mut self, arrival: &Ingress, now: Instant) -> Verdict {
        self.counters.received += 1;
        let verdict = self.classify(arrival, now);
        match verdict {
            Verdict::Forwarded(_) => self.counters.forwarded += 1,
            Verdict::Duplicate => self.counters.duplicates += 1,
            Verdict::Reconfirmed => self.counters.reconfirmations += 1,
            _ => self.counters.dropped += 1,
        }
        verdict
    }

    fn classify(&mut self, arrival: &Ingress, now: Instant) -> Verdict {
        let src = &arrival.frame.data;
        let Ok(header) = PacketHeader::parse(src) else {
            return Verdict::Unparseable;
        };
        let Ok(options) = ParsedOptions::extract(src, header.options_range.clone()) else {
            return Verdict::Unparseable;
        };

        // Step 1: duplicate suppression, against the one cache the whole
        // bridge shares. A Route Retry variant keys differently and so
        // forwards normally, which is the point of it.
        let key = forwarding_dup_key_parsed(&header, src);
        if let Some(key) = &key
            && let Some(entry) = self.cache.get(key, now)
        {
            return self.on_duplicate(entry, key, arrival, &header, now);
        }

        // Step 2: local origin and local destination. This is also what
        // keeps the bridge's own transmissions, overheard through
        // another of its interfaces, from being bridged back.
        if self.is_local(src, &header) {
            return Verdict::Local;
        }

        // Step 3: locally handled unicast. A forwarding-only bridge runs
        // no node logic, so nothing is ever handled locally and this
        // step never declines a frame. It is kept as a step so the
        // procedure can be read against the specification.

        // Step 4: an option the bridge does not understand, marked
        // critical, means the frame must not be relayed blind.
        if options.has_unknown_critical {
            return Verdict::UnknownCriticalOption;
        }

        // Step 5: policy.
        if !self.policy.region_admits(&options) {
            return Verdict::Policy("region");
        }
        if !self.policy.admit(&self.interfaces, arrival.iface, now) {
            return Verdict::Policy("rate limit");
        }

        // Step 6: a source route names its next hop, and if that is not
        // us the frame is not ours to carry.
        let routed = match rewrite::next_source_route_hop(src, &options) {
            Some(next) if next == self.router_hint => true,
            Some(_) => return Verdict::NotOurHop,
            None => false,
        };

        // The measurements of the radio that actually heard the frame.
        // A client's radio is one of the bridge's own, and the tunnel
        // carries its reception verbatim, so this is a real reading
        // whichever interface the frame came in on. Steps 8 and 10 both
        // read it, and step 10 needs it even on a source-routed hop that
        // skips step 8.
        let meta = arrival_rx_meta(&arrival.frame);

        if !routed {
            // Step 7: flood hop accounting. An absent FHOPS field is not an
            // unlimited budget — it is the sender declining to be flooded at
            // all, and nothing downstream can restore the field or bound the
            // frame once it is carried. A frame with no field and no source
            // route therefore stops here.
            let Some(hops) = header.flood_hops else {
                return Verdict::NotFloodable;
            };
            if hops.remaining() == 0 {
                return Verdict::HopsExhausted;
            }

            // Step 8: signal-quality thresholds.
            if let Some(reason) = self.too_weak(meta) {
                return Verdict::TooWeak(reason);
            }
        }

        // Steps 9 and 10 happen inside the rewrite.
        let plan = RewritePlan {
            router_hint: self.router_hint,
            signal: TraceSignalEntry::from_measurements(meta.rssi_dbm, meta.snr_cb),
            consume_source_route: routed,
            decrement_flood_hops: !routed,
            exit_clamp: self.exit_clamp,
        };
        let rewritten = match rewrite::rewrite(src, &header, &options, plan, MAX_FRAME_SIZE) {
            Ok(rewritten) => rewritten,
            Err(error) => return Verdict::Undeliverable(error),
        };

        // Step 11: accept. The insertion happens before any
        // transmission, which is normative for a bridge — it is what
        // stops the bridge's own zero-hop confirmation copy from
        // sterilizing the live flood at a repeater that hears the copy
        // first.
        let Some(key) = key else {
            // A frame with no key cannot be suppressed, re-confirmed, or
            // recognized when it comes back. Forwarding it would risk a
            // loop the cache cannot break.
            return Verdict::Undeliverable(RewriteError::Malformed);
        };
        self.cache.insert(
            key.clone(),
            CacheEntry {
                arrival: arrival.iface,
                accepted_at: now,
                confirmation: rewritten.confirmation().to_vec(),
                hop_byte: header.flood_hops.map(|hops| hops.0),
                source_routed: routed,
            },
            now,
        );

        // Step 12: fan out on every other interface policy allows.
        // These introduce the packet to segments that have not carried
        // it, so the flood contention window does not apply.
        let mut sent = 0;
        for iface in &self.interfaces.all {
            if !self
                .policy
                .may_forward(&self.interfaces, arrival.iface, iface.id)
            {
                continue;
            }
            iface.send(TunnelFrame::new(
                rewritten.forward.clone(),
                transmit_metadata(),
            ));
            sent += 1;
        }

        // Step 13: the confirmation copy, back the way the frame came.
        self.schedule_confirmation(arrival.iface, key, rewritten.confirmation(), routed, now);
        Verdict::Forwarded(sent)
    }

    /// A duplicate is silence, with one exception: a previous hop
    /// retrying because our confirmation copy was lost.
    fn on_duplicate(
        &mut self,
        entry: CacheEntry,
        key: &DupCacheKey,
        arrival: &Ingress,
        header: &PacketHeader,
        now: Instant,
    ) -> Verdict {
        if entry.arrival != arrival.iface {
            // An ordinary suppressed duplicate: the frame reached us by
            // a second path. Nothing is transmitted anywhere.
            return Verdict::Duplicate;
        }
        if now.saturating_duration_since(entry.accepted_at) > self.reconfirmation_window() {
            return Verdict::Duplicate;
        }

        // On the arrival interface, inside the window, two very
        // different things look alike. A byte-identical hop count is the
        // previous hop retrying — it has not heard our confirmation and
        // will declare the route failed if it never does. A different
        // one is somebody else's forwarding of the same packet, which
        // confirms the previous hop just as well as ours would, so our
        // copy can stand down.
        //
        // Only for a flood hop. A source-routed hop's copy is the
        // previous hop's *only* confirmation — nobody else is going to
        // forward that packet — so it is never abandoned.
        let arriving_hop_byte = header.flood_hops.map(|hops| hops.0);
        if !entry.source_routed && arriving_hop_byte != entry.hop_byte {
            self.defer_confirmation(arrival.iface, key, now);
            return Verdict::Duplicate;
        }

        // The copy may still be waiting out its contention window; this
        // retransmission replaces it rather than stacking a second one.
        //
        // A retry answered here happens even on an interface whose flood
        // confirmations are suppressed, deliberately: the retry means
        // the previous hop heard nothing — the co-located device's own
        // re-forward was lost too — so the stored copy is the
        // confirmation of last resort.
        self.cancel_pending(arrival.iface, key);
        self.transmit_confirmation(arrival.iface, &entry.confirmation);
        Verdict::Reconfirmed
    }

    fn is_local(&self, src: &[u8], header: &PacketHeader) -> bool {
        if header.dst == Some(self.node_hint) {
            return true;
        }
        match header.source {
            SourceAddrRef::Hint(hint) => hint == self.node_hint,
            SourceAddrRef::FullKeyAt { offset } => src
                .get(offset..offset + 3)
                .is_some_and(|key| key == self.node_hint.0),
            // A blinded source cannot be compared without the channel
            // key, which a forwarding-only bridge does not hold.
            SourceAddrRef::Encrypted { .. } | SourceAddrRef::None => false,
        }
    }

    /// Each threshold is applied only where the radio reported the
    /// measurement it needs. A sentinel is "this radio cannot tell you",
    /// not "zero", and treating it as a reading would silence a segment
    /// whose hardware simply does not measure.
    fn too_weak(&self, meta: RxMeta) -> Option<&'static str> {
        if let Some(floor) = self.min_rssi {
            match meta.rssi_dbm {
                Some(rssi) if rssi < floor => return Some("rssi"),
                None => tracing::trace!("no RSSI reported; the minimum-RSSI check is skipped"),
                _ => {}
            }
        }
        if let Some(floor) = self.min_snr_cb {
            match meta.snr_cb {
                Some(snr) if snr < floor => return Some("snr"),
                None => tracing::trace!("no SNR reported; the minimum-SNR check is skipped"),
                _ => {}
            }
        }
        None
    }

    fn reconfirmation_window(&self) -> Duration {
        self.cache.reconfirmation_window
    }

    /// A source-routed hop's confirmation copy is the previous hop's
    /// only confirmation, so it goes out under ordinary channel access
    /// and is never abandoned. A flood hop's is one forwarding among
    /// several on a segment already carrying the packet, so it takes the
    /// contention window and stands down if someone else forwards first.
    fn schedule_confirmation(
        &mut self,
        iface: InterfaceId,
        key: DupCacheKey,
        confirmation: &[u8],
        source_routed: bool,
        now: Instant,
    ) {
        if source_routed {
            self.transmit_confirmation(iface, confirmation);
            return;
        }
        if self
            .policy
            .suppresses_flood_confirmations(&self.interfaces, iface)
        {
            // The device behind this interface re-forwards the flood
            // itself, and that re-forward confirms the previous hop.
            tracing::trace!(
                iface = %self.interfaces.name(iface),
                "flood confirmation copy suppressed; the device's own repeater role covers it"
            );
            return;
        }
        self.pending.push_back(PendingConfirmation {
            iface,
            key,
            frame: confirmation.to_vec(),
            at: now + self.contention_delay(),
            deferrals: 0,
        });
    }

    /// Defer this packet's pending flood confirmation on this interface,
    /// or abandon it once it has stood down often enough. An overheard
    /// forwarding speaks only for its own packet, which is why the match
    /// is on the key and not the interface alone.
    fn defer_confirmation(&mut self, iface: InterfaceId, key: &DupCacheKey, now: Instant) {
        let Some(index) = self
            .pending
            .iter()
            .position(|pending| pending.iface == iface && pending.key == *key)
        else {
            return;
        };
        if self.pending[index].deferrals >= MAX_DEFERRALS {
            tracing::trace!(
                iface = %self.interfaces.name(iface),
                "abandoning a flood confirmation copy; the segment is carrying the packet"
            );
            self.pending.remove(index);
            return;
        }
        self.pending[index].deferrals += 1;
        self.pending[index].at = now + self.contention_delay();
    }

    /// Drop a pending confirmation that a direct retransmission has just
    /// made redundant.
    fn cancel_pending(&mut self, iface: InterfaceId, key: &DupCacheKey) {
        self.pending
            .retain(|pending| !(pending.iface == iface && pending.key == *key));
    }

    fn fire_due(&mut self, now: Instant) {
        while let Some(index) = self.pending.iter().position(|pending| pending.at <= now) {
            let pending = self.pending.remove(index).expect("index from position");
            self.transmit_confirmation(pending.iface, &pending.frame);
        }
    }

    fn transmit_confirmation(&self, iface: InterfaceId, frame: &[u8]) {
        tracing::trace!(
            iface = %self.interfaces.name(iface),
            "confirmation copy"
        );
        self.interfaces
            .get(iface)
            .send(TunnelFrame::new(frame.to_vec(), transmit_metadata()));
    }

    /// A uniform spread over the contention window.
    ///
    /// An ordinary repeater weights this by signal quality so the
    /// weakest-placed hearer speaks first. A bridge cannot: the
    /// measurements it has for a tunneled frame belong to a radio
    /// somewhere else, and may be sentinels.
    fn contention_delay(&self) -> Duration {
        if self.contention.is_zero() {
            return Duration::ZERO;
        }
        Duration::from_millis(rand::random_range(0..=self.contention.as_millis() as u64))
    }
}

/// The arrival's receive metadata, with anything unreadable reported as
/// unmeasured.
///
/// Metadata that does not decode is not a measurement of zero. Reading it
/// as one would both silence a segment at step 8 and write a fabricated
/// entry into a trace signal at step 10, and the second is worse than the
/// first: a threshold that never trips is visible in the counters, while
/// an invented signal reading is indistinguishable from a real one for
/// every node downstream.
fn arrival_rx_meta(frame: &TunnelFrame) -> RxMeta {
    RxMeta::decode(&frame.metadata).unwrap_or_else(|error| {
        tracing::warn!(
            ?error,
            "undecodable receive metadata; treating it as unmeasured"
        );
        RxMeta::default()
    })
}

/// The transmit metadata the server composes for every frame it sends.
///
/// Default power — the device's own configuration is the local decision,
/// not the bridge's — and no flags. `TX_FLAG_NODUTY` is clear and stays
/// clear: the device's duty-cycle enforcement is the backstop against a
/// bridge that would otherwise spend a whole segment's airtime budget.
fn transmit_metadata() -> Vec<u8> {
    let mut buf = [0u8; TxMeta::WIRE_LEN];
    TxMeta::default()
        .encode(&mut buf)
        .expect("buffer sized with WIRE_LEN");
    buf.to_vec()
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

struct PendingConfirmation {
    iface: InterfaceId,
    /// Routing identity of the packet this copy confirms, so overheard
    /// forwardings and retries touch only their own packet's copy.
    key: DupCacheKey,
    frame: Vec<u8>,
    at: Instant,
    deferrals: u8,
}

#[derive(Clone)]
struct CacheEntry {
    /// The interface the frame was accepted from — the only one a
    /// re-confirmation may go back out on.
    arrival: InterfaceId,
    accepted_at: Instant,
    /// The copy to re-transmit if the previous hop retries. Stored
    /// rather than recomputed, so a re-confirmation is a queue push.
    confirmation: Vec<u8>,
    /// The raw hop-count byte of the frame as accepted, which is how a
    /// previous hop's retry is told from somebody else's forwarding.
    hop_byte: Option<u8>,
    source_routed: bool,
}

/// The bridge's duplicate cache.
///
/// [`umsh_mac::DuplicateCache`] holds keys and nothing else, which is
/// all a single-radio repeater needs. A bridge has to remember where a
/// frame came from and what it sent back, so it keeps its own store —
/// keyed identically, since that key is the interop surface.
struct DuplicateCache {
    entries: VecDeque<(DupCacheKey, CacheEntry)>,
    capacity: usize,
    reconfirmation_window: Duration,
}

impl DuplicateCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
            reconfirmation_window: Duration::from_secs(30),
        }
    }

    fn with_window(mut self, window: Duration) -> Self {
        self.reconfirmation_window = window;
        self
    }

    fn get(&mut self, key: &DupCacheKey, now: Instant) -> Option<CacheEntry> {
        self.expire(now);
        self.entries
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, entry)| entry.clone())
    }

    /// First insert wins: a key already present keeps its original
    /// arrival interface and acceptance time, which is what the
    /// re-confirmation window is measured against.
    fn insert(&mut self, key: DupCacheKey, entry: CacheEntry, now: Instant) {
        self.expire(now);
        if self.entries.iter().any(|(candidate, _)| *candidate == key) {
            return;
        }
        while self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((key, entry));
    }

    /// Insertion-ordered, so expiry prunes from the front without a
    /// scan.
    fn expire(&mut self, now: Instant) {
        while let Some((_, entry)) = self.entries.front() {
            if now.saturating_duration_since(entry.accepted_at) < CACHE_TTL {
                break;
            }
            self.entries.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_core::{FloodHops, OptionNumber, PacketBuilder};

    use crate::config::Config;

    /// A pinned-client address the fixtures can use.
    fn address(seed: u8) -> String {
        use umsh_crypto::NodeIdentity as _;
        umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&[seed; 32])
            .public_key()
            .to_string()
    }

    /// A server with a radio and two clients, plus whatever the caller
    /// adds to `[server.forwarding]`.
    fn engine(forwarding: &str) -> (Engine, std::sync::Arc<Interfaces>, BridgeIdentity) {
        let text = format!(
            "[identity]\nkey_file = \"k\"\n[server]\n\
             [server.radio]\ntype = \"ble\"\n\
             [server.forwarding]\n{forwarding}\
             [[server.clients]]\nname = \"cabin\"\naddress = \"{}\"\n\
             [[server.clients]]\nname = \"summit\"\naddress = \"{}\"\n",
            address(0xAA),
            address(0xBB)
        );
        let config: Config = toml::from_str(&text).unwrap();
        config.validate().unwrap();
        let server = config.server.unwrap();
        let interfaces = std::sync::Arc::new(Interfaces::build(&server));
        for iface in &interfaces.all {
            iface.set_connected(true);
        }
        let policy = Policy::build(&server, &interfaces).unwrap();
        let identity = BridgeIdentity::from_seed(&[0x42; 32]);
        let engine = Engine::new(&identity, &server, interfaces.clone(), policy);
        (engine, interfaces, identity)
    }

    fn ingress(
        iface: InterfaceId,
        data: Vec<u8>,
        rssi: Option<i16>,
        snr_cb: Option<i16>,
    ) -> Ingress {
        let mut metadata = [0u8; RxMeta::WIRE_LEN];
        RxMeta {
            rssi_dbm: rssi,
            lqi: None,
            snr_cb,
        }
        .encode(&mut metadata)
        .unwrap();
        Ingress {
            iface,
            frame: TunnelFrame::new(data, metadata.to_vec()),
        }
    }

    fn heard(iface: InterfaceId, data: Vec<u8>) -> Ingress {
        ingress(iface, data, Some(-70), Some(80))
    }

    fn broadcast(remaining: u8, source: NodeHint, options: &[(OptionNumber, Vec<u8>)]) -> Vec<u8> {
        let mut buf = [0u8; 255];
        let mut builder = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(source)
            .flood_hops(remaining);
        for (number, value) in options {
            builder = builder.option(*number, value);
        }
        builder.payload(b"hello").build().unwrap().to_vec()
    }

    /// A broadcast with no `FHOPS` field at all — what a sender emits when
    /// the frame must not be flooded onward.
    fn unfloodable_broadcast(source: NodeHint, options: &[(OptionNumber, Vec<u8>)]) -> Vec<u8> {
        let mut buf = [0u8; 255];
        let mut builder = PacketBuilder::new(&mut buf).broadcast().source_hint(source);
        for (number, value) in options {
            builder = builder.option(*number, value);
        }
        builder.payload(b"hello").build().unwrap().to_vec()
    }

    /// Drain what each interface was asked to transmit.
    fn sent(interfaces: &Interfaces) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for iface in &interfaces.all {
            while let Some(crate::tunnel::Dequeued::Frame(frame)) = poll_once(&iface.egress) {
                out.push((iface.name.clone(), frame.data));
            }
        }
        out
    }

    fn poll_once(queue: &crate::tunnel::TunnelQueue) -> Option<crate::tunnel::Dequeued> {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        match queue.poll_pop(queue.generation(), &mut cx) {
            std::task::Poll::Ready(dequeued) => Some(dequeued),
            std::task::Poll::Pending => None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_flood_frame_fans_out_everywhere_but_the_way_it_came() {
        let (mut engine, interfaces, _) = engine("");
        let cabin = interfaces.by_client(0).unwrap().id;
        let frame = broadcast(3, NodeHint([1, 2, 3]), &[]);

        assert_eq!(
            engine.evaluate(&heard(cabin, frame), Instant::now()),
            Verdict::Forwarded(2)
        );
        let names: Vec<String> = sent(&interfaces)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, ["radio", "summit"]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_same_frame_from_a_second_client_is_suppressed() {
        let (mut engine, interfaces, _) = engine("");
        let cabin = interfaces.by_client(0).unwrap().id;
        let summit = interfaces.by_client(1).unwrap().id;
        let frame = broadcast(3, NodeHint([1, 2, 3]), &[]);

        engine.evaluate(&heard(cabin, frame.clone()), Instant::now());
        sent(&interfaces);
        assert_eq!(
            engine.evaluate(&heard(summit, frame), Instant::now()),
            Verdict::Duplicate
        );
        assert!(
            sent(&interfaces).is_empty(),
            "a duplicate transmits nothing"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_bridges_own_traffic_is_never_bridged_back() {
        let (mut engine, interfaces, identity) = engine("");
        let cabin = interfaces.by_client(0).unwrap().id;

        let from_us = broadcast(3, identity.node_hint(), &[]);
        assert_eq!(
            engine.evaluate(&heard(cabin, from_us), Instant::now()),
            Verdict::Local
        );
        assert!(sent(&interfaces).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_spent_flood_budget_ends_the_flood() {
        let (mut engine, _, _) = engine("");
        let frame = broadcast(0, NodeHint([1, 2, 3]), &[]);
        assert_eq!(
            engine.evaluate(&heard(0, frame), Instant::now()),
            Verdict::HopsExhausted
        );
    }

    /// A frame with no `FHOPS` field at all asked to travel one hop and no
    /// further. Reading the absence as an unbounded budget is what let a
    /// bridge carry unfloodable frames — including the Identity Requests
    /// whose replies then arrived once per copy heard.
    #[tokio::test(start_paused = true)]
    async fn a_frame_with_no_flood_budget_is_never_carried() {
        let (mut engine, interfaces, _) = engine("");
        let frame = unfloodable_broadcast(NodeHint([1, 2, 3]), &[]);
        assert_eq!(
            engine.evaluate(&heard(0, frame), Instant::now()),
            Verdict::NotFloodable
        );
        assert!(sent(&interfaces).is_empty());
    }

    /// The absence of a budget is a *flood* rule. A frame the sender routed
    /// explicitly through this bridge still gets carried, because a
    /// source-routed hop spends nothing from `FHOPS` and never needed the
    /// field in the first place.
    #[tokio::test(start_paused = true)]
    async fn a_source_routed_hop_needs_no_flood_budget() {
        let (mut engine, interfaces, identity) = engine("");
        let hint = identity.router_hint();
        let frame = unfloodable_broadcast(
            NodeHint([1, 2, 3]),
            &[(OptionNumber::SourceRoute, hint.0.to_vec())],
        );
        assert!(matches!(
            engine.evaluate(&heard(0, frame), Instant::now()),
            Verdict::Forwarded(_)
        ));
        assert!(!sent(&interfaces).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_route_that_names_someone_else_is_not_ours_to_carry() {
        let (mut engine, _, _) = engine("");
        let frame = broadcast(
            3,
            NodeHint([1, 2, 3]),
            &[(OptionNumber::SourceRoute, vec![0x0A, 0x0B])],
        );
        assert_eq!(
            engine.evaluate(&heard(0, frame), Instant::now()),
            Verdict::NotOurHop
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_routed_hop_is_confirmed_at_once_and_spends_no_budget() {
        let (mut engine, interfaces, identity) = engine("");
        let cabin = interfaces.by_client(0).unwrap().id;
        let frame = broadcast(
            5,
            NodeHint([1, 2, 3]),
            &[(
                OptionNumber::SourceRoute,
                [identity.router_hint().0, [0x0A, 0x0B]].concat(),
            )],
        );

        assert_eq!(
            engine.evaluate(&heard(cabin, frame), Instant::now()),
            Verdict::Forwarded(2)
        );
        // Two fan-outs plus a confirmation copy, with no waiting.
        let transmitted = sent(&interfaces);
        assert_eq!(transmitted.len(), 3);
        let confirmation = transmitted
            .iter()
            .find(|(name, _)| name == "cabin")
            .expect("the confirmation copy goes back the way it came");
        let header = PacketHeader::parse(&confirmation.1).unwrap();
        assert_eq!(header.flood_hops.unwrap().remaining(), 0);
        assert_eq!(
            header.flood_hops.unwrap().accumulated(),
            0,
            "a routed hop spends nothing from the flood budget"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_flood_confirmation_copy_waits_out_the_contention_window() {
        let (mut engine, interfaces, _) = engine("flood_contention_ms = 1600\n");
        let cabin = interfaces.by_client(0).unwrap().id;
        let frame = broadcast(3, NodeHint([1, 2, 3]), &[]);

        engine.evaluate(&heard(cabin, frame), Instant::now());
        assert!(
            !sent(&interfaces).iter().any(|(name, _)| name == "cabin"),
            "nothing on the arrival interface yet"
        );

        engine.fire_due(Instant::now() + Duration::from_millis(1600));
        let transmitted = sent(&interfaces);
        assert_eq!(transmitted.len(), 1);
        assert_eq!(transmitted[0].0, "cabin");
        assert_eq!(
            PacketHeader::parse(&transmitted[0].1)
                .unwrap()
                .flood_hops
                .unwrap()
                .remaining(),
            0,
            "the copy recruits no forwarders"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_previous_hop_retrying_gets_another_confirmation_copy() {
        let (mut engine, interfaces, _) = engine("flood_contention_ms = 0\n");
        let cabin = interfaces.by_client(0).unwrap().id;
        let frame = broadcast(3, NodeHint([1, 2, 3]), &[]);

        let start = Instant::now();
        engine.evaluate(&heard(cabin, frame.clone()), start);
        engine.fire_due(start);
        sent(&interfaces);

        // The identical frame again, on the same interface: the previous
        // hop never heard us.
        assert_eq!(
            engine.evaluate(&heard(cabin, frame.clone()), start + Duration::from_secs(5)),
            Verdict::Reconfirmed
        );
        let transmitted = sent(&interfaces);
        assert_eq!(transmitted.len(), 1);
        assert_eq!(transmitted[0].0, "cabin");

        // Outside the window it is an ordinary duplicate again.
        assert_eq!(
            engine.evaluate(&heard(cabin, frame), start + Duration::from_secs(31)),
            Verdict::Duplicate
        );
        assert!(sent(&interfaces).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_overheard_forwarding_stands_our_copy_down() {
        let (mut engine, interfaces, _) = engine("flood_contention_ms = 1600\n");
        let cabin = interfaces.by_client(0).unwrap().id;
        let frame = broadcast(3, NodeHint([1, 2, 3]), &[]);

        let start = Instant::now();
        engine.evaluate(&heard(cabin, frame.clone()), start);
        sent(&interfaces);

        // Somebody else's forwarding of the same packet: same key,
        // different hop count.
        let mut forwarded = frame.clone();
        forwarded[1] = FloodHops::new(2, 1).unwrap().0;
        for round in 0..=MAX_DEFERRALS {
            assert_eq!(
                engine.evaluate(&heard(cabin, forwarded.clone()), start),
                Verdict::Duplicate,
                "round {round}"
            );
        }

        // Deferred three times, then abandoned: the segment is plainly
        // carrying the packet without our help.
        engine.fire_due(start + Duration::from_secs(60));
        assert!(sent(&interfaces).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_overheard_forwarding_stands_down_only_its_own_packets_copy() {
        let (mut engine, interfaces, _) = engine("flood_contention_ms = 1600\n");
        let cabin = interfaces.by_client(0).unwrap().id;
        let frame_a = broadcast(3, NodeHint([1, 2, 3]), &[]);
        let frame_b = broadcast(3, NodeHint([9, 9, 9]), &[]);

        let start = Instant::now();
        engine.evaluate(&heard(cabin, frame_a.clone()), start);
        engine.evaluate(&heard(cabin, frame_b.clone()), start);
        sent(&interfaces);

        // A storm of overheard forwardings — all of packet A. However
        // many arrive, they may only ever defer and abandon A's copy.
        let mut forwarded = frame_a.clone();
        forwarded[1] = FloodHops::new(2, 1).unwrap().0;
        for _ in 0..8 {
            engine.evaluate(&heard(cabin, forwarded.clone()), start);
        }

        engine.fire_due(start + Duration::from_secs(60));
        let transmitted = sent(&interfaces);
        assert_eq!(transmitted.len(), 1, "packet B's copy still fires");
        let header = PacketHeader::parse(&transmitted[0].1).unwrap();
        assert_eq!(
            header.source,
            umsh_core::SourceAddrRef::Hint(NodeHint([9, 9, 9])),
            "and it is B's copy, not A's"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_inside_the_contention_window_replaces_the_pending_copy() {
        let (mut engine, interfaces, _) = engine("flood_contention_ms = 1600\n");
        let cabin = interfaces.by_client(0).unwrap().id;
        let frame = broadcast(3, NodeHint([1, 2, 3]), &[]);

        let start = Instant::now();
        engine.evaluate(&heard(cabin, frame.clone()), start);
        sent(&interfaces);

        // The previous hop retries before our copy has left the
        // contention window: answer at once...
        assert_eq!(
            engine.evaluate(&heard(cabin, frame), start + Duration::from_millis(500)),
            Verdict::Reconfirmed
        );
        assert_eq!(sent(&interfaces).len(), 1);

        // ...and the copy that was waiting must not fire on top of it.
        engine.fire_due(start + Duration::from_secs(60));
        assert!(
            sent(&interfaces).is_empty(),
            "the pending copy was replaced, not doubled"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_weak_frame_is_not_relayed_but_a_missing_measurement_is_not_weakness() {
        let (mut engine, _, _) = engine("min_rssi = -100\nmin_snr = -3.0\n");
        let frame = broadcast(3, NodeHint([1, 2, 3]), &[]);

        assert_eq!(
            engine.evaluate(
                &ingress(0, frame.clone(), Some(-120), Some(80)),
                Instant::now()
            ),
            Verdict::TooWeak("rssi")
        );
        assert_eq!(
            engine.evaluate(
                &ingress(0, frame.clone(), Some(-70), Some(-90)),
                Instant::now()
            ),
            Verdict::TooWeak("snr")
        );
        // A radio that reports neither is not a weak radio.
        assert!(matches!(
            engine.evaluate(&ingress(0, frame, None, None), Instant::now()),
            Verdict::Forwarded(_)
        ));
    }

    /// The trace-signal option of the first frame the bridge transmitted.
    fn forwarded_trace_signal(interfaces: &Interfaces) -> Vec<u8> {
        let (_, frame) = sent(interfaces).into_iter().next().expect("a forward");
        let header = PacketHeader::parse(&frame).unwrap();
        let options = ParsedOptions::extract(&frame, header.options_range.clone()).unwrap();
        frame[options.trace_signal.clone().expect("a trace signal")].to_vec()
    }

    #[tokio::test(start_paused = true)]
    async fn a_crossing_records_the_signal_of_the_radio_that_heard_it() {
        // Not the server's radio: a client's radio is one of the
        // bridge's own, and the tunnel carries its reception verbatim.
        let (mut engine, interfaces, _) = engine("");
        let summit = interfaces.by_client(1).unwrap().id;
        let frame = broadcast(
            3,
            NodeHint([1, 2, 3]),
            &[
                (OptionNumber::TraceRoute, vec![]),
                (OptionNumber::TraceSignal, vec![]),
            ],
        );

        assert!(matches!(
            engine.evaluate(&ingress(summit, frame, Some(-91), Some(42)), Instant::now()),
            Verdict::Forwarded(_)
        ));
        assert_eq!(
            forwarded_trace_signal(&interfaces),
            TraceSignalEntry::new(-91, 42).as_bytes(),
            "-91 dBm at 4.2 dB, as the summit client heard it"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn undecodable_metadata_records_no_signal_rather_than_a_made_up_one() {
        let (mut engine, interfaces, _) = engine("");
        let cabin = interfaces.by_client(0).unwrap().id;
        let frame = broadcast(
            3,
            NodeHint([1, 2, 3]),
            &[
                (OptionNumber::TraceRoute, vec![]),
                (OptionNumber::TraceSignal, vec![]),
            ],
        );
        // Short of `RxMeta::WIRE_LEN`, and not the empty block that
        // legitimately means "no metadata at all".
        let arrival = Ingress {
            iface: cabin,
            frame: TunnelFrame::new(frame, vec![0x5A, 0x00]),
        };

        assert!(matches!(
            engine.evaluate(&arrival, Instant::now()),
            Verdict::Forwarded(_)
        ));
        assert_eq!(
            forwarded_trace_signal(&interfaces),
            TraceSignalEntry::UNMEASURED.as_bytes(),
            "the entry keeps the pairing without claiming a measurement"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_rate_limited_client_stops_being_forwarded() {
        let text = format!(
            "[identity]\nkey_file = \"k\"\n[server]\n\
             [server.radio]\ntype = \"ble\"\n\
             [[server.clients]]\nname = \"cabin\"\naddress = \"{}\"\n\
             max_frames_per_minute = 2\n",
            address(0xAA)
        );
        let config: Config = toml::from_str(&text).unwrap();
        config.validate().unwrap();
        let server = config.server.unwrap();
        let interfaces = std::sync::Arc::new(Interfaces::build(&server));
        for iface in &interfaces.all {
            iface.set_connected(true);
        }
        let policy = Policy::build(&server, &interfaces).unwrap();
        let identity = BridgeIdentity::from_seed(&[7; 32]);
        let mut engine = Engine::new(&identity, &server, interfaces.clone(), policy);
        let cabin = interfaces.by_client(0).unwrap().id;

        for index in 0..2u8 {
            let frame = broadcast(3, NodeHint([1, 2, index]), &[]);
            assert!(matches!(
                engine.evaluate(&heard(cabin, frame), Instant::now()),
                Verdict::Forwarded(_)
            ));
        }
        let frame = broadcast(3, NodeHint([1, 2, 9]), &[]);
        assert_eq!(
            engine.evaluate(&heard(cabin, frame), Instant::now()),
            Verdict::Policy("rate limit")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn suppression_silences_flood_confirmations_but_not_routed_ones() {
        let text = format!(
            "[identity]\nkey_file = \"k\"\n[server]\n\
             [server.radio]\ntype = \"ble\"\n\
             [server.forwarding]\nflood_contention_ms = 0\n\
             [[server.clients]]\nname = \"cabin\"\naddress = \"{}\"\n\
             suppress_flood_confirmations = true\n",
            address(0xAA)
        );
        let config: Config = toml::from_str(&text).unwrap();
        config.validate().unwrap();
        let server = config.server.unwrap();
        let interfaces = std::sync::Arc::new(Interfaces::build(&server));
        for iface in &interfaces.all {
            iface.set_connected(true);
        }
        let policy = Policy::build(&server, &interfaces).unwrap();
        let identity = BridgeIdentity::from_seed(&[9; 32]);
        let mut engine = Engine::new(&identity, &server, interfaces.clone(), policy);
        let cabin = interfaces.by_client(0).unwrap().id;

        engine.evaluate(
            &heard(cabin, broadcast(3, NodeHint([1, 2, 3]), &[])),
            Instant::now(),
        );
        engine.fire_due(Instant::now() + Duration::from_secs(10));
        assert!(
            !sent(&interfaces).iter().any(|(name, _)| name == "cabin"),
            "the device's own repeater role covers the flood confirmation"
        );

        // A source-routed hop still gets one: the device will not
        // forward that.
        let routed = broadcast(
            3,
            NodeHint([4, 5, 6]),
            &[(OptionNumber::SourceRoute, identity.router_hint().0.to_vec())],
        );
        engine.evaluate(&heard(cabin, routed), Instant::now());
        assert!(sent(&interfaces).iter().any(|(name, _)| name == "cabin"));
    }

    #[tokio::test(start_paused = true)]
    async fn the_cache_is_first_insert_wins_and_bounded() {
        let mut cache = DuplicateCache::new(2).with_window(Duration::from_secs(30));
        let now = Instant::now();
        let entry = |arrival| CacheEntry {
            arrival,
            accepted_at: now,
            confirmation: Vec::new(),
            hop_byte: None,
            source_routed: false,
        };

        cache.insert(DupCacheKey::Hash32(1), entry(0), now);
        cache.insert(DupCacheKey::Hash32(1), entry(7), now);
        assert_eq!(
            cache.get(&DupCacheKey::Hash32(1), now).unwrap().arrival,
            0,
            "the first arrival interface is the one that counts"
        );

        cache.insert(DupCacheKey::Hash32(2), entry(0), now);
        cache.insert(DupCacheKey::Hash32(3), entry(0), now);
        assert!(cache.get(&DupCacheKey::Hash32(1), now).is_none(), "evicted");
        assert!(cache.get(&DupCacheKey::Hash32(3), now).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_cache_entry_ages_out() {
        let mut cache = DuplicateCache::new(8);
        let now = Instant::now();
        cache.insert(
            DupCacheKey::Hash32(1),
            CacheEntry {
                arrival: 0,
                accepted_at: now,
                confirmation: Vec::new(),
                hop_byte: None,
                source_routed: false,
            },
            now,
        );
        assert!(
            cache
                .get(&DupCacheKey::Hash32(1), now + CACHE_TTL / 2)
                .is_some()
        );
        assert!(
            cache
                .get(
                    &DupCacheKey::Hash32(1),
                    now + CACHE_TTL + Duration::from_secs(1)
                )
                .is_none()
        );
    }

    #[test]
    fn the_transmit_metadata_never_asks_to_skip_the_duty_limit() {
        let meta = TxMeta::decode(&transmit_metadata()).unwrap();
        assert_eq!(meta.flags & umsh_ulcp::meta::TX_FLAG_NODUTY, 0);
        assert_eq!(meta.power, umsh_ulcp::meta::TX_POWER_DEFAULT);
    }
}
