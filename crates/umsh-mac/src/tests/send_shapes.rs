//! Send shapes at the frame limit: [`Mac::payload_capacity`], the fallback
//! chain, the Trace allowance, and the room a Route Retry needs.

use super::*;
use umsh_core::BuildError;

const MAX_FRAME: usize = 255;
const CHANNEL_KEY: ChannelKey = ChannelKey([0x5A; 32]);

/// One send kind, set up on a fresh MAC.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Broadcast,
    Multicast,
    Unicast,
    BlindUnicast,
}

struct Setup {
    mac: TestMac,
    local_id: LocalIdentityId,
    peer_key: PublicKey,
    peer_id: PeerId,
}

fn fresh() -> Setup {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    mac.add_channel(CHANNEL_KEY).unwrap();
    Setup {
        mac,
        local_id,
        peer_key,
        peer_id,
    }
}

impl Setup {
    fn destination(&self, kind: Kind) -> SendDestination<'_> {
        match kind {
            Kind::Broadcast => SendDestination::Broadcast,
            Kind::Multicast => SendDestination::Multicast(&CHANNEL_KEY),
            Kind::Unicast => SendDestination::Unicast(&self.peer_key),
            Kind::BlindUnicast => SendDestination::BlindUnicast {
                peer: &self.peer_key,
                channel: &CHANNEL_KEY,
            },
        }
    }

    fn capacity(&self, kind: Kind, options: &SendOptions) -> usize {
        self.mac
            .payload_capacity(self.local_id, self.destination(kind), options)
            .unwrap()
    }

    /// Queue `payload_len` bytes, returning the receipt of an ack-requested
    /// send.
    fn send(
        &mut self,
        kind: Kind,
        payload_len: usize,
        options: &SendOptions,
    ) -> Result<Option<SendReceipt>, SendError> {
        let payload = std::vec![0x5A; payload_len];
        let (local_id, peer_key, channel) = (self.local_id, self.peer_key, CHANNEL_KEY);
        match kind {
            Kind::Broadcast => self
                .mac
                .queue_broadcast(local_id, &payload, options)
                .map(Some),
            Kind::Multicast => self
                .mac
                .queue_multicast(local_id, &channel, &payload, options)
                .map(Some),
            Kind::Unicast => self
                .mac
                .queue_unicast(local_id, &peer_key, &payload, options),
            Kind::BlindUnicast => self
                .mac
                .queue_blind_unicast(local_id, &peer_key, &channel, &payload, options),
        }
    }

    /// The frame that just went into the transmit queue.
    fn sent_frame(&mut self) -> heapless::Vec<u8, 256> {
        self.mac
            .tx_queue_mut()
            .pop_next()
            .expect("a queued frame")
            .frame
            .as_slice()
            .iter()
            .copied()
            .collect()
    }

    /// Time out `receipt`'s ack and return the frame its Route Retry sends.
    /// The peer is heard just before, which earns even a send that assumed
    /// no route its retry.
    fn route_retry(&mut self, receipt: SendReceipt) -> heapless::Vec<u8, 256> {
        let now_ms = self.mac.clock().now_ms().max(1);
        self.mac.peer_registry_mut().touch(self.peer_id, now_ms);
        let pending = self
            .mac
            .identity_mut(self.local_id)
            .unwrap()
            .pending_ack_mut(&receipt)
            .unwrap();
        pending.state = AckState::AwaitingAck;
        pending.ack_deadline_ms = 0;
        self.mac.service_pending_ack_timeouts(|_, _| {}).unwrap();
        let retry = self.mac.tx_queue_mut().pop_next().expect("a route retry");
        assert_eq!(retry.priority, TxPriority::Retry);
        retry.frame.as_slice().iter().copied().collect()
    }

    /// Mark the peer as recently heard without flooding, so a send to it
    /// owes no discovery trace.
    fn hear_peer_directly(&mut self) {
        let now_ms = self.mac.clock().now_ms();
        self.mac
            .peer_registry_mut()
            .note_arrival(self.peer_id, false, now_ms);
    }

    fn cache_route(&mut self, hints: &[RouterHint]) {
        self.mac.peer_registry_mut().update_route(
            self.peer_id,
            CachedRoute::Source(heapless::Vec::from_slice(hints).unwrap()),
        );
    }
}

fn carries(frame: &[u8], number: OptionNumber) -> bool {
    let header = PacketHeader::parse(frame).unwrap();
    iter_options(frame, header.options_range)
        .any(|entry| OptionNumber::from(entry.unwrap().0) == number)
}

fn options_of(frame: &[u8]) -> ParsedOptions {
    let header = PacketHeader::parse(frame).unwrap();
    ParsedOptions::extract(frame, header.options_range).unwrap()
}

/// Send exactly `payload_capacity` bytes and one more, and check the frame
/// that goes out. A traced frame is held one byte below the limit; an
/// ack-requested flooded send's Route Retry fits the traced limit too.
fn assert_capacity_is_exact(mut setup: Setup, kind: Kind, options: &SendOptions) -> usize {
    let capacity = setup.capacity(kind, options);
    assert_eq!(
        setup.send(kind, capacity + 1, options),
        Err(SendError::Build(BuildError::BufferTooSmall)),
        "{kind:?}: one byte past capacity is refused"
    );
    let receipt = setup.send(kind, capacity, options).unwrap();
    let frame = setup.sent_frame();
    let traced = options_of(&frame).trace.is_some();
    assert!(
        frame.len() <= if traced { MAX_FRAME - 1 } else { MAX_FRAME },
        "{kind:?}: a {} frame of {} bytes",
        if traced { "traced" } else { "untraced" },
        frame.len()
    );
    if options.ack_requested && options.flood_hops.is_some_and(|hops| hops > 0) {
        let retry = setup.route_retry(receipt.unwrap());
        let retry_options = options_of(&retry);
        assert!(retry_options.route_retry && retry_options.trace.is_some());
        assert!(
            retry.len() < MAX_FRAME,
            "{kind:?}: a route retry of {} bytes",
            retry.len()
        );
        assert_eq!(setup.mac.counters().route_retry_oversize, 0);
    }
    frame.len()
}

#[test]
fn every_send_kind_fills_exactly_its_capacity() {
    let plain = SendOptions::default();
    let acked = SendOptions::default().with_ack_requested(true);
    let cases = [
        (Kind::Broadcast, plain.clone()),
        (
            Kind::Broadcast,
            plain.clone().with_full_source().with_trace(),
        ),
        (Kind::Multicast, plain.clone()),
        (Kind::Multicast, plain.clone().with_trace().with_salt()),
        (Kind::Unicast, plain.clone()),
        (Kind::Unicast, acked.clone()),
        (Kind::Unicast, acked.clone().with_full_source().with_salt()),
        (Kind::BlindUnicast, plain.clone()),
        (Kind::BlindUnicast, acked.clone()),
        (Kind::BlindUnicast, acked.clone().unencrypted()),
    ];
    for (kind, options) in cases {
        for callsign in [false, true] {
            let mut setup = fresh();
            if callsign {
                setup.mac.operating_policy_mut().operator_callsign =
                    Some(HamAddr::try_from_callsign("KZ2X").unwrap());
            }
            assert_capacity_is_exact(setup, kind, &options);
        }
    }
}

/// A cached source route is part of the frame's overhead, and the planner
/// sizes the send so its Route Retry, which drops the route, still fits.
#[test]
fn a_cached_route_counts_against_capacity() {
    let acked = SendOptions::default().with_ack_requested(true);
    for kind in [Kind::Unicast, Kind::BlindUnicast] {
        let mut setup = fresh();
        setup.cache_route(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])]);
        setup.hear_peer_directly();
        let len = assert_capacity_is_exact(setup, kind, &acked);
        assert!(len <= MAX_FRAME);
    }
}

/// An untraced frame at capacity fills the frame. One that may not be
/// Route-Retried keeps all of it.
#[test]
fn an_untraced_send_that_cannot_retry_fills_the_frame() {
    // No ack: nothing to retry.
    let mut setup = fresh();
    setup.hear_peer_directly();
    setup
        .mac
        .peer_registry_mut()
        .update_route(setup.peer_id, CachedRoute::Direct);
    let options = SendOptions::default();
    assert_eq!(
        assert_capacity_is_exact(setup, Kind::Unicast, &options),
        MAX_FRAME
    );

    // An ack, but `no_flood()` along a source route: no budget to retry with.
    let mut setup = fresh();
    setup.hear_peer_directly();
    let options = SendOptions::default()
        .with_ack_requested(true)
        .no_flood()
        .try_with_source_route(&[RouterHint([0x01, 0x02])])
        .unwrap();
    let options = SendOptions {
        flood_hops: None,
        ..options
    };
    assert_eq!(
        assert_capacity_is_exact(setup, Kind::Unicast, &options),
        MAX_FRAME
    );
}

/// The trace allowance applies to whichever shape the payload ends up in:
/// a payload that only fits untraced goes out untraced, at the full limit.
#[test]
fn a_payload_too_big_for_the_trace_allowance_goes_out_untraced() {
    let options = SendOptions::default().with_trace();
    let mut setup = fresh();
    let capacity = setup.capacity(Kind::Broadcast, &options);

    setup.send(Kind::Broadcast, capacity, &options).unwrap();
    let frame = setup.sent_frame();
    assert_eq!(frame.len(), MAX_FRAME);
    assert!(options_of(&frame).trace.is_none());

    // Two bytes less (the trace option and the allowance) and the trace fits.
    setup.send(Kind::Broadcast, capacity - 2, &options).unwrap();
    let frame = setup.sent_frame();
    assert_eq!(frame.len(), MAX_FRAME - 1);
    assert!(options_of(&frame).trace.is_some());
}

/// The fallback chain sheds the Ack MIC before the trace.
#[test]
fn the_ack_mic_goes_before_the_trace() {
    let options = SendOptions {
        ack_mic: Some([0xA1, 0xB2, 0xC3, 0xD4]),
        ..SendOptions::default()
    };
    let mut setup = fresh();
    let capacity = setup.capacity(Kind::Unicast, &options);
    // At the traced shape's own capacity: the trace stays, the Ack MIC goes.
    let traced_capacity = capacity - 2;
    setup
        .send(Kind::Unicast, traced_capacity, &options)
        .unwrap();
    let frame = setup.sent_frame();
    assert!(carries(&frame, OptionNumber::Trace));
    assert!(!carries(&frame, OptionNumber::AckMic));
}

/// When the payload only fits without the cached route, the send floods
/// with a budget that covers the route instead.
#[test]
fn a_route_that_does_not_fit_is_flooded_instead() {
    let route = [
        RouterHint([0x01, 0x02]),
        RouterHint([0x03, 0x04]),
        RouterHint([0x05, 0x06]),
    ];
    let options = SendOptions::default();
    let mut setup = fresh();
    setup.cache_route(&route);
    setup.hear_peer_directly();
    let capacity = setup.capacity(Kind::Unicast, &options);
    setup.send(Kind::Unicast, capacity, &options).unwrap();
    let frame = setup.sent_frame();
    let header = PacketHeader::parse(&frame).unwrap();
    assert!(options_of(&frame).source_route.is_none());
    let hops = header.flood_hops.expect("a flood budget").remaining();
    assert!(usize::from(hops) >= route.len());

    // Under `no_flood()` the route is the only way there: it is kept, and
    // the capacity counts it.
    let options = SendOptions::default().no_flood();
    let mut setup = fresh();
    setup.cache_route(&route);
    setup.hear_peer_directly();
    let routed_capacity = setup.capacity(Kind::Unicast, &options);
    assert!(routed_capacity < capacity);
    setup
        .send(Kind::Unicast, routed_capacity, &options)
        .unwrap();
    let frame = setup.sent_frame();
    assert!(options_of(&frame).source_route.is_some());
    assert_eq!(
        setup.send(Kind::Unicast, routed_capacity + 1, &options),
        Err(SendError::Build(BuildError::BufferTooSmall))
    );
}

/// Should a stored frame's rewrite not fit anyway, its Route Retry sends
/// the original again, counted, rather than a frame repeaters must drop.
#[test]
fn an_oversized_route_retry_resends_the_original() {
    let mut setup = fresh();
    let options = SendOptions::default().with_ack_requested(true);
    let receipt = setup.send(Kind::Unicast, 8, &options).unwrap().unwrap();
    setup.sent_frame();

    // An untraced flooded frame of 253 bytes, whose rewrite adds Route
    // Retry and Trace and reaches the full limit.
    let mut buf = [0u8; MAX_FRAME];
    let build = |buf: &mut [u8], payload_len: usize| {
        PacketBuilder::new(buf)
            .unicast(setup.peer_key.hint())
            .source_hint(NodeHint([0x10; 3]))
            .frame_counter(1)
            .ack_requested()
            .encrypted()
            .flood_hops(5)
            .payload(&std::vec![0x5A; payload_len])
            .build()
            .unwrap()
            .as_bytes()
            .to_vec()
    };
    let overhead = build(&mut buf, 1).len() - 1;
    let oversized = build(&mut buf, MAX_FRAME - 2 - overhead);
    assert_eq!(oversized.len(), MAX_FRAME - 2);
    setup
        .mac
        .identity_mut(setup.local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap()
        .resend = ResendRecord::try_new(&oversized, None)
        .unwrap()
        .with_requested_flood_hops(Some(5));

    let retry = setup.route_retry(receipt);
    assert_eq!(retry.as_slice(), oversized.as_slice());
    assert_eq!(setup.mac.counters().route_retry_oversize, 1);

    // The send has had its one Route Retry: the next timeout ends it.
    let pending = setup
        .mac
        .identity_mut(setup.local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;
    let mut timed_out = false;
    setup
        .mac
        .service_pending_ack_timeouts(|_, event| {
            timed_out |= matches!(event, MacEventRef::AckTimeout { .. });
        })
        .unwrap();
    assert!(timed_out);
}
