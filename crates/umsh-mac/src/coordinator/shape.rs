//! Send shapes: everything a frame carries besides its payload.
//!
//! Besides what [`SendOptions`] asks for, a send carries fields that come
//! from MAC state: the operator callsign, and for unicast and blind unicast
//! the cached route, the flood budget narrowed against it, and a trace for
//! route discovery. A [`SendShape`] holds all of it, resolved once, so that
//! building a frame and asking how much payload one can take see the same
//! frame.
//!
//! Each send kind resolves a short chain of complete shapes in order of
//! preference. The MAC sends the first one the payload fits, and
//! [`Mac::payload_capacity`] reports the most any of them can take.

use super::*;
use umsh_core::MicSize;

/// Where a send goes, as far as building its frame is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendDestination<'a> {
    /// A broadcast.
    Broadcast,
    /// A multicast on a configured channel, named by its key.
    Multicast(&'a ChannelKey),
    /// A unicast to a registered peer.
    Unicast(&'a PublicKey),
    /// A blind unicast to a registered peer over a configured channel.
    BlindUnicast {
        /// The destination.
        peer: &'a PublicKey,
        /// The configured channel it is sealed under, named by its key.
        channel: &'a ChannelKey,
    },
}

impl SendDestination<'_> {
    /// `channel_id` is the identifier the destination's channel key
    /// derives, for the kinds that have one. Only its width matters to a
    /// measurement.
    pub(super) fn target(&self, channel_id: Option<ChannelId>) -> SendTarget {
        let channel_id = || channel_id.unwrap_or(ChannelId([0; 2]));
        match *self {
            Self::Broadcast => SendTarget::Broadcast,
            Self::Multicast(_) => SendTarget::Multicast(channel_id()),
            Self::Unicast(peer) => SendTarget::Unicast(peer.hint()),
            Self::BlindUnicast { peer, .. } => SendTarget::BlindUnicast {
                channel: channel_id(),
                dst: peer.hint(),
            },
        }
    }

    pub(super) fn channel(&self) -> Option<&ChannelKey> {
        match *self {
            Self::Multicast(channel) | Self::BlindUnicast { channel, .. } => Some(channel),
            Self::Broadcast | Self::Unicast(_) => None,
        }
    }

    fn peer(&self) -> Option<&PublicKey> {
        match *self {
            Self::Unicast(peer) | Self::BlindUnicast { peer, .. } => Some(peer),
            Self::Broadcast | Self::Multicast(_) => None,
        }
    }
}

/// The addressing a frame is built with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SendTarget {
    Broadcast,
    Multicast(ChannelId),
    Unicast(NodeHint),
    BlindUnicast { channel: ChannelId, dst: NodeHint },
}

/// Every field and option a frame carries, apart from the payload and the
/// values fixed only when it is sent: the frame counter, the salt, and the
/// MIC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SendShape {
    pub full_source: bool,
    pub ack_requested: bool,
    pub encrypted: bool,
    pub mic_size: MicSize,
    pub salted: bool,
    pub flood_hops: Option<u8>,
    /// Never empty: a route that constrains no hop is not attached.
    pub source_route: Option<Vec<RouterHint, MAX_SOURCE_ROUTE_HINTS>>,
    pub operator_callsign: Option<HamAddr>,
    pub trace: bool,
    pub ack_mic: Option<[u8; 4]>,
    pub region_code: Option<[u8; 2]>,
    /// The MAC would Route-Retry this frame if its ack timed out, so its
    /// retry form has to fit too.
    pub route_retry: bool,
    /// A Frame Signature option on a broadcast, `D` on anything else.
    pub signed: bool,
}

/// A broadcast or multicast between choosing its shape and being queued.
/// Signing awaits the identity in between, and the frame is rebuilt from
/// this afterward rather than held across the wait.
pub(super) struct PreparedSend {
    pub shape: SendShape,
    pub receipt: SendReceipt,
    pub frame_counter: u32,
    pub salt: Option<u16>,
    pub not_before_ms: u64,
}

/// A send's shapes, most preferred first.
pub(super) type ShapeChain = Vec<SendShape, 4>;

/// A frame built from a [`SendShape`]. A broadcast is finished once built;
/// every other kind still has to be sealed.
pub(super) enum ShapedFrame<'b> {
    Plain(&'b [u8]),
    Secured(UnsealedPacket<'b>),
}

impl ShapedFrame<'_> {
    pub fn len(&self) -> usize {
        match self {
            Self::Plain(frame) => frame.len(),
            Self::Secured(packet) => packet.total_len(),
        }
    }
}

/// Apply the shape's options, which every builder type spells the same way
/// but no trait unites. They go in ascending number order: Source Route (3),
/// Operator Callsign (4), Trace (7), Ack MIC (8), Region Code (11). A
/// broadcast's Frame Signature (0) goes ahead of them all, added by
/// [`build_shaped`].
macro_rules! apply_shape {
    ($builder:expr, $shape:expr) => {{
        let shape: &SendShape = $shape;
        let mut builder = $builder;
        if let Some(hops) = shape.flood_hops {
            builder = builder.flood_hops(hops);
        }
        if let Some(route) = shape.source_route.as_ref() {
            builder = builder.source_route(route.as_slice());
        }
        if let Some(callsign) = shape.operator_callsign.as_ref() {
            builder = builder.option(OptionNumber::OperatorCallsign, callsign.as_trimmed_slice());
        }
        if shape.trace {
            builder = builder.trace();
        }
        if let Some(ack_mic) = shape.ack_mic.as_ref() {
            builder = builder.option(OptionNumber::AckMic, ack_mic);
        }
        if let Some(region_code) = shape.region_code {
            builder = builder.region_code(region_code);
        }
        builder
    }};
}

/// Build `payload` into `buf` in `shape`, from `source`.
pub(super) fn build_shaped<'b>(
    target: SendTarget,
    source: &PublicKey,
    shape: &SendShape,
    frame_counter: u32,
    salt: Option<u16>,
    payload: &[u8],
    buf: &'b mut [u8],
) -> Result<ShapedFrame<'b>, BuildError> {
    macro_rules! with_source {
        ($builder:expr) => {
            if shape.full_source {
                $builder.source_full(source)
            } else {
                $builder.source_hint(source.hint())
            }
        };
    }
    macro_rules! secured {
        ($builder:expr) => {{
            let mut builder = $builder.mic_size(shape.mic_size);
            if let Some(salt) = salt {
                builder = builder.salt(salt);
            }
            if shape.signed {
                builder = builder.signed();
            }
            apply_shape!(builder, shape).payload(payload).build()
        }};
    }
    let builder = PacketBuilder::new(buf);
    Ok(match target {
        SendTarget::Broadcast => {
            let mut builder = with_source!(builder.broadcast());
            if shape.signed {
                builder = builder.signed(frame_counter);
            }
            ShapedFrame::Plain(apply_shape!(builder, shape).payload(payload).build()?)
        }
        SendTarget::Multicast(channel) => {
            let mut builder = with_source!(builder.multicast(channel)).frame_counter(frame_counter);
            if shape.encrypted {
                builder = builder.encrypted();
            }
            ShapedFrame::Secured(secured!(builder)?)
        }
        SendTarget::Unicast(dst) => {
            let mut builder = with_source!(builder.unicast(dst)).frame_counter(frame_counter);
            if shape.ack_requested {
                builder = builder.ack_requested();
            }
            if shape.encrypted {
                builder = builder.encrypted();
            }
            ShapedFrame::Secured(secured!(builder)?)
        }
        SendTarget::BlindUnicast { channel, dst } => {
            let mut builder =
                with_source!(builder.blind_unicast(channel, dst)).frame_counter(frame_counter);
            if shape.ack_requested {
                builder = builder.ack_requested();
            }
            if !shape.encrypted {
                builder = builder.unencrypted();
            }
            ShapedFrame::Secured(secured!(builder)?)
        }
    })
}

/// Whether a send earns its one Route Retry when its ack times out.
///
/// Shared by the timeout path, which knows every input, and send-time
/// planning, which asks whether a retry could ever happen and so takes the
/// runtime inputs as true. Only a send with an ack to wait for learns that
/// it failed, and only one with a flood budget of its own has a budget to
/// rediscover a route with. Past that, a send that assumed a route (an
/// attached source route, or a budget the MAC narrowed) always earns one,
/// and one that assumed nothing earns one only when the peer was heard
/// recently (see [`Mac::can_attempt_route_retry`]).
pub(super) fn route_retry_eligible(
    expects_ack: bool,
    requested_flood_hops: Option<u8>,
    already_retried: bool,
    route_assumed: bool,
    peer_heard_recently: bool,
) -> bool {
    expects_ack
        && requested_flood_hops.is_some_and(|hops| hops > 0)
        && !already_retried
        && (route_assumed || peer_heard_recently)
}

impl<
    P: Platform,
    const IDENTITIES: usize,
    const PEERS: usize,
    const CHANNELS: usize,
    const ACKS: usize,
    const TX: usize,
    const FRAME: usize,
    const DUP: usize,
    const HOLDS: usize,
    const RX_STRANGERS: usize,
> Mac<P, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP, HOLDS, RX_STRANGERS>
{
    /// The most payload a send from `from` to `destination` with `options`
    /// can carry.
    ///
    /// A payload within it builds in some shape the MAC is allowed to send,
    /// and if that shape could be Route-Retried, its retry form fits too.
    /// A frame that carries a Trace is held one byte below the frame limit,
    /// so the first repeater always has room for at least a truncated trace.
    pub fn payload_capacity(
        &self,
        from: LocalIdentityId,
        destination: SendDestination<'_>,
        options: &SendOptions,
    ) -> Result<usize, SendError> {
        let source = *self
            .identity(from)
            .ok_or(SendError::IdentityMissing)?
            .identity()
            .public_key();
        let options = Self::sanitized_send_options(destination, options);
        let chain = self.resolve_send_shapes(destination, &options)?;
        let mut capacity = 0;
        for shape in &chain {
            let Ok((len, retry_len)) =
                self.measure_shape(destination, &source, shape, &[0], options.flood_hops)
            else {
                continue;
            };
            let mut shape_capacity = self.shape_limit(shape).saturating_sub(len - 1);
            if let Some(retry_len) = retry_len {
                let retry_capacity = (self.max_frame() - 1).saturating_sub(retry_len - 1);
                shape_capacity = shape_capacity.min(retry_capacity);
            }
            capacity = capacity.max(shape_capacity);
        }
        Ok(capacity)
    }

    /// The largest frame the radio sends.
    pub(super) fn max_frame(&self) -> usize {
        self.radio.max_frame_size().min(FRAME)
    }

    /// The frame limit a shape is held to: one byte below the radio's for a
    /// traced frame, so a repeater can still add its entry (at worst a
    /// lone `0xFF`).
    pub(super) fn shape_limit(&self, shape: &SendShape) -> usize {
        if shape.trace {
            self.max_frame() - 1
        } else {
            self.max_frame()
        }
    }

    /// The options a send of this kind actually honors. Broadcasts are
    /// unencrypted, unacknowledged and unsalted; multicast is never
    /// acknowledged; only unicast and blind unicast carry an Ack MIC.
    pub(super) fn sanitized_send_options(
        destination: SendDestination<'_>,
        options: &SendOptions,
    ) -> SendOptions {
        let mut options = options.clone();
        match destination {
            SendDestination::Broadcast => {
                options.encrypted = false;
                options.ack_requested = false;
                options.salt = false;
                options.ack_mic = None;
            }
            SendDestination::Multicast(_) => {
                options.ack_requested = false;
                options.ack_mic = None;
            }
            SendDestination::Unicast(_) | SendDestination::BlindUnicast { .. } => {}
        }
        options
    }

    /// The chain of shapes a send may go out in, most preferred first:
    ///
    /// 1. everything the send asks for and the MAC adds;
    /// 2. the same without the Ack MIC;
    /// 3. then without the trace;
    /// 4. then, for unicast and blind unicast, without the cached source
    ///    route, flooding with the budget that covers it instead. A route
    ///    is dropped only when that budget reaches the peer: under
    ///    `no_flood()`, or a budget too short for the route, the route is
    ///    the only way there and the chain ends at step 3.
    ///
    /// `options` must already be [sanitized](Self::sanitized_send_options).
    pub(super) fn resolve_send_shapes(
        &self,
        destination: SendDestination<'_>,
        options: &SendOptions,
    ) -> Result<ShapeChain, SendError> {
        if let Some(channel) = destination.channel()
            && self.channels.lookup_by_key(channel).is_none()
        {
            return Err(SendError::ChannelMissing);
        }
        let base = SendShape {
            full_source: options.full_source,
            ack_requested: options.ack_requested,
            encrypted: options.encrypted,
            mic_size: options.mic_size,
            salted: options.salt,
            flood_hops: options.flood_hops,
            source_route: options
                .source_route
                .clone()
                .filter(|route| !route.is_empty()),
            operator_callsign: self.operating_policy.operator_callsign,
            trace: false,
            ack_mic: options.ack_mic,
            region_code: options.region_code,
            route_retry: false,
            signed: options.signed,
        };
        let mut chain = ShapeChain::new();
        let mut push = |shape: SendShape| {
            if chain.last() != Some(&shape) {
                // At most four shapes are ever pushed.
                let _ = chain.push(shape);
            }
        };

        let Some(peer) = destination.peer() else {
            let primary = SendShape {
                trace: options.trace
                    && Self::frame_is_repeatable(base.flood_hops, base.source_route.as_deref()),
                ..base
            };
            push(primary.clone());
            push(SendShape {
                trace: false,
                ..primary
            });
            return Ok(chain);
        };

        let (peer_id, _) = self
            .peer_registry
            .lookup_by_key(peer)
            .ok_or(SendError::PeerMissing)?;
        let route = self.effective_source_route(peer_id, options);
        let flood_hops = self.effective_flood_hops(peer_id, options, route.as_ref());
        // A caller asking for a trace is asking for a path to be recorded,
        // not for an empty option: a frame no repeater may carry has no path
        // to record, and the request is dropped rather than honored blind.
        let trace = Self::frame_is_repeatable(flood_hops, route.as_deref())
            && (options.trace || self.needs_route_discovery(peer_id, route.as_ref()));
        // Planning asks whether a retry could ever happen, so the inputs only
        // known at timeout are taken as true.
        let route_retry =
            route_retry_eligible(options.ack_requested, options.flood_hops, false, true, true);
        let primary = SendShape {
            flood_hops,
            source_route: route.clone(),
            trace,
            route_retry,
            ..base
        };
        push(primary.clone());
        let without_ack_mic = SendShape {
            ack_mic: None,
            ..primary
        };
        push(without_ack_mic.clone());
        let without_trace = SendShape {
            trace: false,
            ..without_ack_mic
        };
        push(without_trace.clone());

        // Only a route the MAC attached from its cache may be dropped; one
        // the caller attached is the caller's to keep.
        if options.source_route.is_none()
            && let Some(route) = route
        {
            let flooded = self.effective_flood_hops(peer_id, options, None);
            if flooded.is_some_and(|hops| usize::from(hops) >= route.len()) {
                push(SendShape {
                    flood_hops: flooded,
                    source_route: None,
                    ..without_trace
                });
            }
        }
        Ok(chain)
    }

    /// The length of `payload` built in `shape`, and of its Route Retry
    /// form when the shape has one (`usize::MAX` when that form does not
    /// fit a frame at all).
    fn measure_shape(
        &self,
        destination: SendDestination<'_>,
        source: &PublicKey,
        shape: &SendShape,
        payload: &[u8],
        requested_flood_hops: Option<u8>,
    ) -> Result<(usize, Option<usize>), BuildError> {
        // The counter and salt have fixed widths, so placeholders measure
        // exactly what the real values will.
        let mut buf = [0u8; FRAME];
        let salt = shape.salted.then_some(0);
        let channel_id = destination
            .channel()
            .and_then(|key| self.channels.lookup_by_key(key))
            .map(|channel| channel.derived.channel_id);
        let frame = build_shaped(
            destination.target(channel_id),
            source,
            shape,
            0,
            salt,
            payload,
            &mut buf,
        )?;
        let len = frame.len();
        let retry_len = match (&frame, destination.peer()) {
            (ShapedFrame::Secured(packet), Some(peer)) if shape.route_retry => Some(
                ResendRecord::<FRAME>::try_new(
                    packet.as_bytes(),
                    shape.source_route.as_ref().map(|route| route.as_slice()),
                )
                .ok()
                .map(|resend| resend.with_requested_flood_hops(requested_flood_hops))
                .and_then(|resend| self.synthesize_route_retry_resend(peer, &resend))
                .map_or(usize::MAX, |retry| retry.frame.len()),
            ),
            _ => None,
        };
        Ok((len, retry_len))
    }

    /// The first shape in `chain` that `payload` fits: within the shape's
    /// limit, and with a retry form within the traced limit when it has one.
    pub(super) fn choose_send_shape(
        &self,
        destination: SendDestination<'_>,
        source: &PublicKey,
        chain: &ShapeChain,
        payload: &[u8],
        requested_flood_hops: Option<u8>,
    ) -> Result<SendShape, SendError> {
        let mut last_error = BuildError::BufferTooSmall;
        for shape in chain {
            match self.measure_shape(destination, source, shape, payload, requested_flood_hops) {
                Ok((len, retry_len))
                    if len <= self.shape_limit(shape)
                        && retry_len.is_none_or(|retry| retry < self.max_frame()) =>
                {
                    return Ok(shape.clone());
                }
                Ok(_) | Err(BuildError::BufferTooSmall) => {}
                Err(error) => last_error = error,
            }
        }
        Err(SendError::Build(last_error))
    }
}
