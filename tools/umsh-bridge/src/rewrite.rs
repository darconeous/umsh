//! Turning an arriving frame into the one the bridge transmits.
//!
//! Steps 6, 7, 9 and 10 of the forwarding procedure all edit the frame;
//! this is where those edits happen, and nothing here decides whether
//! they should. What a bridge writes differs from what an ordinary
//! repeater writes in three ways, which is why this is not the MAC
//! coordinator's rewrite with a flag added:
//!
//! - `FHOPS_REM` is clamped to the exit maximum, on flood and
//!   source-routed hops alike.
//! - No region code is ever inserted. A bridge's interfaces may sit in
//!   different regions, so a code added at one segment's exit would
//!   misdescribe the packet everywhere else it goes.
//! - The confirmation copy is a second output: the same frame with
//!   `FHOPS_REM` forced to zero.

use umsh_core::options::OptionEncoder;
use umsh_core::{
    Fcf, FloodHops, OptionNumber, PacketHeader, PacketType, ParsedOptions, RouterHint,
};

/// What the forwarding procedure decided to write.
#[derive(Clone, Copy, Debug)]
pub struct RewritePlan {
    pub router_hint: RouterHint,
    /// Step 6: this hop was named by the source route, so its hint comes
    /// off the front — and steps 7 and 8 are skipped.
    pub consume_source_route: bool,
    /// Step 7: spend one from the flood budget. False for a
    /// source-routed hop, which spends nothing.
    pub decrement_flood_hops: bool,
    /// Step 9: ceiling applied to `FHOPS_REM` after any decrement.
    pub exit_clamp: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewriteError {
    /// The rewritten frame does not fit — which for a trace-route
    /// prepend is a drop, per step 10.
    TooLarge,
    /// The frame's options do not survive a round trip. A frame that
    /// parsed but cannot be re-encoded is one this bridge has no
    /// faithful way to forward.
    Malformed,
}

/// The frame to fan out, and the confirmation copy to send back the way
/// it came.
#[derive(Debug, PartialEq, Eq)]
pub struct Rewritten {
    pub forward: Vec<u8>,
    /// Identical to `forward` except that `FHOPS_REM` is zero. `None`
    /// when the frame carries no flood hop count, in which case the
    /// forwarded frame is already its own confirmation copy.
    confirmation: Option<Vec<u8>>,
}

impl Rewritten {
    /// The copy transmitted on the arrival interface so the previous hop
    /// can confirm the forward.
    ///
    /// Zeroing `FHOPS_REM` is what makes it flood-neutral: a repeater
    /// hearing it rejects it at hop accounting, so it confirms receipt
    /// without extending the local flood. It still matches on the
    /// duplicate-cache key, which excludes the hop count for every
    /// packet type.
    pub fn confirmation(&self) -> &[u8] {
        self.confirmation.as_deref().unwrap_or(&self.forward)
    }
}

/// Rewrite `src` for transmission, given a plan and a size ceiling.
pub fn rewrite(
    src: &[u8],
    header: &PacketHeader,
    options: &ParsedOptions,
    plan: RewritePlan,
    max_frame_size: usize,
) -> Result<Rewritten, RewriteError> {
    let mut out = vec![0u8; max_frame_size.max(src.len() + 4)];
    let len = encode(src, header, options, plan, &mut out)?;
    if len > max_frame_size {
        return Err(RewriteError::TooLarge);
    }
    out.truncate(len);

    // The hop count sits at a fixed offset — immediately after the FCF —
    // so the confirmation copy is one byte's difference, not a second
    // encode.
    let confirmation = header.flood_hops.map(|_| {
        let mut copy = out.clone();
        copy[1] &= 0x0F;
        copy
    });
    Ok(Rewritten {
        forward: out,
        confirmation,
    })
}

fn encode(
    src: &[u8],
    header: &PacketHeader,
    options: &ParsedOptions,
    plan: RewritePlan,
    dst: &mut [u8],
) -> Result<usize, RewriteError> {
    if dst.is_empty() {
        return Err(RewriteError::TooLarge);
    }

    // The options bit is not carried in the new format's FCF; everything
    // else about the frame's shape is preserved exactly.
    dst[0] = Fcf::new(
        header.packet_type(),
        header.fcf.full_source(),
        header.flood_hops.is_some(),
    )
    .0;
    let mut cursor = 1;

    if let Some(flood_hops) = header.flood_hops {
        let spent = if plan.decrement_flood_hops {
            flood_hops.decremented()
        } else {
            flood_hops
        };
        // Step 9. The clamp applies to a source-routed hop too, which is
        // what bounds the flood budget of a hybrid route that goes on to
        // flood beyond the bridge.
        let clamped = FloodHops::new(spent.remaining().min(plan.exit_clamp), spent.accumulated())
            .ok_or(RewriteError::Malformed)?;
        *dst.get_mut(cursor).ok_or(RewriteError::TooLarge)? = clamped.0;
        cursor += 1;
    }

    // DST / CHANNEL / SRC / SECINFO, verbatim: a bridge rewrites routing
    // metadata and nothing else.
    let fhops_len = usize::from(header.flood_hops.is_some());
    let fixed_core = src
        .get(1 + fhops_len..header.options_range.start)
        .ok_or(RewriteError::Malformed)?;
    let core_end = cursor + fixed_core.len();
    dst.get_mut(cursor..core_end)
        .ok_or(RewriteError::TooLarge)?
        .copy_from_slice(fixed_core);
    cursor = core_end;

    cursor += encode_options(src, header, options, plan, &mut dst[cursor..])?;

    // A MAC ack's trailer sits at a fixed offset and needs no marker;
    // otherwise one is needed exactly when data follows the options.
    let needs_marker = !matches!(header.packet_type(), PacketType::MacAck)
        && header.options_range.end < header.total_len;
    if needs_marker {
        *dst.get_mut(cursor).ok_or(RewriteError::TooLarge)? = 0xFF;
        cursor += 1;
    }

    // Body and MIC, verbatim. `options_range.end` is already past the
    // original marker.
    let tail = src
        .get(header.options_range.end..header.total_len)
        .ok_or(RewriteError::Malformed)?;
    let end = cursor + tail.len();
    dst.get_mut(cursor..end)
        .ok_or(RewriteError::TooLarge)?
        .copy_from_slice(tail);
    Ok(end)
}

fn encode_options(
    src: &[u8],
    header: &PacketHeader,
    options: &ParsedOptions,
    plan: RewritePlan,
    dst: &mut [u8],
) -> Result<usize, RewriteError> {
    let mut encoder = OptionEncoder::new(dst);
    if header.options_range.is_empty() {
        return Ok(encoder.finish());
    }

    for entry in umsh_core::iter_options(src, header.options_range.clone()) {
        let (number, value) = entry.map_err(|_| RewriteError::Malformed)?;
        match OptionNumber::from(number) {
            // Step 10: the bridge's hint goes on the front, so a
            // reversed trace is routable back through the bridge.
            OptionNumber::TraceRoute => {
                let mut trace = Vec::with_capacity(2 + value.len());
                trace.extend_from_slice(&plan.router_hint.0);
                trace.extend_from_slice(value);
                encoder
                    .put(number, &trace)
                    .map_err(|_| RewriteError::TooLarge)?;
            }
            // Step 6: remove the hint that named this bridge, preserving
            // the option even when it empties — an empty source route is
            // "the route ran out here", not "there was no route".
            OptionNumber::SourceRoute if plan.consume_source_route => {
                if value.len() < 2 || value.len() % 2 != 0 {
                    return Err(RewriteError::Malformed);
                }
                encoder
                    .put(number, &value[2..])
                    .map_err(|_| RewriteError::TooLarge)?;
            }
            // Region codes pass through untouched, and none is ever
            // added: see the module comment.
            _ => encoder
                .put(number, value)
                .map_err(|_| RewriteError::TooLarge)?,
        }
    }
    let _ = options;
    Ok(encoder.finish())
}

/// The next hop a source route names, if it names one.
pub fn next_source_route_hop(src: &[u8], options: &ParsedOptions) -> Option<RouterHint> {
    let range = options.source_route.clone()?;
    let hint = src.get(range.start..range.start + 2)?;
    Some(RouterHint([hint[0], hint[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_core::{NodeHint, PacketBuilder};

    const BRIDGE: RouterHint = RouterHint([0xB1, 0xD6]);
    const OTHER: RouterHint = RouterHint([0x0A, 0x0B]);

    fn plan() -> RewritePlan {
        RewritePlan {
            router_hint: BRIDGE,
            consume_source_route: false,
            decrement_flood_hops: true,
            exit_clamp: 1,
        }
    }

    /// A broadcast with a flood hop count, plus whatever options the
    /// caller adds — enough shape for every rewrite rule to bite.
    fn frame(remaining: u8, accumulated: u8, options: &[(OptionNumber, Vec<u8>)]) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let mut builder = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(NodeHint([1, 2, 3]))
            .flood_hops(remaining);
        for (number, value) in options {
            builder = builder.option(*number, value);
        }
        let mut frame = builder.payload(b"hello").build().unwrap().to_vec();
        // The builder only ever starts a packet, so a non-zero
        // accumulated count — an already-forwarded packet, which is what
        // a bridge mostly sees — is written in directly.
        frame[1] = FloodHops::new(remaining, accumulated).unwrap().0;
        frame
    }

    fn run(src: &[u8], plan: RewritePlan) -> Result<Rewritten, RewriteError> {
        let header = PacketHeader::parse(src).unwrap();
        let options = ParsedOptions::extract(src, header.options_range.clone()).unwrap();
        rewrite(src, &header, &options, plan, 255)
    }

    fn reparse(frame: &[u8]) -> (PacketHeader, ParsedOptions) {
        let header = PacketHeader::parse(frame).expect("output reparses");
        let options = ParsedOptions::extract(frame, header.options_range.clone()).unwrap();
        (header, options)
    }

    #[test]
    fn a_flood_hop_spends_one_from_the_budget_and_counts_one() {
        let src = frame(7, 2, &[]);
        let out = run(&src, plan()).unwrap();
        let (header, _) = reparse(&out.forward);
        let hops = header.flood_hops.unwrap();
        // Decremented 7 -> 6, then clamped to the exit maximum of 1.
        assert_eq!(hops.remaining(), 1);
        assert_eq!(
            hops.accumulated(),
            3,
            "the hop through the bridge is counted"
        );
    }

    #[test]
    fn the_exit_clamp_only_ever_lowers_the_budget() {
        let src = frame(1, 0, &[]);
        let out = run(&src, plan()).unwrap();
        let (header, _) = reparse(&out.forward);
        // 1 -> 0 by the decrement; the clamp does not raise it back.
        assert_eq!(header.flood_hops.unwrap().remaining(), 0);

        let out = run(
            &src,
            RewritePlan {
                exit_clamp: 8,
                ..plan()
            },
        )
        .unwrap();
        assert_eq!(reparse(&out.forward).0.flood_hops.unwrap().remaining(), 0);
    }

    #[test]
    fn a_source_routed_hop_spends_nothing_but_is_still_clamped() {
        let src = frame(
            9,
            1,
            &[(OptionNumber::SourceRoute, [BRIDGE.0, OTHER.0].concat())],
        );
        let out = run(
            &src,
            RewritePlan {
                consume_source_route: true,
                decrement_flood_hops: false,
                ..plan()
            },
        )
        .unwrap();

        let (header, options) = reparse(&out.forward);
        let hops = header.flood_hops.unwrap();
        assert_eq!(hops.accumulated(), 1, "a routed hop spends no flood budget");
        assert_eq!(hops.remaining(), 1, "but the clamp still applies");

        let route = options.source_route.clone().unwrap();
        assert_eq!(&out.forward[route], &OTHER.0, "our own hint came off");
    }

    #[test]
    fn a_source_route_that_empties_keeps_its_option() {
        let src = frame(2, 0, &[(OptionNumber::SourceRoute, BRIDGE.0.to_vec())]);
        let out = run(
            &src,
            RewritePlan {
                consume_source_route: true,
                decrement_flood_hops: false,
                ..plan()
            },
        )
        .unwrap();
        let (_, options) = reparse(&out.forward);
        let route = options.source_route.clone().expect("the option survives");
        assert!(route.is_empty(), "emptied, not removed");
    }

    #[test]
    fn the_bridges_hint_goes_on_the_front_of_a_trace_route() {
        let src = frame(3, 0, &[(OptionNumber::TraceRoute, OTHER.0.to_vec())]);
        let out = run(&src, plan()).unwrap();
        let (_, options) = reparse(&out.forward);
        let trace = options.trace_route.clone().unwrap();
        assert_eq!(&out.forward[trace], &[BRIDGE.0, OTHER.0].concat()[..]);
    }

    #[test]
    fn a_trace_prepend_that_would_not_fit_is_a_drop() {
        let src = frame(3, 0, &[(OptionNumber::TraceRoute, OTHER.0.to_vec())]);
        let header = PacketHeader::parse(&src).unwrap();
        let options = ParsedOptions::extract(&src, header.options_range.clone()).unwrap();
        // One byte short of what the prepend needs.
        let ceiling = src.len() + 1;
        assert_eq!(
            rewrite(&src, &header, &options, plan(), ceiling),
            Err(RewriteError::TooLarge)
        );
        assert!(rewrite(&src, &header, &options, plan(), ceiling + 1).is_ok());
    }

    #[test]
    fn a_region_code_survives_untouched_and_none_is_added() {
        let src = frame(3, 0, &[(OptionNumber::RegionCode, vec![0x78, 0x53])]);
        let out = run(&src, plan()).unwrap();
        let (_, options) = reparse(&out.forward);
        assert_eq!(options.region_code, Some([0x78, 0x53]));

        // And a frame without one still has none.
        let src = frame(3, 0, &[]);
        let out = run(&src, plan()).unwrap();
        assert_eq!(reparse(&out.forward).1.region_code, None);
    }

    #[test]
    fn everything_but_the_routing_metadata_is_byte_identical() {
        let src = frame(3, 0, &[]);
        let out = run(&src, plan()).unwrap();
        let before = PacketHeader::parse(&src).unwrap();
        let (after, _) = reparse(&out.forward);
        assert_eq!(
            &src[before.body_range.clone()],
            &out.forward[after.body_range.clone()]
        );
        assert_eq!(
            &src[before.mic_range.clone()],
            &out.forward[after.mic_range.clone()]
        );
        assert_eq!(before.channel, after.channel);
        assert_eq!(before.source, after.source);
    }

    #[test]
    fn the_confirmation_copy_differs_in_exactly_the_remaining_hop_count() {
        let src = frame(7, 2, &[]);
        let out = run(&src, plan()).unwrap();
        let confirmation = out.confirmation();

        assert_eq!(confirmation.len(), out.forward.len());
        for (index, (a, b)) in out.forward.iter().zip(confirmation).enumerate() {
            if index == 1 {
                continue;
            }
            assert_eq!(a, b, "byte {index}");
        }
        let (header, _) = reparse(confirmation);
        let hops = header.flood_hops.unwrap();
        assert_eq!(hops.remaining(), 0, "it recruits no forwarders");
        assert_eq!(hops.accumulated(), 3, "the hop count stays honest");

        // And it keys the same, which is the whole point.
        assert_eq!(
            umsh_mac::forward_id::forwarding_dup_key(&out.forward),
            umsh_mac::forward_id::forwarding_dup_key(confirmation)
        );
    }

    #[test]
    fn a_frame_without_a_hop_count_is_its_own_confirmation_copy() {
        let mut buf = [0u8; 128];
        let src = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_hint(NodeHint([1, 2, 3]))
            .payload(b"hello")
            .build()
            .unwrap()
            .to_vec();
        assert!(
            PacketHeader::parse(&src).unwrap().flood_hops.is_none(),
            "this frame is meant to carry no hop count"
        );

        let out = run(
            &src,
            RewritePlan {
                decrement_flood_hops: false,
                ..plan()
            },
        )
        .unwrap();
        assert_eq!(out.confirmation(), out.forward.as_slice());
    }

    #[test]
    fn the_next_source_route_hop_is_the_first_hint() {
        let src = frame(
            3,
            0,
            &[(OptionNumber::SourceRoute, [OTHER.0, BRIDGE.0].concat())],
        );
        let header = PacketHeader::parse(&src).unwrap();
        let options = ParsedOptions::extract(&src, header.options_range.clone()).unwrap();
        assert_eq!(next_source_route_hop(&src, &options), Some(OTHER));

        let src = frame(3, 0, &[]);
        let header = PacketHeader::parse(&src).unwrap();
        let options = ParsedOptions::extract(&src, header.options_range.clone()).unwrap();
        assert_eq!(next_source_route_hop(&src, &options), None);
    }
}
