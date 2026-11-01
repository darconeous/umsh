//! How many optional flood hops a send along an established route carries
//! past the route's end.
//!
//! A learned route narrows a send's flood budget to what the route costs.
//! The slack on top of that keeps delivery working when the far end of the
//! path has changed since the route was learned—most often because the
//! destination moved. It is spent only where something suggests that might
//! have happened: the destination is known to be mobile, or the link nearest
//! it is unmeasured or weak.
//!
//! The route's *last hop* is that link: between the destination and the
//! first node that heard it. For a direct route it is this node's own
//! reception of the destination; for a source route it is how the repeater
//! named by the route's last hint heard the destination, as reported in the
//! trace-signal entry that repeater wrote.

use crate::options::HopSignal;

/// The slack the policy grants, in flood hops, when it grants any.
///
/// Source-route hints must be consumed before this allowance can be used.
/// Originating sends still respect their flood ceiling, including disabled
/// flooding.
pub const ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS: u8 = 1;

/// A destination heard directly above this RSSI has enough link budget
/// that the reverse direction can be trusted without a repeater backstop.
pub const STRONG_DIRECT_RSSI_DBM: i16 = -75;

/// A last hop measured at or below this RSSI is weak enough that the
/// destination may already be out of that repeater's reach.
pub const WEAK_LAST_HOP_RSSI_DBM: i16 = -96;

/// What a sender knows about the far end of the route it is about to use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteEvidence {
    /// The route was chosen by the application rather than learned.
    pub hand_set: bool,
    /// The route reaches the destination without a repeater.
    pub direct: bool,
    /// How the route's last hop was measured, if it was. A point-to-point
    /// entry marks a hop with no radio in it.
    pub last_hop: Option<HopSignal>,
    /// The destination advertises itself as mobile.
    pub peer_mobile: bool,
    /// The frame being acknowledged is a retransmission of one this node
    /// has already acknowledged: whatever went back the first time did not
    /// arrive, however good the link toward this node looks.
    pub peer_retransmitted: bool,
}

/// The flood hops a send along an established route carries past the
/// route's end: [`ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS`] or none.
///
/// A route chosen by hand gets none: the application said where the frame
/// goes. An acknowledgment of a retransmission gets the slack, since the
/// last one did not get through. A destination heard directly and
/// strongly, or over a link with no radio in it, gets none. Otherwise a
/// mobile destination, an unmeasured last hop, or a weak one each earn the
/// slack.
pub fn established_route_slack(evidence: RouteEvidence) -> u8 {
    if evidence.hand_set {
        return 0;
    }
    if evidence.peer_retransmitted {
        return ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS;
    }
    // `None`: never measured. `Some(None)`: a point-to-point hop.
    let last_hop_rssi = evidence.last_hop.map(HopSignal::rssi_dbm);
    let strong_direct = evidence.direct
        && match last_hop_rssi {
            Some(None) => true,
            Some(Some(rssi)) => rssi > STRONG_DIRECT_RSSI_DBM,
            None => false,
        };
    if strong_direct {
        return 0;
    }
    if evidence.peer_mobile {
        return ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS;
    }
    match last_hop_rssi {
        None => ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS,
        Some(Some(rssi)) if rssi <= WEAK_LAST_HOP_RSSI_DBM => ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS,
        Some(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLACK: u8 = ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS;

    fn air(rssi_dbm: i16) -> Option<HopSignal> {
        Some(HopSignal::new(rssi_dbm, 0))
    }

    fn direct(last_hop: Option<HopSignal>) -> RouteEvidence {
        RouteEvidence {
            direct: true,
            last_hop,
            ..RouteEvidence::default()
        }
    }

    fn routed(last_hop: Option<HopSignal>) -> RouteEvidence {
        RouteEvidence {
            last_hop,
            ..RouteEvidence::default()
        }
    }

    #[test]
    fn a_route_chosen_by_hand_never_gets_slack() {
        for evidence in [direct(air(-120)), routed(None), routed(air(-120))] {
            let evidence = RouteEvidence {
                hand_set: true,
                peer_mobile: true,
                ..evidence
            };
            assert_eq!(established_route_slack(evidence), 0);
        }
    }

    #[test]
    fn an_ack_for_a_retransmission_gets_slack_however_strong_the_link() {
        for evidence in [
            direct(air(-30)),
            direct(Some(HopSignal::POINT_TO_POINT)),
            routed(air(-40)),
        ] {
            let evidence = RouteEvidence {
                peer_retransmitted: true,
                ..evidence
            };
            assert_eq!(established_route_slack(evidence), SLACK, "{evidence:?}");
        }
        let hand_set = RouteEvidence {
            hand_set: true,
            peer_retransmitted: true,
            ..direct(air(-30))
        };
        assert_eq!(established_route_slack(hand_set), 0);
    }

    #[test]
    fn a_strong_or_bridged_direct_peer_gets_none_even_when_mobile() {
        for last_hop in [air(-74), air(-30), Some(HopSignal::POINT_TO_POINT)] {
            let evidence = RouteEvidence {
                peer_mobile: true,
                ..direct(last_hop)
            };
            assert_eq!(established_route_slack(evidence), 0, "{last_hop:?}");
        }
    }

    #[test]
    fn a_direct_peer_below_the_strong_threshold_falls_through_to_the_last_hop_rules() {
        assert_eq!(established_route_slack(direct(air(-75))), 0);
        assert_eq!(established_route_slack(direct(air(-95))), 0);
        assert_eq!(established_route_slack(direct(air(-96))), SLACK);
        let mobile = RouteEvidence {
            peer_mobile: true,
            ..direct(air(-75))
        };
        assert_eq!(established_route_slack(mobile), SLACK);
    }

    #[test]
    fn an_unmeasured_last_hop_gets_slack() {
        assert_eq!(established_route_slack(direct(None)), SLACK);
        assert_eq!(established_route_slack(routed(None)), SLACK);
    }

    #[test]
    fn a_mobile_destination_gets_slack_past_any_routed_last_hop() {
        for last_hop in [air(-40), Some(HopSignal::POINT_TO_POINT)] {
            let evidence = RouteEvidence {
                peer_mobile: true,
                ..routed(last_hop)
            };
            assert_eq!(established_route_slack(evidence), SLACK);
        }
    }

    #[test]
    fn only_a_weak_routed_last_hop_gets_slack() {
        assert_eq!(established_route_slack(routed(air(-95))), 0);
        assert_eq!(established_route_slack(routed(air(-96))), SLACK);
        assert_eq!(established_route_slack(routed(air(-120))), SLACK);
        assert_eq!(
            established_route_slack(routed(Some(HopSignal::POINT_TO_POINT))),
            0
        );
    }
}
