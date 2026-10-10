//! How favorable a path looks, from what the frames that crossed it measured.
//!
//! A score ranks paths; it does not predict delivery. An endpoint cannot
//! know the spreading factor, bandwidth, or conditions of a link it does not
//! own—a bridge hides even that—so nothing here models the physics. Each hop
//! is charged by how far its SNR falls short of a comfortable level, the
//! charges add up along the path, and the path with the largest (least
//! negative) score wins.
//!
//! Adding in decibels multiplies in power, which is why a sum of shortfalls
//! behaves like a product of delivery odds without any arithmetic on
//! probabilities. Past a knee the charge steepens: every digital link fails
//! abruptly near its floor, so one hop barely above it must not tie with
//! several hops that are only somewhat weak.
//!
//! Everything is in centibels, the unit the MAC measures SNR in.

use umsh_core::options::TraceSignalEntry;

/// SNR at or above which a hop is charged nothing.
const COMFORT_SNR_CB: i32 = -50;
/// Shortfall below comfort charged one-for-one before the charge steepens.
const KNEE_CB: i32 = 40;
/// How much each centibel of shortfall past the knee costs.
const STEEP_SLOPE: i32 = 3;
/// What every hop costs on top of its shortfall, so that a shorter path wins
/// between two that are otherwise as good, and a longer one wins only when
/// it has to.
const HOP_COST_CB: i32 = 10;
/// How much worse an unmeasured direction is assumed to be than the
/// measured one. A link heard well one way may not work at all the other.
const ASYMMETRY_CB: i32 = 60;
/// The charge for an air hop no frame has measured.
const UNMEASURED_CB: i32 = KNEE_CB;
/// The extra charge for a first hop that has shown it does not hear us.
const UNHEARD_CB: i32 = 120;

/// How much an acknowledged route is credited when a new one is weighed
/// against it. A credit rather than a rank: a route confirmed by an
/// exchange whose flood tail may have done the delivering is still
/// displaced by a much better path.
const CONFIRMED_CREDIT_CB: i32 = 60;
/// How much better a new path must score to displace the one in use, so
/// that ordinary fading does not flip routes back and forth.
const SWITCH_MARGIN_CB: i32 = 30;

/// How long an acknowledgment vouches for the route it came back on.
pub(crate) const CONFIRMATION_TTL_MS: u64 = 10 * 60 * 1000;

/// What is known about one hop of a path, in the direction it would be
/// sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hop {
    /// Measured in the direction this node would send: SNR in centibels.
    Outbound(i16),
    /// Measured only in the direction toward this node.
    Inbound(i16),
    /// A first hop that has shown it does not hear this node, with what was
    /// measured toward this node, if anything.
    Unheard(Option<i16>),
    /// A point-to-point link, with no radio in it.
    PointToPoint,
    /// Not measured in either direction.
    Unmeasured,
}

impl Hop {
    /// What a trace-signal entry says about the hop that wrote it: how well
    /// that repeater heard the transmitter before it, which is the
    /// direction toward this node.
    pub(crate) fn from_trace_entry(entry: TraceSignalEntry) -> Self {
        match entry.snr_centibels() {
            Some(snr) => Self::Inbound(snr),
            None => Self::PointToPoint,
        }
    }

    fn charge_cb(self) -> i32 {
        match self {
            Self::Outbound(snr) => shortfall_charge(i32::from(snr)),
            Self::Inbound(snr) => shortfall_charge(i32::from(snr) - ASYMMETRY_CB),
            Self::Unheard(Some(snr)) => {
                shortfall_charge(i32::from(snr) - ASYMMETRY_CB) + UNHEARD_CB
            }
            Self::Unheard(None) => UNMEASURED_CB + UNHEARD_CB,
            Self::PointToPoint => 0,
            Self::Unmeasured => UNMEASURED_CB,
        }
    }
}

/// The two-slope charge for a hop measured at `snr_cb`.
fn shortfall_charge(snr_cb: i32) -> i32 {
    let shortfall = (COMFORT_SNR_CB - snr_cb).max(0);
    if shortfall <= KNEE_CB {
        shortfall
    } else {
        KNEE_CB + STEEP_SLOPE * (shortfall - KNEE_CB)
    }
}

/// Score a path from its hops, nearest first.
pub(crate) fn path_score(hops: impl IntoIterator<Item = Hop>) -> i16 {
    let total: i32 = hops
        .into_iter()
        .map(|hop| hop.charge_cb() + HOP_COST_CB)
        .fold(0, i32::saturating_add);
    i16::try_from(-total).unwrap_or(i16::MIN)
}

/// Whether a path scoring `candidate` should displace one scoring
/// `current`, given whether an acknowledgment recently vouched for it.
pub(crate) fn displaces(candidate: i16, current: i16, confirmed: bool) -> bool {
    let credit = if confirmed { CONFIRMED_CREDIT_CB } else { 0 };
    i32::from(candidate) > i32::from(current) + credit + SWITCH_MARGIN_CB
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(db: i16) -> i16 {
        db * 10
    }

    /// The example that motivated the steep segment: one hop barely above
    /// its floor must lose to more hops that are each only somewhat weak.
    #[test]
    fn one_nearly_dead_hop_loses_to_several_weak_ones() {
        let shortfall = |short_db: i16| Hop::Outbound(db(-5) - db(short_db));
        let one_bad = path_score([shortfall(9), Hop::Outbound(db(10))]);
        let three_weak = path_score([shortfall(3), shortfall(3), shortfall(3)]);
        assert!(three_weak > one_bad, "{three_weak} vs {one_bad}");
    }

    #[test]
    fn a_stronger_hop_scores_higher_until_comfort() {
        let weak = path_score([Hop::Outbound(db(-10))]);
        let better = path_score([Hop::Outbound(db(-7))]);
        let comfortable = path_score([Hop::Outbound(db(-5))]);
        let strong = path_score([Hop::Outbound(db(12))]);
        assert!(better > weak);
        assert!(comfortable > better);
        assert_eq!(strong, comfortable, "past comfort, more SNR buys nothing");
    }

    /// Between two equally clean paths, the shorter one wins.
    #[test]
    fn every_hop_costs_something() {
        let short = path_score([Hop::Outbound(db(10)), Hop::Inbound(db(10))]);
        let long = path_score([
            Hop::Outbound(db(10)),
            Hop::Inbound(db(10)),
            Hop::Inbound(db(10)),
        ]);
        assert!(short > long);
    }

    /// A hop measured only toward us is assumed worse the other way, so a
    /// marginal reception cannot pass for a usable link.
    #[test]
    fn a_one_way_measurement_is_discounted() {
        assert!(
            path_score([Hop::Outbound(db(-6))]) > path_score([Hop::Inbound(db(-6))]),
            "the same reading counts for more when it was taken our way"
        );
    }

    #[test]
    fn a_first_hop_that_does_not_hear_us_is_heavily_charged() {
        let heard_well_unknown = path_score([Hop::Inbound(db(5)), Hop::Inbound(db(5))]);
        let unheard = path_score([Hop::Unheard(Some(db(5))), Hop::Inbound(db(5))]);
        let longer_but_proven = path_score([
            Hop::Outbound(db(8)),
            Hop::Inbound(db(4)),
            Hop::Inbound(db(5)),
        ]);
        assert!(heard_well_unknown > unheard);
        assert!(
            longer_but_proven > unheard,
            "a repeater that hears us beats a shortcut through one that does not"
        );
    }

    #[test]
    fn a_point_to_point_hop_costs_only_its_hop() {
        assert_eq!(
            path_score([Hop::PointToPoint]),
            path_score([Hop::Outbound(db(20))])
        );
        assert_eq!(
            Hop::from_trace_entry(TraceSignalEntry::POINT_TO_POINT),
            Hop::PointToPoint
        );
        assert_eq!(
            Hop::from_trace_entry(TraceSignalEntry::new(-98, 40)),
            Hop::Inbound(40)
        );
    }

    #[test]
    fn displacing_a_route_takes_a_clear_margin_and_more_when_it_was_acknowledged() {
        let current = db(-10);
        assert!(
            !displaces(current + db(2), current, false),
            "within the margin"
        );
        assert!(displaces(current + db(4), current, false));
        assert!(!displaces(current + db(4), current, true), "acknowledged");
        assert!(displaces(current + db(10), current, true));
    }
}
