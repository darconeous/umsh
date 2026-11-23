//! The bounds and offered choices native code builds its pickers from, so
//! no app writes a protocol limit down a second time.

use umsh_ulcp::ids::{MAX_AUTO_ANNOUNCE_INTERVAL_S, MIN_AUTO_ANNOUNCE_INTERVAL_S};

use crate::mobile_mesh::{DEFAULT_BEACON_FLOOD_HOPS, DEFAULT_FLOOD_HOPS};

/// The cell a phone discloses until the user picks another, in bytes of
/// cell code: what a device starts with too.
pub(crate) const DEFAULT_LOCATION_PRECISION: u8 = 5;

/// The shortest gap between two unnarrowed asks for identities. Each one
/// draws an answer from every node in range.
pub(super) const DISCOVERY_COOLDOWN_MS: u64 = 40_000;

const HOUR_S: u32 = 60 * 60;

/// Advertisement intervals offered, 0 (off) first.
const ADVERT_INTERVAL_CHOICES_S: [u32; 5] = [0, HOUR_S, 4 * HOUR_S, 12 * HOUR_S, 24 * HOUR_S];

/// Beacon intervals offered, 0 (off) first.
const BEACON_INTERVAL_CHOICES_S: [u32; 5] = [0, 20 * 60, 30 * 60, HOUR_S, 4 * HOUR_S];

const _: () = assert!(DEFAULT_LOCATION_PRECISION == umsh_ulcp_device::DEFAULT_IDENT_PRECISION);
const _: () = assert!(umsh_node::location::MAX_PRECISION == umsh_ulcp_device::MAX_IDENT_PRECISION);
const _: () = assert!(umsh_mac::CachedRoute::MAX_HINTS == umsh_ulcp::node_msg::MAX_ROUTE_HINTS);

/// Bounds and offered choices for this phone's own settings, channels and
/// manual paths, and the announcement intervals offered for the phone and
/// its devices alike. Constants: read once.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileLimitsRecord {
    /// Most repeaters a frame may still cross.
    pub max_flood_hops: u8,
    /// The reach a phone starts with; picking past it asks first.
    pub recommended_flood_hops: u8,
    pub recommended_beacon_flood_hops: u8,
    /// Most repeaters a manual path names.
    pub max_route_hints: u8,
    /// Flood allowance a new manual path starts with.
    pub manual_path_flood_hops: u8,
    pub node_hint_len: u8,
    pub repeater_hint_len: u8,
    /// Location precision, in bytes of cell code.
    pub min_location_precision: u8,
    pub max_location_precision: u8,
    pub default_location_precision: u8,
    /// Announcement interval bounds, seconds; 0 is off and lies outside
    /// them.
    pub min_announce_interval_s: u32,
    pub max_announce_interval_s: u32,
    /// Intervals offered, seconds, 0 (off) first. Phone and device pickers.
    pub advert_interval_choices_s: Vec<u32>,
    pub beacon_interval_choices_s: Vec<u32>,
    /// Shortest gap between two unnarrowed asks for identities.
    pub discovery_cooldown_ms: u64,
}

/// See [`MobileLimitsRecord`].
#[uniffi::export]
pub fn mobile_limits() -> MobileLimitsRecord {
    MobileLimitsRecord {
        max_flood_hops: umsh_mac::MAX_FLOOD_HOPS,
        recommended_flood_hops: DEFAULT_FLOOD_HOPS,
        recommended_beacon_flood_hops: DEFAULT_BEACON_FLOOD_HOPS,
        max_route_hints: narrow(umsh_mac::CachedRoute::MAX_HINTS),
        manual_path_flood_hops: umsh_mac::ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS,
        node_hint_len: narrow(umsh_ulcp::node_msg::HINT_LEN),
        repeater_hint_len: narrow(umsh_ulcp::node_msg::REPEATER_HINT_LEN),
        min_location_precision: 1,
        max_location_precision: umsh_node::location::MAX_PRECISION,
        default_location_precision: DEFAULT_LOCATION_PRECISION,
        min_announce_interval_s: MIN_AUTO_ANNOUNCE_INTERVAL_S,
        max_announce_interval_s: MAX_AUTO_ANNOUNCE_INTERVAL_S,
        advert_interval_choices_s: ADVERT_INTERVAL_CHOICES_S.to_vec(),
        beacon_interval_choices_s: BEACON_INTERVAL_CHOICES_S.to_vec(),
        discovery_cooldown_ms: DISCOVERY_COOLDOWN_MS,
    }
}

/// An announcement interval the phone may run: 0 (off) stays off, and any
/// other is held to the bounds devices enforce.
pub(super) fn bounded_interval(seconds: u32) -> u32 {
    if seconds == 0 {
        0
    } else {
        seconds.clamp(MIN_AUTO_ANNOUNCE_INTERVAL_S, MAX_AUTO_ANNOUNCE_INTERVAL_S)
    }
}

/// A small protocol count, as the record carries it.
const fn narrow(value: usize) -> u8 {
    assert!(value <= u8::MAX as usize);
    value as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_interval_choice_is_off_or_in_bounds() {
        let limits = mobile_limits();
        for choices in [
            &limits.advert_interval_choices_s,
            &limits.beacon_interval_choices_s,
        ] {
            assert_eq!(choices.first(), Some(&0));
            for &choice in choices {
                assert!(
                    choice == 0
                        || (limits.min_announce_interval_s..=limits.max_announce_interval_s)
                            .contains(&choice),
                    "{choice}"
                );
                assert_eq!(bounded_interval(choice), choice);
            }
        }
    }

    #[test]
    fn the_defaults_lie_inside_their_ranges() {
        let limits = mobile_limits();
        assert!((1..=limits.max_flood_hops).contains(&limits.recommended_flood_hops));
        assert!((0..=limits.max_flood_hops).contains(&limits.recommended_beacon_flood_hops));
        assert!((0..=limits.max_flood_hops).contains(&limits.manual_path_flood_hops));
        assert!(
            (limits.min_location_precision..=limits.max_location_precision)
                .contains(&limits.default_location_precision)
        );
        assert!(limits.min_announce_interval_s < limits.max_announce_interval_s);
        assert_eq!(
            (
                limits.max_route_hints,
                limits.node_hint_len,
                limits.repeater_hint_len
            ),
            (15, 3, 2)
        );
    }

    #[test]
    fn an_interval_out_of_bounds_is_held_to_them() {
        assert_eq!(bounded_interval(0), 0);
        assert_eq!(bounded_interval(1), MIN_AUTO_ANNOUNCE_INTERVAL_S);
        assert_eq!(bounded_interval(u32::MAX), MAX_AUTO_ANNOUNCE_INTERVAL_S);
    }
}
