//! The sampled-dilation membership rule.
//!
//! Expanded coverage is not stored as geometry. A region's effective
//! membership is *defined* as: a position belongs to a region if any point of
//! a fixed sample pattern — the position itself, six points at half the
//! region's expansion distance, and twelve at the full distance — lands inside
//! the region's core. The pattern is the semantics, not an approximation of
//! something else, which is what lets every implementation agree exactly: each
//! computes the same nineteen spherical destinations and runs the same integer
//! point-in-polygon test.
//!
//! This mirrors `tools/regiondb-build/src/regiondb_build/sampling.py`
//! operation for operation.

/// Mean Earth radius, matching the suggested-default tie-break.
pub const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// Bearings of the full-distance ring, degrees clockwise from north.
pub const FULL_RING_BEARINGS: [f64; 12] = [
    0.0, 30.0, 60.0, 90.0, 120.0, 150.0, 180.0, 210.0, 240.0, 270.0, 300.0, 330.0,
];

/// Bearings of the half-distance ring.
pub const HALF_RING_BEARINGS: [f64; 6] = [0.0, 60.0, 120.0, 180.0, 240.0, 300.0];

/// Spherical direct problem: where `distance_m` at `bearing_deg` lands.
pub fn destination(latitude: f64, longitude: f64, bearing_deg: f64, distance_m: f64) -> (f64, f64) {
    let angular = distance_m / EARTH_RADIUS_M;
    let bearing = bearing_deg.to_radians();
    let lat1 = latitude.to_radians();
    let sin_lat2 = lat1.sin() * angular.cos() + lat1.cos() * angular.sin() * bearing.cos();
    let lat2 = sin_lat2.clamp(-1.0, 1.0).asin();
    let lon2 = longitude.to_radians()
        + (bearing.sin() * angular.sin() * lat1.cos()).atan2(angular.cos() - lat1.sin() * sin_lat2);
    (lat2.to_degrees(), lon2.to_degrees())
}

/// Every position to test against core geometry, the position itself first.
///
/// The position leads so a caller can stop on a core hit, and so the
/// core-versus-expanded distinction falls out of the same loop: a hit at
/// index zero is core, a hit anywhere later is expanded.
pub fn sample_positions(latitude: f64, longitude: f64, expansion_m: i64) -> Vec<(f64, f64)> {
    let mut positions = Vec::with_capacity(19);
    positions.push((latitude, longitude));
    if expansion_m <= 0 {
        return positions;
    }
    let full = expansion_m as f64;
    for bearing in HALF_RING_BEARINGS {
        positions.push(destination(latitude, longitude, bearing, full / 2.0));
    }
    for bearing in FULL_RING_BEARINGS {
        positions.push(destination(latitude, longitude, bearing, full));
    }
    positions
}
