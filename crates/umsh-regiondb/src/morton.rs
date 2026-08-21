//! The fixed lookup grid.
//!
//! Longitude and latitude are each mapped onto 16 bits and interleaved into a
//! 32-bit Z-order key, so that a quadtree cell at any depth is one contiguous
//! range of keys and a lookup is a single indexed query.
//!
//! Every operation here has an exact counterpart in the Python builder
//! (`tools/regiondb-build/src/regiondb_build/morton.py`). Both are written as
//! the same two floating-point operations rather than in whichever idiom each
//! language finds natural, because a position that lands in different cells on
//! different platforms would be a lookup that disagrees with itself.

/// Depth of the grid: 16 bits per axis, so cells are roughly 600 m by 300 m at
/// the equator.
pub const MAX_DEPTH: u32 = 16;

/// Cells per axis at maximum depth.
pub const GRID: f64 = 65536.0;

/// A coordinate that cannot be placed on the grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MortonError {
    /// Longitude or latitude was NaN or infinite.
    NotFinite,
    /// Latitude was outside `[-90, 90]`.
    LatitudeOutOfRange,
}

impl core::fmt::Display for MortonError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFinite => write!(formatter, "coordinate is not finite"),
            Self::LatitudeOutOfRange => write!(formatter, "latitude is outside [-90, 90]"),
        }
    }
}

impl std::error::Error for MortonError {}

/// Wrap longitude into `[-180, 180)`.
///
/// Exactly +180 wraps to -180: the two name the same meridian, and picking one
/// keeps the grid a partition rather than an overlap.
pub fn normalize_longitude(longitude: f64) -> Result<f64, MortonError> {
    if !longitude.is_finite() {
        return Err(MortonError::NotFinite);
    }
    Ok(longitude - 360.0 * ((longitude + 180.0) / 360.0).floor())
}

/// Validate latitude, which is clamped into the grid rather than wrapped.
pub fn check_latitude(latitude: f64) -> Result<f64, MortonError> {
    if !latitude.is_finite() {
        return Err(MortonError::NotFinite);
    }
    if !(-90.0..=90.0).contains(&latitude) {
        return Err(MortonError::LatitudeOutOfRange);
    }
    Ok(latitude)
}

/// Grid coordinates of the cell containing a position.
pub fn cell_xy(latitude: f64, longitude: f64) -> Result<(u32, u32), MortonError> {
    let longitude = normalize_longitude(longitude)?;
    let latitude = check_latitude(latitude)?;
    let x = ((longitude + 180.0) / 360.0 * GRID).floor();
    let y = ((latitude + 90.0) / 180.0 * GRID).floor();
    Ok((clamp_axis(x), clamp_axis(y)))
}

fn clamp_axis(value: f64) -> u32 {
    if value <= 0.0 {
        0
    } else if value >= GRID - 1.0 {
        GRID as u32 - 1
    } else {
        value as u32
    }
}

/// Interleave two 16-bit values, `x` into the even bits.
pub fn interleave(x: u32, y: u32) -> u32 {
    spread(x) | (spread(y) << 1)
}

fn spread(value: u32) -> u32 {
    let mut value = value & 0xFFFF;
    value = (value | (value << 8)) & 0x00FF_00FF;
    value = (value | (value << 4)) & 0x0F0F_0F0F;
    value = (value | (value << 2)) & 0x3333_3333;
    value = (value | (value << 1)) & 0x5555_5555;
    value
}

/// The maximum-depth Morton key for a position.
pub fn key(latitude: f64, longitude: f64) -> Result<u32, MortonError> {
    let (x, y) = cell_xy(latitude, longitude)?;
    Ok(interleave(x, y))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longitude_180_names_the_same_meridian_as_minus_180() {
        assert_eq!(normalize_longitude(180.0).unwrap(), -180.0);
        assert_eq!(key(0.0, 180.0).unwrap(), key(0.0, -180.0).unwrap());
    }

    #[test]
    fn longitudes_wrap_rather_than_clamp() {
        assert!((normalize_longitude(181.0).unwrap() - -179.0).abs() < 1e-9);
        assert!((normalize_longitude(-181.0).unwrap() - 179.0).abs() < 1e-9);
        assert!((normalize_longitude(540.0).unwrap() - -180.0).abs() < 1e-9);
    }

    #[test]
    fn latitude_90_lands_in_the_last_row() {
        let (_, y) = cell_xy(90.0, 0.0).unwrap();
        assert_eq!(y, GRID as u32 - 1);
    }

    #[test]
    fn rejects_coordinates_that_are_not_positions() {
        assert_eq!(check_latitude(90.5), Err(MortonError::LatitudeOutOfRange));
        assert_eq!(check_latitude(f64::NAN), Err(MortonError::NotFinite));
        assert_eq!(
            normalize_longitude(f64::INFINITY),
            Err(MortonError::NotFinite)
        );
    }

    #[test]
    fn interleave_places_longitude_in_the_even_bits() {
        assert_eq!(interleave(1, 0), 0b01);
        assert_eq!(interleave(0, 1), 0b10);
        assert_eq!(interleave(0xFFFF, 0), 0x5555_5555);
        assert_eq!(interleave(0, 0xFFFF), 0xAAAA_AAAA);
    }

    #[test]
    fn corners_of_a_cell_share_its_key_prefix() {
        // Two positions in the same maximum-depth cell must produce the same
        // key, or the cache would answer them from different ranges.
        let first = key(37.5119, -122.2495).unwrap();
        let second = key(37.511_900_1, -122.249_500_1).unwrap();
        assert_eq!(first, second);
    }
}
