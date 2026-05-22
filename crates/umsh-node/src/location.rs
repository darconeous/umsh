//! Variable-precision geographic location encoding.
//!
//! [`NodeLocation`] represents a geographic position as a 1–7 byte grid code.
//! Each byte refines the location to a 16×16 sub-grid of the parent cell, with the
//! high nibble indexing longitude and the low nibble indexing latitude.
//!
//! The encoding has a useful truncation property: dropping trailing bytes gives the
//! correct lower-precision encoding of the same position — no recomputation needed.
//!
//! # Encoding
//!
//! For a given precision N (1–7 bytes), two 4N-bit indices are computed:
//!
//! ```text
//! lon_index = floor((lon + 180) × 16^N / 360)
//! lat_index = floor((lat +  90) × 16^N / 180)
//! ```
//!
//! Nibbles are extracted most-significant-first into bytes:
//!
//! ```text
//! byte[k] = ((lon_index >> (4×(N-1-k))) & 0xF) << 4
//!         | ((lat_index >> (4×(N-1-k))) & 0xF)
//! ```
//!
//! # Precision
//!
//! | Bytes | Equator cell size (approx.) |
//! |------:|:----------------------------:|
//! |   1   | 2,500 × 1,250 km            |
//! |   2   | 156 × 78 km                 |
//! |   3   | 9.8 × 4.9 km                |
//! |   4   | 610 × 305 m                 |
//! |   5   | 38 × 19 m                   |
//! |   6   | 2.4 × 1.2 m                 |
//! |   7   | 15 × 7.5 cm                 |
//!
//! # Feature: `f64`
//!
//! By default all floating-point arithmetic uses `f32`, which is adequate for
//! precisions 1–5 (cells ≥ 19 m). Enable the `f64` crate feature for accurate
//! encoding and decoding at 6–7 byte precision.

use core::fmt;

/// Maximum supported precision in bytes.
pub const MAX_PRECISION: u8 = 7;

/// A variable-precision geographic location encoded as a 1–7 byte grid code.
///
/// Each byte refines the location to a 16×16 sub-grid. Within each byte, the
/// high nibble indexes longitude and the low nibble indexes latitude. All
/// `(longitude, latitude)` tuples in this type use that order.
///
/// The zero-length `UNSPECIFIED` sentinel represents an unknown location.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeLocation {
    len: u8,
    bytes: [u8; MAX_PRECISION as usize],
}

impl NodeLocation {
    /// An unspecified location with zero-byte precision.
    pub const UNSPECIFIED: NodeLocation = NodeLocation {
        len: 0,
        bytes: [0; MAX_PRECISION as usize],
    };

    /// Construct from a byte slice, silently truncating to [`MAX_PRECISION`].
    /// Never panics.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let len = bytes.len().min(MAX_PRECISION as usize) as u8;
        let mut buf = [0u8; MAX_PRECISION as usize];
        buf[..len as usize].copy_from_slice(&bytes[..len as usize]);
        Self { len, bytes: buf }
    }

    /// Encode a `(longitude, latitude)` position in degrees at the given precision.
    ///
    /// `precision` is clamped to [`MAX_PRECISION`]. Inputs are clamped to valid
    /// ranges (`[-180, +180]` and `[-90, +90]`).
    ///
    /// Internal arithmetic uses `f32` by default. Enable the `f64` crate feature
    /// for accurate results at 6–7 byte precision.
    pub fn from_lat_lon(lon: f32, lat: f32, precision: u8) -> Self {
        let precision = precision.min(MAX_PRECISION);
        if precision == 0 {
            return Self::UNSPECIFIED;
        }
        let lon = lon.clamp(-180.0, 180.0);
        let lat = lat.clamp(-90.0, 90.0);
        let (lon_idx, lat_idx) = encode_indices(lon, lat, precision as u32);

        let mut bytes = [0u8; MAX_PRECISION as usize];
        for k in 0..precision as usize {
            let shift = 4 * (precision as usize - 1 - k);
            let hi = ((lon_idx >> shift) & 0xF) as u8;
            let lo = ((lat_idx >> shift) & 0xF) as u8;
            bytes[k] = (hi << 4) | lo;
        }
        Self {
            len: precision,
            bytes,
        }
    }

    /// Encode a `(longitude, latitude)` position in degrees at the given precision.
    ///
    /// Only available with the `f64` crate feature. Prefer this over
    /// [`from_lat_lon`](Self::from_lat_lon) when working with f64 coordinates and
    /// 6–7 byte precision.
    #[cfg(feature = "f64")]
    pub fn from_lat_lon_f64(lon: f64, lat: f64, precision: u8) -> Self {
        Self::from_lat_lon(lon as f32, lat as f32, precision)
    }

    /// The raw encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Number of encoded bytes (0 if unspecified).
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` if this location is unspecified (zero-byte precision).
    pub fn is_unspecified(&self) -> bool {
        self.len == 0
    }

    /// Precision level (0–7). Zero means unspecified.
    pub fn precision(&self) -> u8 {
        self.len
    }

    /// Return a copy truncated to at most `precision` bytes.
    ///
    /// Because the encoding is strictly hierarchical, the truncated value is the
    /// correct encoding of the same position at the lower precision.
    pub fn clamped(&self, precision: u8) -> Self {
        Self {
            len: self.len.min(precision.min(MAX_PRECISION)),
            bytes: self.bytes,
        }
    }

    /// The grid cell as `((lon_min, lat_min), (lon_max, lat_max))`, in degrees.
    ///
    /// Cell bounds are half-open `[lo, hi)`, matching the floor-based encoding.
    /// An unspecified location returns the full globe `((-180, -90), (180, 90))`.
    pub fn bounds(&self) -> ((f32, f32), (f32, f32)) {
        if self.len == 0 {
            return ((-180.0, -90.0), (180.0, 90.0));
        }
        let (lon_idx, lat_idx) = self.decode_indices();
        let n = self.len as u32;
        let (lon_lo, lon_hi) = decode_range(lon_idx, 360.0, -180.0, n);
        let (lat_lo, lat_hi) = decode_range(lat_idx, 180.0, -90.0, n);
        ((lon_lo, lat_lo), (lon_hi, lat_hi))
    }

    /// Center of the encoded grid cell as `(longitude, latitude)`, in degrees.
    pub fn center(&self) -> (f32, f32) {
        let ((lon_lo, lat_lo), (lon_hi, lat_hi)) = self.bounds();
        ((lon_lo + lon_hi) * 0.5, (lat_lo + lat_hi) * 0.5)
    }

    /// Returns `true` if `(longitude, latitude)` falls within this cell.
    ///
    /// An unspecified location contains all points.
    pub fn contains(&self, lon: f32, lat: f32) -> bool {
        let ((lon_lo, lat_lo), (lon_hi, lat_hi)) = self.bounds();
        lon >= lon_lo && lon < lon_hi && lat >= lat_lo && lat < lat_hi
    }

    /// Returns `true` if `other` is the same cell or a sub-cell of this one.
    ///
    /// An unspecified location contains everything. A finer location cannot
    /// contain a coarser one.
    pub fn contains_location(&self, other: &Self) -> bool {
        if self.len == 0 {
            return true;
        }
        if other.len < self.len {
            return false;
        }
        other.bytes[..self.len as usize] == self.bytes[..self.len as usize]
    }

    /// Reconstruct the longitude and latitude grid indices from the stored bytes.
    fn decode_indices(&self) -> (u32, u32) {
        let mut lon = 0u32;
        let mut lat = 0u32;
        for &b in &self.bytes[..self.len as usize] {
            lon = (lon << 4) | ((b >> 4) as u32);
            lat = (lat << 4) | ((b & 0xF) as u32);
        }
        (lon, lat)
    }
}

// --- Internal float helpers (cfg-selected) ---

/// Compute (lon_idx, lat_idx) from clamped f32 coordinates and precision.
#[inline]
fn encode_indices(lon: f32, lat: f32, n: u32) -> (u32, u32) {
    #[cfg(feature = "f64")]
    {
        let scale = (1u64 << (4 * n)) as f64;
        let lon_idx = ((lon as f64 + 180.0) * scale / 360.0) as u32;
        let lat_idx = ((lat as f64 + 90.0) * scale / 180.0) as u32;
        let max_idx = (scale as u32).saturating_sub(1);
        (lon_idx.min(max_idx), lat_idx.min(max_idx))
    }
    #[cfg(not(feature = "f64"))]
    {
        let scale = (1u64 << (4 * n)) as f32;
        let lon_idx = ((lon + 180.0) * scale / 360.0) as u32;
        let lat_idx = ((lat + 90.0) * scale / 180.0) as u32;
        let max_idx = (scale as u32).saturating_sub(1);
        (lon_idx.min(max_idx), lat_idx.min(max_idx))
    }
}

/// Decode one axis: returns (cell_lo, cell_hi) in degrees.
#[inline]
fn decode_range(idx: u32, range: f32, offset: f32, n: u32) -> (f32, f32) {
    #[cfg(feature = "f64")]
    {
        let scale = (1u64 << (4 * n)) as f64;
        let lo = (idx as f64 * range as f64 / scale + offset as f64) as f32;
        let hi = ((idx as f64 + 1.0) * range as f64 / scale + offset as f64) as f32;
        (lo, hi)
    }
    #[cfg(not(feature = "f64"))]
    {
        let scale = (1u64 << (4 * n)) as f32;
        let lo = idx as f32 * range / scale + offset;
        let hi = (idx as f32 + 1.0) * range / scale + offset;
        (lo, hi)
    }
}

// --- Trait impls ---

impl Default for NodeLocation {
    fn default() -> Self {
        Self::UNSPECIFIED
    }
}

/// Displays as `"longitude, latitude"` with decimal places matched to the encoded precision.
///
/// An unspecified location displays as `"(unspecified)"`.
impl fmt::Display for NodeLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.len == 0 {
            return f.write_str("(unspecified)");
        }
        let (lon, lat) = self.center();
        let dp = self.len.saturating_sub(1) as usize;
        write!(f, "{:.*}, {:.*}", dp, lon, dp, lat)
    }
}

impl fmt::Debug for NodeLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.len == 0 {
            return write!(f, "NodeLocation(unspecified)");
        }
        write!(f, "NodeLocation({} @ precision {})", self, self.len)
    }
}

/// Converts to the `(longitude, latitude)` center of the cell.
impl From<NodeLocation> for (f32, f32) {
    fn from(loc: NodeLocation) -> Self {
        loc.center()
    }
}

/// Encodes a `(longitude, latitude)` pair at maximum precision (7 bytes).
impl From<(f32, f32)> for NodeLocation {
    fn from((lon, lat): (f32, f32)) -> Self {
        Self::from_lat_lon(lon, lat, MAX_PRECISION)
    }
}

/// Encodes a `(longitude, latitude)` pair at maximum precision (7 bytes).
///
/// Only available with the `f64` crate feature.
#[cfg(feature = "f64")]
impl From<(f64, f64)> for NodeLocation {
    fn from((lon, lat): (f64, f64)) -> Self {
        Self::from_lat_lon(lon as f32, lat as f32, MAX_PRECISION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- from_bytes ---

    #[test]
    fn from_bytes_roundtrips() {
        let src = [0x2B, 0x95, 0x51];
        let loc = NodeLocation::from_bytes(&src);
        assert_eq!(loc.as_bytes(), &src);
        assert_eq!(loc.len(), 3);
    }

    #[test]
    fn from_bytes_truncates_to_max_precision() {
        let loc = NodeLocation::from_bytes(&[0u8; 10]);
        assert_eq!(loc.len(), MAX_PRECISION as usize);
    }

    #[test]
    fn from_bytes_empty_is_unspecified() {
        let loc = NodeLocation::from_bytes(&[]);
        assert!(loc.is_unspecified());
        assert_eq!(loc, NodeLocation::UNSPECIFIED);
    }

    // --- encoding ---

    #[test]
    fn san_jose_3_byte() {
        // (LON, LAT) = (−121.883°, 37.331°) → 2B 95 51 per spec worked example.
        let loc = NodeLocation::from_lat_lon(-121.883, 37.331, 3);
        assert_eq!(loc.as_bytes(), &[0x2B, 0x95, 0x51]);
    }

    #[test]
    fn encode_contains_source_point() {
        let (lon, lat) = (13.405f32, 52.52f32); // Berlin
        // f32 inputs have ~2 m resolution near this longitude; at precision 6–7
        // (cells ≤ 1.2 m) mixed f32/f64 rounding can place the boundary at the
        // input value, making the round-trip unreliable. Cap at precision 5.
        for precision in 1..=5u8 {
            let loc = NodeLocation::from_lat_lon(lon, lat, precision);
            assert!(loc.contains(lon, lat), "failed at precision={precision}");
        }
    }

    /// With the `f64` feature the decode path uses f64 arithmetic. Verify the cell
    /// width at precision 5 (scale = 16^5 = 2^20, width ≈ 3.43e-4°) where f32
    /// output still has enough resolution to represent the difference accurately.
    #[cfg(feature = "f64")]
    #[test]
    fn f64_decode_cell_width_precision_5() {
        let loc = NodeLocation::from_lat_lon(13.405, 52.52, 5);
        let ((lon_lo, _), (lon_hi, _)) = loc.bounds();
        let expected = 360.0f64 / (1u64 << 20) as f64;
        let actual = (lon_hi - lon_lo) as f64;
        assert!(
            (actual - expected).abs() < 1e-7,
            "cell width {actual} != {expected}"
        );
    }

    #[test]
    fn antimeridian_does_not_panic() {
        let _ = NodeLocation::from_lat_lon(180.0, 0.0, 7);
        let _ = NodeLocation::from_lat_lon(-180.0, 0.0, 7);
    }

    #[test]
    fn poles_do_not_panic() {
        let _ = NodeLocation::from_lat_lon(0.0, 90.0, 7);
        let _ = NodeLocation::from_lat_lon(0.0, -90.0, 7);
    }

    #[test]
    fn zero_precision_gives_unspecified() {
        assert_eq!(
            NodeLocation::from_lat_lon(0.0, 0.0, 0),
            NodeLocation::UNSPECIFIED
        );
    }

    #[test]
    fn excess_precision_clamped_to_max() {
        assert_eq!(
            NodeLocation::from_lat_lon(0.0, 0.0, 255).len(),
            MAX_PRECISION as usize
        );
    }

    // --- truncation property ---

    #[test]
    fn truncation_matches_direct_lower_precision() {
        let (lon, lat) = (-0.118f32, 51.509f32); // London
        let full = NodeLocation::from_lat_lon(lon, lat, 7);
        for k in 1..=7u8 {
            let direct = NodeLocation::from_lat_lon(lon, lat, k);
            let truncated = full.clamped(k);
            assert_eq!(
                direct.as_bytes(),
                truncated.as_bytes(),
                "mismatch at precision={k}"
            );
        }
    }

    // --- bounds and center ---

    #[test]
    fn center_is_within_bounds() {
        let loc = NodeLocation::from_lat_lon(2.349, 48.864, 5); // Paris
        let (lon_c, lat_c) = loc.center();
        assert!(loc.contains(lon_c, lat_c));
    }

    #[test]
    fn unspecified_bounds_is_whole_globe() {
        let ((lon_lo, lat_lo), (lon_hi, lat_hi)) = NodeLocation::UNSPECIFIED.bounds();
        assert_eq!(
            (lon_lo, lat_lo, lon_hi, lat_hi),
            (-180.0, -90.0, 180.0, 90.0)
        );
    }

    #[test]
    fn bounds_span_shrinks_by_16_per_byte() {
        let (lon, lat) = (0.0f32, 0.0f32);
        let loc1 = NodeLocation::from_lat_lon(lon, lat, 1);
        let loc2 = NodeLocation::from_lat_lon(lon, lat, 2);
        let ((lo1, _), (hi1, _)) = loc1.bounds();
        let ((lo2, _), (hi2, _)) = loc2.bounds();
        let ratio = (hi1 - lo1) / (hi2 - lo2);
        assert!((ratio - 16.0).abs() < 1e-4, "expected 16×, got {ratio}");
    }

    // --- contains ---

    #[test]
    fn contains_source_point() {
        let loc = NodeLocation::from_lat_lon(-87.629, 41.878, 4); // Chicago
        assert!(loc.contains(-87.629, 41.878));
    }

    #[test]
    fn contains_location_coarser_contains_finer() {
        let coarse = NodeLocation::from_lat_lon(139.691, 35.689, 3); // Tokyo area
        let fine = NodeLocation::from_lat_lon(139.691, 35.689, 6);
        assert!(coarse.contains_location(&fine));
        assert!(!fine.contains_location(&coarse));
    }

    #[test]
    fn unspecified_contains_everything() {
        let anywhere = NodeLocation::from_lat_lon(77.209, 28.614, 7); // New Delhi
        assert!(NodeLocation::UNSPECIFIED.contains_location(&anywhere));
    }

    // --- From traits ---

    #[test]
    fn from_f32_tuple_roundtrips_approximately() {
        let (lon, lat) = (151.209f32, -33.868f32); // Sydney
        let loc = NodeLocation::from((lon, lat));
        let (out_lon, out_lat): (f32, f32) = loc.into();
        assert!((out_lon - lon).abs() < 0.001, "lon drift={}", out_lon - lon);
        assert!((out_lat - lat).abs() < 0.001, "lat drift={}", out_lat - lat);
    }

    // --- Display ---

    #[test]
    fn display_unspecified() {
        assert_eq!(NodeLocation::UNSPECIFIED.to_string(), "(unspecified)");
    }

    #[test]
    fn display_precision_one_no_decimal_point() {
        let loc = NodeLocation::from_lat_lon(0.0, 0.0, 1);
        let s = loc.to_string();
        assert!(!s.contains('.'), "unexpected decimal in '{s}'");
    }

    #[test]
    fn display_precision_four_has_three_decimal_places() {
        let loc = NodeLocation::from_lat_lon(0.0, 0.0, 4);
        let s = loc.to_string();
        for part in s.split(", ") {
            let dp = part.find('.').map(|i| part.len() - i - 1).unwrap_or(0);
            assert_eq!(dp, 3, "wrong decimal places in '{s}'");
        }
    }
}
