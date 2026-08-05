//! Variable-precision geographic location encoding.
//!
//! [`NodeLocation`] represents a geographic position as a 1–7 byte grid code.
//! Each byte refines the location to a 16×16 sub-grid of the parent cell, with the
//! high nibble indexing latitude and the low nibble indexing longitude.
//!
//! The encoding has a useful truncation property: dropping trailing bytes gives the
//! correct lower-precision encoding of the same position — no recomputation needed.
//!
//! Every coordinate pair in this module is `(latitude, longitude)`, in that
//! order, without exception — parameters, return tuples, and rendered text alike.
//!
//! # Encoding
//!
//! For a given precision N (1–7 bytes), two 4N-bit indices are computed:
//!
//! ```text
//! lat_index = floor((lat +  90) × 16^N / 180)
//! lon_index = floor((lon + 180) × 16^N / 360)
//! ```
//!
//! Nibbles are extracted most-significant-first into bytes:
//!
//! ```text
//! byte[k] = ((lat_index >> (4×(N-1-k))) & 0xF) << 4
//!         | ((lon_index >> (4×(N-1-k))) & 0xF)
//! ```
//!
//! # Precision
//!
//! | Bytes | Equator cell, lat × lon (approx.) |
//! |------:|:---------------------------------:|
//! |   1   | 1,250 × 2,500 km                 |
//! |   2   | 78 × 156 km                      |
//! |   3   | 4.9 × 9.8 km                     |
//! |   4   | 305 × 610 m                      |
//! |   5   | 19 × 38 m                        |
//! |   6   | 1.2 × 2.4 m                      |
//! |   7   | 7.5 × 15 cm                      |
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
/// high nibble indexes latitude and the low nibble indexes longitude. Every
/// coordinate pair in this type is `(latitude, longitude)`, in that order.
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

    /// Encode a `(latitude, longitude)` position in degrees at the given precision.
    ///
    /// `precision` is clamped to [`MAX_PRECISION`]. Inputs are clamped to valid
    /// ranges (`[-90, +90]` and `[-180, +180]`).
    ///
    /// Internal arithmetic uses `f32` by default. Enable the `f64` crate feature
    /// for accurate results at 6–7 byte precision.
    pub fn from_lat_lon(lat: f32, lon: f32, precision: u8) -> Self {
        let precision = precision.min(MAX_PRECISION);
        if precision == 0 {
            return Self::UNSPECIFIED;
        }
        let lat = lat.clamp(-90.0, 90.0);
        let lon = lon.clamp(-180.0, 180.0);
        let (lat_idx, lon_idx) = encode_indices(lat, lon, precision as u32);

        let mut bytes = [0u8; MAX_PRECISION as usize];
        for k in 0..precision as usize {
            let shift = 4 * (precision as usize - 1 - k);
            let hi = ((lat_idx >> shift) & 0xF) as u8;
            let lo = ((lon_idx >> shift) & 0xF) as u8;
            bytes[k] = (hi << 4) | lo;
        }
        Self {
            len: precision,
            bytes,
        }
    }

    /// Encode a `(latitude, longitude)` position in degrees at the given precision.
    ///
    /// Only available with the `f64` crate feature. Prefer this over
    /// [`from_lat_lon`](Self::from_lat_lon) when working with f64 coordinates and
    /// 6–7 byte precision.
    #[cfg(feature = "f64")]
    pub fn from_lat_lon_f64(lat: f64, lon: f64, precision: u8) -> Self {
        Self::from_lat_lon(lat as f32, lon as f32, precision)
    }

    /// Encode a `(latitude, longitude)` position given in units of 1e-7
    /// degrees, exactly and without floating point.
    ///
    /// This is the constructor to use for a position that arrived as
    /// decimal digits — a GNSS receiver's `ddmm.mmmm` fields, most of
    /// all. [`from_lat_lon`](Self::from_lat_lon) has to round the value
    /// into a binary float first, which at 6–7 byte precision can land it
    /// in the neighbouring cell; this cannot, at any precision, with or
    /// without the `f64` feature.
    ///
    /// `precision` is clamped to [`MAX_PRECISION`]; coordinates are
    /// clamped to their valid ranges.
    pub fn from_e7(lat_e7: i32, lon_e7: i32, precision: u8) -> Self {
        const LAT_SPAN_E7: i64 = 1_800_000_000;
        const LON_SPAN_E7: i64 = 3_600_000_000;

        let precision = precision.min(MAX_PRECISION);
        if precision == 0 {
            return Self::UNSPECIFIED;
        }
        let lat = i64::from(lat_e7).clamp(-LAT_SPAN_E7 / 2, LAT_SPAN_E7 / 2);
        let lon = i64::from(lon_e7).clamp(-LON_SPAN_E7 / 2, LON_SPAN_E7 / 2);
        // 16^7 × 3.6e9 is ~2.6e17, comfortably inside i64.
        let cells = 1i64 << (4 * precision as u32);
        let max_index = (cells - 1) as u32;
        let lat_idx = (((lat + LAT_SPAN_E7 / 2) * cells) / LAT_SPAN_E7).min(i64::from(max_index));
        let lon_idx = (((lon + LON_SPAN_E7 / 2) * cells) / LON_SPAN_E7).min(i64::from(max_index));

        let mut bytes = [0u8; MAX_PRECISION as usize];
        for k in 0..precision as usize {
            let shift = 4 * (precision as usize - 1 - k);
            let hi = ((lat_idx >> shift) & 0xF) as u8;
            let lo = ((lon_idx >> shift) & 0xF) as u8;
            bytes[k] = (hi << 4) | lo;
        }
        Self {
            len: precision,
            bytes,
        }
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
        let len = self.len.min(precision.min(MAX_PRECISION));
        // Bytes past `len` are cleared, not merely ignored. Every
        // constructor maintains that invariant, and the derived
        // `PartialEq`/`Hash` compare the whole array — so a `clamped`
        // value that kept its dropped tail would fail to equal the
        // identical encoding built any other way, and callers that
        // compare cells to decide whether a position has moved would see
        // a change that did not happen.
        let mut bytes = [0u8; MAX_PRECISION as usize];
        bytes[..len as usize].copy_from_slice(&self.bytes[..len as usize]);
        Self { len, bytes }
    }

    /// The grid cell as `((lat_min, lon_min), (lat_max, lon_max))`, in degrees.
    ///
    /// Cell bounds are half-open `[lo, hi)`, matching the floor-based encoding.
    /// An unspecified location returns the full globe `((-90, -180), (90, 180))`.
    pub fn bounds(&self) -> ((f32, f32), (f32, f32)) {
        if self.len == 0 {
            return ((-90.0, -180.0), (90.0, 180.0));
        }
        let (lat_idx, lon_idx) = self.decode_indices();
        let n = self.len as u32;
        let (lat_lo, lat_hi) = decode_range(lat_idx, 180.0, -90.0, n);
        let (lon_lo, lon_hi) = decode_range(lon_idx, 360.0, -180.0, n);
        ((lat_lo, lon_lo), (lat_hi, lon_hi))
    }

    /// Center of the encoded grid cell as `(latitude, longitude)`, in degrees.
    pub fn center(&self) -> (f32, f32) {
        let ((lat_lo, lon_lo), (lat_hi, lon_hi)) = self.bounds();
        ((lat_lo + lat_hi) * 0.5, (lon_lo + lon_hi) * 0.5)
    }

    /// Returns `true` if `(latitude, longitude)` falls within this cell.
    ///
    /// An unspecified location contains all points.
    pub fn contains(&self, lat: f32, lon: f32) -> bool {
        let ((lat_lo, lon_lo), (lat_hi, lon_hi)) = self.bounds();
        lat >= lat_lo && lat < lat_hi && lon >= lon_lo && lon < lon_hi
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

    /// Reconstruct the latitude and longitude grid indices from the stored bytes.
    fn decode_indices(&self) -> (u32, u32) {
        let mut lat = 0u32;
        let mut lon = 0u32;
        for &b in &self.bytes[..self.len as usize] {
            lat = (lat << 4) | ((b >> 4) as u32);
            lon = (lon << 4) | ((b & 0xF) as u32);
        }
        (lat, lon)
    }
}

// --- Internal float helpers (cfg-selected) ---

/// Compute (lat_idx, lon_idx) from clamped f32 coordinates and precision.
#[inline]
fn encode_indices(lat: f32, lon: f32, n: u32) -> (u32, u32) {
    #[cfg(feature = "f64")]
    {
        let scale = (1u64 << (4 * n)) as f64;
        let lat_idx = ((lat as f64 + 90.0) * scale / 180.0) as u32;
        let lon_idx = ((lon as f64 + 180.0) * scale / 360.0) as u32;
        let max_idx = (scale as u32).saturating_sub(1);
        (lat_idx.min(max_idx), lon_idx.min(max_idx))
    }
    #[cfg(not(feature = "f64"))]
    {
        let scale = (1u64 << (4 * n)) as f32;
        let lat_idx = ((lat + 90.0) * scale / 180.0) as u32;
        let lon_idx = ((lon + 180.0) * scale / 360.0) as u32;
        let max_idx = (scale as u32).saturating_sub(1);
        (lat_idx.min(max_idx), lon_idx.min(max_idx))
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

/// Displays as `"latitude, longitude"` with decimal places matched to the encoded precision.
///
/// An unspecified location displays as `"(unspecified)"`.
impl fmt::Display for NodeLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.len == 0 {
            return f.write_str("(unspecified)");
        }
        let (lat, lon) = self.center();
        let dp = self.len.saturating_sub(1) as usize;
        write!(f, "{:.*}, {:.*}", dp, lat, dp, lon)
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

/// Converts to the `(latitude, longitude)` center of the cell.
impl From<NodeLocation> for (f32, f32) {
    fn from(loc: NodeLocation) -> Self {
        loc.center()
    }
}

/// Encodes a `(latitude, longitude)` pair at maximum precision (7 bytes).
impl From<(f32, f32)> for NodeLocation {
    fn from((lat, lon): (f32, f32)) -> Self {
        Self::from_lat_lon(lat, lon, MAX_PRECISION)
    }
}

/// Encodes a `(latitude, longitude)` pair at maximum precision (7 bytes).
///
/// Only available with the `f64` crate feature.
#[cfg(feature = "f64")]
impl From<(f64, f64)> for NodeLocation {
    fn from((lat, lon): (f64, f64)) -> Self {
        Self::from_lat_lon(lat as f32, lon as f32, MAX_PRECISION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- from_bytes ---

    #[test]
    fn from_bytes_roundtrips() {
        let src = [0xB2, 0x59, 0x15];
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
        // (LAT, LON) = (37.331°, −121.883°) → B2 59 15 per spec worked example.
        let loc = NodeLocation::from_lat_lon(37.331, -121.883, 3);
        assert_eq!(loc.as_bytes(), &[0xB2, 0x59, 0x15]);
    }

    // --- from_e7 ---

    #[test]
    fn from_e7_matches_the_spec_worked_example() {
        // The same San Jose point, from integer degrees.
        let loc = NodeLocation::from_e7(373_310_000, -1_218_830_000, 3);
        assert_eq!(loc.as_bytes(), &[0xB2, 0x59, 0x15]);
    }

    /// The integer path agrees with the float one wherever the float one
    /// is trustworthy — precisions 1 through 5, which is exactly the
    /// range `from_lat_lon` documents as reliable under `f32`.
    #[test]
    fn from_e7_agrees_with_the_float_path_where_that_path_is_sound() {
        let places = [
            (373_310_000i32, -1_218_830_000i32),
            (525_200_000, 134_050_000),
            (0, 0),
            (-410_000_000, 1_746_000_000),
            (-330_000_000, -700_000_000),
        ];
        for (lat_e7, lon_e7) in places {
            for precision in 1..=5u8 {
                let integer = NodeLocation::from_e7(lat_e7, lon_e7, precision);
                let float =
                    NodeLocation::from_lat_lon(lat_e7 as f32 / 1e7, lon_e7 as f32 / 1e7, precision);
                assert_eq!(
                    integer.as_bytes(),
                    float.as_bytes(),
                    "disagreement at ({lat_e7}, {lon_e7}) precision {precision}"
                );
            }
        }
    }

    /// The truncation property has to survive the integer path too: a
    /// shorter encoding of a point is the prefix of a longer one.
    #[test]
    fn from_e7_is_prefix_truncation_safe_at_every_precision() {
        let (lat_e7, lon_e7) = (373_310_456, -1_218_830_123);
        let full = NodeLocation::from_e7(lat_e7, lon_e7, MAX_PRECISION);
        for precision in 1..=MAX_PRECISION {
            let short = NodeLocation::from_e7(lat_e7, lon_e7, precision);
            assert_eq!(
                short.as_bytes(),
                &full.as_bytes()[..precision as usize],
                "precision {precision} is not a prefix of the full encoding"
            );
            assert_eq!(short, full.clamped(precision));
        }
    }

    /// Two locations naming the same cell at the same precision must
    /// compare equal however each was built. They did not: `clamped` kept
    /// the bytes it had dropped, and equality compares the whole array.
    #[test]
    fn a_clamped_location_equals_the_same_cell_built_directly() {
        let full = NodeLocation::from_e7(373_310_456, -1_218_830_123, MAX_PRECISION);
        for precision in 0..=MAX_PRECISION {
            let clamped = full.clamped(precision);
            let direct = NodeLocation::from_bytes(&full.as_bytes()[..precision as usize]);
            assert_eq!(clamped, direct, "at precision {precision}");
        }
    }

    #[test]
    fn from_e7_clamps_rather_than_wrapping_at_the_extremes() {
        // The poles and the antimeridian land in the last cell, not the
        // first: an index one past the end would read as the far side of
        // the world.
        let corner = NodeLocation::from_e7(900_000_000, 1_800_000_000, 2);
        assert_eq!(corner.as_bytes(), &[0xFF, 0xFF]);
        let opposite = NodeLocation::from_e7(-900_000_000, -1_800_000_000, 2);
        assert_eq!(opposite.as_bytes(), &[0x00, 0x00]);
        // Out-of-range inputs clamp to the same cells rather than wrap.
        assert_eq!(
            NodeLocation::from_e7(i32::MAX, i32::MAX, 2).as_bytes(),
            corner.as_bytes()
        );
        assert_eq!(
            NodeLocation::from_e7(i32::MIN, i32::MIN, 2).as_bytes(),
            opposite.as_bytes()
        );
    }

    #[test]
    fn from_e7_at_zero_precision_is_unspecified() {
        assert!(NodeLocation::from_e7(525_200_000, 134_050_000, 0).is_unspecified());
        // And past the maximum it clamps rather than overflowing.
        assert_eq!(
            NodeLocation::from_e7(525_200_000, 134_050_000, 20).len(),
            MAX_PRECISION as usize
        );
    }

    #[test]
    fn encode_contains_source_point() {
        let (lat, lon) = (52.52f32, 13.405f32); // Berlin
        // f32 inputs have ~2 m resolution near this longitude; at precision 6–7
        // (cells ≤ 1.2 m) mixed f32/f64 rounding can place the boundary at the
        // input value, making the round-trip unreliable. Cap at precision 5.
        for precision in 1..=5u8 {
            let loc = NodeLocation::from_lat_lon(lat, lon, precision);
            assert!(loc.contains(lat, lon), "failed at precision={precision}");
        }
    }

    /// With the `f64` feature the decode path uses f64 arithmetic. Verify the cell
    /// width at precision 5 (scale = 16^5 = 2^20, width ≈ 3.43e-4°) where f32
    /// output still has enough resolution to represent the difference accurately.
    #[cfg(feature = "f64")]
    #[test]
    fn f64_decode_cell_width_precision_5() {
        let loc = NodeLocation::from_lat_lon(52.52, 13.405, 5);
        let ((_, lon_lo), (_, lon_hi)) = loc.bounds();
        let expected = 360.0f64 / (1u64 << 20) as f64;
        let actual = (lon_hi - lon_lo) as f64;
        assert!(
            (actual - expected).abs() < 1e-7,
            "cell width {actual} != {expected}"
        );
    }

    #[test]
    fn antimeridian_does_not_panic() {
        let _ = NodeLocation::from_lat_lon(0.0, 180.0, 7);
        let _ = NodeLocation::from_lat_lon(0.0, -180.0, 7);
    }

    #[test]
    fn poles_do_not_panic() {
        let _ = NodeLocation::from_lat_lon(90.0, 0.0, 7);
        let _ = NodeLocation::from_lat_lon(-90.0, 0.0, 7);
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
        let (lat, lon) = (51.509f32, -0.118f32); // London
        let full = NodeLocation::from_lat_lon(lat, lon, 7);
        for k in 1..=7u8 {
            let direct = NodeLocation::from_lat_lon(lat, lon, k);
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
        let loc = NodeLocation::from_lat_lon(48.864, 2.349, 5); // Paris
        let (lat_c, lon_c) = loc.center();
        assert!(loc.contains(lat_c, lon_c));
    }

    #[test]
    fn unspecified_bounds_is_whole_globe() {
        let ((lat_lo, lon_lo), (lat_hi, lon_hi)) = NodeLocation::UNSPECIFIED.bounds();
        assert_eq!(
            (lat_lo, lon_lo, lat_hi, lon_hi),
            (-90.0, -180.0, 90.0, 180.0)
        );
    }

    #[test]
    fn bounds_span_shrinks_by_16_per_byte() {
        let (lat, lon) = (0.0f32, 0.0f32);
        let loc1 = NodeLocation::from_lat_lon(lat, lon, 1);
        let loc2 = NodeLocation::from_lat_lon(lat, lon, 2);
        let ((lo1, _), (hi1, _)) = loc1.bounds();
        let ((lo2, _), (hi2, _)) = loc2.bounds();
        let ratio = (hi1 - lo1) / (hi2 - lo2);
        assert!((ratio - 16.0).abs() < 1e-4, "expected 16×, got {ratio}");
    }

    // --- contains ---

    #[test]
    fn contains_source_point() {
        let loc = NodeLocation::from_lat_lon(41.878, -87.629, 4); // Chicago
        assert!(loc.contains(41.878, -87.629));
    }

    #[test]
    fn contains_location_coarser_contains_finer() {
        let coarse = NodeLocation::from_lat_lon(35.689, 139.691, 3); // Tokyo area
        let fine = NodeLocation::from_lat_lon(35.689, 139.691, 6);
        assert!(coarse.contains_location(&fine));
        assert!(!fine.contains_location(&coarse));
    }

    #[test]
    fn unspecified_contains_everything() {
        let anywhere = NodeLocation::from_lat_lon(28.614, 77.209, 7); // New Delhi
        assert!(NodeLocation::UNSPECIFIED.contains_location(&anywhere));
    }

    // --- From traits ---

    #[test]
    fn from_f32_tuple_roundtrips_approximately() {
        let (lat, lon) = (-33.868f32, 151.209f32); // Sydney
        let loc = NodeLocation::from((lat, lon));
        let (out_lat, out_lon): (f32, f32) = loc.into();
        assert!((out_lat - lat).abs() < 0.001, "lat drift={}", out_lat - lat);
        assert!((out_lon - lon).abs() < 0.001, "lon drift={}", out_lon - lon);
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
