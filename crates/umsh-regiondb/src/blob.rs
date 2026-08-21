//! The compiled geometry encoding.
//!
//! One blob holds one connected polygon component: an exterior ring and its
//! holes, as 1e-6-degree integer coordinates, delta-encoded and zigzag-varint
//! packed, with ring closure implicit.
//!
//! Working in fixed-point integers is what makes the boundary rule exact. A
//! point on a boundary counts as inside, everywhere, and deciding that with
//! floating-point coordinates would mean choosing an epsilon and hoping three
//! implementations chose the same one.

/// Version of the blob layout this reader understands.
pub const GEOMETRY_FORMAT_VERSION: u8 = 1;

/// Coordinate units per degree.
pub const COORD_SCALE: f64 = 1_000_000.0;

/// The role a ring plays in its polygon.
pub const RING_EXTERIOR: u8 = 0;
/// A hole cut out of the exterior.
pub const RING_HOLE: u8 = 1;

/// A malformed or unsupported geometry blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeometryError {
    /// The blob was empty.
    Empty,
    /// The blob declares a version this reader does not implement.
    UnsupportedVersion(u8),
    /// The blob ended in the middle of a value.
    Truncated,
    /// A varint ran past 64 bits.
    VarintTooLong,
    /// Bytes remained after the last ring.
    TrailingBytes,
    /// The first ring was not an exterior.
    MissingExterior,
}

impl core::fmt::Display for GeometryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(formatter, "empty geometry blob"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported geometry format version {version}")
            }
            Self::Truncated => write!(formatter, "truncated geometry blob"),
            Self::VarintTooLong => write!(formatter, "varint too long"),
            Self::TrailingBytes => write!(formatter, "trailing bytes after geometry blob"),
            Self::MissingExterior => write!(formatter, "geometry part has no exterior ring"),
        }
    }
}

impl std::error::Error for GeometryError {}

/// One closed ring, without its repeated closing vertex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ring {
    /// [`RING_EXTERIOR`] or [`RING_HOLE`].
    pub role: u8,
    /// Vertices as `(longitude, latitude)` in 1e-6 degrees.
    pub points: Vec<(i32, i32)>,
}

/// Quantize a degree value onto the storage grid, rounding half away from zero.
pub fn to_e6(degrees: f64) -> i32 {
    let scaled = degrees * COORD_SCALE;
    let rounded = if scaled >= 0.0 {
        (scaled + 0.5).floor()
    } else {
        -((-scaled + 0.5).floor())
    };
    rounded.clamp(i32::MIN as f64, i32::MAX as f64) as i32
}

/// Convert a stored coordinate back to degrees.
pub fn from_e6(value: i32) -> f64 {
    f64::from(value) / COORD_SCALE
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, GeometryError> {
        let byte = *self.data.get(self.offset).ok_or(GeometryError::Truncated)?;
        self.offset += 1;
        Ok(byte)
    }

    fn varint(&mut self) -> Result<u64, GeometryError> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            result |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift > 63 {
                return Err(GeometryError::VarintTooLong);
            }
        }
    }

    fn zigzag(&mut self) -> Result<i64, GeometryError> {
        let raw = self.varint()?;
        Ok(((raw >> 1) as i64) ^ -((raw & 1) as i64))
    }
}

/// Decode one polygon component.
pub fn decode(data: &[u8]) -> Result<Vec<Ring>, GeometryError> {
    if data.is_empty() {
        return Err(GeometryError::Empty);
    }
    let version = data[0];
    if version != GEOMETRY_FORMAT_VERSION {
        return Err(GeometryError::UnsupportedVersion(version));
    }

    let mut reader = Reader { data, offset: 1 };
    let ring_count = reader.varint()?;
    let mut rings = Vec::with_capacity(ring_count as usize);
    for index in 0..ring_count {
        let role = reader.byte()?;
        if index == 0 && role != RING_EXTERIOR {
            return Err(GeometryError::MissingExterior);
        }
        let point_count = reader.varint()?;
        let mut points = Vec::with_capacity(point_count as usize);
        let mut longitude: i64 = 0;
        let mut latitude: i64 = 0;
        for _ in 0..point_count {
            longitude += reader.zigzag()?;
            latitude += reader.zigzag()?;
            points.push((longitude as i32, latitude as i32));
        }
        rings.push(Ring { role, points });
    }
    if reader.offset != data.len() {
        return Err(GeometryError::TrailingBytes);
    }
    Ok(rings)
}

/// Exact integer point-in-polygon, boundary inclusive.
///
/// A point exactly on a boundary is inside. Two abutting regions therefore both
/// claim their shared edge, which costs an operator one extra region in a list
/// they are reviewing anyway; a gap between them would leave a position with no
/// region at all.
pub fn point_in_rings(rings: &[Ring], longitude_e6: i32, latitude_e6: i32) -> bool {
    let mut exterior = None;
    for ring in rings {
        if on_ring(ring, longitude_e6, latitude_e6) {
            return true;
        }
        if ring.role == RING_EXTERIOR && exterior.is_none() {
            exterior = Some(ring);
        }
    }

    let Some(exterior) = exterior else {
        return false;
    };
    if !strictly_inside(exterior, longitude_e6, latitude_e6) {
        return false;
    }
    !rings
        .iter()
        .filter(|ring| ring.role == RING_HOLE)
        .any(|hole| strictly_inside(hole, longitude_e6, latitude_e6))
}

fn on_ring(ring: &Ring, x: i32, y: i32) -> bool {
    let points = &ring.points;
    let x = i64::from(x);
    let y = i64::from(y);
    for index in 0..points.len() {
        let (x1, y1) = points[index];
        let (x2, y2) = points[(index + 1) % points.len()];
        let (x1, y1, x2, y2) = (i64::from(x1), i64::from(y1), i64::from(x2), i64::from(y2));
        if (x2 - x1) * (y - y1) - (y2 - y1) * (x - x1) != 0 {
            continue;
        }
        if x1.min(x2) <= x && x <= x1.max(x2) && y1.min(y2) <= y && y <= y1.max(y2) {
            return true;
        }
    }
    false
}

/// Crossing-number test with a half-open rule on each edge's vertical span, so
/// that a ray through a vertex counts once rather than twice or not at all.
fn strictly_inside(ring: &Ring, x: i32, y: i32) -> bool {
    let points = &ring.points;
    let x = i64::from(x);
    let y = i64::from(y);
    let mut inside = false;
    for index in 0..points.len() {
        let (x1, y1) = points[index];
        let (x2, y2) = points[(index + 1) % points.len()];
        let (x1, y1, x2, y2) = (i64::from(x1), i64::from(y1), i64::from(x2), i64::from(y2));
        if (y1 > y) != (y2 > y) {
            let side = (x2 - x1) * (y - y1) - (y2 - y1) * (x - x1);
            if side != 0 && (side > 0) == (y2 > y1) {
                inside = !inside;
            }
        }
    }
    inside
}
