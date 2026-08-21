//! Reader and lookup for the UMSH geographic region database.
//!
//! A `.regiondb` answers one question: given a position, which UMSH regions
//! should a repeater there normally be configured to accept? All of the hard
//! geography — nearest-airport partitions, commercial-service classification,
//! metropolitan boundaries, administrative boundaries, border expansion,
//! manual corrections — happens in the build, in
//! `tools/regiondb-build/`. Nothing in this crate knows how any of it was
//! derived, and the radio knows even less: it is handed ordinary region
//! strings through the existing repeater configuration path.
//!
//! ```no_run
//! # fn main() -> Result<(), umsh_regiondb::RegionDbError> {
//! use umsh_regiondb::RegionDb;
//!
//! let database = RegionDb::open("world.regiondb")?;
//! let result = database.lookup_codes(42.1946, -122.7095)?;
//! for region in &result.radio_regions {
//!     println!("{} {}", region.name, region.code);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The file itself is an ordinary SQLite database, and every implementation
//! that reads one — this crate, the Python builder, and the browser viewer —
//! must return identical results for identical positions. That is not left to
//! good intentions: `regions/tests/conformance.json` is replayed by all of
//! them, and the geometry codec and grid arithmetic here are written to match
//! their Python counterparts operation for operation.

#![deny(missing_docs)]

pub mod blob;
pub mod morton;

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use umsh_core::RegionCode;

pub use blob::GeometryError;
pub use morton::MortonError;

/// The database format this crate implements.
pub const FORMAT_VERSION: i64 = 1;

/// Geometry role: the region before expansion.
const ROLE_CORE: i64 = 0;
/// Geometry role: the region a lookup actually matches against.
const ROLE_EFFECTIVE: i64 = 1;

/// Anything that can go wrong opening or querying a region database.
#[derive(Debug)]
pub enum RegionDbError {
    /// The underlying SQLite call failed.
    Sqlite(rusqlite::Error),
    /// The file declares a format version this crate does not implement.
    UnsupportedFormat {
        /// Version the file claims.
        found: i64,
        /// Highest version this crate understands.
        supported: i64,
    },
    /// The file is not a region database at all.
    NotARegionDatabase,
    /// A geometry blob could not be decoded.
    Geometry(GeometryError),
    /// A position could not be placed on the lookup grid.
    Position(MortonError),
}

impl core::fmt::Display for RegionDbError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "region database error: {error}"),
            Self::UnsupportedFormat { found, supported } => write!(
                formatter,
                "region database declares format version {found}; this build understands \
                 up to {supported}"
            ),
            Self::NotARegionDatabase => write!(formatter, "file is not a region database"),
            Self::Geometry(error) => write!(formatter, "region geometry: {error}"),
            Self::Position(error) => write!(formatter, "lookup position: {error}"),
        }
    }
}

impl std::error::Error for RegionDbError {}

impl From<rusqlite::Error> for RegionDbError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<GeometryError> for RegionDbError {
    fn from(error: GeometryError) -> Self {
        Self::Geometry(error)
    }
}

impl From<MortonError> for RegionDbError {
    fn from(error: MortonError) -> Self {
        Self::Position(error)
    }
}

/// Whether a position falls in a region's own area or only in its expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Membership {
    /// Inside the region proper.
    Core,
    /// Inside only the outward buffer that lets a repeater near a border serve
    /// both sides.
    Expanded,
}

/// One semantic region covering a position.
#[derive(Clone, Debug, PartialEq)]
pub struct RegionMatch {
    /// Database row id.
    pub region_id: u32,
    /// Namespaced identifier, such as `iata-airport:SFO`.
    pub region_key: String,
    /// Namespace alone. Tooling only; never transmitted.
    pub namespace: String,
    /// Code within the namespace.
    pub code: String,
    /// Human-readable name.
    pub display_name: String,
    /// The string a radio is configured with.
    pub radio_name: String,
    /// Canonical UMSH region code for [`Self::radio_name`].
    pub wire_code: RegionCode,
    /// Which layer produced this region.
    pub kind: String,
    /// Presentation order relative to other matches.
    pub priority: i64,
    /// Core or expanded.
    pub membership: Membership,
    /// Position of the generating site, for the layers that have one.
    pub site: Option<(f64, f64)>,
    /// Preference order for the suggested default region, if eligible.
    pub default_rank: Option<i64>,
}

/// A region as the radio sees it: a name and its 2-byte code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RadioRegion {
    /// The configured region string.
    pub name: String,
    /// Its canonical code.
    pub code: RegionCode,
}

/// The result of a lookup.
#[derive(Clone, Debug, PartialEq)]
pub struct RegionLookup {
    /// Latitude that was looked up.
    pub latitude: f64,
    /// Longitude that was looked up.
    pub longitude: f64,
    /// Every semantic match, in presentation order. Empty unless the lookup
    /// asked for detail.
    pub matches: Vec<RegionMatch>,
    /// The deduplicated list suitable for a repeater's region filter.
    pub radio_regions: Vec<RadioRegion>,
    /// A narrow region suggested for the packet default tag, if any applies.
    pub suggested_default_region: Option<RadioRegion>,
    /// The data release this answer came from.
    pub dataset_version: String,
}

#[derive(Clone, Debug)]
struct RegionRow {
    region_id: u32,
    region_key: String,
    namespace: String,
    code: String,
    display_name: String,
    radio_name: String,
    wire_code: RegionCode,
    kind: String,
    priority: i64,
    default_rank: Option<i64>,
    site: Option<(f64, f64)>,
}

/// An opened region database.
pub struct RegionDb {
    connection: Connection,
    regions: HashMap<u32, RegionRow>,
    with_core_parts: HashSet<u32>,
    metadata: HashMap<String, String>,
    format_version: i64,
}

impl RegionDb {
    /// Open a database read-only.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RegionDbError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, RegionDbError> {
        let format_version: i64 =
            connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if format_version < 1 {
            return Err(RegionDbError::NotARegionDatabase);
        }
        if format_version > FORMAT_VERSION {
            return Err(RegionDbError::UnsupportedFormat {
                found: format_version,
                supported: FORMAT_VERSION,
            });
        }

        let metadata = connection
            .prepare("SELECT key, value FROM metadata")?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<HashMap<_, _>, _>>()?;

        let regions = connection
            .prepare(
                "SELECT id, region_key, namespace, code, display_name, radio_name, wire_code, \
                 kind, priority, default_rank, site_lon, site_lat FROM regions",
            )?
            .query_map([], |row| {
                let longitude: Option<f64> = row.get(10)?;
                let latitude: Option<f64> = row.get(11)?;
                Ok(RegionRow {
                    region_id: row.get::<_, i64>(0)? as u32,
                    region_key: row.get(1)?,
                    namespace: row.get(2)?,
                    code: row.get(3)?,
                    display_name: row.get(4)?,
                    radio_name: row.get(5)?,
                    wire_code: RegionCode::from_u16(row.get::<_, i64>(6)? as u16),
                    kind: row.get(7)?,
                    priority: row.get(8)?,
                    default_rank: row.get(9)?,
                    site: longitude.zip(latitude),
                })
            })?
            .map(|row| row.map(|row| (row.region_id, row)))
            .collect::<Result<HashMap<_, _>, _>>()?;

        // A region with no stored core parts was never expanded, so its
        // effective geometry is its core and the build did not write it twice.
        let with_core_parts = connection
            .prepare("SELECT DISTINCT region_id FROM geometry_parts WHERE role = ?1")?
            .query_map([ROLE_CORE], |row| Ok(row.get::<_, i64>(0)? as u32))?
            .collect::<Result<HashSet<_>, _>>()?;

        Ok(Self {
            connection,
            regions,
            with_core_parts,
            metadata,
            format_version,
        })
    }

    /// The database format version.
    pub fn format_version(&self) -> i64 {
        self.format_version
    }

    /// The geographic data release, such as `2026.08.1`.
    pub fn dataset_version(&self) -> &str {
        self.metadata
            .get("dataset_version")
            .map(String::as_str)
            .unwrap_or("unknown")
    }

    /// Raw metadata, including source attribution and the content hash.
    pub fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    /// How many regions the database holds.
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Look up a position, returning only what a repeater needs.
    pub fn lookup_codes(
        &self,
        latitude: f64,
        longitude: f64,
    ) -> Result<RegionLookup, RegionDbError> {
        self.lookup(latitude, longitude, false)
    }

    /// Look up a position, keeping every semantic match for display.
    pub fn lookup_detailed(
        &self,
        latitude: f64,
        longitude: f64,
    ) -> Result<RegionLookup, RegionDbError> {
        self.lookup(latitude, longitude, true)
    }

    fn lookup(
        &self,
        latitude: f64,
        longitude: f64,
        detailed: bool,
    ) -> Result<RegionLookup, RegionDbError> {
        let members = self.effective_members(latitude, longitude)?;
        let matches = self.build_matches(&members, latitude, longitude)?;

        let radio_regions = radio_regions(&matches);
        let suggested = suggested_default(&matches, latitude, longitude);
        Ok(RegionLookup {
            latitude,
            longitude,
            matches: if detailed { matches } else { Vec::new() },
            radio_regions,
            suggested_default_region: suggested,
            dataset_version: self.dataset_version().to_owned(),
        })
    }

    /// Answer using the exact polygons alone, ignoring the lookup cache.
    ///
    /// The cache is an optimization over the same geometry, never a second
    /// source of truth, and this is how the build proves it.
    pub fn lookup_exhaustive(
        &self,
        latitude: f64,
        longitude: f64,
    ) -> Result<RegionLookup, RegionDbError> {
        let (longitude_e6, latitude_e6) = self.quantize(latitude, longitude)?;
        let mut members: Vec<u32> = Vec::new();
        for region_id in self.regions.keys().copied() {
            if self.covers(region_id, ROLE_EFFECTIVE, longitude_e6, latitude_e6)? {
                members.push(region_id);
            }
        }
        members.sort_unstable();

        let matches = self.build_matches(&members, latitude, longitude)?;
        let radio_regions = radio_regions(&matches);
        let suggested = suggested_default(&matches, latitude, longitude);
        Ok(RegionLookup {
            latitude,
            longitude,
            matches,
            radio_regions,
            suggested_default_region: suggested,
            dataset_version: self.dataset_version().to_owned(),
        })
    }

    fn build_matches(
        &self,
        members: &[u32],
        latitude: f64,
        longitude: f64,
    ) -> Result<Vec<RegionMatch>, RegionDbError> {
        let (longitude_e6, latitude_e6) = self.quantize(latitude, longitude)?;
        let mut matches = Vec::with_capacity(members.len());
        for region_id in members {
            let Some(row) = self.regions.get(region_id) else {
                continue;
            };
            let membership = if !self.with_core_parts.contains(region_id)
                || self.covers(*region_id, ROLE_CORE, longitude_e6, latitude_e6)?
            {
                Membership::Core
            } else {
                Membership::Expanded
            };
            matches.push(RegionMatch {
                region_id: row.region_id,
                region_key: row.region_key.clone(),
                namespace: row.namespace.clone(),
                code: row.code.clone(),
                display_name: row.display_name.clone(),
                radio_name: row.radio_name.clone(),
                wire_code: row.wire_code,
                kind: row.kind.clone(),
                priority: row.priority,
                membership,
                site: row.site,
                default_rank: row.default_rank,
            });
        }
        matches.sort_by(|first, second| {
            first
                .priority
                .cmp(&second.priority)
                .then(first.membership.cmp(&second.membership))
                .then_with(|| first.region_key.cmp(&second.region_key))
        });
        Ok(matches)
    }

    fn quantize(&self, latitude: f64, longitude: f64) -> Result<(i32, i32), RegionDbError> {
        Ok((
            blob::to_e6(morton::normalize_longitude(longitude)?),
            blob::to_e6(morton::check_latitude(latitude)?),
        ))
    }

    /// The cached path: one indexed range query, then whichever few regions the
    /// build could not decide for that cell.
    fn effective_members(&self, latitude: f64, longitude: f64) -> Result<Vec<u32>, RegionDbError> {
        let key = morton::key(latitude, longitude)?;
        let mut statement = self.connection.prepare_cached(
            "SELECT end_key, base_set_id, candidate_region_ids FROM lookup_ranges \
             WHERE start_key <= ?1 ORDER BY start_key DESC LIMIT 1",
        )?;
        let row = statement
            .query_row([i64::from(key)], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            })
            .ok();

        let Some((end_key, base_set_id, candidates)) = row else {
            return Ok(Vec::new());
        };
        if i64::from(key) > end_key {
            return Ok(Vec::new());
        }

        let payload: Option<Vec<u8>> = self
            .connection
            .prepare_cached("SELECT region_ids FROM region_sets WHERE id = ?1")?
            .query_row([base_set_id], |row| row.get(0))
            .ok();
        let mut members: Vec<u32> = payload
            .map(|data| decode_region_ids(&data))
            .unwrap_or_default();

        if let Some(candidates) = candidates {
            let (longitude_e6, latitude_e6) = self.quantize(latitude, longitude)?;
            for region_id in decode_region_ids(&candidates) {
                if self.covers(region_id, ROLE_EFFECTIVE, longitude_e6, latitude_e6)? {
                    members.push(region_id);
                }
            }
        }
        members.sort_unstable();
        members.dedup();
        Ok(members)
    }

    fn covers(
        &self,
        region_id: u32,
        role: i64,
        longitude_e6: i32,
        latitude_e6: i32,
    ) -> Result<bool, RegionDbError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT geometry, min_lon, min_lat, max_lon, max_lat FROM geometry_parts \
             WHERE region_id = ?1 AND role = ?2 ORDER BY id",
        )?;
        let mut rows = statement.query((i64::from(region_id), role))?;
        while let Some(row) = rows.next()? {
            let min_lon: f64 = row.get(1)?;
            let min_lat: f64 = row.get(2)?;
            let max_lon: f64 = row.get(3)?;
            let max_lat: f64 = row.get(4)?;
            // The stored bounds are the part's own quantized extent, so a point
            // outside them cannot lie on its boundary either.
            if longitude_e6 < blob::to_e6(min_lon)
                || longitude_e6 > blob::to_e6(max_lon)
                || latitude_e6 < blob::to_e6(min_lat)
                || latitude_e6 > blob::to_e6(max_lat)
            {
                continue;
            }
            let payload: Vec<u8> = row.get(0)?;
            if blob::point_in_rings(&blob::decode(&payload)?, longitude_e6, latitude_e6) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Decode a set of region ids stored as varint gaps.
fn decode_region_ids(data: &[u8]) -> Vec<u32> {
    let mut identifiers = Vec::new();
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut current: u64 = 0;
    for byte in data {
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 != 0 {
            shift += 7;
            continue;
        }
        current += value;
        identifiers.push(current as u32);
        value = 0;
        shift = 0;
    }
    identifiers
}

/// Collapse semantic matches onto the list a radio would be given.
///
/// Two matches that encode identically are one region as far as the radio is
/// concerned — the airport and metro senses of `SFO`, say — so the first in
/// policy order takes the slot.
fn radio_regions(matches: &[RegionMatch]) -> Vec<RadioRegion> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in matches {
        if seen.insert(entry.wire_code) {
            out.push(RadioRegion {
                name: entry.radio_name.clone(),
                code: entry.wire_code,
            });
        }
    }
    out
}

/// Choose the region to suggest as the packet default.
///
/// Only the IATA-derived layers are eligible, and a core match beats an
/// expanded one from the same layer. Country and state regions are deliberately
/// never chosen: they are large enough that tagging a flood with one would
/// broaden its scope far past what an operator setting up a repeater intends.
fn suggested_default(
    matches: &[RegionMatch],
    latitude: f64,
    longitude: f64,
) -> Option<RadioRegion> {
    matches
        .iter()
        .filter(|entry| entry.default_rank.is_some())
        .min_by(|first, second| {
            first
                .default_rank
                .cmp(&second.default_rank)
                .then(first.membership.cmp(&second.membership))
                .then_with(|| {
                    site_distance(first, latitude, longitude)
                        .total_cmp(&site_distance(second, latitude, longitude))
                })
                .then_with(|| first.region_key.cmp(&second.region_key))
        })
        .map(|entry| RadioRegion {
            name: entry.radio_name.clone(),
            code: entry.wire_code,
        })
}

/// Great-circle distance to a match's generating site, for breaking ties among
/// overlapping expansion buffers.
///
/// A sphere is enough here: this only ever orders two candidates that are both
/// within a hundred kilometers, and the ellipsoidal correction is far too small
/// to change which is nearer.
fn site_distance(entry: &RegionMatch, latitude: f64, longitude: f64) -> f64 {
    let Some((site_longitude, site_latitude)) = entry.site else {
        return f64::INFINITY;
    };
    let (lat1, lat2) = (latitude.to_radians(), site_latitude.to_radians());
    let delta_lat = lat2 - lat1;
    let delta_lon = (site_longitude - longitude).to_radians();
    let haversine =
        (delta_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
    2.0 * haversine.sqrt().asin() * 6_371_008.8
}
