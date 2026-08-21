//! Geographic region suggestions from a `.regiondb` database.
//!
//! The database proposes; it never writes to a radio. Everything here
//! produces values for the existing repeater-settings surfaces —
//! `regions` strings and a 2-octet `default_region` — and the editor's
//! own apply path remains the only thing that transmits.
//!
//! Region-list policy lives on this side of the boundary deliberately.
//! Whether a configured region "already matches" a suggestion is a
//! question about derived wire codes (`SJC`, `sjc`, and `0x7853` are one
//! region to a radio), and how much a position's uncertainty widens a
//! suggestion is geographic policy. Both must answer identically for
//! every caller, so neither is left to platform code.

use std::sync::{Arc, Mutex};

use umsh_core::RegionCode;
use umsh_node::location::NodeLocation;
use umsh_regiondb::{Membership, RegionDb, RegionDbError, RegionLookup, RegionMatch, sampling};

/// Widest positional uncertainty a proposal accepts, in meters.
///
/// Against 2 km expansion margins and 100 km airport radii, sampling the
/// corners of a coarser position returns dozens of "uncertain" regions —
/// noise dressed up as diligence. 25 km admits advert cells of three
/// bytes (≈ 9.8 km at the equator) and finer, and refuses one- and
/// two-byte cells (≈ 2,500 km and ≈ 156 km).
const MAX_PROPOSAL_UNCERTAINTY_M: f64 = 25_000.0;

/// Meters per degree of longitude at the equator, matching
/// [`crate::ulcp_location_cell_meters`].
const EQUATOR_METERS_PER_DEGREE: f64 = 111_320.0;

/// Anything that can go wrong opening or consulting a region database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileRegionError {
    /// The database file could not be opened or read.
    DatabaseUnavailable,
    /// The file is not a region database at all.
    NotARegionDatabase,
    /// The file declares a format version this build does not implement.
    UnsupportedFormat,
    /// The database needs SQLite's R-tree module and this build has none.
    MissingSpatialIndex,
    /// The database opened but its contents could not be decoded.
    Corrupt,
    /// The position is not a place: a non-finite or out-of-range
    /// coordinate, or an undecodable location cell.
    InvalidPosition,
    /// The position is real but too uncertain to propose from. The
    /// answer is a better source, not a wider guess.
    PositionTooCoarse,
    /// A configured region string or default-region code could not be
    /// read.
    InvalidRegionCode,
}

impl MobileRegionError {
    /// Stable localization key. Rust prose is never shown directly in
    /// the UI.
    pub const fn summary_key(self) -> &'static str {
        match self {
            Self::DatabaseUnavailable => "mobile.error.regiondb.unavailable",
            Self::NotARegionDatabase => "mobile.error.regiondb.not_a_region_database",
            Self::UnsupportedFormat => "mobile.error.regiondb.unsupported_format",
            Self::MissingSpatialIndex => "mobile.error.regiondb.missing_spatial_index",
            Self::Corrupt => "mobile.error.regiondb.corrupt",
            Self::InvalidPosition => "mobile.error.regiondb.invalid_position",
            Self::PositionTooCoarse => "mobile.error.regiondb.position_too_coarse",
            Self::InvalidRegionCode => "mobile.error.region_code.invalid",
        }
    }

    /// Redacted diagnostic code suitable for logs and support bundles.
    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::DatabaseUnavailable => "REGIONDB_UNAVAILABLE",
            Self::NotARegionDatabase => "REGIONDB_NOT_A_REGION_DATABASE",
            Self::UnsupportedFormat => "REGIONDB_UNSUPPORTED_FORMAT",
            Self::MissingSpatialIndex => "REGIONDB_MISSING_SPATIAL_INDEX",
            Self::Corrupt => "REGIONDB_CORRUPT",
            Self::InvalidPosition => "REGION_POSITION_INVALID",
            Self::PositionTooCoarse => "REGION_POSITION_TOO_COARSE",
            Self::InvalidRegionCode => "REGION_CODE_INVALID",
        }
    }
}

impl core::fmt::Display for MobileRegionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.diagnostic_code())
    }
}

impl std::error::Error for MobileRegionError {}

impl From<RegionDbError> for MobileRegionError {
    fn from(error: RegionDbError) -> Self {
        // Payloads are dropped deliberately: invalid input is not copied
        // into the error, preventing accidental disclosure through
        // diagnostics.
        match error {
            RegionDbError::Sqlite(_) => Self::DatabaseUnavailable,
            RegionDbError::NotARegionDatabase => Self::NotARegionDatabase,
            RegionDbError::UnsupportedFormat { .. } => Self::UnsupportedFormat,
            RegionDbError::MissingSpatialIndex => Self::MissingSpatialIndex,
            RegionDbError::Geometry(_) => Self::Corrupt,
            RegionDbError::Position(_) => Self::InvalidPosition,
        }
    }
}

/// Whether a position falls in a region's own area or only in its
/// expansion margin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileRegionMembership {
    /// The position is inside the region's core geometry.
    Core,
    /// Only the sampled expansion margin reaches the position.
    Expanded,
}

impl From<Membership> for MobileRegionMembership {
    fn from(membership: Membership) -> Self {
        match membership {
            Membership::Core => Self::Core,
            Membership::Expanded => Self::Expanded,
        }
    }
}

/// A place to propose regions for, with its honest uncertainty.
///
/// Positions come from sources of very different quality — a node's
/// advertised identity cell, a live GNSS fix, hand-entered coordinates —
/// and the proposal widens itself to match. At most one of
/// `location_bytes` and `accuracy_m` should be set; the cell wins when
/// both are.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileRegionPositionRecord {
    /// Latitude in degrees.
    pub latitude: f64,
    /// Longitude in degrees.
    pub longitude: f64,
    /// The encoded identity cell this position came from, verbatim. Its
    /// bounds are the uncertainty, and supersede `accuracy_m`.
    pub location_bytes: Option<Vec<u8>>,
    /// Horizontal uncertainty of a measured fix, in meters.
    pub accuracy_m: Option<f64>,
}

/// One semantic match from a lookup, mirroring the reader's
/// `RegionMatch`.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileRegionMatchRecord {
    /// Namespaced identity, such as `iata-airport:SFO`.
    pub region_key: String,
    /// The namespace half of the key.
    pub namespace: String,
    /// The string a radio is configured with.
    pub radio_name: String,
    /// The derived 2-octet wire code.
    pub wire_code: Vec<u8>,
    /// The layer that produced the match, such as `commercial_airport`.
    pub layer: String,
    /// Core geometry or expansion margin.
    pub membership: MobileRegionMembership,
    /// The region's site, for nearest-site layers.
    pub site_latitude: Option<f64>,
    /// See `site_latitude`.
    pub site_longitude: Option<f64>,
}

/// A region as a radio is configured with it: the string form and the
/// 2-octet code the string derives to.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileRegionRecord {
    /// The configuration string, such as `SFO` or `SF Bay Area`.
    pub name: String,
    /// The derived wire code, always two octets.
    pub code: Vec<u8>,
}

/// What the database says covers a position.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileRegionLookupRecord {
    /// The queried latitude, degrees.
    pub latitude: f64,
    /// The queried longitude, degrees.
    pub longitude: f64,
    /// Every semantic match, ordered by layer priority.
    pub matches: Vec<MobileRegionMatchRecord>,
    /// The deduplicated radio-facing list the matches produce.
    pub radio_regions: Vec<MobileRegionRecord>,
    /// The best default-tag candidate, when any layer offers one.
    pub suggested_default_region: Option<MobileRegionRecord>,
    /// The data release the answers came from, such as `2026.34.1`.
    pub dataset_version: String,
}

/// One way of applying a proposal: the complete resulting settings, not
/// a delta. The caller assigns both fields into the editor and thinks no
/// further.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileRegionOutcomeRecord {
    /// The resulting forwarding list, as region strings.
    pub regions: Vec<String>,
    /// The resulting default tag, as a 2-octet code.
    pub default_region: Option<Vec<u8>>,
    /// Whether applying this outcome changes the device at all. When
    /// false, the UI can say "already matches" instead of offering a
    /// write that does nothing.
    pub changes_anything: bool,
}

/// A location-derived region proposal, ready for the operator to accept
/// wholesale, take additively, or dismiss.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileRegionProposalRecord {
    /// The merged view across the position's uncertainty: every region
    /// any sample point hit, each match reported once with its best
    /// membership. `radio_regions` here is the suggested list both
    /// outcomes are built from.
    pub lookup: MobileRegionLookupRecord,
    /// Accept wholesale: regions and default tag become the suggestion,
    /// including a `None` default when the lookup suggests nothing.
    pub replace: MobileRegionOutcomeRecord,
    /// Accept additively: missing suggestions are appended, nothing is
    /// removed, and the suggested default tag is adopted only when the
    /// device has none.
    pub add_missing: MobileRegionOutcomeRecord,
    /// Suggested regions the device already forwards, by derived code.
    pub already_present: Vec<String>,
    /// Configured regions this position does not account for. Kept by
    /// `add_missing`, dropped by `replace`.
    pub not_suggested: Vec<String>,
    /// Suggested regions the position's samples do not agree on, as
    /// radio names matching entries in `lookup.radio_regions`. The
    /// position's uncertainty straddles these regions' boundaries.
    pub uncertain_regions: Vec<String>,
    /// Width of the position's uncertainty, in meters, for the UI to
    /// state. `None` for an exact position.
    pub cell_meters: Option<f64>,
}

/// An opened region database.
///
/// Read-only, and cheap to hold open for the life of the app. The lock
/// exists because the underlying SQLite connection is single-threaded,
/// not because anything here blocks for long: a worst-case lookup is
/// about a millisecond.
#[derive(uniffi::Object)]
pub struct MobileRegionDatabase {
    inner: Mutex<RegionDb>,
}

#[uniffi::export]
impl MobileRegionDatabase {
    /// Open the database at an absolute filesystem path, read-only.
    #[uniffi::constructor]
    pub fn open(path: String) -> Result<Arc<Self>, MobileRegionError> {
        if !std::path::Path::new(&path).is_absolute() {
            return Err(MobileRegionError::DatabaseUnavailable);
        }
        let db = RegionDb::open(&path)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(db),
        }))
    }

    /// The data release this database carries, such as `2026.34.1`.
    pub fn dataset_version(&self) -> String {
        self.locked(|db| db.dataset_version().to_owned())
    }

    /// The database format version.
    pub fn format_version(&self) -> u32 {
        self.locked(|db| db.format_version() as u32)
    }

    /// How many regions the database holds.
    pub fn region_count(&self) -> u32 {
        self.locked(|db| db.region_count() as u32)
    }

    /// Every region covering one exact position, with semantic detail.
    pub fn lookup(
        &self,
        latitude: f64,
        longitude: f64,
    ) -> Result<MobileRegionLookupRecord, MobileRegionError> {
        check_coordinates(latitude, longitude)?;
        let lookup = self.locked(|db| db.lookup_detailed(latitude, longitude))?;
        Ok(lookup_record(&lookup))
    }

    /// Propose a region configuration for a position, against what the
    /// device currently holds.
    ///
    /// The proposal samples the position's uncertainty — an identity
    /// cell's center and four corners, or a measured fix's center and
    /// the four cardinal points of its accuracy circle — and suggests
    /// every region any sample hit. A node whose position straddles a
    /// boundary should usually forward both sides, the same reasoning
    /// that gives the database its expansion margins; the non-unanimous
    /// regions are named so the operator can judge.
    pub fn propose(
        &self,
        position: MobileRegionPositionRecord,
        current_regions: Vec<String>,
        current_default_region: Option<Vec<u8>>,
    ) -> Result<MobileRegionProposalRecord, MobileRegionError> {
        check_coordinates(position.latitude, position.longitude)?;
        let plan = sample_points(&position)?;

        let current_codes = current_regions
            .iter()
            .map(|text| {
                text.parse::<RegionCode>()
                    .map_err(|_| MobileRegionError::InvalidRegionCode)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let current_default = current_default_region
            .as_deref()
            .map(|bytes| {
                let bytes: [u8; 2] = bytes
                    .try_into()
                    .map_err(|_| MobileRegionError::InvalidRegionCode)?;
                Ok::<_, MobileRegionError>(RegionCode::from_bytes(bytes))
            })
            .transpose()?;

        let lookups = self.locked(|db| {
            plan.points
                .iter()
                .map(|&(latitude, longitude)| db.lookup_detailed(latitude, longitude))
                .collect::<Result<Vec<_>, _>>()
        })?;

        // The merged view: every match any sample hit, once, with its
        // best membership — a core hit anywhere beats an expanded one.
        let mut merged: Vec<RegionMatch> = Vec::new();
        for lookup in &lookups {
            for candidate in &lookup.matches {
                match merged
                    .iter_mut()
                    .find(|held| held.region_key == candidate.region_key)
                {
                    Some(held) => held.membership = held.membership.min(candidate.membership),
                    None => merged.push(candidate.clone()),
                }
            }
        }
        merged.sort_by(|a, b| {
            (a.priority, a.membership, &a.region_key).cmp(&(
                b.priority,
                b.membership,
                &b.region_key,
            ))
        });

        // The radio-facing suggestion: first entry per distinct wire
        // code, mirroring the reader's own deduplication.
        let mut suggested: Vec<MobileRegionRecord> = Vec::new();
        for candidate in &merged {
            if !suggested
                .iter()
                .any(|held| held.code == candidate.wire_code.to_bytes())
            {
                suggested.push(MobileRegionRecord {
                    name: candidate.radio_name.clone(),
                    code: candidate.wire_code.to_bytes().to_vec(),
                });
            }
        }

        // A suggestion the samples disagree on straddles the position's
        // uncertainty. The center-only lookup is index zero.
        let uncertain_regions = suggested
            .iter()
            .filter(|region| {
                !lookups.iter().all(|lookup| {
                    lookup
                        .radio_regions
                        .iter()
                        .any(|held| held.code.to_bytes().as_slice() == region.code.as_slice())
                })
            })
            .map(|region| region.name.clone())
            .collect();

        let suggested_default =
            lookups[0]
                .suggested_default_region
                .as_ref()
                .map(|region| MobileRegionRecord {
                    name: region.name.clone(),
                    code: region.code.to_bytes().to_vec(),
                });

        let already_present: Vec<String> = suggested
            .iter()
            .filter(|region| {
                current_codes
                    .iter()
                    .any(|held| held.to_bytes().as_slice() == region.code.as_slice())
            })
            .map(|region| region.name.clone())
            .collect();
        let not_suggested: Vec<String> = current_regions
            .iter()
            .zip(&current_codes)
            .filter(|(_, code)| {
                !suggested
                    .iter()
                    .any(|region| region.code.as_slice() == code.to_bytes().as_slice())
            })
            .map(|(text, _)| text.clone())
            .collect();

        let suggested_default_code = suggested_default
            .as_ref()
            .map(|region| RegionCode::from_bytes([region.code[0], region.code[1]]));
        let suggested_codes: Vec<[u8; 2]> = suggested
            .iter()
            .map(|region| [region.code[0], region.code[1]])
            .collect();
        let current_code_bytes: Vec<[u8; 2]> =
            current_codes.iter().map(|code| code.to_bytes()).collect();
        let replace = MobileRegionOutcomeRecord {
            regions: suggested.iter().map(|region| region.name.clone()).collect(),
            default_region: suggested_default.as_ref().map(|region| region.code.clone()),
            changes_anything: suggested_codes != current_code_bytes
                || suggested_default_code != current_default,
        };

        let missing: Vec<&MobileRegionRecord> = suggested
            .iter()
            .filter(|region| {
                !current_codes
                    .iter()
                    .any(|held| held.to_bytes().as_slice() == region.code.as_slice())
            })
            .collect();
        let adopts_default = current_default.is_none() && suggested_default_code.is_some();
        let add_missing = MobileRegionOutcomeRecord {
            regions: current_regions
                .iter()
                .cloned()
                .chain(missing.iter().map(|region| region.name.clone()))
                .collect(),
            default_region: if adopts_default {
                suggested_default.as_ref().map(|region| region.code.clone())
            } else {
                current_default_region.clone()
            },
            changes_anything: !missing.is_empty() || adopts_default,
        };

        Ok(MobileRegionProposalRecord {
            lookup: MobileRegionLookupRecord {
                latitude: position.latitude,
                longitude: position.longitude,
                matches: merged.iter().map(match_record).collect(),
                radio_regions: suggested,
                suggested_default_region: suggested_default,
                dataset_version: lookups[0].dataset_version.clone(),
            },
            replace,
            add_missing,
            already_present,
            not_suggested,
            uncertain_regions,
            cell_meters: plan.width_m,
        })
    }
}

impl MobileRegionDatabase {
    fn locked<T>(&self, operation: impl FnOnce(&RegionDb) -> T) -> T {
        // A poisoned lock means a panic mid-read of a read-only
        // database; the data cannot be inconsistent, so continue.
        let guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        operation(&guard)
    }
}

fn check_coordinates(latitude: f64, longitude: f64) -> Result<(), MobileRegionError> {
    if !latitude.is_finite()
        || latitude.abs() > 90.0
        || !longitude.is_finite()
        || longitude.abs() > 180.0
    {
        return Err(MobileRegionError::InvalidPosition);
    }
    Ok(())
}

/// The points a proposal tests, the position itself first.
struct SamplePlan {
    points: Vec<(f64, f64)>,
    /// The stated width of the uncertainty, for the UI. `None` when the
    /// position is exact.
    width_m: Option<f64>,
}

fn sample_points(position: &MobileRegionPositionRecord) -> Result<SamplePlan, MobileRegionError> {
    let center = (position.latitude, position.longitude);

    if let Some(bytes) = position.location_bytes.as_deref() {
        if bytes.is_empty() || bytes.len() > 7 {
            return Err(MobileRegionError::InvalidPosition);
        }
        // Equatorial cell width, matching `ulcp_location_cell_meters`.
        let cell_meters = 360.0 * EQUATOR_METERS_PER_DEGREE / 16f64.powi(bytes.len() as i32);
        if cell_meters > MAX_PROPOSAL_UNCERTAINTY_M {
            return Err(MobileRegionError::PositionTooCoarse);
        }
        let location = NodeLocation::from_bytes(bytes);
        let ((lat_lo, lon_lo), (lat_hi, lon_hi)) = location.bounds();
        let (lat_lo, lon_lo, lat_hi, lon_hi) =
            (lat_lo as f64, lon_lo as f64, lat_hi as f64, lon_hi as f64);
        return Ok(SamplePlan {
            points: vec![
                center,
                (lat_lo, lon_lo),
                (lat_lo, lon_hi),
                (lat_hi, lon_lo),
                (lat_hi, lon_hi),
            ],
            width_m: Some(cell_meters),
        });
    }

    if let Some(accuracy_m) = position.accuracy_m {
        if !accuracy_m.is_finite() || accuracy_m < 0.0 {
            return Err(MobileRegionError::InvalidPosition);
        }
        if accuracy_m > MAX_PROPOSAL_UNCERTAINTY_M {
            return Err(MobileRegionError::PositionTooCoarse);
        }
        if accuracy_m > 0.0 {
            // The cardinal points of the accuracy circle, not a bounding
            // box: the box's corners lie √2 beyond the stated
            // uncertainty and would widen the proposal past what was
            // measured.
            let mut samples = vec![center];
            for bearing in [0.0, 90.0, 180.0, 270.0] {
                samples.push(sampling::destination(
                    position.latitude,
                    position.longitude,
                    bearing,
                    accuracy_m,
                ));
            }
            return Ok(SamplePlan {
                points: samples,
                width_m: Some(accuracy_m * 2.0),
            });
        }
    }

    Ok(SamplePlan {
        points: vec![center],
        width_m: None,
    })
}

fn lookup_record(lookup: &RegionLookup) -> MobileRegionLookupRecord {
    MobileRegionLookupRecord {
        latitude: lookup.latitude,
        longitude: lookup.longitude,
        matches: lookup.matches.iter().map(match_record).collect(),
        radio_regions: lookup
            .radio_regions
            .iter()
            .map(|region| MobileRegionRecord {
                name: region.name.clone(),
                code: region.code.to_bytes().to_vec(),
            })
            .collect(),
        suggested_default_region: lookup.suggested_default_region.as_ref().map(|region| {
            MobileRegionRecord {
                name: region.name.clone(),
                code: region.code.to_bytes().to_vec(),
            }
        }),
        dataset_version: lookup.dataset_version.clone(),
    }
}

fn match_record(entry: &RegionMatch) -> MobileRegionMatchRecord {
    MobileRegionMatchRecord {
        region_key: entry.region_key.clone(),
        namespace: entry.namespace.clone(),
        radio_name: entry.radio_name.clone(),
        wire_code: entry.wire_code.to_bytes().to_vec(),
        layer: entry.layer.clone(),
        membership: entry.membership.into(),
        site_latitude: entry.site.map(|(_, latitude)| latitude),
        site_longitude: entry.site.map(|(longitude, _)| longitude),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Arc<MobileRegionDatabase> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../regions/tests/fixture/fixture.regiondb"
        );
        MobileRegionDatabase::open(path.to_owned()).expect("fixture opens")
    }

    fn exact(latitude: f64, longitude: f64) -> MobileRegionPositionRecord {
        MobileRegionPositionRecord {
            latitude,
            longitude,
            location_bytes: None,
            accuracy_m: None,
        }
    }

    // San Carlos Airport: the regression the fixture exists for.
    const SAN_CARLOS: (f64, f64) = (37.5119, -122.2495);
    // SFO terminal area.
    const SFO: (f64, f64) = (37.6189, -122.3750);

    #[test]
    fn opens_and_describes_the_fixture() {
        let db = fixture();
        assert_eq!(db.dataset_version(), "fixture-1");
        assert_eq!(db.format_version(), 1);
        assert_eq!(db.region_count(), 12);
    }

    #[test]
    fn relative_path_is_refused() {
        assert_eq!(
            MobileRegionDatabase::open("fixture.regiondb".to_owned()).err(),
            Some(MobileRegionError::DatabaseUnavailable)
        );
    }

    #[test]
    fn lookup_matches_the_reference_answers() {
        let lookup = fixture().lookup(SAN_CARLOS.0, SAN_CARLOS.1).unwrap();
        let keys: Vec<&str> = lookup
            .matches
            .iter()
            .map(|entry| entry.region_key.as_str())
            .collect();
        assert!(keys.contains(&"iata-location:SQL"));
        assert!(keys.contains(&"iata-airport:SFO"));
        assert!(!keys.contains(&"iata-airport:SQL"));
        assert_eq!(
            lookup
                .suggested_default_region
                .as_ref()
                .map(|r| r.name.as_str()),
            Some("XSF")
        );
    }

    #[test]
    fn exact_position_proposes_the_lookup_verbatim() {
        let db = fixture();
        let proposal = db.propose(exact(SFO.0, SFO.1), Vec::new(), None).unwrap();
        let direct = db.lookup(SFO.0, SFO.1).unwrap();
        assert_eq!(proposal.lookup.radio_regions, direct.radio_regions);
        assert!(proposal.uncertain_regions.is_empty());
        assert_eq!(proposal.cell_meters, None);
        assert_eq!(
            proposal.replace.regions,
            direct
                .radio_regions
                .iter()
                .map(|region| region.name.clone())
                .collect::<Vec<_>>()
        );
        assert!(proposal.replace.changes_anything);
        assert_eq!(proposal.replace, proposal.add_missing);
    }

    #[test]
    fn comparison_is_by_derived_wire_code() {
        // "sfo" and the hex spelling of XSF name the same regions the
        // suggestion does, however they are written.
        let proposal = fixture()
            .propose(
                exact(SFO.0, SFO.1),
                vec!["sfo".to_owned(), "0x98FE".to_owned()],
                None,
            )
            .unwrap();
        assert_eq!(proposal.already_present, vec!["SFO", "XSF"]);
        assert!(proposal.not_suggested.is_empty());
        // Add-missing keeps the operator's spellings and appends only
        // what is genuinely absent.
        assert_eq!(proposal.add_missing.regions[..2], ["sfo", "0x98FE"]);
        assert!(!proposal.add_missing.regions.contains(&"SFO".to_owned()));
        assert!(proposal.add_missing.regions.contains(&"US".to_owned()));
        assert!(proposal.add_missing.changes_anything);
    }

    #[test]
    fn foreign_regions_are_kept_by_add_and_dropped_by_replace() {
        let proposal = fixture()
            .propose(exact(SFO.0, SFO.1), vec!["LAX".to_owned()], None)
            .unwrap();
        assert_eq!(proposal.not_suggested, vec!["LAX"]);
        assert!(proposal.add_missing.regions.contains(&"LAX".to_owned()));
        assert!(!proposal.replace.regions.contains(&"LAX".to_owned()));
    }

    #[test]
    fn default_tag_is_adopted_only_when_unset() {
        let db = fixture();
        let xsf = vec![0x98, 0xFE];
        let sfo = vec![0x77, 0xBF];

        let unset = db.propose(exact(SFO.0, SFO.1), Vec::new(), None).unwrap();
        assert_eq!(unset.add_missing.default_region, Some(xsf.clone()));
        assert_eq!(unset.replace.default_region, Some(xsf.clone()));

        let held = db
            .propose(
                exact(SFO.0, SFO.1),
                vec!["SFO".to_owned()],
                Some(sfo.clone()),
            )
            .unwrap();
        assert_eq!(held.add_missing.default_region, Some(sfo));
        assert_eq!(held.replace.default_region, Some(xsf));
    }

    #[test]
    fn matching_configuration_changes_nothing() {
        let db = fixture();
        let direct = db.lookup(SFO.0, SFO.1).unwrap();
        let current: Vec<String> = direct
            .radio_regions
            .iter()
            .map(|region| region.name.clone())
            .collect();
        let default = direct
            .suggested_default_region
            .as_ref()
            .map(|r| r.code.clone());
        let proposal = db.propose(exact(SFO.0, SFO.1), current, default).unwrap();
        assert!(!proposal.replace.changes_anything);
        assert!(!proposal.add_missing.changes_anything);
    }

    #[test]
    fn accuracy_circle_reaching_a_boundary_is_uncertain() {
        // At this point OAK answers and SFO does not, but a 20 km circle
        // reaches across their boundary: the southern and western samples
        // return SFO and lose OAK. Both airports join the suggestion and
        // both are uncertain — the honest answer near a bisector — while
        // the regions every sample agrees on stay certain.
        let position = MobileRegionPositionRecord {
            accuracy_m: Some(20_000.0),
            ..exact(37.70, -122.27)
        };
        let proposal = fixture().propose(position, Vec::new(), None).unwrap();
        let names: Vec<&str> = proposal
            .lookup
            .radio_regions
            .iter()
            .map(|region| region.name.as_str())
            .collect();
        assert!(names.contains(&"OAK"));
        assert!(names.contains(&"SFO"));
        assert!(proposal.uncertain_regions.contains(&"SFO".to_owned()));
        assert!(proposal.uncertain_regions.contains(&"OAK".to_owned()));
        assert!(!proposal.uncertain_regions.contains(&"XSF".to_owned()));
        assert!(!proposal.uncertain_regions.contains(&"US".to_owned()));
        assert_eq!(proposal.cell_meters, Some(40_000.0));
    }

    #[test]
    fn advert_cell_samples_its_corners() {
        let cell = NodeLocation::from_lat_lon(SAN_CARLOS.0 as f32, SAN_CARLOS.1 as f32, 4);
        let position = MobileRegionPositionRecord {
            location_bytes: Some(cell.as_bytes().to_vec()),
            ..exact(SAN_CARLOS.0, SAN_CARLOS.1)
        };
        let proposal = fixture().propose(position, Vec::new(), None).unwrap();
        // A ~600 m cell stays within one answer here; what matters is
        // that the cell path runs and states its width.
        let width = proposal.cell_meters.unwrap();
        assert!((610.0..613.0).contains(&width), "width {width}");
        assert!(
            proposal
                .lookup
                .radio_regions
                .iter()
                .any(|r| r.name == "SQL")
        );
    }

    #[test]
    fn coarse_positions_are_refused() {
        let db = fixture();
        let cell = NodeLocation::from_lat_lon(SAN_CARLOS.0 as f32, SAN_CARLOS.1 as f32, 2);
        let coarse_cell = MobileRegionPositionRecord {
            location_bytes: Some(cell.as_bytes().to_vec()),
            ..exact(SAN_CARLOS.0, SAN_CARLOS.1)
        };
        assert_eq!(
            db.propose(coarse_cell, Vec::new(), None).err(),
            Some(MobileRegionError::PositionTooCoarse)
        );
        let coarse_fix = MobileRegionPositionRecord {
            accuracy_m: Some(30_000.0),
            ..exact(SAN_CARLOS.0, SAN_CARLOS.1)
        };
        assert_eq!(
            db.propose(coarse_fix, Vec::new(), None).err(),
            Some(MobileRegionError::PositionTooCoarse)
        );
    }

    #[test]
    fn invalid_inputs_are_named() {
        let db = fixture();
        assert_eq!(
            db.lookup(91.0, 0.0).err(),
            Some(MobileRegionError::InvalidPosition)
        );
        assert_eq!(
            db.propose(
                MobileRegionPositionRecord {
                    location_bytes: Some(Vec::new()),
                    ..exact(0.0, 0.0)
                },
                Vec::new(),
                None,
            )
            .err(),
            Some(MobileRegionError::InvalidPosition)
        );
        assert_eq!(
            db.propose(exact(0.0, 0.0), Vec::new(), Some(vec![0x12]))
                .err(),
            Some(MobileRegionError::InvalidRegionCode)
        );
        assert_eq!(
            db.propose(exact(0.0, 0.0), vec![String::new()], None).err(),
            Some(MobileRegionError::InvalidRegionCode)
        );
    }
}
