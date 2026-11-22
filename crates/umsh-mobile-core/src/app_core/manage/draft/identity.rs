//! What the device advertises about itself, and where it says it is.

use umsh_ulcp::ids::prop;

use super::{
    Field, Fold, Source, choice, optional_choice, optional_integer, rebased, text, toggle,
};
use crate::app_core::DEFAULT_LOCATION_PRECISION;
use crate::app_core::manage::records::{
    MobileApplyWarning, MobileDraftDetails, MobileFieldProblem, MobileIdentityDraft,
    MobilePositionField,
};
use crate::ulcp::{
    inspect_ulcp_properties, ulcp_encode_location, ulcp_location_cell_meters, ulcp_property_record,
};

/// Meters per degree at the equator, as `ulcp_location_cell_meters`
/// counts them.
const DEGREE_METERS: f64 = 111_320.0;

/// The fewest decimals a placed coordinate is written with.
const MIN_PLACED_DECIMALS: u8 = 5;

pub(super) fn build(source: &Source<'_>) -> MobileIdentityDraft {
    let held = source.held();
    let location = held.ident_location.as_ref();
    let reported = match (held.ident_latitude_deg, held.ident_longitude_deg) {
        (Some(latitude), Some(longitude)) => Some((latitude, longitude)),
        _ => None,
    };
    // What an edit is compared against: the octets themselves, since the
    // decoded pair is not exact at the finest precision. A location that
    // does not decode reads as none, as its pair does.
    let reported_location = reported.and(location).cloned().unwrap_or_default();
    let precision = choice(prop::GNSS_IDENT_PRECISION, held.gnss_ident_precision);
    // A device with no precision property still needs a grid to encode a
    // hand-placed position to: the one it advertises on, or the precision
    // a device resets to.
    let manual_precision = held
        .gnss_ident_precision
        .or_else(|| {
            location
                .and_then(|bytes| u8::try_from(bytes.len()).ok())
                .filter(|length| ulcp_location_cell_meters(*length).is_some())
        })
        .unwrap_or(DEFAULT_LOCATION_PRECISION);
    MobileIdentityDraft {
        reading_revision: source.revision(),
        name: text(prop::DEV_NAME, held.device_name.clone()),
        // A role the device does not state is one it derives, and an
        // altitude it leaves empty is no stated height: values rather
        // than absences, known exactly when the property was answered.
        role: optional_choice(
            prop::IDENT_ROLE,
            source.answered(prop::IDENT_ROLE),
            held.ident_role,
        ),
        mobile: toggle(prop::IDENT_MOBILE, held.ident_mobile),
        discoverable: toggle(prop::DEV_DISCOVERABLE, held.dev_discoverable),
        position: MobilePositionField {
            property_id: prop::IDENT_LOCATION,
            known: location.is_some(),
            reported_latitude: reported.map(|(latitude, _)| latitude),
            reported_longitude: reported.map(|(_, longitude)| longitude),
            reported_location,
            latitude: reported.map(|(latitude, _)| latitude),
            longitude: reported.map(|(_, longitude)| longitude),
        },
        altitude_m: optional_integer(
            prop::IDENT_ALTITUDE,
            source.answered(prop::IDENT_ALTITUDE),
            held.ident_altitude_m,
        ),
        self_positions: toggle(prop::GNSS_IDENT_UPDATE, held.gnss_ident_update),
        precision,
        advert_interval: choice(prop::ADVERT_INTERVAL, held.advert_interval_seconds),
        beacon_interval: choice(prop::BEACON_INTERVAL, held.beacon_interval_seconds),
        startup_beacon: toggle(prop::STARTUP_BEACON, held.startup_beacon),
        manual_precision,
    }
}

pub(super) fn rebase(fresh: MobileIdentityDraft, old: &MobileIdentityDraft) -> MobileIdentityDraft {
    // A position inside the reported cell is clean, as fold judges it, so
    // it follows the device like any clean field.
    let position = if position_edited(old) {
        rebased(fresh.position, &old.position)
    } else {
        fresh.position
    };
    MobileIdentityDraft {
        reading_revision: fresh.reading_revision,
        name: rebased(fresh.name, &old.name),
        role: rebased(fresh.role, &old.role),
        mobile: rebased(fresh.mobile, &old.mobile),
        discoverable: rebased(fresh.discoverable, &old.discoverable),
        position,
        altitude_m: rebased(fresh.altitude_m, &old.altitude_m),
        self_positions: rebased(fresh.self_positions, &old.self_positions),
        precision: rebased(fresh.precision, &old.precision),
        advert_interval: rebased(fresh.advert_interval, &old.advert_interval),
        beacon_interval: rebased(fresh.beacon_interval, &old.beacon_interval),
        startup_beacon: rebased(fresh.startup_beacon, &old.startup_beacon),
        // A local choice, not a device value: a reading has nothing to say
        // about it.
        manual_precision: old.manual_precision,
    }
}

/// Whether the device keeps its own advertised position, now or after
/// this draft: a position written then would be refused.
fn self_positioning(draft: &MobileIdentityDraft) -> bool {
    let field = &draft.self_positions;
    field.known && (field.value || field.reported)
}

/// The grid a typed or placed position is encoded to: the device's own
/// precision where it has one, the local choice otherwise.
fn encoding_precision(draft: &MobileIdentityDraft) -> u8 {
    let field = &draft.precision;
    field
        .known
        .then_some(field.value)
        .flatten()
        .and_then(|precision| u8::try_from(precision).ok())
        .filter(|precision| ulcp_location_cell_meters(*precision).is_some())
        .unwrap_or(draft.manual_precision)
}

/// The decimal places a cell of `precision` resolves: digits finer than
/// the grid would be invented. Five without a cell.
pub(in crate::app_core::manage) fn cell_decimals(precision: u8) -> u8 {
    let Some(cell) = ulcp_location_cell_meters(precision) else {
        return 5;
    };
    let digits = (DEGREE_METERS / cell.max(0.01)).log10().ceil();
    digits.clamp(0.0, 7.0) as u8
}

/// The decimals a placed position is written with at `precision`: enough
/// that the cell it was chosen in survives being shown and read back.
fn placed_decimals(precision: u8) -> u8 {
    cell_decimals(precision).max(MIN_PLACED_DECIMALS)
}

/// Whether the operator chose a grid other than the reported position's.
/// A device whose precision property and advertised position already
/// disagree is not, by itself, an edit.
fn regridded(draft: &MobileIdentityDraft) -> bool {
    let reported = u8::try_from(draft.position.reported_location.len()).unwrap_or(u8::MAX);
    if draft.precision.known {
        draft.precision.dirty() && encoding_precision(draft) != reported
    } else {
        draft.manual_precision != reported
    }
}

fn round(degrees: f64, decimals: u8) -> f64 {
    let scale = 10f64.powi(decimals.into());
    (degrees * scale).round() / scale
}

/// The octets a position's value encodes to at `precision`: `Ok(None)`
/// for half a pair, which is no edit.
fn edited_location(position: &MobilePositionField, precision: u8) -> Result<Option<Vec<u8>>, ()> {
    match (position.latitude, position.longitude) {
        (None, None) => Ok(Some(Vec::new())),
        (Some(latitude), Some(longitude)) => ulcp_encode_location(latitude, longitude, precision)
            .map(Some)
            .map_err(|_| ()),
        _ => Ok(None),
    }
}

/// Whether `draft`'s position is an edit to carry onto a fresh reading:
/// half a pair, a value that will not encode, or one outside the reported
/// cell.
fn position_edited(draft: &MobileIdentityDraft) -> bool {
    let position = &draft.position;
    position.dirty()
        && match edited_location(position, encoding_precision(draft)) {
            Ok(Some(location)) => location != position.reported_location,
            Ok(None) | Err(()) => true,
        }
}

fn decoded(location: &[u8]) -> (Option<f64>, Option<f64>) {
    if location.is_empty() {
        return (None, None);
    }
    let properties = inspect_ulcp_properties(vec![ulcp_property_record(
        prop::IDENT_LOCATION,
        location.to_vec(),
    )]);
    (
        properties.ident_latitude_deg,
        properties.ident_longitude_deg,
    )
}

pub(super) fn fold(draft: &MobileIdentityDraft, fold: &mut Fold) {
    fold.text(&draft.name, |desired, name| {
        desired.device_name = Some(name)
    });
    fold.optional_choice(&draft.role, |desired, role: Option<u8>| {
        desired.ident_role = role;
    });
    fold.toggle(&draft.mobile, |desired, value| {
        desired.ident_mobile = Some(value);
    });
    fold.toggle(&draft.discoverable, |desired, value| {
        desired.dev_discoverable = Some(value);
    });
    fold.toggle(&draft.self_positions, |desired, value| {
        desired.gnss_ident_update = Some(value);
    });
    fold.choice(&draft.precision, |desired, value: u8| {
        desired.gnss_ident_precision = Some(value);
    });
    fold.choice(&draft.advert_interval, |desired, value: u32| {
        desired.advert_interval_seconds = Some(value);
    });
    fold.choice(&draft.beacon_interval, |desired, value: u32| {
        desired.beacon_interval_seconds = Some(value);
    });
    fold.toggle(&draft.startup_beacon, |desired, value| {
        desired.startup_beacon = Some(value);
    });
    // A device keeping its own position refuses both of these, and turning
    // that off in the same apply does not change what it refuses: a write
    // is judged against the policy the device holds when it arrives.
    if self_positioning(draft) {
        return;
    }
    let position = &draft.position;
    if position.dirty() {
        match edited_location(position, encoding_precision(draft)) {
            Err(()) => fold.problem(position.property_id, MobileFieldProblem::OutOfRange),
            Ok(Some(location)) if location != position.reported_location => {
                fold.edit(position.property_id, |desired| {
                    desired.ident_location = Some(location);
                });
            }
            // Half a pair, or a value inside the reported cell.
            Ok(_) => {}
        }
    } else if position.known
        && position.reported_latitude.is_some()
        && regridded(draft)
        && let Ok(Some(location)) = edited_location(position, encoding_precision(draft))
    {
        // The same place on a grid the operator chose is a new location
        // to advertise.
        fold.edit(position.property_id, |desired| {
            desired.ident_location = Some(location);
        });
    }
    fold.optional_integer(
        &draft.altitude_m,
        MobileFieldProblem::OutOfRange,
        |_: i32| true,
        |desired, value| desired.ident_altitude_m = value,
    );
}

pub(super) fn assess(
    draft: &MobileIdentityDraft,
    fold: &Fold,
) -> (Option<MobileApplyWarning>, MobileDraftDetails) {
    let self_positioning = self_positioning(draft);
    let encoding_precision = encoding_precision(draft);
    let position = &draft.position;
    // The summary never shows a place that will not be written.
    let (latitude_deg, longitude_deg) = if !self_positioning
        && fold.is_dirty(prop::IDENT_LOCATION)
        && let Some(location) = fold.desired.ident_location.as_ref()
    {
        decoded(location)
    } else {
        (position.reported_latitude, position.reported_longitude)
    };
    (
        None,
        MobileDraftDetails::Identity {
            self_positioning,
            encoding_precision,
            coordinate_decimals: placed_decimals(encoding_precision),
            latitude_deg,
            longitude_deg,
        },
    )
}

/// Put a place in the position, rounded to the decimals the coordinate
/// fields show at the draft's precision, so what is shown is what Apply
/// writes.
#[uniffi::export]
pub fn draft_place(
    draft: MobileIdentityDraft,
    latitude: f64,
    longitude: f64,
) -> MobileIdentityDraft {
    let mut draft = draft;
    let decimals = placed_decimals(encoding_precision(&draft));
    draft.position.latitude = Some(round(latitude, decimals));
    draft.position.longitude = Some(round(longitude, decimals));
    draft
}

/// Place the device where the phone is. `altitude_m` is the phone's
/// height when its fix states one; it is taken, rounded, where the device
/// answered for an altitude, and left alone otherwise rather than written
/// as a zero.
#[uniffi::export]
pub fn draft_place_from_phone(
    draft: MobileIdentityDraft,
    latitude: f64,
    longitude: f64,
    altitude_m: Option<f64>,
) -> MobileIdentityDraft {
    let mut draft = draft_place(draft, latitude, longitude);
    if let Some(altitude) = altitude_m.filter(|altitude| altitude.is_finite())
        && draft.altitude_m.known
    {
        // A saturating conversion: a height outside the property's range
        // comes back from review as out of range.
        draft.altitude_m.value = Some(altitude.round() as i64);
    }
    draft
}

/// Choose the grid a position is encoded to: the device's precision
/// where it has one, the local choice otherwise.
#[uniffi::export]
pub fn draft_set_precision(draft: MobileIdentityDraft, precision: u8) -> MobileIdentityDraft {
    let mut draft = draft;
    if draft.precision.known {
        draft.precision.value = Some(precision.into());
    } else {
        draft.manual_precision = precision;
    }
    draft
}

/// Advertise no position, and no height with it.
#[uniffi::export]
pub fn draft_clear_position(draft: MobileIdentityDraft) -> MobileIdentityDraft {
    let mut draft = draft;
    draft.position.latitude = None;
    draft.position.longitude = None;
    draft.altitude_m.value = None;
    draft
}
