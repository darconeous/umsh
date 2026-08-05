//! Codecs for the positioning properties (`PROP_GNSS_*`).
//!
//! The receiver's view of the world is one [`GnssSnapshot`], but it
//! reaches a host as five independent properties so that a host that only
//! wants a position never pays for the rest. [`GnssSnapshot::encode`] and
//! [`GnssSnapshot::absorb`] are the two halves of that split: a device
//! encodes whichever property was asked for, and a host folds the
//! properties it read back into one snapshot.
//!
//! Two of the five always answer: `PROP_GNSS_FIX` and
//! `PROP_GNSS_SATELLITES` read `0` when the receiver is off or searching,
//! because "no fix" is a fact the device is sure of. The three that
//! describe a position — location, altitude, precision — answer the empty
//! value until there *is* a position to describe.

use crate::ids::prop;

/// Maximum length of a `PROP_GNSS_LOCATION` value, and of any value this
/// module encodes.
pub const MAX_LOCATION_LEN: usize = 7;

/// Largest encoded property value produced here.
pub const MAX_VALUE_LEN: usize = MAX_LOCATION_LEN;

/// Assumed user-equivalent range error, in decimeters, used to turn a
/// dilution of precision into the horizontal-accuracy estimate reported
/// by `PROP_GNSS_PRECISION`.
const UERE_DM: u32 = 50;

/// `PROP_GNSS_FIX` values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FixKind {
    /// No position solution.
    #[default]
    None = 0,
    /// A two-dimensional solution: position without altitude.
    TwoD = 1,
    /// A three-dimensional solution.
    ThreeD = 2,
}

impl FixKind {
    /// The wire code for this fix quality.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Strict conversion from a wire code.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::TwoD),
            2 => Some(Self::ThreeD),
            _ => None,
        }
    }

    /// Whether there is a position solution at all.
    pub const fn is_fixed(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Encode or decode error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GnssError {
    /// A value whose length, range, or code the property does not allow.
    Malformed,
    /// The output buffer cannot hold the encoded value.
    BufferTooSmall,
    /// The key is not a positioning property this module encodes.
    UnknownProperty,
}

/// The receiver's current view of position and constellation.
///
/// The default is what a disabled or searching receiver reports: no fix,
/// no satellites, nothing positional to say.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GnssSnapshot {
    /// Fix quality.
    pub fix: FixKind,
    location: [u8; MAX_LOCATION_LEN],
    location_len: u8,
    /// Altitude above the WGS-84 ellipsoid in meters, matching the units
    /// of node identity option 2. `None` without a three-dimensional fix.
    pub altitude_m: Option<i32>,
    /// Estimated horizontal accuracy in decimeters.
    pub accuracy_dm: Option<u16>,
    /// Satellites contributing to the solution.
    pub sats_used: u8,
    /// Satellites the receiver can see, whether or not they are used.
    /// `None` when the receiver does not report it.
    pub sats_in_view: Option<u8>,
}

impl GnssSnapshot {
    /// What a receiver that is off — or on but still searching — reports.
    pub const SEARCHING: Self = Self {
        fix: FixKind::None,
        location: [0; MAX_LOCATION_LEN],
        location_len: 0,
        altitude_m: None,
        accuracy_dm: None,
        sats_used: 0,
        sats_in_view: None,
    };

    /// The encoded location, in the variable-precision interleaved
    /// format. Empty when there is no position.
    pub fn location(&self) -> &[u8] {
        &self.location[..self.location_len as usize]
    }

    /// Replace the location, silently truncating past [`MAX_LOCATION_LEN`].
    pub fn set_location(&mut self, bytes: &[u8]) {
        let len = bytes.len().min(MAX_LOCATION_LEN);
        self.location = [0; MAX_LOCATION_LEN];
        self.location[..len].copy_from_slice(&bytes[..len]);
        self.location_len = len as u8;
    }

    /// Turn a horizontal dilution of precision, in hundredths, into the
    /// accuracy estimate `PROP_GNSS_PRECISION` reports.
    ///
    /// This is an estimate scaled by an assumed range error, not a
    /// measured error bound; receivers that report a real accuracy figure
    /// should set [`accuracy_dm`](Self::accuracy_dm) from that instead.
    /// The product cannot overflow: the largest dilution the argument can
    /// express still scales to half of `u16::MAX`.
    pub const fn accuracy_from_hdop_centi(hdop_centi: u16) -> u16 {
        ((hdop_centi as u32 * UERE_DM) / 100) as u16
    }

    /// Encode the value of one positioning property.
    ///
    /// Returns the number of bytes written; zero is the empty value, and
    /// is what the three positional properties answer without a fix.
    pub fn encode(&self, key: u32, out: &mut [u8]) -> Result<usize, GnssError> {
        let mut write = |bytes: &[u8]| -> Result<usize, GnssError> {
            let dst = out
                .get_mut(..bytes.len())
                .ok_or(GnssError::BufferTooSmall)?;
            dst.copy_from_slice(bytes);
            Ok(bytes.len())
        };
        match key {
            prop::GNSS_LOCATION => write(self.location()),
            prop::GNSS_ALTITUDE => match self.altitude_m {
                Some(meters) => write(&meters.to_le_bytes()),
                None => Ok(0),
            },
            prop::GNSS_FIX => write(&[self.fix.code()]),
            prop::GNSS_PRECISION => match self.accuracy_dm {
                Some(dm) => write(&dm.to_le_bytes()),
                None => Ok(0),
            },
            prop::GNSS_SATELLITES => match self.sats_in_view {
                Some(in_view) => write(&[self.sats_used, in_view]),
                None => write(&[self.sats_used]),
            },
            _ => Err(GnssError::UnknownProperty),
        }
    }

    /// Fold one property value back into the snapshot.
    ///
    /// A host reads the positioning properties one at a time; this is how
    /// it reassembles them. The empty value clears the corresponding
    /// field rather than leaving a stale one behind.
    pub fn absorb(&mut self, key: u32, value: &[u8]) -> Result<(), GnssError> {
        match key {
            prop::GNSS_LOCATION => {
                if value.len() > MAX_LOCATION_LEN {
                    return Err(GnssError::Malformed);
                }
                self.set_location(value);
            }
            prop::GNSS_ALTITUDE => {
                self.altitude_m = match value {
                    [] => None,
                    [a, b, c, d] => Some(i32::from_le_bytes([*a, *b, *c, *d])),
                    _ => return Err(GnssError::Malformed),
                };
            }
            prop::GNSS_FIX => {
                let [code] = value else {
                    return Err(GnssError::Malformed);
                };
                self.fix = FixKind::from_code(*code).ok_or(GnssError::Malformed)?;
            }
            prop::GNSS_PRECISION => {
                self.accuracy_dm = match value {
                    [] => None,
                    [low, high] => Some(u16::from_le_bytes([*low, *high])),
                    _ => return Err(GnssError::Malformed),
                };
            }
            prop::GNSS_SATELLITES => match value {
                [used] => {
                    self.sats_used = *used;
                    self.sats_in_view = None;
                }
                [used, in_view] => {
                    self.sats_used = *used;
                    self.sats_in_view = Some(*in_view);
                }
                _ => return Err(GnssError::Malformed),
            },
            _ => return Err(GnssError::UnknownProperty),
        }
        Ok(())
    }
}

/// Whether `key` is one of the positioning properties this module codes.
pub const fn is_positioning_property(key: u32) -> bool {
    matches!(
        key,
        prop::GNSS_LOCATION
            | prop::GNSS_ALTITUDE
            | prop::GNSS_FIX
            | prop::GNSS_PRECISION
            | prop::GNSS_SATELLITES
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> GnssSnapshot {
        let mut snapshot = GnssSnapshot {
            fix: FixKind::ThreeD,
            altitude_m: Some(-31),
            accuracy_dm: Some(62),
            sats_used: 9,
            sats_in_view: Some(14),
            ..GnssSnapshot::SEARCHING
        };
        snapshot.set_location(&[0x8a, 0x1f, 0x4c, 0x00, 0xd3]);
        snapshot
    }

    #[track_caller]
    fn round_trip(snapshot: &GnssSnapshot, key: u32, expected: &[u8]) {
        let mut buf = [0u8; MAX_VALUE_LEN];
        let len = snapshot.encode(key, &mut buf).unwrap();
        assert_eq!(&buf[..len], expected, "encoding of {key}");
        let mut folded = GnssSnapshot::SEARCHING;
        folded.absorb(key, expected).unwrap();
        let mut re = [0u8; MAX_VALUE_LEN];
        let re_len = folded.encode(key, &mut re).unwrap();
        assert_eq!(&re[..re_len], expected, "re-encoding of {key}");
    }

    #[test]
    fn a_fix_encodes_every_property() {
        let snapshot = fixed();
        round_trip(
            &snapshot,
            prop::GNSS_LOCATION,
            &[0x8a, 0x1f, 0x4c, 0x00, 0xd3],
        );
        round_trip(&snapshot, prop::GNSS_ALTITUDE, &[0xe1, 0xff, 0xff, 0xff]);
        round_trip(&snapshot, prop::GNSS_FIX, &[2]);
        round_trip(&snapshot, prop::GNSS_PRECISION, &[62, 0]);
        round_trip(&snapshot, prop::GNSS_SATELLITES, &[9, 14]);
    }

    #[test]
    fn searching_answers_zero_for_facts_and_empty_for_positions() {
        let snapshot = GnssSnapshot::SEARCHING;
        round_trip(&snapshot, prop::GNSS_FIX, &[0]);
        round_trip(&snapshot, prop::GNSS_SATELLITES, &[0]);
        round_trip(&snapshot, prop::GNSS_LOCATION, &[]);
        round_trip(&snapshot, prop::GNSS_ALTITUDE, &[]);
        round_trip(&snapshot, prop::GNSS_PRECISION, &[]);
    }

    #[test]
    fn a_two_dimensional_fix_has_a_position_but_no_altitude() {
        let mut snapshot = fixed();
        snapshot.fix = FixKind::TwoD;
        snapshot.altitude_m = None;
        round_trip(&snapshot, prop::GNSS_FIX, &[1]);
        round_trip(&snapshot, prop::GNSS_ALTITUDE, &[]);
        assert_eq!(snapshot.location().len(), 5);
    }

    #[test]
    fn absorbing_an_empty_value_clears_a_stale_field() {
        let mut snapshot = fixed();
        snapshot.absorb(prop::GNSS_LOCATION, &[]).unwrap();
        snapshot.absorb(prop::GNSS_ALTITUDE, &[]).unwrap();
        snapshot.absorb(prop::GNSS_PRECISION, &[]).unwrap();
        assert_eq!(snapshot.location(), &[] as &[u8]);
        assert_eq!(snapshot.altitude_m, None);
        assert_eq!(snapshot.accuracy_dm, None);
    }

    #[test]
    fn rejects_malformed_values() {
        let mut snapshot = GnssSnapshot::SEARCHING;
        assert_eq!(
            snapshot.absorb(prop::GNSS_LOCATION, &[0; 8]),
            Err(GnssError::Malformed)
        );
        assert_eq!(
            snapshot.absorb(prop::GNSS_ALTITUDE, &[0, 0]),
            Err(GnssError::Malformed)
        );
        assert_eq!(
            snapshot.absorb(prop::GNSS_FIX, &[]),
            Err(GnssError::Malformed)
        );
        assert_eq!(
            snapshot.absorb(prop::GNSS_FIX, &[3]),
            Err(GnssError::Malformed)
        );
        assert_eq!(
            snapshot.absorb(prop::GNSS_PRECISION, &[1]),
            Err(GnssError::Malformed)
        );
        assert_eq!(
            snapshot.absorb(prop::GNSS_SATELLITES, &[1, 2, 3]),
            Err(GnssError::Malformed)
        );
        assert_eq!(
            snapshot.absorb(prop::TIME, &[]),
            Err(GnssError::UnknownProperty)
        );
    }

    #[test]
    fn location_truncates_past_the_maximum_precision() {
        let mut snapshot = GnssSnapshot::SEARCHING;
        snapshot.set_location(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(snapshot.location(), &[1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn encode_reports_short_buffers_and_unknown_keys() {
        let snapshot = fixed();
        let mut small = [0u8; 3];
        assert_eq!(
            snapshot.encode(prop::GNSS_LOCATION, &mut small),
            Err(GnssError::BufferTooSmall)
        );
        let mut buf = [0u8; MAX_VALUE_LEN];
        assert_eq!(
            snapshot.encode(prop::GNSS_ENABLED, &mut buf),
            Err(GnssError::UnknownProperty)
        );
    }

    #[test]
    fn accuracy_scales_dilution_of_precision() {
        // HDOP 1.00 → 5.0 m → 50 dm.
        assert_eq!(GnssSnapshot::accuracy_from_hdop_centi(100), 50);
        // HDOP 2.40 → 12.0 m.
        assert_eq!(GnssSnapshot::accuracy_from_hdop_centi(240), 120);
        // The worst dilution the argument can express still fits.
        assert_eq!(GnssSnapshot::accuracy_from_hdop_centi(u16::MAX), 32_767);
    }

    #[test]
    fn fix_codes_round_trip_strictly() {
        assert_eq!(FixKind::from_code(0), Some(FixKind::None));
        assert_eq!(FixKind::from_code(2), Some(FixKind::ThreeD));
        assert_eq!(FixKind::from_code(3), None);
        assert!(!FixKind::default().is_fixed());
        assert!(FixKind::TwoD.is_fixed());
    }

    #[test]
    fn positioning_properties_are_exactly_the_five() {
        assert!(is_positioning_property(prop::GNSS_LOCATION));
        assert!(is_positioning_property(prop::GNSS_SATELLITES));
        assert!(!is_positioning_property(prop::GNSS_ENABLED));
        assert!(!is_positioning_property(prop::TIME));
    }
}
