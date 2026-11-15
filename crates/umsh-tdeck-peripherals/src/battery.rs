//! The battery-sense divider on GPIO4 (§4.5) reads the board's `+5V` rail,
//! not the cell: the cell on battery, but VBUS less a diode drop on USB,
//! whatever the cell holds.

use umsh_ux_tracker::battery::OcvCurve;

/// The rail's resting reading on battery → the share of runtime left.
///
/// Fit to a T-Deck Plus on its stock 2000 mAh cell, run idle with the
/// panel dark from a charge to brownout and read once a minute. 100% is
/// the 4.05 V reading and 0% the 3.1 V one, 53.6 h apart; the board ran
/// another 0.7 h below 3.1 V. The fit is within 1.5 points of the log.
///
/// The SY8089 buck draws roughly constant power, so runtime left is
/// energy left. The rail sits on a long plateau near 3.55 V, where 120 mV
/// spans a third of the charge: a reading there is only as good as the
/// ADC's calibration.
pub const OCV_CURVE: OcvCurve = OcvCurve::new(&[
    (3_100, 0),
    (3_320, 3),
    (3_460, 16),
    (3_490, 21),
    (3_540, 35),
    (3_580, 48),
    (3_640, 57),
    (3_900, 87),
    (4_050, 100),
]);

/// Above any cell, below any USB supply.
pub const EXTERNAL_MV: u16 = 4300;
/// Below this the rail is off and there is nothing to read.
pub const RAIL_OFF_MV: u16 = 1000;

/// What a reading of the rail says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rail {
    /// On the cell, at this voltage.
    Battery(u16),
    /// On external power: the cell's charge cannot be read.
    External,
    Off,
}

impl Rail {
    /// `mv` is the rail, the divider's reading doubled.
    #[must_use]
    pub const fn classify(mv: u16) -> Self {
        if mv < RAIL_OFF_MV {
            Self::Off
        } else if mv > EXTERNAL_MV {
            Self::External
        } else {
            Self::Battery(mv)
        }
    }
}
