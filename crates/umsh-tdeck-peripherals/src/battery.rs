//! The battery-sense divider on GPIO4 (§4.5) reads the board's `+5V` rail,
//! not the cell: the cell on battery, but VBUS less a diode drop on USB,
//! whatever the cell holds.

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
