//! The locate-alert enumeration (`PROP_ALERT`).
//!
//! The property value is a single PUI naming what the device is currently
//! doing to draw attention to where it physically is. What that consists
//! of is board-defined: a buzzer, an indicator LED, and a display all
//! satisfy the same value.

/// `PROP_ALERT` states.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AlertState {
    /// `ALERT_NONE` — the nominal state.
    #[default]
    None = 0,
    /// `ALERT_LOCATE` — make the device as conspicuous as its hardware
    /// allows until the alert is cleared.
    Locate = 1,
}

impl AlertState {
    /// The wire code for this state.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Strict conversion from a decoded wire code.
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::Locate),
            _ => None,
        }
    }

    /// Whether an alert is in progress.
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Locate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_strictly() {
        assert_eq!(AlertState::from_code(0), Some(AlertState::None));
        assert_eq!(AlertState::from_code(1), Some(AlertState::Locate));
        assert_eq!(AlertState::from_code(2), None);
        assert_eq!(AlertState::None.code(), 0);
        assert_eq!(AlertState::Locate.code(), 1);
    }

    #[test]
    fn default_is_nominal() {
        assert_eq!(AlertState::default(), AlertState::None);
        assert!(!AlertState::default().is_active());
        assert!(AlertState::Locate.is_active());
    }
}
