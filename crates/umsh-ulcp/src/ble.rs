//! The Bluetooth link enumeration (`PROP_BLE_LINK`).
//!
//! The property value is a single octet naming how far the device's
//! Bluetooth transport has got with whoever is on the other end of it.
//! Being connected and being attached are different claims: a central can
//! hold the device's one peripheral slot without ever opening a ULCP
//! session on it, and telling those apart is the difference between "a
//! host is talking to this device" and "something is sitting on its
//! Bluetooth".

/// `PROP_BLE_LINK` states.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BleLinkState {
    /// `BLE_LINK_NONE` — nothing is connected over Bluetooth.
    #[default]
    None = 0,
    /// `BLE_LINK_CONNECTED` — a central holds a connection but has not
    /// opened a ULCP session on it.
    Connected = 1,
    /// `BLE_LINK_ATTACHED` — a host is attached and running ULCP over
    /// Bluetooth.
    Attached = 2,
}

impl BleLinkState {
    /// The wire code for this state.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Strict conversion from a wire octet.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::Connected),
            2 => Some(Self::Attached),
            _ => None,
        }
    }

    /// Whether anything at all holds a Bluetooth connection to the
    /// device, attached or not.
    pub const fn is_connected(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether a host is attached over Bluetooth, which is the question
    /// "is someone managing this device right now" actually asks.
    pub const fn is_attached(self) -> bool {
        matches!(self, Self::Attached)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_strictly() {
        assert_eq!(BleLinkState::from_code(0), Some(BleLinkState::None));
        assert_eq!(BleLinkState::from_code(1), Some(BleLinkState::Connected));
        assert_eq!(BleLinkState::from_code(2), Some(BleLinkState::Attached));
        assert_eq!(BleLinkState::from_code(3), None);
        assert_eq!(BleLinkState::None.code(), 0);
        assert_eq!(BleLinkState::Connected.code(), 1);
        assert_eq!(BleLinkState::Attached.code(), 2);
    }

    #[test]
    fn connected_and_attached_are_different_claims() {
        assert_eq!(BleLinkState::default(), BleLinkState::None);
        assert!(!BleLinkState::None.is_connected());
        assert!(BleLinkState::Connected.is_connected());
        assert!(!BleLinkState::Connected.is_attached());
        assert!(BleLinkState::Attached.is_connected());
        assert!(BleLinkState::Attached.is_attached());
    }
}
