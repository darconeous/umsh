//! Status codes carried in `PROP_LAST_STATUS`.

/// A status code, encoded on the wire as a packed unsigned integer.
///
/// Represented as a newtype rather than an enum so receivers can carry
/// codes defined by future protocol versions without loss.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Status(pub u32);

impl Status {
    pub const OK: Self = Self(0);
    pub const FAILURE: Self = Self(1);
    pub const UNIMPLEMENTED: Self = Self(2);
    pub const INVALID_ARGUMENT: Self = Self(3);
    pub const INVALID_STATE: Self = Self(4);
    pub const INVALID_COMMAND: Self = Self(5);
    pub const INTERNAL_ERROR: Self = Self(7);
    pub const PARSE_ERROR: Self = Self(9);
    pub const IN_PROGRESS: Self = Self(10);
    pub const NOMEM: Self = Self(11);
    pub const BUSY: Self = Self(12);
    pub const PROP_NOT_FOUND: Self = Self(13);
    pub const CCA_FAILURE: Self = Self(18);
    pub const ALREADY: Self = Self(19);
    pub const ITEM_NOT_FOUND: Self = Self(20);
    pub const DUTY_LIMIT: Self = Self(32);

    pub const RESET_POWER_ON: Self = Self(112);
    pub const RESET_EXTERNAL: Self = Self(113);
    pub const RESET_SOFTWARE: Self = Self(114);
    pub const RESET_RESTORED: Self = Self(115);
    pub const RESET_CRASH: Self = Self(116);
    pub const RESET_ASSERT: Self = Self(117);
    pub const RESET_OTHER: Self = Self(118);
    pub const RESET_UNKNOWN: Self = Self(119);
    pub const RESET_WATCHDOG: Self = Self(120);

    /// Whether this code falls in the reset-code range (112-127).
    pub const fn is_reset(self) -> bool {
        self.0 >= 112 && self.0 <= 127
    }

    const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::OK => "OK",
            Self::FAILURE => "FAILURE",
            Self::UNIMPLEMENTED => "UNIMPLEMENTED",
            Self::INVALID_ARGUMENT => "INVALID_ARGUMENT",
            Self::INVALID_STATE => "INVALID_STATE",
            Self::INVALID_COMMAND => "INVALID_COMMAND",
            Self::INTERNAL_ERROR => "INTERNAL_ERROR",
            Self::PARSE_ERROR => "PARSE_ERROR",
            Self::IN_PROGRESS => "IN_PROGRESS",
            Self::NOMEM => "NOMEM",
            Self::BUSY => "BUSY",
            Self::PROP_NOT_FOUND => "PROP_NOT_FOUND",
            Self::CCA_FAILURE => "CCA_FAILURE",
            Self::ALREADY => "ALREADY",
            Self::ITEM_NOT_FOUND => "ITEM_NOT_FOUND",
            Self::DUTY_LIMIT => "DUTY_LIMIT",
            Self::RESET_POWER_ON => "RESET_POWER_ON",
            Self::RESET_EXTERNAL => "RESET_EXTERNAL",
            Self::RESET_SOFTWARE => "RESET_SOFTWARE",
            Self::RESET_RESTORED => "RESET_RESTORED",
            Self::RESET_CRASH => "RESET_CRASH",
            Self::RESET_ASSERT => "RESET_ASSERT",
            Self::RESET_OTHER => "RESET_OTHER",
            Self::RESET_UNKNOWN => "RESET_UNKNOWN",
            Self::RESET_WATCHDOG => "RESET_WATCHDOG",
            _ => return None,
        })
    }
}

impl core::fmt::Debug for Status {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(formatter, "Status::{name}"),
            None => write!(formatter, "Status({})", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_range() {
        assert!(!Status::OK.is_reset());
        assert!(!Status::DUTY_LIMIT.is_reset());
        assert!(Status::RESET_POWER_ON.is_reset());
        assert!(Status::RESET_WATCHDOG.is_reset());
        assert!(Status(127).is_reset());
        assert!(!Status(128).is_reset());
    }

    #[test]
    fn debug_names() {
        assert_eq!(std::format!("{:?}", Status::OK), "Status::OK");
        assert_eq!(std::format!("{:?}", Status(42)), "Status(42)");
    }
}
