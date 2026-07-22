//! Pure BLE security-policy helpers shared by embedded code and host tests.

/// Authentication failures allowed in one power cycle before pairing locks.
pub const MAX_PAIRING_FAILURES: u8 = 3;

pub const fn pairing_enabled(
    pairing_mode: bool,
    pin_configured: bool,
    locked_out: bool,
    bond_count: usize,
    bond_capacity: usize,
) -> bool {
    bond_count < bond_capacity && (pairing_mode || (pin_configured && !locked_out))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingFailureClass {
    ConfirmValue,
    DhKeyCheck,
    Other,
}

/// Per-power-cycle pairing policy state.
///
/// Keeping the event transitions pure makes the security-sensitive behavior
/// testable without a controller or real BLE connection. The embedded task
/// loads this state from atomics, applies one transition, and publishes it
/// back without awaiting in between.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingRuntime {
    pub pairing_mode: bool,
    pub failures: u8,
    pub locked_out: bool,
}

impl PairingRuntime {
    pub const fn record_failure(mut self, failure: PairingFailureClass) -> Self {
        let (failures, locked_out) = record_pairing_failure(self.failures, failure);
        self.failures = failures;
        self.locked_out = locked_out;
        self
    }

    /// Any successful pairing closes the window and clears prior failures.
    /// This is independent of whether Trouble includes the completed bond in
    /// the `PairingComplete` event or exposes it at the protected GATT edge.
    pub const fn pairing_succeeded(mut self) -> Self {
        self.pairing_mode = false;
        self.failures = 0;
        self.locked_out = false;
        self
    }

    /// Re-encryption by a known bond closes an accidentally-open window but
    /// does not rewrite the current failure counter.
    pub const fn bonded_reconnect(mut self) -> Self {
        self.pairing_mode = false;
        self
    }
}

impl PairingFailureClass {
    pub const fn counts_toward_lockout(self) -> bool {
        matches!(self, Self::ConfirmValue | Self::DhKeyCheck)
    }
}

/// Apply one pairing failure to the per-power-cycle lockout counter.
///
/// Protocol errors and policy rejections deliberately leave the counter
/// unchanged so a remote peer cannot lock out legitimate pairing without
/// guessing a PIN.
pub const fn record_pairing_failure(current: u8, failure: PairingFailureClass) -> (u8, bool) {
    if !failure.counts_toward_lockout() {
        return (current, current >= MAX_PAIRING_FAILURES);
    }

    let failures = current.saturating_add(1);
    (failures, failures >= MAX_PAIRING_FAILURES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_authentication_failures_advance_lockout() {
        assert_eq!(
            record_pairing_failure(0, PairingFailureClass::Other),
            (0, false)
        );
        assert!(PairingFailureClass::ConfirmValue.counts_toward_lockout());
        assert!(PairingFailureClass::DhKeyCheck.counts_toward_lockout());
        assert!(!PairingFailureClass::Other.counts_toward_lockout());
    }

    #[test]
    fn third_authentication_failure_locks_pairing() {
        assert_eq!(
            record_pairing_failure(0, PairingFailureClass::ConfirmValue),
            (1, false)
        );
        assert_eq!(
            record_pairing_failure(1, PairingFailureClass::DhKeyCheck),
            (2, false)
        );
        assert_eq!(
            record_pairing_failure(2, PairingFailureClass::ConfirmValue),
            (3, true)
        );
    }

    #[test]
    fn locked_counter_saturates() {
        assert_eq!(
            record_pairing_failure(3, PairingFailureClass::DhKeyCheck),
            (4, true)
        );
        assert_eq!(
            record_pairing_failure(u8::MAX, PairingFailureClass::ConfirmValue),
            (u8::MAX, true)
        );
        assert_eq!(
            record_pairing_failure(u8::MAX, PairingFailureClass::Other),
            (u8::MAX, true)
        );
    }

    #[test]
    fn pairing_gate_combines_mode_pin_lockout_and_capacity() {
        assert!(pairing_enabled(true, false, false, 0, 4));
        assert!(!pairing_enabled(false, false, false, 0, 4));
        assert!(pairing_enabled(false, true, false, 3, 4));
        assert!(!pairing_enabled(false, true, true, 3, 4));

        // Capacity is an unconditional pre-SMP gate even in pairing mode or
        // with a configured PIN.
        assert!(!pairing_enabled(true, false, false, 4, 4));
        assert!(!pairing_enabled(false, true, false, 4, 4));
        assert!(!pairing_enabled(true, true, false, 5, 4));
    }

    #[test]
    fn successful_pairing_clears_failures_even_without_event_bond() {
        let state = PairingRuntime {
            pairing_mode: true,
            failures: 2,
            locked_out: false,
        }
        .pairing_succeeded();

        assert_eq!(
            state,
            PairingRuntime {
                pairing_mode: false,
                failures: 0,
                locked_out: false,
            }
        );
    }

    #[test]
    fn bonded_reconnect_closes_pairing_mode_without_changing_failures() {
        let state = PairingRuntime {
            pairing_mode: true,
            failures: 1,
            locked_out: false,
        }
        .bonded_reconnect();

        assert!(!state.pairing_mode);
        assert_eq!(state.failures, 1);
        assert!(!state.locked_out);
    }
}
