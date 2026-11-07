//! Pure BLE security-policy helpers shared by embedded code and host tests.

/// Authentication failures allowed before pairing first locks.
pub const MAX_PAIRING_FAILURES: u8 = 3;

/// How long the first lockout lasts. Each later one in the same power
/// cycle lasts twice as long as the one before, up to [`LOCKOUT_MAX_MS`].
pub const LOCKOUT_FIRST_MS: u64 = 60_000;
/// The longest a lockout lasts.
pub const LOCKOUT_MAX_MS: u64 = 3_600_000;

/// How long the `lockouts`-th lockout of this power cycle lasts (1-based).
pub const fn lockout_ms(lockouts: u8) -> u64 {
    let doublings = if lockouts == 0 { 0 } else { lockouts - 1 };
    if doublings >= 6 {
        return LOCKOUT_MAX_MS;
    }
    let ms = LOCKOUT_FIRST_MS << doublings;
    if ms > LOCKOUT_MAX_MS {
        LOCKOUT_MAX_MS
    } else {
        ms
    }
}

/// Non-OOB pairing admission.
///
/// Pairing mode is mandatory. A configured PIN selects LESC Passkey Entry;
/// it does not authorize enrollment, so it can never stand in for the
/// physical-presence gesture that arms the window.
///
/// Lockout is conditioned on `pin_configured` deliberately: it exists to stop
/// Passkey Entry bit-leak probing, and under Just Works there is no passkey to
/// leak—gating the unauthenticated path on the same counter would let an
/// in-range attacker deny pairing for the rest of the power cycle with three
/// bad confirm values.
///
/// Bond-store capacity is deliberately **not** a term. A full store evicts its
/// least-recently-used bond on the next successful pairing; enrollment is never
/// refused for lack of space. See [`crate::ble_security`] callers and
/// `umsh_journal_store::ble::upsert_bond`.
pub const fn pairing_enabled(pairing_mode: bool, pin_configured: bool, locked_out: bool) -> bool {
    pairing_mode && (!pin_configured || !locked_out)
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
///
/// A lockout ends after [`lockout_ms`], and the PIN stays the same, so each
/// attempt after one can leak more of it: past the first lockout, a single
/// failure locks again, each time for twice as long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingRuntime {
    pub pairing_mode: bool,
    pub failures: u8,
    pub locked_out: bool,
    /// Lockouts so far this power cycle, the current one included.
    pub lockouts: u8,
}

impl PairingRuntime {
    pub const fn record_failure(mut self, failure: PairingFailureClass) -> Self {
        let (failures, locked_out) = record_pairing_failure(self.failures, failure);
        if locked_out && !self.locked_out {
            self.lockouts = self.lockouts.saturating_add(1);
        }
        self.failures = failures;
        self.locked_out = locked_out;
        self
    }

    /// How long the lockout that `record_failure` just began lasts.
    pub const fn lockout_ms(self) -> u64 {
        lockout_ms(self.lockouts)
    }

    /// The lockout has run its course: pairing opens again, and the next
    /// authentication failure locks it again.
    pub const fn lockout_expired(mut self) -> Self {
        if self.locked_out {
            self.locked_out = false;
            self.failures = MAX_PAIRING_FAILURES - 1;
        }
        self
    }

    /// Any successful pairing closes the window and clears prior failures.
    /// This is independent of whether Trouble includes the completed bond in
    /// the `PairingComplete` event or exposes it at the protected GATT edge.
    pub const fn pairing_succeeded(mut self) -> Self {
        self.pairing_mode = false;
        self.failures = 0;
        self.locked_out = false;
        self.lockouts = 0;
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

/// Apply one pairing failure to the lockout counter.
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
    fn pairing_requires_pairing_mode_even_with_a_configured_pin() {
        // A PIN selects Passkey Entry; it does not authorize enrollment.
        assert!(!pairing_enabled(false, true, false));
        assert!(!pairing_enabled(false, true, true));
        assert!(!pairing_enabled(false, false, false));

        assert!(pairing_enabled(true, false, false));
        assert!(pairing_enabled(true, true, false));
    }

    #[test]
    fn lockout_applies_only_where_a_passkey_can_be_probed() {
        // With a PIN, the failure limit closes the window until the lockout
        // ends, even while pairing mode is armed.
        assert!(!pairing_enabled(true, true, true));
        // Under Just Works there is no passkey to leak, so a remote peer
        // cannot deny pairing by failing the confirm value.
        assert!(pairing_enabled(true, false, true));
    }

    #[test]
    fn successful_pairing_clears_failures_even_without_event_bond() {
        let state = PairingRuntime {
            pairing_mode: true,
            failures: 2,
            locked_out: false,
            lockouts: 1,
        }
        .pairing_succeeded();

        assert_eq!(
            state,
            PairingRuntime {
                pairing_mode: false,
                failures: 0,
                locked_out: false,
                lockouts: 0,
            }
        );
    }

    #[test]
    fn bonded_reconnect_closes_pairing_mode_without_changing_failures() {
        let state = PairingRuntime {
            pairing_mode: true,
            failures: 1,
            locked_out: false,
            lockouts: 0,
        }
        .bonded_reconnect();

        assert!(!state.pairing_mode);
        assert_eq!(state.failures, 1);
        assert!(!state.locked_out);
    }

    #[test]
    fn a_lockout_ends_and_then_one_failure_locks_again_for_longer() {
        let mut state = PairingRuntime {
            pairing_mode: true,
            failures: 0,
            locked_out: false,
            lockouts: 0,
        };
        for _ in 0..MAX_PAIRING_FAILURES {
            state = state.record_failure(PairingFailureClass::ConfirmValue);
        }
        assert!(state.locked_out);
        assert_eq!(state.lockout_ms(), 60_000);
        let mut expected = 60_000;
        for _ in 0..8 {
            state = state.lockout_expired();
            assert!(!state.locked_out);
            assert!(pairing_enabled(true, true, state.locked_out));
            // A failure that is not authentication leaks nothing.
            state = state.record_failure(PairingFailureClass::Other);
            assert!(!state.locked_out);
            state = state.record_failure(PairingFailureClass::DhKeyCheck);
            assert!(state.locked_out);
            expected = (expected * 2).min(LOCKOUT_MAX_MS);
            assert_eq!(state.lockout_ms(), expected);
        }
        assert_eq!(state.lockout_ms(), LOCKOUT_MAX_MS);
        // Success forgets the escalation.
        let state = state.pairing_succeeded();
        assert_eq!(state.lockouts, 0);
        assert_eq!(lockout_ms(255), LOCKOUT_MAX_MS);
    }

    #[test]
    fn an_expiry_with_no_lockout_changes_nothing() {
        let state = PairingRuntime {
            pairing_mode: true,
            failures: 1,
            locked_out: false,
            lockouts: 0,
        };
        assert_eq!(state.lockout_expired(), state);
    }
}
