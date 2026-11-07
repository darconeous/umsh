//! What a receive path may spend on signature verification.
//!
//! Every signed frame heard costs an Ed25519 verification, and its sender,
//! not the receiver, chooses how many arrive. A [`VerifyBudget`] bounds the
//! spend: a bucket of verifications refilled at a steady rate from a
//! monotonic millisecond clock. Used by the host MAC and by the device for
//! its detached host.

/// Verifications a receive path may spend each second, and the most it may
/// spend at once.
pub const VERIFY_BUDGET_PER_SECOND: u32 = 8;

/// The time one verification takes to earn back.
const REFILL_MS: u64 = 1000 / VERIFY_BUDGET_PER_SECOND as u64;

/// A token bucket over signature verifications.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyBudget {
    tokens: u32,
    /// When the bucket last earned a token, or last filled.
    last_ms: u64,
}

impl Default for VerifyBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifyBudget {
    /// A full budget.
    pub const fn new() -> Self {
        Self {
            tokens: VERIFY_BUDGET_PER_SECOND,
            last_ms: 0,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        let earned = now_ms.saturating_sub(self.last_ms) / REFILL_MS;
        if earned == 0 {
            return;
        }
        let tokens = u64::from(self.tokens).saturating_add(earned);
        if tokens >= u64::from(VERIFY_BUDGET_PER_SECOND) {
            self.tokens = VERIFY_BUDGET_PER_SECOND;
            self.last_ms = now_ms;
        } else {
            // Below the cap, so `tokens` fits; time is consumed only as far
            // as it earned whole tokens.
            self.tokens = tokens as u32;
            self.last_ms += earned * REFILL_MS;
        }
    }

    /// Whether a verification could be spent at `now_ms`, spending nothing.
    pub fn ready(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        self.tokens > 0
    }

    /// Spend one verification, if the budget holds one at `now_ms`.
    pub fn try_spend(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_then_the_rate() {
        let mut budget = VerifyBudget::new();
        for _ in 0..VERIFY_BUDGET_PER_SECOND {
            assert!(budget.try_spend(1_000));
        }
        assert!(!budget.ready(1_000));
        assert!(!budget.try_spend(1_000 + REFILL_MS - 1));
        assert!(budget.try_spend(1_000 + REFILL_MS));
        assert!(!budget.try_spend(1_000 + REFILL_MS));
        // A long quiet spell refills no more than the bucket holds.
        for _ in 0..VERIFY_BUDGET_PER_SECOND {
            assert!(budget.try_spend(60_000));
        }
        assert!(!budget.try_spend(60_000));
    }

    #[test]
    fn readiness_spends_nothing() {
        let mut budget = VerifyBudget::new();
        for _ in 0..3 * VERIFY_BUDGET_PER_SECOND {
            assert!(budget.ready(0));
        }
        for _ in 0..VERIFY_BUDGET_PER_SECOND {
            assert!(budget.try_spend(0));
        }
        assert!(!budget.ready(0));
    }
}
