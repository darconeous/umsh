//! Limits on registering strangers on the strength of their own frames.
//!
//! With auto-registration on, a frame from an unknown full-key source costs
//! point validation and an ECDH before it can register, and a key minted for
//! the purpose passes both. These bound what such frames can take: a quota of
//! registrations that displace an entry per window, and a short memory of keys
//! whose frames failed to open, so the same key does not cost an ECDH again
//! for a while.
//!
//! A free slot is taken outside the quota. Filling one displaces nobody, and
//! answers to this node's own questions, such as a discovery's identity
//! replies, arrive from strangers in bursts.

use heapless::{Deque, Vec};
use umsh_core::PublicKey;
use umsh_crypto::PairwiseKeys;

/// Strangers that may take another entry's slot on their own proof within
/// [`AUTO_REGISTER_WINDOW_MS`].
pub const AUTO_REGISTER_QUOTA: usize = 4;
/// The span [`AUTO_REGISTER_QUOTA`] covers.
pub const AUTO_REGISTER_WINDOW_MS: u64 = 10 * 60 * 1000;
/// Keys remembered as having failed to open.
pub const REFUSED_KEYS: usize = 4;
/// How long a key whose frame failed to open is remembered.
pub const REFUSED_KEY_TTL_MS: u64 = 10 * 60 * 1000;

/// What is remembered of a key whose frame failed to open.
pub(crate) enum Recalled {
    /// Nothing: it has not failed lately.
    Unknown,
    /// It is not a usable key, so no frame can ever open under it.
    Unusable,
    /// The pairwise keys it derived, under which its last frame failed. A
    /// forger can name any key, so this saves the ECDH without refusing the
    /// key's real holder.
    Derived(PairwiseKeys),
}

struct Refusal {
    /// The local identity the frame was addressed to, whose secret the
    /// derived keys rest on.
    local: PublicKey,
    key: PublicKey,
    derived: Option<PairwiseKeys>,
    until_ms: u64,
}

/// At most `N` events within any span of a window's length: when the latest
/// `N` happened, oldest first.
#[derive(Clone, Debug, Default)]
pub(crate) struct Quota<const N: usize> {
    at: Deque<u64, N>,
}

impl<const N: usize> Quota<N> {
    pub(crate) const fn new() -> Self {
        Self { at: Deque::new() }
    }

    /// Whether another event at `now_ms` fits the quota over `window_ms`.
    pub(crate) fn allows(&self, now_ms: u64, window_ms: u64) -> bool {
        !self.at.is_full()
            || self
                .at
                .front()
                .is_some_and(|&at| now_ms.saturating_sub(at) >= window_ms)
    }

    pub(crate) fn note(&mut self, now_ms: u64) {
        if self.at.is_full() {
            self.at.pop_front();
        }
        let _ = self.at.push_back(now_ms);
    }
}

#[derive(Default)]
pub(crate) struct Admissions {
    /// Registrations that displaced an entry.
    registered: Quota<AUTO_REGISTER_QUOTA>,
    refused: Vec<Refusal, REFUSED_KEYS>,
}

impl Admissions {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether another displacing registration fits the quota at `now_ms`.
    pub(crate) fn quota_allows(&self, now_ms: u64) -> bool {
        self.registered.allows(now_ms, AUTO_REGISTER_WINDOW_MS)
    }

    pub(crate) fn note_displacing(&mut self, now_ms: u64) {
        self.registered.note(now_ms);
    }

    pub(crate) fn recall(&self, local: &PublicKey, key: &PublicKey, now_ms: u64) -> Recalled {
        match self.refused.iter().find(|refusal| {
            refusal.local == *local && refusal.key == *key && now_ms < refusal.until_ms
        }) {
            None => Recalled::Unknown,
            Some(Refusal { derived: None, .. }) => Recalled::Unusable,
            Some(Refusal {
                derived: Some(keys),
                ..
            }) => Recalled::Derived(keys.clone()),
        }
    }

    /// Remember that a frame from `key` to `local` failed to open, with
    /// the pairwise keys it derived if it got that far.
    pub(crate) fn note_refused(
        &mut self,
        local: &PublicKey,
        key: PublicKey,
        derived: Option<PairwiseKeys>,
        now_ms: u64,
    ) {
        self.forget(local, &key);
        if self.refused.is_full()
            && let Some(index) = self
                .refused
                .iter()
                .enumerate()
                .min_by_key(|(_, refusal)| refusal.until_ms)
                .map(|(index, _)| index)
        {
            // The entry that lapses first gives way.
            self.refused.swap_remove(index);
        }
        let _ = self.refused.push(Refusal {
            local: *local,
            key,
            derived,
            until_ms: now_ms.saturating_add(REFUSED_KEY_TTL_MS),
        });
    }

    pub(crate) fn forget(&mut self, local: &PublicKey, key: &PublicKey) {
        self.refused
            .retain(|refusal| refusal.local != *local || refusal.key != *key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: &PublicKey = &PublicKey([0xF0; 32]);

    fn key(byte: u8) -> PublicKey {
        PublicKey([byte; 32])
    }

    #[test]
    fn the_quota_slides_with_the_window() {
        let mut admissions = Admissions::new();
        for at in 0..AUTO_REGISTER_QUOTA as u64 {
            assert!(admissions.quota_allows(at));
            admissions.note_displacing(at);
        }
        assert!(!admissions.quota_allows(AUTO_REGISTER_WINDOW_MS - 1));
        assert!(admissions.quota_allows(AUTO_REGISTER_WINDOW_MS));
        admissions.note_displacing(AUTO_REGISTER_WINDOW_MS);
        // The second registration has not yet left the window.
        assert!(!admissions.quota_allows(AUTO_REGISTER_WINDOW_MS));
        assert!(admissions.quota_allows(AUTO_REGISTER_WINDOW_MS + 1));
    }

    #[test]
    fn a_refused_key_lapses_and_the_table_stays_bounded() {
        let mut admissions = Admissions::new();
        admissions.note_refused(LOCAL, key(0), None, 0);
        assert!(matches!(
            admissions.recall(LOCAL, &key(0), REFUSED_KEY_TTL_MS - 1),
            Recalled::Unusable
        ));
        assert!(matches!(
            admissions.recall(&key(0xF1), &key(0), 0),
            Recalled::Unknown
        ));
        assert!(matches!(
            admissions.recall(LOCAL, &key(0), REFUSED_KEY_TTL_MS),
            Recalled::Unknown
        ));

        let derived = PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
        };
        for byte in 1..=REFUSED_KEYS as u8 {
            admissions.note_refused(LOCAL, key(byte), Some(derived.clone()), u64::from(byte));
        }
        // The first lapses first, so it gave way to the last.
        assert!(matches!(
            admissions.recall(LOCAL, &key(0), 1),
            Recalled::Unknown
        ));
        assert!((1..=REFUSED_KEYS as u8).all(|byte| matches!(
            admissions.recall(LOCAL, &key(byte), 9),
            Recalled::Derived(keys) if keys.k_mic == [2; 32]
        )));
        admissions.forget(LOCAL, &key(1));
        assert!(matches!(
            admissions.recall(LOCAL, &key(1), 9),
            Recalled::Unknown
        ));
    }
}
