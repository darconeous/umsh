//! A ChaCha20 generator that takes entropy gathered after it was built.
//!
//! A generator seeded once at boot knows only what the device knew at
//! boot. On a board that stays up for months, entropy harvested later
//! reaches the stored seed and the next boot, but nothing that is
//! running. [`ReseedingRng`] closes that gap: whatever harvests entropy
//! offers a fresh seed through a [`ReseedSlot`], and the generator folds
//! it into its key the next time it is used.
//!
//! The slot is a `static`, so the harvester needs no handle to a
//! generator that lives inside a MAC or a task. A generator nobody
//! offers a seed to produces exactly the `ChaCha20Rng` stream for its
//! boot seed.

use core::cell::Cell;
use core::sync::atomic::{AtomicBool, Ordering};

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use umsh_crypto::hkdf_sha256;
use umsh_crypto::software::SoftwareSha256;
use zeroize::Zeroize;

const INFO_RESEED: &[u8] = b"umsh-reseeding-rng-v1";

/// Where a fresh seed waits for one running generator.
pub struct ReseedSlot {
    /// Checked before the lock, so a generator with nothing waiting pays
    /// one atomic load per use.
    pending: AtomicBool,
    seed: Mutex<CriticalSectionRawMutex, Cell<[u8; 32]>>,
}

impl ReseedSlot {
    pub const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            seed: Mutex::new(Cell::new([0; 32])),
        }
    }

    /// Offer a fresh seed to the generator reading this slot.
    ///
    /// A seed not yet taken is replaced. Offers are expected to come
    /// from one accumulating pool, where a later draw already carries
    /// everything an earlier one did.
    pub fn offer(&self, seed: [u8; 32]) {
        self.seed.lock(|slot| {
            slot.set(seed);
            self.pending.store(true, Ordering::Release);
        });
    }

    fn take(&self) -> Option<[u8; 32]> {
        if !self.pending.load(Ordering::Acquire) {
            return None;
        }
        self.seed.lock(|slot| {
            self.pending
                .swap(false, Ordering::AcqRel)
                .then(|| slot.replace([0; 32]))
        })
    }
}

impl Default for ReseedSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// ChaCha20, rekeyed whenever its [`ReseedSlot`] holds a fresh seed.
pub struct ReseedingRng {
    rng: ChaCha20Rng,
    slot: &'static ReseedSlot,
}

impl ReseedingRng {
    pub fn new(seed: [u8; 32], slot: &'static ReseedSlot) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(seed),
            slot,
        }
    }

    /// Fold a waiting seed into the key.
    ///
    /// The new key is derived from the fresh seed and from output of the
    /// running generator, so it is at least as strong as either: a weak
    /// harvest cannot displace what the generator already had, and a
    /// compromised generator is healed by a good harvest.
    fn refresh(&mut self) {
        let Some(mut fresh) = self.slot.take() else {
            return;
        };
        let mut current = [0u8; 32];
        self.rng.fill_bytes(&mut current);
        let mut next = [0u8; 32];
        hkdf_sha256(&SoftwareSha256, &fresh, &current, INFO_RESEED, &mut next);
        self.rng = ChaCha20Rng::from_seed(next);
        fresh.zeroize();
        current.zeroize();
        next.zeroize();
    }
}

impl RngCore for ReseedingRng {
    fn next_u32(&mut self) -> u32 {
        self.refresh();
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.refresh();
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.refresh();
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// ChaCha20 keyed from a cryptographic seed, rekeyed only through HKDF.
impl CryptoRng for ReseedingRng {}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot() -> &'static ReseedSlot {
        Box::leak(Box::new(ReseedSlot::new()))
    }

    fn draw(rng: &mut impl RngCore) -> [u8; 48] {
        let mut out = [0u8; 48];
        rng.fill_bytes(&mut out);
        out
    }

    #[test]
    fn an_unreseeded_stream_is_plain_chacha20() {
        let mut reseeding = ReseedingRng::new([7; 32], slot());
        let mut plain = ChaCha20Rng::from_seed([7; 32]);
        assert_eq!(draw(&mut reseeding), draw(&mut plain));
        assert_eq!(reseeding.next_u32(), plain.next_u32());
        assert_eq!(reseeding.next_u64(), plain.next_u64());
        assert_eq!(draw(&mut reseeding), draw(&mut plain));
    }

    #[test]
    fn a_reseed_takes_effect_at_the_next_use_and_only_once() {
        let slot = slot();
        let mut reseeding = ReseedingRng::new([7; 32], slot);
        let mut plain = ChaCha20Rng::from_seed([7; 32]);
        assert_eq!(draw(&mut reseeding), draw(&mut plain));

        slot.offer([9; 32]);
        let after = draw(&mut reseeding);
        assert_ne!(after, draw(&mut plain));
        // The slot is spent: the stream continues from the new key
        // rather than rekeying on every use.
        let mut twin = ReseedingRng::new([7; 32], self::slot());
        draw(&mut twin);
        twin.slot.offer([9; 32]);
        assert_eq!(draw(&mut twin), after);
        assert_eq!(draw(&mut twin), draw(&mut reseeding));
    }

    #[test]
    fn the_new_key_depends_on_the_old_state_and_the_fresh_seed() {
        let reseeded = |boot: u8, fresh: u8| {
            let slot = slot();
            let mut rng = ReseedingRng::new([boot; 32], slot);
            slot.offer([fresh; 32]);
            draw(&mut rng)
        };
        // Same harvest, different generators: knowing the harvest does
        // not give away the stream.
        assert_ne!(reseeded(1, 9), reseeded(2, 9));
        // Same generator, different harvests: a cloned boot seed is
        // healed.
        assert_ne!(reseeded(1, 9), reseeded(1, 8));
        assert_eq!(reseeded(1, 9), reseeded(1, 9));
    }

    #[test]
    fn where_the_generator_has_got_to_matters() {
        let slot_a = slot();
        let mut a = ReseedingRng::new([3; 32], slot_a);
        let slot_b = slot();
        let mut b = ReseedingRng::new([3; 32], slot_b);
        draw(&mut b);
        slot_a.offer([5; 32]);
        slot_b.offer([5; 32]);
        assert_ne!(draw(&mut a), draw(&mut b));
    }

    #[test]
    fn a_later_offer_replaces_one_not_yet_taken() {
        let slot_a = slot();
        let mut a = ReseedingRng::new([4; 32], slot_a);
        slot_a.offer([1; 32]);
        slot_a.offer([2; 32]);

        let slot_b = slot();
        let mut b = ReseedingRng::new([4; 32], slot_b);
        slot_b.offer([2; 32]);
        assert_eq!(draw(&mut a), draw(&mut b));
    }
}
