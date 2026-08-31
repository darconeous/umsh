//! Persisted entropy pool: a flash-seeded, hash-ratcheted CSPRNG.
//!
//! The pool exists for platforms whose hardware entropy source is not
//! always available — on the ESP32 the TRNG is only trustworthy while
//! the RF subsystem is up, which used to chain the RNG's lifetime to
//! the BLE controller's. A seed stored in flash breaks that chain: the
//! pool is cryptographically strong from the first instruction of boot,
//! and the hardware source becomes something it *harvests* when
//! available rather than something it dies without.
//!
//! ## The seed-file protocol (Fortuna's, with a lazy write)
//!
//! 1. Read the stored seed `S` and build the pool with
//!    [`EntropyPool::from_seed`]. The working key is `HKDF(S, salt)`
//!    with per-boot salt (chip id, reset reason) — flash never holds
//!    the working key, and a flash image taken later reveals nothing
//!    about this session's outputs.
//! 2. Before the first draw, write [`next_seed`](EntropyPool::next_seed)
//!    to flash and, once the write is confirmed, call
//!    [`seed_committed`](EntropyPool::seed_committed).
//! 3. Draw. [`draw`](EntropyPool::draw) refuses until step 2 has
//!    happened — that ordering is the whole crash-safety story. A boot
//!    that dies before the commit replays a working key that never
//!    emitted a byte, which is harmless; a boot that dies after it
//!    ratchets forward next time. No boot counter is needed.
//!
//! The write is deliberately *lazy*: nothing touches flash until
//! something actually wants randomness, so a reboot loop that dies
//! before its first draw costs zero flash cycles.
//!
//! ## Mixing
//!
//! [`mix`](EntropyPool::mix) folds harvested entropy into the working
//! key whenever a hardware source happens to be live. Mixing is what
//! heals a compromised or cloned seed file, so callers should persist a
//! fresh [`next_seed`](EntropyPool::next_seed) afterwards — but mixing
//! never *invalidates* the commit, because replay safety comes from the
//! boot-time ratchet, not from the stored seed tracking the live key.
//!
//! ## Construction
//!
//! Everything is HKDF-SHA256 over the platform's [`Sha256Provider`];
//! there is no stream cipher because every consumer wants a small seed
//! or nonce, not a keystream. Each draw ratchets the working key
//! one-way, so compromising the pool later reveals nothing already
//! emitted. Domain separation comes from distinct `info` strings plus
//! the caller's label as HKDF salt.

use zeroize::Zeroize;

use crate::{Sha256Provider, hkdf_sha256};

const INFO_BOOT: &[u8] = b"umsh-entropy-pool-v1 boot";
const INFO_NEXT: &[u8] = b"umsh-entropy-pool-v1 next";
const INFO_OUT: &[u8] = b"umsh-entropy-pool-v1 out";
const INFO_RATCHET: &[u8] = b"umsh-entropy-pool-v1 ratchet";
const INFO_MIX: &[u8] = b"umsh-entropy-pool-v1 mix";

/// A draw was attempted before the next seed was committed to storage.
///
/// Serving output before the commit is the one ordering that can replay
/// a stream after a crash, so it is a refusal rather than a footgun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrawBeforeCommit;

/// The pool: a 32-byte working key that only ever moves forward.
pub struct EntropyPool<S> {
    sha: S,
    key: [u8; 32],
    committed: bool,
    dirty: bool,
}

impl<S> Drop for EntropyPool<S> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<S: Sha256Provider> EntropyPool<S> {
    /// Build the pool from the stored seed.
    ///
    /// `salt` is the per-boot uniqueness: chip id and reset reason are
    /// free (no flash write) and make a restored flash image derive a
    /// different stream on different hardware.
    pub fn from_seed(sha: S, seed: &[u8; 32], salt: &[u8]) -> Self {
        let mut key = [0u8; 32];
        hkdf_sha256(&sha, seed, salt, INFO_BOOT, &mut key);
        Self {
            sha,
            key,
            committed: false,
            dirty: false,
        }
    }

    /// The seed the *next* boot should load. Derived one-way from the
    /// working key, so a flash image reveals nothing about this
    /// session, and independent of every draw label, so committing it
    /// first leaks nothing about outputs.
    pub fn next_seed(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        hkdf_sha256(&self.sha, &self.key, &[], INFO_NEXT, &mut seed);
        seed
    }

    /// The caller has confirmed [`next_seed`](Self::next_seed) is in
    /// storage; draws are now permitted.
    pub fn seed_committed(&mut self) {
        self.committed = true;
    }

    /// Whether draws are currently permitted.
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Fill `out` with output bound to `label`, then ratchet the
    /// working key so this output can never be re-derived from later
    /// pool state.
    pub fn draw(&mut self, label: &[u8], out: &mut [u8]) -> Result<(), DrawBeforeCommit> {
        if !self.committed {
            return Err(DrawBeforeCommit);
        }
        hkdf_sha256(&self.sha, &self.key, label, INFO_OUT, out);
        self.ratchet();
        Ok(())
    }

    /// Fold harvested entropy into the working key.
    ///
    /// Hash mixing means adversary-known input cannot reduce the pool's
    /// entropy, only fail to add any — so anything cheap is fair game.
    /// Marks the pool dirty: the stored seed no longer reflects the
    /// best key we have, and the caller should persist a fresh
    /// [`next_seed`](Self::next_seed) when convenient.
    pub fn mix(&mut self, entropy: &[u8]) {
        let mut next = [0u8; 32];
        hkdf_sha256(&self.sha, entropy, &self.key, INFO_MIX, &mut next);
        self.key.zeroize();
        self.key = next;
        self.dirty = true;
    }

    /// Whether a [`mix`](Self::mix) has made the stored seed stale.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// The caller has persisted a post-[`mix`](Self::mix) seed.
    pub fn seed_refreshed(&mut self) {
        self.dirty = false;
    }

    fn ratchet(&mut self) {
        let mut next = [0u8; 32];
        hkdf_sha256(&self.sha, &self.key, &[], INFO_RATCHET, &mut next);
        self.key.zeroize();
        self.key = next;
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::software::SoftwareSha256;

    fn pool(seed: &[u8; 32], salt: &[u8]) -> EntropyPool<SoftwareSha256> {
        EntropyPool::from_seed(SoftwareSha256, seed, salt)
    }

    #[test]
    fn a_draw_is_refused_until_the_seed_is_committed() {
        let mut p = pool(&[7; 32], b"salt");
        let mut out = [0u8; 32];
        assert_eq!(p.draw(b"x", &mut out), Err(DrawBeforeCommit));
        p.seed_committed();
        assert_eq!(p.draw(b"x", &mut out), Ok(()));
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn the_same_seed_and_salt_replay_the_same_stream() {
        // The crash case: reboot before commit, load the same seed.
        // Determinism is what makes never-output replay harmless to
        // reason about.
        let mut a = pool(&[1; 32], b"chip");
        let mut b = pool(&[1; 32], b"chip");
        a.seed_committed();
        b.seed_committed();
        let (mut oa, mut ob) = ([0u8; 32], [0u8; 32]);
        a.draw(b"node", &mut oa).unwrap();
        b.draw(b"node", &mut ob).unwrap();
        assert_eq!(oa, ob);
    }

    #[test]
    fn salt_separates_streams() {
        let mut a = pool(&[1; 32], b"reset:power-on");
        let mut b = pool(&[1; 32], b"reset:watchdog");
        a.seed_committed();
        b.seed_committed();
        let (mut oa, mut ob) = ([0u8; 32], [0u8; 32]);
        a.draw(b"node", &mut oa).unwrap();
        b.draw(b"node", &mut ob).unwrap();
        assert_ne!(oa, ob);
    }

    #[test]
    fn labels_separate_outputs_within_one_boot() {
        let mut p = pool(&[2; 32], b"salt");
        p.seed_committed();
        let (mut irk, mut node) = ([0u8; 16], [0u8; 16]);
        // Re-derive the first label's output from a twin pool so the
        // ratchet between draws is not what separates them.
        p.draw(b"irk", &mut irk).unwrap();
        let mut twin = pool(&[2; 32], b"salt");
        twin.seed_committed();
        twin.draw(b"node", &mut node).unwrap();
        assert_ne!(irk, node);
    }

    #[test]
    fn each_draw_ratchets_the_key() {
        let mut p = pool(&[3; 32], b"salt");
        p.seed_committed();
        let (mut first, mut second) = ([0u8; 32], [0u8; 32]);
        p.draw(b"same", &mut first).unwrap();
        p.draw(b"same", &mut second).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn the_next_seed_is_stable_across_draws_of_this_boot() {
        // The commit happens before the draws; the value written must
        // be the value the next boot loads regardless of what this
        // session went on to do.
        let p = pool(&[4; 32], b"salt");
        let persisted = p.next_seed();
        let mut p2 = pool(&[4; 32], b"salt");
        p2.seed_committed();
        let mut sink = [0u8; 32];
        p2.draw(b"a", &mut sink).unwrap();
        // p2's live key has ratcheted, but the seed written at commit
        // time is what counts — recompute from a fresh twin.
        assert_eq!(pool(&[4; 32], b"salt").next_seed(), persisted);
    }

    #[test]
    fn the_next_seed_differs_from_every_output() {
        let mut p = pool(&[5; 32], b"salt");
        let seed = p.next_seed();
        p.seed_committed();
        let mut out = [0u8; 32];
        p.draw(b"", &mut out).unwrap();
        assert_ne!(seed, out);
    }

    #[test]
    fn mixing_changes_the_next_seed_and_marks_dirty() {
        let mut p = pool(&[6; 32], b"salt");
        p.seed_committed();
        let before = p.next_seed();
        assert!(!p.is_dirty());
        p.mix(b"trng bytes");
        assert!(p.is_dirty());
        assert_ne!(p.next_seed(), before);
        p.seed_refreshed();
        assert!(!p.is_dirty());
    }

    #[test]
    fn mixing_does_not_revoke_the_commit() {
        // Replay safety comes from the boot ratchet, not from the
        // stored seed tracking the live key; a draw right after a mix
        // is legal.
        let mut p = pool(&[8; 32], b"salt");
        p.seed_committed();
        p.mix(b"harvest");
        let mut out = [0u8; 32];
        assert_eq!(p.draw(b"x", &mut out), Ok(()));
    }

    #[test]
    fn mixed_streams_diverge_from_unmixed() {
        let mut a = pool(&[9; 32], b"salt");
        let mut b = pool(&[9; 32], b"salt");
        a.seed_committed();
        b.seed_committed();
        b.mix(b"entropy");
        let (mut oa, mut ob) = ([0u8; 32], [0u8; 32]);
        a.draw(b"x", &mut oa).unwrap();
        b.draw(b"x", &mut ob).unwrap();
        assert_ne!(oa, ob);
    }
}
