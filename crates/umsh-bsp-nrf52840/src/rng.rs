//! nRF52840 hardware true-random-number generator wrapper.
//!
//! [`Nrf52840Rng`] wraps the nRF52840's `RNG` peripheral and exposes it as a
//! synchronous, `rand 0.10`-compatible RNG that satisfies
//! [`rand::CryptoRng`] via the auto-impl over `TryRng<Error = Infallible> +
//! TryCryptoRng`. It is the **single** RNG path for every nRF52840-based
//! UMSH firmware:
//!
//! - identity (Ed25519 secret-key) generation at first boot
//! - MAC backoff jitter
//! - MAC frame-counter init
//! - MAC reply / resync nonces and salts
//! - PFS ephemeral key material (when PFS is wired)
//!
//! Everything routes through this one wrapper, so there is no second
//! "non-crypto" PRNG to confuse with this one. Bias correction is enabled
//! at construction, matching what every firmware in this tree already did
//! for the identity-gen path.
//!
//! ## Performance
//!
//! With bias correction (DERCEN) enabled, the nRF52840 RNG produces one
//! byte per ~120 µs. That is fine for:
//!
//! - the MAC's occasional 4-byte reads (well under 1 ms each), and
//! - the one-shot 32-byte identity-gen call at boot (~4 ms).
//!
//! Bias correction is non-negotiable for key material per the nRF52840
//! Product Specification — the raw RNG output has a measurable bias and
//! is **not** suitable for cryptographic use without DERCEN.
//!
//! ## Why blocking
//!
//! We use [`embassy_nrf::rng::Rng`] in `Blocking` mode (busy-polls
//! `EVENTS_VALRDY`) rather than its async/interrupt mode. Reasons:
//!
//! 1. The `rand::TryRng` / `rand::CryptoRng` API is synchronous; an async
//!    RNG cannot satisfy `Platform::Rng` without an executor-aware bridge
//!    and a `block_on`-style hack.
//! 2. The MAC reads at most a handful of bytes per call, so a ~500 µs
//!    spin (for 4 bytes) is invisible at radio timescales (frame airtimes
//!    are tens to hundreds of milliseconds).
//! 3. Identity generation is a one-shot at boot — a 4 ms blocking spin
//!    once per first-boot is irrelevant.
//!
//! No interrupt binding (`bind_interrupts!`) is required.

use core::convert::Infallible;

use embassy_nrf::Peri;
use embassy_nrf::mode::Blocking;
use embassy_nrf::peripherals::RNG;
use embassy_nrf::rng::Rng as EmbassyRng;
use rand::{TryCryptoRng, TryRng};

/// nRF52840 hardware TRNG wrapper that implements the synchronous
/// `rand 0.10` traits.
///
/// Construct **once** at boot, before the MAC, and:
///
/// 1. use [`fill_bytes`](Self::fill_bytes) to seed identity key material
///    (or anything else needed before the MAC exists), then
/// 2. pass ownership into `Mac::new(.., rng, ..)`.
///
/// The MAC takes the RNG by value, so it must outlive any callers that
/// need pre-MAC bytes; this is the same ordering used for the existing
/// hardware-RNG identity-gen path.
pub struct Nrf52840Rng {
    inner: EmbassyRng<'static, Blocking>,
}

impl Nrf52840Rng {
    /// Consume the `RNG` peripheral and return a TRNG-backed RNG with
    /// bias correction (DERCEN) enabled.
    ///
    /// Bias correction is enabled unconditionally — see the module-level
    /// documentation for why this is the only safe default for key
    /// material.
    pub fn new(rng: Peri<'static, RNG>) -> Self {
        let inner = EmbassyRng::new_blocking(rng);
        inner.set_bias_correction(true);
        Self { inner }
    }

    /// Fill `dest` with random bytes by busy-polling `EVENTS_VALRDY`.
    ///
    /// Cost: ~120 µs per byte with bias correction. Acceptable for
    /// boot-time one-shots (identity gen) and small MAC reads; not
    /// appropriate for bulk operations on the order of kilobytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.blocking_fill_bytes(dest);
    }
}

impl TryRng for Nrf52840Rng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.inner.blocking_next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.inner.blocking_next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.blocking_fill_bytes(dest);
        Ok(())
    }
}

// The nRF52840 RNG is a true hardware noise source. With bias correction
// enabled (see `Self::new`) it is appropriate for cryptographic key
// material per the nRF52840 Product Specification.
impl TryCryptoRng for Nrf52840Rng {}
