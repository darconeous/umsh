//! RF-gated cryptographic RNG for Espressif targets.
//!
//! [`EspCryptoRng`] is the **single** RNG path for every ESP32-based UMSH
//! firmware — identity generation, MAC backoff jitter, frame-counter init,
//! reply/resync nonces and salts, and PFS ephemeral key material all route
//! through it. There is deliberately no second "non-crypto" PRNG to
//! confuse it with.
//!
//! ## The RF gate
//!
//! The ESP32 hardware RNG only produces *true* random numbers while
//! physical noise is being mixed into its state, which requires one of:
//!
//! - the RF subsystem being enabled (Wi-Fi or Bluetooth), or
//! - the SAR ADC being used as an entropy source
//!   (`esp_hal::rng::TrngSource`, which **occupies ADC1**).
//!
//! With no entropy source the peripheral still returns bytes — they are
//! merely pseudo-random. That silent degradation is the hazard this
//! wrapper exists to prevent.
//!
//! UMSH firmware takes the RF path: the ADC belongs to the battery
//! sampler, so the BLE controller is what makes the RNG trustworthy.
//! `esp-radio`'s BLE (and Wi-Fi) init raises esp-hal's entropy-source
//! counter, and its deinit lowers it again.
//!
//! ## How the gate is enforced
//!
//! [`EspCryptoRng::new`] fails with [`TrngError`] unless an entropy source
//! is already live, so a firmware that forgets to bring the radio up
//! cannot obtain one at all. Because `esp-radio` can lower the counter
//! later (on BLE deinit) *without* invalidating outstanding handles, every
//! read re-checks the gate and **panics** if entropy has gone away. A
//! panic is the correct outcome here: it is loud, it lands in the RTC-RAM
//! panic capture, and it is strictly better than handing predictable bytes
//! to key generation.
//!
//! Consequently the caller MUST keep the BLE controller alive for as long
//! as the RNG is in use.

use core::convert::Infallible;

use esp_hal::rng::Trng;
pub use esp_hal::rng::TrngError;
use rand::{TryCryptoRng, TryRng};

/// Hardware TRNG wrapper implementing the synchronous `rand 0.10` traits.
///
/// Satisfies [`rand::CryptoRng`] via the auto-impl over
/// `TryRng<Error = Infallible> + TryCryptoRng`, so it can be handed
/// straight to `Mac::new(..)` as `Platform::Rng`.
///
/// Construct **after** the radio is up, and:
///
/// 1. use [`fill_bytes`](Self::fill_bytes) to seed identity key material
///    (or anything else needed before the MAC exists), then
/// 2. pass ownership into `Mac::new(.., rng, ..)`.
pub struct EspCryptoRng {
    // Deliberately not holding a `Trng`: an outstanding handle does not
    // keep the entropy source alive, so caching one would just be a
    // stale claim. Each read re-derives it instead.
    _private: (),
}

impl EspCryptoRng {
    /// Obtain the RNG, or fail if no entropy source is currently active.
    ///
    /// Call this only after the BLE controller has been initialized —
    /// that is what makes the underlying RNG a true noise source.
    pub fn new() -> Result<Self, TrngError> {
        // The handle is dropped immediately; this is purely the gate check.
        Trng::try_new()?;
        Ok(Self { _private: () })
    }

    /// Re-acquire a validated TRNG handle, panicking if the entropy
    /// source has disappeared since construction.
    fn trng() -> Trng {
        match Trng::try_new() {
            Ok(trng) => trng,
            Err(e) => panic!(
                "crypto RNG used with no RF entropy source ({e:?}) — \
                 the BLE controller must stay alive while the RNG is in use"
            ),
        }
    }

    /// Fill `dest` with true-random bytes.
    ///
    /// # Panics
    ///
    /// Panics if the RF entropy source is no longer active. See the
    /// module documentation for why this is deliberate.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        Self::trng().read(dest);
    }
}

impl TryRng for EspCryptoRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(Self::trng().random())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let trng = Self::trng();
        Ok(u64::from(trng.random()) << 32 | u64::from(trng.random()))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        Self::trng().read(dest);
        Ok(())
    }
}

// Sound only because every read above goes through `Self::trng()`, which
// refuses to hand back a generator unless a physical noise source is
// actively being mixed in.
impl TryCryptoRng for EspCryptoRng {}
