//! Hardware randomness with an owned, non-sleeping RF entropy source.
//!
//! [`EspCryptoRng`] consumes the Bluetooth peripheral and initializes its own
//! controller with modem sleep disabled. Owning that controller keeps RF noise
//! active for the RNG's entire lifetime; dropping the RNG tears it down.
//! Safe code cannot share the peripheral with a sleep-enabled controller.
//!
//! The HAL entropy-source counter tracks controller initialization, not modem
//! sleep. Its per-read check is an additional safeguard, not the awake guarantee:
//! the privately owned controller provides that guarantee by construction.
//!
//! Trackers use this RNG only to harvest seeds for the persisted entropy pool
//! and software CSPRNGs. The bring-up console keeps it for the MAC's lifetime.
//! The SAR ADC entropy source is not used; the ADC belongs to battery sampling.

use core::convert::Infallible;

use esp_hal::{peripherals::BT, rng::Trng};
use esp_radio::ble::{Config, controller::BleConnector, controller::BleInitError};
use rand::{TryCryptoRng, TryRng};

/// Failure to establish the owned RF entropy source.
#[derive(Debug)]
pub enum RngError {
    Controller(BleInitError),
    Entropy(esp_hal::rng::TrngError),
}

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Controller(error) => write!(f, "BLE init: {error:?}"),
            Self::Entropy(error) => write!(f, "TRNG: {error:?}"),
        }
    }
}

impl core::error::Error for RngError {}

/// Hardware TRNG with exclusive ownership of its awake BLE controller.
///
/// Implements the synchronous `rand 0.10` cryptographic RNG traits. A borrowed
/// Bluetooth peripheral also bounds this RNG's lifetime, so a harvest must end
/// before the caller can reuse that peripheral for operational BLE.
pub struct EspCryptoRng<'d> {
    _controller: BleConnector<'d>,
}

impl<'d> EspCryptoRng<'d> {
    /// Initialize a non-sleeping controller and verify its entropy source.
    ///
    /// The radio scheduler and heap must already be initialized. Original
    /// ESP32 callers must also arbitrate ADC2 before calling this constructor.
    pub fn new(bt: BT<'d>) -> Result<Self, RngError> {
        let controller = BleConnector::new(bt, Config::default().with_modem_sleep(false))
            .map_err(RngError::Controller)?;
        Trng::try_new().map_err(RngError::Entropy)?;
        Ok(Self {
            _controller: controller,
        })
    }

    /// Recheck the source counter for every read as an additional safeguard.
    fn trng(&self) -> Trng {
        Trng::try_new().unwrap_or_else(|e| {
            panic!("owned RF entropy source disappeared ({e:?})—refusing crypto RNG output")
        })
    }

    /// Fill `dest` with true-random bytes while the owned controller is awake.
    ///
    /// Panics if the hardware entropy-source counter unexpectedly becomes inactive.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.trng().read(dest);
    }
}

impl TryRng for EspCryptoRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.trng().random())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let trng = self.trng();
        Ok(u64::from(trng.random()) << 32 | u64::from(trng.random()))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.trng().read(dest);
        Ok(())
    }
}

impl TryCryptoRng for EspCryptoRng<'_> {}
