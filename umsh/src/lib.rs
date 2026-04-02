//! Umbrella crate that re-exports the current UMSH workspace surface.

use embedded_hal_async::delay::DelayNs;

pub use umsh_core as core;
pub use umsh_crypto as crypto;
pub use umsh_hal as hal;
pub use umsh_mac as mac;

pub trait Platform {
    type Identity: umsh_crypto::NodeIdentity;
    type Aes: umsh_crypto::AesProvider;
    type Sha: umsh_crypto::Sha256Provider;
    type Radio: umsh_hal::Radio;
    type Delay: DelayNs;
    type Clock: umsh_hal::Clock;
    type Rng: umsh_hal::Rng;
    type CounterStore: umsh_hal::CounterStore;
    type KeyValueStore: umsh_hal::KeyValueStore;
}

#[cfg(feature = "software-crypto")]
pub mod test_vectors;

pub mod prelude {
    //! Convenience re-exports for the full public surface of the umbrella crate.

    pub use umsh_core::*;
    pub use umsh_crypto::*;
    pub use umsh_hal::*;
    pub use umsh_mac::*;
}
