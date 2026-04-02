//! Umbrella crate that re-exports the current UMSH workspace surface.

pub use umsh_core as core;
pub use umsh_crypto as crypto;
pub use umsh_hal as hal;

#[cfg(feature = "software-crypto")]
pub mod test_vectors;

pub mod prelude {
    //! Convenience re-exports for the full public surface of the umbrella crate.

    pub use umsh_core::*;
    pub use umsh_crypto::*;
    pub use umsh_hal::*;
}
