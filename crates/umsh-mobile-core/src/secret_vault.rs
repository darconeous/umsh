//! The platform's custody of secrets the store must never hold.
//!
//! Channel keys are group membership, so they live in the platform's
//! protected storage (the Keychain on iOS, Keystore-wrapped files on
//! Android) under the channel's ID, and the store keeps only public
//! metadata.

use std::fmt;

/// Why the vault could not do what it was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum SecretVaultError {
    /// Protected data cannot be read yet: the device has not been unlocked
    /// since it started, or the vault has not finished preparing its
    /// storage. A later call may succeed.
    Unavailable,
    /// The platform refused the operation.
    Failed,
}

impl fmt::Display for SecretVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "secret vault unavailable",
            Self::Failed => "secret vault failed",
        })
    }
}

impl std::error::Error for SecretVaultError {}

/// A throw the platform did not declare is a failure, never a panic.
impl From<uniffi::UnexpectedUniFFICallbackError> for SecretVaultError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed
    }
}

/// The platform's secret storage, for channel keys.
///
/// An account is a channel's ID in uppercase hyphenated form; the vault
/// compares accounts without regard to case. Every call is synchronous and
/// made on the caller's thread, never while the core holds a lock, and an
/// implementation must not hop to another thread to answer it.
#[uniffi::export(with_foreign)]
pub trait SecretVault: Send + Sync {
    /// The secret filed under `account`, or none when there is none.
    /// `Unavailable` when the vault cannot tell, which is never the same
    /// as having none.
    fn load(&self, account: String) -> Result<Option<Vec<u8>>, SecretVaultError>;

    /// File `secret` under `account`, replacing what was there.
    fn store(&self, account: String, secret: Vec<u8>) -> Result<(), SecretVaultError>;

    /// Forget the secret under `account`. Forgetting one that is not there
    /// succeeds.
    fn delete(&self, account: String) -> Result<(), SecretVaultError>;

    /// Forget every secret the vault holds, including any whose channel the
    /// store no longer lists.
    fn delete_all(&self) -> Result<(), SecretVaultError>;
}

/// A vault in memory, for tests.
#[cfg(test)]
pub(crate) mod memory {
    use std::{
        collections::BTreeMap,
        sync::{
            Mutex, PoisonError,
            atomic::{AtomicBool, Ordering},
        },
    };

    use super::{SecretVault, SecretVaultError};

    #[derive(Default)]
    pub(crate) struct MemoryVault {
        secrets: Mutex<BTreeMap<String, Vec<u8>>>,
        /// Loads answer `Unavailable`, as a vault does before the first
        /// unlock.
        locked: AtomicBool,
        /// Every call answers `Unavailable`, as a vault whose store is not
        /// open at all.
        unavailable: AtomicBool,
    }

    impl MemoryVault {
        pub(crate) fn set_locked(&self, locked: bool) {
            self.locked.store(locked, Ordering::SeqCst);
        }

        pub(crate) fn set_unavailable(&self, unavailable: bool) {
            self.unavailable.store(unavailable, Ordering::SeqCst);
        }

        fn refuses(&self) -> Result<(), SecretVaultError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(SecretVaultError::Unavailable);
            }
            Ok(())
        }

        pub(crate) fn accounts(&self) -> Vec<String> {
            self.secrets().keys().cloned().collect()
        }

        fn secrets(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> {
            self.secrets.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl SecretVault for MemoryVault {
        fn load(&self, account: String) -> Result<Option<Vec<u8>>, SecretVaultError> {
            self.refuses()?;
            if self.locked.load(Ordering::SeqCst) {
                return Err(SecretVaultError::Unavailable);
            }
            Ok(self.secrets().get(&account.to_uppercase()).cloned())
        }

        fn store(&self, account: String, secret: Vec<u8>) -> Result<(), SecretVaultError> {
            self.refuses()?;
            self.secrets().insert(account.to_uppercase(), secret);
            Ok(())
        }

        fn delete(&self, account: String) -> Result<(), SecretVaultError> {
            self.refuses()?;
            self.secrets().remove(&account.to_uppercase());
            Ok(())
        }

        fn delete_all(&self) -> Result<(), SecretVaultError> {
            self.refuses()?;
            self.secrets().clear();
            Ok(())
        }
    }
}
