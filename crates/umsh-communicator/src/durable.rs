//! Where a store keeps its records beyond its own memory.

use crate::record::StoreError;

/// What a [`MemoryStore`](crate::MemoryStore) keeps its records in beyond
/// its own memory.
///
/// The store hands each record it changes to the layer, encoded and under
/// its own key, at the end of every step of a commit and of every other
/// change. What the layer keeps therefore follows the commit order, and
/// power lost partway through leaves it where the commit order says is
/// safe. Mounting reads every record back.
pub trait Durable {
    /// Whether anything is kept. A store over a layer that keeps nothing
    /// encodes nothing.
    const KEEPS: bool;

    /// Keep `record` under `key`, in place of what was kept there, or
    /// forget `key` when `record` is `None`.
    fn write(&mut self, key: &[u8], record: Option<&[u8]>) -> Result<(), StoreError>;

    /// Every record kept, each under its key.
    fn read(&mut self, each: &mut dyn FnMut(&[u8], &[u8])) -> Result<(), StoreError>;

    /// Forget everything kept.
    fn clear(&mut self) -> Result<(), StoreError>;
}

/// Keeps nothing: the store's memory is all there is.
#[derive(Clone, Copy, Debug, Default)]
pub struct Volatile;

impl Durable for Volatile {
    const KEEPS: bool = false;

    fn write(&mut self, _key: &[u8], _record: Option<&[u8]>) -> Result<(), StoreError> {
        Ok(())
    }

    fn read(&mut self, _each: &mut dyn FnMut(&[u8], &[u8])) -> Result<(), StoreError> {
        Ok(())
    }

    fn clear(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
}

/// A durable layer, or none when the layer could not be had: storage
/// that fails even to be cleared. A store over [`MaybeKept::Volatile`]
/// works as one in memory, and its chats last until power is lost.
#[derive(Debug)]
pub enum MaybeKept<D> {
    Kept(D),
    Volatile,
}

impl<D> MaybeKept<D> {
    /// Whether what the store holds outlasts a power cycle.
    pub fn is_kept(&self) -> bool {
        matches!(self, Self::Kept(_))
    }
}

impl<D: Durable> Durable for MaybeKept<D> {
    const KEEPS: bool = D::KEEPS;

    fn write(&mut self, key: &[u8], record: Option<&[u8]>) -> Result<(), StoreError> {
        match self {
            Self::Kept(durable) => durable.write(key, record),
            Self::Volatile => Ok(()),
        }
    }

    fn read(&mut self, each: &mut dyn FnMut(&[u8], &[u8])) -> Result<(), StoreError> {
        match self {
            Self::Kept(durable) => durable.read(each),
            Self::Volatile => Ok(()),
        }
    }

    fn clear(&mut self) -> Result<(), StoreError> {
        match self {
            Self::Kept(durable) => durable.clear(),
            Self::Volatile => Ok(()),
        }
    }
}
