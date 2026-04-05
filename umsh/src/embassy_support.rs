//! Embassy-friendly runtime adapters and fixed-capacity in-memory stores.

use core::convert::Infallible;
use core::{cell::RefCell, marker::PhantomData};

use embedded_hal_async::delay::DelayNs;
use heapless::Vec;
use rand::{CryptoRng, TryCryptoRng, TryRng};
use umsh_hal::{Clock, CounterStore, KeyValueStore};

#[cfg(feature = "software-crypto")]
use crate::{
    Platform,
    crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
};

/// [`DelayNs`] adapter backed by `embassy_time`.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmbassyDelay;

impl DelayNs for EmbassyDelay {
    async fn delay_ns(&mut self, ns: u32) {
        embassy_time::Timer::after_nanos(u64::from(ns)).await;
    }
}

/// Monotonic clock backed by `embassy_time::Instant`.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmbassyClock;

impl Clock for EmbassyClock {
    fn now_ms(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}

/// Adapter that preserves a concrete RNG type while forwarding `rand` traits.
pub struct RngCoreAdapter<R>(pub R);

impl<R: TryRng> TryRng for RngCoreAdapter<R> {
    type Error = R::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<R: TryCryptoRng> TryCryptoRng for RngCoreAdapter<R> {}

/// Tiny deterministic RNG useful for tests and examples.
#[derive(Clone, Copy, Debug)]
pub struct XorShift64Rng {
    state: u64,
}

impl XorShift64Rng {
    /// Create the RNG with a non-zero seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_word(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }
}

impl TryRng for XorShift64Rng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next_word() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next_word())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_word().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
        Ok(())
    }
}

/// Errors returned by the fixed-capacity memory stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryStoreError {
    Capacity,
    KeyTooLarge,
    ValueTooLarge,
    BufferTooSmall,
}

/// Fixed-capacity in-memory counter store.
pub struct MemoryCounterStore<const ENTRIES: usize, const KEY_LEN: usize> {
    entries: RefCell<Vec<(Vec<u8, KEY_LEN>, u32), ENTRIES>>,
}

impl<const ENTRIES: usize, const KEY_LEN: usize> Default for MemoryCounterStore<ENTRIES, KEY_LEN> {
    fn default() -> Self {
        Self {
            entries: RefCell::new(Vec::new()),
        }
    }
}

impl<const ENTRIES: usize, const KEY_LEN: usize> CounterStore
    for MemoryCounterStore<ENTRIES, KEY_LEN>
{
    type Error = MemoryStoreError;

    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error> {
        Ok(self
            .entries
            .borrow()
            .iter()
            .find(|(key, _)| key.as_slice() == context)
            .map(|(_, value)| *value)
            .unwrap_or(0))
    }

    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error> {
        let mut entries = self.entries.borrow_mut();
        if let Some((_, stored)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_slice() == context)
        {
            *stored = value;
            return Ok(());
        }
        let key = to_heapless_vec::<KEY_LEN>(context).map_err(|_| MemoryStoreError::KeyTooLarge)?;
        entries
            .push((key, value))
            .map_err(|_| MemoryStoreError::Capacity)
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Fixed-capacity in-memory key-value store.
pub struct MemoryKeyValueStore<const ENTRIES: usize, const KEY_LEN: usize, const VALUE_LEN: usize> {
    entries: RefCell<Vec<(Vec<u8, KEY_LEN>, Vec<u8, VALUE_LEN>), ENTRIES>>,
}

impl<const ENTRIES: usize, const KEY_LEN: usize, const VALUE_LEN: usize> Default
    for MemoryKeyValueStore<ENTRIES, KEY_LEN, VALUE_LEN>
{
    fn default() -> Self {
        Self {
            entries: RefCell::new(Vec::new()),
        }
    }
}

impl<const ENTRIES: usize, const KEY_LEN: usize, const VALUE_LEN: usize> KeyValueStore
    for MemoryKeyValueStore<ENTRIES, KEY_LEN, VALUE_LEN>
{
    type Error = MemoryStoreError;

    async fn load(&self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let entries = self.entries.borrow();
        let Some((_, value)) = entries
            .iter()
            .find(|(stored_key, _)| stored_key.as_slice() == key)
        else {
            return Ok(None);
        };
        if value.len() > buf.len() {
            return Err(MemoryStoreError::BufferTooSmall);
        }
        buf[..value.len()].copy_from_slice(value.as_slice());
        Ok(Some(value.len()))
    }

    async fn store(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        let mut entries = self.entries.borrow_mut();
        let value_vec =
            to_heapless_vec::<VALUE_LEN>(value).map_err(|_| MemoryStoreError::ValueTooLarge)?;
        if let Some((_, stored_value)) = entries
            .iter_mut()
            .find(|(stored_key, _)| stored_key.as_slice() == key)
        {
            *stored_value = value_vec;
            return Ok(());
        }
        let key_vec = to_heapless_vec::<KEY_LEN>(key).map_err(|_| MemoryStoreError::KeyTooLarge)?;
        entries
            .push((key_vec, value_vec))
            .map_err(|_| MemoryStoreError::Capacity)
    }

    async fn delete(&self, key: &[u8]) -> Result<(), Self::Error> {
        let mut entries = self.entries.borrow_mut();
        if let Some(index) = entries
            .iter()
            .position(|(stored_key, _)| stored_key.as_slice() == key)
        {
            entries.swap_remove(index);
        }
        Ok(())
    }
}

/// Convenience [`crate::Platform`] implementation for Embassy-style targets.
#[cfg(feature = "software-crypto")]
pub struct EmbassyPlatform<R, G, CS, KV>(PhantomData<(R, G, CS, KV)>);

#[cfg(feature = "software-crypto")]
impl<R, G, CS, KV> Platform for EmbassyPlatform<R, G, CS, KV>
where
    R: umsh_hal::Radio,
    G: CryptoRng,
    CS: CounterStore,
    KV: KeyValueStore,
{
    type Identity = SoftwareIdentity;
    type Aes = SoftwareAes;
    type Sha = SoftwareSha256;
    type Radio = R;
    type Delay = EmbassyDelay;
    type Clock = EmbassyClock;
    type Rng = G;
    type CounterStore = CS;
    type KeyValueStore = KV;
}

fn to_heapless_vec<const N: usize>(bytes: &[u8]) -> Result<Vec<u8, N>, ()> {
    let mut out = Vec::new();
    out.extend_from_slice(bytes).map_err(|_| ())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    };

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        fn raw_waker() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            fn wake(_: *const ()) {}
            fn wake_by_ref(_: *const ()) {}
            fn drop(_: *const ()) {}

            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
            RawWaker::new(core::ptr::null(), &VTABLE)
        }

        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut future = pin!(future);
        let mut context = Context::from_waker(&waker);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    #[test]
    fn memory_counter_store_round_trips() {
        let store = MemoryCounterStore::<4, 16>::default();
        assert_eq!(block_on_ready(store.load(b"peer")).unwrap(), 0);
        block_on_ready(store.store(b"peer", 9)).unwrap();
        assert_eq!(block_on_ready(store.load(b"peer")).unwrap(), 9);
    }

    #[test]
    fn memory_key_value_store_round_trips() {
        let store = MemoryKeyValueStore::<4, 16, 32>::default();
        block_on_ready(store.store(b"peer", b"value")).unwrap();
        let mut buf = [0u8; 32];
        let len = block_on_ready(store.load(b"peer", &mut buf))
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"value");
        block_on_ready(store.delete(b"peer")).unwrap();
        assert_eq!(block_on_ready(store.load(b"peer", &mut buf)).unwrap(), None);
    }
}
