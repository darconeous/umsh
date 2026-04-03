#![allow(async_fn_in_trait)]

#![cfg_attr(not(feature = "std"), no_std)]

//! Minimal hardware abstraction traits used by the higher UMSH layers.
//!
//! This crate is intentionally independent from the rest of the workspace so
//! platform-specific radio or storage backends can depend on it without pulling
//! in the full protocol stack.

/// Metadata returned with a received frame.
pub struct RxInfo {
    /// Number of bytes written into the receive buffer.
    pub len: usize,
    /// Received signal strength in dBm.
    pub rssi: i16,
    /// Signal-to-noise ratio in dB.
    pub snr: i8,
}

/// Half-duplex radio abstraction used by the MAC coordinator.
pub trait Radio {
    type Error;

    /// Transmit a complete raw UMSH frame.
    async fn transmit(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    /// Receive one frame into `buf`.
    async fn receive(&mut self, buf: &mut [u8]) -> Result<RxInfo, Self::Error>;
    /// Perform channel-activity detection.
    async fn cad(&mut self) -> Result<bool, Self::Error>;
    /// Return the largest supported raw frame size.
    fn max_frame_size(&self) -> usize;
    /// Return the approximate airtime for a maximum-length frame.
    fn t_frame_ms(&self) -> u32;
}

/// Monotonic millisecond clock.
pub trait Clock {
    /// Return milliseconds since an arbitrary monotonic epoch.
    fn now_ms(&self) -> u64;
}

/// Persistent frame-counter storage.
pub trait CounterStore {
    type Error;

    /// Load the stored counter for `context`, or `0` if missing.
    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error>;
    /// Persist a counter value for `context`.
    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error>;
    /// Flush any buffered state to durable storage.
    async fn flush(&self) -> Result<(), Self::Error>;
}

/// Persistent key-value store used by higher layers for cached state.
pub trait KeyValueStore {
    type Error;

    /// Load a value into `buf`, returning the stored length when present.
    async fn load(&self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error>;
    /// Store a value for `key`.
    async fn store(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
    /// Delete any stored value for `key`.
    async fn delete(&self, key: &[u8]) -> Result<(), Self::Error>;
}
