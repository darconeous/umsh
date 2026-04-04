#![allow(async_fn_in_trait)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Minimal hardware abstraction traits used by the higher UMSH layers.
//!
//! This crate is intentionally independent from the rest of the workspace so
//! platform-specific radio or storage backends can depend on it without pulling
//! in the full protocol stack.

use core::task::{Context, Poll};

/// Metadata returned with a received frame.
pub struct RxInfo {
    /// Number of bytes written into the receive buffer.
    pub len: usize,
    /// Received signal strength in dBm.
    pub rssi: i16,
    /// Signal-to-noise ratio in dB.
    pub snr: i8,
}

/// Options controlling how a frame is transmitted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxOptions {
    /// Carrier-activity detection policy applied before transmit.
    ///
    /// `None` skips CAD and transmits immediately.
    /// `Some(0)` performs an immediate CAD gate and only transmits if the
    /// channel is currently clear.
    /// `Some(n)` retries CAD until it succeeds or the timeout budget expires.
    pub cad_timeout_ms: Option<u32>,
}

/// Error returned by [`Radio::transmit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxError<E> {
    /// CAD did not find the channel clear before the timeout expired.
    CadTimeout,
    /// Platform-specific radio or transport failure.
    Io(E),
}

/// Half-duplex radio abstraction used by the MAC coordinator.
pub trait Radio {
    type Error;

    /// Transmit a complete raw UMSH frame.
    async fn transmit(&mut self, data: &[u8], options: TxOptions) -> Result<(), TxError<Self::Error>>;

    /// Poll reception of one frame into `buf`.
    ///
    /// `Poll::Pending` means no frame is currently available right now. The
    /// call does not reserve any receive state; a later poll after transmit
    /// completion can resume probing immediately.
    fn poll_receive(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<RxInfo, Self::Error>>;

    /// Return the largest supported raw frame size.
    fn max_frame_size(&self) -> usize;
    /// Return the approximate airtime for a maximum-length frame.
    fn t_frame_ms(&self) -> u32;
}

/// Monotonic millisecond clock.
pub trait Clock {
    /// Return milliseconds since an arbitrary monotonic epoch.
    fn now_ms(&self) -> u64;

    /// Poll a delay that completes when the monotonic clock reaches `deadline_ms`.
    ///
    /// Returns `Poll::Ready(())` if the deadline has already passed.  Otherwise
    /// the implementation should register `cx.waker()` with a platform timer and
    /// return `Poll::Pending`.
    ///
    /// The default implementation returns `Ready(())` immediately, which causes
    /// callers to busy-poll on timer deadlines.  Platform clocks backed by a
    /// real timer (tokio, embassy, etc.) should override this.
    fn poll_delay_until(&self, cx: &mut Context<'_>, deadline_ms: u64) -> Poll<()> {
        let _ = (cx, deadline_ms);
        Poll::Ready(())
    }
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
