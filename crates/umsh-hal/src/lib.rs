#![allow(async_fn_in_trait)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Minimal hardware abstraction traits used by the higher UMSH layers.
//!
//! This crate is intentionally independent from the rest of the workspace so
//! platform-specific radio or storage backends can depend on it without pulling
//! in the full protocol stack.

use core::num::NonZeroU8;
use core::task::{Context, Poll};

/// Signal-to-noise ratio represented in centibels (0.1 dB units).
///
/// This uses a slightly finer unit than whole decibels while still staying
/// compact and integer-friendly. Some common LoRa radios report SNR in
/// quarter-dB steps. Converting those readings into centibels requires
/// rounding, introducing at most 0.5 cB (0.05 dB) of error.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Snr(i16);

impl Snr {
    /// Construct an SNR value directly from centibels.
    pub const fn from_centibels(centibels: i16) -> Self {
        Self(centibels)
    }

    /// Construct an SNR value from whole decibels.
    pub const fn from_decibels(db: i8) -> Self {
        Self((db as i16) * 10)
    }

    /// Construct an SNR value from quarter-dB steps, rounding to the nearest
    /// centibel.
    pub const fn from_quarter_db_steps(steps: i16) -> Self {
        let scaled = steps * 25;
        let rounded = if scaled >= 0 {
            (scaled + 5) / 10
        } else {
            (scaled - 5) / 10
        };
        Self(rounded)
    }

    /// Return the stored value in centibels.
    pub const fn as_centibels(self) -> i16 {
        self.0
    }

    /// Return the stored value in decibels.
    pub const fn as_decibels(self) -> i16 {
        self.0 / 10
    }
}

impl core::fmt::Display for Snr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let db = self.as_decibels();
        let cdb = self.0 % 10;
        write!(f, "{}.{:01}dB", db, cdb)
    }
}

impl core::fmt::Debug for Snr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Snr({self})")
    }
}

/// Metadata returned with a received frame.
pub struct RxInfo {
    /// Number of bytes written into the receive buffer.
    pub len: usize,
    /// Received signal strength in dBm.
    pub rssi: i16,
    /// Signal-to-noise ratio in centibels.
    pub snr: Snr,
    /// Optional link-quality indicator in a radio-specific normalized scale.
    pub lqi: Option<NonZeroU8>,
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
    async fn transmit(
        &mut self,
        data: &[u8],
        options: TxOptions,
    ) -> Result<(), TxError<Self::Error>>;

    /// Poll reception of one frame into `buf`.
    ///
    /// `Poll::Pending` means no frame is currently available right now. The
    /// call does not reserve any receive state; a later poll after transmit
    /// completion can resume probing immediately.
    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<RxInfo, Self::Error>>;

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

/// Persistent peer directory for the node layer.
///
/// Stores and retrieves peer records keyed by the raw 32-byte Ed25519 public
/// key. `alias` is an optional UTF-8 label (the implementation may silently
/// truncate values longer than 16 bytes). Implementors MUST treat `store_peer`
/// as an upsert — calling it twice for the same key overwrites the record.
pub trait PeerStore {
    type Error;

    /// Upsert the peer record for `key`. `alias`, if present, is a UTF-8
    /// display label; passing `None` removes any existing alias.
    async fn store_peer(&self, key: &[u8; 32], alias: Option<&[u8]>) -> Result<(), Self::Error>;

    /// Remove the peer record for `key`. A no-op if the key is not present.
    async fn delete_peer(&self, key: &[u8; 32]) -> Result<(), Self::Error>;
}

/// No-op peer store — use when peer persistence is not needed.
pub struct NoPeerStore;

impl PeerStore for NoPeerStore {
    type Error = core::convert::Infallible;

    async fn store_peer(&self, _: &[u8; 32], _: Option<&[u8]>) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn delete_peer(&self, _: &[u8; 32]) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Persistent channel directory for the node layer.
///
/// Stores and retrieves shared channel keys keyed by channel name (UTF-8,
/// up to 16 bytes). Implementors MUST treat `store_channel` as an upsert.
pub trait ChannelStore {
    type Error;

    /// Upsert the channel record for `name`.
    async fn store_channel(&self, name: &[u8], key: &[u8; 32]) -> Result<(), Self::Error>;

    /// Remove the channel record for `name`. A no-op if not present.
    async fn delete_channel(&self, name: &[u8]) -> Result<(), Self::Error>;
}

/// No-op channel store — use when channel persistence is not needed.
pub struct NoChannelStore;

impl ChannelStore for NoChannelStore {
    type Error = core::convert::Infallible;

    async fn store_channel(&self, _: &[u8], _: &[u8; 32]) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn delete_channel(&self, _: &[u8]) -> Result<(), Self::Error> {
        Ok(())
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

/// Optional power-control hook for higher layers (e.g. the CLI).
///
/// Implementations request a controlled shutdown — the actual sequencing
/// (display, storage flush, GPIO sense, entering System OFF, etc.) lives
/// in the firmware that owns those peripherals. This call MUST return
/// promptly; it's typically a `Signal::signal(())` to a shutdown task.
pub trait PowerControl {
    fn request_power_off(&self);
}

/// No-op power control — use when shutdown is not implemented for the target.
pub struct NoPowerControl;

impl PowerControl for NoPowerControl {
    fn request_power_off(&self) {}
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
