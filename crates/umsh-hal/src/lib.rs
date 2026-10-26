#![allow(async_fn_in_trait)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Minimal hardware abstraction traits used by the higher UMSH layers.
//!
//! This crate is intentionally independent from the rest of the workspace so
//! platform-specific radio or storage backends can depend on it without pulling
//! in the full protocol stack.

use core::num::NonZeroU8;
use core::task::{Context, Poll};

#[cfg(feature = "embassy")]
mod embassy_clock;
#[cfg(feature = "embassy")]
pub use embassy_clock::EmbassyClock;

pub mod tz;
pub mod wall_clock;

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

    /// Return the stored value in quarter-dB steps, rounding to the nearest
    /// step—the form a peer-repeater entry reports.
    ///
    /// The rounding inverse of [`from_quarter_db_steps`](Self::from_quarter_db_steps):
    /// every value that came from a quarter-dB step returns that step.
    pub const fn as_quarter_db_steps(self) -> i16 {
        let scaled = self.0.saturating_mul(2);
        if scaled >= 0 {
            (scaled + 2) / 5
        } else {
            (scaled - 2) / 5
        }
    }
}

impl core::fmt::Display for Snr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let sign = if self.0 < 0 { "-" } else { "" };
        let magnitude = self.0.unsigned_abs();
        write!(f, "{sign}{}.{}dB", magnitude / 10, magnitude % 10)
    }
}

impl core::fmt::Debug for Snr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Snr({self})")
    }
}

/// Which of a node's bearers a frame crossed.
///
/// A bearer is a shared broadcast medium beside the node's radio, such as
/// an IP multicast group on the local network. A node numbers its own
/// bearers from zero; the number means nothing to any other node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BearerId(u8);

impl BearerId {
    /// How many bearers one node can number.
    pub const COUNT: usize = 8;

    /// The LAN multicast bearer, which every node that has one numbers
    /// first.
    pub const LAN: Self = Self(0);

    /// The bearer numbered `index`, if that is below [`Self::COUNT`].
    pub const fn new(index: u8) -> Option<Self> {
        if (index as usize) < Self::COUNT {
            Some(Self(index))
        } else {
            None
        }
    }

    /// This bearer's number.
    pub const fn index(self) -> u8 {
        self.0
    }
}

/// Where a received frame came from.
///
/// Only [`RxOrigin::Air`] carries real measurements. The others arrive
/// through paths with no radio in them, so their `rssi`, `snr`, and `lqi`
/// carry no information and must be reported as unmeasured wherever a
/// receiver would otherwise read them as a link quality.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RxOrigin {
    /// A reception off the air.
    #[default]
    Air,
    /// A copy of a frame this device just transmitted.
    LocalTx,
    /// A frame handed over by an attached host across a point-to-point link.
    Backhaul,
    /// A frame received from a shared broadcast bearer, heard by every
    /// node attached to it.
    Bearer(BearerId),
}

impl RxOrigin {
    /// Whether the accompanying signal fields are measurements.
    pub const fn is_measured(self) -> bool {
        matches!(self, Self::Air)
    }

    /// The bearer this frame arrived on, if it arrived on one.
    pub const fn bearer(self) -> Option<BearerId> {
        match self {
            Self::Bearer(bearer) => Some(bearer),
            _ => None,
        }
    }
}

/// Buffered-delivery metadata for a frame replayed from a device's inbound
/// queue rather than received live.
///
/// The signal fields in the enclosing [`RxInfo`] are still the measurements
/// taken when the frame originally arrived off the air; only the delivery is
/// delayed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxBuffered {
    /// Seconds the frame spent queued before delivery.
    pub age_s: u32,
    /// Whether the queueing device already acknowledged the frame on the
    /// host's behalf.
    pub acked: bool,
}

/// Metadata returned with a received frame.
#[derive(Clone, Copy)]
pub struct RxInfo {
    /// Number of bytes written into the receive buffer.
    pub len: usize,
    /// Received signal strength in dBm.
    pub rssi: i16,
    /// Signal-to-noise ratio in centibels.
    pub snr: Snr,
    /// Optional link-quality indicator in a radio-specific normalized scale.
    pub lqi: Option<NonZeroU8>,
    /// The path this frame took to reach the receiver.
    pub origin: RxOrigin,
    /// Present when the frame was replayed from an inbound queue.
    pub buffered: Option<RxBuffered>,
}

/// Channel-activity-detection (CAD) policy applied before a transmit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CadPolicy {
    /// Skip CAD entirely and transmit immediately.
    #[default]
    Skip,
    /// Perform CAD once and transmit only if the channel is currently clear.
    /// Equivalent to a retry budget of zero.
    Gate,
    /// Retry CAD until the channel is clear or `timeout_ms` elapses.
    RetryFor { timeout_ms: u32 },
}

/// Options controlling how a frame is transmitted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxOptions {
    /// Channel-activity-detection policy applied before this transmit.
    pub cad: CadPolicy,
    /// This frame's transmit power in dBm, raised to the least the radio
    /// can transmit; `None` sends at the configured power.
    pub power_dbm: Option<i8>,
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

    /// The LoRa spreading factor this radio is currently receiving with,
    /// when it knows.
    ///
    /// The spreading factor alone sets the SNR a LoRa receiver can
    /// demodulate down to, so it is what turns a measured SNR into a
    /// margin. A radio that is not LoRa, or that does not know how its
    /// far end is configured, reports `None`.
    fn spreading_factor(&self) -> Option<u8> {
        None
    }
}

/// Monotonic millisecond clock.
pub trait Clock {
    /// Return milliseconds since the device booted.
    ///
    /// Most of the stack only ever takes differences and would be happy
    /// with any monotonic epoch, but `PROP_UPTIME` reports this value
    /// directly, so the epoch is part of the contract: an implementation
    /// backed by a clock that starts somewhere else MUST subtract its own
    /// origin. A simulated device that emulates a reboot has to restart
    /// this along with the rest of the hardware.
    fn now_ms(&self) -> u64;

    /// Poll a delay that completes when the monotonic clock reaches `deadline_ms`.
    ///
    /// Returns `Poll::Ready(())` if the deadline has already passed. Otherwise
    /// the implementation MUST register `cx.waker()` with a platform timer and
    /// return `Poll::Pending`, so the task is woken when the deadline elapses.
    ///
    /// The default implementation has no real timer: it schedules an immediate
    /// re-poll (via `cx.waker().wake_by_ref()`) and returns `Poll::Pending`, causing
    /// the caller to busy-poll until the monotonic clock reaches the deadline.
    /// This is correct but wastes CPU; platform clocks backed by a real timer
    /// (tokio, embassy, etc.) MUST override this to sleep efficiently. A default
    /// that returned `Ready` unconditionally would spin just as hard; one that
    /// returned `Pending` without waking would stall timer-driven work entirely.
    fn poll_delay_until(&self, cx: &mut Context<'_>, deadline_ms: u64) -> Poll<()> {
        let _ = deadline_ms;
        cx.waker().wake_by_ref();
        Poll::Pending
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

/// No-op counter store—counters restart from zero every boot.
///
/// Use only where counter persistence is not (yet) load-bearing: a node
/// that sends nothing but unsecured broadcasts, or a bring-up stage whose
/// durable store lands later. Reusing TX counters after a reboot breaks
/// replay protection for secured traffic.
pub struct NoCounterStore;

impl CounterStore for NoCounterStore {
    type Error = core::convert::Infallible;

    async fn load(&self, _: &[u8]) -> Result<u32, Self::Error> {
        Ok(0)
    }

    async fn store(&self, _: &[u8], _: u32) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
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

/// No-op key-value store—loads find nothing, stores succeed silently.
/// Use when a platform bundle needs the associated type but nothing in
/// the deployment reads cached state back.
pub struct NoKeyValueStore;

impl KeyValueStore for NoKeyValueStore {
    type Error = core::convert::Infallible;

    async fn load(&self, _: &[u8], _: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(None)
    }

    async fn store(&self, _: &[u8], _: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn delete(&self, _: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Snr;

    /// The wire form of an SNR in a peer-repeater entry is quarter-dB
    /// steps, so a value that arrived as one has to leave as the same one
    ///—otherwise relaying an observation would drift it a step at a
    /// time.
    #[test]
    fn quarter_db_steps_round_trip_through_centibels() {
        for steps in -128..=127i16 {
            assert_eq!(
                Snr::from_quarter_db_steps(steps).as_quarter_db_steps(),
                steps,
                "steps {steps}"
            );
        }
    }

    #[test]
    fn quarter_db_steps_round_to_the_nearest_step() {
        assert_eq!(Snr::from_decibels(0).as_quarter_db_steps(), 0);
        assert_eq!(Snr::from_decibels(5).as_quarter_db_steps(), 20);
        assert_eq!(Snr::from_decibels(-7).as_quarter_db_steps(), -28);
        // 0.3 dB sits between the first and second step and rounds up.
        assert_eq!(Snr::from_centibels(3).as_quarter_db_steps(), 1);
    }

    #[test]
    fn display_keeps_the_sign_off_the_fraction() {
        extern crate std;
        use std::format;

        assert_eq!(format!("{}", Snr::from_centibels(25)), "2.5dB");
        assert_eq!(format!("{}", Snr::from_centibels(0)), "0.0dB");
        assert_eq!(format!("{}", Snr::from_centibels(-5)), "-0.5dB");
        assert_eq!(format!("{}", Snr::from_centibels(-15)), "-1.5dB");
        assert_eq!(format!("{}", Snr::from_centibels(-100)), "-10.0dB");
        assert_eq!(format!("{}", Snr::from_centibels(i16::MIN)), "-3276.8dB");
    }
}
