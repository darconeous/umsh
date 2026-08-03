//! The radio a participant fronts, and the loop that relays frames
//! between it and one queue in each direction.
//!
//! Both roles use this: a client's whole job is this relay, and the
//! server runs one for its own radio alongside its forwarding engine.
//!
//! Attachment follows the spec's [Radio Attachment] rules — a tethered,
//! non-resetting attach with `PROP_MAC_PROMISCUOUS` set, re-asserted
//! after every reconnection because the property is session-scoped —
//! and transmits are confirmed, never `TX_FLAG_NODUTY`.
//!
//! [Radio Attachment]: https://darconeous.github.io/umsh/docs/protocol/internet-bridging.html#radio-attachment

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use tokio::time::Instant;
use umsh::ulcp::{RawRxFrame, UlcpError};
use umsh_hal::TxError;

// Only the two ULCP transports attach, advertise capabilities, or have
// a promiscuous flag to set; a build with neither is fake-radio only.
#[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
use umsh::ulcp::{UlcpDevice, UlcpDeviceConfig};
#[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
use umsh_ulcp::ids::{cap, prop};

use crate::config::RadioConfig;
use crate::tunnel::{Dequeued, TunnelFrame, TunnelQueue};
use crate::udp_radio::UdpFakeRadio;

/// How long to wait before re-opening a device that failed. A radio
/// unplugged and plugged back in should come back on its own, and a
/// radio that is simply gone should not spin the CPU about it.
const REOPEN_DELAY: Duration = Duration::from_secs(3);

/// Channel-access retry pacing. The first re-offer comes quickly, since
/// a channel busy with one neighbour's frame clears within a frame time,
/// and the interval then grows so that a genuinely congested segment is
/// not answered with a stream of command traffic.
const CCA_BACKOFF_MIN: Duration = Duration::from_millis(50);
const CCA_BACKOFF_MAX: Duration = Duration::from_millis(1_000);

/// The RF parameters carried by a device configuration are applied only
/// by the resetting attach, which a bridge never performs: radio
/// configuration is local to each participant and the device keeps
/// whatever it was set up with. These values are therefore inert, and
/// exist because the constructor asks for them.
#[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
fn attach_config() -> UlcpDeviceConfig {
    UlcpDeviceConfig::new(910_525, 62_500, 7, 5)
}

/// What a `PROP_MAC_PROMISCUOUS` set means for the bridge.
#[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
fn promiscuous_outcome(result: Result<Vec<u8>, UlcpError>) -> Result<()> {
    match result {
        Ok(_) => {
            tracing::debug!("promiscuous delivery enabled");
            Ok(())
        }
        // A device that predates the property refuses the set. It still
        // relays whatever its own filtering admits, which is a degraded
        // bridge rather than a broken one.
        Err(UlcpError::Status(status)) => {
            tracing::warn!(
                ?status,
                "device refused promiscuous delivery; this interface carries only what the \
                 device's own receive filtering admits"
            );
            Ok(())
        }
        Err(error) => Err(anyhow!("enabling promiscuous delivery: {error:?}")),
    }
}

/// A ULCP device, or the fake radio that stands in for one.
///
/// The two ULCP transports are separate types rather than a trait
/// object because `UlcpDevice` is generic over its link and its receive
/// path is a `poll` function, not an `async fn` — which is exactly what
/// lets the relay poll a receive and a transmit from the same `&mut`
/// without holding a borrow across an await.
enum Device {
    #[cfg(feature = "serial-radio")]
    Serial(UlcpDevice<umsh::ulcp::SerialFrameLink<tokio_serial::SerialStream>>),
    #[cfg(feature = "ble-radio")]
    Ble(Box<UlcpDevice<umsh::ulcp::BleFrameLink>>),
    Udp(UdpFakeRadio),
}

macro_rules! with_device {
    ($self:expr, $device:ident => $body:expr) => {
        match $self {
            #[cfg(feature = "serial-radio")]
            Device::Serial($device) => $body,
            #[cfg(feature = "ble-radio")]
            Device::Ble($device) => $body,
            Device::Udp($device) => $body,
        }
    };
}

impl Device {
    async fn open(config: &RadioConfig) -> Result<Self> {
        match config {
            #[cfg(feature = "serial-radio")]
            RadioConfig::Serial { port, baud } => {
                let link = open_serial_link(port, *baud).await?;
                let device = UlcpDevice::attach_existing(link, attach_config())
                    .await
                    .map_err(|error| anyhow!("attaching to {port}: {error:?}"))?;
                Ok(Self::Serial(device))
            }
            #[cfg(not(feature = "serial-radio"))]
            RadioConfig::Serial { .. } => {
                bail!("this build has no serial support; rebuild with --features serial-radio")
            }
            #[cfg(feature = "ble-radio")]
            RadioConfig::Ble { selector } => {
                // Connect and attach separately rather than through
                // `open_ble`, which resets the device: a bridge attaches
                // to a radio that is already operating and must not
                // disturb its configuration.
                let link = umsh::ulcp::BleFrameLink::connect(
                    selector.as_deref(),
                    umsh::ulcp::BleFrameLinkConfig::default(),
                )
                .await
                .map_err(|error| anyhow!("connecting over BLE: {error:?}"))?;
                let device = UlcpDevice::attach_existing(link, attach_config())
                    .await
                    .map_err(|error| anyhow!("attaching over BLE: {error:?}"))?;
                Ok(Self::Ble(Box::new(device)))
            }
            #[cfg(not(feature = "ble-radio"))]
            RadioConfig::Ble { .. } => {
                bail!("this build has no BLE support; rebuild with --features ble-radio")
            }
            RadioConfig::UdpMulticast {
                group,
                port,
                rssi,
                snr,
            } => Ok(Self::Udp(
                UdpFakeRadio::bind(*group, *port, *rssi, *snr).await?,
            )),
            RadioConfig::None => bail!("no radio is configured"),
        }
    }

    /// Everything the spec asks of a bridge's attachment, in one place
    /// so a reconnection cannot forget any of it.
    async fn prepare(&mut self) -> Result<()> {
        let transmits = self.can_transmit().await?;
        if !transmits {
            // Not fatal: a receive-only interface still feeds the rest
            // of the bridge, and saying so once is more useful than
            // refusing to start.
            tracing::warn!(
                "device does not advertise CAP_WRITABLE_RAW_STREAM; this interface can receive \
                 but not transmit"
            );
        }
        self.set_promiscuous().await
    }

    async fn can_transmit(&mut self) -> Result<bool> {
        match self {
            #[cfg(feature = "serial-radio")]
            Self::Serial(device) => Ok(device
                .capabilities()
                .await
                .map_err(|error| anyhow!("reading device capabilities: {error:?}"))?
                .contains(&cap::WRITABLE_RAW_STREAM)),
            #[cfg(feature = "ble-radio")]
            Self::Ble(device) => Ok(device
                .capabilities()
                .await
                .map_err(|error| anyhow!("reading device capabilities: {error:?}"))?
                .contains(&cap::WRITABLE_RAW_STREAM)),
            Self::Udp(_) => Ok(true),
        }
    }

    /// A bridge sees frames addressed to everyone, so a device with a
    /// provisioned host domain must be told to stop filtering. The
    /// property is session-scoped, which is why this runs on every
    /// attach rather than once at provisioning time.
    async fn set_promiscuous(&mut self) -> Result<()> {
        match self {
            #[cfg(feature = "serial-radio")]
            Self::Serial(device) => {
                promiscuous_outcome(device.set_prop(prop::MAC_PROMISCUOUS, &[1]).await)
            }
            #[cfg(feature = "ble-radio")]
            Self::Ble(device) => {
                promiscuous_outcome(device.set_prop(prop::MAC_PROMISCUOUS, &[1]).await)
            }
            // The fake radio has no filtering to bypass.
            Self::Udp(_) => Ok(()),
        }
    }

    fn poll_receive_raw(&mut self, cx: &mut Context<'_>) -> Poll<Result<RawRxFrame, UlcpError>> {
        with_device!(self, device => device.poll_receive_raw(cx))
    }

    async fn transmit(&mut self, frame: &TunnelFrame) -> Result<(), TxError<UlcpError>> {
        with_device!(self, device => device
            .transmit_raw_with_meta(&frame.data, &frame.metadata)
            .await)
    }

    fn max_frame_size(&self) -> usize {
        // `UlcpDevice` reports it through the `Radio` trait; the fake
        // radio has it inherently.
        #[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
        use umsh_hal::Radio as _;

        with_device!(self, device => device.max_frame_size())
    }
}

#[cfg(feature = "serial-radio")]
async fn open_serial_link(
    port: &str,
    baud: u32,
) -> Result<umsh::ulcp::SerialFrameLink<tokio_serial::SerialStream>> {
    use anyhow::Context as _;
    use tokio_serial::SerialPortBuilderExt as _;

    let stream = tokio_serial::new(port, baud)
        .open_native_async()
        .with_context(|| format!("opening {port}"))?;
    Ok(umsh::ulcp::SerialFrameLink::new(stream))
}

/// The channel-access retry schedule for one frame.
///
/// Separated from the relay so the policy can be exercised without a
/// radio: it is pure arithmetic over the clock, and the relay only asks
/// it how long to wait next.
struct CcaBackoff {
    deadline: Instant,
    next: Duration,
}

impl CcaBackoff {
    fn new(budget: Duration) -> Self {
        Self {
            deadline: Instant::now() + budget,
            next: CCA_BACKOFF_MIN,
        }
    }

    /// How long to wait before offering the frame again, or `None` when
    /// the budget is spent and the frame should be given up on.
    ///
    /// A zero budget yields `None` on the first ask, which is the single
    /// attempt a segment with no other traffic wants.
    fn next_wait(&mut self) -> Option<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let wait = jittered(self.next).min(remaining);
        self.next = (self.next * 2).min(CCA_BACKOFF_MAX);
        Some(wait)
    }
}

/// Spread each wait across the upper half of its interval.
///
/// Two bridges backing off from the same busy channel must not converge
/// on one retry instant, and the tunnel's additive reconnect jitter is
/// the wrong shape for that — here the randomness has to be a meaningful
/// fraction of the wait itself, while still guaranteeing the interval
/// grows.
fn jittered(backoff: Duration) -> Duration {
    let millis = backoff.as_millis() as u64;
    Duration::from_millis(millis / 2 + rand::random_range(0..=millis / 2))
}

/// One interface's two queues, from the relay's point of view.
pub struct DeviceRelay {
    config: RadioConfig,
    /// Frames the device received, for whoever consumes this interface.
    inbound: Arc<TunnelQueue>,
    /// Frames to put on the air.
    outbound: Arc<TunnelQueue>,
    /// How long a frame refused for a busy channel keeps being offered.
    cca_retry: Duration,
}

impl DeviceRelay {
    pub fn new(
        config: RadioConfig,
        inbound: Arc<TunnelQueue>,
        outbound: Arc<TunnelQueue>,
        cca_retry: Duration,
    ) -> Self {
        Self {
            config,
            inbound,
            outbound,
            cca_retry,
        }
    }

    /// Keep a device attached and relaying for as long as the process
    /// runs, re-opening it after a failure.
    ///
    /// A device outage leaves no backlog to drain — promiscuous-only
    /// frames are never queued while the host is detached — so a fresh
    /// attachment starts clean by construction and this loop needs no
    /// reconciliation of its own.
    pub async fn run(&self) -> ! {
        loop {
            match self.session().await {
                Ok(()) => tracing::warn!(radio = %self.config.describe(), "device link ended"),
                Err(error) => {
                    tracing::warn!(radio = %self.config.describe(), "device: {error:#}");
                }
            }
            // Whatever was queued for a device that is no longer there
            // is as stale as anything queued for a dead tunnel.
            self.outbound.clear();
            tokio::time::sleep(REOPEN_DELAY).await;
        }
    }

    async fn session(&self) -> Result<()> {
        let mut device = Device::open(&self.config).await?;
        device.prepare().await?;
        let max_frame_size = device.max_frame_size();
        tracing::info!(
            radio = %self.config.describe(),
            max_frame_size,
            "radio attached"
        );

        let generation = self.outbound.generation();
        loop {
            // The device is borrowed only for the duration of this
            // poll; the transmit below re-borrows it after the borrow
            // has ended, which is what keeps both directions on one
            // `&mut` without a `select!` borrow conflict.
            let event = {
                let device = &mut device;
                core::future::poll_fn(|cx| {
                    // Reception first: a frame not taken from the device
                    // is a frame the device may have to drop.
                    if let Poll::Ready(result) = device.poll_receive_raw(cx) {
                        return Poll::Ready(Event::Received(result));
                    }
                    match self.outbound.poll_pop(generation, cx) {
                        Poll::Ready(Dequeued::Frame(frame)) => Poll::Ready(Event::Send(frame)),
                        Poll::Ready(Dequeued::SessionEnded) => Poll::Ready(Event::Ended),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await
            };

            match event {
                Event::Ended => return Ok(()),
                Event::Received(Err(error)) => {
                    return Err(anyhow!("receiving from the device: {error:?}"));
                }
                Event::Received(Ok(raw)) => self.accept(raw),
                Event::Send(frame) => {
                    if frame.data.len() > max_frame_size {
                        tracing::debug!(
                            len = frame.data.len(),
                            max_frame_size,
                            "dropping a frame larger than this radio can transmit"
                        );
                        continue;
                    }
                    self.transmit(&mut device, &frame).await?;
                }
            }
        }
    }

    /// Put one frame on the air, offering it again for as long as the
    /// radio reports the channel busy.
    ///
    /// ULCP carries no retry count, so one `CMD_STR_SEND` buys exactly
    /// one channel-access attempt: a device that finds the channel busy
    /// answers `STATUS_CCA_FAILURE` straight away, and the only way to
    /// try again is for the host to offer the frame again. That makes
    /// persistence the bridge's job rather than the radio's.
    async fn transmit(&self, device: &mut Device, frame: &TunnelFrame) -> Result<()> {
        let mut backoff = CcaBackoff::new(self.cca_retry);
        let mut attempts = 0u32;

        loop {
            attempts += 1;
            match device.transmit(frame).await {
                Ok(()) => {
                    if attempts > 1 {
                        tracing::debug!(attempts, "device tx, after waiting out a busy channel");
                    } else {
                        tracing::trace!(len = frame.data.len(), "device tx");
                    }
                    return Ok(());
                }
                Err(TxError::CadTimeout) => {
                    let Some(wait) = backoff.next_wait() else {
                        tracing::warn!(
                            attempts,
                            len = frame.data.len(),
                            "dropped a frame: the channel stayed busy for the whole retry budget"
                        );
                        return Ok(());
                    };
                    self.listen_during(device, wait).await?;
                }
                // A spent duty budget is the device doing its job, and
                // unlike a busy channel it is not worth re-offering:
                // the budget replenishes over minutes, not milliseconds.
                Err(TxError::Io(UlcpError::Status(status))) => {
                    tracing::debug!(?status, "device refused a transmit");
                    return Ok(());
                }
                Err(error) => bail!("transmitting: {error:?}"),
            }
        }
    }

    /// Wait out a backoff without going deaf.
    ///
    /// Reception cannot pause while the relay waits for the channel: a
    /// frame left sitting in the device is a frame the device may have
    /// to drop, so a busy channel would otherwise cost inbound traffic
    /// on top of the outbound frame it is already delaying.
    async fn listen_during(&self, device: &mut Device, wait: Duration) -> Result<()> {
        let sleep = tokio::time::sleep(wait);
        tokio::pin!(sleep);

        core::future::poll_fn(|cx| {
            loop {
                match device.poll_receive_raw(cx) {
                    Poll::Ready(Ok(raw)) => self.accept(raw),
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err(anyhow!("receiving from the device: {error:?}")));
                    }
                    Poll::Pending => break,
                }
            }
            sleep.as_mut().poll(cx).map(Ok)
        })
        .await
    }

    /// One received frame, on its way to whoever consumes this interface.
    fn accept(&self, raw: RawRxFrame) {
        tracing::trace!(len = raw.data.len(), "device rx");
        if self.inbound.push(TunnelFrame::new(raw.data, raw.metadata)) {
            tracing::warn!("inbound queue full; dropped the oldest frame");
        }
    }
}

enum Event {
    Received(Result<RawRxFrame, UlcpError>),
    Send(TunnelFrame),
    Ended,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spend a whole budget, returning what was waited each time.
    async fn schedule(budget: Duration) -> Vec<Duration> {
        let mut backoff = CcaBackoff::new(budget);
        let mut waits = Vec::new();
        while let Some(wait) = backoff.next_wait() {
            waits.push(wait);
            tokio::time::sleep(wait).await;
        }
        waits
    }

    #[tokio::test(start_paused = true)]
    async fn a_busy_channel_is_retried_until_the_budget_is_spent() {
        let waits = schedule(Duration::from_secs(4)).await;
        assert!(
            waits.len() > 4,
            "a four-second budget should buy several attempts, got {}",
            waits.len()
        );
        let total: Duration = waits.iter().sum();
        assert!(
            total <= Duration::from_secs(4),
            "waited {total:?}, past the budget"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_interval_grows_and_then_holds_at_the_ceiling() {
        let waits = schedule(Duration::from_secs(30)).await;
        // Jitter makes each wait a range rather than a value, so the
        // property to assert is the envelope: nothing below half the
        // floor, nothing above the ceiling, and the tail at the ceiling.
        for wait in &waits {
            assert!(*wait >= CCA_BACKOFF_MIN / 2, "{wait:?} is below the floor");
            assert!(*wait <= CCA_BACKOFF_MAX, "{wait:?} is above the ceiling");
        }
        let tail = &waits[waits.len() - 3..waits.len() - 1];
        for wait in tail {
            assert!(
                *wait >= CCA_BACKOFF_MAX / 2,
                "{wait:?} should have reached the ceiling's jitter band by the tail"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_budget_is_a_single_attempt() {
        // The relay asks once before its first re-offer, so a refusal
        // with no budget must abandon immediately rather than sleep.
        assert!(CcaBackoff::new(Duration::ZERO).next_wait().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn the_last_wait_never_overruns_the_budget() {
        // The final interval is clamped to what is left, so a frame is
        // never held past the budget waiting for an attempt that the
        // budget cannot pay for.
        let budget = Duration::from_millis(120);
        let started = Instant::now();
        let waits = schedule(budget).await;
        assert!(!waits.is_empty(), "a non-zero budget buys at least one");
        assert!(
            started.elapsed() <= budget,
            "overran by {:?}",
            started.elapsed()
        );
    }
}
