//! The radio a participant fronts, and the loop that relays frames
//! between it and one queue in each direction.
//!
//! Both roles use this: a client's whole job is this relay, and the
//! server runs one for its own radio alongside the hub.
//!
//! Attachment follows the spec's [Radio Attachment] rules — a tethered,
//! non-resetting attach with `PROP_MAC_BACKHAUL` set, re-asserted after
//! every reconnection because the property is session-scoped. Backhaul
//! mode is what makes the device's own node the far end of a
//! point-to-point link: what this relay sends is delivered to that node
//! as though it had heard it, and what the node transmits comes back
//! here. Transmits are confirmed, never `TX_FLAG_NODUTY`.
//!
//! [Radio Attachment]: https://darconeous.github.io/umsh/docs/protocol/internet-bridging.html#radio-attachment

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use umsh::ulcp::{RawRxFrame, UlcpError};
use umsh_hal::TxError;
use umsh_ulcp::meta::TxMeta;

use umsh_ulcp::ids::cap;

// Only the two ULCP transports attach or have session properties to
// set; a build with neither is fake-radio only.
#[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
use umsh::ulcp::{UlcpDevice, UlcpDeviceConfig};
#[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
use umsh_ulcp::ids::prop;

use crate::config::RadioConfig;
use crate::tunnel::{Dequeued, TunnelFrame, TunnelQueue};
use crate::udp_radio::UdpFakeRadio;

/// How long to wait before re-opening a device that failed. A radio
/// unplugged and plugged back in should come back on its own, and a
/// radio that is simply gone should not spin the CPU about it.
const REOPEN_DELAY: Duration = Duration::from_secs(3);

/// How many times a frame is offered to a device whose node has no room
/// for it.
const MAX_HANDOFF_ATTEMPTS: u8 = 5;

/// How long to wait between those attempts. A backhauled send crosses a
/// wire, so what is being waited out is the node draining its receive
/// queue — a matter of one frame's processing, not one frame's airtime.
const HANDOFF_RETRY: Duration = Duration::from_millis(20);
const HANDOFF_RETRY_JITTER_MS: u64 = 80;

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
///
/// Backhaul mode already decides *which* frames reach this host — the
/// node's transmissions, and nothing off the air — but they still pass
/// the device's receive filtering on the way. A device with no host
/// domain provisioned filters nothing, which is the ordinary case for a
/// bridge; asking for promiscuous delivery anyway is what keeps a device
/// that *has* been provisioned from hiding the repeats this bridge
/// exists to carry. A device that refuses the property is left as it is.
#[cfg(any(feature = "serial-radio", feature = "ble-radio"))]
fn promiscuous_outcome(result: Result<Vec<u8>, UlcpError>) -> Result<()> {
    match result {
        Ok(_) => {
            tracing::debug!("promiscuous delivery enabled");
            Ok(())
        }
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
        let capabilities = self.capabilities().await?;

        if !capabilities.contains(&cap::MAC_BACKHAUL) {
            // Fatal, and deliberately so. Without backhaul this host
            // would sit on the shared medium, and every frame the bridge
            // handed it would go on the air unrepeated: no duplicate
            // suppression, no hop accounting, no forwarding policy. A
            // bridge is not something to half-do.
            bail!(
                "device does not advertise CAP_MAC_BACKHAUL, so it cannot join a bridge; \
                 update its firmware"
            );
        }
        if !capabilities.contains(&cap::WRITABLE_RAW_STREAM) {
            // Not fatal: a receive-only interface still carries what its
            // node transmits to the rest of the bridge, and saying so
            // once is more useful than refusing to start.
            tracing::warn!(
                "device does not advertise CAP_WRITABLE_RAW_STREAM; this interface can receive \
                 but not transmit"
            );
        }

        self.set_backhaul().await?;
        self.set_promiscuous().await?;
        self.report_repeater_state().await;
        Ok(())
    }

    async fn capabilities(&mut self) -> Result<Vec<u32>> {
        match self {
            #[cfg(feature = "serial-radio")]
            Self::Serial(device) => device
                .capabilities()
                .await
                .map_err(|error| anyhow!("reading device capabilities: {error:?}")),
            #[cfg(feature = "ble-radio")]
            Self::Ble(device) => device
                .capabilities()
                .await
                .map_err(|error| anyhow!("reading device capabilities: {error:?}")),
            // The fake radio has no node behind it at all, so it claims
            // what it needs to stand in for one.
            Self::Udp(_) => Ok(vec![cap::MAC_BACKHAUL, cap::WRITABLE_RAW_STREAM]),
        }
    }

    /// Move this host off the shared medium and onto a point-to-point
    /// link to the device's own node. The property is session-scoped,
    /// which is why this runs on every attach rather than once at
    /// provisioning time.
    async fn set_backhaul(&mut self) -> Result<()> {
        let result = match self {
            #[cfg(feature = "serial-radio")]
            Self::Serial(device) => device.set_prop(prop::MAC_BACKHAUL, &[1]).await,
            #[cfg(feature = "ble-radio")]
            Self::Ble(device) => device.set_prop(prop::MAC_BACKHAUL, &[1]).await,
            // The fake radio has no medium to leave.
            Self::Udp(_) => return Ok(()),
        };
        result
            .map(|_| ())
            .map_err(|error| anyhow!("enabling backhaul mode: {error:?}"))
    }

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

    /// Say whether the node behind this radio forwards, and never change
    /// it.
    ///
    /// Whether a device repeats is persisted, device-domain
    /// configuration — its owner's decision, not a bridge's, and one
    /// that outlives the session. A device with its repeater off is a
    /// leaf: it is reachable from everywhere the bridge reaches and its
    /// own traffic crosses, but nothing is carried onward from its
    /// segment. That is a deployment, not a fault, so it is worth one
    /// line and no alarm.
    async fn report_repeater_state(&mut self) {
        let value = match self {
            #[cfg(feature = "serial-radio")]
            Self::Serial(device) => device.get_prop(prop::MAC_REPEATER_ENABLED).await,
            #[cfg(feature = "ble-radio")]
            Self::Ble(device) => device.get_prop(prop::MAC_REPEATER_ENABLED).await,
            Self::Udp(_) => {
                tracing::info!(
                    "fake radio: no node behind it, so frames cross this interface with no \
                     duplicate suppression and no hop accounting"
                );
                return;
            }
        };
        match value.as_deref() {
            Ok([0]) => tracing::info!(
                "device repeater is disabled; this interface is a leaf — its node is reachable \
                 across the bridge, but carries nothing onward from its own segment"
            ),
            Ok(_) => tracing::debug!("device repeater is enabled"),
            Err(error) => tracing::debug!(?error, "could not read the device's repeater state"),
        }
    }

    fn poll_receive_raw(&mut self, cx: &mut Context<'_>) -> Poll<Result<RawRxFrame, UlcpError>> {
        with_device!(self, device => device.poll_receive_raw(cx))
    }

    /// Hand one frame to the node behind this radio.
    ///
    /// The metadata a frame carries across the tunnel describes how it
    /// was *received* at the far end, and is what the staleness limit
    /// reads on the way; a transmit needs metadata of its own. Building
    /// it here, at the last possible moment, is what lets the tunnel stay
    /// byte-faithful. The default asks for the device's configured power
    /// and leaves `TX_FLAG_NODUTY` clear — a bridge does not get to spend
    /// airtime the device's duty ledger has not granted.
    async fn transmit(&mut self, frame: &TunnelFrame) -> Result<(), TxError<UlcpError>> {
        let mut meta = [0u8; TxMeta::WIRE_LEN];
        TxMeta::default()
            .encode(&mut meta)
            .expect("a fixed-size buffer holds fixed-size metadata");
        with_device!(self, device => device
            .transmit_raw_with_meta(&frame.data, &meta)
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

/// How long to wait before offering a frame to a full node again.
///
/// Jittered so that several interfaces relieved by the same node do not
/// all come back at once.
fn handoff_retry() -> Duration {
    HANDOFF_RETRY + Duration::from_millis(rand::random_range(0..=HANDOFF_RETRY_JITTER_MS))
}

/// One interface's two queues, from the relay's point of view.
pub struct DeviceRelay {
    config: RadioConfig,
    /// Frames the device received, for whoever consumes this interface.
    inbound: Arc<TunnelQueue>,
    /// Frames to put on the air.
    outbound: Arc<TunnelQueue>,
}

impl DeviceRelay {
    pub fn new(config: RadioConfig, inbound: Arc<TunnelQueue>, outbound: Arc<TunnelQueue>) -> Self {
        Self {
            config,
            inbound,
            outbound,
        }
    }

    /// Keep a device attached and relaying for as long as the process
    /// runs, re-opening it after a failure.
    ///
    /// A device outage leaves no backlog to drain — backhaul mode ends
    /// with the session, and a detached device queues nothing on this
    /// host's behalf — so a fresh attachment starts clean by
    /// construction and this loop needs no reconciliation of its own. It
    /// is also what recovers a device whose firmware cannot bridge:
    /// attachment fails, the loop waits, and an updated device joins on
    /// its own.
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

    /// Hand one frame to the device's node, retrying a few times if the
    /// node has nowhere to put it.
    ///
    /// A backhauled send never contends for the channel — it crosses a
    /// wire, spends no airtime, and waits for no one. What it can meet is
    /// a node whose receive queue is full, which ULCP reports the only
    /// way it can, as `STATUS_CCA_FAILURE`. The answer is to wait briefly
    /// and offer it again: the node drains as it works, and the waiting
    /// is done listening, which is itself what relieves the queue.
    ///
    /// Whether the frame then goes on the air is the node's decision. A
    /// duplicate it has already seen, or one whose flood budget is spent,
    /// ends there — that is the bridging policy doing its job, not a
    /// failure of this hand-off.
    async fn transmit(&self, device: &mut Device, frame: &TunnelFrame) -> Result<()> {
        for attempt in 1..=MAX_HANDOFF_ATTEMPTS {
            match device.transmit(frame).await {
                Ok(()) => {
                    tracing::trace!(len = frame.data.len(), attempt, "device tx");
                    return Ok(());
                }
                Err(TxError::CadTimeout) => {
                    if attempt < MAX_HANDOFF_ATTEMPTS {
                        self.listen_during(device, handoff_retry()).await?;
                    }
                }
                // A refusal with a status is the device declining for a
                // reason of its own — detached, or handed something it
                // will not send. Re-offering would not change its mind.
                Err(TxError::Io(UlcpError::Status(status))) => {
                    tracing::debug!(?status, "device refused a transmit");
                    return Ok(());
                }
                Err(error) => bail!("transmitting: {error:?}"),
            }
        }

        tracing::debug!(
            attempts = MAX_HANDOFF_ATTEMPTS,
            len = frame.data.len(),
            "hand-off abandoned: the node had no room for it"
        );
        Ok(())
    }

    /// Wait without going deaf.
    ///
    /// Reception cannot pause while the relay waits: a frame left sitting
    /// in the device is a frame the device may have to drop, and when the
    /// wait is for a full node receive queue, draining it is precisely
    /// what makes room for the frame being retried.
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

    #[test]
    fn a_hand_off_retry_is_short_and_jittered() {
        // Short because what is being waited out is a node draining its
        // receive queue, not a frame finishing in the air; jittered so
        // that interfaces sharing a node do not synchronize on it.
        let mut seen_low = false;
        let mut seen_high = false;
        for _ in 0..512 {
            let wait = handoff_retry();
            assert!(wait >= HANDOFF_RETRY);
            assert!(wait <= HANDOFF_RETRY + Duration::from_millis(HANDOFF_RETRY_JITTER_MS));
            seen_low |= wait < HANDOFF_RETRY + Duration::from_millis(HANDOFF_RETRY_JITTER_MS / 4);
            seen_high |= wait > HANDOFF_RETRY + Duration::from_millis(HANDOFF_RETRY_JITTER_MS / 2);
        }
        assert!(seen_low && seen_high, "the range is not being covered");
    }

    #[test]
    fn the_whole_hand_off_is_bounded_well_inside_the_staleness_limit() {
        // Frames are discarded once they are ten seconds old, so the
        // retries must not be able to hold one anywhere near that long.
        let worst = (HANDOFF_RETRY + Duration::from_millis(HANDOFF_RETRY_JITTER_MS))
            * u32::from(MAX_HANDOFF_ATTEMPTS - 1);
        assert!(worst < Duration::from_secs(1), "{worst:?}");
    }

    #[test]
    fn a_transmit_asks_for_no_favors() {
        // Default power, and TX_FLAG_NODUTY clear: the device's duty
        // ledger is the backstop against a bridge that would otherwise
        // spend a segment's whole airtime budget on somebody else's
        // traffic.
        let meta = TxMeta::default();
        assert_eq!(meta.flags, 0);
        assert_eq!(meta.power, umsh_ulcp::meta::TX_POWER_DEFAULT);
    }
}
