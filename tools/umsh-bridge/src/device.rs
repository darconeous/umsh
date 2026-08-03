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

use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
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
                Event::Received(Ok(raw)) => {
                    tracing::trace!(len = raw.data.len(), "device rx");
                    if self.inbound.push(TunnelFrame::new(raw.data, raw.metadata)) {
                        tracing::warn!("inbound queue full; dropped the oldest frame");
                    }
                }
                Event::Send(frame) => {
                    if frame.data.len() > max_frame_size {
                        tracing::debug!(
                            len = frame.data.len(),
                            max_frame_size,
                            "dropping a frame larger than this radio can transmit"
                        );
                        continue;
                    }
                    match device.transmit(&frame).await {
                        Ok(()) => tracing::trace!(len = frame.data.len(), "device tx"),
                        // A busy channel or a spent duty budget is the
                        // device doing its job, not a link failure.
                        Err(TxError::CadTimeout) => {
                            tracing::debug!("transmit abandoned: the channel was busy");
                        }
                        Err(TxError::Io(UlcpError::Status(status))) => {
                            tracing::debug!(?status, "device refused a transmit");
                        }
                        Err(error) => return Err(anyhow!("transmitting: {error:?}")),
                    }
                }
            }
        }
    }
}

enum Event {
    Received(Result<RawRxFrame, UlcpError>),
    Send(TunnelFrame),
    Ended,
}
