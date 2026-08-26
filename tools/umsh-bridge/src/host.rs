//! Host interfaces: a plain socket presenting a simulated ULCP device
//! whose radio is the bridge.
//!
//! Every other interface fronts a real radio, and the node behind that
//! radio is what makes a crossing safe. A host interface has neither. It
//! exists so that a host with no radio at all — an iOS simulator build,
//! `umshctl --tcp`, a test — can join the bridged medium as an ordinary
//! node, running its own MAC over a device that is real code and a
//! fictional PHY.
//!
//! The device is the production [`Session`], wrapped by
//! [`SimulatedDevice`]. Two seams connect it to the bridge: what the
//! session transmits is drained into the hub, and what the hub delivers
//! is fed through the session's real receive path. Neither direction
//! carries measurements, because nothing here measured anything — see
//! the spec's [Host Interfaces].
//!
//! The session outlives any one connection, exactly as a radio outlives
//! the host that unplugs from it: `attach`/`detach` follow the socket,
//! and provisioned state survives a reconnect.
//!
//! [Host Interfaces]: https://darconeous.github.io/umsh/docs/protocol/internet-bridging.html#host-interfaces
//! [`Session`]: umsh_ulcp_device::Session

use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use umsh_ulcp::meta::RxMeta;
use umsh_ulcp::profiles;
use umsh_ulcp_simdev::{DutyLedger, RadioRxInfo, RadioSettings, SessionConfig, SimulatedDevice};

use crate::config::HostEntry;
use crate::iface::{Ingress, Interface, InterfaceId};
use crate::tunnel::{Dequeued, TunnelFrame, TunnelQueue};

/// How much socket data to take in one read. ULCP frames are small; this
/// only bounds a burst.
const READ_CHUNK: usize = 4096;

/// The shape of a bridge's soft device.
///
/// Deliberately spare. A board's capabilities describe hardware, and
/// this has none: no battery to sample, no light sensor, no receiver, no
/// Bluetooth to switch off, and above all no node — see
/// [`SessionConfig::mac_node`], which is what keeps a participant from
/// mistaking this for something it can backhaul through.
///
/// The duty limit is left wide open. A simulated transmission spends no
/// airtime, so a duty ledger here would throttle a host against a budget
/// it is not consuming; the interface's frame rate limit is the control
/// that means something, and the configuration requires one.
fn session_config() -> SessionConfig {
    SessionConfig {
        dev_version: concat!("umsh-bridge-host/", env!("CARGO_PKG_VERSION")),
        dev_model: None,
        default_device_name: "Bridged host interface",
        mtu: 255,
        sync_word: profiles::DEFAULT.sync_word,
        min_tx_power_dbm: -9,
        max_tx_power_dbm: 22,
        freq_khz_min: 150_000,
        freq_khz_max: 960_000,
        defaults: RadioSettings {
            enabled: false,
            freq_khz: profiles::DEFAULT.freq_khz,
            bw_hz: profiles::DEFAULT.bw_hz,
            sf: profiles::DEFAULT.sf,
            cr_denom: profiles::DEFAULT.cr_denom,
            tx_power_dbm: profiles::DEFAULT_TX_POWER_DBM,
        },
        default_duty_limit: 0xFFFF,
        duty: Box::leak(Box::new(DutyLedger::new())),
        battery: None,
        alert: None,
        time: None,
        gnss: None,
        illuminance: false,
        ble: false,
        mac_node: false,
    }
}

/// Metadata for a frame nobody measured.
///
/// A frame reaching a host crossed no air: it was measured on some other
/// segment, by some other radio, and reporting that measurement here
/// would attribute it to a reception that never happened.
fn unmeasured() -> Vec<u8> {
    let mut meta = [0u8; RxMeta::WIRE_LEN];
    RxMeta {
        rssi_dbm: None,
        lqi: None,
        snr_cb: None,
    }
    .encode(&mut meta)
    .expect("buffer sized with WIRE_LEN");
    meta.to_vec()
}

/// One host interface: its listener, its device, and the relay between
/// them.
pub struct HostRelay {
    name: String,
    listen: std::net::SocketAddr,
    iface: Arc<Interface>,
    ingress: mpsc::Sender<Ingress>,
    /// Monotonic clock for the session, in milliseconds since start.
    started: tokio::time::Instant,
}

impl HostRelay {
    pub fn new(entry: &HostEntry, iface: Arc<Interface>, ingress: mpsc::Sender<Ingress>) -> Self {
        Self {
            name: entry.name.clone(),
            listen: entry.listen,
            iface,
            ingress,
            started: tokio::time::Instant::now(),
        }
    }

    /// Serve this interface for as long as the process runs.
    ///
    /// One device, many connections: the session is built once here, and
    /// each accepted socket attaches to it and detaches on the way out.
    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.listen)
            .await
            .with_context(|| format!("listening on {} for host \"{}\"", self.listen, self.name))?;
        if self.listen.ip().is_loopback() {
            tracing::info!(iface = %self.name, listen = %self.listen, "host interface listening");
        } else {
            tracing::warn!(
                iface = %self.name,
                listen = %self.listen,
                "host interface listening off the loopback: this socket is unauthenticated and \
                 whoever reaches it has an RF presence on every segment this bridge touches"
            );
        }

        let mut device = SimulatedDevice::new(session_config());
        let mut current: Option<TcpStream> = None;
        let mut session = self.iface.egress.generation();
        let mut buf = vec![0u8; READ_CHUNK];

        loop {
            let event = self
                .next_event(&listener, current.as_mut(), session, &mut buf)
                .await;

            match event {
                Event::Accepted(stream, peer) => {
                    if current.is_some() {
                        // Newest wins, as for a tunnel client: the older
                        // connection has stopped being the live host,
                        // and holding the interface for it would wedge
                        // this listener behind a socket nobody is
                        // reading.
                        tracing::info!(iface = %self.name, "displacing an earlier host");
                        device.detach();
                    }
                    stream.set_nodelay(true).ok();
                    tracing::info!(iface = %self.name, ?peer, "host attached");

                    // A socket is a cable: attaching resets exactly the
                    // session-scoped state a DTR drop would, and the
                    // egress queue starts empty rather than replaying
                    // what the last host never read.
                    self.iface.egress.clear();
                    session = self.iface.egress.generation();
                    device.attach();
                    self.iface.set_connected(true);
                    current = Some(stream);
                }
                Event::AcceptFailed(error) => {
                    // A per-connection accept failure must not take the
                    // listener down with it.
                    tracing::warn!(iface = %self.name, "accept failed: {error}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Event::Closed(reason) => {
                    self.detach(&mut device, &mut current, reason);
                    continue;
                }
                Event::Read(len) => {
                    // A decode error is the host's problem, not the
                    // link's: the decoder resynchronizes on the next
                    // flag, so a garbled frame costs one frame.
                    if let Err(error) = device.ingest(&buf[..len], self.now_ms()) {
                        tracing::debug!(iface = %self.name, "{error}");
                    }
                    self.drain_transmissions(&mut device);
                }
                Event::Deliver(frame) => {
                    device.inject_radio_rx_with_info(
                        &frame.data,
                        &RadioRxInfo::default(),
                        self.now_ms(),
                    );
                    // Delivering a frame can make the session transmit —
                    // an acknowledgement it was asked to send on the
                    // host's behalf, say.
                    self.drain_transmissions(&mut device);
                }
            }

            // Whatever the device has to say goes out on the connection
            // that is live now, which a displacement may have just
            // replaced.
            let Some(stream) = current.as_mut() else {
                continue;
            };
            while let Some(wire) = device.take_outbound() {
                if let Err(error) = stream.write_all(&wire).await {
                    self.detach(&mut device, &mut current, format!("write failed: {error}"));
                    break;
                }
            }
        }
    }

    /// Wait for whichever comes first: a new host, bytes from the
    /// current one, or a frame to deliver to it.
    ///
    /// The device is not borrowed here, and the writes that follow
    /// happen after this returns, so both directions drive one
    /// `&mut SimulatedDevice` without holding a borrow across an await.
    async fn next_event(
        &self,
        listener: &TcpListener,
        stream: Option<&mut TcpStream>,
        session: u64,
        buf: &mut [u8],
    ) -> Event {
        let queue: &TunnelQueue = &self.iface.egress;
        match stream {
            // No host attached: nothing to read, and nothing to deliver
            // to. The interface is down, so the hub queues nothing for
            // it anyway.
            None => match listener.accept().await {
                Ok((stream, peer)) => Event::Accepted(stream, peer),
                Err(error) => Event::AcceptFailed(error),
            },
            Some(stream) => {
                let accept = listener.accept();
                let read = stream.read(buf);
                tokio::pin!(accept, read);
                core::future::poll_fn(|cx| {
                    // The socket first: a host waiting on a response is
                    // the common case, and draining its request is what
                    // produces one. `read` is cancel-safe, so losing this
                    // poll to either branch below loses no bytes.
                    if let Poll::Ready(result) = read.as_mut().poll(cx) {
                        return Poll::Ready(match result {
                            Ok(0) => Event::Closed("host closed the connection".to_string()),
                            Ok(len) => Event::Read(len),
                            Err(error) => Event::Closed(format!("read failed: {error}")),
                        });
                    }
                    if let Poll::Ready(result) = accept.as_mut().poll(cx) {
                        return Poll::Ready(match result {
                            Ok((stream, peer)) => Event::Accepted(stream, peer),
                            Err(error) => Event::AcceptFailed(error),
                        });
                    }
                    match queue.poll_pop(session, cx) {
                        Poll::Ready(Dequeued::Frame(frame)) => Poll::Ready(Event::Deliver(frame)),
                        // Only this task clears the queue, and only
                        // between polls, so the generation cannot move
                        // underneath a live connection.
                        Poll::Ready(Dequeued::SessionEnded) => {
                            Poll::Ready(Event::Closed("session ended".to_string()))
                        }
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await
            }
        }
    }

    /// Put the interface down and let go of the host that was on it.
    fn detach(
        &self,
        device: &mut SimulatedDevice,
        current: &mut Option<TcpStream>,
        reason: String,
    ) {
        if current.take().is_none() {
            return;
        }
        self.iface.set_connected(false);
        self.iface.egress.clear();
        device.detach();
        tracing::info!(iface = %self.name, "host detached: {reason}");
    }

    /// Move everything the device transmitted into the hub.
    fn drain_transmissions(&self, device: &mut SimulatedDevice) {
        for data in device.take_transmitted() {
            let frame = TunnelFrame::new(data, unmeasured());
            // The hub is the only consumer and its work per frame is
            // bounded; a full channel means the process is shutting
            // down.
            if self
                .ingress
                .try_send(Ingress {
                    iface: self.iface.id,
                    frame,
                })
                .is_err()
            {
                tracing::warn!(iface = %self.name, "the hub is not keeping up; dropped a frame");
            }
        }
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
}

enum Event {
    /// A host connected. If one was already attached, it is displaced.
    Accepted(TcpStream, std::net::SocketAddr),
    AcceptFailed(std::io::Error),
    /// Bytes from the attached host, in the shared buffer.
    Read(usize),
    /// A frame from the hub, for the attached host.
    Deliver(TunnelFrame),
    /// The attached host is gone, for the reason given.
    Closed(String),
}

/// The interface a host relay serves, for the server's wiring.
pub type HostInterfaceId = InterfaceId;

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_ulcp::meta::RxMeta;

    #[test]
    fn a_bridge_host_device_claims_no_node() {
        // The whole safety argument for a host interface rests on this:
        // the device has no node, says so, and a participant that would
        // otherwise backhaul through it is refused by its own check.
        assert!(!session_config().mac_node);
    }

    #[test]
    fn a_bridge_host_device_claims_no_hardware_it_lacks() {
        let config = session_config();
        assert!(config.battery.is_none());
        assert!(
            config.alert.is_none(),
            "no alert, so nothing polls a deadline"
        );
        assert!(config.time.is_none());
        assert!(config.gnss.is_none());
        assert!(!config.illuminance);
        assert!(!config.ble);
    }

    #[test]
    fn delivered_frames_carry_no_measurements() {
        let meta = unmeasured();
        let decoded = RxMeta::decode(&meta).expect("fixed-size metadata");
        assert_eq!(decoded.rssi_dbm, None);
        assert_eq!(decoded.snr_cb, None);
        assert_eq!(decoded.lqi, None);
    }
}
