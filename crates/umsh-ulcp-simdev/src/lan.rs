//! The LAN virtual radio: a soft device whose PHY is the LAN bearer's
//! multicast group.
//!
//! What the device transmits is sent to the group, where every radio with
//! its bearer enabled hears it; what any participant sends to the group is
//! received unmeasured, since nothing here measured it. The device lives
//! for as long as its owner runs it, whether or not a host is attached:
//! detached, it goes on receiving, acknowledging for its host, and
//! queueing, exactly as a companion radio does.
//!
//! The group is the device's own `PROP_LAN_BEARER_GROUP`, joined while
//! its PHY is on, and `PROP_LAN_BEARER_STATE` says how that went: a host
//! moves the radio to another group by writing the property, as it would
//! on a radio that forwards.
//!
//! The host's link is the caller's. [`run`] takes the host's side as
//! [`HostEvent`]s, each attach bringing the sink its replies go to, so one
//! driver serves an in-memory pipe, a local socket ([`serve`]), and
//! anything else that carries HDLC-Lite.

use std::fs::{File, TryLockError};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio::net::unix::OwnedReadHalf;
use tokio::sync::mpsc;
use tokio::time::Instant;
use umsh_lan_bearer::socket::{LanConfig, LanSocket};
use umsh_lan_bearer::{Datagram, MAX_FRAME};
use umsh_ulcp::lan::State;
use umsh_ulcp::profiles;
use umsh_ulcp_device::QueuedNotice;

use crate::soft::{SoftDevice, SoftPlatform};
use crate::{DutyLedger, RadioRxInfo, RadioSettings, SessionConfig};

/// The shape of a virtual radio, reporting itself as `dev_version`.
///
/// Spare, like a bridge's host interface: no hardware to describe and no
/// node behind it. The PHY settings it reports are the default profile's,
/// fixed; the frames it sends are transmitted later by whichever LoRa
/// radios forward them, so the frame time a host's MAC derives from these
/// is an estimate either way. The duty limit is left open—sending to the
/// group spends no airtime—and the radios' ingress limits are the control
/// that means something.
///
/// The configuration borrows a duty ledger for the life of the process,
/// so a caller builds one per device it runs, not one per attach.
pub fn session_config(dev_version: &'static str) -> SessionConfig {
    SessionConfig {
        dev_version,
        dev_model: None,
        default_device_name: "Virtual radio",
        mtu: MAX_FRAME as u16,
        tx_preamble_symbols: 32,
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
        battery_diagnostics: Default::default(),
        battery: None,
        alert: None,
        time: None,
        gnss: None,
        display_motion_wake: false,
        display: None,
        keyboard: false,
        illuminance: false,
        temperatures: false,
        ble: false,
        ble_pairing: false,
        ble_pin: false,
        // The device is a task in its owner's process; there is nothing
        // for `CMD_REBOOT` to restart.
        reboot: false,
        dev_identity: false,
        stats: None,
        mac_node: false,
        meshcore_forwarder: false,
        // The group is this device's PHY.
        lan_bearer: umsh_ulcp_device::LanBearerRole::Phy,
        wifi: None,
        ip: None,
        bridge_client: false,
        i2c_buses: &[],
        i2c_devices: &[],
    }
}

/// Exclusive use of one virtual radio's state directory, for as long as
/// it is held.
///
/// Two devices sharing an identity would send under one key with two
/// frame counters, and each would see the other's frames as replays. The
/// lock is the operating system's, so it holds across processes—a tool
/// and its twin, or an app and its extension—and is released when its
/// holder exits, however it exits.
pub struct StateLock {
    _file: File,
}

impl StateLock {
    /// Take the lock on `dir`, or `None` if another holder has it.
    pub fn try_acquire(dir: &Path) -> io::Result<Option<Self>> {
        let file = File::create(dir.join("lock"))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error),
        }
    }
}

/// Where an attached host's bytes go: one HDLC-Lite frame per call.
pub type WireSink = Box<dyn FnMut(Vec<u8>) + Send>;

/// What a host does on its side of the link.
pub enum HostEvent {
    /// A link came up, taking the device's replies at its sink. A host
    /// that attaches while another is attached replaces it: the earlier
    /// sink is dropped and hears nothing more, not even what was owed to
    /// its session.
    Attach(WireSink),
    /// Bytes from the host, in HDLC-Lite.
    Bytes(Vec<u8>),
    /// The link went down.
    Detach,
}

/// How long to wait before trying the group again when it could not be
/// joined, as when the host has no network yet.
const REJOIN_DELAY: Duration = Duration::from_secs(2);

/// The device's membership in its group.
#[derive(Default)]
struct Membership {
    /// The group last tried, or `None` while the PHY is off.
    group: Option<SocketAddrV4>,
    socket: Option<LanSocket>,
    /// When to try `group` again, after it could not be joined.
    retry_at: Option<Instant>,
}

impl Membership {
    /// Join the group the device asks for, if it is not already joined,
    /// and report the outcome as the bearer's state.
    fn follow<P: SoftPlatform>(&mut self, device: &mut SoftDevice<P>, base: LanConfig) {
        let session = device.session();
        let wanted = session.settings().enabled.then(|| {
            let group = session.lan_bearer_config().group();
            SocketAddrV4::new(Ipv4Addr::from(group.address), group.port)
        });
        let retry_due = self.group.is_some() && self.socket.is_none() && self.retry_at.is_none();
        if wanted == self.group && !retry_due {
            return;
        }
        self.group = wanted;
        self.socket = None;
        self.retry_at = None;
        let state = match wanted {
            None => State::Disabled,
            Some(group) => match LanSocket::bind(LanConfig { group, ..base }) {
                Ok(socket) => {
                    self.socket = Some(socket);
                    State::Active
                }
                Err(_) => {
                    self.retry_at = Some(Instant::now() + REJOIN_DELAY);
                    State::NoNetwork
                }
            },
        };
        device.set_lan_bearer_state(state);
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.socket {
            Some(socket) => socket.recv(buf).await,
            None => std::future::pending().await,
        }
    }
}

/// Run `device` until the sender of `host` is dropped, joining its group
/// on the interface and with the loopback `base` names, and telling
/// `queued` of each frame queued while no host is attached.
///
/// The device starts detached; a [`HostEvent::Attach`] attaches it.
/// Bytes that arrive while detached belong to no session and are
/// dropped.
pub async fn run<P: SoftPlatform>(
    mut device: SoftDevice<P>,
    base: LanConfig,
    mut host: mpsc::UnboundedReceiver<HostEvent>,
    mut queued: impl FnMut(QueuedNotice),
) {
    let started = Instant::now();
    let now_ms = || started.elapsed().as_millis() as u64;
    let mut sink: Option<WireSink> = None;
    let mut membership = Membership::default();
    let mut datagram = [0u8; MAX_FRAME + 1];
    loop {
        // A host's write may have moved the group or switched the PHY.
        membership.follow(&mut device, base);
        // Whatever the device has to say goes out first: the attach's
        // own notice, then each reply in turn.
        while let Some(wire) = device.take_outbound() {
            if let Some(sink) = &mut sink {
                sink(wire);
            }
        }
        for frame in device.take_transmitted() {
            // A send that fails, or finds no group, is a frame lost on
            // the medium, which the protocol above already tolerates.
            if let Some(socket) = &membership.socket {
                let _ = socket.send(&frame).await;
            }
        }
        tokio::select! {
            event = host.recv() => match event {
                None => break,
                Some(HostEvent::Attach(next)) => {
                    if sink.replace(next).is_some() {
                        device.detach();
                    }
                    device.attach();
                }
                Some(HostEvent::Detach) => {
                    if sink.take().is_some() {
                        device.detach();
                    }
                }
                // A garbled frame costs one frame: the decoder
                // resynchronizes on the next flag.
                Some(HostEvent::Bytes(bytes)) if sink.is_some() => {
                    let _ = device.ingest(&bytes, now_ms());
                }
                Some(HostEvent::Bytes(_)) => {}
            },
            () = tokio::time::sleep_until(membership.retry_at.unwrap_or_else(Instant::now)),
                if membership.retry_at.is_some() =>
            {
                membership.retry_at = None;
            }
            received = membership.recv(&mut datagram) => {
                if let Ok((len, _)) = received
                    && umsh_lan_bearer::classify(&datagram[..len]) == Datagram::Umsh
                {
                    device.inject_radio_rx(&datagram[..len], &RadioRxInfo::default(), now_ms());
                    if let Some(notice) = device.session_mut().take_queued_notice() {
                        queued(notice);
                    }
                }
            }
        }
    }
    if sink.is_some() {
        device.detach();
    }
}

/// Make the local socket a host attaches through at `path`, replacing
/// whatever a previous holder of the state left there. The caller holds
/// the state's [`StateLock`], so no live device owns that file.
#[cfg(unix)]
pub fn bind_local_socket(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// How much of a local socket to take in one read. ULCP frames are
/// small; this only bounds a burst.
#[cfg(unix)]
const READ_CHUNK: usize = 4096;

/// Attach whoever connects to `listener`, until the receiver of `host`
/// is dropped.
///
/// A connection is a session: connecting attaches, closing detaches, and
/// a new connection replaces the current one, whose socket is closed.
#[cfg(unix)]
pub async fn serve(listener: UnixListener, host: mpsc::UnboundedSender<HostEvent>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut current: Option<OwnedReadHalf> = None;
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let event = tokio::select! {
            accepted = listener.accept() => {
                // A failed accept costs that one connection.
                let Ok((stream, _)) = accepted else { continue };
                let (read, mut write) = stream.into_split();
                let (wire_tx, mut wire) = mpsc::unbounded_channel::<Vec<u8>>();
                // The writer ends when the device drops this sink, which
                // closes the connection.
                tokio::spawn(async move {
                    while let Some(bytes) = wire.recv().await {
                        if write.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                });
                current = Some(read);
                HostEvent::Attach(Box::new(move |bytes| {
                    let _ = wire_tx.send(bytes);
                }))
            }
            read = async {
                match &mut current {
                    Some(read) => read.read(&mut buf).await,
                    None => std::future::pending().await,
                }
            } => match read {
                Ok(0) | Err(_) => {
                    current = None;
                    HostEvent::Detach
                }
                Ok(len) => HostEvent::Bytes(buf[..len].to_vec()),
            },
        };
        if host.send(event).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use umsh_lan_bearer::socket::LanConfig;
    use umsh_ulcp::{frame, hdlc, ids::prop};

    use super::*;
    use crate::host::HostPlatform;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("umsh-lan-radio-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn encoded(request: &[u8]) -> Vec<u8> {
        let mut wire = vec![0; hdlc::max_encoded_len(request.len())];
        let len = hdlc::encode_frame(request, &mut wire).unwrap();
        wire.truncate(len);
        wire
    }

    fn host_local() -> LanConfig {
        LanConfig::host_local(Ipv4Addr::new(239, 255, 42, 111), 47_111)
    }

    /// An attach whose replies arrive on the returned receiver.
    fn attach() -> (HostEvent, mpsc::UnboundedReceiver<Vec<u8>>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let event = HostEvent::Attach(Box::new(move |wire| {
            let _ = tx.send(wire);
        }));
        (event, rx)
    }

    async fn next(out: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(1), out.recv())
            .await
            .ok()
            .flatten()
    }

    /// The frames in `wire`, decoded.
    fn frames(wire: &[u8]) -> Vec<Vec<u8>> {
        let mut decoder = hdlc::Decoder::<512>::new();
        wire.iter()
            .filter_map(|&byte| decoder.push(byte).map(|frame| frame.unwrap().to_vec()))
            .collect()
    }

    /// The last byte of the next frame the host hears.
    async fn next_value(out: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> u8 {
        let wire = next(out).await.expect("the device answers");
        *frames(&wire)[0].last().unwrap()
    }

    fn running(
        dir: &Path,
    ) -> (
        mpsc::UnboundedSender<HostEvent>,
        tokio::task::JoinHandle<()>,
    ) {
        let device = SoftDevice::new(session_config("test"), HostPlatform::new(dir).unwrap());
        let (host, events) = mpsc::unbounded_channel();
        (
            host,
            tokio::spawn(run(device, host_local(), events, |_| {})),
        )
    }

    #[test]
    fn one_holder_at_a_time() {
        let dir = scratch("lock");
        let first = StateLock::try_acquire(&dir).unwrap();
        assert!(first.is_some());
        assert!(StateLock::try_acquire(&dir).unwrap().is_none());
        drop(first);
        assert!(StateLock::try_acquire(&dir).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The device answers only while attached, announces each attach with
    /// a session reset, and a second attach takes the link from the
    /// first.
    #[tokio::test(flavor = "current_thread")]
    async fn bytes_reach_the_device_only_while_attached() {
        let dir = scratch("attach");
        let (host, task) = running(&dir);

        let mut request = [0u8; 16];
        let len = frame::prop_get(&mut request, 1, prop::PROTOCOL_VERSION).unwrap();
        host.send(HostEvent::Bytes(encoded(&request[..len])))
            .unwrap();
        let (event, mut first) = attach();
        host.send(event).unwrap();
        host.send(HostEvent::Bytes(encoded(&request[..len])))
            .unwrap();

        // The session reset, then the one answer: the request sent
        // before the attach went nowhere.
        assert!(next(&mut first).await.is_some());
        assert!(next(&mut first).await.is_some());

        let (event, mut second) = attach();
        host.send(event).unwrap();
        assert!(next(&mut second).await.is_some());
        // The first host's sink is gone.
        assert_eq!(next(&mut first).await, None);

        drop(host);
        task.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The device joins the group its property names while its PHY is
    /// on, and says so.
    #[tokio::test(flavor = "current_thread")]
    async fn the_group_follows_the_phy() {
        let dir = scratch("phy");
        let mut device = SoftDevice::new(session_config("test"), HostPlatform::new(&dir).unwrap());
        let group = umsh_ulcp::lan::Group {
            address: [239, 255, 42, 113],
            port: 47_113,
        };
        device.session_mut().set_lan_bearer_group(Some(group));
        let (host, events) = mpsc::unbounded_channel();
        let task = tokio::spawn(run(device, host_local(), events, |_| {}));
        let (event, mut out) = attach();
        host.send(event).unwrap();
        let mut request = [0u8; 16];
        let len = frame::prop_get(&mut request, 1, prop::LAN_BEARER_STATE).unwrap();
        host.send(HostEvent::Bytes(encoded(&request[..len])))
            .unwrap();
        next(&mut out).await;
        assert_eq!(next_value(&mut out).await, State::Disabled as u8);

        // Switching the PHY on joins the group, and the host hears it.
        let len = frame::prop_set(&mut request, 2, prop::PHY_ENABLED, &[1]).unwrap();
        host.send(HostEvent::Bytes(encoded(&request[..len])))
            .unwrap();
        let mut heard = Vec::new();
        while let Some(wire) = next(&mut out).await {
            heard.push(wire);
        }
        let active = encoded(&{
            let mut frame = [0u8; 16];
            let len = frame::prop_is(
                &mut frame,
                0,
                prop::LAN_BEARER_STATE,
                &[State::Active as u8],
            )
            .unwrap();
            frame[..len].to_vec()
        });
        assert!(heard.contains(&active));
        drop(host);
        task.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Over a local socket, connecting attaches and a second connection
    /// replaces the first, whose socket closes.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_local_socket_connection_is_a_session() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let dir = scratch("socket");
        let path = dir.join("ulcp");
        // A stale file from an earlier holder is replaced.
        std::fs::write(&path, b"").unwrap();
        let listener = bind_local_socket(&path).unwrap();
        let (host, task) = running(&dir);
        let server = tokio::spawn(serve(listener, host));

        let read_some = async |stream: &mut UnixStream| {
            let mut buf = [0u8; 512];
            match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
                Ok(Ok(len)) => buf[..len].to_vec(),
                _ => panic!("the device is silent"),
            }
        };
        let mut first = UnixStream::connect(&path).await.unwrap();
        // The session reset.
        assert!(!read_some(&mut first).await.is_empty());
        let mut request = [0u8; 16];
        let len = frame::prop_get(&mut request, 1, prop::PROTOCOL_VERSION).unwrap();
        first.write_all(&encoded(&request[..len])).await.unwrap();
        assert!(!read_some(&mut first).await.is_empty());

        let mut second = UnixStream::connect(&path).await.unwrap();
        assert!(!read_some(&mut second).await.is_empty());
        // Closed: end of stream.
        assert!(read_some(&mut first).await.is_empty());

        server.abort();
        let _ = server.await;
        task.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
