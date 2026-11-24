//! The LAN virtual radio: a companion radio with no hardware, whose PHY is
//! the LAN bearer's multicast group.
//!
//! The device is the production ULCP session on a file-backed platform.
//! The platform attaches to it with the same HDLC-Lite bytes it would
//! send a radio over a serial link, so everything above—the ULCP session,
//! the mesh, the chat—is the code that runs against a T1000-E. The
//! device runs on a worker thread of its own for as long as this object
//! lives, attached or not: detached, it acknowledges for its host and
//! queues, and reports each queued frame so the platform can tell the
//! user.
//!
//! The group is the device's own `PROP_LAN_BEARER_GROUP`, set through
//! the same management as any radio's, and a network to join it on comes
//! and goes as `PROP_LAN_BEARER_STATE` reports.

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};
use umsh_lan_bearer::socket::LanConfig;
use umsh_lan_bearer::{DEFAULT_GROUP, DEFAULT_PORT};
use umsh_ulcp_device::{QueuedClass, QueuedNotice};
use umsh_ulcp_simdev::driven::{self, SpawnError};
use umsh_ulcp_simdev::host::{HostPlatform, StateLock};
use umsh_ulcp_simdev::lan::{self, HostEvent};
use umsh_ulcp_simdev::soft::SoftDevice;

/// What the device reports itself as.
const DEV_VERSION: &str = concat!("umsh-mobile-lan/", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileVirtualRadioError {
    /// The state directory could not be created or locked.
    StateUnavailable,
    /// Another virtual radio, in this process or another, is using the
    /// state directory.
    StateInUse,
    /// The device's worker could not be started.
    WorkerUnavailable,
    /// The local socket could not be made.
    SocketUnavailable,
}

impl fmt::Display for MobileVirtualRadioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StateUnavailable => "the virtual radio's state directory is unavailable",
            Self::StateInUse => "another virtual radio is using this state directory",
            Self::WorkerUnavailable => "the virtual radio's worker could not start",
            Self::SocketUnavailable => "the virtual radio's local socket could not be made",
        })
    }
}

impl std::error::Error for MobileVirtualRadioError {}

/// Who hears the virtual radio's group.
///
/// Every start names one, so nothing joins the LAN by default: a LAN may
/// have a bridge that carries whatever reaches the group onto the air.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileVirtualRadioReach {
    /// The group on the network the host routes it through.
    Lan,
    /// The group on this host's loopback interface: only its own
    /// participants hear it. For tests.
    ThisHost,
}

impl MobileVirtualRadioReach {
    fn config(self) -> LanConfig {
        match self {
            Self::Lan => LanConfig::lan(),
            Self::ThisHost => LanConfig::host_local(DEFAULT_GROUP.into(), DEFAULT_PORT),
        }
    }
}

/// What a queued frame is, as far as a notification is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileQueuedClass {
    /// Addressed to the host.
    Direct,
    /// Multicast or broadcast.
    Group,
}

/// A frame entered the inbound queue while no host was attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileQueuedNoticeRecord {
    pub class: MobileQueuedClass,
    /// The frame earns a notification of its own: a message for the
    /// user, in a conversation that is not muted. Counts follow every
    /// frame regardless.
    pub cue: bool,
    /// Frames in the queue after this one.
    pub depth: u32,
}

impl From<QueuedNotice> for MobileQueuedNoticeRecord {
    fn from(notice: QueuedNotice) -> Self {
        Self {
            class: match notice.class {
                QueuedClass::Direct => MobileQueuedClass::Direct,
                QueuedClass::Group => MobileQueuedClass::Group,
            },
            cue: notice.cue,
            depth: u32::try_from(notice.depth).unwrap_or(u32::MAX),
        }
    }
}

/// What the device has for the platform, beyond a host's own replies.
///
/// Called on the device's worker thread; implementations hand the value
/// to their own executor and return.
#[uniffi::export(with_foreign)]
pub trait MobileVirtualRadioListener: Send + Sync {
    /// A frame was queued while no host was attached.
    fn on_queued(&self, notice: MobileQueuedNoticeRecord);
}

/// Where one attached host's replies go.
///
/// Called on the device's worker thread. Each attach brings its own sink,
/// and a sink hears nothing once its host detaches or is replaced, so it
/// never carries the bytes of another session.
#[uniffi::export(with_foreign)]
pub trait MobileWireSink: Send + Sync {
    /// HDLC-Lite bytes for the host.
    fn on_wire(&self, bytes: Vec<u8>);
}

/// A running virtual radio. Dropping it, or calling [`Self::stop`], stops
/// the device and releases its state directory.
#[derive(uniffi::Object)]
pub struct MobileVirtualRadio {
    events: mpsc::Sender<HostEvent>,
    /// Dropped to stop the device.
    stop: Mutex<Option<oneshot::Sender<()>>>,
}

#[uniffi::export]
impl MobileVirtualRadio {
    /// Start a virtual radio keeping its saved configuration under
    /// `state_dir`, for a host in this process.
    ///
    /// With `enable_phy`, the device comes up listening whatever it saved:
    /// starting it is choosing the network. Without, its saved state
    /// decides, so a host that turned the PHY off and saved keeps it off
    /// across restarts. Either way, `reach` decides who hears it: a host
    /// that attaches may turn the PHY on.
    #[uniffi::constructor]
    pub fn start(
        state_dir: String,
        enable_phy: bool,
        reach: MobileVirtualRadioReach,
        listener: Arc<dyn MobileVirtualRadioListener>,
    ) -> Result<Arc<Self>, MobileVirtualRadioError> {
        Self::launch(
            PathBuf::from(state_dir),
            None,
            enable_phy,
            reach.config(),
            listener,
        )
    }

    /// Start a virtual radio as [`Self::start`] does, for hosts that
    /// connect to the local socket at `socket_path`: connecting attaches,
    /// closing detaches, and a new connection replaces the current one.
    /// The socket is placed where only processes entitled to the radio
    /// can reach it, and is removed when the radio stops.
    #[uniffi::constructor]
    pub fn serve(
        state_dir: String,
        socket_path: String,
        enable_phy: bool,
        reach: MobileVirtualRadioReach,
        listener: Arc<dyn MobileVirtualRadioListener>,
    ) -> Result<Arc<Self>, MobileVirtualRadioError> {
        Self::launch(
            PathBuf::from(state_dir),
            Some(PathBuf::from(socket_path)),
            enable_phy,
            reach.config(),
            listener,
        )
    }

    /// A host in this process attached, taking replies at `sink`: the
    /// device starts a session, which the attach itself does not announce.
    pub fn attach(&self, sink: Arc<dyn MobileWireSink>) {
        self.send(HostEvent::Attach(Box::new(move |bytes| {
            sink.on_wire(bytes)
        })));
    }

    /// Bytes from the attached host, in HDLC-Lite, in any chunking.
    pub fn receive(&self, bytes: Vec<u8>) {
        self.send(HostEvent::Bytes(bytes));
    }

    /// The host went away: the device carries on detached.
    pub fn detach(&self) {
        self.send(HostEvent::Detach);
    }

    /// Stop the device. It cannot be started again; make another.
    pub fn stop(&self) {
        if let Ok(mut stop) = self.stop.lock() {
            stop.take();
        }
    }
}

impl MobileVirtualRadio {
    /// Hand the device a host event without waiting: these are called on
    /// the platform's threads, which may be the one a sink reports on. An
    /// event dropped because the device fell [`lan::HOST_EVENT_DEPTH`]
    /// behind costs what it carried; the host's own retries cover lost
    /// bytes.
    fn send(&self, event: HostEvent) {
        if let Err(mpsc::error::TrySendError::Full(event)) = self.events.try_send(event) {
            log::warn!(event = event.kind(); "the virtual radio fell behind and dropped a host event");
        }
    }

    fn launch(
        dir: PathBuf,
        socket: Option<PathBuf>,
        enable_phy: bool,
        lan: LanConfig,
        listener: Arc<dyn MobileVirtualRadioListener>,
    ) -> Result<Arc<Self>, MobileVirtualRadioError> {
        let platform =
            HostPlatform::new(&dir).map_err(|_| MobileVirtualRadioError::StateUnavailable)?;
        let lock = StateLock::try_acquire(&dir)
            .map_err(|_| MobileVirtualRadioError::StateUnavailable)?
            .ok_or(MobileVirtualRadioError::StateInUse)?;

        let (events, host_events) = mpsc::channel(lan::HOST_EVENT_DEPTH);
        let socket_events = events.clone();
        let stop = driven::spawn("umsh-virtual-radio", move || {
            // The socket binds to the worker's reactor, so it is made there
            // rather than by the caller.
            let local = socket
                .as_deref()
                .map(lan::bind_local_socket)
                .transpose()
                .map_err(|_| MobileVirtualRadioError::SocketUnavailable)?;
            let held = Held {
                socket,
                _lock: lock,
            };
            let mut device = SoftDevice::new(lan::session_config(DEV_VERSION), platform);
            if enable_phy && !device.session().settings().enabled {
                let _ = device.session_mut().toggle_radio(&mut |_| {});
            }
            Ok(async move {
                let _held = held;
                let running = lan::run(device, lan, host_events, move |notice| {
                    listener.on_queued(notice.into())
                });
                let serving = async move {
                    if let Some(local) = local {
                        lan::serve(local, socket_events).await;
                    }
                    std::future::pending::<()>().await
                };
                tokio::select! {
                    () = running => {}
                    () = serving => {}
                }
            })
        })
        .map_err(|error| match error {
            SpawnError::Worker => MobileVirtualRadioError::WorkerUnavailable,
            SpawnError::Start(error) => error,
        })?;
        Ok(Arc::new(Self {
            events,
            stop: Mutex::new(Some(stop)),
        }))
    }
}

/// What a running virtual radio holds until it stops: its state, and the
/// socket it serves on, which goes with it.
struct Held {
    socket: Option<PathBuf>,
    _lock: StateLock,
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(path) = &self.socket {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc as std_mpsc;
    use std::time::Duration;

    use umsh_ulcp::{frame, hdlc, ids::prop};

    use super::*;

    struct Collect(Mutex<std_mpsc::Sender<Vec<u8>>>);

    impl MobileVirtualRadioListener for Collect {
        fn on_queued(&self, _: MobileQueuedNoticeRecord) {}
    }

    /// `ThisHost` stays on the loopback interface: a test radio that joined
    /// the LAN could reach a bridge that carries it onto the air.
    #[test]
    fn reach_this_host_is_loopback_only() {
        let this_host = MobileVirtualRadioReach::ThisHost.config();
        assert_eq!(this_host.interface, std::net::Ipv4Addr::LOCALHOST);
        assert_eq!(
            this_host,
            LanConfig::host_local(DEFAULT_GROUP.into(), DEFAULT_PORT)
        );
        assert_eq!(MobileVirtualRadioReach::Lan.config(), LanConfig::lan());
        assert_ne!(
            MobileVirtualRadioReach::Lan.config().interface,
            std::net::Ipv4Addr::LOCALHOST
        );
    }

    impl MobileWireSink for Collect {
        fn on_wire(&self, bytes: Vec<u8>) {
            let _ = self.0.lock().unwrap().send(bytes);
        }
    }

    /// Start a radio that joins its group on the loopback interface only.
    /// The device names the group; the interface keeps it on this host. A
    /// test never joins the LAN: what reaches the group there may be
    /// carried onto the air.
    fn start_local(
        path: &str,
        enable_phy: bool,
        listener: Arc<Collect>,
    ) -> Result<Arc<MobileVirtualRadio>, MobileVirtualRadioError> {
        let lan = LanConfig::host_local(std::net::Ipv4Addr::new(239, 255, 42, 112), 47_112);
        MobileVirtualRadio::launch(PathBuf::from(path), None, enable_phy, lan, listener)
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "umsh-mobile-virtual-radio-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// A host's request is answered, and a second radio on the same state
    /// is refused while the first runs.
    #[test]
    fn a_host_reaches_the_device() {
        let dir = scratch("host");
        let (wire_tx, wire) = std_mpsc::channel();
        let listener = Arc::new(Collect(Mutex::new(wire_tx)));
        let path = dir.to_string_lossy().into_owned();
        let radio = start_local(&path, true, listener.clone()).unwrap();
        assert_eq!(
            start_local(&path, true, listener.clone()).err(),
            Some(MobileVirtualRadioError::StateInUse)
        );

        radio.attach(listener.clone());
        let mut request = [0u8; 16];
        let len = frame::prop_get(&mut request, 1, prop::PHY_ENABLED).unwrap();
        let mut encoded = vec![0; hdlc::max_encoded_len(len)];
        let encoded_len = hdlc::encode_frame(&request[..len], &mut encoded).unwrap();
        radio.receive(encoded[..encoded_len].to_vec());

        // The largest frame and its two-octet FCS.
        let mut decoder = hdlc::Decoder::<{ umsh_ulcp::gatt::MAX_FRAME + 2 }>::new();
        let mut frames = Vec::new();
        while frames.is_empty() {
            let bytes = wire
                .recv_timeout(Duration::from_secs(2))
                .expect("the device answers");
            for byte in bytes {
                if let Some(Ok(frame)) = decoder.push(byte) {
                    frames.push(frame.to_vec());
                }
            }
        }
        // The attach emits nothing, so the first frame is the answer to
        // the GET: PHY on, as asked for at start.
        assert_eq!(frames[0].last(), Some(&1));

        radio.stop();
        // The worker lets go of the state as it winds down.
        let mut again = None;
        for _ in 0..100 {
            match start_local(&path, false, listener.clone()) {
                Ok(radio) => {
                    again = Some(radio);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        assert!(again.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A serving radio answers on a connection to its socket, and takes
    /// its socket with it when it stops.
    #[test]
    fn a_serving_radio_answers_on_its_socket() {
        use std::io::Read;

        let dir = scratch("serve");
        let socket = dir.join("ulcp");
        let (wire_tx, _) = std_mpsc::channel();
        let listener = Arc::new(Collect(Mutex::new(wire_tx)));
        let radio = MobileVirtualRadio::serve(
            dir.to_string_lossy().into_owned(),
            socket.to_string_lossy().into_owned(),
            false,
            MobileVirtualRadioReach::ThisHost,
            listener,
        )
        .unwrap();
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = [0u8; 8];
        let len = frame::nop(&mut request, 1).unwrap();
        let mut encoded = vec![0; hdlc::max_encoded_len(len)];
        let encoded_len = hdlc::encode_frame(&request[..len], &mut encoded).unwrap();
        std::io::Write::write_all(&mut stream, &encoded[..encoded_len]).unwrap();
        let mut buf = [0u8; 64];
        assert!(stream.read(&mut buf).unwrap() > 0);

        radio.stop();
        for _ in 0..100 {
            if !socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!socket.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
