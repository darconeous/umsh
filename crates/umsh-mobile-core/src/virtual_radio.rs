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
use umsh_ulcp_device::{QueuedClass, QueuedNotice};
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
    events: mpsc::UnboundedSender<HostEvent>,
    /// Dropped to stop the device.
    stop: Mutex<Option<oneshot::Sender<()>>>,
}

#[uniffi::export]
impl MobileVirtualRadio {
    /// Start a virtual radio keeping its saved configuration under
    /// `state_dir`, for a host in this process.
    ///
    /// With `enable_phy`, the device comes up listening whatever it saved:
    /// starting it is choosing the LAN. Without, its saved state decides,
    /// so a host that turned the PHY off and saved keeps it off across
    /// restarts.
    #[uniffi::constructor]
    pub fn start(
        state_dir: String,
        enable_phy: bool,
        listener: Arc<dyn MobileVirtualRadioListener>,
    ) -> Result<Arc<Self>, MobileVirtualRadioError> {
        Self::launch(PathBuf::from(state_dir), None, enable_phy, listener)
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
        listener: Arc<dyn MobileVirtualRadioListener>,
    ) -> Result<Arc<Self>, MobileVirtualRadioError> {
        Self::launch(
            PathBuf::from(state_dir),
            Some(PathBuf::from(socket_path)),
            enable_phy,
            listener,
        )
    }

    /// A host in this process attached, taking replies at `sink`: the
    /// device starts a session, announcing it with `CMD_SESSION_RESET`.
    pub fn attach(&self, sink: Arc<dyn MobileWireSink>) {
        let _ = self.events.send(HostEvent::Attach(Box::new(move |bytes| {
            sink.on_wire(bytes)
        })));
    }

    /// Bytes from the attached host, in HDLC-Lite, in any chunking.
    pub fn receive(&self, bytes: Vec<u8>) {
        let _ = self.events.send(HostEvent::Bytes(bytes));
    }

    /// The host went away: the device carries on detached.
    pub fn detach(&self) {
        let _ = self.events.send(HostEvent::Detach);
    }

    /// Stop the device. It cannot be started again; make another.
    pub fn stop(&self) {
        if let Ok(mut stop) = self.stop.lock() {
            stop.take();
        }
    }
}

impl MobileVirtualRadio {
    fn launch(
        dir: PathBuf,
        socket: Option<PathBuf>,
        enable_phy: bool,
        listener: Arc<dyn MobileVirtualRadioListener>,
    ) -> Result<Arc<Self>, MobileVirtualRadioError> {
        let platform =
            HostPlatform::new(&dir).map_err(|_| MobileVirtualRadioError::StateUnavailable)?;
        let lock = StateLock::try_acquire(&dir)
            .map_err(|_| MobileVirtualRadioError::StateUnavailable)?
            .ok_or(MobileVirtualRadioError::StateInUse)?;

        let (events, host_events) = mpsc::unbounded_channel();
        let socket_events = events.clone();
        let (stop, stopped) = oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("umsh-virtual-radio".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ = ready_tx.send(Err(MobileVirtualRadioError::WorkerUnavailable));
                        return;
                    }
                };
                // The socket binds to this runtime's reactor, so it is
                // made here rather than by the caller.
                let local = match &socket {
                    Some(path) => match runtime.block_on(async { lan::bind_local_socket(path) }) {
                        Ok(local) => Some(local),
                        Err(_) => {
                            let _ = ready_tx.send(Err(MobileVirtualRadioError::SocketUnavailable));
                            return;
                        }
                    },
                    None => None,
                };
                let mut device = SoftDevice::new(lan::session_config(DEV_VERSION), platform);
                if enable_phy && !device.session().settings().enabled {
                    let _ = device.session_mut().toggle_radio(&mut |_| {});
                }
                let _ = ready_tx.send(Ok(()));
                runtime.block_on(async move {
                    // Boxed so the session lives on the heap, not this
                    // thread's stack.
                    let running = Box::pin(lan::run(
                        device,
                        LanConfig::lan(),
                        host_events,
                        move |notice| listener.on_queued(notice.into()),
                    ));
                    let serving = async move {
                        if let Some(local) = local {
                            lan::serve(local, socket_events).await;
                        }
                        std::future::pending::<()>().await
                    };
                    tokio::select! {
                        () = running => {}
                        () = serving => {}
                        _ = stopped => {}
                    }
                });
                if let Some(path) = socket {
                    let _ = std::fs::remove_file(path);
                }
                drop(lock);
            })
            .map_err(|_| MobileVirtualRadioError::WorkerUnavailable)?;
        ready_rx
            .recv()
            .map_err(|_| MobileVirtualRadioError::WorkerUnavailable)??;
        Ok(Arc::new(Self {
            events,
            stop: Mutex::new(Some(stop)),
        }))
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

    impl MobileWireSink for Collect {
        fn on_wire(&self, bytes: Vec<u8>) {
            let _ = self.0.lock().unwrap().send(bytes);
        }
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
        let radio = MobileVirtualRadio::start(path.clone(), true, listener.clone()).unwrap();
        assert_eq!(
            MobileVirtualRadio::start(path.clone(), true, listener.clone()).err(),
            Some(MobileVirtualRadioError::StateInUse)
        );

        radio.attach(listener.clone());
        let mut request = [0u8; 16];
        let len = frame::prop_get(&mut request, 1, prop::PHY_ENABLED).unwrap();
        let mut encoded = vec![0; hdlc::max_encoded_len(len)];
        let encoded_len = hdlc::encode_frame(&request[..len], &mut encoded).unwrap();
        radio.receive(encoded[..encoded_len].to_vec());

        let mut decoder = hdlc::Decoder::<512>::new();
        let mut frames = Vec::new();
        while frames.len() < 2 {
            let bytes = wire
                .recv_timeout(Duration::from_secs(2))
                .expect("the device answers");
            for byte in bytes {
                if let Some(Ok(frame)) = decoder.push(byte) {
                    frames.push(frame.to_vec());
                }
            }
        }
        // The answer to the GET: PHY on, as asked for at start.
        assert_eq!(frames[1].last(), Some(&1));

        radio.stop();
        // The worker lets go of the state as it winds down.
        let mut again = None;
        for _ in 0..100 {
            match MobileVirtualRadio::start(path.clone(), false, listener.clone()) {
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

    /// A serving radio greets a connection with a session reset, and
    /// takes its socket with it when it stops.
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
            listener,
        )
        .unwrap();
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
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
