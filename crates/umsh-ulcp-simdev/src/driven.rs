//! A soft device driven for as long as its owner runs it, on a medium the
//! owner chooses.
//!
//! [`run`] takes the host's side of the link as [`HostEvent`]s, each
//! attach bringing the sink its replies go to, and puts what the device
//! transmits on a [`Medium`], which also brings it what it hears. The LAN
//! virtual radio's medium is its multicast group (`lan::LanGroup`); a
//! staged mesh's is memory. [`spawn`] gives such a device a thread of its
//! own.

use std::future::Future;

use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use umsh_ulcp_device::{QueuedNotice, RadioRxInfo, TxOutcome};

use crate::soft::{SoftDevice, SoftPlatform};

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

impl HostEvent {
    /// What the event is, for a log line.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Attach(_) => "attach",
            Self::Bytes(_) => "bytes",
            Self::Detach => "detach",
        }
    }
}

/// Host events waiting for the device: a host that writes faster than
/// the device reads waits for room.
pub const HOST_EVENT_DEPTH: usize = 64;

/// A frame the device heard, with what its receiver measured.
pub struct Heard {
    pub frame: Vec<u8>,
    pub info: RadioRxInfo,
}

/// What a driven device transmits on and hears from.
pub trait Medium {
    /// Bring the medium in line with what the device now holds. Called
    /// before each wait, so it follows anything a host just changed.
    fn follow<P: SoftPlatform>(&mut self, device: &mut SoftDevice<P>);

    /// Put a frame the device transmitted on the medium, and say what
    /// became of it.
    fn transmit(&mut self, frame: &[u8]) -> impl Future<Output = TxOutcome>;

    /// The next frame heard, or `None` when the medium woke for a reason
    /// of its own. Must be cancel-safe: it races the host's events.
    fn hear(&mut self) -> impl Future<Output = Option<Heard>>;
}

/// Why [`spawn`] did not start its worker.
#[derive(Debug, PartialEq, Eq)]
pub enum SpawnError<E> {
    /// The thread or its runtime could not be made.
    Worker,
    /// The caller's `start` failed.
    Start(E),
}

/// Run the future `start` makes on a thread of its own, on a
/// current-thread runtime, until the future ends or the returned sender is
/// dropped.
///
/// `start` runs on that thread within the runtime, so what it binds to a
/// reactor binds to the one its future runs on. This returns once `start`
/// has. The future is dropped on the runtime, so what it holds is let go
/// of there.
pub fn spawn<E, Fut>(
    name: &str,
    start: impl FnOnce() -> Result<Fut, E> + Send + 'static,
) -> Result<oneshot::Sender<()>, SpawnError<E>>
where
    E: Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let (stop, stopped) = oneshot::channel::<()>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                let _ = ready_tx.send(Err(SpawnError::Worker));
                return;
            };
            let running = {
                let _context = runtime.enter();
                match start() {
                    Ok(running) => running,
                    Err(error) => {
                        let _ = ready_tx.send(Err(SpawnError::Start(error)));
                        return;
                    }
                }
            };
            let _ = ready_tx.send(Ok(()));
            runtime.block_on(async move {
                // Boxed so a device's session lives on the heap, not this
                // thread's stack.
                let running = Box::pin(running);
                tokio::select! {
                    () = running => {}
                    _ = stopped => {}
                }
            });
        })
        .map_err(|_| SpawnError::Worker)?;
    ready_rx.recv().map_err(|_| SpawnError::Worker)??;
    Ok(stop)
}

/// Run `device` on `medium` until the sender of `host` is dropped, telling
/// `queued` of each frame queued while no host is attached.
///
/// The device starts detached; a [`HostEvent::Attach`] attaches it.
/// Bytes that arrive while detached belong to no session and are
/// dropped. Each transmission stays in flight until the medium says what
/// became of it, as on a radio.
pub async fn run<P: SoftPlatform, M: Medium>(
    mut device: SoftDevice<P>,
    mut medium: M,
    mut host: mpsc::Receiver<HostEvent>,
    mut queued: impl FnMut(QueuedNotice),
) {
    let started = Instant::now();
    let now_ms = || started.elapsed().as_millis() as u64;
    let mut sink: Option<WireSink> = None;
    device.defer_tx();
    loop {
        // A host's write may have changed what the medium follows.
        medium.follow(&mut device);
        // A completed transmission may start the next.
        loop {
            let transmitted = device.take_transmitted();
            if transmitted.is_empty() {
                break;
            }
            for frame in transmitted {
                let outcome = medium.transmit(&frame).await;
                device.complete_tx(outcome, now_ms());
            }
        }
        // Whatever the device has to say goes out next: an attach's own
        // notice, then each reply in turn.
        while let Some(wire) = device.take_outbound() {
            if let Some(sink) = &mut sink {
                sink(wire);
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
            heard = medium.hear() => {
                if let Some(heard) = heard {
                    device.inject_radio_rx(&heard.frame, &heard.info, now_ms());
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
