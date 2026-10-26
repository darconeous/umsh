//! The LAN virtual radio: a soft ULCP device in this process whose PHY is
//! the LAN bearer's multicast group.
//!
//! The device is the production session on a file-backed platform, so it
//! has an identity and saved configuration of its own that persist from
//! one invocation to the next. The tool reaches it over an in-memory byte
//! pipe carrying the same HDLC-Lite framing a wire does, and everything
//! above that—attach, the mesh session, every command—is unchanged.
//!
//! What the device transmits is sent to the group, where every radio with
//! its bearer enabled hears it; what any participant sends to the group
//! is received unmeasured, since nothing here measured it.

use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use umsh::tokio_support::LanConfig;
use umsh_ulcp_simdev::host::{HostPlatform, StateLock};
use umsh_ulcp_simdev::lan::{self, HostEvent};
use umsh_ulcp_simdev::soft::SoftDevice;

/// How much of the pipe to take in one read. ULCP frames are small; this
/// only bounds a burst.
const READ_CHUNK: usize = 4096;

/// How long an open waits for a previous virtual radio in this process
/// to let go of its state.
const LOCK_PATIENCE: Duration = Duration::from_secs(2);

/// Where the virtual radio keeps its identity and saved configuration.
fn device_dir() -> Result<PathBuf> {
    crate::connection::state_dir()
        .map(|dir| dir.join("lan-device"))
        .ok_or_else(|| anyhow!("no HOME directory to keep the LAN device's state in"))
}

/// Start a virtual radio and return the host's end of the link to it.
/// A `group` stands in for the radio's own until it exits, as an unsaved
/// write of `PROP_LAN_BEARER_GROUP` would.
///
/// The device runs on this thread's `LocalSet` until the host's end is
/// dropped.
pub async fn open(group: Option<SocketAddrV4>) -> Result<DuplexStream> {
    let dir = device_dir()?;
    let platform =
        HostPlatform::new(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let deadline = tokio::time::Instant::now() + LOCK_PATIENCE;
    let lock = loop {
        if let Some(lock) =
            StateLock::try_acquire(&dir).with_context(|| format!("locking {}", dir.display()))?
        {
            break lock;
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "another umshctl is already the LAN virtual radio ({} is locked)",
                dir.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let (host, device_end) = tokio::io::duplex(READ_CHUNK);
    let mut device = SoftDevice::new(
        lan::session_config(concat!("umshctl-lan/", env!("CARGO_PKG_VERSION"))),
        platform,
    );
    // Asking for the LAN is asking for it on. A LoRa radio comes up off
    // so that a throwaway identity never reaches the air; this one has no
    // node of its own and sends only its host's frames.
    if !device.session().settings().enabled {
        let _ = device.session_mut().toggle_radio(&mut |_| {});
    }
    if let Some(group) = group {
        device
            .session_mut()
            .set_lan_bearer_group(Some(umsh::ulcp_wire::lan::Group {
                address: group.ip().octets(),
                port: group.port(),
            }));
    }
    let (events, host_events) = mpsc::unbounded_channel();
    let (wire_tx, wire_rx) = mpsc::unbounded_channel();
    let _ = events.send(HostEvent::Attach(Box::new(move |wire| {
        let _ = wire_tx.send(wire);
    })));
    tokio::task::spawn_local(async move {
        // Nobody is told of a queued frame: the tool is attached for as
        // long as the device runs.
        lan::run(device, LanConfig::lan(), host_events, |_| {}).await;
        drop(lock);
    });
    tokio::task::spawn_local(relay(device_end, events, wire_rx));
    Ok(host)
}

/// Carry the pipe to the device and back until the host lets go, which
/// stops the device.
async fn relay(
    mut pipe: DuplexStream,
    events: mpsc::UnboundedSender<HostEvent>,
    mut wire: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        tokio::select! {
            read = pipe.read(&mut buf) => match read {
                Ok(0) | Err(_) => break,
                Ok(len) => {
                    if events.send(HostEvent::Bytes(buf[..len].to_vec())).is_err() {
                        break;
                    }
                }
            },
            frame = wire.recv() => match frame {
                Some(frame) if pipe.write_all(&frame).await.is_ok() => {}
                _ => break,
            },
        }
    }
}
