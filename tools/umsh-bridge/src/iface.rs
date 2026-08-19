//! The server's interfaces: its own radio, plus one per configured
//! client.
//!
//! The set is static — clients are named in the configuration, and a
//! disconnected client is an interface that is down, not an interface
//! that is gone — so an interface is an index for the whole run and the
//! engine can name one in a log line without a lookup.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::config::{RADIO_INTERFACE, ServerConfig};
use crate::tunnel::{TunnelFrame, TunnelQueue};

/// Index into [`Interfaces::all`].
pub type InterfaceId = usize;

/// What stands behind an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceKind {
    /// The server's own radio.
    Radio,
    /// A tunnel client, as an index into `ServerConfig::clients`.
    Client(usize),
    /// A host interface, as an index into `ServerConfig::hosts`: a
    /// socket presenting a simulated device whose radio is the bridge.
    Host(usize),
}

pub struct Interface {
    pub id: InterfaceId,
    pub name: String,
    /// Frames waiting to leave through this interface.
    pub egress: Arc<TunnelQueue>,
    pub kind: InterfaceKind,
    connected: AtomicBool,
}

impl Interface {
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub fn set_connected(&self, connected: bool) {
        self.connected.store(connected, Ordering::Relaxed);
    }

    /// Queue a frame for transmission, unless the interface is down —
    /// in which case there is nothing to hold it for.
    pub fn send(&self, frame: TunnelFrame) {
        if !self.is_connected() {
            return;
        }
        if self.egress.push(frame) {
            tracing::warn!(iface = %self.name, "egress queue full; dropped the oldest frame");
        }
    }
}

pub struct Interfaces {
    pub all: Vec<Arc<Interface>>,
    /// The server's own radio, when it has one.
    pub radio: Option<InterfaceId>,
}

impl Interfaces {
    pub fn build(config: &ServerConfig) -> Self {
        let max_age = Duration::from_secs(config.tunnel.max_frame_age_secs);
        let depth = config.tunnel.queue_depth;
        let mut all: Vec<Arc<Interface>> = Vec::new();

        let radio = (!config.radio.is_none()).then(|| {
            all.push(Arc::new(Interface {
                id: 0,
                name: RADIO_INTERFACE.to_string(),
                egress: Arc::new(TunnelQueue::new(depth, max_age)),
                kind: InterfaceKind::Radio,
                // Always up: the relay re-opens a failed device on its
                // own, and the bounded, staleness-dropped queue holds
                // what little accrues in the meantime.
                connected: AtomicBool::new(true),
            }));
            0
        });

        for (index, client) in config.clients.iter().enumerate() {
            all.push(Arc::new(Interface {
                id: all.len(),
                name: client.name.clone(),
                egress: Arc::new(TunnelQueue::new(depth, max_age)),
                kind: InterfaceKind::Client(index),
                connected: AtomicBool::new(false),
            }));
        }

        for (index, host) in config.hosts.iter().enumerate() {
            all.push(Arc::new(Interface {
                id: all.len(),
                name: host.name.clone(),
                egress: Arc::new(TunnelQueue::new(depth, max_age)),
                kind: InterfaceKind::Host(index),
                connected: AtomicBool::new(false),
            }));
        }

        Self { all, radio }
    }

    pub fn get(&self, id: InterfaceId) -> &Arc<Interface> {
        &self.all[id]
    }

    pub fn by_client(&self, client: usize) -> Option<&Arc<Interface>> {
        self.all
            .iter()
            .find(|iface| iface.kind == InterfaceKind::Client(client))
    }

    pub fn by_host(&self, host: usize) -> Option<&Arc<Interface>> {
        self.all
            .iter()
            .find(|iface| iface.kind == InterfaceKind::Host(host))
    }

    pub fn name(&self, id: InterfaceId) -> &str {
        &self.all[id].name
    }
}

/// A frame that arrived, and where from.
pub struct Ingress {
    pub iface: InterfaceId,
    pub frame: TunnelFrame,
}
