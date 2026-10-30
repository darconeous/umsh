//! The host as one more board under the Pager's firmware: its ULCP
//! session driver, radio multiplexer, and device node, all from
//! `umsh-ulcp-runtime`, wired as `firmware-esp32`'s tracker wires them.
//! What the host supplies is what any board supplies: a clock
//! ([`time`]), a radio ([`phy`], an IP multicast group), and storage and
//! resets ([`env`], files in the instance's directory).
//!
//! Everything runs on one single-threaded runtime that the window's loop
//! drives between frames, so the node, the chats, and the window share a
//! thread, as they share a core on the Pager.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU32;
use std::time::Duration;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tokio::task::LocalSet;
use umsh::tokio_support::{LanConfig, TokioFileCounterStore};
use umsh_communicator::task::{self, Inbox};
use umsh_communicator::{
    ChannelCrypto, CommunicatorNode, FlashMap, FlashMapStore, Quota, Seeds, WellKnownChannels,
};
use umsh_crypto::CryptoEngine;
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_radio_loraphy::{Channels, DeviceControl};
use umsh_ulcp::stats::StatsLedger;
use umsh_ulcp_admin::local::driver::DriverPort;
use umsh_ulcp_device::{DutyLedger, SNAPSHOT_MAX};
use umsh_ulcp_runtime::device_node::{self, NodeHooks};
use umsh_ulcp_runtime::driver::{
    self, DeviceLink, DeviceRuntime, InputChannel, SnapshotControl, TransportChannels,
};
use umsh_ulcp_runtime::{admin_responder, radio_mux};
use umsh_ulcp_simdev::host::{HostPlatform, StateLock};
use umsh_ulcp_simdev::soft::SoftPlatform as _;

use crate::flash::{self, FileFlash};
use umsh_ux_communicator::model::Node as _;

use crate::node::{self, CLOCK, Node};

mod env;
mod phy;
mod time;

type Mutex = CriticalSectionRawMutex;
type RadioCh = Channels<Mutex, 4, 2>;
type CounterStore = TokioFileCounterStore;
type Session = umsh_ulcp_device::Session<SoftwareAes, SoftwareSha256, 8>;

/// The radio itself, which the multiplexer owns.
static REAL_CH: RadioCh = RadioCh::new();
/// The session's share of it; the device node's is `NODE_CH`.
static SESSION_CH: RadioCh = RadioCh::new();
static MUX_CLIENTS: [&RadioCh; 2] = [&SESSION_CH, &device_node::NODE_CH];
/// The radio's settings, as the session applies them.
static DEVICE_CTL: DeviceControl<Mutex> = DeviceControl::new();
static INPUT_CH: InputChannel<Mutex> = InputChannel::new();
static OUT_CH: TransportChannels<Mutex> = TransportChannels::new();
/// The communicator's way into the session.
static DEVICE_LINK: DeviceLink<Mutex> = DeviceLink::new();
static SESSION_GEN: AtomicU32 = AtomicU32::new(0);
static SNAPSHOT_CTL: SnapshotControl<Mutex> = SnapshotControl::new();
/// The device's one traffic ledger and one airtime ledger.
pub static STATS: StatsLedger = StatsLedger::new();
pub static DUTY: DutyLedger = DutyLedger::new();
/// What the device node received for the chats.
static INBOX: Inbox<Mutex> = Inbox::new();

/// The communicator's port into the session.
pub type Port = DriverPort<Mutex>;

/// How the device reaches its group.
#[derive(Clone, Copy)]
pub enum Network {
    /// Joined on `base`'s interface, with its loopback.
    Lan(LanConfig),
    /// Never joined: a script's device shows only what the script did.
    Offline,
}

/// A device, booted.
pub struct Board {
    runtime: Runtime,
    local: LocalSet,
    pub node: &'static Node,
    _lock: StateLock,
}

/// Why a device could not boot.
#[derive(Debug)]
pub enum BootError {
    /// Another process is this device already.
    Running,
    Io(io::Error),
}

impl From<io::Error> for BootError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => f.write_str("already running"),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl Board {
    /// Boots the device kept in `dir`, named `name` until it is given a
    /// name of its own; with `reset`, from nothing, as if new.
    pub fn start(
        dir: &Path,
        name: &'static str,
        network: Network,
        reset: bool,
    ) -> Result<Self, BootError> {
        std::fs::create_dir_all(dir)?;
        let lock = StateLock::try_acquire(dir)?.ok_or(BootError::Running)?;
        if reset {
            erase(dir);
        }
        time::start();
        // The host's clock is the device's real-time clock.
        if let Some(epoch) = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|since| u32::try_from(since.as_secs()).ok())
        {
            umsh_hal::wall_clock::apply(epoch, umsh_hal::wall_clock::TimeSource::ExternalRtc, true);
        }
        let mut files = HostPlatform::new(dir)?;

        // A device identity always exists: one is made at the first boot,
        // as firmware makes it.
        let secret = match files.load_identity() {
            Some(secret) => secret,
            None => {
                let secret = files.generate_identity_secret();
                files
                    .store_identity(Some(&secret))
                    .map_err(|()| io::Error::other("the device identity was not kept"))?;
                secret
            }
        };
        let (public, _) = driver::device_identity_record(&secret);
        let boot_snapshot = files.load_snapshot();
        let seed = files.generate_secret();
        let nonce = files.generate_secret();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let local = LocalSet::new();
        let node = chats(dir, &mut files)?;

        // The session, over the lists the chat store keeps, as the Pager's.
        let session: &'static mut Session = Box::leak(Box::new(Session::new(
            node::config(name),
            env::boot_reason(),
            CryptoEngine::new(SoftwareAes, SoftwareSha256),
        )));
        let snapshot: &'static mut [u8; SNAPSHOT_MAX] = Box::leak(Box::new([0; SNAPSHOT_MAX]));
        let defaults = Box::leak(Box::new(ChannelCrypto::software().starting_keys()));
        let kept = node.device_lists(&mut snapshot[..]).ok().flatten();
        session.hold_lists(defaults, kept);

        let default_group = umsh_ulcp::lan::Group::default();
        let (group, followed) = watch::channel(SocketAddrV4::new(
            Ipv4Addr::from(default_group.address),
            default_group.port,
        ));
        let (lan_state, lan_reported) = watch::channel(umsh_ulcp::lan::State::Disabled);
        let counters = dir.join("counters");
        let device = env::HostEnv {
            dir: dir.to_path_buf(),
            files,
            counters: counters.clone(),
            chats: node,
            group,
            lan_state: lan_reported,
        };
        let (base, offline) = match network {
            Network::Lan(base) => (base, false),
            Network::Offline => (LanConfig::lan(), true),
        };
        local.spawn_local(
            phy::Phy {
                base,
                group: followed,
                state: lan_state,
                offline,
            }
            .run(),
        );
        local.spawn_local(radio_mux::radio_mux(
            &REAL_CH,
            &MUX_CLIENTS,
            &radio_mux::MUX_MODE,
            Some(&STATS),
        ));
        local.spawn_local(async move {
            let boot_snapshot = boot_snapshot;
            driver::run_with_storage(
                session,
                snapshot,
                boot_snapshot.as_deref(),
                Some(public),
                DeviceRuntime {
                    input: &INPUT_CH,
                    radio: &SESSION_CH,
                    ctl: &DEVICE_CTL,
                    out: &OUT_CH,
                    session_gen: &SESSION_GEN,
                    device: Some(&DEVICE_LINK),
                    snapshot: &SNAPSHOT_CTL,
                },
                device,
            )
            .await
        });

        // The device node, and its tasks in the order the Pager spawns them.
        let arena = Box::leak(Box::new(core::mem::MaybeUninit::uninit()));
        let parts = local.block_on(
            &runtime,
            device_node::bring_up(
                arena,
                &secret,
                seed,
                umsh::tokio_support::UdpMulticastRadio::SIMULATED_T_FRAME_MS,
                CounterStore::new(counters)?,
                &DUTY,
                NodeHooks::default(),
            ),
        );
        std::mem::forget(task::listen(
            &parts.node,
            &INBOX,
            umsh::core::PublicKey(parts.node_key),
            WellKnownChannels::derive(),
        ));
        let mesh = parts.node.clone();
        local.spawn_local(async move {
            task::run(
                node,
                &mesh,
                &INBOX,
                |at| embassy_time::Timer::at(embassy_time::Instant::from_millis(at)),
                // The window takes the node's events every frame.
                || {},
            )
            .await
        });
        local.spawn_local(device_node::pump_loop(parts.host, parts.mac, Some(&STATS)));
        local.spawn_local(device_node::identity_blob_loop(
            parts.node.clone(),
            SoftwareIdentity::from_secret_bytes(&secret),
        ));
        local.spawn_local(device_node::dev_sync_loop(
            parts.node.clone(),
            parts.mac,
            parts.node_key,
        ));
        local.spawn_local(device_node::identity_profile_loop(parts.node.clone()));
        local.spawn_local(admin_responder::responder_loop(
            parts.node.clone(),
            &INPUT_CH,
            u16::from_be_bytes([nonce[0], nonce[1]]),
        ));
        local.spawn_local(device_node::beacon_loop(
            parts.node,
            SoftwareIdentity::from_secret_bytes(&secret),
            NodeHooks::default(),
        ));
        local.spawn_local(device_node::advert_loop(parts.mac));
        local.spawn_local(device_node::reboot_quiesce_loop(parts.mac));

        let board = Self {
            runtime,
            local,
            node,
            _lock: lock,
        };
        board.prime();
        Ok(board)
    }

    /// Waits for the node's first read of the settings, so the first frame
    /// shows the device's name and brightness rather than defaults.
    fn prime(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !self.node.primed() && std::time::Instant::now() < deadline {
            self.node.pump();
            self.run_for(Duration::from_millis(20));
        }
        self.node.pump();
        // The settings the interface reads in building its state.
        while self.node.next_event().is_some() {}
    }

    /// Lets the device run for `span`.
    pub fn run_for(&self, span: Duration) {
        self.runtime.block_on(
            self.local
                .run_until(async { tokio::time::sleep(span).await }),
        );
    }
}

/// The communicator's node over the session, with its chats in a flash
/// partition that is a file beside the device's other state.
fn chats(dir: &Path, files: &mut HostPlatform) -> io::Result<&'static Node> {
    let flash = FileFlash::open(&dir.join("chats.flash"))?;
    let buffer = Box::leak(vec![0u8; 2048].into_boxed_slice());
    let store = FlashMapStore::mount(
        FlashMap::new(flash, 0..flash::SIZE as u32, buffer),
        Quota::DEFAULT,
    )
    .map_err(|error| io::Error::other(format!("the chats did not mount: {error:?}")))?;
    let seed = files.generate_secret();
    let (session_id, jitter_seed) = seed.split_at(8);
    Ok(Box::leak(Box::new(CommunicatorNode::new(
        DriverPort::new(&INPUT_CH, &DEVICE_LINK),
        store,
        ChannelCrypto::software(),
        &std::alloc::System,
        &CLOCK,
        Seeds {
            session_id: u64::from_be_bytes(session_id.try_into().unwrap()),
            jitter_seed: u64::from_be_bytes(jitter_seed[..8].try_into().unwrap()),
        },
    ))))
}

/// What a device keeps in its directory, and the staged copies its files
/// are written through. Nothing else there is the device's to erase.
const KEPT: &[&str] = &[
    "identity.key",
    "identity.key.new",
    "snapshot.bin",
    "snapshot.bin.new",
    "lists.bin",
    "lists.bin.new",
    "chats.flash",
    "counters",
];

/// Erases everything the device in `dir` keeps, as a factory reset does.
fn erase(dir: &Path) {
    for name in KEPT {
        let path = dir.join(name);
        let _ = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
    }
}

/// Where instance `name` keeps itself by default:
/// `$XDG_CONFIG_HOME/umsh-host-communicator/NAME`, or under `~/.config`.
pub fn instance_dir(name: &str) -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(config.join("umsh-host-communicator").join(name))
}
