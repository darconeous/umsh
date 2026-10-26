//! What the session driver needs of this board: where the saved
//! configuration and the device identity are kept, the device lists in the
//! chat store as on the Pager, the wall clock, the radio's group, and what
//! a reboot or a factory reset does.
//!
//! The process is the device, so restarting it is a reboot: the
//! executable runs again in place with the same arguments.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

use tokio::sync::watch;
use umsh_journal_store::proto::StoredIdentity;
use umsh_ulcp::Status;
use umsh_ulcp_device::IdentityForm;
use umsh_ulcp_runtime::device_node;
use umsh_ulcp_runtime::driver::{self, DevDomainSnapshot, LanBearerSettings, PublishEvent};
use umsh_ulcp_runtime::log::debug_log;
use umsh_ulcp_simdev::host::HostPlatform;
use umsh_ulcp_simdev::soft::SoftPlatform as _;

use crate::node::Node;

/// Set in the environment of a process that a reboot started, so that it
/// boots as a software reset rather than a power-on.
pub const REBOOTED: &str = "UMSH_HOST_COMMUNICATOR_REBOOTED";

pub struct HostEnv {
    /// The instance's directory, and its snapshot and identity files.
    pub dir: PathBuf,
    pub files: HostPlatform,
    /// The node's frame-counter boundaries.
    pub counters: PathBuf,
    pub chats: &'static Node,
    /// The group the radio is to join.
    pub group: watch::Sender<SocketAddrV4>,
    /// How joining it went.
    pub lan_state: watch::Receiver<umsh_ulcp::lan::State>,
}

impl HostEnv {
    /// The process again, in place: what a reset does to a board.
    fn restart(&self) -> ! {
        use std::os::unix::process::CommandExt as _;
        let error = std::process::Command::new(std::env::current_exe().unwrap_or_default())
            .args(std::env::args_os().skip(1))
            .env(REBOOTED, "1")
            .exec();
        eprintln!("host-communicator: restarting: {error}");
        std::process::exit(1)
    }
}

impl driver::DeviceEnv for HostEnv {
    async fn persist_snapshot(&mut self, bytes: &[u8]) -> Result<(), ()> {
        self.files.store_snapshot(Some(bytes))
    }

    async fn clear_snapshot(&mut self) -> Result<(), ()> {
        self.files.store_snapshot(None)
    }

    async fn persist_identity(&mut self, bytes: &[u8]) -> Result<(), ()> {
        match driver::stored_device_identity(Some(bytes)) {
            StoredIdentity::Keys { secret, .. } => self.files.store_identity(Some(&secret)),
            _ => Err(()),
        }
    }

    async fn clear_identity(&mut self) -> Result<(), ()> {
        self.files.store_identity(None)
    }

    async fn clear_counters(&mut self) {
        let _ = std::fs::remove_dir_all(&self.counters);
    }

    async fn persist_lists(&mut self, record: Option<&[u8]>) -> Result<(), ()> {
        self.chats.keep_device_lists(record).map_err(|_| ())
    }

    fn fill_secret(&mut self, secret: &mut [u8; 32]) -> Result<(), ()> {
        *secret = self.files.generate_secret();
        Ok(())
    }

    async fn read_time(&mut self) -> Option<u32> {
        umsh_hal::wall_clock::now()
    }

    async fn apply_time(&mut self, epoch: Option<u32>) {
        match epoch {
            Some(seconds) => {
                umsh_hal::wall_clock::set_manual(seconds);
            }
            None => umsh_hal::wall_clock::clear(),
        }
    }

    async fn publish_event(&mut self) -> PublishEvent {
        if self.lan_state.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
        PublishEvent::LanBearerState(*self.lan_state.borrow_and_update())
    }

    async fn sign_identity(&mut self, out: &mut [u8], form: IdentityForm) -> Option<usize> {
        device_node::sign_identity_blob(out, form).await
    }

    async fn apply_pairing_pin(&mut self, _pin: Option<u32>) -> bool {
        false
    }

    fn apply_lan_bearer(&mut self, settings: LanBearerSettings<'_>) {
        let group = settings.config.group();
        self.group.send_if_modified(|current| {
            let wanted = SocketAddrV4::new(Ipv4Addr::from(group.address), group.port);
            core::mem::replace(current, wanted) != wanted
        });
    }

    async fn factory_reset(&mut self) -> ! {
        debug_log(format_args!("FACTORY RESET: erasing storage + restart"));
        device_node::quiesce_for_reboot().await;
        super::erase(&self.dir);
        self.restart()
    }

    async fn reboot(&mut self) -> ! {
        device_node::quiesce_for_reboot().await;
        debug_log(format_args!("REBOOT: restarting"));
        self.restart()
    }

    fn set_advertising_allowed(&mut self, _allowed: bool) {}

    async fn publish_device_name(&mut self, name: &str) {
        device_node::set_device_name(name.as_bytes());
    }

    fn publish_dev_domain(&mut self, snapshot: DevDomainSnapshot) {
        umsh_hal::wall_clock::set_tz_rule(snapshot.tz_rule);
        umsh_hal::wall_clock::set_hour24(snapshot.time_24h);
        device_node::publish_snapshot(snapshot);
    }

    fn trace(&mut self, args: core::fmt::Arguments<'_>) {
        debug_log(args);
    }
}

/// How the process came to be running.
pub fn boot_reason() -> Status {
    if std::env::var_os(REBOOTED).is_some() {
        Status::RESET_SOFTWARE
    } else {
        Status::RESET_POWER_ON
    }
}
