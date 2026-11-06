//! A device configuration with everything turned on, so that no property a
//! real node offers is out of a target's reach.

use std::cell::Cell;
use std::rc::Rc;

use umsh_ulcp::stats::{COUNTERS, Counter, StatsLedger};
use umsh_ulcp_device::Effect;
use umsh_ulcp_simdev::soft::{DeviceSession, SoftDevice, SoftPlatform};
use umsh_ulcp_simdev::{DutyLedger, LanBearerRole, SessionConfig, SimulatedPlatform, full_config};

static DUTY: DutyLedger = DutyLedger::new();
static STATS: StatsLedger = StatsLedger::new();

/// The configuration a target's device runs. The ledgers are statics rather
/// than leaked per input: a leak per run would read as a finding.
pub fn config() -> SessionConfig {
    reset_ledgers();
    SessionConfig {
        mac_node: true,
        meshcore_forwarder: true,
        lan_bearer: LanBearerRole::None,
        messaging: true,
        ..full_config(&DUTY, Some(&STATS))
    }
}

/// Clear what outlives a session, so that one input cannot affect the next.
pub fn reset_ledgers() {
    DUTY.reset_accounting();
    for counter in Counter::ALL.iter().take(COUNTERS) {
        STATS.reset(*counter);
    }
}

/// Set to make a device's storage refuse writes.
pub type StorageFault = Rc<Cell<bool>>;

/// The simulated platform, with storage a script can make fail.
pub struct FaultyPlatform {
    pub inner: SimulatedPlatform,
    failing: StorageFault,
}

impl FaultyPlatform {
    fn check(&self) -> Result<(), ()> {
        if self.failing.get() { Err(()) } else { Ok(()) }
    }
}

impl SoftPlatform for FaultyPlatform {
    fn load_snapshot(&mut self) -> Option<Vec<u8>> {
        self.inner.load_snapshot()
    }

    fn store_snapshot(&mut self, snapshot: Option<&[u8]>) -> Result<(), ()> {
        self.check()?;
        self.inner.store_snapshot(snapshot)
    }

    fn load_identity(&mut self) -> Option<[u8; 32]> {
        self.inner.load_identity()
    }

    fn store_identity(&mut self, secret: Option<&[u8; 32]>) -> Result<(), ()> {
        self.check()?;
        self.inner.store_identity(secret)
    }

    fn generate_secret(&mut self) -> [u8; 32] {
        self.inner.generate_secret()
    }

    fn wall_clock(&mut self) -> Option<u32> {
        self.inner.wall_clock()
    }

    fn set_wall_clock(&mut self, epoch: Option<u32>) {
        self.inner.set_wall_clock(epoch);
    }

    fn held_lists(&self) -> Option<&'static [[u8; 32]]> {
        self.inner.held_lists()
    }

    fn load_lists(&mut self) -> Option<Vec<u8>> {
        self.inner.load_lists()
    }

    fn store_lists(&mut self, record: Option<&[u8]>) -> Result<(), ()> {
        self.check()?;
        self.inner.store_lists(record)
    }

    fn on_boot(&mut self, session: &mut DeviceSession) {
        self.inner.on_boot(session);
    }

    fn erase(&mut self) {
        self.inner.erase();
    }

    fn peripheral(
        &mut self,
        effect: Effect,
        session: &mut DeviceSession,
        emit: &mut dyn FnMut(&[u8]),
    ) {
        self.inner.peripheral(effect, session, emit);
    }

    fn settle(&mut self, session: &mut DeviceSession, now_ms: u64, emit: &mut dyn FnMut(&[u8])) {
        self.inner.settle(session, now_ms, emit);
    }
}

/// A soft device on this module's configuration.
pub fn soft_device() -> (SoftDevice<FaultyPlatform>, StorageFault) {
    let failing = StorageFault::default();
    let platform = FaultyPlatform {
        inner: SimulatedPlatform::new(),
        failing: failing.clone(),
    };
    (SoftDevice::new(config(), platform), failing)
}
