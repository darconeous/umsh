//! What a board does with a GNSS fix, shared by every board that has one.
//!
//! [`umsh_gnss`] gets a receiver talking and turns its sentences into a
//! [`Fix`](umsh_gnss::Fix). This turns a `Fix` into the three things UMSH
//! actually wants from one:
//!
//! * the ULCP positioning properties a host reads and the device
//!   announces,
//! * the wall clock, when the receiver's time is trusted,
//! * the advertised node identity's location, when that is switched on.
//!
//! It lives here rather than in `umsh-gnss` because all three are
//! protocol concerns, and here rather than in each firmware because both
//! cargo workspaces would otherwise write it twice. A board contributes
//! its pins; this contributes the meaning.
//!
//! # Reading versus announcing
//!
//! The last fix is cached here and nowhere else. The ULCP session
//! deliberately never caches a reading — a `CMD_PROP_GET` samples — so
//! "the most recent thing the receiver said" has to live somewhere the
//! sampler can reach, and this is it.
//!
//! **A position is never announced.** Where the device is, how high, how
//! well it knows, and off how many satellites are all poll-only: a host
//! that wants them asks, and asks no more often than it has something to
//! do with the answer. Announcing them instead would put this board on
//! the air continuously for no one — a receiver reports about a fix a
//! second, and at the precision the cache keeps, ordinary noise from a
//! receiver that has not moved is enough to make consecutive readings
//! differ. Every one of those would have cost a BLE notification and a
//! wakeup at both ends.
//!
//! The fix *indicator* is the exception, and the reason it is one is that
//! it is not a measurement: it changes when the receiver acquires or
//! loses a solution, which is a handful of times a session, and it is how
//! a host knows whether asking is worth anything at all.

use core::cell::Cell;
use core::sync::atomic::{AtomicBool, Ordering};

use embassy_sync::blocking_mutex::CriticalSectionMutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::watch::Watch;
use umsh_gnss::{Fix, FixQuality};
use umsh_hal::wall_clock::{self, TimeSource, Update};
use umsh_node::location::{MAX_PRECISION, NodeLocation};
use umsh_ulcp::gnss::GnssSnapshot;
use umsh_ulcp::ids::prop;

/// How many consumers can wait on [`ANNOUNCE`] at once.
///
/// One: the ULCP driver's publication arm. A second would be a second
/// thing publishing the same property.
const ANNOUNCE_RECEIVERS: usize = 1;

/// Precision the cached snapshot's location is encoded at.
///
/// The finest the format carries. What a *host* sees is this; what the
/// mesh sees is clamped separately by `PROP_GNSS_IDENT_PRECISION`,
/// because telling the host you are attached to where you are is a
/// different disclosure from telling the mesh.
const CACHE_PRECISION: u8 = MAX_PRECISION;

/// Something the device should publish unasked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Announce {
    /// A positioning property, named by its key.
    Gnss(u32, GnssSnapshot),
    /// The wall clock; `None` means it went back to unknown.
    Time(Option<u32>),
}

/// How many consumers can wait on [`ENABLE`] at once: the pump, and
/// nothing else.
const ENABLE_RECEIVERS: usize = 1;

/// How many consumers can wait on [`IDENTITY`] at once: whatever owns the
/// node's identity profile. A second would be a second writer of the same
/// three fields.
const IDENTITY_RECEIVERS: usize = 1;

/// The most recent fix, as the ULCP property surface sees it.
///
/// A `CriticalSectionMutex` rather than atomics: the snapshot is bigger
/// than a word and its fields have to move together, or a host could read
/// this second's satellite count against last second's position.
static SNAPSHOT: CriticalSectionMutex<Cell<GnssSnapshot>> =
    CriticalSectionMutex::new(Cell::new(GnssSnapshot::SEARCHING));

/// `PROP_GNSS_ENABLED`, as the pump sees it.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Wakes the pump when [`ENABLED`] moves.
static ENABLE: Watch<CriticalSectionRawMutex, bool, ENABLE_RECEIVERS> = Watch::new();

/// The rest of the positioning policy, at its post-reset values until the
/// device domain says otherwise.
static POLICY: CriticalSectionMutex<Cell<Policy>> = CriticalSectionMutex::new(Cell::new(Policy {
    trust_time: true,
    update_identity: false,
    identity_precision: 5,
}));

/// Set once the device domain has applied its positioning settings.
///
/// A `Watch` because it has to be awaitable and it has to be *late*-
/// readable: whoever waits on it may arrive long after it fired, and a
/// `Watch` retains its value where a `Signal` consumes it. One receiver
/// slot, for the one thing that waits on it.
static CONFIGURED: Watch<CriticalSectionRawMutex, (), 1> = Watch::new();

/// Publications waiting for the driver's select loop.
///
/// A `Watch` rather than a `Signal` because the driver's hook must be
/// cancellation-safe: the select drops and re-creates it on every other
/// event, and a `Signal` would lose whatever it was cancelled on.
static ANNOUNCE: Watch<CriticalSectionRawMutex, Announce, ANNOUNCE_RECEIVERS> = Watch::new();

/// The position last handed to the node identity, at the advertised
/// precision. `None` until one has been advertised.
static ADVERTISED: CriticalSectionMutex<Cell<Option<NodeLocation>>> =
    CriticalSectionMutex::new(Cell::new(None));

/// Wakes whoever owns the identity profile when [`ADVERTISED`] moves.
///
/// A `Watch` for the same reason [`ANNOUNCE`] is one: the consumer selects
/// on this against a refresh timer, so the wait is dropped and rebuilt
/// constantly and must not lose an edge it was cancelled on.
static IDENTITY: Watch<CriticalSectionRawMutex, (), IDENTITY_RECEIVERS> = Watch::new();

/// The receiver's current view, for a `CMD_PROP_GET`.
///
/// [`GnssSnapshot::SEARCHING`] before the first cycle and after the
/// receiver is switched off, which is what makes `PROP_GNSS_FIX` read 0
/// rather than empty on a board that has never had a fix.
pub fn snapshot() -> GnssSnapshot {
    SNAPSHOT.lock(|cell| cell.get())
}

/// A handle on the publication stream, held by whatever drives the ULCP
/// session's announcement arm.
pub type Announcer =
    embassy_sync::watch::Receiver<'static, CriticalSectionRawMutex, Announce, ANNOUNCE_RECEIVERS>;

/// Take the publication receiver.
///
/// Cancellation-safe to await. `None` only if one was already taken,
/// which would mean two things publishing the same properties — a wiring
/// mistake rather than a runtime condition.
pub fn announcer() -> Option<Announcer> {
    ANNOUNCE.receiver()
}

/// Forget everything the receiver said.
///
/// Called when the receiver is switched off: a position from before is a
/// position the device may no longer be at, and reporting it because it
/// was the last one seen is how a tracker ends up insisting it is
/// somewhere it left hours ago.
pub fn clear() {
    SNAPSHOT.lock(|cell| cell.set(GnssSnapshot::SEARCHING));
    set_advertised(None);
    publish(Announce::Gnss(prop::GNSS_FIX, GnssSnapshot::SEARCHING));
}

/// Move the advertised position, waking the identity owner if this
/// changed it. Returns whether it did.
fn set_advertised(location: Option<NodeLocation>) -> bool {
    let changed = ADVERTISED.lock(|cell| {
        let changed = cell.get() != location;
        if changed {
            cell.set(location);
        }
        changed
    });
    if changed {
        IDENTITY.sender().send(());
    }
    changed
}

/// The policy a fix is folded in under: everything the device domain says
/// about what to do with one.
///
/// Passed in per fix rather than read from a static, because it comes
/// from the ULCP device-domain mirror and the sink has no business
/// holding a second copy of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// `PROP_GNSS_TIME_TRUST`: whether the receiver may set the clock.
    pub trust_time: bool,
    /// `PROP_GNSS_IDENT_UPDATE`: whether fixes refresh the advertised
    /// node identity's location.
    pub update_identity: bool,
    /// `PROP_GNSS_IDENT_PRECISION`: what the advertised location is
    /// clamped to.
    pub identity_precision: u8,
}

/// What folding a fix in changed, for a caller that has to act on it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// The advertised location moved to a new cell and the identity
    /// should be re-signed.
    pub identity_moved: bool,
    /// The wall clock was set or stepped.
    pub clock_changed: bool,
}

/// The ULCP view of one fix.
///
/// Pure, and separate from [`absorb`] for that reason: this is the part
/// with rules in it — which fields survive a degraded solution, what a
/// dilution figure becomes — and it is worth being able to check without
/// a clock, a receiver, or a board.
pub fn to_snapshot(fix: &Fix) -> GnssSnapshot {
    let mut snapshot = GnssSnapshot::SEARCHING;
    snapshot.fix = match fix.quality {
        FixQuality::None => umsh_ulcp::gnss::FixKind::None,
        FixQuality::TwoD => umsh_ulcp::gnss::FixKind::TwoD,
        FixQuality::ThreeD => umsh_ulcp::gnss::FixKind::ThreeD,
    };
    snapshot.sats_used = fix.sats_used;
    snapshot.sats_in_view = fix.sats_in_view;
    if let Some(location) = fix_location(fix) {
        snapshot.set_location(location.as_bytes());
    }
    snapshot.altitude_m = fix.altitude_m;
    snapshot.accuracy_dm = fix.hdop_centi.map(GnssSnapshot::accuracy_from_hdop_centi);
    snapshot
}

/// The fix's position at the cache precision, or `None` without one.
fn fix_location(fix: &Fix) -> Option<NodeLocation> {
    match (fix.latitude_e7, fix.longitude_e7) {
        (Some(lat), Some(lon)) => Some(NodeLocation::from_e7(lat, lon, CACHE_PRECISION)),
        _ => None,
    }
}

/// Fold one fix into the property surface, the clock, and the identity.
///
/// The single place a fix means anything. Returns what changed, so a
/// caller can re-sign an identity or note a clock step without inspecting
/// the fix a second time and reaching a different conclusion.
pub fn absorb(fix: &Fix, policy: Policy) -> Outcome {
    let mut outcome = Outcome::default();

    // ─── The property surface ────────────────────────────────────────
    let previous = snapshot();
    let current = to_snapshot(fix);
    let location = fix_location(fix);
    SNAPSHOT.lock(|cell| cell.set(current));

    // The fix indicator is what a host watches to know whether the device
    // is located at all, so its transitions are always worth a frame. The
    // position, altitude, accuracy and satellite count are not announced
    // at any threshold — see the module docs. They are read.
    if current.fix != previous.fix {
        publish(Announce::Gnss(prop::GNSS_FIX, current));
    }

    // ─── The wall clock ──────────────────────────────────────────────
    //
    // Every fix carrying an instant offers it. The precedence rule in
    // `wall_clock` decides what happens next — a manual set outranks
    // this, and a cleared trust flag refuses it outright — so there is
    // no second copy of that decision here.
    if let Some(at) = fix.time
        && let Some(epoch) = at.to_unix()
    {
        let source = if fix.time_from_fix {
            TimeSource::GnssFix
        } else {
            // A receiver that knows the time without a fix is reading its
            // own clock, which is a restore rather than a correction.
            TimeSource::GnssRtc
        };
        let update = wall_clock::apply(epoch, source, policy.trust_time);
        if update.is_notable() {
            outcome.clock_changed = true;
            publish(Announce::Time(Some(epoch)));
        }
        debug_assert!(
            !matches!(update, Update::Refused) || !policy.trust_time || !fix.time_from_fix,
            "a trusted fix time was refused"
        );
    }

    // ─── The advertised identity ─────────────────────────────────────
    //
    // Only a change in the *clamped* cell counts. At the default
    // precision a stationary node's fixes all land in the same cell, and
    // re-signing for each would put a fresh identity on the air every
    // second to say exactly what the last one said.
    if policy.update_identity
        && let Some(location) = location
    {
        outcome.identity_moved = set_advertised(Some(location.clamped(policy.identity_precision)));
    }

    outcome
}

/// Apply the device domain's positioning settings.
///
/// Called from the ULCP driver's device-domain mirror, which is what
/// makes a host write, a boot restore and a `CMD_RST` all reach the
/// receiver by one path. Switching the receiver off also forgets its last
/// position: a fix from before is a place the device may have left.
pub fn configure(enabled: bool, policy: Policy) {
    POLICY.lock(|cell| cell.set(policy));
    // Switching the update off retracts what it put there. Leaving the
    // last auto-set cell in place would advertise a position nothing is
    // refreshing any more, which ages into a lie at walking pace — and it
    // would make the switch mean "stop correcting my location" rather
    // than "stop telling people where I am".
    if !policy.update_identity {
        set_advertised(None);
    }
    if ENABLED.swap(enabled, Ordering::AcqRel) != enabled {
        if !enabled {
            clear();
        }
        ENABLE.sender().send(enabled);
    }
    CONFIGURED.sender().send(());
}

/// Complete once [`configure`] has run at least once.
///
/// The boot-time receiver-RTC read needs this. That read is gated on
/// `PROP_GNSS_TIME_TRUST`, and [`policy`] answers with the post-reset
/// default until the saved state has been restored — so a read that did
/// not wait would trust a receiver on a device configured not to, exactly
/// once per boot, which is the one time it matters.
///
/// Returns immediately once it has fired, however long ago.
///
/// Single-caller: the channel has one receiver slot, because the boot-time
/// RTC read is the only thing that needs to wait for this.
pub async fn wait_configured() {
    let Some(mut configured) = CONFIGURED.receiver() else {
        // Silently skipping a wait a caller asked for would be worse than
        // the wiring bug that got here, but this is not worth a panic on a
        // shipping device — the cost is one boot's clock restore.
        debug_assert!(false, "gnss: wait_configured is single-caller");
        return;
    };
    configured.get().await;
}

/// The positioning policy currently in effect.
pub fn policy() -> Policy {
    POLICY.lock(|cell| cell.get())
}

/// `PROP_GNSS_ENABLED`.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// The pump's view of the enable switch.
///
/// Construct one per pump; there is only one pump.
pub struct EnableSource {
    changed:
        embassy_sync::watch::Receiver<'static, CriticalSectionRawMutex, bool, ENABLE_RECEIVERS>,
}

impl EnableSource {
    /// Take the pump's enable receiver, or `None` if one was already
    /// taken — which would mean two pumps for one receiver.
    pub fn new() -> Option<Self> {
        ENABLE.receiver().map(|changed| Self { changed })
    }
}

impl umsh_gnss::pump::Enable for EnableSource {
    fn enabled(&self) -> bool {
        // Read the flag rather than the last value seen on the channel:
        // the pump asks this after a cancelled wait, and the answer must
        // be what is true now.
        enabled()
    }

    async fn changed(&mut self) {
        self.changed.changed().await;
    }
}

/// The pump's sink: folds each cycle into the property surface, the
/// clock, and the advertised identity under the current policy.
pub struct FixSink;

impl umsh_gnss::pump::Sink for FixSink {
    async fn fix(&mut self, fix: &Fix) {
        absorb(fix, policy());
    }
}

/// The location to advertise, at the precision it is advertised at, or
/// `None` when there is nothing to advertise.
pub fn advertised_location() -> Option<NodeLocation> {
    ADVERTISED.lock(|cell| cell.get())
}

/// The altitude to advertise alongside it.
pub fn advertised_altitude_m() -> Option<i32> {
    snapshot().altitude_m
}

/// A handle on the advertised position, held by whatever owns the node's
/// identity profile.
pub type IdentityUpdates =
    embassy_sync::watch::Receiver<'static, CriticalSectionRawMutex, (), IDENTITY_RECEIVERS>;

/// Take the identity-update receiver.
///
/// Cancellation-safe to await. `None` only if one was already taken,
/// which would mean two things writing the same profile fields.
pub fn identity_updates() -> Option<IdentityUpdates> {
    IDENTITY.receiver()
}

/// Write the advertised position into a node identity profile.
///
/// The one place that decides what an identity says about where the node
/// is, called both by the loop that reacts to movement and by the
/// device-domain sync that rebuilds the profile from scratch — those two
/// must not be able to disagree, and a profile rebuilt without this would
/// silently drop the position until the node next moved.
///
/// Both fields move together, including to `None`: an altitude without a
/// position describes nothing.
pub fn stamp_identity(profile: &mut umsh_node::NodeIdentityProfile) {
    let location = advertised_location();
    profile.location = location;
    profile.altitude_m = location.and(advertised_altitude_m());
}

fn publish(announce: Announce) {
    ANNOUNCE.sender().send(announce);
}

/// A time driver for the host tests.
///
/// [`absorb`] offers every fix's instant to the wall clock, so a test
/// that calls it links `embassy_time`'s driver hook — which on a device
/// is the RTC and here is nothing at all. A monotonic counter is enough:
/// no test in this module asserts on elapsed time.
#[cfg(test)]
mod test_driver {
    use core::sync::atomic::{AtomicU64, Ordering};
    use core::task::Waker;

    struct Stub;

    impl embassy_time_driver::Driver for Stub {
        fn now(&self) -> u64 {
            static TICKS: AtomicU64 = AtomicU64::new(0);
            TICKS.fetch_add(1, Ordering::Relaxed)
        }

        fn schedule_wake(&self, _at: u64, _waker: &Waker) {
            unimplemented!("these tests never wait on a timer");
        }
    }

    embassy_time_driver::time_driver_impl!(static DRIVER: Stub = Stub);
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_gnss::DateTime;

    fn policy() -> Policy {
        Policy {
            trust_time: true,
            update_identity: false,
            identity_precision: 5,
        }
    }

    fn fixed_at(lat_e7: i32, lon_e7: i32) -> Fix {
        Fix {
            quality: FixQuality::ThreeD,
            latitude_e7: Some(lat_e7),
            longitude_e7: Some(lon_e7),
            altitude_m: Some(31),
            hdop_centi: Some(120),
            sats_used: 9,
            sats_in_view: Some(13),
            time: Some(DateTime {
                year: 2026,
                month: 8,
                day: 4,
                hour: 12,
                minute: 0,
                second: 0,
            }),
            time_from_fix: true,
        }
    }

    #[test]
    fn a_fix_becomes_the_property_surface() {
        let snapshot = to_snapshot(&fixed_at(481_173_000, 115_166_666));
        assert_eq!(snapshot.fix, umsh_ulcp::gnss::FixKind::ThreeD);
        assert_eq!(snapshot.sats_used, 9);
        assert_eq!(snapshot.sats_in_view, Some(13));
        assert_eq!(snapshot.altitude_m, Some(31));
        // HDOP 1.20 scaled by the assumed range error.
        assert_eq!(snapshot.accuracy_dm, Some(60));
        assert_eq!(snapshot.location().len(), MAX_PRECISION as usize);
        // The cached location is the finest the format carries: what the
        // *mesh* sees is clamped separately, because telling a host
        // where you are is a different disclosure from telling everyone.
        assert_eq!(
            snapshot.location(),
            NodeLocation::from_e7(481_173_000, 115_166_666, MAX_PRECISION).as_bytes()
        );
    }

    /// A searching receiver reports zero for the facts it is sure of and
    /// empty for the position it does not have — never a stale one.
    #[test]
    fn a_searching_cycle_carries_no_position() {
        let snapshot = to_snapshot(&Fix::default());
        assert_eq!(snapshot.fix, umsh_ulcp::gnss::FixKind::None);
        assert!(snapshot.location().is_empty());
        assert_eq!(snapshot.altitude_m, None);
        assert_eq!(snapshot.accuracy_dm, None);
        assert_eq!(snapshot.sats_used, 0);
    }

    /// Half a coordinate pair is not a position.
    #[test]
    fn a_partial_coordinate_pair_yields_no_location() {
        let mut fix = fixed_at(481_173_000, 115_166_666);
        fix.longitude_e7 = None;
        assert!(to_snapshot(&fix).location().is_empty());
    }

    /// The advertised cell is what decides whether an identity is worth
    /// re-signing: at the default precision a stationary node's fixes all
    /// land in the same cell, and re-signing each would put a fresh
    /// identity on the air every second to say what the last one said.
    #[test]
    fn only_a_change_of_advertised_cell_is_a_move() {
        let precision = policy().identity_precision;
        let here = fix_location(&fixed_at(481_173_000, 115_166_666))
            .unwrap()
            .clamped(precision);
        // A jitter of a few centimetres.
        let jittered = fix_location(&fixed_at(481_173_010, 115_166_680))
            .unwrap()
            .clamped(precision);
        assert_eq!(here, jittered, "a sub-cell jitter changed the cell");

        let elsewhere = fix_location(&fixed_at(490_000_000, 120_000_000))
            .unwrap()
            .clamped(precision);
        assert_ne!(here, elsewhere);

        // The advertised value is coarser than the cached one, and is a
        // prefix of it: the same position, said less precisely.
        let cached = fix_location(&fixed_at(481_173_000, 115_166_666)).unwrap();
        assert_eq!(here.precision(), precision);
        assert_eq!(here.as_bytes(), &cached.as_bytes()[..precision as usize]);
    }

    /// The whole advertised-position lifecycle, in one test on purpose:
    /// it is the only one that touches the module's statics, and two of
    /// them would race each other for the same globals.
    #[test]
    fn the_advertised_position_follows_the_switch_that_governs_it() {
        let profile = || {
            umsh_node::NodeIdentityProfile::new(
                umsh_core::PublicKey([7; 32]),
                umsh_node::NodeRole::Tracker,
                umsh_node::NodeCapabilities::empty(),
            )
        };
        // Undated fixes throughout: what the clock does with a fix is a
        // separate decision with its own tests, and letting these set it
        // would leave a wall clock behind for whatever runs next.
        let untimed = |lat_e7, lon_e7| Fix {
            time: None,
            ..fixed_at(lat_e7, lon_e7)
        };
        let updating = Policy {
            update_identity: true,
            ..policy()
        };

        // Nothing advertised until a fix arrives under the switch.
        configure(true, updating);
        assert_eq!(advertised_location(), None);
        let mut blank = profile();
        stamp_identity(&mut blank);
        assert_eq!(blank.location, None);
        assert_eq!(blank.altitude_m, None, "an altitude with no position");

        // The first fix moves it; a second in the same cell does not.
        let here = untimed(481_173_000, 115_166_666);
        assert!(absorb(&here, updating).identity_moved);
        assert!(!absorb(&here, updating).identity_moved);
        let advertised = advertised_location().expect("a fix went unadvertised");
        assert_eq!(advertised.precision(), updating.identity_precision);

        let mut located = profile();
        stamp_identity(&mut located);
        assert_eq!(located.location, Some(advertised));
        assert_eq!(located.altitude_m, Some(31));

        // Far enough to leave the cell.
        assert!(absorb(&untimed(490_000_000, 120_000_000), updating).identity_moved);

        // Turning the switch off retracts what it advertised, rather than
        // leaving a position nothing is refreshing any more.
        configure(true, policy());
        assert_eq!(advertised_location(), None);
        let mut retracted = profile();
        stamp_identity(&mut retracted);
        assert_eq!(retracted.location, None);
        assert_eq!(retracted.altitude_m, None);

        // And a fix arriving while it is off changes nothing.
        assert!(!absorb(&here, policy()).identity_moved);
        assert_eq!(advertised_location(), None);

        // Switching the receiver off retracts it too: the last position
        // is a place the device may have left.
        configure(true, updating);
        assert!(absorb(&here, updating).identity_moved);
        configure(false, updating);
        assert_eq!(advertised_location(), None);
    }
}
