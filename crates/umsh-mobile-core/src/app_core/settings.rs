//! What native code's preferences and readings set: the policy, the
//! location shared, and the two announcement schedules.
//!
//! Policy comes in whole and the core compares, so a schedule restarts only
//! when its interval changed and flood hops are pushed only when they
//! changed. Nothing of the policy reaches the session before the first
//! `set_policy`.

use std::rc::Rc;

use tokio::task::JoinHandle;

use super::limits::bounded_interval;
use super::records::MobileAppLifecycle;
use super::worker::Worker;
use crate::mobile_mesh::MobileMeshSharedLocationRecord;

/// The user's preferences the core acts on.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppPolicyRecord {
    /// Seconds between scheduled advertisements; 0 is off. Any other is
    /// held to `mobile_limits()`' announcement bounds.
    pub advert_interval_seconds: u32,
    /// Seconds between scheduled beacons; 0 is off. Held likewise.
    pub beacon_interval_seconds: u32,
    /// Whether this phone answers nearby nodes' identity requests.
    pub discoverable: bool,
    /// How far this phone's frames flood. Clamped to the protocol's
    /// ceiling.
    pub flood_hops: u8,
    /// How far its beacons flood. Clamped likewise.
    pub beacon_flood_hops: u8,
    /// The cell size this phone's identity discloses, in bytes of cell
    /// code; `None` is not sharing.
    pub location_precision: Option<u8>,
    /// Whether a test message on EMERGENCY notifies.
    pub test_message_alerts: bool,
}

/// Where the phone is.
#[derive(Clone, Copy, Debug, PartialEq, uniffi::Record)]
pub struct MobilePositionRecord {
    pub latitude_degrees: f64,
    pub longitude_degrees: f64,
    /// Horizontal accuracy in meters, when the platform gives one.
    pub accuracy_meters: Option<f64>,
}

/// Up to this fraction of an interval is added to each announcement, so
/// nodes that share an interval do not stay in step. It only ever delays,
/// so the interval stays the shortest gap.
const SCATTER_FRACTION: f64 = 0.25;

#[derive(Default)]
pub(super) struct Settings {
    pub(super) policy: Option<MobileAppPolicyRecord>,
    /// The latest reading, kept while sharing so a new session, or a new
    /// precision, discloses it at once.
    pub(super) position: Option<MobilePositionRecord>,
    advert: Schedule,
    beacon: Schedule,
    /// Tests pin the scatter: a fraction of the most allowed.
    #[cfg(test)]
    pub(super) scatter: Option<f64>,
}

#[derive(Default)]
struct Schedule {
    seconds: u32,
    task: Option<JoinHandle<()>>,
}

impl Schedule {
    fn cancel(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Clone, Copy)]
enum Announcement {
    Advert,
    Beacon,
}

impl Worker {
    /// Take a new policy. Kept in any state; acted on while running.
    pub(super) async fn set_policy(self: &Rc<Self>, policy: MobileAppPolicyRecord) {
        // In turn with `start`, so a policy set mid-start is not missed.
        let _transition = self.transitions.lock().await;
        let policy = MobileAppPolicyRecord {
            flood_hops: policy.flood_hops.min(umsh_mac::MAX_FLOOD_HOPS),
            beacon_flood_hops: policy.beacon_flood_hops.min(umsh_mac::MAX_FLOOD_HOPS),
            advert_interval_seconds: bounded_interval(policy.advert_interval_seconds),
            beacon_interval_seconds: bounded_interval(policy.beacon_interval_seconds),
            ..policy
        };
        let previous = self.settings.borrow_mut().policy.replace(policy.clone());
        if previous.as_ref() == Some(&policy) {
            return;
        }
        // A reading is kept only while sharing, whatever the lifecycle.
        if policy.location_precision.is_none() {
            self.settings.borrow_mut().position = None;
        }
        self.rearm_schedules();
        // The radio's test-alert setting is the pass's to write.
        self.policy_triggered();
        if self.lifecycle() != MobileAppLifecycle::Running {
            return;
        }
        let Some(session) = self.session() else {
            return;
        };
        // The first policy is pushed whole.
        let first = previous.is_none();
        let previous = previous.unwrap_or_else(|| policy.clone());
        if (first
            || (previous.flood_hops, previous.beacon_flood_hops)
                != (policy.flood_hops, policy.beacon_flood_hops))
            && let Err(error) = session
                .set_flood_hops(policy.flood_hops, policy.beacon_flood_hops)
                .await
        {
            log::warn!(error:? = error; "flood hops not pushed");
        }
        if first || previous.discoverable != policy.discoverable {
            self.push_discoverability().await;
        }
        if first || previous.location_precision != policy.location_precision {
            self.push_location().await;
        }
        if first || previous.test_message_alerts != policy.test_message_alerts {
            self.push_silent_tests();
        }
    }

    /// Take a location reading, or the loss of one. A reading is kept only
    /// while sharing; `None` while sharing withdraws the location at once.
    pub(super) async fn set_location(&self, position: Option<MobilePositionRecord>) {
        let _transition = self.transitions.lock().await;
        let sharing = self
            .settings
            .borrow()
            .policy
            .as_ref()
            .is_some_and(|policy| policy.location_precision.is_some());
        if !sharing {
            return;
        }
        self.settings.borrow_mut().position = position;
        if self.lifecycle() == MobileAppLifecycle::Running {
            self.push_location().await;
        }
    }

    pub(super) fn test_message_alerts(&self) -> bool {
        self.settings
            .borrow()
            .policy
            .as_ref()
            .is_none_or(|policy| policy.test_message_alerts)
    }

    /// What a new session starts without: the name, discoverability, the
    /// location, and flood hops. Nothing of the policy before the first
    /// `set_policy`; the name goes regardless.
    pub(super) async fn push_settings(&self) {
        self.push_discoverability().await;
        let Some(policy) = self.settings.borrow().policy.clone() else {
            return;
        };
        let Some(session) = self.session() else {
            return;
        };
        self.push_location().await;
        if let Err(error) = session
            .set_flood_hops(policy.flood_hops, policy.beacon_flood_hops)
            .await
        {
            log::warn!(error:? = error; "flood hops not pushed");
        }
    }

    /// The stored name, as an advertisement carries it.
    pub(super) fn advertised_name(&self) -> Option<String> {
        let owner = self.owner()?;
        self.store
            .local_advertised_name(owner)
            .ok()
            .flatten()
            .filter(|name| !name.is_empty())
    }

    /// Discoverability with the name it answers with, and the name group
    /// messages carry, which discoverability does not govern.
    pub(super) async fn push_discoverability(&self) {
        let Some(session) = self.session() else {
            return;
        };
        let name = self.advertised_name();
        let discoverable = self
            .settings
            .borrow()
            .policy
            .as_ref()
            .map(|policy| policy.discoverable);
        // Nothing of the policy before the first `set_policy`.
        if let Some(discoverable) = discoverable
            && let Err(error) = session.set_discoverable(discoverable, name.clone()).await
        {
            log::warn!(error:? = error; "discoverability not pushed");
        }
        let name = name.unwrap_or_default();
        #[cfg(test)]
        self.hooks
            .pushed_names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(name.clone());
        if let Err(error) = session.set_chat_display_name(name).await {
            log::warn!(error:? = error; "chat display name not pushed");
        }
    }

    /// The shared location as policy and the latest reading say, or none.
    async fn push_location(&self) {
        let Some(session) = self.session() else {
            return;
        };
        let shared = {
            let settings = self.settings.borrow();
            let precision = settings
                .policy
                .as_ref()
                .and_then(|policy| policy.location_precision);
            precision
                .zip(settings.position)
                .map(
                    |(precision_bytes, position)| MobileMeshSharedLocationRecord {
                        latitude_degrees: position.latitude_degrees,
                        longitude_degrees: position.longitude_degrees,
                        precision_bytes,
                    },
                )
        };
        if let Err(error) = session.set_advertised_location(shared).await {
            // An unencodable precision or reading shares nothing.
            log::warn!(error:? = error; "location not shared");
            let _ = session.set_advertised_location(None).await;
        }
    }

    /// Start, restart or stop each schedule whose interval changed.
    fn rearm_schedules(self: &Rc<Self>) {
        let Some(policy) = self.settings.borrow().policy.clone() else {
            return;
        };
        for (kind, seconds) in [
            (Announcement::Advert, policy.advert_interval_seconds),
            (Announcement::Beacon, policy.beacon_interval_seconds),
        ] {
            let mut settings = self.settings.borrow_mut();
            let schedule = match kind {
                Announcement::Advert => &mut settings.advert,
                Announcement::Beacon => &mut settings.beacon,
            };
            if schedule.seconds == seconds && (seconds == 0 || schedule.task.is_some()) {
                continue;
            }
            schedule.cancel();
            schedule.seconds = seconds;
            if seconds > 0 {
                schedule.task = Some(tokio::task::spawn_local(
                    self.clone().run_schedule(kind, seconds),
                ));
            }
        }
    }

    /// Stop both schedules: the core is stopping.
    pub(super) fn cancel_schedules(&self) {
        let mut settings = self.settings.borrow_mut();
        settings.advert.cancel();
        settings.beacon.cancel();
        settings.advert.seconds = 0;
        settings.beacon.seconds = 0;
    }

    /// Announce every `seconds` plus scatter, whatever the radio's state.
    /// Due times are checked after each sleep and whenever the core is
    /// woken, so an announcement overdue after the phone slept goes on the
    /// first wake.
    async fn run_schedule(self: Rc<Self>, kind: Announcement, seconds: u32) {
        let interval_ms = i64::from(seconds) * 1000;
        loop {
            let due = self.clock.monotonic_ms() + interval_ms + self.scatter_ms(interval_ms);
            loop {
                if self.clock.monotonic_ms() >= due {
                    break;
                }
                let check = self.schedule_check.notified();
                tokio::select! {
                    () = self.clock.sleep_until(due) => {}
                    () = check => {}
                }
            }
            self.announce(kind).await;
        }
    }

    async fn announce(&self, kind: Announcement) {
        if self.lifecycle() != MobileAppLifecycle::Running {
            return;
        }
        let Some(session) = self.session() else {
            return;
        };
        let sent = match kind {
            Announcement::Advert => {
                let timestamp = u32::try_from(self.clock.now_ms() / 1000).unwrap_or(u32::MAX);
                session
                    .advertise_identity_scheduled(self.advertised_name(), Some(timestamp))
                    .await
            }
            Announcement::Beacon => session.send_beacon().await,
        };
        if let Err(error) = sent {
            log::debug!(error:? = error; "a scheduled announcement was not sent");
        }
    }

    /// How much later than its interval this announcement goes.
    fn scatter_ms(&self, interval_ms: i64) -> i64 {
        #[cfg(test)]
        if let Some(fraction) = self.settings.borrow().scatter {
            return (interval_ms as f64 * SCATTER_FRACTION * fraction) as i64;
        }
        let most = (interval_ms as f64 * SCATTER_FRACTION) as i64;
        if most <= 0 {
            return 0;
        }
        rand::random_range(0..=most)
    }
}
