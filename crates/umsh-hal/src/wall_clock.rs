//! The device's wall clock: what time it is, where that came from, and
//! whether it is known at all.
//!
//! A device of this class has a monotonic timer and, usually, nothing
//! else. Wall-clock time arrives from outside—a GNSS fix, a
//! battery-backed real-time clock, a host that was asked—and is held as
//! an *offset* from the monotonic timer rather than as a counter of its
//! own, so it costs nothing to maintain and cannot drift relative to
//! everything else the device schedules.
//!
//! Two things here are policy rather than mechanism, and both are
//! deliberately in one place:
//!
//! * **Not knowing is a state.** [`WallClockState::now`] returns `None`
//!   until something sets the clock. Callers must not substitute zero, a
//!   build timestamp, or any other plausible-looking value—a device
//!   that does not know the time **must not** display one.
//! * **Sources outrank each other.** [`WallClockState::apply`] holds the
//!   whole precedence rule, so no caller has to remember it and no two
//!   callers can disagree about it.
//!
//! [`WallClockState`] is pure and testable on any host. The module-level
//! statics behind the `embassy` feature are the single live instance the
//! firmware shares.

use crate::tz::Rule;

/// Where a wall-clock reading came from.
///
/// The ordering is not a precedence ranking—see
/// [`WallClockState::apply`], where the rule depends on more than the
/// source alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeSource {
    /// A host wrote it, or a person did. The most authoritative source
    /// there is: somebody decided this was the time.
    Manual,
    /// The time carried by a GNSS position fix.
    GnssFix,
    /// The GNSS receiver's own real-time-clock domain, read at boot. On
    /// boards where that domain is the only clock that survives a power
    /// cycle, it *is* the board's real-time clock.
    GnssRtc,
    /// A dedicated battery-backed real-time clock on the board.
    ExternalRtc,
}

impl TimeSource {
    /// Whether the reading ultimately came from the GNSS receiver, and is
    /// therefore governed by `PROP_GNSS_TIME_TRUST`.
    pub const fn is_receiver_derived(self) -> bool {
        matches!(self, Self::GnssFix | Self::GnssRtc)
    }
}

/// How far the clock must move for the change to be worth telling anyone
/// about, in seconds.
///
/// A receiver re-synchronizing a clock it already agrees with produces a
/// sub-second correction every time it gets a fix. Announcing those would
/// spend a frame to say nothing, and writing them to a real-time clock
/// would spend flash-equivalent wear to the same effect.
pub const NOTABLE_STEP_SECS: u32 = 2;

/// How far a running clock must disagree with the battery-backed
/// real-time clock before [`WallClockState::correct_from_rtc`] moves it,
/// in seconds.
///
/// Above [`NOTABLE_STEP_SECS`], so that a correction is always a notable
/// step, and wide enough that two clocks read a second apart never count
/// as disagreeing.
pub const RTC_CORRECTION_SECS: u32 = 3;

/// How long a reading from the GNSS receiver outranks the real-time clock
/// during a correction, in milliseconds.
///
/// A receiver's sub-notable re-syncs are not written back, so a real-time
/// clock can fall behind a running clock that is better than it is.
pub const GNSS_OUTRANKS_RTC_MS: u64 = 60 * 60 * 1_000;

/// What [`WallClockState::apply`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Update {
    /// The device went from not knowing the time to knowing it. Always
    /// worth acting on: it is the transition that lets a display start
    /// showing a clock.
    Set,
    /// The clock moved by at least [`NOTABLE_STEP_SECS`].
    Stepped {
        /// What the clock read immediately before.
        previous: u32,
    },
    /// The clock was already this time, near enough. Applied, but not
    /// worth announcing or persisting.
    Unchanged,
    /// Nothing changed: the source is not trusted, or a restore arrived
    /// at a clock that was already set.
    Refused,
}

impl Update {
    /// Whether this change is worth announcing to a host and worth
    /// pushing into a real-time clock.
    pub const fn is_notable(self) -> bool {
        matches!(self, Self::Set | Self::Stepped { .. })
    }

    /// Whether the clock changed at all.
    pub const fn applied(self) -> bool {
        !matches!(self, Self::Refused)
    }
}

/// The wall clock, as an offset from a monotonic millisecond timer.
///
/// Every method takes the current monotonic reading rather than fetching
/// one, which is what keeps this testable without a clock at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallClockState {
    /// Unix milliseconds minus monotonic milliseconds, or `None` when the
    /// device does not know what time it is.
    ///
    /// Held in milliseconds rather than seconds so that a clock set from
    /// a sub-second-accurate source does not lose that accuracy the
    /// moment it is stored, and signed because the monotonic timer starts
    /// at zero on a device whose wall clock is in 2026.
    offset_ms: Option<i64>,
    /// The zone (`PROP_TZ_RULE`). Always known, even while the time is
    /// not—see the module documentation.
    tz_rule: Rule,
    /// Where the current reading came from, or `None` while unset.
    source: Option<TimeSource>,
    /// The monotonic reading at which the current one was taken.
    set_at_ms: u64,
}

impl Default for WallClockState {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

impl WallClockState {
    /// A device that does not know what time it is, at UTC.
    pub const UNKNOWN: Self = Self {
        offset_ms: None,
        tz_rule: Rule::UTC,
        source: None,
        set_at_ms: 0,
    };

    /// The current time in Unix seconds, or `None` when unknown.
    pub const fn now(&self, monotonic_ms: u64) -> Option<u32> {
        match self.now_ms(monotonic_ms) {
            Some(millis) => Some((millis / 1_000) as u32),
            None => None,
        }
    }

    /// The current time in Unix milliseconds, or `None` when unknown.
    ///
    /// A clock whose offset would put it before the epoch or past what
    /// `PROP_TIME` can carry reads as unknown rather than as a wrapped
    /// value: those are only reachable from an absurd set, and reporting
    /// a wrapped time is worse than reporting none.
    pub const fn now_ms(&self, monotonic_ms: u64) -> Option<u64> {
        let Some(offset) = self.offset_ms else {
            return None;
        };
        let millis = monotonic_ms as i64 + offset;
        if millis < 0 || millis > u32::MAX as i64 * 1_000 {
            return None;
        }
        Some(millis as u64)
    }

    /// The local wall-clock reading in seconds—the time shifted by the
    /// configured zone—or `None` when the time is unknown.
    ///
    /// A reading for presentation, not an instant: it does not name a
    /// point in time on its own, and nothing should send it anywhere.
    pub fn local_now(&self, monotonic_ms: u64) -> Option<u32> {
        let utc = self.now(monotonic_ms)?;
        let local = i64::from(utc) + i64::from(self.tz_rule.offset_at(i64::from(utc))) * 60;
        if local < 0 || local > u32::MAX as i64 {
            return None;
        }
        Some(local as u32)
    }

    /// Whether the device knows what time it is.
    pub const fn is_set(&self) -> bool {
        self.offset_ms.is_some()
    }

    /// Where the current reading came from, or `None` while unset.
    pub const fn source(&self) -> Option<TimeSource> {
        self.source
    }

    /// The monotonic reading at which the current one was taken, or `None`
    /// while unset.
    pub const fn set_at(&self) -> Option<u64> {
        match self.source {
            Some(_) => Some(self.set_at_ms),
            None => None,
        }
    }

    /// The time zone.
    pub const fn tz_rule(&self) -> Rule {
        self.tz_rule
    }

    /// Set the time zone. Independent of the clock: the zone is known
    /// from commissioning, and changing it never makes the time known or
    /// unknown.
    pub const fn set_tz_rule(&mut self, rule: Rule) {
        self.tz_rule = rule;
    }

    /// Return the device to not knowing what time it is.
    ///
    /// The zone survives, because where the device is has not changed.
    pub const fn clear(&mut self) {
        self.offset_ms = None;
        self.source = None;
    }

    /// Offer a reading from `source`, applying the precedence rule.
    ///
    /// `trust_receiver` is `PROP_GNSS_TIME_TRUST`. The rule:
    ///
    /// * [`TimeSource::Manual`] always applies. The operator is the more
    ///   authoritative source by definition, including while the receiver
    ///   is distrusted—distrusting the sky is *why* somebody would set
    ///   the clock by hand.
    /// * [`TimeSource::GnssFix`] applies whenever the receiver is
    ///   trusted, overwriting whatever was there. Every fix re-synchronizes
    ///   the clock, which is what keeps it good over a long deployment.
    /// * [`TimeSource::GnssRtc`] applies only when trusted **and** the
    ///   clock is unset. It is a boot-time restore, not a correction: the
    ///   receiver may have re-synchronized its own RTC from a bad sky
    ///   while the device was running, so it must not displace a reading
    ///   that is already in hand.
    /// * [`TimeSource::ExternalRtc`] applies only when the clock is
    ///   unset, for the same reason, but is not subject to the receiver
    ///   trust flag—it is not the receiver. Correcting a running clock
    ///   from it is [`Self::correct_from_rtc`].
    pub const fn apply(
        &mut self,
        epoch: u32,
        monotonic_ms: u64,
        source: TimeSource,
        trust_receiver: bool,
    ) -> Update {
        let permitted = match source {
            TimeSource::Manual => true,
            TimeSource::GnssFix => trust_receiver,
            TimeSource::GnssRtc => trust_receiver && !self.is_set(),
            TimeSource::ExternalRtc => !self.is_set(),
        };
        if !permitted {
            return Update::Refused;
        }
        let previous = self.now(monotonic_ms);
        self.offset_ms = Some(epoch as i64 * 1_000 - monotonic_ms as i64);
        self.source = Some(source);
        self.set_at_ms = monotonic_ms;
        match previous {
            None => Update::Set,
            Some(previous) => {
                let delta = epoch.abs_diff(previous);
                if delta >= NOTABLE_STEP_SECS {
                    Update::Stepped { previous }
                } else {
                    Update::Unchanged
                }
            }
        }
    }

    /// Correct a running clock from the battery-backed real-time clock.
    ///
    /// The running clock free-runs on the monotonic timer, which through
    /// light sleep is only as good as the chip's RC slow clock, while the
    /// real-time clock counts a crystal the whole time. So a disagreement
    /// of at least [`RTC_CORRECTION_SECS`] is settled in its favor, with
    /// three exceptions, each [`Update::Refused`]:
    ///
    /// * The clock is unset. A host that cleared it asked the running
    ///   device not to know the time; the next boot restores it.
    /// * The clock was set at or after `read_began_ms`, while the reading
    ///   was in flight, so the reading is older than the clock.
    /// * The clock came from the GNSS receiver within
    ///   [`GNSS_OUTRANKS_RTC_MS`].
    ///
    /// A closer reading is [`Update::Unchanged`] and leaves the clock and
    /// its source alone. The clock moves here only to agree with the
    /// real-time clock, so a caller has nothing to write back.
    pub const fn correct_from_rtc(
        &mut self,
        epoch: u32,
        monotonic_ms: u64,
        read_began_ms: u64,
    ) -> Update {
        let (Some(previous), Some(source)) = (self.now(monotonic_ms), self.source) else {
            return Update::Refused;
        };
        if self.set_at_ms >= read_began_ms {
            return Update::Refused;
        }
        if source.is_receiver_derived()
            && monotonic_ms.saturating_sub(self.set_at_ms) < GNSS_OUTRANKS_RTC_MS
        {
            return Update::Refused;
        }
        let delta = epoch.abs_diff(previous);
        if delta < RTC_CORRECTION_SECS {
            return Update::Unchanged;
        }
        self.offset_ms = Some(epoch as i64 * 1_000 - monotonic_ms as i64);
        self.source = Some(TimeSource::ExternalRtc);
        self.set_at_ms = monotonic_ms;
        Update::Stepped { previous }
    }
}

#[cfg(feature = "embassy")]
mod live {
    use core::cell::Cell;
    use core::sync::atomic::{AtomicBool, Ordering};

    use embassy_sync::blocking_mutex::CriticalSectionMutex;
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::signal::Signal;
    use embassy_time::Instant;

    use super::{Rule, TimeSource, Update, WallClockState};

    /// The device's one wall clock.
    ///
    /// A single shared instance rather than something threaded through
    /// every consumer: the ULCP session, the GNSS pump, the display, and
    /// whatever stamps outgoing identities must agree about what time it
    /// is, and a value each of them held separately would eventually not.
    static CLOCK: CriticalSectionMutex<Cell<WallClockState>> =
        CriticalSectionMutex::new(Cell::new(WallClockState::UNKNOWN));

    /// Raised when what a shown clock reads changes by more than the
    /// passing of time: the clock is set, stepped, or cleared, or the zone
    /// or the way hours are written changes.
    static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

    static HOUR24: AtomicBool = AtomicBool::new(true);

    fn with<R>(f: impl FnOnce(&mut WallClockState) -> R) -> R {
        CLOCK.lock(|cell| {
            let mut state = cell.get();
            let result = f(&mut state);
            cell.set(state);
            result
        })
    }

    /// The current time in Unix seconds, or `None` when the device does
    /// not know what time it is.
    pub fn now() -> Option<u32> {
        CLOCK.lock(|cell| cell.get().now(Instant::now().as_millis()))
    }

    /// The whole clock, for a caller that wants the reading, the zone,
    /// and the source without three separate critical sections.
    pub fn snapshot() -> WallClockState {
        CLOCK.lock(|cell| cell.get())
    }

    /// Whether the device knows what time it is.
    pub fn is_set() -> bool {
        CLOCK.lock(|cell| cell.get().is_set())
    }

    /// The local hour and minute, or `None` when the time is unknown.
    ///
    /// The one accessor a display needs, and the reason it returns an
    /// `Option`: a panel that cannot obtain a reading has nothing to draw,
    /// which is exactly the required behavior rather than an error to
    /// work around.
    pub fn local_hhmm() -> Option<(u8, u8)> {
        let local = CLOCK.lock(|cell| cell.get().local_now(Instant::now().as_millis()))?;
        let minutes_of_day = (local % 86_400) / 60;
        Some(((minutes_of_day / 60) as u8, (minutes_of_day % 60) as u8))
    }

    /// Milliseconds until the next minute boundary, or `None` when the
    /// time is unknown.
    ///
    /// What a display arms its redraw timer on. Computed in UTC, which
    /// costs nothing in correctness: every real time-zone offset is a
    /// whole number of minutes, so the local minute always turns over
    /// with the UTC one—including in the half- and quarter-hour zones.
    pub fn millis_to_next_minute() -> Option<u32> {
        let monotonic = Instant::now().as_millis();
        let millis = CLOCK.lock(|cell| cell.get().now_ms(monotonic))?;
        Some(60_000 - (millis % 60_000) as u32)
    }

    /// The time zone.
    pub fn tz_rule() -> Rule {
        CLOCK.lock(|cell| cell.get().tz_rule())
    }

    /// Set the time zone.
    pub fn set_tz_rule(rule: Rule) {
        let before = with(|state| core::mem::replace(&mut state.tz_rule, rule));
        if before != rule {
            CHANGED.signal(());
        }
    }

    /// Whether a shown clock writes hours from 0 to 23
    /// (`PROP_TIME_24H`).
    pub fn hour24() -> bool {
        HOUR24.load(Ordering::Relaxed)
    }

    /// Set how a shown clock writes hours.
    pub fn set_hour24(on: bool) {
        if HOUR24.swap(on, Ordering::Relaxed) != on {
            CHANGED.signal(());
        }
    }

    /// Waits until what a shown clock reads changes by more than the
    /// passing of time. For the one task that draws the time: a second
    /// waiter would take the first's wakes.
    pub async fn changed() {
        CHANGED.wait().await;
    }

    /// Offer a reading, applying the precedence rule. See
    /// [`WallClockState::apply`].
    pub fn apply(epoch: u32, source: TimeSource, trust_receiver: bool) -> Update {
        let monotonic = Instant::now().as_millis();
        let update = with(|state| state.apply(epoch, monotonic, source, trust_receiver));
        if update.is_notable() {
            CHANGED.signal(());
        }
        update
    }

    /// Correct a running clock from the real-time clock. See
    /// [`WallClockState::correct_from_rtc`]; `read_began_ms` is the
    /// monotonic reading taken before the chip was asked.
    pub fn correct_from_rtc(epoch: u32, read_began_ms: u64) -> Update {
        let monotonic = Instant::now().as_millis();
        let update = with(|state| state.correct_from_rtc(epoch, monotonic, read_began_ms));
        if update.is_notable() {
            CHANGED.signal(());
        }
        update
    }

    /// Set the clock from a host or an operator.
    ///
    /// Separate from [`apply`] because [`TimeSource::Manual`] outranks
    /// every receiver-derived source unconditionally: there is no trust
    /// flag to pass, and a caller that had to pass one would be inventing
    /// an answer to a question that does not apply.
    pub fn set_manual(epoch: u32) -> Update {
        apply(epoch, TimeSource::Manual, true)
    }

    /// Return the device to not knowing what time it is.
    pub fn clear() {
        let was_set = with(|state| {
            let was_set = state.is_set();
            state.clear();
            was_set
        });
        if was_set {
            CHANGED.signal(());
        }
    }
}

#[cfg(feature = "embassy")]
pub use live::{
    apply, changed, clear, correct_from_rtc, hour24, is_set, local_hhmm, millis_to_next_minute,
    now, set_hour24, set_manual, set_tz_rule, snapshot, tz_rule,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// A plausible monotonic reading: the device has been up a while.
    const UP: u64 = 4_000;
    const T0: u32 = 1_780_000_000;

    #[test]
    fn a_fresh_clock_knows_nothing_but_its_zone() {
        let clock = WallClockState::UNKNOWN;
        assert!(!clock.is_set());
        assert_eq!(clock.now(UP), None);
        assert_eq!(clock.local_now(UP), None);
        assert_eq!(clock.source(), None);
        // The zone is known from the start, which is the whole reason it
        // is a separate property.
        assert_eq!(clock.tz_rule(), Rule::UTC);
    }

    #[test]
    fn the_clock_advances_with_the_monotonic_timer() {
        let mut clock = WallClockState::UNKNOWN;
        assert_eq!(clock.apply(T0, UP, TimeSource::Manual, true), Update::Set);
        assert_eq!(clock.now(UP), Some(T0));
        assert_eq!(clock.now(UP + 90_000), Some(T0 + 90));
        assert_eq!(clock.source(), Some(TimeSource::Manual));
        assert_eq!(clock.set_at(), Some(UP));
    }

    #[test]
    fn the_zone_shifts_the_reading_without_touching_the_instant() {
        let mut clock = WallClockState::UNKNOWN;
        clock.apply(T0, UP, TimeSource::Manual, true);
        clock.set_tz_rule(Rule::parse("PST8PDT,M3.2.0,M11.1.0").unwrap());
        assert_eq!(clock.now(UP), Some(T0), "the instant is unchanged");
        // T0 is in May: daylight time.
        assert_eq!(clock.local_now(UP), Some(T0 - 7 * 3_600));
        clock.set_tz_rule(Rule::parse("IST-5:30").unwrap());
        assert_eq!(clock.local_now(UP), Some(T0 + 5 * 3_600 + 1_800));
    }

    /// Well after [`UP`], with the read beginning just before it.
    const LATER: u64 = UP + 10 * GNSS_OUTRANKS_RTC_MS;
    const READ: u64 = LATER - 10;

    #[test]
    fn the_rtc_corrects_a_running_clock_that_has_drifted() {
        let mut clock = WallClockState::UNKNOWN;
        clock.apply(T0, UP, TimeSource::Manual, true);
        let running = clock.now(LATER).unwrap();
        assert_eq!(
            clock.correct_from_rtc(running - 3, LATER, READ),
            Update::Stepped { previous: running },
        );
        assert_eq!(clock.now(LATER), Some(running - 3));
        assert_eq!(clock.source(), Some(TimeSource::ExternalRtc));
        assert_eq!(clock.set_at(), Some(LATER));
    }

    #[test]
    fn the_rtc_leaves_a_clock_within_tolerance_alone() {
        let mut clock = WallClockState::UNKNOWN;
        clock.apply(T0, UP, TimeSource::Manual, true);
        let running = clock.now(LATER).unwrap();
        assert_eq!(
            clock.correct_from_rtc(running - 2, LATER, READ),
            Update::Unchanged,
        );
        assert_eq!(clock.now(LATER), Some(running));
        assert_eq!(clock.source(), Some(TimeSource::Manual));
        assert_eq!(clock.set_at(), Some(UP));
    }

    #[test]
    fn the_rtc_does_not_set_a_clock_a_host_cleared() {
        let mut clock = WallClockState::UNKNOWN;
        clock.apply(T0, UP, TimeSource::Manual, true);
        clock.clear();
        assert_eq!(clock.correct_from_rtc(T0, LATER, READ), Update::Refused);
        assert!(!clock.is_set());
    }

    #[test]
    fn a_reading_older_than_the_clock_is_refused() {
        let mut clock = WallClockState::UNKNOWN;
        clock.apply(T0, READ + 5, TimeSource::Manual, true);
        assert_eq!(
            clock.correct_from_rtc(T0 - 60, LATER, READ),
            Update::Refused
        );
        assert_eq!(clock.source(), Some(TimeSource::Manual));
    }

    #[test]
    fn a_recent_gnss_reading_outranks_the_rtc() {
        let mut clock = WallClockState::UNKNOWN;
        clock.apply(T0, UP, TimeSource::GnssFix, true);
        let recent = UP + GNSS_OUTRANKS_RTC_MS - 1;
        assert_eq!(
            clock.correct_from_rtc(T0 - 60, recent, recent - 10),
            Update::Refused,
        );
        let stale = UP + GNSS_OUTRANKS_RTC_MS;
        assert!(matches!(
            clock.correct_from_rtc(T0 - 60, stale, stale - 10),
            Update::Stepped { .. },
        ));
        assert_eq!(clock.source(), Some(TimeSource::ExternalRtc));
    }

    #[test]
    fn clearing_forgets_the_time_and_keeps_the_zone() {
        let mut clock = WallClockState::UNKNOWN;
        clock.apply(T0, UP, TimeSource::Manual, true);
        let eastern = Rule::parse("EST5EDT,M3.2.0,M11.1.0").unwrap();
        clock.set_tz_rule(eastern);
        clock.clear();
        assert!(!clock.is_set());
        assert_eq!(clock.now(UP), None);
        assert_eq!(clock.source(), None);
        assert_eq!(clock.tz_rule(), eastern, "where it is has not changed");
    }

    #[test]
    fn a_manual_set_outranks_everything_including_distrust() {
        let mut clock = WallClockState::UNKNOWN;
        clock.apply(T0, UP, TimeSource::GnssFix, true);
        // Distrusting the receiver is exactly why somebody sets a clock
        // by hand, so the flag must not block them.
        assert_eq!(
            clock.apply(T0 + 600, UP, TimeSource::Manual, false),
            Update::Stepped { previous: T0 }
        );
        assert_eq!(clock.now(UP), Some(T0 + 600));
        assert_eq!(clock.source(), Some(TimeSource::Manual));
    }

    #[test]
    fn fixes_resynchronize_a_running_clock_but_only_while_trusted() {
        let mut clock = WallClockState::UNKNOWN;
        clock.apply(T0, UP, TimeSource::Manual, true);
        // Every trusted fix refreshes the clock, which is how it stays
        // good across a long deployment.
        assert_eq!(
            clock.apply(T0 + 30, UP, TimeSource::GnssFix, true),
            Update::Stepped { previous: T0 }
        );
        assert_eq!(clock.now(UP), Some(T0 + 30));

        // With trust withdrawn, nothing the receiver says lands.
        assert_eq!(
            clock.apply(T0 + 90_000, UP, TimeSource::GnssFix, false),
            Update::Refused
        );
        assert_eq!(clock.now(UP), Some(T0 + 30));
        assert_eq!(clock.source(), Some(TimeSource::GnssFix));
    }

    #[test]
    fn real_time_clocks_restore_but_never_correct() {
        // A restore into an unset clock is the whole point of having one.
        let mut clock = WallClockState::UNKNOWN;
        assert_eq!(
            clock.apply(T0, UP, TimeSource::ExternalRtc, true),
            Update::Set
        );
        // A second restore must not displace a reading already in hand.
        assert_eq!(
            clock.apply(T0 - 500, UP, TimeSource::ExternalRtc, true),
            Update::Refused
        );
        assert_eq!(clock.now(UP), Some(T0));

        // The receiver's own RTC behaves the same, and is additionally
        // subject to the trust flag: it may have re-synchronized itself
        // from a bad sky while the device was running.
        let mut clock = WallClockState::UNKNOWN;
        assert_eq!(
            clock.apply(T0, UP, TimeSource::GnssRtc, false),
            Update::Refused
        );
        assert!(!clock.is_set());
        assert_eq!(clock.apply(T0, UP, TimeSource::GnssRtc, true), Update::Set);
        assert_eq!(clock.source(), Some(TimeSource::GnssRtc));
    }

    #[test]
    fn retained_time_restores_without_gnss_trust_but_corrections_require_it() {
        let mut clock = WallClockState::UNKNOWN;
        assert_eq!(
            clock.apply(T0, UP, TimeSource::ExternalRtc, false),
            Update::Set
        );
        assert_eq!(clock.now(UP + 60_000), Some(T0 + 60));
        assert_eq!(
            clock.apply(T0 + 90, UP + 60_000, TimeSource::GnssFix, false),
            Update::Refused
        );
        assert_eq!(clock.now(UP + 60_000), Some(T0 + 60));
        assert_eq!(
            clock.apply(T0 + 90, UP + 60_000, TimeSource::GnssFix, true),
            Update::Stepped { previous: T0 + 60 }
        );
        assert_eq!(clock.source(), Some(TimeSource::GnssFix));
    }

    #[test]
    fn only_real_movement_is_worth_announcing() {
        let mut clock = WallClockState::UNKNOWN;
        assert!(clock.apply(T0, UP, TimeSource::Manual, true).is_notable());
        // A receiver agreeing with the clock to within a second or two
        // still applies; it is just not news.
        let update = clock.apply(T0 + 1, UP, TimeSource::GnssFix, true);
        assert_eq!(update, Update::Unchanged);
        assert!(!update.is_notable());
        assert!(update.applied());
        assert_eq!(clock.now(UP), Some(T0 + 1));

        let update = clock.apply(T0 + 1 + NOTABLE_STEP_SECS, UP, TimeSource::GnssFix, true);
        assert!(update.is_notable());
        // Backwards counts the same as forwards.
        let update = clock.apply(T0, UP, TimeSource::GnssFix, true);
        assert!(update.is_notable());
        assert!(!Update::Refused.applied());
    }

    #[test]
    fn an_absurd_offset_reads_as_unknown_rather_than_wrapping() {
        // A clock set near the end of the representable range, then left
        // to run past it, has nothing honest to report.
        let mut clock = WallClockState::UNKNOWN;
        clock.apply(u32::MAX, 0, TimeSource::Manual, true);
        assert_eq!(clock.now(0), Some(u32::MAX));
        assert_eq!(clock.now(60_000), None);
    }

    #[test]
    fn receiver_derived_sources_are_the_ones_trust_governs() {
        assert!(TimeSource::GnssFix.is_receiver_derived());
        assert!(TimeSource::GnssRtc.is_receiver_derived());
        assert!(!TimeSource::Manual.is_receiver_derived());
        assert!(!TimeSource::ExternalRtc.is_receiver_derived());
    }
}
