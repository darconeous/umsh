//! Choosing a network: the rules of `docs/protocol/src/ulcp-wifi.md`
//! § Choosing a Network, as a state machine the platform's station task
//! drives.
//!
//! It does no I/O and keeps no clock. The platform tells it what the
//! table holds, what a scan heard, and how each join went, passing the
//! time in milliseconds, and asks [`Chooser::next`] what to do. Both the
//! hardware station and the simulated device run this, which is what keeps
//! them choosing the same way.
//!
//! The session is not where this lives because it has no timers and does
//! not see enough: a scan nobody is listening to never reaches it, and the
//! table it would report is bounded where this one is not.

use heapless::Vec;
use umsh_ulcp::wifi::{self, Link, LinkReason, LinkState};

use crate::known_networks::{KnownNetworks, MAX_NETWORKS};
use crate::net::{NetworkName, StationIntent};

/// The first wait between scans while no candidate is heard.
pub const SEARCH_MIN_MS: u64 = 15_000;
/// The longest wait between scans: what a battery can bear and a mesh
/// radio sharing the antenna can afford.
pub const SEARCH_MAX_MS: u64 = 300_000;
/// The first wait before a network that failed is tried again.
pub const RETRY_MIN_MS: u64 = 2_000;
/// The longest: a wrong passphrase is retried a few times an hour, which
/// costs nothing and recovers by itself when someone fixes the router.
pub const RETRY_MAX_MS: u64 = 900_000;
/// Hidden candidates are probed by name every this many searches; each
/// costs a directed scan on every channel.
pub const HIDDEN_PROBE_EVERY: u32 = 4;

/// What the station should do now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Join this network.
    Join(NetworkName),
    /// Scan, probing the hidden candidates by name when `probe_hidden`.
    Scan { probe_hidden: bool },
    /// Nothing until this time, or until something changes when `None`.
    Wait(Option<u64>),
}

/// What the station has been told, as [`crate::net::StationIntent`]
/// reduces to here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode<'a> {
    /// Join nothing.
    Paused,
    /// Keep trying this network.
    Hold(&'a [u8]),
    /// Choose among the candidates.
    Choose,
}

/// A network the table holds, as far as choosing goes.
#[derive(Clone, Copy, Debug)]
struct Slot {
    ssid: NetworkName,
    hidden: bool,
    /// Joined only when told to: never a candidate.
    manual: bool,
    /// Heard in the last scan, or answered a probe, and not since found
    /// missing by a join.
    heard: bool,
    rssi: i8,
    /// Joins that failed since this one last succeeded.
    failures: u8,
    /// Not tried again before this.
    retry_at_ms: u64,
}

impl Slot {
    fn ready(&self, now_ms: u64) -> bool {
        self.retry_at_ms <= now_ms
    }
}

/// Which network to join, and when to look for one.
#[derive(Clone, Debug)]
pub struct Chooser {
    slots: Vec<Slot, MAX_NETWORKS>,
    /// The network last joined, preferred over a stronger one. Kept in
    /// RAM only: after a restart the strongest wins.
    last_joined: NetworkName,
    /// The network associated now.
    associated: Option<NetworkName>,
    /// A held network has been joined during this hold, so losing it
    /// from the air ends the hold.
    held_joined: bool,
    search_wait_ms: u64,
    next_search_ms: u64,
    searches: u32,
    /// The last join that failed, or the association that dropped, since
    /// the last join that worked or the last new instruction.
    failure: Option<(NetworkName, LinkReason)>,
    /// The configuration last taken by [`Chooser::configure`].
    enabled: bool,
    intent: StationIntent,
    networks: KnownNetworks,
}

impl Default for Chooser {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            last_joined: NetworkName::default(),
            associated: None,
            held_joined: false,
            search_wait_ms: SEARCH_MIN_MS,
            next_search_ms: 0,
            searches: 0,
            failure: None,
            enabled: false,
            intent: StationIntent::default(),
            networks: KnownNetworks::default(),
        }
    }
}

impl Chooser {
    /// Take a new configuration: whether the station is on, the table,
    /// and what the session has told it. Answers whether the association
    /// must be dropped: the station went off or was paused, the network's
    /// entry is gone or has a new credential, or a different network is
    /// now held. Cheap when nothing changed, so a platform may call it on
    /// every pass.
    pub fn configure(
        &mut self,
        enabled: bool,
        intent: StationIntent,
        networks: &KnownNetworks,
        now_ms: u64,
    ) -> bool {
        if enabled == self.enabled && intent == self.intent && *networks == self.networks {
            return false;
        }
        let mut renewed: Vec<NetworkName, MAX_NETWORKS> = Vec::new();
        for entry in networks
            .entries()
            .filter_map(|bytes| wifi::NetworkEntry::decode(bytes).ok())
        {
            let same = self.networks.get(entry.ssid).is_some_and(|old| {
                old.security == entry.security
                    && old.raw_key == entry.raw_key
                    && old.credential == entry.credential
            });
            let mut name = NetworkName::default();
            if !same && name.set(entry.ssid).is_ok() {
                _ = renewed.push(name);
            }
        }
        self.set_networks(
            networks
                .entries()
                .filter_map(|bytes| wifi::NetworkEntry::decode(bytes).ok())
                .map(|entry| (entry.ssid, entry.hidden, entry.manual)),
            now_ms,
        );
        for name in &renewed {
            self.refresh(name.as_bytes());
        }
        if intent.hold != self.intent.hold {
            self.hold_changed();
        }
        if intent.epoch != self.intent.epoch || enabled != self.enabled {
            self.failure = None;
        }
        if enabled && !self.enabled {
            self.search_now(now_ms);
        }
        let drop = self.associated.is_some_and(|on| {
            !enabled
                || intent.paused
                || intent.leaves != self.intent.leaves
                || self.slot(on.as_bytes()).is_none()
                || renewed.contains(&on)
                || (!intent.hold.is_empty() && intent.hold != on)
        });
        if drop {
            self.associated = None;
        }
        self.enabled = enabled;
        self.intent = intent;
        self.networks = networks.clone();
        drop
    }

    /// What the configuration last taken says to do.
    pub fn mode(&self) -> Mode<'_> {
        match () {
            _ if !self.enabled || self.intent.paused => Mode::Paused,
            _ if !self.intent.hold.is_empty() => Mode::Hold(self.intent.hold.as_bytes()),
            _ => Mode::Choose,
        }
    }

    /// [`Chooser::next`] under the configuration last taken.
    pub fn step(&mut self, now_ms: u64) -> Next {
        let hold = self.intent.hold;
        let mode = match self.mode() {
            Mode::Paused => Mode::Paused,
            Mode::Hold(_) => Mode::Hold(hold.as_bytes()),
            Mode::Choose => Mode::Choose,
        };
        self.next(mode, now_ms)
    }

    /// The epoch of the configuration last taken, for tagging reports.
    pub fn epoch(&self) -> u32 {
        self.intent.epoch
    }

    /// The network associated now.
    pub fn associated(&self) -> Option<NetworkName> {
        self.associated
    }

    /// Whether any network is one the station may choose by itself.
    pub fn has_candidates(&self) -> bool {
        self.slots.iter().any(|slot| !slot.manual)
    }

    /// The network to report in `PROP_WIFI_NETWORK` while choosing: the
    /// one the station is on, or one that refused it or dropped and is
    /// being tried again. One not heard is searched for, so none is
    /// named. `None` outside choosing, where the session names the held
    /// network itself.
    pub fn naming(&self) -> Option<NetworkName> {
        (self.mode() == Mode::Choose).then(|| {
            self.associated
                .or(self
                    .failure
                    .filter(|failure| failure.1 != LinkReason::NotFound)
                    .map(|failure| failure.0))
                .unwrap_or_default()
        })
    }

    /// `PROP_WIFI_LINK` while not associated: trying, with the last
    /// failure's reason, or down when there is nothing to try.
    pub fn link_down(&self) -> Link {
        let trying = match self.mode() {
            Mode::Paused => false,
            Mode::Hold(_) => true,
            Mode::Choose => self.has_candidates(),
        };
        match trying {
            true => Link {
                state: LinkState::Connecting,
                reason: self.failure.map_or(LinkReason::None, |failure| failure.1),
                association: None,
            },
            false => Link::default(),
        }
    }

    /// The table now holds these networks: `(ssid, hidden, manual)`.
    /// What is known about one that stays is kept; a new one starts
    /// unheard and untried, and the search starts over, since a new
    /// network may be in range already.
    pub fn set_networks<'a>(
        &mut self,
        networks: impl IntoIterator<Item = (&'a [u8], bool, bool)>,
        now_ms: u64,
    ) {
        let mut next: Vec<Slot, MAX_NETWORKS> = Vec::new();
        let mut added = false;
        for (ssid, hidden, manual) in networks {
            let kept = self.slot(ssid).copied();
            added |= kept.is_none();
            let mut name = NetworkName::default();
            if name.set(ssid).is_err() {
                continue;
            }
            let slot = Slot {
                ssid: name,
                hidden,
                manual,
                ..kept.unwrap_or(Slot {
                    ssid: name,
                    hidden,
                    manual,
                    heard: false,
                    rssi: i8::MIN,
                    failures: 0,
                    retry_at_ms: 0,
                })
            };
            if next.push(slot).is_err() {
                break;
            }
        }
        self.slots = next;
        if added {
            self.search_now(now_ms);
        }
    }

    /// A network's entry was replaced with a new credential or mode: try
    /// it again at once rather than wait out a backoff earned by the old
    /// one.
    pub fn refresh(&mut self, ssid: &[u8]) {
        if let Some(slot) = self.slot_mut(ssid) {
            slot.failures = 0;
            slot.retry_at_ms = 0;
        }
    }

    /// Look now rather than at the next scheduled search: the station was
    /// turned on, or a host asked for a scan.
    pub fn search_now(&mut self, now_ms: u64) {
        self.search_wait_ms = SEARCH_MIN_MS;
        self.next_search_ms = now_ms;
    }

    /// A scan began. What earlier scans heard is forgotten.
    pub fn scan_started(&mut self) {
        for slot in &mut self.slots {
            slot.heard = false;
            slot.rssi = i8::MIN;
        }
    }

    /// The scan heard this access point.
    pub fn heard(&mut self, ssid: &[u8], rssi_dbm: i8) {
        if let Some(slot) = self.slot_mut(ssid) {
            slot.heard = true;
            slot.rssi = slot.rssi.max(rssi_dbm);
        }
    }

    /// The scan ended. With no candidate heard, the next search waits
    /// longer than this one did; with one, the wait starts over, since
    /// what was heard goes stale as the device moves.
    pub fn scan_finished(&mut self, now_ms: u64) {
        self.searches = self.searches.wrapping_add(1);
        if self.slots.iter().any(|slot| !slot.manual && slot.heard) {
            self.search_wait_ms = SEARCH_MIN_MS;
        }
        self.next_search_ms = now_ms + self.search_wait_ms;
        self.search_wait_ms = (self.search_wait_ms * 2).min(SEARCH_MAX_MS);
    }

    /// The station associated with `ssid`.
    pub fn joined(&mut self, ssid: &[u8]) {
        if let Some(slot) = self.slot_mut(ssid) {
            slot.failures = 0;
            slot.retry_at_ms = 0;
            slot.heard = true;
        }
        _ = self.last_joined.set(ssid);
        self.failure = None;
        let mut name = NetworkName::default();
        _ = name.set(ssid);
        self.associated = Some(name);
        self.held_joined = true;
    }

    /// The association dropped. The network goes on being tried first:
    /// a dropped link is usually a moment, and the next join says
    /// whether it is more.
    pub fn lost(&mut self) {
        if let Some(name) = self.associated.take() {
            self.failure = Some((name, LinkReason::Lost));
        }
    }

    /// A join of `ssid` failed for `reason`. Answers whether a hold of it
    /// ends here: a held network that was joined and is now not heard.
    pub fn failed(&mut self, ssid: &[u8], reason: LinkReason, now_ms: u64) -> bool {
        self.associated = None;
        let mut name = NetworkName::default();
        if name.set(ssid).is_ok() {
            self.failure = Some((name, reason));
        }
        let Some(slot) = self.slot_mut(ssid) else {
            return false;
        };
        slot.failures = slot.failures.saturating_add(1);
        let wait = RETRY_MIN_MS
            .saturating_mul(1 << (slot.failures - 1).min(20))
            .min(RETRY_MAX_MS);
        slot.retry_at_ms = now_ms + wait;
        let gone = reason == LinkReason::NotFound;
        if gone {
            slot.heard = false;
        }
        let ended = gone && self.held_joined;
        if ended {
            self.held_joined = false;
        }
        ended
    }

    /// A new hold, or none: whether the held network has been joined is
    /// counted afresh.
    pub fn hold_changed(&mut self) {
        self.held_joined = false;
    }

    /// What to do now.
    pub fn next(&mut self, mode: Mode<'_>, now_ms: u64) -> Next {
        match mode {
            Mode::Paused => Next::Wait(None),
            Mode::Hold(ssid) => {
                if self.associated.is_some_and(|name| name.as_bytes() == ssid) {
                    return Next::Wait(None);
                }
                match self.slot(ssid) {
                    None => Next::Wait(None),
                    Some(slot) if slot.ready(now_ms) => Next::Join(slot.ssid),
                    Some(slot) => Next::Wait(Some(slot.retry_at_ms)),
                }
            }
            Mode::Choose => self.choose(now_ms),
        }
    }

    fn choose(&mut self, now_ms: u64) -> Next {
        // A working association is never left for another.
        if self.associated.is_some() {
            return Next::Wait(None);
        }
        let candidates = || self.slots.iter().filter(|slot| !slot.manual);
        if candidates().next().is_none() {
            return Next::Wait(None);
        }
        let last = self.last_joined;
        let best = candidates()
            .filter(|slot| slot.heard && slot.ready(now_ms))
            .max_by_key(|slot| {
                (
                    slot.failures == 0,
                    slot.ssid.as_bytes() == last.as_bytes(),
                    slot.rssi,
                )
            });
        if let Some(slot) = best {
            return Next::Join(slot.ssid);
        }
        // Heard, but each waiting out a failure: the soonest, or the next
        // search if that comes first.
        let retry = candidates()
            .filter(|slot| slot.heard)
            .map(|slot| slot.retry_at_ms)
            .min();
        if now_ms >= self.next_search_ms {
            let probe_hidden =
                self.searches % HIDDEN_PROBE_EVERY == 0 && candidates().any(|slot| slot.hidden);
            return Next::Scan { probe_hidden };
        }
        Next::Wait(Some(
            retry.map_or(self.next_search_ms, |at| at.min(self.next_search_ms)),
        ))
    }

    fn slot(&self, ssid: &[u8]) -> Option<&Slot> {
        self.slots.iter().find(|slot| slot.ssid.as_bytes() == ssid)
    }

    fn slot_mut(&mut self, ssid: &[u8]) -> Option<&mut Slot> {
        self.slots
            .iter_mut()
            .find(|slot| slot.ssid.as_bytes() == ssid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(ssid: &[u8]) -> NetworkName {
        let mut name = NetworkName::default();
        name.set(ssid).unwrap();
        name
    }

    fn chooser(networks: &[(&[u8], bool, bool)]) -> Chooser {
        let mut chooser = Chooser::default();
        chooser.set_networks(networks.iter().copied(), 0);
        chooser
    }

    fn scan(chooser: &mut Chooser, heard: &[(&[u8], i8)], now: u64) {
        chooser.scan_started();
        for (ssid, rssi) in heard {
            chooser.heard(ssid, *rssi);
        }
        chooser.scan_finished(now);
    }

    #[test]
    fn with_nothing_heard_it_scans_then_backs_off() {
        let mut chooser = chooser(&[(b"Home", false, false)]);
        assert_eq!(
            chooser.next(Mode::Choose, 0),
            Next::Scan {
                probe_hidden: false
            }
        );
        scan(&mut chooser, &[], 0);
        assert_eq!(
            chooser.next(Mode::Choose, 1),
            Next::Wait(Some(SEARCH_MIN_MS))
        );
        scan(&mut chooser, &[], SEARCH_MIN_MS);
        assert_eq!(
            chooser.next(Mode::Choose, SEARCH_MIN_MS),
            Next::Wait(Some(3 * SEARCH_MIN_MS))
        );
        // The wait stops growing.
        for _ in 0..10 {
            scan(&mut chooser, &[], 0);
        }
        assert_eq!(chooser.search_wait_ms, SEARCH_MAX_MS);
        // A host scan, or turning the station on, looks at once.
        chooser.search_now(5);
        assert!(matches!(chooser.next(Mode::Choose, 5), Next::Scan { .. }));
    }

    #[test]
    fn the_last_joined_wins_then_the_strongest() {
        let mut chooser = chooser(&[(b"Home", false, false), (b"Cafe", false, false)]);
        scan(&mut chooser, &[(b"Home", -80), (b"Cafe", -50)], 0);
        assert_eq!(chooser.next(Mode::Choose, 0), Next::Join(name(b"Cafe")));
        chooser.joined(b"Home");
        chooser.lost();
        scan(&mut chooser, &[(b"Home", -80), (b"Cafe", -50)], 0);
        assert_eq!(chooser.next(Mode::Choose, 0), Next::Join(name(b"Home")));
    }

    #[test]
    fn a_working_association_is_kept() {
        let mut chooser = chooser(&[(b"Home", false, false), (b"Cafe", false, false)]);
        chooser.joined(b"Home");
        scan(&mut chooser, &[(b"Home", -90), (b"Cafe", -30)], 0);
        assert_eq!(chooser.next(Mode::Choose, 0), Next::Wait(None));
    }

    #[test]
    fn a_failure_moves_on_and_returns_after_its_backoff() {
        let mut chooser = chooser(&[(b"Home", false, false), (b"Cafe", false, false)]);
        scan(&mut chooser, &[(b"Home", -40), (b"Cafe", -70)], 0);
        assert_eq!(chooser.next(Mode::Choose, 0), Next::Join(name(b"Home")));
        assert!(!chooser.failed(b"Home", LinkReason::Auth, 0));
        assert_eq!(chooser.next(Mode::Choose, 1), Next::Join(name(b"Cafe")));
        assert!(!chooser.failed(b"Cafe", LinkReason::Rejected, 1));
        // Both waiting: Home is due first.
        assert_eq!(
            chooser.next(Mode::Choose, 2),
            Next::Wait(Some(RETRY_MIN_MS))
        );
        assert_eq!(
            chooser.next(Mode::Choose, RETRY_MIN_MS),
            Next::Join(name(b"Home"))
        );
        // A failed candidate ranks after one that has not failed.
        let mut chooser = self::chooser(&[(b"Home", false, false), (b"Cafe", false, false)]);
        scan(&mut chooser, &[(b"Home", -40)], 0);
        chooser.failed(b"Home", LinkReason::Auth, 0);
        scan(&mut chooser, &[(b"Home", -40), (b"Cafe", -90)], 0);
        assert_eq!(
            chooser.next(Mode::Choose, RETRY_MIN_MS),
            Next::Join(name(b"Cafe"))
        );
    }

    #[test]
    fn the_retry_backoff_grows_to_a_few_times_an_hour() {
        let mut chooser = chooser(&[(b"Home", false, false)]);
        for _ in 0..30 {
            chooser.failed(b"Home", LinkReason::Auth, 0);
        }
        assert_eq!(chooser.slot(b"Home").unwrap().retry_at_ms, RETRY_MAX_MS);
        // A corrected passphrase is tried at once.
        chooser.refresh(b"Home");
        assert_eq!(
            chooser.next(Mode::Hold(b"Home"), 0),
            Next::Join(name(b"Home"))
        );
    }

    #[test]
    fn a_manual_network_is_joined_only_when_held() {
        let mut chooser = chooser(&[(b"Guest", false, true)]);
        scan(&mut chooser, &[(b"Guest", -30)], 0);
        assert_eq!(chooser.next(Mode::Choose, 0), Next::Wait(None));
        assert_eq!(
            chooser.next(Mode::Hold(b"Guest"), 0),
            Next::Join(name(b"Guest"))
        );
    }

    #[test]
    fn a_hold_ends_when_its_network_is_joined_and_then_not_heard() {
        let mut chooser = chooser(&[(b"Home", false, false)]);
        chooser.hold_changed();
        // Never joined: a hold keeps trying whatever the failure.
        assert!(!chooser.failed(b"Home", LinkReason::NotFound, 0));
        assert_eq!(
            chooser.next(Mode::Hold(b"Home"), 1),
            Next::Wait(Some(RETRY_MIN_MS))
        );
        chooser.joined(b"Home");
        assert_eq!(chooser.next(Mode::Hold(b"Home"), 1), Next::Wait(None));
        chooser.lost();
        // Dropped: retried first, and a failure other than not found
        // keeps the hold.
        assert_eq!(
            chooser.next(Mode::Hold(b"Home"), 1),
            Next::Join(name(b"Home"))
        );
        assert!(!chooser.failed(b"Home", LinkReason::Auth, 1));
        assert!(chooser.failed(b"Home", LinkReason::NotFound, 2));
    }

    #[test]
    fn paused_does_nothing() {
        let mut chooser = chooser(&[(b"Home", false, false)]);
        scan(&mut chooser, &[(b"Home", -30)], 0);
        assert_eq!(chooser.next(Mode::Paused, 0), Next::Wait(None));
        assert_eq!(chooser.next(Mode::Choose, 0), Next::Join(name(b"Home")));
    }

    #[test]
    fn hidden_candidates_are_probed_every_few_searches() {
        let mut chooser = chooser(&[(b"Attic", true, false)]);
        let (mut scans, mut probes, mut now) = (0, 0, 0);
        while scans < 2 * HIDDEN_PROBE_EVERY {
            match chooser.next(Mode::Choose, now) {
                Next::Scan { probe_hidden } => {
                    scans += 1;
                    probes += probe_hidden as u32;
                    scan(&mut chooser, &[], now);
                }
                Next::Wait(Some(at)) => now = at,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(probes, 2);
    }

    #[test]
    fn a_new_network_restarts_the_search_and_known_ones_keep_their_history() {
        let mut chooser = chooser(&[(b"Home", false, false)]);
        chooser.failed(b"Home", LinkReason::Auth, 0);
        scan(&mut chooser, &[], 0);
        chooser.set_networks(
            [
                (b"Home".as_slice(), false, false),
                (b"Cafe".as_slice(), false, false),
            ],
            7,
        );
        assert_eq!(chooser.slot(b"Home").unwrap().failures, 1);
        assert!(matches!(chooser.next(Mode::Choose, 7), Next::Scan { .. }));
        // Forgotten networks are gone, without a new search.
        chooser.set_networks([(b"Cafe".as_slice(), false, false)], 8);
        assert!(chooser.slot(b"Home").is_none());
    }

    fn table(entries: &[(&[u8], &[u8], bool)]) -> KnownNetworks {
        let mut table = KnownNetworks::default();
        for &(ssid, password, manual) in entries {
            let entry = wifi::NetworkEntry {
                hidden: false,
                raw_key: false,
                manual,
                security: wifi::SecurityMode::Wpa2,
                ssid,
                credential: password,
            };
            let mut bytes = [0; wifi::NETWORK_ENTRY_MAX_LEN];
            let len = entry.encode(&mut bytes).unwrap();
            table.insert(&bytes[..len]).unwrap();
        }
        table
    }

    #[test]
    fn a_configuration_says_when_to_drop_the_association() {
        let mut chooser = Chooser::default();
        let mut intent = StationIntent::default();
        let networks = table(&[(b"Home", b"password", false), (b"Cafe", b"password", true)]);
        assert!(!chooser.configure(true, intent, &networks, 0));
        assert_eq!(chooser.mode(), Mode::Choose);
        assert!(chooser.has_candidates());
        // Choosing, a network that refused the station stays named; one
        // not heard is searched for.
        chooser.failed(b"Home", LinkReason::Auth, 0);
        assert_eq!(chooser.naming(), Some(name(b"Home")));
        assert_eq!(chooser.link_down().state, LinkState::Connecting);
        chooser.failed(b"Home", LinkReason::NotFound, 0);
        assert_eq!(chooser.naming(), Some(NetworkName::default()));
        chooser.joined(b"Home");
        assert_eq!(chooser.naming(), Some(name(b"Home")));
        chooser.lost();
        assert_eq!(chooser.link_down().reason, LinkReason::Lost);
        assert_eq!(chooser.naming(), Some(name(b"Home")));
        chooser.joined(b"Home");

        // New flags are not a new credential.
        let flags = table(&[(b"Home", b"password", true), (b"Cafe", b"password", true)]);
        assert!(!chooser.configure(true, intent, &flags, 1));
        assert!(!chooser.has_candidates());
        let renewed = table(&[(b"Home", b"changed!", true), (b"Cafe", b"password", true)]);
        assert!(chooser.configure(true, intent, &renewed, 2));

        // Holding the network already joined keeps it; holding another
        // drops it.
        chooser.joined(b"Home");
        intent.hold.set(b"Home").unwrap();
        intent.epoch += 1;
        assert!(!chooser.configure(true, intent, &renewed, 3));
        assert_eq!(chooser.mode(), Mode::Hold(b"Home"));
        intent.hold.set(b"Cafe").unwrap();
        intent.epoch += 1;
        assert!(chooser.configure(true, intent, &renewed, 4));

        // A leave drops it even when the same network is held again.
        chooser.joined(b"Cafe");
        intent.leaves += 1;
        intent.epoch += 1;
        assert!(chooser.configure(true, intent, &renewed, 5));
        assert_eq!(chooser.epoch(), intent.epoch);

        // A failure is reported until a join works or the instruction
        // changes.
        assert!(!chooser.configure(true, intent, &renewed, 6));
        chooser.failed(b"Cafe", LinkReason::Auth, 6);
        assert_eq!(chooser.link_down().reason, LinkReason::Auth);
        assert_eq!(chooser.naming(), None, "the session names a held network");

        chooser.joined(b"Cafe");
        intent.paused = true;
        intent.hold = NetworkName::default();
        assert!(chooser.configure(true, intent, &renewed, 6));
        assert_eq!(chooser.mode(), Mode::Paused);
        assert!(!chooser.configure(false, intent, &renewed, 7));
        assert_eq!(chooser.mode(), Mode::Paused);
    }
}
