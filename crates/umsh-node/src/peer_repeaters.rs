//! The repeaters a node has heard directly, and how it answers a
//! [Peer Repeaters Request](../../docs/protocol-legacy/src/mac-commands.md).
//!
//! The list is a neighborhood: repeaters heard off their own transmitters.
//! Two sources feed it, because neither is enough on its own:
//!
//! - **Identities.** A repeater that advertises tells its neighbors its name,
//!   its position, and the regions it forwards for. None of that can be
//!   recovered from a hint. Only an identity heard directly counts—one that
//!   arrived forwarded says nothing about whether its owner is in range—
//!   and only on a frame that authenticated its owner and passed replay
//!   detection. An identity's own signature carries no freshness, so one
//!   captured anywhere would otherwise list its owner wherever it was
//!   played back ([`identity_heard_directly`](crate::identity_heard_directly)).
//! - **Transmitter observations** ([`umsh_mac::TransmitterObservations`]).
//!   A repeater prepends its repeater hint to the trace route of every frame
//!   it forwards, so every traced frame off the air names the repeater
//!   that just transmitted it and how well it was heard—including
//!   repeaters that never send this node anything of their own. The hint
//!   is not authenticated, so the MAC keeps the repeaters it has heard
//!   carrying this node's own frames from being displaced by those it has
//!   only heard named.
//!
//! A [`RepeaterHint`] is the first two bytes of a public key and a [`NodeHint`]
//! the first three, so the observation's key is a prefix of the identity's.
//! That is what lets the two merge: an observation is credited to the
//! identities its hint begins ([`PeerRepeaterTable::credited`]), and one
//! credited to none becomes an entry naming a hop by its repeater hint and
//! reporting only what was heard.
//!
//! An identity-bearing entry counts as heard whenever its identity, a frame
//! it originated, or a forward credited to it is heard directly. None of
//! those but the identity is authenticated, so being heard only keeps an
//! entry from giving way in a full table: the entry still goes once
//! [`IDENTITY_LIFETIME_MS`] passes without its identity.

use alloc::string::String;
use alloc::vec::Vec;

use umsh_core::{NodeHint, PublicKey, RepeaterHint};
use umsh_hal::Snr;

use crate::IdentityUpdate;
use crate::identity::{NodeCapabilities, NodeIdentityPayload, NodeRole};
use crate::location::NodeLocation;

/// How many identity-bearing repeaters the table remembers.
///
/// Sized to the MAC's observation table: the two merge into one listing, and
/// a listing longer than the 1-byte Total the response reports would have to
/// be truncated anyway.
pub const MAX_PEER_REPEATERS: usize = 16;

const _: () = assert!(MAX_PEER_REPEATERS <= u16::BITS as usize);

/// How long an entry may go unheard before it is the first to give way:
/// two default beacon intervals.
pub const STALE_AFTER_MS: u64 = 2 * 60 * 60 * 1000;

/// How recently an identity must have been heard for a forward under its
/// repeater hint to be credited to it when other identities share that hint:
/// two default advertisement intervals, so one missed advertisement is
/// forgiven.
pub const ATTRIBUTION_IDENTITY_AGE_MS: u64 = 8 * 60 * 60 * 1000;

/// How long an entry is kept without its identity being heard again.
pub const IDENTITY_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Region codes kept per peer, matching the identity option's own cap.
pub const MAX_PEER_REGIONS: usize = 10;

/// What one repeater's identity told this node about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRepeaterRecord {
    /// The whole node hint, since an identity carries the whole key.
    pub hint: NodeHint,
    pub name: Option<String>,
    pub location: Option<NodeLocation>,
    /// The codes the peer flood-forwards for, derived from the region
    /// strings its identity carried.
    pub regions: Vec<[u8; 2]>,
    /// How well the peer was last heard directly, when the radio measured
    /// it.
    pub rssi_snr: Option<(i16, Snr)>,
    /// When the identity last arrived, on the monotonic clock.
    pub last_identity_ms: u64,
    /// When the peer was last heard directly by any means, on the
    /// monotonic clock.
    pub last_heard_ms: u64,
    /// Where the entry stands in a full table while it is still being
    /// heard; higher stays longer. See [`rank`].
    pub rank: u8,
}

impl PeerRepeaterRecord {
    /// The repeater hint an observation would be keyed by—the first two
    /// bytes of the same public key.
    pub fn repeater_hint(&self) -> RepeaterHint {
        RepeaterHint([self.hint.0[0], self.hint.0[1]])
    }

    /// Note a direct reception at `at_ms`. The newer reception supplies the
    /// signal, falling back to the older one's when it had no radio in it to
    /// measure.
    fn heard(&mut self, at_ms: u64, rssi_snr: Option<(i16, Snr)>) {
        if at_ms >= self.last_heard_ms {
            self.last_heard_ms = at_ms;
            self.rssi_snr = rssi_snr.or(self.rssi_snr);
        } else {
            self.rssi_snr = self.rssi_snr.or(rssi_snr);
        }
    }

    /// The entry's [`rank`], or zero once it has gone unheard for
    /// [`STALE_AFTER_MS`].
    fn standing(&self, now_ms: u64) -> u8 {
        if now_ms.saturating_sub(self.last_heard_ms) >= STALE_AFTER_MS {
            0
        } else {
            self.rank
        }
    }
}

/// How firmly an identity claims to be a repeater, which decides who gives
/// way in a full table: a mobile node first, since it will likely move on;
/// then one forwarding only by role, then one forwarding only by capability;
/// a fixed node claiming both last.
pub fn rank(identity: &NodeIdentityPayload) -> u8 {
    let capabilities = identity.capabilities;
    if capabilities.contains(NodeCapabilities::MOBILE) {
        1
    } else if !capabilities.contains(NodeCapabilities::REPEATER) {
        2
    } else if !matches!(identity.role, NodeRole::Repeater | NodeRole::Bridge) {
        3
    } else {
        4
    }
}

/// The repeaters whose identities this node has heard directly.
///
/// RAM-only: a listing describes a neighborhood as it is now, and a table
/// restored from flash would name repeaters that may have moved or gone.
#[derive(Clone, Debug, Default)]
pub struct PeerRepeaterTable {
    records: Vec<PeerRepeaterRecord>,
    /// Bumped on every mutation, so a paging cursor can tell that the list
    /// it was walking is no longer the list it started on.
    generation: u16,
}

impl PeerRepeaterTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an identity describes a repeater, and so belongs here: one
    /// that [forwards](crate::forwards).
    pub fn is_repeater(identity: &NodeIdentityPayload) -> bool {
        crate::forwards(identity.role, identity.capabilities)
    }

    /// Record what an identity heard directly said.
    ///
    /// The caller vouches that the identity came off its owner's own
    /// transmitter, on a frame that authenticated its owner and passed
    /// replay detection; `rssi_snr` is that reception's measurement, when
    /// the radio made one. Returns whether the table changed.
    ///
    /// Under [`IdentityUpdate::Replace`] a repeat identity replaces the
    /// record rather than merging with it: the newest advertisement is the
    /// node's own account of itself. The same holds when that account no
    /// longer claims repeating—the record an earlier identity left is
    /// withdrawn, name and position with it.
    ///
    /// Under [`IdentityUpdate::Fill`] the identity may be older than what
    /// the table holds, so it adds a repeater not yet listed and fills in
    /// what a listed one lacks, and changes nothing it already has. The
    /// reception itself is current either way, so its measurement and time
    /// are kept.
    ///
    /// A full table makes room by giving up the entry of lowest standing—
    /// one unheard for [`STALE_AFTER_MS`] first, then by [`rank`]—the least
    /// recently heard first among equals, and only an entry standing no
    /// higher than the newcomer's rank. A newcomer outranked by every entry
    /// is turned away.
    pub fn observe_identity(
        &mut self,
        from: &PublicKey,
        identity: &NodeIdentityPayload,
        update: IdentityUpdate,
        rssi_snr: Option<(i16, Snr)>,
        now_ms: u64,
    ) -> bool {
        self.expire(now_ms);
        let hint = from.hint();
        let existing = self.records.iter().position(|entry| entry.hint == hint);
        if !Self::is_repeater(identity) {
            let Some(index) = existing.filter(|_| update == IdentityUpdate::Replace) else {
                return false;
            };
            self.records.swap_remove(index);
            self.bump();
            return true;
        }
        let rank = rank(identity);
        let mut record = PeerRepeaterRecord {
            hint,
            name: identity.name.clone(),
            location: identity.location,
            regions: region_codes(identity),
            rssi_snr,
            last_identity_ms: now_ms,
            last_heard_ms: now_ms,
            rank,
        };
        if let Some(index) = existing {
            let existing = &mut self.records[index];
            // When it was heard outlasts whichever account it gave.
            existing.heard(now_ms, rssi_snr);
            match update {
                IdentityUpdate::Replace => {
                    record.last_heard_ms = existing.last_heard_ms;
                    record.rssi_snr = existing.rssi_snr;
                    *existing = record;
                }
                IdentityUpdate::Fill => {
                    if existing.name.is_none() {
                        existing.name = record.name;
                    }
                    if existing.location.is_none() {
                        existing.location = record.location;
                    }
                    if existing.regions.is_empty() {
                        existing.regions = record.regions;
                    }
                    existing.last_identity_ms = now_ms;
                }
            }
        } else if self.records.len() < MAX_PEER_REPEATERS {
            self.records.push(record);
        } else {
            let Some(giving_way) = self
                .records
                .iter_mut()
                .min_by_key(|entry| (entry.standing(now_ms), entry.last_heard_ms))
                .filter(|entry| entry.standing(now_ms) <= rank)
            else {
                return false;
            };
            *giving_way = record;
        }
        self.bump();
        true
    }

    /// Which entries a forward heard at `at_ms` under repeater hint `hint` is
    /// credited to, one bit per entry in [`iter`](Self::iter) order.
    ///
    /// Every entry whose node hint begins with `hint` and whose identity
    /// arrived within [`ATTRIBUTION_IDENTITY_AGE_MS`] of the forward is
    /// credited. Failing those, an entry that is the only one beginning with
    /// `hint` is credited however old it is; several such, none of them
    /// recent, leave the forward credited to none.
    pub fn credited(&self, hint: RepeaterHint, at_ms: u64) -> u16 {
        let mut matching = 0u16;
        let mut recent = 0u16;
        for (index, entry) in self.records.iter().enumerate() {
            if entry.repeater_hint() == hint {
                matching |= 1 << index;
                if at_ms.saturating_sub(entry.last_identity_ms) < ATTRIBUTION_IDENTITY_AGE_MS {
                    recent |= 1 << index;
                }
            }
        }
        if recent != 0 {
            recent
        } else if matching.count_ones() == 1 {
            matching
        } else {
            0
        }
    }

    /// Note a forward the MAC heard, on each entry it is
    /// [credited](Self::credited) to.
    ///
    /// Noting the same observation again changes nothing, so a caller may
    /// pass along the MAC's whole table as often as it likes. Returns the
    /// entries credited, as [`credited`](Self::credited) does.
    pub fn credit_forwarding(&mut self, observation: &umsh_mac::TransmitterObservation) -> u16 {
        let credited = self.credited(observation.hint, observation.last_seen_ms);
        for (index, entry) in self.records.iter_mut().enumerate() {
            if credited & (1 << index) != 0 {
                entry.heard(observation.last_seen_ms, observation.rssi_snr);
            }
        }
        credited
    }

    /// Note a frame heard directly off the node whose hint is `hint`.
    pub fn note_heard(&mut self, hint: NodeHint, rssi_snr: Option<(i16, Snr)>, at_ms: u64) {
        if let Some(entry) = self.records.iter_mut().find(|entry| entry.hint == hint) {
            entry.heard(at_ms, rssi_snr);
        }
    }

    /// Give up every entry whose identity has not been heard for
    /// [`IDENTITY_LIFETIME_MS`].
    pub fn expire(&mut self, now_ms: u64) {
        while let Some(index) = self
            .records
            .iter()
            .position(|entry| now_ms.saturating_sub(entry.last_identity_ms) >= IDENTITY_LIFETIME_MS)
        {
            self.records.swap_remove(index);
            self.bump();
        }
    }

    /// Mark that entries came, went, or were rewritten. Being heard is not
    /// counted: like a fresh observation in the MAC's table, it moves no
    /// entry in or out.
    fn bump(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn iter(&self) -> impl Iterator<Item = &PeerRepeaterRecord> {
        self.records.iter()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The value a paging cursor carries, so a follow-up request that
    /// resumes into a changed list is recognized as stale.
    pub fn generation(&self) -> u16 {
        self.generation
    }
}

/// Derive the forwarding codes from an identity's region strings.
///
/// The identity carries strings and an entry carries codes: the entry format
/// is tighter on space, and the string form is available from the peer's own
/// identity when one is wanted.
fn region_codes(identity: &NodeIdentityPayload) -> Vec<[u8; 2]> {
    let Some(regions) = identity.supported_regions.as_ref() else {
        return Vec::new();
    };
    regions
        .iter()
        .filter_map(|region| region.parse::<umsh_core::RegionCode>().ok())
        .map(|code| code.to_bytes())
        .take(MAX_PEER_REGIONS)
        .collect()
}

/// One row of a merged listing: everything known about one peer repeater,
/// from either source or both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergedPeerRepeater {
    /// Three bytes when an identity supplied the whole node hint, two when
    /// only an observation named this hop.
    pub hint: Vec<u8>,
    pub name: Option<String>,
    pub location: Option<NodeLocation>,
    pub regions: Vec<[u8; 2]>,
    /// The most recent measured reception, from whichever source heard the
    /// peer last.
    pub rssi_dbm: Option<i16>,
    pub snr: Option<Snr>,
    /// Minutes since this peer was last heard from, by either source.
    pub last_heard_min: Option<u16>,
}

/// Merge the identity table with the MAC's transmitter observations.
///
/// An observation is part of each identity it is
/// [credited](PeerRepeaterTable::credited) to, and one credited to none
/// becomes a two-byte-hint entry. Every source is a direct reception, so
/// whichever heard the peer most recently supplies the signal figures.
///
/// The listing is ordered most recently heard first. The first page is the
/// one a requester is surest to read, and the neighbors on the air right
/// now are the ones it is asking about.
pub fn merge<'a>(
    mut identities: PeerRepeaterTable,
    observations: impl IntoIterator<Item = &'a umsh_mac::TransmitterObservation>,
    now_ms: u64,
) -> Vec<MergedPeerRepeater> {
    // Credit every observation, keeping those credited to none.
    let unclaimed: Vec<&umsh_mac::TransmitterObservation> = observations
        .into_iter()
        .filter(|observation| identities.credit_forwarding(observation) == 0)
        .collect();
    // Each entry alongside the monotonic time it was last heard, which orders
    // the list more finely than the wire's whole minutes can.
    let mut merged: Vec<(u64, MergedPeerRepeater)> = Vec::new();

    for record in identities.records {
        merged.push((
            record.last_heard_ms,
            MergedPeerRepeater {
                hint: Vec::from(&record.hint.0[..]),
                name: record.name,
                location: record.location,
                regions: record.regions,
                rssi_dbm: record.rssi_snr.map(|(rssi, _)| rssi),
                snr: record.rssi_snr.map(|(_, snr)| snr),
                last_heard_min: minutes_since(Some(record.last_heard_ms), now_ms),
            },
        ));
    }

    for observation in unclaimed {
        merged.push((
            observation.last_seen_ms,
            MergedPeerRepeater {
                hint: Vec::from(&observation.hint.0[..]),
                name: None,
                location: None,
                regions: Vec::new(),
                rssi_dbm: observation.rssi_snr.map(|(rssi, _)| rssi),
                snr: observation.rssi_snr.map(|(_, snr)| snr),
                last_heard_min: minutes_since(Some(observation.last_seen_ms), now_ms),
            },
        ));
    }

    // Stable, so peers heard in the same instant keep identity-first order.
    merged.sort_by_key(|(last_heard_ms, _)| core::cmp::Reverse(*last_heard_ms));
    merged.into_iter().map(|(_, entry)| entry).collect()
}

/// Whole minutes between `then_ms` and now, saturating at the two octets the
/// wire form allows—about 45 days, past which "longer ago than that" is the
/// only useful answer anyway.
fn minutes_since(then_ms: Option<u64>, now_ms: u64) -> Option<u16> {
    let then_ms = then_ms?;
    let elapsed_min = now_ms.saturating_sub(then_ms) / 60_000;
    Some(u16::try_from(elapsed_min).unwrap_or(u16::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{NodeCapabilities, NodeRole};

    fn key(seed: u8) -> PublicKey {
        PublicKey([seed; 32])
    }

    fn repeater_identity(name: &str, regions: &[&str]) -> NodeIdentityPayload {
        NodeIdentityPayload {
            role: NodeRole::Repeater,
            capabilities: NodeCapabilities::REPEATER,
            name: Some(String::from(name)),
            location: None,
            altitude_m: None,
            timestamp: None,
            supported_regions: Some(regions.iter().map(|text| String::from(*text)).collect()),
            nonce: None,
            signature: None,
        }
    }

    fn observation(hint: RepeaterHint, last_seen_ms: u64) -> umsh_mac::TransmitterObservation {
        umsh_mac::TransmitterObservation {
            hint,
            rssi_snr: Some((-95, Snr::from_decibels(2))),
            last_seen_ms,
        }
    }

    /// A neighbor heard forwarding over a link no radio measured is listed
    /// like any other, with the signal fields simply absent.
    #[test]
    fn an_unmeasured_neighbor_is_listed_without_a_signal() {
        let table = PeerRepeaterTable::new();
        let observations = [umsh_mac::TransmitterObservation {
            hint: RepeaterHint([0x11, 0x22]),
            rssi_snr: None,
            last_seen_ms: 60_000,
        }];
        let merged = merge(table.clone(), observations.iter(), 120_000);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].hint, [0x11, 0x22]);
        assert_eq!(merged[0].rssi_dbm, None);
        assert_eq!(merged[0].snr, None);
        assert_eq!(merged[0].last_heard_min, Some(1));
    }

    #[test]
    fn only_repeaters_are_recorded() {
        let mut table = PeerRepeaterTable::new();
        let mut chat = repeater_identity("Handset", &[]);
        chat.role = NodeRole::Chat;
        chat.capabilities = NodeCapabilities::TEXT_MESSAGES;
        assert!(!table.observe_identity(&key(1), &chat, IdentityUpdate::Replace, None, 0));
        assert!(table.is_empty());

        // The capability alone is enough—a node may forward while
        // presenting itself as something else.
        let mut forwarding_handset = chat.clone();
        forwarding_handset.capabilities |= NodeCapabilities::REPEATER;
        assert!(table.observe_identity(
            &key(1),
            &forwarding_handset,
            IdentityUpdate::Replace,
            None,
            0
        ));
        assert_eq!(table.len(), 1);

        // A bridge is a node with its repeater enabled, whatever bitmap it
        // advertises.
        let mut bridge = chat.clone();
        bridge.role = NodeRole::Bridge;
        assert!(table.observe_identity(&key(2), &bridge, IdentityUpdate::Replace, None, 0));
        assert_eq!(table.len(), 2);
    }

    /// The newest identity is the node's own account of itself, so one that
    /// stops claiming to forward takes back the position an earlier one
    /// gave—rather than leaving it listed until the table fills or the
    /// node reboots.
    #[test]
    fn an_identity_that_stops_claiming_repeating_withdraws_the_record() {
        let mut table = PeerRepeaterTable::new();
        table.observe_identity(
            &key(1),
            &repeater_identity("Ridge", &[]),
            IdentityUpdate::Replace,
            None,
            0,
        );
        table.observe_identity(
            &key(2),
            &repeater_identity("Saddle", &[]),
            IdentityUpdate::Replace,
            None,
            0,
        );
        let generation = table.generation();

        let mut retired = repeater_identity("Ridge", &[]);
        retired.role = NodeRole::Chat;
        retired.capabilities = NodeCapabilities::TEXT_MESSAGES;
        assert!(table.observe_identity(&key(1), &retired, IdentityUpdate::Replace, None, 1_000));
        assert_eq!(table.len(), 1);
        assert_eq!(table.iter().next().unwrap().hint, key(2).hint());
        // A cursor into the old listing must not resume into this one.
        assert_ne!(table.generation(), generation);

        // Nothing left to withdraw is not a change.
        let generation = table.generation();
        assert!(!table.observe_identity(&key(1), &retired, IdentityUpdate::Replace, None, 2_000));
        assert_eq!(table.generation(), generation);
    }

    #[test]
    fn an_identity_supplies_the_name_and_regions_an_observation_cannot() {
        let mut table = PeerRepeaterTable::new();
        table.observe_identity(
            &key(0xAA),
            &repeater_identity("Ridge", &["SJC"]),
            IdentityUpdate::Replace,
            None,
            1_000,
        );

        let record = table.iter().next().unwrap();
        assert_eq!(record.name.as_deref(), Some("Ridge"));
        assert_eq!(record.regions, [[0x78, 0x53]]);
        assert_eq!(record.hint, key(0xAA).hint());
    }

    /// A repeater hint is a node hint's first two bytes, which is the whole
    /// reason the two tables can be joined at all.
    #[test]
    fn an_identity_claims_the_observation_whose_hint_it_starts_with() {
        let mut table = PeerRepeaterTable::new();
        table.observe_identity(
            &key(0xAA),
            &repeater_identity("Ridge", &["SJC"]),
            IdentityUpdate::Replace,
            Some((-60, Snr::from_decibels(8))),
            60_000,
        );
        let hint = key(0xAA).hint();
        let observations = [
            observation(RepeaterHint([hint.0[0], hint.0[1]]), 120_000),
            observation(RepeaterHint([0x11, 0x22]), 60_000),
        ];

        let merged = merge(table.clone(), observations.iter(), 180_000);
        assert_eq!(merged.len(), 2);

        assert_eq!(merged[0].hint, hint.0);
        assert_eq!(merged[0].name.as_deref(), Some("Ridge"));
        assert_eq!(
            merged[0].rssi_dbm,
            Some(-95),
            "the newer reception supplies the signal"
        );
        assert_eq!(
            merged[0].last_heard_min,
            Some(1),
            "the newer of the two sources is when it was last heard"
        );

        // An observation nothing claims still names a hop, by the only name
        // a trace gives it.
        assert_eq!(merged[1].hint, [0x11, 0x22]);
        assert_eq!(merged[1].name, None);
        assert_eq!(merged[1].rssi_dbm, Some(-95));
        assert_eq!(merged[1].last_heard_min, Some(2));
    }

    /// An identity heard directly is a reception in its own right, so a
    /// repeater that has only ever advertised still comes with a signal.
    #[test]
    fn an_identity_heard_more_recently_than_any_forwarding_supplies_the_signal() {
        let mut table = PeerRepeaterTable::new();
        table.observe_identity(
            &key(0xAA),
            &repeater_identity("Ridge", &[]),
            IdentityUpdate::Replace,
            Some((-60, Snr::from_decibels(8))),
            120_000,
        );
        let hint = key(0xAA).hint();

        let alone = merge(table.clone(), [].iter(), 180_000);
        assert_eq!(alone.len(), 1);
        assert_eq!(alone[0].rssi_dbm, Some(-60));
        assert_eq!(alone[0].snr, Some(Snr::from_decibels(8)));
        assert_eq!(alone[0].last_heard_min, Some(1));

        let older = [observation(RepeaterHint([hint.0[0], hint.0[1]]), 60_000)];
        let merged = merge(table.clone(), older.iter(), 180_000);
        assert_eq!(merged.len(), 1, "the identity claimed the observation");
        assert_eq!(
            merged[0].rssi_dbm,
            Some(-60),
            "the older forwarding does not outrank the newer advertisement"
        );
    }

    /// Whoever was heard last is listed first, whichever source heard them.
    #[test]
    fn the_listing_is_ordered_most_recently_heard_first() {
        let mut table = PeerRepeaterTable::new();
        // An identity heard long ago whose owner was heard forwarding since,
        // one heard recently, and one heard long ago and never since.
        table.observe_identity(
            &key(0xAA),
            &repeater_identity("Refreshed", &[]),
            IdentityUpdate::Replace,
            None,
            10_000,
        );
        table.observe_identity(
            &key(0xBB),
            &repeater_identity("Recent", &[]),
            IdentityUpdate::Replace,
            None,
            200_000,
        );
        table.observe_identity(
            &key(0xCC),
            &repeater_identity("Stale", &[]),
            IdentityUpdate::Replace,
            None,
            20_000,
        );
        let refreshed = key(0xAA).hint();
        let observations = [
            observation(RepeaterHint([refreshed.0[0], refreshed.0[1]]), 300_000),
            // Never introduced, heard forwarding between the other two.
            observation(RepeaterHint([0x11, 0x22]), 100_000),
        ];

        let merged = merge(table.clone(), observations.iter(), 400_000);
        let order: Vec<&[u8]> = merged.iter().map(|entry| &entry.hint[..]).collect();
        assert_eq!(
            order,
            [
                &refreshed.0[..],
                &key(0xBB).hint().0[..],
                &[0x11, 0x22][..],
                &key(0xCC).hint().0[..],
            ]
        );
        assert_eq!(merged[0].last_heard_min, Some(1));
        assert_eq!(merged[3].last_heard_min, Some(6));
    }

    /// A radio that reported no measurement for the advertisement leaves the
    /// signal to whatever forwarding was heard, however old.
    #[test]
    fn an_unmeasured_identity_falls_back_to_the_observation_it_claimed() {
        let mut table = PeerRepeaterTable::new();
        table.observe_identity(
            &key(0xAA),
            &repeater_identity("Ridge", &[]),
            IdentityUpdate::Replace,
            None,
            120_000,
        );
        let hint = key(0xAA).hint();

        let merged = merge(table.clone(), [].iter(), 180_000);
        assert_eq!(merged[0].rssi_dbm, None);
        assert_eq!(merged[0].snr, None);

        let older = [observation(RepeaterHint([hint.0[0], hint.0[1]]), 60_000)];
        let merged = merge(table.clone(), older.iter(), 180_000);
        assert_eq!(merged[0].rssi_dbm, Some(-95));
    }

    #[test]
    fn a_repeat_identity_replaces_the_record_and_moves_the_generation() {
        let mut table = PeerRepeaterTable::new();
        table.observe_identity(
            &key(0xAA),
            &repeater_identity("Ridge", &["SJC"]),
            IdentityUpdate::Replace,
            None,
            0,
        );
        let first = table.generation();
        table.observe_identity(
            &key(0xAA),
            &repeater_identity("Ridge Two", &[]),
            IdentityUpdate::Replace,
            None,
            1_000,
        );
        assert_eq!(table.len(), 1);
        assert_ne!(table.generation(), first);
        let record = table.iter().next().unwrap();
        assert_eq!(record.name.as_deref(), Some("Ridge Two"));
        assert!(
            record.regions.is_empty(),
            "the newest account is the whole account"
        );
    }

    #[test]
    fn a_full_table_drops_the_identity_heard_longest_ago() {
        let mut table = PeerRepeaterTable::new();
        for seed in 0..MAX_PEER_REPEATERS as u8 {
            table.observe_identity(
                &key(seed),
                &repeater_identity("Peer", &[]),
                IdentityUpdate::Replace,
                None,
                1_000 + u64::from(seed),
            );
        }
        table.observe_identity(
            &key(200),
            &repeater_identity("Newcomer", &[]),
            IdentityUpdate::Replace,
            None,
            9_000,
        );
        assert_eq!(table.len(), MAX_PEER_REPEATERS);
        assert!(table.iter().any(|entry| entry.hint == key(200).hint()));
        assert!(
            !table.iter().any(|entry| entry.hint == key(0).hint()),
            "the oldest identity is the one that left"
        );
    }

    #[test]
    fn last_heard_saturates_rather_than_wrapping() {
        assert_eq!(minutes_since(Some(0), 60_000 * 65_535), Some(u16::MAX));
        assert_eq!(minutes_since(Some(0), 60_000 * 100_000), Some(u16::MAX));
        assert_eq!(minutes_since(None, 1_000), None);
        // A clock that ran backwards reads as "just now", not as 45 days.
        assert_eq!(minutes_since(Some(5_000), 1_000), Some(0));
    }

    /// An identity that may only fill lists a repeater not yet known, and
    /// fills in what a listed one lacks without replacing what it has.
    #[test]
    fn a_filling_identity_adds_but_never_replaces() {
        let mut table = PeerRepeaterTable::new();
        assert!(table.observe_identity(
            &key(0xAA),
            &repeater_identity("Ridge", &[]),
            IdentityUpdate::Fill,
            None,
            1_000,
        ));
        let mut older = repeater_identity("Old Ridge", &["SJC"]);
        older.location = Some(NodeLocation::from_lat_lon(37.0, -122.0, 4));
        older.capabilities |= NodeCapabilities::MOBILE;
        table.observe_identity(
            &key(0xAA),
            &older,
            IdentityUpdate::Fill,
            Some((-70, Snr::from_decibels(3))),
            2_000,
        );

        let record = table.iter().next().unwrap();
        assert_eq!(record.name.as_deref(), Some("Ridge"));
        assert_eq!(record.location, older.location);
        assert_eq!(record.regions, [[0x78, 0x53]]);
        // The reception is current whatever the identity's age.
        assert_eq!(record.rssi_snr, Some((-70, Snr::from_decibels(3))));
        assert_eq!(record.last_identity_ms, 2_000);
        assert_eq!(record.rank, 4, "nor is the rank the older account's");

        table.observe_identity(&key(0xAA), &older, IdentityUpdate::Replace, None, 3_000);
        assert_eq!(table.iter().next().unwrap().rank, 1);
    }

    const HOUR_MS: u64 = 60 * 60 * 1000;

    /// A key whose node hint is `hint`, so that several can share a repeater
    /// hint.
    fn key_with_hint(hint: [u8; 3]) -> PublicKey {
        let mut key = [0x5A; 32];
        key[..3].copy_from_slice(&hint);
        PublicKey(key)
    }

    fn mobile_identity(name: &str) -> NodeIdentityPayload {
        let mut identity = repeater_identity(name, &[]);
        identity.capabilities |= NodeCapabilities::MOBILE;
        identity
    }

    fn add(
        table: &mut PeerRepeaterTable,
        first: u8,
        identity: &NodeIdentityPayload,
        at_ms: u64,
    ) -> bool {
        table.observe_identity(
            &key_with_hint([first, 0, 0]),
            identity,
            IdentityUpdate::Replace,
            None,
            at_ms,
        )
    }

    fn listed(table: &PeerRepeaterTable, first: u8) -> bool {
        table.iter().any(|entry| entry.hint.0 == [first, 0, 0])
    }

    #[test]
    fn a_forward_is_credited_to_the_entries_it_could_name() {
        let mut table = PeerRepeaterTable::new();
        for hint in [[1, 2, 3], [1, 2, 4], [7, 7, 7]] {
            table.observe_identity(
                &key_with_hint(hint),
                &repeater_identity("Peer", &[]),
                IdentityUpdate::Replace,
                None,
                0,
            );
        }
        let shared = RepeaterHint([1, 2]);
        assert_eq!(table.credited(shared, HOUR_MS), 0b011, "both recent");
        assert_eq!(
            table.credited(shared, 9 * HOUR_MS),
            0,
            "both too old to tell apart"
        );
        assert_eq!(
            table.credited(RepeaterHint([7, 7]), 100 * HOUR_MS),
            0b100,
            "the only one it could name, however old"
        );
        assert_eq!(table.credited(RepeaterHint([9, 9]), HOUR_MS), 0);

        // A fresh advertisement takes the forward from an old one.
        table.observe_identity(
            &key_with_hint([1, 2, 4]),
            &repeater_identity("Peer", &[]),
            IdentityUpdate::Replace,
            None,
            9 * HOUR_MS,
        );
        assert_eq!(table.credited(shared, 10 * HOUR_MS), 0b010);
    }

    /// Freshness and the listing credit a forward alike: to the entries it
    /// could name, or, failing them, to an entry of its own.
    #[test]
    fn a_forward_freshens_and_merges_into_only_the_entries_credited_with_it() {
        let mut table = PeerRepeaterTable::new();
        for hint in [[1, 2, 3], [1, 2, 4]] {
            table.observe_identity(
                &key_with_hint(hint),
                &repeater_identity("Peer", &[]),
                IdentityUpdate::Replace,
                None,
                0,
            );
        }
        let generation = table.generation();

        let unattributed = observation(RepeaterHint([1, 2]), 9 * HOUR_MS);
        table.credit_forwarding(&unattributed);
        assert!(table.iter().all(|entry| entry.last_heard_ms == 0));
        let merged = merge(table.clone(), [unattributed].iter(), 9 * HOUR_MS);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].hint, [1, 2], "listed under its repeater hint");

        let attributed = observation(RepeaterHint([1, 2]), HOUR_MS);
        table.credit_forwarding(&attributed);
        assert!(table.iter().all(|entry| entry.last_heard_ms == HOUR_MS));
        let merged = merge(table.clone(), [attributed].iter(), 2 * HOUR_MS);
        assert_eq!(merged.len(), 2, "both entries claimed it");
        assert!(merged.iter().all(|entry| entry.last_heard_min == Some(60)));
        assert!(merged.iter().all(|entry| entry.rssi_dbm == Some(-95)));

        assert_eq!(table.generation(), generation, "being heard is no change");
    }

    #[test]
    fn a_frame_heard_off_its_sender_freshens_only_its_own_entry() {
        let mut table = PeerRepeaterTable::new();
        add(&mut table, 1, &repeater_identity("Ridge", &[]), 0);
        add(&mut table, 2, &repeater_identity("Saddle", &[]), 0);
        let generation = table.generation();

        let reading = Some((-70, Snr::from_decibels(5)));
        table.note_heard(key_with_hint([1, 0, 0]).hint(), reading, HOUR_MS);
        table.note_heard(key_with_hint([9, 0, 0]).hint(), None, HOUR_MS);
        let heard: Vec<_> = table
            .iter()
            .map(|entry| (entry.last_heard_ms, entry.rssi_snr))
            .collect();
        assert_eq!(heard, [(HOUR_MS, reading), (0, None)]);
        assert_eq!(table.generation(), generation);
    }

    #[test]
    fn rank_puts_mobile_below_role_only_below_capability_only_below_both() {
        let identity = |role, capabilities| NodeIdentityPayload {
            role,
            capabilities,
            ..repeater_identity("Peer", &[])
        };
        let both = NodeCapabilities::REPEATER;
        let ranks = [
            identity(NodeRole::Repeater, both | NodeCapabilities::MOBILE),
            identity(NodeRole::Bridge, NodeCapabilities::empty()),
            identity(NodeRole::Chat, both),
            identity(NodeRole::Bridge, both),
        ]
        .map(|identity| rank(&identity));
        assert_eq!(ranks, [1, 2, 3, 4]);
    }

    #[test]
    fn a_full_table_gives_way_by_standing_then_by_age() {
        let mut table = PeerRepeaterTable::new();
        // A fixed repeater gone quiet, a mobile node heard since the rest,
        // and fixed repeaters.
        add(&mut table, 0, &repeater_identity("Quiet", &[]), 0);
        for first in 2..MAX_PEER_REPEATERS as u8 {
            add(
                &mut table,
                first,
                &repeater_identity("Fixed", &[]),
                2 * HOUR_MS + u64::from(first),
            );
        }
        add(
            &mut table,
            1,
            &mobile_identity("Passing"),
            2 * HOUR_MS + 1_000,
        );
        let now = 3 * HOUR_MS;

        assert!(add(&mut table, 100, &repeater_identity("New", &[]), now));
        assert!(!listed(&table, 0), "the stale entry goes first");
        assert!(add(&mut table, 101, &repeater_identity("New", &[]), now));
        assert!(!listed(&table, 1), "then the mobile one, however recent");
        assert!(add(&mut table, 102, &repeater_identity("New", &[]), now));
        assert!(!listed(&table, 2), "then the least recently heard");
        assert_eq!(table.len(), MAX_PEER_REPEATERS);
    }

    #[test]
    fn a_newcomer_never_displaces_an_entry_that_outranks_it() {
        let mut table = PeerRepeaterTable::new();
        for first in 0..MAX_PEER_REPEATERS as u8 {
            add(
                &mut table,
                first,
                &repeater_identity("Fixed", &[]),
                u64::from(first),
            );
        }
        let generation = table.generation();
        assert!(!add(&mut table, 200, &mobile_identity("Passing"), 1_000));
        assert!(!listed(&table, 200));
        assert_eq!(table.generation(), generation);

        // An entry that has since turned mobile is one a mobile newcomer may
        // take, though it was heard after the rest.
        add(&mut table, 5, &mobile_identity("Peer"), 1_000);
        assert!(add(&mut table, 200, &mobile_identity("Passing"), 2_000));
        assert!(!listed(&table, 5));
        assert!(listed(&table, 0));
    }

    #[test]
    fn being_heard_keeps_an_entry_from_giving_way() {
        let mut table = PeerRepeaterTable::new();
        for first in 0..MAX_PEER_REPEATERS as u8 {
            add(
                &mut table,
                first,
                &repeater_identity("Fixed", &[]),
                u64::from(first),
            );
        }
        // Neither has advertised since: one is heard forwarding, the other
        // off its own transmitter.
        table.credit_forwarding(&observation(RepeaterHint([0, 0]), 2 * HOUR_MS));
        table.note_heard(key_with_hint([1, 0, 0]).hint(), None, 2 * HOUR_MS);

        assert!(add(
            &mut table,
            200,
            &repeater_identity("New", &[]),
            3 * HOUR_MS
        ));
        assert!(listed(&table, 0) && listed(&table, 1));
        assert!(!listed(&table, 2));
    }

    #[test]
    fn an_entry_goes_a_week_after_its_identity_whatever_else_was_heard() {
        let mut table = PeerRepeaterTable::new();
        add(&mut table, 0, &repeater_identity("Ridge", &[]), 0);
        table.note_heard(
            key_with_hint([0, 0, 0]).hint(),
            None,
            IDENTITY_LIFETIME_MS - 1,
        );
        let generation = table.generation();
        table.expire(IDENTITY_LIFETIME_MS - 1);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.generation(),
            generation,
            "expiring nothing is no change"
        );
        table.expire(IDENTITY_LIFETIME_MS);
        assert!(table.is_empty());
        assert_ne!(table.generation(), generation);

        // Expiry also makes room an outranked newcomer could not take.
        add(&mut table, 0, &repeater_identity("Ridge", &[]), 0);
        for first in 1..MAX_PEER_REPEATERS as u8 {
            add(
                &mut table,
                first,
                &repeater_identity("Fixed", &[]),
                IDENTITY_LIFETIME_MS - 1,
            );
        }
        table.note_heard(
            key_with_hint([0, 0, 0]).hint(),
            None,
            IDENTITY_LIFETIME_MS - 1,
        );
        assert!(add(
            &mut table,
            200,
            &mobile_identity("Passing"),
            IDENTITY_LIFETIME_MS
        ));
        assert!(!listed(&table, 0));
    }

    /// Only the node's current account can withdraw it.
    #[test]
    fn a_filling_identity_never_withdraws_a_repeater() {
        let mut table = PeerRepeaterTable::new();
        table.observe_identity(
            &key(1),
            &repeater_identity("Ridge", &[]),
            IdentityUpdate::Replace,
            None,
            0,
        );
        let mut retired = repeater_identity("Ridge", &[]);
        retired.role = NodeRole::Chat;
        retired.capabilities = NodeCapabilities::empty();
        assert!(!table.observe_identity(&key(1), &retired, IdentityUpdate::Fill, None, 1_000));
        assert_eq!(table.len(), 1);
        assert!(table.observe_identity(&key(1), &retired, IdentityUpdate::Replace, None, 2_000));
        assert!(table.is_empty());
    }
}
