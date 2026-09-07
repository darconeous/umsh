//! The repeaters a node has heard directly, and how it answers a
//! [Peer Repeaters Request](../../docs/protocol/src/mac-commands.md).
//!
//! The list is a neighborhood: repeaters heard off their own transmitters.
//! Two sources feed it, because neither is enough on its own:
//!
//! - **Identities.** A repeater that advertises tells its neighbors its name,
//!   its position, and the regions it forwards for. None of that can be
//!   recovered from a hint. Only an identity heard directly counts—one that
//!   arrived forwarded says nothing about whether its owner is in range.
//! - **Transmitter observations** ([`umsh_mac::TransmitterObservations`]).
//!   A repeater prepends its router hint to the trace route of every frame
//!   it forwards, so every traced frame off the air proves which repeater
//!   just transmitted it and how well it was heard—including repeaters that
//!   never send this node anything of their own.
//!
//! A [`RouterHint`] is the first two bytes of a public key and a [`NodeHint`]
//! the first three, so the observation's key is a prefix of the identity's.
//! That is what lets the two merge: an identity claims the observation whose
//! hint it starts with, and an observation nothing claims becomes an entry
//! naming a hop by its router hint and reporting only what was heard.

use alloc::string::String;
use alloc::vec::Vec;

use umsh_core::{NodeHint, PublicKey, RouterHint};
use umsh_hal::Snr;

use crate::identity::{NodeCapabilities, NodeIdentityPayload, NodeRole};
use crate::location::NodeLocation;

/// How many identity-bearing repeaters the table remembers.
///
/// Sized to the MAC's observation table: the two merge into one listing, and
/// a listing longer than the 1-byte Total the response reports would have to
/// be truncated anyway.
pub const MAX_PEER_REPEATERS: usize = 16;

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
    /// How well the identity was heard, when the radio measured it.
    pub rssi_snr: Option<(i16, Snr)>,
    /// When the identity arrived, on the monotonic clock.
    pub last_identity_ms: u64,
}

impl PeerRepeaterRecord {
    /// The router hint an observation would be keyed by—the first two
    /// bytes of the same public key.
    pub fn router_hint(&self) -> RouterHint {
        RouterHint([self.hint.0[0], self.hint.0[1]])
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

    /// Whether an identity describes a repeater, and so belongs here.
    ///
    /// The capability is the claim that matters—a node may forward while
    /// presenting itself as something else—but a node whose whole role is
    /// repeating counts even if it advertises no capability bitmap.
    pub fn is_repeater(identity: &NodeIdentityPayload) -> bool {
        identity.capabilities.contains(NodeCapabilities::REPEATER)
            || identity.role == NodeRole::Repeater
    }

    /// Record what an identity heard directly said, if it came from a
    /// repeater.
    ///
    /// The caller vouches that the identity came off its owner's own
    /// transmitter; `rssi_snr` is that reception's measurement, when the
    /// radio made one. Returns whether the table changed. A repeat identity
    /// replaces the record rather than merging with it: the newest
    /// advertisement is the node's own account of itself.
    pub fn observe_identity(
        &mut self,
        from: &PublicKey,
        identity: &NodeIdentityPayload,
        rssi_snr: Option<(i16, Snr)>,
        now_ms: u64,
    ) -> bool {
        if !Self::is_repeater(identity) {
            return false;
        }
        let record = PeerRepeaterRecord {
            hint: from.hint(),
            name: identity.name.clone(),
            location: identity.location,
            regions: region_codes(identity),
            rssi_snr,
            last_identity_ms: now_ms,
        };
        self.generation = self.generation.wrapping_add(1);
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|entry| entry.hint == record.hint)
        {
            *existing = record;
            return true;
        }
        if self.records.len() < MAX_PEER_REPEATERS {
            self.records.push(record);
            return true;
        }
        // Full: the identity heard longest ago is the one whose absence says
        // the least.
        let Some(oldest) = self
            .records
            .iter_mut()
            .min_by_key(|entry| entry.last_identity_ms)
        else {
            return false;
        };
        *oldest = record;
        true
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
/// An identity claims the observation whose router hint it starts with; each
/// remaining observation becomes a two-byte-hint entry. Both sources are
/// direct receptions, so whichever heard the peer more recently supplies the
/// signal figures.
///
/// The listing is ordered most recently heard first. The first page is the
/// one a requester is surest to read, and the neighbors on the air right
/// now are the ones it is asking about.
pub fn merge<'a>(
    identities: &PeerRepeaterTable,
    observations: impl IntoIterator<Item = &'a umsh_mac::TransmitterObservation>,
    now_ms: u64,
) -> Vec<MergedPeerRepeater> {
    let observations: Vec<&umsh_mac::TransmitterObservation> = observations.into_iter().collect();
    // Each entry alongside the monotonic time it was last heard, which orders
    // the list more finely than the wire's whole minutes can.
    let mut merged: Vec<(u64, MergedPeerRepeater)> = Vec::new();
    let mut claimed: Vec<RouterHint> = Vec::new();

    for record in identities.iter() {
        let router_hint = record.router_hint();
        let observation = observations
            .iter()
            .find(|entry| entry.hint == router_hint)
            .copied();
        if observation.is_some() {
            claimed.push(router_hint);
        }
        let rssi_snr = match observation {
            Some(entry) if entry.last_seen_ms >= record.last_identity_ms => {
                Some((entry.rssi_dbm, entry.snr))
            }
            Some(entry) => record.rssi_snr.or(Some((entry.rssi_dbm, entry.snr))),
            None => record.rssi_snr,
        };
        let last_heard_ms = observation
            .map(|entry| entry.last_seen_ms.max(record.last_identity_ms))
            .unwrap_or(record.last_identity_ms);
        merged.push((
            last_heard_ms,
            MergedPeerRepeater {
                hint: Vec::from(&record.hint.0[..]),
                name: record.name.clone(),
                location: record.location,
                regions: record.regions.clone(),
                rssi_dbm: rssi_snr.map(|(rssi, _)| rssi),
                snr: rssi_snr.map(|(_, snr)| snr),
                last_heard_min: minutes_since(Some(last_heard_ms), now_ms),
            },
        ));
    }

    for observation in observations {
        if claimed.contains(&observation.hint) {
            continue;
        }
        merged.push((
            observation.last_seen_ms,
            MergedPeerRepeater {
                hint: Vec::from(&observation.hint.0[..]),
                name: None,
                location: None,
                regions: Vec::new(),
                rssi_dbm: Some(observation.rssi_dbm),
                snr: Some(observation.snr),
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

    fn observation(hint: RouterHint, last_seen_ms: u64) -> umsh_mac::TransmitterObservation {
        umsh_mac::TransmitterObservation {
            hint,
            rssi_dbm: -95,
            snr: Snr::from_decibels(2),
            last_seen_ms,
        }
    }

    #[test]
    fn only_repeaters_are_recorded() {
        let mut table = PeerRepeaterTable::new();
        let mut chat = repeater_identity("Handset", &[]);
        chat.role = NodeRole::Chat;
        chat.capabilities = NodeCapabilities::TEXT_MESSAGES;
        assert!(!table.observe_identity(&key(1), &chat, None, 0));
        assert!(table.is_empty());

        // The capability alone is enough—a node may forward while
        // presenting itself as something else.
        let mut forwarding_handset = chat.clone();
        forwarding_handset.capabilities |= NodeCapabilities::REPEATER;
        assert!(table.observe_identity(&key(1), &forwarding_handset, None, 0));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn an_identity_supplies_the_name_and_regions_an_observation_cannot() {
        let mut table = PeerRepeaterTable::new();
        table.observe_identity(
            &key(0xAA),
            &repeater_identity("Ridge", &["SJC"]),
            None,
            1_000,
        );

        let record = table.iter().next().unwrap();
        assert_eq!(record.name.as_deref(), Some("Ridge"));
        assert_eq!(record.regions, [[0x78, 0x53]]);
        assert_eq!(record.hint, key(0xAA).hint());
    }

    /// A router hint is a node hint's first two bytes, which is the whole
    /// reason the two tables can be joined at all.
    #[test]
    fn an_identity_claims_the_observation_whose_hint_it_starts_with() {
        let mut table = PeerRepeaterTable::new();
        table.observe_identity(
            &key(0xAA),
            &repeater_identity("Ridge", &["SJC"]),
            Some((-60, Snr::from_decibels(8))),
            60_000,
        );
        let hint = key(0xAA).hint();
        let observations = [
            observation(RouterHint([hint.0[0], hint.0[1]]), 120_000),
            observation(RouterHint([0x11, 0x22]), 60_000),
        ];

        let merged = merge(&table, observations.iter(), 180_000);
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
            Some((-60, Snr::from_decibels(8))),
            120_000,
        );
        let hint = key(0xAA).hint();

        let alone = merge(&table, [].iter(), 180_000);
        assert_eq!(alone.len(), 1);
        assert_eq!(alone[0].rssi_dbm, Some(-60));
        assert_eq!(alone[0].snr, Some(Snr::from_decibels(8)));
        assert_eq!(alone[0].last_heard_min, Some(1));

        let older = [observation(RouterHint([hint.0[0], hint.0[1]]), 60_000)];
        let merged = merge(&table, older.iter(), 180_000);
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
            None,
            10_000,
        );
        table.observe_identity(&key(0xBB), &repeater_identity("Recent", &[]), None, 200_000);
        table.observe_identity(&key(0xCC), &repeater_identity("Stale", &[]), None, 20_000);
        let refreshed = key(0xAA).hint();
        let observations = [
            observation(RouterHint([refreshed.0[0], refreshed.0[1]]), 300_000),
            // Never introduced, heard forwarding between the other two.
            observation(RouterHint([0x11, 0x22]), 100_000),
        ];

        let merged = merge(&table, observations.iter(), 400_000);
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
        table.observe_identity(&key(0xAA), &repeater_identity("Ridge", &[]), None, 120_000);
        let hint = key(0xAA).hint();

        let merged = merge(&table, [].iter(), 180_000);
        assert_eq!(merged[0].rssi_dbm, None);
        assert_eq!(merged[0].snr, None);

        let older = [observation(RouterHint([hint.0[0], hint.0[1]]), 60_000)];
        let merged = merge(&table, older.iter(), 180_000);
        assert_eq!(merged[0].rssi_dbm, Some(-95));
    }

    #[test]
    fn a_repeat_identity_replaces_the_record_and_moves_the_generation() {
        let mut table = PeerRepeaterTable::new();
        table.observe_identity(&key(0xAA), &repeater_identity("Ridge", &["SJC"]), None, 0);
        let first = table.generation();
        table.observe_identity(
            &key(0xAA),
            &repeater_identity("Ridge Two", &[]),
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
                None,
                1_000 + u64::from(seed),
            );
        }
        table.observe_identity(&key(200), &repeater_identity("Newcomer", &[]), None, 9_000);
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
}
