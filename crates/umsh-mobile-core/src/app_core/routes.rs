//! Routes and manual paths: what the session knows of the way to a peer,
//! holding a path the user chose, and offering the learned one in its place
//! once it has proved itself.

use std::rc::Rc;

use super::mapping::router_hint_text;
use super::settings::MobilePositionRecord;
use super::worker::Worker;
use super::{MobileAppCore, MobileAppError, mesh_error};
use crate::RouterHintRecord;
use crate::mobile_mesh::{MobileMeshExplicitPath, MobileMeshRouteKind, MobileMeshRouteRecord};
use crate::store::MobileStoredManualRouteRecord;

/// A fix no vaguer than this, in meters, can say the phone moved.
const USABLE_ACCURACY_METERS: f64 = 100.0;

/// How far the phone must have gone from where a path was set for one
/// acknowledgement by flood to make the learned path worth offering.
const MOVED_METERS: f64 = 200.0;

/// The mean Earth radius, in meters.
const EARTH_RADIUS_METERS: f64 = 6_371_008.8;

/// The way to a peer, as the session knows it now.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppRouteRecord {
    pub kind: MobileMeshRouteKind,
    /// The path's router hints, rendered. A hint that does not render is
    /// left out.
    pub hints: Vec<RouterHintRecord>,
    pub hop_count: Option<u8>,
    pub flood_hops: Option<u8>,
    pub flood_regions: Vec<Vec<u8>>,
    /// How long a held path is held for yet; `None` when nothing is held.
    pub hold_remaining_ms: Option<u64>,
    pub hold_flood_hops: Option<u8>,
    /// Acknowledgements that came back by flood while a path was held.
    pub fallback_acks: u8,
    /// How long ago the route was last acknowledged.
    pub confirmed_age_ms: Option<u64>,
    /// The route the session learned while a path was held.
    pub candidate: Option<MobileAppRouteCandidateRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppRouteCandidateRecord {
    pub kind: MobileMeshRouteKind,
    pub hints: Vec<RouterHintRecord>,
    pub hop_count: Option<u8>,
}

/// Whether to offer the learned path in place of a held one.
#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum MobileAppLearnedPathOffer {
    None,
    Offer {
        route: MobileAppRouteRecord,
    },
    /// Ask again with the phone's position: whether it moved decides.
    NeedsPosition,
}

/// The phone's position, for a second `learned_path_offer`.
#[derive(Clone, Copy, Debug, PartialEq, uniffi::Enum)]
pub enum MobileAppPositionReading {
    Found {
        position: MobilePositionRecord,
    },
    /// No fix could be had.
    Unavailable,
}

impl MobileAppRouteRecord {
    fn rendered(route: MobileMeshRouteRecord) -> Self {
        let candidate = route
            .candidate_kind
            .map(|kind| MobileAppRouteCandidateRecord {
                kind,
                hints: rendered_hints(&route.candidate_hints),
                hop_count: route.candidate_hop_count,
            });
        Self {
            kind: route.kind,
            hints: rendered_hints(&route.hints),
            hop_count: route.hop_count,
            flood_hops: route.flood_hops,
            flood_regions: route.flood_regions,
            hold_remaining_ms: route.hold_remaining_ms,
            hold_flood_hops: route.hold_flood_hops,
            fallback_acks: route.fallback_acks,
            confirmed_age_ms: route.confirmed_age_ms,
            candidate,
        }
    }
}

pub(super) fn rendered_hints(hints: &[Vec<u8>]) -> Vec<RouterHintRecord> {
    hints
        .iter()
        .filter_map(|bytes| {
            let text = router_hint_text(bytes);
            if text.is_none() {
                log::warn!("a route's router hint does not render");
            }
            Some(RouterHintRecord {
                bytes: bytes.clone(),
                text: text?,
            })
        })
        .collect()
}

/// The great-circle distance between two points, in meters (haversine).
pub(super) fn distance_meters(from: (f64, f64), to: (f64, f64)) -> f64 {
    let (latitude_a, longitude_a) = (from.0.to_radians(), from.1.to_radians());
    let (latitude_b, longitude_b) = (to.0.to_radians(), to.1.to_radians());
    let half_latitude = ((latitude_b - latitude_a) / 2.0).sin();
    let half_longitude = ((longitude_b - longitude_a) / 2.0).sin();
    let a = half_latitude * half_latitude
        + latitude_a.cos() * latitude_b.cos() * half_longitude * half_longitude;
    2.0 * EARTH_RADIUS_METERS * a.sqrt().min(1.0).asin()
}

fn usable(accuracy: f64) -> bool {
    (0.0..=USABLE_ACCURACY_METERS).contains(&accuracy)
}

/// Where the path was set, when that fix is good enough to tell a move by.
fn saved_fix(record: &MobileStoredManualRouteRecord) -> Option<(f64, f64)> {
    let accuracy = record.saved_accuracy?;
    usable(accuracy).then_some((record.saved_latitude?, record.saved_longitude?))
}

/// Whether the phone moved from where the path was set.
pub(super) fn has_moved(
    record: &MobileStoredManualRouteRecord,
    position: &MobilePositionRecord,
) -> bool {
    let Some(saved) = saved_fix(record) else {
        return false;
    };
    position.accuracy_meters.is_some_and(usable)
        && distance_meters(
            saved,
            (position.latitude_degrees, position.longitude_degrees),
        ) >= MOVED_METERS
}

/// The offer rule. Two acknowledgements by flood offer the learned path;
/// one does once the phone has moved from where the path was set.
pub(super) fn learned_path_decision(
    record: &MobileStoredManualRouteRecord,
    route: MobileAppRouteRecord,
    position: Option<MobileAppPositionReading>,
) -> MobileAppLearnedPathOffer {
    if record.prompt_settled
        || route.hold_remaining_ms.is_none()
        || route.candidate.is_none()
        || route.fallback_acks == 0
    {
        return MobileAppLearnedPathOffer::None;
    }
    if route.fallback_acks >= 2 {
        return MobileAppLearnedPathOffer::Offer { route };
    }
    // One: the phone's move decides, which only a saved fix can tell.
    if saved_fix(record).is_none() {
        return MobileAppLearnedPathOffer::None;
    }
    match position {
        None => MobileAppLearnedPathOffer::NeedsPosition,
        Some(MobileAppPositionReading::Found { position }) if has_moved(record, &position) => {
            MobileAppLearnedPathOffer::Offer { route }
        }
        Some(_) => MobileAppLearnedPathOffer::None,
    }
}

impl Worker {
    async fn route_to(&self, address: &str) -> Result<MobileAppRouteRecord, MobileAppError> {
        let session = self.session().ok_or(MobileAppError::NotRunning)?;
        let route = session
            .peer_route(address.to_owned())
            .await
            .map_err(mesh_error)?;
        Ok(MobileAppRouteRecord::rendered(route))
    }

    async fn set_manual_path(
        &self,
        address: String,
        path: MobileMeshExplicitPath,
        hold_ms: u64,
        position: Option<MobilePositionRecord>,
    ) -> Result<bool, MobileAppError> {
        let session = self.session().ok_or(MobileAppError::NotRunning)?;
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        let hold_until_ms = self
            .clock
            .now_ms()
            .saturating_add(i64::try_from(hold_ms).unwrap_or(i64::MAX));
        let held = session
            .hold_peer_route(address.clone(), path.clone(), hold_ms)
            .await
            .map_err(mesh_error)?;
        if !held {
            return Ok(false);
        }
        self.store.save_manual_route(
            owner,
            address,
            path.hints,
            path.flood_hops,
            hold_until_ms,
            position.map(|position| position.latitude_degrees),
            position.map(|position| position.longitude_degrees),
            position.and_then(|position| position.accuracy_meters),
        )?;
        Ok(true)
    }

    async fn clear_manual_path(&self, address: String) -> Result<bool, MobileAppError> {
        let session = self.session().ok_or(MobileAppError::NotRunning)?;
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        self.store.clear_manual_route(owner, address.clone())?;
        session.clear_peer_route(address).await.map_err(mesh_error)
    }

    async fn adopt_learned_path(&self, address: String) -> Result<bool, MobileAppError> {
        let session = self.session().ok_or(MobileAppError::NotRunning)?;
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        let adopted = session
            .adopt_learned_peer_route(address.clone())
            .await
            .map_err(mesh_error)?;
        if adopted {
            self.store.clear_manual_route(owner, address)?;
        }
        Ok(adopted)
    }

    async fn learned_path_offer(
        &self,
        address: String,
        position: Option<MobileAppPositionReading>,
    ) -> Result<MobileAppLearnedPathOffer, MobileAppError> {
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        let Some(record) = self
            .store
            .manual_route(owner, address.clone(), self.clock.now_ms())?
        else {
            return Ok(MobileAppLearnedPathOffer::None);
        };
        if record.prompt_settled {
            return Ok(MobileAppLearnedPathOffer::None);
        }
        let route = self.route_to(&address).await?;
        Ok(learned_path_decision(&record, route, position))
    }
}

/// Checks an address before the session sees it, so a bad one reads as
/// bad input rather than as whatever the session makes of it.
pub(super) fn checked_address(address: &str) -> Result<(), MobileAppError> {
    crate::public_identity_bytes(address.to_owned())
        .map(|_| ())
        .map_err(|error| MobileAppError::InvalidInput { error })
}

/// Checks a conversation's address: a peer's, or a channel conversation's
/// (`ch:` and 32 hex digits).
pub(super) fn checked_conversation_address(address: &str) -> Result<(), MobileAppError> {
    if address.starts_with(super::bootstrap::CHANNEL_ADDRESS_PREFIX) {
        return crate::mobile_chat::parse_channel_address(address)
            .map(|_| ())
            .ok_or(MobileAppError::InvalidInput {
                error: crate::MobileError::InvalidAddressCharacter,
            });
    }
    checked_address(address)
}

#[uniffi::export]
impl MobileAppCore {
    /// The way to a peer, as the session knows it now.
    pub async fn peer_route(
        &self,
        address: String,
    ) -> Result<MobileAppRouteRecord, MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move { worker.route_to(&address).await })
            .await
    }

    /// Forget the route to a peer, and end any hold. Whether one was held.
    pub async fn clear_route(&self, address: String) -> Result<bool, MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move {
            let session = worker.session().ok_or(MobileAppError::NotRunning)?;
            session.clear_peer_route(address).await.map_err(mesh_error)
        })
        .await
    }

    /// Hold `path` to a peer for `hold_ms`, and keep it across launches
    /// with where the phone was, when `position` says. False when the
    /// session would not hold it.
    pub async fn set_manual_path(
        &self,
        address: String,
        path: MobileMeshExplicitPath,
        hold_ms: u64,
        position: Option<MobilePositionRecord>,
    ) -> Result<bool, MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move {
            worker
                .set_manual_path(address, path, hold_ms, position)
                .await
        })
        .await
    }

    /// End a manual path's hold and forget the route it set.
    pub async fn clear_manual_path(&self, address: String) -> Result<bool, MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move { worker.clear_manual_path(address).await })
            .await
    }

    /// Replace a held path with the one the session learned. False when
    /// nothing was held or learned.
    pub async fn adopt_learned_path(&self, address: String) -> Result<bool, MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move { worker.adopt_learned_path(address).await })
            .await
    }

    /// Keep the held path, and stop offering the learned one for it.
    pub async fn keep_manual_path(&self, address: String) -> Result<(), MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move {
            let owner = worker.owner().ok_or(MobileAppError::NoOwner)?;
            Ok(worker.store.settle_manual_route_prompt(owner, address)?)
        })
        .await
    }

    /// Whether to offer the learned path in place of the held one. Called
    /// without a position first; `NeedsPosition` asks for a second call
    /// that says whether a fix was found, which never asks again.
    pub async fn learned_path_offer(
        &self,
        address: String,
        position: Option<MobileAppPositionReading>,
    ) -> Result<MobileAppLearnedPathOffer, MobileAppError> {
        checked_address(&address)?;
        self.command(
            move |worker| async move { worker.learned_path_offer(address, position).await },
        )
        .await
    }
}

impl MobileAppCore {
    /// Run a command on the worker, counted as in flight while it runs.
    pub(super) async fn command<T, F, Fut>(&self, work: F) -> Result<T, MobileAppError>
    where
        T: Send + 'static,
        F: FnOnce(Rc<Worker>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T, MobileAppError>> + 'static,
    {
        self.on_worker(move |worker| async move {
            let _command = worker.begin_command().await?;
            work(worker).await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(accuracy: Option<f64>, settled: bool) -> MobileStoredManualRouteRecord {
        MobileStoredManualRouteRecord {
            public_address: String::new(),
            hints: Vec::new(),
            flood_hops: 1,
            hold_until_ms: 0,
            saved_latitude: Some(44.0),
            saved_longitude: Some(-123.0),
            saved_accuracy: accuracy,
            prompt_settled: settled,
        }
    }

    fn at(latitude: f64, accuracy: f64) -> MobilePositionRecord {
        MobilePositionRecord {
            latitude_degrees: latitude,
            longitude_degrees: -123.0,
            accuracy_meters: Some(accuracy),
        }
    }

    /// About 222 m north of the saved fix, and about 111 m.
    const FAR: f64 = 44.002;
    const NEAR: f64 = 44.001;

    fn route(acks: u8, candidate: bool) -> MobileAppRouteRecord {
        MobileAppRouteRecord {
            kind: MobileMeshRouteKind::Source,
            hints: Vec::new(),
            hop_count: Some(2),
            flood_hops: None,
            flood_regions: Vec::new(),
            hold_remaining_ms: Some(60_000),
            hold_flood_hops: None,
            fallback_acks: acks,
            confirmed_age_ms: None,
            candidate: candidate.then(|| MobileAppRouteCandidateRecord {
                kind: MobileMeshRouteKind::Source,
                hints: Vec::new(),
                hop_count: Some(1),
            }),
        }
    }

    fn offers(
        record: &MobileStoredManualRouteRecord,
        route: MobileAppRouteRecord,
        position: Option<MobileAppPositionReading>,
    ) -> bool {
        matches!(
            learned_path_decision(record, route, position),
            MobileAppLearnedPathOffer::Offer { .. }
        )
    }

    fn found(position: MobilePositionRecord) -> Option<MobileAppPositionReading> {
        Some(MobileAppPositionReading::Found { position })
    }

    #[test]
    fn the_distance_is_great_circle() {
        let degree = distance_meters((44.0, -123.0), (45.0, -123.0));
        assert!((degree - 111_195.0).abs() < 10.0, "{degree}");
        assert_eq!(distance_meters((44.0, -123.0), (44.0, -123.0)), 0.0);
    }

    #[test]
    fn moving_two_hundred_meters_counts() {
        assert!(has_moved(&record(Some(10.0), false), &at(FAR, 10.0)));
        assert!(!has_moved(&record(Some(10.0), false), &at(NEAR, 10.0)));
    }

    #[test]
    fn vague_or_missing_fixes_never_count_as_moving() {
        assert!(!has_moved(&record(Some(10.0), false), &at(FAR, 150.0)));
        assert!(!has_moved(&record(Some(150.0), false), &at(FAR, 10.0)));
        assert!(!has_moved(&record(None, false), &at(FAR, 10.0)));
        let no_accuracy = MobilePositionRecord {
            accuracy_meters: None,
            ..at(FAR, 10.0)
        };
        assert!(!has_moved(&record(Some(10.0), false), &no_accuracy));
    }

    #[test]
    fn an_offer_needs_two_flooded_acks_or_one_after_moving() {
        let saved = record(Some(10.0), false);
        assert!(!offers(&saved, route(1, true), found(at(NEAR, 10.0))));
        assert!(offers(&saved, route(1, true), found(at(FAR, 10.0))));
        assert!(offers(&saved, route(2, true), None));
        assert!(!offers(&saved, route(0, true), found(at(FAR, 10.0))));
        assert!(!offers(&saved, route(3, false), found(at(FAR, 10.0))));
        assert!(!offers(&record(Some(10.0), true), route(3, true), None));
    }

    #[test]
    fn a_position_is_asked_for_only_when_a_saved_fix_can_use_it() {
        let saved = record(Some(10.0), false);
        assert_eq!(
            learned_path_decision(&saved, route(1, true), None),
            MobileAppLearnedPathOffer::NeedsPosition
        );
        // The second call never asks again.
        assert_eq!(
            learned_path_decision(
                &saved,
                route(1, true),
                Some(MobileAppPositionReading::Unavailable)
            ),
            MobileAppLearnedPathOffer::None
        );
        assert_eq!(
            learned_path_decision(&record(None, false), route(1, true), None),
            MobileAppLearnedPathOffer::None
        );
    }
}
