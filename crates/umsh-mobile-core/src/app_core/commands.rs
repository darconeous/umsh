//! The core's commands over the mesh: the advertised name, advertising,
//! pings, a repeater's neighbors, the in-person exchange, and asking
//! claimed radios again to let go of this phone.
//!
//! Adverts need only a session. Pings, repeater pages, the exchange and
//! revocation need the radio attached as this phone's.

use std::rc::Rc;
use std::sync::Arc;

use super::mapping::{self, PeerIndex};
use super::pipeline::carries_this_phone;
use super::policy::MANAGEMENT_BACKSTOP_MS;
use super::records::MobileAppRepeaterListingRecord;
use super::routes::{checked_address, rendered_hints};
use super::worker::Worker;
use super::{MobileAppCore, MobileAppError, mesh_error};
use crate::RouterHintRecord;
use crate::meet::MobileMeetExchange;
use crate::mobile_mesh::{
    MobileMeshExplicitPath, MobileMeshPeerRepeatersPageRecord, MobileMeshPingOutcome,
    MobileMeshSession, MobileTraceSignalRecord,
};
use crate::radio_driver::MobileRadioPhase;
use crate::store::{MobileStoredPeerRepeaterEntryRecord, MobileStoredPeerRepeaterListingRecord};
use crate::ulcp::UlcpHostOwnership;

/// How a ping ended.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileAppPingResult {
    Reply {
        reply: MobileAppPingReplyRecord,
    },
    TimedOut,
    /// A newer ping to the same peer replaced it.
    Canceled,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppPingReplyRecord {
    pub round_trip_ms: Option<u64>,
    pub hop_count: Option<u8>,
    /// The path the reply took, rendered. A hint that does not render is
    /// left out.
    pub route_hints: Vec<RouterHintRecord>,
    pub trace_signal: Vec<MobileTraceSignalRecord>,
    pub rssi_dbm: Option<i16>,
    pub snr_centibels: Option<i16>,
    pub lqi: Option<u8>,
    /// Only the ping's Route Retry was answered: the route it held failed.
    pub via_route_retry: bool,
}

impl Worker {
    /// The session, when the radio is attached as this phone's.
    pub(super) fn radio_session(&self) -> Result<Arc<MobileMeshSession>, MobileAppError> {
        let session = self.session().ok_or(MobileAppError::NotRunning)?;
        let snapshot = self.shared.snapshot();
        let radio = snapshot
            .radio
            .as_ref()
            .filter(|radio| radio.phase == MobileRadioPhase::Attached)
            .ok_or(MobileAppError::NoRadio)?;
        if radio.host != UlcpHostOwnership::Ours {
            return Err(MobileAppError::NotThisPhone);
        }
        Ok(session)
    }

    /// A peer answered: it was heard, as good a hearing as any.
    fn answered(&self, address: &str) {
        let Some(owner) = self.owner() else {
            return;
        };
        match self
            .store
            .touch_last_heard(owner, address.to_owned(), self.clock.now_ms())
        {
            Ok(fired_watch) => self.peers_changed(fired_watch.then(|| address.to_owned())),
            Err(error) => log::warn!(error:? = error; "an answer's hearing was not kept"),
        }
    }

    async fn set_advertised_name(&self, name: String) -> Result<(), MobileAppError> {
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        let trimmed = name.trim();
        let name = (!trimmed.is_empty()).then(|| trimmed.to_owned());
        self.store.update_local_advertised_name(owner, name)?;
        self.push_discoverability().await;
        Ok(())
    }

    async fn advertise_identity(&self) -> Result<(), MobileAppError> {
        let session = self.session().ok_or(MobileAppError::NotRunning)?;
        let timestamp = u32::try_from(self.clock.now_ms() / 1000).unwrap_or(u32::MAX);
        session
            .advertise_identity(self.advertised_name(), Some(timestamp))
            .await
            .map_err(mesh_error)
    }

    async fn ping(
        &self,
        address: String,
        path: Option<MobileMeshExplicitPath>,
    ) -> Result<MobileAppPingResult, MobileAppError> {
        let session = self.radio_session()?;
        let id = session.ping(address.clone(), path).map_err(mesh_error)?;
        let deadline = self.clock.monotonic_ms() + MANAGEMENT_BACKSTOP_MS;
        let event = self.await_ping(id, deadline).await?;
        match event.outcome {
            MobileMeshPingOutcome::Reply => {
                self.answered(&address);
                Ok(MobileAppPingResult::Reply {
                    reply: MobileAppPingReplyRecord {
                        round_trip_ms: event.round_trip_milliseconds,
                        hop_count: event.hop_count,
                        route_hints: rendered_hints(&event.route_hints),
                        trace_signal: event.trace_signal,
                        rssi_dbm: event.rssi_dbm,
                        snr_centibels: event.snr_centibels,
                        lqi: event.lqi,
                        via_route_retry: event.via_route_retry,
                    },
                })
            }
            MobileMeshPingOutcome::TimedOut => Ok(MobileAppPingResult::TimedOut),
            MobileMeshPingOutcome::Canceled => Ok(MobileAppPingResult::Canceled),
            MobileMeshPingOutcome::Failed => Err(MobileAppError::SendFailed),
        }
    }

    async fn request_peer_repeaters(
        &self,
        address: String,
        cursor: Option<Vec<u8>>,
        route: Vec<Vec<u8>>,
    ) -> Result<MobileAppRepeaterListingRecord, MobileAppError> {
        let session = self.radio_session()?;
        let replacing = cursor.is_none();
        let page = session
            .request_peer_repeaters_page(address.clone(), cursor, route)
            .await
            .map_err(mesh_error)?;
        let now_ms = self.clock.now_ms();
        let owner = self.owner().ok_or(MobileAppError::NoOwner)?;
        let entries = stored_entries(&page, now_ms);
        let saved = self.store.save_peer_repeater_page(
            owner.clone(),
            address.clone(),
            entries.clone(),
            page.total.map(i64::from),
            page.next_cursor.clone(),
            replacing,
            now_ms,
        );
        if let Err(error) = saved {
            log::warn!(error:? = error; "a repeater's page was not kept");
        }
        // After the save, so the flag it raises covers the page too.
        self.answered(&address);
        let peers = PeerIndex::of_nodes(self.store.list_nodes(owner.clone()).unwrap_or_default());
        // A repeater with no row has nowhere to keep its listing: the page
        // is the listing.
        let listing = self
            .store
            .peer_repeater_listing(owner, address)
            .ok()
            .flatten()
            .unwrap_or(MobileStoredPeerRepeaterListingRecord {
                entries,
                total: page.total.map(i64::from),
                next_cursor: page.next_cursor,
                as_of_ms: now_ms,
            });
        Ok(mapping::listing(listing, &peers))
    }

    /// Open the meet under a fresh key, when Add Peer wants it and the
    /// radio carries this phone.
    async fn reopen_meet(&self) -> Result<(), MobileAppError> {
        if !self.pipeline.borrow().meet_wanted
            || !carries_this_phone(self.shared.snapshot().radio.as_ref())
        {
            return Ok(());
        }
        let session = self.radio_session()?;
        session
            .open_meet(self.config.platform_model)
            .await
            .map_err(mesh_error)
    }

    fn meet_exchange(&self) -> Option<MobileMeetExchange> {
        self.pipeline
            .borrow()
            .meet
            .as_ref()
            .map(|meet| meet.exchange.clone())
    }

    async fn answer_exchange(&self, accept: bool) -> Result<(), MobileAppError> {
        if !matches!(self.meet_exchange(), Some(MobileMeetExchange::Asked { .. })) {
            return Ok(());
        }
        let session = self.radio_session()?;
        let answered = session.answer_exchange(accept).await.map_err(mesh_error);
        if accept {
            return answered;
        }
        // Declined: a fresh key whether or not the answer went out.
        if let Err(error) = answered {
            log::debug!(error:? = error; "the exchange was not declined");
        }
        self.reopen_meet().await
    }

    async fn back_out_of_exchange(&self) -> Result<(), MobileAppError> {
        let under_way = matches!(
            self.meet_exchange(),
            Some(
                MobileMeetExchange::Asking { .. }
                    | MobileMeetExchange::Accepted { .. }
                    | MobileMeetExchange::Comparing { .. }
                    | MobileMeetExchange::Ended { .. }
            )
        );
        if !under_way {
            return Ok(());
        }
        let session = self.session().ok_or(MobileAppError::NotRunning)?;
        // A fresh key whether or not the cancel went out.
        if let Err(error) = session.cancel_exchange().await {
            log::debug!(error:? = error; "the exchange was not cancelled");
        }
        self.reopen_meet().await
    }

    async fn retry_claimed_radio_revocation(&self) -> Result<(), MobileAppError> {
        self.radio_session()?;
        self.revoke_claimed_radios().await;
        Ok(())
    }
}

fn stored_entries(
    page: &MobileMeshPeerRepeatersPageRecord,
    now_ms: i64,
) -> Vec<MobileStoredPeerRepeaterEntryRecord> {
    page.entries
        .iter()
        .map(|entry| MobileStoredPeerRepeaterEntryRecord {
            hint: entry.hint.clone(),
            name: entry.name.clone(),
            rssi_dbm: entry.rssi_dbm,
            snr_quarter_db: entry.snr_quarter_db,
            last_heard_minutes: entry.last_heard_minutes,
            latitude: entry.latitude_degrees,
            longitude: entry.longitude_degrees,
            location_precision: entry.location_precision,
            region_codes: entry.region_codes.clone(),
            reported_at_ms: now_ms,
        })
        .collect()
}

#[uniffi::export]
impl MobileAppCore {
    /// Keep the name this phone advertises, trimmed; empty clears it. The
    /// session answers with it from then on.
    pub async fn set_advertised_name(&self, name: String) -> Result<(), MobileAppError> {
        self.command(move |worker| async move { worker.set_advertised_name(name).await })
            .await
    }

    /// Broadcast this phone's identity now. Succeeds once queued, whether
    /// or not a radio carries it yet.
    pub async fn advertise_identity(&self) -> Result<(), MobileAppError> {
        self.command(|worker| async move { worker.advertise_identity().await })
            .await
    }

    /// Ping a peer, by the session's route or down `path`, which is not
    /// installed.
    pub async fn ping(
        &self,
        address: String,
        path: Option<MobileMeshExplicitPath>,
    ) -> Result<MobileAppPingResult, MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move { worker.ping(address, path).await })
            .await
    }

    /// Ask a repeater for a page of the neighbors it hears: the first with
    /// no `cursor`, which replaces what was kept. `route` is the path to
    /// it, or empty for the session's own. Answers with the listing kept.
    pub async fn request_peer_repeaters(
        &self,
        address: String,
        cursor: Option<Vec<u8>>,
        route: Vec<Vec<u8>>,
    ) -> Result<MobileAppRepeaterListingRecord, MobileAppError> {
        checked_address(&address)?;
        self.command(move |worker| async move {
            worker.request_peer_repeaters(address, cursor, route).await
        })
        .await
    }

    /// Whether Add Peer wants the meet open. It opens while the radio
    /// carries this phone, and closes otherwise.
    pub async fn set_meet_wanted(&self, wanted: bool) -> Result<(), MobileAppError> {
        self.on_worker(move |worker: Rc<Worker>| async move {
            if worker.pipeline.borrow().meet_wanted != wanted {
                worker.pipeline.borrow_mut().meet_wanted = wanted;
                worker.settle_meet();
            }
            Ok(())
        })
        .await
    }

    /// Ask a nearby device to exchange. Whether the ask went out.
    pub async fn ask_to_exchange(&self, device: u32) -> Result<bool, MobileAppError> {
        self.command(move |worker| async move {
            let session = worker.radio_session()?;
            session.ask_to_exchange(device).await.map_err(mesh_error)
        })
        .await
    }

    /// Answer the device that asked. Declining opens the meet again under
    /// a fresh key. Does nothing unless a device is asking.
    pub async fn answer_exchange(&self, accept: bool) -> Result<(), MobileAppError> {
        self.command(move |worker| async move { worker.answer_exchange(accept).await })
            .await
    }

    /// Whether both screens show the same code.
    pub async fn confirm_code(&self, same: bool) -> Result<(), MobileAppError> {
        self.command(move |worker| async move {
            let session = worker.radio_session()?;
            session.confirm_code(same).await.map_err(mesh_error)
        })
        .await
    }

    /// Leave an exchange under way and open the meet again under a fresh
    /// key. Does nothing unless one is under way.
    pub async fn back_out_of_exchange(&self) -> Result<(), MobileAppError> {
        self.command(|worker| async move { worker.back_out_of_exchange().await })
            .await
    }

    /// Ask each claimed radio again to let go of this phone. Resolves once
    /// the round is done.
    pub async fn retry_claimed_radio_revocation(&self) -> Result<(), MobileAppError> {
        self.command(|worker| async move { worker.retry_claimed_radio_revocation().await })
            .await
    }
}
