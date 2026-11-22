use std::future::Future;

use super::*;
use crate::mobile_mesh::{
    MobileMeshExplicitPath, MobileMeshManagementEventRecord, MobileMeshManagementOutcome,
    MobileMeshPingEventRecord, MobileMeshPingOutcome,
};
use crate::secret_vault::memory::MemoryVault;
use crate::{MobileRadioPhase, public_identity_bytes};

/// Sam Ihara, out of the radio's range behind Glen Alpine Relay.
const SAM: u8 = 0x66;
const GLEN: u8 = 0x77;

/// Long enough for a device's silence to be called: a management response
/// is waited for 20 s once its request is acknowledged.
const SILENCE_WAIT: Duration = Duration::from_secs(45);

/// The phone's identity secret.
const PHONE_SEED: u8 = 0x09;
const PHONE_OWNER: &str = "phone";

/// The speaking peer: the first staged node that carries chat.
fn speaker() -> &'static Node {
    NODES
        .iter()
        .find(|node| !matches!(node.role, Role::Repeater))
        .unwrap()
}

fn address_of(seed: u8) -> String {
    MobileIdentity::unlock(vec![seed; 32])
        .unwrap()
        .public_identity()
        .canonical_address
}

/// A node's router hint: the first two octets of its key.
fn router_hint(seed: u8) -> Vec<u8> {
    public_identity_bytes(address_of(seed)).unwrap()[..2].to_vec()
}

/// Retry `probe` until it answers, or fail after ten seconds.
async fn eventually<T, F: Future<Output = Option<T>>>(what: &str, probe: impl FnMut() -> F) -> T {
    eventually_within(what, Duration::from_secs(10), probe).await
}

/// Retry `probe` until it answers, or fail after `limit`.
async fn eventually_within<T, F: Future<Output = Option<T>>>(
    what: &str,
    limit: Duration,
    mut probe: impl FnMut() -> F,
) -> T {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(value) = probe().await {
            return value;
        }
        assert!(Instant::now() < deadline, "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A phone tethered to the staged radio, with its mesh session on the
/// radio's driver and its chat in a store of its own.
struct Phone {
    air_dir: tempfile::TempDir,
    _counters: tempfile::TempDir,
    air: Arc<MobileStagingAir>,
    driver: Arc<MobileRadioDriver>,
    session: Arc<MobileMeshSession>,
    store: Arc<MobileAppStore>,
}

impl Phone {
    async fn tethered() -> Self {
        let air_dir = tempfile::tempdir().unwrap();
        let air = MobileStagingAir::start(air_dir.path().display().to_string(), false).unwrap();
        let driver = air.radio();
        let address = address_of(PHONE_SEED);
        driver
            .set_host_key(Some(public_identity_bytes(address.clone()).unwrap()))
            .unwrap();
        air.connect();
        tokio::time::timeout(Duration::from_secs(10), driver.attached())
            .await
            .expect("the staged radio attaches")
            .unwrap();

        let counters = tempfile::tempdir().unwrap();
        let session = MobileMeshSession::start(
            MobileIdentity::unlock(vec![PHONE_SEED; 32]).unwrap(),
            MobileCounterStore::new(counters.path().display().to_string()).unwrap(),
        )
        .await
        .unwrap();
        // The staged phone's store, seeded as staging seeds it, so the
        // staged channels are joined.
        let store = MobileAppStore::open(":memory:".to_owned()).unwrap();
        store
            .upsert_identity(PHONE_OWNER.to_owned(), address, 0)
            .unwrap();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        crate::seed_staging(
            store.clone(),
            Arc::new(MemoryVault::default()),
            PHONE_OWNER.to_owned(),
            now_ms,
        )
        .await
        .unwrap();
        session
            .clone()
            .attach_chat_store(store.clone(), PHONE_OWNER.to_owned(), None)
            .unwrap();
        session
            .register_peers(vec![MobilePeerRegistrationRecord {
                address: address_of(speaker().seed),
                mobile: true,
            }])
            .await
            .unwrap();
        session
            .register_channels(
                channel_keys()
                    .into_iter()
                    .map(|key| MobileChannelRegistrationRecord {
                        key,
                        max_flood_hops: None,
                    })
                    .collect(),
            )
            .await
            .unwrap();
        driver
            .use_mesh_session(Some(session.clone()))
            .await
            .unwrap();

        let phone = Self {
            air_dir,
            _counters: counters,
            air,
            driver,
            session,
            store,
        };
        phone.knows_the_phone().await;
        phone
    }

    /// Wait until the peers know the phone: a reaction then has nothing
    /// to answer, where before it had no phone to answer.
    async fn knows_the_phone(&self) {
        eventually("the peers learn the phone", || async {
            match self.air.peer_reacts("+1".to_owned()).await {
                Err(MobileStagingAirError::NoPhone) => None,
                other => Some(other),
            }
        })
        .await
        .expect_err("the phone has said nothing yet");
    }

    /// Register the staged nodes `seeds` with the phone's session.
    async fn knows(&self, seeds: &[u8]) {
        self.session
            .register_peers(
                seeds
                    .iter()
                    .map(|&seed| MobilePeerRegistrationRecord {
                        address: address_of(seed),
                        mobile: false,
                    })
                    .collect(),
            )
            .await
            .unwrap();
    }

    /// Ping the staged node `seed`, and wait for the ping to end.
    async fn ping(
        &self,
        seed: u8,
        path: Option<MobileMeshExplicitPath>,
        limit: Duration,
    ) -> MobileMeshPingEventRecord {
        let operation = self.session.ping(address_of(seed), path).unwrap();
        eventually_within("the ping ends", limit, || async {
            self.session
                .poll_update()
                .ping_events
                .into_iter()
                .find(|event| event.operation_id == operation)
        })
        .await
    }

    /// Wait for the management operation `operation` to end.
    async fn managed(&self, operation: u64, limit: Duration) -> MobileMeshManagementEventRecord {
        eventually_within("the management operation ends", limit, || async {
            self.session
                .poll_update()
                .management_events
                .into_iter()
                .find(|event| {
                    event.operation_id == operation
                        && event.outcome != MobileMeshManagementOutcome::Progress
                })
        })
        .await
    }

    /// The bodies of the phone's conversation at `address`, oldest first.
    fn bodies(&self, address: &str) -> Vec<(bool, String)> {
        self.store
            .chat_message_page_newest(PHONE_OWNER.to_owned(), address.to_owned(), 50)
            .map(|page| {
                page.messages
                    .into_iter()
                    .map(|message| (message.outbound, message.body))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Wait until the phone's conversation at `address` holds `body`.
    async fn hears(&self, address: &str, body: &str) {
        eventually(&format!("the phone hears {body:?}"), || async {
            self.bodies(address)
                .iter()
                .any(|(outbound, said)| !outbound && said == body)
                .then_some(())
        })
        .await;
    }
}

#[tokio::test]
async fn the_staged_radio_attaches_as_a_tracker() {
    let phone = Phone::tethered().await;
    let state = phone.driver.refresh().await.unwrap();
    assert_eq!(state.phase, MobileRadioPhase::Attached);
    assert_eq!(state.name.as_deref(), Some(RADIO_NAME));
    assert!(state.battery.is_some());
    assert!(state.provisioning.is_some_and(|sync| sync.phy_enabled));
}

#[tokio::test]
async fn a_control_needs_a_tethered_phone() {
    let dir = tempfile::tempdir().unwrap();
    let air = MobileStagingAir::start(dir.path().display().to_string(), false).unwrap();
    assert_eq!(
        air.peer_says("hello".to_owned(), false).await,
        Err(MobileStagingAirError::NoPhone)
    );
    // The air's thread winds down after the call returns.
    air.stop();
    eventually("the air stops", || async {
        (air.peer_says("hello".to_owned(), false).await == Err(MobileStagingAirError::Stopped))
            .then_some(())
    })
    .await;
}

#[tokio::test]
async fn a_stopped_air_reports_no_link() {
    let dir = tempfile::tempdir().unwrap();
    let air = MobileStagingAir::start(dir.path().display().to_string(), false).unwrap();
    let driver = air.radio();
    air.stop();
    air.connect();
    let attached = tokio::time::timeout(Duration::from_secs(5), driver.attached())
        .await
        .expect("the driver does not wait on a link that is not coming");
    assert!(attached.is_err());
}

#[tokio::test]
async fn a_peer_and_the_phone_talk_both_ways() {
    let phone = Phone::tethered().await;
    let peer = address_of(speaker().seed);

    phone
        .air
        .peer_says("Trailhead in ten".to_owned(), false)
        .await
        .unwrap();
    phone.hears(&peer, "Trailhead in ten").await;

    phone
        .session
        .send_chat(
            peer.clone(),
            MobileChatSendRequest::Text {
                body: "On my way".to_owned(),
            },
        )
        .await
        .unwrap();
    // The peer replies to what it heard, which it can only name once the
    // phone's message has reached its store.
    eventually("the peer replies to the phone", || async {
        match phone.air.peer_replies("See you there".to_owned()).await {
            Err(MobileStagingAirError::NothingToAnswer) => None,
            other => Some(other),
        }
    })
    .await
    .unwrap();
    phone.hears(&peer, "See you there").await;
}

/// More messages back to back than the peer may await acknowledgments
/// for go out without a stall: the phone's acknowledgments reach the peer
/// while each control waits for its message to go out.
#[tokio::test]
async fn a_burst_of_direct_messages_goes_out_without_stalling() {
    let phone = Phone::tethered().await;
    let peer = address_of(speaker().seed);
    let count = 3 * umsh_mac::DEFAULT_ACKS;
    for index in 0..count {
        let started = std::time::Instant::now();
        phone
            .air
            .peer_says(format!("burst {index}"), false)
            .await
            .unwrap_or_else(|error| panic!("burst {index}: {error}"));
        // A stalled peer waits out an acknowledgment's timeout, seconds
        // long; an unstalled one sends in milliseconds.
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "burst {index} took {:?}",
            started.elapsed()
        );
    }
    phone.hears(&peer, &format!("burst {}", count - 1)).await;
}

#[tokio::test]
async fn a_lost_channel_message_leaves_a_gap() {
    let phone = Phone::tethered().await;
    // The radio hands its host only the channels the host lists, as the
    // app has it list its joined ones.
    phone
        .driver
        .reconcile_host_channel_keys(channel_keys())
        .await
        .unwrap();
    phone
        .air
        .peer_says_losing_one("First".to_owned(), "Lost".to_owned(), "Last".to_owned())
        .await
        .unwrap();
    let channel = channel_address();
    phone.hears(&channel, "Last").await;
    let heard: Vec<String> = phone
        .bodies(&channel)
        .into_iter()
        .map(|(_, body)| body)
        .collect();
    assert!(heard.contains(&"First".to_owned()));
    assert!(!heard.contains(&"Lost".to_owned()));
}

#[tokio::test]
async fn failing_transmissions_never_reach_a_peer() {
    let phone = Phone::tethered().await;
    phone.air.set_transmissions_failing(true);
    phone
        .session
        .send_chat(
            address_of(speaker().seed),
            MobileChatSendRequest::Text {
                body: "Anyone?".to_owned(),
            },
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        phone.air.peer_reacts("+1".to_owned()).await,
        Err(MobileStagingAirError::NothingToAnswer)
    );
}

#[tokio::test]
async fn a_reset_starts_the_peers_over() {
    let phone = Phone::tethered().await;
    let peer = address_of(speaker().seed);
    phone
        .air
        .peer_says("Before".to_owned(), false)
        .await
        .unwrap();
    phone.hears(&peer, "Before").await;
    let generation = |number: u32| phone.air_dir.path().join(number.to_string());
    let speaker_dir = format!("{:02x}", speaker().seed);
    let marker = generation(0).join(&speaker_dir).join("marker");
    std::fs::write(&marker, b"").unwrap();

    phone.air.reset().await.unwrap();
    // An old session ending late may recreate its directory, but never
    // what was in it.
    assert!(!marker.exists(), "the old generation was removed");
    // The peers stand again, knowing the phone, and speak. The phone, which
    // kept its identity, rightly refuses their restarted counters: a reset
    // is for a phone that starts over too.
    phone.knows_the_phone().await;
    phone
        .air
        .peer_says("After".to_owned(), false)
        .await
        .unwrap();
    assert!(
        generation(1).join(&speaker_dir).exists(),
        "the peers keep counters in a new generation"
    );
}

/// Another identity taking the radio is a phone starting over, and the
/// staged mesh starts over with it.
#[tokio::test]
async fn another_identity_on_the_radio_starts_the_mesh_over() {
    let phone = Phone::tethered().await;
    phone.knows_the_phone().await;
    let generation = |number: u32| phone.air_dir.path().join(number.to_string());
    assert!(!generation(1).exists());

    // As erasing the phone's identity does: the radio is let go, and the
    // new identity attaches it.
    let driver = phone.air.radio();
    driver.release_host().await;
    phone.air.disconnect();
    let stranger = public_identity_bytes(address_of(0x99)).unwrap();
    driver.set_host_key(Some(stranger)).unwrap();
    phone.air.connect();
    tokio::time::timeout(Duration::from_secs(10), driver.attached())
        .await
        .expect("the staged radio attaches again")
        .unwrap();
    eventually("the staged nodes stand up again", || async {
        generation(1).exists().then_some(())
    })
    .await;
}

/// What `event` says `property` is worth.
fn answered(event: &MobileMeshManagementEventRecord, property: u32) -> Option<Vec<u8>> {
    event
        .answers
        .iter()
        .find(|answer| answer.property_id == property)
        .and_then(|answer| answer.value.clone())
}

#[tokio::test]
async fn a_peer_behind_a_repeater_is_reached_in_two_hops() {
    let phone = Phone::tethered().await;
    phone.knows(&[SAM]).await;
    let reply = phone.ping(SAM, None, Duration::from_secs(20)).await;
    assert_eq!(reply.outcome, MobileMeshPingOutcome::Reply);
    assert_eq!(reply.hop_count, Some(2));
    assert_eq!(reply.route_hints, vec![router_hint(GLEN)]);
    assert_eq!(
        reply.trace_signal.len(),
        1,
        "the repeater says how it heard"
    );
}

#[tokio::test]
async fn a_flood_from_the_phone_is_echoed_by_both_repeaters() {
    let phone = Phone::tethered().await;
    phone
        .driver
        .reconcile_host_channel_keys(channel_keys())
        .await
        .unwrap();
    let channel = channel_address();
    let body = "Anyone on the ridge?";
    phone
        .session
        .send_chat(
            channel.clone(),
            MobileChatSendRequest::Text {
                body: body.to_owned(),
            },
        )
        .await
        .unwrap();
    // The message floods untraced, so each forward is a repeater that
    // names no hint.
    eventually("both repeaters echo the flood", || async {
        let page = phone
            .store
            .chat_message_page_newest(PHONE_OWNER.to_owned(), channel.clone(), 50)
            .ok()?;
        let message = page
            .messages
            .into_iter()
            .find(|message| message.outbound && message.body == body)?;
        (message.repeats?.anonymous == 2).then_some(())
    })
    .await;
}

#[tokio::test]
async fn each_repeater_lists_the_other() {
    let phone = Phone::tethered().await;
    phone.knows(&[MANAGED_SEED, GLEN]).await;
    for (asked, other) in [(MANAGED_SEED, GLEN), (GLEN, MANAGED_SEED)] {
        let page = phone
            .session
            .request_peer_repeaters_page(address_of(asked), None, Vec::new())
            .await
            .unwrap();
        let name = NODES[place(other)].name;
        assert!(
            page.entries
                .iter()
                .any(|entry| entry.name.as_deref() == Some(name)),
            "{asked:02x} lists {name}: {page:?}"
        );
    }
}

#[tokio::test]
async fn a_held_path_stands_beside_the_one_learned() {
    let phone = Phone::tethered().await;
    phone.knows(&[SAM]).await;
    let sam = address_of(SAM);
    // Tallac Ridge cannot reach Sam, so sends down the held path miss and
    // the flood fallback finds the way through Glen Alpine Relay.
    let held = MobileMeshExplicitPath {
        hints: vec![router_hint(MANAGED_SEED)],
        flood_hops: 0,
    };
    assert!(
        phone
            .session
            .hold_peer_route(sam.clone(), held, 600_000)
            .await
            .unwrap()
    );
    let reply = phone.ping(SAM, None, SILENCE_WAIT).await;
    assert_eq!(reply.outcome, MobileMeshPingOutcome::Reply);
    let route = phone.session.peer_route(sam).await.unwrap();
    assert_eq!(
        route.hints,
        vec![router_hint(MANAGED_SEED)],
        "the hold stands"
    );
    assert_eq!(route.candidate_hints, vec![router_hint(GLEN)]);
}

#[tokio::test]
async fn the_managed_repeater_is_read_written_and_saved() {
    let phone = Phone::tethered().await;
    phone.knows(&[MANAGED_SEED]).await;
    let tallac = address_of(MANAGED_SEED);
    let limit = Duration::from_secs(20);

    let read = phone
        .session
        .begin_management_fetch(tallac.clone(), vec![prop::DEV_KEY, prop::DEV_NAME], true)
        .unwrap();
    let read = phone.managed(read, limit).await;
    assert_eq!(read.outcome, MobileMeshManagementOutcome::Replied);
    assert_eq!(
        answered(&read, prop::DEV_KEY),
        Some(public_identity_bytes(tallac.clone()).unwrap()),
        "the device key is the address the phone manages"
    );
    assert_eq!(
        answered(&read, prop::DEV_NAME).as_deref(),
        Some(NODES[MANAGED].name.as_bytes())
    );

    let written = phone
        .session
        .begin_management_set(tallac.clone(), prop::DEV_NAME, b"Tallac Summit".to_vec())
        .unwrap();
    let written = phone.managed(written, limit).await;
    assert_eq!(written.outcome, MobileMeshManagementOutcome::Replied);
    assert_eq!(
        answered(&written, prop::DEV_NAME).as_deref(),
        Some(&b"Tallac Summit"[..])
    );

    let saved = phone.session.begin_management_save(tallac).unwrap();
    let saved = phone.managed(saved, limit).await;
    assert_eq!(saved.outcome, MobileMeshManagementOutcome::Replied);
    assert_eq!(saved.refusal, None);
}

#[tokio::test]
async fn a_non_administrator_meets_silence() {
    let phone = Phone::tethered().await;
    phone.knows(&[MANAGED_SEED]).await;
    let tallac = address_of(MANAGED_SEED);
    let removed = phone
        .session
        .begin_management_remove_admin(tallac.clone(), phone.session.node_public_key())
        .unwrap();
    let removed = phone.managed(removed, Duration::from_secs(20)).await;
    assert_eq!(removed.outcome, MobileMeshManagementOutcome::Replied);

    let refused = phone
        .session
        .begin_management_get(tallac, prop::DEV_NAME)
        .unwrap();
    let refused = phone.managed(refused, SILENCE_WAIT).await;
    assert_eq!(refused.outcome, MobileMeshManagementOutcome::TimedOut);
}

#[tokio::test]
async fn an_unreachable_repeater_is_not_reached() {
    let phone = Phone::tethered().await;
    phone.knows(&[MANAGED_SEED]).await;
    phone.air.set_remote_device_reachable(false);
    let get = phone
        .session
        .begin_management_get(address_of(MANAGED_SEED), prop::DEV_NAME)
        .unwrap();
    let get = phone.managed(get, SILENCE_WAIT).await;
    assert_eq!(get.outcome, MobileMeshManagementOutcome::Unreachable);
}

#[tokio::test]
async fn a_reset_rebuilds_the_repeaters() {
    let phone = Phone::tethered().await;
    phone.knows(&[MANAGED_SEED]).await;
    phone.air.reset().await.unwrap();
    phone.knows_the_phone().await;
    let managed_dir = format!("{MANAGED_SEED:02x}");
    eventually(
        "the managed repeater stands in the new generation",
        || async {
            phone
                .air_dir
                .path()
                .join("1")
                .join(&managed_dir)
                .exists()
                .then_some(())
        },
    )
    .await;
    let reply = phone
        .ping(MANAGED_SEED, None, Duration::from_secs(20))
        .await;
    assert_eq!(reply.outcome, MobileMeshPingOutcome::Reply);
}
