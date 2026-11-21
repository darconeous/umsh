use std::future::Future;

use super::*;
use crate::secret_vault::memory::MemoryVault;
use crate::{MobileRadioPhase, public_identity_bytes};

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

/// Retry `probe` until it answers, or fail after ten seconds.
async fn eventually<T, F: Future<Output = Option<T>>>(
    what: &str,
    mut probe: impl FnMut() -> F,
) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
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
        let air = MobileStagingAir::start(air_dir.path().display().to_string()).unwrap();
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

#[test]
fn a_flood_is_forwarded_with_one_hop_spent() {
    // Flood hops follow: three left, one spent.
    assert_eq!(forwarded(&[0x01, 0x31, 0xAA]), Some(vec![0x01, 0x22, 0xAA]));
    assert_eq!(forwarded(&[0x01, 0x05]), None, "no hops left");
    assert_eq!(forwarded(&[0x00, 0x31]), None, "not a flood");
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
    let air = MobileStagingAir::start(dir.path().display().to_string()).unwrap();
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
    let air = MobileStagingAir::start(dir.path().display().to_string()).unwrap();
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
