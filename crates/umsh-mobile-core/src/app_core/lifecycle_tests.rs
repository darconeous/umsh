//! `start`, `erase`, `stop` and `use_radio`, checked by the state they
//! leave.

use std::time::Duration;

use super::test_support::{Core, identity};
use super::{MobileAppError, MobileAppLifecycle, MobileAppStartFailure};
use crate::radio_driver::{MobileRadioError, MobileRadioPhase};
use crate::store::MobileStoredChannelKind;
use crate::test_support::{eventually, linked_driver};

#[tokio::test]
async fn commands_wait_for_a_running_identity() {
    let core = Core::new();
    assert_eq!(
        core.core.mesh_session().await.err(),
        Some(MobileAppError::NotRunning)
    );
    assert_eq!(
        core.core.content_changed().await,
        Err(MobileAppError::NotRunning)
    );
}

#[tokio::test]
async fn start_brings_the_identity_up_with_its_built_in_channels() {
    let core = Core::new();
    let me = core.start(3).await;

    assert_eq!(
        core.core.poll_changes().lifecycle,
        Some(MobileAppLifecycle::Running)
    );
    let owner = me.canonical_address.clone();
    assert!(
        core.store
            .knows_identity(owner.clone(), owner.clone())
            .unwrap()
    );
    let channels = core.store.channels(owner.clone()).unwrap();
    let mut builtin: Vec<_> = channels
        .iter()
        .filter(|channel| channel.kind == MobileStoredChannelKind::Builtin)
        .map(|channel| channel.canonical_name.clone().unwrap())
        .collect();
    builtin.sort();
    assert_eq!(builtin, ["emergency", "public"]);
    assert!(channels.iter().all(|channel| channel.joined_phone));
    assert_eq!(core.vault.accounts().len(), 2, "each key in the vault");
    // The public conversation is there to open.
    let state = core.core.state(true).unwrap();
    assert_eq!(state.channel_conversations.len(), 1);
    assert_eq!(
        state.channel_conversations[0]
            .channel
            .canonical_name
            .as_deref(),
        Some("public")
    );
    // The session is the identity's.
    let session = core.core.mesh_session().await.unwrap();
    assert_eq!(
        session.node_public_key(),
        crate::public_identity_bytes(owner).unwrap()
    );

    // A second start is refused; the first is still running.
    assert_eq!(
        core.core.start(identity(4)).await,
        Err(MobileAppError::Busy)
    );
    assert_eq!(core.lifecycle(), MobileAppLifecycle::Running);
}

#[tokio::test]
async fn a_start_that_cannot_open_its_counters_fails_and_can_be_erased() {
    let core = Core::new();
    // A file where the counter directory goes.
    std::fs::write(core.counter_directory(), b"in the way").unwrap();
    assert_eq!(
        core.core.start(identity(3)).await,
        Err(MobileAppError::StartFailed {
            reason: MobileAppStartFailure::Session
        })
    );
    assert_eq!(
        core.lifecycle(),
        MobileAppLifecycle::Failed {
            reason: MobileAppStartFailure::Session
        }
    );
    assert_eq!(
        core.core.mesh_session().await.err(),
        Some(MobileAppError::NotRunning)
    );

    std::fs::remove_file(core.counter_directory()).unwrap();
    core.core.erase(false).await.unwrap();
    assert_eq!(core.lifecycle(), MobileAppLifecycle::Idle);
    core.start(4).await;
}

#[tokio::test]
async fn erase_takes_the_identity_down_and_another_starts() {
    let core = Core::new();
    let me = core.start(3).await;
    let session = core.core.mesh_session().await.unwrap();
    // Something to reserve, so the counter directory exists.
    session
        .ping(identity(4).public_identity().canonical_address, None)
        .unwrap();
    let counters = core.counter_directory();
    eventually("the counters reserved", || counters.exists());

    core.core.erase(false).await.unwrap();
    assert_eq!(core.lifecycle(), MobileAppLifecycle::Idle);
    assert_eq!(core.core.state(true), Err(MobileAppError::NoOwner));
    assert!(core.vault.accounts().is_empty());
    assert!(!core.counter_directory().exists());
    // A handle kept past the erase answers nothing.
    assert!(session.send_beacon().await.is_err());
    // The narrow erase keeps the store's content.
    assert!(
        !core
            .store
            .channels(me.canonical_address.clone())
            .unwrap()
            .is_empty()
    );

    let next = core.start(4).await;
    assert_ne!(next.canonical_address, me.canonical_address);
    assert_eq!(core.vault.accounts().len(), 2);
}

#[tokio::test]
async fn erasing_content_too_leaves_an_empty_store() {
    let core = Core::new();
    let me = core.start(3).await;
    core.core.erase(true).await.unwrap();
    assert!(
        core.store
            .channels(me.canonical_address)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn radio_commands_say_why_there_is_no_radio() {
    let core = Core::new();
    let peer = identity(4).public_identity().canonical_address;
    assert_eq!(
        core.core.ping(peer.clone(), None).await,
        Err(MobileAppError::NotRunning)
    );
    core.start(3).await;
    assert_eq!(
        core.core.ping(peer.clone(), None).await,
        Err(MobileAppError::NoRadio)
    );
    assert_eq!(
        core.core
            .ping("not an address".to_owned(), None)
            .await
            .err()
            .map(|error| { matches!(error, MobileAppError::InvalidInput { .. }) }),
        Some(true)
    );
    let operation = super::MobileOperation::new();
    assert_eq!(
        core.core.remote_save(operation.clone(), peer.clone()).await,
        Err(MobileAppError::NoRadio)
    );
    assert_eq!(
        core.core.remote_save(operation, peer).await,
        Err(MobileAppError::OperationReused)
    );
    // Advertising needs only the session.
    core.core.advertise_identity().await.unwrap();
}

#[tokio::test]
async fn the_advertised_name_is_kept_trimmed() {
    let core = Core::new();
    let owner = core.start(3).await.canonical_address;
    core.core
        .set_advertised_name("  Ridge Camp \n".to_owned())
        .await
        .unwrap();
    assert_eq!(
        core.store
            .local_advertised_name(owner.clone())
            .unwrap()
            .as_deref(),
        Some("Ridge Camp")
    );
    core.core
        .set_advertised_name("   ".to_owned())
        .await
        .unwrap();
    assert_eq!(core.store.local_advertised_name(owner).unwrap(), None);
}

#[tokio::test]
async fn with_no_radio_a_frame_fails_at_once() {
    let core = Core::new();
    core.start(3).await;
    let session = core.core.mesh_session().await.unwrap();
    // Without the core failing it, the beacon would wait out the 35 s
    // completion timeout with nobody to carry it.
    tokio::time::timeout(Duration::from_secs(5), session.send_beacon())
        .await
        .expect("the frame failed at once")
        .ok();
}

#[tokio::test]
async fn a_radio_carries_the_running_identity_and_native_code_cannot_take_it() {
    let core = Core::new();
    let (_link, driver) = linked_driver();
    core.core.use_radio(Some(driver.clone())).await.unwrap();
    eventually("the radio waiting for a host", || {
        driver.state().phase == MobileRadioPhase::AwaitingHost
    });

    let me = core.start(3).await;
    eventually("attached as this phone's radio", || {
        driver.state().phase == MobileRadioPhase::Attached
    });
    core.until("the core saw the attach", |core| {
        core.status()
            .unwrap()
            .radio
            .is_some_and(|radio| radio.phase == MobileRadioPhase::Attached)
    })
    .await;
    // The radio's key is now this phone's.
    assert_eq!(
        driver.set_host_key(Some(vec![9; 32])),
        Err(MobileRadioError::RadioUnavailable)
    );
    assert_eq!(
        driver.use_mesh_session(None).await,
        Err(MobileRadioError::RadioUnavailable)
    );
    assert_eq!(driver.poll_update(), Default::default());
    let _ = me;

    // A frame reaches the air through the radio.
    let session = core.core.mesh_session().await.unwrap();
    session.send_beacon().await.unwrap();
}

#[tokio::test]
async fn use_radio_moves_the_session_and_gives_the_old_driver_back() {
    let core = Core::new();
    core.start(3).await;
    let (_first_link, first) = linked_driver();
    core.core.use_radio(Some(first.clone())).await.unwrap();
    eventually("the first attached", || {
        first.state().phase == MobileRadioPhase::Attached
    });

    let (_second_link, second) = linked_driver();
    core.core.use_radio(Some(second.clone())).await.unwrap();
    eventually("the second attached", || {
        second.state().phase == MobileRadioPhase::Attached
    });
    // The first is native code's again.
    assert!(first.set_host_key(None).is_ok());

    core.core.use_radio(None).await.unwrap();
    assert!(second.set_host_key(None).is_ok());
    assert_eq!(
        core.core.status().unwrap().radio,
        None,
        "no radio is attached"
    );
}

#[tokio::test]
async fn stop_takes_a_running_identity_down_and_lets_go_of_the_radio() {
    let core = Core::new();
    core.start(3).await;
    let (_link, driver) = linked_driver();
    core.core.use_radio(Some(driver.clone())).await.unwrap();
    let session = core.core.mesh_session().await.unwrap();
    // A secured frame reserves counters, which makes their directory.
    session
        .ping(identity(4).public_identity().canonical_address, None)
        .unwrap();
    let counters = core.counter_directory();
    eventually("the counters reserved", || counters.exists());

    core.core.stop().await;
    assert_eq!(core.core.status(), Err(MobileAppError::Stopped));
    assert!(driver.set_host_key(None).is_ok(), "native code's again");
    assert!(session.send_beacon().await.is_err(), "the session is shut");
    assert_eq!(
        core.core.start(identity(4)).await,
        Err(MobileAppError::Stopped)
    );
    assert!(
        driver.poll_update().state.is_some(),
        "native code gets the state the driver is in"
    );
    assert!(
        core.counter_directory().exists(),
        "the counters stay: only erase removes them"
    );
}

#[tokio::test]
async fn letting_go_of_the_radio_is_a_detach() {
    let core = Core::new();
    let (_link, driver) = linked_driver();
    core.core.use_radio(Some(driver.clone())).await.unwrap();
    core.start(3).await;
    core.until("the radio's claim", |core| {
        core.claimed_radios().is_ok_and(|claims| claims.len() == 1)
            && core.stranded_radios().is_ok_and(|radios| radios.is_empty())
    })
    .await;

    core.core.use_radio(None).await.unwrap();
    assert_eq!(
        core.core.stranded_radios().unwrap().len(),
        1,
        "the radio left holding this phone's key is stranded"
    );
    let peer = identity(4).public_identity().canonical_address;
    assert_eq!(
        core.core.ping(peer, None).await,
        Err(MobileAppError::NoRadio)
    );
}

#[tokio::test]
async fn an_advert_goes_once_its_interval_and_scatter_have_passed() {
    let core = Core::new();
    let (link, driver) = linked_driver();
    core.core.use_radio(Some(driver.clone())).await.unwrap();
    core.start(3).await;
    eventually("attached as this phone's radio", || {
        driver.state().phase == MobileRadioPhase::Attached
    });
    core.core
        .set_policy(super::MobileAppPolicyRecord {
            advert_interval_seconds: 60,
            beacon_interval_seconds: 0,
            discoverable: true,
            flood_hops: 1,
            beacon_flood_hops: 0,
            location_precision: None,
            test_message_alerts: true,
        })
        .await
        .unwrap();
    let transmitted = || link.device.lock().unwrap().take_transmitted().len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    transmitted();

    // Short of the interval: nothing.
    core.clock.advance(59_000);
    core.core.resumed();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(transmitted(), 0);

    // Past the interval and the most scatter allows (a quarter): sent.
    core.clock.advance(16_001);
    core.core.resumed();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while transmitted() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the advert never went"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
