//! `start`, `erase`, `stop` and `use_radio`, checked by the state they
//! leave.

use std::sync::Arc;
use std::time::Duration;

use super::test_support::{Core, NOW_MS, identity};
use super::worker::TestHooks;
use super::{
    MobileAppCore, MobileAppCoreListener, MobileAppError, MobileAppLifecycle,
    MobileAppStartFailure, Options,
};
use crate::radio_driver::{MobileRadioError, MobileRadioPhase};
use crate::store::MobileStoredChannelKind;
use crate::test_support::{eventually, linked_driver};

#[tokio::test]
async fn commands_wait_for_a_running_identity() {
    let core = Core::new();
    assert_eq!(
        core.core.identity_share_uri().await.err(),
        Some(MobileAppError::NotRunning)
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
    let session = core.session().await.unwrap();
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
        core.core.identity_share_uri().await.err(),
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
    let session = core.session().await.unwrap();
    // Something to reserve, so the counter directory exists.
    session
        .ping(identity(4).public_identity().canonical_address, None)
        .unwrap();
    let counters = core.counter_directory();
    eventually("the counters reserved", || counters.exists());
    core.core.poll_changes();

    core.core.erase(false).await.unwrap();
    assert_eq!(core.lifecycle(), MobileAppLifecycle::Idle);
    // The old owner's claims no longer read.
    assert!(core.core.poll_changes().claimed_radios_changed);
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

/// A listener that drains each batch the moment it is told of one, and
/// reads the stranded radios whenever their flag is up.
#[derive(Default)]
struct EagerReader {
    core: std::sync::OnceLock<std::sync::Weak<MobileAppCore>>,
    stranded: std::sync::Mutex<Vec<Result<usize, MobileAppError>>>,
}

impl MobileAppCoreListener for EagerReader {
    fn on_changes_pending(&self) {
        let Some(core) = self.core.get().and_then(std::sync::Weak::upgrade) else {
            return;
        };
        if core.poll_changes().claimed_radios_changed {
            let read = core.stranded_radios().map(|radios| radios.len());
            self.stranded.lock().unwrap().push(read);
        }
    }
}

#[tokio::test]
async fn lists_raised_while_erasing_are_raised_again_once_idle() {
    let core = Core::new();
    let me = core.start(3).await;
    let radio = identity(4).public_identity().canonical_address;
    core.store
        .record_claimed_radio(me.canonical_address, radio, None, NOW_MS)
        .unwrap();
    let reader = Arc::new(EagerReader::default());
    let _ = reader.core.set(Arc::downgrade(&core.core));
    core.core.set_listener(reader.clone());
    core.core.poll_changes();

    core.core.erase(false).await.unwrap();
    // The last read of the list is the one that finds no owner, not one
    // refused while erasing.
    assert_eq!(
        reader.stranded.lock().unwrap().last(),
        Some(&Err(MobileAppError::NoOwner))
    );
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
    let device = core.core.manage_device(peer, false).await.unwrap();
    assert_eq!(
        device.refresh_card().await,
        Ok(crate::MobileManagementOutcome::Failed {
            problem: crate::MobileManagementProblem::NoRadio
        })
    );
    device.release();
    assert_eq!(
        core.core.advertise_identity().await,
        Err(MobileAppError::NoRadio)
    );
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
    let session = core.session().await.unwrap();
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
    let session = core.session().await.unwrap();
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
    let session = core.session().await.unwrap();
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
            // The shortest interval the core runs.
            advert_interval_seconds: 20 * 60,
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
    core.clock.advance(1_199_000);
    core.core.resumed();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(transmitted(), 0);

    // Past the interval and the most scatter allows (a quarter): sent.
    core.clock.advance(301_001);
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

/// A core whose `start` holds once it is starting, until a permit is
/// added to its gate.
fn gated() -> (Core, Arc<TestHooks>) {
    let hooks = Arc::new(TestHooks {
        start_gate: Some(tokio::sync::Semaphore::new(0)),
        ..TestHooks::default()
    });
    let core = Core::with_options(Options {
        hooks: hooks.clone(),
        ..Options::default()
    });
    (core, hooks)
}

/// Start `seed`'s identity in the background, and wait until it is held
/// at the gate.
async fn start_held(core: &Core, seed: u8) -> tokio::task::JoinHandle<Result<(), MobileAppError>> {
    let app = core.core.clone();
    let starting = tokio::spawn(async move { app.start(identity(seed)).await });
    core.until("starting", |core| {
        core.status().unwrap().lifecycle == MobileAppLifecycle::Starting
    })
    .await;
    starting
}

/// Give the spawned calls time to reach the worker, and check that each is
/// still waiting there.
async fn still_waiting<T>(calls: &[&tokio::task::JoinHandle<T>]) {
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(calls.iter().all(|call| !call.is_finished()));
}

fn pushed_names(hooks: &TestHooks) -> Vec<String> {
    hooks.pushed_names.lock().unwrap().clone()
}

#[tokio::test]
async fn a_command_made_while_starting_runs_once_the_start_is_done() {
    let (core, hooks) = gated();
    let starting = start_held(&core, 3).await;
    let owner = identity(3).public_identity().canonical_address;

    let app = core.core.clone();
    let shared = tokio::spawn(async move { app.identity_share_uri().await });
    let app = core.core.clone();
    let named = tokio::spawn(async move { app.set_advertised_name(" Ridge Camp ".into()).await });
    still_waiting(&[&named]).await;
    assert!(!shared.is_finished());

    hooks.start_gate.as_ref().unwrap().add_permits(1);
    starting.await.unwrap().unwrap();
    // Signed by the identity the start brought up.
    let link = crate::inspect_node_uri(shared.await.unwrap().unwrap()).unwrap();
    assert_eq!(link.canonical_address, owner);
    assert_eq!(
        link.identity.map(|identity| identity.signature),
        Some(crate::IdentitySignatureState::Valid)
    );
    named.await.unwrap().unwrap();
    assert_eq!(
        core.store.local_advertised_name(owner).unwrap().as_deref(),
        Some("Ridge Camp")
    );
    // The session carries the name, whichever push came last.
    assert_eq!(
        pushed_names(&hooks).last().map(String::as_str),
        Some("Ridge Camp")
    );
}

#[tokio::test]
async fn lists_read_while_starting_are_raised_again_once_running() {
    let (core, hooks) = gated();
    let starting = start_held(&core, 3).await;
    // A listener that read everything while the start held, before the
    // built-in channels and the public conversation were written.
    let early = core.core.poll_changes();
    assert!(early.channels_changed);
    assert!(core.core.state(true).unwrap().channels.is_empty());

    hooks.start_gate.as_ref().unwrap().add_permits(1);
    starting.await.unwrap().unwrap();
    let running = core.core.poll_changes();
    assert_eq!(running.lifecycle, Some(MobileAppLifecycle::Running));
    assert!(running.channels_changed);
    assert!(running.conversations_changed);
    assert!(running.all_transcripts);
    assert_eq!(core.core.state(true).unwrap().channels.len(), 2);
}

#[tokio::test]
async fn a_command_made_while_a_start_fails_is_not_running() {
    let (core, hooks) = gated();
    let owner = identity(3).public_identity().canonical_address;
    // A returning identity, whose row the store already holds.
    core.store
        .upsert_identity(owner.clone(), owner.clone(), 1)
        .unwrap();
    // A file where the counter directory goes.
    std::fs::write(core.counter_directory(), b"in the way").unwrap();
    let starting = start_held(&core, 3).await;

    let app = core.core.clone();
    let advertised = tokio::spawn(async move { app.advertise_identity().await });
    let app = core.core.clone();
    let named = tokio::spawn(async move { app.set_advertised_name("Ridge Camp".into()).await });
    still_waiting(&[&advertised, &named]).await;

    hooks.start_gate.as_ref().unwrap().add_permits(1);
    assert_eq!(
        starting.await.unwrap(),
        Err(MobileAppError::StartFailed {
            reason: MobileAppStartFailure::Session
        })
    );
    assert_eq!(advertised.await.unwrap(), Err(MobileAppError::NotRunning));
    // Failed with an owner, the name is still kept for the next start.
    named.await.unwrap().unwrap();
    assert_eq!(
        core.store.local_advertised_name(owner).unwrap().as_deref(),
        Some("Ridge Camp")
    );
    assert!(pushed_names(&hooks).is_empty());
}

#[tokio::test]
async fn a_name_kept_while_idle_is_the_one_the_start_pushes() {
    let hooks = Arc::new(TestHooks::default());
    let core = Core::with_options(Options {
        hooks: hooks.clone(),
        ..Options::default()
    });
    assert_eq!(
        core.core.set_advertised_name("Ridge Camp".into()).await,
        Err(MobileAppError::NoOwner)
    );
    let owner = identity(3).public_identity().canonical_address;
    core.store
        .upsert_identity(owner.clone(), owner.clone(), 1)
        .unwrap();
    core.core.set_owner(Some(owner.clone())).unwrap();
    core.core
        .set_advertised_name("  Ridge Camp \n".into())
        .await
        .unwrap();
    assert_eq!(
        core.store
            .local_advertised_name(owner.clone())
            .unwrap()
            .as_deref(),
        Some("Ridge Camp")
    );
    // Nothing runs to push it to.
    assert!(pushed_names(&hooks).is_empty());

    core.start(3).await;
    assert_eq!(pushed_names(&hooks), ["Ridge Camp"]);
}

#[tokio::test]
async fn a_name_kept_before_the_identity_has_a_row_is_the_one_the_start_pushes() {
    let hooks = Arc::new(TestHooks::default());
    let core = Core::with_options(Options {
        hooks: hooks.clone(),
        ..Options::default()
    });
    // Never started: the store has no row for the owner yet.
    let owner = identity(3).public_identity().canonical_address;
    core.core.set_owner(Some(owner.clone())).unwrap();
    core.core
        .set_advertised_name("Ridge Camp".into())
        .await
        .unwrap();
    assert_eq!(
        core.store
            .local_advertised_name(owner.clone())
            .unwrap()
            .as_deref(),
        Some("Ridge Camp")
    );

    // A start that fails before its repairs leaves the name where it was.
    std::fs::write(core.counter_directory(), b"in the way").unwrap();
    assert!(core.core.start(identity(3)).await.is_err());
    core.core
        .set_advertised_name("Summit Camp".into())
        .await
        .unwrap();
    assert_eq!(
        core.store
            .local_advertised_name(owner.clone())
            .unwrap()
            .as_deref(),
        Some("Summit Camp")
    );
    assert!(pushed_names(&hooks).is_empty());

    std::fs::remove_file(core.counter_directory()).unwrap();
    core.start(3).await;
    assert_eq!(pushed_names(&hooks), ["Summit Camp"]);
}

// --- An erase during a start. ---

fn starts_announced(hooks: &TestHooks) -> usize {
    hooks
        .starts_announced
        .load(std::sync::atomic::Ordering::Relaxed)
}

#[tokio::test]
async fn an_erase_while_starting_waits_and_then_runs() {
    let (core, hooks) = gated();
    let starting = start_held(&core, 3).await;
    let app = core.core.clone();
    let erasing = tokio::spawn(async move { app.erase(false).await });
    still_waiting(&[&erasing]).await;
    assert_eq!(core.lifecycle(), MobileAppLifecycle::Starting);

    hooks.start_gate.as_ref().unwrap().add_permits(1);
    starting.await.unwrap().unwrap();
    erasing.await.unwrap().unwrap();
    assert_eq!(core.lifecycle(), MobileAppLifecycle::Idle);
    assert!(core.vault.accounts().is_empty());
    assert!(!core.counter_directory().exists());
    assert_eq!(core.core.state(true), Err(MobileAppError::NoOwner));
    // The start it waited on put nothing on the air.
    assert_eq!(starts_announced(&hooks), 0);

    // A start nobody waits on does.
    hooks.start_gate.as_ref().unwrap().add_permits(1);
    core.start(4).await;
    assert_eq!(starts_announced(&hooks), 1);
}

#[tokio::test]
async fn an_erase_while_a_start_fails_runs_from_failed() {
    let (core, hooks) = gated();
    // A file where the counter directory goes.
    std::fs::write(core.counter_directory(), b"in the way").unwrap();
    let starting = start_held(&core, 3).await;
    let app = core.core.clone();
    let erasing = tokio::spawn(async move { app.erase(false).await });
    still_waiting(&[&erasing]).await;

    hooks.start_gate.as_ref().unwrap().add_permits(1);
    assert_eq!(
        starting.await.unwrap(),
        Err(MobileAppError::StartFailed {
            reason: MobileAppStartFailure::Session
        })
    );
    // It ran: the file in the way is not a directory it can remove, which
    // only an erase that ran reports.
    assert_eq!(
        erasing.await.unwrap(),
        Err(MobileAppError::CountersNotRemoved)
    );
    assert_eq!(core.lifecycle(), MobileAppLifecycle::Idle);
    assert_eq!(starts_announced(&hooks), 0);
}

#[tokio::test]
async fn an_erase_queued_behind_a_stop_finds_the_core_stopped() {
    let (core, hooks) = gated();
    let starting = start_held(&core, 3).await;
    let app = core.core.clone();
    let stopping = tokio::spawn(async move { app.stop().await });
    still_waiting(&[&stopping]).await;
    let app = core.core.clone();
    let erasing = tokio::spawn(async move { app.erase(false).await });
    still_waiting(&[&erasing]).await;

    hooks.start_gate.as_ref().unwrap().add_permits(1);
    starting.await.unwrap().unwrap();
    stopping.await.unwrap();
    assert_eq!(erasing.await.unwrap(), Err(MobileAppError::Stopped));
}
