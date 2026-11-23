//! The peer, conversation and channel commands, over a running core with
//! no radio.

use super::test_support::{Core, NOW_MS};
use super::{MobileAppChangesRecord, MobileAppError, mesh_error};
use crate::radio_driver::{MobileRadioPhase, MobileRadioStateRecord};
use crate::store::{MobilePeerUpsertRecord, MobileStoredChannelKind, MobileStoredNodeKind};
use crate::ulcp::UlcpHostOwnership;
use crate::{
    ChannelKindRecord, IdentitySignatureState, MobileMeshError, NodeIdentityProfileRecord,
    SecretVaultError,
};

/// The phone's identity secret.
const PHONE: u8 = 0x31;

fn address_of(seed: u8) -> String {
    super::test_support::identity(seed)
        .public_identity()
        .canonical_address
}

/// A running core with no radio, and its owner.
async fn running() -> (Core, String) {
    let core = Core::new();
    let owner = core.start(PHONE).await.canonical_address;
    core.core.poll_changes();
    (core, owner)
}

/// The conversation address a name's channel is kept under.
fn named_address(name: &str) -> String {
    let key = crate::inspect_channel_name(name.to_owned()).unwrap().key;
    crate::channel_conversation_address(key).unwrap()
}

/// Whether the running session holds the channel kept under `address`.
async fn session_holds(core: &Core, address: &str) -> bool {
    let session = core.session().await.unwrap();
    session
        .request_identity_by_hint(address.to_owned(), vec![1, 2, 3])
        .await
        != Err(MobileMeshError::UnknownConversation)
}

/// Refresh the channels on the worker, then run the pass.
async fn refresh(core: &Core) {
    core.core
        .on_worker(|worker| async move {
            worker.refresh_channels().await;
            worker.policy_triggered();
            Ok(())
        })
        .await
        .unwrap();
}

/// The ceiling the core registered a channel under, when it did.
async fn registered_ceiling(core: &Core, id: &str) -> Option<Option<u8>> {
    let id = id.to_owned();
    core.core
        .on_worker(
            move |worker| async move { Ok(worker.channels.borrow().registered_ceiling(&id)) },
        )
        .await
        .unwrap()
}

fn channel_id_named(core: &Core, owner: &str, canonical: &str) -> String {
    core.store
        .channels(owner.to_owned())
        .unwrap()
        .into_iter()
        .find(|channel| channel.canonical_name.as_deref() == Some(canonical))
        .unwrap()
        .id
}

/// Join named channels until the session's table is full; answers how
/// many fit.
async fn fill_the_table(core: &Core) -> usize {
    for index in 0..64 {
        match core
            .core
            .join_channel(format!("filler {index}"), None, false)
            .await
        {
            Ok(_) => {}
            Err(MobileAppError::ChannelTableFull) => return index,
            Err(error) => panic!("{error:?}"),
        }
    }
    panic!("the table never filled");
}

/// A message in a conversation's transcript, written as the chat store
/// would.
fn message_in(core: &Core, owner: &str, address: &str) {
    rusqlite::Connection::open(core.directory.path().join("app.sqlite"))
        .unwrap()
        .execute(
            "INSERT INTO chat_message (owner_identity_id, session_id, handle,
                conversation_address, direction, body, created_at_ms)
            VALUES (?, 's', 1, ?, 0, 'hello', 30)",
            rusqlite::params![owner, address],
        )
        .unwrap();
}

fn changes(core: &Core) -> MobileAppChangesRecord {
    core.core.poll_changes()
}

// --- Channels. ---

#[tokio::test]
async fn a_join_stores_the_key_and_the_row_and_registers_the_channel() {
    let (core, owner) = running().await;
    let joined = core
        .core
        .join_channel("Ridge Crew".into(), Some("  Crew ".into()), false)
        .await
        .unwrap();
    assert_eq!(joined.conversation_address, None);
    let key = crate::inspect_channel_name("Ridge Crew".into())
        .unwrap()
        .key;
    assert!(core.vault.accounts().contains(&joined.channel_id));
    let row = core
        .store
        .channel_by_id(&owner, &joined.channel_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.kind, MobileStoredChannelKind::Named);
    assert_eq!(row.canonical_name.as_deref(), Some("ridge crew"));
    assert_eq!(row.name.as_deref(), Some("Ridge Crew"));
    assert_eq!(row.alias.as_deref(), Some("Crew"));
    assert!(row.joined_phone && !row.notifications_enabled);
    assert_eq!(row.joined_at_ms, Some(NOW_MS));
    assert!(changes(&core).channels_changed);
    let address = crate::channel_conversation_address(key).unwrap();
    assert!(session_holds(&core, &address).await);
}

#[tokio::test]
async fn a_join_that_opens_its_conversation_answers_with_it() {
    let (core, owner) = running().await;
    let joined = core
        .core
        .join_channel("Ridge Crew".into(), None, true)
        .await
        .unwrap();
    let address = named_address("Ridge Crew");
    assert_eq!(
        joined.conversation_address.as_deref(),
        Some(address.as_str())
    );
    let changes = changes(&core);
    assert!(changes.channels_changed && changes.conversations_changed);
    let state = core.core.state(false).unwrap();
    assert!(
        state
            .channel_conversations
            .iter()
            .any(|conversation| conversation.conversation_address == address
                && conversation.channel.owner_identity_id == owner)
    );
}

#[tokio::test]
async fn a_join_the_session_refuses_is_taken_back() {
    let (core, owner) = running().await;
    let fitted = fill_the_table(&core).await;
    assert!(fitted > 0);
    let refused = crate::inspect_channel_name(format!("filler {fitted}")).unwrap();
    assert_eq!(
        core.store
            .channel(
                owner.clone(),
                crate::channel_key_digest(refused.key.clone())
            )
            .unwrap(),
        None,
        "the refused row went"
    );
    // Public, EMERGENCY and those that fit: one key each, nothing more.
    let rows = core.store.channels(owner).unwrap();
    assert_eq!(rows.len(), fitted + 2);
    assert_eq!(core.vault.accounts().len(), fitted + 2);
    // A refresh, run again, does not register what was taken back.
    refresh(&core).await;
    let address = crate::channel_conversation_address(refused.key).unwrap();
    assert!(!session_holds(&core, &address).await);
}

#[tokio::test]
async fn a_held_key_keeps_its_settings_and_fills_what_it_lacks() {
    let (core, owner) = running().await;
    let first = core
        .core
        .join_channel("Ridge".into(), Some("Mine".into()), false)
        .await
        .unwrap();
    core.core
        .set_channel_routing(first.channel_id.clone(), vec![0x5553], None)
        .await
        .unwrap();
    let key = crate::inspect_channel_name("Ridge".into()).unwrap().key;
    let invitation = crate::format_channel_invitation(
        key,
        Some("Ridge".into()),
        None,
        Some(4),
        Some(vec![0x12, 0x34]),
    )
    .unwrap();
    let again = core
        .core
        .join_channel(invitation, None, false)
        .await
        .unwrap();
    assert_eq!(again.channel_id, first.channel_id);
    let row = core
        .store
        .channel_by_id(&owner, &first.channel_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.alias.as_deref(), Some("Mine"), "an empty alias keeps");
    assert_eq!(
        row.region_code,
        Some(vec![0x55, 0x53]),
        "the region it had stays"
    );
    assert_eq!(
        row.max_flood_hops,
        Some(4),
        "the ceiling it lacked is filled"
    );
    assert_eq!(
        registered_ceiling(&core, &first.channel_id).await,
        Some(Some(4))
    );
}

#[tokio::test]
async fn two_joins_of_one_key_make_one_channel() {
    let (core, owner) = running().await;
    let before = core.store.channels(owner.clone()).unwrap().len();
    let (first, second) = tokio::join!(
        core.core.join_channel("Ridge".into(), None, false),
        core.core.join_channel("ridge".into(), None, true),
    );
    assert_eq!(
        first.unwrap().channel_id,
        second.as_ref().unwrap().channel_id
    );
    assert_eq!(
        second.unwrap().conversation_address,
        Some(named_address("ridge"))
    );
    assert_eq!(core.store.channels(owner).unwrap().len(), before + 1);
}

#[tokio::test]
async fn a_join_with_the_vault_unavailable_writes_nothing() {
    let (core, owner) = running().await;
    let before = core.store.channels(owner.clone()).unwrap();
    core.vault.set_unavailable(true);
    assert_eq!(
        core.core.join_channel("Ridge".into(), None, false).await,
        Err(MobileAppError::Vault {
            error: SecretVaultError::Unavailable
        })
    );
    assert_eq!(core.store.channels(owner).unwrap(), before);
}

#[tokio::test]
async fn a_private_channel_is_made_with_a_key_no_answer_carries() {
    let (core, owner) = running().await;
    assert_eq!(
        core.core.create_private_channel("  ".into()).await,
        Err(MobileAppError::InvalidRequest)
    );
    let id = core
        .core
        .create_private_channel(" Ops ".into())
        .await
        .unwrap();
    let row = core.store.channel_by_id(&owner, &id).unwrap().unwrap();
    assert_eq!(row.kind, MobileStoredChannelKind::PrivateKey);
    assert_eq!(row.name.as_deref(), Some("Ops"));
    assert_eq!(row.alias, None);
    assert!(row.joined_phone);
    use crate::secret_vault::SecretVault as _;
    let key = core.vault.load(id.clone()).unwrap().unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(registered_ceiling(&core, &id).await, Some(None));
    // Only the invitation carries it, because it is the key.
    let invitation = core.core.channel_invitation(id).await.unwrap();
    let preview = crate::inspect_channel_uri(invitation).unwrap();
    assert_eq!(preview.kind, ChannelKindRecord::PrivateKey);
    assert_eq!(preview.key, key);
    assert_eq!(preview.display_name.as_deref(), Some("Ops"));
}

#[tokio::test]
async fn leaving_a_private_channel_takes_its_row_key_and_history() {
    let (core, owner) = running().await;
    let id = core
        .core
        .create_private_channel("Ops".into())
        .await
        .unwrap();
    let address = core
        .core
        .open_channel_conversation(id.clone())
        .await
        .unwrap();
    message_in(&core, &owner, &address);
    assert!(session_holds(&core, &address).await);
    changes(&core);

    core.core.leave_channel(id.clone()).await.unwrap();
    assert_eq!(core.store.channel_by_id(&owner, &id).unwrap(), None);
    assert!(!core.vault.accounts().contains(&id));
    assert_eq!(
        core.store
            .chat_message_count(owner.clone(), address.clone())
            .unwrap(),
        0
    );
    assert!(
        core.store
            .channel_conversation_by_address(&owner, &address)
            .unwrap()
            .is_none()
    );
    let changes = changes(&core);
    assert!(changes.channels_changed && changes.conversations_changed);
    assert_eq!(changes.transcripts, vec![address.clone()]);
    assert!(!session_holds(&core, &address).await, "no longer decrypted");
    assert_eq!(
        core.core.leave_channel(id).await,
        Err(MobileAppError::NotFound)
    );
}

#[tokio::test]
async fn the_radio_s_membership_keeps_no_row() {
    let (core, owner) = running().await;
    let joined = core
        .core
        .join_channel("Ridge".into(), None, false)
        .await
        .unwrap();
    // A row the radio is marked as holding: leaving deletes it all the same.
    core.store
        .set_channel_membership(joined.channel_id.clone(), true, true, NOW_MS)
        .unwrap();
    core.core
        .leave_channel(joined.channel_id.clone())
        .await
        .unwrap();
    assert_eq!(
        core.store
            .channel_by_id(&owner, &joined.channel_id)
            .unwrap(),
        None
    );
    assert!(!core.vault.accounts().contains(&joined.channel_id));
}

#[tokio::test]
async fn a_left_channel_s_key_is_not_read_at_the_next_start() {
    let (core, owner) = running().await;
    for name in ["public", "emergency"] {
        let id = channel_id_named(&core, &owner, name);
        core.core.leave_channel(id).await.unwrap();
    }
    core.core.stop().await;
    let next = core.relaunched();
    core.vault.set_locked(true);
    next.start(super::test_support::identity(PHONE))
        .await
        .unwrap();
    let public = channel_id_named(&core, &owner, "public");
    let (state, locked, incomplete) = next
        .on_worker(move |worker| async move {
            let report = worker.refresh_channels().await;
            let cache = worker.channels.borrow();
            Ok((report.state(&public), cache.locked, cache.incomplete))
        })
        .await
        .unwrap();
    assert_eq!(state, super::channels::ChannelState::NotJoined);
    assert!(!locked, "no key was read");
    assert!(!incomplete);
}

#[tokio::test]
async fn a_built_in_channel_stays_to_be_joined_again() {
    let (core, owner) = running().await;
    let public = channel_id_named(&core, &owner, "public");
    let address = named_address("public");
    assert!(
        core.store
            .channel_conversation_by_address(&owner, &address)
            .unwrap()
            .is_some()
    );
    core.core.leave_channel(public.clone()).await.unwrap();
    let row = core.store.channel_by_id(&owner, &public).unwrap().unwrap();
    assert!(!row.joined_phone);
    assert!(core.vault.accounts().contains(&public));
    assert!(
        core.store
            .channel_conversation_by_address(&owner, &address)
            .unwrap()
            .is_none()
    );
    assert!(!session_holds(&core, &address).await);
    assert_eq!(
        core.core.open_channel_conversation(public.clone()).await,
        Err(MobileAppError::InvalidRequest),
        "a left channel has no conversation to open"
    );
    changes(&core);

    core.core.rejoin_channel(public.clone()).await.unwrap();
    assert!(
        core.store
            .channel_by_id(&owner, &public)
            .unwrap()
            .unwrap()
            .joined_phone
    );
    assert!(session_holds(&core, &address).await);
    assert!(
        core.store
            .channel_conversation_by_address(&owner, &address)
            .unwrap()
            .is_some(),
        "Public's conversation returns"
    );
    let changes_now = changes(&core);
    assert!(changes_now.channels_changed && changes_now.conversations_changed);
    // Already joined.
    core.core.rejoin_channel(public.clone()).await.unwrap();

    // Left and joined again with its conversation still open: nothing
    // opened.
    core.store
        .set_channel_joined_phone(&public, false, NOW_MS)
        .unwrap();
    core.core.rejoin_channel(public).await.unwrap();
    let changes_now = changes(&core);
    assert!(changes_now.channels_changed && !changes_now.conversations_changed);
}

#[tokio::test]
async fn only_public_s_rejoin_brings_its_conversation_back() {
    let (core, owner) = running().await;
    let public = named_address("public");
    core.core.delete_conversation(public.clone()).await.unwrap();
    let emergency = channel_id_named(&core, &owner, "emergency");
    core.core.leave_channel(emergency.clone()).await.unwrap();
    changes(&core);

    core.core.rejoin_channel(emergency.clone()).await.unwrap();
    assert!(
        core.store
            .channel_conversation_by_address(&owner, &public)
            .unwrap()
            .is_none(),
        "a deleted conversation stays deleted"
    );
    assert!(!changes(&core).conversations_changed);
    core.core.leave_channel(emergency).await.unwrap();
    core.core
        .join_channel("EMERGENCY".into(), None, false)
        .await
        .unwrap();
    assert!(
        core.store
            .channel_conversation_by_address(&owner, &public)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn opening_an_open_conversation_changes_nothing() {
    let (core, owner) = running().await;
    let public = channel_id_named(&core, &owner, "public");
    changes(&core);
    assert_eq!(
        core.core.open_channel_conversation(public).await,
        Ok(named_address("public"))
    );
    assert!(!changes(&core).conversations_changed);
}

#[tokio::test]
async fn a_leave_with_the_vault_unavailable_succeeds_and_keeps_the_key() {
    let (core, owner) = running().await;
    let id = core
        .core
        .create_private_channel("Ops".into())
        .await
        .unwrap();
    core.vault.set_unavailable(true);
    core.core.leave_channel(id.clone()).await.unwrap();
    assert_eq!(core.store.channel_by_id(&owner, &id).unwrap(), None);
    core.vault.set_unavailable(false);
    assert!(
        core.vault.accounts().contains(&id),
        "the key waits for erase"
    );
}

#[tokio::test]
async fn a_refused_rejoin_leaves_the_channel_left() {
    let (core, owner) = running().await;
    let public = channel_id_named(&core, &owner, "public");
    let emergency = channel_id_named(&core, &owner, "emergency");
    core.core.leave_channel(public.clone()).await.unwrap();
    fill_the_table(&core).await;
    assert_eq!(
        core.core.rejoin_channel(public.clone()).await,
        Err(MobileAppError::ChannelTableFull)
    );
    assert!(
        !core
            .store
            .channel_by_id(&owner, &public)
            .unwrap()
            .unwrap()
            .joined_phone
    );

    core.core.leave_channel(emergency.clone()).await.unwrap();
    core.vault.set_locked(true);
    assert_eq!(
        core.core.rejoin_channel(emergency.clone()).await,
        Err(MobileAppError::Vault {
            error: SecretVaultError::Unavailable
        })
    );
    assert!(
        !core
            .store
            .channel_by_id(&owner, &emergency)
            .unwrap()
            .unwrap()
            .joined_phone
    );
}

/// A refusal the refresh counts as complete (the key is gone) still has
/// its rollback reach the cache: tests stop arriving silently in a channel
/// left again.
#[tokio::test]
async fn a_rollback_reaches_the_cache() {
    use crate::secret_vault::SecretVault;

    async fn silent_tests_in(core: &Core) -> Option<Option<String>> {
        core.core
            .on_worker(|worker| async move { Ok(worker.channels.borrow().silent_tests_in.clone()) })
            .await
            .unwrap()
    }

    let (core, owner) = running().await;
    core.core
        .set_policy(super::MobileAppPolicyRecord {
            advert_interval_seconds: 0,
            beacon_interval_seconds: 0,
            discoverable: false,
            flood_hops: 1,
            beacon_flood_hops: 0,
            location_precision: None,
            test_message_alerts: false,
        })
        .await
        .unwrap();
    let emergency = channel_id_named(&core, &owner, "emergency");
    let address = named_address("emergency");
    assert_eq!(silent_tests_in(&core).await, Some(Some(address)));
    core.core.leave_channel(emergency.clone()).await.unwrap();
    assert_eq!(silent_tests_in(&core).await, Some(None));

    // The rejoin's refresh counts EMERGENCY joined before its key turns
    // out gone.
    core.vault.delete(emergency.clone()).unwrap();
    assert_eq!(
        core.core.rejoin_channel(emergency).await,
        Err(MobileAppError::Vault {
            error: SecretVaultError::Failed
        })
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while silent_tests_in(&core).await != Some(None) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "never: the pass takes the rollback in"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn a_changed_ceiling_is_restated_and_bad_routing_refused() {
    let (core, owner) = running().await;
    let id = core
        .core
        .join_channel("Ridge".into(), None, false)
        .await
        .unwrap()
        .channel_id;
    assert_eq!(registered_ceiling(&core, &id).await, Some(None));
    core.core
        .set_channel_routing(id.clone(), vec![0x5553], Some(3))
        .await
        .unwrap();
    let row = core.store.channel_by_id(&owner, &id).unwrap().unwrap();
    assert_eq!(row.region_code, Some(vec![0x55, 0x53]));
    assert_eq!(row.max_flood_hops, Some(3));
    assert_eq!(registered_ceiling(&core, &id).await, Some(Some(3)));
    assert!(changes(&core).channels_changed);

    for (regions, hops) in [(vec![1, 2], None), (vec![], Some(16))] {
        assert_eq!(
            core.core
                .set_channel_routing(id.clone(), regions, hops)
                .await,
            Err(MobileAppError::InvalidRequest)
        );
    }
    let public = channel_id_named(&core, &owner, "public");
    assert_eq!(
        core.core
            .set_channel_routing(public.clone(), vec![], Some(3))
            .await,
        Err(MobileAppError::InvalidRequest),
        "the protocol fixes Public's"
    );
    core.core
        .set_channel_routing(public, vec![0x5553], None)
        .await
        .unwrap();
    assert_eq!(
        core.core
            .set_channel_routing("00000000-0000-4000-8000-000000000000".into(), vec![], None)
            .await,
        Err(MobileAppError::NotFound)
    );
}

#[tokio::test]
async fn the_alias_and_notifications_are_the_user_s() {
    let (core, owner) = running().await;
    let id = core
        .core
        .join_channel("Ridge".into(), Some("Mine".into()), false)
        .await
        .unwrap()
        .channel_id;
    changes(&core);
    core.core
        .set_channel_notifications(id.clone(), true)
        .await
        .unwrap();
    core.core
        .set_channel_alias(id.clone(), Some("  ".into()))
        .await
        .unwrap();
    let row = core.store.channel_by_id(&owner, &id).unwrap().unwrap();
    assert!(row.notifications_enabled);
    assert_eq!(row.alias, None, "an empty alias clears");
    assert!(changes(&core).channels_changed);
}

#[tokio::test]
async fn a_removed_row_s_channel_leaves_the_session() {
    let (core, _) = running().await;
    let id = core
        .core
        .join_channel("Ridge".into(), None, false)
        .await
        .unwrap()
        .channel_id;
    let address = named_address("Ridge");
    assert!(session_holds(&core, &address).await);
    core.store.delete_channel(id.clone()).unwrap();
    refresh(&core).await;
    assert!(!session_holds(&core, &address).await);
    assert_eq!(registered_ceiling(&core, &id).await, None);
}

#[tokio::test]
async fn refreshes_never_leave_the_session_holding_a_channel_with_no_row() {
    let (core, owner) = running().await;
    let fitted = fill_the_table(&core).await;
    // Joins the session refuses, each beside a pass.
    for attempt in 0..4 {
        let name = format!("refused {attempt}");
        let (joined, ()) = tokio::join!(
            core.core.join_channel(name.clone(), None, false),
            refresh(&core),
        );
        assert_eq!(joined, Err(MobileAppError::ChannelTableFull));
        assert!(!session_holds(&core, &named_address(&name)).await);
    }
    assert_eq!(core.store.channels(owner).unwrap().len(), fitted + 2);
}

#[tokio::test]
async fn an_invitation_carries_what_the_channel_shares() {
    let (core, owner) = running().await;
    let id = core
        .core
        .join_channel("Ridge".into(), Some("Mine".into()), false)
        .await
        .unwrap()
        .channel_id;
    core.core
        .set_channel_routing(id.clone(), vec![0x5553], Some(4))
        .await
        .unwrap();
    let invitation = core.core.channel_invitation(id.clone()).await.unwrap();
    assert!(!invitation.contains("Mine"), "the alias never travels");
    let preview = crate::inspect_channel_uri(invitation).unwrap();
    assert_eq!(preview.kind, ChannelKindRecord::NamedPublic);
    assert_eq!(preview.display_name.as_deref(), Some("Ridge"));
    assert_eq!(preview.max_flood_hops, Some(4));
    assert_eq!(preview.region, Some(vec![0x55, 0x53]));

    // A display name that is not the channel's name travels as one, and
    // the URI still names the channel the key is derived from.
    let shared = crate::format_channel_invitation(
        Vec::new(),
        Some("ridge crew".into()),
        Some("Ridge Crew North".into()),
        None,
        None,
    )
    .unwrap();
    let crew = core
        .core
        .join_channel(shared.clone(), None, false)
        .await
        .unwrap()
        .channel_id;
    let preview =
        crate::inspect_channel_uri(core.core.channel_invitation(crew).await.unwrap()).unwrap();
    let original = crate::inspect_channel_uri(shared).unwrap();
    assert_eq!(preview.canonical_name.as_deref(), Some("ridge crew"));
    assert_eq!(preview.key, original.key);
    assert_eq!(preview.display_name.as_deref(), Some("Ridge Crew North"));

    // A ceiling the protocol fixes is not restated.
    for name in ["public", "emergency"] {
        let built_in = channel_id_named(&core, &owner, name);
        core.store
            .update_channel_details(built_in.clone(), None, None, Some(4), false)
            .unwrap();
        let preview =
            crate::inspect_channel_uri(core.core.channel_invitation(built_in).await.unwrap())
                .unwrap();
        assert_eq!(preview.canonical_name.as_deref(), Some(name));
        assert_eq!(preview.max_flood_hops, None);
    }

    // A named channel's key is its name's: no vault read.
    let private = core
        .core
        .create_private_channel("Ops".into())
        .await
        .unwrap();
    core.vault.set_locked(true);
    core.core.channel_invitation(id).await.unwrap();
    assert_eq!(
        core.core.channel_invitation(private).await,
        Err(MobileAppError::Vault {
            error: SecretVaultError::Unavailable
        })
    );
}

#[tokio::test]
async fn opening_a_conversation_reads_the_cache_and_falls_back_once() {
    let (core, owner) = running().await;
    let id = core
        .core
        .join_channel("Ridge".into(), None, false)
        .await
        .unwrap()
        .channel_id;
    core.vault.set_locked(true);
    let address = core
        .core
        .open_channel_conversation(id.clone())
        .await
        .unwrap();
    assert_eq!(address, named_address("Ridge"));
    assert!(changes(&core).conversations_changed);
    assert_eq!(
        core.core
            .open_channel_conversation("00000000-0000-4000-8000-000000000000".into())
            .await,
        Err(MobileAppError::NotFound)
    );

    // A channel whose key was never read this session, with the vault
    // locked, has no address to give.
    let key = crate::inspect_channel_name("Other".into()).unwrap().key;
    let other = "00000000-0000-4000-8000-0000000000AA".to_owned();
    core.store
        .insert_channel(
            crate::store::MobileStoredChannelRecord {
                id: other.clone(),
                owner_identity_id: owner,
                kind: MobileStoredChannelKind::Named,
                canonical_name: Some("other".into()),
                name: Some("Other".into()),
                alias: None,
                channel_id_hex: "0000".into(),
                tint: vec![0, 0, 0],
                region_code: None,
                max_flood_hops: None,
                joined_phone: true,
                joined_device: false,
                notifications_enabled: false,
                joined_at_ms: None,
            },
            crate::channel_key_digest(key.clone()),
            NOW_MS,
        )
        .unwrap();
    use crate::secret_vault::SecretVault as _;
    core.vault.store(other.clone(), key).unwrap();
    assert_eq!(
        core.core.open_channel_conversation(other.clone()).await,
        Err(MobileAppError::Vault {
            error: SecretVaultError::Unavailable
        })
    );
    core.vault.set_locked(false);
    assert_eq!(
        core.core.open_channel_conversation(other).await,
        Ok(named_address("Other"))
    );
}

// --- Peers and conversations. ---

/// A bundle for `seed`'s node, signed or not, with a name and a timestamp.
async fn bundle(seed: u8, name: &str, timestamp: Option<u32>, signed: bool) -> Vec<u8> {
    let profile = NodeIdentityProfileRecord {
        role_code: 2,
        capability_bits: 0,
        name: Some(name.to_owned()),
        latitude: None,
        longitude: None,
        location_precision: None,
        altitude_m: None,
        timestamp,
    };
    if signed {
        return crate::sign_node_identity_bundle(vec![seed; 32], profile)
            .await
            .unwrap();
    }
    let payload = umsh_node::NodeIdentityPayload {
        role: umsh_node::NodeRole::from_byte(profile.role_code),
        capabilities: umsh_node::NodeCapabilities::empty(),
        name: profile.name,
        location: None,
        altitude_m: None,
        timestamp,
        supported_regions: None,
        nonce: None,
        signature: None,
    };
    let mut buf = [0u8; 192];
    let len = payload.encode(&mut buf).unwrap();
    buf[..len].to_vec()
}

async fn link(seed: u8, name: &str, timestamp: Option<u32>, signed: bool) -> String {
    crate::node_uri_with_identity(
        address_of(seed),
        bundle(seed, name, timestamp, signed).await,
    )
    .unwrap()
}

fn heard(core: &Core, owner: &str, seed: u8, payload: Vec<u8>, name: &str) {
    core.store
        .upsert_peer(
            owner.to_owned(),
            address_of(seed),
            MobilePeerUpsertRecord {
                advertised_name: Some(name.to_owned()),
                node_kind: Some(MobileStoredNodeKind::Repeater),
                advertisement: Some(payload),
                advertisement_authenticated: true,
                advertisement_received_at_ms: Some(NOW_MS),
                ..MobilePeerUpsertRecord::default()
            },
        )
        .unwrap();
}

#[tokio::test]
async fn a_link_replaces_a_stored_identity_only_when_signed_and_newer() {
    let peer = 0x41;
    let link_record = |payload: Vec<u8>| crate::NodeUriPreviewRecord {
        canonical_address: address_of(peer),
        hint: crate::inspect_public_identity(address_of(peer))
            .unwrap()
            .hint,
        has_identity_data: true,
        identity: crate::decode_node_identity(address_of(peer), payload.clone()).ok(),
        identity_payload: Some(payload),
    };
    let stored = |payload: Option<Vec<u8>>| crate::MobileStoredNodeRecord {
        id: 1,
        owner_identity_id: String::new(),
        public_address: address_of(peer),
        alias: None,
        advertised_name: None,
        system_role: None,
        node_kind: None,
        advertisement: payload,
        advertisement_authenticated: false,
        last_heard_at_ms: None,
        is_saved: false,
        is_favorite: false,
        on_device_identity: false,
        notify_when_heard: false,
        advertisement_received_at_ms: None,
    };
    let replaces = |stored: Option<&crate::MobileStoredNodeRecord>, link: Vec<u8>| {
        super::pipeline::link_identity_replaces(stored, &link_record(link))
    };
    let signed_new = bundle(peer, "New", Some(200), true).await;
    let signed_old = bundle(peer, "Old", Some(100), true).await;
    let signed_undated = bundle(peer, "Undated", None, true).await;
    let unsigned_new = bundle(peer, "Unsigned", Some(300), false).await;
    assert_eq!(
        crate::decode_node_identity(address_of(peer), unsigned_new.clone())
            .unwrap()
            .signature,
        IdentitySignatureState::Unsigned
    );

    // Nothing stored: any bundle that may be stored.
    assert!(replaces(None, unsigned_new.clone()));
    assert!(replaces(Some(&stored(None)), signed_undated.clone()));
    // A stored bundle: only a signed, dated, newer one.
    let held = stored(Some(signed_old.clone()));
    assert!(replaces(Some(&held), signed_new.clone()));
    assert!(!replaces(Some(&held), signed_old.clone()), "the same age");
    assert!(!replaces(Some(&held), unsigned_new.clone()));
    assert!(!replaces(Some(&held), signed_undated.clone()));
    assert!(!replaces(Some(&stored(Some(signed_new))), signed_old));
    // A stored bundle with no timestamp gives way to a dated one.
    assert!(replaces(
        Some(&stored(Some(signed_undated))),
        bundle(peer, "Dated", Some(1), true).await
    ));
}

#[tokio::test]
async fn saving_a_stale_link_keeps_the_heard_identity() {
    let (core, owner) = running().await;
    let peer = 0x42;
    let heard_bundle = bundle(peer, "Heard", Some(500), true).await;
    heard(&core, &owner, peer, heard_bundle.clone(), "Heard");
    let address = core
        .core
        .save_peer(
            link(peer, "Stale", Some(100), true).await,
            Some(" Pal ".into()),
            false,
        )
        .await
        .unwrap();
    assert_eq!(address, address_of(peer));
    let node = core.store.node(&owner, &address).unwrap().unwrap();
    assert!(node.is_saved);
    assert_eq!(node.alias.as_deref(), Some("Pal"));
    assert_eq!(node.advertised_name.as_deref(), Some("Heard"));
    assert_eq!(node.node_kind, Some(MobileStoredNodeKind::Repeater));
    assert_eq!(node.advertisement, Some(heard_bundle));
    assert!(node.advertisement_authenticated);
    assert_eq!(node.advertisement_received_at_ms, Some(NOW_MS));
    assert!(changes(&core).peers_changed);
    assert!(
        core.store
            .direct_conversation_id(&owner, &address)
            .unwrap()
            .is_none(),
        "no conversation unless asked"
    );

    // A newer signed card replaces it, as one identity.
    let newer = bundle(peer, "Newer", Some(900), true).await;
    core.core
        .save_peer(
            crate::node_uri_with_identity(address.clone(), newer.clone()).unwrap(),
            None,
            false,
        )
        .await
        .unwrap();
    let node = core.store.node(&owner, &address).unwrap().unwrap();
    assert_eq!(node.advertised_name.as_deref(), Some("Newer"));
    assert_eq!(node.node_kind, Some(MobileStoredNodeKind::Chat));
    assert_eq!(node.advertisement, Some(newer));
    assert!(!node.advertisement_authenticated);
    assert_eq!(node.advertisement_received_at_ms, None);
    assert_eq!(node.alias.as_deref(), Some("Pal"), "no alias keeps it");
}

#[tokio::test]
async fn saving_with_a_conversation_opens_it_and_this_phone_is_refused() {
    let (core, owner) = running().await;
    assert_eq!(
        core.core.save_peer(owner.clone(), None, false).await,
        Err(MobileAppError::InvalidRequest)
    );
    let address = core
        .core
        .save_peer(link(0x43, "Pal", Some(1), false).await, None, true)
        .await
        .unwrap();
    assert!(
        core.store
            .direct_conversation_id(&owner, &address)
            .unwrap()
            .is_some()
    );
    let node = core.store.node(&owner, &address).unwrap().unwrap();
    assert_eq!(
        node.advertised_name.as_deref(),
        Some("Pal"),
        "unsigned over none"
    );
    let changes = changes(&core);
    assert!(changes.peers_changed && changes.conversations_changed);
    assert!(matches!(
        core.core
            .save_peer("not an address".into(), None, false)
            .await,
        Err(MobileAppError::InvalidInput { .. })
    ));
}

#[tokio::test]
async fn a_link_records_an_unknown_node_and_leaves_a_known_one() {
    let (core, owner) = running().await;
    assert_eq!(core.core.record_link_peer(owner.clone()).await, Ok(None));
    let peer = 0x44;
    let address = core
        .core
        .record_link_peer(link(peer, "Stranger", Some(1), true).await)
        .await
        .unwrap()
        .unwrap();
    let node = core.store.node(&owner, &address).unwrap().unwrap();
    assert!(!node.is_saved);
    assert_eq!(node.advertised_name.as_deref(), Some("Stranger"));
    assert!(changes(&core).peers_changed);

    // Known: left as it is, even by a newer link.
    core.core
        .record_link_peer(link(peer, "Newer", Some(9), true).await)
        .await
        .unwrap();
    let again = core.store.node(&owner, &address).unwrap().unwrap();
    assert_eq!(again, node);
    assert!(!changes(&core).peers_changed);
}

#[tokio::test]
async fn an_administered_device_keeps_its_kind_without_a_role() {
    let (core, owner) = running().await;
    let peer = 0x45;
    heard(
        &core,
        &owner,
        peer,
        bundle(peer, "Ridge", None, true).await,
        "Ridge",
    );
    core.core
        .save_administered_device(address_of(peer), Some("Ridge Top".into()), None)
        .await
        .unwrap();
    let node = core.store.node(&owner, &address_of(peer)).unwrap().unwrap();
    assert!(node.is_saved);
    assert_eq!(node.node_kind, Some(MobileStoredNodeKind::Repeater));
    assert_eq!(node.advertised_name.as_deref(), Some("Ridge Top"));
    assert_eq!(node.alias, None);
    core.core
        .save_administered_device(address_of(peer), None, Some(5))
        .await
        .unwrap();
    let node = core.store.node(&owner, &address_of(peer)).unwrap().unwrap();
    assert_eq!(node.node_kind, Some(MobileStoredNodeKind::Bridge));
}

#[tokio::test]
async fn peer_settings_need_a_row_and_raise_the_peers() {
    let (core, owner) = running().await;
    let stranger = address_of(0x46);
    assert_eq!(
        core.core
            .set_alias(stranger.clone(), Some("x".into()))
            .await,
        Err(MobileAppError::NotFound)
    );
    assert_eq!(
        core.core.set_favorite(stranger.clone(), true).await,
        Err(MobileAppError::NotFound)
    );
    assert_eq!(
        core.core
            .set_notify_when_heard(stranger.clone(), true)
            .await,
        Err(MobileAppError::NotFound)
    );
    assert_eq!(
        core.core.promote_peer(stranger.clone()).await,
        Err(MobileAppError::NotFound)
    );
    assert_eq!(
        core.core.demote_peer(stranger.clone()).await,
        Err(MobileAppError::NotFound)
    );
    assert_eq!(
        core.core.delete_peer(stranger.clone(), true).await,
        Err(MobileAppError::NotFound)
    );
    assert_eq!(
        core.core.start_conversation(stranger).await,
        Err(MobileAppError::NotFound)
    );

    let peer = 0x47;
    let address = address_of(peer);
    heard(
        &core,
        &owner,
        peer,
        bundle(peer, "Ridge", None, true).await,
        "Ridge",
    );
    changes(&core);
    core.core
        .set_alias(address.clone(), Some(" Pal ".into()))
        .await
        .unwrap();
    core.core
        .set_notify_when_heard(address.clone(), true)
        .await
        .unwrap();
    assert!(changes(&core).peers_changed);
    let node = core.store.node(&owner, &address).unwrap().unwrap();
    assert_eq!(node.alias.as_deref(), Some("Pal"));
    assert!(node.notify_when_heard && !node.is_saved);

    core.core.set_favorite(address.clone(), true).await.unwrap();
    assert!(core.store.node(&owner, &address).unwrap().unwrap().is_saved);
    core.core.demote_peer(address.clone()).await.unwrap();
    let node = core.store.node(&owner, &address).unwrap().unwrap();
    assert!(!node.is_saved && !node.is_favorite && node.alias.is_none());
    core.core.promote_peer(address.clone()).await.unwrap();
    assert!(core.store.node(&owner, &address).unwrap().unwrap().is_saved);
    core.core.set_alias(address.clone(), None).await.unwrap();
    assert_eq!(
        core.store.node(&owner, &address).unwrap().unwrap().alias,
        None
    );
}

#[tokio::test]
async fn a_peer_with_a_conversation_is_deleted_only_with_it() {
    let (core, owner) = running().await;
    let peer = 0x48;
    let address = address_of(peer);
    heard(
        &core,
        &owner,
        peer,
        bundle(peer, "Ridge", None, true).await,
        "Ridge",
    );
    assert_eq!(
        core.core.start_conversation(address.clone()).await,
        Ok(address.clone())
    );
    // Idempotent.
    core.core.start_conversation(address.clone()).await.unwrap();
    assert!(changes(&core).conversations_changed);
    message_in(&core, &owner, &address);

    assert_eq!(
        core.core.delete_peer(address.clone(), false).await,
        Err(MobileAppError::InvalidRequest)
    );
    assert!(core.store.node(&owner, &address).unwrap().is_some());
    core.core.delete_peer(address.clone(), true).await.unwrap();
    assert_eq!(core.store.node(&owner, &address).unwrap(), None);
    assert_eq!(
        core.store
            .chat_message_count(owner.clone(), address.clone())
            .unwrap(),
        0
    );
    let changes = changes(&core);
    assert!(changes.peers_changed && changes.conversations_changed);
    assert_eq!(changes.transcripts, vec![address]);

    // Without a conversation, alone.
    let other = address_of(0x49);
    heard(
        &core,
        &owner,
        0x49,
        bundle(0x49, "Other", None, true).await,
        "Other",
    );
    core.core.delete_peer(other.clone(), false).await.unwrap();
    assert_eq!(core.store.node(&owner, &other).unwrap(), None);
}

#[tokio::test]
async fn clearing_discovered_nodes_keeps_the_saved() {
    let (core, owner) = running().await;
    heard(
        &core,
        &owner,
        0x4A,
        bundle(0x4A, "Passing", None, true).await,
        "Passing",
    );
    heard(
        &core,
        &owner,
        0x4B,
        bundle(0x4B, "Kept", None, true).await,
        "Kept",
    );
    core.core.promote_peer(address_of(0x4B)).await.unwrap();
    changes(&core);
    core.core.clear_discovered().await.unwrap();
    assert_eq!(core.store.node(&owner, &address_of(0x4A)).unwrap(), None);
    assert!(
        core.store
            .node(&owner, &address_of(0x4B))
            .unwrap()
            .is_some()
    );
    assert!(changes(&core).peers_changed);
}

#[tokio::test]
async fn conversations_of_both_kinds_are_deleted_by_address() {
    let (core, owner) = running().await;
    let peer = 0x4C;
    let address = address_of(peer);
    heard(
        &core,
        &owner,
        peer,
        bundle(peer, "Ridge", None, true).await,
        "Ridge",
    );
    core.core.start_conversation(address.clone()).await.unwrap();
    message_in(&core, &owner, &address);
    changes(&core);

    core.core
        .delete_conversation(address.clone())
        .await
        .unwrap();
    assert!(
        core.store
            .direct_conversation_id(&owner, &address)
            .unwrap()
            .is_none()
    );
    assert!(
        core.store.node(&owner, &address).unwrap().is_some(),
        "the peer stays"
    );
    assert_eq!(
        core.store
            .chat_message_count(owner.clone(), address.clone())
            .unwrap(),
        0
    );
    let changes_now = changes(&core);
    assert!(changes_now.conversations_changed);
    assert_eq!(changes_now.transcripts, vec![address.clone()]);
    // Nothing there is not an error.
    core.core
        .delete_conversation(address.clone())
        .await
        .unwrap();

    let public = named_address("public");
    message_in(&core, &owner, &public);
    core.core.delete_conversation(public.clone()).await.unwrap();
    assert!(
        core.store
            .channel_conversation_by_address(&owner, &public)
            .unwrap()
            .is_none()
    );
    let public_id = channel_id_named(&core, &owner, "public");
    assert!(
        core.store
            .channel_by_id(&owner, &public_id)
            .unwrap()
            .unwrap()
            .joined_phone,
        "the channel stays joined"
    );
    assert_eq!(
        core.core.delete_conversation("ch:zz".into()).await,
        Err(MobileAppError::InvalidInput {
            error: crate::MobileError::InvalidAddressCharacter
        })
    );

    // A chat batch that opens the deleted conversation again is new to the
    // pass.
    let known = core
        .core
        .on_worker({
            let address = address.clone();
            move |worker| async move {
                Ok(worker
                    .pipeline
                    .borrow()
                    .known_conversations
                    .contains(&address))
            }
        })
        .await
        .unwrap();
    assert!(!known);
}

#[tokio::test]
async fn a_direct_conversation_s_notifications() {
    let (core, owner) = running().await;
    let peer = 0x4D;
    let address = address_of(peer);
    heard(
        &core,
        &owner,
        peer,
        bundle(peer, "Ridge", None, true).await,
        "Ridge",
    );
    assert_eq!(
        core.core
            .set_conversation_notifications(address.clone(), false)
            .await,
        Err(MobileAppError::NotFound)
    );
    core.core.start_conversation(address.clone()).await.unwrap();
    changes(&core);
    core.core
        .set_conversation_notifications(address.clone(), false)
        .await
        .unwrap();
    assert!(changes(&core).conversations_changed);
    let conversation = core
        .store
        .list_direct_conversations(owner)
        .unwrap()
        .into_iter()
        .find(|conversation| conversation.node.public_address == address)
        .unwrap();
    assert!(!conversation.notifications_enabled);
    assert_eq!(
        core.core
            .set_conversation_notifications(named_address("public"), false)
            .await,
        Err(MobileAppError::InvalidRequest),
        "a channel's is the channel's"
    );
}

#[tokio::test]
async fn asking_the_air_needs_this_phone_s_radio() {
    let (core, _) = running().await;
    let peer = address_of(0x4E);
    let public = named_address("public");
    let ask = || async {
        [
            core.core.fetch_identity(peer.clone()).await,
            core.core.discover(None, None, Vec::new()).await,
            core.core
                .request_member_identity(public.clone(), vec![1, 2, 3])
                .await,
        ]
    };
    for answer in ask().await {
        assert_eq!(answer, Err(MobileAppError::NoRadio));
    }
    // A radio held by another phone.
    core.core
        .on_worker(|worker| async move {
            worker.shared.publish(|snapshot| {
                snapshot.radio = Some(MobileRadioStateRecord {
                    phase: MobileRadioPhase::Attached,
                    host: UlcpHostOwnership::OtherHost,
                    ..MobileRadioStateRecord::idle()
                });
                MobileAppChangesRecord::default()
            });
            Ok(())
        })
        .await
        .unwrap();
    for answer in ask().await {
        assert_eq!(answer, Err(MobileAppError::NotThisPhone));
    }
    // Arguments are checked first.
    assert_eq!(
        core.core.discover(None, Some(vec![1]), Vec::new()).await,
        Err(MobileAppError::InvalidRequest)
    );
    assert_eq!(
        core.core.discover(None, None, vec![vec![1, 2, 3]]).await,
        Err(MobileAppError::InvalidRequest)
    );
    assert_eq!(
        core.core.request_member_identity(peer, vec![1, 2, 3]).await,
        Err(MobileAppError::InvalidRequest)
    );
    assert_eq!(
        core.core.request_member_identity(public, vec![1, 2]).await,
        Err(MobileAppError::InvalidRequest)
    );
}

/// Report a radio attached as this phone's.
async fn attached(core: &Core) {
    core.core
        .on_worker(|worker| async move {
            worker.shared.publish(|snapshot| {
                snapshot.radio = Some(MobileRadioStateRecord {
                    phase: MobileRadioPhase::Attached,
                    host: UlcpHostOwnership::Ours,
                    ..MobileRadioStateRecord::idle()
                });
                MobileAppChangesRecord::default()
            });
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn an_unnarrowed_ask_goes_once_per_cooldown() {
    let (core, _) = running().await;
    let wait = || core.core.discovery_wait_ms().unwrap();
    let ask = |role: Option<u8>, route: Vec<Vec<u8>>| core.core.discover(role, None, route);
    // Refused before the radio is asked for, so a refusal starts none.
    assert_eq!(ask(None, Vec::new()).await, Err(MobileAppError::NoRadio));
    assert_eq!(wait(), 0);
    attached(&core).await;
    // One the session refuses (more hints than a route carries) starts none
    // either.
    assert_eq!(
        ask(None, vec![vec![1, 2]; 16]).await,
        Err(MobileAppError::InvalidRequest)
    );
    assert_eq!(wait(), 0);

    ask(None, Vec::new()).await.unwrap();
    assert_eq!(wait(), 40_000);
    assert_eq!(
        ask(None, Vec::new()).await,
        Err(MobileAppError::InvalidRequest)
    );
    // Whatever its role or route.
    assert_eq!(
        ask(Some(1), vec![vec![1, 2]]).await,
        Err(MobileAppError::InvalidRequest)
    );
    // An ask narrowed to one node is not held back, and does not restart
    // the wait.
    core.clock.advance(1_000);
    core.core
        .discover(None, Some(vec![1, 2, 3]), Vec::new())
        .await
        .unwrap();
    assert_eq!(wait(), 39_000);
    // The wall clock moving does not move it.
    core.clock.set_wall(NOW_MS - 3_600_000);
    assert_eq!(wait(), 39_000);
    core.clock.advance(38_999);
    assert_eq!(wait(), 1);
    assert_eq!(
        ask(None, Vec::new()).await,
        Err(MobileAppError::InvalidRequest)
    );
    core.clock.advance(1);
    assert_eq!(wait(), 0);
    ask(None, Vec::new()).await.unwrap();
    assert_eq!(wait(), 40_000);

    core.core.stop().await;
    assert_eq!(core.core.discovery_wait_ms(), Err(MobileAppError::Stopped));
}

#[tokio::test]
async fn two_unnarrowed_asks_at_once_send_one() {
    let (core, _) = running().await;
    attached(&core).await;
    let (first, second) = tokio::join!(
        core.core.discover(None, None, Vec::new()),
        core.core.discover(Some(1), None, Vec::new()),
    );
    let mut answers = [first, second];
    answers.sort_by_key(Result::is_err);
    assert_eq!(answers, [Ok(()), Err(MobileAppError::InvalidRequest)]);
}

#[tokio::test]
async fn an_ask_held_back_by_another_s_radio_starts_no_cooldown() {
    let (core, _) = running().await;
    core.core
        .on_worker(|worker| async move {
            worker.shared.publish(|snapshot| {
                snapshot.radio = Some(MobileRadioStateRecord {
                    phase: MobileRadioPhase::Attached,
                    host: UlcpHostOwnership::OtherHost,
                    ..MobileRadioStateRecord::idle()
                });
                MobileAppChangesRecord::default()
            });
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        core.core.discover(None, None, Vec::new()).await,
        Err(MobileAppError::NotThisPhone)
    );
    assert_eq!(core.core.discovery_wait_ms().unwrap(), 0);
}

#[tokio::test]
async fn two_hops_that_share_a_hint_are_a_path() {
    let (core, _) = running().await;
    let peer = address_of(0x4E);
    let held = core
        .core
        .set_manual_path(
            peer.clone(),
            crate::mobile_mesh::MobileMeshExplicitPath {
                hints: vec![vec![0x2A, 0xE1], vec![0x2A, 0xE1]],
                flood_hops: 1,
            },
            60_000,
            None,
        )
        .await
        .unwrap();
    assert!(held);
    let route = core.core.peer_route(peer).await.unwrap();
    assert_eq!(route.hints.len(), 2);
}

#[tokio::test]
async fn a_route_says_where_an_ask_near_its_peer_can_be_steered() {
    let (core, owner) = running().await;
    let hold = |peer: String, hints: Vec<Vec<u8>>| {
        let app = core.core.clone();
        async move {
            assert!(
                app.set_manual_path(
                    peer,
                    crate::mobile_mesh::MobileMeshExplicitPath {
                        hints,
                        flood_hops: 1
                    },
                    60_000,
                    None,
                )
                .await
                .unwrap()
            );
        }
    };
    let vantage = |peer: String| {
        let app = core.core.clone();
        async move {
            app.peer_route(peer)
                .await
                .unwrap()
                .discovery_vantage
                .map(|vantage| {
                    (
                        vantage
                            .repeaters
                            .into_iter()
                            .map(|hint| hint.bytes)
                            .collect::<Vec<_>>(),
                        vantage.lands_at_peer,
                        vantage.evidence,
                    )
                })
        }
    };
    let repeater_hint =
        |peer: &str| crate::public_identity_bytes(peer.to_owned()).unwrap()[..2].to_vec();

    // Nothing learned yet.
    let unstored = address_of(0x4E);
    assert_eq!(vantage(unstored.clone()).await, None);
    // Heard directly, and nothing stored about it: asked through.
    hold(unstored.clone(), Vec::new()).await;
    assert_eq!(
        vantage(unstored.clone()).await,
        Some((
            vec![repeater_hint(&unstored)],
            true,
            super::MobileRepeaterEvidence::Unknown
        ))
    );
    // Stored as something that does not forward: not asked through, and a
    // learned path ends one short of it.
    let chat = address_of(0x4F);
    core.store
        .upsert_peer(
            owner.clone(),
            chat.clone(),
            MobilePeerUpsertRecord {
                node_kind: Some(MobileStoredNodeKind::Chat),
                ..MobilePeerUpsertRecord::default()
            },
        )
        .unwrap();
    hold(chat.clone(), Vec::new()).await;
    assert_eq!(vantage(chat.clone()).await, None);
    hold(chat.clone(), vec![vec![0x2A, 0xE1]]).await;
    assert_eq!(
        vantage(chat).await,
        Some((
            vec![vec![0x2A, 0xE1]],
            false,
            super::MobileRepeaterEvidence::No
        ))
    );
    // A stored repeater is asked at, past the path.
    let repeater = address_of(0x50);
    core.store
        .upsert_peer(
            owner,
            repeater.clone(),
            MobilePeerUpsertRecord {
                node_kind: Some(MobileStoredNodeKind::Repeater),
                ..MobilePeerUpsertRecord::default()
            },
        )
        .unwrap();
    hold(repeater.clone(), vec![vec![0x2A, 0xE1]]).await;
    assert_eq!(
        vantage(repeater.clone()).await,
        Some((
            vec![vec![0x2A, 0xE1], repeater_hint(&repeater)],
            true,
            super::MobileRepeaterEvidence::Yes
        ))
    );
}

#[tokio::test]
async fn announcement_intervals_are_held_to_the_device_bounds() {
    let (core, _) = running().await;
    let policy = |advert: u32, beacon: u32| super::MobileAppPolicyRecord {
        advert_interval_seconds: advert,
        beacon_interval_seconds: beacon,
        discoverable: true,
        flood_hops: 1,
        beacon_flood_hops: 0,
        location_precision: None,
        test_message_alerts: false,
    };
    let kept = || async {
        core.core
            .on_worker(|worker| async move {
                let settings = worker.settings.borrow();
                let policy = settings.policy.as_ref().unwrap();
                Ok((
                    policy.advert_interval_seconds,
                    policy.beacon_interval_seconds,
                ))
            })
            .await
            .unwrap()
    };
    core.core.set_policy(policy(1, 0)).await.unwrap();
    assert_eq!(kept().await, (20 * 60, 0), "nothing shorter than 20 min");
    core.core.set_policy(policy(0, u32::MAX)).await.unwrap();
    assert_eq!(kept().await, (0, 24 * 60 * 60));
    core.core.set_policy(policy(3_600, 1_800)).await.unwrap();
    assert_eq!(kept().await, (3_600, 1_800));
}

#[tokio::test]
async fn commands_need_a_running_identity() {
    let core = Core::new();
    assert_eq!(
        core.core.clear_discovered().await,
        Err(MobileAppError::NotRunning)
    );
    assert_eq!(
        core.core.join_channel("Ridge".into(), None, false).await,
        Err(MobileAppError::NotRunning)
    );
    assert_eq!(
        core.core.record_link_peer(address_of(0x50)).await,
        Err(MobileAppError::NotRunning)
    );
}

#[test]
fn a_full_table_reads_as_one() {
    assert_eq!(
        mesh_error(MobileMeshError::ChannelCapacity),
        MobileAppError::ChannelTableFull
    );
    assert_eq!(
        mesh_error(MobileMeshError::UnknownConversation),
        MobileAppError::SendFailed
    );
}

#[test]
fn the_well_known_channels() {
    use crate::{MobileWellKnownChannel, well_known_channel};
    assert_eq!(
        well_known_channel(Some("public".into())).map(|known| known.channel),
        Some(MobileWellKnownChannel::Public)
    );
    let emergency = well_known_channel(Some("emergency".into())).unwrap();
    assert_eq!(emergency.channel, MobileWellKnownChannel::Emergency);
    assert_eq!(emergency.fixed_max_flood_hops, 10);
    assert_eq!(
        well_known_channel(Some("Public".into())),
        None,
        "canonical only"
    );
    assert_eq!(well_known_channel(None), None);
}
