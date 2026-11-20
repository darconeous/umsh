use crate::secret_vault::memory::MemoryVault;
use crate::{IdentitySignatureState, decode_node_identity};

use super::*;

const OWNER: &str = "owner";
const NOW_MS: i64 = 1_790_000_000_000;

fn channel_named(store: &MobileAppStore, owner: &str, name: &str) -> MobileStoredChannelRecord {
    store
        .channels(owner.into())
        .unwrap()
        .into_iter()
        .find(|channel| channel.name.as_deref() == Some(name))
        .unwrap()
}

fn open() -> (tempfile::TempDir, Arc<MobileAppStore>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join("staging.sqlite")
        .display()
        .to_string();
    let store = MobileAppStore::open(path).unwrap();
    store
        .insert_identity(OWNER.into(), "owner-public".into(), 1)
        .unwrap();
    (directory, store)
}

async fn seeded(now_ms: i64) -> (tempfile::TempDir, Arc<MobileAppStore>, Arc<MemoryVault>) {
    let (directory, store) = open();
    let vault = Arc::new(MemoryVault::default());
    seed_staging(store.clone(), vault.clone(), OWNER.into(), now_ms)
        .await
        .unwrap();
    (directory, store, vault)
}

/// Everything the seed writes, read back through the store.
#[derive(Debug, PartialEq)]
struct Snapshot {
    nodes: Vec<crate::store::MobileStoredNodeRecord>,
    channels: Vec<MobileStoredChannelRecord>,
    direct: Vec<crate::store::MobileStoredDirectConversationRecord>,
    group: Vec<crate::store::MobileStoredChannelConversationRecord>,
    transcripts: Vec<Vec<crate::store::MobileStoredChatMessageRecord>>,
}

fn snapshot(store: &MobileAppStore) -> Snapshot {
    let owner = || OWNER.to_owned();
    let direct = store.list_direct_conversations(owner()).unwrap();
    let group = store.list_channel_conversations(owner()).unwrap();
    let addresses = direct
        .iter()
        .map(|conversation| conversation.node.public_address.clone())
        .chain(
            group
                .iter()
                .map(|conversation| conversation.conversation_address.clone()),
        );
    let transcripts = addresses
        .map(|address| {
            store
                .chat_message_page_newest(owner(), address, 100)
                .unwrap()
                .messages
        })
        .collect();
    Snapshot {
        nodes: store.list_nodes(owner()).unwrap(),
        channels: store.channels(owner()).unwrap(),
        direct,
        group,
        transcripts,
    }
}

#[tokio::test]
async fn the_staged_mesh_is_written_through_the_store() {
    let (_directory, store, vault) = seeded(NOW_MS).await;
    let state = snapshot(&store);

    assert_eq!(state.nodes.len(), NODES.len());
    let saved = state.nodes.iter().filter(|node| node.is_saved).count();
    assert_eq!(saved, 5);
    let favorites = state.nodes.iter().filter(|node| node.is_favorite).count();
    assert_eq!(favorites, 2);

    // Three one-to-one conversations, only Maya's left unread.
    assert_eq!(state.direct.len(), 3);
    for conversation in &state.direct {
        let unread = conversation.node.advertised_name.as_deref() == Some("Maya Ortiz");
        assert_eq!(conversation.unread_count > 0, unread);
    }

    // Both channels, their keys in the vault under their IDs.
    let mut ids: Vec<_> = state
        .channels
        .iter()
        .map(|channel| channel.id.clone())
        .collect();
    ids.sort();
    assert_eq!(ids.len(), 2);
    assert_eq!(vault.accounts(), ids);
    assert_eq!(
        vault
            .load(channel_named(&store, OWNER, PRIVATE_CHANNEL_NAME).id)
            .unwrap(),
        Some(PRIVATE_CHANNEL_KEY.to_vec())
    );
    assert_eq!(state.group.len(), 2);

    let lengths: Vec<_> = state.transcripts.iter().map(Vec::len).collect();
    let mut expected: Vec<_> = DIRECT_SCRIPTS
        .iter()
        .map(|script| script.lines.len())
        .collect();
    expected.extend([CHANNEL_LINES.len(), PRIVATE_CHANNEL_LINES.len()]);
    let mut sorted = lengths.clone();
    sorted.sort_unstable();
    expected.sort_unstable();
    assert_eq!(sorted, expected);

    // No conversation is newer than what was said in it, or it would sort
    // above conversations with newer messages.
    let created = state
        .direct
        .iter()
        .map(|conversation| conversation.created_at_ms)
        .chain(
            state
                .group
                .iter()
                .map(|conversation| conversation.created_at_ms),
        );
    for (created, transcript) in created.zip(&state.transcripts) {
        assert_eq!(
            Some(created),
            transcript.iter().map(|message| message.created_at_ms).min()
        );
    }

    // The newest message is four minutes old: the timeline counts back from
    // the seed's now.
    let newest = state
        .transcripts
        .iter()
        .flatten()
        .map(|message| message.created_at_ms)
        .max();
    assert_eq!(newest, Some(NOW_MS - 4 * MINUTE_MS));
}

#[tokio::test]
async fn a_staged_bundle_verifies_and_carries_its_claims() {
    let (_directory, store, _vault) = seeded(NOW_MS).await;
    let node = store
        .list_nodes(OWNER.into())
        .unwrap()
        .into_iter()
        .find(|node| node.advertised_name.as_deref() == Some("Tallac Ridge"))
        .unwrap();
    let identity = decode_node_identity(node.public_address, node.advertisement.unwrap()).unwrap();
    assert_eq!(identity.signature, IdentitySignatureState::Valid);
    assert_eq!(identity.name.as_deref(), Some("Tallac Ridge"));
    assert_eq!(identity.role_code, umsh_node::NodeRole::Repeater.as_byte());
    assert_eq!(identity.altitude_m, Some(2_967));
    assert!(identity.latitude.is_some());
    assert_eq!(
        identity.timestamp,
        Some(((NOW_MS - 2 * MINUTE_MS) / 1_000) as u32)
    );
}

#[tokio::test]
async fn a_fixed_now_reproduces_the_same_store() {
    let (_first_directory, first, _) = seeded(NOW_MS).await;
    let (_second_directory, second, _) = seeded(NOW_MS).await;
    assert_eq!(snapshot(&first), snapshot(&second));
}

#[tokio::test]
async fn seeding_again_replaces_rather_than_accumulates() {
    // A replaced message is a new row, so only its row ID may change.
    let without_row_ids = |mut state: Snapshot| {
        for message in state.transcripts.iter_mut().flatten() {
            message.row_id = 0;
        }
        state
    };
    let (_directory, store, vault) = seeded(NOW_MS).await;
    let first = without_row_ids(snapshot(&store));
    seed_staging(store.clone(), vault.clone(), OWNER.into(), NOW_MS)
        .await
        .unwrap();
    assert_eq!(without_row_ids(snapshot(&store)), first);
    assert_eq!(vault.accounts().len(), 2);
}

/// A new identity on a store an earlier one was staged in: the earlier
/// identity's channels keep their IDs, and the new one gets its own.
#[tokio::test]
async fn another_identity_is_staged_beside_the_first() {
    let (_directory, store, vault) = seeded(NOW_MS).await;
    store
        .insert_identity("other".into(), "other-public".into(), 2)
        .unwrap();
    seed_staging(store.clone(), vault.clone(), "other".into(), NOW_MS)
        .await
        .unwrap();

    let first = channel_named(&store, OWNER, CHANNEL_NAME);
    let second = channel_named(&store, "other", CHANNEL_NAME);
    assert_ne!(first.id, second.id);
    assert_eq!(
        store
            .list_channel_conversations("other".into())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(vault.accounts().len(), 4);
}

/// A store an earlier seeder filled, under an ID of its own choosing, keeps
/// that channel, and its key is restated under that ID.
#[tokio::test]
async fn a_channel_already_held_keeps_its_id() {
    let (_directory, store) = open();
    let key = umsh_node::Channel::named(CHANNEL_NAME)
        .unwrap()
        .key()
        .0
        .to_vec();
    let id = "0F8E6A52-1B3C-4D7E-9F00-112233445566".to_owned();
    store
        .insert_channel(
            MobileStoredChannelRecord {
                id: id.clone(),
                owner_identity_id: OWNER.into(),
                kind: MobileStoredChannelKind::Named,
                canonical_name: Some(CHANNEL_NAME.to_ascii_lowercase()),
                name: Some(CHANNEL_NAME.into()),
                alias: None,
                channel_id_hex: "0000".into(),
                tint: vec![0, 0, 0],
                region_code: None,
                max_flood_hops: None,
                joined_phone: true,
                joined_device: true,
                notifications_enabled: true,
                joined_at_ms: Some(1),
            },
            crate::channel_key_digest(key.clone()),
            1,
        )
        .unwrap();
    let vault = Arc::new(MemoryVault::default());
    seed_staging(store.clone(), vault.clone(), OWNER.into(), NOW_MS)
        .await
        .unwrap();

    assert_eq!(channel_named(&store, OWNER, CHANNEL_NAME).id, id);
    assert_eq!(store.channels(OWNER.into()).unwrap().len(), 2);
    assert_eq!(vault.load(id).unwrap(), Some(key));
}

/// A vault that refuses every write.
struct LockedVault;

impl SecretVault for LockedVault {
    fn load(&self, _: String) -> Result<Option<Vec<u8>>, SecretVaultError> {
        Err(SecretVaultError::Unavailable)
    }

    fn store(&self, _: String, _: Vec<u8>) -> Result<(), SecretVaultError> {
        Err(SecretVaultError::Unavailable)
    }

    fn delete(&self, _: String) -> Result<(), SecretVaultError> {
        Err(SecretVaultError::Unavailable)
    }

    fn delete_all(&self) -> Result<(), SecretVaultError> {
        Err(SecretVaultError::Unavailable)
    }
}

#[tokio::test]
async fn a_channel_whose_key_cannot_be_kept_is_not_joined() {
    let (_directory, store) = open();
    let result = seed_staging(store.clone(), Arc::new(LockedVault), OWNER.into(), NOW_MS).await;
    assert_eq!(
        result,
        Err(MobileStagingError::Vault {
            error: SecretVaultError::Unavailable
        })
    );
    assert!(store.channels(OWNER.into()).unwrap().is_empty());
}
