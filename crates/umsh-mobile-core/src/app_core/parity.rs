//! The read-mapping parity oracle: the stores the goldens were made from,
//! and the generator that writes them. See `parity/README.md`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use umsh_core::ChannelKey;
use umsh_crypto::software::SoftwareIdentity;
use umsh_node::NodeCapabilities;

use crate::mobile_chat::hex;
use crate::secret_vault::memory::MemoryVault;
use crate::store::{
    MobileAppStore, MobilePeerUpsertRecord, MobileStagedChatMessageRecord,
    MobileStagedChatReactionRecord, MobileStagedChatRegarding, MobileStoredChannelKind,
    MobileStoredChannelRecord, MobileStoredChatDeliveryState, MobileStoredChatReceptionRecord,
    MobileStoredNodeKind, MobileStoredPeerRepeaterEntryRecord, MobileStoredSystemRole,
};
use crate::{NodeIdentityProfileRecord, public_identity_record, signed_node_identity_bundle};

/// The instant both stores are written relative to.
pub(super) const NOW_MS: i64 = 1_790_000_000_000;

/// The owner `seed_staging` writes `seeded.sqlite` under.
pub(super) const SEEDED_OWNER: &str = "owner";

/// The owner the v31 fixture's rows belong to.
pub(super) const AUGMENTED_OWNER: &str = "alice";

const MINUTE_MS: i64 = 60_000;

/// Where the committed stores and goldens live.
pub(super) fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/app_core/parity")
}

/// One added peer. `counter` picks its key: the first eight bytes of the
/// secret, the rest `0x5A`. The counters were searched for so that the
/// node hints start with the bytes the matching cases need.
struct Peer {
    name: &'static str,
    counter: u64,
    /// The first bytes its node hint must start with.
    prefix: &'static [u8],
    kind: Option<MobileStoredNodeKind>,
    system_role: Option<MobileStoredSystemRole>,
    advertisement: Advertisement,
    saved: bool,
    favorite: bool,
    alias: Option<&'static str>,
    heard_minutes_ago: Option<i64>,
}

enum Advertisement {
    None,
    /// A signed bundle with this role and these capabilities.
    Signed {
        role: umsh_node::NodeRole,
        capabilities: NodeCapabilities,
    },
    /// Bytes that do not decode.
    Garbled,
}

const RIDGE: usize = 0;
const TWIN: usize = 1;
const ECHO_A: usize = 2;
const ECHO_B: usize = 3;
const SPAN: usize = 4;

const PEERS: &[Peer] = &[
    Peer {
        name: "Ridge",
        counter: 10_930,
        prefix: &[0x01, 0x02],
        kind: Some(MobileStoredNodeKind::Repeater),
        system_role: None,
        advertisement: Advertisement::Signed {
            role: umsh_node::NodeRole::Repeater,
            capabilities: NodeCapabilities::REPEATER,
        },
        saved: true,
        favorite: true,
        alias: None,
        heard_minutes_ago: Some(3),
    },
    Peer {
        name: "Twin",
        counter: 70_327,
        prefix: &[0x01, 0x02],
        kind: Some(MobileStoredNodeKind::Chat),
        system_role: None,
        advertisement: Advertisement::Signed {
            role: umsh_node::NodeRole::Chat,
            capabilities: NodeCapabilities::MOBILE.union(NodeCapabilities::TEXT_MESSAGES),
        },
        saved: false,
        favorite: false,
        alias: None,
        heard_minutes_ago: Some(40),
    },
    Peer {
        name: "Echo A",
        counter: 181_615,
        prefix: &[0x05, 0x06],
        kind: Some(MobileStoredNodeKind::Chat),
        system_role: None,
        advertisement: Advertisement::Signed {
            role: umsh_node::NodeRole::Chat,
            capabilities: NodeCapabilities::TEXT_MESSAGES,
        },
        saved: true,
        favorite: false,
        alias: Some("Echo \"the first\"\tA"),
        heard_minutes_ago: Some(12),
    },
    Peer {
        name: "Echo B",
        counter: 220_150,
        prefix: &[0x05, 0x06],
        kind: Some(MobileStoredNodeKind::Chat),
        system_role: None,
        advertisement: Advertisement::Signed {
            role: umsh_node::NodeRole::Chat,
            capabilities: NodeCapabilities::TEXT_MESSAGES,
        },
        saved: true,
        favorite: false,
        alias: None,
        heard_minutes_ago: None,
    },
    Peer {
        name: "Span",
        counter: 14_818,
        prefix: &[0x07, 0x08],
        kind: Some(MobileStoredNodeKind::Bridge),
        system_role: None,
        advertisement: Advertisement::None,
        saved: true,
        favorite: false,
        alias: Some("Span"),
        heard_minutes_ago: Some(90),
    },
    // Shares 0x0708 with Span, so the bridge wins it by its stored kind.
    Peer {
        name: "Span Twin",
        counter: 81_574,
        prefix: &[0x07, 0x08],
        kind: Some(MobileStoredNodeKind::Chat),
        system_role: None,
        advertisement: Advertisement::None,
        saved: false,
        favorite: false,
        alias: None,
        heard_minutes_ago: Some(95),
    },
    // Shares 0x0506 with the two chat nodes; its advertisement does not
    // decode, so its stored kind makes it the likely repeater.
    Peer {
        name: "Garbled",
        counter: 397_275,
        prefix: &[0x05, 0x06],
        kind: Some(MobileStoredNodeKind::Repeater),
        system_role: None,
        advertisement: Advertisement::Garbled,
        saved: false,
        favorite: false,
        alias: None,
        heard_minutes_ago: Some(200),
    },
    Peer {
        name: "Radio",
        counter: 2,
        prefix: &[],
        kind: Some(MobileStoredNodeKind::Repeater),
        system_role: Some(MobileStoredSystemRole::CompanionRadio),
        advertisement: Advertisement::None,
        saved: true,
        favorite: false,
        alias: None,
        heard_minutes_ago: Some(1),
    },
];

/// A peer with its key resolved.
struct Resolved {
    address: String,
    hint: Vec<u8>,
}

fn identity(counter: u64) -> SoftwareIdentity {
    let mut secret = [0x5A; 32];
    secret[..8].copy_from_slice(&counter.to_be_bytes());
    SoftwareIdentity::from_secret_bytes(&secret)
}

fn ago(minutes: i64) -> i64 {
    NOW_MS - minutes * MINUTE_MS
}

/// Write `seeded.sqlite` and `augmented.sqlite`. Run by hand after a
/// change to what either holds, then update the goldens to match.
#[tokio::test]
#[ignore = "writes the committed parity stores"]
async fn generate_parity_stores() {
    let scratch = tempfile::tempdir().unwrap();

    let seeded = scratch.path().join("seeded.sqlite");
    {
        let store = MobileAppStore::open(seeded.to_string_lossy().into_owned()).unwrap();
        store
            .insert_identity(SEEDED_OWNER.to_owned(), owner_address(), NOW_MS)
            .unwrap();
        crate::seed_staging(
            store,
            Arc::new(MemoryVault::default()),
            SEEDED_OWNER.to_owned(),
            NOW_MS,
        )
        .await
        .unwrap();
    }
    install(&seeded, "seeded.sqlite");

    let augmented = scratch.path().join("augmented.sqlite");
    std::fs::write(
        &augmented,
        include_bytes!("../store/swift_store_v31.sqlite"),
    )
    .unwrap();
    {
        let store = MobileAppStore::open(augmented.to_string_lossy().into_owned()).unwrap();
        augment(&store).await;
    }
    install(&augmented, "augmented.sqlite");
}

/// Write a closed store into the parity directory as one compact file,
/// its write-ahead log folded in.
fn install(path: &Path, name: &str) {
    let destination = directory().join(name);
    let _ = std::fs::remove_file(&destination);
    rusqlite::Connection::open(path)
        .unwrap()
        .execute("VACUUM INTO ?", [destination.to_string_lossy()])
        .unwrap();
}

async fn augment(store: &MobileAppStore) {
    let owner = || AUGMENTED_OWNER.to_owned();
    let mut resolved = Vec::with_capacity(PEERS.len());
    for peer in PEERS {
        let identity = identity(peer.counter);
        let public = public_identity_record(umsh_crypto::NodeIdentity::public_key(&identity));
        assert!(
            public.hint.bytes.starts_with(peer.prefix),
            "{}'s hint {:02x?} lost its prefix",
            peer.name,
            public.hint.bytes
        );
        let advertisement = match peer.advertisement {
            Advertisement::None => None,
            Advertisement::Garbled => Some(vec![0xFF, 0x00, 0x13]),
            Advertisement::Signed { role, capabilities } => Some(
                signed_node_identity_bundle(
                    &identity,
                    NodeIdentityProfileRecord {
                        role_code: role.as_byte(),
                        capability_bits: capabilities.bits(),
                        name: Some(peer.name.to_owned()),
                        latitude: Some(47.6062),
                        longitude: Some(-122.3321),
                        location_precision: Some(5),
                        altitude_m: Some(120),
                        timestamp: Some(u32::try_from(ago(60) / 1_000).unwrap()),
                    },
                )
                .await
                .unwrap(),
            ),
        };
        let received_at = advertisement.as_ref().map(|_| ago(60));
        store
            .upsert_peer(
                owner(),
                public.canonical_address.clone(),
                MobilePeerUpsertRecord {
                    alias: peer.alias.map(str::to_owned),
                    advertised_name: Some(peer.name.to_owned()),
                    is_saved: peer.saved,
                    node_kind: peer.kind,
                    system_role: peer.system_role,
                    radio_identifier: None,
                    advertisement,
                    advertisement_authenticated: true,
                    advertisement_received_at_ms: received_at,
                },
            )
            .unwrap();
        if let Some(minutes) = peer.heard_minutes_ago {
            store
                .touch_last_heard(owner(), public.canonical_address.clone(), ago(minutes))
                .unwrap();
        }
        if peer.favorite {
            store
                .set_peer_favorite(owner(), public.canonical_address.clone(), true)
                .unwrap();
        }
        resolved.push(Resolved {
            address: public.canonical_address,
            hint: public.hint.bytes,
        });
    }

    write_direct_conversations(store, &resolved);
    write_channels(store, &resolved);
    write_listings(store, &resolved);
}

fn inbound(handle: u32, body: &str, minutes_ago: i64) -> MobileStagedChatMessageRecord {
    MobileStagedChatMessageRecord {
        handle,
        body: body.to_owned(),
        outbound: false,
        created_at_ms: ago(minutes_ago),
        sender_address: None,
        sender_hint: None,
        sender_handle: None,
        delivery_state: None,
        reception: None,
        reactions: Vec::new(),
        regarding: None,
        is_deleted: false,
        wire_id: None,
        epoch: None,
    }
}

fn outbound(
    handle: u32,
    body: &str,
    minutes_ago: i64,
    state: MobileStoredChatDeliveryState,
) -> MobileStagedChatMessageRecord {
    MobileStagedChatMessageRecord {
        outbound: true,
        delivery_state: Some(state),
        ..inbound(handle, body, minutes_ago)
    }
}

fn reception(hops: u8, routes: &[[u8; 2]]) -> MobileStoredChatReceptionRecord {
    MobileStoredChatReceptionRecord {
        rssi_dbm: Some(-91),
        snr_centibels: Some(-35),
        lqi: Some(200),
        hop_count: Some(hops),
        route_hints: routes.iter().map(|hint| hint.to_vec()).collect(),
        source_authenticated: true,
    }
}

fn write_direct_conversations(store: &MobileAppStore, resolved: &[Resolved]) {
    let owner = || AUGMENTED_OWNER.to_owned();
    let ridge = &resolved[RIDGE].address;
    store
        .ensure_direct_conversation(owner(), ridge.clone(), ago(300))
        .unwrap();
    store
        .seed_staged_transcript(
            owner(),
            ridge.clone(),
            "parity-ridge".to_owned(),
            vec![
                MobileStagedChatMessageRecord {
                    reception: Some(reception(2, &[[0x01, 0x02], [0x07, 0x08]])),
                    reactions: vec![MobileStagedChatReactionRecord {
                        body: "+1".to_owned(),
                        outbound: true,
                        created_at_ms: ago(280),
                        sender_address: None,
                        sender_hint: None,
                    }],
                    ..inbound(1, "Morning from the ridge", 290)
                },
                MobileStagedChatMessageRecord {
                    regarding: Some(MobileStagedChatRegarding::Message { handle: 1 }),
                    reactions: vec![MobileStagedChatReactionRecord {
                        body: "<3".to_owned(),
                        outbound: false,
                        created_at_ms: ago(260),
                        sender_address: Some(ridge.clone()),
                        sender_hint: Some(resolved[RIDGE].hint.clone()),
                    }],
                    ..outbound(
                        2,
                        "On my way.\nTwo \"hours\"\tout\u{7}",
                        270,
                        MobileStoredChatDeliveryState::Acknowledged,
                    )
                },
                outbound(
                    3,
                    "Lost this one",
                    250,
                    MobileStoredChatDeliveryState::Failed,
                ),
                MobileStagedChatMessageRecord {
                    is_deleted: true,
                    ..inbound(4, "Never mind", 240)
                },
                MobileStagedChatMessageRecord {
                    regarding: Some(MobileStagedChatRegarding::Message { handle: 4 }),
                    ..inbound(5, "Which one?", 230)
                },
                MobileStagedChatMessageRecord {
                    regarding: Some(MobileStagedChatRegarding::Missing),
                    reception: Some(reception(1, &[])),
                    ..inbound(6, "Re: the gate code", 220)
                },
                outbound(
                    7,
                    "Undelivered, sadly",
                    210,
                    MobileStoredChatDeliveryState::Undelivered,
                ),
                outbound(
                    8,
                    "Still sending",
                    1,
                    MobileStoredChatDeliveryState::Pending,
                ),
            ],
        )
        .unwrap();

    let echo = &resolved[ECHO_A].address;
    let echo_conversation = store
        .ensure_direct_conversation(owner(), echo.clone(), ago(100))
        .unwrap();
    store
        .seed_staged_transcript(
            owner(),
            echo.clone(),
            "parity-echo".to_owned(),
            vec![
                MobileStagedChatMessageRecord {
                    reception: Some(reception(3, &[[0x05, 0x06], [0xEE, 0xEE]])),
                    ..inbound(1, "Héllo, wörld 👋", 95)
                },
                outbound(
                    2,
                    "Sent, not acked",
                    90,
                    MobileStoredChatDeliveryState::Sent,
                ),
                // Two in the same millisecond, ordered by row.
                inbound(3, "Same instant one", 80),
                inbound(4, "Same instant two", 80),
            ],
        )
        .unwrap();
    store
        .update_draft(owner(), echo_conversation, "half a thought".to_owned())
        .unwrap();
}

/// One joined channel with named senders, and one left channel whose
/// conversation the loader must not show.
fn write_channels(store: &MobileAppStore, resolved: &[Resolved]) {
    let owner = || AUGMENTED_OWNER.to_owned();
    for (name, joined, session, tint_seed) in [
        ("Bay Net", true, "parity-bay-net", 0x11u8),
        ("Old Crew", false, "parity-old-crew", 0x22),
    ] {
        let channel = umsh_node::Channel::named(name).unwrap();
        let key: ChannelKey = *channel.key();
        let id = format!("00000000-0000-8000-8000-0000000000{tint_seed:02X}");
        let created = ago(2_000);
        store
            .insert_channel(
                MobileStoredChannelRecord {
                    id: id.clone(),
                    owner_identity_id: owner(),
                    kind: MobileStoredChannelKind::Named,
                    canonical_name: Some(name.to_ascii_lowercase()),
                    name: Some(name.to_owned()),
                    alias: (!joined).then(|| "The old crew".to_owned()),
                    channel_id_hex: hex(&channel.channel_id().0),
                    tint: crate::channel_tint(&key),
                    region_code: joined.then(|| vec![0x55, 0x53]),
                    max_flood_hops: joined.then_some(4),
                    joined_phone: joined,
                    joined_device: false,
                    notifications_enabled: joined,
                    joined_at_ms: Some(created),
                },
                crate::channel_key_digest(key.0.to_vec()),
                created,
            )
            .unwrap();
        let address = crate::mobile_chat::channel_address(crate::channel_tag(&key));
        store
            .ensure_channel_conversation(owner(), id, address.clone(), ago(1_000))
            .unwrap();
        let ridge = &resolved[RIDGE];
        store
            .seed_staged_transcript(
                owner(),
                address,
                session.to_owned(),
                vec![
                    MobileStagedChatMessageRecord {
                        sender_address: Some(ridge.address.clone()),
                        sender_hint: Some(ridge.hint.clone()),
                        sender_handle: Some("Ridge".to_owned()),
                        reception: Some(reception(2, &[[0x07, 0x08]])),
                        ..inbound(1, "Net check, ridge here", 50)
                    },
                    MobileStagedChatMessageRecord {
                        sender_hint: Some(vec![0xAA, 0xBB, 0xCC]),
                        sender_handle: Some("Drifter".to_owned()),
                        regarding: Some(MobileStagedChatRegarding::Message { handle: 1 }),
                        reactions: vec![MobileStagedChatReactionRecord {
                            body: "ha".to_owned(),
                            outbound: false,
                            created_at_ms: ago(40),
                            sender_address: Some(ridge.address.clone()),
                            sender_hint: Some(ridge.hint.clone()),
                        }],
                        ..inbound(2, "Copy, drifting by", 45)
                    },
                    outbound(3, "Checking in", 30, MobileStoredChatDeliveryState::Sent),
                ],
            )
            .unwrap();
    }
}

fn entry(hint: &[u8], name: Option<&str>, minutes_ago: i64) -> MobileStoredPeerRepeaterEntryRecord {
    MobileStoredPeerRepeaterEntryRecord {
        hint: hint.to_vec(),
        name: name.map(str::to_owned),
        rssi_dbm: Some(-97),
        snr_quarter_db: Some(-22),
        last_heard_minutes: Some(3),
        latitude: Some(47.25),
        longitude: Some(-122.4375),
        location_precision: Some(4),
        region_codes: vec![vec![0x55, 0x53]],
        reported_at_ms: ago(minutes_ago),
    }
}

/// Ridge's listing names a node hint, and repeater hints that several peers
/// share: one decided by an advertisement (0x0102), one by a stored kind
/// over an advertisement that does not decode (0x0506), one by a stored
/// bridge (0x0708). It ends with a hint nobody holds. Echo B's stopped
/// partway.
fn write_listings(store: &MobileAppStore, resolved: &[Resolved]) {
    let owner = || AUGMENTED_OWNER.to_owned();
    store
        .save_peer_repeater_page(
            owner(),
            resolved[RIDGE].address.clone(),
            vec![
                entry(&resolved[TWIN].hint, Some("Twin"), 20),
                entry(&[0x01, 0x02], None, 20),
                entry(&[0x05, 0x06], Some("Echo?"), 20),
                MobileStoredPeerRepeaterEntryRecord {
                    rssi_dbm: None,
                    snr_quarter_db: None,
                    last_heard_minutes: None,
                    latitude: None,
                    longitude: None,
                    location_precision: None,
                    region_codes: Vec::new(),
                    ..entry(&[0x07, 0x08], None, 20)
                },
                entry(&[0xAB, 0xCD, 0xEF], Some("Stranger"), 20),
            ],
            Some(5),
            None,
            true,
            ago(20),
        )
        .unwrap();
    store
        .save_peer_repeater_page(
            owner(),
            resolved[ECHO_B].address.clone(),
            vec![entry(&resolved[SPAN].hint, Some("Span"), 15)],
            Some(9),
            Some(vec![0x00, 0x01]),
            true,
            ago(15),
        )
        .unwrap();
}

/// The seeded owner's own address, which no read looks at.
fn owner_address() -> String {
    public_identity_record(umsh_crypto::NodeIdentity::public_key(&identity(3))).canonical_address
}

// The comparison: renders what `MobileAppCore` answers in the goldens'
// format and compares it with what Swift wrote.

mod render {
    use std::fmt::Write as _;

    use crate::IdentitySignatureState;
    use crate::app_core::records::{
        MobileAppChannelConversationRecord, MobileAppChannelRecord,
        MobileAppDirectConversationRecord, MobileAppMessageRecord, MobileAppNeighborReportRecord,
        MobileAppPeerRecord, MobileAppPreviewRecord, MobileAppRepeaterListingRecord,
        MobileAppRepeaterNeighborRecord, MobileAppStateRecord,
    };
    use crate::mobile_chat::MobileChatPresence;
    use crate::store::{
        MobileStoredChannelKind, MobileStoredChatDeliveryState, MobileStoredChatMessageRefRecord,
        MobileStoredNodeKind, MobileStoredSystemRole,
    };

    /// One `name=value` list, in the order written.
    #[derive(Default)]
    pub(super) struct Fields(String);

    impl Fields {
        fn put(mut self, name: &str, value: impl AsRef<str>) -> Self {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            let _ = write!(self.0, "{name}={}", value.as_ref());
            self
        }

        fn line(self, kind: &str) -> String {
            format!("{kind} {}", self.0)
        }

        fn record(self) -> String {
            format!("{{{}}}", self.0)
        }
    }

    const ABSENT: &str = "-";

    fn optional<T>(value: Option<T>, render: impl FnOnce(T) -> String) -> String {
        value.map_or_else(|| ABSENT.to_owned(), render)
    }

    fn string(value: &str) -> String {
        let mut quoted = String::from("\"");
        for character in value.chars() {
            match character {
                '\\' => quoted.push_str("\\\\"),
                '"' => quoted.push_str("\\\""),
                '\n' => quoted.push_str("\\n"),
                '\r' => quoted.push_str("\\r"),
                '\t' => quoted.push_str("\\t"),
                control if u32::from(control) < 0x20 => {
                    let _ = write!(quoted, "\\u{{{:x}}}", u32::from(control));
                }
                other => quoted.push(other),
            }
        }
        quoted.push('"');
        quoted
    }

    fn optional_string(value: Option<&str>) -> String {
        optional(value, string)
    }

    fn bytes(value: &[u8]) -> String {
        format!("x{}", crate::mobile_chat::hex(value))
    }

    fn optional_bytes(value: Option<&[u8]>) -> String {
        optional(value, bytes)
    }

    fn number(value: impl std::fmt::Display) -> String {
        value.to_string()
    }

    fn optional_number<T: std::fmt::Display>(value: Option<T>) -> String {
        optional(value, number)
    }

    fn float(value: Option<f64>) -> String {
        optional(value, |value| format!("{value:.7}"))
    }

    fn list(items: impl IntoIterator<Item = String>) -> String {
        format!("[{}]", items.into_iter().collect::<Vec<_>>().join(","))
    }

    fn reference(reference: &MobileStoredChatMessageRefRecord) -> String {
        string(&format!("{}:{}", reference.session_id, reference.handle))
    }

    fn node_kind(kind: Option<MobileStoredNodeKind>) -> String {
        match kind {
            None | Some(MobileStoredNodeKind::Unknown) => ABSENT,
            Some(MobileStoredNodeKind::Repeater) => "repeater",
            Some(MobileStoredNodeKind::Chat) => "chat",
            Some(MobileStoredNodeKind::Tracker) => "tracker",
            Some(MobileStoredNodeKind::Sensor) => "sensor",
            Some(MobileStoredNodeKind::Bridge) => "bridge",
            Some(MobileStoredNodeKind::ChatRoom) => "chatroom",
            Some(MobileStoredNodeKind::TemporarySession) => "temporarysession",
        }
        .to_owned()
    }

    fn system_role(role: Option<MobileStoredSystemRole>) -> String {
        optional(role, |MobileStoredSystemRole::CompanionRadio| {
            "companionradio".to_owned()
        })
    }

    fn channel_kind(kind: MobileStoredChannelKind) -> &'static str {
        match kind {
            MobileStoredChannelKind::Builtin => "builtin",
            MobileStoredChannelKind::Named => "named",
            MobileStoredChannelKind::PrivateKey => "privatekey",
        }
    }

    fn delivery(state: MobileStoredChatDeliveryState) -> String {
        match state {
            MobileStoredChatDeliveryState::Pending => "pending",
            MobileStoredChatDeliveryState::Sent => "sent",
            MobileStoredChatDeliveryState::Acknowledged => "acknowledged",
            MobileStoredChatDeliveryState::Failed => "failed",
            MobileStoredChatDeliveryState::Undelivered => "undelivered",
        }
        .to_owned()
    }

    fn presence(presence: MobileChatPresence) -> &'static str {
        match presence {
            MobileChatPresence::Present => "present",
            MobileChatPresence::GapPending => "gappending",
            MobileChatPresence::GapIdle => "gapidle",
            MobileChatPresence::Unavailable => "unavailable",
        }
    }

    fn peer(peer: &MobileAppPeerRecord) -> String {
        let stored = &peer.stored;
        Fields::default()
            .put("id", number(stored.id))
            .put("address", string(&peer.identity.canonical_address))
            .put("hint", string(&peer.identity.hint.text))
            .put("alias", optional_string(stored.alias.as_deref()))
            .put(
                "advertised_name",
                optional_string(stored.advertised_name.as_deref()),
            )
            .put("system_role", system_role(stored.system_role))
            .put("node_kind", node_kind(stored.node_kind))
            .put(
                "advertised",
                optional(peer.advertised_identity.as_ref(), |identity| {
                    Fields::default()
                        .put("role", number(identity.role_code))
                        .put("capabilities", number(identity.capability_bits))
                        .put("forwards", number(identity.forwards))
                        .put("name", optional_string(identity.name.as_deref()))
                        .put("latitude", float(identity.latitude))
                        .put("longitude", float(identity.longitude))
                        .put("precision", optional_number(identity.location_precision))
                        .put("altitude", optional_number(identity.altitude_m))
                        .put("timestamp", optional_number(identity.timestamp))
                        .put(
                            "signature",
                            match identity.signature {
                                IdentitySignatureState::Unsigned => "unsigned",
                                IdentitySignatureState::Valid => "valid",
                                IdentitySignatureState::Invalid => "invalid",
                            },
                        )
                        .record()
                }),
            )
            .put("authenticated", number(stored.advertisement_authenticated))
            .put(
                "received_at",
                optional_number(stored.advertisement_received_at_ms),
            )
            .put("last_heard", optional_number(stored.last_heard_at_ms))
            .put("saved", number(stored.is_saved))
            .put("favorite", number(stored.is_favorite))
            .put("on_device", number(stored.on_device_identity))
            .put("notify_when_heard", number(stored.notify_when_heard))
            .line("peer")
    }

    fn channel(channel: &MobileAppChannelRecord) -> String {
        let stored = &channel.stored;
        Fields::default()
            .put("id", string(&stored.id))
            .put("kind", channel_kind(stored.kind))
            .put(
                "canonical_name",
                optional_string(stored.canonical_name.as_deref()),
            )
            .put("name", optional_string(stored.name.as_deref()))
            .put("alias", optional_string(stored.alias.as_deref()))
            .put("channel_id_hex", string(&stored.channel_id_hex))
            .put("tint", bytes(&stored.tint))
            .put("region_code", optional_bytes(stored.region_code.as_deref()))
            .put("max_flood_hops", optional_number(stored.max_flood_hops))
            .put("joined_phone", number(stored.joined_phone))
            .put("notifications", number(stored.notifications_enabled))
            .put("joined_at", optional_number(stored.joined_at_ms))
            .line("channel")
    }

    fn preview(preview: Option<&MobileAppPreviewRecord>) -> String {
        optional(preview, |preview| {
            let stored = &preview.stored;
            Fields::default()
                .put("created", number(stored.created_at_ms))
                .put("body", string(&stored.body))
                .put("outbound", number(stored.is_outbound))
                .put("deleted", number(stored.is_deleted))
                .put(
                    "sender_address",
                    optional_string(stored.sender_address.as_deref()),
                )
                .put("sender_hint", optional_bytes(stored.sender_hint.as_deref()))
                .put("status", number(stored.is_status))
                .put(
                    "sender_node_hint",
                    optional_string(preview.sender_node_hint.as_deref()),
                )
                .record()
        })
    }

    fn direct(conversation: &MobileAppDirectConversationRecord) -> String {
        Fields::default()
            .put("id", number(conversation.id))
            .put(
                "peer",
                string(&conversation.peer.identity.canonical_address),
            )
            .put("draft", string(&conversation.draft_text))
            .put("unread", number(conversation.unread_count))
            .put("created", number(conversation.created_at_ms))
            .put("notifications", number(conversation.notifications_enabled))
            .put("last", preview(conversation.last_message.as_ref()))
            .line("direct")
    }

    fn channel_conversation(conversation: &MobileAppChannelConversationRecord) -> String {
        Fields::default()
            .put("id", number(conversation.id))
            .put("channel", string(&conversation.channel.id))
            .put("address", string(&conversation.conversation_address))
            .put("draft", string(&conversation.draft_text))
            .put("unread", number(conversation.unread_count))
            .put("created", number(conversation.created_at_ms))
            .put("last", preview(conversation.last_message.as_ref()))
            .line("channel_conversation")
    }

    pub(super) fn neighbor(neighbor: &MobileAppRepeaterNeighborRecord) -> String {
        let entry = &neighbor.entry;
        Fields::default()
            .put("hint", bytes(&entry.hint))
            .put(
                "hint_text",
                string(
                    &neighbor
                        .hint_text
                        .clone()
                        .unwrap_or_else(|| crate::mobile_chat::hex(&entry.hint).to_uppercase()),
                ),
            )
            .put("name", optional_string(entry.name.as_deref()))
            .put("rssi", optional_number(entry.rssi_dbm))
            .put("snr", optional_number(entry.snr_quarter_db))
            .put(
                "last_heard_minutes",
                optional_number(entry.last_heard_minutes),
            )
            .put("latitude", float(entry.latitude))
            .put("longitude", float(entry.longitude))
            .put("precision", optional_number(entry.location_precision))
            .put(
                "regions",
                list(entry.region_codes.iter().map(|code| bytes(code))),
            )
            .put("reported_at", number(entry.reported_at_ms))
            .put("peer", optional_string(neighbor.peer_address.as_deref()))
            .record()
    }

    fn report(report: &MobileAppNeighborReportRecord) -> String {
        Fields::default()
            .put("reporter", string(&report.reporter_address))
            .put("neighbor", neighbor(&report.neighbor))
            .line("report")
    }

    /// The `## state` lines, sorted.
    pub(super) fn state(state: &MobileAppStateRecord) -> Vec<String> {
        let mut lines: Vec<String> = state
            .peers
            .iter()
            .flatten()
            .map(peer)
            .chain(state.channels.iter().map(channel))
            .chain(state.direct_conversations.iter().map(direct))
            .chain(state.channel_conversations.iter().map(channel_conversation))
            .chain(state.neighbor_reports.iter().flatten().map(report))
            .collect();
        lines.sort();
        lines
    }

    pub(super) fn message(message: &MobileAppMessageRecord) -> String {
        let stored = &message.stored;
        Fields::default()
            .put("id", reference(&stored.reference))
            .put(
                "cursor",
                format!("{}/{}", stored.created_at_ms, stored.row_id),
            )
            .put("created", number(stored.created_at_ms))
            .put("body", string(&stored.body))
            .put("outbound", number(stored.outbound))
            .put("delivery", optional(stored.delivery_state, delivery))
            .put("deleted", number(stored.is_deleted))
            .put("edited", number(stored.is_edited))
            .put("wire", optional_number(stored.wire_id))
            .put("epoch", optional_number(stored.epoch))
            .put("presence", presence(stored.presence))
            .put("received_late", number(stored.received_late))
            .put("delivered_late", number(stored.delivered_late))
            .put("delivered_flooded", number(stored.delivered_flooded))
            .put("edit_of_unknown", number(stored.is_edit_of_unknown))
            .put("status", number(stored.is_status))
            .put("forward_secret", number(stored.is_forward_secret))
            .put(
                "original_body",
                optional_string(stored.original_body.as_deref()),
            )
            .put(
                "sender_address",
                optional_string(stored.sender_address.as_deref()),
            )
            .put("sender_hint", optional_bytes(stored.sender_hint.as_deref()))
            .put(
                "sender_handle",
                optional_string(stored.sender_handle.as_deref()),
            )
            .put(
                "sender_node_hint",
                optional_string(message.sender_node_hint.as_deref()),
            )
            .put(
                "reception",
                optional(stored.reception.as_ref(), |reception| {
                    Fields::default()
                        .put("rssi", optional_number(reception.rssi_dbm))
                        .put("snr", optional_number(reception.snr_centibels))
                        .put("lqi", optional_number(reception.lqi))
                        .put("hops", optional_number(reception.hop_count))
                        .put(
                            "routes",
                            list(reception.route_hints.iter().map(|hint| bytes(hint))),
                        )
                        .put("authenticated", number(reception.source_authenticated))
                        .record()
                }),
            )
            .put(
                "reactions",
                list(stored.reactions.iter().map(|reaction| {
                    Fields::default()
                        .put("body", string(&reaction.body))
                        .put("mine", number(reaction.outbound))
                        .put(
                            "sender_address",
                            optional_string(reaction.sender_address.as_deref()),
                        )
                        .put(
                            "sender_hint",
                            optional_bytes(reaction.sender_hint.as_deref()),
                        )
                        .put("target", reference(&reaction.reference))
                        .put("wire", optional_number(reaction.wire_id))
                        .put("epoch", optional_number(reaction.epoch))
                        .put(
                            "failed",
                            number(
                                reaction.outbound
                                    && matches!(
                                        reaction.delivery_state,
                                        Some(
                                            MobileStoredChatDeliveryState::Failed
                                                | MobileStoredChatDeliveryState::Undelivered
                                        )
                                    ),
                            ),
                        )
                        .put("forward_secret", number(reaction.forward_secret))
                        .record()
                })),
            )
            .put(
                "quote",
                optional(stored.quote.as_ref(), |quote| match &quote.original {
                    None => "unavailable".to_owned(),
                    Some(original) => Fields::default()
                        .put(
                            "state",
                            if original.is_deleted {
                                "deleted"
                            } else {
                                "present"
                            },
                        )
                        .put("target", reference(&original.reference))
                        .put(
                            "body",
                            string(if original.is_deleted {
                                ""
                            } else {
                                &original.body
                            }),
                        )
                        .put("outbound", number(original.outbound))
                        .put(
                            "sender_address",
                            optional_string(original.sender_address.as_deref()),
                        )
                        .put(
                            "sender_handle",
                            optional_string(original.sender_handle.as_deref()),
                        )
                        .put(
                            "sender_node_hint",
                            optional_string(message.quoted_sender_node_hint.as_deref()),
                        )
                        .record(),
                }),
            )
            .put(
                "repeats",
                optional(stored.repeats.as_ref(), |repeats| {
                    Fields::default()
                        .put("anonymous", number(repeats.anonymous))
                        .put("progress_at", number(repeats.progress_at_ms))
                        .put(
                            "repeaters",
                            list(message.repeaters.iter().map(|repeater| {
                                Fields::default()
                                    .put("hint", bytes(&repeater.hint))
                                    .put(
                                        "text",
                                        string(&repeater.hint_text.clone().unwrap_or_else(|| {
                                            crate::mobile_chat::hex(&repeater.hint)
                                        })),
                                    )
                                    .put("peer", optional_string(repeater.peer_address.as_deref()))
                                    .record()
                            })),
                        )
                        .record()
                }),
            )
            .line("message")
    }

    pub(super) fn listing(listing: &MobileAppRepeaterListingRecord) -> Vec<String> {
        std::iter::once(
            Fields::default()
                .put("total", optional_number(listing.total))
                .put(
                    "next_cursor",
                    optional_bytes(listing.next_cursor.as_deref()),
                )
                .put("as_of", number(listing.as_of_ms))
                .line("listing"),
        )
        .chain(
            listing
                .entries
                .iter()
                .map(|entry| format!("entry {}", neighbor(entry))),
        )
        .collect()
    }
}

/// A golden, split into its sections.
struct Golden {
    state: Vec<String>,
    transcripts: Vec<(String, Vec<String>)>,
    repeaters: Vec<(String, Vec<String>)>,
}

impl Golden {
    fn read(name: &str) -> Self {
        let path = directory().join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let mut golden = Self {
            state: Vec::new(),
            transcripts: Vec::new(),
            repeaters: Vec::new(),
        };
        let mut section: Option<&mut Vec<String>> = None;
        for line in text.lines() {
            if line == "## state" {
                section = Some(&mut golden.state);
            } else if let Some(address) = line.strip_prefix("## transcript ") {
                golden.transcripts.push((address.to_owned(), Vec::new()));
                section = golden.transcripts.last_mut().map(|(_, lines)| lines);
            } else if let Some(address) = line.strip_prefix("## repeaters ") {
                golden.repeaters.push((address.to_owned(), Vec::new()));
                section = golden.repeaters.last_mut().map(|(_, lines)| lines);
            } else {
                section
                    .as_mut()
                    .unwrap_or_else(|| panic!("{name}: a line before any section"))
                    .push(line.to_owned());
            }
        }
        golden
    }
}

/// Compare two runs of lines, naming the first that differs.
fn assert_lines(what: &str, ours: &[String], theirs: &[String]) {
    for (index, (ours, theirs)) in ours.iter().zip(theirs).enumerate() {
        assert_eq!(ours, theirs, "{what}, line {}", index + 1);
    }
    assert_eq!(ours.len(), theirs.len(), "{what}: line count");
}

/// `MobileAppCore`'s answers over one committed store, against Swift's.
fn compare(store_name: &str, golden_name: &str, owner: &str) {
    let golden = Golden::read(golden_name);
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join(store_name);
    std::fs::copy(directory().join(store_name), &path).unwrap();
    let store = MobileAppStore::open(path.to_string_lossy().into_owned()).unwrap();
    let core = super::MobileAppCore::new(
        store,
        Arc::new(crate::secret_vault::memory::MemoryVault::default()),
        super::MobileAppConfigRecord {
            counter_directory: scratch.path().join("counters").display().to_string(),
            platform_model: 0,
        },
    )
    .unwrap();
    core.set_owner(Some(owner.to_owned())).unwrap();

    let state = core.state(false).unwrap();
    assert_lines(
        &format!("{golden_name} state"),
        &render::state(&state),
        &golden.state,
    );

    for (address, lines) in &golden.transcripts {
        let page = core.transcript_newest(address.clone(), 500).unwrap();
        let ours: Vec<String> = std::iter::once(format!(
            "page has_older={} has_newer={}",
            page.has_older, page.has_newer
        ))
        .chain(page.messages.iter().map(render::message))
        .collect();
        assert_lines(&format!("{golden_name} transcript {address}"), &ours, lines);
    }

    for (address, lines) in &golden.repeaters {
        let listing = core
            .peer_repeaters(address.clone())
            .unwrap()
            .unwrap_or_else(|| panic!("{golden_name}: no listing for {address}"));
        assert_lines(
            &format!("{golden_name} repeaters {address}"),
            &render::listing(&listing),
            lines,
        );
    }
    // Every listing Swift wrote is one the core has, and none is missed:
    // each state peer with a listing has a section.
    let with_listings: Vec<&str> = state
        .peers
        .iter()
        .flatten()
        .map(|peer| peer.identity.canonical_address.as_str())
        .filter(|address| {
            core.peer_repeaters((*address).to_owned())
                .unwrap()
                .is_some()
        })
        .collect();
    let sections: Vec<&str> = golden
        .repeaters
        .iter()
        .map(|(address, _)| address.as_str())
        .collect();
    let mut expected = with_listings.clone();
    expected.sort_unstable();
    assert_eq!(expected, sections, "{golden_name}: repeater sections");
}

#[test]
fn the_seeded_store_reads_as_swift_read_it() {
    compare("seeded.sqlite", "seeded.golden", SEEDED_OWNER);
}

#[test]
fn the_augmented_store_reads_as_swift_read_it() {
    compare("augmented.sqlite", "augmented.golden", AUGMENTED_OWNER);
}
