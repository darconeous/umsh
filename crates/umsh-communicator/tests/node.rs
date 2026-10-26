//! The node, against the soft device's real session through the device's
//! own interface, and fed channel frames as the device node hands them
//! over.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

mod support;

use support::{Port, SharedFlash, config, device, phone_inserts, provision, starting_keys};
use umsh_communicator::settings::{SAVE_DELAY_MS, STATISTICS_READ_MS};
use umsh_communicator::task::Command;
use umsh_communicator::task::{Arrival, Secrecy};
use umsh_communicator::{
    ChannelCrypto, Clock, CommunicatorNode, FlashMap, FlashMapStore, MemoryStore, Quota, Seeds,
};
use umsh_core::{
    ChannelId, ChannelKey, ChannelTag, Fcf, PacketHeader, PacketType, ParsedOptions, PayloadType,
    PublicKey, SourceAddrRef,
};
use umsh_crypto::CryptoEngine;
use umsh_crypto::NodeIdentity;
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_mac::{ChannelInfoRef, ReceivedPacketRef, RxMetadata, Snr};
use umsh_node::{NodeCapabilities, NodeIdentityPayload, NodeRole};
use umsh_text::ConversationKey;
use umsh_text::chat::ChatFacade;
use umsh_text::engine::{ComposeIntent, EngineConfig, RegardingRef};
use umsh_text::node_adapter::{
    Inbound, InboundText, RxSummary, Sent, WellKnownChannels, inbound_text,
};
use umsh_text::validate::DirectChannelProfile;
use umsh_ulcp::frame;
use umsh_ulcp::hdlc;
use umsh_ulcp::ids::prop;
use umsh_ulcp::profiles::VETTED;
use umsh_ulcp_simdev::{SessionConfig, SimulatedDevice, TimeConfig};
use umsh_ux_communicator::model::{
    ChannelAccess, ChannelEntry, ChatKind, Chats, Delivery, Direction, KeyboardSettings, Node,
    NodeEvent, PeerEntry, Peers, Presence, Profile, Reaction, Rule, Setting, Shareable,
};

/// 14:32 UTC, when the test clock starts.
const STARTED: u32 = 1_792_247_520;

/// A clock the test moves by hand.
struct TestClock(AtomicU64);

impl TestClock {
    fn set(&self, ms: u64) {
        self.0.store(ms, Ordering::Relaxed);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn wall(&self) -> Option<u32> {
        Some(STARTED + (self.now_ms() / 1_000) as u32)
    }
}

fn tag(key: &ChannelKey) -> ChannelTag {
    CryptoEngine::new(SoftwareAes, SoftwareSha256).derive_channel_tag(key)
}

/// Anyone's key but the device's: the device's own is made at random.
const LOCAL: PublicKey = PublicKey([0x42; 32]);

/// A node over `sim`, with its settings read, and the clock it reads.
fn node(sim: &Rc<RefCell<SimulatedDevice>>) -> (CommunicatorNode<Port>, &'static TestClock) {
    let clock: &'static TestClock = Box::leak(Box::new(TestClock(AtomicU64::new(0))));
    let node = CommunicatorNode::new(
        Port(sim.clone()),
        MemoryStore::new(),
        ChannelCrypto::software(),
        &std::alloc::System,
        clock,
        Seeds {
            session_id: 1,
            jitter_seed: 2,
        },
    );
    node.pump();
    assert!(node.primed());
    (node, clock)
}

/// Gives `sim` an identity, as whoever holds the device may.
fn identify(sim: &Rc<RefCell<SimulatedDevice>>) {
    provision(sim, None);
}

/// A node over a device with an identity, whose chats have started, with
/// what it first said taken.
fn started(sim: &Rc<RefCell<SimulatedDevice>>) -> (CommunicatorNode<Port>, &'static TestClock) {
    identify(sim);
    let (node, clock) = node(sim);
    assert!(node.started());
    events(&node);
    (node, clock)
}

fn events(node: &CommunicatorNode<Port>) -> Vec<NodeEvent> {
    core::iter::from_fn(|| node.next_event()).collect()
}

fn chats(node: &CommunicatorNode<Port>) -> Chats {
    let mut chats = Chats::new();
    node.chats(&mut chats);
    chats
}

/// What a channel member's own chat session sends: `body` under the
/// Sender Handle `handle`, as the payload of one frame.
fn composed(from: PublicKey, key: ChannelKey, handle: &str, body: &str) -> Vec<u8> {
    let mut peer: ChatFacade = ChatFacade::new(
        DirectChannelProfile,
        from,
        EngineConfig::default(),
        Seeds {
            session_id: 7,
            jitter_seed: 8,
        },
    );
    peer.channels_mut().register(tag(&key), key, None);
    peer.set_local_handle(handle);
    let conversation = ConversationKey::ChannelGroup { channel: tag(&key) };
    let batch = peer
        .compose(
            conversation,
            1,
            ComposeIntent::Text {
                body,
                status: false,
            },
            None,
            0,
        )
        .unwrap();
    let outbound = peer.commit(batch).unwrap();
    outbound.transmissions()[0].payload.to_vec()
}

/// A channel frame from `from`, as the MAC hands it to the device node
/// once its channel key has authenticated it.
fn received(key: &ChannelKey, from: PublicKey, payload: &[u8]) -> InboundText {
    channel_frame(key, from, true, payload)
}

/// A channel frame from `from`, naming them by full key or by hint.
fn channel_frame(key: &ChannelKey, from: PublicKey, full_key: bool, payload: &[u8]) -> InboundText {
    let mut bytes = vec![PayloadType::TextMessage as u8];
    bytes.extend_from_slice(payload);
    let header = PacketHeader {
        fcf: Fcf::new(PacketType::Multicast, full_key, false),
        options_range: 0..0,
        flood_hops: None,
        dst: None,
        channel: Some(ChannelId([0, 0])),
        source: if full_key {
            SourceAddrRef::FullKeyAt { offset: 0 }
        } else {
            SourceAddrRef::Hint(from.hint())
        },
        sec_info: None,
        body_range: 0..0,
        mic_range: 0..0,
        total_len: 0,
    };
    let packet = ReceivedPacketRef::new(
        &[],
        &bytes,
        header,
        ParsedOptions::default(),
        full_key.then_some(from),
        Some(from.hint()),
        false,
        Some(ChannelInfoRef {
            id: ChannelId([0, 0]),
            key,
        }),
        RxMetadata::new(Some(-97), Some(Snr::from_centibels(65)), None, None),
    );
    match inbound_text(&packet, &LOCAL, &WellKnownChannels::derive()) {
        Some(Inbound::Text(text)) => text,
        _ => panic!("not a text frame"),
    }
}

// ─── Settings ────────────────────────────────────────────────────────

#[test]
fn the_first_boot_saves_what_the_device_starts_with() {
    let sim = device();
    assert!(sim.borrow().saved_snapshot().is_none());
    let (_node, _) = node(&sim);
    assert!(sim.borrow().saved_snapshot().is_some());

    // With a snapshot in effect, the next boot leaves it alone.
    let before = sim.borrow().saved_snapshot().unwrap().to_vec();
    let (_node, _) = node(&sim);
    assert_eq!(sim.borrow().saved_snapshot().unwrap(), &before[..]);
}

/// A change reads at once, and the device keeps the snapshot in step with
/// it: no save is asked for while one is in effect.
#[test]
fn a_change_reads_at_once_and_is_kept() {
    let sim = device();
    let (node, clock) = node(&sim);
    events(&node);
    let before = sim.borrow().saved_snapshot().unwrap().to_vec();

    node.set_name("Juniper");
    assert_eq!(node.device_name(), "Juniper");
    clock.set(1_000);
    node.pump();
    assert_eq!(events(&node), [NodeEvent::SettingsChanged]);
    assert_eq!(node.device_name(), "Juniper");
    let kept = sim.borrow().saved_snapshot().unwrap().to_vec();
    assert_ne!(kept, before, "the snapshot was kept in step");
    clock.set(1_000 + SAVE_DELAY_MS);
    node.pump();
    assert_eq!(sim.borrow().saved_snapshot().unwrap(), &kept[..]);
}

#[test]
fn the_profile_picker_reads_vetted_and_custom() {
    let sim = device();
    let (node, clock) = node(&sim);
    let index = VETTED
        .iter()
        .position(|profile| profile.id == "meshcore-us-ca")
        .unwrap();
    assert_eq!(node.radio().profile, Profile::Vetted(index));
    assert_eq!(node.profile(index), Some(VETTED[index].name));
    assert_eq!(node.profile_count(), VETTED.len());

    let other = (index + 1) % VETTED.len();
    node.set_profile(other);
    assert_eq!(node.radio().profile, Profile::Vetted(other));
    clock.set(1_000);
    node.pump();
    assert_eq!(node.radio().profile, Profile::Vetted(other));

    node.set_profile(VETTED.len());
    assert_eq!(
        events(&node).last(),
        Some(&NodeEvent::SettingRefused(Setting::Profile))
    );
}

#[test]
fn a_refused_change_reads_back_what_the_device_kept() {
    // A radio that cannot reach the band above 900 MHz.
    let mut sim = SimulatedDevice::holding_lists(
        SessionConfig {
            freq_khz_max: 900_000,
            ..config()
        },
        starting_keys(),
    );
    sim.open_device_interface();
    let sim = Rc::new(RefCell::new(sim));
    let (node, clock) = node(&sim);
    events(&node);
    let kept = node.radio().profile;
    let unreachable = VETTED
        .iter()
        .position(|profile| profile.freq_khz > 900_000)
        .unwrap();
    node.set_profile(unreachable);
    assert_eq!(node.radio().profile, Profile::Vetted(unreachable));
    clock.set(1_000);
    node.pump();
    assert_eq!(events(&node), [NodeEvent::SettingRefused(Setting::Profile)]);
    assert_eq!(node.radio().profile, kept);

    // A setting the device does not have is refused before it goes out.
    node.set_forwarding(true);
    assert_eq!(
        events(&node),
        [NodeEvent::SettingRefused(Setting::Forwarding)]
    );
    assert!(!node.radio().forwarding);
}

#[test]
fn brightness_and_the_keyboard_are_device_settings() {
    let sim = device();
    let (node, clock) = node(&sim);
    assert_eq!(node.brightness(), 113);
    assert_eq!(
        node.keyboard(),
        KeyboardSettings {
            capitalize: true,
            period: true,
            light: true
        }
    );
    let before = sim.borrow().saved_snapshot().unwrap().to_vec();
    node.set_brightness(0);
    let keyboard = KeyboardSettings {
        capitalize: false,
        period: true,
        light: false,
    };
    node.set_keyboard(keyboard);
    assert_eq!(node.brightness(), 0);
    assert_eq!(node.keyboard(), keyboard);
    clock.set(1_000);
    node.pump();
    assert_eq!(node.brightness(), 0);
    assert_eq!(node.keyboard(), keyboard);
    // Saved with the rest, as a switch at the device is.
    assert_ne!(sim.borrow().saved_snapshot().unwrap(), &before[..]);
}

#[test]
fn sound_is_a_saved_device_setting() {
    let sim = device();
    let (node, clock) = node(&sim);
    assert_eq!(node.sound_enabled(), Some(true));
    assert_eq!(node.sound_volume(), 191);
    let before = sim.borrow().saved_snapshot().unwrap().to_vec();
    node.set_sound_enabled(false);
    node.set_sound_volume(40);
    assert_eq!(node.sound_enabled(), Some(false));
    clock.set(1_000);
    node.pump();
    assert_eq!(node.sound_enabled(), Some(false));
    assert_eq!(node.sound_volume(), 40);
    assert_ne!(sim.borrow().saved_snapshot().unwrap(), &before[..]);
}

#[test]
fn auto_lock_is_a_device_setting_and_0_is_never() {
    let sim = device();
    let (node, clock) = node(&sim);
    assert_eq!(node.auto_lock(), Some(30));
    node.set_auto_lock(0);
    clock.set(1_000);
    node.pump();
    assert_eq!(node.auto_lock(), Some(0));
    // The device raises too short a time to the shortest it keeps.
    node.set_auto_lock(3);
    clock.set(2_000);
    node.pump();
    assert_eq!(node.auto_lock(), Some(10));
}

#[test]
fn statistics_are_read_only_while_watched() {
    let mut sim = SimulatedDevice::holding_lists(
        SessionConfig {
            stats: Some(Box::leak(Box::new(umsh_ulcp::stats::StatsLedger::new()))),
            ..config()
        },
        starting_keys(),
    );
    sim.open_device_interface();
    let sim = Rc::new(RefCell::new(sim));
    let (node, clock) = node(&sim);
    events(&node);
    // Nothing is read until someone looks.
    assert_eq!(node.statistics().sent, None);
    node.watch_statistics(true);
    clock.set(1_000);
    node.pump();
    let read = node.statistics();
    assert_eq!(read.sent, Some(0));
    assert!(read.uptime.is_some());
    assert!(events(&node).contains(&NodeEvent::SettingsChanged));
    // Read again on its schedule, and not once let go of.
    assert!(node.next_deadline() <= Some(1_000 + STATISTICS_READ_MS));
    node.watch_statistics(false);
    assert!(node.next_deadline() > Some(1_000 + STATISTICS_READ_MS));
}

#[test]
fn the_zone_and_the_hours_are_device_settings() {
    let mut sim = SimulatedDevice::holding_lists(
        SessionConfig {
            time: Some(TimeConfig),
            ..config()
        },
        starting_keys(),
    );
    sim.open_device_interface();
    let sim = Rc::new(RefCell::new(sim));
    let (node, clock) = node(&sim);
    events(&node);
    assert_eq!(Node::clock(&node).zone, Rule::UTC);
    assert!(Node::clock(&node).hour24);
    let before = sim.borrow().saved_snapshot().map(<[u8]>::to_vec);
    node.set_zone("CET-1CEST,M3.5.0,M10.5.0/3");
    node.set_hour24(false);
    clock.set(1_000);
    node.pump();
    clock.set(4_000);
    node.pump();
    assert_eq!(Node::clock(&node).zone.std_offset_min(), 60);
    assert!(!Node::clock(&node).hour24);
    assert!(!events(&node).contains(&NodeEvent::SettingRefused(Setting::Clock)));
    assert_ne!(sim.borrow().saved_snapshot().map(<[u8]>::to_vec), before);
    // A rule the device cannot read is refused.
    node.set_zone("PST8PDT,M3.2.0");
    clock.set(5_000);
    node.pump();
    assert!(events(&node).contains(&NodeEvent::SettingRefused(Setting::Clock)));
    assert_eq!(Node::clock(&node).zone.std_offset_min(), 60);
}

/// What a phone attached to the device changes, the node hears.
#[test]
fn a_change_an_attached_phone_makes_reaches_the_node() {
    let sim = device();
    let (node, clock) = node(&sim);
    events(&node);
    sim.borrow_mut().attach();
    while sim.borrow_mut().take_outbound().is_some() {}

    let mut request = [0u8; 32];
    let len = frame::prop_set(&mut request, 2, prop::DEV_NAME, b"Willow").unwrap();
    let mut encoded = vec![0u8; hdlc::max_encoded_len(len)];
    let len = hdlc::encode_frame(&request[..len], &mut encoded).unwrap();
    sim.borrow_mut().ingest(&encoded[..len], 2_000).unwrap();

    clock.set(2_000);
    node.pump();
    assert_eq!(events(&node), [NodeEvent::SettingsChanged]);
    assert_eq!(node.device_name(), "Willow");
}

#[test]
fn the_address_and_share_link_come_from_the_device_identity() {
    let sim = device();
    {
        let (node, _) = node(&sim);
        assert_eq!(node.address(), "");
        assert!(!node.started());
        assert_eq!(node.share_uri(Shareable::Identity), None);
    }
    identify(&sim);
    let (node, _) = node(&sim);
    let address = node.address();
    assert_eq!(address.len(), 44);
    let uri = node.share_uri(Shareable::Identity).unwrap();
    assert_eq!(uri.as_str(), format!("umsh:n:{address}"));
    assert_eq!(node.share_uri(Shareable::Channel(99)), None);
}

// ─── Chats ───────────────────────────────────────────────────────────

/// A communicator starts out on Public and `EMERGENCY`, and its chats
/// for them are there before anything arrives.
#[test]
fn a_communicator_starts_out_on_public_and_emergency() {
    let sim = device();
    let (node, _) = started(&sim);
    let names: Vec<String> = chats(&node)
        .iter()
        .map(|chat| chat.name.as_str().into())
        .collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"Public".into()), "{names:?}");
    assert!(names.contains(&"EMERGENCY".into()), "{names:?}");
}

/// A channel a phone joins is listed by its tag alone; its chat appears
/// once the device node's key for it is learned.
#[test]
fn a_channel_joined_elsewhere_is_taken_from_the_device_node() {
    let sim = device();
    let (node, clock) = started(&sim);
    let crew = ChannelKey([0x5c; 32]);
    phone_inserts(&sim, prop::DEV_CHANNEL_KEYS, &crew.0);
    clock.set(2_000);
    node.pump();
    assert!(node.misses_channel_keys());
    assert_eq!(chats(&node).len(), 2);

    node.learn_channel_keys(&[WellKnownChannels::derive().public, crew]);
    assert!(!node.misses_channel_keys());
    let names: Vec<String> = chats(&node)
        .iter()
        .map(|chat| chat.name.as_str().into())
        .collect();
    assert_eq!(names.len(), 3, "{names:?}");
    assert!(
        names.iter().any(|name| name.starts_with("Channel ")),
        "{names:?}"
    );
}

/// A channel joined by its name is held by the device, and shared by the
/// name its key derives from.
#[test]
fn a_channel_is_joined_by_its_name_and_shared_by_it() {
    let sim = device();
    let (node, clock) = started(&sim);
    assert_eq!(node.inspect_channel(" "), ChannelEntry::Empty);
    assert_eq!(node.inspect_channel("Trail Crew"), ChannelEntry::Named);
    assert_eq!(node.inspect_channel("trail:crew"), ChannelEntry::Invalid);
    assert_eq!(node.inspect_channel("umsh:cs:"), ChannelEntry::Empty);

    let crew = node.add_channel("Trail Crew").unwrap();
    assert_eq!(crew.name, "Trail Crew");
    assert_eq!(
        crew.kind,
        ChatKind::Channel {
            access: ChannelAccess::Named
        }
    );
    clock.set(1_000);
    node.pump();
    assert!(
        !events(&node)
            .iter()
            .any(|event| matches!(event, NodeEvent::ChatRemoved(_)))
    );
    let uri = node.share_uri(Shareable::Channel(crew.id)).unwrap();
    assert_eq!(uri.as_str(), "umsh:cs:trail%20crew");
    // The same channel, by its invitation: joined already.
    assert_eq!(node.add_channel(&uri).unwrap().id, crew.id);
    assert_eq!(node.add_channel("public").unwrap().name, "Public");
    assert_eq!(chats(&node).len(), 3);

    // The device holds it: a node started over it again lists its tag.
    drop(node);
    assert!(node_over(&sim).misses_channel_keys());
}

/// The base58 digits of `key`.
fn digits(key: &ChannelKey) -> String {
    String::from_utf8(umsh_core::base58::encode(&key.0).to_vec()).unwrap()
}

/// A private channel's invitation is read as it is typed, joined under
/// the name it gives, and shared as it came.
#[test]
fn a_private_channel_is_joined_by_its_invitation() {
    let sim = device();
    let (node, _) = started(&sim);
    let key = ChannelKey([0x6d; 32]);
    let uri = format!("umsh:ck:{}?n=Base%20Camp", digits(&key));
    assert_eq!(
        node.inspect_channel("umsh:ck"),
        ChannelEntry::Partial { missing: 44 }
    );
    assert_eq!(
        node.inspect_channel(&uri[..20]),
        ChannelEntry::Partial { missing: 32 }
    );
    assert_eq!(node.inspect_channel("umsh:ck:0"), ChannelEntry::Invalid);
    assert_eq!(node.inspect_channel(&uri), ChannelEntry::Private);

    let camp = node.add_channel(&uri).unwrap();
    assert_eq!(camp.name, "Base Camp");
    assert_eq!(
        camp.kind,
        ChatKind::Channel {
            access: ChannelAccess::Private
        }
    );
    assert_eq!(
        node.share_uri(Shareable::Channel(camp.id))
            .unwrap()
            .as_str(),
        uri
    );
}

/// A message that is a whole invitation is shown as one, and joining it
/// under another name shares it by that name.
#[test]
fn an_invitation_in_a_message_is_joined() {
    let sim = device();
    let (node, clock) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let robin = PublicKey([0x37; 32]);
    let key = ChannelKey([0x6d; 32]);
    let uri = format!("umsh:ck:{}?n=Base%20Camp", digits(&key));
    let payload = composed(robin, public, "Robin", &format!(" {uri}\n"));
    node.arrive(Arrival::Text(received(&public, robin, &payload)));
    let Some(NodeEvent::Arrived { chat, message }) = events(&node)
        .into_iter()
        .find(|event| matches!(event, NodeEvent::Arrived { .. }))
    else {
        panic!("nothing arrived");
    };
    let invite = node
        .message(chat, message)
        .unwrap()
        .invite()
        .cloned()
        .unwrap();
    assert_eq!(&*invite.name, "Base Camp");
    assert_eq!(invite.access, ChannelAccess::Private);
    assert_eq!(invite.key, key.0);

    let camp = node.join(&invite, "Camp").unwrap();
    assert_eq!(camp.name, "Camp");
    clock.set(1_000);
    node.pump();
    assert_eq!(node.join(&invite, "Camp").unwrap().id, camp.id);
    assert_eq!(
        node.share_uri(Shareable::Channel(camp.id))
            .unwrap()
            .as_str(),
        format!("umsh:ck:{}?n=Camp", digits(&key))
    );

    // Text around an invitation is a message, not an invitation.
    let ash = PublicKey([0x38; 32]);
    let payload = composed(ash, public, "Ash", &format!("join {uri}"));
    node.arrive(Arrival::Text(received(&public, ash, &payload)));
    let Some(NodeEvent::Arrived { chat, message }) = events(&node)
        .into_iter()
        .find(|event| matches!(event, NodeEvent::Arrived { .. }))
    else {
        panic!("nothing arrived");
    };
    assert_eq!(node.message(chat, message).unwrap().card, None);
}

/// A channel the device has no room for goes again, chat and all.
#[test]
fn a_channel_the_device_will_not_hold_goes_again() {
    let sim = device();
    let (node, clock) = started(&sim);
    // Public and EMERGENCY, and six more, fill the device's list.
    for index in 0..6 {
        node.add_channel(&format!("crew{index}")).unwrap();
        clock.set(1_000 * (index + 1));
        node.pump();
    }
    events(&node);
    assert_eq!(chats(&node).len(), 8);

    let more = node.add_channel("one too many").unwrap();
    assert_eq!(chats(&node).len(), 9);
    clock.set(10_000);
    node.pump();
    assert!(events(&node).contains(&NodeEvent::ChatRemoved(more.id)));
    assert_eq!(chats(&node).len(), 8);
    assert_eq!(node.chat(more.id), None);
}

/// This node's code carries its contact, read afresh: who it is, signed,
/// and mobile, as a communicator's device identity starts out, so it
/// carries no position.
#[test]
fn the_identity_link_carries_a_signed_mobile_contact() {
    let sim = device();
    let (node, clock) = started(&sim);
    node.set_name("Juniper");
    clock.set(1_000);
    node.pump();
    node.read_contact();
    clock.set(2_000);
    node.pump();
    let uri = node.share_uri(Shareable::Identity).unwrap();
    let rest = uri.strip_prefix("umsh:n:").unwrap();
    let (address, contact) = rest.split_once(':').expect("a contact follows the address");
    assert_eq!(address, node.address().as_str());
    let blob = umsh_uri::decode_base58_bytes(contact).unwrap();
    let contact = NodeIdentityPayload::from_bytes(&blob).unwrap();
    assert_eq!(contact.name.as_deref(), Some("Juniper"));
    assert!(contact.signature.is_some());
    assert!(contact.capabilities.contains(NodeCapabilities::MOBILE));
    assert_eq!(contact.location, None);
}

/// A channel left goes, chat and all, and stays gone: the device lets go
/// of it, the well-known Public as much as one joined here.
#[test]
fn a_channel_left_goes_and_stays_gone() {
    let sim = device();
    let (node, clock) = started(&sim);
    let crew = node.add_channel("Trail Crew").unwrap();
    let public = node.add_channel("public").unwrap();
    clock.set(1_000);
    node.pump();
    events(&node);

    node.leave_channel(public.id);
    node.leave_channel(crew.id);
    let left = events(&node);
    assert!(
        left.contains(&NodeEvent::ChatRemoved(public.id)),
        "{left:?}"
    );
    assert!(left.contains(&NodeEvent::ChatRemoved(crew.id)), "{left:?}");
    for step in 2..5 {
        clock.set(1_000 * step);
        node.pump();
    }
    assert_eq!(node.chat(public.id), None);
    assert_eq!(node.chat(crew.id), None);
    let kept = |node: &CommunicatorNode<Port>| -> Vec<String> {
        chats(node)
            .iter()
            .map(|chat| chat.name.as_str().into())
            .collect()
    };
    assert_eq!(kept(&node), ["EMERGENCY"]);

    drop(node);
    assert_eq!(kept(&node_over(&sim)), ["EMERGENCY"]);
}

/// A chat renamed goes by the new name, and by its channel's own again
/// once the name is taken away; one muted says so.
#[test]
fn a_chat_is_renamed_and_muted() {
    let sim = device();
    let (node, _) = started(&sim);
    let crew = node.add_channel("Trail Crew").unwrap();
    events(&node);
    node.rename_chat(crew.id, Some("Crew"));
    assert_eq!(events(&node), [NodeEvent::ChatChanged(crew.id)]);
    assert_eq!(node.chat(crew.id).unwrap().name, "Crew");
    node.rename_chat(crew.id, None);
    assert_eq!(node.chat(crew.id).unwrap().name, "Trail Crew");
    node.set_muted(crew.id, true);
    assert!(node.chat(crew.id).unwrap().muted);
}

/// A message on `public` arrives in its chat, under the name its sender
/// gave, with what the radio said about it.
#[test]
fn a_public_message_arrives_with_its_sender_and_details() {
    let sim = device();
    let (node, clock) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let robin = PublicKey([0x37; 32]);
    let payload = composed(robin, public, "Robin", "Anyone near the trailhead?");

    clock.set(5_000);
    node.arrive(Arrival::Text(received(&public, robin, &payload)));
    let arrived = events(&node);
    let Some(&NodeEvent::Arrived { chat, message }) = arrived
        .iter()
        .find(|event| matches!(event, NodeEvent::Arrived { .. }))
    else {
        panic!("nothing arrived: {arrived:?}");
    };
    assert!(arrived.contains(&NodeEvent::IdentitiesLearned));

    let summary = node.chat(chat).unwrap();
    assert_eq!(summary.name, "Public");
    assert!(summary.unread);
    assert_eq!(summary.preview, "Robin: Anyone near the trailhead?");

    let shown = node.message(chat, message).unwrap();
    assert_eq!(&*shown.text, "Anyone near the trailhead?");
    assert_eq!(shown.sender.unwrap().name, "Robin");
    assert_eq!(shown.time, Some(STARTED + 5));

    let details = node.details(chat, message).unwrap();
    assert_eq!(details.time, Some(STARTED + 5));
    assert_eq!(details.rssi, Some(-97));
    assert_eq!(details.snr, Some(65));

    let member = node.member(chat, message).unwrap();
    assert_eq!(member.sender.name, "Robin");
    assert_eq!(member.address.unwrap().len(), 44);

    assert_eq!(node.rows(chat), 1);
    assert_eq!(node.row_message(chat, 0).unwrap().id, message);

    node.opened(chat);
    assert!(!node.chat(chat).unwrap().unread);
}

/// A sender who gives no name is shown by their address.
#[test]
fn a_sender_without_a_name_is_shown_by_address() {
    let sim = device();
    let (node, _) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let quiet = PublicKey([0x91; 32]);
    let payload = composed(quiet, public, "", "hello");
    node.arrive(Arrival::Text(received(&public, quiet, &payload)));
    let Some(NodeEvent::Arrived { chat, message }) = events(&node)
        .into_iter()
        .find(|event| matches!(event, NodeEvent::Arrived { .. }))
    else {
        panic!("nothing arrived");
    };
    let sender = node.message(chat, message).unwrap().sender.unwrap();
    assert!(sender.name.starts_with("Member "), "{}", sender.name);
}

/// A draft of only whitespace is not kept.
#[test]
fn drafts_are_kept_until_cleared() {
    let sim = device();
    let (node, _) = started(&sim);
    let chat = chats(&node)[0].id;
    node.save_draft(chat, "Back at six");
    assert_eq!(node.chat(chat).unwrap().draft.text(), "Back at six");
    node.save_draft(chat, "   ");
    assert_eq!(node.chat(chat).unwrap().draft.text(), "");
}

// ─── The transcript by row ───────────────────────────────────────────

/// A member's own chat session on the channel `key`, under the Sender
/// Handle `handle`, and the conversation it speaks in.
fn member_session(from: PublicKey, key: ChannelKey, handle: &str) -> (ChatFacade, ConversationKey) {
    let mut facade: ChatFacade = ChatFacade::new(
        DirectChannelProfile,
        from,
        EngineConfig::default(),
        Seeds {
            session_id: 7,
            jitter_seed: 8,
        },
    );
    facade.channels_mut().register(tag(&key), key, None);
    facade.set_local_handle(handle);
    (facade, ConversationKey::ChannelGroup { channel: tag(&key) })
}

/// What `facade` sends of `intent`, the payload of one frame, and what a
/// later message can say it is about.
fn spoken(
    facade: &mut ChatFacade,
    conversation: ConversationKey,
    intent: ComposeIntent<'_>,
) -> (Option<RegardingRef>, Vec<u8>) {
    let batch = facade.compose(conversation, 1, intent, None, 0).unwrap();
    let handle = batch
        .mutations
        .first()
        .map(|mutation| RegardingRef::Handle(mutation.handle));
    let outbound = facade.commit(batch).unwrap();
    (handle, outbound.transmissions()[0].payload.to_vec())
}

fn text(body: &str) -> ComposeIntent<'_> {
    ComposeIntent::Text {
        body,
        status: false,
    }
}

/// The chat on Public, once something has been heard on it.
fn public_chat(node: &CommunicatorNode<Port>) -> u32 {
    chats(node)
        .iter()
        .find(|chat| chat.name == "Public")
        .expect("Public is listed")
        .id
}

/// Each row's message of `chat`, oldest first.
fn row_ids(node: &CommunicatorNode<Port>, chat: u32) -> Vec<u32> {
    (0..node.rows(chat))
        .map(|row| node.row_id(chat, row).unwrap())
        .collect()
}

/// Each row's text of `chat`, oldest first.
fn row_texts(node: &CommunicatorNode<Port>, chat: u32) -> Vec<String> {
    (0..node.rows(chat))
        .map(|row| String::from(&*node.row_message(chat, row).unwrap().text))
        .collect()
}

/// A channel's transcript reads by row, oldest first: who said each, and
/// when, as its neighbors see it.
#[test]
fn a_channel_reads_by_row() {
    let sim = device();
    let (node, clock) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let (mut robin, conversation) = member_session(PublicKey([0x37; 32]), public, "Robin");
    let (mut ash, _) = member_session(PublicKey([0x38; 32]), public, "Ash");
    for (at, (from, body)) in [
        (0x37, "Anyone near the trailhead?"),
        (0x37, "Two of us"),
        (0x38, "Behind you"),
    ]
    .into_iter()
    .enumerate()
    {
        clock.set(1_000 * (at as u64 + 1));
        let session = if from == 0x37 { &mut robin } else { &mut ash };
        let (_, payload) = spoken(session, conversation, text(body));
        node.arrive(Arrival::Text(received(
            &public,
            PublicKey([from; 32]),
            &payload,
        )));
    }
    let chat = public_chat(&node);
    clock.set(4_000);
    let mine = node.send(chat, "On my way", None, false).unwrap();
    events(&node);

    assert_eq!(
        row_texts(&node, chat),
        [
            "Anyone near the trailhead?",
            "Two of us",
            "Behind you",
            "On my way"
        ]
    );
    assert_eq!(*row_ids(&node, chat).last().unwrap(), mine.id);
    assert_eq!(node.row_id(chat, 4), None);
    let names: Vec<Option<String>> = (0..4)
        .map(|row| {
            let neighbor = node.neighbor(chat, row).unwrap();
            assert_eq!(neighbor.presence, Presence::Present);
            neighbor
                .sender
                .map(|sender| String::from(sender.name.as_str()))
        })
        .collect();
    assert_eq!(
        names,
        [
            Some("Robin".into()),
            Some("Robin".into()),
            Some("Ash".into()),
            None
        ]
    );
    assert_eq!(
        node.neighbor(chat, 3).unwrap().direction,
        Direction::Outbound
    );
    assert_eq!(node.time_before(chat, 0), None);
    assert_eq!(node.time_before(chat, 2), Some(STARTED + 2));
    // Mine went out once, and a channel acknowledges nothing.
    assert!(node.depart().is_some());
    let latest = node.latest_sent(chat);
    assert_eq!(latest.sent, Some(mine.id));
    assert_eq!(latest.delivered, None);
}

/// Messages missed and asked for again are one row while they are on
/// their way, and their own rows as each comes.
#[test]
fn a_run_on_its_way_again_is_one_row_until_it_comes() {
    let sim = device();
    let (node, _) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let key = PublicKey([0x37; 32]);
    let (mut robin, conversation) = member_session(key, public, "Robin");
    let payloads: Vec<Vec<u8>> = ["one", "two", "three", "four"]
        .into_iter()
        .map(|body| spoken(&mut robin, conversation, text(body)).1)
        .collect();
    let hear = |payload: &[u8]| node.arrive(Arrival::Text(received(&public, key, payload)));
    hear(&payloads[0]);
    hear(&payloads[3]);
    let chat = public_chat(&node);
    assert_eq!(node.rows(chat), 3, "{:?}", row_ids(&node, chat));
    let pending = node.neighbor(chat, 1).unwrap();
    assert_eq!(pending.presence, Presence::PendingRepair);
    assert_eq!(node.neighbor(chat, 2).unwrap().presence, Presence::Present);

    hear(&payloads[1]);
    assert_eq!(node.rows(chat), 4);
    assert_eq!(node.neighbor(chat, 1).unwrap().presence, Presence::Present);
    assert_eq!(
        node.neighbor(chat, 2).unwrap().presence,
        Presence::PendingRepair
    );

    hear(&payloads[2]);
    assert_eq!(row_texts(&node, chat), ["one", "two", "three", "four"]);
}

/// The heap, counted while one thread asks it to be.
struct Counting;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call goes on to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        _ = COUNTING.try_with(|counting| {
            if counting.get() {
                ALLOCATIONS.set(ALLOCATIONS.get() + 1);
            }
        });
        // SAFETY: the caller's promises are the system allocator's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as for `alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static HEAP: Counting = Counting;

/// How many times `read` took from the heap.
fn allocations(read: impl FnOnce()) -> usize {
    ALLOCATIONS.set(0);
    COUNTING.set(true);
    read();
    COUNTING.set(false);
    ALLOCATIONS.get()
}

/// What a row's neighbors read of it takes nothing from the heap, even
/// beside messages that carry reactions.
#[test]
fn reading_a_row_for_its_neighbors_allocates_nothing() {
    let sim = device();
    let (node, clock) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let robin_key = PublicKey([0x37; 32]);
    let ash_key = PublicKey([0x38; 32]);
    let (mut robin, conversation) = member_session(robin_key, public, "Robin");
    let (mut ash, _) = member_session(ash_key, public, "Ash");
    let (asked, payload) = spoken(&mut robin, conversation, text("Anyone near the trailhead?"));
    node.arrive(Arrival::Text(received(&public, robin_key, &payload)));
    clock.set(2_000);
    let (_, payload) = spoken(&mut ash, conversation, text("Behind you"));
    node.arrive(Arrival::Text(received(&public, ash_key, &payload)));
    let (_, payload) = spoken(
        &mut robin,
        conversation,
        ComposeIntent::Reply {
            body: "+1",
            regarding: asked.unwrap(),
            status: true,
        },
    );
    node.arrive(Arrival::Text(received(&public, robin_key, &payload)));
    let chat = public_chat(&node);
    clock.set(3_000);
    node.send(chat, "On my way", None, false).unwrap();
    let last = node.rows(chat) - 1;
    node.react(
        chat,
        node.row_id(chat, last).unwrap(),
        Some(Reaction::Heart),
    );
    assert!(!node.row_message(chat, 0).unwrap().reactions.is_empty());
    assert!(!node.row_message(chat, last).unwrap().reactions.is_empty());

    // The rows are taken once, after the store changes; what is read of
    // them after takes nothing.
    assert_eq!(node.rows(chat), 3);
    let taken = allocations(|| {
        for row in 0..3 {
            assert!(node.neighbor(chat, row).is_some());
            node.time_before(chat, row);
            node.row_id(chat, row);
        }
        node.latest_sent(chat);
    });
    assert_eq!(taken, 0);
    // The whole message, its reactions with it, does.
    assert!(allocations(|| _ = node.row_message(chat, 0)) > 0);
}

// ─── Sending ─────────────────────────────────────────────────────────

/// Robin's address, as typed.
fn address_of(key: &PublicKey) -> String {
    umsh_core::base58::encode(&key.0)
        .iter()
        .map(|&digit| char::from(digit))
        .collect()
}

/// A direct message is kept as Sending and handed to the device node; a
/// frame that cannot go makes it Unconfirmed, and a retry sends it again.
#[test]
fn a_direct_message_goes_out_and_can_be_retried() {
    let sim = device();
    let (node, _) = started(&sim);
    let robin = PublicKey([0x37; 32]);
    let avatar = node.avatar();
    let chat = node
        .direct_chat(&address_of(&robin), "Robin", &avatar)
        .unwrap();
    assert_eq!(chat.name, "Robin");
    assert_eq!(chat.kind, ChatKind::Peer { hops: None });
    events(&node);

    let message = node.send(chat.id, "On my way", None, false).unwrap();
    assert_eq!(message.delivery, Delivery::Sending);
    assert_eq!(message.direction, Direction::Outbound);
    let departure = node.depart().expect("the message leaves");
    assert!(node.depart().is_none(), "one frame");

    assert!(node.departed(departure, Sent::Unsendable));
    // Announced as having come out, so the interface can say so.
    let settled = NodeEvent::Settled {
        chat: chat.id,
        message: message.id,
    };
    assert!(events(&node).contains(&settled));
    let failed = node.message(chat.id, message.id).unwrap();
    assert_eq!(failed.delivery, Delivery::Unconfirmed);

    assert!(node.retry(chat.id, message.id));
    assert_eq!(
        node.message(chat.id, message.id).unwrap().delivery,
        Delivery::Sending
    );
    // Read by row too, before any word on it.
    assert_eq!(
        node.row_message(chat.id, 0).unwrap().delivery,
        Delivery::Sending
    );
    assert_eq!(node.latest_sent(chat.id).sent, Some(message.id));
    let again = node.depart().expect("the message leaves again");
    events(&node);
    assert!(node.departed(again, Sent::Unsendable));
    assert_eq!(
        node.message(chat.id, message.id).unwrap().delivery,
        Delivery::Unconfirmed
    );
    // Failing again comes out again.
    assert!(events(&node).contains(&settled));
}

/// A node over the store kept on `flash`, started.
fn node_on(
    sim: &Rc<RefCell<SimulatedDevice>>,
    flash: &SharedFlash,
) -> CommunicatorNode<Port, FlashMapStore<SharedFlash>> {
    let clock: &'static TestClock = Box::leak(Box::new(TestClock(AtomicU64::new(0))));
    let buffer = Box::leak(vec![0u8; 2048].into_boxed_slice());
    let size = flash.0.borrow().bytes().len() as u32;
    let store = FlashMapStore::mount(
        FlashMap::new(flash.clone(), 0..size, buffer),
        Quota::DEFAULT,
    )
    .unwrap();
    let node = CommunicatorNode::new(
        Port(sim.clone()),
        store,
        ChannelCrypto::software(),
        &std::alloc::System,
        clock,
        Seeds {
            session_id: 1,
            jitter_seed: 2,
        },
    );
    node.pump();
    assert!(node.started());
    while node.next_event().is_some() {}
    node
}

/// A node started again over the same flash has its chats, and carries a
/// conversation's sequence on rather than resetting it.
#[test]
fn a_restarted_node_keeps_its_chats_and_its_sequence() {
    let sim = device();
    identify(&sim);
    let flash = SharedFlash::new(64 * 4096);
    let robin = PublicKey([0x37; 32]);

    let first = node_on(&sim, &flash);
    let chat = first
        .direct_chat(&address_of(&robin), "Robin", &first.avatar())
        .unwrap();
    let said = first.send(chat.id, "On my way", None, false).unwrap();
    let departed = first.depart().unwrap();
    let before = umsh_text::codec::parse(departed.payload()).unwrap();
    let before = before.sequence.unwrap().message_id;
    drop(first);

    let second = node_on(&sim, &flash);
    let mut kept = Chats::new();
    second.chats(&mut kept);
    let chat = kept.iter().find(|kept| kept.name == "Robin").unwrap();
    let message = second.message(chat.id, said.id).unwrap();
    assert_eq!(&*message.text, "On my way");

    second.send(chat.id, "Almost there", None, false).unwrap();
    let departed = second.depart().unwrap();
    let after = umsh_text::codec::parse(departed.payload()).unwrap();
    assert!(!after.sequence_reset, "the stream goes on");
    assert_eq!(after.sequence.unwrap().message_id, before.wrapping_add(1));
}

/// A message on its way when the node stopped reads Unconfirmed once it
/// starts again, and a retry sends it under its wire ID, with word of it
/// reaching the message.
#[test]
fn a_message_cut_off_by_a_restart_can_be_retried() {
    let sim = device();
    identify(&sim);
    let flash = SharedFlash::new(64 * 4096);
    let robin = PublicKey([0x37; 32]);

    let first = node_on(&sim, &flash);
    let chat = first
        .direct_chat(&address_of(&robin), "Robin", &first.avatar())
        .unwrap();
    let said = first.send(chat.id, "On my way", None, false).unwrap();
    let departed = first.depart().unwrap();
    let wire = umsh_text::codec::parse(departed.payload()).unwrap();
    let wire = wire.sequence.unwrap().message_id;
    drop(first);

    let second = node_on(&sim, &flash);
    assert_eq!(
        second.message(chat.id, said.id).unwrap().delivery,
        Delivery::Unconfirmed
    );
    assert!(second.retry(chat.id, said.id));
    assert_eq!(
        second.message(chat.id, said.id).unwrap().delivery,
        Delivery::Sending
    );
    let again = second.depart().expect("the message leaves again");
    let resent = umsh_text::codec::parse(again.payload()).unwrap();
    assert_eq!(resent.sequence.unwrap().message_id, wire);
    assert!(second.departed(again, Sent::Unsendable));
    assert_eq!(
        second.message(chat.id, said.id).unwrap().delivery,
        Delivery::Unconfirmed
    );
}

/// Sending clears the chat's draft, and the chat moves to the top.
#[test]
fn sending_clears_the_draft() {
    let sim = device();
    let (node, _) = started(&sim);
    let chat = chats(&node)[1].id;
    node.save_draft(chat, "Back at six");
    let message = node.send(chat, "Back at six", None, false).unwrap();
    assert_eq!(&*message.text, "Back at six");
    let summary = node.chat(chat).unwrap();
    assert_eq!(summary.draft.text(), "");
    assert_eq!(chats(&node)[0].id, chat);
    // A channel message goes as one multicast.
    assert!(node.depart().is_some());
}

/// A reaction is kept on what it is about, and sent.
#[test]
fn a_reaction_is_kept_and_sent() {
    let sim = device();
    let (node, _) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let robin = PublicKey([0x37; 32]);
    let payload = composed(robin, public, "Robin", "Anyone near the trailhead?");
    node.arrive(Arrival::Text(received(&public, robin, &payload)));
    let Some(NodeEvent::Arrived { chat, message }) = events(&node)
        .into_iter()
        .find(|event| matches!(event, NodeEvent::Arrived { .. }))
    else {
        panic!("nothing arrived");
    };
    node.react(chat, message, Some(Reaction::Heart));
    let reacted = node.message(chat, message).unwrap();
    assert!(
        reacted
            .reactions
            .iter()
            .any(|r| r.reaction == Reaction::Heart && r.mine)
    );
    assert_eq!(node.row_message(chat, 0).unwrap(), reacted);
    assert!(node.depart().is_some());
}

/// Robin's reaction to their own message on Public reaches its chips, and
/// taking it back clears them.
#[test]
fn a_reaction_from_another_node_is_shown_and_withdrawn() {
    let sim = device();
    let (node, _) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let robin = PublicKey([0x37; 32]);
    let mut facade: ChatFacade = ChatFacade::new(
        DirectChannelProfile,
        robin,
        EngineConfig::default(),
        Seeds {
            session_id: 7,
            jitter_seed: 8,
        },
    );
    facade.channels_mut().register(tag(&public), public, None);
    let conversation = ConversationKey::ChannelGroup {
        channel: tag(&public),
    };
    fn say(
        facade: &mut ChatFacade,
        conversation: ConversationKey,
        intent: ComposeIntent<'_>,
    ) -> (Option<RegardingRef>, Vec<u8>) {
        let batch = facade.compose(conversation, 1, intent, None, 0).unwrap();
        let handle = batch
            .mutations
            .first()
            .map(|mutation| RegardingRef::Handle(mutation.handle));
        let outbound = facade.commit(batch).unwrap();
        (handle, outbound.transmissions()[0].payload.to_vec())
    }
    let (asked, payload) = say(
        &mut facade,
        conversation,
        ComposeIntent::Text {
            body: "Anyone near the trailhead?",
            status: false,
        },
    );
    node.arrive(Arrival::Text(received(&public, robin, &payload)));
    let Some(NodeEvent::Arrived { chat, message }) = events(&node)
        .into_iter()
        .find(|event| matches!(event, NodeEvent::Arrived { .. }))
    else {
        panic!("nothing arrived");
    };

    let regarding = asked.unwrap();
    for (body, shown) in [("+1", Some(Reaction::ThumbsUp)), ("", None)] {
        let (_, payload) = say(
            &mut facade,
            conversation,
            ComposeIntent::Reply {
                body,
                regarding,
                status: true,
            },
        );
        node.arrive(Arrival::Text(received(&public, robin, &payload)));
        assert!(
            events(&node).contains(&NodeEvent::MessageChanged { chat, message }),
            "{body:?}"
        );
        let reactions = node.message(chat, message).unwrap().reactions;
        let theirs: Vec<_> = reactions
            .iter()
            .map(|r| (r.reaction, r.count, r.mine))
            .collect();
        assert_eq!(
            theirs,
            shown.map(|r| (r, 1, false)).into_iter().collect::<Vec<_>>()
        );
        // Details say who.
        let reactors = node.details(chat, message).unwrap().reactors;
        let who: Vec<_> = reactors
            .iter()
            .map(|r| (r.name.as_deref().map(String::from), r.reaction))
            .collect();
        let robin_shown = format!("Member {}", &address_of(&robin)[..4]);
        assert_eq!(
            who,
            shown
                .map(|r| (Some(robin_shown.clone()), r))
                .into_iter()
                .collect::<Vec<_>>()
        );
    }

    // Mine is listed as mine.
    node.react(chat, message, Some(Reaction::Heart));
    let reactors = node.details(chat, message).unwrap().reactors;
    assert_eq!(reactors.len(), 1);
    assert_eq!(reactors[0].name, None);
    assert_eq!(reactors[0].reaction, Reaction::Heart);
}

/// A reply arrives quoting whom and what it answers.
#[test]
fn a_reply_quotes_what_it_answers() {
    let sim = device();
    let (node, _) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let robin = PublicKey([0x37; 32]);
    let mut facade: ChatFacade = ChatFacade::new(
        DirectChannelProfile,
        robin,
        EngineConfig::default(),
        Seeds {
            session_id: 7,
            jitter_seed: 8,
        },
    );
    facade.channels_mut().register(tag(&public), public, None);
    facade.set_local_handle("Robin");
    let conversation = ConversationKey::ChannelGroup {
        channel: tag(&public),
    };
    let mut say = |intent| {
        let batch = facade.compose(conversation, 1, intent, None, 0).unwrap();
        let handle = batch
            .mutations
            .first()
            .map(|m| RegardingRef::Handle(m.handle));
        let outbound = facade.commit(batch).unwrap();
        (handle, outbound.transmissions()[0].payload.to_vec())
    };
    let (asked, payload) = say(ComposeIntent::Text {
        body: "Anyone near the trailhead?",
        status: false,
    });
    node.arrive(Arrival::Text(received(&public, robin, &payload)));
    let (_, payload) = say(ComposeIntent::Reply {
        body: "Never mind, found them",
        regarding: asked.unwrap(),
        status: false,
    });
    node.arrive(Arrival::Text(received(&public, robin, &payload)));
    let arrived: Vec<_> = events(&node)
        .into_iter()
        .filter_map(|event| match event {
            NodeEvent::Arrived { chat, message } => Some((chat, message)),
            _ => None,
        })
        .collect();
    let &(chat, message) = arrived.last().unwrap();
    let reply = node.message(chat, message).unwrap().reply.unwrap();
    assert_eq!(reply.name.as_deref(), Some("Robin"));
    assert_eq!(&*reply.text, "Anyone near the trailhead?");
}

// ─── Peers ───────────────────────────────────────────────────────────

/// How a frame came, one link away or more.
fn rx(hop_count: u8) -> RxSummary {
    RxSummary {
        rssi_dbm: Some(-97),
        snr_centibels: Some(65),
        lqi: None,
        hop_count: Some(hop_count),
        route_hints: Vec::new(),
        source_authenticated: true,
        forward_secret: false,
        buffered_age_s: 0,
    }
}

/// A chatting node's identity, named `name`.
fn chatter(name: &str) -> NodeIdentityPayload {
    let mut bytes = vec![
        NodeRole::Chat.as_byte(),
        NodeCapabilities::TEXT_MESSAGES.bits(),
        name.len() as u8,
    ];
    bytes.extend_from_slice(name.as_bytes());
    NodeIdentityPayload::from_bytes(&bytes).unwrap()
}

/// A node heard is found by a word of its name, until it is saved.
#[test]
fn a_heard_node_is_found_by_name() {
    let sim = device();
    let (node, clock) = started(&sim);
    let robin = PublicKey([0x37; 32]);
    clock.set(5_000);
    node.arrive(Arrival::Identity {
        key: robin,
        identity: chatter("Robin Ridge"),
        payload: Vec::new(),
        rx: rx(1),
    });
    clock.set(65_000);
    let found = node.find_heard("rid");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "Robin Ridge");
    assert_eq!(found[0].distance, "Nearby");
    assert_eq!(found[0].age, "1m");
    assert_eq!(found[0].address.as_str(), address_of(&robin));
    assert!(node.find_heard("trail").is_empty());

    // Its direct chat is called by its own name.
    let avatar = node.avatar();
    let chat = node
        .direct_chat(&address_of(&robin), "Robin Ridge", &avatar)
        .unwrap();
    assert_eq!(chat.name, "Robin Ridge");
    assert_eq!(chat.kind, ChatKind::Peer { hops: Some(1) });
}

/// A member saved is kept by the device, listed among the peers, and let
/// go of again.
#[test]
fn a_saved_member_is_kept_by_the_device() {
    let sim = device();
    let (node, clock) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let robin = PublicKey([0x37; 32]);
    let payload = composed(robin, public, "Robin", "Anyone near the trailhead?");
    node.arrive(Arrival::Text(received(&public, robin, &payload)));
    let Some(NodeEvent::Arrived { chat, message }) = events(&node)
        .into_iter()
        .find(|event| matches!(event, NodeEvent::Arrived { .. }))
    else {
        panic!("nothing arrived");
    };
    let member = node.member(chat, message).unwrap();
    assert!(!member.saved);
    let summary = node.save_peer(&member).unwrap();
    assert_eq!(summary.name, "Robin");
    assert!(node.member(chat, message).unwrap().saved);

    clock.set(1_000);
    node.pump();
    let listed = peers(&node);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, summary.id);
    // Another node over the device reads it there.
    assert_eq!(peers(&node_over(&sim)).len(), 1);
    let detail = node.peer_detail(summary.id).unwrap();
    assert_eq!(detail.address.as_str(), address_of(&robin));
    events(&node);

    node.forget_peer(summary.id);
    assert_eq!(events(&node), [NodeEvent::PeerRemoved(summary.id)]);
    clock.set(2_000);
    node.pump();
    assert!(peers(&node).is_empty());
    assert!(peers(&node_over(&sim)).is_empty());
    assert!(!node.member(chat, message).unwrap().saved);
}

/// A peer a phone saves on the device shows among the peers.
#[test]
fn a_peer_saved_elsewhere_is_listed() {
    let sim = device();
    let (node, clock) = started(&sim);
    let robin = PublicKey([0x37; 32]);
    phone_inserts(&sim, prop::DEV_PEERS, &robin.0);
    clock.set(2_000);
    node.pump();
    let peers = peers(&node);
    assert_eq!(peers.len(), 1);
    assert!(events(&node).contains(&NodeEvent::PeerChanged(peers[0].id)));
}

/// A saved peer's row says how they were heard as soon as a message from
/// them arrives, counting hops as the protocol does, and stops saying
/// where they are once that is old.
#[test]
fn a_saved_peers_row_follows_how_they_are_heard() {
    let sim = device();
    let (node, clock) = started(&sim);
    let robin = PublicKey([0x37; 32]);
    phone_inserts(&sim, prop::DEV_PEERS, &robin.0);
    clock.set(2_000);
    node.pump();
    let peer = peers(&node)[0].id;
    assert_eq!(peers(&node)[0].hops, None);
    events(&node);

    let public = WellKnownChannels::derive().public;
    let payload = composed(robin, public, "Robin", "Anyone near the trailhead?");
    let mut inbound = received(&public, robin, &payload);
    inbound.rx.hop_count = Some(1);
    clock.set(5_000);
    node.arrive(Arrival::Text(inbound));
    assert!(events(&node).contains(&NodeEvent::PeerChanged(peer)));
    assert_eq!(peers(&node)[0].hops, Some(1));
    assert!(peers(&node)[0].signal.is_some());
    let route = node.peer_detail(peer).unwrap().route.unwrap();
    assert!(route.starts_with("Direct \u{B7} "), "{route}");

    // Through one repeater: two hops, and no signal of theirs to show.
    let payload = composed(robin, public, "Robin", "Past the ridge now");
    let mut relayed = received(&public, robin, &payload);
    relayed.rx.hop_count = Some(2);
    node.arrive(Arrival::Text(relayed));
    assert_eq!(peers(&node)[0].hops, Some(2));
    assert_eq!(peers(&node)[0].signal, None);
    assert_eq!(
        node.peer_detail(peer).unwrap().route.as_deref(),
        Some("2 hops")
    );
    events(&node);

    clock.set(5_000 + 29 * 60 * 1_000);
    node.tick();
    assert!(!events(&node).contains(&NodeEvent::PeerChanged(peer)));
    clock.set(5_000 + 30 * 60 * 1_000);
    node.tick();
    assert!(events(&node).contains(&NodeEvent::PeerChanged(peer)));
    let lapsed = &peers(&node)[0];
    assert_eq!(lapsed.hops, None);
    assert_eq!(lapsed.signal, None);
    assert_eq!(lapsed.heard, "30m");
}

/// A saved peer is asked for their identity directly, and listed by the
/// name they answer with.
#[test]
fn a_saved_peer_is_asked_for_their_identity() {
    let sim = device();
    let (node, clock) = started(&sim);
    let robin = PublicKey([0x37; 32]);
    phone_inserts(&sim, prop::DEV_PEERS, &robin.0);
    clock.set(2_000);
    node.pump();
    let peer = peers(&node)[0].id;
    events(&node);

    node.request_peer_identity(peer);
    let Some(Command::AskPeer { peer: asked, .. }) = node.command() else {
        panic!("nothing asked");
    };
    assert_eq!(asked, robin);

    node.arrive(Arrival::Identity {
        key: robin,
        identity: chatter("Robin"),
        payload: Vec::new(),
        rx: rx(1),
    });
    assert!(events(&node).contains(&NodeEvent::PeerChanged(peer)));
    assert_eq!(peers(&node)[0].name, "Robin");
}

/// A member saved by the name they gave in a channel goes by each name
/// their identity gives after; an alias given here goes before all of
/// them, in their chat as well, until it is taken away.
#[test]
fn a_saved_peer_follows_their_identity_until_given_an_alias() {
    let sim = device();
    let (node, _clock) = started(&sim);
    let public = WellKnownChannels::derive().public;
    let robin = PublicKey([0x37; 32]);
    let payload = composed(robin, public, "Robin", "Anyone near the trailhead?");
    node.arrive(Arrival::Text(received(&public, robin, &payload)));
    let Some(NodeEvent::Arrived { chat, message }) = events(&node)
        .into_iter()
        .find(|event| matches!(event, NodeEvent::Arrived { .. }))
    else {
        panic!("nothing arrived");
    };
    let member = node.member(chat, message).unwrap();
    let peer = node.save_peer(&member).unwrap().id;
    assert_eq!(peers(&node)[0].name, "Robin");
    let avatar = node.avatar();
    let direct = node
        .direct_chat(&address_of(&robin), "Robin", &avatar)
        .unwrap()
        .id;
    let identify = |name| {
        node.arrive(Arrival::Identity {
            key: robin,
            identity: chatter(name),
            payload: Vec::new(),
            rx: rx(1),
        })
    };
    let chat_name = || node.chat(direct).unwrap().name;

    identify("Robin Ridge");
    assert_eq!(peers(&node)[0].name, "Robin Ridge");
    identify("Ridge Camp");
    assert_eq!(peers(&node)[0].name, "Ridge Camp");
    assert_eq!(chat_name(), "Ridge Camp");
    events(&node);

    node.set_peer_alias(peer, Some("Rob"));
    let changed = events(&node);
    assert!(changed.contains(&NodeEvent::PeerChanged(peer)));
    assert!(changed.contains(&NodeEvent::ChatChanged(direct)));
    identify("Trail Boss");
    assert_eq!(peers(&node)[0].name, "Rob");
    assert_eq!(chat_name(), "Rob");
    let detail = node.peer_detail(peer).unwrap();
    assert_eq!(detail.alias.as_deref(), Some("Rob"));
    assert_eq!(detail.advertised.as_deref(), Some("Trail Boss"));

    node.set_peer_alias(peer, None);
    assert_eq!(peers(&node)[0].name, "Trail Boss");
    assert_eq!(node.peer_detail(peer).unwrap().alias, None);
}

/// A session with forward secrecy is asked for when a saved peer comes to
/// prefer one, again when it ends, and when next needed after one could
/// not be had; it is ended when they no longer prefer one.
#[test]
fn forward_secrecy_is_asked_for_and_kept() {
    let sim = device();
    let (node, clock) = started(&sim);
    let robin = PublicKey([0x37; 32]);
    phone_inserts(&sim, prop::DEV_PEERS, &robin.0);
    clock.set(2_000);
    node.pump();
    let peer = peers(&node)[0].id;
    events(&node);
    let asked = |node: &CommunicatorNode<Port>| match node.command() {
        Some(Command::StartSecrecy { peer, .. }) => peer == robin,
        _ => false,
    };

    node.set_forward_secrecy(peer, true);
    assert!(events(&node).contains(&NodeEvent::PeerChanged(peer)));
    assert!(node.peer_detail(peer).unwrap().forward_secrecy);
    assert!(asked(&node));
    node.set_forward_secrecy(peer, true);
    assert!(node.command().is_none(), "asked once");

    node.arrive(Arrival::Secrecy {
        peer: robin,
        change: Secrecy::Established,
    });
    assert!(node.command().is_none());
    node.arrive(Arrival::Secrecy {
        peer: robin,
        change: Secrecy::Ended,
    });
    assert!(asked(&node), "asked again when it ends");

    node.arrive(Arrival::Secrecy {
        peer: robin,
        change: Secrecy::Failed,
    });
    assert!(node.command().is_none(), "not asked again at once");
    let avatar = node.avatar();
    let chat = node
        .direct_chat(&address_of(&robin), "Robin", &avatar)
        .unwrap();
    node.send(chat.id, "On my way", None, false).unwrap();
    assert!(asked(&node), "asked again when next needed");
    assert!(node.depart().is_some(), "the message does not wait");

    node.set_forward_secrecy(peer, false);
    assert!(!node.peer_detail(peer).unwrap().forward_secrecy);
    assert!(matches!(
        node.command(),
        Some(Command::EndSecrecy { peer, .. }) if peer == robin
    ));
    node.send(chat.id, "Here", None, false).unwrap();
    assert!(node.command().is_none(), "no longer asked");
}

/// What is sent while the chat shows a session with forward secrecy goes
/// under one or not at all: when it cannot, it waits to be sent again as
/// it was, or without, as I choose. What is sent otherwise never goes
/// under one.
#[test]
fn a_message_shown_under_forward_secrecy_never_goes_without() {
    let sim = device();
    let (node, clock) = started(&sim);
    let robin = PublicKey([0x37; 32]);
    phone_inserts(&sim, prop::DEV_PEERS, &robin.0);
    clock.set(2_000);
    node.pump();
    let peer = peers(&node)[0].id;
    let avatar = node.avatar();
    let chat = node
        .direct_chat(&address_of(&robin), "Robin", &avatar)
        .unwrap();
    node.set_forward_secrecy(peer, true);
    while node.command().is_some() {}
    events(&node);
    assert!(
        !node.chat(chat.id).unwrap().forward_secret,
        "not until held"
    );
    node.arrive(Arrival::Secrecy {
        peer: robin,
        change: Secrecy::Established,
    });
    assert!(events(&node).contains(&NodeEvent::ChatChanged(chat.id)));
    assert!(node.chat(chat.id).unwrap().forward_secret);

    let message = node.send(chat.id, "Meet at the ridge", None, true).unwrap();
    assert!(message.forward_secret);
    let departure = node.depart().expect("the message leaves");
    assert_eq!(departure.forward_secrecy(), Some(true));
    // The session lapsed before it went.
    assert!(node.departed(departure, Sent::Unsendable));
    let failed = node.message(chat.id, message.id).unwrap();
    assert_eq!(failed.delivery, Delivery::Unconfirmed);
    assert!(failed.forward_secret);

    assert!(node.retry(chat.id, message.id));
    let again = node.depart().expect("it leaves again");
    assert_eq!(again.forward_secrecy(), Some(true), "as it was");
    assert!(node.departed(again, Sent::Unsendable));

    events(&node);
    assert!(node.retry_without_secrecy(chat.id, message.id));
    assert!(events(&node).contains(&NodeEvent::MessageChanged {
        chat: chat.id,
        message: message.id
    }));
    let without = node.message(chat.id, message.id).unwrap();
    assert!(!without.forward_secret);
    assert_eq!(without.delivery, Delivery::Sending);
    let plain = node.depart().expect("it leaves without");
    assert_eq!(plain.forward_secrecy(), Some(false));
    assert!(node.departed(plain, Sent::Unsendable));

    node.send(chat.id, "Here", None, false).unwrap();
    let held = node.depart().expect("the next leaves");
    assert_eq!(held.forward_secrecy(), Some(false), "though one is held");
}

/// A member known only by their hint is asked about on their channel,
/// and known by name and address once they answer.
#[test]
fn a_member_known_by_hint_is_asked_for() {
    let sim = device();
    let (node, clock) = started(&sim);
    let crew = ChannelKey([0x5C; 32]);
    phone_inserts(&sim, prop::DEV_CHANNEL_KEYS, &crew.0);
    clock.set(1_000);
    node.pump();
    let robin = PublicKey([0x37; 32]);
    let payload = composed(robin, crew, "", "hello");
    node.arrive(Arrival::Text(channel_frame(&crew, robin, false, &payload)));
    let Some(NodeEvent::Arrived { chat, message }) = events(&node)
        .into_iter()
        .find(|event| matches!(event, NodeEvent::Arrived { .. }))
    else {
        panic!("nothing arrived");
    };
    assert_eq!(node.member(chat, message).unwrap().address, None);

    node.request_identity(chat, message);
    let Some(Command::AskChannel { channel, hint, .. }) = node.command() else {
        panic!("nothing asked");
    };
    assert_eq!(channel, crew);
    assert_eq!(hint, robin.hint());

    clock.set(3_000);
    node.arrive(Arrival::Identity {
        key: robin,
        identity: chatter("Robin"),
        payload: Vec::new(),
        rx: rx(2),
    });
    assert!(events(&node).contains(&NodeEvent::IdentitiesLearned));
    let member = node.member(chat, message).unwrap();
    assert_eq!(member.address.as_deref(), Some(address_of(&robin).as_str()));
}

/// Add peer reads an address as far as it goes, and a whole one as the
/// node it names.
#[test]
fn an_address_is_read_as_it_is_typed() {
    let sim = device();
    let (node, _) = started(&sim);
    let robin = PublicKey([0x37; 32]);
    let address = address_of(&robin);
    assert_eq!(node.inspect_peer(""), PeerEntry::Empty);
    assert_eq!(node.inspect_peer("0OIl"), PeerEntry::Invalid);
    let PeerEntry::Partial { missing, .. } = node.inspect_peer(&address[..10]) else {
        panic!("not partial");
    };
    assert_eq!(usize::from(missing), address.len() - 10);
    let PeerEntry::Complete {
        address: whole,
        name,
        ..
    } = node.inspect_peer(&format!("umsh:n:{address}"))
    else {
        panic!("not complete");
    };
    assert_eq!(whole.as_str(), address);
    assert_eq!(name, None);
}

/// A second node over `sim`, as a reboot would start one.
fn node_over(sim: &Rc<RefCell<SimulatedDevice>>) -> CommunicatorNode<Port> {
    let (node, _) = node(sim);
    node.pump();
    node
}

fn peers(node: &CommunicatorNode<Port>) -> Peers {
    let mut peers = Peers::new();
    node.peers(&mut peers);
    peers
}

/// `signer`'s chatting identity named `name`, signed by it, and the link
/// that carries it.
fn signed_link(signer: &SoftwareIdentity, name: &str) -> (Vec<u8>, String) {
    let identity = chatter(name);
    let mut buf = [0u8; 128];
    let len = identity.encode_for_signing(&mut buf).unwrap();
    let signature = ready(signer.sign(&buf[..len])).unwrap();
    let mut payload = buf[..len].to_vec();
    payload.extend_from_slice(&signature);
    let link = format!(
        "umsh:n:{}:{}",
        address_of(signer.public_key()),
        umsh_uri::encode_base58_bytes(&payload)
    );
    (payload, link)
}

/// An unsigned link for `key`, naming it `name`.
fn unsigned_link(key: &PublicKey, name: &str) -> String {
    let mut buf = [0u8; 64];
    let len = chatter(name).encode(&mut buf).unwrap();
    format!(
        "umsh:n:{}:{}",
        address_of(key),
        umsh_uri::encode_base58_bytes(&buf[..len])
    )
}

fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match std::pin::pin!(future).poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("software signing never waits"),
    }
}

/// What `text`, said on `public` by the member `from`, arrives as.
fn said_on_public(
    node: &CommunicatorNode<Port>,
    from: u8,
    text: &str,
) -> umsh_ux_communicator::model::Message {
    let public = WellKnownChannels::derive().public;
    let member = PublicKey([from; 32]);
    let payload = composed(member, public, "Robin", text);
    node.arrive(Arrival::Text(received(&public, member, &payload)));
    let Some(NodeEvent::Arrived { chat, message }) = events(&node)
        .into_iter()
        .find(|event| matches!(event, NodeEvent::Arrived { .. }))
    else {
        panic!("nothing arrived");
    };
    node.message(chat, message).unwrap()
}

/// A message that is nothing but a node's link shows as its contact, called
/// what its signed identity says, and opening it saves nothing.
#[test]
fn a_contact_in_a_message_shows_as_a_card() {
    let sim = device();
    let (node, _) = started(&sim);
    let kit = SoftwareIdentity::from_secret_bytes(&[0x51; 32]);
    let (_, link) = signed_link(&kit, "Kit");

    let message = said_on_public(&node, 0x37, &link);
    let contact = message.contact().expect("a contact card");
    assert_eq!(&*contact.name, "Kit");
    assert_eq!(contact.key, kit.public_key().0);
    let member = node.known_member(&link).unwrap();
    assert_eq!(member.sender.name, "Kit");
    assert_eq!(
        member.address.as_deref(),
        Some(address_of(kit.public_key()).as_str())
    );
    assert!(!member.saved);
    assert!(peers(&node).is_empty());

    // Text around a link is a message, not a contact.
    assert_eq!(
        said_on_public(&node, 0x38, &format!("this is {link}")).card,
        None
    );

    // A signature that is not the key's leaves the link's name out.
    let ash = SoftwareIdentity::from_secret_bytes(&[0x52; 32]);
    let (_, forged) = signed_link(&kit, "Ash");
    let forged = forged.replace(&address_of(kit.public_key()), &address_of(ash.public_key()));
    let lettering = &address_of(ash.public_key())[..4];
    let message = said_on_public(&node, 0x39, &forged);
    assert_eq!(&*message.contact().unwrap().name, lettering);
    assert_eq!(node.known_member(&forged).unwrap().sender.name, lettering);
}

/// What a node says of itself is never replaced by what a link says of it.
#[test]
fn a_nodes_own_name_outranks_a_link() {
    let sim = device();
    let (node, _) = started(&sim);
    let kit = *SoftwareIdentity::from_secret_bytes(&[0x51; 32]).public_key();
    let address = address_of(&kit);

    // Someone else's word stands until the node's own arrives.
    assert_eq!(
        node.known_member(&unsigned_link(&kit, "Kay"))
            .unwrap()
            .sender
            .name,
        "Kay"
    );
    node.arrive(Arrival::Identity {
        key: kit,
        identity: chatter("Kit"),
        payload: Vec::new(),
        rx: rx(1),
    });
    assert_eq!(node.known_member(&address).unwrap().sender.name, "Kit");
    assert_eq!(
        node.known_member(&unsigned_link(&kit, "Kay"))
            .unwrap()
            .sender
            .name,
        "Kit"
    );
}

/// A saved peer's contact carries their own signed identity, which a node
/// it reaches takes as their own word.
#[test]
fn a_saved_peer_is_shared_with_their_own_signed_identity() {
    let sim = device();
    let (node, _) = started(&sim);
    let kit = SoftwareIdentity::from_secret_bytes(&[0x51; 32]);
    let key = *kit.public_key();
    let (payload, link) = signed_link(&kit, "Kit");
    node.arrive(Arrival::Identity {
        key,
        identity: NodeIdentityPayload::from_bytes(&payload).unwrap(),
        payload: payload.clone(),
        rx: rx(1),
    });
    let member = node.known_member(&address_of(&key)).unwrap();
    let saved = node.save_peer(&member).unwrap();
    assert_eq!(node.contact_uri(saved.id).unwrap().as_str(), link);

    let other = device();
    let (elsewhere, _) = started(&other);
    let member = elsewhere.known_member(&link).unwrap();
    assert_eq!(member.sender.name, "Kit");
    assert!(!member.saved);

    // Without a signed identity kept, the link is the address alone.
    let ash = PublicKey([0x38; 32]);
    node.arrive(Arrival::Identity {
        key: ash,
        identity: chatter("Ash"),
        payload: Vec::new(),
        rx: rx(1),
    });
    let saved = node
        .save_peer(&node.known_member(&address_of(&ash)).unwrap())
        .unwrap();
    assert_eq!(
        node.contact_uri(saved.id).unwrap().as_str(),
        format!("umsh:n:{}", address_of(&ash))
    );
}
