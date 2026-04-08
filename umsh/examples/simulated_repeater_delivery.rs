use std::cell::RefCell;
use std::future::{Future, poll_fn};
use std::rc::Rc;
use std::task::{Poll, RawWaker, RawWakerVTable, Waker};

use rand::rngs::ThreadRng;
use umsh::{
    core::{PacketHeader, ParsedOptions, PublicKey},
    crypto::{
        CryptoEngine, NodeIdentity,
        software::{SoftwareAes, SoftwareIdentity, SoftwareSha256},
    },
    embassy_support::{EmbassyClock, EmbassyPlatform, MemoryCounterStore, MemoryKeyValueStore},
    mac::{
        CachedRoute, Mac, MacEventRef, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions,
        test_support::SimulatedNetwork,
    },
    node::Host,
    text::{TextReceiveIssue, UnicastTextChatWrapper},
    uri::encode_public_key_base58,
};

const IDENTITIES: usize = 4;
const PEERS: usize = 16;
const CHANNELS: usize = 8;
const ACKS: usize = 16;
const TX: usize = 16;
const FRAME: usize = 256;
const DUP: usize = 64;

type RepeaterPlatform = EmbassyPlatform<
    umsh::mac::test_support::SimulatedRadio,
    ThreadRng,
    MemoryCounterStore<4, 32>,
    MemoryKeyValueStore<4, 32, 128>,
>;

type RepeaterMac = Mac<RepeaterPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
type RepeaterHost<'a> =
    Host<'a, RepeaterPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

fn main() {
    block_on(async_main());
}

async fn async_main() {
    // This example is intentionally a simulation/demo, not the minimal repeater surface.
    // It shows an end-to-end forwarding topology with Alice -> repeater -> Bob while still
    // using the current Host/LocalNode/text-wrapper layering at the application edge.
    //
    // We intentionally avoid `#[embassy_executor::main]` here: on `arch-std` it would spawn
    // this whole large demo future into Embassy's fixed task arena, which is easy to overflow.
    // A tiny local `block_on` is a better fit for this single-threaded simulated example.
    let network = SimulatedNetwork::new();
    let alice_radio = network.add_radio();
    let repeater_radio = network.add_radio();
    let bob_radio = network.add_radio();
    network.connect_bidirectional(alice_radio.id(), repeater_radio.id());
    network.connect_bidirectional(repeater_radio.id(), bob_radio.id());

    let alice_identity = SoftwareIdentity::from_secret_bytes(&[0x11; 32]);
    let repeater_identity = SoftwareIdentity::from_secret_bytes(&[0x22; 32]);
    let bob_identity = SoftwareIdentity::from_secret_bytes(&[0x33; 32]);
    let alice_key = *alice_identity.public_key();
    let bob_key = *bob_identity.public_key();

    let alice_mac = RefCell::new(build_mac(alice_radio, false));
    let repeater_mac = RefCell::new(build_mac(repeater_radio, true));
    let bob_mac = RefCell::new(build_mac(bob_radio, false));

    let alice_handle = MacHandle::new(&alice_mac);
    let repeater_handle = MacHandle::new(&repeater_mac);
    let bob_handle = MacHandle::new(&bob_mac);

    let alice_id = alice_handle
        .add_identity(alice_identity)
        .expect("alice identity should fit");
    let _repeater_id = repeater_handle
        .add_identity(repeater_identity)
        .expect("repeater identity should fit");
    let bob_id = bob_handle
        .add_identity(bob_identity)
        .expect("bob identity should fit");

    let mut alice_host = RepeaterHost::new(alice_handle);
    let mut bob_host = RepeaterHost::new(bob_handle);
    let alice_node = alice_host.add_node(alice_id);
    let bob_node = bob_host.add_node(bob_id);
    let bob = bob_node.peer(alice_key).expect("alice peer should fit");
    let bob_chat = UnicastTextChatWrapper::from_peer(&bob);
    let alice = alice_node.peer(bob_key).expect("bob peer should fit");
    let alice_chat = UnicastTextChatWrapper::from_peer(&alice);
    let alice_received = Rc::new(RefCell::new(0usize));
    let bob_received = Rc::new(RefCell::new(0usize));
    let alice_raw_received = Rc::new(RefCell::new(0usize));
    let bob_raw_received = Rc::new(RefCell::new(0usize));
    let alice_pfs = Rc::new(RefCell::new(false));
    let bob_pfs = Rc::new(RefCell::new(false));

    let mut _subscriptions = Vec::new();
    _subscriptions.extend(register_debug_callbacks(
        "alice",
        &alice_node,
        &alice_chat,
        &alice,
        alice_received.clone(),
        alice_raw_received.clone(),
    ));
    _subscriptions.extend(register_debug_callbacks(
        "bob",
        &bob_node,
        &bob_chat,
        &bob,
        bob_received.clone(),
        bob_raw_received.clone(),
    ));
    _subscriptions.push({
        let alice_pfs = alice_pfs.clone();
        alice.on_pfs_established(move || {
            println!("[alice:pfs] established with {}", full_key(&bob_key));
            *alice_pfs.borrow_mut() = true;
        })
    });
    _subscriptions.push({
        let bob_pfs = bob_pfs.clone();
        bob.on_pfs_established(move || {
            println!("[bob:pfs] established with {}", full_key(&alice_key));
            *bob_pfs.borrow_mut() = true;
        })
    });

    println!("== step 1: alice floods a trace-routed hello toward bob ==");
    let hello_options = default_chat_options().with_trace_route();
    alice_chat
        .send_text("hello through the repeater", &hello_options)
        .await
        .expect("alice send should queue successfully");
    let alice_first = inspect_next_queued_frame(&alice_mac, "alice queued hello")
        .expect("alice hello should be queued");
    assert_eq!(alice_first.source_route_hops, 0);
    assert_eq!(alice_first.trace_route_hops, 0);
    pump_until(
        &mut alice_host,
        &repeater_handle,
        &mut bob_host,
        || *bob_received.borrow() >= 1,
        96,
        "bob to receive alice hello",
    )
    .await;

    println!(
        "[bob:route] learned route to alice: {}",
        cached_route_summary(&bob_mac, alice_key)
    );

    println!("== step 2: bob replies and should now use a cached source route ==");
    let reply_options = default_chat_options().with_trace_route();
    bob_chat
        .send_text("reply from bob over learned route", &reply_options)
        .await
        .expect("bob reply should queue successfully");
    let bob_reply = inspect_next_queued_frame(&bob_mac, "bob queued reply")
        .expect("bob reply should be queued");
    assert!(
        bob_reply.source_route_hops > 0,
        "bob reply should use a learned source route instead of pure flooding"
    );
    pump_until(
        &mut alice_host,
        &repeater_handle,
        &mut bob_host,
        || *alice_received.borrow() >= 1,
        96,
        "alice to receive bob reply",
    )
    .await;

    println!(
        "[alice:route] learned route to bob: {}",
        cached_route_summary(&alice_mac, bob_key)
    );

    println!("== step 3: alice sends a follow-up and should now use the learned source route too ==");
    let follow_up_options = default_chat_options().with_trace_route();
    alice_chat
        .send_text("alice follow-up over learned route", &follow_up_options)
        .await
        .expect("alice follow-up should queue successfully");
    let alice_follow_up = inspect_next_queued_frame(&alice_mac, "alice queued follow-up")
        .expect("alice follow-up should be queued");
    assert!(
        alice_follow_up.source_route_hops > 0,
        "alice follow-up should use a learned source route instead of flooding again"
    );
    pump_until(
        &mut alice_host,
        &repeater_handle,
        &mut bob_host,
        || *bob_received.borrow() >= 2,
        32,
        "bob to receive alice follow-up",
    )
    .await;

    println!("== step 4: alice requests PFS over the learned route ==");
    let pfs_options = default_chat_options();
    alice
        .request_pfs(60, &pfs_options)
        .await
        .expect("alice pfs request should queue successfully");
    let pfs_request = inspect_next_queued_frame(&alice_mac, "alice queued pfs request")
        .expect("pfs request should be queued");
    assert!(
        pfs_request.source_route_hops > 0,
        "pfs request should also use the learned source route"
    );
    let alice_raw_before = *alice_raw_received.borrow();
    let bob_raw_before = *bob_raw_received.borrow();
    pump_until(
        &mut alice_host,
        &repeater_handle,
        &mut bob_host,
        || *alice_pfs.borrow() && *bob_pfs.borrow(),
        128,
        "both peers to establish pfs",
    )
    .await;
    println!(
        "[pfs] raw packets observed after request: alice={} bob={}",
        *alice_raw_received.borrow() - alice_raw_before,
        *bob_raw_received.borrow() - bob_raw_before,
    );

    println!(
        "[alice:pfs] status = {}",
        format_pfs_status(
            alice
                .pfs_status()
                .expect("alice pfs status should be readable")
        )
    );
    println!(
        "[bob:pfs] status = {}",
        format_pfs_status(
            bob.pfs_status().expect("bob pfs status should be readable")
        )
    );
    if *alice_pfs.borrow() && *bob_pfs.borrow() {
        println!("[pfs] established on both sides during the simulated exchange");
    } else {
        println!(
            "[pfs] not yet established by the end of the simulated exchange; this demo still verified the route transition to source routing"
        );
    }
}

fn build_mac(radio: umsh::mac::test_support::SimulatedRadio, repeater: bool) -> RepeaterMac {
    let mut repeater_config = RepeaterConfig::default();
    repeater_config.enabled = repeater;
    Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        EmbassyClock,
        rand::rng(),
        MemoryCounterStore::<4, 32>::default(),
        repeater_config,
        OperatingPolicy::default(),
    )
}

fn full_key(key: &PublicKey) -> String {
    encode_public_key_base58(key)
}

fn format_mac_command(command: &umsh::node::OwnedMacCommand) -> String {
    match command {
        umsh::node::OwnedMacCommand::BeaconRequest { nonce } => match nonce {
            Some(nonce) => format!("BeaconRequest nonce=0x{nonce:08x}"),
            None => String::from("BeaconRequest"),
        },
        umsh::node::OwnedMacCommand::IdentityRequest => String::from("IdentityRequest"),
        umsh::node::OwnedMacCommand::SignalReportRequest => String::from("SignalReportRequest"),
        umsh::node::OwnedMacCommand::SignalReportResponse { rssi, snr } => {
            format!("SignalReportResponse rssi={rssi} snr={snr}")
        }
        umsh::node::OwnedMacCommand::EchoRequest { data } => {
            format!("EchoRequest {} bytes", data.len())
        }
        umsh::node::OwnedMacCommand::EchoResponse { data } => {
            format!("EchoResponse {} bytes", data.len())
        }
        umsh::node::OwnedMacCommand::PfsSessionRequest {
            ephemeral_key,
            duration_minutes,
        } => format!(
            "PfsSessionRequest ephemeral_key={} duration_minutes={duration_minutes}",
            full_key(ephemeral_key)
        ),
        umsh::node::OwnedMacCommand::PfsSessionResponse {
            ephemeral_key,
            duration_minutes,
        } => format!(
            "PfsSessionResponse ephemeral_key={} duration_minutes={duration_minutes}",
            full_key(ephemeral_key)
        ),
        umsh::node::OwnedMacCommand::EndPfsSession => String::from("EndPfsSession"),
    }
}

fn format_pfs_status(status: umsh::node::PfsStatus) -> String {
    match status {
        umsh::node::PfsStatus::Inactive => String::from("Inactive"),
        umsh::node::PfsStatus::Requested => String::from("Requested"),
        umsh::node::PfsStatus::Active {
            local_ephemeral_id,
            peer_ephemeral,
            expires_ms,
        } => format!(
            "Active local_ephemeral_id={} peer_ephemeral={} expires_ms={expires_ms}",
            local_ephemeral_id.0,
            full_key(&peer_ephemeral)
        ),
    }
}

fn default_chat_options() -> SendOptions {
    SendOptions::default()
        .with_ack_requested(true)
        .with_flood_hops(5)
}

fn register_debug_callbacks(
    label: &'static str,
    node: &RepeaterHostNode<'_>,
    chat: &RepeaterText<'_>,
    peer: &RepeaterPeer<'_>,
    received_count: Rc<RefCell<usize>>,
    raw_received_count: Rc<RefCell<usize>>,
) -> Vec<umsh::node::Subscription> {
    let peer_key = *peer.peer();
    let raw_subscription = node.on_receive(move |packet| {
        println!("[{label}:raw] {}", summarize_received_packet(packet));
        *raw_received_count.borrow_mut() += 1;
        false
    });
    let text_subscription = chat.on_text_with_diagnostics(
        move |packet, text| {
            println!(
                "[{label}:text] from={} body={:?} {}",
                full_key(&peer_key),
                text.body,
                summarize_received_packet(packet)
            );
            *received_count.borrow_mut() += 1;
        },
        move |packet, issue| {
            println!(
                "[{label}:text-reject] from={} issue={} {}",
                full_key(&peer_key),
                match issue {
                    TextReceiveIssue::WrongPayloadType(kind) =>
                        format!("wrong-payload-type({kind:?})"),
                    TextReceiveIssue::Parse(error) => format!("parse-error({error:?})"),
                },
                summarize_received_packet(packet)
            );
        },
    );
    let _ack_received = peer.on_ack_received(move |token| {
        println!("[{label}:ack] received token={token:?}");
    });
    let _ack_timeout = peer.on_ack_timeout(move |token| {
        println!("[{label}:ack] timeout token={token:?}");
    });
    let _mac_commands = node.on_mac_command(move |from, command| {
        println!(
            "[{label}:mac-command] from={} command={}",
            full_key(&from),
            format_mac_command(command)
        );
    });
    vec![
        raw_subscription,
        text_subscription,
        _ack_received,
        _ack_timeout,
        _mac_commands,
    ]
}

type RepeaterHostNode<'a> = umsh::node::LocalNode<
    MacHandle<'a, RepeaterPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>,
>;
type RepeaterPeer<'a> = umsh::node::PeerConnection<
    RepeaterHostNode<'a>,
>;
type RepeaterText<'a> = UnicastTextChatWrapper<RepeaterHostNode<'a>>;

#[derive(Clone, Copy, Debug)]
struct QueuedFrameSummary {
    packet_type: umsh::core::PacketType,
    encrypted: bool,
    full_source: bool,
    flood_hops: Option<umsh::core::FloodHops>,
    source_route_hops: usize,
    trace_route_hops: usize,
}

fn inspect_next_queued_frame(
    mac: &RefCell<RepeaterMac>,
    label: &str,
) -> Option<QueuedFrameSummary> {
    let mut mac = mac.borrow_mut();
    let queued = mac.tx_queue_mut().pop_next()?;
    let summary = summarize_queued_frame(queued.frame.as_slice()).ok()?;
    println!("[inspect] {label}: {}", format_queued_summary(summary));
    mac.tx_queue_mut()
        .enqueue_with_state(
            queued.priority,
            queued.frame.as_slice(),
            queued.receipt,
            queued.identity_id,
            queued.not_before_ms,
            queued.cad_attempts,
            queued.forward_deferrals,
        )
        .expect("requeue after inspection should succeed");
    Some(summary)
}

fn summarize_queued_frame(frame: &[u8]) -> Result<QueuedFrameSummary, umsh::core::ParseError> {
    let header = PacketHeader::parse(frame)?;
    let options = ParsedOptions::extract(frame, header.options_range.clone())?;
    Ok(QueuedFrameSummary {
        packet_type: header.packet_type(),
        encrypted: header
            .sec_info
            .map(|sec| sec.scf.encrypted())
            .unwrap_or(false),
        full_source: header.fcf.full_source(),
        flood_hops: header.flood_hops,
        source_route_hops: options
            .source_route
            .as_ref()
            .map(|range| frame[range.clone()].len() / 2)
            .unwrap_or(0),
        trace_route_hops: options
            .trace_route
            .as_ref()
            .map(|range| frame[range.clone()].len() / 2)
            .unwrap_or(0),
    })
}

fn format_queued_summary(summary: QueuedFrameSummary) -> String {
    format!(
        "ptype={:?} enc={} full_source={} flood={:?} source_route_hops={} trace_route_hops={}",
        summary.packet_type,
        summary.encrypted,
        summary.full_source,
        summary.flood_hops,
        summary.source_route_hops,
        summary.trace_route_hops,
    )
}

fn summarize_received_packet(packet: &umsh::node::ReceivedPacketRef<'_>) -> String {
    format!(
        "ptype={:?} secure={} enc={} auth={} full_source={} flood={:?} source_route_hops={} trace_route_hops={} rssi={:?} snr={:?}",
        packet.packet_type(),
        packet.is_secure(),
        packet.encrypted(),
        packet.source_authenticated(),
        packet.has_full_source(),
        packet.flood_hops(),
        packet.source_route_hop_count(),
        packet.trace_route_hop_count(),
        packet.rssi(),
        packet.snr(),
    )
}

fn cached_route_summary(mac: &RefCell<RepeaterMac>, peer: PublicKey) -> String {
    let mac = mac.borrow();
    let Some((peer_id, _)) = mac.peer_registry().lookup_by_key(&peer) else {
        return "missing-peer".to_string();
    };
    match mac.peer_registry().get(peer_id).and_then(|info| info.route.as_ref()) {
        Some(CachedRoute::Source(route)) => format!(
            "source {:?}",
            route.iter().map(|hop| hop.0).collect::<std::vec::Vec<_>>()
        ),
        Some(CachedRoute::Flood { hops }) => format!("flood hops={hops}"),
        None => "none".to_string(),
    }
}

async fn pump_until(
    alice_host: &mut RepeaterHost<'_>,
    repeater_handle: &MacHandle<'_, RepeaterPlatform, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>,
    bob_host: &mut RepeaterHost<'_>,
    done: impl Fn() -> bool,
    max_steps: usize,
    label: &str,
) {
    for _ in 0..max_steps {
        if done() {
            return;
        }
        match wait_for_any_activity(
            alice_host.pump_once(),
            repeater_handle.next_event(|identity, event| {
                println!(
                    "[repeater:mac] id={identity:?} {}",
                    summarize_mac_event(&event)
                );
            }),
            bob_host.pump_once(),
        )
        .await
        {
            WakeResult::Alice(result) => result.expect("alice pump should succeed"),
            WakeResult::Repeater(result) => result.expect("repeater wake should succeed"),
            WakeResult::Bob(result) => result.expect("bob pump should succeed"),
        }
    }
    panic!("timed out waiting for {label}");
}

enum WakeResult<A, B, C> {
    Alice(A),
    Repeater(B),
    Bob(C),
}

async fn wait_for_any_activity<A, B, C>(
    alice: A,
    repeater: B,
    bob: C,
) -> WakeResult<A::Output, B::Output, C::Output>
where
    A: Future,
    B: Future,
    C: Future,
{
    let mut alice = core::pin::pin!(alice);
    let mut repeater = core::pin::pin!(repeater);
    let mut bob = core::pin::pin!(bob);

    poll_fn(|cx| {
        if let Poll::Ready(output) = alice.as_mut().poll(cx) {
            return Poll::Ready(WakeResult::Alice(output));
        }
        if let Poll::Ready(output) = repeater.as_mut().poll(cx) {
            return Poll::Ready(WakeResult::Repeater(output));
        }
        if let Poll::Ready(output) = bob.as_mut().poll(cx) {
            return Poll::Ready(WakeResult::Bob(output));
        }
        Poll::Pending
    })
    .await
}

fn summarize_mac_event(event: &MacEventRef<'_>) -> String {
    match event {
        MacEventRef::Received(packet) => format!(
            "received ptype={:?} secure={} enc={} auth={} full_source={} flood={:?} source_route_hops={} trace_route_hops={} rssi={:?} snr={:?}",
            packet.packet_type(),
            packet.is_secure(),
            packet.encrypted(),
            packet.source_authenticated(),
            packet.has_full_source(),
            packet.flood_hops(),
            packet.source_route_hop_count(),
            packet.trace_route_hop_count(),
            packet.rssi(),
            packet.snr(),
        ),
        MacEventRef::AckReceived { peer, receipt } => format!(
            "ack-received peer={} receipt={receipt:?}",
            full_key(peer)
        ),
        MacEventRef::AckTimeout { peer, receipt } => format!(
            "ack-timeout peer={} receipt={receipt:?}",
            full_key(peer)
        ),
        MacEventRef::Transmitted {
            identity_id,
            receipt,
        } => format!("transmitted id={identity_id:?} receipt={receipt:?}"),
        MacEventRef::Forwarded {
            identity_id,
            receipt,
            hint,
        } => format!("forwarded id={identity_id:?} receipt={receipt:?} hint={hint:?}"),
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let mut future = core::pin::pin!(future);
    loop {
        match Future::poll(future.as_mut(), &mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => core::hint::spin_loop(),
        }
    }
}

fn noop_waker() -> Waker {
    fn noop_raw_waker() -> RawWaker {
        fn clone(_: *const ()) -> RawWaker {
            noop_raw_waker()
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}

        RawWaker::new(
            core::ptr::null(),
            &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
        )
    }

    unsafe { Waker::from_raw(noop_raw_waker()) }
}
