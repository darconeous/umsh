//! The Peer Repeaters exchange carried by a real MAC.
//!
//! The responder's own unit tests drive `answer_peer_repeaters_request`
//! directly, which pins what a page contains. This one puts a link between
//! the two halves: a repeater that has heard identities and traffic, an
//! asker that sends command 10 and reads command 11 back off the air, and
//! the host receive path — including the unicast-only gate — in between.

#![cfg(feature = "tokio-support")]

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::rng;

use umsh::core::PublicKey;
use umsh::crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh::crypto::{CryptoEngine, NodeIdentity};
use umsh::hal::Radio;
use umsh::mac::test_support::{SimulatedNetwork, SimulatedRadio};
use umsh::mac::{Mac, MacHandle, OperatingPolicy, RepeaterConfig, SendOptions};
use umsh::node::mac_command::{OwnedMacCommand, PeerRepeatersResponseView};
use umsh::node::{
    Host, LocalNode, NodeCapabilities, NodeIdentityPayload, NodeRole, PeerConnection,
};
use umsh::prelude::Transport;
use umsh::tokio_support::{StdClock, TokioFileCounterStore, TokioFileKeyValueStore, TokioPlatform};
use umsh_sync::AsyncRefCell;

const IDENTITIES: usize = 1;
const PEERS: usize = 4;
const CHANNELS: usize = 1;
const ACKS: usize = 8;
const TX: usize = 8;
const FRAME: usize = 256;
const DUP: usize = 32;

type SimPlatform<R> = TokioPlatform<R, TokioFileCounterStore, TokioFileKeyValueStore>;
type SimMac<R> = Mac<SimPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;
type SimHandle<'a, R> =
    MacHandle<'a, SimPlatform<R>, IDENTITIES, PEERS, CHANNELS, ACKS, TX, FRAME, DUP>;

/// A test that stops making progress should fail rather than hang.
const PATIENCE: Duration = Duration::from_secs(30);

/// Response bodies the asker's node took in, in arrival order.
type Responses = Rc<RefCell<Vec<Vec<u8>>>>;

/// Both nodes on a link: one answering, one asking.
///
/// Pumped by hand rather than spawned — the node layer is `!Send`, and a
/// test that owns its own scheduling cannot race itself.
struct Mesh<'a, R: Radio> {
    asker_host: Host<SimHandle<'a, R>>,
    repeater_host: Host<SimHandle<'a, R>>,
    asker_node: LocalNode<SimHandle<'a, R>>,
    asker_key: PublicKey,
    target: PeerConnection<LocalNode<SimHandle<'a, R>>>,
    responses: Responses,
    _subscription: umsh::node::Subscription,
}

impl<R: Radio> Mesh<'_, R>
where
    R::Error: core::fmt::Debug,
{
    /// One turn of both hosts.
    async fn turn(&mut self) {
        tokio::select! {
            result = self.asker_host.pump_once() => result.expect("asker host"),
            result = self.repeater_host.pump_once() => result.expect("repeater host"),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    /// Announce the asker to the repeater as a repeater in its own right.
    ///
    /// The listing is built from identities that *arrived*, so the only
    /// honest way to put one in the table is to send it.
    async fn announce(&mut self, identity: &NodeIdentityPayload) {
        let mut buf = [0u8; 192];
        buf[0] = umsh::core::PayloadType::NodeIdentity as u8;
        let len = identity.encode(&mut buf[1..]).expect("the identity fits") + 1;
        self.target
            .send(&buf[..len], &SendOptions::default())
            .await
            .expect("the asker can announce itself");
        self.settle(20).await;
    }

    /// Ask once and pump until the answer arrives.
    async fn ask(&mut self, nonce: u16, cursor: Option<&[u8]>) -> Vec<u8> {
        self.target
            .request_peer_repeaters(nonce, cursor, &SendOptions::default())
            .await
            .expect("the asker can send");
        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Some(body) = self.responses.borrow_mut().pop() {
                return body;
            }
            assert!(Instant::now() < deadline, "no response ever arrived");
            self.turn().await;
        }
    }

    /// Drive both hosts for a while without expecting anything.
    async fn settle(&mut self, turns: usize) {
        for _ in 0..turns {
            self.turn().await;
        }
    }
}

/// A temporary directory for one test's frame counters, removed with it.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        Self(std::env::temp_dir().join(format!("umsh-peer-repeaters-{name}-{unique}")))
    }

    fn join(&self, leaf: &str) -> PathBuf {
        self.0.join(leaf)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn build_mac<R: Radio>(radio: R, counters: PathBuf) -> SimMac<R> {
    Mac::new(
        radio,
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        StdClock::new(),
        rng(),
        TokioFileCounterStore::new(counters).expect("counter store"),
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    )
}

fn link() -> (SimulatedRadio, SimulatedRadio) {
    let network = SimulatedNetwork::new();
    let asker = network.add_radio_with_config(255, 20);
    let repeater = network.add_radio_with_config(255, 20);
    network.connect_bidirectional(asker.id(), repeater.id());
    (asker, repeater)
}

fn repeater_identity(name: &str, regions: &[&str]) -> NodeIdentityPayload {
    NodeIdentityPayload {
        role: NodeRole::Repeater,
        capabilities: NodeCapabilities::REPEATER,
        name: Some(String::from(name)),
        location: None,
        altitude_m: None,
        timestamp: None,
        supported_regions: Some(regions.iter().map(|text| String::from(*text)).collect()),
        nonce: None,
        signature: None,
    }
}

async fn stand_up<'a, R: Radio>(
    asker_mac: &'a AsyncRefCell<SimMac<R>>,
    repeater_mac: &'a AsyncRefCell<SimMac<R>>,
) -> Mesh<'a, R> {
    let asker_identity = SoftwareIdentity::from_secret_bytes(&[0x11; 32]);
    let repeater_identity_key = SoftwareIdentity::from_secret_bytes(&[0x22; 32]);
    let asker_key = *asker_identity.public_key();
    let repeater_key = *repeater_identity_key.public_key();

    let asker_handle = MacHandle::new(asker_mac);
    let repeater_handle = MacHandle::new(repeater_mac);
    let asker_id = asker_handle
        .add_identity(asker_identity)
        .await
        .expect("the asker identity fits");
    let repeater_id = repeater_handle
        .add_identity(repeater_identity_key)
        .await
        .expect("the repeater identity fits");

    let mut asker_host = Host::new(asker_handle);
    let mut repeater_host = Host::new(repeater_handle);
    let asker_node = asker_host.add_node(asker_id);
    let repeater_node = repeater_host.add_node(repeater_id);
    let target = asker_node.peer(repeater_key).await.expect("peer");
    // The repeater has to hold the asker's key to unseal the request and
    // seal the answer.
    repeater_node.peer(asker_key).await.expect("peer");
    repeater_node.enable_peer_repeaters_responder();

    let responses: Responses = Rc::new(RefCell::new(Vec::new()));
    let subscription = {
        let responses = responses.clone();
        asker_node.on_mac_command(move |_from, command| {
            if let OwnedMacCommand::PeerRepeatersResponse { body } = command {
                responses.borrow_mut().push(body.clone());
            }
        })
    };

    Mesh {
        asker_host,
        repeater_host,
        asker_node,
        asker_key,
        target,
        responses,
        _subscription: subscription,
    }
}

/// `mesh!(name, binding)` — two nodes on a link, bound to `binding`.
macro_rules! mesh {
    ($name:literal, $mesh:ident) => {
        let scratch = Scratch::new($name);
        let (asker_radio, repeater_radio) = link();
        let asker_mac = AsyncRefCell::new(build_mac(asker_radio, scratch.join("asker")));
        let repeater_mac = AsyncRefCell::new(build_mac(repeater_radio, scratch.join("repeater")));
        #[allow(unused_mut)]
        let mut $mesh = stand_up(&asker_mac, &repeater_mac).await;
    };
}

// ─── Tests ───────────────────────────────────────────────────────────────

/// The asker announces itself as a repeater, then asks — and finds itself in
/// the answer, described by both the identity it sent and the reception that
/// carried it.
#[tokio::test(flavor = "current_thread")]
async fn a_repeater_names_the_repeaters_it_knows_of() {
    mesh!("listing", mesh);
    mesh.announce(&repeater_identity("Ridgeline", &["SJC", "Rogue Valley"]))
        .await;

    let body = mesh.ask(0xBEEF, None).await;
    let view = PeerRepeatersResponseView::new(&body);
    assert_eq!(view.nonce(), Some(0xBEEF), "the request's nonce came back");
    assert_eq!(view.cursor(), None, "one page held the neighborhood");

    let entries: Vec<_> = view.entries().collect();
    assert_eq!(entries.len(), 1, "one node has been heard from");
    assert_eq!(
        view.total().map(usize::from),
        Some(entries.len()),
        "Total counts the listing this page came from"
    );

    let entry = &entries[0];
    assert_eq!(entry.name(), Some("Ridgeline"));
    assert_eq!(
        entry.hint(),
        Some(&mesh.asker_key.hint().0[..]),
        "the identity supplied the whole node hint"
    );
    assert_eq!(
        entry.regions().collect::<Vec<_>>(),
        vec![[0x78, 0x53], [0xDF, 0x6F]],
        "region strings reach the asker as derived codes"
    );
    assert!(
        entry.rssi_snr().is_some(),
        "the same peer was heard on the air, so the link is described too"
    );
    assert!(entry.last_heard_min().is_some());
}

/// A node that has only been heard, never introduced, is still a hop worth
/// naming — by the router hint a trace would give it, with signal and
/// nothing else.
#[tokio::test(flavor = "current_thread")]
async fn a_hop_heard_on_the_air_is_listed_without_a_name() {
    mesh!("observed", mesh);
    let body = mesh.ask(1, None).await;
    let view = PeerRepeatersResponseView::new(&body);

    let entries: Vec<_> = view.entries().collect();
    assert_eq!(entries.len(), 1, "the request itself was a reception");
    assert_eq!(
        entries[0].hint().map(<[u8]>::len),
        Some(2),
        "an observation with no identity behind it names a router hint"
    );
    assert_eq!(entries[0].name(), None);
    assert!(entries[0].rssi_snr().is_some());
    assert!(entries[0].regions().next().is_none());
}

/// MAC commands are unicast-only unless the command defines multicast rules,
/// and this one does not.
#[tokio::test(flavor = "current_thread")]
async fn a_multicast_request_is_not_answered() {
    mesh!("multicast", mesh);
    let channel = umsh::node::Channel::private(umsh::core::ChannelKey([0x33; 32]), "trail");
    let asker_channel = mesh
        .asker_node
        .join(&channel)
        .await
        .expect("the asker can join");

    let options = umsh::node::mac_command::PeerRepeatersRequestBuilder::new()
        .nonce(7)
        .unwrap()
        .build();
    let mut buf = [0u8; 64];
    buf[0] = umsh::core::PayloadType::MacCommand as u8;
    let len = umsh::node::mac_command::encode(
        &umsh::node::mac_command::MacCommand::PeerRepeatersRequest { options: &options },
        &mut buf[1..],
    )
    .unwrap()
        + 1;
    asker_channel
        .send_all(&buf[..len], &SendOptions::default())
        .await
        .expect("the asker can send on the channel");

    mesh.settle(20).await;
    assert!(
        mesh.responses.borrow().is_empty(),
        "a multicast MAC command is dropped before any responder sees it"
    );
}
