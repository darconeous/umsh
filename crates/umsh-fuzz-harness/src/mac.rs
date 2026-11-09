//! A `Mac` driven synchronously by a script, and the oracles run against it.
//!
//! Frames enter through a capturing radio and `next_event`, the way they
//! reach a real node. A `Mac` is built fresh for every input.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use std::task::{Context, Poll};

use umsh_core::{
    BlindAddr, MicSize, OptionNumber, PacketBuilder, PacketHeader, PacketType, PayloadType,
};
use umsh_core::{PublicKey, RouterHint};
use umsh_crypto::NodeIdentity;
use umsh_crypto::software::{SoftwareAes, SoftwareIdentity, SoftwareSha256};
use umsh_hal::{CounterStore, Radio, RxInfo, RxOrigin, Snr, TxError, TxOptions};
use umsh_mac::forward_id::forwarding_dup_key;
use umsh_mac::test_support::{DummyClock, DummyDelay, DummyKeyValueStore, DummyRng};
use umsh_mac::{
    AmateurRadioMode, BearerId, LocalIdentityId, Mac, MacCounters, MacEventRef, OperatingPolicy,
    Platform, RepeaterConfig, SendOptions, SendReceipt, SignatureStatus,
};

use crate::fixup::{self, Cast, RAW, cast};
use crate::script::{Fields, Record, records};
use crate::{block_on, targets::umsh_packet};

pub const OP_CONFIG: u8 = 0;
pub const OP_RX: u8 = 1;
pub const OP_ADVANCE: u8 = 2;
pub const OP_SEND: u8 = 3;
pub const OP_ACK: u8 = 4;
pub const OP_ANSWER: u8 = 5;
pub const OP_FAULT: u8 = 6;
const OPS: u8 = 7;

const FRAME: usize = 255;
/// Wakes one settle may take. A node that keeps finding work with no new
/// input and no time passing is spinning, and on a device that is a hang.
pub const WAKE_BOUND: usize = 4096;
/// Far past every retry ladder, contention window, and ack deadline.
const DRAIN_STEP_MS: u64 = 60_000;
const DRAIN_STEPS: usize = 64;

pub const MAC_COMMAND_ECHO_REQUEST_ID: u8 = 4;
pub const MAC_COMMAND_ECHO_RESPONSE_ID: u8 = 5;
pub const MAC_COMMAND_VERIFY_FRAME_ID: u8 = 12;
pub const MAC_COMMAND_FRAME_VERIFIED_ID: u8 = 13;

/// In an `OP_ACK` body: send a Verify Frame naming the send, not an ack.
pub const ACK_VOUCH: u8 = 1;

/// A radio that hands over queued frames and records what goes out.
#[derive(Default)]
pub struct CaptureRadio {
    rx: VecDeque<(Vec<u8>, RxInfo)>,
    tx: Vec<Vec<u8>>,
    /// Polls since the last settle began. Counting here rather than around
    /// `next_event` is what catches a spin inside one poll: that loop never
    /// returns to its driver, but it cannot avoid asking the radio.
    polls: usize,
}

impl CaptureRadio {
    /// Start counting a new settle's polls.
    pub fn refill(&mut self) {
        self.polls = 0;
    }

    /// Queue a frame for the node to hear.
    pub fn inject(&mut self, frame: Vec<u8>, rssi: i16, snr: i8, origin: RxOrigin) {
        let info = RxInfo {
            len: frame.len(),
            rssi,
            snr: Snr::from_decibels(snr),
            lqi: None,
            origin,
            buffered: None,
        };
        self.rx.push_back((frame, info));
    }
}

impl Radio for CaptureRadio {
    type Error = ();

    async fn transmit(&mut self, data: &[u8], _: TxOptions) -> Result<(), TxError<()>> {
        self.tx.push(data.to_vec());
        Ok(())
    }

    fn poll_receive(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<RxInfo, Self::Error>> {
        self.polls += 1;
        assert!(self.polls <= WAKE_BOUND, "the node never went idle");
        match self.rx.pop_front() {
            Some((frame, info)) => {
                let len = frame.len().min(buf.len());
                buf[..len].copy_from_slice(&frame[..len]);
                Poll::Ready(Ok(RxInfo { len, ..info }))
            }
            None => Poll::Pending,
        }
    }

    fn max_frame_size(&self) -> usize {
        FRAME
    }

    fn t_frame_ms(&self) -> u32 {
        1_000
    }

    fn spreading_factor(&self) -> Option<u8> {
        Some(9)
    }
}

/// A counter store a script can make fail.
#[derive(Clone, Default)]
pub struct FaultyCounterStore {
    failing: Rc<Cell<bool>>,
    values: Rc<RefCell<BTreeMap<Vec<u8>, u32>>>,
}

impl CounterStore for FaultyCounterStore {
    type Error = ();

    async fn load(&self, context: &[u8]) -> Result<u32, ()> {
        if self.failing.get() {
            return Err(());
        }
        Ok(self.values.borrow().get(context).copied().unwrap_or(0))
    }

    async fn store(&self, context: &[u8], value: u32) -> Result<(), ()> {
        if self.failing.get() {
            return Err(());
        }
        self.values.borrow_mut().insert(context.to_vec(), value);
        Ok(())
    }

    async fn flush(&self) -> Result<(), ()> {
        if self.failing.get() { Err(()) } else { Ok(()) }
    }
}

pub struct FuzzPlatform;

impl Platform for FuzzPlatform {
    type Identity = SoftwareIdentity;
    type Aes = SoftwareAes;
    type Sha = SoftwareSha256;
    type Radio = CaptureRadio;
    type Delay = DummyDelay;
    type Clock = DummyClock;
    type Rng = DummyRng;
    type CounterStore = FaultyCounterStore;
    type KeyValueStore = DummyKeyValueStore;
}

pub type FuzzMac<const PEERS: usize, const HOLDS: usize> =
    Mac<FuzzPlatform, 4, PEERS, 8, 16, 8, FRAME, 32, HOLDS, 16>;

/// What a script may do.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Frames only, as they came, with no keys in play.
    Raw,
    /// Selectors seal frames for known parties, and the local node sends.
    Sealed,
}

/// What a run leaves behind.
#[derive(Debug, Default)]
pub struct Outcome {
    pub received: Vec<Delivered>,
    /// Who the node knew after each step. Each step, because later traffic
    /// can put back what an earlier frame took away, and every key, because
    /// a forged frame names one nobody in the cast holds.
    pub peers: Vec<BTreeSet<[u8; 32]>>,
    /// Ids of the MAC commands the node sent a known party.
    pub commands_aired: BTreeSet<u8>,
    pub counters: MacCounters,
}

/// One delivery, as an application sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    pub packet_type: u8,
    pub from: Option<[u8; 32]>,
    pub signature_verified: bool,
    pub payload: Vec<u8>,
}

#[derive(Default)]
struct Log {
    received: Vec<Delivered>,
    /// `(from, counter, mic)` of every authenticated delivery.
    authenticated: BTreeSet<([u8; 32], u32, Vec<u8>)>,
    terminal: BTreeSet<u32>,
    acked: BTreeSet<u32>,
}

impl Log {
    /// A resync adopts the peer's counter whatever its value, so the frames
    /// behind the old baseline may be fresh again. Replay protection starts
    /// over for that peer, which is what the spec asks for.
    fn forget(&mut self, peer: &[u8; 32]) {
        self.authenticated.retain(|(from, ..)| from != peer);
    }

    fn record(&mut self, event: MacEventRef<'_>) {
        match event {
            MacEventRef::Received(packet) => {
                let from = packet.from_key().map(|key| key.0);
                let header = packet.header();
                // A fuzzer can reach this on its own: the test RNG's nonces
                // are guessable.
                if let (Some(from), [kind, MAC_COMMAND_ECHO_RESPONSE_ID, ..]) =
                    (from.as_ref(), packet.payload_bytes())
                    && *kind == PayloadType::MacCommand as u8
                {
                    self.forget(from);
                }
                if packet.source_authenticated()
                    && matches!(
                        packet.packet_type(),
                        PacketType::Unicast
                            | PacketType::UnicastAckReq
                            | PacketType::BlindUnicast
                            | PacketType::BlindUnicastAckReq
                    )
                    && let (Some(from), Some(sec_info)) = (from, header.sec_info)
                    && let Some(mic) = packet.wire_bytes().get(header.mic_range.clone())
                {
                    let replay = (from, sec_info.frame_counter, mic.to_vec());
                    assert!(self.authenticated.insert(replay), "a replay was delivered");
                }
                self.received.push(Delivered {
                    packet_type: packet.packet_type() as u8,
                    from,
                    signature_verified: packet.signature() == SignatureStatus::Verified,
                    payload: packet.payload_bytes().to_vec(),
                });
            }
            MacEventRef::AckReceived { receipt, .. } => {
                self.terminal.insert(receipt.0);
                self.acked.insert(receipt.0);
            }
            MacEventRef::AckTimeout { receipt, .. } => {
                self.terminal.insert(receipt.0);
            }
            MacEventRef::TxAbandoned {
                receipt: Some(receipt),
                ..
            } => {
                self.terminal.insert(receipt.0);
            }
            _ => {}
        }
    }
}

struct Harness<const PEERS: usize, const HOLDS: usize> {
    mac: Box<FuzzMac<PEERS, HOLDS>>,
    clock: DummyClock,
    store: FaultyCounterStore,
    local: LocalIdentityId,
    log: Log,
    mode: Mode,
    /// Dup key of each frame heard, with its AAD. A forward must keep both.
    heard: Vec<(Vec<u8>, Vec<u8>)>,
    aired: usize,
    /// Of those, how many a link has already taken.
    carried: usize,
    /// Sends that owe a terminal event.
    tracked: BTreeSet<u32>,
    next_counter: u32,
    peers: Vec<BTreeSet<[u8; 32]>>,
}

/// The same placeholder on both sides of a comparison: a blind unicast's
/// real block is hidden from a forwarder.
fn aad(frame: &[u8]) -> Option<Vec<u8>> {
    let header = PacketHeader::parse(frame).ok()?;
    let blind = header
        .blind_addr_range()
        .and_then(|range| BlindAddr::from_plaintext(&vec![0; range.len()]));
    umsh_packet::aad(&header, frame, blind.as_ref())
}

fn dup_key(frame: &[u8]) -> Option<Vec<u8>> {
    forwarding_dup_key(frame).map(|key| format!("{key:?}").into_bytes())
}

/// A node with `secret`'s identity, the channel, and `peers` pinned.
pub struct Station<const PEERS: usize, const HOLDS: usize> {
    pub mac: Box<FuzzMac<PEERS, HOLDS>>,
    pub clock: DummyClock,
    store: FaultyCounterStore,
    pub local: LocalIdentityId,
}

impl<const PEERS: usize, const HOLDS: usize> Station<PEERS, HOLDS> {
    pub fn new(config: &[u8], repeating: bool, secret: &[u8; 32], peers: &[PublicKey]) -> Self {
        let mut fields = Fields::new(config);
        let flags = fields.u8();
        let default_region = (flags & 0x01 != 0).then(|| [fields.u8(), fields.u8()]);
        let min_rssi = (flags & 0x02 != 0).then(|| -i16::from(fields.u8()));
        let min_snr = (flags & 0x04 != 0).then(|| fields.u8() as i8);
        let amateur_radio_mode = if flags & 0x08 != 0 {
            AmateurRadioMode::LicensedOnly
        } else {
            AmateurRadioMode::Unlicensed
        };

        let clock = DummyClock::new(1);
        let store = FaultyCounterStore::default();
        let repeater = RepeaterConfig {
            enabled: repeating,
            default_region,
            min_rssi,
            min_snr,
            amateur_radio_mode,
            ..RepeaterConfig::default()
        };
        let policy = OperatingPolicy {
            amateur_radio_mode,
            ..OperatingPolicy::default()
        };
        let mut mac = Box::new(Mac::new(
            CaptureRadio::default(),
            fixup::engine(),
            clock.clone(),
            DummyRng(flags >> 4),
            store.clone(),
            repeater,
            policy,
        ));

        let identity = SoftwareIdentity::from_secret_bytes(secret);
        let local = mac.add_identity(identity).expect("a free identity slot");
        for peer in peers {
            mac.add_peer(*peer).expect("a free peer slot");
        }
        mac.add_channel(cast().channel_key)
            .expect("a free channel slot");
        mac.set_auto_register_full_key_peers(flags & 0x80 == 0);
        Self {
            mac,
            clock,
            store,
            local,
        }
    }
}

impl<const PEERS: usize, const HOLDS: usize> Harness<PEERS, HOLDS> {
    fn new(config: &[u8], mode: Mode, repeating: bool) -> Self {
        let cast = cast();
        let pinned = cast.parties[..fixup::PINNED_PARTIES]
            .iter()
            .chain([&cast.canary])
            .map(|party| party.key)
            .collect::<Vec<_>>();
        Self::from_station(
            Station::new(config, repeating, &cast.local_secret, &pinned),
            mode,
        )
    }

    fn from_station(station: Station<PEERS, HOLDS>, mode: Mode) -> Self {
        Self {
            mac: station.mac,
            clock: station.clock,
            store: station.store,
            local: station.local,
            log: Log::default(),
            mode,
            heard: Vec::new(),
            aired: 0,
            carried: 0,
            tracked: BTreeSet::new(),
            next_counter: 1,
            peers: Vec::new(),
        }
    }

    /// Run the node until it has nothing to do at this instant.
    fn settle(&mut self) {
        let Self { mac, log, .. } = self;
        mac.radio_mut().refill();
        for _ in 0..WAKE_BOUND {
            let woke = block_on::poll_once(mac.next_event(|_, event| log.record(event)));
            match woke {
                Some(result) => {
                    let _ = result;
                }
                None => {
                    self.check_aired();
                    return;
                }
            }
        }
        panic!("the node never went idle");
    }

    /// Everything a node transmits parses, and a frame it forwards is the
    /// frame it heard.
    fn check_aired(&mut self) {
        let radio = self.mac.radio();
        for frame in &radio.tx[self.aired..] {
            let header = PacketHeader::parse(frame).expect("a node airs what it can parse");
            umsh_packet::assert_ranges_sane(&header, frame.len());
            let Some(key) = dup_key(frame) else {
                continue;
            };
            // Frames with one MIC and different options share a key, so the
            // forward has only to match one of them.
            let mut heard = self.heard.iter().filter(|(heard, _)| *heard == key);
            if heard.clone().next().is_some() {
                let aired = aad(frame).expect("a forward's options decode");
                assert!(
                    heard.any(|(_, heard)| *heard == aired),
                    "a forward changed the AAD: {aired:02x?}"
                );
            }
        }
        self.aired = radio.tx.len();
    }

    fn deliver(&mut self, frame: Vec<u8>, rssi: i16, snr: i8, origin: RxOrigin) {
        // A radio hands over no more than a frame, but the node still wakes
        // at this instant, as it does for a frame a filtered run leaves out.
        // When it wakes decides which of two sends due together goes first.
        if frame.len() <= FRAME {
            if let (Some(key), Some(heard)) = (dup_key(&frame), aad(&frame)) {
                self.heard.push((key, heard));
            }
            self.mac.radio_mut().inject(frame, rssi, snr, origin);
        }
        self.settle();
    }

    fn rx(&mut self, body: &[u8], omit_raw: bool) {
        let mut fields = Fields::new(body);
        let selector = match (self.mode, fields.u8()) {
            (Mode::Raw, _) => RAW,
            (Mode::Sealed, selector) => selector,
        };
        self.clock.advance_ms(u64::from(fields.u16()));
        let rssi = -i16::from(fields.u8());
        let snr = fields.u8() as i8;
        let origin = match fields.u8() % 8 {
            0..=4 => RxOrigin::Air,
            5 => RxOrigin::Backhaul,
            6 => RxOrigin::LocalTx,
            _ => RxOrigin::Bearer(BearerId::new(0).expect("the first bearer")),
        };
        let frame = fields.rest();
        if omit_raw && selector == RAW && !is_unauthenticated_kind(frame) {
            // The time still passed, and the node still woke for it.
            self.settle();
            return;
        }
        let frame = fixup::apply(frame, selector);
        self.deliver(frame, rssi, snr, origin);
    }

    fn send(&mut self, body: &[u8]) -> Option<u32> {
        if self.mode != Mode::Sealed {
            return None;
        }
        let mut fields = Fields::new(body);
        let kind = fields.u8();
        let flags = fields.u16();
        let hops = fields.u8();
        let delay = fields.u8();
        let payload = fields.rest();

        let mut options = SendOptions::default().with_ack_requested(flags & 0x0001 != 0);
        if flags & 0x0002 != 0 {
            options = options.with_trace();
        }
        if flags & 0x0004 != 0 {
            options = options.with_full_source();
        }
        if flags & 0x0008 != 0 {
            options = options.with_salt();
        }
        if flags & 0x0010 != 0 {
            options = options.unencrypted();
        }
        if flags & 0x0020 != 0 {
            options = options.with_signature();
        }
        if flags & 0x0040 != 0 {
            options = options.no_flood();
        } else if hops != 0 {
            options = options.with_flood_hops(hops);
        }
        if delay != 0 {
            options = options.with_tx_delay_ms(u16::from(delay) * 8);
        }
        options = options.with_mic_size(match flags >> 8 & 3 {
            0 => MicSize::Mic4,
            1 => MicSize::Mic8,
            2 => MicSize::Mic12,
            _ => MicSize::Mic16,
        });
        if flags & 0x0080 != 0
            && let Ok(routed) = options
                .clone()
                .try_with_source_route(&[RouterHint([0x11, 0x22]), RouterHint([0x33, 0x44])])
        {
            options = routed;
        }

        let cast = cast();
        let peer = &cast.parties[usize::from(kind >> 2) % fixup::PARTIES].key;
        let local = self.local;
        let receipt = block_on::ready(async {
            match kind & 3 {
                0 => self.mac.send_unicast(local, peer, payload, &options).await,
                1 => {
                    let channel = &cast.channel_key;
                    self.mac
                        .send_blind_unicast(local, peer, channel, payload, &options)
                        .await
                }
                2 => {
                    let channel = &cast.channel_key;
                    self.mac
                        .send_multicast(local, channel, payload, &options)
                        .await
                        .map(Some)
                }
                _ => self
                    .mac
                    .send_broadcast(local, payload, &options)
                    .await
                    .map(Some),
            }
        });
        let receipt = receipt.ok().flatten().map(|SendReceipt(receipt)| receipt);
        // Only a send to one peer has an ack to wait for.
        if options.ack_requested
            && kind & 3 < 2
            && let Some(receipt) = receipt
        {
            self.tracked.insert(receipt);
        }
        self.settle();
        receipt
    }

    /// What the node has aired since a link last took any.
    fn take_aired(&mut self) -> Vec<Vec<u8>> {
        let tx = &self.mac.radio().tx;
        let frames = tx[self.carried..].to_vec();
        self.carried = tx.len();
        frames
    }

    /// Act as the destination of a send still waiting: acknowledge it, or
    /// with `ACK_VOUCH` ask its sender to vouch for it, naming it by the
    /// Ack MIC only the send's keys produce. Mutation reaches neither.
    fn ack(&mut self, body: &[u8]) {
        if self.mode != Mode::Sealed {
            return;
        }
        let cast = cast();
        let local = self.local;
        let mut fields = Fields::new(body);
        let wanted = usize::from(fields.u8());
        let flags = fields.u8();
        let Some(slot) = self.mac.identity(local) else {
            return;
        };
        let pending: Vec<_> = slot
            .pending_acks()
            .filter(|(_, pending)| pending.expects_ack())
            .map(|(_, pending)| {
                let blind = PacketHeader::parse(pending.resend.frame.as_slice())
                    .is_ok_and(|h| h.packet_type() == PacketType::BlindUnicastAckReq);
                (pending.ack_v, pending.peer, blind)
            })
            .collect();
        if pending.is_empty() {
            return;
        }
        let (ack_v, peer, blind) = pending[wanted % pending.len()];
        let Some(index) = cast.parties.iter().position(|party| party.key == peer) else {
            return;
        };
        let party = &cast.parties[index];
        // Frame Verified's ack is what moves a baseline on this side.
        self.log.forget(&party.key.0);

        let frame = if flags & ACK_VOUCH != 0 {
            let mut payload = vec![PayloadType::MacCommand as u8, MAC_COMMAND_VERIFY_FRAME_ID];
            payload.extend_from_slice(&fields.u32().to_be_bytes());
            let mut ack_mic = [0; 4];
            ack_mic.copy_from_slice(&ack_v[..4]);
            let counter = self.counter(fields.u32());
            reply(index, blind, false, counter, &payload, Some(ack_mic))
        } else {
            let mut buf = [0u8; 64];
            PacketBuilder::new(&mut buf)
                .mac_ack([0; 8])
                .build()
                .ok()
                .map(|frame| frame.to_vec())
                .and_then(|mut frame| {
                    let keys = blind.then(|| fixup::blind_keys(party));
                    fixup::engine()
                        .seal_mac_ack(keys.as_ref().unwrap_or(&party.keys), &ack_v, &mut frame)
                        .is_ok()
                        .then_some(frame)
                })
        };
        if let Some(frame) = frame {
            self.deliver(frame, -60, 5, RxOrigin::Air);
        }
    }

    /// The counter a harness-built reply uses: the script's, or the next
    /// in a run of its own.
    fn counter(&mut self, wanted: u32) -> u32 {
        if wanted != 0 {
            return wanted;
        }
        self.next_counter = self.next_counter.wrapping_add(1);
        self.next_counter
    }

    /// Answer the last counter-resync challenge the node sent, as the party
    /// it went to: an Echo Request with its Echo Response, a Verify Frame
    /// with Frame Verified. Their nonces are secret and fresh, so mutation
    /// alone never reaches what comes next.
    fn answer(&mut self, body: &[u8]) {
        if self.mode != Mode::Sealed {
            return;
        }
        let cast = cast();
        let mut fields = Fields::new(body);
        let index = usize::from(fields.u8()) % fixup::PARTIES;
        let ack_requested = fields.u8() & 1 != 0;
        let counter = self.counter(fields.u32());
        let party = &cast.parties[index];
        let challenge = self.mac.radio().tx.iter().rev().find_map(|frame| {
            let command = command_to(frame, party, cast)?;
            let answer = match command.id {
                MAC_COMMAND_ECHO_REQUEST_ID => MAC_COMMAND_ECHO_RESPONSE_ID,
                MAC_COMMAND_VERIFY_FRAME_ID => MAC_COMMAND_FRAME_VERIFIED_ID,
                _ => return None,
            };
            Some((command, answer))
        });
        let Some((command, answer)) = challenge else {
            return;
        };
        let mut payload = vec![PayloadType::MacCommand as u8, answer];
        payload.extend_from_slice(&command.data);
        let frame = reply(index, command.blind, ack_requested, counter, &payload, None);
        self.log.forget(&party.key.0);
        if let Some(frame) = frame {
            self.deliver(frame, -60, 5, RxOrigin::Air);
        }
    }

    fn step(&mut self, record: Record<'_>, omit_raw: bool) {
        match record.op % OPS {
            OP_RX => self.rx(record.body, omit_raw),
            OP_ADVANCE => {
                self.clock
                    .advance_ms(u64::from(Fields::new(record.body).u16()) * 8);
                self.settle();
            }
            OP_SEND => {
                self.send(record.body);
            }
            OP_ACK => self.ack(record.body),
            OP_ANSWER => self.answer(record.body),
            OP_FAULT => self
                .store
                .failing
                .set(Fields::new(record.body).u8() & 1 != 0),
            _ => {}
        }
    }

    /// Run time forward until everything owed has come due.
    fn drain(&mut self) {
        self.store.failing.set(false);
        for _ in 0..DRAIN_STEPS {
            self.clock.advance_ms(DRAIN_STEP_MS);
            self.settle();
        }
    }

    /// Every send reaches an end, and nothing is left waiting forever.
    fn check_termination(&self) {
        let queued = self.mac.tx_queue().len();
        assert_eq!(queued, 0, "frames still queued after every deadline");
        let slot = self.mac.identity(self.local).expect("the local identity");
        let waiting = slot
            .pending_acks()
            .filter(|(_, pending)| pending.expects_ack())
            .count();
        assert_eq!(waiting, 0, "sends still waiting after every deadline");
        for receipt in &self.tracked {
            assert!(
                self.log.terminal.contains(receipt),
                "send {receipt} never reached a terminal event"
            );
        }
    }

    /// An honest peer the script could not forge for still gets service:
    /// its frame is delivered once, acknowledged, and refused as a replay.
    fn check_canary(&mut self) {
        let cast = cast();
        let payload = [PayloadType::Empty as u8, 0xCA, 0x4E];
        let frame = sealed_ack_requested(&cast.canary, cast, 1, &payload)
            .expect("the canary's frame builds");
        let before = self.log.received.len();
        let aired = self.mac.radio().tx.len();

        self.deliver(frame.clone(), -60, 5, RxOrigin::Air);
        let from = Some(cast.canary.key.0);
        let delivered = self.log.received[before..]
            .iter()
            .filter(|delivered| delivered.from == from)
            .count();
        assert_eq!(delivered, 1, "an honest peer lost service");

        let header = PacketHeader::parse(&frame).expect("it built");
        let v = fixup::engine()
            .packet_tag(&cast.canary.keys.k_mic, &header, &opened(&frame), None)
            .expect("its tag recomputes");
        for _ in 0..DRAIN_STEPS {
            self.clock.advance_ms(1_000);
            self.settle();
        }
        let acked = self.mac.radio().tx[aired..]
            .iter()
            .any(|sent| fixup::engine().verify_mac_ack(&cast.canary.keys, &v, sent));
        assert!(acked, "an honest peer's frame went unacknowledged");

        self.deliver(frame, -60, 5, RxOrigin::Air);
        let again = self.log.received[before..]
            .iter()
            .filter(|delivered| delivered.from == from)
            .count();
        assert_eq!(again, 1, "the canary's frame was delivered twice");
    }

    fn note_peers(&mut self) {
        let peers = self.mac.peer_registry().iter();
        self.peers
            .push(peers.map(|(_, peer)| peer.public_key.0).collect());
    }

    fn outcome(self) -> Outcome {
        let cast = cast();
        let commands_aired = self
            .mac
            .radio()
            .tx
            .iter()
            .flat_map(|frame| {
                cast.parties
                    .iter()
                    .filter_map(|party| command_to(frame, party, cast))
            })
            .map(|command| command.id)
            .collect();
        Outcome {
            received: self.log.received,
            peers: self.peers,
            commands_aired,
            counters: self.mac.counters(),
        }
    }
}

/// A frame whose authenticity is not a matter of a MIC, or noise that means
/// nothing either way, stays in a filtered run: only frames a MIC would
/// decide on are what non-interference removes.
fn is_unauthenticated_kind(frame: &[u8]) -> bool {
    matches!(
        PacketHeader::parse(frame).map(|header| header.packet_type()),
        Ok(PacketType::Broadcast)
    )
}

/// `frame` with its ciphertext opened, as `packet_tag` reads it.
fn opened(frame: &[u8]) -> Vec<u8> {
    let cast = cast();
    let mut buf = frame.to_vec();
    let header = PacketHeader::parse(frame).expect("it built");
    fixup::engine()
        .open_packet(&mut buf, &header, &cast.canary.keys, None)
        .expect("it sealed");
    buf
}

fn seal(frame: Vec<u8>, party: &fixup::Party) -> Option<Vec<u8>> {
    let mut buf = frame;
    let header = PacketHeader::parse(&buf).ok()?;
    let start = header.options_range.start;
    let sec_info = header.sec_info?;
    let mut packet = umsh_core::UnsealedPacket::new(
        &mut buf,
        header.total_len,
        header.body_range.clone(),
        None,
        None,
        header.mic_range.clone(),
        start - sec_info.wire_len()..start,
        header.options_range.clone(),
    );
    fixup::engine().seal_packet(&mut packet, &party.keys).ok()?;
    Some(buf)
}

/// A MAC command the local node sent one party.
struct Command {
    id: u8,
    data: Vec<u8>,
    blind: bool,
}

fn command_to(frame: &[u8], party: &fixup::Party, cast: &Cast) -> Option<Command> {
    let mut buf = frame.to_vec();
    let header = PacketHeader::parse(frame).ok()?;
    let engine = fixup::engine();
    let (range, blind) = match header.packet_type() {
        PacketType::Unicast | PacketType::UnicastAckReq => {
            let range = engine.open_packet(&mut buf, &header, &party.keys, None);
            (range.ok()?, false)
        }
        PacketType::BlindUnicast | PacketType::BlindUnicastAckReq => {
            let opened = engine
                .decrypt_blind_addr(&mut buf, &header, &cast.channel)
                .ok()?;
            let keys = fixup::blind_keys(party);
            let range = engine.open_packet(&mut buf, &header, &keys, Some(&opened.addr));
            (range.ok()?, true)
        }
        _ => return None,
    };
    let (&kind, rest) = buf[range].split_first()?;
    let (&id, data) = rest.split_first()?;
    (kind == PayloadType::MacCommand as u8).then(|| Command {
        id,
        data: data.to_vec(),
        blind,
    })
}

/// A frame from party `index` to the local node, sealed as that party would.
fn reply(
    index: usize,
    blind: bool,
    ack_requested: bool,
    counter: u32,
    payload: &[u8],
    ack_mic: Option<[u8; 4]>,
) -> Option<Vec<u8>> {
    let cast = cast();
    let local = cast.local_key.hint();
    let source = cast.parties[index].identity.hint();
    let mut buf = [0u8; FRAME];
    let frame = if blind {
        let mut builder = PacketBuilder::new(&mut buf)
            .blind_unicast(cast.channel.channel_id, local)
            .source_hint(source)
            .frame_counter(counter);
        if ack_requested {
            builder = builder.ack_requested();
        }
        if let Some(ack_mic) = &ack_mic {
            builder = builder.option(OptionNumber::AckMic, ack_mic);
        }
        builder.payload(payload).build().ok()?.as_bytes().to_vec()
    } else {
        let mut builder = PacketBuilder::new(&mut buf)
            .unicast(local)
            .source_hint(source)
            .frame_counter(counter)
            .encrypted();
        if ack_requested {
            builder = builder.ack_requested();
        }
        if let Some(ack_mic) = &ack_mic {
            builder = builder.option(OptionNumber::AckMic, ack_mic);
        }
        builder.payload(payload).build().ok()?.as_bytes().to_vec()
    };
    Some(fixup::apply(&frame, index as u8))
}

fn sealed_ack_requested(
    party: &fixup::Party,
    cast: &Cast,
    counter: u32,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let mut buf = [0u8; FRAME];
    let packet = PacketBuilder::new(&mut buf)
        .unicast(cast.local_key.hint())
        .source_hint(party.identity.hint())
        .frame_counter(counter)
        .encrypted()
        .ack_requested()
        .payload(payload)
        .build()
        .ok()?;
    seal(packet.as_bytes().to_vec(), party)
}

/// How much of the run's end to check.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Oracles {
    /// What holds at every step, plus the end of every ladder.
    Termination,
    /// Those, then the canary.
    All,
    /// Only what the run delivered, for comparison.
    Compare { omit_raw: bool },
}

fn run_sized<const PEERS: usize, const HOLDS: usize>(
    data: &[u8],
    mode: Mode,
    oracles: Oracles,
) -> Outcome {
    let mut steps = records(data).peekable();
    let config = match steps.peek() {
        Some(Record {
            op: OP_CONFIG,
            body,
        }) => {
            let body = *body;
            steps.next();
            body
        }
        _ => &[],
    };
    // Repeating needs no keys, so a frame failing its MIC may rightly be
    // forwarded, and that spends airtime and draws on the RNG: every later
    // nonce and backoff would differ. A comparison asks about everything else.
    let repeating = !matches!(oracles, Oracles::Compare { .. });
    let mut harness = Harness::<PEERS, HOLDS>::new(config, mode, repeating);
    let omit_raw = matches!(oracles, Oracles::Compare { omit_raw: true });
    for record in steps {
        harness.step(record, omit_raw);
        if matches!(oracles, Oracles::Compare { .. }) {
            harness.note_peers();
        }
    }
    harness.drain();
    match oracles {
        Oracles::Termination => harness.check_termination(),
        Oracles::All => {
            harness.check_termination();
            harness.check_canary();
        }
        Oracles::Compare { .. } => {}
    }
    harness.outcome()
}

pub const LOOP_SEND: u8 = 0;
pub const LOOP_ADVANCE: u8 = 1;
pub const LOOP_FATES: u8 = 2;
const LOOP_OPS: u8 = 3;

const FATE_LOSE: u8 = 0x01;
const FATE_REPEAT: u8 = 0x02;

/// A link between two nodes that loses and repeats what it carries.
struct Link {
    fates: Vec<u8>,
    next: usize,
}

impl Link {
    fn fate(&mut self) -> u8 {
        if self.fates.is_empty() {
            return 0;
        }
        self.next = (self.next + 1) % self.fates.len();
        self.fates[self.next]
    }

    fn carry(&mut self, from: &mut Harness<16, 0>, to: &mut Harness<16, 0>) -> usize {
        let frames = from.take_aired();
        for frame in &frames {
            let fate = self.fate();
            if fate & FATE_LOSE == 0 {
                to.deliver(frame.clone(), -60, 5, RxOrigin::Air);
            }
            if fate & FATE_REPEAT != 0 {
                to.deliver(frame.clone(), -60, 5, RxOrigin::Air);
            }
        }
        frames.len()
    }

    /// Carry frames until neither side has more to say at this instant.
    fn exchange(&mut self, a: &mut Harness<16, 0>, b: &mut Harness<16, 0>) {
        for _ in 0..WAKE_BOUND {
            if self.carry(a, b) + self.carry(b, a) == 0 {
                return;
            }
        }
        panic!("two nodes never went quiet");
    }
}

/// Two whole nodes with a lossy link between them: what arrives is what was
/// sent, and an ack means it arrived.
pub fn run_loop(data: &[u8]) {
    let cast = cast();
    let party = &cast.parties[0];
    let station = Station::new(&[0], false, &cast.local_secret, &[party.key]);
    let mut a = Harness::<16, 0>::from_station(station, Mode::Sealed);
    let station = Station::new(&[0x10], false, &party.secret, &[cast.local_key]);
    let mut b = Harness::<16, 0>::from_station(station, Mode::Sealed);
    let mut link = Link {
        fates: Vec::new(),
        next: 0,
    };
    let mut sent: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut payloads: BTreeSet<Vec<u8>> = BTreeSet::new();

    for record in records(data) {
        match record.op % LOOP_OPS {
            LOOP_SEND => {
                // Only the one peer each node has.
                let mut body = record.body.to_vec();
                if let Some(kind) = body.first_mut() {
                    *kind &= 3;
                }
                let payload = body.get(5..).unwrap_or(&[]).to_vec();
                payloads.insert(payload.clone());
                if let Some(receipt) = a.send(&body) {
                    sent.insert(receipt, payload);
                }
            }
            LOOP_ADVANCE => {
                let ms = u64::from(Fields::new(record.body).u16()) * 8;
                a.clock.advance_ms(ms);
                b.clock.advance_ms(ms);
                a.settle();
                b.settle();
            }
            _ => {
                link.fates = record.body.to_vec();
                link.next = 0;
            }
        }
        link.exchange(&mut a, &mut b);
    }

    for _ in 0..DRAIN_STEPS {
        a.clock.advance_ms(DRAIN_STEP_MS);
        b.clock.advance_ms(DRAIN_STEP_MS);
        a.settle();
        b.settle();
        link.exchange(&mut a, &mut b);
    }
    a.check_termination();
    b.check_termination();

    let is_command = |payload: &[u8]| payload.first() == Some(&(PayloadType::MacCommand as u8));
    for delivered in &b.log.received {
        assert!(
            is_command(&delivered.payload) || payloads.contains(&delivered.payload),
            "a node delivered what nobody sent: {delivered:02x?}"
        );
    }
    for receipt in &a.log.acked {
        let Some(payload) = sent.get(receipt) else {
            continue;
        };
        assert!(
            is_command(payload) || b.log.received.iter().any(|d| d.payload == *payload),
            "an ack for a frame that never arrived: {payload:02x?}"
        );
    }
}

/// Run a script on the `Mac` sizing its config record selects.
pub fn run(data: &[u8], mode: Mode, oracles: Oracles) -> Outcome {
    let sizing = match records(data).next() {
        Some(Record {
            op: OP_CONFIG,
            body,
        }) => Fields::new(body).u8() >> 4 & 3,
        _ => 0,
    };
    match sizing {
        // The device node's own sizing.
        0 | 1 => run_sized::<16, 0>(data, mode, oracles),
        // A small table, so that full-table paths come up in short scripts.
        2 => run_sized::<4, 0>(data, mode, oracles),
        // Route holds exist only when a build has room for them.
        _ => run_sized::<16, 4>(data, mode, oracles),
    }
}
