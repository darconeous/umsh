//! Multi-node simulated-airtime tests for the text engine.
//!
//! Each node runs a real engine; frames travel over a simulated serialized
//! half-duplex link — one outstanding physical transmission per node with a
//! fixed per-frame airtime, matching the mobile one-outstanding-TX rule. The
//! simulation is fully deterministic: virtual clock, explicit drop list, no
//! wall-clock time or RNG.
//!
//! The core storm metric is frames-on-air per delivered message: a healthy
//! link must carry exactly one frame per fragment, with zero resend traffic,
//! no matter how slow delivery is.

#![cfg(feature = "std")]

use std::collections::{HashMap, VecDeque};

use umsh_core::PublicKey;
use umsh_text::codec;
use umsh_text::engine::sequence::MessageHandle;
use umsh_text::engine::{
    ArchiveResult, CompletionStatus, ComposeIntent, DeliveryState, Destination, Diagnostic, Engine,
    EngineConfig, MutationKind, Output,
};
use umsh_text::validate::{DeliveryPath, DirectChannelProfile, Envelope};
use umsh_text::{ConversationKey, MessageType, SenderScope};

type SimEngine = Engine<DirectChannelProfile, 4, 24>;

/// Simulation step granularity. All timing constants in the engine are
/// hundreds of milliseconds or more, so 50 ms steps resolve every deadline.
const STEP_MS: u64 = 50;
/// Cadence at which the platform would drive `Engine::tick`.
const TICK_INTERVAL_MS: u64 = 250;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameKind {
    Content {
        message_id: u8,
        fragment: Option<u8>,
    },
    ResendRequest,
    Unavailable,
    Other,
}

fn classify(payload: &[u8]) -> FrameKind {
    let Ok(message) = codec::parse(payload) else {
        return FrameKind::Other;
    };
    let message_id = message.sequence.map(|s| s.message_id).unwrap_or(0);
    let fragment = message.sequence.and_then(|s| s.fragment).map(|f| f.index);
    match message.message_type {
        MessageType::ResendRequest => FrameKind::ResendRequest,
        MessageType::MessageUnavailable => FrameKind::Unavailable,
        _ => FrameKind::Content {
            message_id,
            fragment,
        },
    }
}

/// One frame that completed its airtime, as seen by a sniffer.
#[derive(Clone, Debug)]
struct AirFrame {
    #[allow(dead_code)]
    at_ms: u64,
    from: usize,
    kind: FrameKind,
}

struct QueuedFrame {
    transmission_id: u32,
    payload: Vec<u8>,
    /// `None` broadcasts to every other node (channel delivery).
    to: Option<usize>,
}

struct Node {
    key: PublicKey,
    engine: SimEngine,
    /// Resendable outbound material, keyed as the engine's `ArchiveKey`.
    archive: HashMap<(ConversationKey, u8, Option<u8>), Vec<u8>>,
    tx_queue: VecDeque<QueuedFrame>,
    current_tx: Option<(QueuedFrame, u64)>,
    /// `(transmission_id, due_ms, delivered)` MAC-ack reports to feed back.
    pending_acks: Vec<(u32, u64, bool)>,
    /// Latest rendered body and status per transcript handle.
    transcript: HashMap<MessageHandle, (String, CompletionStatus)>,
    duplicate_frames: u32,
}

struct SimConfig {
    airtime_ms: u64,
    /// Delay from physical TX completion to the MAC-level ack (or failure)
    /// report arriving back at the sender.
    ack_turnaround_ms: u64,
    /// Global on-air frame ordinals (0-based, in completion order) lost in
    /// flight: the receiver never sees them, the sender still gets no ack.
    drop_frames: Vec<u64>,
    run_ms: u64,
}

struct Sim {
    now: u64,
    nodes: Vec<Node>,
    config: SimConfig,
    air: Vec<AirFrame>,
    air_ordinal: u64,
}

impl Sim {
    fn new(keys: &[PublicKey], engine_config: EngineConfig, config: SimConfig) -> Self {
        let nodes = keys
            .iter()
            .enumerate()
            .map(|(index, key)| Node {
                key: *key,
                engine: Engine::new(
                    DirectChannelProfile,
                    *key,
                    engine_config.clone(),
                    0x5EED + index as u64,
                ),
                archive: HashMap::new(),
                tx_queue: VecDeque::new(),
                current_tx: None,
                pending_acks: Vec::new(),
                transcript: HashMap::new(),
                duplicate_frames: 0,
            })
            .collect();
        Self {
            now: 0,
            nodes,
            config,
            air: Vec::new(),
            air_ordinal: 0,
        }
    }

    fn node_by_key(&self, key: &PublicKey) -> Option<usize> {
        self.nodes.iter().position(|node| node.key == *key)
    }

    fn compose(&mut self, node: usize, conversation: ConversationKey, body: &str) {
        let now = self.now;
        self.nodes[node]
            .engine
            .compose(
                conversation,
                1,
                ComposeIntent::Text {
                    body,
                    status: false,
                },
                now,
            )
            .expect("compose");
        self.process_outputs(node);
    }

    /// Drain one node's engine outputs, servicing archive lookups until the
    /// queue is empty (mirrors the platform contract).
    fn process_outputs(&mut self, index: usize) {
        loop {
            let mut lookups = Vec::new();
            loop {
                let output = match self.nodes[index].engine.poll_output() {
                    Some(output) => output,
                    None => break,
                };
                match output {
                    Output::Transmit(tx) => {
                        if let Some(archive) = tx.archive {
                            self.nodes[index].archive.insert(
                                (archive.conversation, archive.message_id, archive.fragment),
                                tx.payload.to_vec(),
                            );
                        }
                        let to = match tx.destination {
                            Destination::Peer(peer) | Destination::ChannelPeer { peer, .. } => {
                                self.node_by_key(&peer)
                            }
                            Destination::Channel(_) => None,
                        };
                        self.nodes[index].tx_queue.push_back(QueuedFrame {
                            transmission_id: tx.transmission_id,
                            payload: tx.payload.to_vec(),
                            to,
                        });
                    }
                    Output::StoreCheckpoint { .. } => {}
                    Output::LookupOutbound {
                        request_id,
                        conversation,
                        sequence,
                    } => lookups.push((request_id, conversation, sequence)),
                    Output::StoreMessage(mutation) => match mutation.kind {
                        MutationKind::Insert { body, status, .. } => {
                            let text = self.nodes[index].engine.body(&body).to_string();
                            self.nodes[index]
                                .transcript
                                .insert(mutation.handle, (text, status));
                        }
                        MutationKind::UpdateBody { body, status } => {
                            let text = self.nodes[index].engine.body(&body).to_string();
                            self.nodes[index]
                                .transcript
                                .insert(mutation.handle, (text, status));
                        }
                        MutationKind::Edit { .. } | MutationKind::Delete { .. } => {}
                    },
                    Output::Event(_) => {}
                    Output::Diagnostic(
                        Diagnostic::DuplicateFragment { .. } | Diagnostic::DuplicateMessage { .. },
                    ) => {
                        self.nodes[index].duplicate_frames += 1;
                    }
                    Output::Diagnostic(_) => {}
                }
            }
            if lookups.is_empty() {
                break;
            }
            let now = self.now;
            for (request_id, conversation, sequence) in lookups {
                let key = (
                    conversation,
                    sequence.message_id,
                    sequence.fragment.map(|f| f.index),
                );
                let payload = self.nodes[index].archive.get(&key).cloned();
                match payload {
                    Some(bytes) => self.nodes[index].engine.archive_result(
                        request_id,
                        ArchiveResult::Found { payload: &bytes },
                        now,
                    ),
                    None => self.nodes[index].engine.archive_result(
                        request_id,
                        ArchiveResult::Unknown,
                        now,
                    ),
                }
            }
        }
    }

    fn deliver(&mut self, to: usize, from: usize, payload: &[u8]) {
        let sender_key = self.nodes[from].key;
        let envelope = Envelope {
            path: DeliveryPath::Unicast,
            conversation: ConversationKey::Direct { peer: sender_key },
            sender: SenderScope::Peer(sender_key),
        };
        let now = self.now;
        let _ = self.nodes[to]
            .engine
            .receive(&envelope, Some(sender_key), payload, now);
        self.process_outputs(to);
    }

    fn step(&mut self) {
        let now = self.now;

        // Platform tick cadence.
        if now % TICK_INTERVAL_MS == 0 {
            for index in 0..self.nodes.len() {
                self.nodes[index].engine.tick(now);
                self.process_outputs(index);
            }
        }

        // Physical TX completions.
        for index in 0..self.nodes.len() {
            let done = self.nodes[index]
                .current_tx
                .as_ref()
                .is_some_and(|(_, done_at)| now >= *done_at);
            if !done {
                continue;
            }
            let (frame, _) = self.nodes[index].current_tx.take().expect("checked");
            let ordinal = self.air_ordinal;
            self.air_ordinal += 1;
            let dropped = self.config.drop_frames.contains(&ordinal);
            self.air.push(AirFrame {
                at_ms: now,
                from: index,
                kind: classify(&frame.payload),
            });
            self.nodes[index].engine.transmit_update(
                frame.transmission_id,
                DeliveryState::Sent,
                now,
            );
            self.process_outputs(index);
            if !dropped {
                match frame.to {
                    Some(to) => self.deliver(to, index, &frame.payload),
                    None => {
                        for to in 0..self.nodes.len() {
                            if to != index {
                                self.deliver(to, index, &frame.payload);
                            }
                        }
                    }
                }
            }
            let ack_at = now + self.config.ack_turnaround_ms;
            self.nodes[index]
                .pending_acks
                .push((frame.transmission_id, ack_at, !dropped));
        }

        // Start the next serialized transmission on idle radios.
        for node in &mut self.nodes {
            if node.current_tx.is_none()
                && let Some(frame) = node.tx_queue.pop_front()
            {
                let done_at = now + self.config.airtime_ms;
                node.current_tx = Some((frame, done_at));
            }
        }

        // MAC ack reports.
        for index in 0..self.nodes.len() {
            let due: Vec<(u32, bool)> = self.nodes[index]
                .pending_acks
                .iter()
                .filter(|(_, at, _)| now >= *at)
                .map(|(id, _, delivered)| (*id, *delivered))
                .collect();
            if due.is_empty() {
                continue;
            }
            self.nodes[index]
                .pending_acks
                .retain(|(_, at, _)| now < *at);
            for (id, delivered) in due {
                let state = if delivered {
                    DeliveryState::Acked
                } else {
                    DeliveryState::Failed
                };
                self.nodes[index].engine.transmit_update(id, state, now);
                self.process_outputs(index);
            }
        }
    }

    fn run(&mut self) {
        while self.now <= self.config.run_ms {
            self.step();
            self.now += STEP_MS;
        }
    }

    fn count(&self, predicate: impl Fn(&FrameKind) -> bool) -> usize {
        self.air
            .iter()
            .filter(|frame| predicate(&frame.kind))
            .count()
    }

    fn completed_body(&self, node: usize, body: &str) -> bool {
        self.nodes[node]
            .transcript
            .values()
            .any(|(text, status)| text == body && matches!(status, CompletionStatus::Complete))
    }
}

const KEY_A: PublicKey = PublicKey([0xAA; 32]);
const KEY_B: PublicKey = PublicKey([0x11; 32]);

fn two_nodes(config: SimConfig) -> Sim {
    Sim::new(&[KEY_A, KEY_B], EngineConfig::default(), config)
}

/// A 900-byte body fragments into six frames.
fn long_body() -> String {
    "x".repeat(900)
}

/// Finding-1 regression: on a healthy but slow serialized link (LoRa airtime
/// plus one-outstanding-TX), a fragmented message must arrive with exactly
/// one frame on air per fragment and zero repair traffic. The receiver must
/// not request resends of fragments that are still queued at the sender.
#[test]
fn healthy_slow_link_carries_no_repair_traffic() {
    let mut sim = two_nodes(SimConfig {
        airtime_ms: 2_500,
        ack_turnaround_ms: 500,
        drop_frames: vec![],
        run_ms: 120_000,
    });
    let body = long_body();
    sim.compose(0, ConversationKey::Direct { peer: KEY_B }, &body);
    sim.run();

    assert!(
        sim.completed_body(1, &body),
        "receiver should assemble the full message"
    );
    let requests = sim.count(|kind| matches!(kind, FrameKind::ResendRequest));
    let content = sim.count(|kind| matches!(kind, FrameKind::Content { .. }));
    assert_eq!(
        requests, 0,
        "healthy slow delivery must not trigger repair requests"
    );
    assert_eq!(content, 6, "each fragment goes on air exactly once");
    assert_eq!(
        sim.nodes[1].duplicate_frames, 0,
        "receiver saw duplicate frames"
    );
}

/// A genuinely lost fragment is still repaired, with bounded traffic: one
/// resend request and one retransmitted fragment.
#[test]
fn lost_fragment_repairs_with_bounded_traffic() {
    let mut sim = two_nodes(SimConfig {
        airtime_ms: 50,
        ack_turnaround_ms: 10,
        // Ordinal 2 is fragment 2's first pass (frames 0..=5 are the
        // message's fragments; nothing else transmits before them).
        drop_frames: vec![2],
        run_ms: 120_000,
    });
    let body = long_body();
    sim.compose(0, ConversationKey::Direct { peer: KEY_B }, &body);
    sim.run();

    assert!(
        sim.completed_body(1, &body),
        "receiver should repair and assemble the full message"
    );
    let requests = sim.count(|kind| matches!(kind, FrameKind::ResendRequest));
    let content = sim.count(|kind| matches!(kind, FrameKind::Content { .. }));
    assert_eq!(requests, 1, "one lost fragment needs one resend request");
    assert_eq!(content, 7, "six fragments plus one repair retransmission");
}

/// Very slow links (per-frame delivery slower than the initial grace) adapt:
/// after the first observed inter-fragment gap, repair defers to the
/// measured pace instead of firing between fragments.
#[test]
fn repair_holdoff_adapts_to_observed_fragment_pace() {
    let mut sim = two_nodes(SimConfig {
        airtime_ms: 6_000,
        ack_turnaround_ms: 500,
        drop_frames: vec![],
        run_ms: 180_000,
    });
    let body = long_body();
    sim.compose(0, ConversationKey::Direct { peer: KEY_B }, &body);
    sim.run();

    assert!(sim.completed_body(1, &body));
    let requests = sim.count(|kind| matches!(kind, FrameKind::ResendRequest));
    assert_eq!(
        requests, 0,
        "delivery pace within the adaptive holdoff must not trigger repair"
    );
    assert_eq!(
        sim.count(|kind| matches!(kind, FrameKind::Content { .. })),
        6
    );
}

/// The storm metric across a small conversation burst: several fragmented
/// messages back-to-back on a slow link still produce exactly one frame per
/// fragment.
#[test]
fn message_burst_on_slow_link_stays_storm_free() {
    let mut sim = two_nodes(SimConfig {
        airtime_ms: 2_000,
        ack_turnaround_ms: 400,
        drop_frames: vec![],
        run_ms: 240_000,
    });
    let bodies: Vec<String> = (0..3).map(|i| format!("{i}-{}", "y".repeat(500))).collect();
    for body in &bodies {
        sim.compose(0, ConversationKey::Direct { peer: KEY_B }, body);
    }
    sim.run();

    for body in &bodies {
        assert!(
            sim.completed_body(1, body),
            "missing message: {}",
            &body[..8]
        );
    }
    // 500-byte bodies plus prefix fragment into 4 frames each.
    let content = sim.count(|kind| matches!(kind, FrameKind::Content { .. }));
    let requests = sim.count(|kind| matches!(kind, FrameKind::ResendRequest));
    assert_eq!(requests, 0, "burst delivery must not trigger repair");
    assert_eq!(content, 12, "each fragment goes on air exactly once");
    assert_eq!(sim.nodes[1].duplicate_frames, 0);
}

/// Frames from the sniffer log grouped for debugging when assertions fail.
#[allow(dead_code)]
fn dump_air(sim: &Sim) -> String {
    sim.air
        .iter()
        .map(|frame| format!("{}ms n{} {:?}\n", frame.at_ms, frame.from, frame.kind))
        .collect()
}
