//! The text engine: sequencing, fragment reassembly, and repair, driven by
//! a script of received payloads, compositions, and the passage of time.

use umsh_core::{ChannelTag, NodeHint, PublicKey};
use umsh_text::engine::{
    ArchiveResult, ComposeIntent, DeliveryState, Engine, EngineConfig, Output,
};
use umsh_text::validate::{DeliveryPath, DirectChannelProfile, Envelope};
use umsh_text::{ConversationKey, SenderScope};

use crate::script::{Fields, records};

pub const OP_RECEIVE: u8 = 0;
pub const OP_TICK: u8 = 1;
pub const OP_COMPOSE: u8 = 2;

const LOCAL: PublicKey = PublicKey([0xAA; 32]);
const PEERS: [PublicKey; 2] = [PublicKey([0x11; 32]), PublicKey([0x22; 32])];
const CHANNEL: ChannelTag = ChannelTag([0x5A; 16]);
const MEMBERS: [NodeHint; 2] = [NodeHint([0x33, 0x44, 0x55]), NodeHint([0x66, 0x77, 0x88])];

/// How far past the last input the settling ticks run, enough to outlast
/// every repair and reassembly deadline.
const SETTLE_MS: u64 = 24 * 60 * 60 * 1000;
/// Far more settling ticks than any bounded repair can use.
const SETTLE_TICKS: usize = 4096;

type FuzzEngine = Engine<DirectChannelProfile, 4, 24>;

/// The conversation and sender a selector names.
pub fn envelope(selector: u8) -> Envelope {
    let peer = PEERS[usize::from(selector & 1)];
    let member = MEMBERS[usize::from(selector & 1)];
    match (selector >> 1) % 3 {
        0 => Envelope {
            path: DeliveryPath::Unicast,
            conversation: ConversationKey::Direct { peer },
            sender: SenderScope::Peer(peer),
        },
        1 => Envelope {
            path: DeliveryPath::Multicast,
            conversation: ConversationKey::ChannelGroup { channel: CHANNEL },
            sender: SenderScope::ClaimedMember(member),
        },
        _ => Envelope {
            path: DeliveryPath::BlindUnicast,
            conversation: ConversationKey::ChannelDirect {
                channel: CHANNEL,
                peer,
            },
            sender: SenderScope::Peer(peer),
        },
    }
}

/// Serve what the engine asks of a platform, and report how many frames it
/// wanted on the air.
fn drain(engine: &mut FuzzEngine, now_ms: u64) -> usize {
    let mut transmitted = 0;
    while let Some(output) = engine.poll_output() {
        match output {
            Output::Transmit(transmission) => {
                transmitted += 1;
                engine.transmit_update(transmission.transmission_id, DeliveryState::Sent, now_ms);
            }
            Output::LookupOutbound { request_id, .. } => {
                engine.archive_result(request_id, ArchiveResult::Unknown, now_ms);
            }
            _ => {}
        }
    }
    transmitted
}

pub fn run(data: &[u8]) {
    let mut engine = FuzzEngine::new(DirectChannelProfile, LOCAL, EngineConfig::default(), 42);
    let mut now_ms = 0u64;
    for record in records(data) {
        let mut fields = Fields::new(record.body);
        match record.op % 3 {
            OP_RECEIVE => {
                let selector = fields.u8();
                now_ms += u64::from(fields.u16());
                let envelope = envelope(selector);
                let full_key = match envelope.sender {
                    SenderScope::Peer(peer) if selector & 0x80 != 0 => Some(peer),
                    _ => None,
                };
                let _ = engine.receive(&envelope, full_key, fields.rest(), now_ms);
            }
            OP_TICK => {
                now_ms += u64::from(fields.u16()) * 16;
                engine.tick(now_ms);
            }
            _ => {
                let conversation = envelope(fields.u8()).conversation;
                if let Ok(body) = core::str::from_utf8(fields.rest()) {
                    let intent = ComposeIntent::typed(body);
                    let _ = engine.compose(conversation, 1, intent, now_ms);
                }
            }
        }
        drain(&mut engine, now_ms);
    }

    // Everything the script left open has to come to rest. Repair walks a
    // gap one ID at a time with several attempts each, so this can take many
    // ticks, but it has to end.
    for _ in 0..SETTLE_TICKS {
        now_ms += SETTLE_MS;
        engine.tick(now_ms);
        if drain(&mut engine, now_ms) == 0 {
            return;
        }
    }
    panic!("repair never settled");
}
