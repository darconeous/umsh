//! Write the committed seed corpus: `make fuzz-seeds`.
//!
//! Seeds come from the real encoders and the repo's own captures, so a
//! format change regenerates them instead of leaving them quietly dead.

use std::fs;
use std::path::{Path, PathBuf};

use umsh_core::{ChannelId, MicSize, NodeHint, PacketBuilder, PacketHeader, PublicKey};
use umsh_crypto::NodeIdentity;
use umsh_crypto::software::SoftwareIdentity;
use umsh_fuzz_harness::script::push_record;
use umsh_fuzz_harness::targets::text_engine::{OP_RECEIVE, OP_TICK};
use umsh_fuzz_harness::{device, fixup, mac};
use umsh_text::{Fragment, MessageSequence, MessageType, TextMessage, codec};
use umsh_ulcp::frame::{self, Cmd, Frame, FrameWriter};
use umsh_ulcp::ids::prop;
use umsh_ulcp::{Status, hdlc};
use umsh_ulcp_device::{SNAPSHOT_MAX, Session};

/// Ethernet, IPv4, and UDP headers ahead of each frame in the dissector's
/// captures.
const PCAP_LINK_PREFIX: usize = 42;
const PCAP_GLOBAL_HEADER: usize = 24;
const PCAP_RECORD_HEADER: usize = 16;

struct Seeds {
    root: PathBuf,
}

impl Seeds {
    fn write(&self, target: &str, name: &str, bytes: &[u8]) {
        let dir = self.root.join(target);
        fs::create_dir_all(&dir).expect("seed directory");
        fs::write(dir.join(name), bytes).expect("seed file");
    }
}

/// The frames of a classic little-endian pcap written by the dissector's
/// generators.
fn pcap_frames(path: &Path) -> Vec<Vec<u8>> {
    let data = fs::read(path).expect("capture");
    let mut frames = Vec::new();
    let mut at = PCAP_GLOBAL_HEADER;
    while at + PCAP_RECORD_HEADER <= data.len() {
        let captured = u32::from_le_bytes(data[at + 8..at + 12].try_into().unwrap()) as usize;
        let start = at + PCAP_RECORD_HEADER;
        frames.push(data[start + PCAP_LINK_PREFIX..start + captured].to_vec());
        at = start + captured;
    }
    frames
}

fn built_frames() -> Vec<Vec<u8>> {
    let src = PublicKey([0xA1; 32]);
    let hint = NodeHint([0xA1, 0xB2, 0x03]);
    let dst = NodeHint([0xC3, 0xD4, 0x25]);
    let channel = ChannelId([0x7E, 0x5F]);
    let mut frames = Vec::new();

    let mut buf = [0u8; 255];
    let frame = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_hint(hint)
        .region_code([0x12, 0x34])
        .payload(b"hello")
        .build()
        .unwrap();
    frames.push(frame.to_vec());

    let mut buf = [0u8; 255];
    let frame = PacketBuilder::new(&mut buf)
        .unicast(dst)
        .source_hint(hint)
        .frame_counter(9)
        .region_code([0x12, 0x34])
        .encrypted()
        .mic_size(MicSize::Mic8)
        .payload(b"hello")
        .build()
        .unwrap();
    frames.push(frame.as_bytes().to_vec());

    let mut buf = [0u8; 255];
    let frame = PacketBuilder::new(&mut buf)
        .multicast(channel)
        .source_full(&src)
        .frame_counter(3)
        .encrypted()
        .payload(b"hi")
        .build()
        .unwrap();
    frames.push(frame.as_bytes().to_vec());

    let mut buf = [0u8; 255];
    let frame = PacketBuilder::new(&mut buf)
        .blind_unicast(channel, dst)
        .source_hint(hint)
        .frame_counter(3)
        .payload(b"hi")
        .build()
        .unwrap();
    frames.push(frame.as_bytes().to_vec());

    let mut buf = [0u8; 255];
    let frame = PacketBuilder::new(&mut buf)
        .mac_ack([1, 2, 3, 4, 5, 6, 7, 8])
        .region_code([0x12, 0x34])
        .build()
        .unwrap();
    frames.push(frame.to_vec());
    frames
}

fn encode_text(message: &TextMessage<'_>) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let len = codec::encode(message, &mut buf).expect("a sendable message");
    buf[..len].to_vec()
}

fn fragment(id: u8, index: u8, count: u8, body: &[u8]) -> Vec<u8> {
    let mut message = TextMessage::basic("");
    message.sequence = Some(MessageSequence {
        message_id: id,
        fragment: Some(Fragment { index, count }),
    });
    message.body = body;
    encode_text(&message)
}

fn sequenced(id: u8, body: &'static str) -> Vec<u8> {
    let mut message = TextMessage::basic(body);
    message.sequence = Some(MessageSequence::unfragmented(id));
    encode_text(&message)
}

fn typed(kind: MessageType, id: u8, fragment: Option<Fragment>) -> Vec<u8> {
    let mut message = TextMessage::basic("");
    message.message_type = kind;
    message.sequence = Some(MessageSequence {
        message_id: id,
        fragment,
    });
    encode_text(&message)
}

fn receive(script: &mut Vec<u8>, selector: u8, dt_ms: u16, payload: &[u8]) {
    let mut body = vec![selector];
    body.extend_from_slice(&dt_ms.to_be_bytes());
    body.extend_from_slice(payload);
    push_record(script, OP_RECEIVE, &body);
}

fn text(seeds: &Seeds) {
    let bodies: Vec<(&str, Vec<u8>)> = vec![
        ("basic", encode_text(&TextMessage::basic("hello"))),
        ("sequenced", sequenced(7, "hello")),
        ("fragment", fragment(5, 0, 2, b"kept ")),
        (
            "unavailable",
            typed(
                MessageType::MessageUnavailable,
                5,
                Some(Fragment { index: 1, count: 2 }),
            ),
        ),
        ("resend", typed(MessageType::ResendRequest, 5, None)),
    ];
    for (name, body) in &bodies {
        let mut seed = vec![0];
        seed.extend_from_slice(body);
        seeds.write("text_codec", name, &seed);
    }

    // Each conversation shape: direct, channel group, and blind.
    for selector in [0, 2, 4] {
        let mut script = Vec::new();
        receive(&mut script, selector, 10, &fragment(5, 0, 3, b"one "));
        receive(&mut script, selector, 10, &fragment(5, 2, 3, b"three"));
        receive(&mut script, selector, 10, &sequenced(9, "after a gap"));
        push_record(&mut script, OP_TICK, &[0xFF, 0xFF]);
        receive(
            &mut script,
            selector,
            10,
            &typed(
                MessageType::MessageUnavailable,
                5,
                Some(Fragment { index: 1, count: 3 }),
            ),
        );
        receive(
            &mut script,
            selector,
            10,
            &typed(MessageType::ResendRequest, 2, None),
        );
        seeds.write("text_engine", &format!("repair-{selector}"), &script);
    }
}

fn ulcp(seeds: &Seeds) {
    let mut frames: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, build: &dyn Fn(&mut [u8]) -> usize| {
        let mut buf = [0u8; 300];
        let len = build(&mut buf);
        frames.push((name.to_owned(), buf[..len].to_vec()));
    };
    add("nop", &|b| frame::nop(b, 1).unwrap());
    add("reset", &|b| frame::reset(b, 1).unwrap());
    add("save", &|b| frame::save(b, 1).unwrap());
    add("restore", &|b| frame::restore(b, 1).unwrap());
    add("clear", &|b| frame::clear(b, 1).unwrap());
    add("queue_drain", &|b| frame::queue_drain(b, 1).unwrap());
    add("get", &|b| {
        frame::prop_get(b, 1, prop::PHY_ENABLED).unwrap()
    });
    add("set", &|b| {
        frame::prop_set(b, 1, prop::PHY_ENABLED, &[1]).unwrap()
    });
    add("insert", &|b| {
        frame::prop_insert(b, 1, prop::HOST_PEER_KEYS, &[0x11; 32]).unwrap()
    });
    add("multi_get", &|b| {
        frame::prop_multi_get(b, 1, &[prop::PHY_ENABLED, prop::LAST_STATUS]).unwrap()
    });
    add("are", &|b| {
        let mut writer = FrameWriter::new(b, 1, Cmd::PropAre).unwrap();
        writer.write_entry(prop::PHY_ENABLED, &[1]).unwrap();
        writer.write_entry(prop::LAST_STATUS, &[0]).unwrap();
        writer.finish()
    });
    add("session_reset", &|b| {
        frame::session_reset(b, frame::SessionResetReason::Attached).unwrap()
    });

    let mut stream = Vec::new();
    for (name, frame) in &frames {
        seeds.write("ulcp_frame", name, frame);
        let mut wire = vec![0; hdlc::max_encoded_len(frame.len())];
        let len = hdlc::encode_frame(frame, &mut wire).unwrap();
        stream.extend_from_slice(&wire[..len]);
    }
    seeds.write("ulcp_hdlc", "stream", &stream);

    let mut gatt = vec![20];
    for (sar, body) in [(1u8, b"first".as_slice()), (2, b"cont"), (3, b"last")] {
        let mut segment = vec![sar << 6];
        segment.extend_from_slice(body);
        push_record(&mut gatt, 0, &segment);
    }
    seeds.write("ulcp_gatt", "segments", &gatt);

    let session = Session::<_, _>::new(
        device::config(),
        Status::RESET_POWER_ON,
        umsh_crypto::CryptoEngine::new(
            umsh_crypto::software::SoftwareAes,
            umsh_crypto::software::SoftwareSha256,
        ),
    );
    let mut snapshot = [0u8; SNAPSHOT_MAX];
    if let Some(len) = session.encode_snapshot(&mut snapshot) {
        seeds.write("ulcp_snapshot", "fresh", &snapshot[..len]);
    }
}

fn umsh(seeds: &Seeds, repo: &Path) {
    let mut frames = built_frames();
    for capture in ["test_vectors.pcap", "violations.pcap"] {
        frames.extend(pcap_frames(&repo.join("dissectors").join(capture)));
    }
    for (index, frame) in frames.iter().enumerate() {
        seeds.write("umsh_packet", &format!("frame-{index:02}"), frame);
    }
    seeds.write(
        "umsh_options",
        "options",
        &[0x11, 0xAA, 0x21, 0xBB, 0xCC, 0xFF],
    );
}

/// One input per payload kind, selected by the leading byte each target
/// reads.
fn payloads(seeds: &Seeds) {
    use umsh_node::mac_command::{self, MacCommand};

    let mut buf = [0u8; 64];
    let commands = [
        MacCommand::IdentityRequest { options: &[] },
        MacCommand::SignalReportRequest,
        MacCommand::VerifyFrame { nonce: 7 },
        MacCommand::EchoRequest { data: b"ping" },
        MacCommand::EchoResponse { data: b"pong" },
        MacCommand::PeerRepeatersRequest { options: &[] },
        MacCommand::PeerRepeatersResponse { body: &[] },
    ];
    for (index, command) in commands.iter().enumerate() {
        let len = mac_command::encode(command, &mut buf).expect("fits");
        let mut seed = vec![0];
        seed.extend_from_slice(&buf[..len]);
        seeds.write("umsh_payloads", &format!("mac-{index}"), &seed);
    }
    seeds.write("umsh_payloads", "location", &[2, 0x12, 0x34, 0x56, 0x78]);
    seeds.write("umsh_payloads", "meet-hello", &[3, 1, 0, 3, 10]);
    seeds.write("umsh_payloads", "chat", &[4, 0]);

    let key = encode_key();
    seeds.write("uri_base58", "key", key.as_bytes());
    seeds.write("uri_base58", "node", format!("umsh:n:{key}").as_bytes());
    seeds.write("uri_base58", "channel", b"umsh:cs:general?n=General");

    seeds.write("lan_bridge", "datagram", &[0, 0x20, 0, 0]);
    seeds.write("lan_bridge", "txt", b"\x01v=1\nid=abc\nport=15056\n");
    seeds.write("lan_bridge", "tunnel", &[2, 0, 0, 0, 1, 64, 0, 0, 1, 2, 3]);

    let nop = [0x81, 0x00];
    for kind in [0u8, 1, 2, 3, 4, 5, 7, 11, 14, 19] {
        seeds.write(
            "ulcp_values",
            &format!("kind-{kind}"),
            &[kind, 0, 0, 0, 0, 0, 0, 0, 0],
        );
    }
    seeds.write("ulcp_values", "pui", &[20, 0x81, 0x01]);
    seeds.write("ulcp_values", "request", &[21, 0, 0, 0, nop[0], nop[1]]);
    seeds.write(
        "node_mgmt_envelope",
        "bare",
        &[0x12, 0x34, 0xFF, 0x81, 0x00],
    );
}

fn encode_key() -> String {
    umsh_uri::encode_public_key_base58(&PublicKey([0xA1; 32]))
}

/// The sequences a fuzzer cannot stumble on: a counter out of step, and the
/// exchange that repairs it. `tests/replay.rs` holds these to their purpose.
fn resync_seeds(seeds: &Seeds) {
    const FAR: u32 = 0x0100_0000;
    const PAYLOAD: [u8; 3] = [0x01, b'o', b'k'];
    let dst = NodeHint([0, 0, 0]);
    let channel = ChannelId([0, 0]);

    let unicast = |counter: u32, ack: bool| {
        let mut buf = [0u8; 255];
        let builder = PacketBuilder::new(&mut buf)
            .unicast(dst)
            .source_hint(dst)
            .frame_counter(counter)
            .encrypted();
        let builder = if ack {
            builder.ack_requested()
        } else {
            builder
        };
        let frame = builder.payload(&PAYLOAD).build().unwrap();
        frame.as_bytes().to_vec()
    };
    let blind = |counter: u32, ack: bool| {
        let mut buf = [0u8; 255];
        let builder = PacketBuilder::new(&mut buf)
            .blind_unicast(channel, dst)
            .source_hint(dst)
            .frame_counter(counter);
        let builder = if ack {
            builder.ack_requested()
        } else {
            builder
        };
        let frame = builder.payload(&PAYLOAD).build().unwrap();
        frame.as_bytes().to_vec()
    };
    let answer = |counter: u32| {
        let mut body = vec![0, 0];
        body.extend_from_slice(&counter.to_be_bytes());
        body
    };

    type Build<'a> = &'a dyn Fn(u32, bool) -> Vec<u8>;
    for (name, build) in [("unicast", &unicast as Build), ("blind", &blind as Build)] {
        // Asked for an ack: held while its sender vouches for it.
        let mut script = Vec::new();
        push_record(&mut script, mac::OP_CONFIG, &[0]);
        mac_rx(&mut script, 0, &build(1, false));
        mac_rx(&mut script, 0, &build(FAR, true));
        push_record(&mut script, mac::OP_ANSWER, &answer(FAR + 1));
        seeds.write("umsh_mac", &format!("resync-held-{name}"), &script);

        // Not asked for one: dropped behind an Echo Request.
        let mut script = Vec::new();
        push_record(&mut script, mac::OP_CONFIG, &[0]);
        mac_rx(&mut script, 0, &build(1, false));
        mac_rx(&mut script, 0, &build(FAR, false));
        push_record(&mut script, mac::OP_ANSWER, &answer(FAR + 1));
        mac_rx(&mut script, 0, &build(FAR + 2, false));
        seeds.write("umsh_mac", &format!("resync-echo-{name}"), &script);
    }

    // The other side of it: asked to vouch for a send of ours.
    for (name, kind) in [("unicast", 0u8), ("blind", 1)] {
        let mut script = Vec::new();
        push_record(&mut script, mac::OP_CONFIG, &[0]);
        let mut send = vec![kind, 0, 0x01, 3, 0];
        send.extend_from_slice(&PAYLOAD);
        push_record(&mut script, mac::OP_SEND, &send);
        push_record(&mut script, mac::OP_ACK, &[0, mac::ACK_VOUCH, 0, 0, 0, 7]);
        seeds.write("umsh_mac", &format!("vouch-{name}"), &script);
    }
}

/// Signed frames, which no real sender produces for a unicast.
fn signed_seeds(seeds: &Seeds) {
    let dst = NodeHint([0, 0, 0]);
    let src = PublicKey([0xA1; 32]);
    let channel = ChannelId([0, 0]);
    let hello = [0x01, b'h', b'i'];
    let mut frames: Vec<(&str, Vec<u8>)> = Vec::new();

    let mut buf = [0u8; 255];
    let frame = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(&src)
        .signed(7)
        .payload(&hello)
        .build()
        .unwrap();
    frames.push(("broadcast", frame.to_vec()));

    let mut buf = [0u8; 255];
    let frame = PacketBuilder::new(&mut buf)
        .multicast(channel)
        .source_full(&src)
        .frame_counter(7)
        .encrypted()
        .signed()
        .payload(&hello)
        .build()
        .unwrap();
    frames.push(("multicast", frame.as_bytes().to_vec()));

    let mut buf = [0u8; 255];
    let frame = PacketBuilder::new(&mut buf)
        .unicast(dst)
        .source_hint(dst)
        .frame_counter(7)
        .encrypted()
        .signed()
        .payload(&hello)
        .build()
        .unwrap();
    frames.push(("unicast", frame.as_bytes().to_vec()));

    let mut buf = [0u8; 255];
    let frame = PacketBuilder::new(&mut buf)
        .blind_unicast(channel, dst)
        .source_hint(dst)
        .frame_counter(7)
        .signed()
        .payload(&hello)
        .build()
        .unwrap();
    frames.push(("blind", frame.as_bytes().to_vec()));

    for (name, frame) in frames {
        let mut script = Vec::new();
        push_record(&mut script, mac::OP_CONFIG, &[0]);
        mac_rx(&mut script, 0, &frame);
        seeds.write("umsh_mac", &format!("signed-{name}"), &script);
        seeds.write(
            "umsh_mac_noninterference",
            &format!("signed-{name}"),
            &script,
        );
    }
}

/// A device in each starting state, each command in turn, and the radio
/// path behind the provisioning a host runs first.
fn device_targets(seeds: &Seeds) {
    use umsh_fuzz_harness::targets::ulcp_device as dev;

    let mut buf = [0u8; 300];
    let commands: Vec<(&str, Vec<u8>)> = vec![
        (
            "reset",
            frame::reset(&mut buf, 1)
                .map(|n| buf[..n].to_vec())
                .unwrap(),
        ),
        (
            "save",
            frame::save(&mut buf, 1).map(|n| buf[..n].to_vec()).unwrap(),
        ),
        (
            "restore",
            frame::restore(&mut buf, 1)
                .map(|n| buf[..n].to_vec())
                .unwrap(),
        ),
        (
            "clear",
            frame::clear(&mut buf, 1)
                .map(|n| buf[..n].to_vec())
                .unwrap(),
        ),
        (
            "drain",
            frame::queue_drain(&mut buf, 1)
                .map(|n| buf[..n].to_vec())
                .unwrap(),
        ),
        (
            "reboot",
            frame::reboot(&mut buf, 1)
                .map(|n| buf[..n].to_vec())
                .unwrap(),
        ),
        (
            "factory",
            frame::factory_reset(&mut buf, 1)
                .map(|n| buf[..n].to_vec())
                .unwrap(),
        ),
    ];
    for (name, command) in &commands {
        let mut script = Vec::new();
        push_record(&mut script, dev::OP_CONFIG, &[dev::CONFIG_PROVISIONED]);
        push_record(&mut script, dev::OP_FRAME, command);
        seeds.write("ulcp_device", &format!("command-{name}"), &script);
    }

    // Every property id a device could know, by the batch a request holds.
    let keys: Vec<u32> = (0..6000).collect();
    for (index, batch) in keys.chunks(64).enumerate().take(16) {
        let mut script = Vec::new();
        push_record(&mut script, dev::OP_CONFIG, &[dev::CONFIG_PROVISIONED]);
        let len = frame::prop_multi_get(&mut buf, 1, batch).unwrap();
        push_record(&mut script, dev::OP_FRAME, &buf[..len]);
        seeds.write("ulcp_device", &format!("properties-{index}"), &script);
    }

    // The radio path, attached and not, each frame type sealed for a peer.
    for (index, frame) in built_frames().iter().enumerate() {
        for detached in [false, true] {
            let mut script = Vec::new();
            push_record(&mut script, dev::OP_CONFIG, &[dev::CONFIG_PROVISIONED]);
            if detached {
                push_record(&mut script, dev::OP_DETACH, &[]);
            }
            let mut radio = vec![0, 60, 5, 0];
            radio.extend_from_slice(frame);
            push_record(&mut script, dev::OP_RADIO, &radio);
            push_record(&mut script, dev::OP_TX, &[0]);
            push_record(&mut script, dev::OP_ATTACH, &[]);
            let len = frame::queue_drain(&mut buf, 1).unwrap();
            push_record(&mut script, dev::OP_FRAME, &buf[..len]);
            seeds.write(
                "ulcp_device",
                &format!("radio-{index}-detached-{detached}"),
                &script,
            );
        }
    }

    // A transmission, every way it can end.
    for outcome in 0..3u8 {
        let mut script = Vec::new();
        push_record(&mut script, dev::OP_CONFIG, &[dev::CONFIG_PROVISIONED]);
        let len = frame::str_send(&mut buf, 1, 0, &[0xC0, 0, 0, 0], &[]).unwrap();
        push_record(&mut script, dev::OP_FRAME, &buf[..len]);
        push_record(&mut script, dev::OP_TX, &[outcome]);
        seeds.write("ulcp_device", &format!("transmit-{outcome}"), &script);
    }

    // What was saved, across a power cycle.
    let mut script = Vec::new();
    push_record(&mut script, dev::OP_CONFIG, &[dev::CONFIG_PROVISIONED]);
    let len = frame::save(&mut buf, 1).unwrap();
    push_record(&mut script, dev::OP_FRAME, &buf[..len]);
    let len = frame::reboot(&mut buf, 1).unwrap();
    push_record(&mut script, dev::OP_FRAME, &buf[..len]);
    push_record(&mut script, dev::OP_ATTACH, &[]);
    let len = frame::restore(&mut buf, 1).unwrap();
    push_record(&mut script, dev::OP_FRAME, &buf[..len]);
    seeds.write("ulcp_device", "save-reboot-restore", &script);

    // The two other ways in.
    let mut script = Vec::new();
    push_record(&mut script, dev::OP_CONFIG, &[dev::CONFIG_INTERFACE]);
    let len = frame::prop_get(&mut buf, 1, prop::DEV_NAME).unwrap();
    push_record(&mut script, dev::OP_DEVICE, &buf[..len]);
    let mut admin = vec![0, 200];
    let len = frame::prop_get(&mut buf, 0, prop::DEV_NAME).unwrap();
    admin.extend_from_slice(&buf[..len]);
    push_record(&mut script, dev::OP_ADMIN, &admin);
    seeds.write("ulcp_device", "interfaces", &script);
}

/// A request wrapped as an administrator wraps it, and the same conversation
/// over a link that loses and repeats things.
fn node_mgmt_targets(seeds: &Seeds) {
    use umsh_fuzz_harness::targets::{node_mgmt_device as device, node_mgmt_loop as looped};
    use umsh_node_mgmt::envelope::Envelope;
    use umsh_ulcp::i2c::{Op, encode_transfer};
    use umsh_ulcp_simdev::SimulatedI2c;

    let mut buf = [0u8; 300];
    let mut frames: Vec<(&str, Vec<u8>)> = Vec::new();
    let len = frame::prop_get(&mut buf, 0, prop::DEV_NAME).unwrap();
    frames.push(("get", buf[..len].to_vec()));
    let len = frame::prop_multi_get(&mut buf, 0, &[prop::DEV_NAME, prop::CAPS]).unwrap();
    frames.push(("multi-get", buf[..len].to_vec()));
    let len = frame::prop_set(&mut buf, 0, prop::DEV_NAME, b"renamed").unwrap();
    frames.push(("set", buf[..len].to_vec()));
    let len = encode_transfer(
        &mut buf,
        0,
        0,
        SimulatedI2c::ADDRESS,
        &[Op::Write(&[0x04, 0x5A])],
    )
    .unwrap();
    frames.push(("i2c-write", buf[..len].to_vec()));
    let len = frame::reboot(&mut buf, 0).unwrap();
    frames.push(("reboot", buf[..len].to_vec()));
    let len = frame::reset(&mut buf, 0).unwrap();
    frames.push(("reset", buf[..len].to_vec()));

    for (name, frame) in &frames {
        let mut envelope = [0u8; 256];
        let len = Envelope::new([0x12, 0x34], frame)
            .encode(&mut envelope)
            .unwrap();
        let mut body = vec![0, 0, 10];
        body.extend_from_slice(&envelope[..len]);
        let mut script = Vec::new();
        push_record(&mut script, device::OP_REQUEST, &body);
        push_record(&mut script, device::OP_REQUEST, &body);
        seeds.write("node_mgmt_device", name, &script);

        for (fates, label) in [
            (&[0u8][..], "clean"),
            (&[0x01, 0], "lost-request"),
            (&[0x02, 0], "lost-response"),
            (&[0x04], "repeated"),
            (&[0x08], "late"),
            (&[0x10], "undelivered"),
        ] {
            let mut body = vec![0x77, 0x77, fates.len() as u8];
            body.extend_from_slice(fates);
            body.extend_from_slice(frame);
            let mut script = Vec::new();
            push_record(&mut script, looped::OP_EXCHANGE, &body);
            seeds.write("node_mgmt_loop", &format!("{name}-{label}"), &script);
        }
    }
}

/// Two nodes in conversation, and each payload kind past the MIC.
fn closed_loops(seeds: &Seeds) {
    use umsh_fuzz_harness::targets::umsh_authenticated_payloads as payloads;

    for (name, fates) in [
        ("clean", &[0u8][..]),
        ("lossy", &[0, 1, 0, 0]),
        ("repeating", &[2, 0]),
        ("dead", &[1]),
    ] {
        for kind in 0..4u8 {
            for flags in [0x0001u16, 0x0000, 0x0021, 0x0005] {
                let mut script = Vec::new();
                push_record(&mut script, mac::LOOP_FATES, fates);
                let mut send = vec![kind];
                send.extend_from_slice(&flags.to_be_bytes());
                send.extend_from_slice(&[3, 0, 0x03, b'h', b'i']);
                push_record(&mut script, mac::LOOP_SEND, &send);
                push_record(&mut script, mac::LOOP_ADVANCE, &[0x20, 0]);
                push_record(&mut script, mac::LOOP_SEND, &send);
                seeds.write(
                    "umsh_mac_loop",
                    &format!("{name}-{kind}-{flags:04x}"),
                    &script,
                );
            }
        }
    }

    let dst = NodeHint([0, 0, 0]);
    let channel = ChannelId([0, 0]);
    let mut bodies: Vec<(String, Vec<u8>)> = Vec::new();
    for kind in [0u8, 1, 2, 3, 5, 7, 8, 9, 10] {
        bodies.push((format!("type-{kind}"), vec![kind, 0, 1, 2, 3]));
    }
    let mut text = vec![3];
    text.extend_from_slice(&encode_text(&TextMessage::basic("hello")));
    bodies.push(("text".into(), text));
    let mut sequenced_text = vec![3];
    sequenced_text.extend_from_slice(&sequenced(7, "hello"));
    bodies.push(("sequenced-text".into(), sequenced_text));
    bodies.push(("ping".into(), vec![2, 4, 1, 2, 3, 4]));
    bodies.push(("identity-request".into(), vec![2, 1, 0xFF]));
    bodies.push(("pfs".into(), vec![2, 8, 0xFF]));

    for (name, body) in &bodies {
        let mut buf = [0u8; 255];
        let unicast = PacketBuilder::new(&mut buf)
            .unicast(dst)
            .source_hint(dst)
            .frame_counter(7)
            .encrypted()
            .ack_requested()
            .payload(body)
            .build()
            .unwrap()
            .as_bytes()
            .to_vec();
        let mut buf = [0u8; 255];
        let multicast = PacketBuilder::new(&mut buf)
            .multicast(channel)
            .source_hint(dst)
            .frame_counter(8)
            .encrypted()
            .payload(body)
            .build()
            .unwrap()
            .as_bytes()
            .to_vec();
        let mut buf = [0u8; 255];
        let blind = PacketBuilder::new(&mut buf)
            .blind_unicast(channel, dst)
            .source_hint(dst)
            .frame_counter(9)
            .payload(body)
            .build()
            .unwrap()
            .as_bytes()
            .to_vec();
        let mut script = Vec::new();
        for frame in [&unicast, &multicast, &blind] {
            let mut rx = vec![0, 0, 50];
            rx.extend_from_slice(frame);
            push_record(&mut script, payloads::OP_RX, &rx);
        }
        push_record(&mut script, payloads::OP_ADVANCE, &[0x40, 0]);
        seeds.write("umsh_authenticated_payloads", name, &script);
    }
}

/// A real device, asked one frame at a time.
struct Answering {
    device: umsh_ulcp_simdev::SimulatedDevice,
}

impl Answering {
    fn new() -> Self {
        let mut device = umsh_ulcp_simdev::SimulatedDevice::new(device::config());
        device.attach();
        while device.take_outbound().is_some() {}
        Self { device }
    }

    fn ask(&mut self, request: &[u8]) -> Vec<Vec<u8>> {
        let mut wire = vec![0; hdlc::max_encoded_len(request.len())];
        let len = hdlc::encode_frame(request, &mut wire).unwrap();
        self.device.ingest(&wire[..len], 1).unwrap();
        let mut answers = Vec::new();
        while let Some(outbound) = self.device.take_outbound() {
            let mut decoder = hdlc::Decoder::<4096>::new();
            for byte in outbound {
                if let Some(Ok(frame)) = decoder.push(byte) {
                    answers.push(frame.to_vec());
                }
            }
        }
        answers
    }
}

/// Conversations each host held with a real device, so that a fuzzer starts
/// from answers a host believes rather than from noise.
fn host_targets(seeds: &Seeds) {
    use umsh_fuzz_harness::targets::{
        ulcp_admin_model as admin, ulcp_host_mobile as mobile, ulcp_host_web as web,
    };
    use umsh_mobile_core::MobileUlcpSession;
    use umsh_ulcp_admin::Model;
    use umsh_ulcp_web_engine::{DebuggerEngine, Transport};

    // The settings model filling its cache.
    let mut device = Answering::new();
    let mut model = Model::new();
    let mut port = admin::Port::default();
    let mut script = Vec::new();
    push_record(&mut script, admin::OP_REFRESH, &[]);
    model.refresh();
    model.pump(&mut port, 1_000);
    for _ in 0..8 {
        let requests = std::mem::take(&mut port.requests);
        if requests.is_empty() {
            break;
        }
        for request in &requests {
            for answer in device.ask(request) {
                if Frame::parse(&answer).is_ok_and(|frame| frame.header.tid() != 0) {
                    push_record(&mut script, admin::OP_ANSWER, &answer);
                    port.deliver(answer);
                }
            }
        }
        model.pump(&mut port, 2_000);
    }
    seeds.write("ulcp_admin_model", "refresh", &script);
    for (index, covered) in umsh_ulcp_admin::descriptor::COVERED
        .iter()
        .enumerate()
        .take(64)
    {
        let mut one = script.clone();
        let mut set = vec![index as u8];
        set.extend_from_slice(&[1; 4]);
        push_record(&mut one, admin::OP_SET, &set);
        let _ = covered;
        seeds.write("ulcp_admin_model", &format!("set-{index}"), &one);
    }

    // The web debugger's attach.
    let mut device = Answering::new();
    let mut engine = DebuggerEngine::new(Transport::SerialHdlc);
    let _ = engine.attach();
    let mut script = Vec::new();
    push_record(&mut script, 0, &[]);
    for _ in 0..8 {
        let mut any = false;
        while let Some(outbound) = engine.take_outbound() {
            any = true;
            let mut decoder = hdlc::Decoder::<4096>::new();
            let mut requests = Vec::new();
            for byte in outbound {
                if let Some(Ok(frame)) = decoder.push(byte) {
                    requests.push(frame.to_vec());
                }
            }
            for request in requests {
                for answer in device.ask(&request) {
                    let mut wire = vec![0; hdlc::max_encoded_len(answer.len())];
                    let len = hdlc::encode_frame(&answer, &mut wire).unwrap();
                    push_record(&mut script, web::OP_INGEST, &wire[..len]);
                    engine.ingest(&wire[..len]);
                }
            }
        }
        if !any {
            break;
        }
    }
    seeds.write("ulcp_host_web", "attach", &script);

    // The phone's session, from the first frame.
    let mut device = Answering::new();
    let session = MobileUlcpSession::new();
    let update = session.begin(None).unwrap();
    let mut script = Vec::new();
    let mut outbound = update.outbound_frames;
    for _ in 0..16 {
        let mut next = Vec::new();
        for request in &outbound {
            for answer in device.ask(request) {
                push_record(&mut script, mobile::OP_CONSUME, &answer);
                if let Ok(update) = session.consume(answer) {
                    next.extend(update.outbound_frames);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        outbound = next;
    }
    seeds.write("ulcp_host_mobile", "begin", &script);

    let mut with_calls = script.clone();
    for call in 0..8u8 {
        push_record(&mut with_calls, mobile::OP_CALL, &[call]);
        push_record(
            &mut with_calls,
            mobile::OP_ANSWER,
            &[0, 0x81, 0x06, 0x01, 0x00],
        );
    }
    seeds.write("ulcp_host_mobile", "calls", &with_calls);

    // What each screen reads, from a device's real values.
    let mut device = Answering::new();
    let mut body = Vec::new();
    let mut buf = [0u8; 16];
    for key in 0..6000u32 {
        let len = frame::prop_get(&mut buf, 1, key).unwrap();
        for answer in device.ask(&buf[..len]) {
            let Ok(parsed) = Frame::parse(&answer) else {
                continue;
            };
            let Ok((id, used)) = umsh_ulcp::pui::decode(parsed.payload) else {
                continue;
            };
            let value = &parsed.payload[used..];
            if id == key && value.len() < 256 && key < 0x1_0000 {
                body.extend_from_slice(&(key as u16).to_be_bytes());
                body.push(value.len() as u8);
                body.extend_from_slice(value);
            }
        }
    }
    let mut script = Vec::new();
    push_record(&mut script, mobile::OP_RECORDS, &body);
    seeds.write("ulcp_host_mobile", "records", &script);
}

/// An rx record: selector, time, signal, origin, frame.
fn mac_rx(script: &mut Vec<u8>, selector: u8, frame: &[u8]) {
    let mut body = vec![selector, 0, 50, 60, 5, 0];
    body.extend_from_slice(frame);
    push_record(script, mac::OP_RX, &body);
}

fn mac_targets(seeds: &Seeds) {
    let frames = built_frames();

    // Everything as it came: the repeater path, needing no keys.
    let mut raw = Vec::new();
    push_record(&mut raw, mac::OP_CONFIG, &[0]);
    for frame in &frames {
        mac_rx(&mut raw, 0, frame);
    }
    push_record(&mut raw, mac::OP_ADVANCE, &[0x10, 0]);
    seeds.write("umsh_mac_raw", "every-type", &raw);

    // Each frame type, sealed for a pinned peer and for a stranger.
    for (index, frame) in frames.iter().enumerate() {
        for selector in [0, 2] {
            let mut script = Vec::new();
            push_record(&mut script, mac::OP_CONFIG, &[0]);
            mac_rx(&mut script, selector, frame);
            let name = format!("frame-{index}-party-{selector}");
            seeds.write("umsh_mac", &name, &script);
            seeds.write("umsh_mac_noninterference", &name, &script);
        }
    }

    // Local sends of every kind, acknowledged and not, with time to retry.
    for kind in [0u8, 1, 2, 3, 4, 8] {
        let mut script = Vec::new();
        push_record(&mut script, mac::OP_CONFIG, &[0]);
        let mut send = vec![kind, 0, 0x01, 3, 0];
        send.extend_from_slice(&[0x01, b'h', b'i']);
        push_record(&mut script, mac::OP_SEND, &send);
        push_record(&mut script, mac::OP_ACK, &[0]);
        push_record(&mut script, mac::OP_SEND, &send);
        push_record(&mut script, mac::OP_ADVANCE, &[0x20, 0]);
        seeds.write("umsh_mac", &format!("send-{kind}"), &script);
    }

    resync_seeds(seeds);
    signed_seeds(seeds);

    // A small table and a stranger per party, for the eviction paths. The
    // raw frames go unstamped, so they must already name this node, and they
    // name a key that is a real point: only the MIC stands between them and
    // the table.
    let cast = fixup::cast();
    let local = cast.local_key.hint();
    let forged = *SoftwareIdentity::from_secret_bytes(&[0x77; 32]).public_key();
    let mut script = Vec::new();
    push_record(&mut script, mac::OP_CONFIG, &[0x20]);
    let mut buf = [0u8; 255];
    let full = PacketBuilder::new(&mut buf)
        .unicast(local)
        .source_full(&forged)
        .frame_counter(1)
        .encrypted()
        .payload(&[0x01, b'h', b'i'])
        .build()
        .unwrap()
        .as_bytes()
        .to_vec();
    for selector in [2, 0xFF, 3, 0xFF, 2, 3] {
        mac_rx(&mut script, selector, &full);
    }
    seeds.write("umsh_mac", "strangers", &script);
    seeds.write("umsh_mac_noninterference", "strangers", &script);

    // A stranger named inside a blind address, under a MIC that cannot verify.
    // The address's IV comes from the MIC, so it is the body that gets
    // spoiled: touching the MIC would garble the address too, and the frame
    // would never reach the question of who sent it.
    let mut buf = [0u8; 255];
    let blind = PacketBuilder::new(&mut buf)
        .blind_unicast(cast.channel.channel_id, local)
        .source_full(&forged)
        .frame_counter(1)
        .payload(&[0x01, b'h', b'i'])
        .build()
        .unwrap()
        .as_bytes()
        .to_vec();
    let mut spoiled = fixup::apply(&blind, 2);
    let body = PacketHeader::parse(&spoiled)
        .expect("a sealed frame")
        .body_range
        .start;
    spoiled[body] ^= 0x01;
    let mut script = Vec::new();
    push_record(&mut script, mac::OP_CONFIG, &[0x20]);
    mac_rx(&mut script, fixup::RAW, &spoiled);
    mac_rx(&mut script, 3, &blind);
    seeds.write("umsh_mac", "strangers-blind", &script);
    seeds.write("umsh_mac_noninterference", "strangers-blind", &script);
}

fn meshcore(seeds: &Seeds, repo: &Path) {
    let vectors =
        fs::read_to_string(repo.join("crates/umsh-meshcore-forwarder/vectors/vectors.json"))
            .expect("vectors");
    const KEY: &str = "\"frame\": \"";
    let mut script = vec![0, 0];
    let mut written = 0;
    for (index, part) in vectors.split(KEY).skip(1).enumerate() {
        let hex = &part[..part.find('"').expect("a closing quote")];
        let frame: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex"))
            .collect();
        let mut body = vec![0, 10, 40, 40];
        body.extend_from_slice(&frame);
        let mut seed = vec![0, 0];
        push_record(&mut seed, 0, &body);
        if index < 32 {
            seeds.write("meshcore_forwarder", &format!("vector-{index:02}"), &seed);
            written += 1;
        }
        if index < 8 {
            push_record(&mut script, 0, &body);
        }
    }
    assert!(written > 0, "the vectors' layout moved");
    seeds.write("meshcore_forwarder", "several", &script);
}

fn main() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest.join("../..");
    let seeds = Seeds {
        root: manifest.join("seeds"),
    };
    text(&seeds);
    ulcp(&seeds);
    umsh(&seeds, &repo);
    payloads(&seeds);
    mac_targets(&seeds);
    device_targets(&seeds);
    node_mgmt_targets(&seeds);
    closed_loops(&seeds);
    host_targets(&seeds);
    meshcore(&seeds, &repo);
}
