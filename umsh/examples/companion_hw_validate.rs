//! Increment-9 hardware validation for the full companion-radio
//! protocol: drives the same workflow the adapter-free integration
//! tests prove in-process (`umsh/tests/companion_full_protocol.rs`)
//! against a real board over USB serial, one phase per invocation so a
//! power cycle (or DFU-induced reboot) can happen between phases.
//!
//!   phase-a <port>            attach, sync, generate identity,
//!                             provision, configure+enable PHY, save;
//!                             prints DEV_KEY=<hex> for phase-b
//!   phase-b <port> <dev-key>  after a reboot: reconnect, verify boot
//!                             restore + ownership + identity, no-op
//!                             reconcile, drain, measure command RTT
//!   phase-c <port>            CMD_CLEAR; verify live state is retained
//!   phase-d <port>            after another reboot: verify factory
//!                             state, then re-provision + save so the
//!                             board is left ready for autonomous use
//!
//! Every frame in both directions is printed through the host trace
//! hook, so a failure is placed at the exact command that diverged.

use std::time::{Duration, Instant};

use umsh::companion::ids::{cap, prop};
use umsh::companion::items::{Filter, PeerKeyEntry};
use umsh::companion::meta::{BufferedRxMeta, RX_FLAG_ACKED};
use umsh::companion_radio::{
    CompanionRadio, CompanionRadioConfig, FrameLink, HostOwnership, HostProvisioning, NcpSync,
    SerialFrameLink,
};
use umsh::core::{MicSize, NodeHint, PacketBuilder, PacketHeader, PacketType, PublicKey};
use umsh::crypto::software::{SoftwareAes, SoftwareSha256};
use umsh::crypto::{CryptoEngine, PairwiseKeys};
use umsh::hal::{CadPolicy, Radio, TxOptions};

/// This host's identity for the validation run (a fixed test vector,
/// like the integration tests').
const HOST_KEY: [u8; 32] = [0xC4; 32];
const PEER_PUB: [u8; 32] = [0x0A; 32];
const CHANNEL_KEY: [u8; 32] = [0x42; 32];
/// Deterministic secret for the rf-dev-unicast peer *node* identity
/// (a real Ed25519 keypair, unlike the raw-key host fixtures above:
/// the device node derives the pairwise keys via X25519, so the peer
/// must own a valid signing key).
const PEER_NODE_SECRET: [u8; 32] = [0x5E; 32];

fn config() -> CompanionRadioConfig {
    // MeshCore US on-air profile: 910.525 MHz / SF7 / BW 62.5 kHz / CR 4/5,
    // private sync word 0x1424. Matches the firmware's post-reset default
    // profile and the rest of the device fleet, so the validation traffic
    // shares the same channel everything else is already tuned to.
    let mut config = CompanionRadioConfig::new(910_525, 62_500, 7, 5);
    // Point-blank bench geometry: full power saturates the listening
    // radio's front end (~50% frame loss observed at 14 dBm, RSSI
    // −8 dBm); −9 dBm lands at a healthy −35 dBm.
    config.tx_power_dbm = -9;
    config.response_timeout = Duration::from_secs(2);
    config
}

fn desired_provisioning() -> HostProvisioning {
    HostProvisioning {
        host_key: HOST_KEY,
        filters: vec![Filter::PktType(1)],
        channel_keys: vec![CHANNEL_KEY],
        peer_keys: vec![PeerKeyEntry {
            public_key: PEER_PUB,
            k_enc: [0xE0; 16],
            k_mic: [0x50; 16],
        }],
        auto_ack: true,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_key32(text: &str) -> Result<[u8; 32], String> {
    text.parse::<PublicKey>()
        .map(|key| key.0)
        .map_err(|error| format!("expected 44-char base58 or 64-char hex key: {error}"))
}

async fn open(
    port: &str,
) -> Result<CompanionRadio<SerialFrameLink<tokio_serial::SerialStream>>, Box<dyn std::error::Error>>
{
    use tokio_serial::SerialPortBuilderExt;
    let stream = tokio_serial::new(port, 115_200).open_native_async()?;
    let started = Instant::now();
    let mut radio = CompanionRadio::attach_existing(SerialFrameLink::new(stream), config()).await?;
    println!(
        "attached in {:?}: ncp={} boot_status={:?}",
        started.elapsed(),
        radio.ncp_version(),
        radio.boot_status()
    );
    radio.set_frame_trace(Some(Box::new(|direction, line| {
        println!("  {direction} {line}");
    })));
    Ok(radio)
}

fn print_sync(sync: &NcpSync) {
    println!("sync:");
    println!(
        "  last_status={:?} reset_since_last_contact={}",
        sync.last_status, sync.reset_since_last_contact
    );
    println!("  capabilities={:?}", sync.capabilities);
    println!("  ownership={:?}", sync.ownership);
    println!(
        "  phy_enabled={} freq_khz={}",
        sync.phy_enabled, sync.freq_khz
    );
    println!("  device_name={:?}", sync.device_name);
    println!(
        "  saved={:?} queue_count={:?} queue_dropped={:?}",
        sync.saved, sync.queue_count, sync.queue_dropped
    );
    println!("  filters={:?}", sync.filters);
    println!(
        "  host_channel_ids={:?}",
        sync.host_channel_ids
            .as_ref()
            .map(|ids| ids.iter().map(|id| hex(id)).collect::<Vec<_>>())
    );
    println!(
        "  host_peer_keys={:?}",
        sync.host_peer_keys.as_ref().map(|keys| keys
            .iter()
            .map(|key| PublicKey(*key).to_string())
            .collect::<Vec<_>>())
    );
    println!("  auto_ack={:?}", sync.auto_ack);
    println!(
        "  dev_key={:?}",
        sync.dev_key.map(|key| PublicKey(key).to_string())
    );
}

fn expect(condition: bool, what: &str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        println!("PASS {what}");
        Ok(())
    } else {
        Err(format!("FAIL {what}").into())
    }
}

async fn configure_phy<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config();
    radio
        .set_prop(prop::PHY_FREQ, &config.freq_khz.to_le_bytes())
        .await?;
    radio
        .set_prop(prop::PHY_LORA_BW, &config.bandwidth_hz.to_le_bytes())
        .await?;
    radio
        .set_prop(prop::PHY_LORA_SF, &[config.spreading_factor])
        .await?;
    radio
        .set_prop(prop::PHY_LORA_CR, &[config.coding_rate_denom])
        .await?;
    radio
        .set_prop(prop::PHY_TX_POWER, &[config.tx_power_dbm as u8])
        .await?;
    radio.set_prop(prop::PHY_ENABLED, &[1]).await?;
    Ok(())
}

async fn phase_a(port: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    let sync = radio.sync(Some(&HOST_KEY)).await?;
    print_sync(&sync);
    for capability in [
        cap::HOST_FILTER,
        cap::HOST_RX_QUEUE,
        cap::HOST_KEYS,
        cap::HOST_AUTO_ACK,
        cap::SAVE,
        cap::DEV_IDENTITY,
    ] {
        expect(
            sync.has_capability(capability),
            &format!("capability {capability} advertised"),
        )?;
    }
    let capacity = radio.get_prop(prop::HOST_RX_QUEUE_CAPACITY).await?;
    println!(
        "queue capacity = {:?}",
        u16::from_le_bytes(capacity.as_slice().try_into()?)
    );

    let dev_key = radio.ensure_device_identity().await?;
    let again = radio.ensure_device_identity().await?;
    expect(
        dev_key == again,
        "device identity is stable across ensure calls",
    )?;

    let report = radio.provision(&desired_provisioning()).await?;
    println!("provision report: {report:?}");
    configure_phy(&mut radio).await?;
    radio.save().await?;

    let sync = radio.sync(Some(&HOST_KEY)).await?;
    print_sync(&sync);
    expect(sync.ownership == HostOwnership::Ours, "ownership is ours")?;
    expect(sync.saved == Some(true), "snapshot saved")?;
    expect(sync.phy_enabled, "PHY enabled")?;
    expect(sync.dev_key == Some(dev_key), "device key reported")?;
    println!("DEV_KEY={}", PublicKey(dev_key));
    println!("PHASE A OK — power-cycle (or DFU-reboot) the board, then run phase-b");
    Ok(())
}

async fn phase_b(port: &str, expected_dev_key: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    let sync = radio.sync(Some(&HOST_KEY)).await?;
    print_sync(&sync);
    expect(
        sync.reset_since_last_contact,
        "reset detected after power cycle",
    )?;
    expect(
        sync.ownership == HostOwnership::Ours,
        "ownership survives the power cycle",
    )?;
    expect(sync.saved == Some(true), "snapshot still saved")?;
    expect(sync.phy_enabled, "boot restore re-enabled the PHY")?;
    expect(
        sync.freq_khz == config().freq_khz,
        "boot restore applied the saved frequency",
    )?;
    expect(
        sync.auto_ack == Some(true),
        "auto-ack armed from the snapshot",
    )?;
    expect(
        sync.dev_key == Some(expected_dev_key),
        "device identity survives the power cycle",
    )?;

    let report = radio.provision(&desired_provisioning()).await?;
    println!("reconcile report: {report:?}");
    expect(!report.changed(), "reattach reconcile is a no-op")?;

    let mut drained = 0usize;
    radio.queue_drain_with(|_data, _meta| drained += 1).await?;
    println!("drained {drained} buffered frames");

    // Command round-trip latency over USB-CDC (GET PROP_LAST_STATUS).
    radio.set_frame_trace(None);
    let mut samples = Vec::new();
    for _ in 0..50 {
        let started = Instant::now();
        radio.get_prop(prop::LAST_STATUS).await?;
        samples.push(started.elapsed());
    }
    samples.sort();
    println!(
        "command RTT over 50 samples: min={:?} median={:?} max={:?}",
        samples[0],
        samples[samples.len() / 2],
        samples[samples.len() - 1]
    );
    println!("PHASE B OK");
    Ok(())
}

async fn phase_c(port: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    radio.clear().await?;
    let sync = radio.sync(Some(&HOST_KEY)).await?;
    print_sync(&sync);
    expect(sync.saved == Some(false), "snapshot erased")?;
    expect(
        sync.dev_key.is_some(),
        "live identity retained after CMD_CLEAR",
    )?;
    expect(
        sync.ownership == HostOwnership::Ours,
        "live host domain retained after CMD_CLEAR",
    )?;
    println!("PHASE C OK — power-cycle (or DFU-reboot) the board, then run phase-d");
    Ok(())
}

async fn phase_d(port: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    let sync = radio.sync(Some(&HOST_KEY)).await?;
    print_sync(&sync);
    expect(
        sync.ownership == HostOwnership::Unclaimed,
        "factory: no host identity",
    )?;
    expect(sync.saved == Some(false), "factory: nothing saved")?;
    expect(sync.dev_key.is_none(), "factory: device identity erased")?;
    expect(!sync.phy_enabled, "factory: PHY disabled")?;

    // Leave the board provisioned and armed for autonomous operation.
    let dev_key = radio.ensure_device_identity().await?;
    radio.provision(&desired_provisioning()).await?;
    configure_phy(&mut radio).await?;
    radio.save().await?;
    println!("re-provisioned; DEV_KEY={}", PublicKey(dev_key));
    println!("PHASE D OK — full-protocol hardware validation complete on this board");
    Ok(())
}

fn pairwise() -> PairwiseKeys {
    PairwiseKeys {
        k_enc: [0xE0; 16],
        k_mic: [0x50; 16],
    }
}

/// A sealed unicast frame from the provisioned peer to the host, as
/// the T-1000E expects it over the air.
fn sealed_unicast(counter: u32, ack: bool, keys: &PairwiseKeys, dst: [u8; 3]) -> Vec<u8> {
    let mut buf = [0u8; 96];
    let mut builder = PacketBuilder::new(&mut buf)
        .unicast(NodeHint(dst))
        .source_hint(NodeHint([PEER_PUB[0], PEER_PUB[1], PEER_PUB[2]]))
        .frame_counter(counter);
    if ack {
        builder = builder.ack_requested();
    }
    let mut packet = builder
        .mic_size(MicSize::Mic8)
        .payload(&[3, 1, 2])
        .build()
        .unwrap();
    CryptoEngine::new(SoftwareAes, SoftwareSha256)
        .seal_packet(&mut packet, keys)
        .unwrap();
    packet.as_bytes().to_vec()
}

/// Receive one radio frame within `timeout`.
async fn recv_frame<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
    timeout: Duration,
) -> Option<(Vec<u8>, i16)> {
    let mut buf = [0u8; 512];
    let result = tokio::time::timeout(
        timeout,
        core::future::poll_fn(|cx| Radio::poll_receive(radio, cx, &mut buf)),
    )
    .await;
    match result {
        Ok(Ok(info)) => Some((buf[..info.len].to_vec(), info.rssi)),
        _ => None,
    }
}

/// Wait for a MAC acknowledgement on the air, skipping unrelated
/// receptions.
async fn expect_air_ack<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
    what: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(4);
    while let Some(remaining) = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
    {
        let Some((frame, rssi)) = recv_frame(radio, remaining).await else {
            break;
        };
        let Ok(header) = PacketHeader::parse(&frame) else {
            continue;
        };
        if header.fcf.packet_type() == PacketType::MacAck {
            println!("  ack on air ({} bytes, rssi {rssi} dBm)", frame.len());
            return expect(true, what);
        }
    }
    expect(false, what)
}

async fn transmit<L: FrameLink>(
    radio: &mut CompanionRadio<L>,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    Radio::transmit(
        radio,
        data,
        TxOptions {
            cad: CadPolicy::Skip,
        },
    )
    .await
    .map_err(|error| format!("transmit failed: {error:?}").into())
}

/// Non-asserting unicast blast: transmit `count` sealed, ack-requesting
/// unicasts to the provisioned host (counters base..base+count, spaced
/// so the DUT has time to receive+queue each), without waiting for or
/// asserting on the delegated ack. Decouples "does the DUT queue matched
/// unicasts" from "does the ack round-trip land" — check the DUT queue
/// afterward with `phase-e` or `info`.
async fn rf_blast(
    port: &str,
    base: u32,
    count: u32,
    power_dbm: Option<i8>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio_serial::SerialPortBuilderExt;
    let stream = tokio_serial::new(port, 115_200).open_native_async()?;
    let mut radio = CompanionRadio::new(SerialFrameLink::new(stream), config()).await?;
    println!("peer ncp={} base={base} count={count}", radio.ncp_version());
    if let Some(power) = power_dbm {
        radio.set_prop(prop::PHY_TX_POWER, &[power as u8]).await?;
        println!("peer tx power {power} dBm");
    }
    radio.set_prop(prop::MAC_PROMISCUOUS, &[1]).await?;
    for offset in 0..count {
        let counter = base + offset;
        let frame = sealed_unicast(counter, true, &pairwise(), [0xC4, 0xC4, 0xC4]);
        transmit(&mut radio, &frame).await?;
        println!("  unicast counter={counter} ({} bytes) on the air", frame.len());
        // Report everything the peer hears in the inter-frame window —
        // the DUT's delegated ack lands ~120 ms after each unicast, so
        // silence here while an air capture shows the ack is proof of a
        // post-TX receive gap on this peer's radio.
        let window = Instant::now() + Duration::from_millis(1500);
        while let Some(remaining) = window
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        {
            let Some((heard, rssi)) = recv_frame(&mut radio, remaining).await else {
                break;
            };
            let kind = PacketHeader::parse(&heard)
                .map(|header| format!("{:?}", header.fcf.packet_type()))
                .unwrap_or_else(|_| "unparseable".into());
            println!("    peer heard {kind} {} bytes rssi={rssi}", heard.len());
        }
    }
    println!("RF BLAST OK — check the DUT queue (expect count={count} if matching works)");
    Ok(())
}

/// Drive the T-Echo as the RF peer while the T-1000E sits detached:
/// delegated ack on the air, duplicate re-ack, unrelated-traffic
/// rejection, then queue overflow with one late acknowledged frame.
/// Follow with `phase-e <t1000e-port> 16 3 1`.
async fn rf_peer(
    port: &str,
    base: u32,
    power_dbm: Option<i8>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio_serial::SerialPortBuilderExt;
    let stream = tokio_serial::new(port, 115_200).open_native_async()?;
    // The peer radio is disposable: the resetting attach configures its
    // PHY to the same parameters the T-1000E saved.
    let mut radio = CompanionRadio::new(SerialFrameLink::new(stream), config()).await?;
    println!("peer ncp={} base counter={base}", radio.ncp_version());
    if let Some(power) = power_dbm {
        // Bench-geometry escape hatch: at point-blank range full power
        // saturates the DUT's front end and randomly costs frames the
        // final queue arithmetic depends on.
        radio.set_prop(prop::PHY_TX_POWER, &[power as u8]).await?;
        println!("peer tx power {power} dBm");
    }
    // The peer NCP's CMD_RST restored whatever host provisioning its
    // snapshot holds (on a daily-driver board: real filters that drop
    // the DUT's fixture-addressed acks before they reach this host).
    // Promiscuous live delivery bypasses that filtering.
    radio.set_prop(prop::MAC_PROMISCUOUS, &[1]).await?;
    // Warm-up transmit: the LR1110's first post-TX return to RX after a
    // reconfiguration is slow enough to swallow a delegated ack that
    // arrives ~120 ms later (every later turnaround is fine). Burn the
    // slow first re-arm on a broadcast that draws no reply.
    let mut warmup = [0u8; 16];
    let warmup_frame = PacketBuilder::new(&mut warmup)
        .broadcast()
        .source_hint(NodeHint([0xAB, 0xCD, 0xEF]))
        .payload(&[0xFE])
        .build()
        .expect("warm-up frame builds");
    let warmup_frame = warmup_frame.to_vec();
    transmit(&mut radio, &warmup_frame).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    println!("peer warmed up (post-TX RX re-arm exercised)");

    // 1. A relevant, acknowledgement-requesting frame: the detached
    //    T-1000E must queue it and ack on the host's behalf.
    let relevant = sealed_unicast(base, true, &pairwise(), [0xC4, 0xC4, 0xC4]);
    transmit(&mut radio, &relevant).await?;
    expect_air_ack(&mut radio, "delegated ack transmitted on the air").await?;

    // 2. The exact retransmission coalesces and is re-acked.
    transmit(&mut radio, &relevant).await?;
    expect_air_ack(&mut radio, "duplicate re-acked, not re-queued").await?;

    // 3. Unrelated traffic (wrong destination, unknown keys) draws no
    //    ack — and, per the final queue arithmetic, is never queued.
    let unrelated = sealed_unicast(
        base,
        true,
        &PairwiseKeys {
            k_enc: [0x11; 16],
            k_mic: [0x22; 16],
        },
        [0x99, 0x99, 0x99],
    );
    transmit(&mut radio, &unrelated).await?;
    // Promiscuous listening sees ambient traffic (fleet frames, the
    // DUT's own beacons); only a MAC ack would prove the unrelated
    // frame was wrongly accepted.
    let unrelated_deadline = Instant::now() + Duration::from_secs(2);
    let mut stray_ack = false;
    while let Some(remaining) = unrelated_deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
    {
        let Some((frame, _)) = recv_frame(&mut radio, remaining).await else {
            break;
        };
        if let Ok(header) = PacketHeader::parse(&frame)
            && header.fcf.packet_type() == PacketType::MacAck
        {
            stray_ack = true;
            break;
        }
    }
    expect(!stray_ack, "unrelated traffic not acknowledged")?;

    // 4. Overflow: 18 more frames (counters base+1..=base+18). With
    //    the earlier frame that is 19 accepted into a 16-slot queue —
    //    three evictions. Only the last frame requests (and earns) an
    //    ack, so exactly one drained frame carries RX_FLAG_ACKED.
    for offset in 1..=18u32 {
        let ack = offset == 18;
        let frame = sealed_unicast(base + offset, ack, &pairwise(), [0xC4, 0xC4, 0xC4]);
        transmit(&mut radio, &frame).await?;
        if ack {
            expect_air_ack(&mut radio, "late acknowledged frame acked on the air").await?;
        }
    }
    println!("RF PEER OK — run phase-e against the T-1000E: expected count=16 dropped=3 acked=1");
    Ok(())
}

/// Drive the T-Echo as an RF peer transmitting sealed multicast on a
/// device channel (device-node plan increment 3 acceptance). Watch the
/// T-1000E's debug console for `node rx: Multicast` lines; afterwards
/// verify the host queue ignored the frames (`info` queue_count).
async fn rf_dev_multicast(
    port: &str,
    channel_key: [u8; 32],
    base: u32,
    count: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio_serial::SerialPortBuilderExt;
    let stream = tokio_serial::new(port, 115_200).open_native_async()?;
    // The peer radio is disposable: the resetting attach configures its
    // PHY to the fixture parameters the T-1000E saved.
    let mut radio = CompanionRadio::new(SerialFrameLink::new(stream), config()).await?;
    println!(
        "peer ncp={} base counter={base} count={count}",
        radio.ncp_version()
    );

    let crypto = CryptoEngine::new(SoftwareAes, SoftwareSha256);
    let derived = crypto.derive_channel_keys(&umsh::core::ChannelKey(channel_key));
    let keys = PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    };
    println!("channel id {}", hex(&derived.channel_id.0));

    for offset in 0..count {
        let mut buf = [0u8; 96];
        let mut packet = PacketBuilder::new(&mut buf)
            .multicast(derived.channel_id)
            .source_hint(NodeHint([PEER_PUB[0], PEER_PUB[1], PEER_PUB[2]]))
            .frame_counter(base + offset)
            .mic_size(MicSize::Mic8)
            .payload(&[3, 1, 2])
            .build()
            .unwrap();
        crypto.seal_packet(&mut packet, &keys).unwrap();
        transmit(&mut radio, packet.as_bytes()).await?;
        println!("  multicast counter={} on the air", base + offset);
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    println!(
        "RF DEV MULTICAST OK — check the T-1000E console for `node rx: Multicast ch={}`",
        hex(&derived.channel_id.0)
    );
    Ok(())
}

/// Drive the T-Echo as an RF peer sending pairwise-sealed,
/// ack-requesting unicast to the *device identity* (device-node plan
/// increment 4 acceptance). The peer node identity is deterministic —
/// register its printed public key once with
/// `umsh-companionctl <port> dev-peer add <pk>` — and the pairwise
/// keys come from the real X25519 derivation, so the device's MAC
/// authenticates, acks through the shared duty ledger, and schedules
/// an RX counter-boundary persist when the counter jump crosses a
/// 128-frame block.
///
/// `expect` is `ack` (frames are fresh: every one must draw a MAC ack
/// on the air) or `silence` (frames sit at or below the persisted
/// replay boundary: none may be acknowledged) — the latter is the
/// power-cycle replay probe.
async fn rf_dev_unicast(
    port: &str,
    dev_key: [u8; 32],
    base: u32,
    count: u32,
    expect_ack: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio_serial::SerialPortBuilderExt;
    use umsh::crypto::NodeIdentity as _;
    let stream = tokio_serial::new(port, 115_200).open_native_async()?;
    let mut radio = CompanionRadio::new(SerialFrameLink::new(stream), config()).await?;
    println!(
        "peer ncp={} base counter={base} count={count}",
        radio.ncp_version()
    );

    let peer = umsh::crypto::software::SoftwareIdentity::from_secret_bytes(&PEER_NODE_SECRET);
    let peer_pub = *peer.public_key();
    println!("peer node pk {peer_pub} (must be in dev-peer list)");
    let shared = peer
        .shared_secret_with(&PublicKey(dev_key))
        .map_err(|error| format!("pairwise derivation failed: {error:?}"))?;
    let crypto = CryptoEngine::new(SoftwareAes, SoftwareSha256);
    let keys = crypto.derive_pairwise_keys(&shared);

    for offset in 0..count {
        let counter = base + offset;
        let mut buf = [0u8; 96];
        let mut packet = PacketBuilder::new(&mut buf)
            .unicast(PublicKey(dev_key).hint())
            .source_hint(peer_pub.hint())
            .frame_counter(counter)
            .ack_requested()
            .mic_size(MicSize::Mic8)
            .payload(&[4, 2])
            .build()
            .unwrap();
        crypto.seal_packet(&mut packet, &keys).unwrap();
        transmit(&mut radio, packet.as_bytes()).await?;
        println!("  unicast counter={counter} on the air");
        if expect_ack {
            expect_air_ack(&mut radio, &format!("device node acked counter={counter}")).await?;
        } else {
            let stray = recv_frame(&mut radio, Duration::from_secs(3)).await;
            expect(
                stray.is_none(),
                &format!("counter={counter} at/below the persisted boundary drew no ack"),
            )?;
        }
    }
    println!("RF DEV UNICAST OK — check the T-1000E console for `node rx: Unicast` lines");
    Ok(())
}

/// Drive the T-Echo as an RF peer soliciting an advertisement from the
/// device identity (device-node plan increment 5): send an
/// Advertisement Request MAC command as pairwise-sealed unicast, then
/// expect a broadcast advertisement — a NodeIdentity payload carrying
/// the echoed nonce, the device name, and the standalone signature.
async fn rf_advert_request(
    port: &str,
    dev_key: [u8; 32],
    counter: u32,
    nonce: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio_serial::SerialPortBuilderExt;
    use umsh::crypto::NodeIdentity as _;
    let stream = tokio_serial::new(port, 115_200).open_native_async()?;
    let mut radio = CompanionRadio::new(SerialFrameLink::new(stream), config()).await?;
    println!(
        "peer ncp={} counter={counter} nonce={nonce:?}",
        radio.ncp_version()
    );

    let peer = umsh::crypto::software::SoftwareIdentity::from_secret_bytes(&PEER_NODE_SECRET);
    let peer_pub = *peer.public_key();
    println!("peer node pk {peer_pub} (must be in dev-peer list)");
    let shared = peer
        .shared_secret_with(&PublicKey(dev_key))
        .map_err(|error| format!("pairwise derivation failed: {error:?}"))?;
    let crypto = CryptoEngine::new(SoftwareAes, SoftwareSha256);
    let keys = crypto.derive_pairwise_keys(&shared);

    // Typed MAC-command payload: Advertisement Request (id 0).
    let mut command = [0u8; 8];
    command[0] = umsh::core::PayloadType::MacCommand as u8;
    let command_len = 1 + umsh::node::mac_command::encode(
        &umsh::node::MacCommand::AdvertisementRequest { nonce },
        &mut command[1..],
    )
    .map_err(|error| format!("command encode failed: {error:?}"))?;

    let mut buf = [0u8; 96];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(PublicKey(dev_key).hint())
        .source_hint(peer_pub.hint())
        .frame_counter(counter)
        .mic_size(MicSize::Mic8)
        .payload(&command[..command_len])
        .build()
        .unwrap();
    crypto.seal_packet(&mut packet, &keys).unwrap();
    transmit(&mut radio, packet.as_bytes()).await?;
    println!("  advertisement request on the air");

    // The advertisement: a broadcast whose payload parses as a
    // NodeIdentity payload. Skip unrelated receptions (e.g. our own
    // request's processing artifacts) within the window.
    let deadline = Instant::now() + Duration::from_secs(5);
    while let Some(remaining) = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
    {
        let Some((frame, rssi)) = recv_frame(&mut radio, remaining).await else {
            break;
        };
        let Ok(header) = PacketHeader::parse(&frame) else {
            continue;
        };
        if header.fcf.packet_type() != PacketType::Broadcast {
            continue;
        }
        let Some(payload) = frame.get(header.body_range.clone()) else {
            continue;
        };
        let Ok((payload_type, body)) = umsh::node::split_payload_type(payload) else {
            continue;
        };
        if payload_type != umsh::core::PayloadType::NodeIdentity {
            continue;
        }
        let advert = umsh::node::NodeIdentityPayload::from_bytes(body)
            .map_err(|error| format!("advertisement failed to parse: {error:?}"))?;
        println!(
            "  advertisement ({} bytes, rssi {rssi} dBm): role={:?} name={:?} nonce={:?} signed={}",
            frame.len(),
            advert.role,
            advert.name,
            advert.nonce,
            advert.signature.is_some(),
        );
        expect(advert.nonce == nonce, "nonce echoed verbatim")?;
        expect(advert.signature.is_some(), "advertisement is signed")?;
        expect(advert.name.is_some(), "advertisement carries the name")?;
        println!("RF ADVERT REQUEST OK");
        return Ok(());
    }
    expect(false, "advertisement received")
}

/// Hold a non-resetting attached session open for `seconds`: the
/// attached-operation backdrop for node-behavior checks (the device
/// node must keep responding while a host session is live) and the
/// displacement fixture (a second transport's attach must displace
/// this one without disturbing the node).
async fn hold(port: &str, seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    radio.set_frame_trace(None);
    println!("holding attached session for {seconds}s");
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    match radio.get_prop(prop::PHY_ENABLED).await {
        Ok(_) => println!("HOLD DONE (still attached)"),
        Err(error) => println!("HOLD DONE (displaced: {error:?})"),
    }
    Ok(())
}

/// Reattach the T-1000E after the RF pass and verify what autonomous
/// operation left behind.
async fn phase_e(
    port: &str,
    expected_count: u16,
    expected_dropped: u32,
    expected_acked: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    radio.set_frame_trace(None);
    let sync = radio.sync(Some(&HOST_KEY)).await?;
    print_sync(&sync);
    expect(sync.ownership == HostOwnership::Ours, "ownership intact")?;
    expect(
        sync.queue_count == Some(expected_count),
        &format!(
            "queue holds {expected_count} frames (got {:?})",
            sync.queue_count
        ),
    )?;
    expect(
        sync.queue_dropped == Some(expected_dropped),
        &format!(
            "{expected_dropped} evictions counted (got {:?})",
            sync.queue_dropped
        ),
    )?;

    let mut drained: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    radio
        .queue_drain_with(|data, meta| drained.push((data.to_vec(), meta.to_vec())))
        .await?;
    let mut acked = 0usize;
    for (data, meta) in &drained {
        let meta =
            BufferedRxMeta::decode(meta).map_err(|_| "drained frame without buffered metadata")?;
        let header = PacketHeader::parse(data).map_err(|error| format!("{error:?}"))?;
        println!(
            "  drained {:?} {} bytes flags={:#04x} age={}s rssi={:?}",
            header.fcf.packet_type(),
            data.len(),
            meta.flags,
            meta.age_s,
            meta.rx.rssi_dbm,
        );
        if meta.flags & RX_FLAG_ACKED != 0 {
            acked += 1;
        }
    }
    expect(
        drained.len() == usize::from(expected_count),
        "drain delivered every queued frame",
    )?;
    expect(
        acked == expected_acked,
        &format!("exactly {expected_acked} drained frame(s) marked acknowledged (got {acked})"),
    )?;
    let sync = radio.sync(Some(&HOST_KEY)).await?;
    expect(sync.queue_count == Some(0), "queue empty after drain")?;
    println!("PHASE E OK");
    Ok(())
}

/// The full-protocol attach over BLE: connect to the bonded companion
/// service, attach without resetting, and synchronize — the same
/// workflow the USB phases prove, over the other transport binding.
#[cfg(feature = "ble-radio")]
async fn ble_sync(selector: &str) -> Result<(), Box<dyn std::error::Error>> {
    use umsh::companion_radio::{BleFrameLink, BleFrameLinkConfig};
    let link = BleFrameLink::connect(Some(selector), BleFrameLinkConfig::default()).await?;
    let started = Instant::now();
    let mut radio = CompanionRadio::attach_existing(link, config()).await?;
    println!(
        "BLE attached in {:?}: ncp={} boot_status={:?}",
        started.elapsed(),
        radio.ncp_version(),
        radio.boot_status()
    );
    let sync = radio.sync(Some(&HOST_KEY)).await?;
    print_sync(&sync);
    expect(
        sync.ownership == HostOwnership::Ours,
        "ownership verified over BLE",
    )?;
    expect(
        sync.saved == Some(true),
        "saved provisioning visible over BLE",
    )?;
    expect(sync.dev_key.is_some(), "device identity visible over BLE")?;

    let mut samples = Vec::new();
    for _ in 0..20 {
        let started = Instant::now();
        radio.get_prop(prop::LAST_STATUS).await?;
        samples.push(started.elapsed());
    }
    samples.sort();
    println!(
        "BLE command RTT over 20 samples: min={:?} median={:?} max={:?}",
        samples[0],
        samples[samples.len() / 2],
        samples[samples.len() - 1]
    );
    println!("BLE SYNC OK");
    Ok(())
}

/// Neutral queue drain: attach without resetting, drain whatever is
/// queued, and print each frame. No assertions — bench cleanup between
/// runs.
async fn drain(port: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    radio.set_frame_trace(None);
    let mut count = 0usize;
    radio
        .queue_drain_with(|data, meta| {
            let kind = PacketHeader::parse(data)
                .map(|header| format!("{:?}", header.fcf.packet_type()))
                .unwrap_or_else(|_| "unparseable".into());
            let flags = BufferedRxMeta::decode(meta)
                .map(|meta| meta.flags)
                .unwrap_or(0);
            println!("  drained {kind} {} bytes flags={flags:#04x}", data.len());
            count += 1;
        })
        .await?;
    println!("drained {count} frames");
    Ok(())
}

/// Neutral inspection: attach without resetting and print everything
/// `sync` can see — capabilities, ownership (against an optional
/// expected key), PHY state, and the digest forms of all tables. Makes
/// no assertions and changes nothing on the device.
async fn info_serial(
    port: &str,
    expected: Option<[u8; 32]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    radio.set_frame_trace(None);
    let sync = radio.sync(expected.as_ref()).await?;
    print_sync(&sync);
    print_battery(&mut radio).await;
    Ok(())
}

/// As [`info_serial`], over BLE.
#[cfg(feature = "ble-radio")]
async fn info_ble(
    selector: &str,
    expected: Option<[u8; 32]>,
) -> Result<(), Box<dyn std::error::Error>> {
    use umsh::companion_radio::{BleFrameLink, BleFrameLinkConfig};
    let link = BleFrameLink::connect(Some(selector), BleFrameLinkConfig::default()).await?;
    let mut radio = CompanionRadio::attach_existing(link, config()).await?;
    println!(
        "attached: ncp={} boot_status={:?}",
        radio.ncp_version(),
        radio.boot_status()
    );
    let sync = radio.sync(expected.as_ref()).await?;
    print_sync(&sync);
    print_battery(&mut radio).await;
    Ok(())
}

/// Live battery telemetry, deliberately outside `sync`: each read is a
/// fresh measurement, and a sampling failure must not fail inspection.
async fn print_battery<L: FrameLink>(radio: &mut CompanionRadio<L>) {
    match radio.battery_status().await {
        Ok(Some(status)) => println!("battery: {status:?}"),
        Ok(None) => {}
        Err(err) => println!("battery: unavailable ({err})"),
    }
}

/// Focused battery validation: the capability gate, the snapshot's
/// strict decode, field-set stability across reads, and a plausibility
/// window on voltage. Charge-state transitions need an operator —
/// plug/unplug the charger between runs and watch the state follow
/// within one read (sampling is on demand, never cached).
async fn battery_check(port: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    radio.set_frame_trace(None);
    let Some(first) = radio.battery_status().await? else {
        println!("CAP_BATTERY not advertised; nothing to validate");
        return Ok(());
    };
    println!("battery: {first:?}");
    if first.is_empty() {
        println!("reporting unsupported (empty value) — the T-Echo profile");
        println!("BATTERY OK");
        return Ok(());
    }
    let second = radio
        .battery_status()
        .await?
        .ok_or("capability vanished between reads")?;
    println!("battery: {second:?}");
    expect(
        (
            first.voltage_mv.is_some(),
            first.level_percent.is_some(),
            first.charge_state.is_some(),
        ) == (
            second.voltage_mv.is_some(),
            second.level_percent.is_some(),
            second.charge_state.is_some(),
        ),
        "field set stable across reads",
    )?;
    if let Some(mv) = first.voltage_mv {
        expect(
            (2_500..=5_500).contains(&mv),
            &format!("voltage {mv} mV within a plausible single-cell window"),
        )?;
    }
    println!("BATTERY OK");
    Ok(())
}

/// Diagnostic: report the frequency before and after `CMD_RESTORE`,
/// exposing what the boot-time snapshot mirror actually holds.
async fn probe_restore(port: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    radio.set_frame_trace(None);
    let before = radio.get_prop(prop::PHY_FREQ).await?;
    let completion = radio.restore().await?;
    let after = radio.get_prop(prop::PHY_FREQ).await?;
    println!(
        "freq before={:?} restore={completion:?} after={:?}",
        u32::from_le_bytes(before.as_slice().try_into()?),
        u32::from_le_bytes(after.as_slice().try_into()?),
    );
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("phase-a") if args.len() == 3 => phase_a(&args[2]).await,
        Some("phase-b") if args.len() == 4 => phase_b(&args[2], parse_key32(&args[3])?).await,
        Some("phase-c") if args.len() == 3 => phase_c(&args[2]).await,
        Some("phase-d") if args.len() == 3 => phase_d(&args[2]).await,
        Some("rf-peer") if (4..=5).contains(&args.len()) => {
            let power = args.get(4).map(|text| text.parse()).transpose()?;
            rf_peer(&args[2], args[3].parse()?, power).await
        }
        Some("rf-blast") if (5..=6).contains(&args.len()) => {
            let power = args.get(5).map(|text| text.parse()).transpose()?;
            rf_blast(&args[2], args[3].parse()?, args[4].parse()?, power).await
        }
        Some("rf-dev-multicast") if (5..=6).contains(&args.len()) => {
            let count = args
                .get(5)
                .map(|text| text.parse())
                .transpose()?
                .unwrap_or(3);
            rf_dev_multicast(&args[2], parse_key32(&args[3])?, args[4].parse()?, count).await
        }
        Some("rf-advert-request") if (5..=6).contains(&args.len()) => {
            let nonce = args
                .get(5)
                .map(|text| u32::from_str_radix(text.trim_start_matches("0x"), 16))
                .transpose()?;
            rf_advert_request(&args[2], parse_key32(&args[3])?, args[4].parse()?, nonce).await
        }
        Some("rf-dev-unicast") if (5..=7).contains(&args.len()) => {
            let count = args
                .get(5)
                .map(|text| text.parse())
                .transpose()?
                .unwrap_or(1);
            let expect_ack = match args.get(6).map(String::as_str) {
                None | Some("ack") => true,
                Some("silence") => false,
                Some(other) => return Err(format!("expected ack|silence, got {other}").into()),
            };
            rf_dev_unicast(
                &args[2],
                parse_key32(&args[3])?,
                args[4].parse()?,
                count,
                expect_ack,
            )
            .await
        }
        Some("hold") if (3..=4).contains(&args.len()) => {
            let seconds = args
                .get(3)
                .map(|text| text.parse())
                .transpose()?
                .unwrap_or(30);
            hold(&args[2], seconds).await
        }
        Some("probe-restore") if args.len() == 3 => probe_restore(&args[2]).await,
        Some("drain") if args.len() == 3 => drain(&args[2]).await,
        Some("battery") if args.len() == 3 => battery_check(&args[2]).await,
        #[cfg(feature = "ble-radio")]
        Some("ble-sync") if args.len() == 3 => ble_sync(&args[2]).await,
        Some("info") if (3..=4).contains(&args.len()) => {
            let expected = args.get(3).map(|text| parse_key32(text)).transpose()?;
            info_serial(&args[2], expected).await
        }
        #[cfg(feature = "ble-radio")]
        Some("info-ble") if (3..=4).contains(&args.len()) => {
            let expected = args.get(3).map(|text| parse_key32(text)).transpose()?;
            info_ble(&args[2], expected).await
        }
        Some("phase-e") if args.len() == 6 => {
            phase_e(
                &args[2],
                args[3].parse()?,
                args[4].parse()?,
                args[5].parse()?,
            )
            .await
        }
        _ => {
            eprintln!(
                "usage: companion_hw_validate phase-a|phase-c|phase-d <port>\n       companion_hw_validate phase-b <port> <dev-key>\n       companion_hw_validate rf-peer <peer-port> <base-counter>\n       companion_hw_validate rf-dev-multicast <peer-port> <channel-key> <base-counter> [count]\n       companion_hw_validate rf-dev-unicast <peer-port> <dev-key> <base-counter> [count] [ack|silence]\n       companion_hw_validate rf-advert-request <peer-port> <dev-key> <counter> [nonce-hex]\n       companion_hw_validate phase-e <port> <count> <dropped> <acked>\n       companion_hw_validate info <port> [expected-host-key]\n       companion_hw_validate info-ble <selector> [expected-host-key]\n       companion_hw_validate ble-sync <selector>\n       companion_hw_validate hold <port> [seconds]\n       companion_hw_validate probe-restore <port>\n       companion_hw_validate battery <port>"
            );
            std::process::exit(2);
        }
    }
}
