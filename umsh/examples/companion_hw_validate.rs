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

use umsh::companion_radio::{
    CompanionRadio, CompanionRadioConfig, FrameLink, HostOwnership, HostProvisioning, NcpSync,
    SerialFrameLink,
};
use umsh::companion::ids::{cap, prop};
use umsh::companion::items::{Filter, PeerKeyEntry};
use umsh::companion::meta::{BufferedRxMeta, RX_FLAG_ACKED};
use umsh::core::{MicSize, NodeHint, PacketBuilder, PacketHeader, PacketType, PublicKey};
use umsh::crypto::software::{SoftwareAes, SoftwareSha256};
use umsh::crypto::{CryptoEngine, PairwiseKeys};
use umsh::hal::{CadPolicy, Radio, TxOptions};

/// This host's identity for the validation run (a fixed test vector,
/// like the integration tests').
const HOST_KEY: [u8; 32] = [0xC4; 32];
const PEER_PUB: [u8; 32] = [0x0A; 32];
const CHANNEL_KEY: [u8; 32] = [0x42; 32];

fn config() -> CompanionRadioConfig {
    let mut config = CompanionRadioConfig::new(906_875, 250_000, 9, 5);
    config.tx_power_dbm = 10;
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
    let mut radio =
        CompanionRadio::attach_existing(SerialFrameLink::new(stream), config()).await?;
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
    println!("  last_status={:?} reset_since_last_contact={}", sync.last_status, sync.reset_since_last_contact);
    println!("  capabilities={:?}", sync.capabilities);
    println!("  ownership={:?}", sync.ownership);
    println!("  phy_enabled={} freq_khz={}", sync.phy_enabled, sync.freq_khz);
    println!("  device_name={:?}", sync.device_name);
    println!("  saved={:?} queue_count={:?} queue_dropped={:?}", sync.saved, sync.queue_count, sync.queue_dropped);
    println!("  filters={:?}", sync.filters);
    println!("  host_channel_ids={:?}", sync.host_channel_ids.as_ref().map(|ids| ids.iter().map(|id| hex(id)).collect::<Vec<_>>()));
    println!("  host_peer_keys={:?}", sync.host_peer_keys.as_ref().map(|keys| keys.iter().map(|key| PublicKey(*key).to_string()).collect::<Vec<_>>()));
    println!("  auto_ack={:?}", sync.auto_ack);
    println!("  dev_key={:?}", sync.dev_key.map(|key| PublicKey(key).to_string()));
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
    radio.set_prop(prop::PHY_FREQ, &config.freq_khz.to_le_bytes()).await?;
    radio.set_prop(prop::PHY_LORA_BW, &config.bandwidth_hz.to_le_bytes()).await?;
    radio.set_prop(prop::PHY_LORA_SF, &[config.spreading_factor]).await?;
    radio.set_prop(prop::PHY_LORA_CR, &[config.coding_rate_denom]).await?;
    radio.set_prop(prop::PHY_TX_POWER, &[config.tx_power_dbm as u8]).await?;
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
        expect(sync.has_capability(capability), &format!("capability {capability} advertised"))?;
    }
    let capacity = radio.get_prop(prop::HOST_RX_QUEUE_CAPACITY).await?;
    println!("queue capacity = {:?}", u16::from_le_bytes(capacity.as_slice().try_into()?));

    let dev_key = radio.ensure_device_identity().await?;
    let again = radio.ensure_device_identity().await?;
    expect(dev_key == again, "device identity is stable across ensure calls")?;

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
    expect(sync.reset_since_last_contact, "reset detected after power cycle")?;
    expect(sync.ownership == HostOwnership::Ours, "ownership survives the power cycle")?;
    expect(sync.saved == Some(true), "snapshot still saved")?;
    expect(sync.phy_enabled, "boot restore re-enabled the PHY")?;
    expect(sync.freq_khz == config().freq_khz, "boot restore applied the saved frequency")?;
    expect(sync.auto_ack == Some(true), "auto-ack armed from the snapshot")?;
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
    expect(sync.dev_key.is_some(), "live identity retained after CMD_CLEAR")?;
    expect(sync.ownership == HostOwnership::Ours, "live host domain retained after CMD_CLEAR")?;
    println!("PHASE C OK — power-cycle (or DFU-reboot) the board, then run phase-d");
    Ok(())
}

async fn phase_d(port: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut radio = open(port).await?;
    let sync = radio.sync(Some(&HOST_KEY)).await?;
    print_sync(&sync);
    expect(sync.ownership == HostOwnership::Unclaimed, "factory: no host identity")?;
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
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
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
    Radio::transmit(radio, data, TxOptions { cad: CadPolicy::Skip })
        .await
        .map_err(|error| format!("transmit failed: {error:?}").into())
}

/// Drive the T-Echo as the RF peer while the T-1000E sits detached:
/// delegated ack on the air, duplicate re-ack, unrelated-traffic
/// rejection, then queue overflow with one late acknowledged frame.
/// Follow with `phase-e <t1000e-port> 16 3 1 <base>`.
async fn rf_peer(port: &str, base: u32) -> Result<(), Box<dyn std::error::Error>> {
    use tokio_serial::SerialPortBuilderExt;
    let stream = tokio_serial::new(port, 115_200).open_native_async()?;
    // The peer radio is disposable: the resetting attach configures its
    // PHY to the same parameters the T-1000E saved.
    let mut radio = CompanionRadio::new(SerialFrameLink::new(stream), config()).await?;
    println!("peer ncp={} base counter={base}", radio.ncp_version());

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
        &PairwiseKeys { k_enc: [0x11; 16], k_mic: [0x22; 16] },
        [0x99, 0x99, 0x99],
    );
    transmit(&mut radio, &unrelated).await?;
    let stray = recv_frame(&mut radio, Duration::from_secs(2)).await;
    expect(stray.is_none(), "unrelated traffic not acknowledged")?;

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
        &format!("queue holds {expected_count} frames (got {:?})", sync.queue_count),
    )?;
    expect(
        sync.queue_dropped == Some(expected_dropped),
        &format!("{expected_dropped} evictions counted (got {:?})", sync.queue_dropped),
    )?;

    let mut drained: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    radio
        .queue_drain_with(|data, meta| drained.push((data.to_vec(), meta.to_vec())))
        .await?;
    let mut acked = 0usize;
    for (data, meta) in &drained {
        let meta = BufferedRxMeta::decode(meta)
            .map_err(|_| "drained frame without buffered metadata")?;
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
    expect(drained.len() == usize::from(expected_count), "drain delivered every queued frame")?;
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
    expect(sync.ownership == HostOwnership::Ours, "ownership verified over BLE")?;
    expect(sync.saved == Some(true), "saved provisioning visible over BLE")?;
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
        Some("rf-peer") if args.len() == 4 => rf_peer(&args[2], args[3].parse()?).await,
        Some("probe-restore") if args.len() == 3 => probe_restore(&args[2]).await,
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
            phase_e(&args[2], args[3].parse()?, args[4].parse()?, args[5].parse()?).await
        }
        _ => {
            eprintln!(
                "usage: companion_hw_validate phase-a|phase-c|phase-d <port>\n       companion_hw_validate phase-b <port> <dev-key>\n       companion_hw_validate rf-peer <peer-port> <base-counter>\n       companion_hw_validate phase-e <port> <count> <dropped> <acked>\n       companion_hw_validate info <port> [expected-host-key]\n       companion_hw_validate info-ble <selector> [expected-host-key]\n       companion_hw_validate ble-sync <selector>\n       companion_hw_validate probe-restore <port>"
            );
            std::process::exit(2);
        }
    }
}
