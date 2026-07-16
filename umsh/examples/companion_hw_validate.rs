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

fn parse_hex32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err("expected 64 hex digits".into());
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|error| error.to_string())?;
    }
    Ok(out)
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
    println!("  host_peer_keys={:?}", sync.host_peer_keys.as_ref().map(|keys| keys.iter().map(|key| hex(&key[..4])).collect::<Vec<_>>()));
    println!("  auto_ack={:?}", sync.auto_ack);
    println!("  dev_key={:?}", sync.dev_key.map(|key| hex(&key)));
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
    println!("DEV_KEY={}", hex(&dev_key));
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
    println!("re-provisioned; DEV_KEY={}", hex(&dev_key));
    println!("PHASE D OK — full-protocol hardware validation complete on this board");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("phase-a") if args.len() == 3 => phase_a(&args[2]).await,
        Some("phase-b") if args.len() == 4 => phase_b(&args[2], parse_hex32(&args[3])?).await,
        Some("phase-c") if args.len() == 3 => phase_c(&args[2]).await,
        Some("phase-d") if args.len() == 3 => phase_d(&args[2]).await,
        _ => {
            eprintln!(
                "usage: companion_hw_validate phase-a|phase-c|phase-d <port>\n       companion_hw_validate phase-b <port> <dev-key-hex>"
            );
            std::process::exit(2);
        }
    }
}
