//! Throwaway two-board PHY interop probe. One board beacons broadcast
//! frames; the other is watched (non-destructively) for receptions.
//!
//!   rf_probe <rx-port> <tx-port>
//!
//! rx-port is opened with `attach_existing` (provisioning/PHY untouched);
//! tx-port is opened with `new` (resetting attach → configures PHY to the
//! same params) and beacons every 700 ms. Every reception on rx is printed
//! with length + RSSI, so a silent probe means the two radios cannot hear
//! each other on the configured PHY.

use std::time::Duration;

use umsh::companion_radio::{CompanionRadio, CompanionRadioConfig, SerialFrameLink};
use umsh::core::{NodeHint, PacketBuilder};
use umsh::hal::{CadPolicy, Radio, TxOptions};

fn config() -> CompanionRadioConfig {
    let mut config = CompanionRadioConfig::new(910_525, 62_500, 7, 5);
    config.tx_power_dbm = 14;
    config.response_timeout = Duration::from_secs(2);
    config
}

fn beacon(counter: u32) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let packet = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_hint(NodeHint([0xAB, 0xCD, 0xEF]))
        .payload(&[counter as u8, 0x02, 0x03])
        .build()
        .unwrap();
    packet.to_vec()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tokio_serial::SerialPortBuilderExt;
    let args: Vec<String> = std::env::args().collect();

    // tx-only beacon mode: `rf_probe tx <port>` — beacon a recognizable
    // broadcast (source hint AB:CD:EF) for an external sniffer to watch.
    if args.get(1).map(String::as_str) == Some("tx") {
        let stream = tokio_serial::new(args[2].as_str(), 115_200).open_native_async()?;
        let mut tx = CompanionRadio::new(SerialFrameLink::new(stream), config()).await?;
        println!("tx-only {} on {} @ MeshCore US (src hint AB:CD:EF)", tx.ncp_version(), args[2]);
        for counter in 0u32..40 {
            match Radio::transmit(&mut tx, &beacon(counter), TxOptions { cad: CadPolicy::Skip }).await
            {
                Ok(()) => println!("tx beacon counter={counter}"),
                Err(error) => println!("tx FAILED counter={counter}: {error:?}"),
            }
            tokio::time::sleep(Duration::from_millis(800)).await;
        }
        return Ok(());
    }

    let (rx_port, tx_port) = (&args[1], &args[2]);

    let tx_stream = tokio_serial::new(tx_port.as_str(), 115_200).open_native_async()?;
    let mut tx = CompanionRadio::new(SerialFrameLink::new(tx_stream), config()).await?;
    println!("tx {} on {tx_port}", tx.ncp_version());

    let rx_stream = tokio_serial::new(rx_port.as_str(), 115_200).open_native_async()?;
    let mut rx = CompanionRadio::attach_existing(SerialFrameLink::new(rx_stream), config()).await?;
    println!("rx {} on {rx_port} (attached, non-resetting)", rx.ncp_version());
    // Live delivery bypassing whatever host filters the board carries.
    rx.set_prop(umsh::companion::ids::prop::MAC_PROMISCUOUS, &[1])
        .await?;

    let rx_fut = async {
        let mut buf = [0u8; 512];
        let mut heard = 0usize;
        loop {
            match core::future::poll_fn(|cx| Radio::poll_receive(&mut rx, cx, &mut buf)).await {
                Ok(info) => {
                    heard += 1;
                    println!(
                        "  RX #{heard}: {} bytes rssi={} dBm snr={:?}",
                        info.len, info.rssi, info.snr
                    );
                }
                Err(error) => println!("  RX error: {error:?}"),
            }
        }
    };

    let tx_fut = async {
        for counter in 0u32..30 {
            match Radio::transmit(&mut tx, &beacon(counter), TxOptions { cad: CadPolicy::Skip }).await
            {
                Ok(()) => println!("tx beacon counter={counter}"),
                Err(error) => println!("tx FAILED counter={counter}: {error:?}"),
            }
            tokio::time::sleep(Duration::from_millis(700)).await;
        }
    };

    tokio::select! {
        _ = rx_fut => {}
        _ = tx_fut => { println!("tx done"); }
    }
    Ok(())
}
