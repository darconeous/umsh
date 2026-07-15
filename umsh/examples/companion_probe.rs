//! Smoke-test a companion-radio NCP over serial or BLE.
//!
//! Attaches to the NCP (reset, version gate, RF configuration, PHY
//! enable), prints its identity, optionally transmits one test frame,
//! then prints every frame heard on air.
//!
//! ```sh
//! cargo run --example companion_probe --features serial-radio -- \
//!     /dev/cu.usbmodemXXXX [--tx]
//! ```
//!
//! The default RF profile matches the firmware's MeshCore-US bringup
//! defaults (910.525 MHz / SF7 / BW62.5 kHz / CR4-5).

#![cfg_attr(
    not(any(feature = "serial-radio", feature = "ble-radio")),
    allow(unused_variables, unused_assignments, dead_code)
)]

use umsh::companion_radio::{CompanionRadio, CompanionRadioConfig, FrameLink};
use umsh::hal::{Radio, TxOptions};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let first = args.next().ok_or(
        "usage: companion_probe <serial-port> [--tx|--check] | --ble [selector] [--tx|--check]",
    )?;
    let rest: Vec<String> = args.collect();
    let do_tx = rest.iter().any(|arg| arg == "--tx");
    let check_only = rest.iter().any(|arg| arg == "--check");
    let pin_update = rest.iter().find_map(|arg| {
        arg.strip_prefix("--pin=")
            .and_then(|value| value.parse::<u32>().ok())
            .map(Some)
            .or_else(|| (arg == "--clear-pin").then_some(None))
    });

    let mut config = CompanionRadioConfig::new(910_525, 62_500, 7, 5);
    config.tx_power_dbm = 14;

    if first == "--ble" {
        #[cfg(target_os = "linux")]
        eprintln!(
            "Linux pairing is OS-mediated. If attach is rejected, run `bluetoothctl`, enable an agent, then pair/trust the device before retrying."
        );
        #[cfg(feature = "ble-radio")]
        {
            let selector = rest
                .iter()
                .find(|arg| {
                    !matches!(arg.as_str(), "--tx" | "--check" | "--clear-pin")
                        && !arg.starts_with("--pin=")
                })
                .map(String::as_str);
            println!("discovering BLE companion radio ...");
            let radio = CompanionRadio::open_ble(selector, config).await?;
            return run_probe(radio, do_tx, check_only, pin_update).await;
        }
        #[cfg(not(feature = "ble-radio"))]
        return Err("the ble-radio feature is required for --ble".into());
    }

    #[cfg(feature = "serial-radio")]
    {
        println!("attaching to {first} ...");
        let radio = CompanionRadio::open_serial(&first, 115_200, config).await?;
        return run_probe(radio, do_tx, check_only, pin_update).await;
    }
    #[cfg(not(feature = "serial-radio"))]
    Err("the serial-radio feature is required for a serial path".into())
}

async fn run_probe<L: FrameLink>(
    mut radio: CompanionRadio<L>,
    do_tx: bool,
    check_only: bool,
    pin_update: Option<Option<u32>>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("ncp version: {}", radio.ncp_version());
    println!("boot status: {:?}", radio.boot_status());
    println!(
        "mtu: {} bytes, worst-case airtime: {} ms",
        radio.max_frame_size(),
        radio.t_frame_ms()
    );

    if let Some(pin) = pin_update {
        radio.set_ble_pairing_pin(pin).await?;
        println!(
            "BLE pairing PIN {}",
            pin.map_or("cleared".to_owned(), |pin| format!("set to {pin:06}"))
        );
    }

    if check_only {
        return Ok(());
    }

    if do_tx {
        radio
            .transmit(b"UMSH companion probe", TxOptions::default())
            .await
            .map_err(|error| format!("transmit failed: {error:?}"))?;
        println!("transmitted 20-byte test frame");

        // Duty only accumulates when the NCP's radio confirms an on-air
        // transmission, so a non-zero readback proves the TX completed.
        let duty = radio
            .get_prop(umsh::companion::ids::prop::PHY_DUTY_NOW)
            .await?;
        if let [lo, hi, ..] = duty[..] {
            let duty = u16::from_le_bytes([lo, hi]);
            println!(
                "duty cycle now: {duty}/65535 ({:.3}% of the past hour)",
                f64::from(duty) * 100.0 / 65535.0
            );
        }
    }

    println!("listening for frames (ctrl-c to exit) ...");
    let mut buf = [0u8; 256];
    loop {
        let info = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf)).await?;
        println!(
            "rx {} bytes, rssi {} dBm, snr {}: {:02x?}",
            info.len,
            info.rssi,
            info.snr,
            &buf[..info.len]
        );
    }
}
