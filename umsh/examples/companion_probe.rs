//! Smoke-test a companion-radio NCP over a serial port.
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

use umsh::companion_radio::{CompanionRadio, CompanionRadioConfig};
use umsh::hal::{Radio, TxOptions};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: companion_probe <serial-port> [--tx]")?;
    let do_tx = args.next().as_deref() == Some("--tx");

    let mut config = CompanionRadioConfig::new(910_525, 62_500, 7, 5);
    config.tx_power_dbm = 14;

    println!("attaching to {path} ...");
    let mut radio = CompanionRadio::open_serial(&path, 115_200, config).await?;
    println!("ncp version: {}", radio.ncp_version());
    println!(
        "mtu: {} bytes, worst-case airtime: {} ms",
        radio.max_frame_size(),
        radio.t_frame_ms()
    );

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
