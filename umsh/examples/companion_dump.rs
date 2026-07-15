//! Live raw/decoded packet dump from a companion-radio NCP.
//!
//! The default RF profile matches the T-Echo NCP bringup profile:
//! 910.525 MHz, LoRa SF7 / BW62.5 kHz / CR4-5, sync word 0x1424.

#![cfg_attr(
    not(any(feature = "serial-radio", feature = "ble-radio")),
    allow(unused_variables, dead_code)
)]

use std::time::{Duration, Instant};

use umsh::companion_radio::{CompanionRadio, CompanionRadioConfig, FrameLink};
use umsh::core::{PacketHeader, PacketType, ParsedOptions, PayloadType};
use umsh::hal::Radio;

const USAGE: &str = "\
usage: companion_dump <serial-port> [RF options]\n\
       companion_dump --ble [selector] [RF options]\n\n\
RF options (defaults shown):\n\
  --freq-khz=910525\n\
  --bw-hz=62500\n\
  --sf=7\n\
  --cr=5                 coding-rate denominator (4/5)\n\
  --sync-word=0x1424\n\
  --tx-power=14\n\
  --idle-probe-secs=10    verify BLE/NCP/radio health while RF is quiet\n";

#[derive(Clone, Copy)]
struct RfArgs {
    freq_khz: u32,
    bandwidth_hz: u32,
    spreading_factor: u8,
    coding_rate_denom: u8,
    sync_word: u16,
    tx_power_dbm: i8,
    idle_probe_secs: u64,
}

impl Default for RfArgs {
    fn default() -> Self {
        Self {
            freq_khz: 910_525,
            bandwidth_hz: 62_500,
            spreading_factor: 7,
            coding_rate_denom: 5,
            sync_word: 0x1424,
            tx_power_dbm: 14,
            idle_probe_secs: 10,
        }
    }
}

impl RfArgs {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut rf = Self::default();
        for arg in args {
            if let Some(value) = arg.strip_prefix("--freq-khz=") {
                rf.freq_khz = parse_u32(value)?;
            } else if let Some(value) = arg.strip_prefix("--bw-hz=") {
                rf.bandwidth_hz = parse_u32(value)?;
            } else if let Some(value) = arg.strip_prefix("--sf=") {
                rf.spreading_factor = parse_u32(value)?
                    .try_into()
                    .map_err(|_| format!("invalid spreading factor: {value}"))?;
            } else if let Some(value) = arg.strip_prefix("--cr=") {
                rf.coding_rate_denom = parse_u32(value)?
                    .try_into()
                    .map_err(|_| format!("invalid coding rate: {value}"))?;
            } else if let Some(value) = arg.strip_prefix("--sync-word=") {
                rf.sync_word = parse_u32(value)?
                    .try_into()
                    .map_err(|_| format!("invalid sync word: {value}"))?;
            } else if let Some(value) = arg.strip_prefix("--tx-power=") {
                rf.tx_power_dbm = value
                    .parse()
                    .map_err(|_| format!("invalid TX power: {value}"))?;
            } else if let Some(value) = arg.strip_prefix("--idle-probe-secs=") {
                rf.idle_probe_secs = value
                    .parse()
                    .map_err(|_| format!("invalid idle probe interval: {value}"))?;
                if rf.idle_probe_secs == 0 {
                    return Err("idle probe interval must be greater than zero".into());
                }
            } else if arg.starts_with('-') {
                return Err(format!("unknown option: {arg}"));
            }
        }
        Ok(rf)
    }

    fn config(self) -> CompanionRadioConfig {
        let mut config = CompanionRadioConfig::new(
            self.freq_khz,
            self.bandwidth_hz,
            self.spreading_factor,
            self.coding_rate_denom,
        );
        config.sync_word = self.sync_word;
        config.tx_power_dbm = self.tx_power_dbm;
        config
    }
}

fn parse_u32(value: &str) -> Result<u32, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|_| format!("invalid number: {value}"))
    } else {
        value
            .parse()
            .map_err(|_| format!("invalid number: {value}"))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(first) = args.next() else {
        return Err(USAGE.into());
    };
    if first == "--help" || first == "-h" {
        print!("{USAGE}");
        return Ok(());
    }

    let mut rest: Vec<String> = args.collect();
    let selector = if first == "--ble" {
        rest.first().filter(|arg| !arg.starts_with('-')).cloned()
    } else {
        None
    };
    if selector.is_some() {
        rest.remove(0);
    }
    let rf = RfArgs::parse(&rest).map_err(|error| format!("{error}\n\n{USAGE}"))?;
    let config = rf.config();

    if first == "--ble" {
        #[cfg(feature = "ble-radio")]
        {
            println!("discovering BLE companion radio ...");
            let radio = CompanionRadio::open_ble(selector.as_deref(), config).await?;
            return run_dump(radio, rf).await;
        }
        #[cfg(not(feature = "ble-radio"))]
        return Err("the ble-radio feature is required for --ble".into());
    }

    #[cfg(feature = "serial-radio")]
    {
        println!("attaching to {first} ...");
        let radio = CompanionRadio::open_serial(&first, 115_200, config).await?;
        return run_dump(radio, rf).await;
    }
    #[cfg(not(feature = "serial-radio"))]
    Err("the serial-radio feature is required for a serial path".into())
}

async fn run_dump<L: FrameLink>(
    mut radio: CompanionRadio<L>,
    rf: RfArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("ncp: {}", radio.ncp_version());
    println!(
        "radio: {} kHz, BW {} Hz, SF{}, CR 4/{}, sync 0x{:04x}",
        rf.freq_khz, rf.bandwidth_hz, rf.spreading_factor, rf.coding_rate_denom, rf.sync_word,
    );
    println!("dumping packets (ctrl-c to exit) ...");

    let started = Instant::now();
    let mut sequence = 0u64;
    let mut buf = [0u8; 256];
    let idle_probe_interval = Duration::from_secs(rf.idle_probe_secs);
    loop {
        let receive = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf));
        let info = match tokio::time::timeout(idle_probe_interval, receive).await {
            Ok(result) => result?,
            Err(_) => {
                let value = radio
                    .get_prop(umsh::companion::ids::prop::PHY_RSSI)
                    .await
                    .map_err(|error| {
                        format!("idle health probe failed after {sequence} packets: {error}")
                    })?;
                let [rssi] = value.as_slice() else {
                    return Err(format!(
                        "idle health probe returned malformed PHY_RSSI value: {value:02x?}"
                    )
                    .into());
                };
                println!(
                    "idle +{:.3}s  packets={sequence}  link=ok  channel RSSI={} dBm",
                    started.elapsed().as_secs_f64(),
                    *rssi as i8,
                );
                continue;
            }
        };
        sequence += 1;
        let packet = &buf[..info.len];
        println!(
            "\n#{sequence} +{:.3}s  len={}  RSSI={} dBm  SNR={}  LQI={}",
            started.elapsed().as_secs_f64(),
            info.len,
            info.rssi,
            info.snr,
            info.lqi
                .map_or_else(|| "n/a".into(), |lqi| lqi.get().to_string()),
        );
        print!("raw:");
        for byte in packet {
            print!(" {byte:02x}");
        }
        println!();
        print_classification(packet);
    }
}

fn print_classification(packet: &[u8]) {
    let header = match PacketHeader::parse(packet) {
        Ok(header) => header,
        Err(error) => {
            println!("decode: not a valid UMSH packet ({error:?})");
            return;
        }
    };
    let options = ParsedOptions::extract(packet, header.options_range.clone());
    let encrypted = header
        .sec_info
        .is_some_and(|security| security.scf.encrypted());
    let frame_counter = header.sec_info.map(|security| security.frame_counter);
    let payload_type = (!encrypted && header.packet_type() != PacketType::MacAck)
        .then(|| {
            packet
                .get(header.body_range.start)
                .and_then(|byte| PayloadType::from_byte(*byte))
        })
        .flatten();

    println!(
        "decode: UMSH {:?} src={:?} dst={:?} channel={:?}",
        header.packet_type(),
        header.source,
        header.dst,
        header.channel,
    );
    println!(
        "        encrypted={encrypted} frame_counter={frame_counter:?} ack_requested={} body={} mic={} payload={payload_type:?}",
        header.ack_requested(),
        header.body_range.len(),
        header.mic_range.len(),
    );
    match options {
        Ok(options) => println!("        options={options:?}"),
        Err(error) => println!("        options=<decode error: {error:?}>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_and_hex_rf_options() {
        let args = vec![
            "--freq-khz=915000".to_owned(),
            "--sync-word=0x1234".to_owned(),
            "--sf=9".to_owned(),
        ];
        let rf = RfArgs::parse(&args).unwrap();
        assert_eq!(rf.freq_khz, 915_000);
        assert_eq!(rf.sync_word, 0x1234);
        assert_eq!(rf.spreading_factor, 9);
        assert_eq!(rf.idle_probe_secs, 10);
    }

    #[test]
    fn rejects_unknown_options() {
        assert!(RfArgs::parse(&["--mystery=1".to_owned()]).is_err());
    }

    #[test]
    fn parses_and_validates_idle_probe_interval() {
        let rf = RfArgs::parse(&["--idle-probe-secs=3".to_owned()]).unwrap();
        assert_eq!(rf.idle_probe_secs, 3);
        assert!(RfArgs::parse(&["--idle-probe-secs=0".to_owned()]).is_err());
    }
}
