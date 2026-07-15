//! Repeatable companion-link control-plane soak and latency measurement.
//!
//! This intentionally performs no LoRa transmissions. It repeatedly reads a
//! stable NCP property, exercising the complete request/response transport and
//! reporting attach and round-trip latency without changing device state.

#![cfg_attr(
    not(any(feature = "serial-radio", feature = "ble-radio")),
    allow(unused_variables, unused_assignments, dead_code)
)]

use std::time::{Duration, Instant};

use umsh::companion::ids::prop;
use umsh::companion_radio::{CompanionRadio, CompanionRadioConfig, FrameLink};

struct Options {
    transport: String,
    selector: Option<String>,
    duration: Duration,
    interval: Duration,
    segment_payload: usize,
}

impl Options {
    fn parse() -> Result<Self, String> {
        Self::parse_from(std::env::args().skip(1))
    }

    fn parse_from(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut args = args.into_iter();
        let transport = args.next().ok_or_else(Self::usage)?;
        let mut selector = None;
        let mut duration = Duration::from_secs(30 * 60);
        let mut interval = Duration::from_secs(1);
        let mut segment_payload = 19;

        for arg in args {
            if let Some(value) = arg.strip_prefix("--duration=") {
                duration = Duration::from_secs(
                    value.parse().map_err(|_| "invalid --duration".to_owned())?,
                );
            } else if let Some(value) = arg.strip_prefix("--interval-ms=") {
                interval = Duration::from_millis(
                    value
                        .parse()
                        .map_err(|_| "invalid --interval-ms".to_owned())?,
                );
            } else if let Some(value) = arg.strip_prefix("--segment-payload=") {
                segment_payload = value
                    .parse()
                    .map_err(|_| "invalid --segment-payload".to_owned())?;
            } else if selector.replace(arg).is_some() {
                return Err(Self::usage());
            }
        }
        if duration.is_zero() || interval.is_zero() {
            return Err("duration and interval must be nonzero".to_owned());
        }
        Ok(Self {
            transport,
            selector,
            duration,
            interval,
            segment_payload,
        })
    }

    fn usage() -> String {
        "usage: companion_link_soak <serial-port> | --ble [selector] [--duration=SECONDS] [--interval-ms=MILLISECONDS] [--segment-payload=1..511]".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ble_soak_options() {
        let options = Options::parse_from(
            [
                "--ble",
                "T-Echo",
                "--duration=90",
                "--interval-ms=250",
                "--segment-payload=243",
            ]
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(options.transport, "--ble");
        assert_eq!(options.selector.as_deref(), Some("T-Echo"));
        assert_eq!(options.duration, Duration::from_secs(90));
        assert_eq!(options.interval, Duration::from_millis(250));
        assert_eq!(options.segment_payload, 243);
    }

    #[test]
    fn rejects_zero_timing_and_extra_positionals() {
        assert!(Options::parse_from(["--ble", "--duration=0"].map(str::to_owned)).is_err());
        assert!(Options::parse_from(["--ble", "one", "two"].map(str::to_owned)).is_err());
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse()?;
    let mut config = CompanionRadioConfig::new(910_525, 62_500, 7, 5);
    config.tx_power_dbm = 14;
    let attach_started = Instant::now();

    if options.transport == "--ble" {
        #[cfg(feature = "ble-radio")]
        {
            let link_config = umsh::companion_radio::BleFrameLinkConfig {
                segment_payload: options.segment_payload,
                ..Default::default()
            };
            let radio = CompanionRadio::open_ble_with_link_config(
                options.selector.as_deref(),
                config,
                link_config,
            )
            .await?;
            return run(radio, options, attach_started.elapsed()).await;
        }
        #[cfg(not(feature = "ble-radio"))]
        return Err("the ble-radio feature is required for --ble".into());
    }

    if options.selector.is_some() {
        return Err(Options::usage().into());
    }
    #[cfg(feature = "serial-radio")]
    {
        let radio = CompanionRadio::open_serial(&options.transport, 115_200, config).await?;
        run(radio, options, attach_started.elapsed()).await
    }
    #[cfg(not(feature = "serial-radio"))]
    Err("the serial-radio feature is required for a serial path".into())
}

async fn run<L: FrameLink>(
    mut radio: CompanionRadio<L>,
    options: Options,
    attach_time: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("transport={}", options.transport);
    println!("ncp_version={}", radio.ncp_version());
    println!("attach_us={}", attach_time.as_micros());
    println!("duration_s={}", options.duration.as_secs());
    println!("interval_ms={}", options.interval.as_millis());
    println!("sample,elapsed_ms,rtt_us");

    let started = Instant::now();
    let mut samples = 0u64;
    let mut total_us = 0u128;
    let mut min_us = u128::MAX;
    let mut max_us = 0u128;

    while started.elapsed() < options.duration {
        let request_started = Instant::now();
        radio.get_prop(prop::NCP_VERSION).await?;
        let rtt_us = request_started.elapsed().as_micros();
        samples += 1;
        total_us += rtt_us;
        min_us = min_us.min(rtt_us);
        max_us = max_us.max(rtt_us);
        println!("{samples},{},{rtt_us}", started.elapsed().as_millis());
        tokio::time::sleep(options.interval).await;
    }

    let average = if samples == 0 {
        0
    } else {
        total_us / u128::from(samples)
    };
    println!("summary_samples={samples}");
    println!("summary_min_us={}", if samples == 0 { 0 } else { min_us });
    println!("summary_avg_us={average}");
    println!("summary_max_us={max_us}");
    Ok(())
}
