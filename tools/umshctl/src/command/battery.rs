//! Explicit battery polling, with per-property discovery and no overlapping requests.
use super::props::{PropArg, format_value, spell};
use anyhow::{Result, bail};
use serde_json::{Value as Json, json};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use umsh::ulcp::{FrameLink, UlcpDevice, UlcpError};
use umsh::ulcp_wire::{
    Status,
    battery::BatteryStatus,
    battery_diagnostics::{self as diagnostics, Value, VoltageRequest},
    ids::{cap, prop},
};

#[derive(Debug, clap::Args)]
pub struct BatteryArgs {
    /// Keep polling until interrupted.
    #[arg(long)]
    pub watch: bool,
    /// Poll spacing, such as 1s, 500ms, or 1m. Default: 1s locally, 60s over radio.
    #[arg(long, value_parser = parse_interval)]
    pub interval: Option<Duration>,
    /// Emit one JSON object per poll, including units and per-property state.
    #[arg(long)]
    pub json: bool,
    /// Properties to read; default is the complete battery group.
    #[arg(long, value_delimiter = ',')]
    pub properties: Vec<PropArg>,
    /// Stop after this many polls (with --watch).
    #[arg(long, requires = "watch", value_parser = clap::value_parser!(u32).range(1..))]
    pub count: Option<u32>,
}

fn parse_interval(text: &str) -> Result<Duration, String> {
    let (number, scale) = if let Some(n) = text.strip_suffix("ms") {
        (n, 0.001)
    } else if let Some(n) = text.strip_suffix('s') {
        (n, 1.0)
    } else if let Some(n) = text.strip_suffix('m') {
        (n, 60.0)
    } else {
        return Err("use a duration such as 1s, 500ms, or 1m".into());
    };
    let seconds = number.parse::<f64>().map_err(|_| "invalid duration")? * scale;
    if !seconds.is_finite() || !(0.001..=86400.0).contains(&seconds) {
        return Err("interval must be between 1ms and 24h".into());
    }
    Ok(Duration::from_secs_f64(seconds))
}

impl BatteryArgs {
    pub fn validate(&self) -> Result<()> {
        for key in &self.properties {
            if key.0 != prop::BATTERY && diagnostics::index(key.0).is_none() {
                bail!("{} is not a battery property", spell(key.0));
            }
        }
        Ok(())
    }
}

fn result_json(key: u32, result: &Result<Vec<u8>, Status>) -> Json {
    let unit = diagnostics::unit(key);
    match result {
        Err(status) => {
            json!({"state":if *status == Status::PROP_NOT_FOUND {"unsupported"} else {"error"}, "status":status.0, "unit":unit})
        }
        Ok(bytes) if key == prop::BATTERY => match BatteryStatus::decode(bytes) {
            Ok(value) => {
                json!({"state":"available", "voltage":{"value":value.voltage_mv,"unit":"mV"},
                "level":{"value":value.level_percent,"unit":"%"},
                "charge_state":value.charge_state.map(|s| format!("{s:?}").to_lowercase())})
            }
            Err(_) => json!({"state":"malformed"}),
        },
        Ok(bytes) => match Value::decode(key, bytes) {
            Ok(None) => json!({"state":"unavailable","unit":unit}),
            Ok(Some(value)) => {
                let v = match value {
                    Value::Current(v) => json!(v),
                    Value::Unsigned(v) | Value::Format(v) => json!(v),
                    Value::Bool(v) => json!(v),
                    Value::Voltage(VoltageRequest::Millivolts(v)) => json!(v),
                    Value::Voltage(VoltageRequest::Maximum) => json!("maximum"),
                };
                json!({"state":"available","value":v,"unit":unit})
            }
            Err(_) => json!({"state":"malformed","unit":unit}),
        },
    }
}

pub async fn run<L: FrameLink>(device: &mut UlcpDevice<L>, args: BatteryArgs) -> Result<()> {
    args.validate()?;
    let interval = args
        .interval
        .unwrap_or(Duration::from_secs(if device.is_remote() { 60 } else { 1 }));
    let batched = device.capabilities().await?.contains(&cap::CMD_MULTI);
    let mut keys: Vec<_> = if args.properties.is_empty() {
        std::iter::once(prop::BATTERY)
            .chain(diagnostics::KEYS)
            .collect()
    } else {
        args.properties.iter().map(|p| p.0).collect()
    };
    keys.sort_unstable();
    keys.dedup();
    let mut backoff = interval;
    let mut polls = 0;
    loop {
        let start = Instant::now();
        let result: Result<Vec<Result<Vec<u8>, Status>>> = async {
            if batched {
                // A continuation would be another acquisition; do not label a
                // concatenation of different requests as a shared sample.
                let entries = device.get_props(&keys).await?;
                if entries.len() != keys.len() {
                    bail!("battery reply was truncated; request fewer properties");
                }
                entries
                    .into_iter()
                    .zip(&keys)
                    .map(|(entry, requested)| match entry {
                        Ok((key, value)) if key == *requested => Ok(Ok(value)),
                        Ok(_) => anyhow::bail!("battery reply was out of order"),
                        Err(status) => Ok(Err(status)),
                    })
                    .collect()
            } else {
                let mut entries = Vec::new();
                for &key in &keys {
                    entries.push(match device.get_prop(key).await {
                        Ok(v) => Ok(v),
                        Err(UlcpError::Status(s)) => Err(s),
                        Err(e) => return Err(e.into()),
                    });
                }
                Ok(entries)
            }
        }
        .await;
        let received = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        match result {
            Ok(answers) => {
                let values: serde_json::Map<_, _> = keys
                    .iter()
                    .zip(&answers)
                    .map(|(&key, value)| (spell(key), result_json(key, value)))
                    .collect();
                if args.json {
                    println!(
                        "{}",
                        json!({"received_at_unix_ms":received,"exchange_ms":start.elapsed().as_millis(),"shared_sample":batched,"properties":values})
                    );
                } else {
                    println!(
                        "battery sample ({}, {} ms)",
                        if batched {
                            "multi-get"
                        } else {
                            "sequential; not a shared sample"
                        },
                        start.elapsed().as_millis()
                    );
                    for (&key, answer) in keys.iter().zip(&answers) {
                        let display = match answer {
                            Ok(v) if key == prop::BATTERY => BatteryStatus::decode(v)
                                .map(|v| super::info::battery_display(&v))
                                .unwrap_or_else(|_| "malformed".into()),
                            Ok(v) => format_value(key, v),
                            Err(s) => format!("{s:?}"),
                        };
                        println!("  {}: {display}", spell(key));
                    }
                }
                let failed = answers
                    .iter()
                    .any(|v| matches!(v,Err(s) if *s != Status::PROP_NOT_FOUND));
                backoff = if failed {
                    backoff
                        .saturating_mul(2)
                        .min(interval.max(Duration::from_secs(600)))
                } else {
                    interval
                };
                keys = keys
                    .into_iter()
                    .zip(answers)
                    .filter_map(|(key, answer)| {
                        (answer != Err(Status::PROP_NOT_FOUND)).then_some(key)
                    })
                    .collect();
            }
            Err(error) => {
                if args.json {
                    println!(
                        "{}",
                        json!({"received_at_unix_ms":received,"exchange_ms":start.elapsed().as_millis(),"state":"error","error":error.to_string()})
                    );
                } else {
                    eprintln!("battery poll failed: {error}");
                }
                if !args.watch {
                    return Err(error);
                }
                backoff = backoff
                    .saturating_mul(2)
                    .min(interval.max(Duration::from_secs(600)));
            }
        }
        polls += 1;
        if !args.watch || keys.is_empty() || args.count.is_some_and(|count| polls >= count) {
            return Ok(());
        }
        tokio::select! { _ = tokio::time::sleep(backoff) => {}, _ = tokio::signal::ctrl_c() => return Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_values_and_availability_are_distinct() {
        assert_eq!(
            result_json(prop::BATTERY_CURRENT, &Ok(vec![0x9c]))["value"],
            -100
        );
        assert_eq!(
            result_json(prop::BATTERY_CURRENT, &Ok(vec![0x38, 0xff]))["value"],
            -200
        );
        assert_eq!(result_json(prop::BATTERY_CURRENT, &Ok(vec![0]))["value"], 0);
        assert_eq!(
            result_json(prop::BATTERY_CURRENT, &Ok(vec![]))["state"],
            "unavailable"
        );
        assert_eq!(
            result_json(prop::BATTERY_CURRENT, &Err(Status::PROP_NOT_FOUND))["state"],
            "unsupported"
        );
        assert_eq!(
            result_json(prop::BATTERY_CURRENT, &Err(Status::FAILURE))["state"],
            "error"
        );
        assert_eq!(
            result_json(prop::BATTERY_CURRENT, &Ok(vec![0; 5]))["state"],
            "malformed"
        );
    }
}
