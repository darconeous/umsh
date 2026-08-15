//! `info`: everything the device will say about itself, in one report,
//! without changing any of it.

use anyhow::Result;

use umsh::core::PublicKey;
use umsh::ulcp::{FrameLink, HostOwnership, SavedSnapshot, UlcpDevice};
use umsh::ulcp_wire::battery::{BatteryChargeState, BatteryStatus};
use umsh::ulcp_wire::ids::{DUTY_LIMIT_DISABLED, cap, prop};
use umsh::ulcp_wire::items::Filter;
use umsh::ulcp_wire::property_name;

use super::values::{FilterArg, KeyArg};
use super::{decode_u16, duty_percent, phy, repeater};
use crate::output::{field, hex};

#[derive(Debug, clap::Args)]
pub struct InfoArgs {
    /// Report ownership relative to this host identity public key.
    #[arg(long, value_name = "KEY")]
    pub expect_host_key: Option<KeyArg>,
}

pub async fn run<L: FrameLink>(device: &mut UlcpDevice<L>, args: InfoArgs) -> Result<()> {
    let expected = args.expect_host_key.map(|key| key.0);
    let sync = device.sync(expected.as_ref()).await?;

    field("device name", format!("{:?}", sync.device_name));
    match (sync.has_capability(cap::DEV_IDENTITY), sync.dev_key) {
        (true, Some(key)) => field("identity", PublicKey(key)),
        (true, None) => field("identity", "none (run `identity generate`)"),
        (false, _) => field("identity", "unsupported"),
    }
    if sync.reset_since_last_contact {
        field(
            "status",
            format!("{:?} (reset since last host contact)", sync.last_status),
        );
    } else {
        field("status", format!("{:?}", sync.last_status));
    }
    field(
        "capabilities",
        sync.capabilities
            .iter()
            .map(|&code| cap_name(code))
            .collect::<Vec<_>>()
            .join(" "),
    );
    let ownership = match (sync.ownership, expected.is_some()) {
        (HostOwnership::Ours, _) => "configured host key matches --expect-host-key".to_string(),
        (HostOwnership::Unclaimed, _) => "unclaimed (no host provisioned)".to_string(),
        (HostOwnership::Unsupported, _) => "unsupported (minimal protocol)".to_string(),
        (HostOwnership::OtherHost(key), true) => format!("ANOTHER HOST: {}", PublicKey(key)),
        (HostOwnership::OtherHost(key), false) => PublicKey(key).to_string(),
    };
    field("host", ownership);

    let mut parts = vec![
        if sync.phy_enabled {
            "enabled".to_string()
        } else {
            "disabled".to_string()
        },
        format!("{} kHz", sync.freq_khz),
    ];
    if sync.has_capability(cap::PHY_LORA) {
        parts.extend(phy::lora_parts(device).await);
    }
    parts.extend(phy::power_part(device).await);
    field("phy", parts.join(", "));

    if sync.has_capability(cap::PHY_DUTY_LIMIT) {
        let now = device
            .get_prop(prop::PHY_DUTY_NOW)
            .await
            .ok()
            .and_then(|v| decode_u16(&v));
        let limit = device
            .get_prop(prop::PHY_DUTY_LIMIT)
            .await
            .ok()
            .and_then(|v| decode_u16(&v));
        let now = now.map_or("unknown".to_string(), |raw| {
            format!("{:.1}%", duty_percent(raw))
        });
        let limit = limit.map_or("unknown".to_string(), |raw| {
            if raw == DUTY_LIMIT_DISABLED {
                "disabled".to_string()
            } else {
                format!("{:.1}%", duty_percent(raw))
            }
        });
        field("duty", format!("now {now}, limit {limit}"));
    }
    if sync.has_capability(cap::REPEATER) {
        // The policy gates only matter once forwarding is on, so an
        // enabled repeater gets the whole line and a disabled one stays
        // a single word.
        match device.repeater_policy().await {
            Ok(Some(policy)) if policy.enabled => {
                let default = policy
                    .default_region
                    .map_or("untagged".to_string(), |code| code.to_string());
                let floor = match (policy.min_rssi, policy.min_snr) {
                    (None, None) => String::new(),
                    (rssi, snr) => {
                        let rssi = rssi.map_or("any".to_string(), |dbm| format!("{dbm} dBm"));
                        let snr = snr.map_or("any".to_string(), |db| format!("{db} dB"));
                        format!(", floor {rssi}/{snr}")
                    }
                };
                field(
                    "repeater",
                    format!(
                        "on, regions {}, tags {default}{floor}",
                        repeater::format_regions(&policy.regions)
                    ),
                );
            }
            Ok(Some(_)) => field("repeater", "off"),
            Ok(None) | Err(_) => field("repeater", "unknown"),
        }
    }
    if sync.has_capability(cap::BATTERY) {
        // Live telemetry: each GET performs a measurement, so this is
        // fetched here rather than inside sync, and a sampling failure
        // must not abort the rest of the report.
        match device.battery_status().await {
            Ok(Some(status)) => field("battery", battery_display(&status)),
            Ok(None) => {}
            Err(error) => field("battery", format!("unavailable ({error})")),
        }
    }
    if sync.has_capability(cap::ILLUMINANCE) {
        // Live telemetry, like the battery: reading it takes a sample.
        match device.illuminance().await {
            Ok(Some(millilux)) => field("illuminance", format_millilux(millilux)),
            Ok(None) => field("illuminance", "no reading".to_string()),
            Err(error) => field("illuminance", format!("unavailable ({error})")),
        }
    }
    if let Some(saved) = sync.saved {
        field(
            "saved",
            match saved {
                SavedSnapshot::None => "no",
                SavedSnapshot::Current => "yes",
                SavedSnapshot::Fallback => "yes, but running on an older generation (re-save)",
                SavedSnapshot::Unreadable => "unreadable — booted with defaults",
            },
        );
    }
    if let (Some(count), Some(dropped)) = (sync.queue_count, sync.queue_dropped) {
        let capacity = device
            .get_prop(prop::HOST_RX_QUEUE_CAPACITY)
            .await
            .ok()
            .and_then(|v| decode_u16(&v))
            .map_or("?".to_string(), |capacity| capacity.to_string());
        field(
            "rx queue",
            format!("{count} buffered of {capacity}, {dropped} dropped since boot"),
        );
    }
    if let Some(filters) = &sync.filters {
        field("filters", filter_list(filters));
    }
    if let Some(ids) = &sync.host_channel_ids {
        let display = if ids.is_empty() {
            "none".to_string()
        } else {
            ids.iter().map(|id| hex(id)).collect::<Vec<_>>().join(", ")
        };
        field("channel keys", format!("{} (ids: {display})", ids.len()));
    }
    if let Some(peers) = &sync.host_peer_keys {
        let display = if peers.is_empty() {
            "none".to_string()
        } else {
            peers
                .iter()
                .map(|key| PublicKey(*key).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        field("peer keys", format!("{} ({display})", peers.len()));
    }
    if let Some(auto_ack) = sync.auto_ack {
        field("auto-ack", if auto_ack { "on" } else { "off" });
    }
    Ok(())
}

fn filter_list(filters: &[Filter]) -> String {
    if filters.is_empty() {
        return "none".to_string();
    }
    filters
        .iter()
        .map(|filter| FilterArg(*filter).to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn cap_name(code: u32) -> String {
    match code {
        cap::WRITABLE_RAW_STREAM => "WRITABLE_RAW_STREAM".into(),
        cap::PHY_DUTY_LIMIT => "PHY_DUTY_LIMIT".into(),
        cap::PHY_LORA => "PHY_LORA".into(),
        cap::HOST_FILTER => "HOST_FILTER".into(),
        cap::HOST_RX_QUEUE => "HOST_RX_QUEUE".into(),
        cap::HOST_KEYS => "HOST_KEYS".into(),
        cap::HOST_AUTO_ACK => "HOST_AUTO_ACK".into(),
        cap::SAVE => "SAVE".into(),
        cap::DEV_IDENTITY => "DEV_IDENTITY".into(),
        cap::DEV_NAME => "DEV_NAME".into(),
        cap::BATTERY => "BATTERY".into(),
        cap::REPEATER => "REPEATER".into(),
        other => other.to_string(),
    }
}

fn battery_display(status: &BatteryStatus) -> String {
    if status.is_empty() {
        return "unsupported reporting".to_string();
    }
    let voltage = status
        .voltage_mv
        .map_or("voltage unsupported".to_string(), |mv| format!("{mv} mV"));
    let level = status
        .level_percent
        .map_or("level unsupported".to_string(), |percent| {
            format!("{percent}%")
        });
    let state = match status.charge_state {
        Some(BatteryChargeState::Discharging) => "discharging",
        Some(BatteryChargeState::Charging) => "charging",
        Some(BatteryChargeState::Charged) => "charged",
        None => "charge state unsupported",
    };
    format!("{voltage}, {level}, {state}")
}

/// `illuminance`: one ambient light reading, on its own.
///
/// Separate from `info` because calibrating the sensor against a
/// reference meter means taking readings in a tight loop, and a full
/// report per data point is unusable for that.
/// Read several properties in one exchange.
///
/// The point is the round trip, not the rendering: values print as raw
/// hex, because the interesting question is whether the device answered
/// every slot in order and put a status where it could not.
pub async fn props<L: FrameLink>(device: &mut UlcpDevice<L>, keys: &[u32]) -> Result<()> {
    let answers = device.get_props(keys).await?;
    for (requested, answer) in keys.iter().zip(&answers) {
        let label = match property_name(*requested) {
            Some(name) => name.to_owned(),
            None => format!("prop {requested}"),
        };
        match answer {
            Ok((key, value)) if key == requested => field(&label, hex(value)),
            // Position identifies the slot, so a key that disagrees with
            // what was asked for is worth showing rather than hiding.
            Ok((key, value)) => field(&label, format!("{} (answered prop {key})", hex(value))),
            Err(status) => field(&label, format!("{status:?}")),
        }
    }
    if answers.len() < keys.len() {
        field(
            "truncated",
            format!(
                "{} of {} answered; reissue the rest",
                answers.len(),
                keys.len()
            ),
        );
    }
    Ok(())
}

pub async fn illuminance<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<()> {
    if !device.capabilities().await?.contains(&cap::ILLUMINANCE) {
        field("illuminance", "unsupported (no CAP_ILLUMINANCE)");
        return Ok(());
    }
    match device.illuminance().await? {
        Some(millilux) => field(
            "illuminance",
            format!("{} ({millilux} mlux)", format_millilux(millilux)),
        ),
        None => field("illuminance", "no reading".to_string()),
    }
    Ok(())
}

/// Millilux as lux to three decimal places. Fixed rather than adaptive
/// because the readings this is used to calibrate span moonlight to
/// daylight, and a column that keeps its shape is easier to compare
/// against a meter than one that keeps rescaling.
pub fn format_millilux(millilux: u32) -> String {
    format!("{}.{:03} lux", millilux / 1000, millilux % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_render_in_the_spelling_the_flag_accepts() {
        let filters = [Filter::PktType(1), Filter::ChannelId([0x9B, 0x68])];
        assert_eq!(filter_list(&filters), "pkt-type:1, channel-id:9b68");
        assert_eq!(filter_list(&[]), "none");
    }

    #[test]
    fn unknown_capability_codes_survive_as_numbers() {
        assert_eq!(cap_name(cap::SAVE), "SAVE");
        assert_eq!(cap_name(9999), "9999");
    }

    #[test]
    fn battery_names_each_unsupported_component() {
        let status = BatteryStatus {
            voltage_mv: Some(4150),
            level_percent: None,
            charge_state: Some(BatteryChargeState::Charging),
        };
        assert_eq!(
            battery_display(&status),
            "4150 mV, level unsupported, charging"
        );
    }
}
