//! `info`: what the device says about itself, in as few exchanges as it
//! can be asked in.
//!
//! The report is a list of topics ([`topics::TOPICS`]), each a set of
//! properties and two renderings of them. Everything a run needs is
//! fetched in one `CMD_PROP_MULTI_GET` — plus the two that cannot share
//! one — so a whole report costs about what a single property used to.
//!
//! Naming a topic asks for that topic alone, which over the mesh is the
//! difference between a question and an errand.

pub mod props;
pub mod topics;

use anyhow::{Result, bail};

use umsh::ulcp::{FrameLink, UlcpDevice};
use umsh::ulcp_wire::battery::{BatteryChargeState, BatteryStatus};
use umsh::ulcp_wire::ids::{cap, prop};
use umsh::ulcp_wire::property_name;

use props::PropSet;
use topics::{Context, Topic};

use super::values::KeyArg;
use crate::output::{field, subfield};

#[derive(Debug, clap::Args)]
pub struct InfoArgs {
    /// Report host ownership relative to this host identity public key.
    #[arg(long, value_name = "KEY")]
    pub expect_host_key: Option<KeyArg>,

    /// Print `NAME=VALUE` lines a shell can `eval`, rather than prose.
    #[arg(long)]
    pub env: bool,

    /// Report one subject rather than all of them.
    ///
    /// With no topic every subject the device supports is reported, and
    /// each one named here reports that subject alone.
    #[arg(value_name = "TOPIC", value_parser = topic_parser())]
    pub topic: Option<String>,
}

/// The topic names, as a value parser — so clap rejects a misspelling,
/// `--help` lists what there is, and the shell completes them, all from
/// the one table that defines them.
fn topic_parser() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(topics::TOPICS.iter().map(|topic| topic.name))
}

pub async fn run<L: FrameLink>(device: &mut UlcpDevice<L>, args: InfoArgs) -> Result<()> {
    // Two properties cannot travel with the rest and must come first.
    //
    // `PROP_LAST_STATUS` reports a refused position by putting itself
    // into it, so its value and a refusal are the same bytes; asking for
    // it alone is what tells them apart. `PROP_CAPS` decides which
    // topics exist and therefore what the batch contains, so it cannot
    // be in that batch.
    let mut set = PropSet::new();
    set.insert(
        prop::LAST_STATUS,
        Ok(device.get_prop(prop::LAST_STATUS).await?),
    );
    let raw_caps = device.get_prop(prop::CAPS).await?;
    let caps = umsh::ulcp::decode_capabilities(&raw_caps)?;
    set.insert(prop::CAPS, Ok(raw_caps));

    let ctx = Context {
        caps,
        remote: device.is_remote(),
        expect_host_key: args.expect_host_key.map(|key| key.0),
        dev_version: device.dev_version().to_owned(),
        // A device that answers the optional model property with an
        // empty string has not named its hardware any more than one that
        // refuses the read has.
        dev_model: device
            .dev_model()
            .filter(|model| !model.is_empty())
            .map(str::to_owned),
    };

    let selected: Vec<&Topic> = match &args.topic {
        // clap has already checked the name against the same table.
        Some(name) => {
            let topic = topics::topic(name).expect("clap accepted an unknown topic");
            if !(topic.gate)(&ctx) {
                bail!(
                    "this device has nothing to report under {name:?} — see `info` for what it \
                     does report"
                );
            }
            vec![topic]
        }
        None => topics::TOPICS
            .iter()
            .filter(|topic| (topic.gate)(&ctx))
            .collect(),
    };

    // Every property every selected topic wants, asked for at once.
    let mut keys: Vec<u32> = Vec::new();
    for topic in &selected {
        for key in (topic.keys)(&ctx) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    let fetched = props::fetch(device, &keys, props::batched(&ctx.caps)).await?;
    for &key in &keys {
        if let Some(value) = fetched.bytes(key) {
            set.insert(key, Ok(value.to_vec()));
        } else if let Some(status) = fetched.refusal(key) {
            set.insert(key, Err(status));
        }
    }

    if args.env {
        for topic in &selected {
            for (name, value) in (topic.env)(&set, &ctx) {
                println!("{}_{name}={}", topic.prefix, topics::shell_quote(&value));
            }
        }
        return Ok(());
    }

    // One topic on its own reads as a report about that subject, so its
    // lines stand at the left margin. A whole report needs the subject
    // named, and its lines indented under it.
    let single = selected.len() == 1;
    for topic in &selected {
        let lines = (topic.render)(&set, &ctx);
        if single {
            for (label, value) in lines {
                field(&label, value);
            }
        } else {
            println!("{}:", topic.name);
            for (label, value) in lines {
                subfield(&label, value);
            }
        }
        for (key, status) in topics::refusals(&set, &(topic.keys)(&ctx)) {
            let label = property_name(key).map_or_else(|| format!("prop {key}"), str::to_owned);
            let refused = format!("refused: {status:?}");
            if single {
                field(&label, refused);
            } else {
                subfield(&label, refused);
            }
        }
    }
    Ok(())
}

pub fn battery_display(status: &BatteryStatus) -> String {
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
    use super::topics::{Context, shell_quote, topic};
    use super::*;
    use umsh::ulcp_wire::ids::{cap, prop};

    fn context(caps: &[u32]) -> Context {
        Context {
            caps: caps.to_vec(),
            remote: false,
            expect_host_key: None,
            dev_version: "test/0.1".to_string(),
            dev_model: Some("Fake Board".to_string()),
        }
    }

    fn props_of(entries: &[(u32, &[u8])]) -> PropSet {
        let mut set = PropSet::new();
        for (key, value) in entries {
            set.insert(*key, Ok(value.to_vec()));
        }
        set
    }

    fn value(lines: &[(String, String)], label: &str) -> Option<String> {
        lines
            .iter()
            .find(|(name, _)| name == label)
            .map(|(_, value)| value.clone())
    }

    #[test]
    fn every_topic_has_a_distinct_name_and_prefix() {
        for (index, topic) in topics::TOPICS.iter().enumerate() {
            let earlier = &topics::TOPICS[..index];
            assert!(
                !earlier.iter().any(|other| other.name == topic.name),
                "two topics named {}",
                topic.name
            );
            assert!(
                !earlier.iter().any(|other| other.prefix == topic.prefix),
                "two topics prefixed {}",
                topic.prefix
            );
        }
    }

    /// `PROP_LAST_STATUS` reports a refused position by putting itself
    /// into it, so it cannot travel in a batch. No topic may name it.
    #[test]
    fn no_topic_asks_for_the_status_property_in_a_batch() {
        let ctx = context(&[
            cap::PHY_LORA,
            cap::PHY_DUTY_LIMIT,
            cap::BATTERY,
            cap::REPEATER,
            cap::GNSS,
            cap::TIME,
            cap::ADVERT,
            cap::ILLUMINANCE,
            cap::DEV_IDENTITY,
            cap::IDENT,
            cap::HOST_FILTER,
            cap::HOST_KEYS,
        ]);
        for topic in topics::TOPICS {
            let keys = (topic.keys)(&ctx);
            assert!(
                !keys.contains(&prop::LAST_STATUS),
                "{} asks for PROP_LAST_STATUS in a batch",
                topic.name
            );
            assert!(
                !keys.contains(&prop::CAPS),
                "{} asks for PROP_CAPS, which gates the batch it would be in",
                topic.name
            );
        }
    }

    #[test]
    fn a_topic_reports_only_what_its_device_supports() {
        let bare = context(&[]);
        assert!(!(topic("gnss").unwrap().gate)(&bare));
        assert!(!(topic("battery").unwrap().gate)(&bare));
        // The device and its radio are always worth asking about.
        assert!((topic("device").unwrap().gate)(&bare));
        assert!((topic("radio").unwrap().gate)(&bare));

        let gnss = context(&[cap::GNSS]);
        assert!((topic("gnss").unwrap().gate)(&gnss));
    }

    /// Over the mesh the host domain is not visible at all, so the topic
    /// is withheld rather than offered and refused nine times.
    #[test]
    fn the_host_topic_is_absent_over_the_mesh() {
        let mut ctx = context(&[cap::HOST_FILTER, cap::HOST_KEYS]);
        assert!((topic("host").unwrap().gate)(&ctx));
        ctx.remote = true;
        assert!(!(topic("host").unwrap().gate)(&ctx));
    }

    #[test]
    fn the_radio_topic_reads_the_lora_parameters() {
        let ctx = context(&[cap::PHY_LORA]);
        let set = props_of(&[
            (prop::PHY_ENABLED, &[1]),
            (prop::PHY_FREQ, &906_875u32.to_le_bytes()),
            (prop::PHY_TX_POWER, &[0xF7]),
            (prop::PHY_LORA_BW, &250_000u32.to_le_bytes()),
            (prop::PHY_LORA_SF, &[11]),
            (prop::PHY_LORA_CR, &[5]),
        ]);
        let lines = (topic("radio").unwrap().render)(&set, &ctx);
        assert_eq!(value(&lines, "phy").as_deref(), Some("enabled"));
        assert_eq!(value(&lines, "frequency").as_deref(), Some("906875 kHz"));
        assert_eq!(
            value(&lines, "modulation").as_deref(),
            Some("BW 250000 Hz, SF11, CR 4/5")
        );
        // Negative transmit powers are real, and read as signed.
        assert_eq!(value(&lines, "tx power").as_deref(), Some("-9 dBm"));
    }

    /// The gates below an off repeater do nothing, and printing them
    /// invites reading them as if they did.
    #[test]
    fn a_disabled_repeater_is_one_line() {
        let ctx = context(&[cap::REPEATER]);
        let off = props_of(&[(prop::MAC_REPEATER_ENABLED, &[0])]);
        let lines = (topic("repeater").unwrap().render)(&off, &ctx);
        assert_eq!(lines.len(), 1);
        assert_eq!(value(&lines, "forwarding").as_deref(), Some("off"));

        let on = props_of(&[
            (prop::MAC_REPEATER_ENABLED, &[1]),
            (prop::MAC_REPEATER_REGIONS, &[]),
            (prop::MAC_REPEATER_MIN_RSSI, &(-110i16).to_le_bytes()),
            (prop::MAC_REPEATER_MIN_SNR, &[]),
        ]);
        let lines = (topic("repeater").unwrap().render)(&on, &ctx);
        assert_eq!(value(&lines, "floor").as_deref(), Some("-110 dBm/any"));
        assert_eq!(value(&lines, "tags").as_deref(), Some("untagged"));
    }

    #[test]
    fn the_battery_environment_is_something_a_shell_can_eval() {
        let ctx = context(&[cap::BATTERY]);
        let status = BatteryStatus {
            voltage_mv: Some(4100),
            level_percent: Some(95),
            charge_state: Some(BatteryChargeState::Discharging),
        };
        let mut encoded = [0u8; 8];
        let len = status.encode(&mut encoded).unwrap();
        let set = props_of(&[(prop::BATTERY, &encoded[..len])]);
        let env = (topic("battery").unwrap().env)(&set, &ctx);
        assert_eq!(
            env,
            vec![
                ("PRESENT".to_string(), "1".to_string()),
                ("LEVEL".to_string(), "0.95".to_string()),
                ("VOLTS".to_string(), "4.100".to_string()),
                ("STATE".to_string(), "DISCHARGING".to_string()),
            ]
        );
    }

    #[test]
    fn an_unreported_component_is_an_absent_variable_not_an_empty_one() {
        let ctx = context(&[cap::BATTERY]);
        let status = BatteryStatus {
            voltage_mv: None,
            level_percent: Some(7),
            charge_state: None,
        };
        let mut encoded = [0u8; 8];
        let len = status.encode(&mut encoded).unwrap();
        let set = props_of(&[(prop::BATTERY, &encoded[..len])]);
        assert_eq!(
            (topic("battery").unwrap().env)(&set, &ctx),
            vec![
                ("PRESENT".to_string(), "1".to_string()),
                ("LEVEL".to_string(), "0.07".to_string()),
            ]
        );

        // A device with no battery answers with no octets at all, so a
        // script that `eval`s this always has something to test.
        let absent = props_of(&[(prop::BATTERY, &[])]);
        assert_eq!(
            (topic("battery").unwrap().env)(&absent, &ctx),
            vec![("PRESENT".to_string(), "0".to_string())]
        );
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

    /// A device name is whatever somebody typed into it, and the output
    /// is meant to be `eval`ed.
    #[test]
    fn env_values_are_safe_for_a_shell_to_evaluate() {
        assert_eq!(shell_quote("T-Echo"), "T-Echo");
        assert_eq!(shell_quote("Repeater 3"), "'Repeater 3'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
    }

    #[test]
    fn a_minimal_length_signed_altitude_reads_both_ways() {
        let ctx = context(&[cap::IDENT]);
        let up = props_of(&[(prop::IDENT_ALTITUDE, &[0x04, 0xD2])]);
        let lines = (topic("identity").unwrap().render)(&up, &ctx);
        assert_eq!(value(&lines, "altitude").as_deref(), Some("1234 m"));

        // One octet, sign-extended: below sea level is a real altitude.
        let down = props_of(&[(prop::IDENT_ALTITUDE, &[0xF0])]);
        let lines = (topic("identity").unwrap().render)(&down, &ctx);
        assert_eq!(value(&lines, "altitude").as_deref(), Some("-16 m"));
    }
}
