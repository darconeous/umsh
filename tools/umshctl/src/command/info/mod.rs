//! `info`: what the device says about itself, in as few exchanges as it
//! can be asked in.
//!
//! The report is a list of topics ([`topics::TOPICS`]), each a set of
//! properties and two renderings of them. Everything a run needs is
//! fetched in one `CMD_PROP_MULTI_GET`. The retained status and the
//! temperature sampling and labels use requests of their own.
//!
//! Naming topics asks for those topics alone, with the capability list
//! riding in the same batch, which over the mesh is the difference
//! between a question and an errand.

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

    /// Report these subjects rather than all of them.
    ///
    /// With no topic every subject the device supports is reported.
    /// Several named together are fetched together.
    #[arg(value_name = "TOPIC", value_parser = topic_parser())]
    pub topics: Vec<String>,
}

/// The topic names, as a value parser—so clap rejects a misspelling,
/// `--help` lists what there is, and the shell completes them, all from
/// the one table that defines them.
fn topic_parser() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(topics::TOPICS.iter().map(|topic| topic.name))
}

pub async fn run<L: FrameLink>(device: &mut UlcpDevice<L>, args: InfoArgs) -> Result<()> {
    // clap has already checked every name against the same table.
    let mut named: Vec<&'static Topic> = Vec::new();
    for name in &args.topics {
        let topic = topics::topic(name).expect("clap accepted an unknown topic");
        if !named.iter().any(|seen| seen.name == topic.name) {
            named.push(topic);
        }
    }

    // The capability list decides which topics exist and what each one
    // asks for, so it is wanted before anything else—but not
    // necessarily on its own.
    let mut set = PropSet::new();
    let caps = match folded_keys(
        &named,
        device.cached_capabilities().is_some(),
        device.is_remote(),
    ) {
        Some(keys) => {
            let (caps, answers) = device.read_each_with_capabilities(&keys).await?;
            set = props::collect(&keys, answers);
            caps
        }
        None => device.capabilities().await?,
    };

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

    let selected: Vec<&Topic> = if named.is_empty() {
        topics::TOPICS
            .iter()
            .filter(|topic| (topic.gate)(&ctx))
            .collect()
    } else {
        let (reportable, absent): (Vec<&Topic>, Vec<&Topic>) =
            named.iter().partition(|topic| (topic.gate)(&ctx));
        let absent = absent
            .iter()
            .map(|topic| format!("{:?}", topic.name))
            .collect::<Vec<_>>()
            .join(", ");
        if reportable.is_empty() {
            bail!(
                "this device has nothing to report under {absent}—see `info` for what it does \
                 report"
            );
        }
        if !absent.is_empty() {
            crate::output::warn(format!("this device has nothing to report under {absent}"));
        }
        reportable
    };

    // Whatever the selected topics want that no batch has carried yet:
    // everything, for a whole report, and nothing when the named topics
    // were asked for up front.
    let wanted: Vec<u32> = batch_keys(&selected, &ctx)
        .into_iter()
        .filter(|&key| !set.contains(key))
        .collect();
    if !wanted.is_empty() {
        set.merge(props::fetch(device, &wanted).await?);
    }

    // `PROP_LAST_STATUS` reports a refused position by putting itself
    // into it, so its value and a refusal are the same bytes; asking for
    // it alone is what tells them apart.
    if wants_status(&selected) {
        set.insert(
            prop::LAST_STATUS,
            Ok(device.get_prop(prop::LAST_STATUS).await?),
        );
    }

    let has_temperatures = selected
        .iter()
        .any(|topic| (topic.keys)(&ctx).contains(&prop::TEMPERATURES));
    if has_temperatures {
        for key in [prop::TEMPERATURES, prop::TEMPERATURE_NAMES] {
            let answer = match props::fetch_alone(device, key).await {
                Ok(answer) => answer,
                Err(error) if key == prop::TEMPERATURE_NAMES => {
                    eprintln!("sensor names: {error}");
                    continue;
                }
                Err(error) => return Err(error),
            };
            set.merge(answer);
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

/// The keys to ask for alongside the capability list, or `None` when the
/// list should be learned first.
///
/// Named topics are asked for outright, as if the device had every
/// capability, with the list riding in the same batch: the keys of a
/// subject the device lacks come back refused, which costs a few octets
/// rather than an exchange. A whole report learns the list first, since
/// asking for every subject there is would cost more answer than the
/// exchange it saves. A list already known needs neither.
fn folded_keys(named: &[&Topic], caps_known: bool, remote: bool) -> Option<Vec<u32>> {
    if named.is_empty() || caps_known {
        return None;
    }
    Some(batch_keys(
        named,
        &Context::assuming_every_capability(remote),
    ))
}

/// Every property the topics want that can share one batch, each once.
///
/// The temperature samples and their labels are asked for on their own:
/// a sampling array and an appendable list must not share an answer that
/// may be continued across exchanges.
fn batch_keys(selected: &[&Topic], ctx: &Context) -> Vec<u32> {
    let mut keys: Vec<u32> = Vec::new();
    for topic in selected {
        for key in (topic.keys)(ctx) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    keys.retain(|key| !matches!(*key, prop::TEMPERATURES | prop::TEMPERATURE_NAMES));
    keys
}

/// Whether the report includes the retained status, which costs an
/// exchange of its own.
fn wants_status(selected: &[&Topic]) -> bool {
    selected
        .iter()
        .any(|topic| topic.name == topics::DEVICE_TOPIC)
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
        Some(BatteryChargeState::NotCharging) => "not charging",
        None => "charge state unsupported",
    };
    format!("{voltage}, {level}, {state}")
}

/// Read all temperatures, then their current labels, without batching the values.
pub async fn temperatures<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<()> {
    if !device.capabilities().await?.contains(&cap::TEMPERATURE) {
        field("temperatures", "unsupported (no CAP_TEMPERATURE)");
        return Ok(());
    }
    let mut set = props::fetch_alone(device, prop::TEMPERATURES).await?;
    // Preserve measurements even if the metadata exchange fails.
    match props::fetch_alone(device, prop::TEMPERATURE_NAMES).await {
        Ok(names) => set.merge(names),
        Err(error) => eprintln!("sensor names: {error}"),
    }
    for (label, value) in topics::render_temperatures(&set) {
        field(&label, value);
    }
    Ok(())
}

/// `illuminance`: one ambient light reading, on its own.
///
/// Separate from `info` because calibrating the sensor against a
/// reference meter means taking readings in a tight loop, and a full
/// report per data point is unusable for that.
pub async fn illuminance<L: FrameLink>(device: &mut UlcpDevice<L>) -> Result<()> {
    let reading = device.illuminance().await?;
    // The reading learned the capability list on its way, so telling no
    // sensor from no reading costs nothing more.
    if !device.capabilities().await?.contains(&cap::ILLUMINANCE) {
        field("illuminance", "unsupported (no CAP_ILLUMINANCE)");
        return Ok(());
    }
    match reading {
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

    /// Named topics are asked for in the same batch as the capability
    /// list; a whole report, or a device whose list is already known,
    /// does not fold.
    #[test]
    fn named_topics_ride_with_the_capability_list() {
        let stats = topic("stats").unwrap();
        let keys = folded_keys(&[stats], false, true).expect("named topics fold");
        assert_eq!(keys, (stats.keys)(&context(&[])));
        assert!(
            !keys.contains(&prop::CAPS),
            "the device appends the list itself"
        );
        assert!(!keys.contains(&prop::LAST_STATUS));

        assert_eq!(folded_keys(&[], false, true), None, "a whole report");
        assert_eq!(
            folded_keys(&[stats], true, true),
            None,
            "list already known"
        );
    }

    /// Before the list is known, a named topic asks for everything it
    /// could want: what the device lacks comes back refused.
    #[test]
    fn a_folded_batch_assumes_every_capability() {
        let keys = folded_keys(
            &[topic("radio").unwrap(), topic("sensors").unwrap()],
            false,
            true,
        )
        .unwrap();
        assert!(keys.contains(&prop::PHY_LORA_SF));
        assert!(keys.contains(&prop::ILLUMINANCE));
        // Still never the samples or their labels.
        assert!(!keys.contains(&prop::TEMPERATURES));
        assert!(!keys.contains(&prop::TEMPERATURE_NAMES));
    }

    /// The retained status costs an exchange of its own, so only the
    /// topic that prints it pays for it.
    #[test]
    fn only_the_device_topic_reads_the_status() {
        let stats = topic("stats").unwrap();
        let device = topic("device").unwrap();
        assert!(!wants_status(&[stats]));
        assert!(wants_status(&[stats, device]));
    }

    /// A mesh handle read nothing on opening, so the report asks for the
    /// firmware and model itself.
    #[test]
    fn over_the_mesh_the_device_topic_reads_its_own_firmware() {
        let device = topic("device").unwrap();
        let mut ctx = context(&[]);
        assert!(!(device.keys)(&ctx).contains(&prop::DEV_VERSION));

        ctx.remote = true;
        ctx.dev_version = String::new();
        ctx.dev_model = None;
        let keys = (device.keys)(&ctx);
        assert!(keys.contains(&prop::DEV_VERSION));
        assert!(keys.contains(&prop::DEV_MODEL));

        let set = props_of(&[(prop::DEV_VERSION, b"umsh/1.2\0"), (prop::DEV_MODEL, b"\0")]);
        let lines = (device.render)(&set, &ctx);
        assert_eq!(value(&lines, "firmware").as_deref(), Some("umsh/1.2"));
        assert_eq!(value(&lines, "model"), None, "an empty model names nothing");
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
