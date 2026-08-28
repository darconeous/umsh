//! Properties by name, and their values in a form a person can read and
//! type.
//!
//! One vocabulary for the whole tool: `get`, `set`, and the `manage`
//! forms of both take the same spellings and render values the same way.
//! The names and types come from `umsh_ulcp::describe`, so this file
//! holds no second copy of the table it reads.

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};

use umsh::ulcp::{FrameLink, UlcpDevice};
use umsh::ulcp_wire::describe::{PropertyType, property_type};
use umsh::ulcp_wire::ids::saved;
use umsh::ulcp_wire::{PROPERTIES, property_name};

use super::values::{BytesArg, parse_key32, parse_u32};
use crate::output::{address, field, hex};

/// A property named by its mnemonic or its number.
///
/// `phy-freq`, `PHY_FREQ`, `PROP_PHY_FREQ`, `35`, and `0x23` all name
/// the same property. The spelling with dashes is what fits a command
/// line; the others are what the spec and the traces call it, and
/// refusing them would only make somebody transliterate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropArg(pub u32);

impl FromStr for PropArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Ok(key) = parse_u32(text) {
            return Ok(Self(key));
        }
        resolve(text).map(Self).ok_or_else(|| {
            let mut message = format!("no property named {text:?}");
            if let Some(near) = nearest(text) {
                message.push_str(&format!("; did you mean {}?", spell(near)));
            }
            message
        })
    }
}

impl fmt::Display for PropArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match property_name(self.0) {
            Some(name) => write!(f, "{name}"),
            None => write!(f, "prop {}", self.0),
        }
    }
}

/// The identifier a mnemonic names, however it was written.
fn resolve(text: &str) -> Option<u32> {
    PROPERTIES
        .iter()
        .copied()
        .find(|&key| property_name(key).is_some_and(|name| same_name(name, text)))
}

/// Whether `written` names the property `name` spells, ignoring case and
/// the difference between a dash and an underscore, with the `PROP_`
/// prefix optional.
fn same_name(name: &str, written: &str) -> bool {
    let canonical = name.strip_prefix("PROP_").unwrap_or(name);
    let written = written
        .strip_prefix("PROP_")
        .or_else(|| written.strip_prefix("prop_"))
        .or_else(|| written.strip_prefix("prop-"))
        .unwrap_or(written);
    canonical.len() == written.len()
        && canonical
            .bytes()
            .zip(written.bytes())
            .all(|(a, b)| letter(a) == letter(b))
}

fn letter(byte: u8) -> u8 {
    match byte {
        b'-' => b'_',
        other => other.to_ascii_lowercase(),
    }
}

/// The name that shares the longest run of leading characters with what
/// was typed, when that run is long enough to be a typo rather than a
/// coincidence.
fn nearest(text: &str) -> Option<u32> {
    let typed: Vec<u8> = text.bytes().map(letter).collect();
    PROPERTIES
        .iter()
        .copied()
        .filter_map(|key| {
            let name = property_name(key)?;
            let canonical = name.strip_prefix("PROP_").unwrap_or(name);
            let shared = canonical
                .bytes()
                .map(letter)
                .zip(typed.iter().copied())
                .take_while(|(a, b)| a == b)
                .count();
            (shared >= 4).then_some((shared, key))
        })
        .max_by_key(|(shared, _)| *shared)
        .map(|(_, key)| key)
}

/// How this tool writes a property's name on a command line.
pub fn spell(key: u32) -> String {
    match property_name(key) {
        Some(name) => name
            .strip_prefix("PROP_")
            .unwrap_or(name)
            .to_ascii_lowercase()
            .replace('_', "-"),
        None => key.to_string(),
    }
}

/// A property's value as something worth reading.
///
/// The scalar types read as numbers, booleans as on and off, keys as
/// addresses, text as text. Anything whose shape is a structure rather
/// than a scalar reads as hex, which is honest: the octets are the
/// value, and a topic of `info` is where one gets interpreted.
pub fn format_value(key: u32, value: &[u8]) -> String {
    if value.is_empty() {
        // Empty is a real value for a good many properties — no fix, no
        // threshold, no name — and reads better as a word than as the
        // blank line an empty hex string would leave.
        return "(empty)".to_string();
    }
    match property_type(key) {
        Some(PropertyType::Bool) => match value[0] {
            0 => "off".to_string(),
            1 => "on".to_string(),
            other => format!("{other} (neither on nor off)"),
        },
        Some(PropertyType::U8) => scalar(key, u32::from(value[0])),
        Some(PropertyType::I8) => format!("{}", value[0] as i8),
        Some(PropertyType::U16) => match <[u8; 2]>::try_from(value) {
            Ok(bytes) => scalar(key, u32::from(u16::from_le_bytes(bytes))),
            Err(_) => malformed(value),
        },
        Some(PropertyType::I16) => match <[u8; 2]>::try_from(value) {
            Ok(bytes) => format!("{}", i16::from_le_bytes(bytes)),
            Err(_) => malformed(value),
        },
        Some(PropertyType::U32) => match <[u8; 4]>::try_from(value) {
            Ok(bytes) => scalar(key, u32::from_le_bytes(bytes)),
            Err(_) => malformed(value),
        },
        Some(PropertyType::I32) => match <[u8; 4]>::try_from(value) {
            Ok(bytes) => format!("{}", i32::from_le_bytes(bytes)),
            Err(_) => malformed(value),
        },
        Some(PropertyType::Text) => format!(
            "{:?}",
            String::from_utf8_lossy(value).trim_end_matches('\0')
        ),
        Some(PropertyType::Key32) => address(value),
        Some(PropertyType::Status) => format!("{:?}", umsh::ulcp::decode_status(value)),
        Some(PropertyType::Bytes) | None => hex(value),
    }
}

/// A number with the unit the property carries, where it has one worth
/// saying. The bare number stays visible: it is what a `set` takes back.
fn scalar(key: u32, value: u32) -> String {
    use umsh::ulcp_wire::ids::prop;
    match key {
        prop::PHY_FREQ => format!("{value} kHz"),
        prop::PHY_LORA_BW => format!("{value} Hz"),
        prop::PHY_MTU => format!("{value} bytes"),
        prop::UPTIME | prop::ADVERT_INTERVAL | prop::BEACON_INTERVAL => {
            format!("{value} s ({})", super::format_duration(value))
        }
        prop::SAVED => match value as u8 {
            saved::NONE => "0 (nothing saved)".to_string(),
            saved::CURRENT => "1 (current)".to_string(),
            saved::FALLBACK => "2 (running an older generation)".to_string(),
            saved::UNREADABLE => "3 (unreadable)".to_string(),
            _ => value.to_string(),
        },
        _ => value.to_string(),
    }
}

fn malformed(value: &[u8]) -> String {
    format!("{} (unexpected length)", hex(value))
}

/// Turn what somebody typed into the octets a property takes.
///
/// A property whose shape this tool does not know takes hex and nothing
/// else: guessing at the encoding of a structure would write something
/// plausible and wrong.
pub fn encode_value(key: u32, text: &str) -> Result<Vec<u8>> {
    let name = spell(key);
    match property_type(key) {
        Some(PropertyType::Bool) => match text {
            "on" | "true" | "1" => Ok(vec![1]),
            "off" | "false" | "0" => Ok(vec![0]),
            other => bail!("{name} is on or off, not {other:?}"),
        },
        Some(PropertyType::U8) => Ok(vec![number::<u8>(&name, text)?]),
        Some(PropertyType::I8) => Ok(vec![number::<i8>(&name, text)? as u8]),
        Some(PropertyType::U16) => Ok(number::<u16>(&name, text)?.to_le_bytes().to_vec()),
        Some(PropertyType::I16) => Ok(number::<i16>(&name, text)?.to_le_bytes().to_vec()),
        Some(PropertyType::U32) => Ok(number::<u32>(&name, text)?.to_le_bytes().to_vec()),
        Some(PropertyType::I32) => Ok(number::<i32>(&name, text)?.to_le_bytes().to_vec()),
        // The device adds the terminator the wire requires; a string
        // written here is the string meant.
        Some(PropertyType::Text) => Ok(text.as_bytes().to_vec()),
        Some(PropertyType::Key32) => parse_key32(text)
            .map(|key| key.to_vec())
            .map_err(|error| anyhow::anyhow!("{name}: {error}")),
        Some(PropertyType::Status) => {
            bail!("{name} reports what the device last did; it is not written")
        }
        Some(PropertyType::Bytes) | None => text
            .parse::<BytesArg>()
            .map(|bytes| bytes.0)
            .map_err(|error| anyhow::anyhow!("{name} takes hex octets: {error}")),
    }
}

fn number<T>(name: &str, text: &str) -> Result<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    text.parse::<T>()
        .map_err(|error| anyhow::anyhow!("{name}: {error}"))
}

// ─── The commands ────────────────────────────────────────────────────

/// Read properties, named or numbered.
pub async fn get<L: FrameLink>(
    device: &mut UlcpDevice<L>,
    keys: &[PropArg],
    raw: bool,
) -> Result<()> {
    // One key is one exchange either way, and a device that never
    // learned the multi-property commands must still answer.
    let batched = keys.len() > 1
        && device
            .capabilities()
            .await
            .is_ok_and(|caps| caps.contains(&umsh::ulcp_wire::ids::cap::CMD_MULTI));
    let numbers: Vec<u32> = keys.iter().map(|key| key.0).collect();

    if batched {
        let answers = device.read_each(&numbers).await?;
        for (key, answer) in keys.iter().zip(answers) {
            report(*key, answer.as_deref().map_err(|status| *status), raw);
        }
        return Ok(());
    }
    for key in keys {
        let answer = match device.get_prop(key.0).await {
            Ok(value) => Ok(value),
            Err(umsh::ulcp::UlcpError::Status(status)) => Err(status),
            Err(error) => return Err(error.into()),
        };
        report(*key, answer.as_deref().map_err(|status| *status), raw);
    }
    Ok(())
}

fn report(key: PropArg, answer: Result<&[u8], umsh::ulcp_wire::Status>, raw: bool) {
    let label = spell(key.0);
    match answer {
        Ok(value) if raw => field(&label, hex(value)),
        Ok(value) => field(&label, format_value(key.0, value)),
        Err(status) => field(&label, format!("refused: {status:?}")),
    }
}

/// Write one property, reporting what the device stored.
pub async fn set<L: FrameLink>(
    device: &mut UlcpDevice<L>,
    key: PropArg,
    value: &str,
    raw: bool,
) -> Result<()> {
    let encoded = encode_value(key.0, value)?;
    let stored = device.set_prop(key.0, &encoded).await?;
    let label = spell(key.0);
    if raw {
        field(&label, hex(&stored));
    } else {
        field(&label, format_value(key.0, &stored));
    }
    // The device's echo is authoritative: a value it clamped or ignored
    // is worth seeing said so, not assumed.
    if stored != encoded {
        crate::output::note(format!(
            "the device stored {}, not {}",
            format_value(key.0, &stored),
            format_value(key.0, &encoded)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh::core::PublicKey;
    use umsh::ulcp_wire::ids::prop;

    #[test]
    fn a_property_is_named_however_it_is_written() {
        for spelling in [
            "phy-freq",
            "PHY_FREQ",
            "phy_freq",
            "PROP_PHY_FREQ",
            "prop-phy-freq",
            "Phy-Freq",
        ] {
            assert_eq!(
                spelling.parse::<PropArg>().unwrap().0,
                prop::PHY_FREQ,
                "{spelling}"
            );
        }
        // And by number, in either base.
        assert_eq!("35".parse::<PropArg>().unwrap().0, prop::PHY_FREQ);
        assert_eq!("0x23".parse::<PropArg>().unwrap().0, prop::PHY_FREQ);
        // A number this build cannot name is still a property.
        assert_eq!("60000".parse::<PropArg>().unwrap().0, 60_000);
    }

    #[test]
    fn a_misspelling_is_refused_with_a_suggestion() {
        let error = "phy-frequency".parse::<PropArg>().unwrap_err();
        assert!(error.contains("phy-freq"), "{error}");
        // Nothing close enough is just unknown.
        let error = "zzz".parse::<PropArg>().unwrap_err();
        assert!(!error.contains("did you mean"), "{error}");
    }

    /// A name must not match a different property that merely starts the
    /// same way.
    #[test]
    fn a_prefix_is_not_a_name() {
        assert!("phy".parse::<PropArg>().is_err());
        assert!("gnss".parse::<PropArg>().is_err());
        assert_eq!(
            "gnss-enabled".parse::<PropArg>().unwrap().0,
            prop::GNSS_ENABLED
        );
    }

    #[test]
    fn values_read_as_what_they_are() {
        assert_eq!(format_value(prop::PHY_ENABLED, &[1]), "on");
        assert_eq!(format_value(prop::PHY_ENABLED, &[0]), "off");
        assert_eq!(
            format_value(prop::PHY_FREQ, &906_875u32.to_le_bytes()),
            "906875 kHz"
        );
        assert_eq!(format_value(prop::PHY_TX_POWER, &[0xF7]), "-9");
        assert_eq!(format_value(prop::DEV_NAME, b"T-Echo\0"), "\"T-Echo\"");
        assert_eq!(
            format_value(prop::DEV_KEY, &[0xC4; 32]),
            PublicKey([0xC4; 32]).to_string()
        );
        // Structured values stay octets rather than being guessed at.
        assert_eq!(format_value(prop::BATTERY, &[0b101, 0x74, 0x0E]), "05740e");
        // Empty is a real answer for a great many properties.
        assert_eq!(format_value(prop::GNSS_LOCATION, &[]), "(empty)");
        // A scalar of the wrong width says so rather than reading as
        // some other number.
        assert!(format_value(prop::PHY_FREQ, &[1, 2]).contains("unexpected length"));
    }

    #[test]
    fn values_are_written_in_the_form_they_are_read() {
        assert_eq!(encode_value(prop::PHY_ENABLED, "on").unwrap(), vec![1]);
        assert_eq!(encode_value(prop::PHY_ENABLED, "0").unwrap(), vec![0]);
        assert_eq!(
            encode_value(prop::PHY_FREQ, "906875").unwrap(),
            906_875u32.to_le_bytes()
        );
        assert_eq!(encode_value(prop::PHY_TX_POWER, "-9").unwrap(), vec![0xF7]);
        assert_eq!(
            encode_value(prop::TZ_OFFSET, "-480").unwrap(),
            (-480i16).to_le_bytes()
        );
        assert_eq!(
            encode_value(prop::DEV_NAME, "Repeater 3").unwrap(),
            b"Repeater 3".to_vec()
        );
        assert_eq!(
            encode_value(prop::DEV_KEY, &"c4".repeat(32)).unwrap(),
            vec![0xC4; 32]
        );
        // Hex for anything whose shape this tool does not know.
        assert_eq!(
            encode_value(prop::IDENT_LOCATION, "8a1f4c").unwrap(),
            vec![0x8A, 0x1F, 0x4C]
        );
    }

    #[test]
    fn a_value_out_of_range_is_refused_rather_than_wrapped() {
        assert!(encode_value(prop::PHY_LORA_SF, "300").is_err());
        assert!(encode_value(prop::PHY_TX_POWER, "200").is_err());
        assert!(encode_value(prop::PHY_ENABLED, "maybe").is_err());
        assert!(encode_value(prop::DEV_KEY, "nonsense").is_err());
        // The status is a report, not a setting.
        assert!(encode_value(prop::LAST_STATUS, "0").is_err());
    }

    #[test]
    fn a_property_spells_itself_the_way_it_is_typed() {
        assert_eq!(spell(prop::PHY_FREQ), "phy-freq");
        assert_eq!(spell(prop::GNSS_TIME_TRUST), "gnss-time-trust");
        assert_eq!(spell(60_000), "60000");
        // And every spelling round-trips back to its own property.
        for &key in PROPERTIES {
            assert_eq!(
                spell(key).parse::<PropArg>().map(|arg| arg.0).ok(),
                Some(key),
                "{}",
                spell(key)
            );
        }
    }
}
