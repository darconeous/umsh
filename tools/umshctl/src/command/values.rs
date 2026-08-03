//! `FromStr`-backed value parsers for the command tree.
//!
//! clap turns each of these into a typed argument, so a bad value is
//! reported against the flag or positional that carried it instead of
//! being re-checked by hand after parsing. The parsing rules themselves
//! are unchanged from the hand-rolled tool these replaced.

use std::fmt;
use std::str::FromStr;

use umsh::core::{PublicKey, RegionCode};
use umsh::ulcp_wire::items::{Filter, PeerKeyEntry};

pub fn parse_key32(text: &str) -> Result<[u8; 32], String> {
    text.parse::<PublicKey>()
        .map(|key| key.0)
        .map_err(|error| format!("expected 44-char base58 or 64-char hex key: {error}"))
}

pub fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let text = text.trim();
    if text.len() != 2 * N || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("expected {} hex characters, got {text:?}", 2 * N));
    }
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16)
            .map_err(|error| error.to_string())?;
    }
    Ok(out)
}

pub fn parse_bool(text: &str) -> Result<bool, String> {
    match text {
        "on" | "true" | "1" => Ok(true),
        "off" | "false" | "0" => Ok(false),
        other => Err(format!("expected on or off, got {other:?}")),
    }
}

/// A number written in decimal or with an `0x` prefix.
pub fn parse_u32(text: &str) -> Result<u32, String> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => text.parse(),
    }
    .map_err(|_| format!("invalid number: {text}"))
}

/// A 32-byte public key or channel key, written as base58 or hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyArg(pub [u8; 32]);

impl FromStr for KeyArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_key32(text).map(Self)
    }
}

/// `PUB,KENC,KMIC` (or whitespace-separated): a peer public key and the
/// two 16-byte pairwise secrets, hex.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerArg(pub PeerKeyEntry);

impl FromStr for PeerArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let fields: Vec<&str> = text
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|field| !field.is_empty())
            .collect();
        let [public_key, k_enc, k_mic] = fields[..] else {
            return Err(format!(
                "expected peer as PUB,KENC,KMIC (got {} fields)",
                fields.len()
            ));
        };
        Ok(Self(PeerKeyEntry {
            public_key: parse_key32(public_key)?,
            k_enc: parse_hex::<16>(k_enc)?,
            k_mic: parse_hex::<16>(k_mic)?,
        }))
    }
}

/// Redacted: a peer entry is two pairwise secrets, and `--help`-adjacent
/// machinery has no business rendering them.
impl fmt::Debug for PeerArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerArg({}, <secrets>)", PublicKey(self.0.public_key))
    }
}

/// `dest-hint:HHHHHH`, `channel-id:HHHH`, or `pkt-type:N` (`:` or
/// whitespace between type and value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterArg(pub Filter);

impl FromStr for FilterArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let fields: Vec<&str> = text
            .split(|c: char| c == ':' || c.is_whitespace())
            .filter(|field| !field.is_empty())
            .collect();
        let [kind, value] = fields[..] else {
            return Err(format!("expected filter as TYPE:VALUE, got {text:?}"));
        };
        let filter = match kind {
            "dest-hint" => Filter::DestHint(parse_hex::<3>(value)?),
            "channel-id" => Filter::ChannelId(parse_hex::<2>(value)?),
            "pkt-type" => Filter::PktType(
                match value.strip_prefix("0x") {
                    Some(hex) => u8::from_str_radix(hex, 16),
                    None => value.parse(),
                }
                .map_err(|error| format!("pkt-type: {error}"))?,
            ),
            other => {
                return Err(format!(
                    "unknown filter type {other:?}; expected dest-hint, channel-id, or pkt-type"
                ));
            }
        };
        Ok(Self(filter))
    }
}

impl fmt::Display for FilterArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Filter::DestHint(hint) => write!(f, "dest-hint:{}", crate::output::hex(&hint)),
            Filter::ChannelId(id) => write!(f, "channel-id:{}", crate::output::hex(&id)),
            Filter::PktType(pkt_type) => write!(f, "pkt-type:{pkt_type}"),
        }
    }
}

/// A 6-digit BLE pairing PIN, or `clear` to remove the stored one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinArg(pub Option<u32>);

impl FromStr for PinArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == "clear" {
            return Ok(Self(None));
        }
        if text.len() == 6 && text.chars().all(|c| c.is_ascii_digit()) {
            return text
                .parse::<u32>()
                .map(|pin| Self(Some(pin)))
                .map_err(|error| error.to_string());
        }
        Err(format!("expected a 6-digit PIN or `clear`, got {text:?}"))
    }
}

/// A raw duty limit on the 0-65535 scale, or `off` to stop enforcing one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DutyLimitArg(pub u16);

impl FromStr for DutyLimitArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == "off" {
            return Ok(Self(u16::MAX));
        }
        text.parse::<u16>()
            .map(Self)
            .map_err(|_| format!("expected 0-65535 or `off`, got {text:?}"))
    }
}

/// Parse one region code, rejecting the empty element a stray comma
/// leaves behind. Anything that is not an airport code or `0x` literal
/// is hashed as a region name, so this only fails on empty input.
fn parse_region(text: &str) -> Result<RegionCode, String> {
    text.parse::<RegionCode>()
        .map_err(|error| format!("region {text:?}: {error}"))
}

/// A comma-separated region list, or `none` for the empty list — which
/// means "no regional restriction", not a region named "none".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionListArg(pub Vec<RegionCode>);

impl FromStr for RegionListArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.eq_ignore_ascii_case("none") {
            return Ok(Self(Vec::new()));
        }
        text.split(',')
            .map(parse_region)
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
}

/// One region code, or `none` to clear the setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptRegionArg(pub Option<RegionCode>);

impl FromStr for OptRegionArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.eq_ignore_ascii_case("none") {
            return Ok(Self(None));
        }
        parse_region(text).map(|code| Self(Some(code)))
    }
}

/// A received-signal floor in dBm, or `none` to forward regardless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinRssiArg(pub Option<i16>);

impl FromStr for MinRssiArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.eq_ignore_ascii_case("none") {
            return Ok(Self(None));
        }
        text.parse::<i16>()
            .map(|dbm| Self(Some(dbm)))
            .map_err(|_| format!("expected dBm or `none`, got {text:?}"))
    }
}

/// A signal-to-noise floor in dB, or `none` to forward regardless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinSnrArg(pub Option<i8>);

impl FromStr for MinSnrArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.eq_ignore_ascii_case("none") {
            return Ok(Self(None));
        }
        text.parse::<i8>()
            .map(|db| Self(Some(db)))
            .map_err(|_| format!("expected dB or `none`, got {text:?}"))
    }
}

/// An `on`/`off` switch, also accepting the `true`/`false` and `1`/`0`
/// spellings the provisioning file has always allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OnOffArg(pub bool);

impl FromStr for OnOffArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_bool(text).map(Self)
    }
}

/// A 16-bit value written in decimal or hex (`0x1424`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HexU16Arg(pub u16);

impl FromStr for HexU16Arg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_u32(text)?
            .try_into()
            .map(Self)
            .map_err(|_| format!("value out of 16-bit range: {text}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";

    #[test]
    fn parses_filters() {
        assert_eq!(
            "dest-hint:a1b2c3".parse::<FilterArg>().unwrap().0,
            Filter::DestHint([0xA1, 0xB2, 0xC3])
        );
        assert_eq!(
            "channel-id 9b68".parse::<FilterArg>().unwrap().0,
            Filter::ChannelId([0x9B, 0x68])
        );
        assert_eq!(
            "pkt-type:0x0a".parse::<FilterArg>().unwrap().0,
            Filter::PktType(10)
        );
        assert!("src-hint:aabbcc".parse::<FilterArg>().is_err());
        assert!("dest-hint:zzzzzz".parse::<FilterArg>().is_err());
    }

    #[test]
    fn pin_requires_six_digits_or_clear() {
        assert_eq!("042319".parse::<PinArg>().unwrap(), PinArg(Some(42_319)));
        assert_eq!("clear".parse::<PinArg>().unwrap(), PinArg(None));
        assert!("12345".parse::<PinArg>().is_err());
        assert!("1234567".parse::<PinArg>().is_err());
        assert!("abcdef".parse::<PinArg>().is_err());
    }

    #[test]
    fn duty_limit_accepts_the_raw_scale_and_off() {
        assert_eq!("655".parse::<DutyLimitArg>().unwrap().0, 655);
        assert_eq!("off".parse::<DutyLimitArg>().unwrap().0, u16::MAX);
        assert!("70000".parse::<DutyLimitArg>().is_err());
    }

    #[test]
    fn region_lists_parse_every_code_form() {
        assert_eq!(
            "SJC,0x7853,Rogue Valley"
                .parse::<RegionListArg>()
                .unwrap()
                .0,
            vec![
                RegionCode::from_iata("SJC").unwrap(),
                RegionCode::from_u16(0x7853),
                RegionCode::from_name("Rogue Valley"),
            ]
        );
        // `none` is the empty list, which means "no regional
        // restriction" — not a region literally named "none".
        assert_eq!("none".parse::<RegionListArg>().unwrap().0, Vec::new());
        assert!("SJC,".parse::<RegionListArg>().is_err());
    }

    #[test]
    fn gates_accept_their_clear_forms() {
        assert_eq!("-110".parse::<MinRssiArg>().unwrap().0, Some(-110));
        assert_eq!("none".parse::<MinRssiArg>().unwrap().0, None);
        assert_eq!("-7".parse::<MinSnrArg>().unwrap().0, Some(-7));
        assert_eq!("none".parse::<MinSnrArg>().unwrap().0, None);
        assert!("loud".parse::<MinRssiArg>().is_err());
        assert!("-40000".parse::<MinRssiArg>().is_err());
        assert!("-200".parse::<MinSnrArg>().is_err());
    }

    #[test]
    fn keys_accept_base58_and_hex() {
        let hex = KEY_HEX.parse::<KeyArg>().unwrap();
        assert_eq!(hex.0, [0xC4; 32]);
        let base58 = PublicKey(hex.0).to_string();
        assert_eq!(base58.parse::<KeyArg>().unwrap().0, [0xC4; 32]);
        assert!("nonsense".parse::<KeyArg>().is_err());
    }

    #[test]
    fn peer_entries_carry_both_pairwise_secrets() {
        let peer: PeerArg = format!("{KEY_HEX},{},{}", "e0".repeat(16), "50".repeat(16))
            .parse()
            .unwrap();
        assert_eq!(peer.0.public_key, [0xC4; 32]);
        assert_eq!(peer.0.k_enc, [0xE0; 16]);
        assert_eq!(peer.0.k_mic, [0x50; 16]);
        // Secrets are never rendered, not even by a debug format.
        assert!(!format!("{peer:?}").contains("e0e0"));
    }

    #[test]
    fn numbers_accept_hex_and_decimal() {
        assert_eq!(parse_u32("915000").unwrap(), 915_000);
        assert_eq!("0x1234".parse::<HexU16Arg>().unwrap().0, 0x1234);
        assert!("0x1ffff".parse::<HexU16Arg>().is_err());
    }
}
