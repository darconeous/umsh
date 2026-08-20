//! `FromStr`-backed value parsers for the command tree.
//!
//! clap turns each of these into a typed argument, so a bad value is
//! reported against the flag or positional that carried it instead of
//! being re-checked by hand after parsing. The parsing rules themselves
//! are unchanged from the hand-rolled tool these replaced.

use std::fmt;
use std::str::FromStr;

use umsh::core::{ChannelKey, MicSize, PublicKey, RegionCode, RouterHint};
use umsh::crypto::{ChannelNameError, MAX_CHANNEL_NAME_LEN};
use umsh::node::Channel;
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

/// A property value written as hex, of whatever length the property
/// takes. Empty is a value too — it is how a string property is cleared.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BytesArg(pub Vec<u8>);

impl FromStr for BytesArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        if !text.len().is_multiple_of(2) || !text.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "expected an even number of hex digits, got {text:?}"
            ));
        }
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).unwrap_or_default(), 16)
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<u8>, String>>()
            .map(Self)
    }
}

/// `PROP=HEX`: one entry of a write sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignArg(pub u32, pub Vec<u8>);

impl FromStr for AssignArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let Some((key, value)) = text.split_once('=') else {
            return Err(format!("expected PROP=HEX, got {text:?}"));
        };
        Ok(Self(parse_u32(key.trim())?, value.parse::<BytesArg>()?.0))
    }
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
/// two 32-byte pairwise secrets, hex.
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
            k_enc: parse_hex::<32>(k_enc)?,
            k_mic: parse_hex::<32>(k_mic)?,
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

/// Parse one region string — a short code, a name, or a `0x` literal.
/// The string is what the device stores; deriving it here only proves it
/// is within the bounds a device will accept, which rejects the empty
/// element a stray comma leaves behind and anything past 24 octets.
fn parse_region(text: &str) -> Result<String, String> {
    text.parse::<RegionCode>()
        .map_err(|error| format!("region {text:?}: {error}"))?;
    Ok(text.to_owned())
}

/// A comma-separated region list, or `none` for the empty list — which
/// means "no regional restriction", not a region named "none".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionListArg(pub Vec<String>);

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

/// One region string, for the entry-at-a-time edits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionArg(pub String);

impl FromStr for RegionArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse_region(text).map(Self)
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
        // The default region is stored as a code, so it derives here.
        text.parse::<RegionCode>()
            .map(|code| Self(Some(code)))
            .map_err(|error| format!("region {text:?}: {error}"))
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

/// A MIC size, written as its byte length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MicArg(pub MicSize);

impl FromStr for MicArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "4" => Ok(Self(MicSize::Mic4)),
            "8" => Ok(Self(MicSize::Mic8)),
            "12" => Ok(Self(MicSize::Mic12)),
            "16" => Ok(Self(MicSize::Mic16)),
            other => Err(format!("expected 4, 8, 12, or 16, got {other:?}")),
        }
    }
}

/// One region code to stamp on an outgoing frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionCodeArg(pub RegionCode);

impl FromStr for RegionCodeArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse::<RegionCode>()
            .map(Self)
            .map_err(|error| format!("region {text:?}: {error}"))
    }
}

/// A comma-separated source route, first hop first.
///
/// Each hop is either the four hex digits of a router hint, as a capture or
/// a trace route renders it, or a full public key to derive the hint from.
/// An empty route is not a way to say "flood"—`--flood` is—so it is
/// rejected rather than quietly meaning something else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteArg(pub Vec<RouterHint>);

impl FromStr for RouteArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let hops = text
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|hop| !hop.is_empty())
            .map(|hop| {
                if hop.len() == 4 {
                    parse_hex::<2>(hop).map(RouterHint)
                } else {
                    parse_key32(hop)
                        .map(|key| RouterHint::from_public_key(&PublicKey(key)))
                        .map_err(|error| {
                            format!("hop {hop:?}: 4 hex digits or a full key: {error}")
                        })
                }
            })
            .collect::<Result<Vec<_>, String>>()?;
        if hops.is_empty() {
            return Err(String::from("a source route needs at least one hop"));
        }
        // The MAC rejects a longer route too; catching it here attributes the
        // error to the flag that carried it.
        if hops.len() > MAX_ROUTE_HOPS {
            return Err(format!(
                "a source route carries at most {MAX_ROUTE_HOPS} hops, got {}",
                hops.len()
            ));
        }
        Ok(Self(hops))
    }
}

/// The MAC's ceiling on an explicit source route.
const MAX_ROUTE_HOPS: usize = 15;

/// A channel, named or given by its raw 32-byte key.
///
/// A key is spelled the same way a public key is, so anything that parses as
/// one is taken for a private channel key and everything else is a channel
/// name. The name of a key-given channel is its own derived identifier, since
/// there is no name to show and the key must never be printed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelArg(pub Channel);

impl FromStr for ChannelArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Ok(key) = parse_key32(text) {
            let channel = Channel::private(ChannelKey(key), "");
            let named = Channel::private(
                ChannelKey(key),
                &crate::output::hex(&channel.channel_id().0),
            );
            return Ok(Self(named));
        }
        Channel::named(text).map(Self).map_err(|error| match error {
            ChannelNameError::NotAscii => {
                format!("channel {text:?}: names must be ASCII")
            }
            ChannelNameError::TooLong => {
                format!("channel {text:?}: names are at most {MAX_CHANNEL_NAME_LEN} characters")
            }
        })
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
    fn region_lists_keep_every_string_form_as_written() {
        assert_eq!(
            "SJC,0x7853,Rogue Valley"
                .parse::<RegionListArg>()
                .unwrap()
                .0,
            vec!["SJC", "0x7853", "Rogue Valley"]
        );
        // `none` is the empty list, which means "no regional
        // restriction" — not a region literally named "none".
        assert_eq!(
            "none".parse::<RegionListArg>().unwrap().0,
            Vec::<String>::new()
        );
        assert!("SJC,".parse::<RegionListArg>().is_err());
        // The device's bounds are enforced here, not a round trip later.
        assert!("A".repeat(25).parse::<RegionArg>().is_err());
        assert_eq!(
            "Rogue Valley".parse::<RegionArg>().unwrap().0,
            "Rogue Valley"
        );
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
        let peer: PeerArg = format!("{KEY_HEX},{},{}", "e0".repeat(32), "50".repeat(32))
            .parse()
            .unwrap();
        assert_eq!(peer.0.public_key, [0xC4; 32]);
        assert_eq!(peer.0.k_enc, [0xE0; 32]);
        assert_eq!(peer.0.k_mic, [0x50; 32]);
        // Secrets are never rendered, not even by a debug format.
        assert!(!format!("{peer:?}").contains("e0e0"));
    }

    #[test]
    fn mic_sizes_are_named_by_their_byte_length() {
        assert_eq!("4".parse::<MicArg>().unwrap().0, MicSize::Mic4);
        assert_eq!("16".parse::<MicArg>().unwrap().0, MicSize::Mic16);
        assert!("10".parse::<MicArg>().is_err());
        assert!("mic8".parse::<MicArg>().is_err());
    }

    #[test]
    fn routes_take_hints_or_whole_keys() {
        let route = format!("a1b2,{KEY_HEX}").parse::<RouteArg>().unwrap();
        assert_eq!(
            route.0,
            vec![RouterHint([0xA1, 0xB2]), RouterHint([0xC4, 0xC4])]
        );
        // An empty route would silently mean "flood", which is a separate
        // flag, so it is an error rather than a shorthand.
        assert!("".parse::<RouteArg>().is_err());
        assert!("a1b".parse::<RouteArg>().is_err());
        assert!(vec!["a1b2"; 16].join(",").parse::<RouteArg>().is_err());
    }

    #[test]
    fn channels_come_from_a_name_or_a_raw_key() {
        let named = "public".parse::<ChannelArg>().unwrap();
        assert_eq!(named.0, Channel::named("public").unwrap());
        assert_eq!(named.0.name(), "public");

        let private = KEY_HEX.parse::<ChannelArg>().unwrap();
        assert_eq!(private.0.key().0, [0xC4; 32]);
        // The key is never the display name.
        assert!(!private.0.name().contains("c4c4"));
        assert_eq!(
            private.0.name(),
            crate::output::hex(&private.0.channel_id().0)
        );
    }

    #[test]
    fn numbers_accept_hex_and_decimal() {
        assert_eq!(parse_u32("915000").unwrap(), 915_000);
        assert_eq!("0x1234".parse::<HexU16Arg>().unwrap().0, 0x1234);
        assert!("0x1ffff".parse::<HexU16Arg>().is_err());
    }
}
