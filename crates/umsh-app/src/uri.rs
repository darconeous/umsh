use lwuri::prelude::*;

use crate::util::{copy_into, push_byte};
use crate::{EncodeError, ParseError};

/// Parsed `umsh:` URI.
///
/// The crate currently recognizes node URIs, named-channel URIs, and direct
/// channel-key URIs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UmshUri<'a> {
    /// `umsh:n:` URI.
    Node(NodeUri<'a>),
    /// `umsh:cs:` URI.
    ChannelByName(ChannelNameUri<'a>),
    /// `umsh:ck:` URI.
    ChannelByKey(ChannelKeyUri<'a>),
}

/// Parsed node URI.
///
/// The optional `identity_data` tail is preserved verbatim rather than decoded so
/// callers can decide how to interpret or verify an embedded identity bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeUri<'a> {
    /// Base58-decoded node public key.
    pub public_key: umsh_core::PublicKey,
    /// Optional colon-delimited suffix after the public key.
    pub identity_data: Option<&'a str>,
}

/// Advisory channel metadata decoded from a URI query string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelParams<'a> {
    /// Human-readable display name.
    pub display_name: Option<&'a str>,
    /// Recommended maximum flood-hop count.
    pub max_flood_hops: Option<u8>,
    /// Suggested region tag.
    pub region: Option<&'a str>,
    /// Raw query string, preserved so unrecognized keys are not lost.
    pub raw_query: Option<&'a str>,
}

/// Parsed named-channel URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelNameUri<'a> {
    /// Channel derivation string.
    pub name: &'a str,
    /// Advisory query parameters.
    pub params: ChannelParams<'a>,
}

/// Parsed direct-key channel URI.
#[derive(Clone)]
pub struct ChannelKeyUri<'a> {
    /// Raw 32-byte channel key.
    pub key: umsh_core::ChannelKey,
    /// Advisory query parameters.
    pub params: ChannelParams<'a>,
}

impl core::fmt::Debug for ChannelKeyUri<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelKeyUri")
            .field("key", &&self.key.0[..])
            .field("params", &self.params)
            .finish()
    }
}

impl PartialEq for ChannelKeyUri<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.key.0 == other.key.0 && self.params == other.params
    }
}

impl Eq for ChannelKeyUri<'_> {}

/// Parse a `umsh:` URI reference.
///
/// The input must already be parsed as a [`lwuri::UriRef`]. This function only
/// accepts the `umsh` scheme.
///
/// # Example
///
/// ```rust
/// use lwuri::UriRef;
/// use umsh_app::{parse_umsh_uri, UmshUri};
///
/// let uri = UriRef::from_str("umsh:cs:Public?n=Local").unwrap();
/// match parse_umsh_uri(uri).unwrap() {
///     UmshUri::ChannelByName(channel) => assert_eq!(channel.name, "Public"),
///     _ => panic!("unexpected uri kind"),
/// }
/// ```
pub fn parse_umsh_uri<'a>(uri: &'a UriRef) -> Result<UmshUri<'a>, ParseError> {
    if uri.scheme() != Some("umsh") {
        return Err(ParseError::InvalidUri);
    }

    let mut parts = uri.raw_path().splitn(3, ':');
    let kind = parts.next().ok_or(ParseError::InvalidUri)?;
    let value = parts.next().ok_or(ParseError::InvalidUri)?;
    let tail = parts.next();
    let params = parse_channel_params(uri)?;

    match kind {
        "n" => Ok(UmshUri::Node(NodeUri {
            public_key: umsh_core::PublicKey(decode_base58_32(value)?),
            identity_data: tail,
        })),
        "cs" => Ok(UmshUri::ChannelByName(ChannelNameUri { name: value, params })),
        "ck" => Ok(UmshUri::ChannelByKey(ChannelKeyUri {
            key: umsh_core::ChannelKey(decode_base58_32(value)?),
            params,
        })),
        _ => Err(ParseError::InvalidUri),
    }
}

fn parse_channel_params<'a>(uri: &'a UriRef) -> Result<ChannelParams<'a>, ParseError> {
    let mut display_name = None;
    let mut max_flood_hops = None;
    let mut region = None;

    for (key, value) in uri.raw_query_key_values() {
        match key {
            "n" => display_name = Some(value),
            "mh" => {
                max_flood_hops = Some(value.parse::<u8>().map_err(|_| ParseError::InvalidUri)?);
            }
            "r" => region = Some(value),
            _ => {}
        }
    }

    Ok(ChannelParams {
        display_name,
        max_flood_hops,
        region,
        raw_query: uri.raw_query(),
    })
}

fn decode_base58_32(input: &str) -> Result<[u8; 32], ParseError> {
    let mut out = [0u8; 32];
    let len = bs58::decode(input)
        .onto(&mut out)
        .map_err(|_| ParseError::InvalidBase58)?;
    if len != 32 {
        return Err(ParseError::InvalidLength {
            expected: 32,
            actual: len,
        });
    }
    Ok(out)
}

pub fn format_node_uri(key: &umsh_core::PublicKey, buf: &mut [u8]) -> Result<usize, EncodeError> {
    let mut pos = 0usize;
    copy_into(buf, &mut pos, b"umsh:n:")?;
    let written = bs58::encode(key.0)
        .onto(&mut buf[pos..])
        .map_err(|_| EncodeError::BufferTooSmall)?;
    Ok(pos + written)
}

/// Format a named-channel URI of the form `umsh:cs:<name>`.
pub fn format_channel_name_uri(name: &str, buf: &mut [u8]) -> Result<usize, EncodeError> {
    let mut pos = 0usize;
    copy_into(buf, &mut pos, b"umsh:cs:")?;
    copy_into(buf, &mut pos, name.as_bytes())?;
    Ok(pos)
}

/// Format a direct-key channel URI of the form `umsh:ck:<base58>`.
pub fn format_channel_key_uri(
    key: &umsh_core::ChannelKey,
    buf: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut pos = 0usize;
    copy_into(buf, &mut pos, b"umsh:ck:")?;
    let written = bs58::encode(&key.0)
        .onto(&mut buf[pos..])
        .map_err(|_| EncodeError::BufferTooSmall)?;
    Ok(pos + written)
}

/// Format a named-channel URI and append recognized advisory query parameters.
pub fn format_channel_name_uri_with_params(
    name: &str,
    params: &ChannelParams<'_>,
    buf: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut pos = format_channel_name_uri(name, buf)?;
    write_params(params, buf, &mut pos)?;
    Ok(pos)
}

fn write_params(params: &ChannelParams<'_>, buf: &mut [u8], pos: &mut usize) -> Result<(), EncodeError> {
    let mut wrote = false;
    if let Some(display_name) = params.display_name {
        push_byte(buf, pos, if wrote { b';' } else { b'?' })?;
        wrote = true;
        copy_into(buf, pos, b"n=")?;
        copy_into(buf, pos, display_name.as_bytes())?;
    }
    if let Some(max_flood_hops) = params.max_flood_hops {
        push_byte(buf, pos, if wrote { b';' } else { b'?' })?;
        wrote = true;
        copy_into(buf, pos, b"mh=")?;
        let mut tmp = [0u8; 3];
        let digits = itoa_u8(max_flood_hops, &mut tmp);
        copy_into(buf, pos, digits)?;
    }
    if let Some(region) = params.region {
        push_byte(buf, pos, if wrote { b';' } else { b'?' })?;
        copy_into(buf, pos, b"r=")?;
        copy_into(buf, pos, region.as_bytes())?;
    }
    Ok(())
}

fn itoa_u8(value: u8, buf: &mut [u8; 3]) -> &[u8] {
    if value >= 100 {
        buf[0] = b'0' + (value / 100);
        buf[1] = b'0' + ((value / 10) % 10);
        buf[2] = b'0' + (value % 10);
        &buf[..3]
    } else if value >= 10 {
        buf[0] = b'0' + (value / 10);
        buf[1] = b'0' + (value % 10);
        &buf[..2]
    } else {
        buf[0] = b'0' + value;
        &buf[..1]
    }
}