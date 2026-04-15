#![cfg_attr(not(feature = "std"), no_std)]

//! UMSH URI parsing and formatting helpers.

extern crate alloc;

use alloc::string::String;
use core::fmt;

use lwuri::prelude::*;

/// Error returned when parsing or formatting `umsh:` URIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidUtf8,
    InvalidUri,
    InvalidBase58,
    InvalidLength { expected: usize, actual: usize },
    BufferTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Parsed `umsh:` URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UmshUri<'a> {
    Node(NodeUri<'a>),
    ChannelByName(ChannelNameUri<'a>),
    ChannelByKey(ChannelKeyUri<'a>),
}

/// Parsed node URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeUri<'a> {
    pub public_key: umsh_core::PublicKey,
    pub identity_data: Option<&'a str>,
}

/// Advisory channel metadata decoded from a URI query string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelParams<'a> {
    pub display_name: Option<&'a str>,
    pub max_flood_hops: Option<u8>,
    pub region: Option<&'a str>,
    pub raw_query: Option<&'a str>,
}

/// Parsed named-channel URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelNameUri<'a> {
    pub name: &'a str,
    pub params: ChannelParams<'a>,
}

/// Parsed direct-key channel URI.
#[derive(Clone)]
pub struct ChannelKeyUri<'a> {
    pub key: umsh_core::ChannelKey,
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
pub fn parse_umsh_uri<'a>(uri: &'a UriRef) -> Result<UmshUri<'a>, Error> {
    if uri.scheme() != Some("umsh") {
        return Err(Error::InvalidUri);
    }

    let mut parts = uri.raw_path().splitn(3, ':');
    let kind = parts.next().ok_or(Error::InvalidUri)?;
    let value = parts.next().ok_or(Error::InvalidUri)?;
    let tail = parts.next();
    let params = parse_channel_params(uri)?;

    match kind {
        "n" => Ok(UmshUri::Node(NodeUri {
            public_key: umsh_core::PublicKey(decode_base58_32(value)?),
            identity_data: tail,
        })),
        "cs" => Ok(UmshUri::ChannelByName(ChannelNameUri {
            name: value,
            params,
        })),
        "ck" => Ok(UmshUri::ChannelByKey(ChannelKeyUri {
            key: umsh_core::ChannelKey(decode_base58_32(value)?),
            params,
        })),
        _ => Err(Error::InvalidUri),
    }
}

fn parse_channel_params<'a>(uri: &'a UriRef) -> Result<ChannelParams<'a>, Error> {
    let mut display_name = None;
    let mut max_flood_hops = None;
    let mut region = None;

    for (key, value) in uri.raw_query_key_values() {
        match key {
            "n" => display_name = Some(value),
            "mh" => {
                max_flood_hops = Some(value.parse::<u8>().map_err(|_| Error::InvalidUri)?);
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

fn decode_base58_32(input: &str) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    let len = bs58::decode(input)
        .onto(&mut out)
        .map_err(|_| Error::InvalidBase58)?;
    if len != 32 {
        return Err(Error::InvalidLength {
            expected: 32,
            actual: len,
        });
    }
    Ok(out)
}

/// Parse a base58-encoded public key.
pub fn parse_public_key_base58(input: &str) -> Result<umsh_core::PublicKey, Error> {
    Ok(umsh_core::PublicKey(decode_base58_32(input)?))
}

/// Parse a base58-encoded channel key.
pub fn parse_channel_key_base58(input: &str) -> Result<umsh_core::ChannelKey, Error> {
    Ok(umsh_core::ChannelKey(decode_base58_32(input)?))
}

/// Encode a public key as base58.
pub fn encode_public_key_base58(key: &umsh_core::PublicKey) -> String {
    bs58::encode(key.0).into_string()
}

/// Encode a channel key as base58.
pub fn encode_channel_key_base58(key: &umsh_core::ChannelKey) -> String {
    bs58::encode(key.0).into_string()
}

pub fn format_node_uri(key: &umsh_core::PublicKey, buf: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0usize;
    copy_into(buf, &mut pos, b"umsh:n:")?;
    let written = bs58::encode(key.0)
        .onto(&mut buf[pos..])
        .map_err(|_| Error::BufferTooSmall)?;
    Ok(pos + written)
}

pub fn format_channel_name_uri(name: &str, buf: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0usize;
    copy_into(buf, &mut pos, b"umsh:cs:")?;
    copy_into(buf, &mut pos, name.as_bytes())?;
    Ok(pos)
}

pub fn format_channel_key_uri(key: &umsh_core::ChannelKey, buf: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0usize;
    copy_into(buf, &mut pos, b"umsh:ck:")?;
    let written = bs58::encode(&key.0)
        .onto(&mut buf[pos..])
        .map_err(|_| Error::BufferTooSmall)?;
    Ok(pos + written)
}

pub fn format_channel_name_uri_with_params(
    name: &str,
    params: &ChannelParams<'_>,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let mut pos = format_channel_name_uri(name, buf)?;
    write_params(params, buf, &mut pos)?;
    Ok(pos)
}

fn write_params(params: &ChannelParams<'_>, buf: &mut [u8], pos: &mut usize) -> Result<(), Error> {
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
        let digits = write_decimal_u8(max_flood_hops, &mut tmp);
        copy_into(buf, pos, &tmp[..digits])?;
    }
    if let Some(region) = params.region {
        push_byte(buf, pos, if wrote { b';' } else { b'?' })?;
        copy_into(buf, pos, b"r=")?;
        copy_into(buf, pos, region.as_bytes())?;
    }
    Ok(())
}

fn write_decimal_u8(value: u8, out: &mut [u8; 3]) -> usize {
    if value >= 100 {
        out[0] = b'0' + value / 100;
        out[1] = b'0' + (value / 10) % 10;
        out[2] = b'0' + value % 10;
        3
    } else if value >= 10 {
        out[0] = b'0' + value / 10;
        out[1] = b'0' + value % 10;
        2
    } else {
        out[0] = b'0' + value;
        1
    }
}

fn copy_into(dst: &mut [u8], pos: &mut usize, src: &[u8]) -> Result<(), Error> {
    if dst.len().saturating_sub(*pos) < src.len() {
        return Err(Error::BufferTooSmall);
    }
    dst[*pos..*pos + src.len()].copy_from_slice(src);
    *pos += src.len();
    Ok(())
}

fn push_byte(dst: &mut [u8], pos: &mut usize, byte: u8) -> Result<(), Error> {
    copy_into(dst, pos, &[byte])
}

#[cfg(test)]
mod tests {
    use lwuri::UriRef;

    use super::*;

    #[test]
    fn uri_parse_and_format_cover_node_channel_name_and_key() {
        let key = umsh_core::PublicKey([0x33; 32]);
        let mut buf = [0u8; 128];
        let node_len = format_node_uri(&key, &mut buf).unwrap();
        let node_uri = UriRef::from_str(core::str::from_utf8(&buf[..node_len]).unwrap()).unwrap();
        match parse_umsh_uri(node_uri).unwrap() {
            UmshUri::Node(parsed) => assert_eq!(parsed.public_key, key),
            _ => panic!("expected node uri"),
        }

        let params = ChannelParams {
            display_name: Some("Local"),
            max_flood_hops: Some(6),
            region: Some("Eugine"),
            raw_query: None,
        };
        let channel_name_len =
            format_channel_name_uri_with_params("Public", &params, &mut buf).unwrap();
        let channel_name_uri =
            UriRef::from_str(core::str::from_utf8(&buf[..channel_name_len]).unwrap()).unwrap();
        match parse_umsh_uri(channel_name_uri).unwrap() {
            UmshUri::ChannelByName(parsed) => {
                assert_eq!(parsed.name, "Public");
                assert_eq!(parsed.params.display_name, Some("Local"));
                assert_eq!(parsed.params.max_flood_hops, Some(6));
                assert_eq!(parsed.params.region, Some("Eugine"));
            }
            _ => panic!("expected channel name uri"),
        }

        let channel_key = umsh_core::ChannelKey([0x44; 32]);
        let channel_key_len = format_channel_key_uri(&channel_key, &mut buf).unwrap();
        let channel_key_uri =
            UriRef::from_str(core::str::from_utf8(&buf[..channel_key_len]).unwrap()).unwrap();
        match parse_umsh_uri(channel_key_uri).unwrap() {
            UmshUri::ChannelByKey(parsed) => assert_eq!(parsed.key.0, channel_key.0),
            _ => panic!("expected channel key uri"),
        }
    }

    #[test]
    fn base58_key_helpers_round_trip() {
        let public_key = umsh_core::PublicKey([0x33; 32]);
        let channel_key = umsh_core::ChannelKey([0x77; 32]);

        let public_text = encode_public_key_base58(&public_key);
        let channel_text = encode_channel_key_base58(&channel_key);

        assert_eq!(parse_public_key_base58(&public_text).unwrap(), public_key);
        assert_eq!(
            parse_channel_key_base58(&channel_text).unwrap(),
            channel_key
        );
    }
}
