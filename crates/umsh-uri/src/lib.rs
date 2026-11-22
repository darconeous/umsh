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
///
/// String fields are the raw, still-percent-encoded slices borrowed from the
/// URI, because decoding needs an owned buffer this borrow cannot provide. Run
/// them through [`decode_percent`] before display.
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
///
/// The scheme is matched without regard to ASCII case; the kind, the
/// base58 digits, and the parameter names are case-sensitive
/// (UEP-0019 §syntax).
pub fn parse_umsh_uri<'a>(uri: &'a UriRef) -> Result<UmshUri<'a>, Error> {
    if !uri
        .scheme()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("umsh"))
    {
        return Err(Error::InvalidUri);
    }

    let mut parts = uri.raw_path().splitn(3, ':');
    let kind = parts.next().ok_or(Error::InvalidUri)?;
    let value = parts.next().ok_or(Error::InvalidUri)?;
    let tail = parts.next();

    match kind {
        "n" => Ok(UmshUri::Node(NodeUri {
            public_key: umsh_core::PublicKey(decode_base58_32(value)?),
            identity_data: tail,
        })),
        // A group URI has no third segment: `umsh:gs:a:b` would otherwise
        // join the group `a`, not the one its sender meant. `cs` and `ck`
        // are deprecated spellings of `gs` and `gk`.
        "gs" | "cs" if tail.is_none() && !value.is_empty() => {
            Ok(UmshUri::ChannelByName(ChannelNameUri {
                name: value,
                params: parse_channel_params(uri),
            }))
        }
        "gk" | "ck" if tail.is_none() => Ok(UmshUri::ChannelByKey(ChannelKeyUri {
            key: umsh_core::ChannelKey(decode_base58_32(value)?),
            params: parse_channel_params(uri),
        })),
        _ => Err(Error::InvalidUri),
    }
}

/// `text` after a leading `umsh:`, the scheme matched without regard to
/// ASCII case. For entry points that decide whether typed or pasted text is
/// a URI before parsing it.
pub fn strip_scheme(text: &str) -> Option<&str> {
    let scheme = text.get(..5)?;
    scheme
        .eq_ignore_ascii_case("umsh:")
        .then(|| &text[scheme.len()..])
}

/// `rest`, the text after `umsh:`, with a group-name kind (`gs:`, or the
/// deprecated `cs:`) removed.
pub fn strip_group_name_kind(rest: &str) -> Option<&str> {
    rest.strip_prefix("gs:")
        .or_else(|| rest.strip_prefix("cs:"))
}

/// `rest`, the text after `umsh:`, with a group-key kind (`gk:`, or the
/// deprecated `ck:`) removed.
pub fn strip_group_key_kind(rest: &str) -> Option<&str> {
    rest.strip_prefix("gk:")
        .or_else(|| rest.strip_prefix("ck:"))
}

/// Parse `text` as a `umsh:` URI.
pub fn parse_umsh_str(text: &str) -> Result<UmshUri<'_>, Error> {
    let uri = UriRef::from_str(text).map_err(|_| Error::InvalidUri)?;
    parse_umsh_uri(uri)
}

/// The most flood hops a group URI's `mh` may name: the flood radius.
const MAX_SUGGESTED_FLOOD_HOPS: u8 = 15;

/// A parameter that is malformed is left out, never a reason to reject the
/// URI (UEP-0019 §parameters); a repeated one takes its last occurrence.
fn parse_channel_params<'a>(uri: &'a UriRef) -> ChannelParams<'a> {
    let mut display_name = None;
    let mut max_flood_hops = None;
    let mut region = None;

    for (key, value) in uri.raw_query_key_values() {
        match key {
            "n" => display_name = Some(value),
            "mh" => max_flood_hops = parse_flood_hops(value),
            "r" => region = Some(value),
            _ => {}
        }
    }

    ChannelParams {
        display_name,
        max_flood_hops,
        region,
        raw_query: uri.raw_query(),
    }
}

/// One or two decimal digits no greater than the flood radius.
fn parse_flood_hops(value: &str) -> Option<u8> {
    if value.is_empty() || value.len() > 2 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value
        .parse::<u8>()
        .ok()
        .filter(|hops| *hops <= MAX_SUGGESTED_FLOOD_HOPS)
}

fn decode_base58_32(input: &str) -> Result<[u8; 32], Error> {
    umsh_core::base58::decode(input.as_bytes()).map_err(|err| match err {
        umsh_core::AddressParseError::InvalidLength => Error::InvalidLength {
            expected: umsh_core::base58::ENCODED_LEN,
            actual: input.len(),
        },
        _ => Error::InvalidBase58,
    })
}

fn encode_base58_32(bytes: &[u8; 32]) -> String {
    umsh_core::base58::encode(bytes)
        .iter()
        .map(|&digit| char::from(digit))
        .collect()
}

/// Base58 digit alphabet (Bitcoin variant), matching `umsh_core::base58`.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode arbitrary-length bytes as base58 with no fixed width; leading
/// zero bytes render as leading `1` digits. This is the encoding of the
/// optional node-identity bundle segment of a node URI (the 32-byte key
/// segment keeps its fixed 44-digit form).
pub fn encode_base58_bytes(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    let mut digits: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for &byte in &bytes[zeros..] {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let acc = (u32::from(*digit) << 8) + carry;
            *digit = (acc % 58) as u8;
            carry = acc / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &digit in digits.iter().rev() {
        out.push(char::from(BASE58_ALPHABET[usize::from(digit)]));
    }
    out
}

/// The longest base58 text [`decode_base58_bytes`] accepts. Decoding is
/// quadratic in the input, and the text arrives from QR codes and links;
/// every payload a URI carries encodes to far less than this.
pub const MAX_BASE58_TEXT: usize = 2048;

/// Decode a variable-length base58 string produced by
/// [`encode_base58_bytes`].
pub fn decode_base58_bytes(input: &str) -> Result<alloc::vec::Vec<u8>, Error> {
    let bytes = input.as_bytes();
    if bytes.len() > MAX_BASE58_TEXT {
        return Err(Error::InvalidLength {
            expected: MAX_BASE58_TEXT,
            actual: bytes.len(),
        });
    }
    let zeros = bytes.iter().take_while(|&&byte| byte == b'1').count();
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for &digit in &bytes[zeros..] {
        let value = BASE58_ALPHABET
            .iter()
            .position(|&c| c == digit)
            .ok_or(Error::InvalidBase58)? as u32;
        let mut carry = value;
        for byte in out.iter_mut() {
            let acc = u32::from(*byte) * 58 + carry;
            *byte = acc as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            out.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    let mut result = alloc::vec![0u8; zeros];
    result.extend(out.iter().rev());
    Ok(result)
}

/// Parse a base58-encoded public key.
pub fn parse_public_key_base58(input: &str) -> Result<umsh_core::PublicKey, Error> {
    Ok(umsh_core::PublicKey(decode_base58_32(input)?))
}

/// Parse a base58-encoded channel key.
pub fn parse_channel_key_base58(input: &str) -> Result<umsh_core::ChannelKey, Error> {
    Ok(umsh_core::ChannelKey(decode_base58_32(input)?))
}

/// Encode a public key as fixed-width base58.
pub fn encode_public_key_base58(key: &umsh_core::PublicKey) -> String {
    encode_base58_32(&key.0)
}

/// Encode a channel key as fixed-width base58.
pub fn encode_channel_key_base58(key: &umsh_core::ChannelKey) -> String {
    encode_base58_32(&key.0)
}

pub fn format_node_uri(key: &umsh_core::PublicKey, buf: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0usize;
    copy_into(buf, &mut pos, b"umsh:n:")?;
    copy_into(buf, &mut pos, &umsh_core::base58::encode(&key.0))?;
    Ok(pos)
}

/// Format a named-channel URI.
///
/// The name is percent-encoded, so a name containing a space or other
/// non-unreserved character still yields a parseable URI. Parsers recover the
/// original with [`decode_percent`] before canonicalizing it.
pub fn format_channel_name_uri(name: &str, buf: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0usize;
    copy_into(buf, &mut pos, b"umsh:gs:")?;
    write_percent_encoded(buf, &mut pos, name)?;
    Ok(pos)
}

pub fn format_channel_key_uri(key: &umsh_core::ChannelKey, buf: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0usize;
    copy_into(buf, &mut pos, b"umsh:gk:")?;
    copy_into(buf, &mut pos, &umsh_core::base58::encode(&key.0))?;
    Ok(pos)
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

pub fn format_channel_key_uri_with_params(
    key: &umsh_core::ChannelKey,
    params: &ChannelParams<'_>,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let mut pos = format_channel_key_uri(key, buf)?;
    write_params(params, buf, &mut pos)?;
    Ok(pos)
}

/// Write the parameters a group URI carries (UEP-0019 §parameters). An empty
/// display name says nothing and is left out; an `mh` above the flood radius
/// is one a sender must not write.
fn write_params(params: &ChannelParams<'_>, buf: &mut [u8], pos: &mut usize) -> Result<(), Error> {
    if params
        .max_flood_hops
        .is_some_and(|hops| hops > MAX_SUGGESTED_FLOOD_HOPS)
    {
        return Err(Error::InvalidUri);
    }
    let mut wrote = false;
    if let Some(display_name) = params.display_name.filter(|name| !name.is_empty()) {
        push_byte(buf, pos, if wrote { b';' } else { b'?' })?;
        wrote = true;
        copy_into(buf, pos, b"n=")?;
        write_percent_encoded(buf, pos, display_name)?;
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
        write_percent_encoded(buf, pos, region)?;
    }
    Ok(())
}

/// Whether `byte` may appear literally in a parameter value.
///
/// RFC 3986 unreserved only. That is stricter than the query grammar allows,
/// but a channel display name is arbitrary user text and the separators this
/// crate writes (`?`, `;`, `=`) must never appear unescaped inside a value.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn write_percent_encoded(buf: &mut [u8], pos: &mut usize, value: &str) -> Result<(), Error> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in value.as_bytes() {
        if is_unreserved(byte) {
            push_byte(buf, pos, byte)?;
        } else {
            copy_into(
                buf,
                pos,
                &[b'%', HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]],
            )?;
        }
    }
    Ok(())
}

/// Decode percent-escapes in a URI component.
///
/// Parsed [`ChannelParams`] borrow raw slices from the URI; this turns one into
/// displayable text. An escape that is truncated or not valid hex is preserved
/// verbatim rather than rejected, and invalid UTF-8 is reported.
pub fn decode_percent(value: &str) -> Result<String, Error> {
    let bytes = value.as_bytes();
    let mut out = alloc::vec::Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match (bytes[index], bytes.get(index + 1), bytes.get(index + 2)) {
            (b'%', Some(high), Some(low)) => match (hex_value(*high), hex_value(*low)) {
                (Some(high), Some(low)) => {
                    out.push((high << 4) | low);
                    index += 3;
                }
                _ => {
                    out.push(b'%');
                    index += 1;
                }
            },
            (byte, _, _) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidUtf8)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
    fn variable_base58_round_trips_and_matches_fixed_width() {
        for bytes in [
            &[][..],
            &[0u8][..],
            &[0, 0, 1, 2, 3][..],
            &[0xFF; 100][..],
            b"role-caps-options-and-signature".as_slice(),
        ] {
            let encoded = encode_base58_bytes(bytes);
            assert_eq!(decode_base58_bytes(&encoded).unwrap(), bytes);
        }

        // A 32-byte value with no leading zeros must agree with the
        // fixed-width address codec (which only differs by `1` padding).
        let key = [0xFFu8; 32];
        let fixed: alloc::string::String = umsh_core::base58::encode(&key)
            .into_iter()
            .map(char::from)
            .collect();
        assert_eq!(encode_base58_bytes(&key), fixed);

        assert_eq!(
            decode_base58_bytes("not-base58!"),
            Err(Error::InvalidBase58)
        );
    }

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
    fn channel_key_uri_carries_invitation_params() {
        let channel_key = umsh_core::ChannelKey([0x55; 32]);
        let params = ChannelParams {
            display_name: Some("Trail Crew"),
            max_flood_hops: Some(3),
            region: Some("SJC"),
            raw_query: None,
        };
        let mut buf = [0u8; 128];
        let len = format_channel_key_uri_with_params(&channel_key, &params, &mut buf).unwrap();
        let uri = UriRef::from_str(core::str::from_utf8(&buf[..len]).unwrap()).unwrap();
        match parse_umsh_uri(uri).unwrap() {
            UmshUri::ChannelByKey(parsed) => {
                assert_eq!(parsed.key.0, channel_key.0);
                // Parsed params borrow the raw slice, so the space stays escaped
                // until the consumer decodes it.
                assert_eq!(parsed.params.display_name, Some("Trail%20Crew"));
                assert_eq!(
                    decode_percent(parsed.params.display_name.unwrap()).unwrap(),
                    "Trail Crew"
                );
                assert_eq!(parsed.params.max_flood_hops, Some(3));
                assert_eq!(parsed.params.region, Some("SJC"));
            }
            _ => panic!("expected channel key uri"),
        }
    }

    #[test]
    fn param_values_escape_separators_and_round_trip() {
        // A display name containing this crate's own separators must not be
        // able to forge additional parameters.
        let channel_key = umsh_core::ChannelKey([0x88; 32]);
        let hostile = "a?b;c=d&e/f";
        let params = ChannelParams {
            display_name: Some(hostile),
            max_flood_hops: None,
            region: None,
            raw_query: None,
        };
        let mut buf = [0u8; 160];
        let len = format_channel_key_uri_with_params(&channel_key, &params, &mut buf).unwrap();
        let uri = UriRef::from_str(core::str::from_utf8(&buf[..len]).unwrap()).unwrap();
        match parse_umsh_uri(uri).unwrap() {
            UmshUri::ChannelByKey(parsed) => {
                assert_eq!(parsed.params.max_flood_hops, None);
                assert_eq!(parsed.params.region, None);
                assert_eq!(
                    decode_percent(parsed.params.display_name.unwrap()).unwrap(),
                    hostile
                );
            }
            _ => panic!("expected channel key uri"),
        }
    }

    #[test]
    fn decode_percent_preserves_malformed_escapes() {
        assert_eq!(decode_percent("plain").unwrap(), "plain");
        assert_eq!(decode_percent("a%2Fb").unwrap(), "a/b");
        assert_eq!(decode_percent("100%").unwrap(), "100%");
        assert_eq!(decode_percent("%zz").unwrap(), "%zz");
        assert_eq!(decode_percent("%e2%82%ac").unwrap(), "€");
        assert_eq!(decode_percent("%ff"), Err(Error::InvalidUtf8));
    }

    #[test]
    fn channel_key_uri_without_params_matches_the_bare_form() {
        let channel_key = umsh_core::ChannelKey([0x66; 32]);
        let empty = ChannelParams {
            display_name: None,
            max_flood_hops: None,
            region: None,
            raw_query: None,
        };
        let mut with_params = [0u8; 128];
        let mut bare = [0u8; 128];
        let with_len =
            format_channel_key_uri_with_params(&channel_key, &empty, &mut with_params).unwrap();
        let bare_len = format_channel_key_uri(&channel_key, &mut bare).unwrap();
        assert_eq!(&with_params[..with_len], &bare[..bare_len]);
    }

    #[test]
    fn channel_key_uri_with_params_reports_a_short_buffer() {
        let channel_key = umsh_core::ChannelKey([0x77; 32]);
        let params = ChannelParams {
            display_name: Some("Trail Crew"),
            max_flood_hops: None,
            region: None,
            raw_query: None,
        };
        // Room for `umsh:gk:` and the 44-character key, but not the query.
        let mut buf = [0u8; 52];
        assert_eq!(
            format_channel_key_uri_with_params(&channel_key, &params, &mut buf),
            Err(Error::BufferTooSmall)
        );
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

    // The vectors below are those of UEP-0019 Appendix A.

    const NODE_A: &str = "GySVDr1omr3GTodgWFH7qD1ZKav9C5NMPFjdpwb33LvU";
    const GROUP_5A: &str = "75hbt6uvDqjPZ9WgFtMhBnTeyHw7cinoHiz4FD2vEz2d";

    fn hex(text: &str) -> alloc::vec::Vec<u8> {
        let digits: alloc::vec::Vec<u8> =
            text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn variable_base58_matches_the_spec_vectors() {
        for (bytes, text) in [
            ("", ""),
            ("00", "1"),
            ("000001", "112"),
            ("61", "2g"),
            ("FFFF", "LUv"),
            ("000206", "19w"),
        ] {
            let bytes = hex(bytes);
            assert_eq!(encode_base58_bytes(&bytes), text);
            assert_eq!(decode_base58_bytes(text).unwrap(), bytes);
        }
    }

    #[test]
    fn node_uris_match_the_spec_vectors() {
        let address = hex("ED54A59FB1AC3A5123935136294 1B868E85A60E3D7B2485D828821DC7A69C279");
        let bare = alloc::format!("umsh:n:{NODE_A}");
        match parse_umsh_str(&bare).unwrap() {
            UmshUri::Node(node) => {
                assert_eq!(node.public_key.0.as_slice(), address.as_slice());
                assert_eq!(node.identity_data, None);
            }
            _ => panic!("expected a node uri"),
        }

        let signed = hex("02 06 05 41 6C 69 63 65 13 B2 59 15 11 F4 14 6B 36 EC 80 FF
             5CA53BC830CE05AA596EC08C2AEE41A37F5F08D291E6854D4E76E5A2126DC273
             10FC2EDBB20E095F2E7A43613BA373F73943EE97E63B8EC333B84A22E08B3E08");
        let bundle = "9NPVXctGv5bNRLpyNDMXGYvne4bHwV8WxQ1xQoEiA3gemRET41UnDHRfTmWvYSu4TMKK441imEcJSVx3LCwyqj4kY4HZPAJSTrgeazDPGM1nBn59zF";
        assert_eq!(encode_base58_bytes(&signed), bundle);
        let with_bundle = alloc::format!("umsh:n:{NODE_A}:{bundle}");
        match parse_umsh_str(&with_bundle).unwrap() {
            UmshUri::Node(node) => assert_eq!(node.identity_data, Some(bundle)),
            _ => panic!("expected a node uri"),
        }

        let unsigned = hex("02 06 05 41 6C 69 63 65 13 B2 59 15 11 F4 14 6B 36 EC 80");
        assert_eq!(encode_base58_bytes(&unsigned), "NVBjSY2wfbwPypTziMyej18fh");
    }

    #[test]
    fn strip_scheme_ignores_case_and_never_splits_a_character() {
        assert_eq!(strip_scheme("umsh:n:x"), Some("n:x"));
        assert_eq!(strip_scheme("UMSH:n:x"), Some("n:x"));
        assert_eq!(strip_scheme("umsh"), None);
        assert_eq!(strip_scheme("umsh;n:x"), None);
        assert_eq!(strip_scheme("umsé:n"), None);
    }

    #[test]
    fn a_sender_writes_neither_an_empty_name_nor_a_flood_budget_above_15() {
        let key = umsh_core::ChannelKey([0x5A; 32]);
        let mut buf = [0u8; 160];
        let write = |params: ChannelParams<'_>, buf: &mut [u8]| {
            format_channel_key_uri_with_params(&key, &params, buf)
        };
        let params = |name, hops| ChannelParams {
            display_name: name,
            max_flood_hops: hops,
            region: None,
            raw_query: None,
        };
        assert_eq!(
            write(params(None, Some(16)), &mut buf),
            Err(Error::InvalidUri)
        );
        assert_eq!(
            write(params(Some("x"), Some(200)), &mut buf),
            Err(Error::InvalidUri)
        );
        let len = write(params(Some(""), Some(15)), &mut buf).unwrap();
        assert!(
            core::str::from_utf8(&buf[..len])
                .unwrap()
                .ends_with("?mh=15")
        );
        let len = write(params(Some(""), None), &mut buf).unwrap();
        assert!(
            core::str::from_utf8(&buf[..len])
                .unwrap()
                .ends_with(GROUP_5A)
        );
    }

    #[test]
    fn the_deprecated_kinds_parse_as_their_replacements() {
        let new = alloc::format!("umsh:gk:{GROUP_5A}?mh=3");
        let old = alloc::format!("umsh:ck:{GROUP_5A}?mh=3");
        match (parse_umsh_str(&new).unwrap(), parse_umsh_str(&old).unwrap()) {
            (UmshUri::ChannelByKey(new), UmshUri::ChannelByKey(old)) => assert_eq!(new, old),
            _ => panic!("expected group keys"),
        }
        match parse_umsh_str("umsh:cs:Public").unwrap() {
            UmshUri::ChannelByName(group) => assert_eq!(group.name, "Public"),
            _ => panic!("expected a named group"),
        }
        assert!(parse_umsh_str("umsh:cs:a:b").is_err());
        assert!(parse_umsh_str("umsh:cs:").is_err());
        assert!(parse_umsh_str(&alloc::format!("umsh:ck:{GROUP_5A}:x")).is_err());

        assert_eq!(strip_group_name_kind("gs:x"), Some("x"));
        assert_eq!(strip_group_name_kind("cs:x"), Some("x"));
        assert_eq!(strip_group_key_kind("gk:x"), Some("x"));
        assert_eq!(strip_group_key_kind("ck:x"), Some("x"));
        assert_eq!(strip_group_key_kind("gs:x"), None);
    }

    #[test]
    fn the_scheme_is_matched_without_regard_to_case_but_nothing_else_is() {
        assert!(matches!(
            parse_umsh_str(&alloc::format!("UMSH:n:{NODE_A}")),
            Ok(UmshUri::Node(_))
        ));
        assert!(parse_umsh_str(&alloc::format!("umsh:N:{NODE_A}")).is_err());
        assert!(parse_umsh_str("umsh:GS:public").is_err());
        assert!(parse_umsh_str("umsh:CS:public").is_err());
    }

    #[test]
    fn named_group_uris_name_one_group_however_they_are_written() {
        for text in [
            "umsh:gs:Public",
            "umsh:gs:public",
            "umsh:gs:PUBLIC",
            "umsh:gs:%50ublic",
        ] {
            match parse_umsh_str(text).unwrap() {
                UmshUri::ChannelByName(group) => assert_eq!(
                    decode_percent(group.name).unwrap().to_ascii_lowercase(),
                    "public"
                ),
                _ => panic!("expected a named group"),
            }
        }
    }

    #[test]
    fn group_key_uri_carries_the_spec_parameters() {
        let text = alloc::format!("umsh:gk:{GROUP_5A}?n=Trail%20Crew;mh=3;r=SJC");
        match parse_umsh_str(&text).unwrap() {
            UmshUri::ChannelByKey(group) => {
                assert_eq!(group.key.0, [0x5A; 32]);
                assert_eq!(
                    decode_percent(group.params.display_name.unwrap()).unwrap(),
                    "Trail Crew"
                );
                assert_eq!(group.params.max_flood_hops, Some(3));
                assert_eq!(group.params.region, Some("SJC"));
            }
            _ => panic!("expected a group key"),
        }
        // `&` also separates parameters, and the last of a repeat wins.
        let text = alloc::format!("umsh:gk:{GROUP_5A}?mh=2&mh=7");
        match parse_umsh_str(&text).unwrap() {
            UmshUri::ChannelByKey(group) => assert_eq!(group.params.max_flood_hops, Some(7)),
            _ => panic!("expected a group key"),
        }
    }

    #[test]
    fn a_separator_in_a_parameter_value_round_trips() {
        let key = umsh_core::ChannelKey([0x5A; 32]);
        let params = ChannelParams {
            display_name: Some("a?b;c=d&e/f"),
            max_flood_hops: None,
            region: None,
            raw_query: None,
        };
        let mut buf = [0u8; 128];
        let len = format_channel_key_uri_with_params(&key, &params, &mut buf).unwrap();
        let text = core::str::from_utf8(&buf[..len]).unwrap();
        assert!(text.ends_with("?n=a%3Fb%3Bc%3Dd%26e%2Ff"));
    }

    #[test]
    fn the_spec_rejects_these_uris() {
        for text in [
            "umsh:gs:",
            "umsh:gs:a:b",
            "umsh:gs:100%",
            "umsh:gs:public%00x",
            "umsh:gs:a%0Ab",
            "umsh:gs:a b",
            "umsh:gk:75hbt6uvDqjPZ9WgFtMhBnTeyHw7cinoHiz4FD2vEz2d?n=%FF",
            "umsh:gk:GySVDr1omr3GTodgWFH7qD1ZKav9C5NMPFjdpwb33Lv",
            "umsh:x:GySVDr1omr3GTodgWFH7qD1ZKav9C5NMPFjdpwb33LvU",
        ] {
            assert!(parse_umsh_str(text).is_err(), "{text}");
        }
        // A group key with a third segment is as wrong as a name with one.
        assert!(parse_umsh_str(&alloc::format!("umsh:gk:{GROUP_5A}:extra")).is_err());
    }

    #[test]
    fn a_malformed_parameter_is_ignored_not_fatal() {
        for (query, hops) in [
            ("mh=16", None),
            ("mh=x", None),
            ("mh=+3", None),
            ("mh=003", None),
            ("mh=%33", None),
            ("%6D%68=3", None),
            ("mh=", None),
            ("mh=15", Some(15)),
            ("mh=0", Some(0)),
            ("q=1", None),
        ] {
            let text = alloc::format!("umsh:gk:{GROUP_5A}?{query}");
            match parse_umsh_str(&text).unwrap() {
                UmshUri::ChannelByKey(group) => {
                    assert_eq!(group.params.max_flood_hops, hops, "{query}")
                }
                _ => panic!("expected a group key"),
            }
        }
    }
}
