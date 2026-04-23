//! `<peer-ref>` token resolution used by every peer-naming command.
//!
//! Accepts any of:
//! - a registered alias (ASCII, up to 16 chars),
//! - base58-encoded 32-byte pubkey,
//! - base64-encoded 32-byte pubkey (standard or URL-safe alphabet),
//! - hex-encoded 32-byte pubkey (64 hex chars, optional `0x` prefix).
//!
//! 3-byte hints are NOT accepted — they aren't unique and the CLI refuses
//! to guess.

use umsh_core::PublicKey;

/// Decode a `<peer-ref>` token into a `PublicKey`. Alias lookup is the
/// caller's concern; this helper only handles the encoded forms.
///
/// Returns `None` if the token doesn't decode to a full 32-byte key in any
/// of the supported encodings.
pub fn try_parse_pubkey(token: &str) -> Option<PublicKey> {
    if let Some(key) = try_hex(token) {
        return Some(key);
    }
    // Base64 vs base58: base58 alphabet excludes `0OIl+/=`. If the token
    // contains any of those, it can't be base58. Try base64 first in that
    // case; otherwise try base58 first.
    let looks_b64 = token.bytes().any(|b| matches!(b, b'0' | b'O' | b'I' | b'l' | b'+' | b'/' | b'=' | b'-' | b'_'));
    if looks_b64 {
        if let Some(key) = try_b64(token) {
            return Some(key);
        }
        return try_b58(token);
    }
    if let Some(key) = try_b58(token) {
        return Some(key);
    }
    try_b64(token)
}

fn try_hex(token: &str) -> Option<PublicKey> {
    let s = token.strip_prefix("0x").unwrap_or(token);
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nib(s.as_bytes()[i * 2])?;
        let lo = hex_nib(s.as_bytes()[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(PublicKey(out))
}

fn hex_nib(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn try_b58(token: &str) -> Option<PublicKey> {
    let mut out = [0u8; 32];
    match bs58::decode(token).onto(&mut out[..]) {
        Ok(32) => Some(PublicKey(out)),
        _ => None,
    }
}

fn try_b64(token: &str) -> Option<PublicKey> {
    // Minimal base64 decoder for 32-byte keys. Supports both standard and
    // URL-safe alphabets; padding is optional.
    let bytes = token.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    // Strip trailing '=' padding.
    let end = bytes
        .iter()
        .rposition(|&b| b != b'=')
        .map(|i| i + 1)
        .unwrap_or(0);
    let src = &bytes[..end];

    let mut out = [0u8; 32];
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut oi = 0;

    for &b in src {
        let v: u32 = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a') as u32 + 26,
            b'0'..=b'9' => (b - b'0') as u32 + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if oi >= 32 {
                return None;
            }
            out[oi] = ((buf >> bits) & 0xFF) as u8;
            oi += 1;
        }
    }
    if oi == 32 { Some(PublicKey(out)) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    #[test]
    fn decodes_hex() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        assert_eq!(try_parse_pubkey(hex).unwrap().0, KEY);
        let prefixed = "0x0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20";
        assert_eq!(try_parse_pubkey(prefixed).unwrap().0, KEY);
    }

    #[test]
    fn decodes_base58() {
        let b58 = bs58::encode(KEY).into_string();
        assert_eq!(try_parse_pubkey(&b58).unwrap().0, KEY);
    }

    #[test]
    fn rejects_short_or_junk() {
        assert!(try_parse_pubkey("").is_none());
        assert!(try_parse_pubkey("hello").is_none());
        assert!(try_parse_pubkey("0x01").is_none());
    }
}
