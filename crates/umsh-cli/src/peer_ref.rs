//! `<peer-ref>` token resolution used by every peer-naming command.
//!
//! Accepts any of:
//! - a registered alias (ASCII, up to 16 chars),
//! - the canonical fixed-width base58 address (exactly 44 chars),
//! - hex-encoded 32-byte pubkey (64 hex chars, optional `0x` prefix),
//! - base64-encoded 32-byte pubkey (standard or URL-safe alphabet).
//!
//! 3-byte hints are NOT accepted — they aren't unique and the CLI refuses
//! to guess.

use umsh_core::PublicKey;

/// Decode a `<peer-ref>` token into a `PublicKey`. Alias lookup is the
/// caller's concern; this helper only handles the encoded forms.
///
/// The canonical forms (44-char base58 and 64-char hex, distinguished by
/// length) are tried first via [`PublicKey::from_str`], then base64.
///
/// After successful decoding the bytes are validated as a well-formed
/// Ed25519 compressed public-key point on the curve (when the
/// `software-crypto` feature is enabled). Bytes that decode to 32 bytes but
/// do not lie on the curve return `None` so a typo'd hex string can never
/// be accepted as a peer key.
///
/// Returns `None` if the token doesn't decode to a full 32-byte key in any
/// of the supported encodings, or if the decoded bytes are not a valid
/// Ed25519 point.
pub fn try_parse_pubkey(token: &str) -> Option<PublicKey> {
    let canonical = token.strip_prefix("0x").unwrap_or(token);
    let key = canonical
        .parse::<PublicKey>()
        .ok()
        .or_else(|| try_b64(token))?;
    #[cfg(feature = "software-crypto")]
    {
        if !umsh_crypto::is_valid_ed25519_public_key(&key) {
            return None;
        }
    }
    Some(key)
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
    use umsh_crypto::NodeIdentity;
    use umsh_crypto::software::SoftwareIdentity;

    /// A real Ed25519 public key derived from a known seed. Generated at
    /// test time so the constant cannot silently drift away from a
    /// valid point on the curve.
    fn valid_key() -> [u8; 32] {
        SoftwareIdentity::from_secret_bytes(&[0x11; 32])
            .public_key()
            .0
    }

    #[test]
    fn decodes_hex() {
        let key = valid_key();
        let hex = std::format!("{:x}", PublicKey(key));
        assert_eq!(try_parse_pubkey(&hex).unwrap().0, key);
        let prefixed = std::format!("0x{}", hex.to_uppercase());
        assert_eq!(try_parse_pubkey(&prefixed).unwrap().0, key);
    }

    #[test]
    fn decodes_base58() {
        let key = valid_key();
        let b58 = PublicKey(key).to_string();
        assert_eq!(b58.len(), 44);
        assert_eq!(try_parse_pubkey(&b58).unwrap().0, key);
    }

    #[test]
    fn rejects_short_or_junk() {
        assert!(try_parse_pubkey("").is_none());
        assert!(try_parse_pubkey("hello").is_none());
        assert!(try_parse_pubkey("0x01").is_none());
    }

    #[test]
    fn rejects_non_curve_point() {
        // Y = 2 (little-endian) is well-formed hex but does not lie on
        // the Ed25519 curve. Without curve validation this would have
        // been blindly accepted as a peer key and only failed later at
        // ECDH time with `IdentityAgreementFailed`.
        let bogus = "0200000000000000000000000000000000000000000000000000000000000000";
        assert!(try_parse_pubkey(bogus).is_none());
    }
}
