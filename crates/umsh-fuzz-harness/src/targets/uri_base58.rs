//! Addresses and URIs people paste, and the two base58 decoders behind them.

use umsh_core::{PublicKey, base58};
use umsh_uri::{
    decode_base58_bytes, encode_base58_bytes, encode_public_key_base58, parse_public_key_base58,
    parse_umsh_str,
};

/// Past any address or URI, and the variable-width decoder is quadratic.
const MAX: usize = 512;

pub fn run(data: &[u8]) {
    if data.len() > MAX {
        return;
    }
    if let Ok(key) = base58::decode(data) {
        // The fixed form is canonical, and the two decoders agree on it.
        assert_eq!(&base58::encode(&key)[..], data);
        let text = core::str::from_utf8(data).expect("base58 digits are ASCII");
        assert_eq!(parse_public_key_base58(text).ok(), Some(PublicKey(key)));
    }
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let _ = parse_umsh_str(text);
    if let Ok(bytes) = decode_base58_bytes(text) {
        assert_eq!(decode_base58_bytes(&encode_base58_bytes(&bytes)), Ok(bytes));
    }
    if let Ok(key) = parse_public_key_base58(text) {
        let again = encode_public_key_base58(&key);
        assert_eq!(parse_public_key_base58(&again).ok(), Some(key));
    }
}
