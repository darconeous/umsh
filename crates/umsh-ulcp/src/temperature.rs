//! Ordered temperature arrays. Capacities belong to senders, not the wire codec.

use crate::items::{encode_prefixed_item, fixed_items, prefixed_items};

pub const UNKNOWN: u16 = 0xffff;
pub const NAME_MAX_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    BufferTooSmall,
}

/// Validate the complete array before exposing any readings (in tenths of kelvin).
pub fn readings(value: &[u8]) -> Result<impl ExactSizeIterator<Item = Option<u16>> + Clone, Error> {
    Ok(fixed_items::<2>(value)
        .map_err(|_| Error::Malformed)?
        .map(|bytes| {
            let value = u16::from_le_bytes(*bytes);
            (value != UNKNOWN).then_some(value)
        }))
}

/// Encode raw readings, including `UNKNOWN`, without a count prefix.
pub fn encode_readings(values: &[u16], out: &mut [u8]) -> Result<usize, Error> {
    let len = values.len().checked_mul(2).ok_or(Error::BufferTooSmall)?;
    if out.len() < len {
        return Err(Error::BufferTooSmall);
    }
    for (value, bytes) in values.iter().zip(out[..len].chunks_exact_mut(2)) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
    Ok(len)
}

pub fn valid_name(name: &str) -> bool {
    (1..=NAME_MAX_BYTES).contains(&name.len()) && !name.as_bytes().contains(&0)
}

/// Validate every prefix, UTF-8 string, length, and NUL constraint up front.
pub fn names(value: &[u8]) -> Result<impl Iterator<Item = &str> + Clone, Error> {
    for item in prefixed_items(value) {
        let name = core::str::from_utf8(item.map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        if !valid_name(name) {
            return Err(Error::Malformed);
        }
    }
    Ok(prefixed_items(value).map(|item| {
        core::str::from_utf8(item.expect("validated name prefix")).expect("validated UTF-8")
    }))
}

pub fn encode_names(names: &[&str], out: &mut [u8]) -> Result<usize, Error> {
    let mut len = 0usize;
    for name in names {
        if !valid_name(name) {
            return Err(Error::Malformed);
        }
        // Lengths 1–64 have a one-byte PUI prefix.
        len = len
            .checked_add(1 + name.len())
            .ok_or(Error::BufferTooSmall)?;
    }
    if len > out.len() {
        return Err(Error::BufferTooSmall);
    }
    let mut offset = 0;
    for name in names {
        offset += encode_prefixed_item(name.as_bytes(), &mut out[offset..])
            .map_err(|_| Error::BufferTooSmall)?;
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temperature_readings_boundaries_and_order() {
        let values = [2981, 0, 0xfffe, UNKNOWN];
        let mut out = [0; 8];
        assert_eq!(encode_readings(&values, &mut out), Ok(8));
        assert_eq!(out, [0xa5, 0x0b, 0, 0, 0xfe, 0xff, 0xff, 0xff]);
        assert_eq!(
            readings(&out).unwrap().collect::<Vec<_>>(),
            [Some(2981), Some(0), Some(65534), None]
        );
        assert_eq!(readings(&[]).unwrap().len(), 0);
        assert!(readings(&[0]).is_err());
        assert_eq!(
            encode_readings(&values, &mut [0; 7]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(encode_readings(&[], &mut []), Ok(0));
    }

    #[test]
    fn temperature_names_validate_complete_array() {
        let mut out = [0; 128];
        let len = encode_names(&["Die", "電池", "Die"], &mut out).unwrap();
        assert_eq!(
            names(&out[..len]).unwrap().collect::<Vec<_>>(),
            ["Die", "電池", "Die"]
        );
        assert_eq!(names(&[]).unwrap().count(), 0);
        for bad in [
            &[0][..],
            &[1, 0],
            &[1, 0xff],
            &[2, b'a'],
            &[0x80],
            &[1, b'a', 0],
        ] {
            assert!(names(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            encode_names(&["ab"], &mut [0; 2]),
            Err(Error::BufferTooSmall)
        );
        for bad in ["", "a\0b", &"a".repeat(65)] {
            assert_eq!(encode_names(&[bad], &mut out), Err(Error::Malformed));
        }
        assert!(encode_names(&[&"a".repeat(64)], &mut out).is_ok());
        let too_long = [&[65][..], &[b'a'; 65]].concat();
        assert!(names(&too_long).is_err());
        // Reference inventory capacities do not limit host decoding.
        assert_eq!(names(&b"\x01a".repeat(17)).unwrap().count(), 17);
    }
}
