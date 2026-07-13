//! `STR_PHY_RAW` metadata envelopes.
//!
//! The metadata trails the packet data in `CMD_STR_SEND` /
//! `CMD_STR_RECV` payloads and may be absent entirely; decoding an
//! empty slice yields the defaults.

use core::num::NonZeroU8;

/// `TX_POWER` value requesting the radio's default power.
pub const TX_POWER_DEFAULT: i8 = 0x7F;
/// `TX_POWER` value requesting maximum power.
pub const TX_POWER_MAX: i8 = 0x7E;

/// `TX_FLAGS` bit: do not use CCA (or the equivalent LoRa mechanism).
pub const TX_FLAG_NOCCA: u8 = 1 << 0;
/// `TX_FLAGS` bit: send even if it would exceed the duty-cycle limit.
pub const TX_FLAG_NODUTY: u8 = 1 << 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaError {
    /// The metadata was present but shorter than its wire format.
    Truncated,
    /// The output buffer cannot hold the encoded metadata.
    BufferTooSmall,
}

/// Transmit metadata for `Send` on `STR_PHY_RAW`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxMeta {
    /// Transmit power override in dBm, or one of [`TX_POWER_DEFAULT`]
    /// and [`TX_POWER_MAX`].
    pub power: i8,
    /// Combination of the `TX_FLAG_*` bits.
    pub flags: u8,
}

impl Default for TxMeta {
    fn default() -> Self {
        Self {
            power: TX_POWER_DEFAULT,
            flags: 0,
        }
    }
}

impl TxMeta {
    pub const WIRE_LEN: usize = 2;

    pub fn encode(self, out: &mut [u8]) -> Result<usize, MetaError> {
        let [power, flags, ..] = out else {
            return Err(MetaError::BufferTooSmall);
        };
        *power = self.power as u8;
        *flags = self.flags;
        Ok(Self::WIRE_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, MetaError> {
        match input {
            [] => Ok(Self::default()),
            [power, flags, ..] => Ok(Self {
                power: *power as i8,
                flags: *flags,
            }),
            _ => Err(MetaError::Truncated),
        }
    }
}

/// Receive metadata for `Recv` on `STR_PHY_RAW`.
///
/// Each field has a wire-level "not supported" sentinel, mapped to
/// `None` here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxMeta {
    /// RSSI in dBm. On the wire this is the negated RSSI as a `u8`,
    /// with `0xFF` meaning unsupported, so only values in `-254..=0`
    /// are representable; `encode` clamps to that range.
    pub rssi_dbm: Option<i16>,
    /// Link-quality indicator, 1 (worst) to 255 (perfect).
    pub lqi: Option<NonZeroU8>,
    /// Signal-to-noise ratio in centibels. The wire sentinel `0x8000`
    /// (`i16::MIN`, -3276.8 dB) means unsupported. No real link can
    /// report that value, so every genuine measurement round-trips
    /// without distortion.
    pub snr_cb: Option<i16>,
}

impl RxMeta {
    pub const WIRE_LEN: usize = 4;

    pub fn encode(self, out: &mut [u8]) -> Result<usize, MetaError> {
        if out.len() < Self::WIRE_LEN {
            return Err(MetaError::BufferTooSmall);
        }
        out[0] = match self.rssi_dbm {
            None => 0xFF,
            Some(rssi) => (-rssi).clamp(0, 254) as u8,
        };
        out[1] = self.lqi.map(NonZeroU8::get).unwrap_or(0);
        // `i16::MIN` is the "unsupported" sentinel; it is physically
        // unreachable as a real SNR, so no genuine reading needs nudging.
        let snr = self.snr_cb.unwrap_or(i16::MIN);
        out[2..4].copy_from_slice(&snr.to_le_bytes());
        Ok(Self::WIRE_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, MetaError> {
        match input {
            [] => Ok(Self::default()),
            [rssi, lqi, snr_lo, snr_hi, ..] => {
                let snr = i16::from_le_bytes([*snr_lo, *snr_hi]);
                Ok(Self {
                    rssi_dbm: (*rssi != 0xFF).then(|| -i16::from(*rssi)),
                    lqi: NonZeroU8::new(*lqi),
                    snr_cb: (snr != i16::MIN).then_some(snr),
                })
            }
            _ => Err(MetaError::Truncated),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_round_trip() {
        let meta = TxMeta {
            power: 22,
            flags: TX_FLAG_NODUTY,
        };
        let mut buf = [0u8; TxMeta::WIRE_LEN];
        assert_eq!(meta.encode(&mut buf).unwrap(), TxMeta::WIRE_LEN);
        assert_eq!(buf, [22, 0x02]);
        assert_eq!(TxMeta::decode(&buf).unwrap(), meta);
    }

    #[test]
    fn tx_absent_is_default() {
        assert_eq!(TxMeta::decode(&[]).unwrap(), TxMeta::default());
        assert_eq!(TxMeta::default().power, TX_POWER_DEFAULT);
        assert_eq!(TxMeta::decode(&[0x00]), Err(MetaError::Truncated));
    }

    #[test]
    fn rx_round_trip() {
        let meta = RxMeta {
            rssi_dbm: Some(-91),
            lqi: NonZeroU8::new(200),
            snr_cb: Some(-53),
        };
        let mut buf = [0u8; RxMeta::WIRE_LEN];
        meta.encode(&mut buf).unwrap();
        // Spec example: RSSI -91 encodes as 91.
        assert_eq!(buf[0], 91);
        assert_eq!(RxMeta::decode(&buf).unwrap(), meta);
    }

    #[test]
    fn rx_sentinels() {
        let mut buf = [0u8; RxMeta::WIRE_LEN];
        RxMeta::default().encode(&mut buf).unwrap();
        // SNR sentinel is i16::MIN (0x8000), little-endian.
        assert_eq!(buf, [0xFF, 0x00, 0x00, 0x80]);
        assert_eq!(RxMeta::decode(&buf).unwrap(), RxMeta::default());
        assert_eq!(RxMeta::decode(&[]).unwrap(), RxMeta::default());
        assert_eq!(RxMeta::decode(&[91, 0, 0]), Err(MetaError::Truncated));
    }

    #[test]
    fn rx_snr_negative_one_round_trips() {
        // -0.1 dB used to collide with the old 0xFFFF sentinel; with the
        // i16::MIN sentinel it survives a round trip unchanged.
        let meta = RxMeta {
            rssi_dbm: Some(0),
            lqi: None,
            snr_cb: Some(-1),
        };
        let mut buf = [0u8; RxMeta::WIRE_LEN];
        meta.encode(&mut buf).unwrap();
        assert_eq!(RxMeta::decode(&buf).unwrap().snr_cb, Some(-1));
    }
}
