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

/// `RX_FLAGS` bit: the frame was held in the inbound queue and is being
/// delivered by `CMD_QUEUE_DRAIN`.
pub const RX_FLAG_BUFFERED: u8 = 1 << 0;
/// `RX_FLAGS` bit: the NCP already transmitted a MAC ack for this frame
/// on the host's behalf; the host must not ack it again.
pub const RX_FLAG_ACKED: u8 = 1 << 1;

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

/// `Recv` metadata extended with the full protocol's trailing
/// buffered-frame fields (`RX_FLAGS`, `RX_AGE`).
///
/// Live deliveries may omit the trailing fields entirely (they decode
/// as zero), keeping the encoding byte-compatible with the minimal
/// protocol. Truncation is legal only at field boundaries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BufferedRxMeta {
    pub rx: RxMeta,
    /// Combination of the `RX_FLAG_*` bits.
    pub flags: u8,
    /// Seconds between reception and delivery; zero for live delivery.
    pub age_s: u32,
}

impl BufferedRxMeta {
    pub const WIRE_LEN: usize = RxMeta::WIRE_LEN + 5;

    pub fn encode(self, out: &mut [u8]) -> Result<usize, MetaError> {
        if out.len() < Self::WIRE_LEN {
            return Err(MetaError::BufferTooSmall);
        }
        self.rx.encode(out)?;
        out[RxMeta::WIRE_LEN] = self.flags;
        out[RxMeta::WIRE_LEN + 1..Self::WIRE_LEN].copy_from_slice(&self.age_s.to_le_bytes());
        Ok(Self::WIRE_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, MetaError> {
        let rx = RxMeta::decode(input)?;
        let trailer = input.get(RxMeta::WIRE_LEN..).unwrap_or(&[]);
        let (flags, age_s) = match trailer {
            [] => (0, 0),
            [flags] => (*flags, 0),
            [flags, age @ ..] if age.len() >= 4 => (
                *flags,
                u32::from_le_bytes(age[..4].try_into().expect("length checked")),
            ),
            _ => return Err(MetaError::Truncated),
        };
        Ok(Self { rx, flags, age_s })
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
    fn buffered_round_trip_and_boundary_truncation() {
        let meta = BufferedRxMeta {
            rx: RxMeta {
                rssi_dbm: Some(-101),
                lqi: NonZeroU8::new(17),
                snr_cb: Some(-22),
            },
            flags: RX_FLAG_BUFFERED | RX_FLAG_ACKED,
            age_s: 3_601,
        };
        let mut buf = [0u8; BufferedRxMeta::WIRE_LEN];
        assert_eq!(meta.encode(&mut buf).unwrap(), BufferedRxMeta::WIRE_LEN);
        assert_eq!(BufferedRxMeta::decode(&buf).unwrap(), meta);

        // Truncation at each legal field boundary: absent fields are zero.
        assert_eq!(
            BufferedRxMeta::decode(&[]).unwrap(),
            BufferedRxMeta::default()
        );
        let base_only = BufferedRxMeta::decode(&buf[..RxMeta::WIRE_LEN]).unwrap();
        assert_eq!(base_only.rx, meta.rx);
        assert_eq!((base_only.flags, base_only.age_s), (0, 0));
        let with_flags = BufferedRxMeta::decode(&buf[..RxMeta::WIRE_LEN + 1]).unwrap();
        assert_eq!(with_flags.flags, meta.flags);
        assert_eq!(with_flags.age_s, 0);

        // Truncation mid-RX_AGE is malformed.
        for len in RxMeta::WIRE_LEN + 2..BufferedRxMeta::WIRE_LEN {
            assert_eq!(
                BufferedRxMeta::decode(&buf[..len]),
                Err(MetaError::Truncated)
            );
        }
    }

    #[test]
    fn buffered_decode_matches_minimal_live_encoding() {
        // A live minimal-protocol RxMeta decodes as a BufferedRxMeta with
        // zero flags and age: the encodings stay byte-compatible.
        let rx = RxMeta {
            rssi_dbm: Some(-91),
            lqi: None,
            snr_cb: Some(55),
        };
        let mut buf = [0u8; RxMeta::WIRE_LEN];
        rx.encode(&mut buf).unwrap();
        let buffered = BufferedRxMeta::decode(&buf).unwrap();
        assert_eq!(
            buffered,
            BufferedRxMeta {
                rx,
                flags: 0,
                age_s: 0
            }
        );
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
