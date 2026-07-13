//! Service-agnostic frame segmentation and reassembly for GATT links.
//!
//! This implements the GATT Frame Transport from
//! `docs/protocol/src/companion-radio-ble.md`: one SAR header octet per ATT
//! value, no HDLC escaping or checksum, and bounded reassembly state.

/// SAR value for a frame contained in one segment.
pub const SAR_COMPLETE: u8 = 0;
/// SAR value for the first segment of a multi-segment frame.
pub const SAR_FIRST: u8 = 1;
/// SAR value for a middle segment of a multi-segment frame.
pub const SAR_CONT: u8 = 2;
/// SAR value for the final segment of a multi-segment frame.
pub const SAR_LAST: u8 = 3;

const SAR_SHIFT: u8 = 6;
const RESERVED_MASK: u8 = 0x3f;

/// Maximum reassembled frame size for the Companion Link Service.
pub const MAX_FRAME: usize = 512;

/// Return a UMSH UUID with `slot` spliced into the second UUID group.
pub const fn uuid(slot: u16) -> u128 {
    0x21EB_6B15_0000_4CCF_92E4_A079_171B_EC97u128 | ((slot as u128) << 80)
}

/// Companion Link Service UUID.
pub const SERVICE_UUID: u128 = uuid(0x0001);
/// Companion Link Frame In characteristic UUID.
pub const FRAME_IN_UUID: u128 = uuid(0x0002);
/// Companion Link Frame Out characteristic UUID.
pub const FRAME_OUT_UUID: u128 = uuid(0x0003);

/// One header-prefixed GATT frame segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    sar: u8,
    payload: &'a [u8],
}

impl<'a> Segment<'a> {
    /// Encoded segment header octet.
    pub const fn header(&self) -> u8 {
        self.sar << SAR_SHIFT
    }

    /// Frame bytes carried by this segment.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Write the header and payload to `out`, returning the encoded length.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let len = self.payload.len() + 1;
        if out.len() < len {
            return Err(EncodeError::BufferTooSmall);
        }
        out[0] = self.header();
        out[1..len].copy_from_slice(self.payload);
        Ok(len)
    }
}

/// Segment encoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The caller-provided destination cannot hold the segment.
    BufferTooSmall,
}

/// Iterator returned by [`segments`].
pub struct Segments<'a> {
    frame: &'a [u8],
    seg_payload: usize,
    offset: usize,
    emitted_empty: bool,
}

impl<'a> Iterator for Segments<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.frame.is_empty() {
            if self.emitted_empty {
                return None;
            }
            self.emitted_empty = true;
            return Some(Segment {
                sar: SAR_COMPLETE,
                payload: self.frame,
            });
        }
        if self.offset >= self.frame.len() {
            return None;
        }

        let start = self.offset;
        let end = start.saturating_add(self.seg_payload).min(self.frame.len());
        self.offset = end;
        let sar = if self.frame.len() <= self.seg_payload {
            SAR_COMPLETE
        } else if start == 0 {
            SAR_FIRST
        } else if end == self.frame.len() {
            SAR_LAST
        } else {
            SAR_CONT
        };
        Some(Segment {
            sar,
            payload: &self.frame[start..end],
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = if self.frame.is_empty() {
            usize::from(!self.emitted_empty)
        } else {
            (self.frame.len() - self.offset).div_ceil(self.seg_payload)
        };
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Segments<'_> {}

/// Split one frame into segments carrying at most `seg_payload` frame bytes.
///
/// `seg_payload` is the negotiated usable ATT value size minus the header
/// octet (`ATT_MTU - 3 - 1`). It must be nonzero in every build profile.
pub fn segments(frame: &[u8], seg_payload: usize) -> Segments<'_> {
    assert!(seg_payload >= 1, "GATT segment payload must be nonzero");
    Segments {
        frame,
        seg_payload,
        offset: 0,
        emitted_empty: false,
    }
}

/// Segment decoding/reassembly failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Reserved header bits were nonzero.
    ReservedBits,
    /// A continuation/final segment arrived without a partial frame.
    Orphan,
    /// The reassembled frame exceeded the configured bound.
    TooLong,
    /// The ATT value did not contain a header octet.
    Runt,
}

/// Bounded reassembly state for one GATT characteristic.
pub struct Reassembler<const N: usize> {
    buf: [u8; N],
    len: usize,
    in_progress: bool,
    discarding_overflow: bool,
}

impl<const N: usize> Default for Reassembler<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Reassembler<N> {
    /// Construct an idle reassembler.
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
            in_progress: false,
            discarding_overflow: false,
        }
    }

    /// Discard all partial state.
    pub fn reset(&mut self) {
        self.len = 0;
        self.in_progress = false;
        self.discarding_overflow = false;
    }

    /// Push one complete ATT value.
    ///
    /// Returns a borrowed completed frame, a one-shot error, or `None` while a
    /// segmented frame remains in progress. Every error resets normal partial
    /// state; overflow additionally ignores continuations until a new start.
    pub fn push(&mut self, segment: &[u8]) -> Option<Result<&[u8], DecodeError>> {
        let Some((&header, payload)) = segment.split_first() else {
            self.reset();
            return Some(Err(DecodeError::Runt));
        };
        if header & RESERVED_MASK != 0 {
            self.reset();
            return Some(Err(DecodeError::ReservedBits));
        }
        let sar = header >> SAR_SHIFT;

        if matches!(sar, SAR_COMPLETE | SAR_FIRST) {
            self.reset();
        } else if self.discarding_overflow {
            return None;
        } else if !self.in_progress {
            return Some(Err(DecodeError::Orphan));
        }

        if payload.len() > N.saturating_sub(self.len) {
            self.len = 0;
            self.in_progress = false;
            self.discarding_overflow = true;
            return Some(Err(DecodeError::TooLong));
        }
        self.buf[self.len..self.len + payload.len()].copy_from_slice(payload);
        self.len += payload.len();

        match sar {
            SAR_COMPLETE => {
                self.in_progress = false;
                Some(Ok(&self.buf[..self.len]))
            }
            SAR_FIRST | SAR_CONT => {
                self.in_progress = true;
                None
            }
            SAR_LAST => {
                self.in_progress = false;
                Some(Ok(&self.buf[..self.len]))
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(segment: Segment<'_>) -> std::vec::Vec<u8> {
        let mut out = std::vec![0; segment.payload().len() + 1];
        let len = segment.write_to(&mut out).unwrap();
        out.truncate(len);
        out
    }

    fn round_trip(frame: &[u8], size: usize) {
        let mut decoder = Reassembler::<MAX_FRAME>::new();
        let mut result = None;
        for segment in segments(frame, size) {
            if let Some(decoded) = decoder.push(&encoded(segment)) {
                result = Some(decoded.unwrap().to_vec());
            }
        }
        assert_eq!(result.as_deref(), Some(frame));
    }

    #[test]
    fn round_trip_common_mtu_payloads() {
        let frame: std::vec::Vec<u8> = (0..512).map(|n| n as u8).collect();
        for size in [19, 243, 511] {
            round_trip(&frame, size);
        }
    }

    #[test]
    fn complete_exact_empty_and_one_byte_payloads() {
        round_trip(b"one segment", 19);
        round_trip(&[7; 38], 19);
        round_trip(&[], 19);
        round_trip(&[1, 2, 3], 1);
        let empty = segments(&[], 1).next().unwrap();
        assert_eq!(empty.header(), 0);
        assert!(empty.payload().is_empty());
    }

    #[test]
    fn empty_middle_segment_is_legal() {
        let mut r = Reassembler::<8>::new();
        assert_eq!(r.push(&[SAR_FIRST << 6, 1]), None);
        assert_eq!(r.push(&[SAR_CONT << 6]), None);
        assert_eq!(r.push(&[SAR_LAST << 6, 2]), Some(Ok(&[1, 2][..])));
    }

    #[test]
    fn rejects_reserved_orphan_and_runt() {
        let mut r = Reassembler::<8>::new();
        assert_eq!(r.push(&[1, 2]), Some(Err(DecodeError::ReservedBits)));
        assert_eq!(r.push(&[SAR_CONT << 6, 2]), Some(Err(DecodeError::Orphan)));
        assert_eq!(r.push(&[SAR_LAST << 6]), Some(Err(DecodeError::Orphan)));
        assert_eq!(r.push(&[]), Some(Err(DecodeError::Runt)));
        assert_eq!(r.push(&[SAR_FIRST << 6, 1]), None);
        assert_eq!(r.push(&[]), Some(Err(DecodeError::Runt)));
        assert_eq!(r.push(&[SAR_LAST << 6, 2]), Some(Err(DecodeError::Orphan)));
    }

    #[test]
    fn first_discards_partial_and_restarts() {
        let mut r = Reassembler::<8>::new();
        assert_eq!(r.push(&[SAR_FIRST << 6, 1]), None);
        assert_eq!(r.push(&[SAR_FIRST << 6, 2]), None);
        assert_eq!(r.push(&[SAR_LAST << 6, 3]), Some(Ok(&[2, 3][..])));
    }

    #[test]
    fn overflow_reports_once_then_recovers_at_start() {
        let mut r = Reassembler::<3>::new();
        assert_eq!(r.push(&[SAR_FIRST << 6, 1, 2]), None);
        assert_eq!(
            r.push(&[SAR_CONT << 6, 3, 4]),
            Some(Err(DecodeError::TooLong))
        );
        assert_eq!(r.push(&[SAR_LAST << 6, 5]), None);
        assert_eq!(r.push(&[SAR_COMPLETE << 6, 9]), Some(Ok(&[9][..])));
    }

    #[test]
    #[should_panic(expected = "GATT segment payload must be nonzero")]
    fn zero_segment_payload_panics_unconditionally() {
        let _ = segments(b"frame", 0);
    }

    #[test]
    fn uuid_literals_match_spec() {
        assert_eq!(SERVICE_UUID, 0x21EB6B1500014CCF92E4A079171BEC97);
        assert_eq!(FRAME_IN_UUID, 0x21EB6B1500024CCF92E4A079171BEC97);
        assert_eq!(FRAME_OUT_UUID, 0x21EB6B1500034CCF92E4A079171BEC97);
    }
}
