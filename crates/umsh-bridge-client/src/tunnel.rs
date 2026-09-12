//! Bounded, byte-faithful tunnel records and drop-oldest queues.
use crate::{MAX_AGE_MS, MAX_BODY, QUEUE_DEPTH};
use heapless::{Deque, Vec};
use umsh_ulcp::meta::{BufferedRxMeta, RX_FLAG_SELF_TX};

#[derive(Clone, Debug)]
pub struct Frame {
    pub body: Vec<u8, MAX_BODY>,
    pub queued_ms: u64,
}

impl Frame {
    pub fn parse(body: &[u8], now_ms: u64, max_payload: usize) -> Option<Self> {
        let (len, rest) = body.split_at_checked(2)?;
        let len = u16::from_le_bytes(len.try_into().ok()?) as usize;
        if len == 0 || len > max_payload || len > rest.len() {
            return None;
        }
        let metadata = &rest[len..];
        // Unknown trailing metadata is preserved, but a partial known header
        // cannot be interpreted as a valid receipt.
        BufferedRxMeta::decode(metadata).ok()?;
        Some(Self {
            body: Vec::from_slice(body).ok()?,
            queued_ms: now_ms,
        })
    }

    pub fn transmitted(data: &[u8], now_ms: u64) -> Option<Self> {
        let mut body = Vec::new();
        body.extend_from_slice(&(u16::try_from(data.len()).ok()?).to_le_bytes())
            .ok()?;
        body.extend_from_slice(data).ok()?;
        let mut metadata = [0; BufferedRxMeta::WIRE_LEN];
        let len = BufferedRxMeta {
            flags: RX_FLAG_SELF_TX,
            ..Default::default()
        }
        .encode(&mut metadata)
        .ok()?;
        body.extend_from_slice(&metadata[..len]).ok()?;
        Some(Self {
            body,
            queued_ms: now_ms,
        })
    }

    pub fn data(&self) -> &[u8] {
        let len = u16::from_le_bytes([self.body[0], self.body[1]]) as usize;
        &self.body[2..2 + len]
    }

    pub fn stale(&self, now_ms: u64) -> bool {
        let metadata = &self.body[2 + self.data().len()..];
        let device_age = BufferedRxMeta::decode(metadata).map_or(0, |m| u64::from(m.age_s) * 1000);
        now_ms
            .saturating_sub(self.queued_ms)
            .saturating_add(device_age)
            >= MAX_AGE_MS
    }
}

#[derive(Default)]
pub struct Queue {
    frames: Deque<Frame, QUEUE_DEPTH>,
    pub overflow: u32,
    pub stale: u32,
}

impl Queue {
    pub const fn new() -> Self {
        Self {
            frames: Deque::new(),
            overflow: 0,
            stale: 0,
        }
    }
    pub fn clear(&mut self) {
        self.frames.clear();
    }
    pub fn push(&mut self, frame: Frame) {
        if self.frames.is_full() {
            self.frames.pop_front();
            self.overflow = self.overflow.saturating_add(1);
        }
        self.frames.push_back(frame).unwrap();
    }
    pub fn pop(&mut self, now_ms: u64) -> Option<Frame> {
        while let Some(frame) = self.frames.pop_front() {
            if frame.stale(now_ms) {
                self.stale = self.stale.saturating_add(1);
            } else {
                return Some(frame);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queue_drops_oldest_and_expires_frames() {
        let mut queue = Queue::new();
        for n in 0..9 {
            queue.push(Frame::transmitted(&[n], 0).unwrap());
        }
        assert_eq!(queue.overflow, 1);
        assert_eq!(queue.pop(9_999).unwrap().data(), &[1]);
        assert!(queue.pop(10_000).is_none());
        assert_eq!(queue.stale, 7);
    }
    #[test]
    fn raw_record_roundtrip_and_limits() {
        let frame = Frame::transmitted(&[0x7e, 0x7d], 12).unwrap();
        assert_eq!(&frame.body[..2], &[2, 0]);
        assert_eq!(Frame::parse(&frame.body, 12, 255).unwrap().body, frame.body);
        assert!(Frame::parse(&frame.body, 12, 1).is_none());
        assert!(Frame::parse(&[3, 0, 1], 0, 255).is_none());
        assert!(Frame::parse(&[0, 0], 0, 255).is_none());
    }

    #[test]
    fn decoder_handles_flags_escaping_coalescing_and_connection_boundaries() {
        use umsh_ulcp::hdlc;
        let frame = Frame::transmitted(&[0x7e, 0x7d, 3], 0).unwrap();
        let mut encoded = [0; hdlc::max_encoded_len(MAX_BODY)];
        let len = hdlc::encode_frame(&frame.body, &mut encoded).unwrap();
        let mut decoder = hdlc::Decoder::<{ MAX_BODY + 2 }>::new();
        for _ in 0..100 {
            assert!(decoder.push(0x7e).is_none());
        }
        let mut received = 0;
        for byte in encoded[..len].iter().chain(encoded[..len].iter()) {
            if let Some(Ok(body)) = decoder.push(*byte) {
                assert_eq!(Frame::parse(body, 0, 255).unwrap().data(), frame.data());
                received += 1;
            }
        }
        assert_eq!(received, 2);
        for &byte in &encoded[..len / 2] {
            let _ = decoder.push(byte);
        }
        decoder = hdlc::Decoder::new();
        for &byte in &encoded[len / 2..len] {
            assert!(!matches!(decoder.push(byte), Some(Ok(body)) if !body.is_empty()));
        }
        let mut queue = Queue::new();
        queue.push(frame);
        queue.clear();
        assert!(queue.pop(1).is_none());
    }
}
