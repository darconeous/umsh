//! The tunnel wire protocol: HDLC-Lite frames over a TLS stream.
//!
//! Everything here is deliberately parse-free about what it carries. A
//! frame body is one `STR_PHY_RAW` structure and a participant relays it
//! byte for byte; only the server's forwarding engine ever looks inside.
//!
//! Two details are easy to get wrong and are worth stating plainly:
//!
//! - The keepalive is a **bare `0x7E`**, not an empty frame.
//!   `hdlc::encode_frame(&[])` produces a four-byte frame with an FCS,
//!   which is a legal but pointless message; the idle fill the spec
//!   names is the single flag octet.
//! - Liveness is counted in **received octets**, below the decoder. A
//!   conforming decoder silently absorbs bare flags, so a peer that is
//!   only sending keepalives produces no decoded messages at all and
//!   would otherwise look dead.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use umsh_ulcp::hdlc;
use umsh_ulcp::meta::BufferedRxMeta;

/// Largest tunnel body accepted. A `STR_PHY_RAW` structure is a
/// two-byte length, a frame no larger than any LoRa PHY carries, and a
/// short metadata block; this is generous by an order of magnitude and
/// exists only to bound the decoder.
pub const MAX_BODY: usize = 1024;

/// Reassembly capacity: the body plus HDLC's two FCS bytes.
const DECODER_CAPACITY: usize = MAX_BODY + 2;

/// One tunnel message: the `STR_PHY_RAW` structure, split at the
/// boundary its own length field defines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelFrame {
    pub data: Vec<u8>,
    pub metadata: Vec<u8>,
}

impl TunnelFrame {
    pub fn new(data: Vec<u8>, metadata: Vec<u8>) -> Self {
        Self { data, metadata }
    }

    /// `PACKET_LEN (u16 LE) || PACKET_DATA || PACKET_METADATA`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.data.len() + self.metadata.len());
        out.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.data);
        out.extend_from_slice(&self.metadata);
        out
    }

    /// `None` for a body that is malformed rather than merely
    /// unexpected — too short to hold a length, or claiming more data
    /// than it carries.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let (length, rest) = body.split_at_checked(2)?;
        let data_len = u16::from_le_bytes([length[0], length[1]]) as usize;
        let (data, metadata) = rest.split_at_checked(data_len)?;
        Some(Self {
            data: data.to_vec(),
            metadata: metadata.to_vec(),
        })
    }

    /// Time this frame already spent queued on the device, from the
    /// buffered-frame metadata. Zero for a live delivery, and for a
    /// device that reports no age at all.
    pub fn device_age(&self) -> Duration {
        BufferedRxMeta::decode(&self.metadata)
            .map(|meta| Duration::from_secs(u64::from(meta.age_s)))
            .unwrap_or_default()
    }
}

/// Bounded, drop-oldest outbound queue for one tunnel.
///
/// A frame waiting for a tunnel that has failed or backed up is stale by
/// definition, so the queue never grows to hold it: the oldest goes
/// first, and a reconnect discards everything rather than flushing an
/// old session's frames into a new one.
/// Single-consumer: one writer task drains one queue, which is what
/// lets a single stored waker stand in for a full notification queue.
pub struct TunnelQueue {
    state: Mutex<QueueState>,
    depth: usize,
    max_age: Duration,
}

struct QueueState {
    frames: VecDeque<Queued>,
    /// Bumped on `clear`, so a writer parked on the queue can tell that
    /// the session it was draining has ended.
    generation: u64,
    waker: Option<Waker>,
    dropped_full: u64,
    dropped_stale: u64,
}

struct Queued {
    frame: TunnelFrame,
    enqueued: Instant,
    /// Age the frame already had when it arrived, from the device's
    /// inbound queue.
    inherited: Duration,
}

impl Queued {
    fn age(&self, now: Instant) -> Duration {
        self.inherited + now.saturating_duration_since(self.enqueued)
    }
}

/// What a `pop` returned, or why it did not.
pub enum Dequeued {
    Frame(TunnelFrame),
    /// The queue was cleared while waiting: the session it belonged to
    /// is over.
    SessionEnded,
}

impl TunnelQueue {
    pub fn new(depth: usize, max_age: Duration) -> Self {
        Self {
            state: Mutex::new(QueueState {
                frames: VecDeque::with_capacity(depth),
                generation: 0,
                waker: None,
                dropped_full: 0,
                dropped_stale: 0,
            }),
            depth: depth.max(1),
            max_age,
        }
    }

    /// Enqueue a frame, dropping the oldest if the queue is full.
    ///
    /// Returns whether anything had to be dropped to make room, which
    /// is the signal that this tunnel is not keeping up.
    pub fn push(&self, frame: TunnelFrame) -> bool {
        let inherited = frame.device_age();
        let mut state = self.state.lock().expect("queue lock");
        let mut dropped = false;
        while state.frames.len() >= self.depth {
            state.frames.pop_front();
            state.dropped_full += 1;
            dropped = true;
        }
        state.frames.push_back(Queued {
            frame,
            enqueued: Instant::now(),
            inherited,
        });
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        dropped
    }

    /// The session a consumer is draining. Pass it back to `poll_pop`.
    pub fn generation(&self) -> u64 {
        self.state.lock().expect("queue lock").generation
    }

    /// Take the next frame worth writing, discarding any that outlived
    /// the staleness limit while they waited.
    pub fn poll_pop(&self, generation: u64, cx: &mut Context<'_>) -> Poll<Dequeued> {
        let mut state = self.state.lock().expect("queue lock");
        if state.generation != generation {
            return Poll::Ready(Dequeued::SessionEnded);
        }
        let now = Instant::now();
        while let Some(entry) = state.frames.pop_front() {
            if entry.age(now) > self.max_age {
                state.dropped_stale += 1;
                continue;
            }
            return Poll::Ready(Dequeued::Frame(entry.frame));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Await the next frame worth writing.
    ///
    /// Cancel-safe: nothing leaves the queue until this future is ready
    /// to return it.
    pub async fn pop(&self) -> Dequeued {
        let generation = self.generation();
        core::future::poll_fn(|cx| self.poll_pop(generation, cx)).await
    }

    /// Discard everything queued; a re-established connection starts
    /// empty rather than replaying the last one's backlog.
    pub fn clear(&self) {
        let mut state = self.state.lock().expect("queue lock");
        state.frames.clear();
        state.generation += 1;
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// `(dropped because full, dropped because stale)` since start.
    pub fn dropped(&self) -> (u64, u64) {
        let state = self.state.lock().expect("queue lock");
        (state.dropped_full, state.dropped_stale)
    }
}

/// Drain one session of `queue` onto `writer`, emitting the idle
/// keepalive whenever nothing has been written for a keepalive interval.
///
/// The session is the caller's to name: pass the generation read right
/// after the `clear` that opened it, so clearing the queue again is what
/// ends this pump — and a pump that is spawned but not yet polled cannot
/// adopt a successor's session in the meantime.
pub async fn pump_writer<W: AsyncWrite + Unpin>(
    writer: &mut TunnelWriter<W>,
    queue: &TunnelQueue,
    generation: u64,
) -> std::io::Result<()> {
    let interval = writer.keepalive_interval();
    loop {
        let next = core::future::poll_fn(|cx| queue.poll_pop(generation, cx));
        match tokio::time::timeout(interval, next).await {
            Err(_elapsed) => writer.write_keepalive().await?,
            Ok(Dequeued::SessionEnded) => return Ok(()),
            Ok(Dequeued::Frame(frame)) => writer.write_frame(&frame).await?,
        }
    }
}

/// Writes frames and keepalives onto one half of a tunnel.
pub struct TunnelWriter<W> {
    inner: W,
    keepalive: Duration,
    scratch: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> TunnelWriter<W> {
    pub fn new(inner: W, keepalive: Duration) -> Self {
        Self {
            inner,
            keepalive,
            scratch: vec![0u8; hdlc::max_encoded_len(MAX_BODY)],
        }
    }

    pub async fn write_frame(&mut self, frame: &TunnelFrame) -> std::io::Result<()> {
        let body = frame.encode();
        if body.len() > MAX_BODY {
            // Not an error for the connection: the peer simply cannot
            // be told about a frame this large.
            return Ok(());
        }
        let len = hdlc::encode_frame(&body, &mut self.scratch)
            .map_err(|_| std::io::Error::other("tunnel frame does not fit its encode buffer"))?;
        self.inner.write_all(&self.scratch[..len]).await?;
        self.inner.flush().await
    }

    /// The idle fill: a lone flag octet, which the peer's decoder
    /// discards but its liveness counter sees.
    pub async fn write_keepalive(&mut self) -> std::io::Result<()> {
        self.inner.write_all(&[hdlc::FLAG]).await?;
        self.inner.flush().await
    }

    pub fn keepalive_interval(&self) -> Duration {
        self.keepalive
    }
}

/// Reads frames from one half of a tunnel, enforcing the idle timeout.
pub struct TunnelReader<R> {
    inner: R,
    decoder: Box<hdlc::Decoder<DECODER_CAPACITY>>,
    buf: Vec<u8>,
    /// Bytes of `buf` not yet fed to the decoder, so a read that yields
    /// several frames returns them one at a time.
    pending: std::ops::Range<usize>,
    idle_timeout: Duration,
    malformed: u64,
}

/// Why a tunnel read stopped.
#[derive(Debug)]
pub enum ReadError {
    /// The peer closed the connection, or the stream failed.
    Closed(std::io::Error),
    /// Nothing at all arrived within the idle timeout — not even a
    /// keepalive — so the peer's relay has stopped even if its TLS
    /// session has not.
    Idle,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(error) => write!(f, "tunnel closed: {error}"),
            Self::Idle => f.write_str("tunnel idle: nothing received within the idle timeout"),
        }
    }
}

impl<R: AsyncRead + Unpin> TunnelReader<R> {
    pub fn new(inner: R, idle_timeout: Duration) -> Self {
        Self {
            inner,
            decoder: Box::new(hdlc::Decoder::new()),
            buf: vec![0u8; 4096],
            pending: 0..0,
            idle_timeout,
            malformed: 0,
        }
    }

    /// Await the next well-formed frame.
    ///
    /// Malformed and over-long frames are counted and skipped rather
    /// than failing the connection: a corrupt frame under TLS is a peer
    /// bug, and dropping the tunnel would turn it into an outage.
    pub async fn read_frame(&mut self) -> Result<TunnelFrame, ReadError> {
        loop {
            while self.pending.start < self.pending.end {
                let byte = self.buf[self.pending.start];
                self.pending.start += 1;
                match self.decoder.push(byte) {
                    None => continue,
                    Some(Err(error)) => {
                        self.malformed += 1;
                        tracing::debug!(?error, "discarding a malformed tunnel frame");
                    }
                    Some(Ok(body)) => match TunnelFrame::parse(body) {
                        Some(frame) => return Ok(frame),
                        None => {
                            self.malformed += 1;
                            tracing::debug!(
                                len = body.len(),
                                "discarding a tunnel frame that is not a STR_PHY_RAW structure"
                            );
                        }
                    },
                }
            }

            // Every octet counts as liveness, including the keepalive
            // flags the decoder above threw away without a word.
            let read = tokio::time::timeout(self.idle_timeout, self.inner.read(&mut self.buf))
                .await
                .map_err(|_| ReadError::Idle)?
                .map_err(ReadError::Closed)?;
            if read == 0 {
                return Err(ReadError::Closed(std::io::Error::from(
                    std::io::ErrorKind::UnexpectedEof,
                )));
            }
            self.pending = 0..read;
        }
    }

    pub fn malformed(&self) -> u64 {
        self.malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umsh_ulcp::meta::{RX_FLAG_BUFFERED, RxMeta};

    fn frame(data: &[u8]) -> TunnelFrame {
        TunnelFrame::new(data.to_vec(), vec![91, 0, 0, 0x80])
    }

    #[test]
    fn a_body_round_trips_through_its_own_length_field() {
        let original = frame(&[0x11, 0x22, 0x33]);
        let encoded = original.encode();
        assert_eq!(&encoded[..2], &[3, 0], "length is little-endian");
        assert_eq!(TunnelFrame::parse(&encoded).unwrap(), original);
    }

    #[test]
    fn metadata_may_be_absent_or_extended() {
        for metadata in [
            vec![],
            vec![91, 0, 0, 0x80],
            vec![91, 0, 0, 0x80, 1, 5, 0, 0, 0],
        ] {
            let original = TunnelFrame::new(vec![0xAA; 20], metadata);
            assert_eq!(TunnelFrame::parse(&original.encode()).unwrap(), original);
        }
    }

    #[test]
    fn a_truncated_or_overlong_body_does_not_parse() {
        assert!(TunnelFrame::parse(&[]).is_none());
        assert!(TunnelFrame::parse(&[0x03]).is_none());
        // Claims three bytes of data, carries two.
        assert!(TunnelFrame::parse(&[0x03, 0x00, 0xAA, 0xBB]).is_none());
        // Claims zero and carries only metadata: legal.
        assert!(TunnelFrame::parse(&[0x00, 0x00, 0xAA]).is_some());
    }

    #[test]
    fn device_side_queueing_counts_toward_a_frames_age() {
        let mut metadata = [0u8; umsh_ulcp::meta::BufferedRxMeta::WIRE_LEN];
        BufferedRxMeta {
            rx: RxMeta::default(),
            flags: RX_FLAG_BUFFERED,
            age_s: 7,
        }
        .encode(&mut metadata)
        .unwrap();
        let buffered = TunnelFrame::new(vec![0x01], metadata.to_vec());
        assert_eq!(buffered.device_age(), Duration::from_secs(7));
        // A live delivery, and a device that reports no age at all.
        assert_eq!(frame(&[0x01]).device_age(), Duration::ZERO);
        assert_eq!(
            TunnelFrame::new(vec![0x01], vec![]).device_age(),
            Duration::ZERO
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_queue_drops_the_oldest_frame_when_it_is_full() {
        let queue = TunnelQueue::new(2, Duration::from_secs(10));
        assert!(!queue.push(frame(&[1])));
        assert!(!queue.push(frame(&[2])));
        assert!(queue.push(frame(&[3])), "the third push had to make room");

        let Dequeued::Frame(first) = queue.pop().await else {
            panic!("session ended");
        };
        assert_eq!(first.data, [2], "the oldest went, not the newest");
        assert_eq!(queue.dropped(), (1, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_that_outlived_the_limit_is_discarded_rather_than_written() {
        let queue = TunnelQueue::new(8, Duration::from_secs(10));
        queue.push(frame(&[1]));
        tokio::time::sleep(Duration::from_secs(11)).await;
        queue.push(frame(&[2]));

        let Dequeued::Frame(next) = queue.pop().await else {
            panic!("session ended");
        };
        assert_eq!(next.data, [2]);
        assert_eq!(queue.dropped(), (0, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn device_side_age_is_charged_against_the_same_limit() {
        let mut metadata = [0u8; umsh_ulcp::meta::BufferedRxMeta::WIRE_LEN];
        BufferedRxMeta {
            rx: RxMeta::default(),
            flags: RX_FLAG_BUFFERED,
            age_s: 9,
        }
        .encode(&mut metadata)
        .unwrap();

        let queue = TunnelQueue::new(8, Duration::from_secs(10));
        queue.push(TunnelFrame::new(vec![0x01], metadata.to_vec()));
        // Two more seconds is under the limit on its own, but not on top
        // of the nine the frame spent on the device.
        tokio::time::sleep(Duration::from_secs(2)).await;
        queue.push(frame(&[2]));

        let Dequeued::Frame(next) = queue.pop().await else {
            panic!("session ended");
        };
        assert_eq!(next.data, [2]);
        assert_eq!(queue.dropped(), (0, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_reconnect_discards_the_backlog_instead_of_flushing_it() {
        let queue = std::sync::Arc::new(TunnelQueue::new(8, Duration::from_secs(10)));
        queue.push(frame(&[1]));
        queue.push(frame(&[2]));

        queue.clear();
        assert_eq!(queue.dropped(), (0, 0), "a cleared frame is neither");

        // And a writer already parked learns its session is over rather
        // than waking with the next session's first frame.
        let waiter = {
            let queue = queue.clone();
            tokio::spawn(async move { matches!(queue.pop().await, Dequeued::SessionEnded) })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        queue.clear();
        assert!(waiter.await.unwrap());
    }

    #[tokio::test]
    async fn frames_survive_the_wire_and_keepalives_are_invisible_to_the_decoder() {
        let (client, server) = tokio::io::duplex(4096);
        let mut writer = TunnelWriter::new(client, Duration::from_secs(10));
        let mut reader = TunnelReader::new(server, Duration::from_secs(30));

        writer.write_keepalive().await.unwrap();
        writer
            .write_frame(&frame(&[0x7E, 0x7D, 0x11, 0x13]))
            .await
            .unwrap();
        writer.write_keepalive().await.unwrap();
        writer.write_frame(&frame(&[0xFF; 200])).await.unwrap();

        let first = reader.read_frame().await.unwrap();
        assert_eq!(
            first.data,
            [0x7E, 0x7D, 0x11, 0x13],
            "control bytes escaped"
        );
        let second = reader.read_frame().await.unwrap();
        assert_eq!(second.data.len(), 200);
        assert_eq!(reader.malformed(), 0);
    }

    #[tokio::test]
    async fn a_malformed_frame_is_skipped_rather_than_failing_the_tunnel() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut reader = TunnelReader::new(server, Duration::from_secs(30));

        // A body too short to hold a length field, framed correctly.
        let mut scratch = [0u8; 64];
        let len = hdlc::encode_frame(&[0x01], &mut scratch).unwrap();
        client.write_all(&scratch[..len]).await.unwrap();
        // A frame with a corrupt FCS.
        let len = hdlc::encode_frame(&[0x02, 0x00, 0xAA, 0xBB], &mut scratch).unwrap();
        scratch[2] ^= 0xFF;
        client.write_all(&scratch[..len]).await.unwrap();
        // Then a good one.
        let mut writer = TunnelWriter::new(&mut client, Duration::from_secs(10));
        writer.write_frame(&frame(&[0x42])).await.unwrap();

        let good = reader.read_frame().await.unwrap();
        assert_eq!(good.data, [0x42]);
        assert_eq!(reader.malformed(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_pump_keeps_the_peers_idle_timer_from_firing() {
        let (client, server) = tokio::io::duplex(4096);
        let queue = std::sync::Arc::new(TunnelQueue::new(8, Duration::from_secs(10)));
        let mut reader = TunnelReader::new(server, Duration::from_secs(30));

        let pump = {
            let queue = queue.clone();
            let generation = queue.generation();
            tokio::spawn(async move {
                let mut writer = TunnelWriter::new(client, Duration::from_secs(10));
                pump_writer(&mut writer, &queue, generation).await
            })
        };

        // Nothing to send for two minutes; the reader must not time out.
        tokio::time::sleep(Duration::from_secs(120)).await;
        queue.push(frame(&[0x55]));
        assert_eq!(reader.read_frame().await.unwrap().data, [0x55]);

        queue.clear();
        pump.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn silence_past_the_idle_timeout_ends_the_tunnel() {
        let (client, server) = tokio::io::duplex(4096);
        let mut reader = TunnelReader::new(server, Duration::from_secs(30));
        // Keep the write half alive: TLS stays up, the peer's relay does
        // not, and only the idle timer can tell.
        let held = client;

        assert!(matches!(reader.read_frame().await, Err(ReadError::Idle)));
        drop(held);
    }

    #[tokio::test(start_paused = true)]
    async fn a_keepalive_alone_holds_the_tunnel_open() {
        let (client, server) = tokio::io::duplex(4096);
        let mut writer = TunnelWriter::new(client, Duration::from_secs(10));
        let mut reader = TunnelReader::new(server, Duration::from_secs(30));

        let pump = tokio::spawn(async move {
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_secs(10)).await;
                writer.write_keepalive().await.unwrap();
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
            writer.write_frame(&frame(&[0x99])).await.unwrap();
            writer
        });

        // Seventy seconds of nothing but keepalives, against a
        // thirty-second idle timeout.
        let frame = reader.read_frame().await.unwrap();
        assert_eq!(frame.data, [0x99]);
        drop(pump.await.unwrap());
    }
}
