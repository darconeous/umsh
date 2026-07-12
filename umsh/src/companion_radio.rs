//! Host-side client for the minimal companion-radio (NCP) protocol.
//!
//! [`CompanionRadio`] drives an NCP over any reliable byte stream
//! (USB-CDC serial, UART, TCP, a PTY, ...) using HDLC-Lite framing, and
//! exposes the link as a [`umsh_hal::Radio`] so the host can run the
//! full MAC/node stack with the NCP acting purely as the PHY.
//!
//! The wire format lives in [`umsh_companion`] (re-exported as
//! [`crate::companion`]); this module owns the host-side session
//! behavior: the reset/configure handshake, request/response
//! transactions, and queueing of frames that arrive while a command is
//! in flight.
//!
//! See `docs/protocol/src/companion-radio-minimal.md` for the protocol.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

use umsh_companion::Status;
use umsh_companion::airtime::lora_airtime_ms;
use umsh_companion::frame::{self, Cmd, Frame, PropPayload, StreamPayload, TID_UNSOLICITED};
use umsh_companion::hdlc;
use umsh_companion::ids::{self, prop, stream};
use umsh_companion::meta::{RxMeta, TX_FLAG_NOCCA, TxMeta};
use umsh_companion::pui;
use umsh_hal::{Radio, RxInfo, Snr, TxError, TxOptions};

/// Capacity of the HDLC reassembly buffer (unescaped frame + FCS).
const WIRE_BUF: usize = 1024;
/// Size of one read from the underlying stream.
const READ_CHUNK: usize = 256;
/// Received frames buffered while a command transaction is in flight.
/// The oldest frame is dropped on overflow, matching radio-FIFO
/// overrun semantics.
const RX_QUEUE_DEPTH: usize = 8;
/// Stale command responses retained before the oldest is dropped.
const RESPONSE_QUEUE_DEPTH: usize = 8;
/// Delay between transmit retries while CCA reports a busy channel.
const CCA_RETRY_DELAY: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub enum CompanionRadioError {
    Io(io::Error),
    /// The stream reached end-of-file; the NCP link is gone.
    Disconnected,
    /// The NCP violated the companion-radio protocol.
    Protocol(&'static str),
    /// The NCP reported a failure status for a command.
    Status(Status),
    /// The NCP reset outside of an initialization handshake, losing
    /// its configuration. The radio must be re-initialized.
    UnexpectedReset(Status),
    /// The frame exceeds the NCP's advertised MTU.
    FrameTooLarge(usize),
    /// The NCP did not answer a command in time.
    Timeout,
}

impl core::fmt::Display for CompanionRadioError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "io error: {error}"),
            Self::Disconnected => write!(formatter, "companion link disconnected"),
            Self::Protocol(message) => write!(formatter, "protocol error: {message}"),
            Self::Status(status) => write!(formatter, "NCP reported {status:?}"),
            Self::UnexpectedReset(status) => {
                write!(formatter, "NCP reset unexpectedly ({status:?})")
            }
            Self::FrameTooLarge(len) => write!(formatter, "frame too large: {len} bytes"),
            Self::Timeout => write!(formatter, "timed out waiting for NCP response"),
        }
    }
}

impl std::error::Error for CompanionRadioError {}

impl From<io::Error> for CompanionRadioError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// RF and session configuration applied during initialization.
#[derive(Clone, Debug)]
pub struct CompanionRadioConfig {
    /// Center frequency in kHz (`PROP_PHY_FREQ`).
    pub freq_khz: u32,
    /// LoRa bandwidth in Hz (`PROP_PHY_LORA_BW`).
    pub bandwidth_hz: u32,
    /// LoRa spreading factor, 5-12 (`PROP_PHY_LORA_SF`).
    pub spreading_factor: u8,
    /// LoRa coding-rate denominator: 5 for 4/5 through 8 for 4/8
    /// (`PROP_PHY_LORA_CR`).
    pub coding_rate_denom: u8,
    /// Transmit power in dBm (`PROP_PHY_TX_POWER`).
    pub tx_power_dbm: i8,
    /// SX126x-style 16-bit sync word (`PROP_PHY_LORA_SW`).
    pub sync_word: u16,
    /// How long to wait for the NCP to answer one command, excluding
    /// airtime (transmit confirmations extend this by the frame
    /// airtime).
    pub response_timeout: Duration,
}

impl CompanionRadioConfig {
    /// Configuration with the given RF link parameters, 0 dBm transmit
    /// power, the suggested default sync word, and a 2-second response
    /// timeout.
    pub fn new(
        freq_khz: u32,
        bandwidth_hz: u32,
        spreading_factor: u8,
        coding_rate_denom: u8,
    ) -> Self {
        Self {
            freq_khz,
            bandwidth_hz,
            spreading_factor,
            coding_rate_denom,
            tx_power_dbm: 0,
            sync_word: 0x1424,
            response_timeout: Duration::from_secs(2),
        }
    }
}

struct RxPacket {
    data: Vec<u8>,
    meta: RxMeta,
}

/// A `CMD_PROP_IS` received with a non-zero TID (a command response).
struct Response {
    tid: u8,
    key: u32,
    value: Vec<u8>,
}

/// Companion radio attached over a byte stream, usable as a
/// [`umsh_hal::Radio`].
pub struct CompanionRadio<IO> {
    io: IO,
    config: CompanionRadioConfig,
    decoder: hdlc::Decoder<WIRE_BUF>,
    rx_queue: VecDeque<RxPacket>,
    responses: VecDeque<Response>,
    /// Unsolicited reset notification not yet surfaced to the caller.
    seen_reset: Option<Status>,
    max_frame_size: usize,
    t_frame_ms: u32,
    ncp_version: String,
    next_tid: u8,
}

impl<IO> CompanionRadio<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Attach to an NCP: reset it, verify the protocol version, apply
    /// the RF configuration, and enable the PHY.
    pub async fn new(io: IO, config: CompanionRadioConfig) -> Result<Self, CompanionRadioError> {
        let mut radio = Self {
            io,
            config,
            decoder: hdlc::Decoder::new(),
            rx_queue: VecDeque::new(),
            responses: VecDeque::new(),
            seen_reset: None,
            max_frame_size: 0,
            t_frame_ms: 0,
            ncp_version: String::new(),
            next_tid: 1,
        };
        radio.initialize().await?;
        Ok(radio)
    }

    /// The NCP's firmware version string (`PROP_NCP_VERSION`).
    pub fn ncp_version(&self) -> &str {
        &self.ncp_version
    }

    async fn initialize(&mut self) -> Result<(), CompanionRadioError> {
        // Reset and wait for the reset notification. The TID is
        // ignored for CMD_RST; the notification is unsolicited.
        let mut buf = [0u8; 2];
        let len = frame::reset(&mut buf, TID_UNSOLICITED)
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
        self.send_frame_buf(&buf[..len]).await?;
        let deadline = Instant::now() + self.config.response_timeout;
        self.wait_reset(deadline).await?;

        // Reject NCPs speaking an incompatible protocol revision.
        let version = self.get_prop(prop::PROTOCOL_VERSION).await?;
        if version.first().copied() != Some(ids::PROTOCOL_MAJOR_VERSION) {
            return Err(CompanionRadioError::Protocol(
                "protocol major version mismatch",
            ));
        }

        let ncp_version = self.get_prop(prop::NCP_VERSION).await?;
        self.ncp_version = String::from_utf8_lossy(&ncp_version)
            .trim_end_matches('\0')
            .to_owned();

        let mtu = self.get_prop(prop::PHY_MTU).await?;
        let [mtu_lo, mtu_hi, ..] = mtu[..] else {
            return Err(CompanionRadioError::Protocol("malformed PROP_PHY_MTU"));
        };
        self.max_frame_size = usize::from(u16::from_le_bytes([mtu_lo, mtu_hi]));
        if self.max_frame_size == 0 {
            return Err(CompanionRadioError::Protocol("NCP advertised zero MTU"));
        }

        let config = self.config.clone();
        self.set_prop(prop::PHY_FREQ, &config.freq_khz.to_le_bytes())
            .await?;
        self.set_prop(prop::PHY_LORA_BW, &config.bandwidth_hz.to_le_bytes())
            .await?;
        self.set_prop(prop::PHY_LORA_SF, &[config.spreading_factor])
            .await?;
        self.set_prop(prop::PHY_LORA_CR, &[config.coding_rate_denom])
            .await?;
        self.set_prop(prop::PHY_TX_POWER, &[config.tx_power_dbm as u8])
            .await?;
        self.set_prop(prop::PHY_LORA_SW, &config.sync_word.to_le_bytes())
            .await?;
        self.set_prop(prop::PHY_ENABLED, &[1]).await?;

        self.t_frame_ms = lora_airtime_ms(
            config.spreading_factor,
            config.bandwidth_hz,
            config.coding_rate_denom,
            self.max_frame_size,
        )
        .max(1);
        Ok(())
    }

    /// Fetch a property's raw value via `CMD_PROP_GET`.
    pub async fn get_prop(&mut self, key: u32) -> Result<Vec<u8>, CompanionRadioError> {
        let tid = self.alloc_tid();
        let mut buf = [0u8; 8];
        let len = frame::prop_get(&mut buf, tid, key)
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
        self.send_frame_buf(&buf[..len]).await?;
        self.finish_prop_transaction(tid, key).await
    }

    /// Set a property via `CMD_PROP_SET`, returning the authoritative
    /// value echoed by the NCP.
    pub async fn set_prop(
        &mut self,
        key: u32,
        value: &[u8],
    ) -> Result<Vec<u8>, CompanionRadioError> {
        let tid = self.alloc_tid();
        let mut buf = vec![0u8; value.len() + 8];
        let len = frame::prop_set(&mut buf, tid, key, value)
            .map_err(|_| CompanionRadioError::Protocol("frame encode"))?;
        self.send_frame_buf(&buf[..len]).await?;
        self.finish_prop_transaction(tid, key).await
    }

    async fn finish_prop_transaction(
        &mut self,
        tid: u8,
        key: u32,
    ) -> Result<Vec<u8>, CompanionRadioError> {
        let deadline = Instant::now() + self.config.response_timeout;
        let (response_key, value) = self.wait_response(tid, deadline).await?;
        if response_key == key {
            Ok(value)
        } else if response_key == prop::LAST_STATUS {
            Err(CompanionRadioError::Status(decode_status(&value)))
        } else {
            Err(CompanionRadioError::Protocol(
                "response for unexpected property",
            ))
        }
    }

    fn alloc_tid(&mut self) -> u8 {
        let tid = self.next_tid;
        self.next_tid = if tid >= frame::TID_MAX { 1 } else { tid + 1 };
        tid
    }

    /// HDLC-encode and send one companion frame.
    async fn send_frame_buf(&mut self, frame_bytes: &[u8]) -> Result<(), CompanionRadioError> {
        let mut wire = vec![0u8; hdlc::max_encoded_len(frame_bytes.len())];
        let len = hdlc::encode_frame(frame_bytes, &mut wire)
            .expect("buffer sized with max_encoded_len");
        self.io.write_all(&wire[..len]).await?;
        self.io.flush().await?;
        Ok(())
    }

    /// Feed received bytes through the HDLC decoder and sort complete
    /// frames into the receive queue, the response queue, or the
    /// reset flag. Malformed frames are dropped; the decoder
    /// resynchronizes on the next flag byte.
    fn ingest(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            let Some(Ok(frame_bytes)) = self.decoder.push(byte) else {
                continue;
            };
            let Ok(frame) = Frame::parse(frame_bytes) else {
                continue;
            };
            match frame.command() {
                Some(Cmd::StrRecv) => {
                    let Ok(payload) = StreamPayload::parse(frame.payload) else {
                        continue;
                    };
                    if payload.stream != stream::PHY_RAW {
                        continue;
                    }
                    let meta = RxMeta::decode(payload.metadata).unwrap_or_default();
                    if self.rx_queue.len() >= RX_QUEUE_DEPTH {
                        self.rx_queue.pop_front();
                    }
                    self.rx_queue.push_back(RxPacket {
                        data: payload.data.to_vec(),
                        meta,
                    });
                }
                Some(Cmd::PropIs) => {
                    let Ok(payload) = PropPayload::parse(frame.payload) else {
                        continue;
                    };
                    let tid = frame.header.tid();
                    if tid == TID_UNSOLICITED {
                        if payload.key == prop::LAST_STATUS {
                            let status = decode_status(payload.value);
                            if status.is_reset() {
                                self.seen_reset = Some(status);
                            }
                        }
                        // Other unsolicited property updates are not
                        // used by this client yet.
                    } else {
                        if self.responses.len() >= RESPONSE_QUEUE_DEPTH {
                            self.responses.pop_front();
                        }
                        self.responses.push_back(Response {
                            tid,
                            key: payload.key,
                            value: payload.value.to_vec(),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    /// Read from the stream until the response for `tid` arrives.
    ///
    /// Frames received meanwhile are queued for [`Radio::poll_receive`].
    async fn wait_response(
        &mut self,
        tid: u8,
        deadline: Instant,
    ) -> Result<(u32, Vec<u8>), CompanionRadioError> {
        loop {
            // Drain responses before honoring a reset notice: if both
            // arrived in one read, the response was sent first and the
            // command did complete. The reset stays latched for the
            // next receive poll.
            while let Some(response) = self.responses.pop_front() {
                if response.tid == tid {
                    return Ok((response.key, response.value));
                }
                // A stale response from an earlier timed-out
                // transaction; drop it.
            }
            if let Some(status) = self.seen_reset.take() {
                return Err(CompanionRadioError::UnexpectedReset(status));
            }
            self.read_more(deadline).await?;
        }
    }

    /// Read until the NCP announces a reset via `PROP_LAST_STATUS`.
    async fn wait_reset(&mut self, deadline: Instant) -> Result<Status, CompanionRadioError> {
        loop {
            if let Some(status) = self.seen_reset.take() {
                return Ok(status);
            }
            // Accept a reset notice even if the NCP attached a TID.
            while let Some(response) = self.responses.pop_front() {
                if response.key == prop::LAST_STATUS {
                    let status = decode_status(&response.value);
                    if status.is_reset() {
                        return Ok(status);
                    }
                }
            }
            self.read_more(deadline).await?;
        }
    }

    async fn read_more(&mut self, deadline: Instant) -> Result<(), CompanionRadioError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(CompanionRadioError::Timeout);
        }
        let mut chunk = [0u8; READ_CHUNK];
        let read = match tokio::time::timeout(deadline - now, self.io.read(&mut chunk)).await {
            Err(_elapsed) => return Err(CompanionRadioError::Timeout),
            Ok(Err(error)) => return Err(CompanionRadioError::Io(error)),
            Ok(Ok(0)) => return Err(CompanionRadioError::Disconnected),
            Ok(Ok(read)) => read,
        };
        self.ingest(&chunk[..read]);
        Ok(())
    }

    fn pop_rx(&mut self, buf: &mut [u8]) -> Option<RxInfo> {
        let packet = self.rx_queue.pop_front()?;
        let len = packet.data.len().min(buf.len());
        buf[..len].copy_from_slice(&packet.data[..len]);
        Some(RxInfo {
            len,
            rssi: packet.meta.rssi_dbm.unwrap_or(0),
            snr: Snr::from_centibels(packet.meta.snr_cb.unwrap_or(0)),
            lqi: packet.meta.lqi,
        })
    }
}

#[cfg(feature = "serial-radio")]
impl CompanionRadio<tokio_serial::SerialStream> {
    /// Attach to an NCP on a serial port.
    pub async fn open_serial(
        path: impl AsRef<str>,
        baud_rate: u32,
        config: CompanionRadioConfig,
    ) -> Result<Self, CompanionRadioError> {
        use tokio_serial::SerialPortBuilderExt;

        let stream = tokio_serial::new(path.as_ref(), baud_rate)
            .open_native_async()
            .map_err(|error| CompanionRadioError::Io(error.into()))?;
        Self::new(stream, config).await
    }
}

impl<IO> Radio for CompanionRadio<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Error = CompanionRadioError;

    async fn transmit(
        &mut self,
        data: &[u8],
        options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        if data.len() > self.max_frame_size {
            return Err(TxError::Io(CompanionRadioError::FrameTooLarge(data.len())));
        }

        // The NCP performs CCA itself; `cad_timeout_ms` becomes a
        // host-side retry budget around `STATUS_CCA_FAILURE`.
        let mut meta = TxMeta::default();
        let cca_deadline = match options.cad_timeout_ms {
            None => {
                meta.flags |= TX_FLAG_NOCCA;
                None
            }
            Some(timeout_ms) => Some(Instant::now() + Duration::from_millis(timeout_ms.into())),
        };
        let mut meta_buf = [0u8; TxMeta::WIRE_LEN];
        let meta_len = meta
            .encode(&mut meta_buf)
            .expect("buffer sized with WIRE_LEN");

        loop {
            let tid = self.alloc_tid();
            let mut frame_buf = vec![0u8; data.len() + 16];
            let frame_len = frame::str_send(
                &mut frame_buf,
                tid,
                stream::PHY_RAW,
                data,
                &meta_buf[..meta_len],
            )
            .map_err(|_| TxError::Io(CompanionRadioError::Protocol("frame encode")))?;
            self.send_frame_buf(&frame_buf[..frame_len])
                .await
                .map_err(TxError::Io)?;

            // The confirmation arrives only after the frame is on the
            // air (or definitively failed), so allow for airtime.
            let deadline = Instant::now()
                + self.config.response_timeout
                + Duration::from_millis(u64::from(self.t_frame_ms) * 2);
            let (key, value) = self.wait_response(tid, deadline).await.map_err(TxError::Io)?;
            if key != prop::LAST_STATUS {
                return Err(TxError::Io(CompanionRadioError::Protocol(
                    "unexpected transmit response",
                )));
            }
            match decode_status(&value) {
                Status::OK => return Ok(()),
                Status::CCA_FAILURE => match cca_deadline {
                    Some(deadline) if Instant::now() < deadline => {
                        tokio::time::sleep(CCA_RETRY_DELAY).await;
                    }
                    _ => return Err(TxError::CadTimeout),
                },
                status => return Err(TxError::Io(CompanionRadioError::Status(status))),
            }
        }
    }

    fn poll_receive(
        &mut self,
        cx: &mut core::task::Context<'_>,
        buf: &mut [u8],
    ) -> core::task::Poll<Result<RxInfo, Self::Error>> {
        loop {
            if let Some(status) = self.seen_reset.take() {
                return core::task::Poll::Ready(Err(CompanionRadioError::UnexpectedReset(status)));
            }
            if let Some(info) = self.pop_rx(buf) {
                return core::task::Poll::Ready(Ok(info));
            }

            let mut chunk = [0u8; READ_CHUNK];
            let mut read_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.io).poll_read(cx, &mut read_buf) {
                core::task::Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled().len();
                    if filled == 0 {
                        return core::task::Poll::Ready(Err(CompanionRadioError::Disconnected));
                    }
                    self.ingest(&chunk[..filled]);
                }
                core::task::Poll::Ready(Err(error)) => {
                    return core::task::Poll::Ready(Err(CompanionRadioError::Io(error)));
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn t_frame_ms(&self) -> u32 {
        self.t_frame_ms
    }
}

fn decode_status(value: &[u8]) -> Status {
    match pui::decode(value) {
        Ok((code, _)) => Status(code),
        Err(_) => Status::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::DuplexStream;

    /// Payload that makes the fake NCP report a CCA failure.
    const CCA_FAIL: &[u8] = b"cca-fail";
    /// Payload that makes the fake NCP report success and then
    /// announce a spurious watchdog reset.
    const RESET_AFTER: &[u8] = b"reset-after";

    /// Minimal in-process NCP: answers the initialization handshake,
    /// stores property sets, and echoes transmitted frames back as
    /// received frames.
    async fn fake_ncp(mut io: DuplexStream) {
        let mut decoder = hdlc::Decoder::<WIRE_BUF>::new();
        let mut props: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            let read = match io.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            let mut replies: Vec<Vec<u8>> = Vec::new();
            for &byte in &chunk[..read] {
                let Some(Ok(frame_bytes)) = decoder.push(byte) else {
                    continue;
                };
                let frame = Frame::parse(frame_bytes).expect("host sent malformed frame");
                let tid = frame.header.tid();
                let mut buf = vec![0u8; 512];
                match frame.command().expect("host sent unknown command") {
                    Cmd::Reset => {
                        let len =
                            frame::last_status(&mut buf, TID_UNSOLICITED, Status::RESET_SOFTWARE)
                                .unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropGet => {
                        let key = PropPayload::parse(frame.payload).unwrap().key;
                        let value: Vec<u8> = match key {
                            prop::PROTOCOL_VERSION => {
                                vec![ids::PROTOCOL_MAJOR_VERSION, ids::PROTOCOL_MINOR_VERSION]
                            }
                            prop::NCP_VERSION => b"fake-ncp/0.1\0".to_vec(),
                            prop::PHY_MTU => 255u16.to_le_bytes().to_vec(),
                            _ => props.get(&key).cloned().unwrap_or_default(),
                        };
                        let len = frame::prop_is(&mut buf, tid, key, &value).unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropSet => {
                        let payload = PropPayload::parse(frame.payload).unwrap();
                        props.insert(payload.key, payload.value.to_vec());
                        let len =
                            frame::prop_is(&mut buf, tid, payload.key, payload.value).unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::StrSend => {
                        let payload = StreamPayload::parse(frame.payload).unwrap();
                        assert_eq!(payload.stream, stream::PHY_RAW);
                        if payload.data == CCA_FAIL {
                            let len =
                                frame::last_status(&mut buf, tid, Status::CCA_FAILURE).unwrap();
                            replies.push(buf[..len].to_vec());
                            continue;
                        }
                        let len = frame::last_status(&mut buf, tid, Status::OK).unwrap();
                        replies.push(buf[..len].to_vec());
                        if payload.data == RESET_AFTER {
                            let len = frame::last_status(
                                &mut buf,
                                TID_UNSOLICITED,
                                Status::RESET_WATCHDOG,
                            )
                            .unwrap();
                            replies.push(buf[..len].to_vec());
                            continue;
                        }
                        // Echo the packet back as a reception.
                        let mut meta = [0u8; RxMeta::WIRE_LEN];
                        RxMeta {
                            rssi_dbm: Some(-91),
                            lqi: None,
                            snr_cb: Some(55),
                        }
                        .encode(&mut meta)
                        .unwrap();
                        let len =
                            frame::str_recv(&mut buf, stream::PHY_RAW, payload.data, &meta)
                                .unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::Nop => {
                        let len = frame::last_status(&mut buf, tid, Status::OK).unwrap();
                        replies.push(buf[..len].to_vec());
                    }
                    Cmd::PropIs | Cmd::StrRecv => panic!("host sent an NCP-only command"),
                }
            }
            for reply in replies {
                let mut wire = vec![0u8; hdlc::max_encoded_len(reply.len())];
                let len = hdlc::encode_frame(&reply, &mut wire).unwrap();
                if io.write_all(&wire[..len]).await.is_err() {
                    return;
                }
            }
        }
    }

    fn test_config() -> CompanionRadioConfig {
        let mut config = CompanionRadioConfig::new(906_875, 250_000, 11, 5);
        config.tx_power_dbm = 10;
        config.response_timeout = Duration::from_millis(500);
        config
    }

    async fn attached_radio() -> CompanionRadio<DuplexStream> {
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(fake_ncp(server));
        CompanionRadio::new(client, test_config()).await.unwrap()
    }

    #[tokio::test]
    async fn initialization_handshake() {
        let radio = attached_radio().await;
        assert_eq!(radio.max_frame_size(), 255);
        assert_eq!(radio.ncp_version(), "fake-ncp/0.1");
        assert!(radio.t_frame_ms() > 0);
    }

    #[tokio::test]
    async fn transmit_and_receive_round_trip() {
        let mut radio = attached_radio().await;
        let packet = [0x10u8, 0x20, 0x30, 0x40];
        radio.transmit(&packet, TxOptions::default()).await.unwrap();

        let mut buf = [0u8; 256];
        let info = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf))
            .await
            .unwrap();
        assert_eq!(&buf[..info.len], &packet);
        assert_eq!(info.rssi, -91);
        assert_eq!(info.snr.as_centibels(), 55);
    }

    #[tokio::test]
    async fn cca_failure_maps_to_cad_timeout() {
        let mut radio = attached_radio().await;
        let result = radio
            .transmit(
                CCA_FAIL,
                TxOptions {
                    cad_timeout_ms: Some(0),
                },
            )
            .await;
        assert!(matches!(result, Err(TxError::CadTimeout)));
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let mut radio = attached_radio().await;
        let oversized = vec![0u8; radio.max_frame_size() + 1];
        let result = radio.transmit(&oversized, TxOptions::default()).await;
        assert!(matches!(
            result,
            Err(TxError::Io(CompanionRadioError::FrameTooLarge(_)))
        ));
    }

    #[tokio::test]
    async fn unexpected_reset_surfaces_on_receive() {
        let mut radio = attached_radio().await;
        radio
            .transmit(RESET_AFTER, TxOptions::default())
            .await
            .unwrap();

        let mut buf = [0u8; 256];
        let result = core::future::poll_fn(|cx| radio.poll_receive(cx, &mut buf)).await;
        assert!(matches!(
            result,
            Err(CompanionRadioError::UnexpectedReset(status))
                if status == Status::RESET_WATCHDOG
        ));
    }

    #[test]
    fn airtime_is_plausible() {
        // ~255-byte frame at SF11/BW250 is on the order of seconds.
        let airtime = lora_airtime_ms(11, 250_000, 5, 255);
        assert!((500..5_000).contains(&airtime), "airtime {airtime}");
        // Faster settings give shorter airtime.
        assert!(lora_airtime_ms(7, 250_000, 5, 255) < airtime);
    }
}
