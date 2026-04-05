//! Example-only serial shim for the desktop chat demo.
//!
//! This module is intentionally not part of the public `umsh` crate API because
//! the byte-level command protocol used here is only a provisional demo hook.
//! It is not specified by the protocol docs and should not be treated as the
//! intended long-term companion-radio interface.

use std::io;
use std::pin::Pin;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use umsh::hal::{Radio, RxInfo, TxError, TxOptions};

const CMD_TRANSMIT: u8 = 0x01;
const CMD_RECEIVE: u8 = 0x02;
const CMD_CAD: u8 = 0x03;
const CMD_MAX_FRAME_SIZE: u8 = 0x04;
const CMD_T_FRAME_MS: u8 = 0x05;

const RESP_TRANSMIT: u8 = 0x81;
const RESP_RECEIVE: u8 = 0x82;
const RESP_CAD: u8 = 0x83;
const RESP_MAX_FRAME_SIZE: u8 = 0x84;
const RESP_T_FRAME_MS: u8 = 0x85;

#[derive(Debug)]
pub enum DraftSerialRadioError {
    Io(io::Error),
    Protocol(&'static str),
    FrameTooLarge(usize),
}

impl core::fmt::Display for DraftSerialRadioError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "io error: {error}"),
            Self::Protocol(message) => write!(formatter, "protocol error: {message}"),
            Self::FrameTooLarge(len) => write!(formatter, "frame too large: {len} bytes"),
        }
    }
}

impl std::error::Error for DraftSerialRadioError {}

impl From<io::Error> for DraftSerialRadioError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct DraftSerialRadio<IO> {
    io: IO,
    max_frame_size: usize,
    t_frame_ms: u32,
    receive_state: ReceiveState,
    receive_payload: Vec<u8>,
}

enum ReceiveState {
    Idle,
    SendingCommand {
        written: usize,
    },
    FlushingCommand,
    ReadingTag {
        filled: usize,
        tag: [u8; 1],
    },
    ReadingMeta {
        filled: usize,
        meta: [u8; 5],
    },
    ReadingPayload {
        len: usize,
        rssi: i16,
        snr: i8,
        filled: usize,
    },
}

impl<IO> DraftSerialRadio<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn from_stream(mut io: IO) -> Result<Self, DraftSerialRadioError> {
        let max_frame_size =
            query_u16(&mut io, CMD_MAX_FRAME_SIZE, RESP_MAX_FRAME_SIZE).await? as usize;
        let t_frame_ms = query_u32(&mut io, CMD_T_FRAME_MS, RESP_T_FRAME_MS).await?;
        Ok(Self {
            io,
            max_frame_size,
            t_frame_ms,
            receive_state: ReceiveState::Idle,
            receive_payload: vec![0u8; max_frame_size],
        })
    }

    async fn send_tag(&mut self, tag: u8) -> Result<(), DraftSerialRadioError> {
        self.io
            .write_all(&[tag])
            .await
            .map_err(DraftSerialRadioError::Io)?;
        self.io.flush().await.map_err(DraftSerialRadioError::Io)
    }

    async fn expect_tag(&mut self, expected: u8) -> Result<(), DraftSerialRadioError> {
        let mut tag = [0u8; 1];
        self.io
            .read_exact(&mut tag)
            .await
            .map_err(DraftSerialRadioError::Io)?;
        if tag[0] != expected {
            return Err(DraftSerialRadioError::Protocol("unexpected response tag"));
        }
        Ok(())
    }

    async fn cad_busy(&mut self) -> Result<bool, DraftSerialRadioError> {
        self.send_tag(CMD_CAD).await?;
        self.expect_tag(RESP_CAD).await?;
        let mut busy = [0u8; 1];
        self.io
            .read_exact(&mut busy)
            .await
            .map_err(DraftSerialRadioError::Io)?;
        Ok(busy[0] != 0)
    }
}

#[cfg(feature = "serial-radio")]
impl DraftSerialRadio<tokio_serial::SerialStream> {
    pub async fn open_tokio(
        path: impl AsRef<str>,
        baud_rate: u32,
    ) -> Result<Self, DraftSerialRadioError> {
        use tokio_serial::SerialPortBuilderExt;

        let stream = tokio_serial::new(path.as_ref(), baud_rate)
            .open_native_async()
            .map_err(|error| DraftSerialRadioError::Io(error.into()))?;
        Self::from_stream(stream).await
    }
}

impl<IO> Radio for DraftSerialRadio<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Error = DraftSerialRadioError;

    async fn transmit(
        &mut self,
        data: &[u8],
        options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        if data.len() > self.max_frame_size || data.len() > u16::MAX as usize {
            return Err(TxError::Io(DraftSerialRadioError::FrameTooLarge(
                data.len(),
            )));
        }

        if let Some(cad_timeout_ms) = options.cad_timeout_ms {
            let deadline = Instant::now() + Duration::from_millis(u64::from(cad_timeout_ms));
            loop {
                let busy = self.cad_busy().await.map_err(TxError::Io)?;
                if !busy {
                    break;
                }
                if cad_timeout_ms == 0 || Instant::now() >= deadline {
                    return Err(TxError::CadTimeout);
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        self.send_tag(CMD_TRANSMIT).await.map_err(TxError::Io)?;
        self.io
            .write_all(&(data.len() as u16).to_le_bytes())
            .await
            .map_err(DraftSerialRadioError::Io)
            .map_err(TxError::Io)?;
        self.io
            .write_all(data)
            .await
            .map_err(DraftSerialRadioError::Io)
            .map_err(TxError::Io)?;
        self.io
            .flush()
            .await
            .map_err(DraftSerialRadioError::Io)
            .map_err(TxError::Io)?;
        self.expect_tag(RESP_TRANSMIT).await.map_err(TxError::Io)?;
        let mut status = [0u8; 1];
        self.io
            .read_exact(&mut status)
            .await
            .map_err(DraftSerialRadioError::Io)
            .map_err(TxError::Io)?;
        if status[0] != 0 {
            return Err(TxError::Io(DraftSerialRadioError::Protocol(
                "companion transmit rejected frame",
            )));
        }
        Ok(())
    }

    fn poll_receive(
        &mut self,
        cx: &mut core::task::Context<'_>,
        buf: &mut [u8],
    ) -> core::task::Poll<Result<RxInfo, Self::Error>> {
        loop {
            let state = core::mem::replace(&mut self.receive_state, ReceiveState::Idle);
            match state {
                ReceiveState::Idle => {
                    self.receive_state = ReceiveState::SendingCommand { written: 0 };
                }
                ReceiveState::SendingCommand { mut written } => {
                    match poll_write_all(&mut self.io, cx, &[CMD_RECEIVE], &mut written) {
                        core::task::Poll::Ready(Ok(())) => {
                            self.receive_state = ReceiveState::FlushingCommand;
                        }
                        core::task::Poll::Ready(Err(error)) => {
                            return core::task::Poll::Ready(Err(error));
                        }
                        core::task::Poll::Pending => {
                            self.receive_state = ReceiveState::SendingCommand { written };
                            return core::task::Poll::Pending;
                        }
                    }
                }
                ReceiveState::FlushingCommand => match Pin::new(&mut self.io).poll_flush(cx) {
                    core::task::Poll::Ready(Ok(())) => {
                        self.receive_state = ReceiveState::ReadingTag {
                            filled: 0,
                            tag: [0u8; 1],
                        };
                    }
                    core::task::Poll::Ready(Err(error)) => {
                        return core::task::Poll::Ready(Err(DraftSerialRadioError::Io(error)));
                    }
                    core::task::Poll::Pending => {
                        self.receive_state = ReceiveState::FlushingCommand;
                        return core::task::Poll::Pending;
                    }
                },
                ReceiveState::ReadingTag {
                    mut filled,
                    mut tag,
                } => match poll_read_exact(&mut self.io, cx, &mut tag, &mut filled) {
                    core::task::Poll::Ready(Ok(())) => {
                        if tag[0] != RESP_RECEIVE {
                            return core::task::Poll::Ready(Err(DraftSerialRadioError::Protocol(
                                "unexpected response tag",
                            )));
                        }
                        self.receive_state = ReceiveState::ReadingMeta {
                            filled: 0,
                            meta: [0u8; 5],
                        };
                    }
                    core::task::Poll::Ready(Err(error)) => {
                        return core::task::Poll::Ready(Err(error));
                    }
                    core::task::Poll::Pending => {
                        self.receive_state = ReceiveState::ReadingTag { filled, tag };
                        return core::task::Poll::Pending;
                    }
                },
                ReceiveState::ReadingMeta {
                    mut filled,
                    mut meta,
                } => match poll_read_exact(&mut self.io, cx, &mut meta, &mut filled) {
                    core::task::Poll::Ready(Ok(())) => {
                        let len = u16::from_le_bytes([meta[0], meta[1]]) as usize;
                        let rssi = i16::from_le_bytes([meta[2], meta[3]]);
                        let snr = meta[4] as i8;
                        if len == 0 {
                            return core::task::Poll::Pending;
                        }
                        if len > self.max_frame_size {
                            return core::task::Poll::Ready(Err(
                                DraftSerialRadioError::FrameTooLarge(len),
                            ));
                        }
                        if self.receive_payload.len() < len {
                            self.receive_payload.resize(len, 0);
                        }
                        self.receive_state = ReceiveState::ReadingPayload {
                            len,
                            rssi,
                            snr,
                            filled: 0,
                        };
                    }
                    core::task::Poll::Ready(Err(error)) => {
                        return core::task::Poll::Ready(Err(error));
                    }
                    core::task::Poll::Pending => {
                        self.receive_state = ReceiveState::ReadingMeta { filled, meta };
                        return core::task::Poll::Pending;
                    }
                },
                ReceiveState::ReadingPayload {
                    len,
                    rssi,
                    snr,
                    mut filled,
                } => {
                    match poll_read_exact(
                        &mut self.io,
                        cx,
                        &mut self.receive_payload[..len],
                        &mut filled,
                    ) {
                        core::task::Poll::Ready(Ok(())) => {
                            if len > buf.len() {
                                return core::task::Poll::Ready(Err(
                                    DraftSerialRadioError::FrameTooLarge(len),
                                ));
                            }
                            buf[..len].copy_from_slice(&self.receive_payload[..len]);
                            return core::task::Poll::Ready(Ok(RxInfo { len, rssi, snr }));
                        }
                        core::task::Poll::Ready(Err(error)) => {
                            return core::task::Poll::Ready(Err(error));
                        }
                        core::task::Poll::Pending => {
                            self.receive_state = ReceiveState::ReadingPayload {
                                len,
                                rssi,
                                snr,
                                filled,
                            };
                            return core::task::Poll::Pending;
                        }
                    }
                }
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

async fn query_u16<IO>(io: &mut IO, command: u8, response: u8) -> Result<u16, DraftSerialRadioError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    io.write_all(&[command])
        .await
        .map_err(DraftSerialRadioError::Io)?;
    io.flush().await.map_err(DraftSerialRadioError::Io)?;
    let mut tag = [0u8; 1];
    io.read_exact(&mut tag)
        .await
        .map_err(DraftSerialRadioError::Io)?;
    if tag[0] != response {
        return Err(DraftSerialRadioError::Protocol("unexpected response tag"));
    }
    read_u16(io).await
}

async fn query_u32<IO>(io: &mut IO, command: u8, response: u8) -> Result<u32, DraftSerialRadioError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    io.write_all(&[command])
        .await
        .map_err(DraftSerialRadioError::Io)?;
    io.flush().await.map_err(DraftSerialRadioError::Io)?;
    let mut tag = [0u8; 1];
    io.read_exact(&mut tag)
        .await
        .map_err(DraftSerialRadioError::Io)?;
    if tag[0] != response {
        return Err(DraftSerialRadioError::Protocol("unexpected response tag"));
    }
    read_u32(io).await
}

async fn read_u16<IO>(io: &mut IO) -> Result<u16, DraftSerialRadioError>
where
    IO: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    io.read_exact(&mut bytes)
        .await
        .map_err(DraftSerialRadioError::Io)?;
    Ok(u16::from_le_bytes(bytes))
}

async fn read_u32<IO>(io: &mut IO) -> Result<u32, DraftSerialRadioError>
where
    IO: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 4];
    io.read_exact(&mut bytes)
        .await
        .map_err(DraftSerialRadioError::Io)?;
    Ok(u32::from_le_bytes(bytes))
}

fn poll_write_all<IO>(
    io: &mut IO,
    cx: &mut core::task::Context<'_>,
    buf: &[u8],
    written: &mut usize,
) -> core::task::Poll<Result<(), DraftSerialRadioError>>
where
    IO: AsyncWrite + Unpin,
{
    while *written < buf.len() {
        match Pin::new(&mut *io).poll_write(cx, &buf[*written..]) {
            core::task::Poll::Ready(Ok(0)) => {
                return core::task::Poll::Ready(Err(DraftSerialRadioError::Protocol(
                    "short write while sending command",
                )));
            }
            core::task::Poll::Ready(Ok(count)) => {
                *written += count;
            }
            core::task::Poll::Ready(Err(error)) => {
                return core::task::Poll::Ready(Err(DraftSerialRadioError::Io(error)));
            }
            core::task::Poll::Pending => return core::task::Poll::Pending,
        }
    }
    *written = 0;
    core::task::Poll::Ready(Ok(()))
}

fn poll_read_exact<IO>(
    io: &mut IO,
    cx: &mut core::task::Context<'_>,
    buf: &mut [u8],
    filled: &mut usize,
) -> core::task::Poll<Result<(), DraftSerialRadioError>>
where
    IO: AsyncRead + Unpin,
{
    while *filled < buf.len() {
        let mut read_buf = ReadBuf::new(&mut buf[*filled..]);
        match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
            core::task::Poll::Ready(Ok(())) => {
                let count = read_buf.filled().len();
                if count == 0 {
                    return core::task::Poll::Ready(Err(DraftSerialRadioError::Protocol(
                        "unexpected end of stream",
                    )));
                }
                *filled += count;
            }
            core::task::Poll::Ready(Err(error)) => {
                return core::task::Poll::Ready(Err(DraftSerialRadioError::Io(error)));
            }
            core::task::Poll::Pending => return core::task::Poll::Pending,
        }
    }
    *filled = 0;
    core::task::Poll::Ready(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::poll_fn;
    use tokio::io::duplex;

    #[tokio::test]
    async fn draft_serial_radio_round_trips_commands() {
        let (client, mut server) = duplex(256);
        let server_task = tokio::spawn(async move {
            loop {
                let mut tag = [0u8; 1];
                if server.read_exact(&mut tag).await.is_err() {
                    break;
                }
                match tag[0] {
                    CMD_MAX_FRAME_SIZE => {
                        server.write_all(&[RESP_MAX_FRAME_SIZE]).await.unwrap();
                        server.write_all(&255u16.to_le_bytes()).await.unwrap();
                    }
                    CMD_T_FRAME_MS => {
                        server.write_all(&[RESP_T_FRAME_MS]).await.unwrap();
                        server.write_all(&42u32.to_le_bytes()).await.unwrap();
                    }
                    CMD_RECEIVE => {
                        server.write_all(&[RESP_RECEIVE]).await.unwrap();
                        server.write_all(&4u16.to_le_bytes()).await.unwrap();
                        server.write_all(&(-70i16).to_le_bytes()).await.unwrap();
                        server.write_all(&[12u8]).await.unwrap();
                        server.write_all(b"pong").await.unwrap();
                    }
                    CMD_CAD => {
                        server.write_all(&[RESP_CAD, 1]).await.unwrap();
                    }
                    CMD_TRANSMIT => {
                        let len = read_u16(&mut server).await.unwrap() as usize;
                        let mut payload = vec![0u8; len];
                        server.read_exact(&mut payload).await.unwrap();
                        assert_eq!(payload, b"ping");
                        server.write_all(&[RESP_TRANSMIT, 0]).await.unwrap();
                        break;
                    }
                    other => panic!("unexpected command tag {other}"),
                }
                server.flush().await.unwrap();
            }
        });

        let mut radio = DraftSerialRadio::from_stream(client).await.unwrap();
        assert_eq!(radio.max_frame_size(), 255);
        assert_eq!(radio.t_frame_ms(), 42);

        let mut buf = [0u8; 16];
        let rx = poll_fn(|cx| radio.poll_receive(cx, &mut buf))
            .await
            .unwrap();
        assert_eq!(rx.len, 4);
        assert_eq!(rx.rssi, -70);
        assert_eq!(rx.snr, 12);
        assert_eq!(&buf[..rx.len], b"pong");

        radio
            .transmit(
                b"ping",
                TxOptions {
                    cad_timeout_ms: Some(0),
                },
            )
            .await
            .unwrap();
        server_task.await.unwrap();
    }
}
