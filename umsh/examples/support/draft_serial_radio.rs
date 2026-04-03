//! Example-only serial shim for the desktop chat demo.
//!
//! This module is intentionally not part of the public `umsh` crate API because
//! the byte-level command protocol used here is only a provisional demo hook.
//! It is not specified by the protocol docs and should not be treated as the
//! intended long-term companion-radio interface.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use umsh::hal::{Radio, RxInfo};

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
}

impl<IO> DraftSerialRadio<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn from_stream(mut io: IO) -> Result<Self, DraftSerialRadioError> {
        let max_frame_size = query_u16(&mut io, CMD_MAX_FRAME_SIZE, RESP_MAX_FRAME_SIZE).await? as usize;
        let t_frame_ms = query_u32(&mut io, CMD_T_FRAME_MS, RESP_T_FRAME_MS).await?;
        Ok(Self {
            io,
            max_frame_size,
            t_frame_ms,
        })
    }

    async fn send_tag(&mut self, tag: u8) -> Result<(), DraftSerialRadioError> {
        self.io.write_all(&[tag]).await.map_err(DraftSerialRadioError::Io)?;
        self.io.flush().await.map_err(DraftSerialRadioError::Io)
    }

    async fn expect_tag(&mut self, expected: u8) -> Result<(), DraftSerialRadioError> {
        let mut tag = [0u8; 1];
        self.io.read_exact(&mut tag).await.map_err(DraftSerialRadioError::Io)?;
        if tag[0] != expected {
            return Err(DraftSerialRadioError::Protocol("unexpected response tag"));
        }
        Ok(())
    }
}

#[cfg(feature = "serial-radio")]
impl DraftSerialRadio<tokio_serial::SerialStream> {
    pub async fn open_tokio(path: impl AsRef<str>, baud_rate: u32) -> Result<Self, DraftSerialRadioError> {
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

    async fn transmit(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        if data.len() > self.max_frame_size || data.len() > u16::MAX as usize {
            return Err(DraftSerialRadioError::FrameTooLarge(data.len()));
        }
        self.send_tag(CMD_TRANSMIT).await?;
        self.io
            .write_all(&(data.len() as u16).to_le_bytes())
            .await
            .map_err(DraftSerialRadioError::Io)?;
        self.io.write_all(data).await.map_err(DraftSerialRadioError::Io)?;
        self.io.flush().await.map_err(DraftSerialRadioError::Io)?;
        self.expect_tag(RESP_TRANSMIT).await?;
        let mut status = [0u8; 1];
        self.io.read_exact(&mut status).await.map_err(DraftSerialRadioError::Io)?;
        if status[0] != 0 {
            return Err(DraftSerialRadioError::Protocol("companion transmit rejected frame"));
        }
        Ok(())
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<RxInfo, Self::Error> {
        self.send_tag(CMD_RECEIVE).await?;
        self.expect_tag(RESP_RECEIVE).await?;
        let len = read_u16(&mut self.io).await? as usize;
        let rssi = read_i16(&mut self.io).await?;
        let snr = read_i8(&mut self.io).await?;
        if len > buf.len() {
            return Err(DraftSerialRadioError::FrameTooLarge(len));
        }
        self.io.read_exact(&mut buf[..len]).await.map_err(DraftSerialRadioError::Io)?;
        Ok(RxInfo { len, rssi, snr })
    }

    async fn cad(&mut self) -> Result<bool, Self::Error> {
        self.send_tag(CMD_CAD).await?;
        self.expect_tag(RESP_CAD).await?;
        let mut busy = [0u8; 1];
        self.io.read_exact(&mut busy).await.map_err(DraftSerialRadioError::Io)?;
        Ok(busy[0] != 0)
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
    io.write_all(&[command]).await.map_err(DraftSerialRadioError::Io)?;
    io.flush().await.map_err(DraftSerialRadioError::Io)?;
    let mut tag = [0u8; 1];
    io.read_exact(&mut tag).await.map_err(DraftSerialRadioError::Io)?;
    if tag[0] != response {
        return Err(DraftSerialRadioError::Protocol("unexpected response tag"));
    }
    read_u16(io).await
}

async fn query_u32<IO>(io: &mut IO, command: u8, response: u8) -> Result<u32, DraftSerialRadioError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    io.write_all(&[command]).await.map_err(DraftSerialRadioError::Io)?;
    io.flush().await.map_err(DraftSerialRadioError::Io)?;
    let mut tag = [0u8; 1];
    io.read_exact(&mut tag).await.map_err(DraftSerialRadioError::Io)?;
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
    io.read_exact(&mut bytes).await.map_err(DraftSerialRadioError::Io)?;
    Ok(u16::from_le_bytes(bytes))
}

async fn read_u32<IO>(io: &mut IO) -> Result<u32, DraftSerialRadioError>
where
    IO: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 4];
    io.read_exact(&mut bytes).await.map_err(DraftSerialRadioError::Io)?;
    Ok(u32::from_le_bytes(bytes))
}

async fn read_i16<IO>(io: &mut IO) -> Result<i16, DraftSerialRadioError>
where
    IO: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    io.read_exact(&mut bytes).await.map_err(DraftSerialRadioError::Io)?;
    Ok(i16::from_le_bytes(bytes))
}

async fn read_i8<IO>(io: &mut IO) -> Result<i8, DraftSerialRadioError>
where
    IO: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 1];
    io.read_exact(&mut bytes).await.map_err(DraftSerialRadioError::Io)?;
    Ok(bytes[0] as i8)
}

#[cfg(test)]
mod tests {
    use super::*;
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
                    CMD_CAD => {
                        server.write_all(&[RESP_CAD, 1]).await.unwrap();
                    }
                    CMD_RECEIVE => {
                        server.write_all(&[RESP_RECEIVE]).await.unwrap();
                        server.write_all(&4u16.to_le_bytes()).await.unwrap();
                        server.write_all(&(-70i16).to_le_bytes()).await.unwrap();
                        server.write_all(&[12u8]).await.unwrap();
                        server.write_all(b"pong").await.unwrap();
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
        assert!(radio.cad().await.unwrap());

        let mut buf = [0u8; 16];
        let rx = radio.receive(&mut buf).await.unwrap();
        assert_eq!(rx.len, 4);
        assert_eq!(rx.rssi, -70);
        assert_eq!(rx.snr, 12);
        assert_eq!(&buf[..rx.len], b"pong");

        radio.transmit(b"ping").await.unwrap();
        server_task.await.unwrap();
    }
}