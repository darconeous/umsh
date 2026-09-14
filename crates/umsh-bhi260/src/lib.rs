//! BHI260AP host interface, independent of board wiring and motion policy.
//!
//! A sensor firmware image defines the available virtual sensors. Discover them
//! after boot; the existence of a sensor ID in an API is not a capability claim.
//! All chip framing is little-endian, as specified by Bosch (not UMSH framing).
//! Calls own the command/status exchange. After a bus error, timeout, or canceled
//! operation, reset and reload before using the command channel again. The caller
//! must bound I2C transactions themselves; the polling loops here are bounded.
#![no_std]

use embedded_hal_async::{delay::DelayNs, i2c::I2c};

pub mod fifo;

pub const ADDRESS: u8 = 0x28;
/// Maximum payload in a single bus operation, excluding the register address.
pub const TRANSFER_BYTES: usize = 32;

/// Native interrupt status. Bit zero means asserted, not reset/fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptStatus(pub u8);

impl InterruptStatus {
    pub fn asserted(self) -> bool {
        self.0 & 1 != 0
    }
    pub fn fault(self) -> bool {
        self.0 & 0x80 != 0
    }
    pub fn fifo(self, kind: fifo::Kind) -> bool {
        self.0
            & match kind {
                fifo::Kind::Wake => 0x06,
                fifo::Kind::NonWake => 0x18,
            }
            != 0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Bus(E),
    InvalidFirmware,
    WrongProduct(u8),
    Timeout,
    FirmwareVerification(u8),
    Response { expected: u16, actual: u16 },
    Length { expected: usize, actual: usize },
    InvalidArgument,
}

/// Firmware-reported presence bitmap; no interpretation of sensor dependencies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SensorSet(pub [u8; 32]);

impl SensorSet {
    pub fn contains(&self, id: u8) -> bool {
        self.0[usize::from(id) / 8] & (1 << (id % 8)) != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub product: u8,
    pub revision: u8,
    pub rom: u16,
    pub kernel: u16,
    pub user: u16,
}

/// Owns one chip's command channel. The I2C handle can be a shared-bus device;
/// every await between transactions releases that bus's lock.
pub struct Bhi260<I> {
    i2c: I,
    address: u8,
}

impl<I: I2c> Bhi260<I> {
    pub fn new(i2c: I, address: u8) -> Self {
        Self { i2c, address }
    }

    pub fn into_inner(self) -> I {
        self.i2c
    }

    async fn read(&mut self, register: u8, bytes: &mut [u8]) -> Result<(), Error<I::Error>> {
        self.i2c
            .write_read(self.address, &[register], bytes)
            .await
            .map_err(Error::Bus)
    }

    async fn write(&mut self, register: u8, bytes: &[u8]) -> Result<(), Error<I::Error>> {
        if bytes.len() > TRANSFER_BYTES {
            return Err(Error::InvalidArgument);
        }
        let mut packet = [0; TRANSFER_BYTES + 1];
        packet[0] = register;
        packet[1..1 + bytes.len()].copy_from_slice(bytes);
        self.i2c
            .write(self.address, &packet[..1 + bytes.len()])
            .await
            .map_err(Error::Bus)
    }

    pub async fn register(&mut self, register: u8) -> Result<u8, Error<I::Error>> {
        let mut byte = [0];
        self.read(register, &mut byte).await?;
        Ok(byte[0])
    }

    /// Reset to the ROM host interface. No flash writes or external power changes.
    pub async fn reset(&mut self, delay: &mut impl DelayNs) -> Result<(), Error<I::Error>> {
        self.write(0x14, &[1]).await?;
        delay.delay_ms(100).await;
        self.wait_boot(0x10, delay).await
    }

    async fn wait_boot(
        &mut self,
        mask: u8,
        delay: &mut impl DelayNs,
    ) -> Result<(), Error<I::Error>> {
        for _ in 0..100 {
            let status = self.register(0x25).await?;
            if status & 0x40 != 0 {
                return Err(Error::FirmwareVerification(status));
            }
            if status & mask == mask {
                return Ok(());
            }
            delay.delay_ms(50).await;
        }
        Err(Error::Timeout)
    }

    /// Load a complete, word-aligned RAM image using bounded transfers. The
    /// upload length is in words; other command lengths are in bytes.
    pub async fn boot(
        &mut self,
        firmware: &[u8],
        delay: &mut impl DelayNs,
    ) -> Result<Version, Error<I::Error>> {
        if firmware.len() < 4
            || firmware.len() % 4 != 0
            || firmware.len() / 4 > u16::MAX as usize
            || firmware[..2] != [0x2b, 0x66]
        {
            return Err(Error::InvalidFirmware);
        }
        let product = self.register(0x1c).await?;
        if product != 0x89 {
            return Err(Error::WrongProduct(product));
        }
        self.reset(delay).await?;
        // Long-run mode, synchronous status channel, active-high level IRQ.
        // Status responses are read explicitly; they do not assert the IRQ.
        self.write(0x05, &[0]).await?;
        // Bit 6 routes explicit timestamp requests to registers 0x26..0x2a.
        // Without it those registers retain the last IRQ time and a request
        // instead inserts a status packet, disrupting synchronous responses.
        self.write(0x06, &[0x40]).await?;
        self.write(0x07, &[0x0c]).await?;
        let words = (firmware.len() / 4) as u16;
        let mut first = [0; TRANSFER_BYTES];
        first[..4].copy_from_slice(&[2, 0, words as u8, (words >> 8) as u8]);
        let first_len = firmware.len().min(TRANSFER_BYTES - 4);
        first[4..4 + first_len].copy_from_slice(&firmware[..first_len]);
        self.write(0, &first[..4 + first_len]).await?;
        for chunk in firmware[first_len..].chunks(TRANSFER_BYTES) {
            self.write(0, chunk).await?;
        }
        self.wait_boot(0x30, delay).await?;
        self.command(3, &[]).await?;
        self.wait_boot(0x30, delay).await?;
        // ROM's verification bits can remain set while the kernel starts.
        for _ in 0..100 {
            let version = self.version().await?;
            if version.kernel != 0 {
                return Ok(version);
            }
            delay.delay_ms(50).await;
        }
        Err(Error::Timeout)
    }

    pub async fn version(&mut self) -> Result<Version, Error<I::Error>> {
        let mut bytes = [0; 8];
        self.read(0x1c, &mut bytes).await?;
        Ok(Version {
            product: bytes[0],
            revision: bytes[1],
            rom: u16::from_le_bytes([bytes[2], bytes[3]]),
            kernel: u16::from_le_bytes([bytes[4], bytes[5]]),
            user: u16::from_le_bytes([bytes[6], bytes[7]]),
        })
    }

    async fn command(&mut self, command: u16, payload: &[u8]) -> Result<(), Error<I::Error>> {
        let length = payload.len().next_multiple_of(4);
        if length > TRANSFER_BYTES - 4 {
            return Err(Error::InvalidArgument);
        }
        let mut bytes = [0; TRANSFER_BYTES];
        bytes[..2].copy_from_slice(&command.to_le_bytes());
        bytes[2..4].copy_from_slice(&(length as u16).to_le_bytes());
        bytes[4..4 + payload.len()].copy_from_slice(payload);
        self.write(0, &bytes[..4 + length]).await
    }

    /// Configure a virtual sensor. Zero disables it; a positive rate arms an
    /// event sensor. Continuous sensors use Hz and latency in milliseconds.
    /// The caller must discover support and verify the applied configuration.
    pub async fn configure_sensor(
        &mut self,
        id: u8,
        rate_hz: f32,
        latency_ms: u32,
    ) -> Result<(), Error<I::Error>> {
        if id == 0 || id >= 224 || !rate_hz.is_finite() || rate_hz < 0.0 || latency_ms > 0xff_ffff {
            return Err(Error::InvalidArgument);
        }
        let mut payload = [0; 8];
        payload[0] = id;
        payload[1..5].copy_from_slice(&rate_hz.to_le_bytes());
        payload[5..].copy_from_slice(&latency_ms.to_le_bytes()[..3]);
        self.command(0x0d, &payload).await
    }

    /// Request a fresh 40-bit hardware clock latch (64 ticks per millisecond).
    /// This is for timestamp correlation during FIFO service, not polling for
    /// motion. A nonchanging latch fails after five bounded attempts.
    pub async fn timestamp(&mut self, delay: &mut impl DelayNs) -> Result<u64, Error<I::Error>> {
        let mut old = [0; 5];
        self.read(0x26, &mut old).await?;
        self.write(0x15, &[1]).await?;
        for _ in 0..5 {
            delay.delay_ms(1).await;
            let mut new = [0; 5];
            self.read(0x26, &mut new).await?;
            if old != new {
                let mut bytes = [0; 8];
                bytes[..5].copy_from_slice(&new);
                return Ok(u64::from_le_bytes(bytes));
            }
        }
        Err(Error::Timeout)
    }

    /// Read an exact-size parameter in synchronous status mode. Mismatched
    /// replies are drained before returning an error; never accept stale data.
    pub async fn parameter(
        &mut self,
        id: u16,
        out: &mut [u8],
        delay: &mut impl DelayNs,
    ) -> Result<(), Error<I::Error>> {
        if id & 0xf000 != 0 {
            return Err(Error::InvalidArgument);
        }
        self.command(id | 0x1000, &[]).await?;
        let mut ready = false;
        for _ in 0..100 {
            if self.register(0x2d).await? & 0x20 != 0 {
                ready = true;
                break;
            }
            delay.delay_ms(10).await;
        }
        if !ready {
            return Err(Error::Timeout);
        }
        let mut header = [0; 4];
        self.read(3, &mut header).await?;
        let code = u16::from_le_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        // Even an invalid reply has a finite u16 length. Drain in bounded
        // transactions, leaving no remainder to masquerade as the next header.
        let mut scratch = [0; TRANSFER_BYTES];
        let mut offset = 0;
        while offset < length {
            let count = (length - offset).min(TRANSFER_BYTES);
            self.read(3, &mut scratch[..count]).await?;
            if code == id && length == out.len() {
                out[offset..offset + count].copy_from_slice(&scratch[..count]);
            }
            offset += count;
        }
        if code != id {
            return Err(Error::Response {
                expected: id,
                actual: code,
            });
        }
        if length != out.len() {
            return Err(Error::Length {
                expected: out.len(),
                actual: length,
            });
        }
        Ok(())
    }

    pub async fn virtual_sensors(
        &mut self,
        delay: &mut impl DelayNs,
    ) -> Result<SensorSet, Error<I::Error>> {
        let mut set = SensorSet([0; 32]);
        self.parameter(0x11f, &mut set.0, delay).await?;
        Ok(set)
    }

    pub async fn physical_sensors(
        &mut self,
        delay: &mut impl DelayNs,
    ) -> Result<[u8; 8], Error<I::Error>> {
        let mut set = [0; 8];
        self.parameter(0x120, &mut set, delay).await?;
        Ok(set)
    }

    /// Read at most one bounded chunk of a FIFO transfer. `remaining` belongs
    /// to this FIFO and must survive across calls: only a new transfer starts
    /// with a two-byte length header. Reset it after resetting the chip.
    pub async fn read_fifo(
        &mut self,
        fifo: fifo::Kind,
        remaining: &mut u16,
        out: &mut [u8],
    ) -> Result<usize, Error<I::Error>> {
        if out.is_empty() || out.len() > TRANSFER_BYTES {
            return Err(Error::InvalidArgument);
        }
        if *remaining == 0 {
            let mut size = [0; 2];
            self.read(fifo as u8, &mut size).await?;
            *remaining = u16::from_le_bytes(size);
        }
        let count = out.len().min(usize::from(*remaining));
        if count != 0 {
            self.read(fifo as u8, &mut out[..count]).await?;
            *remaining -= count as u16;
        }
        Ok(count)
    }
}
